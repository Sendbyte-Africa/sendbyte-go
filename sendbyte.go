// Package sendbyte is the official Go SDK for SendByte, the email API for
// Africa. Standard library only.
//
//	client := sendbyte.New("sk_test_...")
//	email, err := client.Emails.Send(ctx, sendbyte.SendEmailRequest{
//	    From:    "PayLink <receipts@paylink.ng>",
//	    To:      []string{"amaka@halo.ng"},
//	    Subject: "Receipt",
//	    HTML:    "<p>Thank you.</p>",
//	})
package sendbyte

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	defaultBaseURL     = "https://api.sendbyte.africa"
	version            = "0.3.0"
	defaultTimeout     = 30 * time.Second
	defaultMaxAttempts = 3
	maxBackoff         = 20 * time.Second
	// SignatureHeader carries the webhook HMAC signature.
	SignatureHeader = "sendbyte-signature"
)

// Client is the SendByte API client.
type Client struct {
	apiKey      string
	baseURL     string
	httpClient  *http.Client
	maxAttempts int

	Emails        *EmailsService
	Domains       *DomainsService
	Webhooks      *WebhooksService
	Brands        *BrandsService
	Lists         *ListsService
	Subscribers   *SubscribersService
	Campaigns     *CampaignsService
	Receiving     *ReceivingService
	Received      *ReceivedService
	InboundRoutes *InboundRoutesService
}

// Option configures the client.
type Option func(*Client)

// WithBaseURL overrides the API host (staging, local development).
func WithBaseURL(u string) Option {
	return func(c *Client) { c.baseURL = strings.TrimRight(u, "/") }
}

// WithHTTPClient injects a custom *http.Client. If the injected client has no
// Timeout, the SDK applies a sane default on a private copy so a hung connection
// cannot block forever, without mutating the client you passed in.
func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) { c.httpClient = h }
}

// WithMaxAttempts caps the total attempts per request, including the first (so
// 3 means up to 2 retries). Values below 1 are treated as 1.
func WithMaxAttempts(n int) Option {
	return func(c *Client) { c.maxAttempts = n }
}

// isSecureBaseURL reports whether https is in use; http is tolerated only for
// localhost/loopback dev hosts.
func isSecureBaseURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	host := u.Hostname()
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// New creates a client. The key must start with sk_live_ or sk_test_; requests
// retry on 429, 5xx and transport errors, and sends carry an idempotency key.
func New(apiKey string, opts ...Option) (*Client, error) {
	if !strings.HasPrefix(apiKey, "sk_live_") && !strings.HasPrefix(apiKey, "sk_test_") {
		return nil, &Error{
			Code:    "invalid_api_key",
			Message: "API key must start with sk_live_ or sk_test_. Create one in the dashboard under API keys.",
		}
	}
	return newClient(apiKey, opts...)
}

func newClient(apiKey string, opts ...Option) (*Client, error) {
	c := &Client{
		apiKey:      apiKey,
		baseURL:     defaultBaseURL,
		httpClient:  &http.Client{Timeout: defaultTimeout},
		maxAttempts: defaultMaxAttempts,
	}
	for _, opt := range opts {
		opt(c)
	}
	if c.maxAttempts < 1 {
		c.maxAttempts = 1
	}
	if strings.HasPrefix(apiKey, "sk_live_") && !isSecureBaseURL(c.baseURL) {
		return nil, ErrInsecureURL
	}
	if c.httpClient == nil {
		c.httpClient = &http.Client{Timeout: defaultTimeout}
	} else if c.httpClient.Timeout == 0 {
		cp := *c.httpClient
		cp.Timeout = defaultTimeout
		c.httpClient = &cp
	}
	c.Emails = &EmailsService{c}
	c.Domains = &DomainsService{c}
	c.Brands = &BrandsService{c}
	c.Lists = &ListsService{c}
	c.Subscribers = &SubscribersService{c}
	c.Campaigns = &CampaignsService{c}
	c.Webhooks = &WebhooksService{c}
	c.Receiving = &ReceivingService{c}
	c.Received = &ReceivedService{c}
	c.InboundRoutes = &InboundRoutesService{c}
	return c, nil
}

func (c *Client) request(ctx context.Context, method, path string, body, out any) error {
	// Auto-generate an idempotency key for sends and reuse it across retries so
	// a retried POST /v1/emails cannot double-send. Body-based, matching the API.
	if method == http.MethodPost && path == "/v1/emails" {
		body = withIdempotencyKey(body)
	}

	var payload []byte
	if body != nil {
		marshalled, err := json.Marshal(body)
		if err != nil {
			return err
		}
		payload = marshalled
	}

	var lastErr error
	for attempt := 1; attempt <= c.maxAttempts; attempt++ {
		var reader io.Reader
		if payload != nil {
			reader = bytes.NewReader(payload)
		}
		req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
		req.Header.Set("User-Agent", "sendbyte-go/"+version)
		if payload != nil {
			req.Header.Set("Content-Type", "application/json")
		}

		res, err := c.httpClient.Do(req)
		if err != nil {
			// Transport error (timeout, connection refused): retry if attempts remain.
			lastErr = err
			if attempt < c.maxAttempts {
				if waitErr := sleepCtx(ctx, backoffDelay(attempt, "")); waitErr != nil {
					return waitErr
				}
				continue
			}
			return err
		}
		data, readErr := io.ReadAll(res.Body)
		res.Body.Close()
		if readErr != nil {
			lastErr = readErr
			if attempt < c.maxAttempts {
				if waitErr := sleepCtx(ctx, backoffDelay(attempt, "")); waitErr != nil {
					return waitErr
				}
				continue
			}
			return readErr
		}

		if res.StatusCode >= 400 {
			if isRetryableStatus(res.StatusCode) && attempt < c.maxAttempts {
				lastErr = parseError(data, res.StatusCode)
				if waitErr := sleepCtx(ctx, backoffDelay(attempt, res.Header.Get("Retry-After"))); waitErr != nil {
					return waitErr
				}
				continue
			}
			return parseError(data, res.StatusCode)
		}
		if out != nil {
			return json.Unmarshal(data, out)
		}
		return nil
	}

	if lastErr != nil {
		return lastErr
	}
	return &Error{Code: "request_failed", Message: "request failed after exhausting retries"}
}

// withIdempotencyKey adds a generated idempotency_key to a send body when the
// caller did not set one. It works for SendEmailRequest and for a map body.
func withIdempotencyKey(body any) any {
	switch b := body.(type) {
	case SendEmailRequest:
		if b.IdempotencyKey == "" {
			b.IdempotencyKey = newIdempotencyKey()
		}
		return b
	case *SendEmailRequest:
		if b != nil && b.IdempotencyKey == "" {
			clone := *b
			clone.IdempotencyKey = newIdempotencyKey()
			return clone
		}
		return b
	case map[string]any:
		if _, ok := b["idempotency_key"]; !ok {
			b["idempotency_key"] = newIdempotencyKey()
		}
		return b
	default:
		return body
	}
}

// newIdempotencyKey returns a random RFC 4122 v4 UUID string.
func newIdempotencyKey() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Fall back to a timestamp-derived key; collisions are vanishingly
		// unlikely and a key is still better than none for retry safety.
		return fmt.Sprintf("sb-%d", time.Now().UnixNano())
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func isRetryableStatus(status int) bool {
	return status == 429 || (status >= 500 && status < 600)
}

// parseError turns a non-2xx body into a typed *Error, never failing on a
// non-JSON body (a gateway/proxy 502/504 may return HTML or plain text).
func parseError(data []byte, status int) error {
	var wrapper struct {
		Error Error `json:"error"`
	}
	if jsonErr := json.Unmarshal(data, &wrapper); jsonErr != nil || wrapper.Error.Code == "" {
		return &Error{Code: "request_failed", Message: fmt.Sprintf("request failed with status %d", status), Status: status}
	}
	wrapper.Error.Status = status
	return &wrapper.Error
}

// backoffDelay computes exponential backoff with full jitter, capped, honoring
// Retry-After (delta-seconds or an HTTP-date) when present. attempt is 1-based.
func backoffDelay(attempt int, retryAfter string) time.Duration {
	if d, ok := parseRetryAfter(retryAfter); ok {
		if d > maxBackoff {
			return maxBackoff
		}
		return d
	}
	base := 250 * time.Millisecond * (1 << (attempt - 1))
	if base > maxBackoff {
		base = maxBackoff
	}
	return jitter(base)
}

func parseRetryAfter(value string) (time.Duration, bool) {
	if value == "" {
		return 0, false
	}
	if secs, err := strconv.Atoi(strings.TrimSpace(value)); err == nil {
		if secs < 0 {
			secs = 0
		}
		return time.Duration(secs) * time.Second, true
	}
	if when, err := http.ParseTime(value); err == nil {
		d := time.Until(when)
		if d < 0 {
			d = 0
		}
		return d, true
	}
	return 0, false
}

func jitter(max time.Duration) time.Duration {
	if max <= 0 {
		return 0
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return max
	}
	return time.Duration(n.Int64())
}

// sleepCtx waits for d unless the context is cancelled first.
func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// ---------------------------------------------------------------- Emails

// Attachment is a file to attach to an email. Content is base64-encoded.
//
// Set ContentID to embed the file in the HTML body instead of listing it as a
// download, and reference it as <img src="cid:VALUE">. A ContentID implies an
// inline disposition, so Disposition is only needed to force "attachment" for a
// file that has a Content-ID but should still appear as a download.
type Attachment struct {
	Filename    string `json:"filename"`
	Content     string `json:"content"`
	ContentType string `json:"content_type"`
	ContentID   string `json:"content_id,omitempty"`
	Disposition string `json:"disposition,omitempty"`
}

// ListUnsubscribe carries one-click unsubscribe details (RFC 8058). Provide an
// https URL and/or a mailto. The API emits List-Unsubscribe and, for an https
// URL, List-Unsubscribe-Post so Gmail and Yahoo render a native unsubscribe.
// Recommended for bulk mail under the 2024 sender rules; harmless on
// transactional.
type ListUnsubscribe struct {
	URL    string `json:"url,omitempty"`
	Mailto string `json:"mailto,omitempty"`
}

// SendEmailRequest is the payload for Emails.Send.
type SendEmailRequest struct {
	From            string            `json:"from"`
	To              []string          `json:"to"`
	Subject         string            `json:"subject,omitempty"`
	HTML            string            `json:"html,omitempty"`
	Text            string            `json:"text,omitempty"`
	CC              []string          `json:"cc,omitempty"`
	BCC             []string          `json:"bcc,omitempty"`
	ReplyTo         []string          `json:"reply_to,omitempty"`
	Attachments     []Attachment      `json:"attachments,omitempty"`
	Tags            []string          `json:"tags,omitempty"`
	Headers         map[string]string `json:"headers,omitempty"`
	ListUnsubscribe *ListUnsubscribe  `json:"list_unsubscribe,omitempty"`
	ScheduledAt     string            `json:"scheduled_at,omitempty"`
	TemplateID      string            `json:"template_id,omitempty"`
	Variables       map[string]any    `json:"variables,omitempty"`
	IdempotencyKey  string            `json:"idempotency_key,omitempty"`
}

// Email is a summary of an email in the log.
type Email struct {
	ID      string   `json:"id"`
	From    string   `json:"from"`
	To      []string `json:"to"`
	Subject string   `json:"subject"`
	Status  string   `json:"status"`
	Sandbox bool     `json:"sandbox"`
	Tags    []string `json:"tags"`
	// MessageID is the delivered RFC Message-ID once known (nil until sent). Use
	// it as the threading anchor for In-Reply-To / References on follow-up sends.
	MessageID   *string `json:"message_id"`
	ScheduledAt *string `json:"scheduled_at"`
	CreatedAt   string  `json:"created_at"`
}

// EmailEvent is one lifecycle event on an email.
type EmailEvent struct {
	Type      string         `json:"type"`
	Payload   map[string]any `json:"payload"`
	CreatedAt string         `json:"created_at"`
}

// EmailDetail is the full email record including content and events.
type EmailDetail struct {
	Email
	HTML   *string      `json:"html"`
	Text   *string      `json:"text"`
	Events []EmailEvent `json:"events"`
}

// ListEmailsParams filters Emails.List.
type ListEmailsParams struct {
	Limit  int
	After  string
	Status string
}

// EmailList is a page of the email log.
type EmailList struct {
	Data    []Email `json:"data"`
	HasMore bool    `json:"has_more"`
}

// EmailsService talks to /v1/emails.
type EmailsService struct{ c *Client }

// Send queues an email for delivery.
func (s *EmailsService) Send(ctx context.Context, req SendEmailRequest) (*Email, error) {
	var out Email
	if err := s.c.request(ctx, http.MethodPost, "/v1/emails", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Get fetches one email with its event timeline.
func (s *EmailsService) Get(ctx context.Context, id string) (*EmailDetail, error) {
	var out EmailDetail
	if err := s.c.request(ctx, http.MethodGet, "/v1/emails/"+id, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// List pages through the email log, newest first.
func (s *EmailsService) List(ctx context.Context, params ListEmailsParams) (*EmailList, error) {
	q := url.Values{}
	if params.Limit > 0 {
		q.Set("limit", strconv.Itoa(params.Limit))
	}
	if params.After != "" {
		q.Set("after", params.After)
	}
	if params.Status != "" {
		q.Set("status", params.Status)
	}
	path := "/v1/emails"
	if encoded := q.Encode(); encoded != "" {
		path += "?" + encoded
	}
	var out EmailList
	if err := s.c.request(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ---------------------------------------------------------------- Domains

// DNSRecord is one record to publish for domain verification.
type DNSRecord struct {
	Type string `json:"type"`
	Host string `json:"host"`
	// Name is the relative name for the DNS provider's Name/Host field (apex = "@").
	Name     string `json:"name"`
	Value    string `json:"value"`
	Purpose  string `json:"purpose"`
	Required bool   `json:"required"`
}

// Domain is a sending domain.
type Domain struct {
	ID           string      `json:"id"`
	Domain       string      `json:"domain"`
	Status       string      `json:"status"`
	DKIMSelector *string     `json:"dkim_selector"`
	DNSRecords   []DNSRecord `json:"dns_records"`
	VerifiedAt   *string     `json:"verified_at"`
	// DeliverabilityReady is true once the recommended SPF/DMARC/MAIL FROM records
	// are also published. Distinct from Status: a verified domain (DKIM only) still
	// underperforms at Yahoo/Microsoft until this is true.
	DeliverabilityReady bool   `json:"deliverability_ready"`
	CreatedAt           string `json:"created_at"`
}

// DomainVerification is the result of a verification check. SESVerified lets
// callers tell "DNS passed but SES not yet confirmed" (false) from fully
// verified (true); it is nil when the API does not report it.
type DomainVerification struct {
	ID                  string `json:"id"`
	Domain              string `json:"domain"`
	Status              string `json:"status"`
	SESVerified         *bool  `json:"ses_verified"`
	DeliverabilityReady bool   `json:"deliverability_ready"`
	Checks              []struct {
		Purpose  string `json:"purpose"`
		Host     string `json:"host"`
		Required bool   `json:"required"`
		Pass     bool   `json:"pass"`
	} `json:"checks"`
}

// --- Marketing ---------------------------------------------------------------
//
// Brands hold lists, lists hold subscribers. A subscriber's status belongs to
// the list rather than to the person, which is why these calls take both ids.

// Brand is a marketing brand: the container lists, campaigns and reports live in.
type Brand struct {
	ID            string  `json:"id"`
	Name          string  `json:"name"`
	PublicName    string  `json:"public_name"`
	Description   *string `json:"description"`
	LogoURL       *string `json:"logo_url"`
	FromName      *string `json:"from_name"`
	FromAddress   *string `json:"from_address"`
	ReplyTo       *string `json:"reply_to"`
	PostalAddress *string `json:"postal_address"`
	Timezone      string  `json:"timezone"`
	CreatedAt     string  `json:"created_at"`
}

// ListCounts breaks a list down by membership status.
type ListCounts struct {
	Subscribed   int `json:"subscribed"`
	Unconfirmed  int `json:"unconfirmed"`
	Unsubscribed int `json:"unsubscribed"`
	Bounced      int `json:"bounced"`
	Complained   int `json:"complained"`
}

// SubscriberList is one list inside a brand.
type SubscriberList struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	OptIn     string     `json:"opt_in"`
	Counts    ListCounts `json:"counts"`
	CreatedAt string     `json:"created_at"`
}

// Subscriber is one person's membership of one list.
type Subscriber struct {
	ID         string         `json:"id"`
	Email      string         `json:"email"`
	Name       *string        `json:"name"`
	Attributes map[string]any `json:"attributes"`
	Status     string         `json:"status"`
	Source     string         `json:"source"`
	CreatedAt  string         `json:"created_at"`
}

// AddSubscriberResult reports what happened, including when nothing did.
type AddSubscriberResult struct {
	ID     string `json:"id"`
	Email  string `json:"email"`
	Status string `json:"status"`
	// SkippedReason is set when the person was deliberately left alone: they
	// previously unsubscribed, bounced, or opted out of the whole brand.
	SkippedReason *string `json:"skipped_reason"`
}

// ImportSummary accounts for every row of a batch import.
type ImportSummary struct {
	Imported int `json:"imported"`
	Updated  int `json:"updated"`
	Invalid  int `json:"invalid"`
	Skipped  int `json:"skipped"`
	OverCap  int `json:"overCap"`
	Rejected []struct {
		Email  string `json:"email"`
		Reason string `json:"reason"`
	} `json:"rejected"`
}

// BrandsService talks to /v1/brands.
type BrandsService struct{ c *Client }

func (s *BrandsService) Create(ctx context.Context, name string) (*Brand, error) {
	var out Brand
	if err := s.c.request(ctx, http.MethodPost, "/v1/brands", map[string]any{"name": name}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (s *BrandsService) List(ctx context.Context) ([]Brand, error) {
	var out struct {
		Data []Brand `json:"data"`
	}
	if err := s.c.request(ctx, http.MethodGet, "/v1/brands", nil, &out); err != nil {
		return nil, err
	}
	return out.Data, nil
}

func (s *BrandsService) Get(ctx context.Context, brandID string) (*Brand, error) {
	var out Brand
	if err := s.c.request(ctx, http.MethodGet, "/v1/brands/"+brandID, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListsService talks to /v1/brands/{brand}/lists.
type ListsService struct{ c *Client }

func (s *ListsService) Create(ctx context.Context, brandID, name string) (*SubscriberList, error) {
	var out SubscriberList
	path := "/v1/brands/" + brandID + "/lists"
	if err := s.c.request(ctx, http.MethodPost, path, map[string]any{"name": name}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (s *ListsService) List(ctx context.Context, brandID string) ([]SubscriberList, error) {
	var out struct {
		Data []SubscriberList `json:"data"`
	}
	if err := s.c.request(ctx, http.MethodGet, "/v1/brands/"+brandID+"/lists", nil, &out); err != nil {
		return nil, err
	}
	return out.Data, nil
}

// SubscribersService talks to /v1/brands/{brand}/lists/{list}/subscribers.
type SubscribersService struct{ c *Client }

// Add puts someone on a list.
//
// On a double opt-in list they land as unconfirmed and are never mailed until
// they confirm. Anyone who previously unsubscribed or bounced stays off, and
// the result says so via SkippedReason rather than returning an error: a bulk
// caller should log it and carry on, not stop.
func (s *SubscribersService) Add(ctx context.Context, brandID, listID, email string) (*AddSubscriberResult, error) {
	var out AddSubscriberResult
	path := "/v1/brands/" + brandID + "/lists/" + listID + "/subscribers"
	if err := s.c.request(ctx, http.MethodPost, path, map[string]any{"email": email}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (s *SubscribersService) List(ctx context.Context, brandID, listID string) ([]Subscriber, error) {
	var out struct {
		Data []Subscriber `json:"data"`
	}
	path := "/v1/brands/" + brandID + "/lists/" + listID + "/subscribers"
	if err := s.c.request(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return out.Data, nil
}

// Import adds up to 1,000 rows in one call and accounts for every rejection.
func (s *SubscribersService) Import(ctx context.Context, brandID, listID string, subscribers []map[string]any) (*ImportSummary, error) {
	var out ImportSummary
	path := "/v1/brands/" + brandID + "/lists/" + listID + "/import"
	body := map[string]any{"subscribers": subscribers}
	if err := s.c.request(ctx, http.MethodPost, path, body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// SetStatus changes someone's standing on one list.
func (s *SubscribersService) SetStatus(ctx context.Context, brandID, listID, subscriberID, status string) error {
	path := "/v1/brands/" + brandID + "/lists/" + listID + "/subscribers/" + subscriberID
	return s.c.request(ctx, http.MethodPatch, path, map[string]any{"status": status}, nil)
}

// Campaign is a marketing send to one or more lists.
type Campaign struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Subject    string `json:"subject"`
	From       string `json:"from"`
	Status     string `json:"status"`
	Recipients int    `json:"recipients"`
	Sent       int    `json:"sent"`
	CreatedAt  string `json:"created_at"`
}

// SendResult reports what the send froze and started.
type SendResult struct {
	ID         string `json:"id"`
	Status     string `json:"status"`
	Recipients int    `json:"recipients"`
}

// CampaignsService talks to /v1/brands/{brand}/campaigns.
type CampaignsService struct{ c *Client }

func (s *CampaignsService) Create(ctx context.Context, brandID string, body map[string]any) (*Campaign, error) {
	var out Campaign
	if err := s.c.request(ctx, http.MethodPost, "/v1/brands/"+brandID+"/campaigns", body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (s *CampaignsService) List(ctx context.Context, brandID string) ([]Campaign, error) {
	var out struct {
		Data []Campaign `json:"data"`
	}
	if err := s.c.request(ctx, http.MethodGet, "/v1/brands/"+brandID+"/campaigns", nil, &out); err != nil {
		return nil, err
	}
	return out.Data, nil
}

// Send freezes the audience and starts sending.
//
// The audience is snapshotted at this moment: somebody who joins afterwards is
// not included, somebody who leaves before their turn is skipped, and a person
// on two of the chosen lists receives one email.
func (s *CampaignsService) Send(ctx context.Context, brandID, campaignID string, listIDs []string) (*SendResult, error) {
	var out SendResult
	path := "/v1/brands/" + brandID + "/campaigns/" + campaignID + "/send"
	if err := s.c.request(ctx, http.MethodPost, path, map[string]any{"list_ids": listIDs}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (s *CampaignsService) Cancel(ctx context.Context, brandID, campaignID string) error {
	return s.c.request(ctx, http.MethodPost, "/v1/brands/"+brandID+"/campaigns/"+campaignID+"/cancel", nil, nil)
}

// DomainsService talks to /v1/domains.
type DomainsService struct{ c *Client }

// Create registers a domain and returns the DNS records to publish.
func (s *DomainsService) Create(ctx context.Context, domain string) (*Domain, error) {
	var out Domain
	if err := s.c.request(ctx, http.MethodPost, "/v1/domains", map[string]string{"domain": domain}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// List returns all domains in the project.
func (s *DomainsService) List(ctx context.Context) ([]Domain, error) {
	var out struct {
		Data []Domain `json:"data"`
	}
	if err := s.c.request(ctx, http.MethodGet, "/v1/domains", nil, &out); err != nil {
		return nil, err
	}
	return out.Data, nil
}

// Get fetches one domain by id, including its DNS records.
func (s *DomainsService) Get(ctx context.Context, id string) (*Domain, error) {
	var out Domain
	if err := s.c.request(ctx, http.MethodGet, "/v1/domains/"+id, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Verify checks the published DNS records.
func (s *DomainsService) Verify(ctx context.Context, id string) (*DomainVerification, error) {
	var out DomainVerification
	if err := s.c.request(ctx, http.MethodPost, "/v1/domains/"+id+"/verify", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ---------------------------------------------------------------- Webhooks

// WebhookEvents is the set of events an endpoint subscribes to. The API sends
// either a JSON array of event names or the literal string "all"; when All is
// true the endpoint receives every event and Events is nil.
type WebhookEvents struct {
	All    bool
	Events []string
}

// UnmarshalJSON accepts both the "all" sentinel and an array of event names.
func (e *WebhookEvents) UnmarshalJSON(data []byte) error {
	if string(data) == `"all"` {
		e.All, e.Events = true, nil
		return nil
	}
	e.All = false
	return json.Unmarshal(data, &e.Events)
}

// WebhookEndpoint is a registered webhook destination. Secret is present
// only in the Create response; store it then.
type WebhookEndpoint struct {
	ID       string        `json:"id"`
	URL      string        `json:"url"`
	Events   WebhookEvents `json:"events"`
	Disabled bool          `json:"disabled"`
	// DisabledAt is set when the endpoint was auto-disabled after chronic delivery
	// failures, else nil.
	DisabledAt *string `json:"disabled_at"`
	// ConsecutiveFailures counts failed deliveries in a row (resets to 0 on a
	// success). Watch it to warn before auto-disable.
	ConsecutiveFailures int    `json:"consecutive_failures"`
	CreatedAt           string `json:"created_at"`
	Secret              string `json:"secret,omitempty"`
}

// WebhookReplay is the result of replaying a past delivery.
type WebhookReplay struct {
	ID       string `json:"id"`
	ReplayOf string `json:"replay_of"`
	Status   string `json:"status"`
}

// WebhooksService talks to /v1/webhooks.
type WebhooksService struct{ c *Client }

// Create registers an endpoint. Pass nil events to receive everything.
func (s *WebhooksService) Create(ctx context.Context, endpoint string, events []string) (*WebhookEndpoint, error) {
	body := map[string]any{"url": endpoint}
	if events != nil {
		body["events"] = events
	}
	var out WebhookEndpoint
	if err := s.c.request(ctx, http.MethodPost, "/v1/webhooks", body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// List returns all endpoints (never their secrets).
func (s *WebhooksService) List(ctx context.Context) ([]WebhookEndpoint, error) {
	var out struct {
		Data []WebhookEndpoint `json:"data"`
	}
	if err := s.c.request(ctx, http.MethodGet, "/v1/webhooks", nil, &out); err != nil {
		return nil, err
	}
	return out.Data, nil
}

// Disable stops deliveries to an endpoint.
func (s *WebhooksService) Disable(ctx context.Context, id string) error {
	return s.c.request(ctx, http.MethodDelete, "/v1/webhooks/"+id, nil, nil)
}

// Replay re-enqueues a past delivery by its id.
func (s *WebhooksService) Replay(ctx context.Context, deliveryID string) (*WebhookReplay, error) {
	var out WebhookReplay
	if err := s.c.request(ctx, http.MethodPost, "/v1/webhooks/deliveries/"+deliveryID+"/replay", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ---------------------------------------------------------------- Signatures

// VerifyWebhookSignature reports whether a webhook request came from
// SendByte. Verify against the raw request body. The header format is
// "t=<unix seconds>,v1=<hex hmac-sha256>" over "<t>.<raw body>".
func VerifyWebhookSignature(secret, header string, body []byte) bool {
	return verifyWebhookSignatureAt(secret, header, body, 300, time.Now().Unix())
}

func verifyWebhookSignatureAt(secret, header string, body []byte, tolerance int64, now int64) bool {
	if header == "" {
		return false
	}
	var timestamp int64 = -1
	var signature string
	for _, part := range strings.Split(header, ",") {
		key, value, found := strings.Cut(part, "=")
		if !found {
			continue
		}
		switch key {
		case "t":
			parsed, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return false
			}
			timestamp = parsed
		case "v1":
			signature = value
		}
	}
	if timestamp < 0 || signature == "" {
		return false
	}
	if int64(math.Abs(float64(now-timestamp))) > tolerance {
		return false
	}

	mac := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(mac, "%d.", timestamp)
	mac.Write(body)
	expected := hex.EncodeToString(mac.Sum(nil))
	return subtle.ConstantTimeCompare([]byte(expected), []byte(signature)) == 1
}
