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
	version            = "0.2.0"
	defaultTimeout     = 30 * time.Second
	defaultMaxAttempts = 3
	maxBackoff         = 20 * time.Second
	// SignatureHeader carries the webhook HMAC signature.
	SignatureHeader = "sendbyte-signature"
)

// Error is an error returned by the SendByte API, carrying the documented
// error shape.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	DocsURL string `json:"docs_url"`
	Status  int    `json:"-"`
}

func (e *Error) Error() string {
	return fmt.Sprintf("sendbyte: %s (%s)", e.Message, e.Code)
}

// Client is the SendByte API client.
type Client struct {
	apiKey      string
	baseURL     string
	httpClient  *http.Client
	maxAttempts int

	Emails   *EmailsService
	Domains  *DomainsService
	Webhooks *WebhooksService
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

// New creates a client. The key must start with sk_live_ or sk_test_.
//
// Requests retry on 429 and 5xx (and transport errors) with exponential
// backoff plus jitter, honoring Retry-After, up to the configured attempts.
// On POST /v1/emails an idempotency key is generated and reused across retries
// when the caller did not supply one, so a retried send cannot double-send.
func New(apiKey string, opts ...Option) (*Client, error) {
	if !strings.HasPrefix(apiKey, "sk_live_") && !strings.HasPrefix(apiKey, "sk_test_") {
		return nil, &Error{
			Code:    "invalid_api_key",
			Message: "API key must start with sk_live_ or sk_test_. Create one in the dashboard under API keys.",
		}
	}
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
	// A live key over a non-https base URL would send the secret in cleartext.
	if strings.HasPrefix(apiKey, "sk_live_") && !isSecureBaseURL(c.baseURL) {
		return nil, &Error{
			Code:    "insecure_base_url",
			Message: "Refusing to send a live API key (sk_live_) over an insecure base URL. Use https, or a test key for local http.",
		}
	}
	// An injected client with no timeout would let a hung connection block
	// forever; default a sane timeout. Work on a shallow COPY so we never mutate
	// the caller's *http.Client, which they may share with other code (#67).
	if c.httpClient == nil {
		c.httpClient = &http.Client{Timeout: defaultTimeout}
	} else if c.httpClient.Timeout == 0 {
		cp := *c.httpClient
		cp.Timeout = defaultTimeout
		c.httpClient = &cp
	}
	c.Emails = &EmailsService{c}
	c.Domains = &DomainsService{c}
	c.Webhooks = &WebhooksService{c}
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
type Attachment struct {
	Filename    string `json:"filename"`
	Content     string `json:"content"`
	ContentType string `json:"content_type"`
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
