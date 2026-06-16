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
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	defaultBaseURL = "https://api.sendbyte.africa"
	version        = "0.1.0"
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
	apiKey     string
	baseURL    string
	httpClient *http.Client

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

// WithHTTPClient injects a custom *http.Client.
func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) { c.httpClient = h }
}

// New creates a client. The key must start with sk_live_ or sk_test_.
func New(apiKey string, opts ...Option) (*Client, error) {
	if !strings.HasPrefix(apiKey, "sk_live_") && !strings.HasPrefix(apiKey, "sk_test_") {
		return nil, &Error{
			Code:    "invalid_api_key",
			Message: "API key must start with sk_live_ or sk_test_. Create one in the dashboard under API keys.",
		}
	}
	c := &Client{
		apiKey:     apiKey,
		baseURL:    defaultBaseURL,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
	for _, opt := range opts {
		opt(c)
	}
	c.Emails = &EmailsService{c}
	c.Domains = &DomainsService{c}
	c.Webhooks = &WebhooksService{c}
	return c, nil
}

func (c *Client) request(ctx context.Context, method, path string, body, out any) error {
	var reader io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("User-Agent", "sendbyte-go/"+version)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	res, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	data, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}

	if res.StatusCode >= 400 {
		var wrapper struct {
			Error Error `json:"error"`
		}
		if jsonErr := json.Unmarshal(data, &wrapper); jsonErr != nil || wrapper.Error.Code == "" {
			return &Error{Code: "request_failed", Message: fmt.Sprintf("request failed with status %d", res.StatusCode), Status: res.StatusCode}
		}
		wrapper.Error.Status = res.StatusCode
		return &wrapper.Error
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

// ---------------------------------------------------------------- Emails

// SendEmailRequest is the payload for Emails.Send.
type SendEmailRequest struct {
	From           string            `json:"from"`
	To             []string          `json:"to"`
	Subject        string            `json:"subject,omitempty"`
	HTML           string            `json:"html,omitempty"`
	Text           string            `json:"text,omitempty"`
	CC             []string          `json:"cc,omitempty"`
	BCC            []string          `json:"bcc,omitempty"`
	ReplyTo        []string          `json:"reply_to,omitempty"`
	Tags           []string          `json:"tags,omitempty"`
	Headers        map[string]string `json:"headers,omitempty"`
	ScheduledAt    string            `json:"scheduled_at,omitempty"`
	TemplateID     string            `json:"template_id,omitempty"`
	Variables      map[string]any    `json:"variables,omitempty"`
	IdempotencyKey string            `json:"idempotency_key,omitempty"`
}

// Email is a summary of an email in the log.
type Email struct {
	ID          string   `json:"id"`
	From        string   `json:"from"`
	To          []string `json:"to"`
	Subject     string   `json:"subject"`
	Status      string   `json:"status"`
	Sandbox     bool     `json:"sandbox"`
	Tags        []string `json:"tags"`
	ScheduledAt *string  `json:"scheduled_at"`
	CreatedAt   string   `json:"created_at"`
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
	Type     string `json:"type"`
	Host     string `json:"host"`
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
	CreatedAt    string      `json:"created_at"`
}

// DomainVerification is the result of a verification check.
type DomainVerification struct {
	ID     string `json:"id"`
	Domain string `json:"domain"`
	Status string `json:"status"`
	Checks []struct {
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
	ID        string        `json:"id"`
	URL       string        `json:"url"`
	Events    WebhookEvents `json:"events"`
	Disabled  bool          `json:"disabled"`
	CreatedAt string        `json:"created_at"`
	Secret    string        `json:"secret,omitempty"`
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
