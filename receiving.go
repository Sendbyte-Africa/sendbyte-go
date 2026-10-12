package sendbyte

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// EventEmailReceived is the webhook event type fired for each received email.
const EventEmailReceived = "email.received"

const defaultReceivingSubdomain = "inbound"

// MXRecord is the MX record to publish so a receiving host gets mail.
type MXRecord struct {
	Type     string `json:"type"`
	Host     string `json:"host"`
	Name     string `json:"name"`
	Priority int    `json:"priority"`
	Value    string `json:"value"`
}

// DomainReceiving is the receiving setup of one domain.
// Status is one of "off", "pending", "active" or "failing".
type DomainReceiving struct {
	DomainID  string   `json:"domain_id"`
	Domain    string   `json:"domain"`
	Enabled   bool     `json:"enabled"`
	Subdomain string   `json:"subdomain"`
	Host      string   `json:"host"`
	Status    string   `json:"status"`
	CheckedAt *string  `json:"checked_at"`
	MXRecord  MXRecord `json:"mx_record"`
}

// ReceivingDomain is a domain in the receiving settings, with its sending verification state.
type ReceivingDomain struct {
	DomainReceiving
	Verified bool `json:"verified"`
}

// ReceivingSettings is the project's receiving state and every domain's setup.
type ReceivingSettings struct {
	Available       bool              `json:"available"`
	Enabled         bool              `json:"enabled"`
	EnabledAt       *string           `json:"enabled_at"`
	QuotaNotice     string            `json:"quota_notice"`
	TestHost        *string           `json:"test_host"`
	ContentDays     int               `json:"content_days"`
	ContentDaysLong int               `json:"content_days_long"`
	Domains         []ReceivingDomain `json:"domains"`
}

// ReceivingEnabled is the result of turning receiving on, including the test host.
type ReceivingEnabled struct {
	Enabled     bool   `json:"enabled"`
	TestHost    string `json:"test_host"`
	QuotaNotice string `json:"quota_notice"`
}

// ReceivingTest confirms a test email was sent to a receiving address.
type ReceivingTest struct {
	Sent bool   `json:"sent"`
	To   string `json:"to"`
}

// ReceivingPreflight reports any mail provider already on a domain or its receiving host.
type ReceivingPreflight struct {
	Host         string   `json:"host"`
	RootProvider *string  `json:"root_provider"`
	HostProvider *string  `json:"host_provider"`
	MXRecord     MXRecord `json:"mx_record"`
}

// ReceivingService talks to /v1/receiving and per-domain receiving setup.
type ReceivingService struct{ c *Client }

// Get returns the project's receiving settings and each domain's setup.
func (s *ReceivingService) Get(ctx context.Context) (*ReceivingSettings, error) {
	var out ReceivingSettings
	if err := s.c.request(ctx, http.MethodGet, "/v1/receiving", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Enable turns receiving on. Received emails count toward your monthly quota,
// the same as sent emails; spam and virus mail never counts.
func (s *ReceivingService) Enable(ctx context.Context) (*ReceivingEnabled, error) {
	var out ReceivingEnabled
	body := map[string]any{"acknowledge_quota": true}
	if err := s.c.request(ctx, http.MethodPost, "/v1/receiving/enable", body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Disable turns receiving off for the project.
func (s *ReceivingService) Disable(ctx context.Context) error {
	return s.c.request(ctx, http.MethodPost, "/v1/receiving/disable", map[string]any{}, nil)
}

// SendTest sends a test email to one of the project's receiving addresses.
func (s *ReceivingService) SendTest(ctx context.Context, to string) (*ReceivingTest, error) {
	var out ReceivingTest
	if err := s.c.request(ctx, http.MethodPost, "/v1/receiving/test", map[string]any{"to": to}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Preflight checks a domain before receiving is set up on it.
// An empty subdomain means "inbound".
func (s *ReceivingService) Preflight(ctx context.Context, domainID, subdomain string) (*ReceivingPreflight, error) {
	q := url.Values{}
	q.Set("subdomain", receivingSubdomain(subdomain))
	path := "/v1/domains/" + url.PathEscape(domainID) + "/receiving/preflight?" + q.Encode()
	var out ReceivingPreflight
	if err := s.c.request(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// EnableDomain sets up receiving on a verified domain and returns the MX record to publish.
// An empty subdomain means "inbound".
func (s *ReceivingService) EnableDomain(ctx context.Context, domainID, subdomain string) (*DomainReceiving, error) {
	var out DomainReceiving
	path := "/v1/domains/" + url.PathEscape(domainID) + "/receiving"
	body := map[string]any{"subdomain": receivingSubdomain(subdomain)}
	if err := s.c.request(ctx, http.MethodPost, path, body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// CheckDomain re-checks a domain's receiving MX record now.
func (s *ReceivingService) CheckDomain(ctx context.Context, domainID string) (*DomainReceiving, error) {
	var out DomainReceiving
	path := "/v1/domains/" + url.PathEscape(domainID) + "/receiving/check"
	if err := s.c.request(ctx, http.MethodPost, path, map[string]any{}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DisableDomain stops receiving on a domain.
func (s *ReceivingService) DisableDomain(ctx context.Context, domainID string) (*DomainReceiving, error) {
	var out DomainReceiving
	path := "/v1/domains/" + url.PathEscape(domainID) + "/receiving"
	if err := s.c.request(ctx, http.MethodDelete, path, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func receivingSubdomain(subdomain string) string {
	if subdomain == "" {
		return defaultReceivingSubdomain
	}
	return subdomain
}

// ReceivedEmail is a received email without its bodies. Status is one of
// received, delivered, forwarded, dropped, held or blocked.
type ReceivedEmail struct {
	ID                string   `json:"id"`
	Object            string   `json:"object"`
	ReceivedAt        string   `json:"received_at"`
	Status            string   `json:"status"`
	StatusReason      *string  `json:"status_reason"`
	From              string   `json:"from"`
	EnvelopeFrom      *string  `json:"envelope_from"`
	To                []string `json:"to"`
	CC                []string `json:"cc"`
	ReplyTo           []string `json:"reply_to"`
	Recipients        []string `json:"recipients"`
	Subject           string   `json:"subject"`
	Tag               *string  `json:"tag"`
	MessageID         *string  `json:"message_id"`
	InReplyTo         *string  `json:"in_reply_to"`
	References        []string `json:"references"`
	ThreadID          *string  `json:"thread_id"`
	InReplyToEmailID  *string  `json:"in_reply_to_email_id"`
	DomainID          *string  `json:"domain_id"`
	RouteID           *string  `json:"route_id"`
	Size              int      `json:"size"`
	Spam              *string  `json:"spam"`
	Virus             *string  `json:"virus"`
	SPF               *string  `json:"spf"`
	DKIM              *string  `json:"dkim"`
	DMARC             *string  `json:"dmarc"`
	Counted           bool     `json:"counted"`
	ContentAvailable  bool     `json:"content_available"`
	ContentExpiresAt  string   `json:"content_expires_at"`
	AttachmentCount   int      `json:"attachment_count"`
	ForwardedEmailIDs []string `json:"forwarded_email_ids"`
	ActionAt          *string  `json:"action_at"`
}

// ReceivedAttachment is one attachment on a received email. URL is nil once the content has expired.
type ReceivedAttachment struct {
	ID           string  `json:"id"`
	Filename     string  `json:"filename"`
	ContentType  string  `json:"content_type"`
	Size         int     `json:"size"`
	ContentID    *string `json:"content_id"`
	Disposition  string  `json:"disposition"`
	URL          *string `json:"url"`
	URLExpiresAt *string `json:"url_expires_at"`
}

// EmailHeader is one raw header of a received email.
type EmailHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// ReceivedTruncated reports which bodies were cut short.
// StrippedText is only reported in the email.received webhook.
type ReceivedTruncated struct {
	Text         bool `json:"text"`
	HTML         bool `json:"html"`
	StrippedText bool `json:"stripped_text"`
}

// ConversationItem is one sent or received email in a thread. Direction is "sent" or "received".
type ConversationItem struct {
	Direction string   `json:"direction"`
	ID        string   `json:"id"`
	Subject   string   `json:"subject"`
	From      string   `json:"from"`
	To        []string `json:"to"`
	Status    string   `json:"status"`
	At        string   `json:"at"`
}

// InReplyToEmail is the sent email a received email answers.
type InReplyToEmail struct {
	ID        string   `json:"id"`
	Subject   string   `json:"subject"`
	To        []string `json:"to"`
	Status    string   `json:"status"`
	CreatedAt string   `json:"created_at"`
}

// ReceivedWebhookDelivery is one email.received webhook delivery for a received email.
type ReceivedWebhookDelivery struct {
	ID          string  `json:"id"`
	EndpointID  string  `json:"endpoint_id"`
	URL         string  `json:"url"`
	Status      string  `json:"status"`
	Attempts    []any   `json:"attempts"`
	CreatedAt   string  `json:"created_at"`
	DeliveredAt *string `json:"delivered_at"`
}

// ReceivedEmailDetail is a received email with its bodies, attachments, route and thread.
type ReceivedEmailDetail struct {
	ReceivedEmail
	Text              *string                   `json:"text"`
	HTML              *string                   `json:"html"`
	StrippedText      *string                   `json:"stripped_text"`
	Truncated         ReceivedTruncated         `json:"truncated"`
	Headers           []EmailHeader             `json:"headers"`
	Attachments       []ReceivedAttachment      `json:"attachments"`
	Route             *InboundRoute             `json:"route"`
	InReplyToEmail    *InReplyToEmail           `json:"in_reply_to_email"`
	WebhookDeliveries []ReceivedWebhookDelivery `json:"webhook_deliveries"`
	WebhookPayload    map[string]any            `json:"webhook_payload"`
	Conversation      []ConversationItem        `json:"conversation"`
}

// EmailReceivedEventData is the data of an email.received webhook.
// Attachment URLs in it stay valid for 24 hours.
type EmailReceivedEventData struct {
	ReceivedEmail
	Text         *string              `json:"text"`
	HTML         *string              `json:"html"`
	StrippedText *string              `json:"stripped_text"`
	Truncated    ReceivedTruncated    `json:"truncated"`
	Headers      []EmailHeader        `json:"headers"`
	Attachments  []ReceivedAttachment `json:"attachments"`
}

// ListReceivedParams filters Received.List. Status values are joined with commas:
// all, spam, received, delivered, forwarded, dropped, held, blocked.
type ListReceivedParams struct {
	Status   []string
	DomainID string
	Search   string
	Days     int
	Limit    int
	Before   string
}

// ReceivedEmailList is a page of received emails. Pass NextCursor as Before for the next page.
type ReceivedEmailList struct {
	Data       []ReceivedEmail `json:"data"`
	HasMore    bool            `json:"has_more"`
	NextCursor *string         `json:"next_cursor"`
}

// ReceivedStatsParams filters Received.Stats. Days defaults to 30.
type ReceivedStatsParams struct {
	Days     int
	DomainID string
}

// ReceivedStats counts received emails over a window, by outcome.
type ReceivedStats struct {
	Days      int `json:"days"`
	Received  int `json:"received"`
	Spam      int `json:"spam"`
	Held      int `json:"held"`
	Delivered int `json:"delivered"`
	Blocked   int `json:"blocked"`
	Dropped   int `json:"dropped"`
	Forwarded int `json:"forwarded"`
	Counted   int `json:"counted"`
}

// AttachmentLink is a short-lived download link for one received attachment.
type AttachmentLink struct {
	URL         string `json:"url"`
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
	ExpiresAt   string `json:"expires_at"`
}

// RawLink is a short-lived download link for the original .eml of a received email.
type RawLink struct {
	URL       string `json:"url"`
	ExpiresAt string `json:"expires_at"`
}

// ReplyToReceivedRequest is the payload for Received.Reply. Set Text, HTML or both.
// From defaults to the receiving address and Subject to "Re: " plus the original.
type ReplyToReceivedRequest struct {
	From           string `json:"from,omitempty"`
	Text           string `json:"text,omitempty"`
	HTML           string `json:"html,omitempty"`
	Subject        string `json:"subject,omitempty"`
	ReplyAll       bool   `json:"reply_all,omitempty"`
	IdempotencyKey string `json:"idempotency_key,omitempty"`
}

// ReplyResult is the queued reply.
type ReplyResult struct {
	ID       string  `json:"id"`
	Status   string  `json:"status"`
	ThreadID *string `json:"thread_id"`
}

// ReceivedService talks to /v1/received.
type ReceivedService struct{ c *Client }

// List pages through received emails, newest first.
func (s *ReceivedService) List(ctx context.Context, params ListReceivedParams) (*ReceivedEmailList, error) {
	q := url.Values{}
	if len(params.Status) > 0 {
		q.Set("status", strings.Join(params.Status, ","))
	}
	if params.DomainID != "" {
		q.Set("domain_id", params.DomainID)
	}
	if params.Search != "" {
		q.Set("search", params.Search)
	}
	if params.Days > 0 {
		q.Set("days", strconv.Itoa(params.Days))
	}
	if params.Limit > 0 {
		q.Set("limit", strconv.Itoa(params.Limit))
	}
	if params.Before != "" {
		q.Set("before", params.Before)
	}
	path := "/v1/received"
	if encoded := q.Encode(); encoded != "" {
		path += "?" + encoded
	}
	var out ReceivedEmailList
	if err := s.c.request(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Get fetches one received email with its bodies, attachments and conversation.
func (s *ReceivedService) Get(ctx context.Context, id string) (*ReceivedEmailDetail, error) {
	var out ReceivedEmailDetail
	if err := s.c.request(ctx, http.MethodGet, "/v1/received/"+url.PathEscape(id), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Stats counts received emails by outcome over the last Days days.
func (s *ReceivedService) Stats(ctx context.Context, params ReceivedStatsParams) (*ReceivedStats, error) {
	days := params.Days
	if days <= 0 {
		days = 30
	}
	q := url.Values{}
	q.Set("days", strconv.Itoa(days))
	if params.DomainID != "" {
		q.Set("domain_id", params.DomainID)
	}
	var out ReceivedStats
	if err := s.c.request(ctx, http.MethodGet, "/v1/received/stats?"+q.Encode(), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Attachment returns a fresh download link for one attachment of a received email.
func (s *ReceivedService) Attachment(ctx context.Context, id, attachmentID string) (*AttachmentLink, error) {
	var out AttachmentLink
	path := "/v1/received/" + url.PathEscape(id) + "/attachments/" + url.PathEscape(attachmentID)
	if err := s.c.request(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Raw returns a download link for the original message as an .eml file.
func (s *ReceivedService) Raw(ctx context.Context, id string) (*RawLink, error) {
	var out RawLink
	if err := s.c.request(ctx, http.MethodGet, "/v1/received/"+url.PathEscape(id)+"/raw", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Reply answers a received email in the same thread, with threading headers set for you.
// An idempotency key is generated when none is given, so a retry cannot send twice.
func (s *ReceivedService) Reply(ctx context.Context, id string, req ReplyToReceivedRequest) (*ReplyResult, error) {
	if req.IdempotencyKey == "" {
		req.IdempotencyKey = newIdempotencyKey()
	}
	var out ReplyResult
	if err := s.c.request(ctx, http.MethodPost, "/v1/received/"+url.PathEscape(id)+"/reply", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// InboundRoute decides what happens to mail for matching addresses.
// A nil EndpointIDs sends the webhook to every endpoint subscribed to email.received.
type InboundRoute struct {
	ID           string   `json:"id"`
	DomainID     *string  `json:"domain_id"`
	MatchType    string   `json:"match_type"`
	MatchValue   string   `json:"match_value"`
	Action       string   `json:"action"`
	EndpointIDs  []string `json:"endpoint_ids"`
	ForwardTo    []string `json:"forward_to"`
	AllowSenders []string `json:"allow_senders"`
	BlockSenders []string `json:"block_senders"`
	Enabled      bool     `json:"enabled"`
	CreatedAt    string   `json:"created_at"`
	UpdatedAt    string   `json:"updated_at"`
}

// CreateInboundRouteRequest is the payload for InboundRoutes.Create. MatchType is exact,
// prefix or catch_all; Action is webhook (default), forward or drop.
type CreateInboundRouteRequest struct {
	DomainID     string   `json:"domain_id,omitempty"`
	MatchType    string   `json:"match_type"`
	MatchValue   string   `json:"match_value,omitempty"`
	Action       string   `json:"action,omitempty"`
	EndpointIDs  []string `json:"endpoint_ids,omitempty"`
	ForwardTo    []string `json:"forward_to,omitempty"`
	AllowSenders []string `json:"allow_senders,omitempty"`
	BlockSenders []string `json:"block_senders,omitempty"`
	Enabled      *bool    `json:"enabled,omitempty"`
}

// UpdateInboundRouteRequest is the payload for InboundRoutes.Update. Nil fields are left
// unchanged; a pointer to an empty slice clears that list.
type UpdateInboundRouteRequest struct {
	Action       *string   `json:"action,omitempty"`
	EndpointIDs  *[]string `json:"endpoint_ids,omitempty"`
	ForwardTo    *[]string `json:"forward_to,omitempty"`
	AllowSenders *[]string `json:"allow_senders,omitempty"`
	BlockSenders *[]string `json:"block_senders,omitempty"`
	Enabled      *bool     `json:"enabled,omitempty"`
}

// InboundRoutesService talks to /v1/inbound-routes.
type InboundRoutesService struct{ c *Client }

// List returns a domain's routes in evaluation order.
// An empty domainID lists the routes of the test address.
func (s *InboundRoutesService) List(ctx context.Context, domainID string) ([]InboundRoute, error) {
	path := "/v1/inbound-routes"
	if domainID != "" {
		path += "?" + url.Values{"domain_id": {domainID}}.Encode()
	}
	var out struct {
		Data []InboundRoute `json:"data"`
	}
	if err := s.c.request(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return out.Data, nil
}

// Create adds a route.
func (s *InboundRoutesService) Create(ctx context.Context, req CreateInboundRouteRequest) (*InboundRoute, error) {
	var out InboundRoute
	if err := s.c.request(ctx, http.MethodPost, "/v1/inbound-routes", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Update changes a route's action, targets, sender lists or enabled state.
func (s *InboundRoutesService) Update(ctx context.Context, id string, req UpdateInboundRouteRequest) (*InboundRoute, error) {
	var out InboundRoute
	if err := s.c.request(ctx, http.MethodPatch, "/v1/inbound-routes/"+url.PathEscape(id), req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Delete removes a route.
func (s *InboundRoutesService) Delete(ctx context.Context, id string) error {
	return s.c.request(ctx, http.MethodDelete, "/v1/inbound-routes/"+url.PathEscape(id), nil, nil)
}

// EmailConversation is the thread a sent email belongs to and how many replies it got.
type EmailConversation struct {
	ThreadID *string            `json:"thread_id"`
	Replies  int                `json:"replies"`
	Data     []ConversationItem `json:"data"`
}

// Conversation returns the sent and received emails in a sent email's thread, oldest first.
func (s *EmailsService) Conversation(ctx context.Context, id string) (*EmailConversation, error) {
	var out EmailConversation
	if err := s.c.request(ctx, http.MethodGet, "/v1/emails/"+url.PathEscape(id)+"/conversation", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
