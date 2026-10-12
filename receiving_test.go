package sendbyte

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
)

type capturedRequest struct {
	Method    string
	Path      string
	Query     url.Values
	RawQuery  string
	Body      map[string]any
	RawBody   string
	UserAgent string
}

func recordingServer(t *testing.T, status int, response string) (*Client, *[]capturedRequest) {
	t.Helper()
	var reqs []capturedRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		if len(raw) > 0 {
			_ = json.Unmarshal(raw, &body)
		}
		reqs = append(reqs, capturedRequest{
			Method:    r.Method,
			Path:      r.URL.EscapedPath(),
			Query:     r.URL.Query(),
			RawQuery:  r.URL.RawQuery,
			Body:      body,
			RawBody:   string(raw),
			UserAgent: r.Header.Get("User-Agent"),
		})
		w.WriteHeader(status)
		if response != "" {
			fmt.Fprint(w, response)
		}
	}))
	t.Cleanup(server.Close)
	client, err := New("sk_test_abc", WithBaseURL(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	return client, &reqs
}

func TestUserAgentCarriesVersion(t *testing.T) {
	client, reqs := recordingServer(t, 200, `{}`)
	if _, err := client.Receiving.Get(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := (*reqs)[0].UserAgent; got != "sendbyte-go/0.3.0" {
		t.Fatalf("unexpected user agent %q", got)
	}
}

func TestReceivingGetParsesSettings(t *testing.T) {
	client, reqs := recordingServer(t, 200, `{"available":true,"enabled":true,"enabled_at":"2026-10-12T09:00:00.000Z","quota_notice":"q","test_host":"k3f9ab.in.sendbyte.africa","content_days":3,"content_days_long":30,"domains":[{"domain_id":"dom_1","domain":"yourapp.ng","enabled":true,"subdomain":"inbound","host":"inbound.yourapp.ng","status":"active","checked_at":null,"mx_record":{"type":"MX","host":"inbound.yourapp.ng","name":"inbound","priority":10,"value":"inbound-smtp.af-south-1.amazonaws.com"},"verified":true}]}`)
	settings, err := client.Receiving.Get(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if r := (*reqs)[0]; r.Method != "GET" || r.Path != "/v1/receiving" {
		t.Fatalf("unexpected request %s %s", r.Method, r.Path)
	}
	if settings.TestHost == nil || *settings.TestHost != "k3f9ab.in.sendbyte.africa" || settings.ContentDaysLong != 30 {
		t.Fatalf("settings not parsed: %+v", settings)
	}
	d := settings.Domains[0]
	if !d.Verified || d.DomainID != "dom_1" || d.Status != "active" || d.MXRecord.Priority != 10 || d.CheckedAt != nil {
		t.Fatalf("domain not parsed: %+v", d)
	}
}

func TestReceivingEnableAlwaysAcknowledgesQuota(t *testing.T) {
	client, reqs := recordingServer(t, 200, `{"enabled":true,"test_host":"k3f9ab.in.sendbyte.africa","quota_notice":"q"}`)
	res, err := client.Receiving.Enable(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	r := (*reqs)[0]
	if r.Method != "POST" || r.Path != "/v1/receiving/enable" {
		t.Fatalf("unexpected request %s %s", r.Method, r.Path)
	}
	if r.RawBody != `{"acknowledge_quota":true}` {
		t.Fatalf("expected acknowledge_quota true, got %s", r.RawBody)
	}
	if !res.Enabled || res.TestHost != "k3f9ab.in.sendbyte.africa" {
		t.Fatalf("unexpected result %+v", res)
	}
}

func TestReceivingDisableAndSendTest(t *testing.T) {
	client, reqs := recordingServer(t, 202, `{"sent":true,"to":"test@k3f9ab.in.sendbyte.africa","enabled":false}`)
	if err := client.Receiving.Disable(context.Background()); err != nil {
		t.Fatal(err)
	}
	res, err := client.Receiving.SendTest(context.Background(), "test@k3f9ab.in.sendbyte.africa")
	if err != nil {
		t.Fatal(err)
	}
	disable, send := (*reqs)[0], (*reqs)[1]
	if disable.Method != "POST" || disable.Path != "/v1/receiving/disable" || disable.RawBody != `{}` {
		t.Fatalf("unexpected disable request %s %s %s", disable.Method, disable.Path, disable.RawBody)
	}
	if send.Method != "POST" || send.Path != "/v1/receiving/test" || send.Body["to"] != "test@k3f9ab.in.sendbyte.africa" {
		t.Fatalf("unexpected test request %s %s %v", send.Method, send.Path, send.Body)
	}
	if !res.Sent {
		t.Fatalf("unexpected result %+v", res)
	}
}

func TestReceivingDomainSetup(t *testing.T) {
	client, reqs := recordingServer(t, 200, `{"domain_id":"dom_1","domain":"yourapp.ng","enabled":true,"subdomain":"inbound","host":"inbound.yourapp.ng","status":"pending","checked_at":"x","mx_record":{"type":"MX","host":"inbound.yourapp.ng","name":"inbound","priority":10,"value":"v"},"root_provider":"Google Workspace","host_provider":null}`)
	ctx := context.Background()
	pre, err := client.Receiving.Preflight(ctx, "dom_1", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Receiving.Preflight(ctx, "dom_1", "replies"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Receiving.EnableDomain(ctx, "dom_1", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Receiving.EnableDomain(ctx, "dom_1", "support"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Receiving.CheckDomain(ctx, "dom_1"); err != nil {
		t.Fatal(err)
	}
	off, err := client.Receiving.DisableDomain(ctx, "dom_1")
	if err != nil {
		t.Fatal(err)
	}
	r := *reqs
	expect := []struct{ method, path, query, body string }{
		{"GET", "/v1/domains/dom_1/receiving/preflight", "subdomain=inbound", ""},
		{"GET", "/v1/domains/dom_1/receiving/preflight", "subdomain=replies", ""},
		{"POST", "/v1/domains/dom_1/receiving", "", `{"subdomain":"inbound"}`},
		{"POST", "/v1/domains/dom_1/receiving", "", `{"subdomain":"support"}`},
		{"POST", "/v1/domains/dom_1/receiving/check", "", `{}`},
		{"DELETE", "/v1/domains/dom_1/receiving", "", ""},
	}
	for i, e := range expect {
		if r[i].Method != e.method || r[i].Path != e.path || r[i].RawQuery != e.query || r[i].RawBody != e.body {
			t.Fatalf("request %d: got %s %s?%s %s, want %s %s?%s %s", i, r[i].Method, r[i].Path, r[i].RawQuery, r[i].RawBody, e.method, e.path, e.query, e.body)
		}
	}
	if pre.RootProvider == nil || *pre.RootProvider != "Google Workspace" || pre.HostProvider != nil || pre.MXRecord.Name != "inbound" {
		t.Fatalf("preflight not parsed: %+v", pre)
	}
	if off.Host != "inbound.yourapp.ng" {
		t.Fatalf("domain receiving not parsed: %+v", off)
	}
}

func TestReceivedListPassesStatusCommaList(t *testing.T) {
	client, reqs := recordingServer(t, 200, `{"data":[{"id":"rcv_1","object":"received_email","status":"held","from":"a@b.ng","to":["x@inbound.yourapp.ng"],"cc":[],"reply_to":[],"recipients":["x@inbound.yourapp.ng"],"subject":"Hi","tag":"order-4421","spam":"pass","virus":null,"references":[],"forwarded_email_ids":[],"counted":true}],"has_more":true,"next_cursor":"2026-10-12T09:00:00.000Z_rcv_1"}`)
	page, err := client.Received.List(context.Background(), ListReceivedParams{
		Status:   []string{"spam", "held"},
		DomainID: "dom_1",
		Search:   "invoice 50%",
		Days:     7,
		Limit:    25,
		Before:   "2026-10-12T10:00:00.000Z_rcv_0",
	})
	if err != nil {
		t.Fatal(err)
	}
	r := (*reqs)[0]
	if r.Method != "GET" || r.Path != "/v1/received" {
		t.Fatalf("unexpected request %s %s", r.Method, r.Path)
	}
	want := map[string]string{
		"status":    "spam,held",
		"domain_id": "dom_1",
		"search":    "invoice 50%",
		"days":      "7",
		"limit":     "25",
		"before":    "2026-10-12T10:00:00.000Z_rcv_0",
	}
	for k, v := range want {
		if got := r.Query[k]; len(got) != 1 || got[0] != v {
			t.Fatalf("query %s: got %v, want %q", k, got, v)
		}
	}
	if !page.HasMore || page.NextCursor == nil || page.Data[0].Tag == nil || *page.Data[0].Tag != "order-4421" || page.Data[0].Virus != nil {
		t.Fatalf("page not parsed: %+v", page)
	}

	client2, reqs2 := recordingServer(t, 200, `{"data":[],"has_more":false,"next_cursor":null}`)
	if _, err := client2.Received.List(context.Background(), ListReceivedParams{Status: []string{"delivered,forwarded"}}); err != nil {
		t.Fatal(err)
	}
	if got := (*reqs2)[0].Query.Get("status"); got != "delivered,forwarded" {
		t.Fatalf("pre-joined status not passed through: %q", got)
	}
	if _, err := client2.Received.List(context.Background(), ListReceivedParams{}); err != nil {
		t.Fatal(err)
	}
	if (*reqs2)[1].RawQuery != "" {
		t.Fatalf("expected no query for empty params, got %q", (*reqs2)[1].RawQuery)
	}
}

func TestReceivedGetParsesDetail(t *testing.T) {
	client, reqs := recordingServer(t, 200, `{"id":"rcv_1","object":"received_email","status":"delivered","from":"a@b.ng","to":[],"recipients":[],"subject":"Re: Receipt","thread_id":"thr_1","text":"Thanks","html":null,"stripped_text":"Thanks","truncated":{"text":false,"html":false},"headers":[{"name":"X-A","value":"1"}],"attachments":[{"id":"0","filename":"r.pdf","content_type":"application/pdf","size":10,"content_id":null,"disposition":"attachment","url":"https://s3/x","url_expires_at":"y"}],"route":{"id":"rt_1","domain_id":"dom_1","match_type":"prefix","match_value":"replies","action":"webhook","endpoint_ids":null,"forward_to":[],"allow_senders":[],"block_senders":[],"enabled":true,"created_at":"x","updated_at":"x"},"in_reply_to_email":{"id":"em_1","subject":"Receipt","to":["a@b.ng"],"status":"delivered","created_at":"x"},"webhook_deliveries":[{"id":"wd_1","endpoint_id":"wh_1","url":"https://h","status":"delivered","attempts":[{"status":200}],"created_at":"x","delivered_at":"y"}],"webhook_payload":{"type":"email.received"},"conversation":[{"direction":"sent","id":"em_1","subject":"Receipt","from":"r@yourapp.ng","to":["a@b.ng"],"status":"delivered","at":"x"},{"direction":"received","id":"rcv_1","subject":"Re: Receipt","from":"a@b.ng","to":["r@yourapp.ng"],"status":"delivered","at":"y"}]}`)
	detail, err := client.Received.Get(context.Background(), "rcv_1")
	if err != nil {
		t.Fatal(err)
	}
	if r := (*reqs)[0]; r.Method != "GET" || r.Path != "/v1/received/rcv_1" {
		t.Fatalf("unexpected request %s %s", r.Method, r.Path)
	}
	if detail.ThreadID == nil || *detail.ThreadID != "thr_1" || detail.Text == nil || detail.HTML != nil {
		t.Fatalf("detail not parsed: %+v", detail)
	}
	if detail.Route == nil || detail.Route.EndpointIDs != nil || detail.Route.MatchType != "prefix" {
		t.Fatalf("route not parsed: %+v", detail.Route)
	}
	if detail.InReplyToEmail == nil || detail.InReplyToEmail.ID != "em_1" {
		t.Fatalf("in_reply_to_email not parsed: %+v", detail.InReplyToEmail)
	}
	if len(detail.Attachments) != 1 || detail.Attachments[0].URL == nil || len(detail.WebhookDeliveries) != 1 || len(detail.WebhookDeliveries[0].Attempts) != 1 {
		t.Fatalf("attachments or deliveries not parsed: %+v", detail)
	}
	if len(detail.Conversation) != 2 || detail.Conversation[0].Direction != "sent" || detail.Headers[0].Name != "X-A" {
		t.Fatalf("conversation or headers not parsed: %+v", detail)
	}
}

func TestReceivedStatsAttachmentRaw(t *testing.T) {
	client, reqs := recordingServer(t, 200, `{"days":30,"received":5,"spam":1,"held":0,"delivered":4,"blocked":0,"dropped":0,"forwarded":0,"counted":4,"url":"https://s3/x","filename":"r.pdf","content_type":"application/pdf","expires_at":"y"}`)
	ctx := context.Background()
	stats, err := client.Received.Stats(ctx, ReceivedStatsParams{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Received.Stats(ctx, ReceivedStatsParams{Days: 7, DomainID: "dom_1"}); err != nil {
		t.Fatal(err)
	}
	att, err := client.Received.Attachment(ctx, "rcv_1", "0")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := client.Received.Raw(ctx, "rcv_1")
	if err != nil {
		t.Fatal(err)
	}
	r := *reqs
	if r[0].Path != "/v1/received/stats" || r[0].RawQuery != "days=30" {
		t.Fatalf("stats default: %s?%s", r[0].Path, r[0].RawQuery)
	}
	if r[1].RawQuery != "days=7&domain_id=dom_1" {
		t.Fatalf("stats params: %s", r[1].RawQuery)
	}
	if r[2].Method != "GET" || r[2].Path != "/v1/received/rcv_1/attachments/0" {
		t.Fatalf("attachment: %s %s", r[2].Method, r[2].Path)
	}
	if r[3].Method != "GET" || r[3].Path != "/v1/received/rcv_1/raw" {
		t.Fatalf("raw: %s %s", r[3].Method, r[3].Path)
	}
	if stats.Counted != 4 || att.Filename != "r.pdf" || raw.URL != "https://s3/x" {
		t.Fatalf("results not parsed: %+v %+v %+v", stats, att, raw)
	}
}

func TestReceivedReplyBody(t *testing.T) {
	client, reqs := recordingServer(t, 202, `{"id":"em_9","status":"queued","thread_id":"thr_1"}`)
	res, err := client.Received.Reply(context.Background(), "rcv_1", ReplyToReceivedRequest{
		Text:           "On it.",
		ReplyAll:       true,
		IdempotencyKey: "reply-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	r := (*reqs)[0]
	if r.Method != "POST" || r.Path != "/v1/received/rcv_1/reply" {
		t.Fatalf("unexpected request %s %s", r.Method, r.Path)
	}
	if r.Body["text"] != "On it." || r.Body["reply_all"] != true || r.Body["idempotency_key"] != "reply-1" {
		t.Fatalf("unexpected body %v", r.Body)
	}
	for _, absent := range []string{"from", "html", "subject"} {
		if _, ok := r.Body[absent]; ok {
			t.Fatalf("%s should be omitted when empty: %v", absent, r.Body)
		}
	}
	if res.ID != "em_9" || res.ThreadID == nil || *res.ThreadID != "thr_1" {
		t.Fatalf("unexpected result %+v", res)
	}
}

func TestReceivedReplyRetryReusesGeneratedKey(t *testing.T) {
	var calls int32
	var keys []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if k, ok := body["idempotency_key"].(string); ok {
			keys = append(keys, k)
		}
		if atomic.AddInt32(&calls, 1) == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprint(w, `{"error":{"code":"unavailable"}}`)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		fmt.Fprint(w, `{"id":"em_9","status":"queued","thread_id":null}`)
	}))
	defer server.Close()

	client, _ := New("sk_test_abc", WithBaseURL(server.URL))
	res, err := client.Received.Reply(context.Background(), "rcv_1", ReplyToReceivedRequest{Text: "On it."})
	if err != nil {
		t.Fatal(err)
	}
	if res.ID != "em_9" || res.ThreadID != nil {
		t.Fatalf("unexpected result %+v", res)
	}
	uuidRe := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	if len(keys) != 2 || keys[0] != keys[1] || !uuidRe.MatchString(keys[0]) {
		t.Fatalf("expected one generated key reused across both attempts, got %v", keys)
	}
}

func TestInboundRoutesCRUD(t *testing.T) {
	client, reqs := recordingServer(t, 201, `{"id":"rt_1","domain_id":"dom_1","match_type":"exact","match_value":"support","action":"forward","endpoint_ids":null,"forward_to":["team@yourapp.ng"],"allow_senders":[],"block_senders":[],"enabled":true,"created_at":"x","updated_at":"x","data":[]}`)
	ctx := context.Background()
	enabled := false
	route, err := client.InboundRoutes.Create(ctx, CreateInboundRouteRequest{
		DomainID:   "dom_1",
		MatchType:  "exact",
		MatchValue: "support",
		Action:     "forward",
		ForwardTo:  []string{"team@yourapp.ng"},
		Enabled:    &enabled,
	})
	if err != nil {
		t.Fatal(err)
	}
	action := "webhook"
	cleared := []string{}
	if _, err := client.InboundRoutes.Update(ctx, "rt_1", UpdateInboundRouteRequest{Action: &action, BlockSenders: &cleared}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.InboundRoutes.List(ctx, "dom_1"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.InboundRoutes.List(ctx, ""); err != nil {
		t.Fatal(err)
	}
	r := *reqs
	if r[0].Method != "POST" || r[0].Path != "/v1/inbound-routes" {
		t.Fatalf("create: %s %s", r[0].Method, r[0].Path)
	}
	if r[0].Body["domain_id"] != "dom_1" || r[0].Body["match_type"] != "exact" || r[0].Body["enabled"] != false {
		t.Fatalf("create body: %v", r[0].Body)
	}
	for _, absent := range []string{"endpoint_ids", "allow_senders", "block_senders"} {
		if _, ok := r[0].Body[absent]; ok {
			t.Fatalf("%s should be omitted when unset: %v", absent, r[0].Body)
		}
	}
	if r[1].Method != "PATCH" || r[1].Path != "/v1/inbound-routes/rt_1" || r[1].RawBody != `{"action":"webhook","block_senders":[]}` {
		t.Fatalf("update: %s %s %s", r[1].Method, r[1].Path, r[1].RawBody)
	}
	if r[2].Method != "GET" || r[2].Path != "/v1/inbound-routes" || r[2].RawQuery != "domain_id=dom_1" {
		t.Fatalf("list: %s %s?%s", r[2].Method, r[2].Path, r[2].RawQuery)
	}
	if r[3].RawQuery != "" {
		t.Fatalf("list without domain should send no query, got %q", r[3].RawQuery)
	}
	if route.DomainID == nil || *route.DomainID != "dom_1" || route.EndpointIDs != nil || route.ForwardTo[0] != "team@yourapp.ng" {
		t.Fatalf("route not parsed: %+v", route)
	}
}

func TestInboundRoutesDeleteHandles204(t *testing.T) {
	client, reqs := recordingServer(t, http.StatusNoContent, "")
	if err := client.InboundRoutes.Delete(context.Background(), "rt_1"); err != nil {
		t.Fatalf("204 delete should succeed, got %v", err)
	}
	if r := (*reqs)[0]; r.Method != "DELETE" || r.Path != "/v1/inbound-routes/rt_1" {
		t.Fatalf("unexpected request %s %s", r.Method, r.Path)
	}
}

func TestEmailsConversation(t *testing.T) {
	client, reqs := recordingServer(t, 200, `{"thread_id":"thr_1","replies":2,"data":[{"direction":"sent","id":"em_1","subject":"Receipt","from":"r@yourapp.ng","to":["a@b.ng"],"status":"delivered","at":"x"}]}`)
	conv, err := client.Emails.Conversation(context.Background(), "em_1")
	if err != nil {
		t.Fatal(err)
	}
	if r := (*reqs)[0]; r.Method != "GET" || r.Path != "/v1/emails/em_1/conversation" {
		t.Fatalf("unexpected request %s %s", r.Method, r.Path)
	}
	if conv.Replies != 2 || conv.ThreadID == nil || len(conv.Data) != 1 || conv.Data[0].Direction != "sent" {
		t.Fatalf("conversation not parsed: %+v", conv)
	}
}

func TestPathSegmentsAreEscaped(t *testing.T) {
	client, reqs := recordingServer(t, 200, `{}`)
	if _, err := client.Received.Get(context.Background(), "a/b?c"); err != nil {
		t.Fatal(err)
	}
	if got := (*reqs)[0].Path; !strings.HasPrefix(got, "/v1/received/a%2Fb%3Fc") {
		t.Fatalf("id not escaped: %s", got)
	}
}

func TestEmailReceivedEventDataParses(t *testing.T) {
	payload := `{"type":"email.received","created_at":"x","data":{"id":"rcv_1","object":"received_email","status":"delivered","from":"a@b.ng","subject":"Hi","text":"t","html":"<p>t</p>","stripped_text":"t","truncated":{"text":false,"html":false,"stripped_text":true},"headers":[],"attachments":[]}}`
	var event struct {
		Type string                 `json:"type"`
		Data EmailReceivedEventData `json:"data"`
	}
	if err := json.Unmarshal([]byte(payload), &event); err != nil {
		t.Fatal(err)
	}
	if event.Type != EventEmailReceived || event.Data.ID != "rcv_1" || !event.Data.Truncated.StrippedText || event.Data.HTML == nil {
		t.Fatalf("event not parsed: %+v", event)
	}
}
