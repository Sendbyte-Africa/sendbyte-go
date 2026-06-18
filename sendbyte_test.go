package sendbyte

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sync/atomic"
	"testing"
	"time"
)

func TestRejectsMalformedKeys(t *testing.T) {
	if _, err := New("pk_live_nope"); err == nil {
		t.Fatal("expected error for malformed key")
	}
	var apiErr *Error
	_, err := New("")
	if !errors.As(err, &apiErr) || apiErr.Code != "invalid_api_key" {
		t.Fatalf("expected invalid_api_key, got %v", err)
	}
}

func TestSendCarriesAuthAndBody(t *testing.T) {
	var captured *http.Request
	var body map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = r
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"id":"em_1","status":"queued","sandbox":true,"to":["c@d.ng"]}`)
	}))
	defer server.Close()

	client, _ := New("sk_test_abc", WithBaseURL(server.URL))
	email, err := client.Emails.Send(context.Background(), SendEmailRequest{
		From:           "a@b.ng",
		To:             []string{"c@d.ng"},
		Subject:        "Hi",
		HTML:           "<p>x</p>",
		IdempotencyKey: "order-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if email.ID != "em_1" {
		t.Fatalf("expected em_1, got %s", email.ID)
	}
	if captured.URL.Path != "/v1/emails" {
		t.Fatalf("expected /v1/emails, got %s", captured.URL.Path)
	}
	if captured.Header.Get("Authorization") != "Bearer sk_test_abc" {
		t.Fatal("missing bearer auth")
	}
	if body["idempotency_key"] != "order-1" {
		t.Fatal("idempotency key not passed")
	}
	if _, present := body["subject"]; !present {
		t.Fatal("subject missing from body")
	}
}

func TestListBuildsQuery(t *testing.T) {
	var query string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query = r.URL.RawQuery
		fmt.Fprint(w, `{"data":[],"has_more":false}`)
	}))
	defer server.Close()

	client, _ := New("sk_test_abc", WithBaseURL(server.URL))
	if _, err := client.Emails.List(context.Background(), ListEmailsParams{Limit: 5, Status: "delivered"}); err != nil {
		t.Fatal(err)
	}
	if query != "limit=5&status=delivered" {
		t.Fatalf("unexpected query: %s", query)
	}
}

func TestMapsAPIErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"error":{"code":"domain_not_verified","message":"paylink.ng is not verified.","docs_url":"https://docs.sendbyte.africa/errors/domain_not_verified"}}`)
	}))
	defer server.Close()

	client, _ := New("sk_live_abc", WithBaseURL(server.URL))
	_, err := client.Emails.Send(context.Background(), SendEmailRequest{From: "a@paylink.ng", To: []string{"c@d.ng"}, Subject: "x", Text: "x"})

	var apiErr *Error
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *Error, got %T", err)
	}
	if apiErr.Code != "domain_not_verified" || apiErr.Status != 403 {
		t.Fatalf("unexpected error mapping: %+v", apiErr)
	}
}

func TestDomainsAndWebhooksSurfaces(t *testing.T) {
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		fmt.Fprint(w, `{"data":[]}`)
	}))
	defer server.Close()

	client, _ := New("sk_test_abc", WithBaseURL(server.URL))
	_, _ = client.Domains.List(context.Background())
	_, _ = client.Webhooks.List(context.Background())
	if paths[0] != "/v1/domains" || paths[1] != "/v1/webhooks" {
		t.Fatalf("unexpected paths: %v", paths)
	}
}

func TestDomainGetCarriesDkimSelector(t *testing.T) {
	var captured string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = r.Method + " " + r.URL.Path
		fmt.Fprint(w, `{"id":"dom_1","domain":"paylink.ng","status":"verified","dkim_selector":"sb1","dns_records":[],"verified_at":null,"created_at":"x"}`)
	}))
	defer server.Close()

	client, _ := New("sk_test_abc", WithBaseURL(server.URL))
	dom, err := client.Domains.Get(context.Background(), "dom_1")
	if err != nil {
		t.Fatal(err)
	}
	if captured != "GET /v1/domains/dom_1" {
		t.Fatalf("unexpected request: %s", captured)
	}
	if dom.DKIMSelector == nil || *dom.DKIMSelector != "sb1" {
		t.Fatalf("dkim_selector not parsed: %+v", dom)
	}
}

func TestWebhookReplay(t *testing.T) {
	var captured string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = r.Method + " " + r.URL.Path
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"id":"evt_2","replay_of":"evt_1","status":"pending"}`)
	}))
	defer server.Close()

	client, _ := New("sk_test_abc", WithBaseURL(server.URL))
	replay, err := client.Webhooks.Replay(context.Background(), "evt_1")
	if err != nil {
		t.Fatal(err)
	}
	if captured != "POST /v1/webhooks/deliveries/evt_1/replay" {
		t.Fatalf("unexpected request: %s", captured)
	}
	if replay.ReplayOf != "evt_1" || replay.Status != "pending" {
		t.Fatalf("unexpected replay: %+v", replay)
	}
}

func TestWebhookEventsUnion(t *testing.T) {
	allServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"data":[{"id":"wh_1","url":"https://h","events":"all","disabled":false,"created_at":"x"}]}`)
	}))
	defer allServer.Close()
	client, _ := New("sk_test_abc", WithBaseURL(allServer.URL))
	hooks, err := client.Webhooks.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(hooks) != 1 || !hooks[0].Events.All || hooks[0].Events.Events != nil {
		t.Fatalf(`expected All=true for "all", got %+v`, hooks[0].Events)
	}

	arrServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"id":"wh_2","url":"https://h","events":["email.delivered","email.bounced"],"disabled":false,"created_at":"x","secret":"whsec_x"}`)
	}))
	defer arrServer.Close()
	client2, _ := New("sk_test_abc", WithBaseURL(arrServer.URL))
	wh, err := client2.Webhooks.Create(context.Background(), "https://h", []string{"email.delivered", "email.bounced"})
	if err != nil {
		t.Fatal(err)
	}
	if wh.Events.All || len(wh.Events.Events) != 2 || wh.Events.Events[0] != "email.delivered" {
		t.Fatalf("expected 2 explicit events, got %+v", wh.Events)
	}
	if wh.Secret != "whsec_x" {
		t.Fatalf("expected secret to survive, got %q", wh.Secret)
	}
}

func TestAutoIdempotencyKeyWhenAbsent(t *testing.T) {
	var body map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"id":"em_1"}`)
	}))
	defer server.Close()

	client, _ := New("sk_test_abc", WithBaseURL(server.URL))
	if _, err := client.Emails.Send(context.Background(), SendEmailRequest{From: "a@b.ng", To: []string{"c@d.ng"}, Subject: "Hi", Text: "x"}); err != nil {
		t.Fatal(err)
	}
	key, _ := body["idempotency_key"].(string)
	uuidRe := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	if !uuidRe.MatchString(key) {
		t.Fatalf("expected a v4 UUID idempotency key, got %q", key)
	}
}

func TestRetries429AndReusesIdempotencyKey(t *testing.T) {
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
			w.WriteHeader(http.StatusTooManyRequests)
			fmt.Fprint(w, `{"error":{"code":"rate_limited"}}`)
			return
		}
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"id":"em_1"}`)
	}))
	defer server.Close()

	client, _ := New("sk_test_abc", WithBaseURL(server.URL))
	email, err := client.Emails.Send(context.Background(), SendEmailRequest{From: "a@b.ng", To: []string{"c@d.ng"}, Subject: "Hi", Text: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if email.ID != "em_1" {
		t.Fatalf("expected em_1, got %s", email.ID)
	}
	if len(keys) != 2 || keys[0] != keys[1] || keys[0] == "" {
		t.Fatalf("expected the same non-empty key across both attempts, got %v", keys)
	}
}

func TestRetries5xxThenTypedError(t *testing.T) {
	var calls int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprint(w, `{"error":{"code":"unavailable"}}`)
	}))
	defer server.Close()

	client, _ := New("sk_test_abc", WithBaseURL(server.URL), WithMaxAttempts(2))
	_, err := client.Emails.Send(context.Background(), SendEmailRequest{From: "a@b.ng", To: []string{"c@d.ng"}, Subject: "x", Text: "x"})
	var apiErr *Error
	if !errors.As(err, &apiErr) || apiErr.Status != 503 {
		t.Fatalf("expected a 503 *Error, got %v", err)
	}
	if atomic.LoadInt32(&calls) != 2 {
		t.Fatalf("expected 2 attempts, got %d", calls)
	}
}

func TestNonJSONErrorBodyTypedError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		fmt.Fprint(w, "<html><body>502 Bad Gateway</body></html>")
	}))
	defer server.Close()

	client, _ := New("sk_test_abc", WithBaseURL(server.URL), WithMaxAttempts(1))
	_, err := client.Emails.Send(context.Background(), SendEmailRequest{From: "a@b.ng", To: []string{"c@d.ng"}, Subject: "x", Text: "x"})
	var apiErr *Error
	if !errors.As(err, &apiErr) || apiErr.Code != "request_failed" || apiErr.Status != 502 {
		t.Fatalf("expected request_failed/502 *Error, got %v", err)
	}
}

func TestAttachmentsAndListUnsubscribeInBody(t *testing.T) {
	var body map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"id":"em_1"}`)
	}))
	defer server.Close()

	client, _ := New("sk_test_abc", WithBaseURL(server.URL))
	_, err := client.Emails.Send(context.Background(), SendEmailRequest{
		From:            "a@b.ng",
		To:              []string{"c@d.ng"},
		Subject:         "Hi",
		Text:            "x",
		Attachments:     []Attachment{{Filename: "r.pdf", Content: "Zm9v", ContentType: "application/pdf"}},
		ListUnsubscribe: &ListUnsubscribe{URL: "https://x.ng/u", Mailto: "unsub@x.ng"},
	})
	if err != nil {
		t.Fatal(err)
	}
	atts, ok := body["attachments"].([]any)
	if !ok || len(atts) != 1 {
		t.Fatalf("expected one attachment in body, got %v", body["attachments"])
	}
	att := atts[0].(map[string]any)
	if att["filename"] != "r.pdf" || att["content_type"] != "application/pdf" {
		t.Fatalf("attachment fields not serialized as snake_case: %v", att)
	}
	unsub, ok := body["list_unsubscribe"].(map[string]any)
	if !ok || unsub["url"] != "https://x.ng/u" || unsub["mailto"] != "unsub@x.ng" {
		t.Fatalf("list_unsubscribe not serialized: %v", body["list_unsubscribe"])
	}
}

func TestVerifyParsesSESVerified(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"id":"dom_1","domain":"x.ng","status":"pending","ses_verified":false,"checks":[]}`)
	}))
	defer server.Close()

	client, _ := New("sk_test_abc", WithBaseURL(server.URL))
	res, err := client.Domains.Verify(context.Background(), "dom_1")
	if err != nil {
		t.Fatal(err)
	}
	if res.SESVerified == nil || *res.SESVerified != false {
		t.Fatalf("expected ses_verified=false, got %v", res.SESVerified)
	}
}

func TestRefusesLiveKeyOverInsecureBaseURL(t *testing.T) {
	if _, err := New("sk_live_abc", WithBaseURL("http://api.example.com")); err == nil {
		t.Fatal("expected an error for a live key over http")
	}
	// http tolerated for localhost dev; test keys always allowed.
	if _, err := New("sk_live_abc", WithBaseURL("http://localhost:8080")); err != nil {
		t.Fatalf("localhost http should be allowed, got %v", err)
	}
	if _, err := New("sk_test_abc", WithBaseURL("http://api.example.com")); err != nil {
		t.Fatalf("test key over http should be allowed, got %v", err)
	}
}

func TestInjectedClientGetsDefaultTimeout(t *testing.T) {
	injected := &http.Client{} // no Timeout set
	client, err := New("sk_test_abc", WithHTTPClient(injected))
	if err != nil {
		t.Fatal(err)
	}
	if client.httpClient.Timeout != defaultTimeout {
		t.Fatalf("expected a default timeout on the injected client, got %v", client.httpClient.Timeout)
	}
	// An explicit timeout is preserved.
	withTimeout := &http.Client{Timeout: 5 * time.Second}
	client2, _ := New("sk_test_abc", WithHTTPClient(withTimeout))
	if client2.httpClient.Timeout != 5*time.Second {
		t.Fatalf("expected the caller's timeout to survive, got %v", client2.httpClient.Timeout)
	}
}

func sign(secret string, timestamp int64, body string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(mac, "%d.%s", timestamp, body)
	return fmt.Sprintf("t=%d,v1=%s", timestamp, hex.EncodeToString(mac.Sum(nil)))
}

func TestWebhookSignatures(t *testing.T) {
	secret := "whsec_secret"
	var now int64 = 1750000000
	body := `{"type":"email.delivered"}`

	if !verifyWebhookSignatureAt(secret, sign(secret, now, body), []byte(body), 300, now) {
		t.Fatal("valid signature rejected")
	}
	if verifyWebhookSignatureAt(secret, sign(secret, now, body), []byte(`{"type":"x"}`), 300, now) {
		t.Fatal("tampered body accepted")
	}
	if verifyWebhookSignatureAt(secret, sign(secret, now-301, body), []byte(body), 300, now) {
		t.Fatal("stale timestamp accepted")
	}
	if verifyWebhookSignatureAt(secret, "", []byte(body), 300, now) {
		t.Fatal("missing header accepted")
	}
	if verifyWebhookSignatureAt(secret, "garbage", []byte(body), 300, now) {
		t.Fatal("malformed header accepted")
	}
}
