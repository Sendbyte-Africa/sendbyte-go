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
	"testing"
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
