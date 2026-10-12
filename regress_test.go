package sendbyte

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestModeConstructorsWireEveryService(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, `{"id":"em_1"}`) }))
	defer server.Close()
	c, err := NewSandboxClient("sk_test_x", WithBaseURL(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	if c.Emails == nil || c.Domains == nil || c.Webhooks == nil || c.Brands == nil || c.Receiving == nil || c.Received == nil || c.InboundRoutes == nil {
		t.Fatal("service not wired")
	}
	if _, err := c.Emails.Send(context.Background(), SendEmailRequest{From: "a@b.ng", To: []string{"c@d.ng"}, Text: "x"}); err != nil {
		t.Fatal(err)
	}
}

func TestConstructorErrorsArePointerErrors(t *testing.T) {
	var apiErr *Error
	_, err := New("sk_live_x", WithBaseURL("http://api.example.com"))
	if !errors.As(err, &apiErr) || apiErr.Code != "insecure_base_url" || err != ErrInsecureURL {
		t.Fatalf("got %T %v", err, err)
	}
	_, err = NewLiveClient("bad")
	if !errors.As(err, &apiErr) || !errors.Is(err, ErrInvalidLiveKey) {
		t.Fatalf("got %T %v", err, err)
	}
}
