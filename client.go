package sendbyte

import (
	"context"
	"strings"
)

type (
	//SendByteClient is the client interface that both Sandbox and Live Clients implement to allow
	// the user to select which mode to run the application more cleanly
	SendByteClient interface {
		request(ctx context.Context, method, path string, body, out any) error
	}
)

// NewSandboxClient create a sandbox client. the key must begin with sk_test_.
func NewSandboxClient(apiKey string, opts ...Option) (*Client, error) {
	if !strings.HasPrefix(apiKey, "sk_test_") {
		return nil, ErrInvalidSandboxKey
	}

	return newClient(apiKey, opts...)
}

// NewLiveClient creates a live client. the key must begin with sk_live_.
func NewLiveClient(apiKey string, opts ...Option) (*Client, error) {
	if !strings.HasPrefix(apiKey, "sk_live_") {
		return nil, ErrInvalidLiveKey
	}
	return newClient(apiKey, opts...)
}

// NewEmailService creates a standalone email service.
func NewEmailService(client *Client) *EmailsService {
	return &EmailsService{client}
}

// NewDomainService creates a standalone domain service.
func NewDomainService(client *Client) *DomainsService {
	return &DomainsService{client}
}

// NewWebhookService creates a standalone webhook service.
func NewWebhookService(client *Client) *WebhooksService {
	return &WebhooksService{client}
}
