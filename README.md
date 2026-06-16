# sendbyte-go

The official Go SDK for [SendByte](https://sendbyte.africa), the email API for Africa. Standard library only.

## Install

```bash
go get github.com/Sendbyte-Africa/sendbyte-go
```

Requires Go 1.21 or newer.

## Quickstart

```go
package main

import (
	"context"
	"fmt"
	"log"

	sendbyte "github.com/Sendbyte-Africa/sendbyte-go"
)

func main() {
	client, err := sendbyte.New("sk_test_...")
	if err != nil {
		log.Fatal(err)
	}

	email, err := client.Emails.Send(context.Background(), sendbyte.SendEmailRequest{
		From:    "PayLink <receipts@paylink.ng>",
		To:      []string{"amaka@halo.ng"},
		Subject: "Receipt for your payment",
		HTML:    "<p>Thank you. Your payment was received.</p>",
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(email.ID)
}
```

Keys that start with `sk_test_` run in the sandbox: every endpoint behaves the same, but nothing is actually delivered. Switch to an `sk_live_` key to send for real.

## Configuration

```go
client, err := sendbyte.New("sk_live_...",
	sendbyte.WithBaseURL("https://api.sendbyte.africa"),
	sendbyte.WithHTTPClient(myHTTPClient),
)
```

## API

### Emails

```go
client.Emails.Send(ctx, sendbyte.SendEmailRequest{From: ..., To: ..., Subject: ..., HTML: ...})
client.Emails.Get(ctx, "em_123")
client.Emails.List(ctx, sendbyte.ListEmailsParams{Limit: 20, Status: "delivered"})
```

Pass `IdempotencyKey` to make retries safe, `ScheduledAt` for future sends, and `TemplateID` with `Variables` to render a server side template.

### Domains

```go
domain, _ := client.Domains.Create(ctx, "paylink.ng")
// domain.DNSRecords lists the SPF, DKIM, and DMARC records to publish
client.Domains.List(ctx)
client.Domains.Get(ctx, domain.ID)
client.Domains.Verify(ctx, domain.ID)
```

### Webhooks

```go
endpoint, _ := client.Webhooks.Create(ctx, "https://example.com/hooks/sendbyte",
	[]string{"email.delivered", "email.bounced"})
// endpoint.Secret is shown once, store it now
client.Webhooks.List(ctx)
client.Webhooks.Disable(ctx, endpoint.ID)
client.Webhooks.Replay(ctx, "evt_123")
```

An endpoint subscribed to every event reports `endpoint.Events.All == true`; otherwise `endpoint.Events.Events` holds the specific event names.

## Verifying webhook signatures

Every webhook request carries a `sendbyte-signature` header. Verify it against the raw request body before trusting the payload.

```go
func handler(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	if !sendbyte.VerifyWebhookSignature(secret, r.Header.Get(sendbyte.SignatureHeader), body) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	// handle the event
	w.WriteHeader(http.StatusOK)
}
```

The check rejects missing, malformed, tampered, and stale signatures (tolerance is 300 seconds).

## Errors

Failed requests return a `*sendbyte.Error` carrying the API error shape.

```go
email, err := client.Emails.Send(ctx, req)
var apiErr *sendbyte.Error
if errors.As(err, &apiErr) {
	fmt.Println(apiErr.Code, apiErr.Status, apiErr.Message, apiErr.DocsURL)
}
```

## Links

- Documentation: https://docs.sendbyte.africa

## License

MIT
