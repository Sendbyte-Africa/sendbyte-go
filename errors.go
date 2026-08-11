package sendbyte

import (
	"fmt"
)

type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	DocsURL string `json:"docs_url"`
	Status  int    `json:"-"`
}

func (e *Error) Error() string {
	return fmt.Sprintf("sendbyte: %s (%s)", e.Message, e.Code)
}

var (
	ErrInvalidLiveKey    = &Error{Code: "invalid_api_key", Message: "API key must start with sk_live_ to use the live client, please create one in Dashboard"}
	ErrInvalidSandboxKey = &Error{Code: "invalid_api_key", Message: "API key must start with sk_test_ to use the sandbox client, please create one in Dashboard"}
	ErrInsecureURL       = &Error{Code: "insecure_base_url", Message: "Refusing to send a live API key (sk_live_) over an insecure base URL. Use https, or a test key for local http."}
)
