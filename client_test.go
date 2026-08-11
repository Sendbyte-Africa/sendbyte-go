package sendbyte

import (
	"errors"
	"testing"
)

func TestNewSandBoxClient(t *testing.T) {
	testCases := []struct {
		desc        string
		apiKey      string
		wantErr 	bool
		expectedErr error
	}{
		{
			desc:        "Test with a valid sk_test key",
			apiKey:      "sk_test_key",
			wantErr:	false,
			expectedErr: nil,
		},
		{
			desc:        "Test with invalid sk_test key",
			apiKey:      "keyyy",
			wantErr:	true,
			expectedErr: ErrInvalidSandboxKey,
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			_, err := NewSandboxClient(tC.apiKey)
			if tC.wantErr {
				if err == nil {
					t.Fatalf("expected error: %v, got nil", tC.expectedErr)
				}
				var apiErr *Error
				if !errors.As(err, &apiErr) {
					t.Fatalf("expected error of type %T, got %T", apiErr, err)
				}
				if apiErr.Error() != tC.expectedErr.Error() {
					t.Fatalf("expected error to be %s, got: %s", tC.expectedErr, apiErr)
				}
			}
			
			if !tC.wantErr && err != nil {
				t.Fatalf("expected no error, got: %v", err)
			}
		})
	}
}

func TestNewLiveClient(t *testing.T) {
	testCases := []struct {
		desc        string
		apiKey      string
		wantErr   bool
		expectedErr error
	}{
		{
			desc:        "Test with a valid sk_live key",
			apiKey:      "sk_live_key",
			wantErr:    false,
			expectedErr: nil,
		},
		{
			desc:        "Test with invalid sk_live key",
			apiKey:      "keyyy",
			wantErr:    true,
			expectedErr: ErrInvalidLiveKey,
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			_, err := NewLiveClient(tC.apiKey)
			if tC.wantErr {
				if err == nil {
					t.Fatalf("expected error: %v, got nil", tC.expectedErr)
				}
				var apiErr *Error
				if !errors.As(err, &apiErr) {
					t.Fatalf("expected error of type %T, got %T", apiErr, err)
				}
				if apiErr.Error() != tC.expectedErr.Error() {
					t.Fatalf("expected error to be %s, got: %s", tC.expectedErr, apiErr)
				}
			}
			
			if !tC.wantErr && err != nil {
				t.Fatalf("expected no error, got: %v", err)
			}
		})
	}
}
