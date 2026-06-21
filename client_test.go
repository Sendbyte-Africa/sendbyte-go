package sendbyte

import "testing"

func TestNewSandBoxClient(t *testing.T) {
	testCases := []struct {
		desc        string
		apiKey      string
		expectedErr error
	}{
		{
			desc:        "Test with a valid sk_test key",
			apiKey:      "sk_test_key",
			expectedErr: nil,
		},
		{
			desc:        "Test with invalid sk_test key",
			apiKey:      "keyyy",
			expectedErr: ErrInvalidSandboxKey,
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			_, err := NewSandboxClient(tC.apiKey)
			if err != tC.expectedErr {
				t.Fatalf("expected %v, got %v", tC.expectedErr, err)
			}
		})
	}
}

func TestNewLiveClient(t *testing.T) {
	testCases := []struct {
		desc        string
		apiKey      string
		expectedErr error
	}{
		{
			desc:        "Test with a valid sk_live key",
			apiKey:      "sk_live_key",
			expectedErr: nil,
		},
		{
			desc:        "Test with invalid sk_live key",
			apiKey:      "keyyy",
			expectedErr: ErrInvalidLiveKey,
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			_, err := NewLiveClient(tC.apiKey)
			if err != tC.expectedErr {
				t.Fatalf("expected %v, got %v", tC.expectedErr, err)
			}
		})
	}
}
