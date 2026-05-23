package server

import (
	"strings"
	"testing"

	mpp "github.com/solana-foundation/mpp-sdk/go"
	"github.com/solana-foundation/mpp-sdk/go/protocol"
)

// TestValidateSplitsCount table-tests the cap that prevents a client from
// submitting more than the cross-SDK maximum of 8 splits.
func TestValidateSplitsCount(t *testing.T) {
	cases := []struct {
		name    string
		count   int
		wantErr bool
	}{
		{"empty", 0, false},
		{"single", 1, false},
		{"at_cap", 8, false},
		{"over_cap_by_one", 9, true},
		{"over_cap_by_many", 20, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			splits := make([]protocol.Split, tc.count)
			err := validateSplitsCount(splits)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				sdkErr, ok := err.(*mpp.Error)
				if !ok {
					t.Fatalf("expected *mpp.Error, got %T", err)
				}
				if sdkErr.Code != mpp.ErrCodeTooManySplits {
					t.Fatalf("code = %q, want %q", sdkErr.Code, mpp.ErrCodeTooManySplits)
				}
				if !strings.Contains(sdkErr.Message, "maximum 8") {
					t.Fatalf("message missing cap text: %q", sdkErr.Message)
				}
				countStr := []string{"9", "20"}[map[int]int{9: 0, 20: 1}[tc.count]]
				if !strings.Contains(sdkErr.Message, countStr) {
					t.Fatalf("message missing observed count %q: %q", countStr, sdkErr.Message)
				}
				return
			}
			if err != nil {
				t.Fatalf("expected nil error, got %v", err)
			}
		})
	}
}
