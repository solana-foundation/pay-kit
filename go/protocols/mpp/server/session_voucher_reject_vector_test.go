package server

// Cross-SDK pinning of the voucher reject-reason wire tags.
//
// The reject reason is a documented stable wire contract: every SDK must
// emit the byte-identical string for each reject tag. This test loads the
// shared vector (harness/vectors/session-voucher/session-voucher-reject.json)
// and asserts the Go verifier's emitted tag matches, tag by tag. The
// settlement-window tag is additionally driven through the verifier so the
// emitted (not just the declared) value is pinned.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// voucherRejectVector is one entry of the shared reject-tag vector.
type voucherRejectVector struct {
	Tag         string `json:"tag"`
	Reason      string `json:"reason"`
	Description string `json:"description"`
}

// loadVoucherRejectVectors reads the shared reject-tag vector relative to the
// Go module (the runner tree lives under go/, the vectors at the repo root).
func loadVoucherRejectVectors(t *testing.T) []voucherRejectVector {
	t.Helper()
	path := filepath.Join("..", "..", "..", "..", "harness", "vectors", "session-voucher", "session-voucher-reject.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read reject vector %s: %v", path, err)
	}
	var vectors []voucherRejectVector
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatalf("parse reject vector: %v", err)
	}
	if len(vectors) == 0 {
		t.Fatal("reject vector is empty")
	}
	return vectors
}

// TestVoucherRejectTagsMatchVector pins every Go reject constant's wire value
// against the shared cross-SDK vector byte-for-byte.
func TestVoucherRejectTagsMatchVector(t *testing.T) {
	// The tag -> emitted Go reason string. This is the canonical mapping the
	// wire contract fixes; the vector supplies the required byte string.
	emitted := map[string]string{
		"below-min-delta":                  string(VoucherRejectBelowMinDelta),
		"channel-close-pending":            string(VoucherRejectChannelClosePending),
		"channel-finalized":                string(VoucherRejectChannelFinalized),
		"cumulative-not-monotonic":         string(VoucherRejectCumulativeNotMonotonic),
		"exceeds-deposit":                  string(VoucherRejectExceedsDeposit),
		"expired":                          string(VoucherRejectExpired),
		"expires-within-settlement-window": string(VoucherRejectExpiresWithinSettlementWindow),
		"invalid-cumulative":               string(VoucherRejectInvalidCumulative),
		"invalid-signature":                string(VoucherRejectInvalidSignature),
	}

	vectors := loadVoucherRejectVectors(t)
	if len(vectors) != len(emitted) {
		t.Fatalf("vector has %d tags, Go maps %d", len(vectors), len(emitted))
	}
	for _, v := range vectors {
		got, ok := emitted[v.Tag]
		if !ok {
			t.Fatalf("vector tag %q has no Go mapping", v.Tag)
		}
		if got != v.Reason {
			t.Errorf("tag %q: Go emits %q, vector pins %q", v.Tag, got, v.Reason)
		}
	}
}

// TestVoucherSettlementWindowTagIsCanonical drives the verifier down the
// settlement-window reject path and asserts the EMITTED reason equals the
// canonical string in the vector, not just the declared constant.
func TestVoucherSettlementWindowTagIsCanonical(t *testing.T) {
	var want string
	for _, v := range loadVoucherRejectVectors(t) {
		if v.Tag == "expires-within-settlement-window" {
			want = v.Reason
			break
		}
	}
	if want == "" {
		t.Fatal("vector missing the expires-within-settlement-window tag")
	}

	signer := newTestVoucherSigner(t)
	now := int64(1_000)
	// expiresAt in the future but inside the window: the settlement-window
	// reject path.
	voucher := signer.SignVoucher(t, testVoucherChannelID, 100, now+899)
	state := voucherTestState(signer.Address())

	result := VerifyVoucherForChannel(VerifyVoucherArgs{
		State:                   state,
		Signed:                  voucher,
		Deposit:                 1_000,
		SettlementWindowSeconds: 900,
		NowSeconds:              &now,
	})
	if result.Status != VoucherVerifyRejected {
		t.Fatalf("status = %s, want rejected", result.Status)
	}
	if string(result.Reason) != want {
		t.Fatalf("emitted reason = %q, want canonical %q", result.Reason, want)
	}
}
