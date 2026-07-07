package client

// Branch-coverage tests for the upto client: the challenge recentSlot
// requirement, header-build error propagation, and the malformed-challenge
// parse branches.

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/solana-foundation/pay-kit/go/internal/testutil"
)

func TestBuildUptoPayloadRequiresChallengeRecentSlot(t *testing.T) {
	priv := testutil.NewPrivateKey()
	signer := testSigner{priv}

	missing := uptoRequirements(priv.PublicKey())
	missing.Extra.RecentSlot = ""
	if _, err := BuildUptoPayload(context.Background(), signer, missing, 4102444800, "n-1"); err == nil ||
		!strings.Contains(err.Error(), "missing extra.recentSlot") {
		t.Fatalf("error = %v, want missing recentSlot rejection", err)
	}

	invalid := uptoRequirements(priv.PublicKey())
	invalid.Extra.RecentSlot = "not-a-slot"
	if _, err := BuildUptoPayload(context.Background(), signer, invalid, 4102444800, "n-1"); err == nil ||
		!strings.Contains(err.Error(), "invalid recentSlot") {
		t.Fatalf("error = %v, want invalid recentSlot rejection", err)
	}
}

func TestBuildUptoHeaderPropagatesPayloadError(t *testing.T) {
	priv := testutil.NewPrivateKey()
	signer := testSigner{priv}
	req := uptoRequirements(priv.PublicKey())
	req.Extra.RecentSlot = ""
	if _, err := BuildUptoHeader(context.Background(), signer, req, 4102444800, "n-1"); err == nil ||
		!strings.Contains(err.Error(), "missing extra.recentSlot") {
		t.Fatalf("error = %v, want payload error propagation", err)
	}
}

func TestParseUptoChallengeMalformedInputs(t *testing.T) {
	// Invalid base64 in the header.
	h := http.Header{}
	h.Set("payment-required", "!!not-base64!!")
	if _, ok := ParseUptoChallenge(h, nil); ok {
		t.Fatal("expected not-ok for invalid base64 header")
	}

	// Valid base64, invalid JSON in the header.
	h.Set("payment-required", "bm90LWpzb24=") // "not-json"
	if _, ok := ParseUptoChallenge(h, nil); ok {
		t.Fatal("expected not-ok for invalid JSON header")
	}

	// Invalid JSON body.
	if _, ok := ParseUptoChallenge(http.Header{}, []byte("not-json")); ok {
		t.Fatal("expected not-ok for invalid JSON body")
	}

	// No header and no body.
	if _, ok := ParseUptoChallenge(http.Header{}, nil); ok {
		t.Fatal("expected not-ok for empty inputs")
	}
}
