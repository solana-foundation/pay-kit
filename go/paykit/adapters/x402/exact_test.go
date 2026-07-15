package x402

import (
	"testing"

	"github.com/solana-foundation/pay-kit/go/paykit"
	proto "github.com/solana-foundation/pay-kit/go/protocols/x402"
)

// TestExactAdapterProtocolAndChallengeHeaders exercises the exact adapter's
// Protocol, AcceptsProtocol, and ChallengeHeaders in-package. The wider
// end-to-end behavior is covered from protocols/x402, but that lives in a
// different test binary and does not attribute coverage here.
func TestExactAdapterProtocolAndChallengeHeaders(t *testing.T) {
	a, err := New(cfgLocal())
	if err != nil {
		t.Fatal(err)
	}
	if a.Protocol() != paykit.X402 {
		t.Errorf("Protocol: got %v", a.Protocol())
	}

	g := &paykit.Gate{Amount: paykit.MustParseUSD("0.10"), Desc: "/x"}
	entry, err := a.AcceptsEntry(g)
	if err != nil {
		t.Fatalf("AcceptsEntry: %v", err)
	}
	if entry.AcceptsProtocol() != paykit.X402 {
		t.Error("AcceptsProtocol mismatch")
	}

	h, err := a.ChallengeHeaders(g)
	if err != nil {
		t.Fatalf("ChallengeHeaders: %v", err)
	}
	if h["payment-required"] == "" {
		t.Fatal("missing payment-required header")
	}
}

func TestVerifyAcceptedBindingDirect(t *testing.T) {
	a, err := New(cfgLocal())
	if err != nil {
		t.Fatal(err)
	}
	adapter := a.(*Adapter)
	g := &paykit.Gate{Amount: paykit.MustParseUSD("0.10")}
	route, err := adapter.routeAccepts(g)
	if err != nil {
		t.Fatalf("routeAccepts: %v", err)
	}

	if err := adapter.verifyAcceptedBinding(g, &route); err != nil {
		t.Errorf("matching route should bind: %v", err)
	}

	// Each field mismatch is a hard rejection.
	for _, tc := range []struct {
		name string
		mut  func(e *proto.AcceptsEntry)
	}{
		{"network", func(e *proto.AcceptsEntry) { e.Network = "solana:different" }},
		{"amount", func(e *proto.AcceptsEntry) { e.Amount = "999999" }},
		{"recipient", func(e *proto.AcceptsEntry) { e.PayTo = "SomeOtherRecipient" }},
		{"currency", func(e *proto.AcceptsEntry) { e.Asset = "SomeOtherMint" }},
	} {
		bad := route
		tc.mut(&bad)
		if err := adapter.verifyAcceptedBinding(g, &bad); err == nil {
			t.Errorf("%s mismatch must be rejected", tc.name)
		}
	}
}

func TestNormalizeNetwork(t *testing.T) {
	cases := map[string]string{
		"":              "",
		"solana":        "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
		"mainnet":       "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
		"mainnet-beta":  "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
		"devnet":        "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
		"localnet":      "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
		"testnet":       "solana:4uhcVJyU9pJkvQyS88uRDiswHXSCkY3z",
		"solana:custom": "solana:custom",
	}
	for in, want := range cases {
		if got := normalizeNetwork(in); got != want {
			t.Errorf("normalizeNetwork(%q) = %q, want %q", in, got, want)
		}
	}
}
