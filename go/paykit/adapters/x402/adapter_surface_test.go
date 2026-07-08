package x402

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	paykit "github.com/solana-foundation/pay-kit/go/paykit"
	proto "github.com/solana-foundation/pay-kit/go/protocols/x402"
)

// The adapter's protocol surface: Protocol/AcceptsProtocol tag the adapter and
// its accepts entries as x402, and ChallengeHeaders emits the base64 JSON
// payment-required envelope carrying the accepts entry (with the pre-fetched
// recentBlockhash from the configured provider).
func TestAdapterProtocolSurfaceAndChallengeHeaders(t *testing.T) {
	a, err := New(cfgLocal())
	if err != nil {
		t.Fatal(err)
	}
	adapter := a.(*Adapter)
	if adapter.Protocol() != paykit.X402 {
		t.Errorf("Protocol() = %v, want %v", adapter.Protocol(), paykit.X402)
	}

	gate := &paykit.Gate{Amount: paykit.MustParseUSD("0.10"), Desc: "/paid"}
	entry := adapter.AcceptsEntry(gate)
	if entry.AcceptsProtocol() != paykit.X402 {
		t.Errorf("AcceptsProtocol() = %v, want %v", entry.AcceptsProtocol(), paykit.X402)
	}

	headers := adapter.ChallengeHeaders(gate)
	value := headers[proto.PaymentRequiredHeader]
	if value == "" {
		t.Fatalf("ChallengeHeaders missing %s", proto.PaymentRequiredHeader)
	}
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		t.Fatalf("challenge header is not base64: %v", err)
	}
	var envelope struct {
		X402Version int `json:"x402Version"`
		Resource    struct {
			Type string `json:"type"`
			URL  string `json:"url"`
		} `json:"resource"`
		Accepts []proto.AcceptsEntry `json:"accepts"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatalf("challenge envelope is not JSON: %v", err)
	}
	if envelope.X402Version != proto.X402Version {
		t.Errorf("x402Version = %d, want %d", envelope.X402Version, proto.X402Version)
	}
	if envelope.Resource.URL != "/paid" {
		t.Errorf("resource.url = %q, want %q", envelope.Resource.URL, "/paid")
	}
	if len(envelope.Accepts) != 1 {
		t.Fatalf("accepts length = %d, want 1", len(envelope.Accepts))
	}
	if envelope.Accepts[0].Scheme != "exact" {
		t.Errorf("accepts[0].scheme = %q, want %q", envelope.Accepts[0].Scheme, "exact")
	}
	if envelope.Accepts[0].Extra.RecentBlockhash == "" {
		t.Error("accepts[0].extra.recentBlockhash must carry the provider's pre-fetched blockhash")
	}
}

// normalizeNetwork folds every legacy v1 network alias onto its CAIP-2 id and
// passes unknown values (and the empty string) through unchanged.
func TestNormalizeNetworkAliases(t *testing.T) {
	mainnet := "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"
	devnet := "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"
	testnet := "solana:4uhcVJyU9pJkvQyS88uRDiswHXSCkY3z"
	cases := map[string]string{
		"":               "",
		"solana":         mainnet,
		"mainnet":        mainnet,
		"mainnet-beta":   mainnet,
		"solana-devnet":  devnet,
		"devnet":         devnet,
		"localnet":       devnet,
		"solana-testnet": testnet,
		"testnet":        testnet,
		mainnet:          mainnet, // already CAIP-2: passthrough
		"eip155:1":       "eip155:1",
	}
	for in, want := range cases {
		if got := normalizeNetwork(in); got != want {
			t.Errorf("normalizeNetwork(%q) = %q, want %q", in, got, want)
		}
	}
}
