package server

import (
	"context"
	"testing"

	solana "github.com/gagliardetto/solana-go"

	"github.com/solana-foundation/pay-kit/go/internal/testutil"
	core "github.com/solana-foundation/pay-kit/go/protocols/mpp/core"
)

// chargeWire issues a charge for a human amount and returns the decoded
// wire request, keeping methodDetails as a raw key map so absence is
// observable (RULINGS C2/C3).
func chargeWire(t *testing.T, cfg Config, amount string) (string, map[string]any) {
	t.Helper()
	m, err := New(core.NewMemoryStore(), cfg)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	challenge, err := m.Charge(context.Background(), amount)
	if err != nil {
		t.Fatalf("charge: %v", err)
	}
	var req struct {
		Amount        string         `json:"amount"`
		MethodDetails map[string]any `json:"methodDetails"`
	}
	if err := challenge.Request.Decode(&req); err != nil {
		t.Fatalf("decode request: %v", err)
	}
	return req.Amount, req.MethodDetails
}

// A 0-decimal mint used to be unrepresentable: Decimals == 0 was rewritten
// to 6, so "5" became 5_000_000 base units and the challenge advertised 6.
func TestChargeZeroDecimalMintResolvesFromChain(t *testing.T) {
	cfg := validConfig(t)
	cfg.Decimals = 0
	mint := testutil.NewPrivateKey().PublicKey()
	cfg.RPC.(*testutil.FakeRPC).MintOwners[mint.String()] = solana.TokenProgramID
	cfg.RPC.(*testutil.FakeRPC).MintDecimals[mint.String()] = 0
	cfg.Currency = mint.String()

	amount, details := chargeWire(t, cfg, "5")
	if amount != "5" {
		t.Fatalf("amount = %q, want 5 base units", amount)
	}
	if got, ok := details["decimals"]; !ok || got != float64(0) {
		t.Fatalf("methodDetails.decimals = %v (present %v), want 0", got, ok)
	}
}

func TestChargeArbitraryMintDecimalsComeFromChain(t *testing.T) {
	cfg := validConfig(t)
	cfg.Decimals = 0
	mint := testutil.NewPrivateKey().PublicKey()
	cfg.RPC.(*testutil.FakeRPC).MintOwners[mint.String()] = solana.TokenProgramID
	cfg.RPC.(*testutil.FakeRPC).MintDecimals[mint.String()] = 9
	cfg.Currency = mint.String()

	amount, details := chargeWire(t, cfg, "1")
	if amount != "1000000000" || details["decimals"] != float64(9) {
		t.Fatalf("amount = %q decimals = %v, want 1000000000 and 9", amount, details["decimals"])
	}
}

func TestNewRejectsDecimalsThatContradictTheMint(t *testing.T) {
	cfg := validConfig(t)
	cfg.Decimals = 6
	mint := testutil.NewPrivateKey().PublicKey()
	cfg.RPC.(*testutil.FakeRPC).MintOwners[mint.String()] = solana.TokenProgramID
	cfg.RPC.(*testutil.FakeRPC).MintDecimals[mint.String()] = 9
	cfg.Currency = mint.String()
	if _, err := New(core.NewMemoryStore(), cfg); err == nil {
		t.Fatal("expected configured decimals 6 to be rejected for a 9-decimal mint")
	}
}

// SOL is priced in lamports (9 decimals) and its challenge carries neither
// decimals nor tokenProgram ("MUST be absent when currency is sol").
func TestChargeSOLUsesLamportsAndOmitsMintFields(t *testing.T) {
	cfg := validConfig(t)
	cfg.Currency = "sol"
	cfg.Decimals = 0

	amount, details := chargeWire(t, cfg, "0.001")
	if amount != "1000000" {
		t.Fatalf("amount = %q, want 1000000 lamports", amount)
	}
	for _, key := range []string{"decimals", "tokenProgram"} {
		if _, ok := details[key]; ok {
			t.Fatalf("SOL methodDetails carries %q: %v", key, details)
		}
	}
}

// Positive control: a known stablecoin keeps its 6 decimals and token
// program on the wire.
func TestChargeStablecoinCarriesDecimalsAndTokenProgram(t *testing.T) {
	cfg := validConfig(t)
	cfg.Decimals = 0

	amount, details := chargeWire(t, cfg, "1")
	if amount != "1000000" || details["decimals"] != float64(6) {
		t.Fatalf("amount = %q decimals = %v, want 1000000 and 6", amount, details["decimals"])
	}
	if details["tokenProgram"] == nil {
		t.Fatalf("stablecoin methodDetails omits tokenProgram: %v", details)
	}
}
