package server

import (
	"context"
	"testing"

	solana "github.com/gagliardetto/solana-go"

	"github.com/solana-foundation/pay-kit/go/internal/testutil"
	"github.com/solana-foundation/pay-kit/go/paycore"
	"github.com/solana-foundation/pay-kit/go/protocols/mpp/client"
	core "github.com/solana-foundation/pay-kit/go/protocols/mpp/core"
	"github.com/solana-foundation/pay-kit/go/protocols/mpp/intents"
)

func wireCurrency(t *testing.T, cfg Config) string {
	t.Helper()
	m, err := New(core.NewMemoryStore(), cfg)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	challenge, err := m.Charge(context.Background(), "1")
	if err != nil {
		t.Fatalf("charge: %v", err)
	}
	var req intents.ChargeRequest
	if err := challenge.Request.Decode(&req); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return req.Currency
}

// RULINGS C1: currency on the wire is "sol" or a mint address. A configured
// symbol used to be emitted verbatim ("USDC").
func TestChargeResolvesSymbolToMintOnTheWire(t *testing.T) {
	cases := []struct {
		name, currency, network, want string
	}{
		{name: "usdc_devnet", currency: "USDC", network: "devnet", want: paycore.USDCDevnetMint},
		{name: "usdc_mainnet", currency: "usdc", network: "mainnet", want: paycore.USDCMainnetMint},
		{name: "pyusd_mainnet", currency: "PYUSD", network: "mainnet", want: paycore.PYUSDMainnetMint},
		{name: "sol_uppercase", currency: "SOL", network: "devnet", want: "sol"},
		// Positive control: a mint address is already wire-ready.
		{name: "mint_passthrough", currency: paycore.USDCDevnetMint, network: "devnet", want: paycore.USDCDevnetMint},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validConfig(t)
			cfg.Currency, cfg.Network, cfg.Decimals = tc.currency, tc.network, 0
			if got := wireCurrency(t, cfg); got != tc.want {
				t.Fatalf("wire currency = %q, want %q", got, tc.want)
			}
		})
	}
}

// A symbol-configured server issues a mint, so ataCreationRequired splits
// are expressible, and a credential built from the issued challenge
// verifies against that same server.
func TestSymbolConfiguredServerRoundTripsWithATASplit(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	handler, err := New(core.NewMemoryStore(), Config{
		Recipient: testutil.NewPrivateKey().PublicKey().String(),
		Currency:  "USDC",
		Network:   "devnet",
		SecretKey: "test-secret-key-0123456789abcdef",
		RPC:       rpcClient,
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	required := true
	challenge, err := handler.ChargeWithOptions(context.Background(), "1.00", ChargeOptions{
		Splits: []paycore.Split{{Recipient: testutil.NewPrivateKey().PublicKey().String(), Amount: "1000", AtaCreationRequired: &required}},
	})
	if err != nil {
		t.Fatalf("charge with ataCreationRequired split: %v", err)
	}
	authHeader, err := client.BuildCredentialHeader(context.Background(), testutil.NewPrivateKey(), rpcClient, challenge)
	if err != nil {
		t.Fatalf("build credential: %v", err)
	}
	credential, err := core.ParseAuthorization(authHeader)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, err := verifyCredentialEchoed(handler, context.Background(), credential); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

// Session challenges follow the same rule, and their decimals come from the
// asset rather than a silent 6.
func TestSessionResolvesCurrencyAndDecimals(t *testing.T) {
	session := newTestSession(t, func(o *SessionOptions) {
		o.Currency, o.Network, o.Decimals = "USDC", "devnet", 0
	})
	if session.currency != paycore.USDCDevnetMint || session.core.config.Decimals != paycore.StablecoinDecimals {
		t.Fatalf("currency=%q decimals=%d", session.currency, session.core.config.Decimals)
	}

	mint := testutil.NewPrivateKey().PublicKey()
	rpc := testutil.NewFakeRPC()
	rpc.MintOwners[mint.String()] = solana.MustPublicKeyFromBase58(paycore.Token2022Program)
	rpc.MintDecimals[mint.String()] = 9
	session = newTestSession(t, func(o *SessionOptions) {
		o.Currency, o.Decimals, o.RPC = mint.String(), 0, rpc
	})
	if session.core.config.Decimals != 9 || session.core.config.TokenProgram != paycore.Token2022Program {
		t.Fatalf("decimals=%d tokenProgram=%q, want 9 and Token-2022 from the mint", session.core.config.Decimals, session.core.config.TokenProgram)
	}
}

func TestNewSessionRejectsUnresolvableDecimals(t *testing.T) {
	mint := testutil.NewPrivateKey().PublicKey().String()
	base := SessionOptions{
		Recipient: sessionTestRecipient,
		Cap:       5_000_000,
		Currency:  mint,
		Network:   "localnet",
		SecretKey: sessionMethodSecret,
	}
	// Arbitrary mint with no RPC: decimals cannot be known, so no default.
	if _, err := NewSession(base); err == nil {
		t.Fatal("expected an arbitrary mint without RPC to be rejected")
	}
	// Explicit decimals that contradict the asset are rejected.
	usdc := base
	usdc.Currency, usdc.Decimals = "USDC", 9
	if _, err := NewSession(usdc); err == nil {
		t.Fatal("expected decimals 9 to be rejected for USDC")
	}
}
