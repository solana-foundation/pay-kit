package server

import (
	"context"
	"strings"
	"testing"

	solana "github.com/gagliardetto/solana-go"

	"github.com/solana-foundation/pay-kit/go/internal/testutil"
	"github.com/solana-foundation/pay-kit/go/paycore"
	core "github.com/solana-foundation/pay-kit/go/protocols/mpp/core"
	"github.com/solana-foundation/pay-kit/go/protocols/mpp/intents"
)

func mustDecodeRequest(t *testing.T, challenge core.PaymentChallenge) intents.ChargeRequest {
	t.Helper()
	var req intents.ChargeRequest
	if err := challenge.Request.Decode(&req); err != nil {
		t.Fatalf("decode request: %v", err)
	}
	return req
}

func decodeChallengeDetails(t *testing.T, challenge core.PaymentChallenge, out *paycore.MethodDetails) error {
	t.Helper()
	var req intents.ChargeRequest
	if err := challenge.Request.Decode(&req); err != nil {
		return err
	}
	details, err := decodeMethodDetails(req.MethodDetails)
	if err != nil {
		return err
	}
	*out = details
	return nil
}

// validConfig returns a minimal Config that passes New() so individual tests
// can mutate a single field to exercise a specific guard.
func validConfig(t *testing.T) Config {
	t.Helper()
	return Config{
		Recipient: testutil.NewPrivateKey().PublicKey().String(),
		Currency:  "USDC",
		Decimals:  6,
		Network:   "localnet",
		SecretKey: "test-secret-key-0123456789abcdef",
		RPC:       testutil.NewFakeRPC(),
		Store:     core.NewMemoryStore(),
	}
}

// --- #24 weak secret key ---

func TestNewRejectsShortSecretKey(t *testing.T) {
	cfg := validConfig(t)
	cfg.SecretKey = strings.Repeat("a", minSecretKeyBytes-1)
	if _, err := New(cfg); err == nil {
		t.Fatal("expected rejection of short secret key")
	}
}

func TestNewAcceptsSecretKeyAtMinimumLength(t *testing.T) {
	cfg := validConfig(t)
	cfg.SecretKey = strings.Repeat("a", minSecretKeyBytes)
	if _, err := New(cfg); err != nil {
		t.Fatalf("expected at-minimum secret key to be accepted: %v", err)
	}
}

// --- #37 network allowlist ---

func TestNewAcceptsCanonicalNetworks(t *testing.T) {
	for _, network := range []string{"mainnet", "devnet", "localnet"} {
		cfg := validConfig(t)
		cfg.Network = network
		// USDC resolves from the static table, no RPC fetch needed at boot.
		if _, err := New(cfg); err != nil {
			t.Fatalf("expected network %q to be accepted: %v", network, err)
		}
	}
}

func TestNewRejectsMainnetBetaSlug(t *testing.T) {
	cfg := validConfig(t)
	cfg.Network = "mainnet-beta"
	if _, err := New(cfg); err == nil {
		t.Fatal("expected legacy mainnet-beta slug to be rejected")
	}
}

func TestNewRejectsUnknownNetwork(t *testing.T) {
	cfg := validConfig(t)
	cfg.Network = "testnet"
	if _, err := New(cfg); err == nil {
		t.Fatal("expected unknown network to be rejected")
	}
}

// --- #16 feePayer override without signer ---

func TestChargeOptionsRejectsFeePayerWithoutSigner(t *testing.T) {
	cfg := validConfig(t)
	m, err := New(cfg)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if _, err := m.ChargeWithOptions(context.Background(), "1.00", ChargeOptions{FeePayer: true}); err == nil {
		t.Fatal("expected per-call feePayer override without signer to be rejected")
	}
}

func TestChargeOptionsFeePayerSucceedsWhenSignerConfigured(t *testing.T) {
	cfg := validConfig(t)
	cfg.Currency = "sol"
	cfg.Decimals = 9
	cfg.FeePayerSigner = testutil.NewPrivateKey()
	m, err := New(cfg)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	challenge, err := m.ChargeWithOptions(context.Background(), "0.001", ChargeOptions{FeePayer: true})
	if err != nil {
		t.Fatalf("expected feePayer charge to succeed: %v", err)
	}
	var details paycore.MethodDetails
	if err := decodeChallengeDetails(t, challenge, &details); err != nil {
		t.Fatalf("decode details: %v", err)
	}
	if details.FeePayerKey == "" {
		t.Fatal("expected feePayerKey to be populated")
	}
}

// --- #38 primary recipient in splits + ataCreationRequired ---

func TestChargeRejectsPrimaryRecipientSplitWithATACreation(t *testing.T) {
	cfg := validConfig(t)
	// Use a raw mint-address currency so the ataCreationRequired SPL gate is
	// otherwise satisfiable; the primary-in-splits check must fire first.
	mint := testutil.NewPrivateKey().PublicKey()
	cfg.RPC.(*testutil.FakeRPC).MintOwners[mint.String()] = solana.TokenProgramID
	cfg.Currency = mint.String()
	m, err := New(cfg)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	_, err = m.ChargeWithOptions(context.Background(), "1.00", ChargeOptions{
		Splits: []paycore.Split{
			{Recipient: cfg.Recipient, Amount: "1", AtaCreationRequired: boolp(true)},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "primary recipient") {
		t.Fatalf("expected primary-recipient ATA-recreate rejection, got %v", err)
	}
}

func TestChargeAllowsPrimaryRecipientSplitWithoutATACreation(t *testing.T) {
	cfg := validConfig(t)
	cfg.Currency = "sol"
	cfg.Decimals = 9
	m, err := New(cfg)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	// The primary recipient may appear in splits as long as it does not opt
	// into ataCreationRequired (legitimate merchant-takes-a-cut use case).
	if _, err := m.ChargeWithOptions(context.Background(), "0.002", ChargeOptions{
		Splits: []paycore.Split{{Recipient: cfg.Recipient, Amount: "1"}},
	}); err != nil {
		t.Fatalf("expected primary-in-splits without ATA-create to be allowed: %v", err)
	}
}

// --- #21 split validation at issuance ---

func TestValidateSplits(t *testing.T) {
	good := testutil.NewPrivateKey().PublicKey().String()
	other := testutil.NewPrivateKey().PublicKey().String()

	if err := validateSplits([]paycore.Split{{Recipient: good, Amount: "1"}, {Recipient: other, Amount: "2"}}); err != nil {
		t.Fatalf("valid set rejected: %v", err)
	}
	if err := validateSplits(nil); err != nil {
		t.Fatalf("empty set rejected: %v", err)
	}
	if err := validateSplits([]paycore.Split{{Recipient: "not-a-pubkey", Amount: "1"}}); err == nil {
		t.Fatal("expected invalid recipient rejection")
	}
	if err := validateSplits([]paycore.Split{{Recipient: good, Amount: "nope"}}); err == nil {
		t.Fatal("expected unparseable amount rejection")
	}
	if err := validateSplits([]paycore.Split{{Recipient: good, Amount: "0"}}); err == nil {
		t.Fatal("expected zero amount rejection")
	}
	if err := validateSplits([]paycore.Split{
		{Recipient: good, Amount: "18446744073709551615"},
		{Recipient: other, Amount: "1"},
	}); err == nil {
		t.Fatal("expected overflow rejection")
	}
	if err := validateSplits([]paycore.Split{{Recipient: good, Amount: "1"}, {Recipient: good, Amount: "2"}}); err == nil {
		t.Fatal("expected duplicate recipient rejection")
	}
	overMax := make([]paycore.Split, maxSplits+1)
	for i := range overMax {
		overMax[i] = paycore.Split{Recipient: testutil.NewPrivateKey().PublicKey().String(), Amount: "1"}
	}
	if err := validateSplits(overMax); err == nil {
		t.Fatal("expected count-over-max rejection")
	}
}

// --- #28 token program resolution at boot ---

func TestNewResolvesTokenProgramForKnownStablecoin(t *testing.T) {
	cfg := validConfig(t)
	cfg.Currency = "PYUSD"
	m, err := New(cfg)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if m.tokenProgram != paycore.Token2022Program {
		t.Fatalf("expected PYUSD to resolve to Token-2022, got %q", m.tokenProgram)
	}
}

func TestNewResolvesArbitraryMintFromChain(t *testing.T) {
	cfg := validConfig(t)
	mint := testutil.NewPrivateKey().PublicKey()
	cfg.RPC.(*testutil.FakeRPC).MintOwners[mint.String()] = solana.MustPublicKeyFromBase58(paycore.Token2022Program)
	cfg.Currency = mint.String()
	m, err := New(cfg)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if m.tokenProgram != paycore.Token2022Program {
		t.Fatalf("expected on-chain Token-2022 owner, got %q", m.tokenProgram)
	}
}

func TestNewRejectsArbitraryMintWithUnknownOwner(t *testing.T) {
	cfg := validConfig(t)
	mint := testutil.NewPrivateKey().PublicKey()
	// Owner is some random program, not Token / Token-2022.
	cfg.RPC.(*testutil.FakeRPC).MintOwners[mint.String()] = testutil.NewPrivateKey().PublicKey()
	cfg.Currency = mint.String()
	if _, err := New(cfg); err == nil {
		t.Fatal("expected mint with non-token owner to be rejected at boot")
	}
}

func TestChargeEmitsTokenProgramForArbitraryMint(t *testing.T) {
	cfg := validConfig(t)
	mint := testutil.NewPrivateKey().PublicKey()
	cfg.RPC.(*testutil.FakeRPC).MintOwners[mint.String()] = solana.MustPublicKeyFromBase58(paycore.Token2022Program)
	cfg.Currency = mint.String()
	m, err := New(cfg)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	challenge, err := m.Charge(context.Background(), "1.000000")
	if err != nil {
		t.Fatalf("charge: %v", err)
	}
	var details paycore.MethodDetails
	if err := decodeChallengeDetails(t, challenge, &details); err != nil {
		t.Fatalf("decode details: %v", err)
	}
	if details.TokenProgram != paycore.Token2022Program {
		t.Fatalf("expected challenge to carry Token-2022 program for arbitrary mint, got %q", details.TokenProgram)
	}
}

// --- #5 push mode opt-in ---

func TestPushModeRejectedByDefault(t *testing.T) {
	cfg := validConfig(t)
	cfg.Currency = "sol"
	cfg.Decimals = 9
	m, err := New(cfg)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	challenge, err := m.Charge(context.Background(), "0.001")
	if err != nil {
		t.Fatalf("charge: %v", err)
	}
	credential, err := core.NewPaymentCredential(challenge.ToEcho(), map[string]string{
		"type":      "signature",
		"signature": "5jKh25biPsnrmLWXXuqKNH2Q67Q4UmVVx8Gf2wrS6VoCeyfGE9wKikjY7Q1GQQgmpQ3xy7wJX5U1rcz82q4R8Nkv",
	})
	if err != nil {
		t.Fatalf("credential: %v", err)
	}
	var expected = mustDecodeRequest(t, challenge)
	_, err = m.VerifyCredentialWithExpected(context.Background(), credential, expected)
	if err == nil || !strings.Contains(err.Error(), "push mode") {
		t.Fatalf("expected push mode to be rejected by default, got %v", err)
	}
}
