package client

import (
	"context"
	"strings"
	"testing"

	solana "github.com/gagliardetto/solana-go"

	"github.com/solana-foundation/pay-kit/go/internal/testutil"
	"github.com/solana-foundation/pay-kit/go/paycore"
	"github.com/solana-foundation/pay-kit/go/paycore/solanatx"
	core "github.com/solana-foundation/pay-kit/go/protocols/mpp/core"
)

// solChallenge builds a minimal solana/charge challenge for the credential
// header builder tests, with optional expiry.
func solChallenge(t *testing.T, amount, network, expires string) core.PaymentChallenge {
	t.Helper()
	req, err := core.NewBase64URLJSONValue(map[string]any{
		"amount":        amount,
		"currency":      "sol",
		"recipient":     testutil.NewPrivateKey().PublicKey().String(),
		"methodDetails": map[string]any{"network": network},
	})
	if err != nil {
		t.Fatalf("encode request: %v", err)
	}
	return core.NewChallengeWithSecretFull(
		"binding-secret-0123456789abcdef01234567",
		"realm", core.NewMethodName("solana"), core.NewIntentName("charge"),
		req, expires, "", "", nil,
	)
}

// --- #42 decimals required for SPL ---

func TestBuildChargeRejectsMissingDecimalsForSPL(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	signer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey().String()
	mint := testutil.NewPrivateKey().PublicKey()
	rpcClient.MintOwners[mint.String()] = solana.TokenProgramID

	_, err := BuildChargeTransaction(context.Background(), signer, rpcClient, "1000", mint.String(), recipient, paycore.MethodDetails{
		// Decimals omitted on purpose.
	}, BuildOptions{})
	if err == nil || !strings.Contains(err.Error(), "decimals") {
		t.Fatalf("expected missing-decimals rejection, got %v", err)
	}
}

// --- #26 unknown Token-2022 mint gated ---

func TestBuildChargeRefusesUnknownToken2022WithoutOptIn(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	signer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey().String()
	mint := testutil.NewPrivateKey().PublicKey()
	rpcClient.MintOwners[mint.String()] = solana.MustPublicKeyFromBase58(paycore.Token2022Program)
	decimals := uint8(6)

	_, err := BuildChargeTransaction(context.Background(), signer, rpcClient, "1000", mint.String(), recipient, paycore.MethodDetails{
		Decimals: &decimals,
	}, BuildOptions{})
	if err == nil || !strings.Contains(err.Error(), "Token-2022") {
		t.Fatalf("expected unknown Token-2022 rejection, got %v", err)
	}
}

func TestBuildChargeAllowsUnknownVanillaTokenMint(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	signer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey().String()
	mint := testutil.NewPrivateKey().PublicKey()
	rpcClient.MintOwners[mint.String()] = solana.TokenProgramID
	decimals := uint8(6)

	if _, err := BuildChargeTransaction(context.Background(), signer, rpcClient, "1000", mint.String(), recipient, paycore.MethodDetails{
		Decimals: &decimals,
	}, BuildOptions{}); err != nil {
		t.Fatalf("expected unknown vanilla Token mint to be allowed: %v", err)
	}
}

// --- #20 split ATA only created when flagged ---

func TestBuildChargeSplitATAOnlyWhenFlagged(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	signer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey().String()
	split := testutil.NewPrivateKey().PublicKey().String()
	mint := testutil.NewPrivateKey().PublicKey()
	rpcClient.MintOwners[mint.String()] = solana.TokenProgramID
	decimals := uint8(6)
	required := true

	// Flagged split => an ATA-create instruction is included.
	payload, err := BuildChargeTransaction(context.Background(), signer, rpcClient, "1000", mint.String(), recipient, paycore.MethodDetails{
		Decimals: &decimals,
		Splits:   []paycore.Split{{Recipient: split, Amount: "100", AtaCreationRequired: &required}},
	}, BuildOptions{})
	if err != nil {
		t.Fatalf("build flagged: %v", err)
	}
	flaggedCount := ataCreateCount(t, payload.Transaction)

	// Unflagged split => no ATA-create instruction in client-paid mode.
	payload2, err := BuildChargeTransaction(context.Background(), signer, rpcClient, "1000", mint.String(), recipient, paycore.MethodDetails{
		Decimals: &decimals,
		Splits:   []paycore.Split{{Recipient: split, Amount: "100"}},
	}, BuildOptions{})
	if err != nil {
		t.Fatalf("build unflagged: %v", err)
	}
	unflaggedCount := ataCreateCount(t, payload2.Transaction)

	if flaggedCount <= unflaggedCount {
		t.Fatalf("expected flagged split to create more ATAs (%d) than unflagged (%d)", flaggedCount, unflaggedCount)
	}
	if unflaggedCount != 0 {
		t.Fatalf("expected no split ATA creation when unflagged, got %d", unflaggedCount)
	}
}

func ataCreateCount(t *testing.T, encoded string) int {
	t.Helper()
	ataProgram := solana.MustPublicKeyFromBase58(paycore.AssociatedTokenProgram)
	tx, err := solanatx.DecodeTransactionBase64(encoded)
	if err != nil {
		t.Fatalf("decode tx: %v", err)
	}
	count := 0
	for _, ix := range tx.Message.Instructions {
		if tx.Message.AccountKeys[ix.ProgramIDIndex].Equals(ataProgram) {
			count++
		}
	}
	return count
}

// --- #10 max amount / expected network / expiry ---

func TestBuildCredentialHeaderRejectsAmountAboveMax(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	signer := testutil.NewPrivateKey()
	challenge := solChallenge(t, "1000", "localnet", "")
	_, err := BuildCredentialHeaderWithOptions(context.Background(), signer, rpcClient, challenge, BuildOptions{
		MaxAmountBaseUnits: 999,
	})
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "maximum") {
		t.Fatalf("expected amount-above-max rejection, got %v", err)
	}
}

func TestBuildCredentialHeaderAcceptsAmountAtMax(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	signer := testutil.NewPrivateKey()
	challenge := solChallenge(t, "1000", "localnet", "")
	if _, err := BuildCredentialHeaderWithOptions(context.Background(), signer, rpcClient, challenge, BuildOptions{
		MaxAmountBaseUnits: 1000,
	}); err != nil {
		t.Fatalf("expected at-cap amount to be accepted: %v", err)
	}
}

func TestBuildCredentialHeaderRejectsUnexpectedNetwork(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	signer := testutil.NewPrivateKey()
	challenge := solChallenge(t, "1000", "devnet", "")
	_, err := BuildCredentialHeaderWithOptions(context.Background(), signer, rpcClient, challenge, BuildOptions{
		ExpectedNetwork: "localnet",
	})
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "network") {
		t.Fatalf("expected network mismatch rejection, got %v", err)
	}
}

func TestBuildCredentialHeaderRejectsExpiredChallenge(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	signer := testutil.NewPrivateKey()
	challenge := solChallenge(t, "1000", "localnet", "2000-01-01T00:00:00Z")
	_, err := BuildCredentialHeaderWithOptions(context.Background(), signer, rpcClient, challenge, BuildOptions{})
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "expired") {
		t.Fatalf("expected expired-challenge rejection, got %v", err)
	}
}

// --- #17 method/intent gate ---

func TestBuildCredentialHeaderRejectsNonSolanaMethod(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	signer := testutil.NewPrivateKey()
	req, _ := core.NewBase64URLJSONValue(map[string]any{
		"amount": "1000", "currency": "sol",
		"recipient":     testutil.NewPrivateKey().PublicKey().String(),
		"methodDetails": map[string]any{"network": "localnet"},
	})
	challenge := core.NewChallengeWithSecret("binding-secret-0123456789abcdef01234567", "realm",
		core.NewMethodName("stripe"), core.NewIntentName("charge"), req)
	if _, err := BuildCredentialHeaderWithOptions(context.Background(), signer, rpcClient, challenge, BuildOptions{}); err == nil {
		t.Fatal("expected non-solana method to be rejected")
	}
}

func TestBuildCredentialHeaderRejectsNonChargeIntent(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	signer := testutil.NewPrivateKey()
	req, _ := core.NewBase64URLJSONValue(map[string]any{
		"amount": "1000", "currency": "sol",
		"recipient":     testutil.NewPrivateKey().PublicKey().String(),
		"methodDetails": map[string]any{"network": "localnet"},
	})
	challenge := core.NewChallengeWithSecret("binding-secret-0123456789abcdef01234567", "realm",
		core.NewMethodName("solana"), core.NewIntentName("session"), req)
	if _, err := BuildCredentialHeaderWithOptions(context.Background(), signer, rpcClient, challenge, BuildOptions{}); err == nil {
		t.Fatal("expected non-charge intent to be rejected")
	}
}
