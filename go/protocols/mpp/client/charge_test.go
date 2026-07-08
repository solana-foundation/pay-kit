package client

import (
	"context"
	"errors"
	"strings"
	"testing"

	solana "github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"

	"github.com/solana-foundation/pay-kit/go/internal/testutil"
	"github.com/solana-foundation/pay-kit/go/paycore"
	"github.com/solana-foundation/pay-kit/go/paycore/solanatx"
	core "github.com/solana-foundation/pay-kit/go/protocols/mpp/core"
)

func memoTexts(t *testing.T, tx *solana.Transaction) []string {
	t.Helper()
	var texts []string
	memoProgram := solana.MustPublicKeyFromBase58(paycore.MemoProgram)
	for _, ix := range tx.Message.Instructions {
		if tx.Message.AccountKeys[ix.ProgramIDIndex].Equals(memoProgram) {
			texts = append(texts, string(ix.Data))
		}
	}
	return texts
}

func hasMemoText(texts []string, want string) bool {
	for _, text := range texts {
		if text == want {
			return true
		}
	}
	return false
}

func TestBuildChargeTransactionSOLPull(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	signer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey().String()

	payload, err := BuildChargeTransaction(context.Background(), signer, rpcClient, "1000", "sol", recipient, paycore.MethodDetails{}, BuildOptions{})
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}
	if payload.Type != "transaction" || payload.Transaction == "" {
		t.Fatalf("unexpected payload: %#v", payload)
	}
	tx, err := solanatx.DecodeTransactionBase64(payload.Transaction)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if len(tx.Message.Instructions) != 3 {
		t.Fatalf("expected 3 instructions, got %d", len(tx.Message.Instructions))
	}
	if tx.Signatures[0].IsZero() {
		t.Fatal("expected signer signature to be populated")
	}
}

func TestBuildChargeTransactionSOLWithExternalIDMemo(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	signer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey().String()

	payload, err := BuildChargeTransaction(context.Background(), signer, rpcClient, "1000", "sol", recipient, paycore.MethodDetails{}, BuildOptions{ExternalID: "order-123"})
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}
	tx, err := solanatx.DecodeTransactionBase64(payload.Transaction)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if !hasMemoText(memoTexts(t, tx), "order-123") {
		t.Fatalf("expected externalId memo instruction")
	}
}

func TestBuildChargeTransactionRejectsLongExternalIDMemo(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	signer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey().String()

	_, err := BuildChargeTransaction(context.Background(), signer, rpcClient, "1000", "sol", recipient, paycore.MethodDetails{}, BuildOptions{ExternalID: strings.Repeat("x", 567)})
	if err == nil {
		t.Fatal("expected long externalId memo to fail")
	}
}

func TestBuildChargeTransactionSOLPush(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	signer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey().String()

	payload, err := BuildChargeTransaction(context.Background(), signer, rpcClient, "1000", "sol", recipient, paycore.MethodDetails{}, BuildOptions{Broadcast: true})
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}
	if payload.Type != "signature" || payload.Signature == "" {
		t.Fatalf("unexpected payload: %#v", payload)
	}
}

func TestBuildChargeTransactionWithFeePayer(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	signer := testutil.NewPrivateKey()
	feePayer := testutil.NewPrivateKey().PublicKey()
	recipient := testutil.NewPrivateKey().PublicKey().String()
	enabled := true

	payload, err := BuildChargeTransaction(context.Background(), signer, rpcClient, "1000", "sol", recipient, paycore.MethodDetails{
		FeePayer:    &enabled,
		FeePayerKey: feePayer.String(),
	}, BuildOptions{})
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}
	tx, err := solanatx.DecodeTransactionBase64(payload.Transaction)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if tx.Message.AccountKeys[0] != feePayer {
		t.Fatalf("expected fee payer to be first account, got %s", tx.Message.AccountKeys[0])
	}
	if len(tx.Signatures) != 2 {
		t.Fatalf("expected partial signatures for fee payer flow, got %d", len(tx.Signatures))
	}
}

func TestBuildChargeTransactionTokenPull(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	signer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey().String()
	mint := testutil.NewPrivateKey().PublicKey()
	rpcClient.MintOwners[mint.String()] = solana.TokenProgramID
	decimals := uint8(6)

	payload, err := BuildChargeTransaction(context.Background(), signer, rpcClient, "1000", mint.String(), recipient, paycore.MethodDetails{
		Decimals: &decimals,
	}, BuildOptions{})
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}
	tx, err := solanatx.DecodeTransactionBase64(payload.Transaction)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if len(tx.Message.Instructions) != 3 {
		t.Fatalf("expected 3 instructions, got %d", len(tx.Message.Instructions))
	}
}

// TestBuildChargeTransactionTokenCreateRecipientATAFlag table-tests the
// opt-in CreateRecipientATA flag. The default (false) leaves
// primary-recipient ATA creation to the server, as the other SDK clients
// do, while setting the flag prepends an idempotent
// createAssociatedTokenAccount instruction for first-run wallets that
// do not yet hold a token account for the selected mint.
func TestBuildChargeTransactionTokenCreateRecipientATAFlag(t *testing.T) {
	mint := testutil.NewPrivateKey().PublicKey()
	cases := []struct {
		name             string
		createRecipient  bool
		wantInstructions int
	}{
		{name: "default_skips_primary_ata", createRecipient: false, wantInstructions: 3},
		{name: "opt_in_adds_primary_ata", createRecipient: true, wantInstructions: 4},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rpcClient := testutil.NewFakeRPC()
			rpcClient.MintOwners[mint.String()] = solana.TokenProgramID
			signer := testutil.NewPrivateKey()
			recipient := testutil.NewPrivateKey().PublicKey().String()
			decimals := uint8(6)

			payload, err := BuildChargeTransaction(context.Background(), signer, rpcClient, "1000", mint.String(), recipient, paycore.MethodDetails{
				Decimals: &decimals,
			}, BuildOptions{CreateRecipientATA: tc.createRecipient})
			if err != nil {
				t.Fatalf("build failed: %v", err)
			}
			tx, err := solanatx.DecodeTransactionBase64(payload.Transaction)
			if err != nil {
				t.Fatalf("decode failed: %v", err)
			}
			if len(tx.Message.Instructions) != tc.wantInstructions {
				t.Fatalf("instructions = %d, want %d", len(tx.Message.Instructions), tc.wantInstructions)
			}
		})
	}
}

func TestBuildChargeTransactionTokenWithExternalIDMemo(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	signer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey().String()
	mint := testutil.NewPrivateKey().PublicKey()
	rpcClient.MintOwners[mint.String()] = solana.TokenProgramID
	decimals := uint8(6)

	payload, err := BuildChargeTransaction(context.Background(), signer, rpcClient, "1000", mint.String(), recipient, paycore.MethodDetails{
		Decimals: &decimals,
	}, BuildOptions{ExternalID: "order-123"})
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}
	tx, err := solanatx.DecodeTransactionBase64(payload.Transaction)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if !hasMemoText(memoTexts(t, tx), "order-123") {
		t.Fatalf("expected externalId memo instruction")
	}
}

func TestBuildChargeTransactionSOLWithSplits(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	signer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey().String()
	split1 := testutil.NewPrivateKey().PublicKey().String()
	split2 := testutil.NewPrivateKey().PublicKey().String()

	payload, err := BuildChargeTransaction(context.Background(), signer, rpcClient, "1000", "sol", recipient, paycore.MethodDetails{
		Splits: []paycore.Split{
			{Recipient: split1, Amount: "100", Memo: "platform fee"},
			{Recipient: split2, Amount: "200"},
		},
	}, BuildOptions{})
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}
	tx, err := solanatx.DecodeTransactionBase64(payload.Transaction)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	// 2 compute budget + 1 primary + 2 splits + 1 split memo = 6
	if len(tx.Message.Instructions) != 6 {
		t.Fatalf("expected 6 instructions, got %d", len(tx.Message.Instructions))
	}
	if !hasMemoText(memoTexts(t, tx), "platform fee") {
		t.Fatalf("expected split memo instruction")
	}
}

func TestBuildChargeTransactionToken2022(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	signer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey().String()
	mint := testutil.NewPrivateKey().PublicKey()
	rpcClient.MintOwners[mint.String()] = solana.MustPublicKeyFromBase58(paycore.Token2022Program)
	decimals := uint8(6)

	payload, err := BuildChargeTransaction(context.Background(), signer, rpcClient, "1000", mint.String(), recipient, paycore.MethodDetails{
		Decimals: &decimals,
	}, BuildOptions{AllowUnknownToken2022: true})
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}
	if payload.Type != "transaction" || payload.Transaction == "" {
		t.Fatalf("unexpected payload: %#v", payload)
	}
}

func TestBuildChargeTransactionInvalidRecipient(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	signer := testutil.NewPrivateKey()
	if _, err := BuildChargeTransaction(context.Background(), signer, rpcClient, "1000", "sol", "not-a-key", paycore.MethodDetails{}, BuildOptions{}); err == nil {
		t.Fatal("expected error for invalid recipient")
	}
}

func TestBuildChargeTransactionInvalidAmount(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	signer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey().String()
	if _, err := BuildChargeTransaction(context.Background(), signer, rpcClient, "not-a-number", "sol", recipient, paycore.MethodDetails{}, BuildOptions{}); err == nil {
		t.Fatal("expected error for invalid amount")
	}
}

func TestBuildChargeTransactionWithCustomComputeUnits(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	signer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey().String()

	payload, err := BuildChargeTransaction(context.Background(), signer, rpcClient, "1000", "sol", recipient, paycore.MethodDetails{}, BuildOptions{
		ComputeUnitLimit: 400_000,
		ComputeUnitPrice: 100,
	})
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}
	if payload.Type != "transaction" || payload.Transaction == "" {
		t.Fatalf("unexpected payload: %#v", payload)
	}
}

func TestBuildChargeTransactionBroadcastWithFeePayer(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	signer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey().String()
	enabled := true
	feePayer := testutil.NewPrivateKey().PublicKey()

	// Broadcast mode with feePayer should error
	_, err := BuildChargeTransaction(context.Background(), signer, rpcClient, "1000", "sol", recipient, paycore.MethodDetails{
		FeePayer:    &enabled,
		FeePayerKey: feePayer.String(),
	}, BuildOptions{Broadcast: true})
	if err == nil {
		t.Fatal("expected error for broadcast + fee payer")
	}
}

func TestBuildChargeTransactionTokenWithSplits(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	signer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey().String()
	splitRecipient := testutil.NewPrivateKey().PublicKey().String()
	mint := testutil.NewPrivateKey().PublicKey()
	rpcClient.MintOwners[mint.String()] = solana.TokenProgramID
	decimals := uint8(6)

	payload, err := BuildChargeTransaction(context.Background(), signer, rpcClient, "1000", mint.String(), recipient, paycore.MethodDetails{
		Decimals: &decimals,
		Splits:   []paycore.Split{{Recipient: splitRecipient, Amount: "200", Memo: "platform fee"}},
	}, BuildOptions{})
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}
	tx, err := solanatx.DecodeTransactionBase64(payload.Transaction)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	// 2 compute budget + 1 primary transfer + 1 split transfer + 1 split memo
	// = 5. No split ATA-create: the split does not set ataCreationRequired, so
	// after the #20 fix the client no longer auto-creates it in client-paid mode.
	if len(tx.Message.Instructions) != 5 {
		t.Fatalf("expected 5 instructions, got %d", len(tx.Message.Instructions))
	}
	if !hasMemoText(memoTexts(t, tx), "platform fee") {
		t.Fatalf("expected split memo instruction")
	}
}

func TestBuildChargeTransactionTokenWithFeePayer(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	signer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey().String()
	feePayer := testutil.NewPrivateKey().PublicKey()
	mint := testutil.NewPrivateKey().PublicKey()
	rpcClient.MintOwners[mint.String()] = solana.TokenProgramID
	decimals := uint8(6)
	enabled := true

	payload, err := BuildChargeTransaction(context.Background(), signer, rpcClient, "1000", mint.String(), recipient, paycore.MethodDetails{
		Decimals:    &decimals,
		FeePayer:    &enabled,
		FeePayerKey: feePayer.String(),
	}, BuildOptions{})
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}
	tx, err := solanatx.DecodeTransactionBase64(payload.Transaction)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	// Fee payer should be first account key
	if tx.Message.AccountKeys[0] != feePayer {
		t.Fatalf("expected fee payer as first account, got %s", tx.Message.AccountKeys[0])
	}
}

func TestBuildChargeTransactionSOLBroadcast(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	signer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey().String()

	payload, err := BuildChargeTransaction(context.Background(), signer, rpcClient, "1000", "sol", recipient, paycore.MethodDetails{}, BuildOptions{Broadcast: true})
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}
	if payload.Type != "signature" {
		t.Fatalf("expected signature type, got %q", payload.Type)
	}
	if payload.Signature == "" {
		t.Fatal("expected non-empty signature")
	}
}

func TestBuildChargeTransactionInvalidSplitRecipient(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	signer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey().String()
	if _, err := BuildChargeTransaction(context.Background(), signer, rpcClient, "1000", "sol", recipient, paycore.MethodDetails{
		Splits: []paycore.Split{{Recipient: "bad-key", Amount: "100"}},
	}, BuildOptions{}); err == nil {
		t.Fatal("expected error for invalid split recipient")
	}
}

func TestBuildChargeTransactionInvalidSplitAmount(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	signer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey().String()
	if _, err := BuildChargeTransaction(context.Background(), signer, rpcClient, "1000", "sol", recipient, paycore.MethodDetails{
		Splits: []paycore.Split{{Recipient: testutil.NewPrivateKey().PublicKey().String(), Amount: "abc"}},
	}, BuildOptions{}); err == nil {
		t.Fatal("expected error for invalid split amount")
	}
}

func TestBuildCredentialHeaderRoundTrip(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	signer := testutil.NewPrivateKey()
	challengeRequest, _ := core.NewBase64URLJSONValue(map[string]any{
		"amount":        "1000",
		"currency":      "sol",
		"recipient":     testutil.NewPrivateKey().PublicKey().String(),
		"methodDetails": map[string]any{"network": "localnet"},
	})
	challenge := core.NewChallengeWithSecret("secret", "realm", "solana", "charge", challengeRequest)

	header, err := BuildCredentialHeader(context.Background(), signer, rpcClient, challenge)
	if err != nil {
		t.Fatalf("header failed: %v", err)
	}
	credential, err := core.ParseAuthorization(header)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if credential.Challenge.ID != challenge.ID {
		t.Fatalf("unexpected credential: %#v", credential)
	}
}

func TestBuildCredentialHeaderInvalidRequest(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	signer := testutil.NewPrivateKey()
	// Create a challenge with invalid request JSON
	badRequest := core.NewBase64URLJSONRaw("!!!invalid!!!")
	challenge := core.PaymentChallenge{
		ID:      "test-id",
		Realm:   "realm",
		Method:  "solana",
		Intent:  "charge",
		Request: badRequest,
	}
	if _, err := BuildCredentialHeader(context.Background(), signer, rpcClient, challenge); err == nil {
		t.Fatal("expected error for invalid request")
	}
}

func TestBuildChargeTransactionTokenBroadcast(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	signer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey().String()
	mint := testutil.NewPrivateKey().PublicKey()
	rpcClient.MintOwners[mint.String()] = solana.TokenProgramID
	decimals := uint8(6)

	payload, err := BuildChargeTransaction(context.Background(), signer, rpcClient, "1000", mint.String(), recipient, paycore.MethodDetails{
		Decimals: &decimals,
	}, BuildOptions{Broadcast: true})
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}
	if payload.Type != "signature" {
		t.Fatalf("expected signature type, got %q", payload.Type)
	}
}

func TestBuildCredentialHeaderWithOptions(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	signer := testutil.NewPrivateKey()
	challengeRequest, _ := core.NewBase64URLJSONValue(map[string]any{
		"amount":        "1000",
		"currency":      "sol",
		"recipient":     testutil.NewPrivateKey().PublicKey().String(),
		"methodDetails": map[string]any{"network": "localnet"},
	})
	challenge := core.NewChallengeWithSecret("secret", "realm", "solana", "charge", challengeRequest)

	header, err := BuildCredentialHeaderWithOptions(context.Background(), signer, rpcClient, challenge, BuildOptions{
		ComputeUnitLimit: 300_000,
		ComputeUnitPrice: 50,
	})
	if err != nil {
		t.Fatalf("header failed: %v", err)
	}
	if header == "" {
		t.Fatal("expected non-empty header")
	}
}

func TestBuildChargeTransactionTokenRejectsInvalidFeePayerKey(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	signer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey().String()
	mint := testutil.NewPrivateKey().PublicKey()
	rpcClient.MintOwners[mint.String()] = solana.TokenProgramID
	decimals := uint8(6)
	enabled := true

	_, err := BuildChargeTransaction(context.Background(), signer, rpcClient, "1000", mint.String(), recipient, paycore.MethodDetails{
		Decimals:    &decimals,
		FeePayer:    &enabled,
		FeePayerKey: "not-a-pubkey",
	}, BuildOptions{})
	if err == nil {
		t.Fatal("expected invalid fee payer key to fail")
	}
}

func TestBuildChargeTransactionRejectsUnsupportedTokenProgramHint(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	signer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey().String()
	mint := testutil.NewPrivateKey().PublicKey()
	decimals := uint8(6)

	if _, err := BuildChargeTransaction(context.Background(), signer, rpcClient, "1000", mint.String(), recipient, paycore.MethodDetails{
		Decimals:     &decimals,
		TokenProgram: paycore.SystemProgram,
	}, BuildOptions{}); err == nil {
		t.Fatal("expected unsupported token program hint to fail")
	}
}

func TestBuildCredentialHeaderRejectsInvalidMethodDetails(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	signer := testutil.NewPrivateKey()
	challengeRequest, _ := core.NewBase64URLJSONValue(map[string]any{
		"amount":        "1000",
		"currency":      "sol",
		"recipient":     testutil.NewPrivateKey().PublicKey().String(),
		"methodDetails": map[string]any{"decimals": "not-a-number"},
	})
	challenge := core.NewChallengeWithSecret("secret", "realm", "solana", "charge", challengeRequest)

	if _, err := BuildCredentialHeader(context.Background(), signer, rpcClient, challenge); err == nil {
		t.Fatal("expected invalid methodDetails to fail")
	}
}

// --- merged from charge_branch_test.go ---

// rpcWithBlockhashErr wraps FakeRPC and forces GetLatestBlockhash to error.
type rpcWithBlockhashErr struct {
	// FakeRPC supplies the rest of the stub RPC surface unchanged; only the
	// GetLatestBlockhash method below is overridden to fail.
	*testutil.FakeRPC
}

func (r *rpcWithBlockhashErr) GetLatestBlockhash(_ context.Context, _ rpc.CommitmentType) (*rpc.GetLatestBlockhashResult, error) {
	return nil, errors.New("blockhash rpc down")
}

func TestBuildChargeTransactionInvalidMint(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	signer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey().String()
	decimals := uint8(6)
	// Mint param must be a base58 pubkey; pass an invalid one.
	_, err := BuildChargeTransaction(context.Background(), signer, rpcClient, "1000", "not-a-mint", recipient, paycore.MethodDetails{Decimals: &decimals}, BuildOptions{})
	if err == nil {
		t.Fatal("expected invalid mint error")
	}
}

func TestBuildChargeTransactionTokenResolveError(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	signer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey().String()
	mint := testutil.NewPrivateKey().PublicKey()
	// Mint owner not registered, so ResolveTokenProgram returns "mint not found" error.
	decimals := uint8(6)
	_, err := BuildChargeTransaction(context.Background(), signer, rpcClient, "1000", mint.String(), recipient, paycore.MethodDetails{Decimals: &decimals}, BuildOptions{})
	if err == nil {
		t.Fatal("expected token program resolve error")
	}
}

func TestBuildChargeTransactionTokenInvalidSplitRecipient(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	signer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey().String()
	mint := testutil.NewPrivateKey().PublicKey()
	rpcClient.MintOwners[mint.String()] = solana.TokenProgramID
	decimals := uint8(6)
	_, err := BuildChargeTransaction(context.Background(), signer, rpcClient, "1000", mint.String(), recipient, paycore.MethodDetails{
		Decimals: &decimals,
		Splits:   []paycore.Split{{Recipient: "bad-key", Amount: "10"}},
	}, BuildOptions{})
	if err == nil {
		t.Fatal("expected invalid split recipient error")
	}
}

func TestBuildChargeTransactionTokenInvalidSplitAmount(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	signer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey().String()
	splitRecipient := testutil.NewPrivateKey().PublicKey().String()
	mint := testutil.NewPrivateKey().PublicKey()
	rpcClient.MintOwners[mint.String()] = solana.TokenProgramID
	decimals := uint8(6)
	_, err := BuildChargeTransaction(context.Background(), signer, rpcClient, "1000", mint.String(), recipient, paycore.MethodDetails{
		Decimals: &decimals,
		Splits:   []paycore.Split{{Recipient: splitRecipient, Amount: "abc"}},
	}, BuildOptions{})
	if err == nil {
		t.Fatal("expected invalid split amount error")
	}
}

func TestBuildChargeTransactionBlockhashRPCError(t *testing.T) {
	rpcClient := &rpcWithBlockhashErr{FakeRPC: testutil.NewFakeRPC()}
	signer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey().String()
	// No RecentBlockhash supplied means the code tries to fetch one from RPC.
	_, err := BuildChargeTransaction(context.Background(), signer, rpcClient, "1000", "sol", recipient, paycore.MethodDetails{}, BuildOptions{})
	if err == nil {
		t.Fatal("expected blockhash rpc error")
	}
}

func TestBuildChargeTransactionInvalidFeePayerKey(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	signer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey().String()
	enabled := true
	_, err := BuildChargeTransaction(context.Background(), signer, rpcClient, "1000", "sol", recipient, paycore.MethodDetails{
		FeePayer:    &enabled,
		FeePayerKey: "not-a-valid-pubkey",
	}, BuildOptions{})
	if err == nil {
		t.Fatal("expected invalid fee payer pubkey error")
	}
}

func TestBuildChargeTransactionTokenInvalidFeePayerKey(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	signer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey().String()
	mint := testutil.NewPrivateKey().PublicKey()
	rpcClient.MintOwners[mint.String()] = solana.TokenProgramID
	decimals := uint8(6)
	enabled := true
	_, err := BuildChargeTransaction(context.Background(), signer, rpcClient, "1000", mint.String(), recipient, paycore.MethodDetails{
		Decimals:    &decimals,
		FeePayer:    &enabled,
		FeePayerKey: "not-a-valid-pubkey",
	}, BuildOptions{})
	if err == nil {
		t.Fatal("expected invalid token fee payer pubkey error")
	}
}

func TestBuildChargeTransactionSOLWithSplitMemoTooLong(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	signer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey().String()
	split := testutil.NewPrivateKey().PublicKey().String()
	_, err := BuildChargeTransaction(context.Background(), signer, rpcClient, "1000", "sol", recipient, paycore.MethodDetails{
		Splits: []paycore.Split{{Recipient: split, Amount: "100", Memo: strings.Repeat("x", 600)}},
	}, BuildOptions{})
	if err == nil {
		t.Fatal("expected split memo too long error")
	}
}

func TestBuildChargeTransactionTokenWithSplitMemoTooLong(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	signer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey().String()
	split := testutil.NewPrivateKey().PublicKey().String()
	mint := testutil.NewPrivateKey().PublicKey()
	rpcClient.MintOwners[mint.String()] = solana.TokenProgramID
	decimals := uint8(6)
	_, err := BuildChargeTransaction(context.Background(), signer, rpcClient, "1000", mint.String(), recipient, paycore.MethodDetails{
		Decimals: &decimals,
		Splits:   []paycore.Split{{Recipient: split, Amount: "100", Memo: strings.Repeat("x", 600)}},
	}, BuildOptions{})
	if err == nil {
		t.Fatal("expected token split memo too long error")
	}
}

func TestBuildChargeTransactionTokenWithExternalIDMemoTooLong(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	signer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey().String()
	mint := testutil.NewPrivateKey().PublicKey()
	rpcClient.MintOwners[mint.String()] = solana.TokenProgramID
	decimals := uint8(6)
	_, err := BuildChargeTransaction(context.Background(), signer, rpcClient, "1000", mint.String(), recipient, paycore.MethodDetails{
		Decimals: &decimals,
	}, BuildOptions{ExternalID: strings.Repeat("x", 600)})
	if err == nil {
		t.Fatal("expected long externalId memo error in token path")
	}
}

func TestBuildChargeTransactionBroadcastSendError(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	rpcClient.SendErr = errors.New("send rpc down")
	signer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey().String()
	_, err := BuildChargeTransaction(context.Background(), signer, rpcClient, "1000", "sol", recipient, paycore.MethodDetails{}, BuildOptions{Broadcast: true})
	if err == nil {
		t.Fatal("expected send error")
	}
}

// Reference unused imports
var _ = solanatx.SplitAmounts
