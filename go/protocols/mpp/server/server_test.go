package server

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	solana "github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/programs/token"
	token2022 "github.com/gagliardetto/solana-go/programs/token-2022"
	"github.com/gagliardetto/solana-go/rpc"

	"github.com/solana-foundation/pay-kit/go/internal/testutil"
	"github.com/solana-foundation/pay-kit/go/paycore"
	"github.com/solana-foundation/pay-kit/go/paycore/solanatx"
	"github.com/solana-foundation/pay-kit/go/protocols/mpp/client"
	core "github.com/solana-foundation/pay-kit/go/protocols/mpp/core"
	"github.com/solana-foundation/pay-kit/go/protocols/mpp/intents"
)

func newTestMpp(t *testing.T) (*Mpp, *testutil.FakeRPC, testutilConfig) {
	t.Helper()
	rpcClient := testutil.NewFakeRPC()
	recipientSigner := testutil.NewPrivateKey()
	cfg := testutilConfig{
		Recipient: recipientSigner.PublicKey().String(),
		Client:    testutil.NewPrivateKey(),
		SecretKey: "test-secret-key-0123456789abcdef",
	}
	handler, err := New(Config{
		Recipient: cfg.Recipient,
		Currency:  "sol",
		Decimals:  9,
		Network:   "localnet",
		SecretKey: cfg.SecretKey,
		RPC:       rpcClient,
		Store:     core.NewMemoryStore(),
		// Push-mode (type="signature") credentials are opt-in (#5); the shared
		// fixture enables them so the signature-flow tests exercise settlement.
		AcceptPushMode: true,
	})
	if err != nil {
		t.Fatalf("new mpp failed: %v", err)
	}
	return handler, rpcClient, cfg
}

type testutilConfig struct {
	Recipient string
	Client    solana.PrivateKey
	SecretKey string
}

func newTestTransaction(t *testing.T, payer solana.PrivateKey, instructions ...solana.Instruction) *solana.Transaction {
	t.Helper()
	tx, err := solana.NewTransaction(
		instructions,
		solana.Hash{},
		solana.TransactionPayer(payer.PublicKey()),
	)
	if err != nil {
		t.Fatalf("new transaction failed: %v", err)
	}
	return tx
}

func TestChargeBuildsChallenge(t *testing.T) {
	handler, _, _ := newTestMpp(t)
	challenge, err := handler.ChargeWithOptions(context.Background(), "0.001", ChargeOptions{
		Description: "demo",
		ExternalID:  "order-1",
	})
	if err != nil {
		t.Fatalf("charge failed: %v", err)
	}
	if challenge.Method != "solana" || challenge.Intent != "charge" || challenge.Realm == "" {
		t.Fatalf("unexpected challenge: %#v", challenge)
	}
}

func TestVerifyCredentialTransactionSuccess(t *testing.T) {
	handler, rpcClient, cfg := newTestMpp(t)
	challenge, err := handler.Charge(context.Background(), "0.001")
	if err != nil {
		t.Fatalf("charge failed: %v", err)
	}
	authHeader, err := client.BuildCredentialHeader(context.Background(), cfg.Client, rpcClient, challenge)
	if err != nil {
		t.Fatalf("build credential failed: %v", err)
	}
	credential, err := core.ParseAuthorization(authHeader)
	if err != nil {
		t.Fatalf("parse authorization failed: %v", err)
	}
	receipt, err := verifyCredentialEchoed(handler, context.Background(), credential)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if receipt.Status != core.ReceiptStatusSuccess || receipt.Reference == "" {
		t.Fatalf("unexpected receipt: %#v", receipt)
	}
}

func TestVerifyCredentialSignatureReplayRejected(t *testing.T) {
	handler, rpcClient, cfg := newTestMpp(t)
	challenge, err := handler.Charge(context.Background(), "0.001")
	if err != nil {
		t.Fatalf("charge failed: %v", err)
	}
	authHeader, err := client.BuildCredentialHeaderWithOptions(context.Background(), cfg.Client, rpcClient, challenge, client.BuildOptions{Broadcast: true})
	if err != nil {
		t.Fatalf("build credential failed: %v", err)
	}
	credential, err := core.ParseAuthorization(authHeader)
	if err != nil {
		t.Fatalf("parse authorization failed: %v", err)
	}
	if _, err := verifyCredentialEchoed(handler, context.Background(), credential); err != nil {
		t.Fatalf("first verify failed: %v", err)
	}
	if _, err := verifyCredentialEchoed(handler, context.Background(), credential); err == nil {
		t.Fatal("expected replay to be rejected")
	}
}

func TestVerifyCredentialTransactionReplayRejected(t *testing.T) {
	handler, rpcClient, cfg := newTestMpp(t)
	challenge, err := handler.Charge(context.Background(), "0.001")
	if err != nil {
		t.Fatalf("charge failed: %v", err)
	}
	authHeader, err := client.BuildCredentialHeader(context.Background(), cfg.Client, rpcClient, challenge)
	if err != nil {
		t.Fatalf("build credential failed: %v", err)
	}
	credential, err := core.ParseAuthorization(authHeader)
	if err != nil {
		t.Fatalf("parse authorization failed: %v", err)
	}
	if _, err := verifyCredentialEchoed(handler, context.Background(), credential); err != nil {
		t.Fatalf("first verify failed: %v", err)
	}
	if _, err := verifyCredentialEchoed(handler, context.Background(), credential); err == nil {
		t.Fatal("expected replay to be rejected")
	}
}

func TestVerifyCredentialRejectsSponsoredPushMode(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	recipient := testutil.NewPrivateKey()
	feePayer := testutil.NewPrivateKey()
	handler, err := New(Config{
		Recipient:      recipient.PublicKey().String(),
		Currency:       "sol",
		Decimals:       9,
		Network:        "localnet",
		SecretKey:      "test-secret-key-0123456789abcdef",
		RPC:            rpcClient,
		Store:          core.NewMemoryStore(),
		FeePayerSigner: feePayer,
	})
	if err != nil {
		t.Fatalf("new mpp failed: %v", err)
	}
	challenge, err := handler.Charge(context.Background(), "0.001")
	if err != nil {
		t.Fatalf("charge failed: %v", err)
	}
	credential, err := core.NewPaymentCredential(challenge.ToEcho(), map[string]string{
		"type":      "signature",
		"signature": "5jKh25biPsnrmLWXXuqKNH2Q67Q4UmVVx8Gf2wrS6VoCeyfGE9wKikjY7Q1GQQgmpQ3xy7wJX5U1rcz82q4R8Nkv",
	})
	if err != nil {
		t.Fatalf("credential failed: %v", err)
	}
	if _, err := verifyCredentialEchoed(handler, context.Background(), credential); err == nil {
		t.Fatal("expected sponsored push mode to fail")
	}
}

func TestVerifyCredentialTokenSignatureSuccess(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	recipient := testutil.NewPrivateKey()
	clientSigner := testutil.NewPrivateKey()
	mint := testutil.NewPrivateKey().PublicKey()
	rpcClient.MintOwners[mint.String()] = solana.TokenProgramID
	handler, err := New(Config{
		Recipient:      recipient.PublicKey().String(),
		Currency:       mint.String(),
		Decimals:       6,
		Network:        "localnet",
		SecretKey:      "test-secret-key-0123456789abcdef",
		RPC:            rpcClient,
		Store:          core.NewMemoryStore(),
		AcceptPushMode: true,
	})
	if err != nil {
		t.Fatalf("new mpp failed: %v", err)
	}
	challenge, err := handler.Charge(context.Background(), "1.000000")
	if err != nil {
		t.Fatalf("charge failed: %v", err)
	}
	authHeader, err := client.BuildCredentialHeaderWithOptions(context.Background(), clientSigner, rpcClient, challenge, client.BuildOptions{Broadcast: true})
	if err != nil {
		t.Fatalf("build credential failed: %v", err)
	}
	credential, err := core.ParseAuthorization(authHeader)
	if err != nil {
		t.Fatalf("parse authorization failed: %v", err)
	}
	receipt, err := verifyCredentialEchoed(handler, context.Background(), credential)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if receipt.Status != core.ReceiptStatusSuccess {
		t.Fatalf("unexpected receipt: %#v", receipt)
	}
}

func TestVerifyCredentialUSDCSymbolSignatureSuccess(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	recipient := testutil.NewPrivateKey()
	clientSigner := testutil.NewPrivateKey()
	usdcMint := solana.MustPublicKeyFromBase58("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v")
	rpcClient.MintOwners[usdcMint.String()] = solana.TokenProgramID
	handler, err := New(Config{
		Recipient:      recipient.PublicKey().String(),
		Currency:       "USDC",
		Decimals:       6,
		Network:        "localnet",
		SecretKey:      "test-secret-key-0123456789abcdef",
		RPC:            rpcClient,
		Store:          core.NewMemoryStore(),
		AcceptPushMode: true,
	})
	if err != nil {
		t.Fatalf("new mpp failed: %v", err)
	}
	challenge, err := handler.Charge(context.Background(), "1.000000")
	if err != nil {
		t.Fatalf("charge failed: %v", err)
	}
	authHeader, err := client.BuildCredentialHeaderWithOptions(context.Background(), clientSigner, rpcClient, challenge, client.BuildOptions{Broadcast: true})
	if err != nil {
		t.Fatalf("build credential failed: %v", err)
	}
	credential, err := core.ParseAuthorization(authHeader)
	if err != nil {
		t.Fatalf("parse authorization failed: %v", err)
	}
	receipt, err := verifyCredentialEchoed(handler, context.Background(), credential)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if receipt.Status != core.ReceiptStatusSuccess {
		t.Fatalf("unexpected receipt: %#v", receipt)
	}
}

func TestVerifyTransfersAgainstChallengeDuplicateSOLSplitsRequireDistinctInstructions(t *testing.T) {
	payer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey()
	splitRecipient := testutil.NewPrivateKey().PublicKey()

	primaryIx, err := solanatx.BuildSOLTransfer(payer.PublicKey(), recipient, 800)
	if err != nil {
		t.Fatalf("build primary transfer failed: %v", err)
	}
	splitIx, err := solanatx.BuildSOLTransfer(payer.PublicKey(), splitRecipient, 100)
	if err != nil {
		t.Fatalf("build split transfer failed: %v", err)
	}

	tx := newTestTransaction(t, payer, primaryIx, splitIx)
	err = verifyTransfersAgainstChallenge(tx, 1000, "sol", recipient, "", paycore.MethodDetails{
		Splits: []paycore.Split{
			{Recipient: splitRecipient.String(), Amount: "100"},
			{Recipient: splitRecipient.String(), Amount: "100"},
		},
	})
	if err == nil {
		t.Fatal("expected duplicate split reuse to fail")
	}
}

func TestVerifyTransfersAgainstChallengeSameRecipientSOLSplitsMatchByAmount(t *testing.T) {
	payer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey()

	primaryIx, err := solanatx.BuildSOLTransfer(payer.PublicKey(), recipient, 800)
	if err != nil {
		t.Fatalf("build primary transfer failed: %v", err)
	}
	splitIx, err := solanatx.BuildSOLTransfer(payer.PublicKey(), recipient, 200)
	if err != nil {
		t.Fatalf("build split transfer failed: %v", err)
	}

	tx := newTestTransaction(t, payer, primaryIx, splitIx)
	if err := verifyTransfersAgainstChallenge(tx, 1000, "sol", recipient, "", paycore.MethodDetails{
		Splits: []paycore.Split{{Recipient: recipient.String(), Amount: "200"}},
	}); err != nil {
		t.Fatalf("expected same-recipient SOL transfers to pass: %v", err)
	}
}

func TestVerifyTransfersAgainstChallengeAcceptsSOLExternalIDMemo(t *testing.T) {
	payer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey()

	primaryIx, err := solanatx.BuildSOLTransfer(payer.PublicKey(), recipient, 1000)
	if err != nil {
		t.Fatalf("build primary transfer failed: %v", err)
	}
	memoIx, err := solanatx.BuildMemoInstruction("order-123")
	if err != nil {
		t.Fatalf("build memo failed: %v", err)
	}

	tx := newTestTransaction(t, payer, primaryIx, memoIx)
	if err := verifyTransfersAgainstChallenge(tx, 1000, "sol", recipient, "order-123", paycore.MethodDetails{}); err != nil {
		t.Fatalf("expected SOL externalId memo to pass: %v", err)
	}
}

func TestVerifyTransfersAgainstChallengeRejectsMissingSOLExternalIDMemo(t *testing.T) {
	payer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey()

	primaryIx, err := solanatx.BuildSOLTransfer(payer.PublicKey(), recipient, 1000)
	if err != nil {
		t.Fatalf("build primary transfer failed: %v", err)
	}

	tx := newTestTransaction(t, payer, primaryIx)
	if err := verifyTransfersAgainstChallenge(tx, 1000, "sol", recipient, "order-123", paycore.MethodDetails{}); err == nil {
		t.Fatal("expected missing SOL externalId memo to fail")
	}
}

func TestVerifyTransfersAgainstChallengeRejectsUnexpectedSOLMemo(t *testing.T) {
	payer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey()

	primaryIx, err := solanatx.BuildSOLTransfer(payer.PublicKey(), recipient, 1000)
	if err != nil {
		t.Fatalf("build primary transfer failed: %v", err)
	}
	memoIx, err := solanatx.BuildMemoInstruction("unexpected")
	if err != nil {
		t.Fatalf("build memo failed: %v", err)
	}

	tx := newTestTransaction(t, payer, primaryIx, memoIx)
	if err := verifyTransfersAgainstChallenge(tx, 1000, "sol", recipient, "", paycore.MethodDetails{}); err == nil {
		t.Fatal("expected unexpected SOL memo to fail")
	}
}

func TestVerifyTransfersAgainstChallengeAcceptsSOLSplitMemo(t *testing.T) {
	payer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey()
	splitRecipient := testutil.NewPrivateKey().PublicKey()

	primaryIx, err := solanatx.BuildSOLTransfer(payer.PublicKey(), recipient, 800)
	if err != nil {
		t.Fatalf("build primary transfer failed: %v", err)
	}
	splitIx, err := solanatx.BuildSOLTransfer(payer.PublicKey(), splitRecipient, 200)
	if err != nil {
		t.Fatalf("build split transfer failed: %v", err)
	}
	memoIx, err := solanatx.BuildMemoInstruction("platform fee")
	if err != nil {
		t.Fatalf("build memo failed: %v", err)
	}

	tx := newTestTransaction(t, payer, primaryIx, splitIx, memoIx)
	if err := verifyTransfersAgainstChallenge(tx, 1000, "sol", recipient, "", paycore.MethodDetails{
		Splits: []paycore.Split{{Recipient: splitRecipient.String(), Amount: "200", Memo: "platform fee"}},
	}); err != nil {
		t.Fatalf("expected SOL split memo to pass: %v", err)
	}
}

func TestVerifyTransfersAgainstChallengeSameRecipientSPLSplitsMatchByAmount(t *testing.T) {
	payer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey()
	mint := testutil.NewPrivateKey().PublicKey()

	sourceATA, err := solanatx.FindAssociatedTokenAddressWithProgram(payer.PublicKey(), mint, solana.TokenProgramID)
	if err != nil {
		t.Fatalf("find source ata failed: %v", err)
	}
	recipientATA, err := solanatx.FindAssociatedTokenAddressWithProgram(recipient, mint, solana.TokenProgramID)
	if err != nil {
		t.Fatalf("find recipient ata failed: %v", err)
	}

	primaryIx, err := token.NewTransferCheckedInstruction(
		800,
		6,
		sourceATA,
		mint,
		recipientATA,
		payer.PublicKey(),
		nil,
	).ValidateAndBuild()
	if err != nil {
		t.Fatalf("build primary transfer failed: %v", err)
	}
	splitIx, err := token.NewTransferCheckedInstruction(
		200,
		6,
		sourceATA,
		mint,
		recipientATA,
		payer.PublicKey(),
		nil,
	).ValidateAndBuild()
	if err != nil {
		t.Fatalf("build split transfer failed: %v", err)
	}

	tx := newTestTransaction(t, payer, primaryIx, splitIx)
	if err := verifyTransfersAgainstChallenge(tx, 1000, mint.String(), recipient, "", paycore.MethodDetails{
		Splits: []paycore.Split{{Recipient: recipient.String(), Amount: "200"}},
	}); err != nil {
		t.Fatalf("expected same-recipient SPL transfers to pass: %v", err)
	}
}

func TestVerifyTransfersAgainstChallengeAcceptsSPLExternalIDMemo(t *testing.T) {
	payer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey()
	mint := testutil.NewPrivateKey().PublicKey()

	sourceATA, err := solanatx.FindAssociatedTokenAddressWithProgram(payer.PublicKey(), mint, solana.TokenProgramID)
	if err != nil {
		t.Fatalf("find source ata failed: %v", err)
	}
	recipientATA, err := solanatx.FindAssociatedTokenAddressWithProgram(recipient, mint, solana.TokenProgramID)
	if err != nil {
		t.Fatalf("find recipient ata failed: %v", err)
	}

	primaryIx, err := token.NewTransferCheckedInstruction(
		1000,
		6,
		sourceATA,
		mint,
		recipientATA,
		payer.PublicKey(),
		nil,
	).ValidateAndBuild()
	if err != nil {
		t.Fatalf("build primary transfer failed: %v", err)
	}
	memoIx, err := solanatx.BuildMemoInstruction("order-123")
	if err != nil {
		t.Fatalf("build memo failed: %v", err)
	}

	tx := newTestTransaction(t, payer, primaryIx, memoIx)
	if err := verifyTransfersAgainstChallenge(tx, 1000, mint.String(), recipient, "order-123", paycore.MethodDetails{}); err != nil {
		t.Fatalf("expected SPL externalId memo to pass: %v", err)
	}
}

func TestVerifyTransfersAgainstChallengeRejectsWrongSPLMint(t *testing.T) {
	payer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey()
	mint := testutil.NewPrivateKey().PublicKey()
	wrongMint := testutil.NewPrivateKey().PublicKey()

	sourceATA, err := solanatx.FindAssociatedTokenAddressWithProgram(payer.PublicKey(), wrongMint, solana.TokenProgramID)
	if err != nil {
		t.Fatalf("find source ata failed: %v", err)
	}
	recipientATA, err := solanatx.FindAssociatedTokenAddressWithProgram(recipient, wrongMint, solana.TokenProgramID)
	if err != nil {
		t.Fatalf("find recipient ata failed: %v", err)
	}

	ix, err := token.NewTransferCheckedInstruction(
		1000,
		6,
		sourceATA,
		wrongMint,
		recipientATA,
		payer.PublicKey(),
		nil,
	).ValidateAndBuild()
	if err != nil {
		t.Fatalf("build transfer failed: %v", err)
	}

	tx := newTestTransaction(t, payer, ix)
	if err := verifyTransfersAgainstChallenge(tx, 1000, mint.String(), recipient, "", paycore.MethodDetails{}); err == nil {
		t.Fatal("expected wrong mint to fail")
	}
}

func TestVerifyCredentialExpiredChallengeRejected(t *testing.T) {
	handler, _, _ := newTestMpp(t)
	challenge, err := handler.ChargeWithOptions(context.Background(), "0.001", ChargeOptions{
		Expires: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339),
	})
	if err != nil {
		t.Fatalf("charge failed: %v", err)
	}
	credential, err := core.NewPaymentCredential(challenge.ToEcho(), map[string]string{
		"type":      "signature",
		"signature": testutil.NewPrivateKey().PublicKey().String(),
	})
	if err != nil {
		t.Fatalf("credential failed: %v", err)
	}
	if _, err := verifyCredentialEchoed(handler, context.Background(), credential); err == nil {
		t.Fatal("expected expired challenge to fail")
	}
}

func TestNewMissingRecipient(t *testing.T) {
	if _, err := New(Config{SecretKey: "secret"}); err == nil {
		t.Fatal("expected error for missing recipient")
	}
}

func TestNewInvalidRecipientPubkey(t *testing.T) {
	if _, err := New(Config{Recipient: "not-a-pubkey", SecretKey: "secret"}); err == nil {
		t.Fatal("expected error for invalid recipient pubkey")
	}
}

func TestNewMissingSecretKey(t *testing.T) {
	t.Setenv("MPP_SECRET_KEY", "")
	recipient := testutil.NewPrivateKey().PublicKey().String()
	if _, err := New(Config{Recipient: recipient}); err == nil {
		t.Fatal("expected error for missing secret key")
	}
}

func TestNewSecretKeyFromEnv(t *testing.T) {
	const envSecret = "env-secret-key-0123456789abcdef012345"
	t.Setenv("MPP_SECRET_KEY", envSecret)
	recipient := testutil.NewPrivateKey().PublicKey().String()
	rpcClient := testutil.NewFakeRPC()
	handler, err := New(Config{Recipient: recipient, RPC: rpcClient})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if handler.secretKey != envSecret {
		t.Fatalf("expected env secret, got %q", handler.secretKey)
	}
}

func TestNewRejectsShortEnvSecretKey(t *testing.T) {
	// The env-var path shares the >= 32-byte gate with Config.SecretKey (#24).
	t.Setenv("MPP_SECRET_KEY", "too-short")
	recipient := testutil.NewPrivateKey().PublicKey().String()
	rpcClient := testutil.NewFakeRPC()
	if _, err := New(Config{Recipient: recipient, RPC: rpcClient}); err == nil {
		t.Fatal("expected error for short env secret key")
	}
}

func TestChargeToken(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	recipient := testutil.NewPrivateKey().PublicKey().String()
	handler, err := New(Config{
		Recipient: recipient,
		Currency:  "USDC",
		Decimals:  6,
		Network:   "localnet",
		SecretKey: "test-secret-key-0123456789abcdef",
		RPC:       rpcClient,
		Store:     core.NewMemoryStore(),
	})
	if err != nil {
		t.Fatalf("new mpp failed: %v", err)
	}
	challenge, err := handler.Charge(context.Background(), "1.000000")
	if err != nil {
		t.Fatalf("charge failed: %v", err)
	}
	if challenge.Method != "solana" || challenge.Intent != "charge" {
		t.Fatalf("unexpected challenge: %#v", challenge)
	}
}

func TestChargeWithOptionsDescriptionAndExternalID(t *testing.T) {
	handler, _, _ := newTestMpp(t)
	challenge, err := handler.ChargeWithOptions(context.Background(), "0.001", ChargeOptions{
		Description: "Test Payment",
		ExternalID:  "order-42",
		Expires:     time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339),
	})
	if err != nil {
		t.Fatalf("charge failed: %v", err)
	}
	if challenge.Description != "Test Payment" {
		t.Fatalf("expected description, got %q", challenge.Description)
	}
	// Verify the request contains the external ID
	var req map[string]any
	if err := challenge.Request.Decode(&req); err != nil {
		t.Fatalf("decode request failed: %v", err)
	}
	if req["externalId"] != "order-42" {
		t.Fatalf("expected externalId in request, got %v", req["externalId"])
	}
}

func TestChargeWithOptionsSplits(t *testing.T) {
	handler, _, _ := newTestMpp(t)
	vendor := testutil.NewPrivateKey().PublicKey().String()
	processor := testutil.NewPrivateKey().PublicKey().String()
	challenge, err := handler.ChargeWithOptions(context.Background(), "1.00", ChargeOptions{
		Splits: []paycore.Split{
			{Recipient: vendor, Amount: "500000", Memo: "Vendor payout"},
			{Recipient: processor, Amount: "29000"},
		},
	})
	if err != nil {
		t.Fatalf("charge failed: %v", err)
	}
	var req map[string]any
	if err := challenge.Request.Decode(&req); err != nil {
		t.Fatalf("decode request failed: %v", err)
	}
	md, ok := req["methodDetails"].(map[string]any)
	if !ok {
		t.Fatal("expected methodDetails")
	}
	splits, ok := md["splits"].([]any)
	if !ok {
		t.Fatal("expected splits in methodDetails")
	}
	if len(splits) != 2 {
		t.Fatalf("expected 2 splits, got %d", len(splits))
	}
	first := splits[0].(map[string]any)
	if first["amount"] != "500000" {
		t.Fatalf("expected amount 500000, got %v", first["amount"])
	}
	if first["memo"] != "Vendor payout" {
		t.Fatalf("expected memo, got %v", first["memo"])
	}
}

func TestChargeWithOptionsNoSplitsOmitted(t *testing.T) {
	handler, _, _ := newTestMpp(t)
	challenge, err := handler.Charge(context.Background(), "1.00")
	if err != nil {
		t.Fatalf("charge failed: %v", err)
	}
	var req map[string]any
	if err := challenge.Request.Decode(&req); err != nil {
		t.Fatalf("decode request failed: %v", err)
	}
	md, ok := req["methodDetails"].(map[string]any)
	if !ok {
		t.Fatal("expected methodDetails")
	}
	if _, exists := md["splits"]; exists {
		t.Fatal("splits should not be present when empty")
	}
}

func TestVerifyCredentialMissingPayloadType(t *testing.T) {
	handler, _, _ := newTestMpp(t)
	challenge, _ := handler.Charge(context.Background(), "0.001")
	// Empty payload type
	credential, err := core.NewPaymentCredential(challenge.ToEcho(), map[string]string{
		"type": "",
	})
	if err != nil {
		t.Fatalf("credential failed: %v", err)
	}
	if _, err := verifyCredentialEchoed(handler, context.Background(), credential); err == nil {
		t.Fatal("expected error for missing payload type")
	}
}

func TestVerifyCredentialMissingTransactionData(t *testing.T) {
	handler, _, _ := newTestMpp(t)
	challenge, _ := handler.Charge(context.Background(), "0.001")
	credential, err := core.NewPaymentCredential(challenge.ToEcho(), map[string]string{
		"type":        "transaction",
		"transaction": "",
	})
	if err != nil {
		t.Fatalf("credential failed: %v", err)
	}
	if _, err := verifyCredentialEchoed(handler, context.Background(), credential); err == nil {
		t.Fatal("expected error for missing transaction data")
	}
}

func TestVerifyCredentialSimulationFailure(t *testing.T) {
	handler, rpcClient, cfg := newTestMpp(t)
	challenge, _ := handler.Charge(context.Background(), "0.001")
	authHeader, err := client.BuildCredentialHeader(context.Background(), cfg.Client, rpcClient, challenge)
	if err != nil {
		t.Fatalf("build credential failed: %v", err)
	}
	credential, _ := core.ParseAuthorization(authHeader)
	// Make simulation fail
	rpcClient.SimulateErr = fmt.Errorf("simulation failed")
	if _, err := verifyCredentialEchoed(handler, context.Background(), credential); err == nil {
		t.Fatal("expected error for simulation failure")
	}
}

func TestVerifyCredentialSendFailure(t *testing.T) {
	handler, rpcClient, cfg := newTestMpp(t)
	challenge, _ := handler.Charge(context.Background(), "0.001")
	authHeader, err := client.BuildCredentialHeader(context.Background(), cfg.Client, rpcClient, challenge)
	if err != nil {
		t.Fatalf("build credential failed: %v", err)
	}
	credential, _ := core.ParseAuthorization(authHeader)
	rpcClient.SendErr = fmt.Errorf("send failed")
	if _, err := verifyCredentialEchoed(handler, context.Background(), credential); err == nil {
		t.Fatal("expected error for send failure")
	}
}

func TestVerifyCredentialGetTxFailure(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	recipient := testutil.NewPrivateKey()
	clientSigner := testutil.NewPrivateKey()
	handler, err := New(Config{
		Recipient: recipient.PublicKey().String(),
		Currency:  "sol",
		Decimals:  9,
		Network:   "localnet",
		SecretKey: "test-secret-key-0123456789abcdef",
		RPC:       rpcClient,
		Store:     core.NewMemoryStore(),
	})
	if err != nil {
		t.Fatalf("new mpp failed: %v", err)
	}
	challenge, _ := handler.Charge(context.Background(), "0.001")
	// Use push mode so verifyOnChain is called
	authHeader, err := client.BuildCredentialHeaderWithOptions(context.Background(), clientSigner, rpcClient, challenge, client.BuildOptions{Broadcast: true})
	if err != nil {
		t.Fatalf("build credential failed: %v", err)
	}
	credential, _ := core.ParseAuthorization(authHeader)
	// Make GetTransaction fail
	rpcClient.GetTxErr = fmt.Errorf("transaction not found")
	if _, err := verifyCredentialEchoed(handler, context.Background(), credential); err == nil {
		t.Fatal("expected error for get transaction failure")
	}
}

func TestVerifyCredentialMissingSignature(t *testing.T) {
	handler, _, _ := newTestMpp(t)
	challenge, _ := handler.Charge(context.Background(), "0.001")
	credential, err := core.NewPaymentCredential(challenge.ToEcho(), map[string]string{
		"type":      "signature",
		"signature": "",
	})
	if err != nil {
		t.Fatalf("credential failed: %v", err)
	}
	if _, err := verifyCredentialEchoed(handler, context.Background(), credential); err == nil {
		t.Fatal("expected error for missing signature")
	}
}

func TestChargeWithFeePayer(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	feePayer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey()
	handler, err := New(Config{
		Recipient:      recipient.PublicKey().String(),
		Currency:       "sol",
		Decimals:       9,
		Network:        "localnet",
		SecretKey:      "test-secret-key-0123456789abcdef",
		RPC:            rpcClient,
		Store:          core.NewMemoryStore(),
		FeePayerSigner: feePayer,
	})
	if err != nil {
		t.Fatalf("new mpp failed: %v", err)
	}
	challenge, err := handler.Charge(context.Background(), "0.001")
	if err != nil {
		t.Fatalf("charge failed: %v", err)
	}
	var req map[string]any
	if err := challenge.Request.Decode(&req); err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	md, ok := req["methodDetails"].(map[string]any)
	if !ok {
		t.Fatal("expected methodDetails in request")
	}
	if md["feePayer"] != true {
		t.Fatal("expected feePayer=true in method details")
	}
	if md["feePayerKey"] != feePayer.PublicKey().String() {
		t.Fatalf("expected feePayerKey, got %v", md["feePayerKey"])
	}
}

func TestNewWithDefaultValues(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	recipient := testutil.NewPrivateKey().PublicKey().String()
	handler, err := New(Config{
		Recipient: recipient,
		SecretKey: "test-secret-key-0123456789abcdef",
		RPC:       rpcClient,
	})
	if err != nil {
		t.Fatalf("new mpp failed: %v", err)
	}
	if handler.currency != "USDC" {
		t.Fatalf("expected default currency USDC, got %q", handler.currency)
	}
	if handler.decimals != 6 {
		t.Fatalf("expected default decimals 6, got %d", handler.decimals)
	}
	if handler.network != "mainnet" {
		t.Fatalf("expected default network mainnet, got %q", handler.network)
	}
}

func TestChargeKnownStablecoinTokenPrograms(t *testing.T) {
	for _, tt := range []struct {
		currency string
		want     string
	}{
		{currency: "USDC", want: paycore.TokenProgram},
		{currency: "USDT", want: paycore.TokenProgram},
		{currency: "PYUSD", want: paycore.Token2022Program},
		{currency: "USDG", want: paycore.Token2022Program},
		{currency: "CASH", want: paycore.Token2022Program},
	} {
		rpcClient := testutil.NewFakeRPC()
		handler, err := New(Config{
			Recipient: testutil.NewPrivateKey().PublicKey().String(),
			Currency:  tt.currency,
			Decimals:  6,
			Network:   "mainnet",
			SecretKey: "test-secret-key-0123456789abcdef",
			RPC:       rpcClient,
			Store:     core.NewMemoryStore(),
		})
		if err != nil {
			t.Fatalf("new mpp failed: %v", err)
		}
		challenge, err := handler.Charge(context.Background(), "1.000000")
		if err != nil {
			t.Fatalf("charge failed: %v", err)
		}
		var req map[string]any
		if err := challenge.Request.Decode(&req); err != nil {
			t.Fatalf("decode failed: %v", err)
		}
		md, ok := req["methodDetails"].(map[string]any)
		if !ok {
			t.Fatal("expected methodDetails in request")
		}
		if md["tokenProgram"] != tt.want {
			t.Fatalf("expected %s tokenProgram %s, got %v", tt.currency, tt.want, md["tokenProgram"])
		}
	}
}

func TestVerifyCredentialTokenTransactionSuccess(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	recipient := testutil.NewPrivateKey()
	clientSigner := testutil.NewPrivateKey()
	mint := testutil.NewPrivateKey().PublicKey()
	rpcClient.MintOwners[mint.String()] = solana.TokenProgramID
	handler, err := New(Config{
		Recipient: recipient.PublicKey().String(),
		Currency:  mint.String(),
		Decimals:  6,
		Network:   "localnet",
		SecretKey: "test-secret-key-0123456789abcdef",
		RPC:       rpcClient,
		Store:     core.NewMemoryStore(),
	})
	if err != nil {
		t.Fatalf("new mpp failed: %v", err)
	}
	challenge, err := handler.Charge(context.Background(), "1.000000")
	if err != nil {
		t.Fatalf("charge failed: %v", err)
	}
	// Use pull mode (transaction)
	authHeader, err := client.BuildCredentialHeader(context.Background(), clientSigner, rpcClient, challenge)
	if err != nil {
		t.Fatalf("build credential failed: %v", err)
	}
	credential, _ := core.ParseAuthorization(authHeader)
	receipt, err := verifyCredentialEchoed(handler, context.Background(), credential)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if receipt.Status != core.ReceiptStatusSuccess {
		t.Fatalf("unexpected receipt: %#v", receipt)
	}
}

func TestVerifyCredentialSignatureSuccess(t *testing.T) {
	handler, rpcClient, cfg := newTestMpp(t)
	challenge, _ := handler.Charge(context.Background(), "0.001")
	authHeader, err := client.BuildCredentialHeaderWithOptions(context.Background(), cfg.Client, rpcClient, challenge, client.BuildOptions{Broadcast: true})
	if err != nil {
		t.Fatalf("build credential failed: %v", err)
	}
	credential, _ := core.ParseAuthorization(authHeader)
	receipt, err := verifyCredentialEchoed(handler, context.Background(), credential)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if receipt.Status != core.ReceiptStatusSuccess || receipt.Reference == "" {
		t.Fatalf("unexpected receipt: %#v", receipt)
	}
}

func TestRPCURL(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	recipient := testutil.NewPrivateKey().PublicKey().String()
	handler, err := New(Config{
		Recipient: recipient,
		SecretKey: "test-secret-key-0123456789abcdef",
		Network:   "devnet",
		RPC:       rpcClient,
	})
	if err != nil {
		t.Fatalf("new mpp failed: %v", err)
	}
	if handler.RPCURL() != "https://api.devnet.solana.com" {
		t.Fatalf("unexpected RPC URL: %q", handler.RPCURL())
	}
}

func TestVerifyCredentialTransactionWithFeePayerSigner(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	recipient := testutil.NewPrivateKey()
	feePayer := testutil.NewPrivateKey()
	clientSigner := testutil.NewPrivateKey()
	handler, err := New(Config{
		Recipient:      recipient.PublicKey().String(),
		Currency:       "sol",
		Decimals:       9,
		Network:        "localnet",
		SecretKey:      "test-secret-key-0123456789abcdef",
		RPC:            rpcClient,
		Store:          core.NewMemoryStore(),
		FeePayerSigner: feePayer,
	})
	if err != nil {
		t.Fatalf("new mpp failed: %v", err)
	}
	challenge, _ := handler.Charge(context.Background(), "0.001")
	// Build a pull-mode credential (transaction type)
	authHeader, err := client.BuildCredentialHeader(context.Background(), clientSigner, rpcClient, challenge)
	if err != nil {
		t.Fatalf("build credential failed: %v", err)
	}
	credential, _ := core.ParseAuthorization(authHeader)
	receipt, err := verifyCredentialEchoed(handler, context.Background(), credential)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if receipt.Status != core.ReceiptStatusSuccess {
		t.Fatalf("unexpected receipt: %#v", receipt)
	}
}

// TestVerifyCredentialRejectsTamperedTransferBeforeBroadcast covers the
// pre-broadcast verifier in sponsored pull mode: a credential whose SOL
// transfer amount has been tampered after the client signed must be
// rejected before the server co-signs or sends the transaction. Mirrors
// the Rust reference (`verify_versioned_transaction_pre_broadcast` in
// rust/src/server/charge.rs). Regression for the codex finding that
// flagged sign-then-broadcast-then-verify ordering.
func TestVerifyCredentialRejectsTamperedTransferBeforeBroadcast(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	recipient := testutil.NewPrivateKey()
	feePayer := testutil.NewPrivateKey()
	clientSigner := testutil.NewPrivateKey()
	handler, err := New(Config{
		Recipient:      recipient.PublicKey().String(),
		Currency:       "sol",
		Decimals:       9,
		Network:        "localnet",
		SecretKey:      "test-secret-key-0123456789abcdef",
		RPC:            rpcClient,
		Store:          core.NewMemoryStore(),
		FeePayerSigner: feePayer,
	})
	if err != nil {
		t.Fatalf("new mpp failed: %v", err)
	}
	challenge, err := handler.Charge(context.Background(), "0.001")
	if err != nil {
		t.Fatalf("charge failed: %v", err)
	}
	authHeader, err := client.BuildCredentialHeader(context.Background(), clientSigner, rpcClient, challenge)
	if err != nil {
		t.Fatalf("build credential failed: %v", err)
	}
	credential, err := core.ParseAuthorization(authHeader)
	if err != nil {
		t.Fatalf("parse authorization failed: %v", err)
	}
	var payload paycore.CredentialPayload
	if err := credential.PayloadAs(&payload); err != nil {
		t.Fatalf("decode credential payload: %v", err)
	}
	tx, err := solanatx.DecodeTransactionBase64(payload.Transaction)
	if err != nil {
		t.Fatalf("decode transaction: %v", err)
	}
	// Tamper the SOL transfer: bump the lamports far above the challenge
	// amount. The client signature stays as-is, but the pre-broadcast
	// verifier inspects instructions and must reject before sign/send.
	tampered := false
	for index, compiled := range tx.Message.Instructions {
		programID, err := resolveProgramID(tx, compiled.ProgramIDIndex)
		if err != nil {
			t.Fatalf("resolve program id: %v", err)
		}
		if !programID.Equals(solana.SystemProgramID) {
			continue
		}
		data := []byte(compiled.Data)
		// System Transfer layout: 4-byte little-endian discriminator (2)
		// followed by 8-byte little-endian lamports. Anything else (e.g.
		// CreateAccount, CreateAccountWithSeed) carries different bytes
		// and is skipped.
		if len(data) != 12 || binary.LittleEndian.Uint32(data[0:4]) != 2 {
			continue
		}
		current := binary.LittleEndian.Uint64(data[4:12])
		binary.LittleEndian.PutUint64(data[4:12], current+999_999)
		tx.Message.Instructions[index].Data = data
		tampered = true
		break
	}
	if !tampered {
		t.Fatal("expected at least one SOL transfer to tamper")
	}
	rebuiltEncoded, err := solanatx.EncodeTransactionBase64(tx)
	if err != nil {
		t.Fatalf("re-encode transaction: %v", err)
	}
	tamperedCredential, err := core.NewPaymentCredential(credential.Challenge, map[string]string{
		"type":        "transaction",
		"transaction": rebuiltEncoded,
	})
	if err != nil {
		t.Fatalf("rebuild credential: %v", err)
	}
	if _, err := verifyCredentialEchoed(handler, context.Background(), tamperedCredential); err == nil {
		t.Fatal("expected tampered transfer amount to be rejected pre-broadcast")
	}
	// Pre-broadcast rejection: the FakeRPC must not have observed any
	// broadcast attempt. This is the load-bearing assertion for the codex
	// finding (sign → verify → broadcast, not sign → broadcast → verify).
	if got := len(rpcClient.Sent); got != 0 {
		t.Fatalf("expected zero broadcasts before pre-broadcast verify, got %d", got)
	}
}

func TestVerifyCredentialChallengeMismatchRejected(t *testing.T) {
	handler, _, _ := newTestMpp(t)
	request, _ := core.NewBase64URLJSONValue(map[string]any{
		"amount":    "1000",
		"currency":  "sol",
		"recipient": testutil.NewPrivateKey().PublicKey().String(),
	})
	challenge := core.NewChallengeWithSecret("wrong-secret", "realm", "solana", "charge", request)
	credential, err := core.NewPaymentCredential(challenge.ToEcho(), map[string]string{
		"type":      "signature",
		"signature": testutil.NewPrivateKey().PublicKey().String(),
	})
	if err != nil {
		t.Fatalf("credential failed: %v", err)
	}
	if _, err := verifyCredentialEchoed(handler, context.Background(), credential); err == nil {
		t.Fatal("expected challenge mismatch to fail")
	}
}

func TestVerifyTransfersAgainstChallengeRejectsMissingSPLSplitMemo(t *testing.T) {
	payer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey()
	splitRecipient := testutil.NewPrivateKey().PublicKey()
	mint := testutil.NewPrivateKey().PublicKey()

	sourceATA, err := solanatx.FindAssociatedTokenAddressWithProgram(payer.PublicKey(), mint, solana.TokenProgramID)
	if err != nil {
		t.Fatalf("find source ata failed: %v", err)
	}
	recipientATA, err := solanatx.FindAssociatedTokenAddressWithProgram(recipient, mint, solana.TokenProgramID)
	if err != nil {
		t.Fatalf("find recipient ata failed: %v", err)
	}
	splitATA, err := solanatx.FindAssociatedTokenAddressWithProgram(splitRecipient, mint, solana.TokenProgramID)
	if err != nil {
		t.Fatalf("find split ata failed: %v", err)
	}

	primaryIx, err := token.NewTransferCheckedInstruction(800, 6, sourceATA, mint, recipientATA, payer.PublicKey(), nil).ValidateAndBuild()
	if err != nil {
		t.Fatalf("build primary transfer failed: %v", err)
	}
	splitIx, err := token.NewTransferCheckedInstruction(200, 6, sourceATA, mint, splitATA, payer.PublicKey(), nil).ValidateAndBuild()
	if err != nil {
		t.Fatalf("build split transfer failed: %v", err)
	}

	tx := newTestTransaction(t, payer, primaryIx, splitIx)
	if err := verifyTransfersAgainstChallenge(tx, 1000, mint.String(), recipient, "", paycore.MethodDetails{
		Splits: []paycore.Split{{Recipient: splitRecipient.String(), Amount: "200", Memo: "platform fee"}},
	}); err == nil {
		t.Fatal("expected missing SPL split memo to fail")
	}
}

func TestVerifyTransfersAgainstChallengeRejectsUnexpectedSPLMemo(t *testing.T) {
	payer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey()
	mint := testutil.NewPrivateKey().PublicKey()

	sourceATA, err := solanatx.FindAssociatedTokenAddressWithProgram(payer.PublicKey(), mint, solana.TokenProgramID)
	if err != nil {
		t.Fatalf("find source ata failed: %v", err)
	}
	recipientATA, err := solanatx.FindAssociatedTokenAddressWithProgram(recipient, mint, solana.TokenProgramID)
	if err != nil {
		t.Fatalf("find recipient ata failed: %v", err)
	}

	primaryIx, err := token.NewTransferCheckedInstruction(1000, 6, sourceATA, mint, recipientATA, payer.PublicKey(), nil).ValidateAndBuild()
	if err != nil {
		t.Fatalf("build primary transfer failed: %v", err)
	}
	memoIx, err := solanatx.BuildMemoInstruction("unexpected")
	if err != nil {
		t.Fatalf("build memo failed: %v", err)
	}

	tx := newTestTransaction(t, payer, primaryIx, memoIx)
	if err := verifyTransfersAgainstChallenge(tx, 1000, mint.String(), recipient, "", paycore.MethodDetails{}); err == nil {
		t.Fatal("expected unexpected SPL memo to fail")
	}
}

func TestVerifyTransfersAgainstChallengeAcceptsToken2022Transfer(t *testing.T) {
	payer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey()
	mint := testutil.NewPrivateKey().PublicKey()
	tokenProgram := solana.MustPublicKeyFromBase58(paycore.Token2022Program)

	sourceATA, err := solanatx.FindAssociatedTokenAddressWithProgram(payer.PublicKey(), mint, tokenProgram)
	if err != nil {
		t.Fatalf("find source ata failed: %v", err)
	}
	recipientATA, err := solanatx.FindAssociatedTokenAddressWithProgram(recipient, mint, tokenProgram)
	if err != nil {
		t.Fatalf("find recipient ata failed: %v", err)
	}
	ix, err := token2022.NewTransferCheckedInstruction(1000, 6, sourceATA, mint, recipientATA, payer.PublicKey(), nil).ValidateAndBuild()
	if err != nil {
		t.Fatalf("build transfer failed: %v", err)
	}

	tx := newTestTransaction(t, payer, ix)
	if err := verifyTransfersAgainstChallenge(tx, 1000, mint.String(), recipient, "", paycore.MethodDetails{
		TokenProgram: paycore.Token2022Program,
	}); err != nil {
		t.Fatalf("expected token2022 transfer to pass: %v", err)
	}
}

func TestBuildExpectedTransfersRejectsInvalidSplitFields(t *testing.T) {
	recipient := testutil.NewPrivateKey().PublicKey()
	if _, err := buildExpectedTransfers(1000, recipient, paycore.MethodDetails{
		Splits: []paycore.Split{{Recipient: testutil.NewPrivateKey().PublicKey().String(), Amount: "not-a-number"}},
	}); err == nil {
		t.Fatal("expected invalid split amount to fail")
	}
	if _, err := buildExpectedTransfers(1000, recipient, paycore.MethodDetails{
		Splits: []paycore.Split{{Recipient: "not-a-pubkey", Amount: "100"}},
	}); err == nil {
		t.Fatal("expected invalid split recipient to fail")
	}
}

func TestVerifyCredentialRejectsInvalidPayloadType(t *testing.T) {
	handler, _, _ := newTestMpp(t)
	challenge, err := handler.Charge(context.Background(), "0.001")
	if err != nil {
		t.Fatalf("charge failed: %v", err)
	}
	credential, err := core.NewPaymentCredential(challenge.ToEcho(), map[string]string{
		"type": "voucher",
	})
	if err != nil {
		t.Fatalf("credential failed: %v", err)
	}
	if _, err := verifyCredentialEchoed(handler, context.Background(), credential); err == nil {
		t.Fatal("expected invalid payload type to fail")
	}
}

func TestVerifyCredentialWithExpectedRejectsInvalidExpectedMethodDetails(t *testing.T) {
	handler, _, _ := newTestMpp(t)
	challenge, err := handler.Charge(context.Background(), "0.001")
	if err != nil {
		t.Fatalf("charge failed: %v", err)
	}
	credential, err := core.NewPaymentCredential(challenge.ToEcho(), map[string]string{
		"type":      "signature",
		"signature": testutil.NewPrivateKey().PublicKey().String(),
	})
	if err != nil {
		t.Fatalf("credential failed: %v", err)
	}

	var expected intents.ChargeRequest
	if err := challenge.Request.Decode(&expected); err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	expected.MethodDetails = map[string]any{"decimals": "not-a-number"}

	if _, err := handler.VerifyCredentialWithExpected(context.Background(), credential, expected); err == nil {
		t.Fatal("expected invalid expected methodDetails to fail")
	}
}

func TestVerifyCredentialMalformedTransactionData(t *testing.T) {
	handler, _, _ := newTestMpp(t)
	challenge, _ := handler.Charge(context.Background(), "0.001")
	credential, err := core.NewPaymentCredential(challenge.ToEcho(), map[string]string{
		"type":        "transaction",
		"transaction": "not-base64",
	})
	if err != nil {
		t.Fatalf("credential failed: %v", err)
	}
	if _, err := verifyCredentialEchoed(handler, context.Background(), credential); err == nil {
		t.Fatal("expected error for malformed transaction data")
	}
}

// --- merged from server_branch_test.go ---

func TestChargeWithOptionsInvalidAmount(t *testing.T) {
	handler, _, _ := newTestMpp(t)
	if _, err := handler.ChargeWithOptions(context.Background(), "not-a-number", ChargeOptions{}); err == nil {
		t.Fatal("expected invalid amount error")
	}
}

func TestVerifyCredentialWithExpectedRejectsCurrencyMismatch(t *testing.T) {
	handler, _, cfg := newTestMpp(t)
	challenge, err := handler.Charge(context.Background(), "0.001")
	if err != nil {
		t.Fatalf("charge: %v", err)
	}
	credential, err := core.NewPaymentCredential(challenge.ToEcho(), map[string]string{
		"type":      "signature",
		"signature": testutil.NewPrivateKey().PublicKey().String(),
	})
	if err != nil {
		t.Fatalf("credential: %v", err)
	}
	_, err = handler.VerifyCredentialWithExpected(context.Background(), credential, intents.ChargeRequest{
		Amount:    "1000000",
		Currency:  "usdc",
		Recipient: cfg.Recipient,
	})
	if err == nil || !strings.Contains(err.Error(), "currency") {
		t.Fatalf("expected currency mismatch, got %v", err)
	}
}

func TestVerifyCredentialWithExpectedRejectsRecipientMismatch(t *testing.T) {
	handler, _, _ := newTestMpp(t)
	challenge, err := handler.Charge(context.Background(), "0.001")
	if err != nil {
		t.Fatalf("charge: %v", err)
	}
	credential, err := core.NewPaymentCredential(challenge.ToEcho(), map[string]string{
		"type":      "signature",
		"signature": testutil.NewPrivateKey().PublicKey().String(),
	})
	if err != nil {
		t.Fatalf("credential: %v", err)
	}
	_, err = handler.VerifyCredentialWithExpected(context.Background(), credential, intents.ChargeRequest{
		Amount:    "1000000",
		Currency:  "sol",
		Recipient: testutil.NewPrivateKey().PublicKey().String(),
	})
	if err == nil || !strings.Contains(err.Error(), "recipient") {
		t.Fatalf("expected recipient mismatch, got %v", err)
	}
}

func TestVerifyCredentialWithExpectedDecodeError(t *testing.T) {
	handler, _, cfg := newTestMpp(t)
	challenge, err := handler.Charge(context.Background(), "0.001")
	if err != nil {
		t.Fatalf("charge: %v", err)
	}
	credential, err := core.NewPaymentCredential(challenge.ToEcho(), map[string]string{
		"type":      "signature",
		"signature": testutil.NewPrivateKey().PublicKey().String(),
	})
	if err != nil {
		t.Fatalf("credential: %v", err)
	}
	// Make MethodDetails an un-marshalable value (channel) by using a func.
	// We can't marshal a channel via json — this triggers decodeMethodDetails error path.
	_, err = handler.VerifyCredentialWithExpected(context.Background(), credential, intents.ChargeRequest{
		Amount:        "1000000",
		Currency:      "sol",
		Recipient:     cfg.Recipient,
		MethodDetails: make(chan int),
	})
	if err == nil {
		t.Fatal("expected decodeMethodDetails error")
	}
}

func TestDecodeMethodDetailsNilReturnsEmpty(t *testing.T) {
	out, err := decodeMethodDetails(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Network != "" {
		t.Fatalf("expected empty details, got %#v", out)
	}
}

func TestDecodeMethodDetailsMarshalError(t *testing.T) {
	_, err := decodeMethodDetails(make(chan int))
	if err == nil {
		t.Fatal("expected marshal error")
	}
}

func TestDecodeMethodDetailsUnmarshalError(t *testing.T) {
	// A JSON value that doesn't fit MethodDetails struct (a string).
	// json.Unmarshal will fail trying to unmarshal a string into a struct.
	_, err := decodeMethodDetails("just-a-string")
	if err == nil {
		t.Fatal("expected unmarshal error")
	}
}

func TestVerifyTransactionMissingTransaction(t *testing.T) {
	handler, _, _ := newTestMpp(t)
	challenge, err := handler.Charge(context.Background(), "0.001")
	if err != nil {
		t.Fatalf("charge: %v", err)
	}
	credential, err := core.NewPaymentCredential(challenge.ToEcho(), map[string]string{
		"type":        "transaction",
		"transaction": "",
	})
	if err != nil {
		t.Fatalf("credential: %v", err)
	}
	if _, err := verifyCredentialEchoed(handler, context.Background(), credential); err == nil {
		t.Fatal("expected missing transaction error")
	}
}

func TestVerifyTransactionInvalidBase64(t *testing.T) {
	handler, _, _ := newTestMpp(t)
	challenge, err := handler.Charge(context.Background(), "0.001")
	if err != nil {
		t.Fatalf("charge: %v", err)
	}
	credential, err := core.NewPaymentCredential(challenge.ToEcho(), map[string]string{
		"type":        "transaction",
		"transaction": "!!!not-base64!!!",
	})
	if err != nil {
		t.Fatalf("credential: %v", err)
	}
	if _, err := verifyCredentialEchoed(handler, context.Background(), credential); err == nil {
		t.Fatal("expected invalid base64 error")
	}
}

func TestVerifyTransactionUnknownPayloadType(t *testing.T) {
	handler, _, _ := newTestMpp(t)
	challenge, err := handler.Charge(context.Background(), "0.001")
	if err != nil {
		t.Fatalf("charge: %v", err)
	}
	credential, err := core.NewPaymentCredential(challenge.ToEcho(), map[string]string{
		"type": "unknown",
	})
	if err != nil {
		t.Fatalf("credential: %v", err)
	}
	if _, err := verifyCredentialEchoed(handler, context.Background(), credential); err == nil {
		t.Fatal("expected invalid payload type error")
	}
}

func TestVerifySignatureMissingSignature(t *testing.T) {
	handler, _, _ := newTestMpp(t)
	challenge, err := handler.Charge(context.Background(), "0.001")
	if err != nil {
		t.Fatalf("charge: %v", err)
	}
	credential, err := core.NewPaymentCredential(challenge.ToEcho(), map[string]string{
		"type":      "signature",
		"signature": "",
	})
	if err != nil {
		t.Fatalf("credential: %v", err)
	}
	if _, err := verifyCredentialEchoed(handler, context.Background(), credential); err == nil {
		t.Fatal("expected missing signature error")
	}
}

func TestVerifySignatureInvalidSignatureBase58(t *testing.T) {
	handler, _, _ := newTestMpp(t)
	challenge, err := handler.Charge(context.Background(), "0.001")
	if err != nil {
		t.Fatalf("charge: %v", err)
	}
	credential, err := core.NewPaymentCredential(challenge.ToEcho(), map[string]string{
		"type":      "signature",
		"signature": "not-a-valid-base58-sig",
	})
	if err != nil {
		t.Fatalf("credential: %v", err)
	}
	if _, err := verifyCredentialEchoed(handler, context.Background(), credential); err == nil {
		t.Fatal("expected invalid signature base58 error")
	}
}

// rpcSimErr forces simulate to error to hit verifyTransaction simulate error branch.
type rpcSimErr struct{ *testutil.FakeRPC }

func (r *rpcSimErr) SimulateTransactionWithOpts(_ context.Context, _ *solana.Transaction, _ *rpc.SimulateTransactionOpts) (*rpc.SimulateTransactionResponse, error) {
	return nil, errors.New("simulate down")
}

func buildSOLPullTransaction(t *testing.T, payer solana.PrivateKey, recipient solana.PublicKey, lamports uint64, blockhash solana.Hash) string {
	t.Helper()
	ix, err := solanatx.BuildSOLTransfer(payer.PublicKey(), recipient, lamports)
	if err != nil {
		t.Fatalf("ix: %v", err)
	}
	tx, err := solana.NewTransaction([]solana.Instruction{ix}, blockhash, solana.TransactionPayer(payer.PublicKey()))
	if err != nil {
		t.Fatalf("tx: %v", err)
	}
	if err := solanatx.SignTransaction(tx, payer); err != nil {
		t.Fatalf("sign: %v", err)
	}
	encoded, err := solanatx.EncodeTransactionBase64(tx)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return encoded
}

func TestVerifyTransactionSimulateError(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	wrapped := &rpcSimErr{FakeRPC: rpcClient}
	recipient := testutil.NewPrivateKey()
	handler, err := New(Config{
		Recipient: recipient.PublicKey().String(),
		Currency:  "sol",
		Decimals:  9,
		Network:   "localnet",
		SecretKey: "test-secret-key-0123456789abcdef",
		RPC:       wrapped,
		Store:     core.NewMemoryStore(),
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	challenge, err := handler.Charge(context.Background(), "0.001")
	if err != nil {
		t.Fatalf("charge: %v", err)
	}
	payer := testutil.NewPrivateKey()
	encoded := buildSOLPullTransaction(t, payer, recipient.PublicKey(), 1_000_000, rpcClient.Blockhash)
	credential, err := core.NewPaymentCredential(challenge.ToEcho(), map[string]string{
		"type":        "transaction",
		"transaction": encoded,
	})
	if err != nil {
		t.Fatalf("credential: %v", err)
	}
	if _, err := verifyCredentialEchoed(handler, context.Background(), credential); err == nil {
		t.Fatal("expected simulate error")
	}
}

// rpcSendErrRPC fails on send to exercise the send error branch in verifyTransaction.
type rpcSendErrRPC struct{ *testutil.FakeRPC }

func (r *rpcSendErrRPC) SendTransactionWithOpts(_ context.Context, _ *solana.Transaction, _ rpc.TransactionOpts) (solana.Signature, error) {
	return solana.Signature{}, errors.New("send down")
}

func TestVerifyTransactionSendError(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	wrapped := &rpcSendErrRPC{FakeRPC: rpcClient}
	recipient := testutil.NewPrivateKey()
	handler, err := New(Config{
		Recipient: recipient.PublicKey().String(),
		Currency:  "sol",
		Decimals:  9,
		Network:   "localnet",
		SecretKey: "test-secret-key-0123456789abcdef",
		RPC:       wrapped,
		Store:     core.NewMemoryStore(),
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	challenge, err := handler.Charge(context.Background(), "0.001")
	if err != nil {
		t.Fatalf("charge: %v", err)
	}
	payer := testutil.NewPrivateKey()
	encoded := buildSOLPullTransaction(t, payer, recipient.PublicKey(), 1_000_000, rpcClient.Blockhash)
	credential, err := core.NewPaymentCredential(challenge.ToEcho(), map[string]string{
		"type":        "transaction",
		"transaction": encoded,
	})
	if err != nil {
		t.Fatalf("credential: %v", err)
	}
	if _, err := verifyCredentialEchoed(handler, context.Background(), credential); err == nil {
		t.Fatal("expected send error")
	}
}

// rpcGetTxErr fails on GetTransaction to exercise verifyOnChain not-found.
type rpcGetTxErr struct{ *testutil.FakeRPC }

func (r *rpcGetTxErr) GetTransaction(_ context.Context, _ solana.Signature, _ *rpc.GetTransactionOpts) (*rpc.GetTransactionResult, error) {
	return nil, errors.New("not found")
}

func TestVerifyOnChainTransactionNotFound(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	wrapped := &rpcGetTxErr{FakeRPC: rpcClient}
	recipient := testutil.NewPrivateKey()
	handler, err := New(Config{
		Recipient: recipient.PublicKey().String(),
		Currency:  "sol",
		Decimals:  9,
		Network:   "localnet",
		SecretKey: "test-secret-key-0123456789abcdef",
		RPC:       wrapped,
		Store:     core.NewMemoryStore(),
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	challenge, err := handler.Charge(context.Background(), "0.001")
	if err != nil {
		t.Fatalf("charge: %v", err)
	}
	// Use signature payload path to skip simulate+send.
	credential, err := core.NewPaymentCredential(challenge.ToEcho(), map[string]string{
		"type":      "signature",
		"signature": "5jKh25biPsnrmLWXXuqKNH2Q67Q4UmVVx8Gf2wrS6VoCeyfGE9wKikjY7Q1GQQgmpQ3xy7wJX5U1rcz82q4R8Nkv",
	})
	if err != nil {
		t.Fatalf("credential: %v", err)
	}
	if _, err := verifyCredentialEchoed(handler, context.Background(), credential); err == nil {
		t.Fatal("expected transaction not found error")
	}
}

// errStore is a Store implementation that errors on PutIfAbsent.
type errStore struct{}

func (errStore) PutIfAbsent(_ context.Context, _ string, _ any) (bool, error) {
	return false, errors.New("store down")
}
func (errStore) Get(_ context.Context, _ string) (json.RawMessage, bool, error) {
	return nil, false, nil
}
func (errStore) Put(_ context.Context, _ string, _ any) error { return nil }
func (errStore) Delete(_ context.Context, _ string) error     { return nil }

func TestVerifyTransactionStoreError(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	recipient := testutil.NewPrivateKey()
	handler, err := New(Config{
		Recipient: recipient.PublicKey().String(),
		Currency:  "sol",
		Decimals:  9,
		Network:   "localnet",
		SecretKey: "test-secret-key-0123456789abcdef",
		RPC:       rpcClient,
		Store:     errStore{},
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	challenge, err := handler.Charge(context.Background(), "0.001")
	if err != nil {
		t.Fatalf("charge: %v", err)
	}
	payer := testutil.NewPrivateKey()
	encoded := buildSOLPullTransaction(t, payer, recipient.PublicKey(), 1_000_000, rpcClient.Blockhash)
	credential, err := core.NewPaymentCredential(challenge.ToEcho(), map[string]string{
		"type":        "transaction",
		"transaction": encoded,
	})
	if err != nil {
		t.Fatalf("credential: %v", err)
	}
	if _, err := verifyCredentialEchoed(handler, context.Background(), credential); err == nil {
		t.Fatal("expected store error")
	}
}

func TestVerifyTransactionMissingPrimarySignature(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	recipient := testutil.NewPrivateKey()
	handler, err := New(Config{
		Recipient: recipient.PublicKey().String(),
		Currency:  "sol",
		Decimals:  9,
		Network:   "localnet",
		SecretKey: "test-secret-key-0123456789abcdef",
		RPC:       rpcClient,
		Store:     core.NewMemoryStore(),
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	challenge, err := handler.Charge(context.Background(), "0.001")
	if err != nil {
		t.Fatalf("charge: %v", err)
	}
	payer := testutil.NewPrivateKey()
	ix, _ := solanatx.BuildSOLTransfer(payer.PublicKey(), recipient.PublicKey(), 1_000_000)
	tx, _ := solana.NewTransaction([]solana.Instruction{ix}, rpcClient.Blockhash, solana.TransactionPayer(payer.PublicKey()))
	// Intentionally do NOT sign — zero signatures slot remains, primary is zero.
	tx.Signatures = []solana.Signature{{}}
	encoded, _ := solanatx.EncodeTransactionBase64(tx)
	credential, err := core.NewPaymentCredential(challenge.ToEcho(), map[string]string{
		"type":        "transaction",
		"transaction": encoded,
	})
	if err != nil {
		t.Fatalf("credential: %v", err)
	}
	if _, err := verifyCredentialEchoed(handler, context.Background(), credential); err == nil {
		t.Fatal("expected missing primary signature error")
	}
}

func TestVerifyTransactionWrongNetworkBlockhash(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	recipient := testutil.NewPrivateKey()
	handler, err := New(Config{
		Recipient: recipient.PublicKey().String(),
		Currency:  "sol",
		Decimals:  9,
		Network:   "mainnet",
		SecretKey: "test-secret-key-0123456789abcdef",
		RPC:       rpcClient,
		Store:     core.NewMemoryStore(),
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	// Surfpool-style blockhash should be rejected on mainnet.
	surfpool := "Surfpoo1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
	hash, herr := solana.HashFromBase58(surfpool)
	if herr != nil {
		t.Skip("surfpool hash not a valid base58 hash; skipping")
	}
	payer := testutil.NewPrivateKey()
	encoded := buildSOLPullTransaction(t, payer, recipient.PublicKey(), 1_000_000, hash)
	challenge, err := handler.Charge(context.Background(), "0.001")
	if err != nil {
		t.Fatalf("charge: %v", err)
	}
	credential, err := core.NewPaymentCredential(challenge.ToEcho(), map[string]string{
		"type":        "transaction",
		"transaction": encoded,
	})
	if err != nil {
		t.Fatalf("credential: %v", err)
	}
	if _, err := verifyCredentialEchoed(handler, context.Background(), credential); err == nil {
		t.Fatal("expected wrong network error")
	}
}

// reference time and httptest to silence unused imports
var _ = time.Now
var _ = httptest.NewRecorder
var _ http.Handler = (http.HandlerFunc)(nil)
var _ = solanatx.SplitAmounts
var _ = paycore.MemoProgram

// --- merged from server_more_branch_test.go ---

func TestFormatAmountDisplayLongUnknownCurrencyTruncates(t *testing.T) {
	out := formatAmountDisplay("1000000", "SUPERLONGCURRENCYNAME", 6)
	if !strings.Contains(out, "SUPERL") {
		t.Fatalf("expected truncated currency label, got %q", out)
	}
	if strings.Contains(out, "SUPERLO") {
		t.Fatalf("expected currency label truncated to 6 chars, got %q", out)
	}
}

func TestFormatAmountDisplayInvalidNumberRendersZero(t *testing.T) {
	out := formatAmountDisplay("not-a-number", "USDC", 6)
	if !strings.Contains(out, "$") {
		t.Fatalf("expected stablecoin format on invalid number, got %q", out)
	}
}

func TestFormatAmountDisplaySOLFractional(t *testing.T) {
	out := formatAmountDisplay("500000000", "sol", 9)
	if !strings.Contains(out, "SOL") {
		t.Fatalf("expected SOL label, got %q", out)
	}
}

func TestMarkAuthorizationBoundResponseExistingVary(t *testing.T) {
	h := http.Header{}
	h.Set("Vary", "Accept, Authorization")
	markAuthorizationBoundResponse(h)
	values := h.Values("Vary")
	if len(values) != 1 {
		t.Fatalf("expected Vary preserved, got %v", values)
	}
}

func TestMarkAuthorizationBoundResponseWildcardVary(t *testing.T) {
	h := http.Header{}
	h.Set("Vary", "*")
	markAuthorizationBoundResponse(h)
	if got := h.Values("Vary"); len(got) != 1 || got[0] != "*" {
		t.Fatalf("expected wildcard Vary preserved, got %v", got)
	}
}

func TestVerifyTransfersToken2022Path(t *testing.T) {
	payer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey()
	mint := testutil.NewPrivateKey().PublicKey()
	t2022 := solana.MustPublicKeyFromBase58(paycore.Token2022Program)

	sourceATA, _ := solanatx.FindAssociatedTokenAddressWithProgram(payer.PublicKey(), mint, t2022)
	recipientATA, _ := solanatx.FindAssociatedTokenAddressWithProgram(recipient, mint, t2022)

	primaryIx, err := token2022.NewTransferCheckedInstruction(
		1000, 6, sourceATA, mint, recipientATA, payer.PublicKey(), nil,
	).ValidateAndBuild()
	if err != nil {
		t.Fatalf("build token2022 transfer failed: %v", err)
	}
	tx := newTestTransaction(t, payer, primaryIx)
	err = verifyTransfersAgainstChallenge(tx, 1000, mint.String(), recipient, "", paycore.MethodDetails{
		TokenProgram: paycore.Token2022Program,
	})
	if err != nil {
		t.Fatalf("expected token2022 verify to pass, got: %v", err)
	}
}

func TestVerifyTransfersToken2022WrongMint(t *testing.T) {
	payer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey()
	mint := testutil.NewPrivateKey().PublicKey()
	wrongMint := testutil.NewPrivateKey().PublicKey()
	t2022 := solana.MustPublicKeyFromBase58(paycore.Token2022Program)

	sourceATA, _ := solanatx.FindAssociatedTokenAddressWithProgram(payer.PublicKey(), wrongMint, t2022)
	recipientATA, _ := solanatx.FindAssociatedTokenAddressWithProgram(recipient, wrongMint, t2022)

	primaryIx, err := token2022.NewTransferCheckedInstruction(
		1000, 6, sourceATA, wrongMint, recipientATA, payer.PublicKey(), nil,
	).ValidateAndBuild()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	tx := newTestTransaction(t, payer, primaryIx)
	if err := verifyTransfersAgainstChallenge(tx, 1000, mint.String(), recipient, "", paycore.MethodDetails{
		TokenProgram: paycore.Token2022Program,
	}); err == nil {
		t.Fatal("expected mint-mismatch failure")
	}
}

func TestBuildExpectedTransfersInvalidSplitAmount(t *testing.T) {
	_, err := buildExpectedTransfers(1000, testutil.NewPrivateKey().PublicKey(), paycore.MethodDetails{
		Splits: []paycore.Split{{Recipient: testutil.NewPrivateKey().PublicKey().String(), Amount: "not-a-number"}},
	})
	if err == nil {
		t.Fatal("expected invalid split amount error")
	}
}

func TestBuildExpectedTransfersInvalidSplitRecipient(t *testing.T) {
	_, err := buildExpectedTransfers(1000, testutil.NewPrivateKey().PublicKey(), paycore.MethodDetails{
		Splits: []paycore.Split{{Recipient: "bad-key", Amount: "100"}},
	})
	if err == nil {
		t.Fatal("expected invalid split recipient error")
	}
}

func TestBuildExpectedTransfersSplitsExceedTotal(t *testing.T) {
	_, err := buildExpectedTransfers(100, testutil.NewPrivateKey().PublicKey(), paycore.MethodDetails{
		Splits: []paycore.Split{{Recipient: testutil.NewPrivateKey().PublicKey().String(), Amount: "200"}},
	})
	if err == nil {
		t.Fatal("expected splits-exceed error")
	}
}

func TestVerifyMemoInstructionsTooLong(t *testing.T) {
	payer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey()
	ix, _ := solanatx.BuildSOLTransfer(payer.PublicKey(), recipient, 1)
	tx := newTestTransaction(t, payer, ix)
	matched := make([]bool, len(tx.Message.Instructions))
	err := verifyMemoInstructions(tx, matched, strings.Repeat("x", 600), nil)
	if err == nil {
		t.Fatal("expected memo too long error")
	}
}

// Middleware: marshal challenge JSON error is unreachable (challenge is always
// marshalable). Test that PaymentMiddleware writes JSON on plain Accept header.
func TestPaymentMiddlewareWritesJSON402(t *testing.T) {
	handler, _, _ := newTestMpp(t)
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mw := PaymentMiddleware(handler, func(_ *http.Request) (string, ChargeOptions, error) {
		return "0.001", ChargeOptions{}, nil
	})(next)
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, req)
	if w.Code != http.StatusPaymentRequired {
		t.Fatalf("expected 402, got %d", w.Code)
	}
	if !strings.Contains(w.Header().Get("Content-Type"), "json") {
		t.Fatalf("expected JSON content type, got %q", w.Header().Get("Content-Type"))
	}
}

func TestPaymentMiddlewareReceiptFromContextAbsent(t *testing.T) {
	if _, ok := ReceiptFromContext(context.Background()); ok {
		t.Fatal("expected no receipt in fresh context")
	}
}

// Reference mpp to silence unused import in some configurations.
var _ = core.AuthorizationHeader
