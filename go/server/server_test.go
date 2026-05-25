package server

import (
	"context"
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	solana "github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/programs/token"
	token2022 "github.com/gagliardetto/solana-go/programs/token-2022"

	mpp "github.com/solana-foundation/pay-kit/go"
	"github.com/solana-foundation/pay-kit/go/client"
	"github.com/solana-foundation/pay-kit/go/internal/testutil"
	"github.com/solana-foundation/pay-kit/go/internal/utils"
	"github.com/solana-foundation/pay-kit/go/protocol"
	"github.com/solana-foundation/pay-kit/go/protocol/intents"
)

func newTestMpp(t *testing.T) (*Mpp, *testutil.FakeRPC, testutilConfig) {
	t.Helper()
	rpcClient := testutil.NewFakeRPC()
	recipientSigner := testutil.NewPrivateKey()
	cfg := testutilConfig{
		Recipient: recipientSigner.PublicKey().String(),
		Client:    testutil.NewPrivateKey(),
		SecretKey: "test-secret",
	}
	handler, err := New(Config{
		Recipient: cfg.Recipient,
		Currency:  "sol",
		Decimals:  9,
		Network:   "localnet",
		SecretKey: cfg.SecretKey,
		RPC:       rpcClient,
		Store:     mpp.NewMemoryStore(),
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
	credential, err := mpp.ParseAuthorization(authHeader)
	if err != nil {
		t.Fatalf("parse authorization failed: %v", err)
	}
	receipt, err := handler.VerifyCredential(context.Background(), credential)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if receipt.Status != mpp.ReceiptStatusSuccess || receipt.Reference == "" {
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
	credential, err := mpp.ParseAuthorization(authHeader)
	if err != nil {
		t.Fatalf("parse authorization failed: %v", err)
	}
	if _, err := handler.VerifyCredential(context.Background(), credential); err != nil {
		t.Fatalf("first verify failed: %v", err)
	}
	if _, err := handler.VerifyCredential(context.Background(), credential); err == nil {
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
	credential, err := mpp.ParseAuthorization(authHeader)
	if err != nil {
		t.Fatalf("parse authorization failed: %v", err)
	}
	if _, err := handler.VerifyCredential(context.Background(), credential); err != nil {
		t.Fatalf("first verify failed: %v", err)
	}
	if _, err := handler.VerifyCredential(context.Background(), credential); err == nil {
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
		SecretKey:      "test-secret",
		RPC:            rpcClient,
		Store:          mpp.NewMemoryStore(),
		FeePayerSigner: feePayer,
	})
	if err != nil {
		t.Fatalf("new mpp failed: %v", err)
	}
	challenge, err := handler.Charge(context.Background(), "0.001")
	if err != nil {
		t.Fatalf("charge failed: %v", err)
	}
	credential, err := mpp.NewPaymentCredential(challenge.ToEcho(), map[string]string{
		"type":      "signature",
		"signature": "5jKh25biPsnrmLWXXuqKNH2Q67Q4UmVVx8Gf2wrS6VoCeyfGE9wKikjY7Q1GQQgmpQ3xy7wJX5U1rcz82q4R8Nkv",
	})
	if err != nil {
		t.Fatalf("credential failed: %v", err)
	}
	if _, err := handler.VerifyCredential(context.Background(), credential); err == nil {
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
		Recipient: recipient.PublicKey().String(),
		Currency:  mint.String(),
		Decimals:  6,
		Network:   "localnet",
		SecretKey: "test-secret",
		RPC:       rpcClient,
		Store:     mpp.NewMemoryStore(),
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
	credential, err := mpp.ParseAuthorization(authHeader)
	if err != nil {
		t.Fatalf("parse authorization failed: %v", err)
	}
	receipt, err := handler.VerifyCredential(context.Background(), credential)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if receipt.Status != mpp.ReceiptStatusSuccess {
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
		Recipient: recipient.PublicKey().String(),
		Currency:  "USDC",
		Decimals:  6,
		Network:   "localnet",
		SecretKey: "test-secret",
		RPC:       rpcClient,
		Store:     mpp.NewMemoryStore(),
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
	credential, err := mpp.ParseAuthorization(authHeader)
	if err != nil {
		t.Fatalf("parse authorization failed: %v", err)
	}
	receipt, err := handler.VerifyCredential(context.Background(), credential)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if receipt.Status != mpp.ReceiptStatusSuccess {
		t.Fatalf("unexpected receipt: %#v", receipt)
	}
}

func TestVerifyTransfersAgainstChallengeDuplicateSOLSplitsRequireDistinctInstructions(t *testing.T) {
	payer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey()
	splitRecipient := testutil.NewPrivateKey().PublicKey()

	primaryIx, err := utils.BuildSOLTransfer(payer.PublicKey(), recipient, 800)
	if err != nil {
		t.Fatalf("build primary transfer failed: %v", err)
	}
	splitIx, err := utils.BuildSOLTransfer(payer.PublicKey(), splitRecipient, 100)
	if err != nil {
		t.Fatalf("build split transfer failed: %v", err)
	}

	tx := newTestTransaction(t, payer, primaryIx, splitIx)
	err = verifyTransfersAgainstChallenge(tx, 1000, "sol", recipient, "", protocol.MethodDetails{
		Splits: []protocol.Split{
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

	primaryIx, err := utils.BuildSOLTransfer(payer.PublicKey(), recipient, 800)
	if err != nil {
		t.Fatalf("build primary transfer failed: %v", err)
	}
	splitIx, err := utils.BuildSOLTransfer(payer.PublicKey(), recipient, 200)
	if err != nil {
		t.Fatalf("build split transfer failed: %v", err)
	}

	tx := newTestTransaction(t, payer, primaryIx, splitIx)
	if err := verifyTransfersAgainstChallenge(tx, 1000, "sol", recipient, "", protocol.MethodDetails{
		Splits: []protocol.Split{{Recipient: recipient.String(), Amount: "200"}},
	}); err != nil {
		t.Fatalf("expected same-recipient SOL transfers to pass: %v", err)
	}
}

func TestVerifyTransfersAgainstChallengeAcceptsSOLExternalIDMemo(t *testing.T) {
	payer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey()

	primaryIx, err := utils.BuildSOLTransfer(payer.PublicKey(), recipient, 1000)
	if err != nil {
		t.Fatalf("build primary transfer failed: %v", err)
	}
	memoIx, err := utils.BuildMemoInstruction("order-123")
	if err != nil {
		t.Fatalf("build memo failed: %v", err)
	}

	tx := newTestTransaction(t, payer, primaryIx, memoIx)
	if err := verifyTransfersAgainstChallenge(tx, 1000, "sol", recipient, "order-123", protocol.MethodDetails{}); err != nil {
		t.Fatalf("expected SOL externalId memo to pass: %v", err)
	}
}

func TestVerifyTransfersAgainstChallengeRejectsMissingSOLExternalIDMemo(t *testing.T) {
	payer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey()

	primaryIx, err := utils.BuildSOLTransfer(payer.PublicKey(), recipient, 1000)
	if err != nil {
		t.Fatalf("build primary transfer failed: %v", err)
	}

	tx := newTestTransaction(t, payer, primaryIx)
	if err := verifyTransfersAgainstChallenge(tx, 1000, "sol", recipient, "order-123", protocol.MethodDetails{}); err == nil {
		t.Fatal("expected missing SOL externalId memo to fail")
	}
}

func TestVerifyTransfersAgainstChallengeRejectsUnexpectedSOLMemo(t *testing.T) {
	payer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey()

	primaryIx, err := utils.BuildSOLTransfer(payer.PublicKey(), recipient, 1000)
	if err != nil {
		t.Fatalf("build primary transfer failed: %v", err)
	}
	memoIx, err := utils.BuildMemoInstruction("unexpected")
	if err != nil {
		t.Fatalf("build memo failed: %v", err)
	}

	tx := newTestTransaction(t, payer, primaryIx, memoIx)
	if err := verifyTransfersAgainstChallenge(tx, 1000, "sol", recipient, "", protocol.MethodDetails{}); err == nil {
		t.Fatal("expected unexpected SOL memo to fail")
	}
}

func TestVerifyTransfersAgainstChallengeAcceptsSOLSplitMemo(t *testing.T) {
	payer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey()
	splitRecipient := testutil.NewPrivateKey().PublicKey()

	primaryIx, err := utils.BuildSOLTransfer(payer.PublicKey(), recipient, 800)
	if err != nil {
		t.Fatalf("build primary transfer failed: %v", err)
	}
	splitIx, err := utils.BuildSOLTransfer(payer.PublicKey(), splitRecipient, 200)
	if err != nil {
		t.Fatalf("build split transfer failed: %v", err)
	}
	memoIx, err := utils.BuildMemoInstruction("platform fee")
	if err != nil {
		t.Fatalf("build memo failed: %v", err)
	}

	tx := newTestTransaction(t, payer, primaryIx, splitIx, memoIx)
	if err := verifyTransfersAgainstChallenge(tx, 1000, "sol", recipient, "", protocol.MethodDetails{
		Splits: []protocol.Split{{Recipient: splitRecipient.String(), Amount: "200", Memo: "platform fee"}},
	}); err != nil {
		t.Fatalf("expected SOL split memo to pass: %v", err)
	}
}

func TestVerifyTransfersAgainstChallengeSameRecipientSPLSplitsMatchByAmount(t *testing.T) {
	payer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey()
	mint := testutil.NewPrivateKey().PublicKey()

	sourceATA, err := utils.FindAssociatedTokenAddressWithProgram(payer.PublicKey(), mint, solana.TokenProgramID)
	if err != nil {
		t.Fatalf("find source ata failed: %v", err)
	}
	recipientATA, err := utils.FindAssociatedTokenAddressWithProgram(recipient, mint, solana.TokenProgramID)
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
	if err := verifyTransfersAgainstChallenge(tx, 1000, mint.String(), recipient, "", protocol.MethodDetails{
		Splits: []protocol.Split{{Recipient: recipient.String(), Amount: "200"}},
	}); err != nil {
		t.Fatalf("expected same-recipient SPL transfers to pass: %v", err)
	}
}

func TestVerifyTransfersAgainstChallengeAcceptsSPLExternalIDMemo(t *testing.T) {
	payer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey()
	mint := testutil.NewPrivateKey().PublicKey()

	sourceATA, err := utils.FindAssociatedTokenAddressWithProgram(payer.PublicKey(), mint, solana.TokenProgramID)
	if err != nil {
		t.Fatalf("find source ata failed: %v", err)
	}
	recipientATA, err := utils.FindAssociatedTokenAddressWithProgram(recipient, mint, solana.TokenProgramID)
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
	memoIx, err := utils.BuildMemoInstruction("order-123")
	if err != nil {
		t.Fatalf("build memo failed: %v", err)
	}

	tx := newTestTransaction(t, payer, primaryIx, memoIx)
	if err := verifyTransfersAgainstChallenge(tx, 1000, mint.String(), recipient, "order-123", protocol.MethodDetails{}); err != nil {
		t.Fatalf("expected SPL externalId memo to pass: %v", err)
	}
}

func TestVerifyTransfersAgainstChallengeRejectsWrongSPLMint(t *testing.T) {
	payer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey()
	mint := testutil.NewPrivateKey().PublicKey()
	wrongMint := testutil.NewPrivateKey().PublicKey()

	sourceATA, err := utils.FindAssociatedTokenAddressWithProgram(payer.PublicKey(), wrongMint, solana.TokenProgramID)
	if err != nil {
		t.Fatalf("find source ata failed: %v", err)
	}
	recipientATA, err := utils.FindAssociatedTokenAddressWithProgram(recipient, wrongMint, solana.TokenProgramID)
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
	if err := verifyTransfersAgainstChallenge(tx, 1000, mint.String(), recipient, "", protocol.MethodDetails{}); err == nil {
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
	credential, err := mpp.NewPaymentCredential(challenge.ToEcho(), map[string]string{
		"type":      "signature",
		"signature": testutil.NewPrivateKey().PublicKey().String(),
	})
	if err != nil {
		t.Fatalf("credential failed: %v", err)
	}
	if _, err := handler.VerifyCredential(context.Background(), credential); err == nil {
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
	t.Setenv("MPP_SECRET_KEY", "env-secret")
	recipient := testutil.NewPrivateKey().PublicKey().String()
	rpcClient := testutil.NewFakeRPC()
	handler, err := New(Config{Recipient: recipient, RPC: rpcClient})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if handler.secretKey != "env-secret" {
		t.Fatalf("expected env secret, got %q", handler.secretKey)
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
		SecretKey: "test-secret",
		RPC:       rpcClient,
		Store:     mpp.NewMemoryStore(),
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
	challenge, err := handler.ChargeWithOptions(context.Background(), "1.00", ChargeOptions{
		Splits: []protocol.Split{
			{Recipient: "VendorPayoutsWaLLetxxxxxxxxxxxxxxxxxxxxxx1111", Amount: "500000", Memo: "Vendor payout"},
			{Recipient: "ProcessorFeeWaLLetxxxxxxxxxxxxxxxxxxxxxxx1111", Amount: "29000"},
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
	credential, err := mpp.NewPaymentCredential(challenge.ToEcho(), map[string]string{
		"type": "",
	})
	if err != nil {
		t.Fatalf("credential failed: %v", err)
	}
	if _, err := handler.VerifyCredential(context.Background(), credential); err == nil {
		t.Fatal("expected error for missing payload type")
	}
}

func TestVerifyCredentialMissingTransactionData(t *testing.T) {
	handler, _, _ := newTestMpp(t)
	challenge, _ := handler.Charge(context.Background(), "0.001")
	credential, err := mpp.NewPaymentCredential(challenge.ToEcho(), map[string]string{
		"type":        "transaction",
		"transaction": "",
	})
	if err != nil {
		t.Fatalf("credential failed: %v", err)
	}
	if _, err := handler.VerifyCredential(context.Background(), credential); err == nil {
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
	credential, _ := mpp.ParseAuthorization(authHeader)
	// Make simulation fail
	rpcClient.SimulateErr = fmt.Errorf("simulation failed")
	if _, err := handler.VerifyCredential(context.Background(), credential); err == nil {
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
	credential, _ := mpp.ParseAuthorization(authHeader)
	rpcClient.SendErr = fmt.Errorf("send failed")
	if _, err := handler.VerifyCredential(context.Background(), credential); err == nil {
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
		SecretKey: "test-secret",
		RPC:       rpcClient,
		Store:     mpp.NewMemoryStore(),
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
	credential, _ := mpp.ParseAuthorization(authHeader)
	// Make GetTransaction fail
	rpcClient.GetTxErr = fmt.Errorf("transaction not found")
	if _, err := handler.VerifyCredential(context.Background(), credential); err == nil {
		t.Fatal("expected error for get transaction failure")
	}
}

func TestVerifyCredentialMissingSignature(t *testing.T) {
	handler, _, _ := newTestMpp(t)
	challenge, _ := handler.Charge(context.Background(), "0.001")
	credential, err := mpp.NewPaymentCredential(challenge.ToEcho(), map[string]string{
		"type":      "signature",
		"signature": "",
	})
	if err != nil {
		t.Fatalf("credential failed: %v", err)
	}
	if _, err := handler.VerifyCredential(context.Background(), credential); err == nil {
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
		SecretKey:      "test-secret",
		RPC:            rpcClient,
		Store:          mpp.NewMemoryStore(),
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
		SecretKey: "test-secret",
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
	if handler.network != "mainnet-beta" {
		t.Fatalf("expected default network mainnet-beta, got %q", handler.network)
	}
}

func TestChargeKnownStablecoinTokenPrograms(t *testing.T) {
	for _, tt := range []struct {
		currency string
		want     string
	}{
		{currency: "USDC", want: protocol.TokenProgram},
		{currency: "USDT", want: protocol.TokenProgram},
		{currency: "PYUSD", want: protocol.Token2022Program},
		{currency: "USDG", want: protocol.Token2022Program},
		{currency: "CASH", want: protocol.Token2022Program},
	} {
		rpcClient := testutil.NewFakeRPC()
		handler, err := New(Config{
			Recipient: testutil.NewPrivateKey().PublicKey().String(),
			Currency:  tt.currency,
			Decimals:  6,
			Network:   "mainnet-beta",
			SecretKey: "test-secret",
			RPC:       rpcClient,
			Store:     mpp.NewMemoryStore(),
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
		SecretKey: "test-secret",
		RPC:       rpcClient,
		Store:     mpp.NewMemoryStore(),
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
	credential, _ := mpp.ParseAuthorization(authHeader)
	receipt, err := handler.VerifyCredential(context.Background(), credential)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if receipt.Status != mpp.ReceiptStatusSuccess {
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
	credential, _ := mpp.ParseAuthorization(authHeader)
	receipt, err := handler.VerifyCredential(context.Background(), credential)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if receipt.Status != mpp.ReceiptStatusSuccess || receipt.Reference == "" {
		t.Fatalf("unexpected receipt: %#v", receipt)
	}
}

func TestRPCURL(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	recipient := testutil.NewPrivateKey().PublicKey().String()
	handler, err := New(Config{
		Recipient: recipient,
		SecretKey: "secret",
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
		SecretKey:      "test-secret",
		RPC:            rpcClient,
		Store:          mpp.NewMemoryStore(),
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
	credential, _ := mpp.ParseAuthorization(authHeader)
	receipt, err := handler.VerifyCredential(context.Background(), credential)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if receipt.Status != mpp.ReceiptStatusSuccess {
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
		SecretKey:      "test-secret",
		RPC:            rpcClient,
		Store:          mpp.NewMemoryStore(),
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
	credential, err := mpp.ParseAuthorization(authHeader)
	if err != nil {
		t.Fatalf("parse authorization failed: %v", err)
	}
	var payload protocol.CredentialPayload
	if err := credential.PayloadAs(&payload); err != nil {
		t.Fatalf("decode credential payload: %v", err)
	}
	tx, err := utils.DecodeTransactionBase64(payload.Transaction)
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
	rebuiltEncoded, err := utils.EncodeTransactionBase64(tx)
	if err != nil {
		t.Fatalf("re-encode transaction: %v", err)
	}
	tamperedCredential, err := mpp.NewPaymentCredential(credential.Challenge, map[string]string{
		"type":        "transaction",
		"transaction": rebuiltEncoded,
	})
	if err != nil {
		t.Fatalf("rebuild credential: %v", err)
	}
	if _, err := handler.VerifyCredential(context.Background(), tamperedCredential); err == nil {
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
	request, _ := mpp.NewBase64URLJSONValue(map[string]any{
		"amount":    "1000",
		"currency":  "sol",
		"recipient": testutil.NewPrivateKey().PublicKey().String(),
	})
	challenge := mpp.NewChallengeWithSecret("wrong-secret", "realm", "solana", "charge", request)
	credential, err := mpp.NewPaymentCredential(challenge.ToEcho(), map[string]string{
		"type":      "signature",
		"signature": testutil.NewPrivateKey().PublicKey().String(),
	})
	if err != nil {
		t.Fatalf("credential failed: %v", err)
	}
	if _, err := handler.VerifyCredential(context.Background(), credential); err == nil {
		t.Fatal("expected challenge mismatch to fail")
	}
}

func TestVerifyTransfersAgainstChallengeRejectsMissingSPLSplitMemo(t *testing.T) {
	payer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey()
	splitRecipient := testutil.NewPrivateKey().PublicKey()
	mint := testutil.NewPrivateKey().PublicKey()

	sourceATA, err := utils.FindAssociatedTokenAddressWithProgram(payer.PublicKey(), mint, solana.TokenProgramID)
	if err != nil {
		t.Fatalf("find source ata failed: %v", err)
	}
	recipientATA, err := utils.FindAssociatedTokenAddressWithProgram(recipient, mint, solana.TokenProgramID)
	if err != nil {
		t.Fatalf("find recipient ata failed: %v", err)
	}
	splitATA, err := utils.FindAssociatedTokenAddressWithProgram(splitRecipient, mint, solana.TokenProgramID)
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
	if err := verifyTransfersAgainstChallenge(tx, 1000, mint.String(), recipient, "", protocol.MethodDetails{
		Splits: []protocol.Split{{Recipient: splitRecipient.String(), Amount: "200", Memo: "platform fee"}},
	}); err == nil {
		t.Fatal("expected missing SPL split memo to fail")
	}
}

func TestVerifyTransfersAgainstChallengeRejectsUnexpectedSPLMemo(t *testing.T) {
	payer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey()
	mint := testutil.NewPrivateKey().PublicKey()

	sourceATA, err := utils.FindAssociatedTokenAddressWithProgram(payer.PublicKey(), mint, solana.TokenProgramID)
	if err != nil {
		t.Fatalf("find source ata failed: %v", err)
	}
	recipientATA, err := utils.FindAssociatedTokenAddressWithProgram(recipient, mint, solana.TokenProgramID)
	if err != nil {
		t.Fatalf("find recipient ata failed: %v", err)
	}

	primaryIx, err := token.NewTransferCheckedInstruction(1000, 6, sourceATA, mint, recipientATA, payer.PublicKey(), nil).ValidateAndBuild()
	if err != nil {
		t.Fatalf("build primary transfer failed: %v", err)
	}
	memoIx, err := utils.BuildMemoInstruction("unexpected")
	if err != nil {
		t.Fatalf("build memo failed: %v", err)
	}

	tx := newTestTransaction(t, payer, primaryIx, memoIx)
	if err := verifyTransfersAgainstChallenge(tx, 1000, mint.String(), recipient, "", protocol.MethodDetails{}); err == nil {
		t.Fatal("expected unexpected SPL memo to fail")
	}
}

func TestVerifyTransfersAgainstChallengeAcceptsToken2022Transfer(t *testing.T) {
	payer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey()
	mint := testutil.NewPrivateKey().PublicKey()
	tokenProgram := solana.MustPublicKeyFromBase58(protocol.Token2022Program)

	sourceATA, err := utils.FindAssociatedTokenAddressWithProgram(payer.PublicKey(), mint, tokenProgram)
	if err != nil {
		t.Fatalf("find source ata failed: %v", err)
	}
	recipientATA, err := utils.FindAssociatedTokenAddressWithProgram(recipient, mint, tokenProgram)
	if err != nil {
		t.Fatalf("find recipient ata failed: %v", err)
	}
	ix, err := token2022.NewTransferCheckedInstruction(1000, 6, sourceATA, mint, recipientATA, payer.PublicKey(), nil).ValidateAndBuild()
	if err != nil {
		t.Fatalf("build transfer failed: %v", err)
	}

	tx := newTestTransaction(t, payer, ix)
	if err := verifyTransfersAgainstChallenge(tx, 1000, mint.String(), recipient, "", protocol.MethodDetails{
		TokenProgram: protocol.Token2022Program,
	}); err != nil {
		t.Fatalf("expected token2022 transfer to pass: %v", err)
	}
}

func TestBuildExpectedTransfersRejectsInvalidSplitFields(t *testing.T) {
	recipient := testutil.NewPrivateKey().PublicKey()
	if _, err := buildExpectedTransfers(1000, recipient, protocol.MethodDetails{
		Splits: []protocol.Split{{Recipient: testutil.NewPrivateKey().PublicKey().String(), Amount: "not-a-number"}},
	}); err == nil {
		t.Fatal("expected invalid split amount to fail")
	}
	if _, err := buildExpectedTransfers(1000, recipient, protocol.MethodDetails{
		Splits: []protocol.Split{{Recipient: "not-a-pubkey", Amount: "100"}},
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
	credential, err := mpp.NewPaymentCredential(challenge.ToEcho(), map[string]string{
		"type": "voucher",
	})
	if err != nil {
		t.Fatalf("credential failed: %v", err)
	}
	if _, err := handler.VerifyCredential(context.Background(), credential); err == nil {
		t.Fatal("expected invalid payload type to fail")
	}
}

func TestVerifyCredentialWithExpectedRejectsInvalidExpectedMethodDetails(t *testing.T) {
	handler, _, _ := newTestMpp(t)
	challenge, err := handler.Charge(context.Background(), "0.001")
	if err != nil {
		t.Fatalf("charge failed: %v", err)
	}
	credential, err := mpp.NewPaymentCredential(challenge.ToEcho(), map[string]string{
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
	credential, err := mpp.NewPaymentCredential(challenge.ToEcho(), map[string]string{
		"type":        "transaction",
		"transaction": "not-base64",
	})
	if err != nil {
		t.Fatalf("credential failed: %v", err)
	}
	if _, err := handler.VerifyCredential(context.Background(), credential); err == nil {
		t.Fatal("expected error for malformed transaction data")
	}
}
