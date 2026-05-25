package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	solana "github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"

	mpp "github.com/solana-foundation/pay-kit/go"
	"github.com/solana-foundation/pay-kit/go/internal/solanautil"
	"github.com/solana-foundation/pay-kit/go/internal/testutil"
	"github.com/solana-foundation/pay-kit/go/protocol"
	"github.com/solana-foundation/pay-kit/go/protocol/intents"
)

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
	credential, err := mpp.NewPaymentCredential(challenge.ToEcho(), map[string]string{
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
	credential, err := mpp.NewPaymentCredential(challenge.ToEcho(), map[string]string{
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
	credential, err := mpp.NewPaymentCredential(challenge.ToEcho(), map[string]string{
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
	credential, err := mpp.NewPaymentCredential(challenge.ToEcho(), map[string]string{
		"type":        "transaction",
		"transaction": "",
	})
	if err != nil {
		t.Fatalf("credential: %v", err)
	}
	if _, err := handler.VerifyCredential(context.Background(), credential); err == nil {
		t.Fatal("expected missing transaction error")
	}
}

func TestVerifyTransactionInvalidBase64(t *testing.T) {
	handler, _, _ := newTestMpp(t)
	challenge, err := handler.Charge(context.Background(), "0.001")
	if err != nil {
		t.Fatalf("charge: %v", err)
	}
	credential, err := mpp.NewPaymentCredential(challenge.ToEcho(), map[string]string{
		"type":        "transaction",
		"transaction": "!!!not-base64!!!",
	})
	if err != nil {
		t.Fatalf("credential: %v", err)
	}
	if _, err := handler.VerifyCredential(context.Background(), credential); err == nil {
		t.Fatal("expected invalid base64 error")
	}
}

func TestVerifyTransactionUnknownPayloadType(t *testing.T) {
	handler, _, _ := newTestMpp(t)
	challenge, err := handler.Charge(context.Background(), "0.001")
	if err != nil {
		t.Fatalf("charge: %v", err)
	}
	credential, err := mpp.NewPaymentCredential(challenge.ToEcho(), map[string]string{
		"type": "unknown",
	})
	if err != nil {
		t.Fatalf("credential: %v", err)
	}
	if _, err := handler.VerifyCredential(context.Background(), credential); err == nil {
		t.Fatal("expected invalid payload type error")
	}
}

func TestVerifySignatureMissingSignature(t *testing.T) {
	handler, _, _ := newTestMpp(t)
	challenge, err := handler.Charge(context.Background(), "0.001")
	if err != nil {
		t.Fatalf("charge: %v", err)
	}
	credential, err := mpp.NewPaymentCredential(challenge.ToEcho(), map[string]string{
		"type":      "signature",
		"signature": "",
	})
	if err != nil {
		t.Fatalf("credential: %v", err)
	}
	if _, err := handler.VerifyCredential(context.Background(), credential); err == nil {
		t.Fatal("expected missing signature error")
	}
}

func TestVerifySignatureInvalidSignatureBase58(t *testing.T) {
	handler, _, _ := newTestMpp(t)
	challenge, err := handler.Charge(context.Background(), "0.001")
	if err != nil {
		t.Fatalf("charge: %v", err)
	}
	credential, err := mpp.NewPaymentCredential(challenge.ToEcho(), map[string]string{
		"type":      "signature",
		"signature": "not-a-valid-base58-sig",
	})
	if err != nil {
		t.Fatalf("credential: %v", err)
	}
	if _, err := handler.VerifyCredential(context.Background(), credential); err == nil {
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
	ix, err := solanautil.BuildSOLTransfer(payer.PublicKey(), recipient, lamports)
	if err != nil {
		t.Fatalf("ix: %v", err)
	}
	tx, err := solana.NewTransaction([]solana.Instruction{ix}, blockhash, solana.TransactionPayer(payer.PublicKey()))
	if err != nil {
		t.Fatalf("tx: %v", err)
	}
	if err := solanautil.SignTransaction(tx, payer); err != nil {
		t.Fatalf("sign: %v", err)
	}
	encoded, err := solanautil.EncodeTransactionBase64(tx)
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
		SecretKey: "test-secret",
		RPC:       wrapped,
		Store:     mpp.NewMemoryStore(),
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
	credential, err := mpp.NewPaymentCredential(challenge.ToEcho(), map[string]string{
		"type":        "transaction",
		"transaction": encoded,
	})
	if err != nil {
		t.Fatalf("credential: %v", err)
	}
	if _, err := handler.VerifyCredential(context.Background(), credential); err == nil {
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
		SecretKey: "test-secret",
		RPC:       wrapped,
		Store:     mpp.NewMemoryStore(),
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
	credential, err := mpp.NewPaymentCredential(challenge.ToEcho(), map[string]string{
		"type":        "transaction",
		"transaction": encoded,
	})
	if err != nil {
		t.Fatalf("credential: %v", err)
	}
	if _, err := handler.VerifyCredential(context.Background(), credential); err == nil {
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
		SecretKey: "test-secret",
		RPC:       wrapped,
		Store:     mpp.NewMemoryStore(),
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	challenge, err := handler.Charge(context.Background(), "0.001")
	if err != nil {
		t.Fatalf("charge: %v", err)
	}
	// Use signature payload path to skip simulate+send.
	credential, err := mpp.NewPaymentCredential(challenge.ToEcho(), map[string]string{
		"type":      "signature",
		"signature": "5jKh25biPsnrmLWXXuqKNH2Q67Q4UmVVx8Gf2wrS6VoCeyfGE9wKikjY7Q1GQQgmpQ3xy7wJX5U1rcz82q4R8Nkv",
	})
	if err != nil {
		t.Fatalf("credential: %v", err)
	}
	if _, err := handler.VerifyCredential(context.Background(), credential); err == nil {
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
		SecretKey: "test-secret",
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
	credential, err := mpp.NewPaymentCredential(challenge.ToEcho(), map[string]string{
		"type":        "transaction",
		"transaction": encoded,
	})
	if err != nil {
		t.Fatalf("credential: %v", err)
	}
	if _, err := handler.VerifyCredential(context.Background(), credential); err == nil {
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
		SecretKey: "test-secret",
		RPC:       rpcClient,
		Store:     mpp.NewMemoryStore(),
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	challenge, err := handler.Charge(context.Background(), "0.001")
	if err != nil {
		t.Fatalf("charge: %v", err)
	}
	payer := testutil.NewPrivateKey()
	ix, _ := solanautil.BuildSOLTransfer(payer.PublicKey(), recipient.PublicKey(), 1_000_000)
	tx, _ := solana.NewTransaction([]solana.Instruction{ix}, rpcClient.Blockhash, solana.TransactionPayer(payer.PublicKey()))
	// Intentionally do NOT sign — zero signatures slot remains, primary is zero.
	tx.Signatures = []solana.Signature{{}}
	encoded, _ := solanautil.EncodeTransactionBase64(tx)
	credential, err := mpp.NewPaymentCredential(challenge.ToEcho(), map[string]string{
		"type":        "transaction",
		"transaction": encoded,
	})
	if err != nil {
		t.Fatalf("credential: %v", err)
	}
	if _, err := handler.VerifyCredential(context.Background(), credential); err == nil {
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
		Network:   "mainnet-beta",
		SecretKey: "test-secret",
		RPC:       rpcClient,
		Store:     mpp.NewMemoryStore(),
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
	credential, err := mpp.NewPaymentCredential(challenge.ToEcho(), map[string]string{
		"type":        "transaction",
		"transaction": encoded,
	})
	if err != nil {
		t.Fatalf("credential: %v", err)
	}
	if _, err := handler.VerifyCredential(context.Background(), credential); err == nil {
		t.Fatal("expected wrong network error")
	}
}

// reference time and httptest to silence unused imports
var _ = time.Now
var _ = httptest.NewRecorder
var _ http.Handler = (http.HandlerFunc)(nil)
var _ = solanautil.SplitAmounts
var _ = protocol.MemoProgram
