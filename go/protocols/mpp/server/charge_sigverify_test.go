package server

import (
	"bytes"
	"context"
	"testing"

	solana "github.com/gagliardetto/solana-go"

	"github.com/solana-foundation/pay-kit/go/internal/testutil"
	"github.com/solana-foundation/pay-kit/go/paycore/solanatx"
	"github.com/solana-foundation/pay-kit/go/protocols/mpp/client"
	core "github.com/solana-foundation/pay-kit/go/protocols/mpp/core"
)

// forgedSignature stands in for a signature copied from some other landed
// transaction: 64 bytes that do not sign this message.
func forgedSignature() solana.Signature {
	var sig solana.Signature
	copy(sig[:], bytes.Repeat([]byte{7}, 64))
	return sig
}

func credentialWithTransaction(t *testing.T, credential core.PaymentCredential, tx *solana.Transaction) core.PaymentCredential {
	t.Helper()
	encoded, err := solanatx.EncodeTransactionBase64(tx)
	if err != nil {
		t.Fatalf("encode transaction: %v", err)
	}
	rebuilt, err := core.NewPaymentCredential(credential.Challenge, map[string]string{
		"type":        "transaction",
		"transaction": encoded,
	})
	if err != nil {
		t.Fatalf("rebuild credential: %v", err)
	}
	return rebuilt
}

// assertNothingClaimed checks that no charge state exists under signature:
// no consumed-signature claim and no pending record a retry could reconcile.
func assertNothingClaimed(t *testing.T, handler *Mpp, signature solana.Signature) {
	t.Helper()
	ctx := context.Background()
	if _, found, _ := handler.store.Get(ctx, pendingChargePrefix+signature.String()); found {
		t.Fatalf("a pending record was written under %s", signature)
	}
	claimed, err := handler.consumed().Claim(ctx, signature.String())
	if err != nil {
		t.Fatal(err)
	}
	if !claimed {
		t.Fatalf("signature %s was claimed", signature)
	}
}

// newSponsoredMpp is a handler that co-signs as the fee payer, with a pull
// credential for a fresh challenge signed by a separate client key.
func newSponsoredMpp(t *testing.T) (*Mpp, *testutil.FakeRPC, core.PaymentCredential, *solana.Transaction, solana.PrivateKey) {
	t.Helper()
	rpcClient := testutil.NewFakeRPC()
	feePayer := testutil.NewPrivateKey()
	handler, err := New(core.NewMemoryStore(), Config{
		Recipient:      testutil.NewPrivateKey().PublicKey().String(),
		Currency:       "sol",
		Decimals:       9,
		Network:        "localnet",
		SecretKey:      "test-secret-key-0123456789abcdef",
		RPC:            rpcClient,
		FeePayerSigner: feePayer,
	})
	if err != nil {
		t.Fatalf("new mpp failed: %v", err)
	}
	challenge, err := handler.Charge(context.Background(), "0.001")
	if err != nil {
		t.Fatalf("charge failed: %v", err)
	}
	authHeader, err := client.BuildCredentialHeader(context.Background(), testutil.NewPrivateKey(), rpcClient, challenge)
	if err != nil {
		t.Fatalf("build credential failed: %v", err)
	}
	credential, err := core.ParseAuthorization(authHeader)
	if err != nil {
		t.Fatalf("parse authorization failed: %v", err)
	}
	var payload struct {
		Transaction string `json:"transaction"`
	}
	if err := credential.PayloadAs(&payload); err != nil {
		t.Fatalf("payload: %v", err)
	}
	tx, err := solanatx.DecodeTransactionBase64(payload.Transaction)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !tx.Message.AccountKeys[0].Equals(feePayer.PublicKey()) || len(tx.Signatures) != 2 {
		t.Fatalf("expected a sponsored transaction with the fee payer in slot 0 and two signatures")
	}
	return handler, rpcClient, credential, tx, feePayer
}

func sponsorSignature(t *testing.T, tx *solana.Transaction, feePayer solana.PrivateKey) solana.Signature {
	t.Helper()
	msg, err := tx.Message.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := feePayer.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

// A slot-0 signature copied from a landed transaction is refused before the
// charge is claimed, recorded pending, simulated or sent. Written first, the
// pending record would let a concurrent copy reconcile the landed
// transaction's status into a receipt.
func TestForgedClientSignatureIsRefusedBeforeItIsClaimed(t *testing.T) {
	handler, rpcClient, cfg := newTestMpp(t)
	credential, tx := pullCredential(t, handler, rpcClient, cfg.Client)
	tx.Signatures[0] = forgedSignature()

	_, err := verifyCredentialEchoed(handler, context.Background(), credentialWithTransaction(t, credential, tx))
	if code := errCode(t, err); code != core.ErrCodeInvalidPayload {
		t.Fatalf("code = %q, want %q (%v)", code, core.ErrCodeInvalidPayload, err)
	}
	if len(rpcClient.Simulated) != 0 || len(rpcClient.Sent) != 0 {
		t.Fatalf("a forged transaction reached the node: simulated=%d sent=%d", len(rpcClient.Simulated), len(rpcClient.Sent))
	}
	assertNothingClaimed(t, handler, forgedSignature())

	// Positive control: the genuine credential for the same challenge settles.
	if _, err := verifyCredentialEchoed(handler, context.Background(), credential); err != nil {
		t.Fatalf("genuine credential failed: %v", err)
	}
}

// In sponsored mode the client's own slot must verify too; only the fee
// payer slot the server signs itself may arrive empty.
func TestSponsoredForgedClientSignatureIsRefusedBeforeItIsClaimed(t *testing.T) {
	handler, rpcClient, credential, tx, feePayer := newSponsoredMpp(t)
	tx.Signatures[1] = forgedSignature()

	_, err := verifyCredentialEchoed(handler, context.Background(), credentialWithTransaction(t, credential, tx))
	if code := errCode(t, err); code != core.ErrCodeInvalidPayload {
		t.Fatalf("code = %q, want %q (%v)", code, core.ErrCodeInvalidPayload, err)
	}
	if len(rpcClient.Simulated) != 0 || len(rpcClient.Sent) != 0 {
		t.Fatalf("a forged transaction reached the node: simulated=%d sent=%d", len(rpcClient.Simulated), len(rpcClient.Sent))
	}
	assertNothingClaimed(t, handler, sponsorSignature(t, tx, feePayer))
}

// A client-filled fee payer slot never names the charge: the server always
// re-signs its own slot, and the transaction it sends verifies.
func TestSponsoredClientFilledFeePayerSlotIsOverwritten(t *testing.T) {
	handler, rpcClient, credential, tx, feePayer := newSponsoredMpp(t)
	tx.Signatures[0] = forgedSignature()

	receipt, err := verifyCredentialEchoed(handler, context.Background(), credentialWithTransaction(t, credential, tx))
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if len(rpcClient.Sent) != 1 {
		t.Fatalf("sent = %d, want 1", len(rpcClient.Sent))
	}
	sent := rpcClient.Sent[0]
	if err := sent.VerifySignatures(); err != nil {
		t.Fatalf("the sent transaction does not verify: %v", err)
	}
	want := sponsorSignature(t, tx, feePayer)
	if sent.Signatures[0] != want || receipt.Reference != want.String() {
		t.Fatalf("charge settled under %s, want the sponsor's signature %s", receipt.Reference, want)
	}
	assertNothingClaimed(t, handler, forgedSignature())
}

// A signature list shorter than the message's required signatures is
// refused before anything is claimed or sent.
func TestTruncatedSignatureListIsRefusedBeforeItIsClaimed(t *testing.T) {
	handler, rpcClient, credential, tx, feePayer := newSponsoredMpp(t)
	tx.Signatures = tx.Signatures[:1]

	_, err := verifyCredentialEchoed(handler, context.Background(), credentialWithTransaction(t, credential, tx))
	if err == nil {
		t.Fatal("a truncated signature list was settled")
	}
	if len(rpcClient.Simulated) != 0 || len(rpcClient.Sent) != 0 {
		t.Fatalf("a truncated transaction reached the node: simulated=%d sent=%d", len(rpcClient.Simulated), len(rpcClient.Sent))
	}
	assertNothingClaimed(t, handler, sponsorSignature(t, tx, feePayer))
}

// Positive control: an honestly signed sponsored credential settles and the
// sent transaction carries every signature, valid.
func TestSponsoredGenuineCredentialSettles(t *testing.T) {
	handler, rpcClient, credential, _, _ := newSponsoredMpp(t)
	if _, err := verifyCredentialEchoed(handler, context.Background(), credential); err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if len(rpcClient.Sent) != 1 {
		t.Fatalf("sent = %d, want 1", len(rpcClient.Sent))
	}
	if err := rpcClient.Sent[0].VerifySignatures(); err != nil {
		t.Fatalf("the sent transaction does not verify: %v", err)
	}
}
