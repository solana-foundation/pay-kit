package x402

import (
	"bytes"
	"context"
	"encoding/base64"
	"testing"

	solana "github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"
	"github.com/solana-foundation/pay-kit/go/paycore/solanatx"
	"github.com/solana-foundation/pay-kit/go/paykit"
)

// forgedSignature stands in for a signature copied from some other landed
// transaction: 64 bytes that do not sign this message.
func forgedSignature() solana.Signature {
	var sig solana.Signature
	copy(sig[:], bytes.Repeat([]byte{7}, 64))
	return sig
}

// operatorSignature is the signature the operator puts in slot 0 when it
// co-signs tx: the key this payment would be claimed and recorded under.
func operatorSignature(t *testing.T, a *Adapter, tx *solana.Transaction) solana.Signature {
	t.Helper()
	msg, err := tx.Message.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := a.signer.Sign(context.Background(), msg)
	if err != nil {
		t.Fatal(err)
	}
	return solana.SignatureFromBytes(raw)
}

// assertNothingClaimed checks that no settlement state exists under key:
// no consumed-signature claim and no pending record a retry could reconcile.
func assertNothingClaimed(t *testing.T, a *Adapter, key solana.Signature) {
	t.Helper()
	ctx := context.Background()
	if _, found, _ := a.ledgerStore().Get(ctx, pendingSettlementPrefix+key.String()); found {
		t.Fatalf("a pending record was written under %s", key)
	}
	claimed, err := a.consumed().Claim(ctx, key.String())
	if err != nil {
		t.Fatal(err)
	}
	if !claimed {
		t.Fatalf("signature %s was claimed", key)
	}
}

// A client signature that does not verify is refused before the payment is
// claimed or sent: the node would refuse it with -32003 (no preflight data),
// the claim and the pending record would be kept, and a retry would be
// granted on the status of whatever landed transaction owns the signature.
func TestVerifyAndSettleRefusesForgedClientSignatureBeforeClaim(t *testing.T) {
	fake := &fakeRPC{sig: solana.MustSignatureFromBase58(sampleSig), confirm: rpc.ConfirmationStatusConfirmed}
	a, gate, tx, _ := settleFixtureParts(t, fake)
	tx.Signatures[1] = forgedSignature()
	_, err := a.VerifyAndSettle(&paykit.AdapterRequest{Gate: gate, PaymentSig: credentialFor(t, a, gate, tx)})
	if settleCode(err) != "invalid_payload" {
		t.Fatalf("expected invalid_payload, got %v", err)
	}
	if fake.sends != 0 {
		t.Fatalf("a transaction with a forged signature was sent: sends=%d", fake.sends)
	}
	assertNothingClaimed(t, a, operatorSignature(t, a, tx))
	assertNothingClaimed(t, a, forgedSignature())
}

// A landed signature S copied into the operator slot never names the
// payment: the operator always re-signs its own slot, so the transaction
// sent and the key claimed are the operator's own signature, never S.
func TestVerifyAndSettleOverwritesClientFilledOperatorSlot(t *testing.T) {
	fake := &fakeRPC{sig: solana.MustSignatureFromBase58(sampleSig), confirm: rpc.ConfirmationStatusConfirmed}
	a, gate, tx, _ := settleFixtureParts(t, fake)
	tx.Signatures[0] = forgedSignature()
	if _, err := a.VerifyAndSettle(&paykit.AdapterRequest{Gate: gate, PaymentSig: credentialFor(t, a, gate, tx)}); err != nil {
		t.Fatalf("expected settle to succeed, got %v", err)
	}
	sent, err := solanatx.DecodeTransactionBase64(fake.sent)
	if err != nil {
		t.Fatal(err)
	}
	if sent.Signatures[0] == forgedSignature() {
		t.Fatal("the client-filled operator slot was sent as is")
	}
	if err := sent.VerifySignatures(); err != nil {
		t.Fatalf("the sent transaction does not verify: %v", err)
	}
	if sent.Signatures[0] != operatorSignature(t, a, tx) {
		t.Fatal("slot 0 is not the operator's signature")
	}
	assertNothingClaimed(t, a, forgedSignature())
}

// A signature list shorter than the message's required signatures is
// refused before anything is claimed or sent.
func TestVerifyAndSettleRefusesTruncatedSignatureList(t *testing.T) {
	fake := &fakeRPC{sig: solana.MustSignatureFromBase58(sampleSig), confirm: rpc.ConfirmationStatusConfirmed}
	a, gate, tx, _ := settleFixtureParts(t, fake)
	tx.Signatures = tx.Signatures[:1]
	_, err := a.VerifyAndSettle(&paykit.AdapterRequest{Gate: gate, PaymentSig: credentialFor(t, a, gate, tx)})
	if err == nil {
		t.Fatal("a truncated signature list was settled")
	}
	if fake.sends != 0 {
		t.Fatalf("a transaction with a truncated signature list was sent: sends=%d", fake.sends)
	}
	assertNothingClaimed(t, a, operatorSignature(t, a, tx))
}

// Positive control: a correctly client-signed transaction is co-signed,
// sent with every signature valid, and claimed under the operator's
// signature.
func TestVerifyAndSettleSendsAFullyVerifiedTransaction(t *testing.T) {
	fake := &fakeRPC{sig: solana.MustSignatureFromBase58(sampleSig), confirm: rpc.ConfirmationStatusConfirmed}
	a, gate, tx, _ := settleFixtureParts(t, fake)
	if _, err := a.VerifyAndSettle(&paykit.AdapterRequest{Gate: gate, PaymentSig: credentialFor(t, a, gate, tx)}); err != nil {
		t.Fatalf("expected settle to succeed, got %v", err)
	}
	wire, err := base64.StdEncoding.DecodeString(fake.sent)
	if err != nil {
		t.Fatal(err)
	}
	key, err := transactionReplayKey(wire)
	if err != nil {
		t.Fatalf("the sent transaction does not verify: %v", err)
	}
	if key != operatorSignature(t, a, tx).String() {
		t.Fatalf("claimed %s, want the operator's signature", key)
	}
	claimed, err := a.consumed().Claim(context.Background(), key)
	if err != nil || claimed {
		t.Fatalf("the settled signature must be claimed: claimed=%v err=%v", claimed, err)
	}
}
