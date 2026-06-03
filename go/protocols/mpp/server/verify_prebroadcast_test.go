package server

import (
	"errors"
	"testing"

	solana "github.com/gagliardetto/solana-go"

	"github.com/solana-foundation/pay-kit/go/internal/testutil"
	"github.com/solana-foundation/pay-kit/go/paycore"
	"github.com/solana-foundation/pay-kit/go/paycore/solanatx"
	core "github.com/solana-foundation/pay-kit/go/protocols/mpp/core"
	"github.com/solana-foundation/pay-kit/go/protocols/mpp/intents"
)

// encodePreBroadcastSOLTransfer builds a single-instruction SOL transfer
// transaction for `amount` lamports from payer to recipient and base64-encodes
// it the way a client credential payload would carry it.
func encodePreBroadcastSOLTransfer(t *testing.T, payer solana.PrivateKey, recipient solana.PublicKey, amount uint64, extra ...solana.Instruction) (string, *solana.Transaction) {
	t.Helper()
	primaryIx, err := solanatx.BuildSOLTransfer(payer.PublicKey(), recipient, amount)
	if err != nil {
		t.Fatalf("build SOL transfer failed: %v", err)
	}
	instructions := append([]solana.Instruction{primaryIx}, extra...)
	tx := newTestTransaction(t, payer, instructions...)
	encoded, err := solanatx.EncodeTransactionBase64(tx)
	if err != nil {
		t.Fatalf("encode transaction failed: %v", err)
	}
	return encoded, tx
}

func TestVerifyChargeTransactionPreBroadcastAcceptsValidSOLTransfer(t *testing.T) {
	payer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey()

	encoded, _ := encodePreBroadcastSOLTransfer(t, payer, recipient, 1000)
	request := intents.ChargeRequest{Amount: "1000", Currency: "sol", Recipient: recipient.String()}

	if err := VerifyChargeTransactionPreBroadcast(encoded, request, paycore.MethodDetails{}, "localnet"); err != nil {
		t.Fatalf("expected valid SOL transfer to pass pre-broadcast verify: %v", err)
	}
}

func TestVerifyChargeTransactionPreBroadcastRejectsMissingTransaction(t *testing.T) {
	recipient := testutil.NewPrivateKey().PublicKey()
	request := intents.ChargeRequest{Amount: "1000", Currency: "sol", Recipient: recipient.String()}

	err := VerifyChargeTransactionPreBroadcast("", request, paycore.MethodDetails{}, "localnet")
	assertPreBroadcastCode(t, err, core.ErrCodeMissingTransaction)
}

func TestVerifyChargeTransactionPreBroadcastRejectsTooManySplits(t *testing.T) {
	payer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey()
	encoded, _ := encodePreBroadcastSOLTransfer(t, payer, recipient, 1000)

	splits := make([]paycore.Split, maxSplits+1)
	for i := range splits {
		splits[i] = paycore.Split{Recipient: recipient.String(), Amount: "1"}
	}
	request := intents.ChargeRequest{Amount: "1000", Currency: "sol", Recipient: recipient.String()}

	err := VerifyChargeTransactionPreBroadcast(encoded, request, paycore.MethodDetails{Splits: splits}, "localnet")
	assertPreBroadcastCode(t, err, core.ErrCodeTooManySplits)
}

func TestVerifyChargeTransactionPreBroadcastRejectsUndecodableTransaction(t *testing.T) {
	recipient := testutil.NewPrivateKey().PublicKey()
	request := intents.ChargeRequest{Amount: "1000", Currency: "sol", Recipient: recipient.String()}

	if err := VerifyChargeTransactionPreBroadcast("not-base64!!!", request, paycore.MethodDetails{}, "localnet"); err == nil {
		t.Fatal("expected undecodable transaction to be rejected")
	}
}

func TestVerifyChargeTransactionPreBroadcastRejectsAddressLookupTables(t *testing.T) {
	payer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey()

	_, tx := encodePreBroadcastSOLTransfer(t, payer, recipient, 1000)
	// Mark the message as v0 so the address-table lookups survive the
	// marshal/unmarshal round trip the verifier performs.
	tx.Message.SetVersion(solana.MessageVersionV0)
	tx.Message.SetAddressTableLookups([]solana.MessageAddressTableLookup{
		{AccountKey: testutil.NewPrivateKey().PublicKey(), WritableIndexes: []byte{0}, ReadonlyIndexes: []byte{}},
	})
	encoded, err := solanatx.EncodeTransactionBase64(tx)
	if err != nil {
		t.Fatalf("encode ALT transaction failed: %v", err)
	}
	request := intents.ChargeRequest{Amount: "1000", Currency: "sol", Recipient: recipient.String()}

	err = VerifyChargeTransactionPreBroadcast(encoded, request, paycore.MethodDetails{}, "localnet")
	assertPreBroadcastCode(t, err, core.ErrCodeInvalidPayload)
}

func TestVerifyChargeTransactionPreBroadcastRejectsComputeBudgetOverCap(t *testing.T) {
	payer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey()

	overCapIx, err := solanatx.BuildComputeUnitLimit(maxComputeUnitLimit + 1)
	if err != nil {
		t.Fatalf("build compute unit limit failed: %v", err)
	}
	encoded, _ := encodePreBroadcastSOLTransfer(t, payer, recipient, 1000, overCapIx)
	request := intents.ChargeRequest{Amount: "1000", Currency: "sol", Recipient: recipient.String()}

	if err := VerifyChargeTransactionPreBroadcast(encoded, request, paycore.MethodDetails{}, "localnet"); err == nil {
		t.Fatal("expected compute-budget over-cap transaction to be rejected")
	}
}

func TestVerifyChargeTransactionPreBroadcastRejectsComputeBudgetPriceOverCap(t *testing.T) {
	payer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey()

	overCapIx, err := solanatx.BuildComputeUnitPrice(maxComputeUnitPriceMicroLamports + 1)
	if err != nil {
		t.Fatalf("build compute unit price failed: %v", err)
	}
	encoded, _ := encodePreBroadcastSOLTransfer(t, payer, recipient, 1000, overCapIx)
	request := intents.ChargeRequest{Amount: "1000", Currency: "sol", Recipient: recipient.String()}

	if err := VerifyChargeTransactionPreBroadcast(encoded, request, paycore.MethodDetails{}, "localnet"); err == nil {
		t.Fatal("expected compute-budget price over-cap transaction to be rejected")
	}
}

func TestFeePayerKey(t *testing.T) {
	if got := feePayerKey(paycore.MethodDetails{}); got != nil {
		t.Fatalf("expected nil fee payer for empty key, got %v", got)
	}
	if got := feePayerKey(paycore.MethodDetails{FeePayerKey: "not-a-pubkey"}); got != nil {
		t.Fatalf("expected nil fee payer for invalid key, got %v", got)
	}
	valid := testutil.NewPrivateKey().PublicKey()
	got := feePayerKey(paycore.MethodDetails{FeePayerKey: valid.String()})
	if got == nil || !got.Equals(valid) {
		t.Fatalf("expected fee payer %s, got %v", valid, got)
	}
}

func TestVerifyChargeTransactionPreBroadcastRejectsInvalidAmount(t *testing.T) {
	payer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey()
	encoded, _ := encodePreBroadcastSOLTransfer(t, payer, recipient, 1000)

	request := intents.ChargeRequest{Amount: "not-a-number", Currency: "sol", Recipient: recipient.String()}
	if err := VerifyChargeTransactionPreBroadcast(encoded, request, paycore.MethodDetails{}, "localnet"); err == nil {
		t.Fatal("expected invalid amount to be rejected")
	}
}

func TestVerifyChargeTransactionPreBroadcastRejectsInvalidRecipient(t *testing.T) {
	payer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey()
	encoded, _ := encodePreBroadcastSOLTransfer(t, payer, recipient, 1000)

	request := intents.ChargeRequest{Amount: "1000", Currency: "sol", Recipient: "not-a-pubkey"}
	err := VerifyChargeTransactionPreBroadcast(encoded, request, paycore.MethodDetails{}, "localnet")
	assertPreBroadcastCode(t, err, core.ErrCodeInvalidConfig)
}

func TestVerifyChargeTransactionPreBroadcastRejectsTransferMismatch(t *testing.T) {
	payer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey()
	// Encode a transfer for the wrong amount; the transfer/challenge check
	// must reject it.
	encoded, _ := encodePreBroadcastSOLTransfer(t, payer, recipient, 500)

	request := intents.ChargeRequest{Amount: "1000", Currency: "sol", Recipient: recipient.String()}
	if err := VerifyChargeTransactionPreBroadcast(encoded, request, paycore.MethodDetails{}, "localnet"); err == nil {
		t.Fatal("expected transfer-amount mismatch to be rejected")
	}
}

func assertPreBroadcastCode(t *testing.T, err error, want core.ErrorCode) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error with code %s, got nil", want)
	}
	var perr *core.Error
	if !errors.As(err, &perr) {
		t.Fatalf("expected structured *core.Error, got %T: %v", err, err)
	}
	if perr.Code != want {
		t.Fatalf("expected error code %s, got %s", want, perr.Code)
	}
}
