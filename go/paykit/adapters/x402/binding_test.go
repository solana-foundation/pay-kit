package x402

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	solana "github.com/gagliardetto/solana-go"
	"github.com/solana-foundation/pay-kit/go/paycore/signer"
	"github.com/solana-foundation/pay-kit/go/paykit"
	proto "github.com/solana-foundation/pay-kit/go/protocols/x402"
)

func bindingAdapter(t *testing.T) *Adapter {
	t.Helper()
	op := signer.Generate()
	return &Adapter{
		cfg: paykit.Config{
			Network:     paykit.SolanaMainnet,
			Stablecoins: []paykit.Stablecoin{paykit.USDC},
			Operator:    paykit.Operator{Signer: op, Recipient: op.Pubkey()},
			X402:        paykit.X402Config{Scheme: "exact"},
		},
		signer:            op,
		blockhashProvider: func() (string, error) { return "BH", nil },
	}
}

func encodeCredential(t *testing.T, cred proto.Credential) string {
	t.Helper()
	raw, err := json.Marshal(cred)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func TestVerifyRejectsLyingAcceptedAmount(t *testing.T) {
	a := bindingAdapter(t)
	gate := paykit.Gate{Amount: paykit.MustParseUSD("0.10")}

	route := a.routeAccepts(&gate)
	tampered := route
	tampered.Amount = "999999999"
	tampered.MaxAmountRequired = "999999999"

	cred := proto.Credential{
		X402Version: proto.X402Version,
		Payload:     proto.CredentialPayload{Transaction: base64.StdEncoding.EncodeToString([]byte("ignored"))},
		Accepted:    &tampered,
	}
	_, err := a.VerifyAndSettle(&paykit.AdapterRequest{Gate: &gate, PaymentSig: encodeCredential(t, cred)})
	var perr *paykit.PaymentError
	if !errors.As(err, &perr) || perr.Code != "charge_request_mismatch" {
		t.Fatalf("expected charge_request_mismatch for lying amount, got %v", err)
	}
}

func TestVerifyRejectsLyingAcceptedRecipient(t *testing.T) {
	a := bindingAdapter(t)
	gate := paykit.Gate{Amount: paykit.MustParseUSD("0.10")}

	route := a.routeAccepts(&gate)
	tampered := route
	tampered.PayTo = string(signer.Generate().Pubkey())

	cred := proto.Credential{
		X402Version: proto.X402Version,
		Payload:     proto.CredentialPayload{Transaction: base64.StdEncoding.EncodeToString([]byte("ignored"))},
		Accepted:    &tampered,
	}
	_, err := a.VerifyAndSettle(&paykit.AdapterRequest{Gate: &gate, PaymentSig: encodeCredential(t, cred)})
	var perr *paykit.PaymentError
	if !errors.As(err, &perr) || perr.Code != "charge_request_mismatch" {
		t.Fatalf("expected charge_request_mismatch for lying recipient, got %v", err)
	}
}

// TestCosignRefusesOperatorOutsideFeePayerSlot is the fee-payer-slot-pin
// regression: the
// operator must only ever co-sign the fee-payer slot (account key index 0). A
// transaction that places the operator key at any other index with a zero
// signature slot must NOT be co-signed, even though the operator's key appears
// in the account list — matching the Rust/TS index-0 pin. Signing an arbitrary
// slot would let a crafted transaction spend the operator's signature on an
// instruction it never intended to authorize.
//
// Before the fix cosign scanned for the first zero-signature slot matching the
// operator anywhere in AccountKeys and signed it, so a slot-2 operator was
// co-signed.
func TestCosignRefusesOperatorOutsideFeePayerSlot(t *testing.T) {
	op := signer.Generate()
	opPub := solana.MustPublicKeyFromBase58(string(op.Pubkey()))
	a := &Adapter{
		cfg: paykit.Config{
			Network:  paykit.SolanaMainnet,
			Operator: paykit.Operator{Signer: op, Recipient: op.Pubkey()},
			X402:     paykit.X402Config{Scheme: "exact"},
		},
		signer: op,
	}

	// Operator key sits at index 2, not the fee-payer index 0.
	feePayer := solana.NewWallet().PublicKey()
	other := solana.NewWallet().PublicKey()
	tx := &solana.Transaction{
		Message: solana.Message{
			AccountKeys: solana.PublicKeySlice{feePayer, other, opPub},
		},
		// Three signature slots, all zero: slot 0 (fee payer), slot 1, slot 2
		// (the operator). A pre-fix cosign would fill slot 2.
		Signatures: []solana.Signature{{}, {}, {}},
	}
	rawTx, err := tx.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	wire, err := a.cosign(context.Background(), tx, rawTx)
	if err != nil {
		t.Fatalf("cosign should not error when the operator is not the fee payer, got %v", err)
	}
	// The operator must not have signed any slot: the wire bytes are unchanged.
	if !bytes.Equal(wire, rawTx) {
		t.Fatal("cosign signed a non-fee-payer slot; operator must only co-sign account key index 0")
	}
}

// TestCosignSignsFeePayerSlotZero is the fee-payer-slot-pin positive: when the operator IS the
// fee payer (account key index 0) and its signature slot is zero, cosign fills
// exactly slot 0 and leaves every other slot untouched.
func TestCosignSignsFeePayerSlotZero(t *testing.T) {
	op := signer.Generate()
	opPub := solana.MustPublicKeyFromBase58(string(op.Pubkey()))
	a := &Adapter{
		cfg: paykit.Config{
			Network:  paykit.SolanaMainnet,
			Operator: paykit.Operator{Signer: op, Recipient: op.Pubkey()},
			X402:     paykit.X402Config{Scheme: "exact"},
		},
		signer: op,
	}

	clientSig := solana.MustSignatureFromBase58(sampleClientSig)
	other := solana.NewWallet().PublicKey()
	tx := &solana.Transaction{
		Message: solana.Message{
			AccountKeys: solana.PublicKeySlice{opPub, other},
		},
		// Slot 0 (operator/fee payer) zero; slot 1 already carries a client
		// signature that must be preserved.
		Signatures: []solana.Signature{{}, clientSig},
	}
	rawTx, err := tx.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	wire, err := a.cosign(context.Background(), tx, rawTx)
	if err != nil {
		t.Fatalf("cosign: %v", err)
	}
	if bytes.Equal(wire, rawTx) {
		t.Fatal("cosign left slot 0 unsigned; the operator fee-payer slot must be filled")
	}
	// Slot 1 (offset 1+64=65 .. 129) must be byte-identical to the client's
	// signature: only slot 0 changed.
	if !bytes.Equal(wire[1+64:1+128], rawTx[1+64:1+128]) {
		t.Fatal("cosign mutated a non-fee-payer signature slot")
	}
}

// TestCosignSkipsAlreadyFilledFeePayerSlot covers the no-op path: the operator
// is the fee payer at index 0 but slot 0 already carries a signature, so cosign
// leaves the wire untouched.
func TestCosignSkipsAlreadyFilledFeePayerSlot(t *testing.T) {
	op := signer.Generate()
	opPub := solana.MustPublicKeyFromBase58(string(op.Pubkey()))
	a := &Adapter{
		cfg:    paykit.Config{Network: paykit.SolanaMainnet, Operator: paykit.Operator{Signer: op, Recipient: op.Pubkey()}, X402: paykit.X402Config{Scheme: "exact"}},
		signer: op,
	}
	filled := solana.MustSignatureFromBase58(sampleClientSig)
	tx := &solana.Transaction{
		Message:    solana.Message{AccountKeys: solana.PublicKeySlice{opPub}},
		Signatures: []solana.Signature{filled},
	}
	rawTx, err := tx.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	wire, err := a.cosign(context.Background(), tx, rawTx)
	if err != nil {
		t.Fatalf("cosign: %v", err)
	}
	if !bytes.Equal(wire, rawTx) {
		t.Fatal("cosign overwrote an already-filled fee-payer slot")
	}
}

// TestCosignRejectsWideSignerVector covers the short-vec prefix guard: once the
// signature count reaches the compact-u16 two-byte threshold (128) the fixed
// one-byte-prefix slot-0 offset no longer holds, so cosign refuses rather than
// mis-offsetting the write.
func TestCosignRejectsWideSignerVector(t *testing.T) {
	op := signer.Generate()
	opPub := solana.MustPublicKeyFromBase58(string(op.Pubkey()))
	a := &Adapter{
		cfg:    paykit.Config{Network: paykit.SolanaMainnet, Operator: paykit.Operator{Signer: op, Recipient: op.Pubkey()}, X402: paykit.X402Config{Scheme: "exact"}},
		signer: op,
	}
	keys := make(solana.PublicKeySlice, 128)
	keys[0] = opPub
	for i := 1; i < 128; i++ {
		keys[i] = solana.NewWallet().PublicKey()
	}
	sigs := make([]solana.Signature, 128) // slot 0 zero, operator is fee payer.
	tx := &solana.Transaction{Message: solana.Message{AccountKeys: keys}, Signatures: sigs}
	rawTx, err := tx.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.cosign(context.Background(), tx, rawTx); err == nil {
		t.Fatal("cosign must refuse a >=128 signer vector (multi-byte short-vec prefix)")
	}
}

func TestVerifyAcceptsHonestAcceptedThenProceeds(t *testing.T) {
	a := bindingAdapter(t)
	gate := paykit.Gate{Amount: paykit.MustParseUSD("0.10")}

	honest := a.routeAccepts(&gate)
	cred := proto.Credential{
		X402Version: proto.X402Version,
		Payload:     proto.CredentialPayload{Transaction: base64.StdEncoding.EncodeToString([]byte("not-a-tx"))},
		Accepted:    &honest,
	}
	_, err := a.VerifyAndSettle(&paykit.AdapterRequest{Gate: &gate, PaymentSig: encodeCredential(t, cred)})
	var perr *paykit.PaymentError
	if !errors.As(err, &perr) {
		t.Fatalf("expected a PaymentError, got %v", err)
	}
	if perr.Code == "charge_request_mismatch" {
		t.Fatalf("honest accepted should pass the binding gate, got %v", err)
	}
}
