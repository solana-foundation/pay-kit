package x402

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"github.com/solana-foundation/pay-kit/go/paycore/signer"
	"github.com/solana-foundation/pay-kit/go/paykit"
	proto "github.com/solana-foundation/pay-kit/go/protocols/x402"
	solana "github.com/solana-foundation/solana-go/v2"
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

func TestTotalUnitsRejectsPositiveSubBaseUnitPrice(t *testing.T) {
	a := bindingAdapter(t)
	gate := &paykit.Gate{Amount: paykit.MustParseUSD("0.0000009")}

	if _, err := a.totalUnits(gate, "USDC"); err == nil {
		t.Fatal("expected a positive price below one base unit to be rejected")
	}
	if entry, err := a.AcceptsEntry(gate); err == nil || entry != nil {
		t.Fatalf("sub-base-unit price must fail accepts entry construction, got entry=%v err=%v", entry, err)
	}
	if headers, err := a.ChallengeHeaders(gate); err == nil || headers != nil {
		t.Fatalf("sub-base-unit price must fail challenge construction, got headers=%v err=%v", headers, err)
	}

	_, err := a.VerifyAndSettle(&paykit.AdapterRequest{
		Gate:       gate,
		PaymentSig: encodeCredential(t, proto.Credential{}),
	})
	var perr *paykit.PaymentError
	if !errors.As(err, &perr) || perr.Code != "invalid_gate" {
		t.Fatalf("expected invalid_gate for sub-base-unit price, got %v", err)
	}
}

func TestTotalUnitsRejectsFractionalBaseUnitPrice(t *testing.T) {
	a := bindingAdapter(t)
	gate := &paykit.Gate{Amount: paykit.MustParseUSD("0.0000019")}

	if _, err := a.totalUnits(gate, "USDC"); err == nil {
		t.Fatal("expected a fractional base-unit price to be rejected")
	}
}

func TestTotalUnitsBindsExactlyOneBaseUnit(t *testing.T) {
	a := bindingAdapter(t)
	gate := &paykit.Gate{Amount: paykit.MustParseUSD("0.000001")}

	units, err := a.totalUnits(gate, "USDC")
	if err != nil {
		t.Fatalf("one base unit should be accepted: %v", err)
	}
	if units != "1" {
		t.Fatalf("totalUnits = %q, want %q", units, "1")
	}

	route, err := a.routeAccepts(gate)
	if err != nil {
		t.Fatalf("routeAccepts: %v", err)
	}
	if route.Amount != "1" || route.MaxAmountRequired != "1" {
		t.Fatalf("route amounts = (%q, %q), want (1, 1)", route.Amount, route.MaxAmountRequired)
	}
	reqs, err := a.transferRequirements(gate)
	if err != nil {
		t.Fatalf("transferRequirements: %v", err)
	}
	if reqs.Amount != 1 {
		t.Fatalf("transfer amount = %d, want 1", reqs.Amount)
	}
}

func TestVerifyRejectsLyingAcceptedAmount(t *testing.T) {
	a := bindingAdapter(t)
	gate := paykit.Gate{Amount: paykit.MustParseUSD("0.10")}

	route, err := a.routeAccepts(&gate)
	if err != nil {
		t.Fatal(err)
	}
	tampered := route
	tampered.Amount = "999999999"
	tampered.MaxAmountRequired = "999999999"

	cred := proto.Credential{
		X402Version: proto.X402Version,
		Payload:     proto.CredentialPayload{Transaction: base64.StdEncoding.EncodeToString([]byte("ignored"))},
		Accepted:    &tampered,
	}
	_, err = a.VerifyAndSettle(&paykit.AdapterRequest{Gate: &gate, PaymentSig: encodeCredential(t, cred)})
	var perr *paykit.PaymentError
	if !errors.As(err, &perr) || perr.Code != "charge_request_mismatch" {
		t.Fatalf("expected charge_request_mismatch for lying amount, got %v", err)
	}
}

func TestVerifyRejectsLyingAcceptedRecipient(t *testing.T) {
	a := bindingAdapter(t)
	gate := paykit.Gate{Amount: paykit.MustParseUSD("0.10")}

	route, err := a.routeAccepts(&gate)
	if err != nil {
		t.Fatal(err)
	}
	tampered := route
	tampered.PayTo = string(signer.Generate().Pubkey())

	cred := proto.Credential{
		X402Version: proto.X402Version,
		Payload:     proto.CredentialPayload{Transaction: base64.StdEncoding.EncodeToString([]byte("ignored"))},
		Accepted:    &tampered,
	}
	_, err = a.VerifyAndSettle(&paykit.AdapterRequest{Gate: &gate, PaymentSig: encodeCredential(t, cred)})
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
// in the account list, matching the Rust/TS index-0 pin. Signing an arbitrary
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
			Header:      solana.MessageHeader{NumRequiredSignatures: 3},
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
			Header:      solana.MessageHeader{NumRequiredSignatures: 2},
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
		Message:    solana.Message{AccountKeys: solana.PublicKeySlice{opPub}, Header: solana.MessageHeader{NumRequiredSignatures: 1}},
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

// TestCosignSupportsWideSignerVector proves co-signing uses the transaction
// encoder instead of relying on a one-byte short-vector prefix offset.
func TestCosignSupportsWideSignerVector(t *testing.T) {
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
	tx := &solana.Transaction{
		Message:    solana.Message{AccountKeys: keys, Header: solana.MessageHeader{NumRequiredSignatures: 128}},
		Signatures: sigs,
	}
	rawTx, err := tx.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	wire, err := a.cosign(context.Background(), tx, rawTx)
	if err != nil {
		t.Fatalf("cosign wide signer vector: %v", err)
	}
	if len(wire) == 0 || tx.Signatures[0].IsZero() {
		t.Fatal("cosign must fill the fee-payer signature in a wide signer vector")
	}
	for i := 1; i < len(tx.Signatures); i++ {
		if !tx.Signatures[i].IsZero() {
			t.Fatalf("cosign mutated non-fee-payer signature slot %d", i)
		}
	}
}

func TestCosignRejectsSignerVectorMismatchedWithMessage(t *testing.T) {
	op := signer.Generate()
	opPub := solana.MustPublicKeyFromBase58(string(op.Pubkey()))
	a := &Adapter{
		cfg:    paykit.Config{Network: paykit.SolanaMainnet, Operator: paykit.Operator{Signer: op, Recipient: op.Pubkey()}, X402: paykit.X402Config{Scheme: "exact"}},
		signer: op,
	}
	tx := &solana.Transaction{
		Message: solana.Message{
			AccountKeys: solana.PublicKeySlice{opPub},
			Header:      solana.MessageHeader{NumRequiredSignatures: 1},
		},
	}
	rawTx, err := tx.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.cosign(context.Background(), tx, rawTx); err == nil {
		t.Fatal("cosign must reject an in-memory transaction whose signature vector does not match the message")
	}
}

func TestCosignRejectsReadOnlyFeePayer(t *testing.T) {
	op := signer.Generate()
	opPub := solana.MustPublicKeyFromBase58(string(op.Pubkey()))
	a := &Adapter{
		cfg:    paykit.Config{Network: paykit.SolanaMainnet, Operator: paykit.Operator{Signer: op, Recipient: op.Pubkey()}, X402: paykit.X402Config{Scheme: "exact"}},
		signer: op,
	}
	tx := &solana.Transaction{
		Message: solana.Message{
			AccountKeys: solana.PublicKeySlice{opPub},
			Header: solana.MessageHeader{
				NumRequiredSignatures:     1,
				NumReadonlySignedAccounts: 1,
			},
		},
		Signatures: []solana.Signature{{}},
	}
	rawTx, err := tx.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.cosign(context.Background(), tx, rawTx); err == nil {
		t.Fatal("cosign must reject a read-only fee payer")
	}
}

func TestVerifyAcceptsHonestAcceptedThenProceeds(t *testing.T) {
	a := bindingAdapter(t)
	gate := paykit.Gate{Amount: paykit.MustParseUSD("0.10")}

	honest, err := a.routeAccepts(&gate)
	if err != nil {
		t.Fatal(err)
	}
	cred := proto.Credential{
		X402Version: proto.X402Version,
		Payload:     proto.CredentialPayload{Transaction: base64.StdEncoding.EncodeToString([]byte("not-a-tx"))},
		Accepted:    &honest,
	}
	_, err = a.VerifyAndSettle(&paykit.AdapterRequest{Gate: &gate, PaymentSig: encodeCredential(t, cred)})
	var perr *paykit.PaymentError
	if !errors.As(err, &perr) {
		t.Fatalf("expected a PaymentError, got %v", err)
	}
	if perr.Code == "charge_request_mismatch" {
		t.Fatalf("honest accepted should pass the binding gate, got %v", err)
	}
}
