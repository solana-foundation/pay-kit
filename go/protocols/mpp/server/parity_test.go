package server

import (
	"context"
	"errors"
	"strings"
	"testing"

	solana "github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/programs/system"
	"github.com/gagliardetto/solana-go/programs/token"

	"github.com/solana-foundation/pay-kit/go/internal/testutil"
	"github.com/solana-foundation/pay-kit/go/paycore"
	"github.com/solana-foundation/pay-kit/go/paycore/solanatx"
	core "github.com/solana-foundation/pay-kit/go/protocols/mpp/core"
	"github.com/solana-foundation/pay-kit/go/protocols/mpp/intents"
)

// errTxNotFound forces the on-chain fetch to fail in push-mode tests.
var errTxNotFound = errors.New("transaction not found")

// boolp is a small helper for *bool challenge fields.
func boolp(b bool) *bool { return &b }

// u8p is a small helper for *uint8 challenge fields.
func u8p(v uint8) *uint8 { return &v }

// buildSPLTransferWithAuthority builds a transferChecked whose authority,
// source ATA, and decimals byte can each be controlled, so the fee-payer
// and decimals guards can be exercised independently. Matches the rust
// account layout [source, mint, destination, authority].
func buildSPLTransferWithAuthority(t *testing.T, authority, source, recipient, mint solana.PublicKey, amount uint64, decimals uint8) solana.Instruction {
	t.Helper()
	recipientATA, err := solanatx.FindAssociatedTokenAddressWithProgram(recipient, mint, solana.TokenProgramID)
	if err != nil {
		t.Fatalf("recipient ata: %v", err)
	}
	ix, err := token.NewTransferCheckedInstruction(amount, decimals, source, mint, recipientATA, authority, nil).ValidateAndBuild()
	if err != nil {
		t.Fatalf("build transfer: %v", err)
	}
	return ix
}

// Finding #15: the configured fee payer must not authorize the SPL
// payment transfer (rust charge.rs:1642-1647). Hard reject.
func TestSPLRejectsFeePayerAsAuthority(t *testing.T) {
	feePayer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey()
	mint := testutil.NewPrivateKey().PublicKey()

	source, _ := solanatx.FindAssociatedTokenAddressWithProgram(testutil.NewPrivateKey().PublicKey(), mint, solana.TokenProgramID)
	transfer := buildSPLTransferWithAuthority(t, feePayer.PublicKey(), source, recipient, mint, 1000, 6)
	tx := newTestTransaction(t, feePayer, transfer)

	details := paycore.MethodDetails{FeePayer: boolp(true), FeePayerKey: feePayer.PublicKey().String(), Decimals: u8p(6)}
	err := verifyTransfersAgainstChallenge(tx, 1000, mint.String(), recipient, "", details)
	if err == nil || !strings.Contains(err.Error(), "fee payer cannot authorize") {
		t.Fatalf("expected fee-payer-authority rejection, got %v", err)
	}
}

// Finding #15: the configured fee payer's token account must not fund
// the SPL payment transfer (rust charge.rs:1649-1657). Hard reject.
func TestSPLRejectsFeePayerATAAsSource(t *testing.T) {
	feePayer := testutil.NewPrivateKey()
	authority := testutil.NewPrivateKey().PublicKey()
	recipient := testutil.NewPrivateKey().PublicKey()
	mint := testutil.NewPrivateKey().PublicKey()

	feePayerATA, _ := solanatx.FindAssociatedTokenAddressWithProgram(feePayer.PublicKey(), mint, solana.TokenProgramID)
	transfer := buildSPLTransferWithAuthority(t, authority, feePayerATA, recipient, mint, 1000, 6)
	tx := newTestTransaction(t, feePayer, transfer)

	details := paycore.MethodDetails{FeePayer: boolp(true), FeePayerKey: feePayer.PublicKey().String(), Decimals: u8p(6)}
	err := verifyTransfersAgainstChallenge(tx, 1000, mint.String(), recipient, "", details)
	if err == nil || !strings.Contains(err.Error(), "fee payer token account cannot fund") {
		t.Fatalf("expected fee-payer-source rejection, got %v", err)
	}
}

// Finding #17: the transferChecked decimals byte must match the
// challenge-pinned decimals (rust charge.rs:1623-1624). A transfer with
// the wrong decimals byte does not match.
func TestSPLRejectsDecimalsByteMismatch(t *testing.T) {
	payer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey()
	mint := testutil.NewPrivateKey().PublicKey()

	source, _ := solanatx.FindAssociatedTokenAddressWithProgram(payer.PublicKey(), mint, solana.TokenProgramID)
	// Wrong decimals byte (9) versus the pinned 6.
	transfer := buildSPLTransferWithAuthority(t, payer.PublicKey(), source, recipient, mint, 1000, 9)
	tx := newTestTransaction(t, payer, transfer)

	details := paycore.MethodDetails{Decimals: u8p(6)}
	err := verifyTransfersAgainstChallenge(tx, 1000, mint.String(), recipient, "", details)
	if err == nil || !strings.Contains(err.Error(), "no matching token transfer") {
		t.Fatalf("expected decimals-mismatch rejection, got %v", err)
	}
}

// Finding #17 (positive): a matching decimals byte still verifies.
func TestSPLAcceptsMatchingDecimalsByte(t *testing.T) {
	payer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey()
	mint := testutil.NewPrivateKey().PublicKey()

	source, _ := solanatx.FindAssociatedTokenAddressWithProgram(payer.PublicKey(), mint, solana.TokenProgramID)
	transfer := buildSPLTransferWithAuthority(t, payer.PublicKey(), source, recipient, mint, 1000, 6)
	tx := newTestTransaction(t, payer, transfer)

	details := paycore.MethodDetails{Decimals: u8p(6)}
	if err := verifyTransfersAgainstChallenge(tx, 1000, mint.String(), recipient, "", details); err != nil {
		t.Fatalf("expected matching-decimals transfer to pass, got %v", err)
	}
}

// Finding #16: the configured fee payer must not fund the SOL payment
// transfer (rust charge.rs:1525-1528). Hard reject.
func TestSOLRejectsFeePayerAsSource(t *testing.T) {
	feePayer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey()

	transfer, err := system.NewTransferInstruction(1000, feePayer.PublicKey(), recipient).ValidateAndBuild()
	if err != nil {
		t.Fatalf("build sol transfer: %v", err)
	}
	tx := newTestTransaction(t, feePayer, transfer)

	details := paycore.MethodDetails{FeePayer: boolp(true), FeePayerKey: feePayer.PublicKey().String()}
	verr := verifyTransfersAgainstChallenge(tx, 1000, "sol", recipient, "", details)
	if verr == nil || !strings.Contains(verr.Error(), "fee payer cannot fund the SOL") {
		t.Fatalf("expected SOL fee-payer-source rejection, got %v", verr)
	}
}

// Finding #18 (verify side): when a split required an ATA-create but the
// currency is a stablecoin symbol rather than a raw mint address, the
// verifier rejects (rust charge.rs:1120-1124).
func TestVerifyRejectsATARequiredWithSymbolCurrency(t *testing.T) {
	payer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey()
	splitRecipient := testutil.NewPrivateKey().PublicKey()

	mint := solana.MustPublicKeyFromBase58(paycore.USDCMainnetMint)
	transfer := buildSPLTransferIx(t, payer.PublicKey(), recipient, mint, 1000)
	tx := newTestTransaction(t, payer, transfer)

	details := paycore.MethodDetails{
		Network:  "mainnet-beta",
		Decimals: u8p(6),
		Splits: []paycore.Split{
			{Recipient: splitRecipient.String(), Amount: "1", AtaCreationRequired: boolp(true)},
		},
	}
	// Currency is the symbol "USDC", not the mint address: must reject.
	err := verifyTransfersAgainstChallenge(tx, 1000, "USDC", recipient, "", details)
	if err == nil || !strings.Contains(err.Error(), "SPL token mint address") {
		t.Fatalf("expected symbol-currency rejection, got %v", err)
	}
}

// Finding #18 (issuance side): ChargeWithOptions rejects an
// ataCreationRequired split when the configured currency is SOL.
func TestChargeRejectsATARequiredOnSOL(t *testing.T) {
	m := &Mpp{currency: "SOL", network: "mainnet-beta"}
	err := m.validateChargeOptions(ChargeOptions{
		Splits: []paycore.Split{{Recipient: testutil.NewPrivateKey().PublicKey().String(), Amount: "1", AtaCreationRequired: boolp(true)}},
	})
	if err == nil || !strings.Contains(err.Error(), "SPL token currency") {
		t.Fatalf("expected SOL ataCreationRequired rejection, got %v", err)
	}
}

// Finding #18 (issuance side): ChargeWithOptions rejects an
// ataCreationRequired split when the currency is a stablecoin symbol.
func TestChargeRejectsATARequiredOnSymbolCurrency(t *testing.T) {
	m := &Mpp{currency: "USDC", network: "mainnet-beta"}
	err := m.validateChargeOptions(ChargeOptions{
		Splits: []paycore.Split{{Recipient: testutil.NewPrivateKey().PublicKey().String(), Amount: "1", AtaCreationRequired: boolp(true)}},
	})
	if err == nil || !strings.Contains(err.Error(), "SPL token mint address") {
		t.Fatalf("expected symbol ataCreationRequired rejection, got %v", err)
	}
}

// Finding #18 (issuance side, positive): a raw mint-address currency is
// accepted for ataCreationRequired splits.
func TestChargeAcceptsATARequiredOnMintCurrency(t *testing.T) {
	m := &Mpp{currency: paycore.USDCMainnetMint, network: "mainnet-beta"}
	err := m.validateChargeOptions(ChargeOptions{
		Splits: []paycore.Split{{Recipient: testutil.NewPrivateKey().PublicKey().String(), Amount: "1", AtaCreationRequired: boolp(true)}},
	})
	if err != nil {
		t.Fatalf("expected mint-address ataCreationRequired to pass, got %v", err)
	}
}

// errCode extracts the *core.Error code for assertions.
func errCode(t *testing.T, err error) core.ErrorCode {
	t.Helper()
	sdkErr, ok := err.(*core.Error)
	if !ok {
		t.Fatalf("expected *core.Error, got %T (%v)", err, err)
	}
	return sdkErr.Code
}

// Finding #18 (issuance side): the rejection carries the invalid-payload code.
func TestChargeATARejectionCode(t *testing.T) {
	m := &Mpp{currency: "SOL", network: "mainnet-beta"}
	err := m.validateChargeOptions(ChargeOptions{
		Splits: []paycore.Split{{Recipient: "x", Amount: "1", AtaCreationRequired: boolp(true)}},
	})
	if code := errCode(t, err); code != core.ErrCodeInvalidPayload {
		t.Fatalf("code = %q, want %q", code, core.ErrCodeInvalidPayload)
	}
}

// Finding #19: push mode (signature credential) verifies on-chain BEFORE
// consuming the replay marker, and never burns the marker on a verify
// failure. Mirrors rust verify_push -> consume_signature
// (charge.rs:563-595). Before the fix the marker was consumed first and
// deleted on failure; after the fix a failed verify leaves the marker
// untouched, so a later legitimate settlement of the same signature can
// still proceed.
func TestPushModeVerifyBeforeConsumeLeavesMarkerOnFailure(t *testing.T) {
	handler, rpc, _ := newTestMpp(t)
	// Force the on-chain fetch to fail so push-mode verification errors.
	rpc.GetTxErr = errTxNotFound

	sig := testutil.NewPrivateKey().PublicKey().String() // any base58 32-byte value
	cred := core.PaymentCredential{Challenge: core.ChallengeEcho{ID: "challenge-1"}}
	request := intents.ChargeRequest{Amount: "1000", Currency: "sol", Recipient: handler.recipient.String()}
	payload := paycore.CredentialPayload{Type: "signature", Signature: sig}

	_, err := handler.verifySignature(context.Background(), cred, request, paycore.MethodDetails{}, payload)
	if err == nil {
		t.Fatal("expected push-mode verify to fail when the tx is not found")
	}

	// The marker must NOT have been consumed: PutIfAbsent inserts, proving
	// the key was absent after the failed verify.
	inserted, err := handler.store.PutIfAbsent(context.Background(), consumedPrefix+sig, true)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	if !inserted {
		t.Fatal("failed push-mode verify must not consume the replay marker")
	}
}

// Finding #20: a v0 transaction carrying address lookup tables is
// rejected with a structured error, matching rust
// reject_address_lookup_tables (charge.rs:1213-1225). v0 static-key
// transactions remain accepted (decoded by the underlying library).
func TestVerifyTransactionRejectsAddressLookupTables(t *testing.T) {
	handler, _, _ := newTestMpp(t)

	payer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey()
	transfer, err := system.NewTransferInstruction(1000, payer.PublicKey(), recipient).ValidateAndBuild()
	if err != nil {
		t.Fatalf("build transfer: %v", err)
	}
	tx := newTestTransaction(t, payer, transfer)
	// Promote to v0 with a non-empty address lookup table.
	tx.Message.SetAddressTableLookups([]solana.MessageAddressTableLookup{
		{AccountKey: testutil.NewPrivateKey().PublicKey(), WritableIndexes: []uint8{0}},
	})
	encoded, err := solanatx.EncodeTransactionBase64(tx)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	cred := core.PaymentCredential{Challenge: core.ChallengeEcho{ID: "challenge-1"}}
	request := intents.ChargeRequest{Amount: "1000", Currency: "sol", Recipient: handler.recipient.String()}
	payload := paycore.CredentialPayload{Type: "transaction", Transaction: encoded}

	_, err = handler.verifyTransaction(context.Background(), cred, request, paycore.MethodDetails{}, payload)
	if err == nil || !strings.Contains(err.Error(), "address lookup tables") {
		t.Fatalf("expected ALT rejection, got %v", err)
	}
}
