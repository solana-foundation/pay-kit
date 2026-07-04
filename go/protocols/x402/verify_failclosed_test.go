package x402

import (
	"errors"
	"testing"

	solana "github.com/gagliardetto/solana-go"
	"github.com/solana-foundation/pay-kit/go/paycore/solanatx"
)

// The fee-payer-ATA drain guard must fail closed if the ATA derivation it
// relies on cannot be evaluated. Previously the derivation error was
// swallowed (`if err == nil && source.Equals(...)`), so a derivation failure
// silently skipped a security check. Mirror the Rust reference, whose helper
// is effectively infallible: on error, return a VerifyFail so the guard fails
// closed. The seam (findATA) is unexported and defaults to the production
// helper; only the test overrides it, so no production path is weakened.
func TestVerifyExactTransactionFailsClosedOnFeePayerATADerivationError(t *testing.T) {
	feePayer := solana.NewWallet().PublicKey()
	mint := solana.NewWallet().PublicKey()
	payTo := solana.NewWallet().PublicKey()
	authority := solana.NewWallet().PublicKey()
	dest := sourceATA(t, payTo, mint)
	src := sourceATA(t, authority, mint)

	tx := buildValidTx(t, []solana.Instruction{
		makeComputeBudgetIx(2, []byte{200, 0, 0, 0}),
		makeComputeBudgetIx(3, []byte{0, 0, 0, 0, 0, 0, 0, 0}),
		makeTransferCheckedIx(src, mint, dest, authority, 1000, solana.TokenProgramID),
	}, feePayer)

	// Force the fee-payer-ATA derivation to error. The default helper is
	// effectively infallible, so this is the only way to exercise the guard's
	// error path. The seam is restored after the test.
	prev := findATA
	findATA = func(wallet, m, tokenProgram solana.PublicKey) (solana.PublicKey, error) {
		if wallet.Equals(feePayer) {
			return solana.PublicKey{}, errors.New("forced derivation failure")
		}
		return prev(wallet, m, tokenProgram)
	}
	t.Cleanup(func() { findATA = prev })

	err := VerifyExactTransaction(tx, validTransferReq(feePayer, mint, payTo, 1000))
	if err == nil {
		t.Fatal("expected fail-closed VerifyFail when fee-payer-ATA derivation errs, got nil")
	}
	ve, ok := err.(*VerifyError)
	if !ok {
		t.Fatalf("expected *VerifyError, got %T: %v", err, err)
	}
	if ve.Code != "invalid_exact_svm_payload_transaction_fee_payer_transferring_funds" {
		t.Fatalf("expected fee_payer_transferring_funds code, got %q", ve.Code)
	}
}

// A route may advertise one token program while the on-wire transaction runs
// under another (e.g. a route that accepts either classic SPL Token or
// Token-2022). The recipient ATA must be derived from the instruction's
// resolved token program, not from req.TokenProgram, matching the Rust/TS/Ruby
// verifiers. Here req.TokenProgram is the classic program but the transfer
// runs under Token-2022 with a Token-2022-derived destination ATA; Go must
// accept exactly like the sibling verifiers. Before the fix Go derives the
// expected destination under the classic program and spurious-rejects with a
// recipient mismatch.
func TestVerifyExactTransactionDerivesRecipientATAFromInstructionProgram(t *testing.T) {
	feePayer := solana.NewWallet().PublicKey()
	mint := solana.NewWallet().PublicKey()
	payTo := solana.NewWallet().PublicKey()
	authority := solana.NewWallet().PublicKey()

	dest, err := solanatx.FindAssociatedTokenAddressWithProgram(payTo, mint, solana.Token2022ProgramID)
	if err != nil {
		t.Fatalf("derive dest ATA: %v", err)
	}
	src, err := solanatx.FindAssociatedTokenAddressWithProgram(authority, mint, solana.Token2022ProgramID)
	if err != nil {
		t.Fatalf("derive src ATA: %v", err)
	}

	tx := buildValidTx(t, []solana.Instruction{
		makeComputeBudgetIx(2, []byte{200, 0, 0, 0}),
		makeComputeBudgetIx(3, []byte{0, 0, 0, 0, 0, 0, 0, 0}),
		makeTransferCheckedIx(src, mint, dest, authority, 1000, solana.Token2022ProgramID),
	}, feePayer)

	// The advertised requirement pins the classic token program, but the
	// instruction runs under Token-2022. The recipient ATA is derived from the
	// instruction program, so this must be accepted.
	req := validTransferReq(feePayer, mint, payTo, 1000)
	req.TokenProgram = solana.TokenProgramID
	if err := VerifyExactTransaction(tx, req); err != nil {
		t.Fatalf("expected accept when recipient ATA is derived from the instruction program, got %v", err)
	}
}
