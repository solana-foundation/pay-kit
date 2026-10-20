package x402

import (
	"errors"
	"testing"

	solana "github.com/gagliardetto/solana-go"

	"github.com/solana-foundation/pay-kit/go/paycore"
)

// s3Fixture is one route plus a client paying it with the static layout.
type s3Fixture struct {
	feePayer, mint, payTo, authority solana.PublicKey
	src, dest                        solana.PublicKey
}

func newS3Fixture(t *testing.T) s3Fixture {
	t.Helper()
	f := s3Fixture{
		feePayer:  solana.NewWallet().PublicKey(),
		mint:      solana.NewWallet().PublicKey(),
		payTo:     solana.NewWallet().PublicKey(),
		authority: solana.NewWallet().PublicKey(),
	}
	f.src = sourceATA(t, f.authority, f.mint)
	f.dest = sourceATA(t, f.payTo, f.mint)
	return f
}

func (f s3Fixture) tx(t *testing.T, extra ...solana.Instruction) *solana.Transaction {
	t.Helper()
	ixs := []solana.Instruction{
		makeComputeBudgetIx(2, []byte{200, 0, 0, 0}),
		makeComputeBudgetIx(3, []byte{1, 0, 0, 0, 0, 0, 0, 0}),
		makeTransferCheckedIx(f.src, f.mint, f.dest, f.authority, 1000, solana.TokenProgramID),
	}
	return buildValidTx(t, append(ixs, extra...), f.feePayer)
}

func (f s3Fixture) req(amount uint64) TransferRequirements {
	return validTransferReq(f.feePayer, f.mint, f.payTo, amount)
}

func memoIx(data string, accounts ...solana.PublicKey) solana.Instruction {
	metas := solana.AccountMetaSlice{}
	for _, a := range accounts {
		metas = append(metas, solana.Meta(a).SIGNER())
	}
	return solana.NewInstruction(solana.MustPublicKeyFromBase58(paycore.MemoProgram), metas, []byte(data))
}

func wantCode(t *testing.T, err error, code string) {
	t.Helper()
	var ve *VerifyError
	if !errors.As(err, &ve) || ve.Code != code {
		t.Fatalf("err = %v, want code %s", err, code)
	}
}

// §1.4: a matching transfer MAY exceed the required amount; it MUST NOT be
// less. The verifier used to require the exact amount.
func TestVerifyExactTransactionAcceptsOverpayment(t *testing.T) {
	f := newS3Fixture(t)
	if err := VerifyExactTransaction(f.tx(t, memoIx("nonce")), f.req(600)); err != nil {
		t.Fatalf("overpayment rejected: %v", err)
	}
	wantCode(t, VerifyExactTransaction(f.tx(t, memoIx("nonce")), f.req(1001)), "invalid_exact_svm_payload_amount_mismatch")
}

// §1.4: zero matching transfers is a reject.
func TestVerifyExactTransactionRejectsNoMatchingTransfer(t *testing.T) {
	f := newS3Fixture(t)
	other := newS3Fixture(t)
	req := f.req(1000)
	req.PayTo = other.payTo
	wantCode(t, VerifyExactTransaction(f.tx(t, memoIx("nonce")), req), "invalid_exact_svm_payload_recipient_mismatch")
}

// §1.4: more than one matching transfer is ambiguous and is rejected for
// that reason, not as an unknown trailing instruction.
func TestVerifyExactTransactionRejectsMultipleMatchingTransfers(t *testing.T) {
	f := newS3Fixture(t)
	second := makeTransferCheckedIx(f.src, f.mint, f.dest, f.authority, 1000, solana.TokenProgramID)
	wantCode(t, VerifyExactTransaction(f.tx(t, second, memoIx("nonce")), f.req(1000)),
		"invalid_exact_svm_payload_multiple_matching_transfers")
}

const feePayerIsolationCode = "invalid_exact_svm_payload_transaction_fee_payer_included_in_instruction_accounts"

// §2.1.1: the fee payer MUST NOT appear in any instruction's accounts. A
// memo listing the fee payer used to pass, since only the transfer
// authority was compared to it.
func TestVerifyExactTransactionRejectsFeePayerInInstructionAccounts(t *testing.T) {
	f := newS3Fixture(t)
	wantCode(t, VerifyExactTransaction(f.tx(t, memoIx("nonce", f.feePayer)), f.req(1000)), feePayerIsolationCode)

	// The fee payer as the transfer source (not the authority) is also
	// referenced by an instruction.
	g := newS3Fixture(t)
	g.src = g.feePayer
	wantCode(t, VerifyExactTransaction(g.tx(t, memoIx("nonce")), g.req(1000)), feePayerIsolationCode)
}

// §2.1.1: the fee payer MUST NOT be invoked as a program.
func TestVerifyExactTransactionRejectsFeePayerAsProgram(t *testing.T) {
	f := newS3Fixture(t)
	asProgram := solana.NewInstruction(f.feePayer, solana.AccountMetaSlice{}, []byte{1})
	wantCode(t, VerifyExactTransaction(f.tx(t, asProgram), f.req(1000)), feePayerIsolationCode)
}

// The authority-specific code still wins when the fee payer authorizes the
// transfer itself.
func TestVerifyExactTransactionRejectsFeePayerAuthority(t *testing.T) {
	f := newS3Fixture(t)
	f.authority = f.feePayer
	f.src = sourceATA(t, f.feePayer, f.mint)
	wantCode(t, VerifyExactTransaction(f.tx(t, memoIx("nonce")), f.req(1000)),
		"invalid_exact_svm_payload_transaction_fee_payer_transferring_funds")
}

// §2.1.1 positive control: the fee payer MAY be the payment recipient
// (feePayer == payTo); funds land in ATA(payTo), which no instruction
// signs for as the fee payer.
func TestVerifyExactTransactionAllowsFeePayerAsPayTo(t *testing.T) {
	f := newS3Fixture(t)
	f.payTo = f.feePayer
	f.dest = sourceATA(t, f.payTo, f.mint)
	if err := VerifyExactTransaction(f.tx(t, memoIx("nonce")), f.req(1000)); err != nil {
		t.Fatalf("feePayer == payTo rejected: %v", err)
	}
}
