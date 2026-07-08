package x402

import (
	"encoding/binary"
	"testing"

	solana "github.com/gagliardetto/solana-go"
	"github.com/solana-foundation/pay-kit/go/paycore"
	"github.com/solana-foundation/pay-kit/go/paycore/solanatx"
)

func makeTransferCheckedIx(source, mint, destination, authority solana.PublicKey, amount uint64, tokenProg solana.PublicKey) solana.Instruction {
	data := make([]byte, 10)
	data[0] = 12
	binary.LittleEndian.PutUint64(data[1:], amount)
	return solana.NewInstruction(tokenProg,
		solana.AccountMetaSlice{
			solana.Meta(source).WRITE(),
			solana.Meta(mint),
			solana.Meta(destination).WRITE(),
			solana.Meta(authority).SIGNER(),
		},
		data,
	)
}

func makeComputeBudgetIx(discriminator byte, args []byte) solana.Instruction {
	data := append([]byte{discriminator}, args...)
	return solana.NewInstruction(solana.MustPublicKeyFromBase58(ComputeBudgetProgram), nil, data)
}

func validTransferReq(feePayer, mint, payTo solana.PublicKey, amount uint64) TransferRequirements {
	return TransferRequirements{
		PayTo:        payTo,
		Mint:         mint,
		TokenProgram: solana.TokenProgramID,
		Amount:       amount,
		FeePayer:     feePayer,
	}
}

func buildValidTx(t *testing.T, ixs []solana.Instruction, feePayer solana.PublicKey) *solana.Transaction {
	t.Helper()
	tx, err := solana.NewTransaction(ixs, solana.MustHashFromBase58("4vJ9JU1bJJbzZ4aJ8AqGxH9bK5VwY8bGf3sD5QG6h7h"), solana.TransactionPayer(feePayer))
	if err != nil {
		t.Fatalf("NewTransaction: %v", err)
	}
	return tx
}

func sourceATA(t *testing.T, owner, mint solana.PublicKey) solana.PublicKey {
	t.Helper()
	ata, err := solanatx.FindAssociatedTokenAddressWithProgram(owner, mint, solana.TokenProgramID)
	if err != nil {
		t.Fatalf("FindATA: %v", err)
	}
	return ata
}

func TestVerifyExactTransactionAcceptsValid(t *testing.T) {
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

	if err := VerifyExactTransaction(tx, validTransferReq(feePayer, mint, payTo, 1000)); err != nil {
		t.Fatalf("VerifyExactTransaction: %v", err)
	}
}

func TestVerifyExactTransactionAcceptsValidToken2022(t *testing.T) {
	feePayer := solana.NewWallet().PublicKey()
	mint := solana.NewWallet().PublicKey()
	payTo := solana.NewWallet().PublicKey()
	authority := solana.NewWallet().PublicKey()
	dest, _ := solanatx.FindAssociatedTokenAddressWithProgram(payTo, mint, solana.Token2022ProgramID)
	src, _ := solanatx.FindAssociatedTokenAddressWithProgram(authority, mint, solana.Token2022ProgramID)

	tx := buildValidTx(t, []solana.Instruction{
		makeComputeBudgetIx(2, []byte{200, 0, 0, 0}),
		makeComputeBudgetIx(3, []byte{0, 0, 0, 0, 0, 0, 0, 0}),
		makeTransferCheckedIx(src, mint, dest, authority, 1000, solana.Token2022ProgramID),
	}, feePayer)

	req := validTransferReq(feePayer, mint, payTo, 1000)
	req.TokenProgram = solana.Token2022ProgramID
	if err := VerifyExactTransaction(tx, req); err != nil {
		t.Fatalf("VerifyExactTransaction Token2022: %v", err)
	}
}

func TestVerifyExactTransactionRejectsWrongInstructionCount(t *testing.T) {
	feePayer := solana.NewWallet().PublicKey()
	tx := buildValidTx(t, []solana.Instruction{
		makeComputeBudgetIx(2, []byte{200, 0, 0, 0}),
		makeComputeBudgetIx(3, []byte{0, 0, 0, 0, 0, 0, 0, 0}),
	}, feePayer)

	if err := VerifyExactTransaction(tx, TransferRequirements{}); err == nil {
		t.Fatal("expected error for 2 instructions")
	}
}

func TestVerifyExactTransactionRejectsTooManyInstructions(t *testing.T) {
	feePayer := solana.NewWallet().PublicKey()
	authority := solana.NewWallet().PublicKey()
	mint := solana.NewWallet().PublicKey()
	payTo := solana.NewWallet().PublicKey()
	dest := sourceATA(t, payTo, mint)
	src := sourceATA(t, authority, mint)
	ixs := []solana.Instruction{
		makeComputeBudgetIx(2, []byte{200, 0, 0, 0}),
		makeComputeBudgetIx(3, []byte{0, 0, 0, 0, 0, 0, 0, 0}),
		makeTransferCheckedIx(src, mint, dest, authority, 1, solana.TokenProgramID),
	}
	for i := 0; i < 5; i++ {
		ixs = append(ixs, solana.NewInstruction(solana.SystemProgramID, nil, nil))
	}
	tx := buildValidTx(t, ixs, feePayer)
	if err := VerifyExactTransaction(tx, TransferRequirements{}); err == nil {
		t.Fatal("expected error for 8 instructions")
	}
}

func TestVerifyExactTransactionRejectsWrongComputeLimit(t *testing.T) {
	feePayer := solana.NewWallet().PublicKey()
	ixs := []solana.Instruction{
		solana.NewInstruction(solana.SystemProgramID, nil, nil),
		makeComputeBudgetIx(3, []byte{0, 0, 0, 0, 0, 0, 0, 0}),
		solana.NewInstruction(solana.TokenProgramID, nil, []byte{12, 0, 0, 0, 0, 0, 0, 0, 0, 0}),
	}
	tx := buildValidTx(t, ixs, feePayer)
	if err := VerifyExactTransaction(tx, TransferRequirements{}); err == nil {
		t.Fatal("expected error for wrong compute limit")
	}
}

func TestVerifyExactTransactionRejectsWrongComputePrice(t *testing.T) {
	feePayer := solana.NewWallet().PublicKey()
	ixs := []solana.Instruction{
		makeComputeBudgetIx(2, []byte{200, 0, 0, 0}),
		solana.NewInstruction(solana.SystemProgramID, nil, nil),
		solana.NewInstruction(solana.TokenProgramID, nil, []byte{12, 0, 0, 0, 0, 0, 0, 0, 0, 0}),
	}
	tx := buildValidTx(t, ixs, feePayer)
	if err := VerifyExactTransaction(tx, TransferRequirements{}); err == nil {
		t.Fatal("expected error for wrong compute price")
	}
}

func TestVerifyExactTransactionRejectsHighComputePrice(t *testing.T) {
	feePayer := solana.NewWallet().PublicKey()
	ixs := []solana.Instruction{
		makeComputeBudgetIx(2, []byte{200, 0, 0, 0}),
		makeComputeBudgetIx(3, []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}),
		solana.NewInstruction(solana.TokenProgramID, nil, []byte{12, 0, 0, 0, 0, 0, 0, 0, 0, 0}),
	}
	tx := buildValidTx(t, ixs, feePayer)
	if err := VerifyExactTransaction(tx, TransferRequirements{}); err == nil {
		t.Fatal("expected error for high compute price")
	}
}

func TestVerifyExactTransactionRejectsTransferAuthorityIsFeePayer(t *testing.T) {
	feePayer := solana.NewWallet().PublicKey()
	mint := solana.NewWallet().PublicKey()
	payTo := solana.NewWallet().PublicKey()
	dest := sourceATA(t, payTo, mint)
	src := sourceATA(t, feePayer, mint)
	tx := buildValidTx(t, []solana.Instruction{
		makeComputeBudgetIx(2, []byte{200, 0, 0, 0}),
		makeComputeBudgetIx(3, []byte{0, 0, 0, 0, 0, 0, 0, 0}),
		makeTransferCheckedIx(src, mint, dest, feePayer, 1000, solana.TokenProgramID),
	}, feePayer)
	if err := VerifyExactTransaction(tx, validTransferReq(feePayer, mint, payTo, 1000)); err == nil {
		t.Fatal("expected error for fee payer as authority")
	}
}

func TestVerifyExactTransactionRejectsMintMismatch(t *testing.T) {
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
	req := validTransferReq(feePayer, solana.NewWallet().PublicKey(), payTo, 1000)
	if err := VerifyExactTransaction(tx, req); err == nil {
		t.Fatal("expected error for mint mismatch")
	}
}

func TestVerifyExactTransactionRejectsRecipientMismatch(t *testing.T) {
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
	req := validTransferReq(feePayer, mint, solana.NewWallet().PublicKey(), 1000)
	if err := VerifyExactTransaction(tx, req); err == nil {
		t.Fatal("expected error for recipient mismatch")
	}
}

func TestVerifyExactTransactionRejectsAmountMismatch(t *testing.T) {
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
	req := validTransferReq(feePayer, mint, payTo, 999)
	if err := VerifyExactTransaction(tx, req); err == nil {
		t.Fatal("expected error for amount mismatch")
	}
}

func TestVerifyExactTransactionAcceptsMemoInstructions(t *testing.T) {
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
		solana.NewInstruction(solana.MustPublicKeyFromBase58(paycore.MemoProgram), nil, []byte("test memo")),
	}, feePayer)

	req := validTransferReq(feePayer, mint, payTo, 1000)
	req.ExpectedMemo = "test memo"
	if err := VerifyExactTransaction(tx, req); err != nil {
		t.Fatalf("VerifyExactTransaction: %v", err)
	}
}

func TestVerifyExactTransactionRejectsMemoCountMismatch(t *testing.T) {
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

	req := validTransferReq(feePayer, mint, payTo, 1000)
	req.ExpectedMemo = "test"
	if err := VerifyExactTransaction(tx, req); err == nil {
		t.Fatal("expected error for memo count mismatch")
	}
}

func TestVerifyExactTransactionRejectsMemoMismatch(t *testing.T) {
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
		solana.NewInstruction(solana.MustPublicKeyFromBase58(paycore.MemoProgram), nil, []byte("wrong memo")),
	}, feePayer)

	req := validTransferReq(feePayer, mint, payTo, 1000)
	req.ExpectedMemo = "test"
	if err := VerifyExactTransaction(tx, req); err == nil {
		t.Fatal("expected error for memo mismatch")
	}
}

func TestVerifyExactTransactionAcceptsLighthouseInstruction(t *testing.T) {
	feePayer := solana.NewWallet().PublicKey()
	mint := solana.NewWallet().PublicKey()
	payTo := solana.NewWallet().PublicKey()
	authority := solana.NewWallet().PublicKey()
	lighthouse := solana.MustPublicKeyFromBase58(LighthouseProgram)
	dest := sourceATA(t, payTo, mint)
	src := sourceATA(t, authority, mint)
	tx := buildValidTx(t, []solana.Instruction{
		makeComputeBudgetIx(2, []byte{200, 0, 0, 0}),
		makeComputeBudgetIx(3, []byte{0, 0, 0, 0, 0, 0, 0, 0}),
		makeTransferCheckedIx(src, mint, dest, authority, 1000, solana.TokenProgramID),
		solana.NewInstruction(lighthouse, nil, nil),
	}, feePayer)

	if err := VerifyExactTransaction(tx, validTransferReq(feePayer, mint, payTo, 1000)); err != nil {
		t.Fatalf("VerifyExactTransaction: %v", err)
	}
}

func TestVerifyExactTransactionRejectsUnknownOptional(t *testing.T) {
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
		solana.NewInstruction(solana.SystemProgramID, nil, nil),
	}, feePayer)

	if err := VerifyExactTransaction(tx, validTransferReq(feePayer, mint, payTo, 1000)); err == nil {
		t.Fatal("expected error for unknown optional instruction")
	}
}
