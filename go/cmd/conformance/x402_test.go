package main

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/solana-foundation/pay-kit/go/paycore/solanatx"
	proto "github.com/solana-foundation/pay-kit/go/protocols/x402"
	solana "github.com/solana-foundation/solana-go/v2"
)

func TestVerifyX402ExactTransactionRetainsAllManagedSigners(t *testing.T) {
	feePayer := solana.NewWallet().PublicKey()
	secondManaged := solana.NewWallet().PublicKey()
	source := solana.NewWallet().PublicKey()
	mint := solana.NewWallet().PublicKey()
	payTo := solana.NewWallet().PublicKey()
	tokenProgram := solana.TokenProgramID
	destination, err := solanatx.FindAssociatedTokenAddressWithProgram(payTo, mint, tokenProgram)
	if err != nil {
		t.Fatal(err)
	}
	transferData := make([]byte, 10)
	transferData[0] = 12
	binary.LittleEndian.PutUint64(transferData[1:9], 1000)
	transferData[9] = 6
	transfer := solana.NewInstruction(
		tokenProgram,
		solana.AccountMetaSlice{
			solana.Meta(source).WRITE(),
			solana.Meta(mint),
			solana.Meta(destination).WRITE(),
			solana.Meta(secondManaged).SIGNER(),
		},
		transferData,
	)
	tx, err := solana.NewTransaction([]solana.Instruction{
		solana.NewInstruction(solana.MustPublicKeyFromBase58(proto.ComputeBudgetProgram), nil, []byte{2, 200, 0, 0, 0}),
		solana.NewInstruction(solana.MustPublicKeyFromBase58(proto.ComputeBudgetProgram), nil, []byte{3, 0, 0, 0, 0, 0, 0, 0, 0}),
		transfer,
	}, solana.MustHashFromBase58("4vJ9JU1bJJbzZ4aJ8AqGxH9bK5VwY8bGf3sD5QG6h7h"), solana.TransactionPayer(feePayer))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := tx.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	requirement := &X402ExactRequirement{
		Asset:  mint.String(),
		PayTo:  payTo.String(),
		Amount: "1000",
	}
	requirement.Extra.TokenProgram = tokenProgram.String()
	err = verifyX402ExactTransaction(Vector{Input: VectorInput{
		Transaction:             base64.StdEncoding.EncodeToString(raw),
		X402ExactManagedSigners: []string{feePayer.String(), secondManaged.String()},
		X402ExactRequirement:    requirement,
	}})
	var verifyErr *proto.VerifyError
	if !errors.As(err, &verifyErr) || verifyErr.Code != "invalid_exact_svm_payload_transaction_fee_payer_transferring_funds" {
		t.Fatalf("expected later managed signer rejection, got %v", err)
	}
}
