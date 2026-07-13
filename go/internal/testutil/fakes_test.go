package testutil

import (
	"context"
	"testing"

	solana "github.com/solana-foundation/solana-go/v2"
	"github.com/solana-foundation/solana-go/v2/programs/system"
	"github.com/solana-foundation/solana-go/v2/rpc"
)

func TestFakeRPCRoundTrip(t *testing.T) {
	rpcClient := NewFakeRPC()
	signer := NewPrivateKey()
	recipient := NewPrivateKey().PublicKey()
	ix, _ := system.NewTransferInstruction(1000, signer.PublicKey(), recipient).ValidateAndBuild()
	tx, _ := solana.NewTransaction([]solana.Instruction{ix}, rpcClient.Blockhash, solana.TransactionPayer(signer.PublicKey()))
	message, _ := tx.Message.MarshalBinary()
	sig, _ := signer.Sign(message)
	tx.Signatures = []solana.Signature{sig}
	if _, err := rpcClient.SendTransactionWithOpts(context.Background(), tx, rpc.TransactionOpts{}); err != nil {
		t.Fatalf("send failed: %v", err)
	}
	if len(rpcClient.Sent) != 1 {
		t.Fatal("expected transaction to be recorded")
	}
	if _, err := rpcClient.GetTransaction(context.Background(), tx.Signatures[0], nil); err != nil {
		t.Fatalf("get transaction failed: %v", err)
	}
}

func TestFakeRPCHelpers(t *testing.T) {
	rpcClient := NewFakeRPC()
	mint := NewPrivateKey().PublicKey()
	rpcClient.MintOwners[mint.String()] = solana.TokenProgramID

	if _, err := rpcClient.GetLatestBlockhash(context.Background(), ""); err != nil {
		t.Fatalf("blockhash failed: %v", err)
	}
	if _, err := rpcClient.GetAccountInfoWithOpts(context.Background(), mint, nil); err != nil {
		t.Fatalf("account info failed: %v", err)
	}
	sig := solana.MustSignatureFromBase58("5jKh25biPsnrmLWXXuqKNH2Q67Q4UmVVx8Gf2wrS6VoCeyfGE9wKikjY7Q1GQQgmpQ3xy7wJX5U1rcz82q4R8Nkv")
	if _, err := rpcClient.GetSignatureStatuses(context.Background(), true, sig); err != nil {
		t.Fatalf("status failed: %v", err)
	}
	signer := NewPrivateKey()
	recipient := NewPrivateKey().PublicKey()
	ix, _ := system.NewTransferInstruction(1000, signer.PublicKey(), recipient).ValidateAndBuild()
	tx, _ := solana.NewTransaction([]solana.Instruction{ix}, rpcClient.Blockhash, solana.TransactionPayer(signer.PublicKey()))
	message, _ := tx.Message.MarshalBinary()
	signature, _ := signer.Sign(message)
	tx.Signatures = []solana.Signature{signature}
	if _, err := rpcClient.SimulateTransactionWithOpts(context.Background(), tx, &rpc.SimulateTransactionOpts{}); err != nil {
		t.Fatalf("simulate failed: %v", err)
	}
}
