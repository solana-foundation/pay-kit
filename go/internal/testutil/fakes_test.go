package testutil

import (
	"context"
	"testing"

	solana "github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/programs/system"
	"github.com/gagliardetto/solana-go/rpc"
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

func TestFakeRPCReportsTransactionVersion(t *testing.T) {
	rpcClient := NewFakeRPC()
	if rpcClient.TxVersion != "0" {
		t.Fatalf("default TxVersion = %q, want 0", rpcClient.TxVersion)
	}
	signer := NewPrivateKey()
	ix, _ := system.NewTransferInstruction(1000, signer.PublicKey(), NewPrivateKey().PublicKey()).ValidateAndBuild()
	tx, _ := solana.NewTransaction([]solana.Instruction{ix}, rpcClient.Blockhash, solana.TransactionPayer(signer.PublicKey()))
	message, _ := tx.Message.MarshalBinary()
	sig, _ := signer.Sign(message)
	tx.Signatures = []solana.Signature{sig}
	rpcClient.BySig[sig.String()] = tx
	cases := []struct {
		version string
		want    rpc.TransactionVersion
	}{
		{version: "0", want: 0},
		{version: `"legacy"`, want: rpc.LegacyTransactionVersion},
		// An omitted field decodes as the zero value, indistinguishable from 0.
		{version: "", want: 0},
	}
	for _, tc := range cases {
		rpcClient.TxVersion = tc.version
		result, err := rpcClient.GetTransaction(context.Background(), sig, nil)
		if err != nil {
			t.Fatalf("version %q: get transaction failed: %v", tc.version, err)
		}
		if result.Version != tc.want {
			t.Fatalf("version %q: reported %v, want %v", tc.version, result.Version, tc.want)
		}
	}
}
