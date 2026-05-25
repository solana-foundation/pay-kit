package client

import (
	"context"
	"errors"
	"strings"
	"testing"

	solana "github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"

	"github.com/solana-foundation/pay-kit/go/internal/solanautil"
	"github.com/solana-foundation/pay-kit/go/internal/testutil"
	"github.com/solana-foundation/pay-kit/go/protocol"
)

// rpcWithBlockhashErr wraps FakeRPC and forces GetLatestBlockhash to error.
type rpcWithBlockhashErr struct {
	*testutil.FakeRPC
}

func (r *rpcWithBlockhashErr) GetLatestBlockhash(_ context.Context, _ rpc.CommitmentType) (*rpc.GetLatestBlockhashResult, error) {
	return nil, errors.New("blockhash rpc down")
}

func TestBuildChargeTransactionInvalidMint(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	signer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey().String()
	decimals := uint8(6)
	// Mint param must be a base58 pubkey; pass an invalid one.
	_, err := BuildChargeTransaction(context.Background(), signer, rpcClient, "1000", "not-a-mint", recipient, protocol.MethodDetails{Decimals: &decimals}, BuildOptions{})
	if err == nil {
		t.Fatal("expected invalid mint error")
	}
}

func TestBuildChargeTransactionTokenResolveError(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	signer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey().String()
	mint := testutil.NewPrivateKey().PublicKey()
	// Mint owner not registered, so ResolveTokenProgram returns "mint not found" error.
	decimals := uint8(6)
	_, err := BuildChargeTransaction(context.Background(), signer, rpcClient, "1000", mint.String(), recipient, protocol.MethodDetails{Decimals: &decimals}, BuildOptions{})
	if err == nil {
		t.Fatal("expected token program resolve error")
	}
}

func TestBuildChargeTransactionTokenInvalidSplitRecipient(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	signer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey().String()
	mint := testutil.NewPrivateKey().PublicKey()
	rpcClient.MintOwners[mint.String()] = solana.TokenProgramID
	decimals := uint8(6)
	_, err := BuildChargeTransaction(context.Background(), signer, rpcClient, "1000", mint.String(), recipient, protocol.MethodDetails{
		Decimals: &decimals,
		Splits:   []protocol.Split{{Recipient: "bad-key", Amount: "10"}},
	}, BuildOptions{})
	if err == nil {
		t.Fatal("expected invalid split recipient error")
	}
}

func TestBuildChargeTransactionTokenInvalidSplitAmount(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	signer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey().String()
	splitRecipient := testutil.NewPrivateKey().PublicKey().String()
	mint := testutil.NewPrivateKey().PublicKey()
	rpcClient.MintOwners[mint.String()] = solana.TokenProgramID
	decimals := uint8(6)
	_, err := BuildChargeTransaction(context.Background(), signer, rpcClient, "1000", mint.String(), recipient, protocol.MethodDetails{
		Decimals: &decimals,
		Splits:   []protocol.Split{{Recipient: splitRecipient, Amount: "abc"}},
	}, BuildOptions{})
	if err == nil {
		t.Fatal("expected invalid split amount error")
	}
}

func TestBuildChargeTransactionBlockhashRPCError(t *testing.T) {
	rpcClient := &rpcWithBlockhashErr{FakeRPC: testutil.NewFakeRPC()}
	signer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey().String()
	// No RecentBlockhash supplied means the code tries to fetch one from RPC.
	_, err := BuildChargeTransaction(context.Background(), signer, rpcClient, "1000", "sol", recipient, protocol.MethodDetails{}, BuildOptions{})
	if err == nil {
		t.Fatal("expected blockhash rpc error")
	}
}

func TestBuildChargeTransactionInvalidFeePayerKey(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	signer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey().String()
	enabled := true
	_, err := BuildChargeTransaction(context.Background(), signer, rpcClient, "1000", "sol", recipient, protocol.MethodDetails{
		FeePayer:    &enabled,
		FeePayerKey: "not-a-valid-pubkey",
	}, BuildOptions{})
	if err == nil {
		t.Fatal("expected invalid fee payer pubkey error")
	}
}

func TestBuildChargeTransactionTokenInvalidFeePayerKey(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	signer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey().String()
	mint := testutil.NewPrivateKey().PublicKey()
	rpcClient.MintOwners[mint.String()] = solana.TokenProgramID
	decimals := uint8(6)
	enabled := true
	_, err := BuildChargeTransaction(context.Background(), signer, rpcClient, "1000", mint.String(), recipient, protocol.MethodDetails{
		Decimals:    &decimals,
		FeePayer:    &enabled,
		FeePayerKey: "not-a-valid-pubkey",
	}, BuildOptions{})
	if err == nil {
		t.Fatal("expected invalid token fee payer pubkey error")
	}
}

func TestBuildChargeTransactionSOLWithSplitMemoTooLong(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	signer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey().String()
	split := testutil.NewPrivateKey().PublicKey().String()
	_, err := BuildChargeTransaction(context.Background(), signer, rpcClient, "1000", "sol", recipient, protocol.MethodDetails{
		Splits: []protocol.Split{{Recipient: split, Amount: "100", Memo: strings.Repeat("x", 600)}},
	}, BuildOptions{})
	if err == nil {
		t.Fatal("expected split memo too long error")
	}
}

func TestBuildChargeTransactionTokenWithSplitMemoTooLong(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	signer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey().String()
	split := testutil.NewPrivateKey().PublicKey().String()
	mint := testutil.NewPrivateKey().PublicKey()
	rpcClient.MintOwners[mint.String()] = solana.TokenProgramID
	decimals := uint8(6)
	_, err := BuildChargeTransaction(context.Background(), signer, rpcClient, "1000", mint.String(), recipient, protocol.MethodDetails{
		Decimals: &decimals,
		Splits:   []protocol.Split{{Recipient: split, Amount: "100", Memo: strings.Repeat("x", 600)}},
	}, BuildOptions{})
	if err == nil {
		t.Fatal("expected token split memo too long error")
	}
}

func TestBuildChargeTransactionTokenWithExternalIDMemoTooLong(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	signer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey().String()
	mint := testutil.NewPrivateKey().PublicKey()
	rpcClient.MintOwners[mint.String()] = solana.TokenProgramID
	decimals := uint8(6)
	_, err := BuildChargeTransaction(context.Background(), signer, rpcClient, "1000", mint.String(), recipient, protocol.MethodDetails{
		Decimals: &decimals,
	}, BuildOptions{ExternalID: strings.Repeat("x", 600)})
	if err == nil {
		t.Fatal("expected long externalId memo error in token path")
	}
}

// rpcSendErr forces SendTransaction to error to cover the broadcast error branch.
type rpcSendErr struct{ *testutil.FakeRPC }

func TestBuildChargeTransactionBroadcastSendError(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	rpcClient.SendErr = errors.New("send rpc down")
	signer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey().String()
	_, err := BuildChargeTransaction(context.Background(), signer, rpcClient, "1000", "sol", recipient, protocol.MethodDetails{}, BuildOptions{Broadcast: true})
	if err == nil {
		t.Fatal("expected send error")
	}
}

// Reference unused imports
var _ = solanautil.SplitAmounts
