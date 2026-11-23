package client

import (
	"context"
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	solana "github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"

	"github.com/solana-foundation/pay-kit/go/internal/testutil"
	"github.com/solana-foundation/pay-kit/go/paycore"
	"github.com/solana-foundation/pay-kit/go/paycore/solanatx"
	core "github.com/solana-foundation/pay-kit/go/protocols/mpp/core"
)

// computeBudgetProgram is the ComputeBudget program id.
var computeBudgetProgram = solana.MustPublicKeyFromBase58("ComputeBudget111111111111111111111111111111")

// decodedInstruction is one top-level instruction with its program resolved.
type decodedInstruction struct {
	program solana.PublicKey
	data    []byte
}

func decodeInstructions(t *testing.T, payload paycore.CredentialPayload) (*solana.Transaction, []decodedInstruction) {
	t.Helper()
	tx, err := solanatx.DecodeTransactionBase64(payload.Transaction)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	out := make([]decodedInstruction, 0, len(tx.Message.Instructions))
	for _, ix := range tx.Message.Instructions {
		program, err := tx.Message.Program(ix.ProgramIDIndex)
		if err != nil {
			t.Fatalf("resolve program: %v", err)
		}
		out = append(out, decodedInstruction{program: program, data: ix.Data})
	}
	return tx, out
}

// assertComputeBudgetFirst checks the x402 exact SVM layout the charge
// builder follows: SetComputeUnitLimit at ix 0, SetComputeUnitPrice at ix 1.
func assertComputeBudgetFirst(t *testing.T, ixs []decodedInstruction, units uint32, microLamports uint64) {
	t.Helper()
	if len(ixs) < 3 {
		t.Fatalf("expected at least 3 instructions, got %d", len(ixs))
	}
	limit, price := ixs[0], ixs[1]
	if limit.program != computeBudgetProgram || len(limit.data) != 5 || limit.data[0] != 2 {
		t.Fatalf("ix 0 must be SetComputeUnitLimit, got program %s data %x", limit.program, limit.data)
	}
	if got := binary.LittleEndian.Uint32(limit.data[1:]); got != units {
		t.Fatalf("compute unit limit = %d, want %d", got, units)
	}
	if price.program != computeBudgetProgram || len(price.data) != 9 || price.data[0] != 3 {
		t.Fatalf("ix 1 must be SetComputeUnitPrice, got program %s data %x", price.program, price.data)
	}
	if got := binary.LittleEndian.Uint64(price.data[1:]); got != microLamports {
		t.Fatalf("compute unit price = %d, want %d", got, microLamports)
	}
	for i, ix := range ixs[2:] {
		if ix.program == computeBudgetProgram {
			t.Fatalf("ix %d is a ComputeBudget instruction after the transfer", i+2)
		}
	}
}

func TestBuildChargeTransactionTokenWithFeePayerOrdersLimitPriceTransfer(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	signer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey().String()
	feePayer := testutil.NewPrivateKey().PublicKey()
	mint := testutil.NewPrivateKey().PublicKey()
	rpcClient.MintOwners[mint.String()] = solana.TokenProgramID
	decimals := uint8(6)
	enabled := true

	payload, err := BuildChargeTransaction(context.Background(), signer, rpcClient, "1000", mint.String(), recipient, paycore.MethodDetails{
		Decimals:    &decimals,
		FeePayer:    &enabled,
		FeePayerKey: feePayer.String(),
	}, BuildOptions{})
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}
	tx, ixs := decodeInstructions(t, payload)
	if tx.Message.AccountKeys[0] != feePayer {
		t.Fatalf("expected the server fee payer first, got %s", tx.Message.AccountKeys[0])
	}
	if len(ixs) != 3 {
		t.Fatalf("expected limit, price, transfer; got %d instructions", len(ixs))
	}
	assertComputeBudgetFirst(t, ixs, 200_000, 1)
	transfer := ixs[2]
	if transfer.program != solana.TokenProgramID || len(transfer.data) != 10 || transfer.data[0] != 12 {
		t.Fatalf("ix 2 must be TransferChecked, got program %s data %x", transfer.program, transfer.data)
	}
	if got := binary.LittleEndian.Uint64(transfer.data[1:9]); got != 1000 {
		t.Fatalf("transfer amount = %d, want 1000", got)
	}
}

func TestBuildChargeTransactionSOLOrdersCustomLimitBeforePrice(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	signer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey().String()

	payload, err := BuildChargeTransaction(context.Background(), signer, rpcClient, "1000", "sol", recipient, paycore.MethodDetails{}, BuildOptions{
		ComputeUnitLimit: 400_000,
		ComputeUnitPrice: 100,
	})
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}
	_, ixs := decodeInstructions(t, payload)
	if len(ixs) != 3 {
		t.Fatalf("expected limit, price, transfer; got %d instructions", len(ixs))
	}
	assertComputeBudgetFirst(t, ixs, 400_000, 100)
	if ixs[2].program != solana.SystemProgramID {
		t.Fatalf("ix 2 must be the System transfer, got %s", ixs[2].program)
	}
}

func TestBuildChargeTransactionSigningErrorPropagates(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	signer := failingSigner{pub: testutil.NewPrivateKey().PublicKey()}
	recipient := testutil.NewPrivateKey().PublicKey().String()

	_, err := BuildChargeTransaction(context.Background(), signer, rpcClient, "1000", "sol", recipient, paycore.MethodDetails{}, BuildOptions{})
	if err == nil || !strings.Contains(err.Error(), "signer unavailable") {
		t.Fatalf("expected the signing error, got %v", err)
	}
}

// failedStatusRPC reports every signature as failed on chain.
type failedStatusRPC struct {
	*testutil.FakeRPC
}

func (f failedStatusRPC) GetSignatureStatuses(_ context.Context, _ bool, signatures ...solana.Signature) (*rpc.GetSignatureStatusesResult, error) {
	values := make([]*rpc.SignatureStatusesResult, 0, len(signatures))
	for range signatures {
		values = append(values, &rpc.SignatureStatusesResult{Err: "InstructionError"})
	}
	return &rpc.GetSignatureStatusesResult{Value: values}, nil
}

func TestBuildChargeTransactionBroadcastConfirmationFailure(t *testing.T) {
	rpcClient := failedStatusRPC{FakeRPC: testutil.NewFakeRPC()}
	signer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey().String()

	_, err := BuildChargeTransaction(context.Background(), signer, rpcClient, "1000", "sol", recipient, paycore.MethodDetails{}, BuildOptions{Broadcast: true})
	var coreErr *core.Error
	if !errors.As(err, &coreErr) || coreErr.Code != core.ErrCodeTransactionFailed {
		t.Fatalf("expected a transaction-failed error, got %v", err)
	}
}

func TestBuildCredentialHeaderMaxAmountRejectsUnparsableAmount(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	signer := testutil.NewPrivateKey()
	challengeRequest, _ := core.NewBase64URLJSONValue(map[string]any{
		"amount":        "not-a-number",
		"currency":      "sol",
		"recipient":     testutil.NewPrivateKey().PublicKey().String(),
		"methodDetails": map[string]any{"network": "localnet"},
	})
	challenge := core.NewChallengeWithSecret("secret", "realm", "solana", "charge", challengeRequest)

	if _, err := BuildCredentialHeaderWithOptions(context.Background(), signer, rpcClient, challenge, BuildOptions{MaxAmountBaseUnits: 1000}); err == nil {
		t.Fatal("expected an amount parse error before the cap check")
	}
}
