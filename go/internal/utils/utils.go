// Package utils holds internal Solana-toolchain glue used by the
// MPP charge handlers and client builders: a minimal Signer interface,
// an RPCClient interface mirroring the subset of gagliardetto's
// solana-go RPC client the SDK depends on, plus helpers to build SOL /
// SPL transfer / associated-token-account / compute-budget / memo
// instructions, decode transactions, split amounts, and run the
// simulate-broadcast-confirm sequence. Internal-only; the public SDK
// surface lives in the top-level mpp/server/client packages.
package utils

import (
	"context"
	"encoding/base64"
	"fmt"
	"math/bits"
	"strconv"
	"time"

	bin "github.com/gagliardetto/binary"
	solana "github.com/gagliardetto/solana-go"
	computebudget "github.com/gagliardetto/solana-go/programs/compute-budget"
	"github.com/gagliardetto/solana-go/programs/system"
	"github.com/gagliardetto/solana-go/programs/token"
	token2022 "github.com/gagliardetto/solana-go/programs/token-2022"
	"github.com/gagliardetto/solana-go/rpc"

	mpp "github.com/solana-foundation/pay-kit/go"
	"github.com/solana-foundation/pay-kit/go/protocol"
)

// Signer is the minimal signer surface shared by the client and server packages.
type Signer interface {
	PublicKey() solana.PublicKey
	Sign(payload []byte) (solana.Signature, error)
}

// RPCClient captures the RPC methods used by the SDK.
type RPCClient interface {
	GetAccountInfoWithOpts(context.Context, solana.PublicKey, *rpc.GetAccountInfoOpts) (*rpc.GetAccountInfoResult, error)
	GetLatestBlockhash(context.Context, rpc.CommitmentType) (*rpc.GetLatestBlockhashResult, error)
	GetSignatureStatuses(context.Context, bool, ...solana.Signature) (*rpc.GetSignatureStatusesResult, error)
	GetTransaction(context.Context, solana.Signature, *rpc.GetTransactionOpts) (*rpc.GetTransactionResult, error)
	SendTransactionWithOpts(context.Context, *solana.Transaction, rpc.TransactionOpts) (solana.Signature, error)
	SimulateTransactionWithOpts(context.Context, *solana.Transaction, *rpc.SimulateTransactionOpts) (*rpc.SimulateTransactionResponse, error)
}

// BuildSOLTransfer appends a native SOL transfer.
func BuildSOLTransfer(from, to solana.PublicKey, lamports uint64) (solana.Instruction, error) {
	return system.NewTransferInstruction(lamports, from, to).ValidateAndBuild()
}

// BuildComputeUnitLimit appends a compute budget limit instruction.
func BuildComputeUnitLimit(units uint32) (solana.Instruction, error) {
	return computebudget.NewSetComputeUnitLimitInstruction(units).ValidateAndBuild()
}

// BuildComputeUnitPrice appends a compute budget price instruction.
func BuildComputeUnitPrice(microLamports uint64) (solana.Instruction, error) {
	return computebudget.NewSetComputeUnitPriceInstruction(microLamports).ValidateAndBuild()
}

// BuildMemoInstruction builds a Solana Memo Program instruction.
func BuildMemoInstruction(memo string) (solana.Instruction, error) {
	if len([]byte(memo)) > 566 {
		return nil, fmt.Errorf("memo cannot exceed 566 bytes")
	}
	programID, err := solana.PublicKeyFromBase58(protocol.MemoProgram)
	if err != nil {
		return nil, err
	}
	return solana.NewInstruction(programID, solana.AccountMetaSlice{}, []byte(memo)), nil
}

// BuildCreateAssociatedTokenAccount creates an idempotent ATA create instruction.
func BuildCreateAssociatedTokenAccount(payer, wallet, mint, tokenProgram solana.PublicKey) (solana.Instruction, error) {
	ata, err := FindAssociatedTokenAddressWithProgram(wallet, mint, tokenProgram)
	if err != nil {
		return nil, err
	}
	return solana.NewInstruction(
		solana.SPLAssociatedTokenAccountProgramID,
		solana.AccountMetaSlice{
			solana.Meta(payer).WRITE().SIGNER(),
			solana.Meta(ata).WRITE(),
			solana.Meta(wallet),
			solana.Meta(mint),
			solana.Meta(solana.SystemProgramID),
			solana.Meta(tokenProgram),
		},
		[]byte{1},
	), nil
}

// BuildTransferChecked builds a token transfer checked instruction.
func BuildTransferChecked(amount uint64, decimals uint8, source, mint, destination, owner, tokenProgram solana.PublicKey) (solana.Instruction, error) {
	if tokenProgram.Equals(solana.TokenProgramID) {
		return token.NewTransferCheckedInstruction(amount, decimals, source, mint, destination, owner, nil).ValidateAndBuild()
	}
	if tokenProgram.Equals(solana.MustPublicKeyFromBase58(protocol.Token2022Program)) {
		return token2022.NewTransferCheckedInstruction(amount, decimals, source, mint, destination, owner, nil).ValidateAndBuild()
	}
	return nil, fmt.Errorf("unsupported token program %s", tokenProgram)
}

// FindAssociatedTokenAddress derives the ATA for a wallet and mint.
func FindAssociatedTokenAddress(wallet, mint solana.PublicKey) (solana.PublicKey, error) {
	ata, _, err := solana.FindAssociatedTokenAddress(wallet, mint)
	return ata, err
}

// FindAssociatedTokenAddressWithProgram derives an ATA for either Token or Token-2022.
func FindAssociatedTokenAddressWithProgram(wallet, mint, tokenProgram solana.PublicKey) (solana.PublicKey, error) {
	if tokenProgram.Equals(solana.TokenProgramID) {
		return FindAssociatedTokenAddress(wallet, mint)
	}
	address, _, err := solana.FindProgramAddress([][]byte{
		wallet[:],
		tokenProgram[:],
		mint[:],
	}, solana.SPLAssociatedTokenAccountProgramID)
	return address, err
}

// EncodeTransactionBase64 returns a base64 wire transaction.
func EncodeTransactionBase64(tx *solana.Transaction) (string, error) {
	wire, err := tx.MarshalBinary()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(wire), nil
}

// DecodeTransactionBase64 decodes a base64 wire transaction.
func DecodeTransactionBase64(encoded string) (*solana.Transaction, error) {
	wire, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	tx := new(solana.Transaction)
	if err := tx.UnmarshalWithDecoder(bin.NewBinDecoder(wire)); err != nil {
		return nil, err
	}
	return tx, nil
}

// SignTransaction signs a transaction for a single signer without requiring a solana.PrivateKey getter.
func SignTransaction(tx *solana.Transaction, signer Signer) error {
	message, err := tx.Message.MarshalBinary()
	if err != nil {
		return err
	}
	signature, err := signer.Sign(message)
	if err != nil {
		return err
	}
	signers := tx.Message.Signers()
	if len(tx.Signatures) != len(signers) {
		tx.Signatures = make([]solana.Signature, len(signers))
	}
	index := -1
	for i, key := range signers {
		if key.Equals(signer.PublicKey()) {
			index = i
			break
		}
	}
	if index < 0 {
		return fmt.Errorf("signer %s is not required by transaction", signer.PublicKey())
	}
	tx.Signatures[index] = signature
	return nil
}

// ResolveTokenProgram resolves the mint owner into the token program ID.
func ResolveTokenProgram(ctx context.Context, rpcClient RPCClient, mint solana.PublicKey, tokenProgramHint string) (solana.PublicKey, error) {
	if tokenProgramHint != "" {
		return solana.PublicKeyFromBase58(tokenProgramHint)
	}
	account, err := rpcClient.GetAccountInfoWithOpts(ctx, mint, &rpc.GetAccountInfoOpts{
		Commitment: rpc.CommitmentConfirmed,
		Encoding:   solana.EncodingBase64,
	})
	if err != nil {
		return solana.PublicKey{}, err
	}
	if account.Value == nil {
		return solana.PublicKey{}, fmt.Errorf("mint account not found")
	}
	switch account.Value.Owner.String() {
	case protocol.TokenProgram:
		return solana.TokenProgramID, nil
	case protocol.Token2022Program:
		return solana.MustPublicKeyFromBase58(protocol.Token2022Program), nil
	default:
		return solana.PublicKey{}, fmt.Errorf("unsupported mint owner %s", account.Value.Owner)
	}
}

// ResolveRecentBlockhash returns the provided blockhash or fetches one from RPC.
func ResolveRecentBlockhash(ctx context.Context, rpcClient RPCClient, provided string) (solana.Hash, error) {
	if provided != "" {
		return solana.HashFromBase58(provided)
	}
	out, err := rpcClient.GetLatestBlockhash(ctx, rpc.CommitmentConfirmed)
	if err != nil {
		return solana.Hash{}, err
	}
	return out.Value.Blockhash, nil
}

// WaitForConfirmation polls the RPC until a signature reaches confirmed/finalized.
func WaitForConfirmation(ctx context.Context, rpcClient RPCClient, signature solana.Signature) error {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		out, err := rpcClient.GetSignatureStatuses(ctx, true, signature)
		if err == nil && out != nil && len(out.Value) > 0 && out.Value[0] != nil {
			status := out.Value[0]
			if status.Err != nil {
				return fmt.Errorf("transaction failed on-chain: %v", status.Err)
			}
			if status.ConfirmationStatus == rpc.ConfirmationStatusConfirmed || status.ConfirmationStatus == rpc.ConfirmationStatusFinalized || status.Confirmations == nil {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// SimulateTransaction runs preflight simulation.
func SimulateTransaction(ctx context.Context, rpcClient RPCClient, tx *solana.Transaction) error {
	out, err := rpcClient.SimulateTransactionWithOpts(ctx, tx, &rpc.SimulateTransactionOpts{
		Commitment: rpc.CommitmentConfirmed,
		SigVerify:  true,
	})
	if err != nil {
		return err
	}
	if out != nil && out.Value != nil && out.Value.Err != nil {
		return fmt.Errorf("simulation failed: %v", out.Value.Err)
	}
	return nil
}

// SendTransaction submits the transaction to the cluster.
func SendTransaction(ctx context.Context, rpcClient RPCClient, tx *solana.Transaction) (solana.Signature, error) {
	return rpcClient.SendTransactionWithOpts(ctx, tx, rpc.TransactionOpts{
		SkipPreflight:       false,
		PreflightCommitment: rpc.CommitmentConfirmed,
	})
}

// FetchTransaction returns a decoded transaction plus meta.
func FetchTransaction(ctx context.Context, rpcClient RPCClient, signature solana.Signature) (*solana.Transaction, *rpc.TransactionMeta, error) {
	version := uint64(0)
	result, err := rpcClient.GetTransaction(ctx, signature, &rpc.GetTransactionOpts{
		Commitment:                     rpc.CommitmentConfirmed,
		Encoding:                       solana.EncodingBase64,
		MaxSupportedTransactionVersion: &version,
	})
	if err != nil {
		return nil, nil, err
	}
	tx, err := result.Transaction.GetTransaction()
	if err != nil {
		return nil, nil, err
	}
	return tx, result.Meta, nil
}

// SplitAmounts computes the primary transfer amount and validates the split set.
func SplitAmounts(total uint64, splits []protocol.Split) (uint64, error) {
	if len(splits) > 8 {
		return 0, mpp.NewError(mpp.ErrCodeTooManySplits, "splits exceed maximum of 8 entries")
	}
	var splitTotal uint64
	for _, split := range splits {
		amount, err := strconv.ParseUint(split.Amount, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid split amount %q", split.Amount)
		}
		sum, carry := bits.Add64(splitTotal, amount, 0)
		if carry != 0 {
			return 0, mpp.NewError(mpp.ErrCodeSplitsExceed, "splits consume the entire amount")
		}
		splitTotal = sum
	}
	if splitTotal >= total {
		return 0, mpp.NewError(mpp.ErrCodeSplitsExceed, "splits consume the entire amount")
	}
	return total - splitTotal, nil
}
