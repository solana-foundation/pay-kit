// Package testutil holds unit-test scaffolding shared across the Go
// MPP packages: a deterministic in-memory RPC fake that satisfies the
// utils.RPCClient interface and a helper for generating ephemeral
// signers. Internal-only; consumers depending on the SDK should not
// import this package.
package testutil

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"

	bin "github.com/gagliardetto/binary"
	solana "github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"
)

// NewPrivateKey returns a fresh test signer. Panics on key-generation
// failure (only possible if the crypto/rand source is broken, which
// should never happen in a unit test environment).
func NewPrivateKey() solana.PrivateKey {
	key, err := solana.NewRandomPrivateKey()
	if err != nil {
		panic(err)
	}
	return key
}

// FakeRPC is a deterministic RPC stub for unit tests.
type FakeRPC struct {
	mu sync.Mutex

	Blockhash  solana.Hash
	MintOwners map[string]solana.PublicKey
	Statuses   map[string]*rpc.SignatureStatusesResult
	BySig      map[string]*solana.Transaction

	SimulateErr error
	SendErr     error
	GetTxErr    error

	Simulated []*solana.Transaction
	Sent      []*solana.Transaction
}

// NewFakeRPC creates a FakeRPC with sensible defaults.
func NewFakeRPC() *FakeRPC {
	blockhash := solana.MustHashFromBase58("4vJ9JU1bJJbzZ4aJ8AqGxH9bK5VwY8bGf3sD5QG6h7h")
	return &FakeRPC{
		Blockhash:  blockhash,
		MintOwners: map[string]solana.PublicKey{},
		Statuses:   map[string]*rpc.SignatureStatusesResult{},
		BySig:      map[string]*solana.Transaction{},
	}
}

// GetAccountInfoWithOpts looks up the canned mint owner registered for
// account; returns rpc.ErrNotFound when the account is unknown so the
// SDK exercises the same not-found branch as a live RPC.
func (f *FakeRPC) GetAccountInfoWithOpts(_ context.Context, account solana.PublicKey, _ *rpc.GetAccountInfoOpts) (*rpc.GetAccountInfoResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	owner, ok := f.MintOwners[account.String()]
	if !ok {
		return nil, rpc.ErrNotFound
	}
	return &rpc.GetAccountInfoResult{
		Value: &rpc.Account{
			Owner: owner,
		},
	}, nil
}

// GetLatestBlockhash returns the canned Blockhash on the fake RPC.
func (f *FakeRPC) GetLatestBlockhash(_ context.Context, _ rpc.CommitmentType) (*rpc.GetLatestBlockhashResult, error) {
	return &rpc.GetLatestBlockhashResult{
		Value: &rpc.LatestBlockhashResult{Blockhash: f.Blockhash},
	}, nil
}

// GetSignatureStatuses returns the canned per-signature status, falling
// back to a confirmed status so the WaitForConfirmation poll completes
// in a single round when no override is registered.
func (f *FakeRPC) GetSignatureStatuses(_ context.Context, _ bool, signatures ...solana.Signature) (*rpc.GetSignatureStatusesResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	values := make([]*rpc.SignatureStatusesResult, 0, len(signatures))
	for _, signature := range signatures {
		if status, ok := f.Statuses[signature.String()]; ok {
			values = append(values, status)
			continue
		}
		values = append(values, &rpc.SignatureStatusesResult{
			ConfirmationStatus: rpc.ConfirmationStatusConfirmed,
		})
	}
	return &rpc.GetSignatureStatusesResult{Value: values}, nil
}

// GetTransaction returns the canned GetTxErr first (so tests can force
// not-found / RPC failure branches), then the recorded transaction for
// the signature, or rpc.ErrNotFound when neither is set.
func (f *FakeRPC) GetTransaction(_ context.Context, signature solana.Signature, _ *rpc.GetTransactionOpts) (*rpc.GetTransactionResult, error) {
	if f.GetTxErr != nil {
		return nil, f.GetTxErr
	}
	f.mu.Lock()
	tx, ok := f.BySig[signature.String()]
	f.mu.Unlock()
	if !ok {
		return nil, rpc.ErrNotFound
	}
	return TxResultFromTransaction(tx)
}

// SendTransactionWithOpts records the broadcast transaction (clone) and
// returns its first signature, defaulting the per-signature status to
// confirmed so a follow-up WaitForConfirmation poll terminates on the
// first round.
func (f *FakeRPC) SendTransactionWithOpts(_ context.Context, tx *solana.Transaction, _ rpc.TransactionOpts) (solana.Signature, error) {
	if f.SendErr != nil {
		return solana.Signature{}, f.SendErr
	}
	cloned, err := cloneTransaction(tx)
	if err != nil {
		return solana.Signature{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Sent = append(f.Sent, cloned)
	signature := cloned.Signatures[0]
	f.BySig[signature.String()] = cloned
	if _, ok := f.Statuses[signature.String()]; !ok {
		f.Statuses[signature.String()] = &rpc.SignatureStatusesResult{
			ConfirmationStatus: rpc.ConfirmationStatusConfirmed,
		}
	}
	return signature, nil
}

// SimulateTransactionWithOpts records the simulated transaction (clone)
// and returns a successful empty response, or the canned SimulateErr
// when tests force a simulation failure branch.
func (f *FakeRPC) SimulateTransactionWithOpts(_ context.Context, tx *solana.Transaction, _ *rpc.SimulateTransactionOpts) (*rpc.SimulateTransactionResponse, error) {
	if f.SimulateErr != nil {
		return nil, f.SimulateErr
	}
	cloned, err := cloneTransaction(tx)
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Simulated = append(f.Simulated, cloned)
	return &rpc.SimulateTransactionResponse{
		Value: &rpc.SimulateTransactionResult{},
	}, nil
}

// TxResultFromTransaction converts a transaction into an rpc.GetTransactionResult.
func TxResultFromTransaction(tx *solana.Transaction) (*rpc.GetTransactionResult, error) {
	wire, err := tx.MarshalBinary()
	if err != nil {
		return nil, err
	}
	payload := fmt.Sprintf(`{"slot":1,"transaction":["%s","base64"],"meta":null,"version":"legacy"}`, base64.StdEncoding.EncodeToString(wire))
	var out rpc.GetTransactionResult
	if err := json.Unmarshal([]byte(payload), &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func cloneTransaction(tx *solana.Transaction) (*solana.Transaction, error) {
	wire, err := tx.MarshalBinary()
	if err != nil {
		return nil, err
	}
	cloned := new(solana.Transaction)
	if err := cloned.UnmarshalWithDecoder(bin.NewBinDecoder(wire)); err != nil {
		return nil, err
	}
	return cloned, nil
}
