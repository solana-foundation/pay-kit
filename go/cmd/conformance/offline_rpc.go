package main

import (
	"context"
	"fmt"

	solana "github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"
)

// offlineRPC satisfies solanatx.RPCClient but refuses every network call.
// Conformance build/verify vectors pin a recent blockhash and resolve the
// token program ahead of time, so a real RPC call here signals the vector
// was under-specified rather than a determinism gap to paper over: every
// method returns an error that surfaces as a clear runner reject.
type offlineRPC struct{}

func newOfflineRPC() *offlineRPC { return &offlineRPC{} }

func (o *offlineRPC) errOffline(method string) error {
	return fmt.Errorf("offline conformance runner refused RPC call %s: vector must pin blockhash and token program", method)
}

func (o *offlineRPC) GetAccountInfoWithOpts(context.Context, solana.PublicKey, *rpc.GetAccountInfoOpts) (*rpc.GetAccountInfoResult, error) {
	return nil, o.errOffline("GetAccountInfo")
}

func (o *offlineRPC) GetLatestBlockhash(context.Context, rpc.CommitmentType) (*rpc.GetLatestBlockhashResult, error) {
	return nil, o.errOffline("GetLatestBlockhash")
}

func (o *offlineRPC) GetSignatureStatuses(context.Context, bool, ...solana.Signature) (*rpc.GetSignatureStatusesResult, error) {
	return nil, o.errOffline("GetSignatureStatuses")
}

func (o *offlineRPC) GetTransaction(context.Context, solana.Signature, *rpc.GetTransactionOpts) (*rpc.GetTransactionResult, error) {
	return nil, o.errOffline("GetTransaction")
}

func (o *offlineRPC) SendTransactionWithOpts(context.Context, *solana.Transaction, rpc.TransactionOpts) (solana.Signature, error) {
	return solana.Signature{}, o.errOffline("SendTransaction")
}

func (o *offlineRPC) SimulateTransactionWithOpts(context.Context, *solana.Transaction, *rpc.SimulateTransactionOpts) (*rpc.SimulateTransactionResponse, error) {
	return nil, o.errOffline("SimulateTransaction")
}
