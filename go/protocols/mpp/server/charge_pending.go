package server

import (
	"context"
	"encoding/json"
	"fmt"

	solana "github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"

	"github.com/solana-foundation/pay-kit/go/paycore"
	core "github.com/solana-foundation/pay-kit/go/protocols/mpp/core"
	"github.com/solana-foundation/pay-kit/go/protocols/mpp/intents"
)

// A pull charge whose transaction may have left the server but whose
// outcome is unknown (an ambiguous sendTransaction error, a confirmation
// timeout) is recorded as pending under its locally derived signature. The
// consumed-signature claim is kept, so the transaction can never be
// broadcast twice, and the client is told the settlement is in progress
// rather than handed a fresh challenge it could pay a second time. Retrying
// the identical credential reconciles the record against the chain.
const (
	pendingChargePrefix  = "solana-charge:pending:"
	resolvedChargePrefix = "solana-charge:pending-resolved:"
)

type pendingCharge struct {
	ChallengeID string `json:"challengeId"`
}

func settlementInProgress(signature string, cause error) *core.Error {
	return core.WrapError(core.ErrCodeSettlementInProgress,
		fmt.Sprintf("settlement of transaction %s is in progress; retry the same credential", signature), cause)
}

// markPending records signature as an in-flight charge for challengeID and
// returns the settlement-in-progress error to surface. It never releases
// the claim: if the record cannot be written the charge still fails closed
// (the signature stays consumed), it just cannot be reconciled to a receipt.
func (m *Mpp) markPending(ctx context.Context, signature, challengeID string, cause error) error {
	ctx = context.WithoutCancel(ctx)
	if err := m.store.Put(ctx, pendingChargePrefix+signature, pendingCharge{ChallengeID: challengeID}); err != nil {
		return settlementInProgress(signature, fmt.Errorf("%w (recording the pending charge failed: %w)", cause, err))
	}
	return settlementInProgress(signature, cause)
}

// reconcilePending resolves a presentation whose signature is already
// claimed. Without a pending record for this challenge the signature was
// settled before, so it is a replay. With one, only an explicit on-chain
// outcome resolves it: a missing status is never proof of non-execution
// (the node may lag or lack history for a transaction that committed in
// time), so it stays in progress.
func (m *Mpp) reconcilePending(
	ctx context.Context,
	credential core.PaymentCredential,
	request intents.ChargeRequest,
	details paycore.MethodDetails,
	signature solana.Signature,
) (core.Receipt, error) {
	consumed := core.NewError(core.ErrCodeSignatureConsumed, "transaction signature already consumed")
	key := signature.String()
	raw, ok, err := m.store.Get(ctx, pendingChargePrefix+key)
	if err != nil {
		return core.Receipt{}, err
	}
	if !ok {
		return core.Receipt{}, consumed
	}
	var record pendingCharge
	if err := json.Unmarshal(raw, &record); err != nil || record.ChallengeID != credential.Challenge.ID {
		return core.Receipt{}, consumed
	}
	out, err := m.rpc.GetSignatureStatuses(ctx, true, signature)
	if err != nil {
		return core.Receipt{}, settlementInProgress(key, err)
	}
	if out == nil || len(out.Value) == 0 || out.Value[0] == nil {
		return core.Receipt{}, settlementInProgress(key, nil)
	}
	status := out.Value[0]
	if status.Err != nil {
		_ = m.store.Delete(context.WithoutCancel(ctx), pendingChargePrefix+key)
		return core.Receipt{}, core.NewError(core.ErrCodeTransactionFailed,
			fmt.Sprintf("transaction landed on-chain but failed: %v", status.Err))
	}
	if status.ConfirmationStatus != rpc.ConfirmationStatusConfirmed &&
		status.ConfirmationStatus != rpc.ConfirmationStatusFinalized {
		return core.Receipt{}, settlementInProgress(key, nil)
	}
	if err := m.verifyOnChain(ctx, signature, request, details); err != nil {
		return core.Receipt{}, err
	}
	// Grant the landed charge exactly once across concurrent retries.
	granted, err := m.store.PutIfAbsent(ctx, resolvedChargePrefix+key, true)
	if err != nil {
		return core.Receipt{}, err
	}
	if !granted {
		return core.Receipt{}, consumed
	}
	_ = m.store.Delete(context.WithoutCancel(ctx), pendingChargePrefix+key)
	return successReceipt(key, credential.Challenge.ID, request.ExternalID), nil
}
