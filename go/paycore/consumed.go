package paycore

import (
	"context"
	"encoding/json"
)

// ClaimStore is the slice of a replay store the consumed-signature ledger
// needs: an atomic insert-if-absent, a delete, and a read for the
// pre-ledger keys. The MPP core.Store satisfies it, so one store instance
// backs both protocols.
type ClaimStore interface {
	Get(ctx context.Context, key string) (json.RawMessage, bool, error)
	PutIfAbsent(ctx context.Context, key string, value any) (bool, error)
	Delete(ctx context.Context, key string) error
}

// ConsumedSignatures is the protocol-independent ledger of Solana
// transaction signatures that already authorized a protected response.
//
// MPP charge and x402 exact both claim here, so one on-chain payment
// authorizes one request whichever protocol presents it: a transaction
// settled through MPP cannot be presented again as an x402 signature proof
// on a gate that shares the store, and vice versa. The key is the
// signature alone (a signature commits to a cluster-specific blockhash),
// and matches the key every other SDK claims under so mixed-language
// replicas sharing one store agree.
type ConsumedSignatures struct {
	store ClaimStore
}

// NewConsumedSignatures wraps store as the shared ledger.
func NewConsumedSignatures(store ClaimStore) ConsumedSignatures {
	return ConsumedSignatures{store: store}
}

func consumedSignatureKey(signature string) string {
	return "solana:consumed-signature:" + signature
}

// legacyConsumedSignatureKey is the key MPP charge claimed signatures under
// before the shared ledger. x402 exact kept its claims in process memory
// then, so it left no store record to honour.
//
// Every claim also takes this key, so that during a rolling upgrade a
// replica still running the previous release (which claims and checks only
// this key) sees a payment this release accepted, and the other way round.
func legacyConsumedSignatureKey(signature string) string {
	return "solana-charge:consumed:" + signature
}

// Claim atomically claims signature. false means an earlier presentation,
// through any protocol and any release, already claimed it.
//
// The legacy key is taken first, with PutIfAbsent, so a replica on the
// previous release, which claims that key the same way, contends on the
// very same key: at most one of them wins, with no window between a check
// and a write. A signature already held under it (a pre-ledger claim, or a
// previous release's) stays consumed and is never migrated. When the claim
// fails, refused or on a store error, the legacy key this call took is
// given back: the caller then neither sends nor serves anything for it.
func (c ConsumedSignatures) Claim(ctx context.Context, signature string) (bool, error) {
	legacy := legacyConsumedSignatureKey(signature)
	took, err := c.store.PutIfAbsent(ctx, legacy, true)
	if err != nil || !took {
		return false, err
	}
	claimed, err := c.store.PutIfAbsent(ctx, consumedSignatureKey(signature), true)
	if err != nil || !claimed {
		_ = c.store.Delete(context.WithoutCancel(ctx), legacy)
		return false, err
	}
	return true, nil
}

// Release drops a claim this caller made for a transaction that provably
// never landed (for example a preflight rejection), so the payer may retry
// it. The ledger key goes first, then the legacy key the claim took.
func (c ConsumedSignatures) Release(ctx context.Context, signature string) error {
	if err := c.store.Delete(ctx, consumedSignatureKey(signature)); err != nil {
		return err
	}
	return c.store.Delete(ctx, legacyConsumedSignatureKey(signature))
}
