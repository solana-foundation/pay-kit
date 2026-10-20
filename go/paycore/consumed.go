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
func legacyConsumedSignatureKey(signature string) string {
	return "solana-charge:consumed:" + signature
}

// Claim atomically claims signature. false means an earlier presentation,
// through any protocol, already claimed it.
func (c ConsumedSignatures) Claim(ctx context.Context, signature string) (bool, error) {
	consumed, err := c.consumedBeforeLedger(ctx, signature)
	if err != nil || consumed {
		return false, err
	}
	return c.store.PutIfAbsent(ctx, consumedSignatureKey(signature), true)
}

// consumedBeforeLedger reports whether signature was claimed under the
// pre-ledger MPP key, by a replica running an older release or before this
// one upgraded. Read only and fail closed: such a signature stays consumed,
// it is never migrated or claimed again.
func (c ConsumedSignatures) consumedBeforeLedger(ctx context.Context, signature string) (bool, error) {
	_, found, err := c.store.Get(ctx, legacyConsumedSignatureKey(signature))
	return found, err
}

// Release drops a claim this caller made for a transaction that provably
// never landed (for example a preflight rejection), so the payer may retry
// it.
func (c ConsumedSignatures) Release(ctx context.Context, signature string) error {
	return c.store.Delete(ctx, consumedSignatureKey(signature))
}
