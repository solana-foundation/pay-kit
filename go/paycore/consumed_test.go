package paycore_test

import (
	"context"
	"testing"

	"github.com/solana-foundation/pay-kit/go/paycore"
	"github.com/solana-foundation/pay-kit/go/protocols/mpp/core"
)

// A signature claimed under the pre-ledger MPP key (by an older replica, or
// just before an upgrade) stays consumed, and the legacy record is only
// read, never rewritten.
func TestLegacyMppChargeClaimStaysConsumed(t *testing.T) {
	ctx := context.Background()
	store := core.NewMemoryStore()
	ledger := paycore.NewConsumedSignatures(store)
	const legacyKey = "solana-charge:consumed:sig-legacy"
	if err := store.Put(ctx, legacyKey, true); err != nil {
		t.Fatal(err)
	}

	claimed, err := ledger.Claim(ctx, "sig-legacy")
	if err != nil || claimed {
		t.Fatalf("legacy claim = %v, %v; want refused", claimed, err)
	}
	if _, found, _ := store.Get(ctx, "solana:consumed-signature:sig-legacy"); found {
		t.Fatal("legacy signature was migrated into the ledger")
	}
	if _, found, _ := store.Get(ctx, legacyKey); !found {
		t.Fatal("legacy record was rewritten")
	}

	// Signatures without a legacy record claim normally, once.
	if claimed, err := ledger.Claim(ctx, "sig-fresh"); err != nil || !claimed {
		t.Fatalf("fresh claim = %v, %v; want claimed", claimed, err)
	}
	if claimed, _ := ledger.Claim(ctx, "sig-fresh"); claimed {
		t.Fatal("second claim of sig-fresh succeeded")
	}
}
