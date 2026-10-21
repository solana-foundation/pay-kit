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

// Rolling upgrade: a replica on the previous release claims and checks only
// the legacy key. Every claim takes it too, so such a replica refuses a
// payment this release accepted; a release gives it back.
func TestClaimIsVisibleToReplicasOnThePreviousRelease(t *testing.T) {
	ctx := context.Background()
	store := core.NewMemoryStore()
	ledger := paycore.NewConsumedSignatures(store)
	const legacyKey = "solana-charge:consumed:sig-new"

	if claimed, err := ledger.Claim(ctx, "sig-new"); err != nil || !claimed {
		t.Fatalf("claim = %v, %v", claimed, err)
	}
	if took, _ := store.PutIfAbsent(ctx, legacyKey, true); took {
		t.Fatal("a previous-release replica could claim a signature this release accepted")
	}

	if err := ledger.Release(ctx, "sig-new"); err != nil {
		t.Fatal(err)
	}
	if _, found, _ := store.Get(ctx, legacyKey); found {
		t.Fatal("release left the legacy key behind")
	}
	if claimed, err := ledger.Claim(ctx, "sig-new"); err != nil || !claimed {
		t.Fatalf("claim after release = %v, %v", claimed, err)
	}
}

// A refused claim gives back the legacy key it took.
func TestRefusedClaimGivesBackTheLegacyKey(t *testing.T) {
	ctx := context.Background()
	store := core.NewMemoryStore()
	ledger := paycore.NewConsumedSignatures(store)
	if err := store.Put(ctx, "solana:consumed-signature:sig-held", true); err != nil {
		t.Fatal(err)
	}
	if claimed, _ := ledger.Claim(ctx, "sig-held"); claimed {
		t.Fatal("claimed a held signature")
	}
	if _, found, _ := store.Get(ctx, "solana-charge:consumed:sig-held"); found {
		t.Fatal("a refused claim kept the legacy key")
	}
}
