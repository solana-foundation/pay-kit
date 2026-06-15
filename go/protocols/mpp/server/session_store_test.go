package server

// MemoryChannelStore coverage: insert-on-missing updates, mutator error
// handling, concurrent update serialization, list filtering, delete,
// finalization, and clone isolation.

import (
	"context"
	"errors"
	"sync"
	"testing"
)

func testChannelState(channelID string, deposit uint64) ChannelState {
	return ChannelState{
		ChannelID:        channelID,
		AuthorizedSigner: "11111111111111111111111111111111",
		Deposit:          deposit,
	}
}

func TestMemoryChannelStoreUpdateChannelInsertsWhenMissing(t *testing.T) {
	store := NewMemoryChannelStore()
	ctx := context.Background()

	result, err := store.UpdateChannel(ctx, "c1", func(current *ChannelState) (ChannelState, error) {
		if current != nil {
			t.Fatalf("expected nil current state, got %+v", current)
		}
		return testChannelState("c1", 5), nil
	})
	if err != nil {
		t.Fatalf("UpdateChannel: %v", err)
	}
	if result.Deposit != 5 {
		t.Fatalf("deposit = %d, want 5", result.Deposit)
	}

	stored, err := store.GetChannel(ctx, "c1")
	if err != nil || stored == nil {
		t.Fatalf("GetChannel: state=%v err=%v", stored, err)
	}
	if stored.Deposit != 5 {
		t.Fatalf("stored deposit = %d, want 5", stored.Deposit)
	}
}

func TestMemoryChannelStoreUpdateChannelSeesPriorWrites(t *testing.T) {
	store := NewMemoryChannelStore()
	ctx := context.Background()

	if _, err := store.UpdateChannel(ctx, "c1", func(*ChannelState) (ChannelState, error) {
		return testChannelState("c1", 1), nil
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}

	next, err := store.UpdateChannel(ctx, "c1", func(current *ChannelState) (ChannelState, error) {
		if current == nil || current.Deposit != 1 {
			t.Fatalf("current = %+v, want deposit 1", current)
		}
		out := *current
		out.Deposit = 2
		return out, nil
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if next.Deposit != 2 {
		t.Fatalf("deposit = %d, want 2", next.Deposit)
	}
}

func TestMemoryChannelStoreSerializesConcurrentUpdates(t *testing.T) {
	store := NewMemoryChannelStore()
	ctx := context.Background()

	if _, err := store.UpdateChannel(ctx, "c1", func(*ChannelState) (ChannelState, error) {
		return testChannelState("c1", 1_000_000), nil
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}

	// Fire 50 concurrent increments; each must see the previous value.
	const workers = 50
	var wg sync.WaitGroup
	wg.Add(workers)
	for range workers {
		go func() {
			defer wg.Done()
			_, err := store.UpdateChannel(ctx, "c1", func(current *ChannelState) (ChannelState, error) {
				out := *current
				out.Cumulative++
				return out, nil
			})
			if err != nil {
				t.Errorf("concurrent update: %v", err)
			}
		}()
	}
	wg.Wait()

	stored, err := store.GetChannel(ctx, "c1")
	if err != nil || stored == nil {
		t.Fatalf("GetChannel: state=%v err=%v", stored, err)
	}
	if stored.Cumulative != workers {
		t.Fatalf("cumulative = %d, want %d", stored.Cumulative, workers)
	}
}

func TestMemoryChannelStoreMutatorErrorLeavesStateUnchanged(t *testing.T) {
	store := NewMemoryChannelStore()
	ctx := context.Background()

	if _, err := store.UpdateChannel(ctx, "c1", func(*ChannelState) (ChannelState, error) {
		state := testChannelState("c1", 1_000_000)
		state.Cumulative = 7
		return state, nil
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}

	wantErr := errors.New("nope")
	if _, err := store.UpdateChannel(ctx, "c1", func(*ChannelState) (ChannelState, error) {
		return ChannelState{}, wantErr
	}); !errors.Is(err, wantErr) {
		t.Fatalf("err = %v, want %v", err, wantErr)
	}

	stored, err := store.GetChannel(ctx, "c1")
	if err != nil || stored == nil {
		t.Fatalf("GetChannel: state=%v err=%v", stored, err)
	}
	if stored.Cumulative != 7 || stored.Deposit != 1_000_000 {
		t.Fatalf("state mutated by failed update: %+v", stored)
	}

	// A failed update must not poison subsequent updates on the same channel.
	next, err := store.UpdateChannel(ctx, "c1", func(current *ChannelState) (ChannelState, error) {
		out := *current
		out.Cumulative++
		return out, nil
	})
	if err != nil {
		t.Fatalf("follow-up update: %v", err)
	}
	if next.Cumulative != 8 {
		t.Fatalf("cumulative = %d, want 8", next.Cumulative)
	}
}

func TestMemoryChannelStoreListChannelsAppliesFilters(t *testing.T) {
	store := NewMemoryChannelStore()
	ctx := context.Background()

	mustInsert := func(state ChannelState) {
		t.Helper()
		if _, err := store.UpdateChannel(ctx, state.ChannelID, func(*ChannelState) (ChannelState, error) {
			return state, nil
		}); err != nil {
			t.Fatalf("insert %s: %v", state.ChannelID, err)
		}
	}
	mustInsert(testChannelState("a", 1))
	finalized := testChannelState("b", 1)
	finalized.Finalized = true
	mustInsert(finalized)
	closing := testChannelState("c", 1)
	closeAt := uint64(123)
	closing.CloseRequestedAt = &closeAt
	mustInsert(closing)

	all, err := store.ListChannels(ctx, nil)
	if err != nil {
		t.Fatalf("ListChannels: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("len(all) = %d, want 3", len(all))
	}

	wantTrue, wantFalse := true, false
	onlyFinalized, err := store.ListChannels(ctx, &ListChannelsFilter{Finalized: &wantTrue})
	if err != nil {
		t.Fatalf("ListChannels finalized: %v", err)
	}
	if len(onlyFinalized) != 1 || onlyFinalized[0].ChannelID != "b" {
		t.Fatalf("finalized filter = %+v, want only b", onlyFinalized)
	}

	closePending, err := store.ListChannels(ctx, &ListChannelsFilter{Finalized: &wantFalse, ClosePending: &wantTrue})
	if err != nil {
		t.Fatalf("ListChannels closePending: %v", err)
	}
	if len(closePending) != 1 || closePending[0].ChannelID != "c" {
		t.Fatalf("closePending filter = %+v, want only c", closePending)
	}
}

func TestMemoryChannelStoreDeleteAndMarkFinalized(t *testing.T) {
	store := NewMemoryChannelStore()
	ctx := context.Background()

	if _, err := store.UpdateChannel(ctx, "c1", func(*ChannelState) (ChannelState, error) {
		return testChannelState("c1", 1), nil
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}

	state, err := store.MarkFinalized(ctx, "c1")
	if err != nil {
		t.Fatalf("MarkFinalized: %v", err)
	}
	if !state.Finalized {
		t.Fatal("expected finalized state")
	}
	stored, err := store.GetChannel(ctx, "c1")
	if err != nil || stored == nil || !stored.Finalized {
		t.Fatalf("stored state = %+v err=%v, want finalized", stored, err)
	}

	if err := store.DeleteChannel(ctx, "c1"); err != nil {
		t.Fatalf("DeleteChannel: %v", err)
	}
	missing, err := store.GetChannel(ctx, "c1")
	if err != nil {
		t.Fatalf("GetChannel after delete: %v", err)
	}
	if missing != nil {
		t.Fatalf("expected nil after delete, got %+v", missing)
	}

	if _, err := store.MarkFinalized(ctx, "ghost"); err == nil {
		t.Fatal("expected error marking missing channel finalized")
	}
}

func TestMemoryChannelStoreReturnsClones(t *testing.T) {
	store := NewMemoryChannelStore()
	ctx := context.Background()

	signature := "sig"
	if _, err := store.UpdateChannel(ctx, "c1", func(*ChannelState) (ChannelState, error) {
		state := testChannelState("c1", 1)
		state.HighestVoucherSignature = &signature
		state.PendingDeliveries = []PendingDelivery{{DeliveryID: "c1:1", Amount: 1, Sequence: 1, ExpiresAt: 9}}
		return state, nil
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}

	got, err := store.GetChannel(ctx, "c1")
	if err != nil || got == nil {
		t.Fatalf("GetChannel: state=%v err=%v", got, err)
	}
	*got.HighestVoucherSignature = "tampered"
	got.PendingDeliveries[0].Amount = 99

	fresh, err := store.GetChannel(ctx, "c1")
	if err != nil || fresh == nil {
		t.Fatalf("GetChannel: state=%v err=%v", fresh, err)
	}
	if *fresh.HighestVoucherSignature != "sig" {
		t.Fatalf("stored signature mutated through returned pointer: %q", *fresh.HighestVoucherSignature)
	}
	if fresh.PendingDeliveries[0].Amount != 1 {
		t.Fatalf("stored pending delivery mutated through returned slice: %+v", fresh.PendingDeliveries)
	}
}
