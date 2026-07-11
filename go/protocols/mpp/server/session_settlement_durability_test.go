package server

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/solana-foundation/pay-kit/go/internal/testutil"
)

// sharedJSONChannelBackend models a durable database shared by independent
// ChannelStore clients. Every update crosses a JSON serialization boundary.
type sharedJSONChannelBackend struct {
	mu   sync.Mutex
	data map[string][]byte
}

type sharedJSONChannelStore struct {
	backend *sharedJSONChannelBackend
}

func newSharedJSONChannelStores(count int) (*sharedJSONChannelBackend, []*sharedJSONChannelStore) {
	backend := &sharedJSONChannelBackend{data: make(map[string][]byte)}
	stores := make([]*sharedJSONChannelStore, count)
	for i := range stores {
		stores[i] = &sharedJSONChannelStore{backend: backend}
	}
	return backend, stores
}

func (*sharedJSONChannelStore) SessionStoreDurability() SessionStoreDurability {
	return SessionStoreDurabilityDurableShared
}

func checkStoreContext(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func decodeJSONChannel(data []byte) (*ChannelState, error) {
	if data == nil {
		return nil, nil
	}
	var state ChannelState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	return &state, nil
}

func (s *sharedJSONChannelStore) GetChannel(ctx context.Context, channelID string) (*ChannelState, error) {
	if err := checkStoreContext(ctx); err != nil {
		return nil, err
	}
	s.backend.mu.Lock()
	defer s.backend.mu.Unlock()
	return decodeJSONChannel(s.backend.data[channelID])
}

func (s *sharedJSONChannelStore) UpdateChannel(ctx context.Context, channelID string, mutator ChannelMutator) (ChannelState, error) {
	if err := checkStoreContext(ctx); err != nil {
		return ChannelState{}, err
	}
	s.backend.mu.Lock()
	defer s.backend.mu.Unlock()
	current, err := decodeJSONChannel(s.backend.data[channelID])
	if err != nil {
		return ChannelState{}, err
	}
	next, err := mutator(current)
	if err != nil {
		return ChannelState{}, err
	}
	encoded, err := json.Marshal(next)
	if err != nil {
		return ChannelState{}, err
	}
	s.backend.data[channelID] = encoded
	stored, err := decodeJSONChannel(encoded)
	if err != nil {
		return ChannelState{}, err
	}
	return *stored, nil
}

func (s *sharedJSONChannelStore) DeleteChannel(ctx context.Context, channelID string) error {
	if err := checkStoreContext(ctx); err != nil {
		return err
	}
	s.backend.mu.Lock()
	defer s.backend.mu.Unlock()
	delete(s.backend.data, channelID)
	return nil
}

func (s *sharedJSONChannelStore) ListChannels(ctx context.Context, filter *ListChannelsFilter) ([]ChannelState, error) {
	if err := checkStoreContext(ctx); err != nil {
		return nil, err
	}
	s.backend.mu.Lock()
	defer s.backend.mu.Unlock()
	states := make([]ChannelState, 0, len(s.backend.data))
	for _, encoded := range s.backend.data {
		state, err := decodeJSONChannel(encoded)
		if err != nil {
			return nil, err
		}
		if filter != nil {
			if filter.Sealed != nil && state.Sealed != *filter.Sealed {
				continue
			}
			if filter.ClosePending != nil && (state.CloseRequestedAt != nil) != *filter.ClosePending {
				continue
			}
		}
		states = append(states, *state)
	}
	return states, nil
}

func (s *sharedJSONChannelStore) MarkSealed(ctx context.Context, channelID string) (ChannelState, error) {
	return s.UpdateChannel(ctx, channelID, func(current *ChannelState) (ChannelState, error) {
		if current == nil {
			return ChannelState{}, fmt.Errorf("channel %s not found", channelID)
		}
		next := *current
		next.Sealed = true
		return next, nil
	})
}

func (b *sharedJSONChannelBackend) raw(channelID string) string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return string(b.data[channelID])
}

func TestSharedJSONStoresObserveSettlementClaimAndPendingSignature(t *testing.T) {
	backend, stores := newSharedJSONChannelStores(2)
	baseRPC := testutil.NewFakeRPC()
	blockingRPC := &blockingConfirmationRPC{
		FakeRPC:       baseRPC,
		statusEntered: make(chan struct{}, 1),
		releaseStatus: make(chan struct{}),
	}
	merchant := testutil.NewPrivateKey()
	newWithStore := func(store ChannelStore) *Session {
		return newTestSession(t, func(o *SessionOptions) {
			o.Store = store
			o.RPC = baseRPC
			o.Signer = merchant
		})
	}
	first := newWithStore(stores[0])
	second := newWithStore(stores[1])
	_, channelID := openTrustedChannel(t, first, 1_000)
	first.rpc = blockingRPC
	second.rpc = blockingRPC
	blockingRPC.block.Store(true)

	type settleResult struct {
		signature string
		err       error
	}
	firstDone := make(chan settleResult, 1)
	go func() {
		signature, err := first.closeAndSettleChannel(context.Background(), channelID)
		firstDone <- settleResult{signature: signature, err: err}
	}()

	select {
	case <-blockingRPC.statusEntered:
	case <-time.After(3 * time.Second):
		t.Fatal("first store client never reached settlement confirmation")
	}

	raw := backend.raw(channelID)
	if !strings.Contains(raw, `"settling":true`) || !strings.Contains(raw, `"settled_signature":`) {
		t.Fatalf("in-flight durable state = %s", raw)
	}
	state, err := stores[1].GetChannel(context.Background(), channelID)
	if err != nil || state == nil || !state.Settling || state.SettledSignature == nil {
		t.Fatalf("second store client state=%+v err=%v", state, err)
	}
	if signature, err := second.closeAndSettleChannel(context.Background(), channelID); err != nil || signature != "" {
		t.Fatalf("competing store settle = %q, %v", signature, err)
	}
	if len(baseRPC.Sent) != 1 {
		t.Fatalf("shared-store broadcasts = %d, want 1", len(baseRPC.Sent))
	}

	close(blockingRPC.releaseStatus)
	result := <-firstDone
	if result.err != nil || result.signature == "" {
		t.Fatalf("winning store settle = %q, %v", result.signature, result.err)
	}
	state, err = stores[1].GetChannel(context.Background(), channelID)
	if err != nil || state == nil || !state.Sealed || state.Settling || state.SettledSignature == nil {
		t.Fatalf("reconciled shared state=%+v err=%v", state, err)
	}
}

func TestSharedJSONStoreRetryReconfirmsPendingSignatureWithoutBroadcast(t *testing.T) {
	_, stores := newSharedJSONChannelStores(2)
	baseRPC := testutil.NewFakeRPC()
	merchant := testutil.NewPrivateKey()
	first := newTestSession(t, func(o *SessionOptions) {
		o.Store = stores[0]
		o.RPC = baseRPC
		o.Signer = merchant
	})
	second := newTestSession(t, func(o *SessionOptions) {
		o.Store = stores[1]
		o.RPC = baseRPC
		o.Signer = merchant
	})
	_, channelID := openTrustedChannel(t, first, 1_000)
	first.rpc = &failingStatusRPC{FakeRPC: baseRPC}

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	if _, err := first.closeAndSettleChannel(ctx, channelID); err == nil {
		t.Fatal("uncertain settlement confirmation unexpectedly succeeded")
	}
	pending, err := stores[1].GetChannel(context.Background(), channelID)
	if err != nil || pending == nil || pending.Sealed || pending.Settling || pending.SettledSignature == nil {
		t.Fatalf("pending shared state=%+v err=%v", pending, err)
	}
	pendingSignature := *pending.SettledSignature

	retryRPC := testutil.NewFakeRPC()
	second.rpc = retryRPC
	settled, err := second.closeAndSettleChannel(context.Background(), channelID)
	if err != nil {
		t.Fatalf("shared-store settlement retry: %v", err)
	}
	if settled != pendingSignature || len(retryRPC.Sent) != 0 {
		t.Fatalf("retry signature=%q broadcasts=%d want signature=%q broadcasts=0", settled, len(retryRPC.Sent), pendingSignature)
	}
}
