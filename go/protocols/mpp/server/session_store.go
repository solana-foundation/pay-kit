package server

// Per-channel state store for the MPP session server.
//
// The in-memory implementation serializes UpdateChannel calls per channel id
// with a per-channel mutex, so the read-modify-write sequence inside the
// mutator is atomic from the perspective of any other caller targeting the
// same channel while updates to different channels run concurrently.
//
// The voucher verifier (see session_voucher.go) is intentionally
// side-effect-free: it computes a verdict, and the caller persists any
// accepted delta through ChannelStore.UpdateChannel.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
)

// PendingDelivery is one delivery the server has reserved against a channel
// but not yet received a signed voucher for.
type PendingDelivery struct {
	// DeliveryID is the idempotency key for this delivery.
	DeliveryID string `json:"deliveryId"`

	// Amount reserved for this delivery in base units.
	Amount uint64 `json:"amount"`

	// Sequence is the monotonic per-channel delivery sequence.
	Sequence uint64 `json:"sequence"`

	// ExpiresAt is the Unix timestamp after which the delivery should not be
	// committed.
	ExpiresAt int64 `json:"expiresAt"`
}

// CommittedDelivery is a delivery that has been committed by a signed
// voucher. Kept for idempotent commit replay.
type CommittedDelivery struct {
	// DeliveryID is the idempotency key for this delivery.
	DeliveryID string `json:"deliveryId"`

	// Amount committed for this delivery in base units.
	Amount uint64 `json:"amount"`

	// Cumulative is the channel watermark after this commit.
	Cumulative uint64 `json:"cumulative"`

	// VoucherSignature is the signature of the committing voucher (base58).
	VoucherSignature string `json:"voucherSignature"`
}

// ChannelState is the persisted state of a single payment channel from the
// server's point of view. The JSON tags are the shared snake_case wire
// names, so durable stores can interoperate across the language SDKs.
type ChannelState struct {
	// ChannelID is the on-chain channel address (base58).
	//
	// Push sessions: the payment-channel address.
	// Pull sessions: the FixedDelegation PDA address.
	ChannelID string `json:"channel_id"`

	// AuthorizedSigner is the public key authorized to sign vouchers for this
	// session (base58).
	AuthorizedSigner string `json:"authorized_signer"`

	// Deposit is the total deposit / approved amount locked for this session
	// (base units).
	Deposit uint64 `json:"deposit"`

	// OpenSlot is the slot recorded in the channel open args (push sessions).
	// It is a channel PDA seed, so it is persisted to re-derive the address
	// and to drive the post-distribute reclaim. Zero for pull sessions and
	// for opens that never carried it.
	OpenSlot uint64 `json:"open_slot"`

	// Cumulative is the highest cumulative amount accepted by the server (the
	// settled watermark).
	Cumulative uint64 `json:"cumulative"`

	// Sealed is true once the channel has been sealed on-chain (the program's
	// seal instruction, formerly finalize).
	Sealed bool `json:"sealed"`

	// HighestVoucherSignature is the signature of the highest accepted voucher
	// (base58). Stored for idempotent replay detection.
	HighestVoucherSignature *string `json:"highest_voucher_signature"`

	// HighestVoucherExpiresAt is the expiry timestamp from the highest
	// accepted voucher. Needed when the server later settles that voucher
	// on-chain.
	HighestVoucherExpiresAt *int64 `json:"highest_voucher_expires_at"`

	// CloseRequestedAt is the Unix timestamp (seconds) when cooperative close
	// was requested. Once set, no further vouchers are accepted.
	CloseRequestedAt *uint64 `json:"close_requested_at"`

	// SettledSignature is the signature (base58) of the broadcast
	// settle-and-distribute transaction. A close-pending channel with no
	// settled signature is re-drivable: a close retry may attempt settlement
	// again.
	//
	// An extension beyond the core channel-state shape, recorded only when
	// this server drives on-chain settlement. Serialized with omitempty so a
	// channel state without a settlement round-trips cleanly.
	SettledSignature *string `json:"settled_signature,omitempty"`

	// Operator is the client wallet pubkey (base58) for pull-mode sessions;
	// nil for push sessions.
	Operator *string `json:"operator"`

	// NextDeliverySequence is the next server-side metered delivery sequence.
	NextDeliverySequence uint64 `json:"next_delivery_sequence"`

	// PendingDeliveries are reserved by the server but not yet committed.
	PendingDeliveries []PendingDelivery `json:"pending_deliveries"`

	// CommittedDeliveries are recently committed deliveries, kept for
	// idempotent commit replay.
	CommittedDeliveries []CommittedDelivery `json:"committed_deliveries"`
}

// channelStateJSON mirrors ChannelState so UnmarshalJSON can decode the
// struct fields without recursing into itself.
type channelStateJSON ChannelState

// UnmarshalJSON rejects records persisted before the upstream finalize→seal
// rename. encoding/json ignores unknown fields, so without this guard a
// legacy record carrying "finalized": true (and no "sealed" key) would
// silently reload a closed channel as unsealed, letting the upgraded server
// accept further vouchers or re-settle an already-distributed channel. The
// epoch-addressed migration is intentionally pre-1.0 breaking (no alias):
// legacy records fail loudly, matching the Python and Rust stores.
func (s *ChannelState) UnmarshalJSON(data []byte) error {
	var probe struct {
		Finalized *bool `json:"finalized"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return err
	}
	if probe.Finalized != nil {
		return errors.New(
			`legacy pre-seal channel record (field "finalized") is not supported; migrate or reset the durable channel store`,
		)
	}
	var decoded channelStateJSON
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*s = ChannelState(decoded)
	return nil
}

// clone returns a deep copy so callers can never alias store-internal state.
func (s ChannelState) clone() ChannelState {
	out := s
	if s.HighestVoucherSignature != nil {
		v := *s.HighestVoucherSignature
		out.HighestVoucherSignature = &v
	}
	if s.HighestVoucherExpiresAt != nil {
		v := *s.HighestVoucherExpiresAt
		out.HighestVoucherExpiresAt = &v
	}
	if s.CloseRequestedAt != nil {
		v := *s.CloseRequestedAt
		out.CloseRequestedAt = &v
	}
	if s.SettledSignature != nil {
		v := *s.SettledSignature
		out.SettledSignature = &v
	}
	if s.Operator != nil {
		v := *s.Operator
		out.Operator = &v
	}
	if s.PendingDeliveries != nil {
		out.PendingDeliveries = append([]PendingDelivery(nil), s.PendingDeliveries...)
	}
	if s.CommittedDeliveries != nil {
		out.CommittedDeliveries = append([]CommittedDelivery(nil), s.CommittedDeliveries...)
	}
	return out
}

// ListChannelsFilter is an optional filter for ChannelStore.ListChannels.
type ListChannelsFilter struct {
	// Sealed, when non-nil, only includes channels matching this sealed
	// state.
	Sealed *bool

	// ClosePending, when non-nil, only includes channels whose
	// CloseRequestedAt presence matches.
	ClosePending *bool
}

// ChannelMutator is handed to UpdateChannel. It receives the current state
// (nil if no channel exists) and returns the next state or an error, in which
// case the stored state is left unchanged.
//
// Implementations MUST guarantee the mutator runs without interleaving with
// other UpdateChannel calls for the same channel id.
type ChannelMutator func(current *ChannelState) (ChannelState, error)

// ChannelStore is the pluggable store for per-channel session state.
//
// UpdateChannel is the only way to mutate a channel: the voucher verifier
// always needs an atomic read-modify-write to avoid double-spend under
// concurrent vouchers, so no direct put is exposed.
type ChannelStore interface {
	// GetChannel reads a channel. Returns nil when it does not exist.
	GetChannel(ctx context.Context, channelID string) (*ChannelState, error)

	// UpdateChannel atomically read-modify-writes a channel's state and
	// returns the stored result.
	UpdateChannel(ctx context.Context, channelID string, mutator ChannelMutator) (ChannelState, error)

	// DeleteChannel removes a channel from the store. Deleting a missing
	// channel is a no-op.
	DeleteChannel(ctx context.Context, channelID string) error

	// ListChannels returns a snapshot list. The filter is applied after read;
	// nil means no filter.
	ListChannels(ctx context.Context, filter *ListChannelsFilter) ([]ChannelState, error)

	// MarkSealed flips Sealed to true. Errors when the channel is not
	// found.
	MarkSealed(ctx context.Context, channelID string) (ChannelState, error)
}

// MemoryChannelStore is an in-memory ChannelStore with per-channel locking:
// UpdateChannel calls for the same channel id run strictly sequentially while
// calls for different ids run concurrently.
type MemoryChannelStore struct {
	// mu guards data and locks.
	mu sync.Mutex

	// data maps channel id to stored state; values are cloned on the way in
	// and out so callers never share memory with the store.
	data map[string]ChannelState

	// locks holds the per-channel mutex serializing UpdateChannel calls for
	// the same channel id.
	locks map[string]*sync.Mutex
}

// NewMemoryChannelStore creates an empty MemoryChannelStore.
func NewMemoryChannelStore() *MemoryChannelStore {
	return &MemoryChannelStore{
		data:  map[string]ChannelState{},
		locks: map[string]*sync.Mutex{},
	}
}

// channelLock returns the mutex serializing updates for channelID.
func (s *MemoryChannelStore) channelLock(channelID string) *sync.Mutex {
	s.mu.Lock()
	defer s.mu.Unlock()
	lock, ok := s.locks[channelID]
	if !ok {
		lock = &sync.Mutex{}
		s.locks[channelID] = lock
	}
	return lock
}

// GetChannel reads a channel. Returns nil when it does not exist.
func (s *MemoryChannelStore) GetChannel(_ context.Context, channelID string) (*ChannelState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, ok := s.data[channelID]
	if !ok {
		return nil, nil
	}
	out := state.clone()
	return &out, nil
}

// UpdateChannel atomically read-modify-writes a channel's state. A mutator
// error leaves the stored state unchanged and does not poison later updates.
func (s *MemoryChannelStore) UpdateChannel(_ context.Context, channelID string, mutator ChannelMutator) (ChannelState, error) {
	lock := s.channelLock(channelID)
	lock.Lock()
	defer lock.Unlock()

	s.mu.Lock()
	current, ok := s.data[channelID]
	s.mu.Unlock()

	var currentPtr *ChannelState
	if ok {
		snapshot := current.clone()
		currentPtr = &snapshot
	}
	next, err := mutator(currentPtr)
	if err != nil {
		return ChannelState{}, err
	}

	s.mu.Lock()
	s.data[channelID] = next.clone()
	s.mu.Unlock()
	return next, nil
}

// DeleteChannel removes a channel from the store.
func (s *MemoryChannelStore) DeleteChannel(_ context.Context, channelID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, channelID)
	return nil
}

// ListChannels returns a snapshot of all channels matching the filter.
func (s *MemoryChannelStore) ListChannels(_ context.Context, filter *ListChannelsFilter) ([]ChannelState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]ChannelState, 0, len(s.data))
	for _, state := range s.data {
		if filter != nil {
			if filter.Sealed != nil && state.Sealed != *filter.Sealed {
				continue
			}
			if filter.ClosePending != nil {
				closePending := state.CloseRequestedAt != nil
				if closePending != *filter.ClosePending {
					continue
				}
			}
		}
		out = append(out, state.clone())
	}
	return out, nil
}

// MarkSealed flips Sealed to true, erroring when the channel is
// missing.
func (s *MemoryChannelStore) MarkSealed(ctx context.Context, channelID string) (ChannelState, error) {
	return s.UpdateChannel(ctx, channelID, func(current *ChannelState) (ChannelState, error) {
		if current == nil {
			return ChannelState{}, fmt.Errorf("channel %s not found", channelID)
		}
		next := *current
		next.Sealed = true
		return next, nil
	})
}
