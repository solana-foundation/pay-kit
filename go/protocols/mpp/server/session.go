package server

// Server-side session intent: challenge issuance, voucher verification, and
// channel lifecycle management.
//
// 1. The server calls SessionServer.BuildChallengeRequest to produce the
//    SessionRequest embedded in a 402 challenge.
// 2. The client responds with an open action; the server calls
//    SessionServer.ProcessOpen to record the channel.
// 3. For each subsequent API call the client attaches a voucher action; the
//    server calls SessionServer.VerifyVoucher to validate and advance the
//    settled watermark atomically.
// 4. At session end the client (or server) triggers close via
//    SessionServer.ProcessClose; on-chain settlement is driven by the host
//    once the close-pending state is recorded.
//
// On-chain verification is a seam in this layer: when
// SessionConfig.VerifyOpenTx / VerifyTopUpTx are set, ProcessOpen (push mode)
// and ProcessTopUp invoke them before persisting channel state, binding the
// payload to the attached transaction and confirming the signature on-chain.
// When nil, the transaction signature and
// deposit amount are trusted as provided, which is suitable only for unit
// tests or deployments that verify transactions out of band.

import (
	"context"
	"fmt"
	"math"
	"strconv"
	"time"

	solana "github.com/gagliardetto/solana-go"

	"github.com/solana-foundation/pay-kit/go/protocols/mpp/intents"
)

// Split is a payment split committed at channel open; distributed at close.
type Split struct {
	// Recipient of this split.
	Recipient solana.PublicKey

	// BPS is the share in basis points.
	BPS uint16
}

// SessionTxVerifier confirms an on-chain transaction referenced by a session
// payload before channel state is persisted. Implementations typically decode
// the attached transaction, bind the payload signature to it, and confirm the
// signature on-chain. This is the seam the on-chain layer plugs into; nil
// skips verification.
//
// It returns the channel payer recorded by the verified transaction (open
// account 0, base58): the deposit funder and the distribute refund
// destination, which the program pins to channel.payer. The returned payer is
// empty when the verifier cannot establish it (signature-only verification, or
// a top-up that carries no open transaction); callers then fall back to the
// payload's owner/payer fields.
type SessionTxVerifier[P any] func(ctx context.Context, payload *P) (string, error)

// SessionConfig is the server configuration for the session intent.
type SessionConfig struct {
	// Operator public key (base58). Shown to clients in the challenge.
	Operator string

	// Recipient is the primary payment recipient (base58).
	Recipient string

	// Splits are optional splits routed to specific recipients at close.
	Splits []Split

	// MaxCap is the maximum cap the server will offer per session (base
	// units). Clients may request a lower cap but not a higher one.
	MaxCap uint64

	// Currency identifier (e.g., "USDC", mint address).
	Currency string

	// Decimals is the token decimals (default 6 for USDC).
	Decimals uint8

	// Network is the Solana network: "mainnet", "devnet", "localnet".
	Network string

	// ProgramID is the payment-channel program ID. Nil defaults to the
	// canonical program.
	ProgramID *solana.PublicKey

	// MinVoucherDelta is the minimum voucher increment (base units). 0 = no
	// minimum.
	MinVoucherDelta uint64

	// SettlementWindowSeconds is the channel's forced-close grace period in
	// seconds. When positive, a non-zero voucher expiry must outlast this
	// window (expiresAt >= now + settlementWindowSeconds) so the async settle
	// transaction cannot be rejected on-chain after the server has served. 0
	// disables the extra margin (plain `expiresAt > now` only). A voucher
	// expiresAt of 0 never expires regardless of this setting. Should match the
	// grace period the open transaction locks into the channel.
	SettlementWindowSeconds int64

	// Modes are the session modes this server accepts, advertised to clients
	// in the 402 challenge. An empty list or [push] means only the
	// payment-channel push mode is supported.
	Modes []intents.SessionMode

	// PullVoucherStrategy is the voucher authority used for pull sessions.
	// Required when Modes includes pull.
	PullVoucherStrategy *intents.SessionPullVoucherStrategy

	// VerifyOpenTx, when set, confirms the open transaction on-chain (push
	// mode) before ProcessOpen persists channel state. See SessionTxVerifier.
	VerifyOpenTx SessionTxVerifier[intents.OpenPayload]

	// VerifyTopUpTx, when set, confirms the top-up transaction on-chain
	// before ProcessTopUp raises the deposit. See SessionTxVerifier.
	VerifyTopUpTx SessionTxVerifier[intents.TopUpPayload]
}

// DeliveryRequest is a request to reserve a metered delivery for client-side
// ack/commit. Zero values mean "absent" for the optional fields.
type DeliveryRequest struct {
	// SessionID is the channel/session ID that will pay for the delivery.
	SessionID string

	// Amount owed for this delivery in base units.
	Amount uint64

	// DeliveryID is an optional idempotency key. When empty the server
	// derives "<sessionId>:<sequence>".
	DeliveryID string

	// CommitURL is an optional commit endpoint hint surfaced to the client.
	CommitURL string

	// Proof is an optional opaque proof surfaced to the client.
	Proof string

	// ExpiresAt is an optional directive expiry (Unix seconds). Zero defaults
	// to intents.DefaultSessionExpiresAt.
	ExpiresAt int64
}

// SessionServer is the server-side session manager. Pluggable over the
// channel store to support in-memory testing and production persistence
// backends.
type SessionServer struct {
	// config is the immutable server configuration captured at construction.
	config SessionConfig

	// store persists per-channel state; every mutation goes through its
	// atomic UpdateChannel so voucher watermarks stay double-spend safe.
	store ChannelStore
}

// NewSessionServer creates a SessionServer over the given store.
func NewSessionServer(config SessionConfig, store ChannelStore) *SessionServer {
	return &SessionServer{config: config, store: store}
}

// Store returns the channel store backing this server, so hosts can share it
// with metering side channels.
func (s *SessionServer) Store() ChannelStore {
	return s.store
}

// BuildChallengeRequest builds the SessionRequest to embed in a 402
// challenge. cap is the maximum this session will allow, clamped to
// SessionConfig.MaxCap. MinVoucherDelta is included only when positive,
// Modes is omitted when push-only, and PullVoucherStrategy is included only
// when pull is offered.
func (s *SessionServer) BuildChallengeRequest(cap uint64) intents.SessionRequest {
	effectiveCap := min(cap, s.config.MaxCap)
	decimals := s.config.Decimals

	request := intents.SessionRequest{
		Cap:       strconv.FormatUint(effectiveCap, 10),
		Currency:  s.config.Currency,
		Decimals:  &decimals,
		Operator:  s.config.Operator,
		Recipient: s.config.Recipient,
	}
	if s.config.Network != "" {
		network := s.config.Network
		request.Network = &network
	}
	for _, split := range s.config.Splits {
		request.Splits = append(request.Splits, intents.SessionSplit{
			Recipient: split.Recipient.String(),
			BPS:       split.BPS,
		})
	}
	if s.config.ProgramID != nil {
		programID := s.config.ProgramID.String()
		request.ProgramID = &programID
	}
	if s.config.MinVoucherDelta > 0 {
		minDelta := strconv.FormatUint(s.config.MinVoucherDelta, 10)
		request.MinVoucherDelta = &minDelta
	}
	// Omit modes when only push is supported; clients assume push when modes
	// is absent.
	if !s.pushOnly() {
		request.Modes = append([]intents.SessionMode(nil), s.config.Modes...)
	}
	if s.supportsMode(intents.SessionModePull) && s.config.PullVoucherStrategy != nil {
		strategy := *s.config.PullVoucherStrategy
		request.PullVoucherStrategy = &strategy
	}
	return request
}

// pushOnly reports whether the configured modes reduce to push-only.
func (s *SessionServer) pushOnly() bool {
	return len(s.config.Modes) == 0 ||
		(len(s.config.Modes) == 1 && s.config.Modes[0] == intents.SessionModePush)
}

// supportsMode reports whether the server accepts mode. Empty configured
// modes mean push-only.
func (s *SessionServer) supportsMode(mode intents.SessionMode) bool {
	if len(s.config.Modes) == 0 {
		return mode == intents.SessionModePush
	}
	for _, supported := range s.config.Modes {
		if supported == mode {
			return true
		}
	}
	return false
}

// ProcessOpen processes an open action and persists the channel state.
//
// The channel is keyed by OpenPayload.SessionID (channelId first, then
// tokenAccount for pull opens). Replayed opens are idempotent: when a channel
// already exists for the session id with the same authorized signer, the
// existing state is returned unchanged and the voucher watermark is never
// reset. Opens for an existing channel are rejected when the channel is
// finalized or when the payload's authorized signer differs from the stored
// one.
func (s *SessionServer) ProcessOpen(ctx context.Context, payload *intents.OpenPayload) (ChannelState, error) {
	if !s.supportsMode(payload.Mode) {
		return ChannelState{}, fmt.Errorf("session mode %q is not supported by this challenge", payload.Mode)
	}

	sessionID, err := payload.SessionID()
	if err != nil {
		return ChannelState{}, err
	}
	deposit, err := payload.DepositAmount()
	if err != nil {
		return ChannelState{}, err
	}
	if deposit == 0 {
		return ChannelState{}, fmt.Errorf("deposit must be greater than zero")
	}
	if deposit > s.config.MaxCap {
		return ChannelState{}, fmt.Errorf("deposit %d exceeds max cap %d", deposit, s.config.MaxCap)
	}

	// On-chain verification seam (push mode only; pull-mode host integrations
	// submit server-broadcast transactions or validate delegated-token state
	// before invoking this lower-level store method).
	var verifiedPayer string
	if payload.Mode == intents.SessionModePush && s.config.VerifyOpenTx != nil {
		var err error
		verifiedPayer, err = s.config.VerifyOpenTx(ctx, payload)
		if err != nil {
			return ChannelState{}, fmt.Errorf("open tx verification failed: %w", err)
		}
	}

	// The channel payer (the deposit funder / distribute refund destination,
	// which the program pins to channel.payer) is recorded as Operator. Prefer
	// the payer read from the verified open transaction (account 0, what the
	// channel actually records) over the client-supplied payload fields, which
	// could be stale/wrong. Fall back to the payload only for opens with no
	// transaction to verify (bare push assertion / pull).
	operator := operatorFromVerifiedOpen(verifiedPayer, payload.Owner, payload.Payer)
	fresh := ChannelState{
		ChannelID:        sessionID,
		AuthorizedSigner: payload.AuthorizedSigner,
		Deposit:          deposit,
		Operator:         operator,
	}

	// Atomic check-and-insert: a replayed open re-passes all checks above
	// (the referenced tx is genuinely confirmed), so it MUST NOT overwrite
	// existing state; that would reset the voucher watermark and erase
	// accepted vouchers before close.
	return s.store.UpdateChannel(ctx, sessionID, func(existing *ChannelState) (ChannelState, error) {
		if existing != nil {
			if existing.Finalized {
				return ChannelState{}, fmt.Errorf("channel %s is already finalized", sessionID)
			}
			if existing.AuthorizedSigner != payload.AuthorizedSigner {
				return ChannelState{}, fmt.Errorf("channel %s already exists with a different authorized signer", sessionID)
			}
			// Idempotent replay: keep existing state untouched.
			return *existing, nil
		}
		return fresh, nil
	})
}

// operatorFromVerifiedOpen resolves the channel payer (recorded as Operator)
// for an open, preferring the payer read from the verified open transaction
// (authoritative: open account 0) over the client-supplied payload fields.
// Returns nil only when none of the three is set.
func operatorFromVerifiedOpen(verifiedPayer string, owner, payer *string) *string {
	if verifiedPayer != "" {
		return &verifiedPayer
	}
	if owner != nil {
		return owner
	}
	return payer
}

// VoucherAcceptance is the detailed outcome of a voucher accepted by the
// server. Replayed reports whether the voucher was an idempotent replay of the
// already-stored highest voucher (same cumulative AND same signature): a replay
// advanced the watermark by zero, so callers must NOT serve a fresh response
// for it (charged 0). A non-replay acceptance advanced the watermark by
// Charged base units.
type VoucherAcceptance struct {
	// Cumulative is the channel watermark after this voucher (base units).
	Cumulative uint64

	// Charged is the amount this voucher advanced the watermark by (base
	// units). Zero for an idempotent replay.
	Charged uint64

	// Replayed is true when the voucher was an exact idempotent replay of the
	// stored highest voucher (charged 0). Callers should treat it as a
	// no-charge no-op rather than a fresh serve.
	Replayed bool
}

// VerifyVoucher verifies a voucher, advances the watermark, and returns the
// new cumulative.
//
// An exact idempotent replay (same cumulative AND same signature) returns the
// stored cumulative with a nil error; use VerifyVoucherDetailed to distinguish
// a replay (charged 0) from a fresh charge.
func (s *SessionServer) VerifyVoucher(ctx context.Context, payload *intents.VoucherPayload) (uint64, error) {
	acceptance, err := s.VerifyVoucherDetailed(ctx, payload)
	if err != nil {
		return 0, err
	}
	return acceptance.Cumulative, nil
}

// VerifyVoucherDetailed verifies a voucher, advances the watermark, and returns
// the detailed acceptance (cumulative, amount charged, and whether the voucher
// was an idempotent replay).
//
// The full ordered check sequence runs as a preflight outside the store lock
// (see VerifyVoucherForChannel), then the state-dependent checks are re-applied
// inside the atomic mutator before the watermark is persisted. An exact replay
// (same cumulative AND same signature) is reported as Replayed with Charged 0;
// it is the cumulative-as-nonce contract that makes a re-submitted voucher a
// no-charge no-op rather than a fresh serve.
func (s *SessionServer) VerifyVoucherDetailed(ctx context.Context, payload *intents.VoucherPayload) (VoucherAcceptance, error) {
	voucher := payload.Voucher
	channelID := voucher.Data.ChannelID

	state, err := s.store.GetChannel(ctx, channelID)
	if err != nil {
		return VoucherAcceptance{}, err
	}
	if state == nil {
		return VoucherAcceptance{}, fmt.Errorf("channel %s not found", channelID)
	}

	// Preflight outside the lock (expensive signature check happens before
	// touching the store).
	result := VerifyVoucherForChannel(VerifyVoucherArgs{
		State:                   *state,
		Signed:                  voucher,
		Deposit:                 state.Deposit,
		MinVoucherDelta:         s.config.MinVoucherDelta,
		SettlementWindowSeconds: s.config.SettlementWindowSeconds,
	})
	switch result.Status {
	case VoucherVerifyRejected:
		// Surface the stable reject tag ahead of the detail
		// ("<reason>: <detail>").
		return VoucherAcceptance{}, fmt.Errorf("%s: %s", result.Reason, result.Detail)
	case VoucherVerifyReplayed:
		// Exact replay: charged 0, watermark unchanged.
		return VoucherAcceptance{Cumulative: result.NewCumulative, Charged: 0, Replayed: true}, nil
	}

	newCumulative := result.NewCumulative
	newSignature := result.NewSignature
	newExpiresAt := result.NewExpiresAt

	// Atomic read-modify-write: re-check everything state-dependent inside
	// the mutator. replayed captures a race where a concurrent writer landed
	// this exact voucher first, so it collapses to a charged-0 replay.
	replayed := false
	previousCumulative := uint64(0)
	newState, err := s.store.UpdateChannel(ctx, channelID, func(current *ChannelState) (ChannelState, error) {
		replayed = false
		if current == nil {
			return ChannelState{}, fmt.Errorf("channel %s not found", channelID)
		}
		previousCumulative = current.Cumulative
		if current.Finalized {
			return ChannelState{}, fmt.Errorf("channel %s is already finalized", channelID)
		}
		if current.CloseRequestedAt != nil {
			return ChannelState{}, fmt.Errorf("channel %s close is pending; no further vouchers accepted", channelID)
		}
		// Idempotent replay inside the mutator.
		if newCumulative == current.Cumulative &&
			current.HighestVoucherSignature != nil &&
			*current.HighestVoucherSignature == newSignature {
			replayed = true
			return *current, nil
		}
		// Concurrent watermark advancement check.
		if newCumulative <= current.Cumulative {
			return ChannelState{}, fmt.Errorf("concurrent update: watermark advanced")
		}
		next := *current
		next.Cumulative = newCumulative
		next.HighestVoucherSignature = &newSignature
		next.HighestVoucherExpiresAt = &newExpiresAt
		return next, nil
	})
	if err != nil {
		return VoucherAcceptance{}, err
	}
	if replayed {
		return VoucherAcceptance{Cumulative: newState.Cumulative, Charged: 0, Replayed: true}, nil
	}
	return VoucherAcceptance{
		Cumulative: newState.Cumulative,
		Charged:    newState.Cumulative - previousCumulative,
		Replayed:   false,
	}, nil
}

// ProcessTopUp processes a topUp action: atomically raise the channel's
// deposit cap.
//
// The new deposit must exceed the current deposit and must not exceed the
// configured max cap. Top-ups are rejected once the channel is finalized or a
// close has been requested.
func (s *SessionServer) ProcessTopUp(ctx context.Context, payload *intents.TopUpPayload) (ChannelState, error) {
	newDeposit, err := strconv.ParseUint(payload.NewDeposit, 10, 64)
	if err != nil {
		return ChannelState{}, fmt.Errorf("invalid newDeposit: %s", payload.NewDeposit)
	}

	// On-chain verification seam (same shape as ProcessOpen). A top-up never
	// establishes the channel payer, so the returned payer is ignored.
	if s.config.VerifyTopUpTx != nil {
		if _, err := s.config.VerifyTopUpTx(ctx, payload); err != nil {
			return ChannelState{}, fmt.Errorf("top-up tx verification failed: %w", err)
		}
	}

	maxCap := s.config.MaxCap
	channelID := payload.ChannelID
	return s.store.UpdateChannel(ctx, channelID, func(current *ChannelState) (ChannelState, error) {
		if current == nil {
			return ChannelState{}, fmt.Errorf("channel %s not found", channelID)
		}
		if current.Finalized {
			return ChannelState{}, fmt.Errorf("channel %s is already finalized", channelID)
		}
		if current.CloseRequestedAt != nil {
			return ChannelState{}, fmt.Errorf("channel %s close is pending; no further top-ups accepted", channelID)
		}
		if newDeposit <= current.Deposit {
			return ChannelState{}, fmt.Errorf("new deposit %d must exceed current deposit %d", newDeposit, current.Deposit)
		}
		if newDeposit > maxCap {
			return ChannelState{}, fmt.Errorf("new deposit %d exceeds max cap %d", newDeposit, maxCap)
		}
		next := *current
		next.Deposit = newDeposit
		return next, nil
	})
}

// BeginDelivery reserves capacity for a delivered message/response and
// returns the metering directive the client must commit after processing it.
//
// The reservation requires cumulative + pendingTotal + amount <= deposit,
// assigns the next sequence, and defaults the delivery id to
// "<sessionId>:<sequence>".
func (s *SessionServer) BeginDelivery(ctx context.Context, request DeliveryRequest) (intents.MeteringDirective, error) {
	if request.Amount == 0 {
		return intents.MeteringDirective{}, fmt.Errorf("delivery amount must be greater than zero")
	}

	sessionID := request.SessionID
	amount := request.Amount
	expiresAt := request.ExpiresAt
	if expiresAt == 0 {
		expiresAt = intents.DefaultSessionExpiresAt
	}

	var directive intents.MeteringDirective
	_, err := s.store.UpdateChannel(ctx, sessionID, func(current *ChannelState) (ChannelState, error) {
		if current == nil {
			return ChannelState{}, fmt.Errorf("channel %s not found", sessionID)
		}
		if current.Finalized {
			return ChannelState{}, fmt.Errorf("channel %s is already finalized", sessionID)
		}
		if current.CloseRequestedAt != nil {
			return ChannelState{}, fmt.Errorf("channel %s close is pending; no further deliveries accepted", sessionID)
		}
		pendingTotal := uint64(0)
		for _, delivery := range current.PendingDeliveries {
			pendingTotal += delivery.Amount
		}
		if !fitsInDeposit(current.Cumulative, pendingTotal, amount, current.Deposit) {
			return ChannelState{}, fmt.Errorf("delivery amount %d exceeds available deposit", amount)
		}

		sequence := current.NextDeliverySequence + 1
		deliveryID := request.DeliveryID
		if deliveryID == "" {
			deliveryID = fmt.Sprintf("%s:%d", sessionID, sequence)
		}
		for _, delivery := range current.PendingDeliveries {
			if delivery.DeliveryID == deliveryID {
				return ChannelState{}, fmt.Errorf("delivery %s already exists", deliveryID)
			}
		}
		for _, delivery := range current.CommittedDeliveries {
			if delivery.DeliveryID == deliveryID {
				return ChannelState{}, fmt.Errorf("delivery %s already exists", deliveryID)
			}
		}

		next := *current
		next.NextDeliverySequence = sequence
		next.PendingDeliveries = append(next.PendingDeliveries, PendingDelivery{
			DeliveryID: deliveryID,
			Amount:     amount,
			Sequence:   sequence,
			ExpiresAt:  expiresAt,
		})

		directive = intents.MeteringDirective{
			DeliveryID: deliveryID,
			SessionID:  sessionID,
			Amount:     strconv.FormatUint(amount, 10),
			Currency:   s.config.Currency,
			Sequence:   sequence,
			ExpiresAt:  expiresAt,
		}
		if request.CommitURL != "" {
			commitURL := request.CommitURL
			directive.CommitURL = &commitURL
		}
		if request.Proof != "" {
			proof := request.Proof
			directive.Proof = &proof
		}
		return next, nil
	})
	if err != nil {
		return intents.MeteringDirective{}, err
	}
	return directive, nil
}

// fitsInDeposit reports whether cumulative + pendingTotal + amount <= deposit
// without overflowing u64; any overflow is treated as exceeding the deposit.
func fitsInDeposit(cumulative, pendingTotal, amount, deposit uint64) bool {
	if pendingTotal > math.MaxUint64-cumulative {
		return false
	}
	reserved := cumulative + pendingTotal
	if amount > math.MaxUint64-reserved {
		return false
	}
	return reserved+amount <= deposit
}

// ProcessCommit commits a reserved delivery by verifying the attached
// voucher and advancing the settled watermark. Replaying a commit for an
// already-committed delivery (same cumulative and same signature) returns the
// cached receipt with status replayed after re-verifying the voucher
// signature.
func (s *SessionServer) ProcessCommit(ctx context.Context, payload *intents.CommitPayload) (intents.CommitReceipt, error) {
	channelID := payload.Voucher.Data.ChannelID
	newCumulative, err := strconv.ParseUint(payload.Voucher.Data.Cumulative, 10, 64)
	if err != nil {
		return intents.CommitReceipt{}, fmt.Errorf("invalid cumulative in commit voucher: %s", payload.Voucher.Data.Cumulative)
	}

	state, err := s.store.GetChannel(ctx, channelID)
	if err != nil {
		return intents.CommitReceipt{}, err
	}
	if state == nil {
		return intents.CommitReceipt{}, fmt.Errorf("channel %s not found", channelID)
	}

	// Preflight outside the lock.
	if committed := findCommitted(state.CommittedDeliveries, payload.DeliveryID); committed != nil {
		if committed.Cumulative == newCumulative && committed.VoucherSignature == payload.Voucher.Signature {
			if err := verifySessionVoucher(payload.Voucher, state.AuthorizedSigner, s.config.SettlementWindowSeconds); err != nil {
				return intents.CommitReceipt{}, err
			}
			return commitReceipt(payload.DeliveryID, channelID, committed.Amount, committed.Cumulative, intents.CommitStatusReplayed), nil
		}
		return intents.CommitReceipt{}, fmt.Errorf("delivery %s was already committed with different voucher", payload.DeliveryID)
	}
	pending := findPending(state.PendingDeliveries, payload.DeliveryID)
	if pending == nil {
		return intents.CommitReceipt{}, fmt.Errorf("delivery %s not found", payload.DeliveryID)
	}
	now := time.Now().Unix()
	if pending.ExpiresAt <= now {
		return intents.CommitReceipt{}, fmt.Errorf("delivery %s has expired", payload.DeliveryID)
	}
	if newCumulative <= state.Cumulative {
		return intents.CommitReceipt{}, fmt.Errorf("commit cumulative %d must exceed watermark %d", newCumulative, state.Cumulative)
	}
	if err := verifySessionVoucher(payload.Voucher, state.AuthorizedSigner, s.config.SettlementWindowSeconds); err != nil {
		return intents.CommitReceipt{}, err
	}

	deliveryID := payload.DeliveryID
	signature := payload.Voucher.Signature
	voucherExpiresAt := payload.Voucher.Data.ExpiresAt

	var receiptAmount, receiptCumulative uint64
	var receiptStatus intents.CommitStatus
	_, err = s.store.UpdateChannel(ctx, channelID, func(current *ChannelState) (ChannelState, error) {
		if current == nil {
			return ChannelState{}, fmt.Errorf("channel %s not found", channelID)
		}
		if current.Finalized {
			return ChannelState{}, fmt.Errorf("channel %s is already finalized", channelID)
		}
		if current.CloseRequestedAt != nil {
			return ChannelState{}, fmt.Errorf("channel %s close is pending; no further commits accepted", channelID)
		}
		if committed := findCommitted(current.CommittedDeliveries, deliveryID); committed != nil {
			if committed.Cumulative == newCumulative && committed.VoucherSignature == signature {
				receiptAmount, receiptCumulative = committed.Amount, committed.Cumulative
				receiptStatus = intents.CommitStatusReplayed
				return *current, nil
			}
			return ChannelState{}, fmt.Errorf("delivery %s was already committed with different voucher", deliveryID)
		}
		pendingIndex := -1
		for i, delivery := range current.PendingDeliveries {
			if delivery.DeliveryID == deliveryID {
				pendingIndex = i
				break
			}
		}
		if pendingIndex < 0 {
			return ChannelState{}, fmt.Errorf("delivery %s not found", deliveryID)
		}
		reserved := current.PendingDeliveries[pendingIndex]
		if reserved.ExpiresAt <= now {
			return ChannelState{}, fmt.Errorf("delivery %s has expired", deliveryID)
		}
		if newCumulative <= current.Cumulative {
			return ChannelState{}, fmt.Errorf("commit cumulative %d must exceed watermark %d", newCumulative, current.Cumulative)
		}
		actualAmount := newCumulative - current.Cumulative
		if actualAmount > reserved.Amount {
			return ChannelState{}, fmt.Errorf("commit amount %d exceeds reserved amount %d", actualAmount, reserved.Amount)
		}

		next := *current
		next.PendingDeliveries = append(
			append([]PendingDelivery(nil), current.PendingDeliveries[:pendingIndex]...),
			current.PendingDeliveries[pendingIndex+1:]...,
		)
		next.Cumulative = newCumulative
		next.HighestVoucherSignature = &signature
		next.HighestVoucherExpiresAt = &voucherExpiresAt
		next.CommittedDeliveries = append(append([]CommittedDelivery(nil), current.CommittedDeliveries...), CommittedDelivery{
			DeliveryID:       deliveryID,
			Amount:           actualAmount,
			Cumulative:       newCumulative,
			VoucherSignature: signature,
		})
		receiptAmount, receiptCumulative = actualAmount, newCumulative
		receiptStatus = intents.CommitStatusCommitted
		return next, nil
	})
	if err != nil {
		return intents.CommitReceipt{}, err
	}
	return commitReceipt(deliveryID, channelID, receiptAmount, receiptCumulative, receiptStatus), nil
}

// commitReceipt builds a CommitReceipt with stringified amounts.
func commitReceipt(deliveryID, sessionID string, amount, cumulative uint64, status intents.CommitStatus) intents.CommitReceipt {
	return intents.CommitReceipt{
		DeliveryID: deliveryID,
		SessionID:  sessionID,
		Amount:     strconv.FormatUint(amount, 10),
		Cumulative: strconv.FormatUint(cumulative, 10),
		Status:     status,
	}
}

// findPending returns the pending delivery with the given id, or nil.
func findPending(deliveries []PendingDelivery, deliveryID string) *PendingDelivery {
	for i := range deliveries {
		if deliveries[i].DeliveryID == deliveryID {
			return &deliveries[i]
		}
	}
	return nil
}

// findCommitted returns the committed delivery with the given id, or nil.
func findCommitted(deliveries []CommittedDelivery, deliveryID string) *CommittedDelivery {
	for i := range deliveries {
		if deliveries[i].DeliveryID == deliveryID {
			return &deliveries[i]
		}
	}
	return nil
}

// ProcessClose processes a close action: atomically set close-pending and
// accept a final voucher if provided.
//
// Once CloseRequestedAt is set, vouchers, deliveries, commits, and top-ups
// are all rejected, and a second close is rejected with "close already
// requested". A non-monotonic final voucher is a hard error (unless it is an
// idempotent replay of the current highest voucher) and leaves the state
// unchanged. On-chain settlement (settle_and_finalize + distribute) is driven
// by the host after this returns; see MarkFinalized for the post-settlement
// transition.
func (s *SessionServer) ProcessClose(ctx context.Context, payload *intents.ClosePayload) (ChannelState, error) {
	now := uint64(time.Now().Unix())
	channelID := payload.ChannelID
	voucher := payload.Voucher

	return s.store.UpdateChannel(ctx, channelID, func(current *ChannelState) (ChannelState, error) {
		if current == nil {
			return ChannelState{}, fmt.Errorf("channel %s not found", channelID)
		}
		if current.Finalized {
			return ChannelState{}, fmt.Errorf("channel %s is already finalized", channelID)
		}
		if current.CloseRequestedAt != nil {
			return ChannelState{}, fmt.Errorf("close already requested")
		}

		next := *current
		if voucher != nil {
			cumulative, err := strconv.ParseUint(voucher.Data.Cumulative, 10, 64)
			if err != nil {
				return ChannelState{}, fmt.Errorf("invalid cumulative in final voucher: %s", voucher.Data.Cumulative)
			}
			if cumulative <= current.Cumulative {
				// Idempotent replay of the current highest voucher is allowed;
				// any other non-monotonic final voucher is a hard error.
				replay := cumulative == current.Cumulative &&
					current.HighestVoucherSignature != nil &&
					*current.HighestVoucherSignature == voucher.Signature
				if !replay {
					return ChannelState{}, fmt.Errorf(
						"final voucher cumulative %d must exceed watermark %d", cumulative, current.Cumulative)
				}
				// Recheck expiry/window even on idempotent replay so a close is not
				// recorded against a voucher that no longer outlasts the settlement
				// window (the async settle would then be rejected on-chain).
				if err := verifySessionVoucher(*voucher, current.AuthorizedSigner, s.config.SettlementWindowSeconds); err != nil {
					return ChannelState{}, err
				}
				if next.HighestVoucherExpiresAt == nil {
					expiresAt := voucher.Data.ExpiresAt
					next.HighestVoucherExpiresAt = &expiresAt
				}
			} else {
				if cumulative > current.Deposit {
					return ChannelState{}, fmt.Errorf("final voucher exceeds deposit")
				}
				if err := verifySessionVoucher(*voucher, current.AuthorizedSigner, s.config.SettlementWindowSeconds); err != nil {
					return ChannelState{}, err
				}
				signature := voucher.Signature
				expiresAt := voucher.Data.ExpiresAt
				next.Cumulative = cumulative
				next.HighestVoucherSignature = &signature
				next.HighestVoucherExpiresAt = &expiresAt
			}
		}
		closeRequestedAt := now
		next.CloseRequestedAt = &closeRequestedAt
		return next, nil
	})
}

// MarkFinalized marks a channel as finalized. Call after the on-chain
// finalize transaction confirms.
func (s *SessionServer) MarkFinalized(ctx context.Context, channelID string) error {
	_, err := s.store.MarkFinalized(ctx, channelID)
	return err
}
