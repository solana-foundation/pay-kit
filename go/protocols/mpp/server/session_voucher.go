package server

// Voucher verifier for the MPP session server.
//
// Pure function: given a current channel snapshot and a signed voucher,
// decide whether to accept (and what the new watermark would be), reject,
// or treat as an idempotent replay. The caller persists any accepted delta
// through ChannelStore.UpdateChannel, re-checking inside the atomic mutator.
//
// The check sequence (order and operators) is pinned across the language
// SDKs and harness-tested:
// parse u64 -> finalized -> close pending -> idempotent replay (same
// cumulative AND same signature, signature re-verified) -> cumulative >
// watermark strictly -> cumulative <= deposit -> delta >= minVoucherDelta ->
// Ed25519 verify against the stored authorizedSigner -> expiresAt > now.

import (
	"crypto/ed25519"
	"fmt"
	"strconv"
	"time"

	solana "github.com/gagliardetto/solana-go"

	"github.com/solana-foundation/pay-kit/go/protocols/mpp/intents"
)

// VoucherVerifyStatus is the outcome class of a voucher verification.
type VoucherVerifyStatus string

const (
	// VoucherVerifyAccepted means the voucher advanced the channel watermark.
	VoucherVerifyAccepted VoucherVerifyStatus = "accepted"

	// VoucherVerifyReplayed means an already-accepted voucher was re-submitted
	// (idempotent).
	VoucherVerifyReplayed VoucherVerifyStatus = "replayed"

	// VoucherVerifyRejected means the voucher was rejected; see
	// VoucherRejectReason.
	VoucherVerifyRejected VoucherVerifyStatus = "rejected"
)

// VoucherRejectReason is a stable string tag for voucher rejections so the
// caller can map to HTTP statuses / log levels without parsing free text.
// The tag values are stable across the language SDKs.
type VoucherRejectReason string

const (
	// VoucherRejectBelowMinDelta: the delta is below the configured minimum.
	VoucherRejectBelowMinDelta VoucherRejectReason = "below-min-delta"

	// VoucherRejectChannelClosePending: a close was already requested.
	VoucherRejectChannelClosePending VoucherRejectReason = "channel-close-pending"

	// VoucherRejectChannelFinalized: the channel is already finalized.
	VoucherRejectChannelFinalized VoucherRejectReason = "channel-finalized"

	// VoucherRejectCumulativeNotMonotonic: the cumulative does not strictly
	// exceed the watermark.
	VoucherRejectCumulativeNotMonotonic VoucherRejectReason = "cumulative-not-monotonic"

	// VoucherRejectExceedsDeposit: the cumulative exceeds the deposit cap.
	VoucherRejectExceedsDeposit VoucherRejectReason = "exceeds-deposit"

	// VoucherRejectExpired: the voucher expiry is not in the future.
	VoucherRejectExpired VoucherRejectReason = "expired"

	// VoucherRejectInvalidCumulative: the cumulative does not parse as a u64.
	VoucherRejectInvalidCumulative VoucherRejectReason = "invalid-cumulative"

	// VoucherRejectInvalidSignature: the Ed25519 signature check failed.
	VoucherRejectInvalidSignature VoucherRejectReason = "invalid-signature"
)

// VoucherVerifyResult is the verdict of VerifyVoucherForChannel.
//
// Status selects which fields are meaningful: NewCumulative for accepted and
// replayed; NewExpiresAt and NewSignature for accepted only; Reason and
// Detail for rejected only.
type VoucherVerifyResult struct {
	// Status is the outcome class.
	Status VoucherVerifyStatus

	// NewCumulative is the watermark to persist (accepted) or the existing
	// watermark (replayed).
	NewCumulative uint64

	// NewExpiresAt is the expiry of the now-highest voucher (accepted only).
	NewExpiresAt int64

	// NewSignature is the signature to persist as HighestVoucherSignature
	// (accepted only, base58).
	NewSignature string

	// Reason is the stable rejection tag (rejected only).
	Reason VoucherRejectReason

	// Detail is a human-readable rejection detail. Safe to log; not stable.
	Detail string
}

// VerifyVoucherArgs are the inputs to VerifyVoucherForChannel.
type VerifyVoucherArgs struct {
	// State is the channel snapshot, typically read just before calling.
	State ChannelState

	// Signed is the voucher being submitted.
	Signed intents.SignedVoucher

	// Deposit is the authoritative deposit cap. Passed in (rather than read
	// off State) because some callers carry an updated cap after a recent
	// top-up that has not yet been written back into the store.
	Deposit uint64

	// MinVoucherDelta is the optional minimum delta from the previous
	// cumulative. Zero disables the check.
	MinVoucherDelta uint64

	// NowSeconds overrides the clock (Unix seconds) for deterministic tests.
	// Nil defaults to time.Now().
	NowSeconds *int64
}

// VerifyVoucherForChannel verifies a voucher against a channel snapshot.
//
// Returns a verdict; the caller is responsible for persisting any accepted
// delta via ChannelStore.UpdateChannel. The verifier is pure: no store,
// network, or clock side effects (the clock is injectable).
func VerifyVoucherForChannel(args VerifyVoucherArgs) VoucherVerifyResult {
	state := args.State
	signed := args.Signed

	// 1. Parse new cumulative from the payload.
	newCumulative, err := strconv.ParseUint(signed.Data.Cumulative, 10, 64)
	if err != nil {
		return voucherReject(VoucherRejectInvalidCumulative,
			fmt.Sprintf("invalid cumulative in voucher: %s", signed.Data.Cumulative))
	}

	// 2. Channel must not be finalized.
	if state.Finalized {
		return voucherReject(VoucherRejectChannelFinalized,
			fmt.Sprintf("channel %s is already finalized", state.ChannelID))
	}

	// 3. Channel must not be in close-pending.
	if state.CloseRequestedAt != nil {
		return voucherReject(VoucherRejectChannelClosePending,
			fmt.Sprintf("channel %s close is pending; no further vouchers accepted", state.ChannelID))
	}

	// 4. Idempotent replay: same cumulative AND same signature. The signature
	// is re-verified so a replay of a forged voucher cannot slip through.
	if newCumulative == state.Cumulative &&
		state.HighestVoucherSignature != nil &&
		*state.HighestVoucherSignature == signed.Signature {
		if err := verifyVoucherSignatureBytes(signed, state.AuthorizedSigner); err != nil {
			return voucherReject(VoucherRejectInvalidSignature, err.Error())
		}
		if signed.Data.ExpiresAt <= voucherNow(args.NowSeconds) {
			return voucherReject(VoucherRejectExpired, "voucher has expired")
		}
		return VoucherVerifyResult{Status: VoucherVerifyReplayed, NewCumulative: newCumulative}
	}

	// 5. Must strictly exceed the watermark (non-replay case).
	if newCumulative <= state.Cumulative {
		return voucherReject(VoucherRejectCumulativeNotMonotonic,
			fmt.Sprintf("voucher cumulative %d must exceed watermark %d", newCumulative, state.Cumulative))
	}

	// 6. Must not exceed the deposit.
	if newCumulative > args.Deposit {
		return voucherReject(VoucherRejectExceedsDeposit,
			fmt.Sprintf("voucher cumulative %d exceeds deposit %d", newCumulative, args.Deposit))
	}

	// 7. Min delta check.
	delta := newCumulative - state.Cumulative
	if args.MinVoucherDelta > 0 && delta < args.MinVoucherDelta {
		return voucherReject(VoucherRejectBelowMinDelta,
			fmt.Sprintf("voucher delta %d is below minimum %d", delta, args.MinVoucherDelta))
	}

	// 8. Verify the Ed25519 signature over the 48-byte canonical payload.
	if err := verifyVoucherSignatureBytes(signed, state.AuthorizedSigner); err != nil {
		return voucherReject(VoucherRejectInvalidSignature, err.Error())
	}

	// 9. Expiry. The caller may override NowSeconds for deterministic tests.
	if signed.Data.ExpiresAt <= voucherNow(args.NowSeconds) {
		return voucherReject(VoucherRejectExpired, "voucher has expired")
	}

	return VoucherVerifyResult{
		Status:        VoucherVerifyAccepted,
		NewCumulative: newCumulative,
		NewExpiresAt:  signed.Data.ExpiresAt,
		NewSignature:  signed.Signature,
	}
}

// voucherReject builds a rejected verdict.
func voucherReject(reason VoucherRejectReason, detail string) VoucherVerifyResult {
	return VoucherVerifyResult{Status: VoucherVerifyRejected, Reason: reason, Detail: detail}
}

// voucherNow returns the override when set, otherwise the wall clock in Unix
// seconds.
func voucherNow(override *int64) int64 {
	if override != nil {
		return *override
	}
	return time.Now().Unix()
}

// verifyVoucherSignatureBytes checks the voucher's Ed25519 signature over the
// canonical 48-byte voucher payload against the authorized signer (both
// base58). The expiry check is not included; callers order it explicitly.
func verifyVoucherSignatureBytes(signed intents.SignedVoucher, authorizedSigner string) error {
	message, err := signed.Data.MessageBytes()
	if err != nil {
		return err
	}
	signature, err := solana.SignatureFromBase58(signed.Signature)
	if err != nil {
		return fmt.Errorf("invalid signature encoding: %w", err)
	}
	pubkey, err := solana.PublicKeyFromBase58(authorizedSigner)
	if err != nil {
		return fmt.Errorf("invalid authorized signer: %w", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(pubkey.Bytes()), message, signature[:]) {
		return fmt.Errorf("voucher signature verification failed")
	}
	return nil
}

// verifySessionVoucher checks expiry first (against the wall clock), then
// the Ed25519 signature. Used by the commit and close paths; the voucher
// handler orders the two checks itself.
func verifySessionVoucher(signed intents.SignedVoucher, authorizedSigner string) error {
	if signed.Data.ExpiresAt <= time.Now().Unix() {
		return fmt.Errorf("voucher has expired")
	}
	return verifyVoucherSignatureBytes(signed, authorizedSigner)
}
