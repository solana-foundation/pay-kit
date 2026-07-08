"""Voucher verifier for the MPP session server.

Pure function: given a current channel snapshot and a signed voucher, decide
whether to accept (and what the new watermark would be), reject, or treat as an
idempotent replay. The caller persists any accepted delta through the channel
store, re-checking inside the atomic mutator.

The check sequence (order and operators) is normative and must be applied in
exactly this order::

    parse u64 -> sealed -> close pending -> idempotent replay (same
    cumulative AND same signature, signature re-verified) -> cumulative >
    watermark strictly -> cumulative <= deposit -> delta >= min_voucher_delta ->
    Ed25519 verify against the stored authorized_signer -> expiry.

Expiry follows the on-chain program's ``settle_and_seal`` rule
(``payment_channels`` ``helpers/voucher.rs``): the program rejects a voucher
only when ``expires_at != 0 && now >= expires_at``, so ``expires_at == 0`` means
**never-expires** and is always accepted. Off-chain acceptance mirrors that, with
one extra guard: because settlement is asynchronous (the server may co-sign and
broadcast the close up to the channel's forced-close grace period later), a
non-zero ``expires_at`` must also OUTLAST the settlement window — we reject when
``expires_at < now + settlement_window`` so a voucher cannot expire on-chain
after the server has already served the request but before the settle lands.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from enum import StrEnum

from solana_pay_kit.protocols.mpp.intents.session import SignedVoucher


class VoucherVerifyStatus(StrEnum):
    """The outcome class of a voucher verification."""

    #: The voucher advanced the channel watermark.
    ACCEPTED = "accepted"

    #: An already-accepted voucher was re-submitted (idempotent).
    REPLAYED = "replayed"

    #: The voucher was rejected; see ``VoucherVerifyResult.reason``.
    REJECTED = "rejected"


class VoucherRejectReason(StrEnum):
    """A stable string tag for voucher rejections so the caller can map to HTTP
    statuses / log levels without parsing free text. The tag values are part of
    the wire contract and must not change.
    """

    #: The delta is below the configured minimum.
    BELOW_MIN_DELTA = "below-min-delta"

    #: A close was already requested.
    CHANNEL_CLOSE_PENDING = "channel-close-pending"

    #: The channel is already sealed.
    CHANNEL_SEALED = "channel-sealed"

    #: The cumulative does not strictly exceed the watermark.
    CUMULATIVE_NOT_MONOTONIC = "cumulative-not-monotonic"

    #: The cumulative exceeds the deposit cap.
    EXCEEDS_DEPOSIT = "exceeds-deposit"

    #: The voucher expiry is not in the future.
    EXPIRED = "expired"

    #: The non-zero voucher expiry is in the future but does not outlast the
    #: settlement window, so it could expire on-chain before the asynchronous
    #: close settlement lands.
    EXPIRES_BEFORE_SETTLEMENT = "expires-before-settlement"

    #: The cumulative does not parse as a u64.
    INVALID_CUMULATIVE = "invalid-cumulative"

    #: The Ed25519 signature check failed.
    INVALID_SIGNATURE = "invalid-signature"


@dataclass
class ChannelState:
    """The persisted state of a single payment channel from the server's point
    of view, as read by the voucher verifier.

    The voucher verifier only reads a subset of the full channel state; this
    dataclass carries the fields it needs.
    """

    #: The on-chain channel address (base58).
    channel_id: str

    #: The public key authorized to sign vouchers for this session (base58).
    authorized_signer: str

    #: The total deposit / approved amount locked for this session (base units).
    deposit: int = 0

    #: The highest cumulative amount accepted by the server (the settled
    #: watermark).
    cumulative: int = 0

    #: True once the channel has been sealed on-chain.
    sealed: bool = False

    #: The signature of the highest accepted voucher (base58). Stored for
    #: idempotent replay detection.
    highest_voucher_signature: str | None = None

    #: The expiry timestamp from the highest accepted voucher.
    highest_voucher_expires_at: int | None = None

    #: The Unix timestamp (seconds) when cooperative close was requested. Once
    #: set, no further vouchers are accepted.
    close_requested_at: int | None = None


@dataclass
class VoucherVerifyResult:
    """The verdict of :func:`verify_voucher_for_channel`.

    ``status`` selects which fields are meaningful: ``new_cumulative`` for
    accepted and replayed; ``new_expires_at`` and ``new_signature`` for accepted
    only; ``reason`` and ``detail`` for rejected only.
    """

    #: The outcome class.
    status: VoucherVerifyStatus

    #: The watermark to persist (accepted) or the existing watermark (replayed).
    new_cumulative: int = 0

    #: The expiry of the now-highest voucher (accepted only).
    new_expires_at: int = 0

    #: The signature to persist as ``highest_voucher_signature`` (accepted only,
    #: base58).
    new_signature: str = ""

    #: The stable rejection tag (rejected only).
    reason: VoucherRejectReason | None = None

    #: A human-readable rejection detail. Safe to log; not stable.
    detail: str = ""


@dataclass
class VerifyVoucherArgs:
    """The inputs to :func:`verify_voucher_for_channel`."""

    #: The channel snapshot, typically read just before calling.
    state: ChannelState

    #: The voucher being submitted.
    signed: SignedVoucher

    #: The authoritative deposit cap. Passed in (rather than read off ``state``)
    #: because some callers carry an updated cap after a recent top-up that has
    #: not yet been written back into the store.
    deposit: int = 0

    #: The optional minimum delta from the previous cumulative. Zero disables
    #: the check.
    min_voucher_delta: int = 0

    #: The settlement window in seconds: the channel forced-close grace period
    #: the server must survive between accepting a voucher and landing the
    #: on-chain close settlement. A non-zero voucher ``expires_at`` must outlast
    #: ``now + settlement_window`` or it is rejected (see
    #: :attr:`VoucherRejectReason.EXPIRES_BEFORE_SETTLEMENT`). Zero disables the
    #: outlast check (only ``expires_at <= now`` rejects a non-zero expiry).
    settlement_window: int = 0

    #: Overrides the clock (Unix seconds) for deterministic tests. ``None``
    #: defaults to the wall clock.
    now_seconds: int | None = None


def verify_voucher_for_channel(args: VerifyVoucherArgs) -> VoucherVerifyResult:
    """Verify a voucher against a channel snapshot.

    Returns a verdict; the caller is responsible for persisting any accepted
    delta via the channel store. The verifier is pure: no store, network, or
    clock side effects (the clock is injectable).
    """
    state = args.state
    signed = args.signed

    # 1. Parse new cumulative from the payload.
    try:
        new_cumulative = _parse_u64(signed.data.cumulative)
    except ValueError:
        return _voucher_reject(
            VoucherRejectReason.INVALID_CUMULATIVE,
            f"invalid cumulative in voucher: {signed.data.cumulative}",
        )

    # 2. Channel must not be sealed.
    if state.sealed:
        return _voucher_reject(
            VoucherRejectReason.CHANNEL_SEALED,
            f"channel {state.channel_id} is already sealed",
        )

    # 3. Channel must not be in close-pending.
    if state.close_requested_at is not None:
        return _voucher_reject(
            VoucherRejectReason.CHANNEL_CLOSE_PENDING,
            f"channel {state.channel_id} close is pending; no further vouchers accepted",
        )

    # 4. Idempotent replay: same cumulative AND same signature. The signature is
    # re-verified so a replay of a forged voucher cannot slip through.
    if (
        new_cumulative == state.cumulative
        and state.highest_voucher_signature is not None
        and state.highest_voucher_signature == signed.signature
    ):
        err = _verify_voucher_signature_bytes(signed, state.authorized_signer)
        if err is not None:
            return _voucher_reject(VoucherRejectReason.INVALID_SIGNATURE, err)
        expiry_reject = _check_voucher_expiry(
            signed.data.expires_at, _voucher_now(args.now_seconds), args.settlement_window
        )
        if expiry_reject is not None:
            return expiry_reject
        return VoucherVerifyResult(status=VoucherVerifyStatus.REPLAYED, new_cumulative=new_cumulative)

    # 5. Must strictly exceed the watermark (non-replay case).
    if new_cumulative <= state.cumulative:
        return _voucher_reject(
            VoucherRejectReason.CUMULATIVE_NOT_MONOTONIC,
            f"voucher cumulative {new_cumulative} must exceed watermark {state.cumulative}",
        )

    # 6. Must not exceed the deposit.
    if new_cumulative > args.deposit:
        return _voucher_reject(
            VoucherRejectReason.EXCEEDS_DEPOSIT,
            f"voucher cumulative {new_cumulative} exceeds deposit {args.deposit}",
        )

    # 7. Min delta check.
    delta = new_cumulative - state.cumulative
    if args.min_voucher_delta > 0 and delta < args.min_voucher_delta:
        return _voucher_reject(
            VoucherRejectReason.BELOW_MIN_DELTA,
            f"voucher delta {delta} is below minimum {args.min_voucher_delta}",
        )

    # 8. Verify the Ed25519 signature over the 50-byte canonical payload.
    err = _verify_voucher_signature_bytes(signed, state.authorized_signer)
    if err is not None:
        return _voucher_reject(VoucherRejectReason.INVALID_SIGNATURE, err)

    # 9. Expiry. ``expires_at == 0`` is never-expires (matches the on-chain
    # settle); a non-zero expiry must be in the future AND outlast the settlement
    # window. The caller may override now_seconds for deterministic tests.
    expiry_reject = _check_voucher_expiry(
        signed.data.expires_at, _voucher_now(args.now_seconds), args.settlement_window
    )
    if expiry_reject is not None:
        return expiry_reject

    return VoucherVerifyResult(
        status=VoucherVerifyStatus.ACCEPTED,
        new_cumulative=new_cumulative,
        new_expires_at=signed.data.expires_at,
        new_signature=signed.signature,
    )


def _voucher_reject(reason: VoucherRejectReason, detail: str) -> VoucherVerifyResult:
    """Build a rejected verdict."""
    return VoucherVerifyResult(status=VoucherVerifyStatus.REJECTED, reason=reason, detail=detail)


def _check_voucher_expiry(expires_at: int, now: int, settlement_window: int) -> VoucherVerifyResult | None:
    """Apply the on-chain-aligned voucher expiry policy.

    Returns a rejected :class:`VoucherVerifyResult` when the voucher is expired
    or expires before the settlement window, or ``None`` when the expiry is
    acceptable.

    Policy (mirrors ``payment_channels`` ``helpers/voucher.rs``):

    - ``expires_at == 0`` is **never-expires** and is always accepted (the
      on-chain settle only rejects ``expires_at != 0 && now >= expires_at``).
    - A non-zero ``expires_at <= now`` is already expired -> ``EXPIRED``.
    - A non-zero ``expires_at`` that is in the future but does not outlast
      ``now + settlement_window`` could expire on-chain before the asynchronous
      close settlement lands -> ``EXPIRES_BEFORE_SETTLEMENT``. ``settlement_window``
      of 0 disables this guard.
    """
    if expires_at == 0:
        return None
    if expires_at <= now:
        return _voucher_reject(VoucherRejectReason.EXPIRED, "voucher has expired")
    if settlement_window > 0 and expires_at < now + settlement_window:
        return _voucher_reject(
            VoucherRejectReason.EXPIRES_BEFORE_SETTLEMENT,
            f"voucher expires_at {expires_at} does not outlast the settlement window "
            f"(now {now} + {settlement_window}s = {now + settlement_window})",
        )
    return None


def _voucher_now(override: int | None) -> int:
    """Return the override when set, otherwise the wall clock in Unix seconds."""
    if override is not None:
        return override
    return int(time.time())


_U64_MAX = (1 << 64) - 1


def _parse_u64(raw: str) -> int:
    """Parse a canonical unsigned base-10 ``u64``.

    Rejects empty, signed, fractional, non-ASCII-digit, or out-of-range values.
    """
    if not (raw.isascii() and raw.isdigit()):
        raise ValueError(f"invalid cumulative {raw!r}")
    value = int(raw, 10)
    if value > _U64_MAX:
        raise ValueError(f"cumulative {raw!r} exceeds u64 range")
    return value


def _verify_voucher_signature_bytes(signed: SignedVoucher, authorized_signer: str) -> str | None:
    """Check the voucher's Ed25519 signature over the canonical 50-byte voucher
    payload against the authorized signer (both base58). The expiry check is not
    included; callers order it explicitly.

    Returns ``None`` on success or a human-readable error string on failure.
    """
    from solders.pubkey import Pubkey  # type: ignore[import-untyped]
    from solders.signature import Signature  # type: ignore[import-untyped]

    try:
        message = signed.data.message_bytes()
    except ValueError as exc:
        return str(exc)
    try:
        signature = Signature.from_string(signed.signature)
    except (ValueError, TypeError) as exc:
        return f"invalid signature encoding: {exc}"
    try:
        pubkey = Pubkey.from_string(authorized_signer)
    except (ValueError, TypeError) as exc:
        return f"invalid authorized signer: {exc}"
    if not signature.verify(pubkey, message):
        return "voucher signature verification failed"
    return None


def verify_session_voucher(signed: SignedVoucher, authorized_signer: str, settlement_window: int = 0) -> str | None:
    """Check expiry (including the settlement-window margin), then the signature.

    Used by the commit and close paths; the voucher handler orders the two
    checks itself. Returns ``None`` on success or a human-readable error string
    on failure.

    Expiry mirrors the on-chain settle rule and the voucher path's
    :func:`_check_voucher_expiry`: ``expires_at == 0`` is never-expires; a
    non-zero ``expires_at <= now`` has expired; and when ``settlement_window``
    is positive, a voucher that does not outlast ``now + settlement_window`` is
    rejected so a committed or closing voucher cannot expire before the async
    settle transaction lands on-chain.
    """
    rejection = _check_voucher_expiry(signed.data.expires_at, int(time.time()), settlement_window)
    if rejection is not None:
        return rejection.detail
    return _verify_voucher_signature_bytes(signed, authorized_signer)
