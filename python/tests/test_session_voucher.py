"""Voucher verifier coverage plus adversarial ordering checks.

Ports ``go/protocols/mpp/server/session_voucher_test.go``. The check sequence
(order and operators) is part of the wire contract and is asserted explicitly.
"""

from __future__ import annotations

import time

from solders.keypair import Keypair  # type: ignore[import-untyped]

from solana_pay_kit.protocols.mpp.intents.session import SignedVoucher, VoucherData
from solana_pay_kit.protocols.mpp.server.session_voucher import (
    ChannelState,
    VerifyVoucherArgs,
    VoucherRejectReason,
    VoucherVerifyStatus,
    verify_voucher_for_channel,
)

TEST_VOUCHER_CHANNEL_ID = "11111111111111111111111111111111"


class _TestVoucherSigner:
    """In-memory Ed25519 keypair for voucher tests.

    Mirrors the Go ``testVoucherSigner`` helper.
    """

    def __init__(self, seed: int) -> None:
        self._kp = Keypair.from_seed(bytes([seed] * 32))

    def address(self) -> str:
        return str(self._kp.pubkey())

    def sign_voucher(self, channel_id: str, cumulative: int, expires_at: int) -> SignedVoucher:
        data = VoucherData(
            channel_id=channel_id,
            cumulative=str(cumulative),
            expires_at=expires_at,
        )
        signature = self._kp.sign_message(data.message_bytes())
        return SignedVoucher(data=data, signature=str(signature))


def _far_future() -> int:
    return int(time.time()) + 3600


def _voucher_test_state(authorized_signer: str) -> ChannelState:
    return ChannelState(
        channel_id=TEST_VOUCHER_CHANNEL_ID,
        authorized_signer=authorized_signer,
        deposit=1_000,
    )


def test_verify_voucher_for_channel_happy_path() -> None:
    signer = _TestVoucherSigner(1)
    state = _voucher_test_state(signer.address())
    expires_at = _far_future()
    voucher = signer.sign_voucher(state.channel_id, 100, expires_at)

    result = verify_voucher_for_channel(VerifyVoucherArgs(state=state, signed=voucher, deposit=state.deposit))
    assert result.status == VoucherVerifyStatus.ACCEPTED
    assert result.new_cumulative == 100
    assert result.new_signature == voucher.signature
    assert result.new_expires_at == expires_at


def test_verify_voucher_for_channel_idempotent_replay() -> None:
    signer = _TestVoucherSigner(1)
    voucher = signer.sign_voucher(TEST_VOUCHER_CHANNEL_ID, 100, _far_future())
    state = _voucher_test_state(signer.address())
    state.cumulative = 100
    state.highest_voucher_signature = voucher.signature

    result = verify_voucher_for_channel(VerifyVoucherArgs(state=state, signed=voucher, deposit=1_000))
    assert result.status == VoucherVerifyStatus.REPLAYED
    assert result.new_cumulative == 100


def test_verify_voucher_for_channel_replay_re_verifies_signature() -> None:
    signer = _TestVoucherSigner(1)
    forger = _TestVoucherSigner(2)
    # A forged voucher whose signature somehow got persisted as the highest:
    # the replay path must still reject it on signature re-verification.
    forged = forger.sign_voucher(TEST_VOUCHER_CHANNEL_ID, 100, _far_future())
    state = _voucher_test_state(signer.address())
    state.cumulative = 100
    state.highest_voucher_signature = forged.signature

    result = verify_voucher_for_channel(VerifyVoucherArgs(state=state, signed=forged, deposit=1_000))
    assert result.status == VoucherVerifyStatus.REJECTED
    assert result.reason == VoucherRejectReason.INVALID_SIGNATURE


def test_verify_voucher_for_channel_replay_of_expired_voucher_rejected() -> None:
    signer = _TestVoucherSigner(1)
    past = int(time.time()) - 10
    voucher = signer.sign_voucher(TEST_VOUCHER_CHANNEL_ID, 100, past)
    state = _voucher_test_state(signer.address())
    state.cumulative = 100
    state.highest_voucher_signature = voucher.signature

    result = verify_voucher_for_channel(VerifyVoucherArgs(state=state, signed=voucher, deposit=1_000))
    assert result.status == VoucherVerifyStatus.REJECTED
    assert result.reason == VoucherRejectReason.EXPIRED


def test_verify_voucher_for_channel_decreasing_cumulative_rejected() -> None:
    signer = _TestVoucherSigner(1)
    voucher = signer.sign_voucher(TEST_VOUCHER_CHANNEL_ID, 50, _far_future())
    state = _voucher_test_state(signer.address())
    state.cumulative = 100

    result = verify_voucher_for_channel(VerifyVoucherArgs(state=state, signed=voucher, deposit=1_000))
    assert result.status == VoucherVerifyStatus.REJECTED
    assert result.reason == VoucherRejectReason.CUMULATIVE_NOT_MONOTONIC


def test_verify_voucher_for_channel_equal_cumulative_without_matching_signature_rejected() -> None:
    signer = _TestVoucherSigner(1)
    voucher = signer.sign_voucher(TEST_VOUCHER_CHANNEL_ID, 100, _far_future())
    other_signature = "5J6vbXSpEpGv4VLLqDhuRG6Tbj5n6dgEgvtTwTKpoSjvSwLTW9PSqQc6dpMUDPCvD3KZ5dGsmiTk5jzwYZyD8Xkz"
    state = _voucher_test_state(signer.address())
    state.cumulative = 100
    state.highest_voucher_signature = other_signature

    result = verify_voucher_for_channel(VerifyVoucherArgs(state=state, signed=voucher, deposit=1_000))
    assert result.status == VoucherVerifyStatus.REJECTED
    assert result.reason == VoucherRejectReason.CUMULATIVE_NOT_MONOTONIC


def test_verify_voucher_for_channel_exceeds_deposit_rejected() -> None:
    signer = _TestVoucherSigner(1)
    voucher = signer.sign_voucher(TEST_VOUCHER_CHANNEL_ID, 2_000, _far_future())
    state = _voucher_test_state(signer.address())

    result = verify_voucher_for_channel(VerifyVoucherArgs(state=state, signed=voucher, deposit=1_000))
    assert result.status == VoucherVerifyStatus.REJECTED
    assert result.reason == VoucherRejectReason.EXCEEDS_DEPOSIT


def test_verify_voucher_for_channel_below_min_delta_rejected() -> None:
    signer = _TestVoucherSigner(1)
    voucher = signer.sign_voucher(TEST_VOUCHER_CHANNEL_ID, 5, _far_future())
    state = _voucher_test_state(signer.address())

    result = verify_voucher_for_channel(
        VerifyVoucherArgs(state=state, signed=voucher, deposit=1_000, min_voucher_delta=100)
    )
    assert result.status == VoucherVerifyStatus.REJECTED
    assert result.reason == VoucherRejectReason.BELOW_MIN_DELTA


def test_verify_voucher_for_channel_bad_signature_rejected() -> None:
    signer = _TestVoucherSigner(1)
    other = _TestVoucherSigner(2)
    # Sign with other, but the channel authorizes signer; sig must fail.
    voucher = other.sign_voucher(TEST_VOUCHER_CHANNEL_ID, 100, _far_future())
    state = _voucher_test_state(signer.address())

    result = verify_voucher_for_channel(VerifyVoucherArgs(state=state, signed=voucher, deposit=1_000))
    assert result.status == VoucherVerifyStatus.REJECTED
    assert result.reason == VoucherRejectReason.INVALID_SIGNATURE


def test_verify_voucher_for_channel_expired_rejected() -> None:
    signer = _TestVoucherSigner(1)
    voucher = signer.sign_voucher(TEST_VOUCHER_CHANNEL_ID, 100, int(time.time()) - 10)
    state = _voucher_test_state(signer.address())

    result = verify_voucher_for_channel(VerifyVoucherArgs(state=state, signed=voucher, deposit=1_000))
    assert result.status == VoucherVerifyStatus.REJECTED
    assert result.reason == VoucherRejectReason.EXPIRED


def test_verify_voucher_for_channel_finalized_rejected() -> None:
    signer = _TestVoucherSigner(1)
    voucher = signer.sign_voucher(TEST_VOUCHER_CHANNEL_ID, 100, _far_future())
    state = _voucher_test_state(signer.address())
    state.finalized = True

    result = verify_voucher_for_channel(VerifyVoucherArgs(state=state, signed=voucher, deposit=1_000))
    assert result.status == VoucherVerifyStatus.REJECTED
    assert result.reason == VoucherRejectReason.CHANNEL_FINALIZED


def test_verify_voucher_for_channel_close_pending_rejected() -> None:
    signer = _TestVoucherSigner(1)
    voucher = signer.sign_voucher(TEST_VOUCHER_CHANNEL_ID, 100, _far_future())
    state = _voucher_test_state(signer.address())
    state.close_requested_at = 1

    result = verify_voucher_for_channel(VerifyVoucherArgs(state=state, signed=voucher, deposit=1_000))
    assert result.status == VoucherVerifyStatus.REJECTED
    assert result.reason == VoucherRejectReason.CHANNEL_CLOSE_PENDING


def test_verify_voucher_for_channel_now_seconds_override_is_deterministic() -> None:
    signer = _TestVoucherSigner(1)
    voucher = signer.sign_voucher(TEST_VOUCHER_CHANNEL_ID, 100, 1_000)
    state = _voucher_test_state(signer.address())

    expired = verify_voucher_for_channel(
        VerifyVoucherArgs(state=state, signed=voucher, deposit=1_000, now_seconds=2_000)
    )
    assert expired.status == VoucherVerifyStatus.REJECTED
    assert expired.reason == VoucherRejectReason.EXPIRED

    fresh = verify_voucher_for_channel(VerifyVoucherArgs(state=state, signed=voucher, deposit=1_000, now_seconds=500))
    assert fresh.status == VoucherVerifyStatus.ACCEPTED


def test_verify_voucher_for_channel_invalid_cumulative_rejected() -> None:
    signer = _TestVoucherSigner(1)
    real = signer.sign_voucher(TEST_VOUCHER_CHANNEL_ID, 100, _far_future())
    # Tamper the data field after signing; the verifier should reject on parse
    # before the signature check.
    tampered = SignedVoucher(
        data=VoucherData(
            channel_id=real.data.channel_id,
            cumulative="not-a-number",
            expires_at=real.data.expires_at,
        ),
        signature=real.signature,
    )
    state = _voucher_test_state(signer.address())

    result = verify_voucher_for_channel(VerifyVoucherArgs(state=state, signed=tampered, deposit=1_000))
    assert result.status == VoucherVerifyStatus.REJECTED
    assert result.reason == VoucherRejectReason.INVALID_CUMULATIVE


# Ordering checks: each earlier step must win over every later failure present
# in the same voucher.


def test_verify_voucher_for_channel_ordering_parse_beats_finalized() -> None:
    signer = _TestVoucherSigner(1)
    state = _voucher_test_state(signer.address())
    state.finalized = True
    voucher = SignedVoucher(
        data=VoucherData(
            channel_id=state.channel_id,
            cumulative="bogus",
            expires_at=_far_future(),
        ),
        signature="sig",
    )

    result = verify_voucher_for_channel(VerifyVoucherArgs(state=state, signed=voucher, deposit=1_000))
    assert result.reason == VoucherRejectReason.INVALID_CUMULATIVE


def test_verify_voucher_for_channel_ordering_finalized_beats_close_pending() -> None:
    signer = _TestVoucherSigner(1)
    state = _voucher_test_state(signer.address())
    state.finalized = True
    state.close_requested_at = 1
    voucher = signer.sign_voucher(state.channel_id, 100, _far_future())

    result = verify_voucher_for_channel(VerifyVoucherArgs(state=state, signed=voucher, deposit=1_000))
    assert result.reason == VoucherRejectReason.CHANNEL_FINALIZED


def test_verify_voucher_for_channel_ordering_monotonic_beats_deposit() -> None:
    signer = _TestVoucherSigner(1)
    state = _voucher_test_state(signer.address())
    state.deposit = 10
    state.cumulative = 100
    # Non-monotonic AND over deposit: monotonicity is checked first.
    voucher = signer.sign_voucher(state.channel_id, 50, _far_future())

    result = verify_voucher_for_channel(VerifyVoucherArgs(state=state, signed=voucher, deposit=10))
    assert result.reason == VoucherRejectReason.CUMULATIVE_NOT_MONOTONIC


def test_verify_voucher_for_channel_ordering_deposit_beats_min_delta() -> None:
    signer = _TestVoucherSigner(1)
    state = _voucher_test_state(signer.address())
    state.deposit = 10
    # Over deposit AND below min delta relative to a large min: deposit wins.
    voucher = signer.sign_voucher(state.channel_id, 20, _far_future())

    result = verify_voucher_for_channel(
        VerifyVoucherArgs(state=state, signed=voucher, deposit=10, min_voucher_delta=100)
    )
    assert result.reason == VoucherRejectReason.EXCEEDS_DEPOSIT


def test_verify_voucher_for_channel_ordering_min_delta_beats_signature() -> None:
    signer = _TestVoucherSigner(1)
    other = _TestVoucherSigner(2)
    state = _voucher_test_state(signer.address())
    # Below min delta AND wrongly signed: min delta is checked first.
    voucher = other.sign_voucher(state.channel_id, 5, _far_future())

    result = verify_voucher_for_channel(
        VerifyVoucherArgs(state=state, signed=voucher, deposit=1_000, min_voucher_delta=100)
    )
    assert result.reason == VoucherRejectReason.BELOW_MIN_DELTA


def test_verify_voucher_for_channel_ordering_signature_beats_expiry() -> None:
    signer = _TestVoucherSigner(1)
    other = _TestVoucherSigner(2)
    state = _voucher_test_state(signer.address())
    # Wrongly signed AND expired: the signature is verified before expiry.
    voucher = other.sign_voucher(state.channel_id, 100, int(time.time()) - 10)

    result = verify_voucher_for_channel(VerifyVoucherArgs(state=state, signed=voucher, deposit=1_000))
    assert result.reason == VoucherRejectReason.INVALID_SIGNATURE


# -- Fix #9: expiry vs. async settlement --------------------------------------
#
# The on-chain settle (payment_channels helpers/voucher.rs) rejects only
# ``expires_at != 0 && now >= expires_at``; ``expires_at == 0`` is never-expires
# and must be ACCEPTED off-chain too. A non-zero expiry must additionally
# outlast the settlement window so the voucher cannot expire on-chain after the
# request is served but before the close settlement lands.


def test_verify_voucher_for_channel_zero_expires_at_is_never_expires() -> None:
    """expires_at == 0 means never-expires: it must be accepted, never rejected
    as EXPIRED (mirrors the on-chain ``expires_at != 0`` guard)."""
    signer = _TestVoucherSigner(1)
    voucher = signer.sign_voucher(TEST_VOUCHER_CHANNEL_ID, 100, 0)
    state = _voucher_test_state(signer.address())

    # Even with a far-future clock, a zero expiry is accepted.
    result = verify_voucher_for_channel(
        VerifyVoucherArgs(state=state, signed=voucher, deposit=1_000, now_seconds=10_000_000_000)
    )
    assert result.status == VoucherVerifyStatus.ACCEPTED
    assert result.new_expires_at == 0


def test_verify_voucher_for_channel_zero_expires_at_replay_is_never_expires() -> None:
    """A replay of a zero-expiry voucher is idempotent (REPLAYED), not EXPIRED."""
    signer = _TestVoucherSigner(1)
    voucher = signer.sign_voucher(TEST_VOUCHER_CHANNEL_ID, 100, 0)
    state = _voucher_test_state(signer.address())
    state.cumulative = 100
    state.highest_voucher_signature = voucher.signature

    result = verify_voucher_for_channel(
        VerifyVoucherArgs(state=state, signed=voucher, deposit=1_000, now_seconds=10_000_000_000)
    )
    assert result.status == VoucherVerifyStatus.REPLAYED
    assert result.new_cumulative == 100


def test_verify_voucher_for_channel_zero_expires_at_survives_settlement_window() -> None:
    """A zero expiry outlasts any settlement window (never-expires)."""
    signer = _TestVoucherSigner(1)
    voucher = signer.sign_voucher(TEST_VOUCHER_CHANNEL_ID, 100, 0)
    state = _voucher_test_state(signer.address())

    result = verify_voucher_for_channel(
        VerifyVoucherArgs(
            state=state, signed=voucher, deposit=1_000, now_seconds=1_000, settlement_window=900
        )
    )
    assert result.status == VoucherVerifyStatus.ACCEPTED


def test_verify_voucher_for_channel_nonzero_expires_at_must_outlast_settlement_window() -> None:
    """A non-zero expiry in the future but inside the settlement window is
    rejected: it could expire on-chain before the async close settlement."""
    signer = _TestVoucherSigner(1)
    # now=1000, window=900 -> need expires_at >= 1900. 1500 is in the future but
    # does not outlast the window.
    voucher = signer.sign_voucher(TEST_VOUCHER_CHANNEL_ID, 100, 1_500)
    state = _voucher_test_state(signer.address())

    result = verify_voucher_for_channel(
        VerifyVoucherArgs(
            state=state, signed=voucher, deposit=1_000, now_seconds=1_000, settlement_window=900
        )
    )
    assert result.status == VoucherVerifyStatus.REJECTED
    assert result.reason == VoucherRejectReason.EXPIRES_BEFORE_SETTLEMENT


def test_verify_voucher_for_channel_nonzero_expires_at_outlasting_window_accepted() -> None:
    """A non-zero expiry at/after now + settlement_window is accepted."""
    signer = _TestVoucherSigner(1)
    voucher = signer.sign_voucher(TEST_VOUCHER_CHANNEL_ID, 100, 1_900)
    state = _voucher_test_state(signer.address())

    result = verify_voucher_for_channel(
        VerifyVoucherArgs(
            state=state, signed=voucher, deposit=1_000, now_seconds=1_000, settlement_window=900
        )
    )
    assert result.status == VoucherVerifyStatus.ACCEPTED


def test_verify_voucher_for_channel_expired_beats_settlement_window() -> None:
    """An already-expired non-zero voucher reports EXPIRED, not
    EXPIRES_BEFORE_SETTLEMENT (the ``<= now`` check runs first)."""
    signer = _TestVoucherSigner(1)
    voucher = signer.sign_voucher(TEST_VOUCHER_CHANNEL_ID, 100, 500)
    state = _voucher_test_state(signer.address())

    result = verify_voucher_for_channel(
        VerifyVoucherArgs(
            state=state, signed=voucher, deposit=1_000, now_seconds=1_000, settlement_window=900
        )
    )
    assert result.status == VoucherVerifyStatus.REJECTED
    assert result.reason == VoucherRejectReason.EXPIRED


def test_verify_voucher_for_channel_settlement_window_zero_disables_outlast_check() -> None:
    """With settlement_window == 0 only ``expires_at <= now`` rejects a non-zero
    expiry; a near-future expiry is accepted (backward compatible)."""
    signer = _TestVoucherSigner(1)
    voucher = signer.sign_voucher(TEST_VOUCHER_CHANNEL_ID, 100, 1_001)
    state = _voucher_test_state(signer.address())

    result = verify_voucher_for_channel(
        VerifyVoucherArgs(state=state, signed=voucher, deposit=1_000, now_seconds=1_000)
    )
    assert result.status == VoucherVerifyStatus.ACCEPTED


def test_verify_voucher_for_channel_nonzero_expires_at_window_applies_to_replay() -> None:
    """The settlement-window outlast guard also applies on the replay path."""
    signer = _TestVoucherSigner(1)
    voucher = signer.sign_voucher(TEST_VOUCHER_CHANNEL_ID, 100, 1_500)
    state = _voucher_test_state(signer.address())
    state.cumulative = 100
    state.highest_voucher_signature = voucher.signature

    result = verify_voucher_for_channel(
        VerifyVoucherArgs(
            state=state, signed=voucher, deposit=1_000, now_seconds=1_000, settlement_window=900
        )
    )
    assert result.status == VoucherVerifyStatus.REJECTED
    assert result.reason == VoucherRejectReason.EXPIRES_BEFORE_SETTLEMENT


# -- Fix #8: cumulative-as-nonce / replay -------------------------------------
#
# A new charge requires a STRICT cumulative increment; an exact replay (same
# cumulative AND same signature) is an idempotent no-charge (REPLAYED), not a
# fresh serve; a different/lower voucher is rejected.


def test_verify_voucher_for_channel_strict_increment_advances() -> None:
    """A strictly larger cumulative is a fresh ACCEPTED charge."""
    signer = _TestVoucherSigner(1)
    state = _voucher_test_state(signer.address())
    state.cumulative = 100
    voucher = signer.sign_voucher(state.channel_id, 101, _far_future())

    result = verify_voucher_for_channel(VerifyVoucherArgs(state=state, signed=voucher, deposit=1_000))
    assert result.status == VoucherVerifyStatus.ACCEPTED
    assert result.new_cumulative == 101


def test_verify_voucher_for_channel_exact_replay_is_zero_charge() -> None:
    """An exact replay (same cumulative + same signature) is idempotent: REPLAYED
    with the watermark unchanged, signalling a zero-charge no-op (not a fresh
    serve). The caller distinguishes REPLAYED from ACCEPTED to avoid charging or
    re-serving."""
    signer = _TestVoucherSigner(1)
    voucher = signer.sign_voucher(TEST_VOUCHER_CHANNEL_ID, 250, _far_future())
    state = _voucher_test_state(signer.address())
    state.cumulative = 250
    state.highest_voucher_signature = voucher.signature

    result = verify_voucher_for_channel(VerifyVoucherArgs(state=state, signed=voucher, deposit=1_000))
    assert result.status == VoucherVerifyStatus.REPLAYED
    # Watermark is unchanged: nothing new is charged on a replay.
    assert result.new_cumulative == state.cumulative == 250


def test_verify_voucher_for_channel_same_cumulative_different_signature_rejected() -> None:
    """Same cumulative as the watermark but a DIFFERENT signature is not an
    idempotent replay; it fails the strict-increment check and is rejected as
    non-monotonic (a forged/swapped voucher cannot pose as a replay)."""
    signer = _TestVoucherSigner(1)
    prior = signer.sign_voucher(TEST_VOUCHER_CHANNEL_ID, 100, _far_future())
    # A second, distinct signature over the same cumulative (different expiry
    # changes the signed bytes, so the signature differs).
    other = signer.sign_voucher(TEST_VOUCHER_CHANNEL_ID, 100, _far_future() + 1)
    assert other.signature != prior.signature
    state = _voucher_test_state(signer.address())
    state.cumulative = 100
    state.highest_voucher_signature = prior.signature

    result = verify_voucher_for_channel(VerifyVoucherArgs(state=state, signed=other, deposit=1_000))
    assert result.status == VoucherVerifyStatus.REJECTED
    assert result.reason == VoucherRejectReason.CUMULATIVE_NOT_MONOTONIC


def test_verify_voucher_for_channel_lower_cumulative_rejected() -> None:
    """A lower cumulative than the watermark is rejected as non-monotonic (no
    refunds / rewinds through a stale voucher)."""
    signer = _TestVoucherSigner(1)
    voucher = signer.sign_voucher(TEST_VOUCHER_CHANNEL_ID, 99, _far_future())
    state = _voucher_test_state(signer.address())
    state.cumulative = 100

    result = verify_voucher_for_channel(VerifyVoucherArgs(state=state, signed=voucher, deposit=1_000))
    assert result.status == VoucherVerifyStatus.REJECTED
    assert result.reason == VoucherRejectReason.CUMULATIVE_NOT_MONOTONIC
