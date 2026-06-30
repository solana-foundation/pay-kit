"""Off-chain session handler coverage.

Ports ``go/protocols/mpp/server/session_server_test.go``: open, voucher
verification, top-up, delivery begin/commit, close, and challenge-request
building. Each test mirrors a single Go ``Test...`` behavior through the public
:class:`SessionServer` interface.
"""

from __future__ import annotations

import time
from dataclasses import replace

import pytest
from solders.keypair import Keypair  # type: ignore[import-untyped]

from solana_pay_kit.protocols.mpp.intents.session import (
    DEFAULT_SESSION_EXPIRES_AT,
    ClosePayload,
    CommitPayload,
    OpenPayload,
    SignedVoucher,
    TopUpPayload,
    VoucherData,
    VoucherPayload,
)
from solana_pay_kit.protocols.mpp.server.session import (
    DeliveryRequest,
    SessionConfig,
    SessionServer,
    Split,
)
from solana_pay_kit.protocols.mpp.server.session_store import MemoryChannelStore

SESSION_TEST_RECIPIENT = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY"


def session_test_config() -> SessionConfig:
    return SessionConfig(
        operator=SESSION_TEST_RECIPIENT,
        recipient=SESSION_TEST_RECIPIENT,
        max_cap=10_000_000,
        currency="USDC",
        decimals=6,
        network="localnet",
        modes=["push"],
    )


def new_session_test_server(config: SessionConfig) -> SessionServer:
    return SessionServer(config, MemoryChannelStore())


def session_open_payload(channel_id: str, deposit: int, signer: str) -> OpenPayload:
    return OpenPayload.push(channel_id, str(deposit), signer, "dummy_tx_sig")


class _TestVoucherSigner:
    """In-memory Ed25519 keypair for voucher tests. Mirrors Go testVoucherSigner."""

    def __init__(self, seed: int) -> None:
        self._kp = Keypair.from_seed(bytes([seed] * 32))

    def address(self) -> str:
        return str(self._kp.pubkey())

    def sign_voucher(self, channel_id: str, cumulative: int, expires_at: int) -> SignedVoucher:
        data = VoucherData(channel_id=channel_id, cumulative=str(cumulative), expires_at=expires_at)
        signature = self._kp.sign_message(data.message_bytes())
        return SignedVoucher(data=data, signature=str(signature))


def _far_future() -> int:
    return int(time.time()) + 3600


def _channel_key() -> str:
    return str(Keypair().pubkey())


async def _open_test_channel(server: SessionServer, deposit: int) -> tuple[_TestVoucherSigner, str]:
    signer = _TestVoucherSigner(seed=7)
    channel_id = _channel_key()
    await server.process_open(session_open_payload(channel_id, deposit, signer.address()))
    return signer, channel_id


async def _submit_voucher(server: SessionServer, signer: _TestVoucherSigner, channel_id: str, cumulative: int) -> int:
    voucher = signer.sign_voucher(channel_id, cumulative, _far_future())
    return await server.verify_voucher(VoucherPayload(voucher=voucher))


# -- BuildChallengeRequest --


def test_build_challenge_request_canonical_shape() -> None:
    """Mirrors TestBuildChallengeRequestCanonicalShape."""
    config = session_test_config()
    config.min_voucher_delta = 0
    server = new_session_test_server(config)

    request = server.build_challenge_request(1_000_000)
    assert request.cap == "1000000"
    assert request.currency == "USDC"
    assert request.operator == SESSION_TEST_RECIPIENT
    assert request.recipient == SESSION_TEST_RECIPIENT
    assert request.decimals == 6
    assert request.network == "localnet"

    wire = request.to_dict()
    for absent in ("minVoucherDelta", "modes", "pullVoucherStrategy", "recentBlockhash"):
        assert absent not in wire


def test_build_challenge_request_clamps_cap_to_max() -> None:
    """Mirrors TestBuildChallengeRequestClampsCapToMax."""
    server = new_session_test_server(session_test_config())
    request = server.build_challenge_request(99_000_000)
    assert request.cap == "10000000"


def test_build_challenge_request_includes_min_voucher_delta_when_positive() -> None:
    """Mirrors TestBuildChallengeRequestIncludesMinVoucherDeltaWhenPositive."""
    config = session_test_config()
    config.min_voucher_delta = 250
    server = new_session_test_server(config)
    request = server.build_challenge_request(1_000)
    assert request.min_voucher_delta == "250"


def test_build_challenge_request_advertises_pull_mode_and_strategy() -> None:
    """Mirrors TestBuildChallengeRequestAdvertisesPullModeAndStrategy."""
    config = session_test_config()
    config.modes = ["push", "pull"]
    config.pull_voucher_strategy = "clientVoucher"
    config.splits = [Split(recipient=SESSION_TEST_RECIPIENT, bps=10)]
    server = new_session_test_server(config)

    request = server.build_challenge_request(1_000)
    assert len(request.modes) == 2
    assert request.pull_voucher_strategy == "clientVoucher"
    assert len(request.splits) == 1
    assert request.splits[0].recipient == SESSION_TEST_RECIPIENT
    assert request.splits[0].bps == 10


# -- process_open --


async def test_process_open_stores_state() -> None:
    """Mirrors TestProcessOpenStoresState."""
    server = new_session_test_server(session_test_config())
    state = await server.process_open(session_open_payload("chan1", 1_000_000, "signer1"))
    assert state.deposit == 1_000_000
    assert state.cumulative == 0
    assert not state.finalized
    assert state.authorized_signer == "signer1"


async def test_process_open_zero_deposit_rejected() -> None:
    """Mirrors TestProcessOpenZeroDepositRejected."""
    server = new_session_test_server(session_test_config())
    with pytest.raises(ValueError):
        await server.process_open(session_open_payload("chan1", 0, "signer1"))


async def test_process_open_exceeds_cap_rejected() -> None:
    """Mirrors TestProcessOpenExceedsCapRejected."""
    server = new_session_test_server(session_test_config())
    with pytest.raises(ValueError):
        await server.process_open(session_open_payload("chan1", 20_000_000, "signer1"))


async def test_process_open_rejects_unadvertised_pull_mode() -> None:
    """Mirrors TestProcessOpenRejectsUnadvertisedPullMode."""
    server = new_session_test_server(session_test_config())
    payload = OpenPayload.payment_channel_with_mode(
        "pull", "chan1", "1000000", "payer", SESSION_TEST_RECIPIENT, "mint", 1, 900, "signer1", "pending"
    )
    with pytest.raises(ValueError, match="not supported"):
        await server.process_open(payload)


async def test_process_open_accepts_advertised_pull_client_voucher_channel() -> None:
    """Mirrors TestProcessOpenAcceptsAdvertisedPullClientVoucherChannel."""
    config = session_test_config()
    config.modes = ["pull"]
    config.pull_voucher_strategy = "clientVoucher"
    server = new_session_test_server(config)
    payload = OpenPayload.payment_channel_with_mode(
        "pull", "chan1", "1000000", "payer", SESSION_TEST_RECIPIENT, "mint", 1, 900, "signer1", "pending"
    )
    state = await server.process_open(payload)
    assert state.channel_id == "chan1"
    assert state.deposit == 1_000_000
    assert state.operator == "payer"


async def test_process_open_prefers_channel_id_over_token_account() -> None:
    """Mirrors TestProcessOpenPrefersChannelIDOverTokenAccount."""
    config = session_test_config()
    config.modes = ["pull"]
    config.pull_voucher_strategy = "clientVoucher"
    server = new_session_test_server(config)

    payload = OpenPayload.pull("token-acct", "1000", "owner", "signer1", "sig")
    payload.channel_id = "delegation-pda"

    state = await server.process_open(payload)
    assert state.channel_id == "delegation-pda"
    assert state.operator == "owner"


async def test_process_open_replay_preserves_watermark() -> None:
    """Mirrors TestProcessOpenReplayPreservesWatermark."""
    server = new_session_test_server(session_test_config())
    signer, channel_id = await _open_test_channel(server, 1_000_000)

    await _submit_voucher(server, signer, channel_id, 250)

    replayed = await server.process_open(session_open_payload(channel_id, 1_000_000, signer.address()))
    assert replayed.cumulative == 250
    assert replayed.highest_voucher_signature is not None


async def test_process_open_replay_with_different_signer_rejected() -> None:
    """Mirrors TestProcessOpenReplayWithDifferentSignerRejected."""
    server = new_session_test_server(session_test_config())
    _, channel_id = await _open_test_channel(server, 1_000_000)

    other = _TestVoucherSigner(seed=9)
    with pytest.raises(ValueError, match="different authorized signer"):
        await server.process_open(session_open_payload(channel_id, 1_000_000, other.address()))


async def test_process_open_replay_on_finalized_channel_rejected() -> None:
    """Mirrors TestProcessOpenReplayOnFinalizedChannelRejected."""
    server = new_session_test_server(session_test_config())
    signer, channel_id = await _open_test_channel(server, 1_000_000)

    await server.mark_finalized(channel_id)
    with pytest.raises(ValueError, match="finalized"):
        await server.process_open(session_open_payload(channel_id, 1_000_000, signer.address()))


async def test_process_open_invokes_verify_open_tx_seam_for_push() -> None:
    """Mirrors TestProcessOpenInvokesVerifyOpenTxSeamForPush."""
    calls: list[OpenPayload] = []

    async def verifier(payload: OpenPayload) -> None:
        calls.append(payload)

    config = session_test_config()
    config.verify_open_tx = verifier
    server = new_session_test_server(config)
    await server.process_open(session_open_payload("chan1", 1_000, "signer1"))
    assert len(calls) == 1
    assert calls[0].signature == "dummy_tx_sig"


async def test_process_open_verify_open_tx_error_rejects_without_persisting() -> None:
    """Mirrors TestProcessOpenVerifyOpenTxErrorRejectsWithoutPersisting."""

    async def verifier(_: OpenPayload) -> None:
        raise ValueError("tx not found")

    config = session_test_config()
    config.verify_open_tx = verifier
    server = new_session_test_server(config)

    with pytest.raises(ValueError, match="tx not found"):
        await server.process_open(session_open_payload("chan1", 1_000, "signer1"))
    state = await server.store().get_channel("chan1")
    assert state is None


async def test_process_open_skips_verify_open_tx_for_pull() -> None:
    """Mirrors TestProcessOpenSkipsVerifyOpenTxForPull."""

    async def verifier(_: OpenPayload) -> None:
        raise AssertionError("verify_open_tx must not run for pull opens")

    config = session_test_config()
    config.modes = ["pull"]
    config.pull_voucher_strategy = "clientVoucher"
    config.verify_open_tx = verifier
    server = new_session_test_server(config)

    payload = OpenPayload.pull("token-acct", "1000", "owner", "signer1", "sig")
    await server.process_open(payload)


# -- verify_voucher --


async def test_verify_voucher_advances_watermark() -> None:
    """Mirrors TestVerifyVoucherAdvancesWatermark."""
    server = new_session_test_server(session_test_config())
    signer, channel_id = await _open_test_channel(server, 1_000_000)

    assert await _submit_voucher(server, signer, channel_id, 100) == 100
    assert await _submit_voucher(server, signer, channel_id, 300) == 300

    state = await server.store().get_channel(channel_id)
    assert state is not None
    assert state.cumulative == 300
    assert state.highest_voucher_signature is not None
    assert state.highest_voucher_expires_at is not None


async def test_verify_voucher_rejects_expiry_inside_settlement_window() -> None:
    """The configured ``settlement_window`` threads into voucher acceptance: a
    non-zero voucher expiry that does not outlast ``now + settlement_window`` is
    rejected so it cannot expire on-chain before the async close settlement."""
    config = replace(session_test_config(), settlement_window=3_600)
    server = new_session_test_server(config)
    signer, channel_id = await _open_test_channel(server, 1_000_000)

    # Expires in 60s, but the settlement window is 3600s: rejected.
    soon = int(time.time()) + 60
    voucher = signer.sign_voucher(channel_id, 100, soon)
    with pytest.raises(ValueError, match="expires-before-settlement|settlement window"):
        await server.verify_voucher(VoucherPayload(voucher=voucher))


async def test_verify_voucher_accepts_zero_expiry_under_settlement_window() -> None:
    """A zero (never-expires) voucher is accepted even when a settlement window
    is configured, matching the on-chain ``expires_at == 0`` semantics."""
    config = replace(session_test_config(), settlement_window=3_600)
    server = new_session_test_server(config)
    signer, channel_id = await _open_test_channel(server, 1_000_000)

    voucher = signer.sign_voucher(channel_id, 100, 0)
    assert await server.verify_voucher(VoucherPayload(voucher=voucher)) == 100


async def test_verify_voucher_unknown_channel_rejected() -> None:
    """Mirrors TestVerifyVoucherUnknownChannelRejected."""
    server = new_session_test_server(session_test_config())
    signer = _TestVoucherSigner(seed=3)
    voucher = signer.sign_voucher("11111111111111111111111111111111", 100, _far_future())
    with pytest.raises(ValueError, match="not found"):
        await server.verify_voucher(VoucherPayload(voucher=voucher))


async def test_verify_voucher_non_monotonic_rejected() -> None:
    """Mirrors TestVerifyVoucherNonMonotonicRejected."""
    server = new_session_test_server(session_test_config())
    signer, channel_id = await _open_test_channel(server, 1_000_000)

    await _submit_voucher(server, signer, channel_id, 200)
    with pytest.raises(ValueError, match="must exceed watermark"):
        await _submit_voucher(server, signer, channel_id, 150)
    # Equal cumulative with a different signature (different expiry) is not a
    # replay and must also be rejected as non-monotonic.
    different = signer.sign_voucher(channel_id, 200, _far_future() + 60)
    with pytest.raises(ValueError, match="must exceed watermark"):
        await server.verify_voucher(VoucherPayload(voucher=different))


async def test_verify_voucher_idempotent_replay_returns_same_cumulative() -> None:
    """Mirrors TestVerifyVoucherIdempotentReplayReturnsSameCumulative."""
    server = new_session_test_server(session_test_config())
    signer, channel_id = await _open_test_channel(server, 1_000_000)

    voucher = signer.sign_voucher(channel_id, 150, _far_future())
    await server.verify_voucher(VoucherPayload(voucher=voucher))
    assert await server.verify_voucher(VoucherPayload(voucher=voucher)) == 150


async def test_verify_voucher_respects_min_voucher_delta() -> None:
    """Mirrors TestVerifyVoucherRespectsMinVoucherDelta."""
    config = session_test_config()
    config.min_voucher_delta = 100
    server = new_session_test_server(config)
    signer, channel_id = await _open_test_channel(server, 1_000_000)

    with pytest.raises(ValueError):
        await _submit_voucher(server, signer, channel_id, 50)
    assert await _submit_voucher(server, signer, channel_id, 100) == 100


async def test_verify_voucher_accepts_legacy_cumulative_alias() -> None:
    """Mirrors TestVerifyVoucherAcceptsLegacyCumulativeAlias."""
    server = new_session_test_server(session_test_config())
    signer, channel_id = await _open_test_channel(server, 1_000_000)

    signed = signer.sign_voucher(channel_id, 400, _far_future())
    # Re-encode the voucher payload with the legacy "cumulative" wire alias.
    wire = {
        "voucher": {
            "data": {"channelId": channel_id, "cumulative": "400", "expiresAt": signed.data.expires_at},
            "signature": signed.signature,
        }
    }
    payload = VoucherPayload.from_dict(wire)
    assert await server.verify_voucher(payload) == 400


# -- process_top_up --


async def test_process_top_up_raises_deposit() -> None:
    """Mirrors TestProcessTopUpRaisesDeposit."""
    server = new_session_test_server(session_test_config())
    _, channel_id = await _open_test_channel(server, 1_000_000)

    state = await server.process_top_up(
        TopUpPayload(channel_id=channel_id, new_deposit="2000000", signature="topup_sig")
    )
    assert state.deposit == 2_000_000


async def test_process_top_up_rejects_non_increasing_deposit() -> None:
    """Mirrors TestProcessTopUpRejectsNonIncreasingDeposit."""
    server = new_session_test_server(session_test_config())
    _, channel_id = await _open_test_channel(server, 1_000_000)

    with pytest.raises(ValueError, match="must exceed current deposit"):
        await server.process_top_up(TopUpPayload(channel_id=channel_id, new_deposit="1000000", signature="sig"))


async def test_process_top_up_rejects_over_max_cap() -> None:
    """Mirrors TestProcessTopUpRejectsOverMaxCap."""
    server = new_session_test_server(session_test_config())
    _, channel_id = await _open_test_channel(server, 1_000_000)

    with pytest.raises(ValueError, match="exceeds max cap"):
        await server.process_top_up(TopUpPayload(channel_id=channel_id, new_deposit="20000000", signature="sig"))


async def test_process_top_up_rejects_when_finalized_or_close_pending() -> None:
    """Mirrors TestProcessTopUpRejectsWhenFinalizedOrClosePending."""
    server = new_session_test_server(session_test_config())
    _, channel_id = await _open_test_channel(server, 1_000_000)
    await server.process_close(ClosePayload(channel_id=channel_id))
    with pytest.raises(ValueError, match="close is pending"):
        await server.process_top_up(TopUpPayload(channel_id=channel_id, new_deposit="2000000", signature="sig"))

    server2 = new_session_test_server(session_test_config())
    _, channel_id2 = await _open_test_channel(server2, 1_000_000)
    await server2.mark_finalized(channel_id2)
    with pytest.raises(ValueError, match="finalized"):
        await server2.process_top_up(TopUpPayload(channel_id=channel_id2, new_deposit="2000000", signature="sig"))


async def test_process_top_up_invokes_verify_top_up_tx_seam() -> None:
    """Mirrors TestProcessTopUpInvokesVerifyTopUpTxSeam."""

    async def verifier(payload: TopUpPayload) -> None:
        assert payload.signature == "topup_sig"
        raise ValueError("topup tx unknown")

    config = session_test_config()
    config.verify_top_up_tx = verifier
    server = new_session_test_server(config)
    _, channel_id = await _open_test_channel(server, 1_000_000)

    with pytest.raises(ValueError, match="topup tx unknown"):
        await server.process_top_up(TopUpPayload(channel_id=channel_id, new_deposit="2000000", signature="topup_sig"))
    state = await server.store().get_channel(channel_id)
    assert state is not None
    assert state.deposit == 1_000_000


async def test_voucher_accepted_after_top_up_raises_deposit() -> None:
    """Mirrors TestVoucherAcceptedAfterTopUpRaisesDeposit."""
    server = new_session_test_server(session_test_config())
    signer, channel_id = await _open_test_channel(server, 1_000)

    with pytest.raises(ValueError):
        await _submit_voucher(server, signer, channel_id, 2_000)
    await server.process_top_up(TopUpPayload(channel_id=channel_id, new_deposit="5000", signature="sig"))
    assert await _submit_voucher(server, signer, channel_id, 2_000) == 2_000


# -- begin_delivery --


async def test_begin_delivery_assigns_sequence_and_default_delivery_id() -> None:
    """Mirrors TestBeginDeliveryAssignsSequenceAndDefaultDeliveryID."""
    server = new_session_test_server(session_test_config())
    _, channel_id = await _open_test_channel(server, 1_000_000)

    first = await server.begin_delivery(DeliveryRequest(session_id=channel_id, amount=100))
    assert first.delivery_id == f"{channel_id}:1"
    assert first.sequence == 1
    assert first.amount == "100"
    assert first.currency == "USDC"
    assert first.session_id == channel_id
    assert first.expires_at == DEFAULT_SESSION_EXPIRES_AT

    second = await server.begin_delivery(DeliveryRequest(session_id=channel_id, amount=50))
    assert second.delivery_id == f"{channel_id}:2"
    assert second.sequence == 2


async def test_begin_delivery_honors_explicit_fields() -> None:
    """Mirrors TestBeginDeliveryHonorsExplicitFields."""
    server = new_session_test_server(session_test_config())
    _, channel_id = await _open_test_channel(server, 1_000_000)

    expires_at = int(time.time()) + 60
    directive = await server.begin_delivery(
        DeliveryRequest(
            session_id=channel_id,
            amount=100,
            delivery_id="custom-id",
            commit_url="https://example.test/commit",
            proof="proof-blob",
            expires_at=expires_at,
        )
    )
    assert directive.delivery_id == "custom-id"
    assert directive.expires_at == expires_at
    assert directive.commit_url == "https://example.test/commit"
    assert directive.proof == "proof-blob"


async def test_begin_delivery_rejects_zero_amount_and_unknown_channel() -> None:
    """Mirrors TestBeginDeliveryRejectsZeroAmountAndUnknownChannel."""
    server = new_session_test_server(session_test_config())
    with pytest.raises(ValueError):
        await server.begin_delivery(DeliveryRequest(session_id="ghost", amount=0))
    with pytest.raises(ValueError):
        await server.begin_delivery(DeliveryRequest(session_id="ghost", amount=5))


async def test_begin_delivery_rejects_duplicate_delivery_id() -> None:
    """Mirrors TestBeginDeliveryRejectsDuplicateDeliveryID."""
    server = new_session_test_server(session_test_config())
    _, channel_id = await _open_test_channel(server, 1_000_000)

    await server.begin_delivery(DeliveryRequest(session_id=channel_id, amount=10, delivery_id="dup"))
    with pytest.raises(ValueError, match="already exists"):
        await server.begin_delivery(DeliveryRequest(session_id=channel_id, amount=10, delivery_id="dup"))


async def test_begin_delivery_reservation_math() -> None:
    """Mirrors TestBeginDeliveryReservationMath."""
    server = new_session_test_server(session_test_config())
    signer, channel_id = await _open_test_channel(server, 1_000)

    # Advance the watermark to 400 so the reservation has to account for it.
    await _submit_voucher(server, signer, channel_id, 400)
    # Reserve 500: cumulative 400 + pending 500 = 900 <= 1000.
    await server.begin_delivery(DeliveryRequest(session_id=channel_id, amount=500))
    # Reserve 100 more: 400 + 500 + 100 = 1000 <= 1000 (boundary holds).
    await server.begin_delivery(DeliveryRequest(session_id=channel_id, amount=100))
    # One more unit must fail: 400 + 600 + 1 > 1000.
    with pytest.raises(ValueError, match="exceeds available deposit"):
        await server.begin_delivery(DeliveryRequest(session_id=channel_id, amount=1))


async def test_begin_delivery_rejected_when_close_pending() -> None:
    """Mirrors TestBeginDeliveryRejectedWhenClosePending."""
    server = new_session_test_server(session_test_config())
    _, channel_id = await _open_test_channel(server, 1_000_000)
    await server.process_close(ClosePayload(channel_id=channel_id))
    with pytest.raises(ValueError, match="close is pending"):
        await server.begin_delivery(DeliveryRequest(session_id=channel_id, amount=5))


# -- process_commit --


async def test_process_commit_commits_reserved_delivery() -> None:
    """Mirrors TestProcessCommitCommitsReservedDelivery."""
    server = new_session_test_server(session_test_config())
    signer, channel_id = await _open_test_channel(server, 1_000_000)

    directive = await server.begin_delivery(DeliveryRequest(session_id=channel_id, amount=100))
    voucher = signer.sign_voucher(channel_id, 100, _far_future())
    receipt = await server.process_commit(CommitPayload(delivery_id=directive.delivery_id, voucher=voucher))
    assert receipt.status == "committed"
    assert receipt.amount == "100"
    assert receipt.cumulative == "100"

    state = await server.store().get_channel(channel_id)
    assert state is not None
    assert state.cumulative == 100
    assert len(state.pending_deliveries) == 0
    assert len(state.committed_deliveries) == 1


async def test_process_commit_replay_returns_cached_receipt() -> None:
    """Mirrors TestProcessCommitReplayReturnsCachedReceipt."""
    server = new_session_test_server(session_test_config())
    signer, channel_id = await _open_test_channel(server, 1_000_000)

    directive = await server.begin_delivery(DeliveryRequest(session_id=channel_id, amount=100))
    voucher = signer.sign_voucher(channel_id, 100, _far_future())
    payload = CommitPayload(delivery_id=directive.delivery_id, voucher=voucher)

    await server.process_commit(payload)
    replay = await server.process_commit(payload)
    assert replay.status == "replayed"
    assert replay.amount == "100"
    assert replay.cumulative == "100"


async def test_process_commit_replay_with_different_voucher_rejected() -> None:
    """Mirrors TestProcessCommitReplayWithDifferentVoucherRejected."""
    server = new_session_test_server(session_test_config())
    signer, channel_id = await _open_test_channel(server, 1_000_000)

    directive = await server.begin_delivery(DeliveryRequest(session_id=channel_id, amount=200))
    first = signer.sign_voucher(channel_id, 100, _far_future())
    await server.process_commit(CommitPayload(delivery_id=directive.delivery_id, voucher=first))

    different = signer.sign_voucher(channel_id, 150, _far_future())
    with pytest.raises(ValueError, match="already committed with different voucher"):
        await server.process_commit(CommitPayload(delivery_id=directive.delivery_id, voucher=different))


async def test_process_commit_replay_re_verifies_signature() -> None:
    """Mirrors TestProcessCommitReplayReVerifiesSignature."""
    server = new_session_test_server(session_test_config())
    signer, channel_id = await _open_test_channel(server, 1_000_000)

    directive = await server.begin_delivery(DeliveryRequest(session_id=channel_id, amount=100))
    voucher = signer.sign_voucher(channel_id, 100, _far_future())
    await server.process_commit(CommitPayload(delivery_id=directive.delivery_id, voucher=voucher))

    # Same signature and cumulative, but tampered expiry: the replayed voucher
    # no longer verifies and must be rejected.
    tampered = SignedVoucher(
        data=VoucherData(channel_id=channel_id, cumulative="100", expires_at=voucher.data.expires_at + 1),
        signature=voucher.signature,
    )
    with pytest.raises(ValueError):
        await server.process_commit(CommitPayload(delivery_id=directive.delivery_id, voucher=tampered))


async def test_process_commit_unknown_delivery_rejected() -> None:
    """Mirrors TestProcessCommitUnknownDeliveryRejected."""
    server = new_session_test_server(session_test_config())
    signer, channel_id = await _open_test_channel(server, 1_000_000)

    voucher = signer.sign_voucher(channel_id, 100, _far_future())
    with pytest.raises(ValueError, match="not found"):
        await server.process_commit(CommitPayload(delivery_id="ghost", voucher=voucher))


async def test_process_commit_expired_directive_rejected() -> None:
    """Mirrors TestProcessCommitExpiredDirectiveRejected."""
    server = new_session_test_server(session_test_config())
    signer, channel_id = await _open_test_channel(server, 1_000_000)

    directive = await server.begin_delivery(
        DeliveryRequest(session_id=channel_id, amount=100, expires_at=int(time.time()) - 10)
    )
    voucher = signer.sign_voucher(channel_id, 100, _far_future())
    with pytest.raises(ValueError, match="has expired"):
        await server.process_commit(CommitPayload(delivery_id=directive.delivery_id, voucher=voucher))


async def test_process_commit_over_reserved_amount_rejected() -> None:
    """Mirrors TestProcessCommitOverReservedAmountRejected."""
    server = new_session_test_server(session_test_config())
    signer, channel_id = await _open_test_channel(server, 1_000_000)

    directive = await server.begin_delivery(DeliveryRequest(session_id=channel_id, amount=100))
    # The voucher claims 150 against a 100 reservation.
    voucher = signer.sign_voucher(channel_id, 150, _far_future())
    with pytest.raises(ValueError, match="exceeds reserved amount"):
        await server.process_commit(CommitPayload(delivery_id=directive.delivery_id, voucher=voucher))


# -- process_close --


async def test_process_close_flips_close_pending_and_blocks_further_activity() -> None:
    """Mirrors TestProcessCloseFlipsClosePendingAndBlocksFurtherActivity."""
    server = new_session_test_server(session_test_config())
    signer, channel_id = await _open_test_channel(server, 1_000_000)

    state = await server.process_close(ClosePayload(channel_id=channel_id))
    assert state.close_requested_at is not None

    with pytest.raises(ValueError):
        await _submit_voucher(server, signer, channel_id, 100)
    with pytest.raises(ValueError):
        await server.begin_delivery(DeliveryRequest(session_id=channel_id, amount=1))


async def test_process_close_double_close_rejected() -> None:
    """Mirrors TestProcessCloseDoubleCloseRejected."""
    server = new_session_test_server(session_test_config())
    _, channel_id = await _open_test_channel(server, 1_000_000)

    await server.process_close(ClosePayload(channel_id=channel_id))
    with pytest.raises(ValueError, match="close already requested"):
        await server.process_close(ClosePayload(channel_id=channel_id))


async def test_process_close_final_voucher_advances_watermark() -> None:
    """Mirrors TestProcessCloseFinalVoucherAdvancesWatermark."""
    server = new_session_test_server(session_test_config())
    signer, channel_id = await _open_test_channel(server, 1_000_000)

    await _submit_voucher(server, signer, channel_id, 100)
    final = signer.sign_voucher(channel_id, 500, _far_future())
    state = await server.process_close(ClosePayload(channel_id=channel_id, voucher=final))
    assert state.cumulative == 500
    assert state.highest_voucher_signature == final.signature


async def test_process_close_non_monotonic_final_voucher_is_hard_error() -> None:
    """Mirrors TestProcessCloseNonMonotonicFinalVoucherIsHardError."""
    server = new_session_test_server(session_test_config())
    signer, channel_id = await _open_test_channel(server, 1_000_000)

    await _submit_voucher(server, signer, channel_id, 300)
    stale = signer.sign_voucher(channel_id, 200, _far_future())
    with pytest.raises(ValueError, match="must exceed watermark"):
        await server.process_close(ClosePayload(channel_id=channel_id, voucher=stale))

    # The failed close must not flip close-pending.
    state = await server.store().get_channel(channel_id)
    assert state is not None
    assert state.close_requested_at is None
    assert state.cumulative == 300


async def test_process_close_accepts_replay_of_current_highest_voucher() -> None:
    """Mirrors TestProcessCloseAcceptsReplayOfCurrentHighestVoucher."""
    server = new_session_test_server(session_test_config())
    signer, channel_id = await _open_test_channel(server, 1_000_000)

    highest = signer.sign_voucher(channel_id, 300, _far_future())
    await server.verify_voucher(VoucherPayload(voucher=highest))
    state = await server.process_close(ClosePayload(channel_id=channel_id, voucher=highest))
    assert state.close_requested_at is not None
    assert state.cumulative == 300


async def test_process_close_final_voucher_exceeding_deposit_rejected() -> None:
    """Mirrors TestProcessCloseFinalVoucherExceedingDepositRejected."""
    server = new_session_test_server(session_test_config())
    signer, channel_id = await _open_test_channel(server, 1_000)

    final = signer.sign_voucher(channel_id, 2_000, _far_future())
    with pytest.raises(ValueError, match="exceeds deposit"):
        await server.process_close(ClosePayload(channel_id=channel_id, voucher=final))


async def test_process_close_unknown_channel_rejected() -> None:
    """Mirrors TestProcessCloseUnknownChannelRejected."""
    server = new_session_test_server(session_test_config())
    with pytest.raises(ValueError, match="not found"):
        await server.process_close(ClosePayload(channel_id="ghost"))
