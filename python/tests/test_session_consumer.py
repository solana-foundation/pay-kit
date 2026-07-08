"""Tests for the client-side metered-delivery consumer.

Mirrors the ``#[cfg(test)] mod tests`` in
``rust/crates/mpp/src/client/session_consumer.rs`` and the parity-verified Go
port: ack/commit send through the transport and advance the local watermark,
the commit alias and ``into_parts`` work, invalid directives (wrong session,
zero amount, non-numeric amount) are rejected before commit, a failed commit
does not advance the watermark, a ``replayed`` receipt still records the
prepared voucher (rust/TS parity), and a fresh delivery advances.
"""

from __future__ import annotations

import pytest
from solders.keypair import Keypair  # type: ignore[import-untyped]
from solders.pubkey import Pubkey  # type: ignore[import-untyped]

from solana_pay_kit.protocols.mpp.client.session import ActiveSession
from solana_pay_kit.protocols.mpp.client.session_consumer import CommitTransport, SessionConsumer
from solana_pay_kit.protocols.mpp.intents.session import (
    DEFAULT_SESSION_EXPIRES_AT,
    CommitPayload,
    CommitReceipt,
    MeteredEnvelope,
    MeteringDirective,
)


class _RecordingTransport:
    """In-process commit transport that records payloads and echoes a receipt.

    Models server-side dedupe by deliveryId: re-committing a deliveryId already
    seen returns a ``replayed`` receipt pinned to the cumulative first settled
    for it, so the consumer's idempotency handling can be exercised.
    """

    def __init__(self, fail: bool = False) -> None:
        self.commits: list[CommitPayload] = []
        self.fail = fail
        # The cumulative first settled per deliveryId.
        self._settled: dict[str, str] = {}

    def commit(self, directive: MeteringDirective, payload: CommitPayload) -> CommitReceipt:
        if self.fail:
            raise ValueError("commit failed")
        prior = self._settled.get(directive.delivery_id)
        if prior is not None:
            return CommitReceipt(
                delivery_id=directive.delivery_id,
                session_id=directive.session_id,
                amount=directive.amount,
                cumulative=prior,
                status="replayed",
            )
        cumulative = payload.voucher.data.cumulative
        self._settled[directive.delivery_id] = cumulative
        self.commits.append(payload)
        return CommitReceipt(
            delivery_id=directive.delivery_id,
            session_id=directive.session_id,
            amount=directive.amount,
            cumulative=cumulative,
            status="committed",
        )


def _signer(seed: int = 7) -> Keypair:
    return Keypair.from_seed(bytes([seed] * 32))


def _channel() -> Pubkey:
    return Pubkey.from_string("11111111111111111111111111111112")


def _consumer(transport: CommitTransport) -> SessionConsumer:
    return SessionConsumer(ActiveSession(_channel(), _signer()), transport)


def _directive(session_id: str, amount: int, delivery_id: str = "d1") -> MeteringDirective:
    return MeteringDirective(
        delivery_id=delivery_id,
        session_id=session_id,
        amount=str(amount),
        currency="USDC",
        sequence=1,
        expires_at=DEFAULT_SESSION_EXPIRES_AT,
    )


def test_ack_sends_commit_and_advances_local_watermark() -> None:
    transport = _RecordingTransport()
    consumer = _consumer(transport)
    envelope = MeteredEnvelope(payload="work", metering=_directive(consumer.session.channel_id_string, 250))

    delivery = consumer.accept(envelope)
    assert delivery.payload == "work"
    receipt = delivery.ack()

    assert receipt.cumulative == "250"
    assert receipt.status == "committed"
    assert consumer.session.cumulative == 250
    assert len(transport.commits) == 1


def test_commit_alias_and_into_parts() -> None:
    transport = _RecordingTransport()
    consumer = _consumer(transport)
    consumer.session.set_expires_at(1234)
    envelope = MeteredEnvelope(payload="payload", metering=_directive(consumer.session.channel_id_string, 50))

    delivery = consumer.accept(envelope)
    assert delivery.metering.amount == "50"
    receipt = delivery.commit()
    assert receipt.cumulative == "50"
    assert transport.commits[0].voucher.data.expires_at == 1234

    second = MeteredEnvelope(
        payload="second",
        metering=_directive(consumer.session.channel_id_string, 75, delivery_id="d2"),
    )
    delivery2 = consumer.accept(second)
    payload, metering = delivery2.into_parts()
    assert payload == "second"
    assert metering.amount == "75"


def test_commit_directive_directly() -> None:
    transport = _RecordingTransport()
    consumer = _consumer(transport)
    directive = _directive(consumer.session.channel_id_string, 25)

    receipt = consumer.commit_directive(directive)
    assert receipt.cumulative == "25"
    assert len(transport.commits) == 1
    assert consumer.transport is transport


def test_wrong_session_rejected_before_commit() -> None:
    transport = _RecordingTransport()
    consumer = _consumer(transport)

    wrong = MeteredEnvelope(payload=None, metering=_directive("other-session", 1))
    with pytest.raises(ValueError, match="does not match active session"):
        consumer.accept(wrong)
    assert len(transport.commits) == 0


def test_zero_amount_rejected_before_commit() -> None:
    transport = _RecordingTransport()
    consumer = _consumer(transport)
    zero = _directive(consumer.session.channel_id_string, 0)
    with pytest.raises(ValueError, match="greater than zero"):
        consumer.commit_directive(zero)
    assert len(transport.commits) == 0


def test_invalid_amount_rejected_before_commit() -> None:
    transport = _RecordingTransport()
    consumer = _consumer(transport)
    invalid = _directive(consumer.session.channel_id_string, 1)
    invalid.amount = "bad"
    with pytest.raises(ValueError, match="invalid metering amount"):
        consumer.commit_directive(invalid)
    assert len(transport.commits) == 0
    assert consumer.session.cumulative == 0


def test_failed_commit_does_not_advance_local_watermark() -> None:
    transport = _RecordingTransport(fail=True)
    consumer = _consumer(transport)
    directive = _directive(consumer.session.channel_id_string, 250)

    with pytest.raises(ValueError, match="commit failed"):
        consumer.commit_directive(directive)
    assert consumer.session.cumulative == 0
    # Retry after the transport recovers reuses the same cumulative cleanly.
    transport.fail = False
    receipt = consumer.commit_directive(directive)
    assert receipt.cumulative == "250"
    assert consumer.session.cumulative == 250


class _ReplayTransport:
    """Transport that reports every commit as already settled at a fixed
    cumulative, regardless of the voucher it is sent."""

    def __init__(self, settled: str) -> None:
        self.settled = settled

    def commit(self, directive: MeteringDirective, payload: CommitPayload) -> CommitReceipt:
        del payload  # always reports the fixed settled cumulative, ignores the voucher
        return CommitReceipt(
            delivery_id=directive.delivery_id,
            session_id=directive.session_id,
            amount=directive.amount,
            cumulative=self.settled,
            status="replayed",
        )


def test_duplicate_delivery_replay_does_not_double_count() -> None:
    # Re-committing the same deliveryId returns a replayed receipt pinned to the
    # originally settled cumulative (100). The consumer reconciles to that settled
    # value (clamped to the prepared voucher) instead of recording the freshly
    # prepared higher voucher, so a duplicate send does not double-count. Mirrors
    # Go SessionConsumer.commit_directive (settled.min(prepared), never regress).
    transport = _RecordingTransport()
    consumer = _consumer(transport)
    d = _directive(consumer.session.channel_id_string, 100, delivery_id="d1")

    r1 = consumer.commit_directive(d)
    assert r1.status == "committed"
    assert consumer.session.cumulative == 100

    r2 = consumer.commit_directive(d)
    assert r2.status == "replayed"
    assert r2.cumulative == "100"
    assert consumer.session.cumulative == 100  # no double-count
    assert len(transport.commits) == 1


def test_replayed_receipt_reconciles_to_clamped_settled() -> None:
    # Lost-response case: the server reports the delivery already settled at 100.
    # The client reconciles its watermark to the settled value, clamped to the
    # voucher it just prepared (250) since the server is untrusted: min(100, 250)
    # = 100. Mirrors Go reconcile_settled (the #162 fix).
    consumer = _consumer(_ReplayTransport(settled="100"))
    receipt = consumer.commit_directive(_directive(consumer.session.channel_id_string, 250))
    assert receipt.status == "replayed"
    assert consumer.session.cumulative == 100


def test_replayed_receipt_never_regresses_watermark() -> None:
    # Client is already ahead at 300 (later deliveries settled). A stale replayed
    # receipt at 100 must not regress the watermark.
    consumer = _consumer(_ReplayTransport(settled="100"))
    consumer.session.reconcile_settled(300)
    consumer.commit_directive(_directive(consumer.session.channel_id_string, 50))
    assert consumer.session.cumulative == 300


def test_replayed_receipt_clamps_inflated_server_cumulative() -> None:
    # A malicious/buggy server reports a replay settled far above the prepared
    # voucher; the watermark clamps to the prepared value (250), never the
    # inflated one, so the next voucher cannot over-authorize.
    consumer = _consumer(_ReplayTransport(settled="1000000"))
    consumer.commit_directive(_directive(consumer.session.channel_id_string, 250))
    assert consumer.session.cumulative == 250


def test_fresh_delivery_advances_after_prior() -> None:
    transport = _RecordingTransport()
    consumer = _consumer(transport)

    consumer.commit_directive(_directive(consumer.session.channel_id_string, 100, delivery_id="a"))
    consumer.commit_directive(_directive(consumer.session.channel_id_string, 30, delivery_id="b"))
    assert consumer.session.cumulative == 130
    assert [c.voucher.data.cumulative for c in transport.commits] == ["100", "130"]
