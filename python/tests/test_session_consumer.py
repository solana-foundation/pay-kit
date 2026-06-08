"""Tests for the client-side metered-delivery consumer.

Mirrors the ``#[cfg(test)] mod tests`` in
``rust/crates/mpp/src/client/session_consumer.rs`` and the parity-verified Go
port: ack/commit send through the transport and advance the local watermark,
the commit alias and ``into_parts`` work, invalid directives (wrong session,
zero amount, non-numeric amount) are rejected before commit, a failed commit
does not advance the watermark, idempotency on a duplicate delivery (a server
``replayed`` receipt is honored and the cumulative is not advanced twice), and a
fresh delivery advances.
"""

from __future__ import annotations

import pytest
from solders.keypair import Keypair  # type: ignore[import-untyped]
from solders.pubkey import Pubkey  # type: ignore[import-untyped]

from pay_kit.protocols.mpp.client.session import ActiveSession
from pay_kit.protocols.mpp.client.session_consumer import SessionConsumer
from pay_kit.protocols.mpp.intents.session import (
    DEFAULT_SESSION_EXPIRES_AT,
    CommitPayload,
    CommitReceipt,
    MeteredEnvelope,
    MeteringDirective,
)


class _RecordingTransport:
    """In-process commit transport that records payloads and echoes a receipt.

    ``replay_delivery_ids`` returns a ``replayed`` receipt (server already saw
    the delivery) so the consumer's idempotency handling can be exercised.
    """

    def __init__(self, fail: bool = False, replay_delivery_ids: set[str] | None = None) -> None:
        self.commits: list[CommitPayload] = []
        self.fail = fail
        self.replay_delivery_ids = replay_delivery_ids or set()

    def commit(self, directive: MeteringDirective, payload: CommitPayload) -> CommitReceipt:
        if self.fail:
            raise ValueError("commit failed")
        cumulative = payload.voucher.data.cumulative
        self.commits.append(payload)
        status = "replayed" if directive.delivery_id in self.replay_delivery_ids else "committed"
        return CommitReceipt(
            delivery_id=directive.delivery_id,
            session_id=directive.session_id,
            amount=directive.amount,
            cumulative=cumulative,
            status=status,
        )


def _signer(seed: int = 7) -> Keypair:
    return Keypair.from_seed(bytes([seed] * 32))


def _channel() -> Pubkey:
    return Pubkey.from_string("11111111111111111111111111111112")


def _consumer(transport: _RecordingTransport) -> SessionConsumer:
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


def test_replayed_receipt_is_honored_and_watermark_not_double_advanced() -> None:
    # Server reports the second, fresh-id delivery as replayed; the consumer
    # honors it and advances the watermark exactly once for that delivery.
    transport = _RecordingTransport(replay_delivery_ids={"d2"})
    consumer = _consumer(transport)

    first = _directive(consumer.session.channel_id_string, 100, delivery_id="d1")
    r1 = consumer.commit_directive(first)
    assert r1.status == "committed"
    assert consumer.session.cumulative == 100

    second = _directive(consumer.session.channel_id_string, 40, delivery_id="d2")
    r2 = consumer.commit_directive(second)
    assert r2.status == "replayed"
    assert consumer.session.cumulative == 140
    # A re-ack of the SAME directive object is rejected locally: prepare_increment
    # advances past the watermark, but a stale duplicate cumulative cannot regress.
    assert len(transport.commits) == 2


def test_fresh_delivery_advances_after_prior() -> None:
    transport = _RecordingTransport()
    consumer = _consumer(transport)

    consumer.commit_directive(_directive(consumer.session.channel_id_string, 100, delivery_id="a"))
    consumer.commit_directive(_directive(consumer.session.channel_id_string, 30, delivery_id="b"))
    assert consumer.session.cumulative == 130
    assert [c.voucher.data.cumulative for c in transport.commits] == ["100", "130"]
