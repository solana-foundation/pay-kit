"""Kafka-style client helpers for metered session deliveries.

:class:`SessionConsumer` wraps an :class:`~pay_kit.protocols.mpp.client.session.ActiveSession`
so applications can process delivered messages and call ``ack``/``commit``
instead of manually signing and posting vouchers. A failed commit never
advances the local watermark, so the same directive can be retried safely.

Behavior mirrors the Rust spine in
``rust/crates/mpp/src/client/session_consumer.rs`` and the parity-verified Go
port in ``go/protocols/mpp/client/session_consumer.go``.
"""

from __future__ import annotations

from typing import Any, Generic, Protocol, TypeVar, runtime_checkable

from pay_kit.protocols.mpp.client.session import ActiveSession
from pay_kit.protocols.mpp.intents.session import (
    CommitPayload,
    CommitReceipt,
    MeteredEnvelope,
    MeteringDirective,
)

__all__ = [
    "CommitTransport",
    "SessionConsumer",
    "MeteredDelivery",
]

P = TypeVar("P")


@runtime_checkable
class CommitTransport(Protocol):
    """Transport used by :class:`SessionConsumer` to send commit payloads.

    HTTP clients, queues, and in-process tests can all implement this. The
    directive is passed alongside the payload so transports can use
    ``commit_url``, ``proof``, or other routing hints without those fields being
    repeated in the signed commit body.

    The ``commit`` signature mirrors the Rust ``CommitTransport`` trait exactly:
    it takes the directive and the :class:`CommitPayload` and returns a
    :class:`CommitReceipt`.
    """

    def commit(self, directive: MeteringDirective, payload: CommitPayload) -> CommitReceipt:
        """Send ``payload`` for ``directive`` and return the server receipt."""
        ...


class SessionConsumer:
    """Client-side consumer for session-metered deliveries.

    Not safe for concurrent use; the underlying :class:`ActiveSession` watermark
    is advanced inside :meth:`commit_directive`. Mirrors rust ``SessionConsumer``.
    """

    def __init__(self, session: ActiveSession, transport: CommitTransport) -> None:
        """Wrap a session and a commit transport. Mirrors rust ``SessionConsumer::new``."""
        self._session = session
        self._transport = transport

    @property
    def session(self) -> ActiveSession:
        """The wrapped session. Mirrors rust ``SessionConsumer::session``."""
        return self._session

    @property
    def transport(self) -> CommitTransport:
        """The wrapped commit transport."""
        return self._transport

    def accept(self, envelope: MeteredEnvelope) -> MeteredDelivery[Any]:
        """Validate an envelope and return a delivery handle with ``ack``/``commit``.

        The directive is validated up front so a mismatched session is rejected
        before the application processes the payload. Mirrors rust
        ``SessionConsumer::accept``.
        """
        self._validate_directive(envelope.metering)
        return MeteredDelivery(consumer=self, payload=envelope.payload, metering=envelope.metering)

    def commit_directive(self, directive: MeteringDirective) -> CommitReceipt:
        """Sign a voucher for the directive amount, send it, and advance the
        local watermark only on success.

        Rejects directives whose session does not match, whose amount is not a
        valid base-unit integer, or whose amount is zero. The prepare/record
        split makes a failed commit safe to retry without double-counting: the
        voucher is prepared (no watermark advance), sent, and only recorded once
        the transport returns a receipt. A server ``replayed`` receipt is
        honored unconditionally — the recorded voucher cumulative is strictly
        greater than the prior watermark so the watermark advances exactly once.
        Mirrors rust ``SessionConsumer::commit_directive``.
        """
        self._validate_directive(directive)
        amount = directive.amount_base_units()
        if amount == 0:
            raise ValueError("metered delivery amount must be greater than zero")

        voucher = self._session.prepare_increment(amount)
        payload = CommitPayload(delivery_id=directive.delivery_id, voucher=voucher)

        receipt = self._transport.commit(directive, payload)
        self._session.record_voucher(payload.voucher)
        return receipt

    def _validate_directive(self, directive: MeteringDirective) -> None:
        channel_id = self._session.channel_id_string
        if directive.session_id != channel_id:
            raise ValueError(
                f"metered delivery session {directive.session_id} does not match active session {channel_id}"
            )


class MeteredDelivery(Generic[P]):
    """A delivered payload paired with its metering directive.

    Call :meth:`ack` (or its :meth:`commit` alias) after the application has
    processed :attr:`payload`. Mirrors rust ``MeteredDelivery``.
    """

    def __init__(self, consumer: SessionConsumer, payload: P, metering: MeteringDirective) -> None:
        self._consumer = consumer
        self._payload = payload
        self._metering = metering

    @property
    def payload(self) -> P:
        """The delivered payload."""
        return self._payload

    @property
    def metering(self) -> MeteringDirective:
        """The metering directive that accompanied the payload."""
        return self._metering

    def ack(self) -> CommitReceipt:
        """Sign and commit a voucher for the directive amount.

        Mirrors rust ``MeteredDelivery::ack``.
        """
        return self._consumer.commit_directive(self._metering)

    def commit(self) -> CommitReceipt:
        """Alias for :meth:`ack`. Mirrors rust ``MeteredDelivery::commit``."""
        return self.ack()

    def into_parts(self) -> tuple[P, MeteringDirective]:
        """Return the payload and metering directive without committing.

        Mirrors rust ``MeteredDelivery::into_parts``.
        """
        return self._payload, self._metering
