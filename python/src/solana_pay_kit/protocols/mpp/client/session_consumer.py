"""Kafka-style client helpers for metered session deliveries.

:class:`SessionConsumer` wraps an :class:`~solana_pay_kit.protocols.mpp.client.session.ActiveSession`
so applications can process delivered messages and call ``ack``/``commit``
instead of manually signing and posting vouchers. A failed commit never
advances the local watermark, so the same directive can be retried safely.
"""

from __future__ import annotations

from typing import Any, Generic, Protocol, TypeVar, runtime_checkable

from solana_pay_kit.protocols.mpp.client.session import ActiveSession
from solana_pay_kit.protocols.mpp.intents.session import (
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

    The ``commit`` method takes the directive and the :class:`CommitPayload` and
    returns a :class:`CommitReceipt`.
    """

    def commit(self, directive: MeteringDirective, payload: CommitPayload) -> CommitReceipt:
        """Send ``payload`` for ``directive`` and return the server receipt."""
        ...


class SessionConsumer:
    """Client-side consumer for session-metered deliveries.

    Not safe for concurrent use; the underlying :class:`ActiveSession` watermark
    is advanced inside :meth:`commit_directive`.
    """

    def __init__(self, session: ActiveSession, transport: CommitTransport) -> None:
        """Wrap a session and a commit transport."""
        self._session = session
        self._transport = transport

    @property
    def session(self) -> ActiveSession:
        """The wrapped session."""
        return self._session

    @property
    def transport(self) -> CommitTransport:
        """The wrapped commit transport."""
        return self._transport

    def accept(self, envelope: MeteredEnvelope) -> MeteredDelivery[Any]:
        """Validate an envelope and return a delivery handle with ``ack``/``commit``.

        The directive is validated up front so a mismatched session is rejected
        before the application processes the payload.
        """
        self._validate_directive(envelope.metering)
        return MeteredDelivery(consumer=self, payload=envelope.payload, metering=envelope.metering)

    def commit_directive(self, directive: MeteringDirective) -> CommitReceipt:
        """Sign a voucher for the directive amount, send it, and advance the
        local watermark only on success.

        Rejects directives whose session does not match, whose amount is not a
        valid base-unit integer, or whose amount is zero. The prepare/record
        split makes a failed commit safe to retry without double-counting: the
        voucher is prepared (no watermark advance), sent, and recorded once the
        transport returns a receipt. The prepared voucher is recorded for both
        ``committed`` and ``replayed`` receipts: the server's deliveryId dedupe
        keeps the settled amount authoritative on its side, and the locally
        signed cumulative stays the client watermark so subsequent vouchers
        remain monotonic.
        """
        self._validate_directive(directive)
        amount = directive.amount_base_units()
        if amount == 0:
            raise ValueError("metered delivery amount must be greater than zero")

        voucher = self._session.prepare_increment(amount)
        payload = CommitPayload(delivery_id=directive.delivery_id, voucher=voucher)

        receipt = self._transport.commit(directive, payload)
        if receipt.status == "replayed":
            # The server already settled this delivery; its cumulative is the
            # authoritative settled position. Clamp to the just-prepared voucher
            # so an untrusted server cannot push the watermark past what we
            # signed. Reconcile (never regress) instead of recording the voucher.
            prepared = int(payload.voucher.data.cumulative)
            self._session.reconcile_settled(min(receipt.cumulative_base_units(), prepared))
        else:
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
    processed :attr:`payload`.
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
        """Sign and commit a voucher for the directive amount."""
        return self._consumer.commit_directive(self._metering)

    def commit(self) -> CommitReceipt:
        """Alias for :meth:`ack`."""
        return self.ack()

    def into_parts(self) -> tuple[P, MeteringDirective]:
        """Return the payload and metering directive without committing."""
        return self._payload, self._metering
