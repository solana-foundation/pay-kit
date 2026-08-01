"""Client-side Solana MPP payment handling.

Exposes the charge transport plus the client-only session surface: the
:class:`ActiveSession` voucher tracker, the :class:`SessionConsumer` metered
ack/commit helper, the challenge-driven payment-channel openers, the metered
SSE streaming helpers, and the :func:`serialize_session_credential` /
:func:`parse_session_challenge` credential framing free functions. The
per-intent modules (:mod:`solana_pay_kit.protocols.mpp.client.charge`,
:mod:`solana_pay_kit.protocols.mpp.client.session`,
:mod:`solana_pay_kit.protocols.mpp.client.payment_channels`,
:mod:`solana_pay_kit.protocols.mpp.client.http_stream`,
:mod:`solana_pay_kit.protocols.mpp.client.session_consumer`) remain the canonical
import path; the session types are re-exported here for convenience.
"""

from __future__ import annotations

from solana_pay_kit.protocols.mpp.client.http_stream import (
    HttpCommitTransport,
    MeteredSseEvent,
    MeteredSseSession,
    MeteredSseStream,
    SseDecoder,
    SseEvent,
    parse_metered_sse_event,
)
from solana_pay_kit.protocols.mpp.client.payment_channels import (
    DEFAULT_GRACE_PERIOD_SECONDS,
    PaymentChannelOpen,
    PaymentChannelOpenOptions,
    PaymentChannelOpenTransaction,
    PaymentChannelSessionOpen,
    PaymentChannelSessionOpenOptions,
    build_open_payment_channel_transaction,
    create_payment_channel_session_opener,
    derive_payment_channel_open,
    generate_authorized_signer,
    unique_salt,
)
from solana_pay_kit.protocols.mpp.client.session import (
    ActiveSession,
    parse_session_challenge,
    serialize_session_credential,
)
from solana_pay_kit.protocols.mpp.client.session_consumer import (
    CommitTransport,
    MeteredDelivery,
    SessionConsumer,
)
from solana_pay_kit.protocols.mpp.client.transport import PaymentTransport

__all__ = [
    "PaymentTransport",
    "ActiveSession",
    "CommitTransport",
    "SessionConsumer",
    "MeteredDelivery",
    "serialize_session_credential",
    "parse_session_challenge",
    "DEFAULT_GRACE_PERIOD_SECONDS",
    "PaymentChannelOpen",
    "PaymentChannelOpenOptions",
    "PaymentChannelOpenTransaction",
    "PaymentChannelSessionOpen",
    "PaymentChannelSessionOpenOptions",
    "build_open_payment_channel_transaction",
    "create_payment_channel_session_opener",
    "derive_payment_channel_open",
    "generate_authorized_signer",
    "unique_salt",
    "HttpCommitTransport",
    "MeteredSseEvent",
    "MeteredSseSession",
    "MeteredSseStream",
    "SseDecoder",
    "SseEvent",
    "parse_metered_sse_event",
]
