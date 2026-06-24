"""Client-side Solana MPP payment handling.

Exposes the charge transport plus the client-only session surface: the
:class:`ActiveSession` voucher tracker, the :class:`SessionConsumer` metered
ack/commit helper, the challenge-driven payment-channel openers, the metered
SSE streaming helpers, and the :func:`serialize_session_credential` /
:func:`parse_session_challenge` credential framing free functions. The
per-intent modules (:mod:`pay_kit.protocols.mpp.client.charge`,
:mod:`pay_kit.protocols.mpp.client.session`,
:mod:`pay_kit.protocols.mpp.client.payment_channels`,
:mod:`pay_kit.protocols.mpp.client.http_stream`,
:mod:`pay_kit.protocols.mpp.client.session_consumer`) remain the canonical
import path; the session types are re-exported here for convenience.
"""

from __future__ import annotations

from pay_kit.protocols.mpp.client.http_stream import (
    HttpCommitTransport,
    MeteredSseEvent,
    MeteredSseSession,
    MeteredSseStream,
    SseDecoder,
    SseEvent,
    parse_metered_sse_event,
)
from pay_kit.protocols.mpp.client.payment_channels import (
    DEFAULT_GRACE_PERIOD_SECONDS,
    PENDING_SERVER_SIGNATURE,
    PaymentChannelOpen,
    PaymentChannelOpenOptions,
    PaymentChannelOpenTransaction,
    PaymentChannelSessionOpen,
    PaymentChannelSessionOpenOptions,
    ServerOpenedPaymentChannelSessionOpenOptions,
    build_open_payment_channel_transaction,
    create_payment_channel_session_opener,
    create_server_opened_payment_channel_session_opener,
    derive_payment_channel_open,
    generate_authorized_signer,
    unique_salt,
)
from pay_kit.protocols.mpp.client.session import (
    ActiveSession,
    parse_session_challenge,
    serialize_session_credential,
    session_request_modes,
)
from pay_kit.protocols.mpp.client.session_consumer import (
    CommitTransport,
    MeteredDelivery,
    SessionConsumer,
)
from pay_kit.protocols.mpp.client.transport import PaymentTransport

__all__ = [
    "PaymentTransport",
    "ActiveSession",
    "CommitTransport",
    "SessionConsumer",
    "MeteredDelivery",
    "serialize_session_credential",
    "parse_session_challenge",
    "session_request_modes",
    "DEFAULT_GRACE_PERIOD_SECONDS",
    "PENDING_SERVER_SIGNATURE",
    "PaymentChannelOpen",
    "PaymentChannelOpenOptions",
    "PaymentChannelOpenTransaction",
    "PaymentChannelSessionOpen",
    "PaymentChannelSessionOpenOptions",
    "ServerOpenedPaymentChannelSessionOpenOptions",
    "build_open_payment_channel_transaction",
    "create_payment_channel_session_opener",
    "create_server_opened_payment_channel_session_opener",
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
