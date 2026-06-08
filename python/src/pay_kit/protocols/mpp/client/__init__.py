"""Client-side Solana MPP payment handling.

Exposes the charge transport plus the client-only session surface: the
:class:`ActiveSession` voucher tracker, the :class:`SessionConsumer` metered
ack/commit helper, and the :func:`serialize_session_credential` /
:func:`parse_session_challenge` credential framing free functions. The
per-intent modules (:mod:`pay_kit.protocols.mpp.client.charge`,
:mod:`pay_kit.protocols.mpp.client.session`,
:mod:`pay_kit.protocols.mpp.client.session_consumer`) remain the canonical
import path; the session types are re-exported here for convenience.
"""

from __future__ import annotations

from pay_kit.protocols.mpp.client.session import (
    ActiveSession,
    parse_session_challenge,
    serialize_session_credential,
)
from pay_kit.protocols.mpp.client.session_consumer import (
    MeteredDelivery,
    SessionConsumer,
)
from pay_kit.protocols.mpp.client.transport import PaymentTransport

__all__ = [
    "PaymentTransport",
    "ActiveSession",
    "SessionConsumer",
    "MeteredDelivery",
    "serialize_session_credential",
    "parse_session_challenge",
]
