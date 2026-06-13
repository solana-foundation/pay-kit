"""Metering side channel for the session method.

The reserve/commit side channel is an extension beyond the draft MPP spec:
SessionFetch-style clients POST to ``/__402/session/deliveries`` to reserve
capacity for a metered delivery and to ``/__402/session/commit`` to commit it
with a signed voucher. Hosts mount the two handlers on those paths themselves.

Ports ``go/protocols/mpp/server/session_routes.go``. The Go ``Routes()`` is a
method on the HTTP-facing ``Session``; the routes only ever touch the
lower-level ``SessionServer`` (the Go ``s.core``) plus an idle-close ``touch``
hook, so this port builds the handlers over a :class:`SessionServer` directly.

House style follows the existing server modules (``middleware.py``): handlers
are framework-agnostic. Each takes the HTTP method and the raw request body and
returns a :class:`RouteResponse` carrying the status and a JSON-ready body, so
hosts can adapt it to any ASGI/WSGI framework.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from pay_kit.protocols.mpp.intents.session import CommitPayload, SignedVoucher
from pay_kit.protocols.mpp.server.session import DeliveryRequest, SessionServer

__all__ = [
    "RouteResponse",
    "SessionRoutes",
    "session_routes",
]

_U64_MAX = (1 << 64) - 1

# A touch hook called with the session id after a successful reserve/commit, so
# a host's idle-close watchdog can be armed. ``None`` disables it. Mirrors the
# Go ``Session.touch``.
TouchFn = Callable[[str], None]

# A handler takes the request method and the raw request body (the JSON text or
# bytes) and returns a RouteResponse. Mirrors the Go ``http.HandlerFunc`` shape
# (method gating + JSON body decode) in a framework-agnostic form.
RouteHandler = Callable[[str, "str | bytes"], Awaitable["RouteResponse"]]


@dataclass
class RouteResponse:
    """The result of a side-channel handler: an HTTP status plus a JSON-ready
    body. Successful reserves/commits carry the directive/receipt dict; failures
    carry ``{"error": message}``, the failure body the side-channel clients
    expect (Go ``writeSessionRouteError``).
    """

    status: int
    body: dict[str, Any] = field(default_factory=dict)


@dataclass
class SessionRoutes:
    """The metering side-channel handlers built by :func:`session_routes`.

    Both share the session's channel store, so deliveries see channels opened
    through the session method. Mirrors Go ``SessionRoutes``.
    """

    # deliveries reserves capacity for a metered delivery. Mount at
    # POST /__402/session/deliveries.
    deliveries: RouteHandler

    # commit commits a reserved delivery with a signed voucher. Mount at
    # POST /__402/session/commit.
    commit: RouteHandler


def _parse_session_u64(value: str, name: str) -> int:
    """Parse a non-negative decimal string into a u64, naming the field in the
    error. Mirrors Go ``parseSessionU64``."""
    if not isinstance(value, str) or not (value.isascii() and value.isdigit()):
        raise ValueError(f"{name} is not an unsigned integer string: {value}")
    parsed = int(value, 10)
    if parsed > _U64_MAX:
        raise ValueError(f"{name} is not an unsigned integer string: {value}")
    return parsed


def _decode_body(raw: str | bytes) -> dict[str, Any]:
    """Decode a JSON object request body. Raises on non-object or invalid JSON,
    mirroring Go's ``json.NewDecoder(r.Body).Decode(&body)`` into a struct."""
    decoded = json.loads(raw)
    if not isinstance(decoded, dict):
        raise ValueError("request body must be a JSON object")
    return decoded


class _DecodeError(ValueError):
    """A request-body type mismatch caught at the decode layer. Surfaced as
    HTTP 400 "invalid request body", matching Go's ``json.Decode`` rejection of
    a JSON value whose type does not match the typed struct field."""


def _string_field(body: dict[str, Any], name: str) -> str:
    """Read a JSON string field, defaulting an absent/null value to "".

    Mirrors a Go ``string`` struct field: a present value of any non-string JSON
    type (number, bool, object, array) fails ``json.Decode``, so reject it as
    ``invalid request body`` before any processing."""
    value = body.get(name)
    if value is None:
        return ""
    if not isinstance(value, str):
        raise _DecodeError(name)
    return value


def _int64_field(body: dict[str, Any], name: str) -> int:
    """Read a JSON integer field, defaulting an absent/null value to 0.

    Mirrors a Go ``int64`` struct field: ``json.Decode`` accepts only a JSON
    integer. A JSON float (``10.0``/``10.5``), a numeric or non-numeric string
    (``"10"``/``"soon"``), or a bool all fail decode, so reject them as
    ``invalid request body`` before any processing. (Python parses ``bool`` as a
    subclass of ``int`` and JSON integers as ``int``; exclude ``bool`` so only
    true integers pass.)"""
    value = body.get(name)
    if value is None:
        return 0
    if isinstance(value, bool) or not isinstance(value, int):
        raise _DecodeError(name)
    return value


def session_routes(core: SessionServer, touch: TouchFn | None = None) -> SessionRoutes:
    """Build the metering side-channel handlers for a session server.

    ``touch`` is the idle-close hook called with the session id after a
    successful reserve/commit; ``None`` disables it. Mirrors Go
    ``Session.Routes`` (whose handlers delegate to ``s.core`` and ``s.touch``).
    """

    def _touch(session_id: str) -> None:
        if touch is not None:
            touch(session_id)

    async def deliveries(method: str, raw: str | bytes) -> RouteResponse:
        if method != "POST":
            return _error(405, "POST required")
        try:
            body = _decode_body(raw)
            # Strict typed decode (Go sessionDeliveryRequestBody): reject any
            # field whose JSON type does not match the Go struct field before any
            # store access, matching Go's json.Decode rejection.
            session_id = _string_field(body, "sessionId")
            amount_raw = _string_field(body, "amount")
            delivery_id = _string_field(body, "deliveryId")
            commit_url = _string_field(body, "commitUrl")
            proof = _string_field(body, "proof")
            expires_at = _int64_field(body, "expiresAt")
        except (ValueError, json.JSONDecodeError):
            return _error(400, "invalid request body")
        if not session_id:
            return _error(400, "sessionId required")
        try:
            amount = _parse_session_u64(amount_raw, "amount")
        except ValueError as exc:
            return _error(400, str(exc))
        if amount == 0:
            return _error(400, "amount must be positive")
        try:
            directive = await core.begin_delivery(
                DeliveryRequest(
                    session_id=session_id,
                    amount=amount,
                    delivery_id=delivery_id,
                    commit_url=commit_url,
                    proof=proof,
                    expires_at=expires_at,
                )
            )
        except ValueError as exc:
            return _error(400, str(exc))
        _touch(session_id)
        return RouteResponse(status=200, body=directive.to_dict())

    async def commit(method: str, raw: str | bytes) -> RouteResponse:
        if method != "POST":
            return _error(405, "POST required")
        try:
            body = _decode_body(raw)
            # Strict typed decode (Go sessionCommitRequestBody): deliveryId is a
            # string field, so a non-string JSON value is rejected up front.
            delivery_id = _string_field(body, "deliveryId")
        except (ValueError, json.JSONDecodeError):
            return _error(400, "invalid request body")
        if not delivery_id:
            return _error(400, "deliveryId required")
        voucher_raw = body.get("voucher")
        if voucher_raw is None:
            return _error(400, "voucher required")
        voucher = SignedVoucher.from_dict(voucher_raw)
        try:
            receipt = await core.process_commit(CommitPayload(delivery_id=delivery_id, voucher=voucher))
        except ValueError as exc:
            return _error(400, str(exc))
        _touch(receipt.session_id)
        return RouteResponse(status=200, body=receipt.to_dict())

    return SessionRoutes(deliveries=deliveries, commit=commit)


def _error(status: int, message: str) -> RouteResponse:
    """Build the ``{"error": message}`` failure body the side-channel clients
    expect. Mirrors Go ``writeSessionRouteError``."""
    return RouteResponse(status=status, body={"error": message})
