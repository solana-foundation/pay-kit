"""Flask shim for pay_kit (optional dependency, caveat #6).

Exposes a :func:`require_payment` view decorator that gates a Flask route on a
verified payment, plus :func:`is_paid` / :func:`payment` request accessors. The
decorator delegates every protocol/scheme decision to
:class:`pay_kit._middleware.PayCore`; this module only translates ``PayCore``'s
outcome into Flask idioms (caveat #6):

* a settled :class:`~pay_kit.payment.Payment` is stashed on ``flask.g`` (under
  the same ``paykit_payment`` attribute the host-neutral trio reads) and its
  settlement headers are merged onto the response;
* a :class:`~pay_kit.errors.PaymentRequiredError` becomes ``flask.abort`` with a
  JSON 402 carrying the challenge headers + body;
* any other :class:`~pay_kit.errors.PayKitError` becomes ``flask.abort`` at its
  declared :attr:`http_status` (402 for invalid proof, 406 for unsupported
  protocol).

Header constants stay canonical casing here; Flask/Werkzeug normalise them at
the response boundary.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from functools import wraps
from typing import TYPE_CHECKING, Any, NoReturn, TypeVar

import flask
from flask import abort, g, make_response

from pay_kit._middleware import PAYMENT_ATTR, PayCore
from pay_kit.config import config as _global_config
from pay_kit.errors import PayKitError, PaymentRequiredError
from pay_kit.payment import Payment

if TYPE_CHECKING:
    from pay_kit.config import Config
    from pay_kit.gate import DynamicGate, Gate
    from pay_kit.price import Price
    from pay_kit.pricing import Pricing

__all__ = ["require_payment", "is_paid", "payment"]

_F = TypeVar("_F", bound="Callable[..., Any]")

#: Gate reference shapes the decorator accepts (forwarded verbatim to PayCore).
GateRef = "Gate | DynamicGate | Price | str | Callable[[Any], Gate]"


def require_payment(
    gate_ref: Gate | DynamicGate | Price | str | Callable[[Any], Gate],
    *,
    pricing: Pricing | None = None,
    config: Config | None = None,
) -> Callable[[_F], _F]:
    """Decorate a Flask view so it serves only after a verified payment.

    On a successful verify the settled :class:`~pay_kit.payment.Payment` is
    attached to ``flask.g`` and its settlement headers are merged onto the
    response. A missing/invalid proof aborts with the right HTTP status: 402 with
    the challenge headers + JSON body for :class:`PaymentRequiredError`, otherwise
    the error's :attr:`~pay_kit.errors.PayKitError.http_status`.
    """

    def decorator(view: _F) -> _F:
        @wraps(view)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            request = flask.request
            core = PayCore.for_config(config if config is not None else _global_config())
            try:
                payment_obj = _run(core.process(gate_ref, pricing, request))
            except PaymentRequiredError as exc:
                _abort_payment_required(exc)
            except PayKitError as exc:
                _abort_pay_kit_error(exc)

            setattr(g, PAYMENT_ATTR, payment_obj)
            response = make_response(view(*args, **kwargs))
            for header, value in payment_obj.settlement_headers.items():
                response.headers[header] = value
            return response

        return wrapper  # type: ignore[return-value]

    return decorator


def payment() -> Payment | None:
    """The verified payment attached to the current request, or ``None``."""
    value = getattr(g, PAYMENT_ATTR, None)
    return value if isinstance(value, Payment) else None


def is_paid(
    gate_ref: Gate | DynamicGate | Price | str | Callable[[Any], Gate] | None = None,
) -> bool:
    """Whether the current request carries a verified payment.

    With no argument, reports whether any payment is attached. Given a gate (or
    gate name) it additionally checks the payment was settled for that gate;
    other gate-reference shapes only confirm presence (Payment carries no gate
    identity beyond its name).
    """
    current = payment()
    if current is None:
        return False
    if gate_ref is None:
        return True
    if isinstance(gate_ref, str):
        return current.gate_name == gate_ref
    name = getattr(gate_ref, "name", None)
    if isinstance(name, str):
        return current.gate_name == name
    return True


# -- internals --------------------------------------------------------------


def _abort_payment_required(exc: PaymentRequiredError) -> NoReturn:
    """Render a 402 from a PaymentRequiredError's stashed challenge."""
    headers: dict[str, str] = getattr(exc, "challenge_headers", {}) or {}
    body: dict[str, Any] = getattr(exc, "body", None) or {"error": "payment_required"}
    response = make_response(flask.jsonify(body), exc.http_status)
    for header, value in headers.items():
        response.headers[header] = value
    abort(response)


def _abort_pay_kit_error(exc: PayKitError) -> NoReturn:
    """Render a non-402-challenge PayKitError at its declared http_status."""
    status = getattr(exc, "http_status", 402)
    code = getattr(exc, "code", None)
    body: dict[str, Any] = {"error": str(exc)}
    if isinstance(code, str):
        body["code"] = code
    response = make_response(flask.jsonify(body), status)
    abort(response)


def _run(coro: Any) -> Payment:
    """Drive PayCore's async pipeline from Flask's synchronous view context.

    Uses :func:`asyncio.run` when no loop is running; falls back to a dedicated
    short-lived loop if one is somehow already active on this thread.
    """
    try:
        return asyncio.run(coro)
    except RuntimeError:
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()
