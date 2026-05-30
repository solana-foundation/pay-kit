"""Django integration for pay_kit (caveat #6 host quirks).

Two entry points, both delegating to the host-neutral
:class:`pay_kit._middleware.PayCore`:

* :func:`require_payment` decorates a view with a gate reference. On a missing
  or unusable proof it returns a ``402`` :class:`~django.http.JsonResponse`
  carrying the challenge headers and the ``{"error","resource","accepts"}``
  body; on success it sets ``request.payment`` (and the canonical
  ``paykit_payment`` attribute the trio reads) before calling the view, then
  echoes the settlement headers onto the response.
* :class:`PaymentMiddleware` is the optional MIDDLEWARE-stack form: it attaches
  ``request.payment`` for routes whose ``paykit_gate`` attribute was set (e.g.
  by a URLconf wrapper) and translates any escaping :class:`PayKitError` into
  the matching JSON response via :attr:`PayKitError.http_status`.

``PayCore.process`` is async; Django request handling is synchronous by
default, so both forms drive the coroutine with :func:`asyncio.run` (or a
fresh loop when one is already running, e.g. under ASGI). Wire-level header
constants stay canonical-cased; Django lowercases response header names at the
WSGI/ASGI boundary on its own.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from functools import wraps
from typing import TYPE_CHECKING, Any, cast

from pay_kit._middleware import PAYMENT_ATTR, PayCore, is_paid
from pay_kit._middleware import payment as _core_payment
from pay_kit.config import config as _config
from pay_kit.errors import PayKitError, PaymentRequiredError
from pay_kit.payment import Payment

if TYPE_CHECKING:
    from django.http import (  # pyright: ignore[reportMissingTypeStubs]  # django ships no type stubs (django-stubs is third-party)
        HttpRequest,
        HttpResponse,
        JsonResponse,
    )

    from pay_kit.config import Config
    from pay_kit.gate import DynamicGate, Gate
    from pay_kit.price import Price
    from pay_kit.pricing import Pricing

    GateRef = Gate | DynamicGate | Price | str | Callable[[HttpRequest], Gate]

__all__ = ["require_payment", "PaymentMiddleware", "is_paid", "payment"]

#: Request attribute a URLconf wrapper or middleware may set to bind a gate to
#: a view when the :class:`PaymentMiddleware` stack form is used.
GATE_ATTR = "paykit_gate"


def require_payment(
    gate_ref: GateRef,
    *,
    pricing: Pricing | None = None,
    config: Config | None = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorate a Django view to require payment for ``gate_ref``.

    On success attaches the verified :class:`~pay_kit.payment.Payment` to
    ``request.payment`` (and the canonical ``paykit_payment`` attribute), calls
    the view, then merges the settlement headers onto the returned response. On
    a missing/invalid proof returns a ``402`` :class:`~django.http.JsonResponse`
    built from the challenge; any other :class:`~pay_kit.errors.PayKitError`
    renders its :attr:`~pay_kit.errors.PayKitError.http_status`.
    """

    def decorator(view: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(view)
        def wrapper(request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
            core = PayCore.for_config(config if config is not None else _config())
            try:
                payment = _run(core.process(gate_ref, pricing, request))
            except PayKitError as exc:
                return _error_response(exc)
            _attach(request, payment)
            response = view(request, *args, **kwargs)
            return _merge_settlement_headers(response, payment)

        return wrapper

    return decorator


class PaymentMiddleware:
    """Django MIDDLEWARE-stack form gating views that declare a gate.

    A view becomes gated by exposing a gate reference on the request under the
    ``paykit_gate`` attribute (e.g. via a thin URLconf wrapper that sets it
    before dispatch). For such requests the middleware verifies the proof,
    attaches ``request.payment``, and echoes the settlement headers; otherwise
    it passes the request through untouched. Any :class:`PayKitError` raised by
    a downstream view (e.g. an imperative :func:`require_payment` from the
    trio) is converted to the matching JSON response.
    """

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        """Store the next handler in the Django middleware chain."""
        self._get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        """Gate the request when it declares a gate, else pass it through."""
        gate_ref = getattr(request, GATE_ATTR, None)
        if gate_ref is None:
            return self._passthrough(request)

        core = PayCore.for_config(_config())
        try:
            payment = _run(core.process(gate_ref, _request_pricing(request), request))
        except PayKitError as exc:
            return _error_response(exc)
        _attach(request, payment)
        response = self._passthrough(request)
        return _merge_settlement_headers(response, payment)

    def _passthrough(self, request: HttpRequest) -> HttpResponse:
        """Call the next handler, translating any escaping PayKitError."""
        try:
            return self._get_response(request)
        except PayKitError as exc:
            return _error_response(exc)


def payment(request: HttpRequest) -> Payment | None:
    """Return the verified payment attached to ``request``, or ``None``."""
    return _core_payment(request)


# -- internals --------------------------------------------------------------


def _attach(request: HttpRequest, payment: Payment) -> None:
    """Bind the verified payment to the request for views and the trio."""
    setattr(request, PAYMENT_ATTR, payment)
    # Friendly Django-idiomatic alias mirroring the cross-SDK request.payment.
    request.payment = payment  # type: ignore[attr-defined]


def _merge_settlement_headers(response: HttpResponse, payment: Payment) -> HttpResponse:
    """Echo the payment's settlement headers onto the framework response."""
    for key, value in payment.settlement_headers.items():
        response[key] = value
    return response


def _error_response(exc: PayKitError) -> JsonResponse:
    """Render a PayKitError as a JsonResponse using its HTTP status.

    A :class:`~pay_kit.errors.PaymentRequiredError` carries the rendered 402
    challenge (``challenge_headers`` + ``body``) from
    :meth:`PayCore.build_402`; everything else falls back to a minimal error
    body keyed on the exception's canonical code (if any).
    """
    from django.http import JsonResponse  # pyright: ignore[reportMissingTypeStubs]  # django ships no type stubs

    status = getattr(exc, "http_status", 500)
    raw_body = getattr(exc, "body", None)
    body: dict[str, Any] = (
        cast("dict[str, Any]", raw_body)
        if isinstance(raw_body, dict)
        else {"error": getattr(exc, "code", "payment_error"), "message": str(exc)}
    )

    response = JsonResponse(body, status=status)
    if isinstance(exc, PaymentRequiredError):
        challenge_headers = cast("dict[str, str]", getattr(exc, "challenge_headers", {}))
        for key, value in challenge_headers.items():
            response[key] = value
    return response


def _request_pricing(request: HttpRequest) -> Pricing | None:
    """Pull an optional Pricing registry a wrapper attached to the request."""
    pricing = getattr(request, "paykit_pricing", None)
    return pricing


def _run(coro: Any) -> Payment:
    """Drive an async coroutine to completion from sync Django request code.

    Uses :func:`asyncio.run` when no loop is running; spins a dedicated loop in
    a fresh thread when called from within a running loop (ASGI handlers).
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)

    import threading

    result: dict[str, Any] = {}

    def _runner() -> None:
        try:
            result["value"] = asyncio.run(coro)
        except BaseException as exc:  # re-raised on the calling thread below
            result["error"] = exc

    thread = threading.Thread(target=_runner)
    thread.start()
    thread.join()
    error = result.get("error")
    if error is not None:
        raise error
    return result["value"]
