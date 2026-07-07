"""Django integration for solana_pay_kit (caveat #6 host quirks).

Two entry points, both delegating to the host-neutral
:class:`solana_pay_kit._middleware.PayCore`:

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
import contextlib
import weakref
from collections.abc import Callable, Coroutine
from functools import wraps
from typing import TYPE_CHECKING, Any, TypeVar, cast

from solana_pay_kit._middleware import PAYMENT_ATTR, PayCore, is_paid
from solana_pay_kit._middleware import payment as _core_payment
from solana_pay_kit.config import config as _config
from solana_pay_kit.errors import InvalidProofError, PayKitError, PaymentRequiredError
from solana_pay_kit.payment import Payment
from solana_pay_kit.usage import CHARGE_ATTR, Charge, fetch_recent_blockhash, finalize_usage

if TYPE_CHECKING:
    from django.http import (  # pyright: ignore[reportMissingTypeStubs]  # django ships no type stubs (django-stubs is third-party)
        HttpRequest,
        HttpResponse,
        JsonResponse,
    )

    from solana_pay_kit.config import Config
    from solana_pay_kit.gate import DynamicGate, Gate
    from solana_pay_kit.price import Price
    from solana_pay_kit.pricing import Pricing
    from solana_pay_kit.protocols.x402.upto import X402Upto

    GateRef = Gate | DynamicGate | Price | str | Callable[[HttpRequest], Gate]
    UsageGateRef = Gate | Callable[[HttpRequest], Gate]

__all__ = [
    "require_payment",
    "require_usage",
    "RequireUsage",
    "PaymentMiddleware",
    "is_paid",
    "payment",
    "charge",
    "Charge",
]

_T = TypeVar("_T")

#: Request attribute a URLconf wrapper or middleware may set to bind a gate to
#: a view when the :class:`PaymentMiddleware` stack form is used.
GATE_ATTR = "paykit_gate"

#: One x402 ``upto`` engine per Config - it owns the per-channel in-flight
#: reservation set, so it must be a singleton (a fresh engine per request would
#: not dedupe concurrent settlements on the same channel). Mirrors fastapi.py.
_UPTO_CACHE: weakref.WeakKeyDictionary[Config, X402Upto] = weakref.WeakKeyDictionary()


def _upto_engine(config: Config) -> X402Upto:
    """Return the per-Config singleton x402 ``upto`` engine, building it once."""
    cached = _UPTO_CACHE.get(config)
    if cached is not None:
        return cached
    from solana_pay_kit.protocols.x402.upto import X402Upto

    # Pre-fetch ``extra.recentBlockhash`` from the configured RPC (parity with
    # fastapi/the harness server; degrades to None on any RPC failure).
    engine = X402Upto(
        config,
        recent_blockhash_provider=lambda: fetch_recent_blockhash(config.effective_rpc_url()),
    )
    _UPTO_CACHE[config] = engine
    return engine


def require_payment(
    gate_ref: GateRef,
    *,
    pricing: Pricing | None = None,
    config: Config | None = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorate a Django view to require payment for ``gate_ref``.

    On success attaches the verified :class:`~solana_pay_kit.payment.Payment` to
    ``request.payment`` (and the canonical ``paykit_payment`` attribute), calls
    the view, then merges the settlement headers onto the returned response. On
    a missing/invalid proof returns a ``402`` :class:`~django.http.JsonResponse`
    built from the challenge; any other :class:`~solana_pay_kit.errors.PayKitError`
    renders its :attr:`~solana_pay_kit.errors.PayKitError.http_status`.
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


def require_usage(
    gate_ref: UsageGateRef,
    *,
    config: Config | None = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorate a Django view to require an x402 ``upto`` usage gate.

    Two-phase: before the view it opens + binds the payment channel, attaching a
    :class:`~solana_pay_kit.usage.Charge` meter to ``request.charge`` (read it with
    :func:`charge` or :func:`solana_pay_kit.usage.charge_from`); after the view it
    settles the metered amount. A missing/invalid credential returns a ``402``
    :class:`~django.http.JsonResponse` carrying the upto challenge. The view MUST
    call ``charge.charge(actual_base_units)`` with a positive amount before
    returning, else the body is withheld (fail-closed, 402) and the channel is
    finalized with a full refund.
    """

    def decorator(view: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(view)
        def wrapper(request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
            from solana_pay_kit.gate import Gate as _Gate

            engine = _upto_engine(config if config is not None else _config())
            gate = gate_ref if isinstance(gate_ref, _Gate) else gate_ref(request)
            if not engine.detect_usage(request):
                return _usage_challenge_response(engine, gate, request)
            try:
                verified = _run(engine.verify_open(gate, request))
            except PaymentRequiredError:
                return _usage_challenge_response(engine, gate, request)
            except InvalidProofError as exc:
                return _usage_challenge_response(engine, gate, request, exc)
            except PayKitError as exc:
                return _error_response(exc)

            meter = Charge(verified.max_amount)
            _attach_charge(request, meter)
            try:
                response = view(request, *args, **kwargs)
            except BaseException:
                # The channel is open on-chain; settle 0 (finalize + full refund)
                # so an abandoned request never leaves the deposit locked.
                with contextlib.suppress(Exception):
                    _run(engine.settle_actual(verified, 0))
                raise

            outcome = _run(finalize_usage(engine, verified, meter))
            if not outcome.ok:
                return _usage_outcome_response(engine, gate, request, outcome)
            for key, value in outcome.settlement_headers.items():
                response[key] = value
            return response

        return wrapper

    return decorator


#: FastAPI-parity alias; the Django form is a view decorator, not a dependency.
RequireUsage = require_usage


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


def charge(request: HttpRequest) -> Charge | None:
    """Return the usage :class:`~solana_pay_kit.usage.Charge` meter on ``request``, or ``None``."""
    from solana_pay_kit.usage import charge_from

    return charge_from(request)


# -- internals --------------------------------------------------------------


def _attach(request: HttpRequest, payment: Payment) -> None:
    """Bind the verified payment to the request for views and the trio."""
    setattr(request, PAYMENT_ATTR, payment)
    # Friendly Django-idiomatic alias mirroring the cross-SDK request.payment.
    request.payment = payment  # type: ignore[attr-defined]


def _attach_charge(request: HttpRequest, meter: Charge) -> None:
    """Bind the usage Charge meter to the request for the view and charge_from."""
    setattr(request, CHARGE_ATTR, meter)
    # Friendly Django-idiomatic alias mirroring the cross-SDK request.charge.
    request.charge = meter  # type: ignore[attr-defined]


def _merge_settlement_headers(response: HttpResponse, payment: Payment) -> HttpResponse:
    """Echo the payment's settlement headers onto the framework response."""
    for key, value in payment.settlement_headers.items():
        response[key] = value
    return response


def _error_response(exc: PayKitError) -> JsonResponse:
    """Render a PayKitError as a JsonResponse using its HTTP status.

    A :class:`~solana_pay_kit.errors.PaymentRequiredError` carries the rendered 402
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


def _usage_challenge_response(
    engine: X402Upto,
    gate: Gate,
    request: HttpRequest,
    exc: InvalidProofError | None = None,
) -> JsonResponse:
    """Render a 402 carrying the x402 upto challenge for a missing/invalid credential."""
    from django.http import JsonResponse  # pyright: ignore[reportMissingTypeStubs]  # django ships no type stubs

    body: dict[str, Any] = {
        "error": "payment_required",
        "resource": request.path,
        "accepts": [engine.accepts_entry(gate, request)],
    }
    if exc is not None:
        body["code"] = exc.code or "invalid_proof"
        body["message"] = str(exc)
    response = JsonResponse(body, status=402)
    for key, value in engine.challenge_headers(gate, request).items():
        response[key] = value
    return response


def _usage_outcome_response(
    engine: X402Upto,
    gate: Gate,
    request: HttpRequest,
    outcome: Any,
) -> JsonResponse:
    """Withhold the body with a 402 upto challenge when settlement fails closed."""
    from django.http import JsonResponse  # pyright: ignore[reportMissingTypeStubs]  # django ships no type stubs

    body: dict[str, Any] = {
        "error": "payment_required",
        "code": outcome.code,
        "message": outcome.detail or "",
    }
    response = JsonResponse(body, status=outcome.status)
    for key, value in engine.challenge_headers(gate, request).items():
        response[key] = value
    return response


def _request_pricing(request: HttpRequest) -> Pricing | None:
    """Pull an optional Pricing registry a wrapper attached to the request."""
    pricing = getattr(request, "paykit_pricing", None)
    return pricing


def _run(coro: Coroutine[Any, Any, _T]) -> _T:
    """Drive an async coroutine to completion from sync Django request code.

    Uses :func:`asyncio.run` when no loop is running; spins a dedicated loop in
    a fresh thread when called from within a running loop (ASGI handlers).
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)

    import threading

    result: dict[str, _T] = {}
    error: dict[str, BaseException] = {}

    def _runner() -> None:
        try:
            result["value"] = asyncio.run(coro)
        except BaseException as exc:  # re-raised on the calling thread below
            error["error"] = exc

    thread = threading.Thread(target=_runner)
    thread.start()
    thread.join()
    raised = error.get("error")
    if raised is not None:
        raise raised
    return result["value"]
