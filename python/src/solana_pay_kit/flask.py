"""Flask shim for solana_pay_kit (optional dependency, caveat #6).

Exposes a :func:`require_payment` view decorator that gates a Flask route on a
verified payment, plus :func:`is_paid` / :func:`payment` request accessors. The
decorator delegates every protocol/scheme decision to
:class:`solana_pay_kit._middleware.PayCore`; this module only translates ``PayCore``'s
outcome into Flask idioms (caveat #6):

* a settled :class:`~solana_pay_kit.payment.Payment` is stashed on ``flask.g`` (under
  the same ``paykit_payment`` attribute the host-neutral trio reads) and its
  settlement headers are merged onto the response;
* a :class:`~solana_pay_kit.errors.PaymentRequiredError` becomes ``flask.abort`` with a
  JSON 402 carrying the challenge headers + body;
* any other :class:`~solana_pay_kit.errors.PayKitError` becomes ``flask.abort`` at its
  declared :attr:`http_status` (402 for invalid proof, 406 for unsupported
  protocol).

Header constants stay canonical casing here; Flask/Werkzeug normalise them at
the response boundary.
"""

from __future__ import annotations

import contextlib
import logging
import weakref
from collections.abc import Callable, Coroutine
from functools import wraps
from typing import TYPE_CHECKING, Any, NoReturn, TypeVar

import flask
from flask import abort, g, make_response

from solana_pay_kit._middleware import PAYMENT_ATTR, PayCore
from solana_pay_kit._paycore.loops import run_blocking
from solana_pay_kit.config import config as _global_config
from solana_pay_kit.errors import InvalidProofError, PayKitError, PaymentRequiredError
from solana_pay_kit.payment import Payment
from solana_pay_kit.usage import (
    CHARGE_ATTR,
    Charge,
    batch_challenge,
    fetch_recent_blockhash_and_slot,
    finalize_batch,
    finalize_usage,
)

if TYPE_CHECKING:
    from solana_pay_kit.config import Config
    from solana_pay_kit.gate import DynamicGate, Gate
    from solana_pay_kit.price import Price
    from solana_pay_kit.pricing import Pricing
    from solana_pay_kit.protocols.x402.batch_settlement.engine import X402BatchSettlement
    from solana_pay_kit.protocols.x402.batch_settlement.types import BatchRequirements, VoucherSigner
    from solana_pay_kit.protocols.x402.upto import X402Upto

__all__ = [
    "require_payment",
    "require_usage",
    "RequireUsage",
    "require_batch",
    "RequireBatch",
    "is_paid",
    "payment",
    "charge",
    "Charge",
]

_F = TypeVar("_F", bound="Callable[..., Any]")
_T = TypeVar("_T")
logger = logging.getLogger("solana_pay_kit")


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

    # Pre-fetch ``extra.recentBlockhash`` and ``extra.recentSlot`` (one
    # getLatestBlockhash call) from the configured RPC (parity with
    # fastapi/the harness server; degrades to None on any RPC failure).
    engine = X402Upto(
        config,
        recent_state_provider=lambda: fetch_recent_blockhash_and_slot(config.effective_rpc_url()),
    )
    _UPTO_CACHE[config] = engine
    return engine


#: Gate reference shapes the decorator accepts (forwarded verbatim to PayCore).
GateRef = "Gate | DynamicGate | Price | str | Callable[[Any], Gate]"


def require_payment(
    gate_ref: Gate | DynamicGate | Price | str | Callable[[Any], Gate],
    *,
    pricing: Pricing | None = None,
    config: Config | None = None,
) -> Callable[[_F], _F]:
    """Decorate a Flask view so it serves only after a verified payment.

    On a successful verify the settled :class:`~solana_pay_kit.payment.Payment` is
    attached to ``flask.g`` and its settlement headers are merged onto the
    response. A missing/invalid proof aborts with the right HTTP status: 402 with
    the challenge headers + JSON body for :class:`PaymentRequiredError`, otherwise
    the error's :attr:`~solana_pay_kit.errors.PayKitError.http_status`.
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


def require_usage(
    gate_ref: Gate | Callable[[Any], Gate],
    *,
    config: Config | None = None,
) -> Callable[[_F], _F]:
    """Decorate a Flask view so it serves only after an x402 ``upto`` usage gate.

    Two-phase: before the view it opens + binds the payment channel, attaching a
    :class:`~solana_pay_kit.usage.Charge` meter (read it with :func:`charge` or
    :func:`solana_pay_kit.usage.charge_from`); after the view it settles the metered
    amount. A missing/invalid credential aborts with a 402 carrying the upto
    challenge. The view MUST call ``charge.charge(actual_base_units)`` with a
    positive amount before returning, else the body is withheld (fail-closed,
    402) and the channel is sealed with a full refund.
    """

    def decorator(view: _F) -> _F:
        @wraps(view)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            from solana_pay_kit.gate import Gate as _Gate

            request = flask.request
            cfg = config if config is not None else _global_config()
            engine = _upto_engine(cfg)
            gate = gate_ref if isinstance(gate_ref, _Gate) else gate_ref(request)
            if not engine.detect_usage(request):
                _abort_usage_required(engine, gate, request)
            try:
                verified = _run(engine.verify_open(gate, request))
            except PaymentRequiredError:
                _abort_usage_required(engine, gate, request)
            except InvalidProofError as exc:
                _abort_usage_required(engine, gate, request, exc)
            except PayKitError as exc:
                _abort_pay_kit_error(exc)

            meter = Charge(verified.max_amount)
            setattr(request, CHARGE_ATTR, meter)
            setattr(g, CHARGE_ATTR, meter)
            try:
                response = make_response(view(*args, **kwargs))
            except BaseException:
                # The channel is open on-chain; settle 0 (seal + full refund)
                # so an abandoned request never leaves the deposit locked.
                with contextlib.suppress(Exception):
                    _run(engine.settle_actual(verified, 0))
                raise

            outcome = _run(finalize_usage(engine, verified, meter))
            if not outcome.ok:
                _abort_usage_outcome(engine, gate, request, outcome)
            for header, value in outcome.settlement_headers.items():
                response.headers[header] = value
            return response

        return wrapper  # type: ignore[return-value]

    return decorator


#: FastAPI-parity alias; the Flask form is a view decorator, not a dependency.
RequireUsage = require_usage


def require_batch(
    gate_ref: Gate | Callable[[Any], Gate],
    *,
    config: Config | None = None,
    voucher_signer: VoucherSigner | None = None,
) -> Callable[[_F], _F]:
    """Decorate a Flask view so it serves only after an x402 ``batch-settlement`` payment.

    Before the view it verifies the voucher (or payer proof) and reserves the
    price on the channel, attaching a :class:`~solana_pay_kit.usage.Charge`
    (read it with :func:`charge`). After a 2xx view it commits the charge;
    otherwise the reservation is released. Server-signed requests are metered:
    the view MUST call ``charge.charge(actual)`` (``0`` is allowed), else the
    body is withheld (402). A refund is answered without running the view.
    """

    def decorator(view: _F) -> _F:
        @wraps(view)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            from solana_pay_kit.gate import Gate as _Gate
            from solana_pay_kit.protocols.x402.batch_settlement import batch_engine
            from solana_pay_kit.protocols.x402.batch_settlement.engine import CorrectiveRequired, VerifiedBatchRequest

            request = flask.request
            engine = batch_engine(config if config is not None else _global_config())
            gate = gate_ref if isinstance(gate_ref, _Gate) else gate_ref(request)
            if not engine.detect_batch(request):
                _abort_batch_required(engine, gate, request, voucher_signer)
            try:
                verified = _run(engine.verify_and_reserve(gate, request, voucher_signer=voucher_signer))
            except CorrectiveRequired as exc:
                _abort_batch_required(engine, gate, request, voucher_signer, exc, exc.accepts)
            except InvalidProofError as exc:
                _abort_batch_required(engine, gate, request, voucher_signer, exc)
            except PayKitError as exc:
                _abort_pay_kit_error(exc)
            if not isinstance(verified, VerifiedBatchRequest):
                # A refund is a payment-control operation: the view is bypassed.
                closed = make_response("channel close initiated", 200)
                closed.headers.update(engine.settlement_headers(verified))
                return closed

            meter = Charge(verified.ceiling)
            setattr(request, CHARGE_ATTR, meter)
            setattr(g, CHARGE_ATTR, meter)
            try:
                response = make_response(view(*args, **kwargs))
            except BaseException:
                # A failed view charges nothing; the reservation also expires on its own.
                with contextlib.suppress(Exception):
                    _run(engine.release(verified))
                raise
            if not 200 <= response.status_code < 300:
                _run(engine.release(verified))
                return response
            outcome = _run(finalize_batch(engine, verified, meter))
            if not outcome.ok:
                logger.warning("solana_pay_kit: withholding a batch-settlement body: %s", outcome.detail)
                body = {"error": "payment_required", "code": outcome.code}
                withheld = make_response(flask.jsonify(body), outcome.status)
                withheld.headers.update(engine.challenge_headers(gate, request, error=outcome.code))
                abort(withheld)
            for header, value in outcome.settlement_headers.items():
                response.headers[header] = value
            return response

        return wrapper  # type: ignore[return-value]

    return decorator


#: FastAPI-parity alias; the Flask form is a view decorator, not a dependency.
RequireBatch = require_batch


def payment() -> Payment | None:
    """The verified payment attached to the current request, or ``None``."""
    value = getattr(g, PAYMENT_ATTR, None)
    return value if isinstance(value, Payment) else None


def charge() -> Charge | None:
    """The usage :class:`~solana_pay_kit.usage.Charge` meter for the request, or ``None``."""
    value = getattr(g, CHARGE_ATTR, None)
    return value if isinstance(value, Charge) else None


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
    logger.warning("solana_pay_kit: refusing a request: %s", exc)
    body: dict[str, Any] = {"error": code if isinstance(code, str) else "payment_error"}
    if isinstance(code, str):
        body["code"] = code
    response = make_response(flask.jsonify(body), status)
    abort(response)


def _abort_usage_required(
    engine: X402Upto,
    gate: Gate,
    request: Any,
    exc: InvalidProofError | None = None,
) -> NoReturn:
    """Render a 402 carrying the x402 upto challenge for a missing/invalid credential."""
    body: dict[str, Any] = {
        "error": "payment_required",
        "resource": request.path,
        "accepts": [engine.accepts_entry(gate, request)],
    }
    if exc is not None:
        body["code"] = exc.code or "invalid_proof"
        logger.warning("solana_pay_kit: refused an x402 upto credential: %s", exc)
    response = make_response(flask.jsonify(body), 402)
    for header, value in engine.challenge_headers(gate, request).items():
        response.headers[header] = value
    abort(response)


def _abort_batch_required(
    engine: X402BatchSettlement,
    gate: Gate,
    request: Any,
    voucher_signer: VoucherSigner | None,
    exc: InvalidProofError | None = None,
    accepts: list[BatchRequirements] | None = None,
) -> NoReturn:
    """Render a 402 carrying the ``batch-settlement`` challenge (corrective accepts when given)."""
    headers, body = batch_challenge(
        engine, gate, request, request.path, voucher_signer=voucher_signer, error=exc, accepts=accepts
    )
    response = make_response(flask.jsonify(body), 402)
    response.headers.update(headers)
    abort(response)


def _abort_usage_outcome(
    engine: X402Upto,
    gate: Gate,
    request: Any,
    outcome: Any,
) -> NoReturn:
    """Withhold the body with a 402 upto challenge when settlement fails closed."""
    logger.warning("solana_pay_kit: withholding an x402 upto body: %s", outcome.detail)
    body: dict[str, Any] = {"error": "payment_required", "code": outcome.code}
    response = make_response(flask.jsonify(body), outcome.status)
    for header, value in engine.challenge_headers(gate, request).items():
        response.headers[header] = value
    abort(response)


def _run(coro: Coroutine[Any, Any, _T]) -> _T:
    """Drive a solana_pay_kit async coroutine from Flask's synchronous view context.

    Catching the loop error around :func:`asyncio.run` would swallow the scheme
    errors that subclass ``RuntimeError`` (``StoreInvariantError``) and re-await
    a coroutine that is already consumed, so the loop is probed first.
    """
    return run_blocking(coro)
