"""FastAPI shim: a ``Depends``-compatible payment gate plus error mapping.

Optional dependency: install with ``pay_kit[fastapi]``. Importing this module
without FastAPI present raises a clear :class:`ImportError`.

Usage::

    from fastapi import FastAPI, Depends
    import pay_kit
    from pay_kit.fastapi import RequirePayment, install_exception_handler, payment

    pay_kit.configure(network="solana_localnet")
    app = FastAPI()
    install_exception_handler(app)

    @app.get("/report")
    async def report(payment=Depends(RequirePayment("report", pricing=pricing))):
        return {"ok": True, "tx": payment.transaction}

:func:`RequirePayment` returns a FastAPI dependency. On a missing/invalid proof
it raises ``fastapi.HTTPException`` carrying the 402 challenge headers and JSON
body; on success it attaches the verified :class:`~pay_kit.payment.Payment` to
``request.state`` (so :func:`payment` / the trio can read it) and schedules
the settlement headers to be merged onto the response (caveat #6: FastAPI/
Starlette lowercase header names at the boundary, so canonical casing is safe).
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any, cast

try:
    from fastapi import HTTPException, Request, Response
except ImportError as exc:  # pragma: no cover - exercised only without the extra
    raise ImportError("pay_kit.fastapi requires FastAPI; install with 'pay_kit[fastapi]'") from exc

from pay_kit._middleware import PAYMENT_ATTR, PayCore, payment
from pay_kit.config import config as _config
from pay_kit.errors import PayKitError, PaymentRequiredError
from pay_kit.payment import Payment

if TYPE_CHECKING:
    from pay_kit.config import Config
    from pay_kit.gate import DynamicGate, Gate
    from pay_kit.price import Price
    from pay_kit.pricing import Pricing

__all__ = ["RequirePayment", "install_exception_handler", "payment", "Payment"]

#: Header that carries each settlement header's name through the response hook.
_SETTLEMENT_STATE_ATTR = "paykit_settlement_headers"

GateRef = "Gate | DynamicGate | Price | str | Callable[[Request], Gate]"


def RequirePayment(  # noqa: N802 - factory reads as a dependency constructor
    gate_ref: Gate | DynamicGate | Price | str | Callable[[Request], Gate],
    *,
    pricing: Pricing | None = None,
    config: Config | None = None,
) -> Callable[..., Any]:
    """Build a FastAPI dependency that gates a route behind ``gate_ref``.

    The returned coroutine resolves and verifies payment on every request.
    Pass ``config`` to gate against a specific :class:`~pay_kit.config.Config`;
    otherwise the process-wide configured instance is used lazily at request
    time. On success the verified :class:`Payment` is returned (so the handler
    can ``Depends`` on it) and stashed on ``request.state`` for the trio.
    """

    async def dependency(request: Request) -> Payment:
        core = PayCore.for_config(config if config is not None else _config())
        try:
            payment = await core.process(gate_ref, pricing, request)
        except PaymentRequiredError as exc:
            raise _http_exception(exc) from exc
        except PayKitError as exc:
            raise _http_exception(exc) from exc

        setattr(request.state, PAYMENT_ATTR, payment)
        if payment.settlement_headers:
            setattr(
                request.state,
                _SETTLEMENT_STATE_ATTR,
                dict(payment.settlement_headers),
            )
        return payment

    return dependency


def install_exception_handler(app: Any) -> None:
    """Register handlers mapping :class:`PayKitError` to its HTTP status.

    Routes that gate imperatively (calling :func:`pay_kit.require_payment`
    inside the handler rather than via :func:`RequirePayment`) raise
    :class:`~pay_kit.errors.PayKitError` subclasses directly; this handler
    renders them with the correct status and (for a 402) challenge headers.
    Also installs a middleware that echoes settlement headers onto successful
    responses for gated routes.
    """

    @app.exception_handler(PayKitError)
    async def _paykit_error_handler(  # pyright: ignore[reportUnusedFunction]  # registered via @app.exception_handler
        _request: Request, exc: PayKitError
    ) -> Response:
        http_exc = _http_exception(exc)
        from fastapi.responses import JSONResponse

        return JSONResponse(
            status_code=http_exc.status_code,
            content=http_exc.detail,
            headers=http_exc.headers,
        )

    @app.middleware("http")
    async def _paykit_settlement_headers(  # pyright: ignore[reportUnusedFunction]  # registered via @app.middleware
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response = await call_next(request)
        settlement = getattr(request.state, _SETTLEMENT_STATE_ATTR, None)
        if isinstance(settlement, dict):
            for name, value in cast("dict[str, str]", settlement).items():
                response.headers[name] = value
        return response


def _http_exception(exc: PayKitError) -> HTTPException:
    """Translate a :class:`PayKitError` into a FastAPI ``HTTPException``.

    A 402 carries the challenge headers and JSON body the core stashed on the
    :class:`~pay_kit.errors.PaymentRequiredError`; other errors render a compact
    ``{"error": ...}`` detail keyed by the error's canonical code when present.
    """
    status = getattr(exc, "http_status", 500)
    headers = getattr(exc, "challenge_headers", None)
    body = getattr(exc, "body", None)

    detail: dict[str, Any]
    if isinstance(body, dict):
        detail = cast("dict[str, Any]", body)
    else:
        code = getattr(exc, "code", None)
        detail = {"error": code or "payment_error", "message": str(exc)}

    return HTTPException(
        status_code=status,
        detail=detail,
        headers=cast("dict[str, str]", headers) if isinstance(headers, dict) else None,
    )
