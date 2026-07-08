"""FastAPI shim: a ``Depends``-compatible payment gate plus error mapping.

Optional dependency: install with ``solana_pay_kit[fastapi]``. Importing this module
without FastAPI present raises a clear :class:`ImportError`.

Usage::

    from fastapi import FastAPI, Depends
    import solana_pay_kit
    from solana_pay_kit.fastapi import RequirePayment, install_exception_handler, payment

    solana_pay_kit.configure(network="solana_localnet")
    app = FastAPI()
    install_exception_handler(app)

    @app.get("/report")
    async def report(payment=Depends(RequirePayment("report", pricing=pricing))):
        return {"ok": True, "tx": payment.transaction}

:func:`RequirePayment` returns a FastAPI dependency. On a missing/invalid proof
it raises ``fastapi.HTTPException`` carrying the 402 challenge headers and JSON
body; on success it attaches the verified :class:`~solana_pay_kit.payment.Payment` to
``request.state`` (so :func:`payment` / the trio can read it) and schedules
the settlement headers to be merged onto the response (caveat #6: FastAPI/
Starlette lowercase header names at the boundary, so canonical casing is safe).
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal, cast

try:
    from fastapi import HTTPException, Request, Response
except ImportError as exc:  # pragma: no cover - exercised only without the extra
    raise ImportError("solana_pay_kit.fastapi requires FastAPI; install with 'solana_pay_kit[fastapi]'") from exc

import weakref

from starlette.routing import Match

from solana_pay_kit._middleware import PAYMENT_ATTR, PayCore, payment
from solana_pay_kit.config import config as _config
from solana_pay_kit.errors import InvalidProofError, PayKitError, PaymentRequiredError
from solana_pay_kit.payment import Payment
from solana_pay_kit.usage import CHARGE_ATTR, Charge, fetch_recent_blockhash_and_slot, finalize_usage

if TYPE_CHECKING:
    from solana_pay_kit.config import Config, PayConfig
    from solana_pay_kit.gate import DynamicGate, Gate
    from solana_pay_kit.price import Price
    from solana_pay_kit.pricing import Pricing
    from solana_pay_kit.protocols.mpp.server import Session, SessionChallengeOptions
    from solana_pay_kit.protocols.x402.upto import X402Upto

__all__ = [
    "RequirePayment",
    "RequireSession",
    "RequireUsage",
    "PaywallConfig",
    "install_exception_handler",
    "install_paywall",
    "install_paywall_from_config",
    "pay_not_required",
    "pay_required",
    "payment",
    "Payment",
    "Charge",
]

#: Request-state attribute holding a pending usage settlement
#: ``(engine, verified, charge, gate)`` set by :func:`RequireUsage` and drained
#: by the usage-settlement middleware after the handler returns.
_USAGE_STATE_ATTR = "paykit_usage_pending"

#: App-state marker set by :func:`install_exception_handler` once the usage
#: settle-after middleware is registered. :func:`RequireUsage` checks it and
#: refuses to open a channel when the middleware is absent (else settlement
#: would never run and the deposit would stay locked).
_USAGE_READY_ATTR = "paykit_usage_settle_installed"

#: One x402 ``upto`` engine per Config - it owns the per-channel in-flight
#: reservation set, so it must be a singleton (a fresh engine per request would
#: not dedupe concurrent settlements on the same channel).
_UPTO_CACHE: weakref.WeakKeyDictionary[Config, X402Upto] = weakref.WeakKeyDictionary()


def _upto_engine(config: Config) -> X402Upto:
    cached = _UPTO_CACHE.get(config)
    if cached is not None:
        return cached
    from solana_pay_kit.protocols.x402.upto import X402Upto

    # Pre-fetch ``extra.recentBlockhash`` and ``extra.recentSlot`` (one
    # getLatestBlockhash call) from the configured RPC so the client can build
    # the channel-open without an extra round-trip (parity with the harness
    # server; the helper degrades to None on any RPC failure).
    engine = X402Upto(
        config,
        recent_state_provider=lambda: fetch_recent_blockhash_and_slot(config.effective_rpc_url()),
    )
    _UPTO_CACHE[config] = engine
    return engine


#: Header that carries each settlement header's name through the response hook.
_SETTLEMENT_STATE_ATTR = "paykit_settlement_headers"

GateRef = "Gate | DynamicGate | Price | str | Callable[[Request], Gate]"

PaywallDefaultPolicy = Literal["public", "paid"]

_PAYWALL_REQUIRED_ATTR = "__solana_pay_kit_pay_required__"
_PAYWALL_NOT_REQUIRED_ATTR = "__solana_pay_kit_pay_not_required__"


@dataclass(frozen=True)
class _PaywallRequirement:
    """Route-level paywall metadata written by :func:`pay_required`."""

    gate_ref: Gate | DynamicGate | Price | str | Callable[[Request], Gate] | None = None
    pricing: Pricing | None = None
    config: Config | None = None


@dataclass(frozen=True)
class PaywallConfig:
    """Application-level paywall policy for :func:`install_paywall_from_config`.

    ``default_policy="public"`` mirrors DRF's default-open permission model:
    only endpoints marked with :func:`pay_required` or a paid tag are gated.
    ``default_policy="paid"`` mirrors Django's ``LoginRequiredMiddleware``:
    every matched route is gated unless it is marked with :func:`pay_not_required`
    or a public tag.
    """

    gate_ref: Gate | DynamicGate | Price | str | Callable[[Request], Gate] | None = None
    pricing: Pricing | None = None
    config: Config | None = None
    default_policy: PaywallDefaultPolicy = "public"
    paid_tags: tuple[str, ...] = ("paid", "pay")
    public_tags: tuple[str, ...] = ("public", "free")


def pay_required(
    gate_ref: Gate | DynamicGate | Price | str | Callable[[Request], Gate] | None = None,
    *,
    pricing: Pricing | None = None,
    config: Config | None = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Mark a FastAPI endpoint as payment-required.

    The route can supply its own gate, or omit ``gate_ref`` to inherit the
    application default from :class:`PaywallConfig`. This decorator only writes
    metadata; :func:`install_paywall_from_config` performs the enforcement.
    """

    def decorator(endpoint: Callable[..., Any]) -> Callable[..., Any]:
        setattr(
            endpoint,
            _PAYWALL_REQUIRED_ATTR,
            _PaywallRequirement(gate_ref=gate_ref, pricing=pricing, config=config),
        )
        return endpoint

    return decorator


def pay_not_required() -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Mark a FastAPI endpoint as public when the default paywall policy is paid."""

    def decorator(endpoint: Callable[..., Any]) -> Callable[..., Any]:
        setattr(endpoint, _PAYWALL_NOT_REQUIRED_ATTR, True)
        return endpoint

    return decorator


def RequirePayment(  # noqa: N802 - factory reads as a dependency constructor
    gate_ref: Gate | DynamicGate | Price | str | Callable[[Request], Gate],
    *,
    pricing: Pricing | None = None,
    config: Config | None = None,
) -> Callable[..., Any]:
    """Build a FastAPI dependency that gates a route behind ``gate_ref``.

    The returned coroutine resolves and verifies payment on every request.
    Pass ``config`` to gate against a specific :class:`~solana_pay_kit.config.Config`;
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


def RequireSession(  # noqa: N802 - factory reads as a dependency constructor
    session: Session,
    challenge_options: SessionChallengeOptions,
) -> Callable[..., Any]:
    """Build a FastAPI dependency that gates a route behind an MPP session.

    The returned coroutine reads the ``Authorization`` header and runs the
    framework-agnostic :meth:`~solana_pay_kit.protocols.mpp.server.Session.handle` gate.
    On a missing or invalid credential it raises ``HTTPException`` carrying the
    402 challenge headers and problem body; on success it schedules the receipt
    headers to be merged onto the response (the same settlement-header echo path
    :func:`RequirePayment` uses) and returns the receipt headers dict, so a
    handler can ``Depends`` on it to attach them to a ``StreamingResponse``.
    """
    from solana_pay_kit.protocols.mpp.core.headers import AUTHORIZATION_HEADER

    async def dependency(request: Request) -> dict[str, str]:
        auth = request.headers.get(AUTHORIZATION_HEADER)
        result = await session.handle(auth, challenge_options)
        if not result.ok:
            raise HTTPException(result.status, detail=result.body, headers=result.headers)
        setattr(request.state, _SETTLEMENT_STATE_ATTR, dict(result.headers))
        return result.headers

    return dependency


def RequireUsage(  # noqa: N802 - factory reads as a dependency constructor
    gate_ref: Gate | Callable[[Request], Gate],
    *,
    config: Config | None = None,
) -> Callable[..., Any]:
    """Build a FastAPI dependency that gates a route behind an x402 ``upto`` usage gate.

    On a missing/invalid credential it raises ``HTTPException`` carrying the 402
    upto challenge. On success it opens + binds the payment channel, attaches a
    :class:`~solana_pay_kit.usage.Charge` meter to ``request.state`` (read it with
    :func:`~solana_pay_kit.usage.charge_from`, or ``Depends`` on this), and registers a
    pending settlement that the usage middleware finalizes after the handler
    returns. The handler MUST call ``charge.charge(actual_base_units)`` with a
    positive amount before returning, else the response is withheld (fail-closed)
    and the channel is sealed with a full refund. Requires :func:`install`
    (or :func:`install_exception_handler`) so the settlement middleware runs.
    """

    async def dependency(request: Request) -> Charge:
        from solana_pay_kit.gate import Gate as _Gate

        # Refuse to open a channel if the settle-after middleware is not installed:
        # otherwise the handler runs, the channel opens, but settlement never fires
        # and the payer deposit stays locked until the channel times out.
        if not getattr(request.app.state, _USAGE_READY_ATTR, False):
            raise RuntimeError(
                "solana_pay_kit.fastapi.RequireUsage needs the settlement middleware; "
                "call solana_pay_kit.fastapi.install(app) or install_exception_handler(app) at startup."
            )
        cfg = config if config is not None else _config()
        engine = _upto_engine(cfg)
        gate = gate_ref if isinstance(gate_ref, _Gate) else gate_ref(request)
        if not engine.detect_usage(request):
            raise _http_exception(_usage_challenge(engine, gate, request))
        try:
            verified = await engine.verify_open(gate, request)
        except PaymentRequiredError as exc:
            raise _http_exception(_usage_challenge(engine, gate, request)) from exc
        except InvalidProofError as exc:
            raise _http_exception(_usage_challenge(engine, gate, request, exc)) from exc
        charge = Charge(verified.max_amount)
        setattr(request.state, CHARGE_ATTR, charge)
        setattr(request.state, _USAGE_STATE_ATTR, (engine, verified, charge, gate))
        return charge

    return dependency


def _usage_challenge(
    engine: X402Upto,
    gate: Gate,
    request: Request,
    exc: InvalidProofError | None = None,
) -> PaymentRequiredError:
    """Build a 402 PaymentRequiredError carrying the upto challenge for the shim."""
    err = PaymentRequiredError("solana_pay_kit: payment required")
    body: dict[str, Any] = {
        "error": "payment_required",
        "resource": request.url.path,
        "accepts": [engine.accepts_entry(gate, request)],
    }
    if exc is not None:
        body["code"] = exc.code or "invalid_proof"
        body["message"] = str(exc)
    err.challenge_headers = engine.challenge_headers(gate, request)  # type: ignore[attr-defined]
    err.body = body  # type: ignore[attr-defined]
    return err


#: Response headers carrying MPP/x402 payment challenges and settlement proofs.
#: A browser client reading them cross-origin needs them in the CORS expose list.
PAYMENT_HEADERS: tuple[str, ...] = (
    "www-authenticate",
    "payment-receipt",
    "x-payment-required",
    "x-payment-response",
)


def install_paywall_from_config(
    app: Any,
    paywall: PaywallConfig,
    *,
    cors_origins: Sequence[str] | None = ("*",),
) -> None:
    """Install a Django/DRF-style paywall over an existing FastAPI app.

    The middleware inspects FastAPI's actual route table for the current
    request, then applies the route metadata from :func:`pay_required`,
    :func:`pay_not_required`, route tags, and the configured default policy.
    This avoids duplicating endpoint paths in a separate payment allowlist.
    """
    if paywall.default_policy not in ("public", "paid"):
        raise ValueError("solana_pay_kit.fastapi: default_policy must be 'public' or 'paid'")

    install_exception_handler(app)

    @app.middleware("http")
    async def _paykit_paywall(  # pyright: ignore[reportUnusedFunction]  # registered via @app.middleware
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        route = _matched_route(app, request)
        requirement = _paywall_requirement(paywall, route)
        if requirement is None:
            return await call_next(request)

        gate_ref = requirement.gate_ref if requirement.gate_ref is not None else paywall.gate_ref
        if gate_ref is None:
            raise RuntimeError(
                "solana_pay_kit.fastapi: a paid route needs a gate_ref; "
                "set PaywallConfig(gate_ref=...) or pass one to pay_required(...)"
            )
        pricing = requirement.pricing if requirement.pricing is not None else paywall.pricing
        config = requirement.config if requirement.config is not None else paywall.config
        core = PayCore.for_config(config if config is not None else _config())

        try:
            verified = await core.process(gate_ref, pricing, request)
        except PayKitError as exc:
            http_exc = _http_exception(exc)
            from fastapi.responses import JSONResponse

            return JSONResponse(
                http_exc.detail,
                status_code=http_exc.status_code,
                headers=http_exc.headers,
            )

        setattr(request.state, PAYMENT_ATTR, verified)
        if verified.settlement_headers:
            setattr(request.state, _SETTLEMENT_STATE_ATTR, dict(verified.settlement_headers))

        return await call_next(request)

    if cors_origins is not None:
        from fastapi.middleware.cors import CORSMiddleware

        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(cors_origins),
            allow_methods=["*"],
            allow_headers=["*"],
            expose_headers=list(PAYMENT_HEADERS),
        )


def install_paywall(
    app: Any,
    config: PayConfig | Mapping[str, Any],
    *,
    env_prefix: str | None = None,
    default_policy: PaywallDefaultPolicy = "public",
    paid_tags: tuple[str, ...] = ("paid", "pay"),
    public_tags: tuple[str, ...] = ("public", "free"),
    cors_origins: Sequence[str] | None = ("*",),
) -> None:
    """Install a route-metadata paywall from app-level Pay settings.

    ``config`` may be a :class:`~solana_pay_kit.config.PayConfig` or a plain
    mapping loaded from TOML/YAML/env. Disabled configs are a no-op.
    """
    from solana_pay_kit.config import PayConfig as _PayConfig

    pay_config = _PayConfig.from_sources(config, env_prefix=env_prefix)
    if not pay_config.enabled:
        return

    install_paywall_from_config(
        app,
        PaywallConfig(
            gate_ref=pay_config.gate_ref(),
            config=pay_config.build_config(preserve_global=True),
            default_policy=default_policy,
            paid_tags=paid_tags,
            public_tags=public_tags,
        ),
        cors_origins=cors_origins,
    )


def install(app: Any, *, cors_origins: Sequence[str] | None = ("*",)) -> None:
    """One-call FastAPI setup for a pay-kit server.

    Bundles what every pay-kit FastAPI server otherwise repeats by hand:

    * CORS that exposes the payment challenge / settlement headers
      (:data:`PAYMENT_HEADERS`) so a browser client can read them cross-origin.
      Pass ``cors_origins=None`` to skip CORS (e.g. behind a gateway that adds
      it), or a concrete origin list to lock it down.
    * the :class:`~solana_pay_kit.errors.PayKitError` -> HTTP handler and the
      settlement-header echo middleware (see :func:`install_exception_handler`).
    * an ``HTTPException`` handler that renders a ``dict`` detail as the bare
      response body, so a guard raising ``HTTPException(detail={"error": ...})``
      keeps that shape instead of Starlette's ``{"detail": {...}}`` wrapper.

    Usage::

        app = FastAPI()
        solana_pay_kit.fastapi.install(app)
    """
    if cors_origins is not None:
        from fastapi.middleware.cors import CORSMiddleware

        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(cors_origins),
            allow_methods=["*"],
            allow_headers=["*"],
            expose_headers=list(PAYMENT_HEADERS),
        )

    install_exception_handler(app)

    from fastapi.responses import JSONResponse
    from starlette.exceptions import HTTPException as StarletteHTTPException

    @app.exception_handler(StarletteHTTPException)
    async def _http_exception_handler(  # pyright: ignore[reportUnusedFunction]  # registered via @app.exception_handler
        _request: Request, exc: StarletteHTTPException
    ) -> Response:
        body = exc.detail if isinstance(exc.detail, dict) else {"error": exc.detail}
        return JSONResponse(body, status_code=exc.status_code, headers=getattr(exc, "headers", None))


def install_exception_handler(app: Any) -> None:
    """Register handlers mapping :class:`PayKitError` to its HTTP status.

    Routes that gate imperatively (calling :func:`solana_pay_kit.require_payment`
    inside the handler rather than via :func:`RequirePayment`) raise
    :class:`~solana_pay_kit.errors.PayKitError` subclasses directly; this handler
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

    @app.middleware("http")
    async def _paykit_usage_settle(  # pyright: ignore[reportUnusedFunction]  # registered via @app.middleware
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        import contextlib

        from fastapi.responses import JSONResponse

        try:
            response = await call_next(request)
        except BaseException:
            # The channel is open on-chain; settle 0 (seal + full refund) so
            # an abandoned request never leaves the deposit locked.
            pending = getattr(request.state, _USAGE_STATE_ATTR, None)
            if pending is not None:
                setattr(request.state, _USAGE_STATE_ATTR, None)
                engine, verified, _charge, _gate = pending
                # best-effort finalize on handler failure
                with contextlib.suppress(Exception):
                    await engine.settle_actual(verified, 0)
            raise
        pending = getattr(request.state, _USAGE_STATE_ATTR, None)
        if pending is None:
            return response
        setattr(request.state, _USAGE_STATE_ATTR, None)
        engine, verified, charge, gate = pending
        outcome = await finalize_usage(engine, verified, charge)
        if not outcome.ok:
            return JSONResponse(
                {"error": "payment_required", "code": outcome.code, "message": outcome.detail or ""},
                status_code=outcome.status,
                headers=engine.challenge_headers(gate, request),
            )
        for name, value in outcome.settlement_headers.items():
            response.headers[name] = value
        return response

    # Mark the app so RequireUsage knows the settle-after middleware is live.
    if hasattr(app, "state"):
        setattr(app.state, _USAGE_READY_ATTR, True)


def _matched_route(app: Any, request: Request) -> object | None:
    """Return the Starlette route that would handle ``request``, if any."""
    return _matched_route_in_routes(cast("Iterable[object]", getattr(app, "routes", ())), request.scope)


def _matched_route_in_routes(routes: Iterable[object], scope: Mapping[str, Any]) -> object | None:
    """Return the deepest matched route for ``scope``, including mounted apps."""
    for route in routes:
        matcher = getattr(route, "matches", None)
        if not callable(matcher):
            continue
        try:
            match, child_scope = cast("tuple[Match, dict[str, Any]]", matcher(scope))
        except Exception:  # pragma: no cover - defensive for third-party routes
            continue
        if match is Match.FULL:
            endpoint = child_scope.get("endpoint")
            child_routes = getattr(endpoint, "routes", None)
            if child_routes is not None:
                child_route = _matched_route_in_routes(
                    cast("Iterable[object]", child_routes),
                    {**scope, **child_scope},
                )
                return child_route
            return route
    return None


def _paywall_requirement(
    paywall: PaywallConfig,
    route: object | None,
) -> _PaywallRequirement | None:
    """Resolve whether a matched route should be pay-gated."""
    if route is None:
        return None

    if _endpoint_attr(route, _PAYWALL_NOT_REQUIRED_ATTR) is True:
        return None

    requirement = _endpoint_attr(route, _PAYWALL_REQUIRED_ATTR)
    if isinstance(requirement, _PaywallRequirement):
        return requirement

    tags = _route_tags(route)
    if any(tag in paywall.public_tags for tag in tags):
        return None
    if any(tag in paywall.paid_tags for tag in tags):
        return _PaywallRequirement()

    if paywall.default_policy == "paid":
        return _PaywallRequirement()
    return None


def _endpoint_attr(route: object, name: str) -> object:
    """Read metadata from a route endpoint, including bound methods."""
    endpoint = getattr(route, "endpoint", None)
    if endpoint is None:
        return None
    value = getattr(endpoint, name, None)
    if value is not None:
        return value
    function = getattr(endpoint, "__func__", None)
    if function is not None:
        return getattr(function, name, None)
    return None


def _route_tags(route: object) -> tuple[str, ...]:
    """Return FastAPI route tags as a string tuple."""
    raw_tags = getattr(route, "tags", ())
    if isinstance(raw_tags, (list, tuple, set)):
        tags = cast("list[object] | tuple[object, ...] | set[object]", raw_tags)
        return tuple(str(tag) for tag in tags)
    return ()


def _http_exception(exc: PayKitError) -> HTTPException:
    """Translate a :class:`PayKitError` into a FastAPI ``HTTPException``.

    A 402 carries the challenge headers and JSON body the core stashed on the
    :class:`~solana_pay_kit.errors.PaymentRequiredError`; other errors render a compact
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
