# examples/playground_api/charges.py
"""Charge-gated endpoints: stock data, weather, a marketplace purchase with
multi-recipient splits (all gated through the ``pay_kit`` umbrella surface),
and the fortune payment link served straight from the protocol-layer MPP
server with the HTML challenge page enabled. The 402 challenge fires before
any handler body runs.

Mirrors the TypeScript example's ``modules/charges.ts``. The umbrella
:func:`RequirePayment` dependency stands in for Express's ``requirePayment``
middleware: a per-request gate builder reads the path/query and returns a
fully-validated :class:`Gate`. Guard dependencies (404 unknown city/product,
400 missing query) are declared ahead of the payment dependency so they fire
before the 402, matching the Express middleware ordering.

The stock routes serve canned demo data rather than a live market feed: the
example exists to exercise the payment gate, and the Python playground stays
network-free like its weather / marketplace / x402 routes.

The fortune route drops to the protocol layer (:class:`Mpp` with HTML enabled)
because the umbrella dispatcher renders the cross-SDK JSON challenge body;
dropping down a layer to serve the interactive payment page is the intended
escape hatch.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from decimal import Decimal
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response

import pay_kit
from pay_kit import Gate, Price, usd
from pay_kit._paycore.errors import PaymentError
from pay_kit._paycore.rpc import SolanaRpc
from pay_kit._paycore.store import MemoryStore
from pay_kit.fastapi import RequirePayment, payment
from pay_kit.protocols.mpp.core.headers import format_www_authenticate, parse_authorization
from pay_kit.protocols.mpp.intents.charge import ChargeRequest
from pay_kit.protocols.mpp.server import (
    ChargeOptions,
    Mpp,
    accepts_html,
    challenge_to_html,
    is_service_worker_request,
    service_worker_js,
)
from pay_kit.protocols.mpp.server import (
    Config as MppConfig,
)

from . import constants
from .utils import json_error, log_tx

# --- canned demo data -------------------------------------------------------

# The canned per-city weather payload: whole-degree C, sky label, % humidity.
_WEATHER_BY_CITY: dict[str, dict[str, Any]] = {
    "san-francisco": {"temperature": 15, "conditions": "Foggy", "humidity": 85},
    "new-york": {"temperature": 22, "conditions": "Partly Cloudy", "humidity": 60},
    "london": {"temperature": 12, "conditions": "Rainy", "humidity": 90},
    "tokyo": {"temperature": 26, "conditions": "Sunny", "humidity": 55},
    "paris": {"temperature": 18, "conditions": "Overcast", "humidity": 70},
    "sydney": {"temperature": 24, "conditions": "Clear", "humidity": 45},
    "berlin": {"temperature": 10, "conditions": "Cloudy", "humidity": 75},
    "dubai": {"temperature": 38, "conditions": "Sunny", "humidity": 30},
}


@dataclass(frozen=True)
class _Product:
    """One marketplace catalog entry.

    ``price`` is the seller's list price in USD; the platform and referral
    basis-point fees are charged on top of it, not carved out. ``seller`` is the
    base58 wallet that receives the list price as the charge's primary pay-to.
    """

    name: str
    price: Price
    seller: str
    description: str


# The canned marketplace catalog.
_PRODUCTS: dict[str, _Product] = {
    "sol-hoodie": _Product(
        name="Solana Hoodie",
        price=usd("2.00"),
        seller="7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
        description="Premium Solana-branded hoodie",
    ),
    "validator-mug": _Product(
        name="Validator Mug",
        price=usd("1.00"),
        seller="7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
        description="Ceramic mug for node operators",
    ),
    "nft-sticker-pack": _Product(
        name="NFT Sticker Pack",
        price=usd("0.50"),
        seller="7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
        description="Holographic sticker collection",
    ),
}

_PLATFORM_FEE_BPS = 500  # 5%
_REFERRAL_FEE_BPS = 200  # 2%

# The canned fortune-cookie pool.
_FORTUNES = [
    "A beautiful, smart, and loving person will be coming into your life.",
    "A faithful friend is a strong defense.",
    "A golden egg of opportunity falls into your lap this month.",
    "All your hard work will soon pay off.",
    "Curiosity kills boredom. Nothing can kill curiosity.",
    "Every day in your life is a special occasion.",
    "Good news will come to you by mail.",
    "If you continually give, you will continually have.",
]


def _bps(price: Price, basis_points: int) -> Price:
    """Return the given basis-point percentage of a price, e.g.
    ``_bps(usd 2.00, 500)`` is ``usd 0.10``.
    """
    return usd((price.amount * Decimal(basis_points)) / Decimal(10_000))


def _display_usd(price: Price) -> str:
    """Render a price as the playground's two-decimal USDC label."""
    return f"{price.amount:.2f} USDC"


def _city_key(city: str) -> str:
    """Normalize a city path segment onto the weather table key."""
    return city.lower().replace(" ", "-")


# --- registration -----------------------------------------------------------


def register_charges(app: FastAPI, state: Any) -> None:
    """Mount every charge-gated endpoint plus the free marketplace catalog.

    ``state`` is the :class:`~examples.playground_api.app.AppState`; typed
    loosely to avoid a circular import with the boot module.
    """
    platform = state.recipient
    accept_default = pay_kit.config().accept

    def _log_settlement(request: Request) -> None:
        """Surface the settlement signature once a gated handler runs."""
        proof = payment(request)
        if proof is not None and proof.transaction:
            log_tx(request.url.path, proof.transaction)

    # -- guard dependencies (run before the payment gate) --------------------

    def _require_query(name: str):  # noqa: ANN202 (returns a FastAPI dependency)
        def guard(request: Request) -> None:
            if not request.query_params.get(name):
                raise HTTPException(status_code=400, detail=json_error(f"Missing ?{name}= parameter"))

        return guard

    def _require_known_city(city: str) -> None:
        if _city_key(city) not in _WEATHER_BY_CITY:
            raise HTTPException(
                status_code=404,
                detail=json_error(f"City not found. Available: {', '.join(_WEATHER_BY_CITY)}"),
            )

    def _require_known_product(productId: str) -> None:  # noqa: N803 (mirrors the route path param)
        if productId not in _PRODUCTS:
            raise HTTPException(status_code=404, detail=json_error("Product not found"))

    # -- gate builders -------------------------------------------------------

    def _static_gate(name: str, amount: str, describe):  # noqa: ANN001, ANN202
        def builder(request: Request) -> Gate:
            return Gate.build(
                name=name,
                amount=usd(amount),
                description=describe(request),
                default_pay_to=platform,
                accept_default=accept_default,
            )

        return builder

    def _buy_gate(request: Request) -> Gate:
        product = _PRODUCTS[request.path_params["productId"]]  # validated by the guard dependency
        fee_on_top: dict[str, Price] = {platform: _bps(product.price, _PLATFORM_FEE_BPS)}
        referrer = request.query_params.get("referrer", "")
        if referrer:
            fee_on_top[referrer] = _bps(product.price, _REFERRAL_FEE_BPS)
        return Gate.build(
            name="marketplaceBuy",
            amount=product.price,
            pay_to=product.seller,
            description=f"Purchase: {product.name}",
            fee_on_top=fee_on_top,
            default_pay_to=platform,
            accept_default=accept_default,
        )

    # -- stocks (canned demo quotes) -----------------------------------------

    gate_stock_quote = RequirePayment(
        _static_gate("stockQuote", "0.01", lambda r: f"Stock quote: {r.path_params['symbol']}")
    )
    gate_stock_search = RequirePayment(
        _static_gate("stockSearch", "0.01", lambda r: f"Stock search: {r.query_params.get('q', '')}")
    )
    gate_stock_history = RequirePayment(
        _static_gate("stockHistory", "0.05", lambda r: f"Stock history: {r.path_params['symbol']}")
    )
    gate_weather = RequirePayment(_static_gate("weather", "0.01", lambda r: f"Weather for {r.path_params['city']}"))

    @app.get("/api/v1/stocks/quote/{symbol}", dependencies=[Depends(gate_stock_quote)])
    async def stock_quote(request: Request, symbol: str) -> JSONResponse:
        _log_settlement(request)
        return JSONResponse({"symbol": symbol.upper(), "regularMarketPrice": 150.0, "currency": "USD"})

    @app.get(
        "/api/v1/stocks/search",
        dependencies=[Depends(_require_query("q")), Depends(gate_stock_search)],
    )
    async def stock_search(request: Request) -> JSONResponse:
        _log_settlement(request)
        q = request.query_params.get("q", "")
        return JSONResponse([{"symbol": q.upper(), "shortname": q.upper(), "exchange": "NMS"}])

    @app.get("/api/v1/stocks/history/{symbol}", dependencies=[Depends(gate_stock_history)])
    async def stock_history(request: Request, symbol: str) -> JSONResponse:
        _log_settlement(request)
        return JSONResponse({"symbol": symbol.upper(), "quotes": [{"close": 150.0}]})

    # -- weather: unknown cities 404 before the payment gate -----------------

    @app.get(
        "/api/v1/weather/{city}",
        dependencies=[Depends(_require_known_city), Depends(gate_weather)],
    )
    async def weather(request: Request, city: str) -> JSONResponse:
        _log_settlement(request)
        return JSONResponse({"city": city, **_WEATHER_BY_CITY[_city_key(city)]})

    # -- marketplace: free catalog plus the split purchase -------------------

    @app.get("/api/v1/marketplace/products")
    async def marketplace_products() -> JSONResponse:
        listing = [
            {
                "id": product_id,
                "name": product.name,
                "description": product.description,
                "price": _display_usd(product.price),
                "priceRaw": str(int(product.price.amount * (Decimal(10) ** constants.USDC_DECIMALS))),
            }
            for product_id, product in _PRODUCTS.items()
        ]
        return JSONResponse(listing)

    @app.get(
        "/api/v1/marketplace/buy/{productId}",
        dependencies=[Depends(_require_known_product), Depends(RequirePayment(_buy_gate))],
    )
    async def marketplace_buy(request: Request, productId: str) -> JSONResponse:  # noqa: N803 (route path param)
        product = _PRODUCTS[productId]
        platform_fee = _bps(product.price, _PLATFORM_FEE_BPS)
        total = product.price.amount + platform_fee.amount
        breakdown = {
            "seller": _display_usd(product.price),
            "platformFee": _display_usd(platform_fee),
        }
        if request.query_params.get("referrer"):
            referral_fee = _bps(product.price, _REFERRAL_FEE_BPS)
            breakdown["referralFee"] = _display_usd(referral_fee)
            total += referral_fee.amount
        breakdown["total"] = f"{total:.2f} USDC"
        _log_settlement(request)
        return JSONResponse({"product": product.name, "breakdown": breakdown, "status": "purchased"})

    # -- fortune: a charge payment link with the interactive HTML challenge ---
    #
    # Stays on the protocol layer directly (Mpp with HTML enabled) because the
    # umbrella dispatcher renders the cross-SDK JSON challenge body; dropping
    # down a layer is the intended escape hatch for the interactive page.
    fortune_mpp = Mpp(
        MppConfig(
            recipient=state.recipient,
            currency="USDC",
            decimals=constants.USDC_DECIMALS,
            network=state.network,
            rpc_url=state.rpc_url,
            secret_key=state.secret_key,
            html=True,
            fee_payer_signer=state.fee_payer,
            store=MemoryStore(),
        )
    )

    @app.get("/api/v1/fortune")
    async def fortune(request: Request) -> Response:
        # The interactive payment page registers its service worker at scope
        # "/" from a script served under /api/v1/fortune, which browsers only
        # allow with this header.
        sw_header = {"Service-Worker-Allowed": "/"} if is_service_worker_request(str(request.url)) else {}
        challenge = fortune_mpp.charge_with_options("0.01", ChargeOptions(description="Open a fortune cookie"))

        auth_header = request.headers.get("authorization")
        if auth_header:
            try:
                credential = parse_authorization(auth_header)
                expected = ChargeRequest.from_dict(challenge.decode_request())
                rpc = SolanaRpc(state.rpc_url)
                try:
                    async with fortune_mpp.using_rpc(rpc):
                        receipt = await fortune_mpp.verify_credential_with_expected(credential, expected)
                finally:
                    await rpc.aclose()
            except PaymentError as err:
                return _fortune_challenge(request, challenge, state.network, fortune_mpp.rpc_url, sw_header, err)
            except Exception as err:  # noqa: BLE001 (framework/parse errors map to a 402)
                return _fortune_challenge(
                    request,
                    challenge,
                    state.network,
                    fortune_mpp.rpc_url,
                    sw_header,
                    PaymentError(str(err), code="payment_invalid"),
                )

            headers = dict(sw_header)
            if receipt.reference:
                headers["payment-receipt"] = receipt.reference
                log_tx(request.url.path, receipt.reference)
            return JSONResponse({"fortune": random.choice(_FORTUNES)}, headers=headers)

        return _fortune_challenge(request, challenge, state.network, fortune_mpp.rpc_url, sw_header, None)


# --- fortune 402 rendering --------------------------------------------------


def _fortune_challenge(
    request: Request,
    challenge: Any,
    network: str,
    rpc_url: str,
    extra_headers: dict[str, str],
    error: PaymentError | None,
) -> Response:
    """Render the fortune 402: the service-worker script on the SW request, the
    interactive HTML payment page when the client accepts HTML, otherwise the
    canonical JSON challenge body.
    """
    headers = dict(extra_headers)
    headers["www-authenticate"] = format_www_authenticate(challenge)
    headers["cache-control"] = "no-store"

    if is_service_worker_request(str(request.url)):
        return PlainTextResponse(service_worker_js(), media_type="application/javascript", headers=headers)

    if accepts_html(request.headers.get("accept")):
        return HTMLResponse(challenge_to_html(challenge, rpc_url, network), status_code=402, headers=headers)

    code = (error.code if error and error.code else None) or "payment_invalid"
    detail = (str(error) if error else None) or "Payment required"
    return JSONResponse(
        {
            "type": "about:blank",
            "title": "Payment Required",
            "status": 402,
            "code": code,
            "error": code,
            "detail": detail,
        },
        status_code=402,
        headers=headers,
    )
