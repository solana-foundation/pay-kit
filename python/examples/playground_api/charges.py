# examples/playground_api/charges.py
"""The two charge-gated demo endpoints, gated through the ``pay_kit`` umbrella
surface: a single-recipient stock quote and a multi-recipient marketplace
purchase with split fees. The 402 challenge fires before any handler body runs.

Mirrors the TypeScript example's ``modules/charges.ts``. The umbrella
:func:`RequirePayment` dependency stands in for Express's ``requirePayment``
middleware: a per-request gate builder reads the path/query and returns a
fully-validated :class:`Gate`. The unknown-product guard is declared ahead of
the payment dependency so the 404 fires before the 402.

The stock quote pulls live market data from the ``yfinance`` library (the
Python counterpart to the TypeScript example's ``yahoo-finance2``). A lookup
failure degrades gracefully so the example still runs offline: an unknown
symbol is a 404 and a network outage returns a small safe default.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse

import pay_kit
from pay_kit import Gate, Price, usd
from pay_kit.fastapi import RequirePayment, payment

from . import constants
from .utils import json_error, log_tx

# --- marketplace catalog ----------------------------------------------------


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


def _bps(price: Price, basis_points: int) -> Price:
    """Return the given basis-point percentage of a price, e.g.
    ``_bps(usd 2.00, 500)`` is ``usd 0.10``.
    """
    return usd((price.amount * Decimal(basis_points)) / Decimal(10_000))


def _display_usd(price: Price) -> str:
    """Render a price as the playground's two-decimal USDC label."""
    return f"{price.amount:.2f} USDC"


def _quote(symbol: str) -> dict[str, Any]:
    """Live quote via ``yfinance.Ticker.info``; a 404 for an unknown symbol and
    a safe default when the network is unreachable so the example runs offline.
    """
    import yfinance as yf

    sym = symbol.upper()
    try:
        info = yf.Ticker(sym).info
    except Exception:  # noqa: BLE001 (offline / lib error -> safe default)
        return {"symbol": sym, "regularMarketPrice": 150.0, "currency": "USD"}
    price = info.get("regularMarketPrice") or info.get("currentPrice")
    if price is None:
        raise HTTPException(status_code=404, detail=json_error(f"Unknown symbol: {sym}"))
    return info


# --- registration -----------------------------------------------------------


def register_charges(app: FastAPI, state: Any) -> None:
    """Mount the stock-quote and marketplace charge routes plus the free
    product catalog.

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

    def _require_known_product(productId: str) -> None:  # noqa: N803 (mirrors the route path param)
        if productId not in _PRODUCTS:
            raise HTTPException(status_code=404, detail=json_error("Product not found"))

    # -- stock quote: single-recipient charge --------------------------------

    def _quote_gate(request: Request) -> Gate:
        return Gate.build(
            name="stockQuote",
            amount=usd("0.01"),
            description=f"Stock quote: {request.path_params['symbol']}",
            default_pay_to=platform,
            accept_default=accept_default,
        )

    @app.get("/api/v1/stocks/quote/{symbol}", dependencies=[Depends(RequirePayment(_quote_gate))])
    async def stock_quote(request: Request, symbol: str) -> JSONResponse:
        _log_settlement(request)
        return JSONResponse(await run_in_threadpool(_quote, symbol))

    # -- marketplace: free catalog plus a split-fee purchase -----------------

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
