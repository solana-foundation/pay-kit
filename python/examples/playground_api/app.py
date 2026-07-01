# examples/playground_api/app.py
"""The pay-kit playground API (FastAPI), gated with the unified solana_pay_kit surface.

Aligned with the TypeScript playground (`typescript/examples/playground-api`):
one config boots the server and a small route catalogue exercises every gate the
Python SDK ships today.

    GET  /api/v1/fortune          fixed charge, MPP or x402 (client's choice)
    GET  /api/v1/quote/{symbol}   fixed charge, MPP or x402
    GET  /api/v1/joke             MPP charge with a platform split (x402 auto-off)
    GET  /api/v1/stream           MPP session: open a channel, stream metered SSE
    POST /api/v1/summarize        x402 upto: authorize a ceiling, bill metered tokens
    GET  /api/v1/docs[...]        unpaid SDK reference (docs.py)
    POST /api/v1/faucet/airdrop   localnet-only USDC faucet (sandbox.py)
    GET  /openapi.json            OpenAPI 3.1 discovery (x-payment-info offers)
    GET  /api/v1/health           free liveness probe + operator/network info

The x402 `upto` usage gate is served at `POST /api/v1/summarize` (mirrors the TS
playground). The MPP `subscription` gate (TS `/api/v1/feed`) is intentionally
absent: the Python SDK does not ship that gate kind yet.

Run:

    cd python
    uvicorn examples.playground_api.app:app --port 3000

Drive it:

    curl -i http://127.0.0.1:3000/api/v1/fortune     # 402 payment required
    pay curl http://127.0.0.1:3000/api/v1/fortune     # pays and succeeds
    curl -i -X POST http://127.0.0.1:3000/api/v1/summarize  # 402 x402 upto challenge
"""

from __future__ import annotations

import os
import random

from fastapi import Depends, FastAPI, Request

import solana_pay_kit
from solana_pay_kit import Gate, Pricing, usd
from solana_pay_kit._paycore.protocol import Protocol
from solana_pay_kit.fastapi import Charge, Payment, RequirePayment, RequireUsage, install

from . import discovery
from .docs import register_docs
from .sandbox import fund_sandbox, fund_usdc, register_faucet

solana_pay_kit.configure(
    network=os.getenv("PAY_KIT_NETWORK", "solana_localnet"),
    # Point at a specific Solana RPC (e.g. a local surfnet) when set; otherwise
    # the network default is used. Mirrors the TS playground's RPC_URL knob.
    rpc_url=os.getenv("PAY_KIT_RPC_URL") or None,
)

# Imported after configure() so the session method builds from the resolved
# operator / recipient / challenge-binding secret.
from . import sessions  # noqa: E402

_cfg = solana_pay_kit.config()
_RECIPIENT = _cfg.effective_recipient()
# A second recipient for the split demo (the platform's cut). A fixed, valid
# base58 pubkey distinct from the operator/recipient.
PLATFORM = "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin"


class Catalog(Pricing):
    """The route catalogue: every charge-gated route declares its gate here."""

    def __init__(self) -> None:
        defaults = {"default_pay_to": _RECIPIENT, "accept_default": _cfg.accept}
        # Fixed charges, settled over whichever protocol the client picks.
        self.fortune = Gate.build(name="fortune", amount=usd("0.01"), description="A fortune cookie", **defaults)
        self.quote = Gate.build(name="quote", amount=usd("0.01"), description="Stock quote", **defaults)
        # MPP charge with a split: the platform takes 0.003 of the 0.01, the
        # seller (operator) nets 0.007. Multi-recipient splits are not expressible
        # in x402 `exact`, so this gate names MPP explicitly (a fee gate that
        # inherited the default accept would be rejected for still listing x402).
        self.joke = Gate.build(
            name="joke",
            amount=usd("0.01"),
            description="A programmer joke",
            external_id="paykit/joke: seller payout",
            fee_within={PLATFORM: usd("0.003")},
            accept=(Protocol.MPP,),
            default_pay_to=_RECIPIENT,
        )


catalog = Catalog()

# Module-level dependency singletons (FastAPI resolves them per request).
require_fortune = Depends(RequirePayment("fortune", pricing=catalog))
require_quote = Depends(RequirePayment("quote", pricing=catalog))
require_joke = Depends(RequirePayment("joke", pricing=catalog))

# x402 `upto` usage gate (POST /api/v1/summarize): authorize up to $0.10 and bill
# the tokens produced. Mirrors the TypeScript playground's summarize route.
summarize_gate = Gate.build(
    name="summarize",
    amount=usd("0.10"),
    description="Summarize text, billed per token",
    default_pay_to=_RECIPIENT,
    accept=(Protocol.X402,),
)
require_summarize = Depends(RequireUsage(summarize_gate))

#: Base units billed per summarized token (matches the TS playground).
PRICE_PER_TOKEN = 100

JOKES = (
    "Why do programmers prefer dark mode? Because light attracts bugs.",
    'A SQL query walks into a bar, sees two tables, and asks: "Can I JOIN you?"',
    "There are 10 kinds of people: those who understand binary and those who don't.",
)
FORTUNES = (
    "A smooth long journey! Great expectations.",
    "Your code will compile on the first try today.",
    "A thrilling time is in your immediate future.",
    "The settlement you await will confirm on-chain.",
)

# `openapi_url=None` frees /openapi.json for our discovery document (below);
# FastAPI's auto-generated schema would otherwise own that path.
app = FastAPI(title="PayKit Playground (Python)", openapi_url=None)
# One-call setup: payment-header CORS + the PayKitError -> 402 challenge mapping.
install(app)
app.include_router(sessions.router)


# ── Priced routes ──
# Paths are generic (/api/v1/<name>); the protocol + scheme each route accepts is
# carried by the discovery offers (method/scheme), not the URL.


@app.get("/api/v1/fortune")
async def fortune(_payment: Payment = require_fortune) -> dict[str, str]:
    """Fixed charge, settled over whichever protocol the client picks."""
    return {"fortune": random.choice(FORTUNES)}


@app.get("/api/v1/quote/{symbol}")
async def quote(symbol: str, payment: Payment = require_quote) -> dict[str, object]:
    """Fixed charge. ``via`` reports which protocol settled the request."""
    sym = symbol.upper()
    return {"price": 100 + (ord(sym[0]) % 50) if sym else 100, "symbol": sym, "via": payment.protocol.value}


@app.get("/api/v1/joke")
async def joke(_payment: Payment = require_joke) -> dict[str, str]:
    """MPP charge with a platform split (seller nets 0.007, platform 0.003)."""
    return {"joke": random.choice(JOKES)}


@app.post("/api/v1/summarize")
async def summarize(request: Request, charge: Charge = require_summarize) -> dict[str, object]:
    """x402 ``upto``: authorize up to $0.10, then bill the tokens produced.

    The client opens a channel for the ceiling; this handler meters the request
    (about one token per four bytes of body) and the gate settles only that
    amount after it returns, refunding the unused remainder.
    """
    raw = await request.body()
    text = raw.decode("utf-8", "replace") if raw else ""
    tokens = max(1, len(text) // 4)
    billed = tokens * PRICE_PER_TOKEN
    charge.charge(billed)
    return {"billedBaseUnits": str(billed), "summarizedBytes": len(text), "tokens": str(tokens)}


@app.get("/api/v1/health")
async def health_info() -> dict[str, object]:
    """Free liveness probe + operator/recipient/network info (no balance RPC)."""
    return {
        "feePayer": _cfg.operator.signer.pubkey(),
        "network": _cfg.network.value,
        "ok": True,
        "recipient": _RECIPIENT,
    }


# ── Docs + sandbox faucet ──
register_docs(app)
if _cfg.network.value == "solana_localnet":
    register_faucet(app, _cfg.effective_rpc_url())
    # Optional zero-config funding for a live localnet run. Off by default so the
    # smoke test (which boots the app) never touches the network.
    if os.getenv("PAY_KIT_PLAYGROUND_FUND") == "1":
        fund_sandbox(_cfg.effective_rpc_url(), _cfg.operator.signer.pubkey(), _RECIPIENT)
        # The split recipient only needs a USDC account to receive its cut (no SOL).
        fund_usdc(_cfg.effective_rpc_url(), PLATFORM)


# ── Discovery ──
# OpenAPI 3.1 with an `x-payment-info.offers` list per gated route, byte-aligned
# with the TS playground's /openapi.json (see discovery.py).
_OPENAPI = discovery.build_openapi_document(
    info={"title": "PayKit Playground", "version": "1.0.0"},
    routes=[
        {
            "method": "GET",
            "path": "/api/v1/fortune",
            "summary": catalog.fortune.description,
            "offers": discovery.charge_offers(catalog.fortune, _cfg),
        },
        {
            "method": "GET",
            "path": "/api/v1/quote/{symbol}",
            "summary": catalog.quote.description,
            "offers": discovery.charge_offers(catalog.quote, _cfg),
        },
        {
            "method": "GET",
            "path": "/api/v1/joke",
            "summary": catalog.joke.description,
            "offers": discovery.charge_offers(catalog.joke, _cfg),
        },
        {
            "method": "GET",
            "path": "/api/v1/stream",
            "summary": "Metered token stream",
            "offers": [
                discovery.session_offer(
                    _cfg,
                    cap_base_units="1000000",
                    unit_price_base_units="100",
                    pay_to=_RECIPIENT,
                )
            ],
        },
        {
            "method": "POST",
            "path": "/api/v1/summarize",
            "summary": summarize_gate.description,
            "offers": [discovery.upto_offer(summarize_gate, _cfg)],
        },
    ],
)


@app.get("/openapi.json")
async def openapi_discovery(_request: Request) -> dict[str, object]:
    """OpenAPI 3.1 discovery document (advisory; the 402 challenge is authoritative)."""
    return _OPENAPI
