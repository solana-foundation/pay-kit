# examples/playground_api/sessions.py
"""One metered-session route for the playground (FastAPI).

solana_pay_kit ships the session gate as ``RequireSession`` (the session counterpart of
the charge/x402 ``RequirePayment`` shim); sessions themselves live in
``solana_pay_kit.protocols.mpp.server`` as framework-agnostic primitives
(:func:`new_session`, :func:`session_routes`, :meth:`Session.handle`). So the
402 gate is one ``Depends(RequireSession(...))`` line: verify an
``Authorization`` credential, or answer 402 with a ``WWW-Authenticate``
challenge.

Boot config comes from ``solana_pay_kit.config()`` (the same resolved operator,
recipient, and challenge-binding secret the charge routes use), not hand-rolled
env wiring.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, StreamingResponse

import solana_pay_kit
from solana_pay_kit._paycore.rpc import SolanaRpc
from solana_pay_kit._paycore.solana import resolve_mint, stablecoin_decimals
from solana_pay_kit.fastapi import RequireSession
from solana_pay_kit.protocols.mpp.server import (
    SessionChallengeOptions,
    SessionOptions,
    new_session,
    session_routes,
)

router = APIRouter()

# One session method, built from the shared solana_pay_kit config. Each use costs
# 100 base units and the challenge suggests a 1.00 USDC channel deposit. The
# operator signer and RPC verify funding and settle the channel on-chain.
_cfg = solana_pay_kit.config()
session = new_session(
    SessionOptions(
        operator=_cfg.operator.signer.pubkey(),
        recipient=_cfg.effective_recipient(),
        amount=100,
        currency=resolve_mint("USDC", "mainnet"),
        decimals=stablecoin_decimals("USDC"),
        network=_cfg.network.value,
        secret_key=_cfg.mpp.challenge_binding_secret or "",
        suggested_deposit=1_000_000,
        signer=_cfg.operator.signer,
        rpc=SolanaRpc(_cfg.effective_rpc_url()),
        idle_timeout_seconds=2,
    )
)

_challenge = SessionChallengeOptions(description="Metered token stream")

# The session 402 gate, now shipped by the SDK: verify an Authorization
# credential (returning the receipt headers) or answer 402 with a fresh
# challenge. Mirrors what RequirePayment does for charge routes.
_gate = Depends(RequireSession(session, _challenge))

# Streamed deliveries, billed per chunk against the session voucher. Mirrors the
# TypeScript playground's `GET /api/v1/stream` (SSE) session route.
_TOKEN_CHUNKS = (
    "A payment channel ",
    "lets a client and server ",
    "authorize many small ",
    "off-chain debits ",
    "against a single on-chain ",
    "deposit, settling the highest ",
    "cumulative voucher at close.",
)
#: Per-chunk price in USDC base units (6 decimals): $0.0001.
_PRICE_PER_CHUNK = 100


@router.get("/api/v1/stream")
async def stream(headers: dict[str, str] = _gate) -> StreamingResponse:
    """Metered SSE stream: open a session, then emit per-chunk deliveries.

    Settlement runs out-of-band (the client commits vouchers via the side-channel
    routes below); each chunk advertises its per-delivery cost.
    """

    async def events() -> AsyncIterator[str]:
        for chunk in _TOKEN_CHUNKS:
            yield f"data: {json.dumps({'chunk': chunk, 'cost': str(_PRICE_PER_CHUNK)})}\n\n"
            await asyncio.sleep(0.08)  # pace deliveries, mirroring the TS stream
        yield "data: [DONE]\n\n"

    return StreamingResponse(events(), media_type="text/event-stream", headers=headers)


@router.post("/api/v1/stream")
async def stream_voucher(request: Request, headers: dict[str, str] = _gate) -> JSONResponse:
    """Voucher commit at the resource URL.

    The SessionFetch client re-POSTs each signed voucher (in the Authorization
    credential) to the URL it opened against; ``_gate`` verifies it (or answers
    402) and returns the receipt headers. Mirrors the TS ``streamRoutes.voucher``
    handler — without it the client's commit hits 405.
    """
    raw = await request.body()
    body = json.loads(raw) if raw else {}
    return JSONResponse(
        {
            "amount": str(body.get("amount", "0")),
            "deliveryId": str(body.get("deliveryId", "")),
            "status": "committed",
        },
        headers=headers,
    )


# Reserve/commit side channel: the shipped session_routes builder. The touch hook
# resets the idle-close watchdog after each reserve/commit so the channel settles
# only once deliveries stop.
_routes = session_routes(session.core(), touch=session._touch)


@router.post("/__402/session/deliveries")
async def deliveries(request: Request) -> JSONResponse:
    r = await _routes.deliveries(request.method, await request.body() or b"{}")
    return JSONResponse(r.body, status_code=r.status)


@router.post("/__402/session/commit")
async def commit(request: Request) -> JSONResponse:
    r = await _routes.commit(request.method, await request.body() or b"{}")
    return JSONResponse(r.body, status_code=r.status)


@router.get("/sessions/receipt/{channel_id}")
async def receipt(channel_id: str) -> JSONResponse:
    """Settle-status poll for a channel — mirrors the TS playground's receipt route.

    Settlement is out-of-band (idle-close watchdog), so a client polls this for
    the settled signature once the channel is sealed.
    """
    state = await session.core().store().get_channel(channel_id)
    if state is None:
        return JSONResponse({"error": "channel-not-found"}, status_code=404)
    return JSONResponse(
        {
            "channelId": channel_id,
            "cumulative": str(state.cumulative),
            "deposit": str(state.deposit),
            "sealed": state.sealed,
            "settledSignature": state.settled_signature,
        }
    )
