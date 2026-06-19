# examples/playground_api/sessions.py
"""One metered-session route for the playground (FastAPI).

pay_kit ships a charge/x402 route shim (``RequirePayment`` +
``install_exception_handler``), but it ships *no* session gate: sessions live in
``pay_kit.protocols.mpp.server`` as framework-agnostic primitives
(:func:`new_session`, :func:`session_routes`). So the 402 gate below is the one
piece an idiomatic session example must hand-roll today. It is the same shape a
charge route gets for free: verify an ``Authorization`` credential, or answer
402 with a ``WWW-Authenticate`` challenge.

Boot config comes from ``pay_kit.config()`` (the same resolved operator,
recipient, and challenge-binding secret the charge routes use), not hand-rolled
env wiring.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse

import pay_kit
from pay_kit._paycore.errors import PaymentError, payment_required_response
from pay_kit._paycore.solana import resolve_mint
from pay_kit.protocols.mpp.core.headers import (
    AUTHORIZATION_HEADER,
    PAYMENT_RECEIPT_HEADER,
    format_receipt,
    format_www_authenticate,
    parse_authorization,
)
from pay_kit.protocols.mpp.server import (
    SessionChallengeOptions,
    SessionOptions,
    new_session,
    session_routes,
)

router = APIRouter()

# One session method, built from the shared pay_kit config. cap is the ceiling
# the server will offer in a challenge (0.50 USDC at 6 decimals); pull mode +
# clientVoucher is the metered-billing flavour.
_cfg = pay_kit.config()
session = new_session(
    SessionOptions(
        operator=_cfg.operator.signer.pubkey(),
        recipient=_cfg.effective_recipient(),
        cap=500_000,
        currency=resolve_mint("USDC", "mainnet"),
        decimals=6,
        network=_cfg.network.value,
        secret_key=_cfg.mpp.challenge_binding_secret or "",
        modes=["pull"],
        pull_voucher_strategy="clientVoucher",
    )
)

_challenge = SessionChallengeOptions(cap="500000", description="Metered compute")


async def _session_gate(request: Request) -> dict[str, str]:
    """The one hand-rolled piece (no session shim ships): verify the credential
    or raise 402 with a fresh challenge. Mirrors what RequirePayment does for
    charge routes."""
    auth = request.headers.get(AUTHORIZATION_HEADER)
    if auth:
        try:
            receipt = await session.verify_credential(parse_authorization(auth))
            return {PAYMENT_RECEIPT_HEADER: format_receipt(receipt)}
        except PaymentError as err:
            error = err
        except Exception as err:  # noqa: BLE001 (parse/framework errors map to 402)
            error = PaymentError(str(err), code="invalid-payload")
    else:
        error = None
    problem = payment_required_response(
        str(error) if error else "Payment required",
        code=(error.code if error and error.code else "payment_invalid"),
        challenge_header=format_www_authenticate(await session.challenge(_challenge)),
    )
    raise HTTPException(problem["status_code"], detail=problem["body"], headers=problem["headers"])


_gate = Depends(_session_gate)

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
        yield "data: [DONE]\n\n"

    return StreamingResponse(events(), media_type="text/event-stream", headers=headers)


# Reserve/commit side channel: the shipped session_routes builder, mounted as-is
# so a client can sign and commit each voucher. No custom logic.
_routes = session_routes(session.core())


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
    the settled signature once the channel finalizes.
    """
    state = await session.core().store().get_channel(channel_id)
    if state is None:
        return JSONResponse({"error": "channel-not-found"}, status_code=404)
    return JSONResponse(
        {
            "channelId": channel_id,
            "cumulative": str(state.cumulative),
            "deposit": str(state.deposit),
            "finalized": state.finalized,
            "settledSignature": state.settled_signature,
        }
    )
