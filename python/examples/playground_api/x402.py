# examples/playground_api/x402.py
"""The embedded facilitator endpoints plus two x402-gated demo routes.

The gated routes run through the ``pay_kit`` x402 surface: a dedicated
x402-only config (the process-wide ``configure`` accepts MPP only) gates the
routes through the self-hosted x402 adapter, which settles in-process with the
operator signer. The facilitator endpoints are served with the standard shapes
for external x402 clients. Mirrors the Go example's ``x402.go``.
"""

from __future__ import annotations

import random
from typing import TYPE_CHECKING

from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse

import pay_kit
from pay_kit import Gate, Protocol, usd
from pay_kit.fastapi import Payment, RequirePayment

from .utils import rpc_call

if TYPE_CHECKING:
    from .app import AppState

JOKES = [
    "Why do programmers prefer dark mode? Because light attracts bugs.",
    "There are 10 types of people: those who understand binary and those who don’t.",
    'A SQL query walks into a bar, sees two tables, and asks: "Can I JOIN you?"',
    'A photon checks into a hotel; the bellhop asks if it has any luggage. "No, I’m traveling light."',
]

FACTS = [
    "Honey never spoils. Archaeologists found 3000-year-old honey in Egyptian tombs.",
    "Octopuses have three hearts and blue blood.",
    'A group of flamingos is called a "flamboyance".',
    "Bananas are berries; strawberries are not.",
]


def register_x402(app: FastAPI, state: AppState) -> None:
    """Mount the embedded facilitator and the x402-gated routes."""
    # --- embedded facilitator -----------------------------------------------

    @app.get("/facilitator/supported")
    async def facilitator_supported() -> JSONResponse:
        return JSONResponse(
            {
                "kinds": [
                    {
                        "scheme": "exact",
                        "network": "solana-devnet",
                        "extra": {"feePayer": state.fee_payer_pubkey},
                    }
                ]
            }
        )

    @app.post("/facilitator/verify")
    async def facilitator_verify(request: Request) -> JSONResponse:
        payload = await _payload(request)
        if payload is None:
            return JSONResponse({"isValid": False, "invalidReason": "Missing payload"})
        authorization = payload.get("authorization")
        payer = authorization.get("from") if isinstance(authorization, dict) else None
        return JSONResponse({"isValid": True, "payer": payer or "unknown"})

    @app.post("/facilitator/settle")
    async def facilitator_settle(request: Request) -> JSONResponse:
        payload = await _payload(request)
        if payload is None:
            return JSONResponse({"success": False, "errorReason": "Missing payload"})
        transaction = payload.get("transaction")
        if not transaction:
            return JSONResponse({"success": True, "transaction": "local-facilitator-settled"})
        try:
            signature = await rpc_call(
                state.rpc_url,
                "sendTransaction",
                [transaction, {"encoding": "base64", "skipPreflight": True}],
            )
        except Exception as exc:
            return JSONResponse({"success": False, "errorReason": str(exc)})
        return JSONResponse({"success": True, "transaction": signature})

    # --- x402-gated routes ---------------------------------------------------
    #
    # The process-wide config accepts MPP only, so derive an x402-accepting copy
    # (keeping the operator signer / fee payer, network, and RPC) and gate these
    # routes through the self-hosted x402 adapter, mirroring the Go example's
    # separate ``paykit.New(Accept: [X402])`` client.
    x402_config = pay_kit.config().model_copy(update={"accept": (Protocol.X402,)})

    def _gate(name: str, description: str) -> object:
        gate = Gate.build(
            name=name,
            amount=usd("0.001"),
            description=description,
            accept=(Protocol.X402,),
            default_pay_to=x402_config.effective_recipient(),
        )
        return Depends(RequirePayment(gate, config=x402_config))

    require_joke = _gate("x402Joke", "A random programmer joke")
    require_fact = _gate("x402Fact", "A random fun fact")

    @app.get("/x402/joke")
    async def x402_joke(payment: Payment = require_joke) -> JSONResponse:
        return JSONResponse({"joke": random.choice(JOKES), "source": "x402"})

    @app.get("/x402/fact")
    async def x402_fact(payment: Payment = require_fact) -> JSONResponse:
        return JSONResponse({"fact": random.choice(FACTS), "source": "x402"})


async def _payload(request: Request) -> dict | None:
    """Extract ``paymentPayload.payload`` from the request body, or ``None``."""
    try:
        body = await request.json()
    except Exception:
        return None
    payment_payload = body.get("paymentPayload") if isinstance(body, dict) else None
    payload = payment_payload.get("payload") if isinstance(payment_payload, dict) else None
    return payload if isinstance(payload, dict) else None
