# examples/playground_api/x402.py
"""The embedded facilitator endpoints plus two x402-gated demo routes.

The Python x402 adapter only implements self-hosted mode (it verifies and
settles in-process with the operator signer), so the ``/x402/joke`` and
``/x402/fact`` gates here settle locally instead of POSTing to the embedded
facilitator. The facilitator endpoints are still served with the standard
shapes for external x402 clients. See README.md.

Mirrors the Go example's ``x402.go``. The gated routes are guarded through the
``pay_kit`` umbrella surface with a per-gate ``accept=(Protocol.X402,)``, so the
shared in-process x402 adapter (configured in ``app.create_app`` via the
operator signer / fee payer) issues the 402 challenge and settles the proof.
"""

from __future__ import annotations

import random
from typing import TYPE_CHECKING

from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse

import pay_kit
from pay_kit import Gate, Protocol, usd
from pay_kit.fastapi import Payment, RequirePayment, install_exception_handler

from .utils import rpc_call

if TYPE_CHECKING:
    from .app import AppState

# jokes is the canned joke pool.
JOKES = [
    "Why do programmers prefer dark mode? Because light attracts bugs.",
    "There are 10 types of people: those who understand binary and those who don’t.",
    'A SQL query walks into a bar, sees two tables, and asks: "Can I JOIN you?"',
    'A photon checks into a hotel; the bellhop asks if it has any luggage. "No, I’m traveling light."',
]

# facts is the canned fun-fact pool.
FACTS = [
    "Honey never spoils. Archaeologists found 3000-year-old honey in Egyptian tombs.",
    "Octopuses have three hearts and blue blood.",
    'A group of flamingos is called a "flamboyance".',
    "Bananas are berries; strawberries are not.",
]


def register_x402(app: FastAPI, state: AppState) -> None:
    """Mount the embedded facilitator and the x402-gated routes."""
    # The umbrella exception handler renders the 402 challenge (and settlement
    # headers) for the gated routes below; idempotent if already installed.
    install_exception_handler(app)

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
        try:
            body = await request.json()
        except Exception:
            body = None
        payment_payload = body.get("paymentPayload") if isinstance(body, dict) else None
        payload = payment_payload.get("payload") if isinstance(payment_payload, dict) else None
        if not isinstance(payload, dict):
            return JSONResponse({"isValid": False, "invalidReason": "Missing payload"})
        payer = "unknown"
        authorization = payload.get("authorization")
        if isinstance(authorization, dict):
            from_field = authorization.get("from")
            if isinstance(from_field, str) and from_field:
                payer = from_field
        return JSONResponse({"isValid": True, "payer": payer})

    @app.post("/facilitator/settle")
    async def facilitator_settle(request: Request) -> JSONResponse:
        try:
            body = await request.json()
        except Exception:
            body = None
        payment_payload = body.get("paymentPayload") if isinstance(body, dict) else None
        payload = payment_payload.get("payload") if isinstance(payment_payload, dict) else None
        if not isinstance(payload, dict):
            return JSONResponse({"success": False, "errorReason": "Missing payload"})
        transaction = payload.get("transaction")
        if not isinstance(transaction, str) or transaction == "":
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
    # A dedicated x402-only config (mirrors the Go example's separate
    # ``paykit.New(Accept: [X402])`` client): the process-wide ``configure`` in
    # ``app.create_app`` accepts MPP only, so the x402 adapter is not wired on
    # the global PayCore. Deriving an x402-accepting copy of that config keeps
    # the operator signer / fee payer, network, and RPC, and gates these routes
    # through the self-hosted x402 adapter (verify + cosign + broadcast).
    x402_config = pay_kit.config().model_copy(update={"accept": (Protocol.X402,)})

    joke_gate = Gate.build(
        name="x402Joke",
        amount=usd("0.001"),
        description="A random programmer joke",
        accept=(Protocol.X402,),
        default_pay_to=x402_config.effective_recipient(),
    )
    require_joke = Depends(RequirePayment(joke_gate, config=x402_config))

    @app.get("/x402/joke")
    async def x402_joke(payment: Payment = require_joke) -> JSONResponse:
        return JSONResponse({"joke": random.choice(JOKES), "source": "x402"})

    fact_gate = Gate.build(
        name="x402Fact",
        amount=usd("0.001"),
        description="A random fun fact",
        accept=(Protocol.X402,),
        default_pay_to=x402_config.effective_recipient(),
    )
    require_fact = Depends(RequirePayment(fact_gate, config=x402_config))

    @app.get("/x402/fact")
    async def x402_fact(payment: Payment = require_fact) -> JSONResponse:
        return JSONResponse({"fact": random.choice(FACTS), "source": "x402"})
