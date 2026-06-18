# examples/playground_api/app.py
"""The pay-kit playground API (FastAPI), gated with the unified pay_kit surface.

Zero-config: ``pay_kit.configure()`` boots against solana_localnet (the hosted
Surfpool sandbox at https://402.surfnet.dev:8899) with the shipped demo signer
as operator and recipient. No keys, no .env, no flags.

Routes:

    GET  /health   -> free, returns {"ok": true}
    GET  /report   -> charge-gated via RequirePayment (both protocols)
    POST /compute  -> session-gated, metered (see sessions.py)

Run:

    cd python
    uvicorn examples.playground_api.app:app --port 3000

Drive it from a client:

    curl -i http://127.0.0.1:3000/report     # 402 payment required
    pay curl http://127.0.0.1:3000/report    # pays and succeeds
"""

from __future__ import annotations

from fastapi import Depends, FastAPI

import pay_kit
from pay_kit import Gate, Pricing, usd
from pay_kit.fastapi import Payment, RequirePayment, install

pay_kit.configure(network="solana_localnet")

# Imported after configure() so the session method builds from the resolved
# operator / recipient / challenge-binding secret.
from . import sessions  # noqa: E402


class Catalog(Pricing):
    """The route catalogue: every charge-gated route declares its gate here."""

    def __init__(self) -> None:
        self.report = Gate.build(
            name="report",
            amount=usd("0.01"),
            description="Premium report",
            default_pay_to=pay_kit.config().effective_recipient(),
            accept_default=pay_kit.config().accept,
        )


catalog = Catalog()

# Module-level dependency singleton (FastAPI resolves it per request).
require_report = Depends(RequirePayment("report", pricing=catalog))

app = FastAPI(title="PayKit Playground (Python)")
# One-call setup: payment-header CORS + the PayKitError -> 402 challenge mapping.
install(app)
app.include_router(sessions.router)


@app.get("/health")
async def health() -> dict[str, bool]:
    """Free liveness probe."""
    return {"ok": True}


@app.get("/report")
async def report(payment: Payment = require_report) -> dict[str, object]:
    """Charge-gated route. ``payment`` is the verified proof for this request."""
    return {"ok": True, "tx": payment.transaction, "protocol": payment.protocol.value}
