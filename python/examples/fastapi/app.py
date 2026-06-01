# examples/fastapi/app.py
"""FastAPI server gated with pay_kit.

Zero-config: a bare ``pay_kit.configure()`` boots against solana_localnet
(the hosted Surfpool sandbox at https://402.surfnet.dev:8899) with the
shipped demo signer as the recipient. No keys, no .env, no flags.

Two routes:

    GET /health  -> free, returns {"ok": true}
    GET /report  -> gated. The RequirePayment dependency answers 402 with a
                    WWW-Authenticate challenge until a valid proof arrives,
                    then hands the verified Payment to the handler.

Run:

    pip install -e ".[fastapi]"
    uvicorn examples.fastapi.app:app --port 8000

Drive it from a client:

    curl -i http://127.0.0.1:8000/report     # 402 payment required
    pay curl http://127.0.0.1:8000/report    # pays and succeeds
"""

from __future__ import annotations

from fastapi import Depends, FastAPI

import pay_kit
from pay_kit import Gate, Pricing, usd
from pay_kit.fastapi import Payment, RequirePayment, install_exception_handler

pay_kit.configure(network="solana_localnet")


class Catalog(Pricing):
    """The route catalogue: every paid route declares its gate here."""

    def __init__(self) -> None:
        self.report = Gate.build(
            name="report",
            amount=usd("0.10"),
            description="Premium report",
            default_pay_to=pay_kit.config().effective_recipient(),
            accept_default=pay_kit.config().accept,
        )


catalog = Catalog()

# Module-level dependency singleton (FastAPI resolves it per request).
require_report = Depends(RequirePayment("report", pricing=catalog))

app = FastAPI()
install_exception_handler(app)


@app.get("/health")
async def health() -> dict[str, bool]:
    """Free liveness probe."""
    return {"ok": True}


@app.get("/report")
async def report(payment: Payment = require_report) -> dict[str, object]:
    """Paid route. ``payment`` is the verified proof for this request."""
    return {"ok": True, "tx": payment.transaction, "protocol": payment.protocol.value}
