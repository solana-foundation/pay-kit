# examples/fastapi/app.py
"""FastAPI server gated with solana_pay_kit route metadata.

Zero-config: ``install_paywall`` builds a localnet config against the hosted
Surfpool sandbox at https://402.surfnet.dev:8899 with the shipped demo signer
as the recipient. No keys, no .env, no flags.

Two routes:

    GET /health  -> free, returns {"ok": true}
    GET /report  -> gated by its "paid" tag. The paywall answers 402 with a
                    WWW-Authenticate challenge until a valid proof arrives.

Run:

    pip install -e ".[fastapi]"
    uvicorn examples.fastapi.app:app --port 8000

Drive it from a client:

    curl -i http://127.0.0.1:8000/report     # 402 payment required
    pay curl http://127.0.0.1:8000/report    # pays and succeeds
"""

from __future__ import annotations

from fastapi import FastAPI, Request

from solana_pay_kit.fastapi import install_paywall, payment

app = FastAPI()
install_paywall(
    app,
    {
        "enabled": True,
        "network": "solana_localnet",
        "price_usd": "0.10",
        "signer_env": None,
    },
    paid_tags=("paid",),
)


@app.get("/health")
async def health() -> dict[str, bool]:
    """Free liveness probe."""
    return {"ok": True}


@app.get("/report", tags=["paid"])
async def report(request: Request) -> dict[str, object]:
    """Paid route. ``payment(request)`` is the verified proof."""
    verified = payment(request)
    return {
        "ok": True,
        "tx": verified.transaction if verified else None,
        "protocol": verified.protocol.value if verified else None,
    }
