# Server-side FastAPI paywall: install one middleware and mark paid routes.
#
# Mirrors the app-level pattern used by integrations that want route metadata
# to be the source of truth. See ../../../docs/snippets-convention.md.
from fastapi import FastAPI, Request
from solana_pay_kit.fastapi import install_paywall, payment

app = FastAPI()

# snippet:start
install_paywall(
    app,
    {
        "enabled": True,
        "network": "solana_localnet",
        "price_usd": "0.01",
        "preflight": False,
        "signer_env": None,
    },
    paid_tags=("paid",),
)


@app.post("${PATH}", tags=["paid"])
async def chat_completions(request: Request) -> dict[str, object]:
    verified = payment(request)
    return {"ok": True, "tx": verified.transaction if verified else None}


@app.get("/health")
async def health() -> dict[str, bool]:
    return {"ok": True}


# snippet:end
