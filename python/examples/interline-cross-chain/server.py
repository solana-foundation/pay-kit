# python/examples/interline-cross-chain/server.py
"""pay-kit on Solana + Interline for Base/EVM — one service, agents on either chain pay it.

pay-kit gives you Solana-native payments (x402 + MPP). That's great when your
buyers are on Solana. But an agent paying from Base / another EVM chain can't
settle against a Solana gate.

[Interline](https://github.com/Choppaaahh/interline-routes) is a neutral,
non-custodial *cross-CHAIN* x402 router (`pip install interline`). Put it in
front of the same capability and your endpoint *also* accepts Base/EVM x402 —
the chain pay-kit doesn't cover — without you holding any funds.

This example serves the SAME "premium report" two ways so the difference is
obvious:

    GET /solana/report      gated by pay-kit  -> Solana USDC only
    GET /crosschain/report  gated by Interline -> Base(EVM) USDC *and* Solana USDC
    GET /health             free

Both routes are zero-config: pay-kit boots against its hosted Surfpool sandbox,
and Interline wires mock facilitators (no wallet/keys/chain) so the 402 dance
runs out of the box. To settle live, swap in the real facilitators where noted.

Run:
    pip install -e ".[fastapi]"   # pay-kit, from the repo's python/ dir (not yet on PyPI)
    pip install interline         # the cross-chain router
    uvicorn server:app --port 8000

Drive it:
    curl -i http://127.0.0.1:8000/solana/report        # 402 (Solana challenge)
    curl -i http://127.0.0.1:8000/crosschain/report    # 402 advertising BOTH chains
"""
from __future__ import annotations

import os
import sys

from fastapi import Depends, FastAPI, Request

# --- pay-kit (Solana-native x402 + MPP) ----------------------------------------
import pay_kit
from pay_kit import Gate, Pricing, usd
from pay_kit.fastapi import Payment, RequirePayment, install_exception_handler

# --- Interline (neutral cross-chain x402 router) -------------------------------
from router.facilitator_real import get_facilitator
from router.paywall import Paywall
from router.rails import X402Rail

pay_kit.configure(network="solana_localnet")

app = FastAPI(title="pay-kit + Interline: cross-chain payments")
install_exception_handler(app)

# The capability both routes sell. In a real service this is your actual work.
def premium_report() -> dict[str, object]:
    return {"report": "the paid work product goes here", "rows": [1, 2, 3]}

# Your EVM receiving wallet — read from env so it's never hardcoded. The seller
# NEVER holds funds (each rail settles buyer -> this address directly). The
# placeholder is harmless under the mock facilitator (nothing settles), but set
# EVM_PAY_TO to your real wallet BEFORE wiring a live facilitator — otherwise live
# funds would route to a dead address.
_PLACEHOLDER_PAY_TO = "0x0000000000000000000000000000000000000000"
EVM_PAY_TO = os.getenv("EVM_PAY_TO", _PLACEHOLDER_PAY_TO)
if EVM_PAY_TO == _PLACEHOLDER_PAY_TO:
    print(
        "[interline-cross-chain] WARNING: EVM_PAY_TO is the placeholder address — fine "
        "for the mock demo, but export EVM_PAY_TO=<your-wallet> before going live.",
        file=sys.stderr,
    )


# ============================================================================
# Route 1 — pay-kit alone: Solana USDC.
# ============================================================================
class Catalog(Pricing):
    """pay-kit route catalogue: each paid route declares its gate here."""

    def __init__(self) -> None:
        self.report = Gate.build(
            name="report",
            amount=usd("0.10"),
            description="Premium report (Solana)",
            default_pay_to=pay_kit.config().effective_recipient(),
            accept_default=pay_kit.config().accept,
        )


catalog = Catalog()
require_solana = Depends(RequirePayment("report", pricing=catalog))


@app.get("/solana/report")
async def solana_report(payment: Payment = require_solana) -> dict[str, object]:
    """Paid via pay-kit. Only an agent paying on Solana can settle this."""
    return {**premium_report(), "paid_via": "pay-kit", "protocol": payment.protocol.value}


# ============================================================================
# Route 2 — add Interline: the SAME report, now reachable on Base(EVM) OR Solana.
# Interline's one Paywall offers N rails; the 402 advertises both chains and the
# buyer's agent pays on whichever it speaks. Adding a chain is one list entry.
# ============================================================================
def _evm_x402_requirements(resource: str) -> dict:
    """x402 USDC on Base Sepolia (the chain pay-kit can't reach)."""
    return {
        "scheme": "exact",
        "network": "eip155:84532",  # Base Sepolia (CAIP-2)
        "asset": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",  # test USDC
        "amount": "100000",  # atomic; USDC has 6 decimals -> 0.10 USDC
        "payTo": EVM_PAY_TO,
        "maxTimeoutSeconds": 120,
        "extra": {"name": "USDC", "version": "2", "chainId": 84532},
    }


# get_facilitator() is a mock until you set live env vars; for a real cross-chain
# settle, give each rail its own live facilitator (Base x402 + a Solana facilitator).
interline_paywall = Paywall(rails=[
    X402Rail(get_facilitator(), _evm_x402_requirements, name="x402-base", network_family="eip155"),
])


@app.get("/crosschain/report")
def crosschain_report(request: Request):
    """Paid via Interline. One line gates the work; Interline runs the 402 dance,
    selects the rail the buyer speaks (here: Base/EVM x402), settles, and returns
    the on-chain receipt header. Pair this route with the pay-kit route above and
    your service accepts agents on Solana AND Base."""
    return interline_paywall.gate(request, premium_report)


@app.get("/health")
def health() -> dict[str, object]:
    return {
        "ok": True,
        "routes": {
            "/solana/report": "pay-kit (Solana USDC)",
            "/crosschain/report": "Interline (Base/EVM USDC; add Solana rail for both)",
        },
    }
