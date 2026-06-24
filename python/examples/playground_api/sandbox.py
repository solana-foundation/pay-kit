# examples/playground_api/sandbox.py
"""LOCAL SANDBOX ONLY — port of the TypeScript playground's `sandbox.ts`.

Funding here uses the surfnet (``https://402.surfnet.dev:8899``) cheatcode RPC
methods ``surfnet_setAccount`` / ``surfnet_setTokenAccount``. They exist only on
the local Solana Payment Sandbox; on devnet/mainnet they are no-ops (caught and
warned). None of this is how a real pay-kit server runs — it just makes the
playground work zero-config.

Funding never runs at import or app startup (the smoke test boots the app and
must not touch the network). Call :func:`fund_sandbox` explicitly, or hit the
faucet route registered by :func:`register_faucet`.
"""

from __future__ import annotations

import json
import urllib.request
from typing import Any

from pay_kit._paycore.mints import SYSTEM_PROGRAM, TOKEN_PROGRAM
from pay_kit._paycore.solana import resolve_mint

# The sandbox clones mainnet state, so it funds the *mainnet* USDC mint
# regardless of the configured network tag (mirrors sandbox.ts).
USDC_MINT = resolve_mint("USDC", "mainnet")
SOL_FUND_LAMPORTS = 100_000_000_000  # 100 SOL
USDC_FUND_AMOUNT = 100_000_000  # 100 USDC (6 decimals)

_RPC_TIMEOUT_SECONDS = 8.0


def _rpc_call(rpc_url: str, method: str, params: list[Any]) -> None:
    """Minimal JSON-RPC 2.0 call for the surfnet cheatcode methods."""
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    request = urllib.request.Request(  # noqa: S310 - fixed sandbox RPC URL, JSON body
        rpc_url, data=payload, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(request, timeout=_RPC_TIMEOUT_SECONDS) as response:  # noqa: S310
        body = json.loads(response.read())
    if isinstance(body, dict) and body.get("error"):
        raise RuntimeError(f"{method}: {body['error'].get('message', body['error'])}")


def fund_sandbox(rpc_url: str, *addresses: str) -> None:
    """Fund each address with SOL + USDC on the local sandbox. Best-effort."""
    try:
        for address in addresses:
            _rpc_call(
                rpc_url,
                "surfnet_setAccount",
                [
                    address,
                    {
                        "lamports": SOL_FUND_LAMPORTS,
                        "data": "",
                        "executable": False,
                        "owner": SYSTEM_PROGRAM,
                        "rentEpoch": 0,
                    },
                ],
            )
            _rpc_call(
                rpc_url,
                "surfnet_setTokenAccount",
                [address, USDC_MINT, {"amount": USDC_FUND_AMOUNT, "state": "initialized"}, TOKEN_PROGRAM],
            )
    except Exception as err:  # noqa: BLE001 - sandbox funding is best-effort
        print(f"  Sandbox RPC not reachable — accounts may be unfunded ({err}).")


def fund_usdc(rpc_url: str, *addresses: str) -> None:
    """Fund each address with USDC only (no SOL) on the local sandbox.

    Client wallets never pay network fees — the operator fee-pays every gate —
    so they only need a USDC balance. Best-effort.
    """
    try:
        for address in addresses:
            _rpc_call(
                rpc_url,
                "surfnet_setTokenAccount",
                [address, USDC_MINT, {"amount": USDC_FUND_AMOUNT, "state": "initialized"}, TOKEN_PROGRAM],
            )
    except Exception as err:  # noqa: BLE001 - sandbox funding is best-effort
        print(f"  Sandbox RPC not reachable — USDC not funded ({err}).")


def register_faucet(app: Any, rpc_url: str) -> None:
    """Mount a USDC faucet (no SOL needed): airdrop sandbox USDC to an address."""
    from fastapi import Request
    from fastapi.responses import JSONResponse

    @app.get("/api/v1/faucet/status")
    async def faucet_status() -> dict[str, str]:  # pyright: ignore[reportUnusedFunction]
        return {"usdcAmount": "100 USDC", "usdcMint": USDC_MINT}

    @app.post("/api/v1/faucet/airdrop")
    async def faucet_airdrop(request: Request) -> JSONResponse:  # pyright: ignore[reportUnusedFunction]
        body = await request.json() if await request.body() else {}
        address = body.get("address") if isinstance(body, dict) else None
        if not address:
            return JSONResponse({"error": "Missing `address` in request body"}, status_code=400)
        try:
            fund_usdc(rpc_url, address)
        except Exception as err:  # noqa: BLE001 - report failure to the caller
            return JSONResponse({"error": "Airdrop failed", "details": str(err)}, status_code=500)
        return JSONResponse({"ok": True, "usdc": "100 USDC"})
