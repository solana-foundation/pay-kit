# examples/playground_api/faucet.py
"""SOL + USDC airdrops via the surfnet cheatcodes."""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from . import constants
from .utils import json_error, rpc_call

if TYPE_CHECKING:
    from .app import AppState


def register_faucet(app: FastAPI, state: AppState) -> None:
    @app.get("/api/v1/faucet/status")
    async def faucet_status() -> JSONResponse:
        return JSONResponse(
            {
                "solAmount": "100 SOL",
                "usdcAmount": "100 USDC",
                "usdcMint": constants.USDC_MAINNET_MINT,
            }
        )

    @app.post("/api/v1/faucet/airdrop")
    async def faucet_airdrop(request: Request) -> JSONResponse:
        body = await request.json()
        address = body.get("address")
        if not address:
            return JSONResponse(json_error("Missing `address` in request body"), status_code=400)
        try:
            await rpc_call(
                state.rpc_url,
                "surfnet_setAccount",
                [
                    address,
                    {
                        "lamports": constants.SOL_FUND_LAMPORTS,
                        "data": "",
                        "executable": False,
                        "owner": constants.SYSTEM_PROGRAM_ID,
                        "rentEpoch": 0,
                    },
                ],
            )
            await rpc_call(
                state.rpc_url,
                "surfnet_setTokenAccount",
                [
                    address,
                    constants.USDC_MAINNET_MINT,
                    {"amount": constants.USDC_FUND_AMOUNT, "state": "initialized"},
                    constants.TOKEN_PROGRAM_ID,
                ],
            )
        except Exception as exc:
            return JSONResponse({"error": "Airdrop failed", "details": str(exc)}, status_code=500)
        return JSONResponse({"ok": True, "sol": "100 SOL", "usdc": "100 USDC"})
