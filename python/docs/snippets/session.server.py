# Server-side session: a metered payment channel, billed per delivery.
#
# Mirrors examples/playground_api/sessions.py. See
# ../../../docs/snippets-convention.md for the snippet:start/end convention.
import solana_pay_kit
from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, StreamingResponse
from solana_pay_kit._paycore.rpc import SolanaRpc
from solana_pay_kit._paycore.solana import resolve_mint, stablecoin_decimals
from solana_pay_kit.fastapi import RequireSession
from solana_pay_kit.protocols.mpp.server import (
    SessionChallengeOptions,
    SessionOptions,
    new_session,
    session_routes,
)

router = APIRouter()
cfg = solana_pay_kit.config()

# snippet:start
# One session method, built from the shared config. `cap` is the ceiling the
# server offers; on-chain settle-at-close needs the operator signer + RPC.
session = new_session(
    SessionOptions(
        operator=cfg.operator.signer.pubkey(),
        recipient=cfg.effective_recipient(),
        cap=1_000_000,  # 1.00 USDC ceiling
        currency=resolve_mint("USDC", "mainnet"),
        decimals=stablecoin_decimals("USDC"),
        network=cfg.network.value,
        secret_key=cfg.mpp.challenge_binding_secret or "",
        signer=cfg.operator.signer,
        rpc=SolanaRpc(cfg.effective_rpc_url()),
        open_tx_submitter="server",
        close_delay=2.0,  # idle-close watchdog
    )
)
challenge = SessionChallengeOptions(cap="1000000", description="Metered token stream")

# RequireSession is the 402 gate: verify a credential/voucher or answer with a
# fresh challenge — the session counterpart of RequirePayment.
gate = Depends(RequireSession(session, challenge))


@router.get("${PATH}")
async def stream(_=gate) -> StreamingResponse:
    ...  # stream metered deliveries, billed per chunk against the voucher


# Mount the reserve/commit metering side channel built by session_routes.
routes = session_routes(session.core())


@router.post("/__402/session/deliveries")
async def deliveries(request: Request) -> JSONResponse:
    r = await routes.deliveries(request.method, await request.body() or b"{}")
    return JSONResponse(r.body, status_code=r.status)
# snippet:end
