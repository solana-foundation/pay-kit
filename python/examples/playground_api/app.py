# examples/playground_api/app.py
"""The HTTP API behind the pay-kit playground (FastAPI).

Serves the playground endpoints with their payment gating (MPP charges and
sessions through the ``pay_kit`` umbrella surface), so the playground web app
works against it by only setting ``PAYKIT_PLAYGROUND_API_URL``.

    cd python
    uvicorn examples.playground_api.app:app --port 3000

Environment: PORT, NETWORK, RPC_URL, RECIPIENT, FEE_PAYER_KEY, MPP_SECRET_KEY.
See README.md for the full table.

This module owns the boot wiring (:class:`AppState`, :func:`create_app`) and
the free hub endpoints (health, config catalog). The charge / session / faucet
/ docs feature endpoints plug into the ``register_*`` seam in
:func:`create_app` and are filled in separately.
"""

from __future__ import annotations

import logging
import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse, Response
from solders.keypair import Keypair

import pay_kit
from pay_kit._paycore.network import Network
from pay_kit.fastapi import install
from pay_kit.signer import LocalSigner

from .docs import build_docs_router, find_repo_root
from .faucet import register_faucet
from .sessions import register_sessions
from .utils import env_or, json_error, rpc_call

logger = logging.getLogger("playground-api")


@dataclass
class AppState:
    """Boot configuration shared by every module.

    Mirrors the TS example's module-level env constants: the raw network tag,
    RPC endpoint, settlement recipient, MPP challenge-binding secret, the
    operator fee-payer keypair, and the repository root (``None`` outside a
    checkout, which disables the docs default root and the SPA file server).
    """

    network: str
    rpc_url: str
    recipient: str
    secret_key: str
    fee_payer: LocalSigner
    repo_root: str | None = None
    port: int = 3000

    @property
    def fee_payer_pubkey(self) -> str:
        """Base58 operator pubkey used as the fee payer and health label."""
        return self.fee_payer.pubkey()

    @property
    def pay_kit_network(self) -> Network:
        """The :class:`Network` enum for the raw ``NETWORK`` tag.

        Surfpool localnet clones mainnet state, so the bare ``localnet`` /
        ``devnet`` / ``mainnet`` tags map onto the ``solana_*`` enum members.
        """
        normalized = self.network.strip().lower()
        if normalized in ("localnet", "solana_localnet"):
            return Network.SOLANA_LOCALNET
        if normalized in ("devnet", "solana_devnet"):
            return Network.SOLANA_DEVNET
        if normalized in ("mainnet", "mainnet-beta", "solana_mainnet"):
            return Network.SOLANA_MAINNET
        raise ValueError(f"unknown NETWORK tag: {self.network!r}")


def state_from_env() -> AppState:
    """Build :class:`AppState` from the environment, matching the TS example's
    module-level defaults.
    """
    raw_fee_payer = os.getenv("FEE_PAYER_KEY")
    fee_payer = LocalSigner.from_base58(raw_fee_payer) if raw_fee_payer else LocalSigner.from_keypair(Keypair())
    return AppState(
        network=env_or("NETWORK", "localnet"),
        # Default to the hosted Solana Payment Sandbox so the playground works
        # zero-config: it has the payment-channels program preloaded and
        # supports the surfnet cheatcodes the faucet uses. Override RPC_URL to
        # point at a local surfpool when you need offline iteration.
        rpc_url=env_or("RPC_URL", "https://402.surfnet.dev:8899"),
        recipient=env_or("RECIPIENT", fee_payer.pubkey()),
        secret_key=os.getenv("MPP_SECRET_KEY") or secrets.token_hex(32),
        fee_payer=fee_payer,
        repo_root=find_repo_root(),
        port=int(env_or("PORT", "3000")),
    )


# --- endpoint catalog (drives the playground web app's sidebar) -------------


# The /api/v1/config endpoint catalog the web app renders in its sidebar. A
# curated subset of the live routes (mirrors the TS buildEndpointList): every
# entry here has a server route, but not every route is advertised.
_ENDPOINT_CATALOG: list[dict[str, Any]] = [
    {
        "id": "stocks-quote",
        "primitive": "charge",
        "method": "GET",
        "path": "/api/v1/stocks/quote/:symbol",
        "title": "Stock quote",
        "description": "Real-time price for a single ticker.",
        "cost": "0.01 USDC",
        "params": [{"name": "symbol", "default": "AAPL"}],
    },
    {
        "id": "marketplace-buy",
        "primitive": "charge",
        "method": "GET",
        "path": "/api/v1/marketplace/buy/:productId",
        "title": "Marketplace purchase",
        "description": "Multi-recipient split (seller + platform + referral).",
        "cost": "varies",
        "params": [
            {"name": "productId", "default": "sol-hoodie"},
            {"name": "referrer", "default": ""},
        ],
    },
    {
        "id": "sessions-stream",
        "primitive": "session",
        "method": "GET",
        "path": "/sessions/stream",
        "title": "Metered stream",
        "description": "Pay-per-chunk SSE delivery via session vouchers.",
        "cost": "0.0001 USDC / chunk",
        "unitPrice": "100",
    },
    {
        "id": "sessions-compute",
        "primitive": "session",
        "method": "POST",
        "path": "/sessions/compute",
        "title": "Pay-per-call compute",
        "description": "Voucher-billed inference; cap 0.50 USDC per session.",
        "cost": "0.005 USDC / call",
        "unitPrice": "5000",
    },
]


# --- hub endpoints: health / config -----------------------------------------


def register_hub(app: FastAPI, state: AppState) -> None:
    """Mount the health check and the endpoint catalog driving the web app's
    sidebar.

    The RPC url is intentionally omitted from both responses: it is operator
    infrastructure that should not be exposed to the browser.
    """

    @app.get("/api/v1/health")
    async def health() -> JSONResponse:
        body: dict[str, Any] = {
            "ok": True,
            "feePayer": state.fee_payer_pubkey,
            "recipient": state.recipient,
            "network": state.network,
        }
        try:
            result = await rpc_call(state.rpc_url, "getBalance", [state.fee_payer_pubkey])
            value = result.get("value") if isinstance(result, dict) else result
            if value is not None:
                body["feePayerBalance"] = float(value) / 1e9
        except Exception:
            # Best-effort balance: omitted when the RPC is unreachable.
            pass
        return JSONResponse(body)

    @app.get("/api/v1/config")
    async def config() -> JSONResponse:
        return JSONResponse(
            {
                "recipient": state.recipient,
                "network": state.network,
                "feePayer": state.fee_payer_pubkey,
                "endpoints": _ENDPOINT_CATALOG,
            }
        )


# --- feature-module registration seam ---------------------------------------
#
# The charge endpoints plug in here. faucet, docs, and sessions register from
# their own modules directly in create_app. Each registrar takes the app and
# shared state and mounts its routes; sessions returns a shutdown hook.


def register_charges(app: FastAPI, state: AppState) -> None:
    """Mount the MPP charge-gated endpoints (stock quote, marketplace purchase)
    plus the free product catalog. Implemented in :mod:`charges`.
    """
    from .charges import register_charges as _register

    _register(app, state)


# --- SPA static serving ------------------------------------------------------


def register_spa(app: FastAPI, repo_root: str | None) -> None:
    """Serve the built playground web app (``playground/app/dist`` at the repo
    root) with an index.html catch-all.

    Registered last so the API routes win; the catch-all only sees paths no
    earlier route matched.
    """
    dist = Path(repo_root) / "playground" / "app" / "dist" if repo_root else None

    @app.get("/{full_path:path}")
    async def spa(full_path: str) -> Response:
        if dist:
            candidate = dist / full_path
            if candidate.is_file():
                return FileResponse(str(candidate))
            index = dist / "index.html"
            if index.is_file():
                return FileResponse(str(index))
        return JSONResponse(
            json_error("not found (build playground/app to serve the web app from this server)"),
            status_code=404,
        )


# --- app factory ------------------------------------------------------------


def create_app(state: AppState | None = None) -> FastAPI:
    """Wire every module onto one FastAPI app.

    Split from the entrypoint so a smoke test can boot the full route table
    against a stub RPC without binding a real port or funding accounts. The
    sessions shutdown hook is registered as an ASGI shutdown handler.
    """
    if state is None:
        state = state_from_env()

    # Configure the umbrella surface so the charge / session registrars share
    # one boot. Preflight is skipped here: the live-RPC check belongs to the
    # entrypoint's boot path, not the app factory the smoke test reuses.
    pay_kit.configure(
        network=state.pay_kit_network,
        rpc_url=state.rpc_url,
        accept=pay_kit.Protocol.MPP,
        preflight=False,
        operator=pay_kit.Operator(recipient=state.recipient, signer=state.fee_payer),
        mpp=pay_kit.MppConfig(realm="PayKit Playground", challenge_binding_secret=state.secret_key),
    )

    app = FastAPI(title="PayKit Playground (Python)")
    # One-call pay-kit setup: payment-header CORS, the PayKitError -> HTTP
    # response mapping + settlement-header echo, and the bare-dict HTTPException
    # shape the guards rely on.
    install(app)

    register_hub(app, state)
    register_faucet(app, state)
    app.include_router(build_docs_router(state))
    register_charges(app, state)
    sessions_shutdown = register_sessions(app, state)

    # The SPA catch-all must register after every API route.
    register_spa(app, state.repo_root)

    @app.on_event("shutdown")
    async def _shutdown() -> None:
        sessions_shutdown()

    return app


# Module-level app for ``uvicorn examples.playground_api.app:app``. Boots from
# the environment; the entrypoint in ``main.py`` does the same with funding.
app = create_app()
