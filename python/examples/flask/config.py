"""Environment-driven configuration for the Flask MPP example.

All knobs are read from environment variables so the same module can be
imported by the app factory, tests, and ad-hoc scripts without mutating
process state.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from solana_mpp._rpc import SolanaRpc
from solana_mpp.server.mpp import Config
from solana_mpp.store import MemoryStore

DEFAULT_RPC_URL = "https://402.surfnet.dev:8899"
DEFAULT_CURRENCY = "USDC"
DEFAULT_PAY_TO = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY"
DEFAULT_AMOUNT = "0.001"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8000


@dataclass(frozen=True)
class ServerSettings:
    """Top-level Flask runtime settings (host, port, default amount)."""

    host: str
    port: int
    amount: str


def server_settings_from_env() -> ServerSettings:
    return ServerSettings(
        host=os.environ.get("HOST", DEFAULT_HOST),
        port=int(os.environ.get("PORT", str(DEFAULT_PORT))),
        amount=os.environ.get("MPP_AMOUNT", DEFAULT_AMOUNT),
    )


def mpp_config_from_env() -> Config:
    """Build the :class:`Config` for the MPP server from environment vars."""
    rpc_url = os.environ.get("MPP_RPC_URL", DEFAULT_RPC_URL)
    return Config(
        recipient=os.environ.get("MPP_PAY_TO", DEFAULT_PAY_TO),
        currency=os.environ.get("MPP_CURRENCY", DEFAULT_CURRENCY),
        decimals=6,
        network=os.environ.get("MPP_NETWORK", "localnet"),
        rpc_url=rpc_url,
        secret_key=os.environ.get("MPP_SECRET_KEY", "python-mpp-dev-secret"),
        realm="Python Flask Example",
        store=MemoryStore(),
        rpc=SolanaRpc(rpc_url),
    )
