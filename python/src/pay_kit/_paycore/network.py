"""Solana network slugs plus default RPC endpoints and CAIP-2 identifiers."""

from __future__ import annotations

from enum import StrEnum

__all__ = [
    "Network",
    "PUBLIC_RPC_URLS",
    "SOLANA_MAINNET_CAIP2",
    "SOLANA_DEVNET_CAIP2",
    "MIN_FEE_PAYER_LAMPORTS",
    "AUTOFUND_LAMPORTS",
]

# CAIP-2 chain identifiers advertised in x402 + MPP accepts entries. These must
# byte-match the Rust spine (PHP PayCore/Network.php caip2()): Surfpool-localnet
# clones mainnet state but reuses the devnet genesis hash by convention, so
# localnet shares the devnet CAIP-2.
SOLANA_MAINNET_CAIP2 = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"
SOLANA_DEVNET_CAIP2 = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"

# Boot-time preflight thresholds (caveat #3). Defined here so config + preflight
# share a single source of truth without a cross-layer import.
MIN_FEE_PAYER_LAMPORTS = 1_000_000
AUTOFUND_LAMPORTS = 10_000_000_000


class Network(StrEnum):
    """Solana network slug; backing values match the Rust spine's wire form."""

    SOLANA_MAINNET = "solana_mainnet"
    SOLANA_DEVNET = "solana_devnet"
    SOLANA_LOCALNET = "solana_localnet"

    def default_rpc_url(self) -> str:
        """Default public RPC endpoint for this network (caveat #2)."""
        return PUBLIC_RPC_URLS[self]

    def mints_label(self) -> str:
        """Bare network slug consumed by the mints registry (mainnet/devnet/localnet)."""
        return _MINTS_LABELS[self]

    def caip2(self) -> str:
        """CAIP-2 chain identifier advertised in accepts entries."""
        return _CAIP2[self]


# Localnet defaults to the hosted Surfpool endpoint (mainnet-state fork) so a
# zero-config localnet boot is reachable (caveat #2), not http://localhost:8899.
PUBLIC_RPC_URLS: dict[Network, str] = {
    Network.SOLANA_MAINNET: "https://api.mainnet-beta.solana.com",
    Network.SOLANA_DEVNET: "https://api.devnet.solana.com",
    Network.SOLANA_LOCALNET: "https://402.surfnet.dev:8899",
}

_MINTS_LABELS: dict[Network, str] = {
    Network.SOLANA_MAINNET: "mainnet",
    Network.SOLANA_DEVNET: "devnet",
    Network.SOLANA_LOCALNET: "localnet",
}

_CAIP2: dict[Network, str] = {
    Network.SOLANA_MAINNET: SOLANA_MAINNET_CAIP2,
    Network.SOLANA_DEVNET: SOLANA_DEVNET_CAIP2,
    Network.SOLANA_LOCALNET: SOLANA_DEVNET_CAIP2,
}
