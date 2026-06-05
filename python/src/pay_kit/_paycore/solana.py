"""Solana-specific protocol types and helpers."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

SYSTEM_PROGRAM = "11111111111111111111111111111111"
TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
TOKEN_2022_PROGRAM = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
ASSOCIATED_TOKEN_PROGRAM = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"
MEMO_PROGRAM = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"
COMPUTE_BUDGET_PROGRAM = "ComputeBudget111111111111111111111111111111"


# Mint addresses keyed by currency symbol, then by network.
#
# Canonical network slug is ``mainnet`` (mirrors Ruby and the L1 lock from PR
# #96 / #102 across Rust, PHP, Lua). ``mainnet-beta`` is accepted as a
# backward compatible alias via :func:`_canonical_network`.
KNOWN_MINTS: dict[str, dict[str, str]] = {
    "USDC": {
        "mainnet": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
        "devnet": "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
        "testnet": "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
    },
    "USDT": {
        "mainnet": "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB",
    },
    "USDG": {
        "mainnet": "2u1tszSeqZ3qBWF3uNGPFc8TzMk2tdiwknnRMWGWjGWH",
        "devnet": "4F6PM96JJxngmHnZLBh9n58RH4aTVNWvDs2nuwrT5BP7",
        "testnet": "4F6PM96JJxngmHnZLBh9n58RH4aTVNWvDs2nuwrT5BP7",
    },
    "PYUSD": {
        "mainnet": "2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo",
        "devnet": "CXk2AMBfi3TwaEL2468s6zP8xq9NxTXjp9gjMgzeUynM",
        "testnet": "CXk2AMBfi3TwaEL2468s6zP8xq9NxTXjp9gjMgzeUynM",
    },
    "CASH": {
        "mainnet": "CASHx9KJUStyftLFWGvEVf59SGeG9sh5FfcnZMVPCASH",
    },
}


def _canonical_network(network: str) -> str:
    """Normalize ``mainnet-beta`` to the canonical ``mainnet`` slug.

    L1 lock from PR #96 / #102 picked ``mainnet`` as the canonical network slug
    across every SDK. ``mainnet-beta`` is accepted as a backward compatible
    alias so credentials issued against either spelling round-trip cleanly.
    """
    return "mainnet" if network == "mainnet-beta" else network


STABLECOIN_TOKEN_PROGRAMS: dict[str, str] = {
    "USDC": TOKEN_PROGRAM,
    "USDT": TOKEN_PROGRAM,
    "USDG": TOKEN_2022_PROGRAM,
    "PYUSD": TOKEN_2022_PROGRAM,
    "CASH": TOKEN_2022_PROGRAM,
}


def default_rpc_url(network: str) -> str:
    """Return the default RPC endpoint for a Solana network."""
    network = _canonical_network(network)
    if network == "devnet":
        return "https://api.devnet.solana.com"
    if network == "localnet":
        return "http://localhost:8899"
    # Solana Labs still publishes RPC under the ``mainnet-beta`` host even
    # though the canonical SDK slug is ``mainnet``; mirror Rust and Ruby.
    return "https://api.mainnet-beta.solana.com"


def resolve_mint(currency: str, network: str) -> str:
    """Convert a symbolic currency into a mint address.

    Returns empty string for native SOL. Falls back to treating currency
    as a raw mint address if not found in KNOWN_MINTS.
    """
    upper = currency.upper()
    if upper == "SOL":
        return ""
    if upper in KNOWN_MINTS:
        networks = KNOWN_MINTS[upper]
        network = _canonical_network(network)
        return networks.get(network, networks.get("mainnet", currency))
    return currency


def stablecoin_symbol(currency: str) -> str | None:
    """Return the supported stablecoin symbol for a symbol or known mint."""
    upper = currency.upper()
    if upper in KNOWN_MINTS:
        return upper
    for symbol, networks in KNOWN_MINTS.items():
        if currency in networks.values():
            return symbol
    return None


def default_token_program_for_currency(currency: str, network: str) -> str:
    """Return the known default token program for a currency or mint."""
    symbol = stablecoin_symbol(resolve_mint(currency, network)) or stablecoin_symbol(currency)
    if symbol:
        return STABLECOIN_TOKEN_PROGRAMS[symbol]
    return TOKEN_PROGRAM


def is_native_sol(currency: str) -> bool:
    """Return True if the currency represents native SOL."""
    return currency.upper() == "SOL"


# Maximum number of additional split recipients on a single charge. Pinned to
# the Rust spine ``splits.len() > 8`` guard in
# ``rust/src/server/charge.rs::verify_versioned_transaction_pre_broadcast`` and
# the mirrored ``count($splits) > 8`` / ``splits.length > 8`` guards in PHP,
# Ruby, Go, Lua. Shared by the client fail-fast check and the server
# pre-broadcast verifier so the cap cannot drift between the two paths.
MAX_SPLITS = 8


@dataclass
class MethodDetails:
    """Solana-specific challenge method details."""

    network: str = "mainnet"
    decimals: int | None = None
    token_program: str | None = None
    fee_payer: bool = False
    fee_payer_key: str = ""
    recent_blockhash: str = ""
    splits: list[Split] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dict, omitting empty fields."""
        d: dict[str, Any] = {}
        if self.network:
            d["network"] = self.network
        if self.decimals is not None:
            d["decimals"] = self.decimals
        if self.token_program:
            d["tokenProgram"] = self.token_program
        if self.fee_payer:
            d["feePayer"] = self.fee_payer
        if self.fee_payer_key:
            d["feePayerKey"] = self.fee_payer_key
        if self.recent_blockhash:
            d["recentBlockhash"] = self.recent_blockhash
        if self.splits:
            d["splits"] = [s.to_dict() for s in self.splits]
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> MethodDetails:
        """Deserialize from a JSON-compatible dict."""
        splits = [Split.from_dict(s) for s in data.get("splits", [])]
        return cls(
            network=_canonical_network(data.get("network", "mainnet")),
            decimals=data.get("decimals"),
            token_program=data.get("tokenProgram"),
            fee_payer=data.get("feePayer", False),
            fee_payer_key=data.get("feePayerKey", ""),
            recent_blockhash=data.get("recentBlockhash", ""),
            splits=splits,
        )


@dataclass
class Split:
    """An additional transfer in the same asset."""

    recipient: str
    amount: str
    label: str = ""
    memo: str = ""
    ata_creation_required: bool = False

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"recipient": self.recipient, "amount": self.amount}
        if self.ata_creation_required:
            d["ataCreationRequired"] = self.ata_creation_required
        if self.label:
            d["label"] = self.label
        if self.memo:
            d["memo"] = self.memo
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Split:
        return cls(
            recipient=data["recipient"],
            amount=data["amount"],
            label=data.get("label", ""),
            memo=data.get("memo", ""),
            ata_creation_required=data.get("ataCreationRequired", False),
        )


@dataclass
class CredentialPayload:
    """Credential payload sent by clients."""

    type: str  # "transaction" or "signature"
    transaction: str = ""
    signature: str = ""

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"type": self.type}
        if self.transaction:
            d["transaction"] = self.transaction
        if self.signature:
            d["signature"] = self.signature
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CredentialPayload:
        return cls(
            type=data.get("type", ""),
            transaction=data.get("transaction", ""),
            signature=data.get("signature", ""),
        )
