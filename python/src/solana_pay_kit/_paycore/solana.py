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


# Audit #37: canonical Solana network allowlist. The server rejects anything
# outside this set at boot rather than silently treating unknown slugs (typos,
# "testnet", or the RPC-hostname spelling "mainnet-beta") as mainnet. Mirrors
# Rust ``validate_network`` (rust/crates/mpp/src/protocol/solana.rs).
NETWORK_MAINNET = "mainnet"
NETWORK_DEVNET = "devnet"
NETWORK_LOCALNET = "localnet"
DEFAULT_NETWORK = NETWORK_MAINNET
_ALLOWED_NETWORKS = frozenset({NETWORK_MAINNET, NETWORK_DEVNET, NETWORK_LOCALNET})

# Audit #24: HMAC-SHA256 secret key minimum size. NIST SP 800-107 recommends a
# key at least as long as the hash output (32 bytes for SHA-256). Mirrors Rust
# ``MIN_SECRET_KEY_BYTES``.
MIN_SECRET_KEY_BYTES = 32


def validate_network(network: str) -> None:
    """Reject any network slug outside the canonical allowlist (Audit #37).

    ``mainnet-beta`` is canonicalized to ``mainnet`` first (backward-compat
    alias). Empty input gets a distinct message for clearer boot diagnostics.
    """
    if not network:
        raise ValueError("network is required (one of: mainnet, devnet, localnet)")
    canonical = _canonical_network(network)
    if canonical not in _ALLOWED_NETWORKS:
        raise ValueError(
            f"unknown network '{network}'; must be one of: mainnet, devnet, localnet "
            "('mainnet-beta' is accepted as an alias for 'mainnet')"
        )


def derive_default_realm(recipient: str) -> str:
    """Derive a per-recipient default realm (Audit #15).

    A shared static default realm puts every server that reuses a secret key in
    one HMAC credential namespace, enabling cross-service replay. The recipient
    pubkey is unique per merchant and already mandatory, so deriving the default
    realm from it gives two services with the same secret but different
    recipients different realms (different HMAC ids). Mirrors Rust
    ``derive_default_realm``: SHA-256 of the recipient, first 4 bytes mod 1e8.
    """
    import hashlib

    digest = hashlib.sha256(recipient.encode("utf-8")).digest()
    suffix = int.from_bytes(digest[:4], "big") % 100_000_000
    return f"App Id - #{suffix}"


def is_known_stablecoin_mint(currency: str) -> bool:
    """Return True if ``currency`` is a known stablecoin symbol or mint address."""
    return stablecoin_symbol(currency) is not None


def _is_valid_pubkey(value: str) -> bool:
    try:
        from solders.pubkey import Pubkey

        Pubkey.from_string(value)
        return True
    except Exception:
        return False


def resolve_server_token_program(currency: str, network: str, rpc_url: str | None) -> str | None:
    """Resolve the token program a server should advertise for ``currency`` (Audit #28).

    Mirrors Rust ``resolve_server_token_program``:

    - native SOL → ``None`` (no token program).
    - a known stablecoin symbol/mint → the program from the static table
      (correctly Token-2022 for PYUSD/USDG/CASH, classic Token for USDC/USDT).
    - an arbitrary mint address → fetch the mint account owner on-chain and
      return it, rejecting any owner that is not the SPL Token or Token-2022
      program. The server fails fast at boot if the mint is unreachable.
    - anything that is neither a known symbol nor a valid pubkey → reject.

    Unlike a silent fallback to the classic Token program, an arbitrary
    Token-2022 mint is resolved to its real owner so the emitted
    ``tokenProgram`` (and the derived ATAs) are correct.
    """
    if is_native_sol(currency):
        return None
    if is_known_stablecoin_mint(currency):
        return default_token_program_for_currency(currency, network)
    # Arbitrary currency: must be a real mint pubkey.
    if not _is_valid_pubkey(currency):
        raise ValueError(
            f"currency '{currency}' is neither a known stablecoin symbol nor a valid mint address"
        )
    owner = _fetch_mint_owner_sync(currency, rpc_url)
    if owner not in (TOKEN_PROGRAM, TOKEN_2022_PROGRAM):
        raise ValueError(
            f"mint '{currency}' is owned by an unexpected program '{owner}'; "
            "only the SPL Token and Token-2022 programs are supported"
        )
    return owner


def _fetch_mint_owner_sync(mint: str, rpc_url: str | None) -> str:
    """Fetch the owner program of ``mint`` via a synchronous getAccountInfo call.

    Runs once at server boot (``Mpp.__init__`` is synchronous). Raises if the
    RPC is unreachable or the mint account does not exist, so a misconfigured
    arbitrary mint fails fast rather than shipping a wrong ``tokenProgram``.
    """
    if not rpc_url:
        raise ValueError(
            f"cannot resolve token program for arbitrary mint '{mint}': no rpc_url configured"
        )
    import httpx

    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getAccountInfo",
        "params": [mint, {"encoding": "base64"}],
    }
    try:
        resp = httpx.post(rpc_url, json=payload, timeout=30.0)
        resp.raise_for_status()
        body = resp.json()
    except Exception as exc:  # noqa: BLE001 — surface any RPC failure at boot
        raise ValueError(f"failed to fetch mint '{mint}' owner from {rpc_url}: {exc}") from exc
    value = (body.get("result") or {}).get("value")
    if not value:
        raise ValueError(f"mint account '{mint}' not found on chain")
    owner = value.get("owner")
    if not owner:
        raise ValueError(f"mint account '{mint}' has no owner field in RPC response")
    return str(owner)


def validate_splits(splits: list[Split]) -> None:
    """Validate a split set at challenge issuance (Audit #21).

    Enforces, before the splits are embedded into a signed challenge:
    count <= ``MAX_SPLITS``; each recipient parses as a pubkey; each amount
    parses as a non-negative integer and is strictly positive; the aggregate
    does not overflow (Python ints are unbounded, but a parse failure is still
    rejected); and no duplicate recipients. Mirrors Rust ``validate_splits``.
    """
    if len(splits) > MAX_SPLITS:
        raise ValueError(f"too many splits: maximum is {MAX_SPLITS}")
    seen: set[str] = set()
    for split in splits:
        if not _is_valid_pubkey(split.recipient):
            raise ValueError(f"split recipient '{split.recipient}' is not a valid pubkey")
        try:
            amount = int(split.amount)
        except (ValueError, TypeError) as exc:
            raise ValueError(f"split amount '{split.amount}' is not a valid integer") from exc
        if amount <= 0:
            raise ValueError("split amount must be positive")
        if split.recipient in seen:
            raise ValueError(f"duplicate split recipient '{split.recipient}'")
        seen.add(split.recipient)


STABLECOIN_TOKEN_PROGRAMS: dict[str, str] = {
    "USDC": TOKEN_PROGRAM,
    "USDT": TOKEN_PROGRAM,
    "USDG": TOKEN_2022_PROGRAM,
    "PYUSD": TOKEN_2022_PROGRAM,
    "CASH": TOKEN_2022_PROGRAM,
}

# Base-unit precision (token decimals) per supported stablecoin. KNOWN_MINTS
# carries no decimals column, so this is the single source of truth for the
# decimals helper. Every supported stablecoin is 6-decimal today.
STABLECOIN_DECIMALS: dict[str, int] = {
    "USDC": 6,
    "USDT": 6,
    "USDG": 6,
    "PYUSD": 6,
    "CASH": 6,
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


def stablecoin_decimals(currency: str, network: str = "mainnet") -> int:
    """Return the base-unit precision for a stablecoin symbol or known mint.

    Accepts a symbol (``"USDC"``) or a raw mint address; resolves to the
    supported stablecoin and returns its decimals (USDC/USDT/PYUSD = 6). Falls
    back to 6 for an unknown currency, matching every supported stablecoin.
    """
    symbol = stablecoin_symbol(resolve_mint(currency, network)) or stablecoin_symbol(currency)
    return STABLECOIN_DECIMALS.get(symbol or "", 6)


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
