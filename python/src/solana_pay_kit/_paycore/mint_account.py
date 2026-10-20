"""On-chain SPL mint lookup: the token program and decimals of a mint.

A client that is not told a mint's token program (MPP ``methodDetails.
tokenProgram`` omitted) or decimals (x402 ``exact``, where decimals are not on
the wire) reads them from the mint account. draft-solana-charge-00 forbids any
fallback: "If that lookup fails, returns an unexpected owner, or cannot be
verified, clients MUST reject the challenge rather than falling back to the
Token Program." So the only way to obtain a :class:`MintAccount` is through
:func:`parse_mint_account`, which accepts nothing but an initialized mint owned
by the SPL Token or Token-2022 program; every failure raises
:class:`MintLookupError`.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Any

from solana_pay_kit._paycore.errors import InvalidChallengeError
from solana_pay_kit._paycore.solana import TOKEN_2022_PROGRAM, TOKEN_PROGRAM

__all__ = [
    "MINT_ACCOUNT_LEN",
    "MintAccount",
    "MintLookupError",
    "fetch_mint_account",
    "fetch_mint_account_sync",
    "parse_mint_account",
]

#: SPL Token mint base layout: COption<Pubkey> mint_authority (36), u64 supply
#: (8), u8 decimals @44, bool is_initialized @45, COption<Pubkey> freeze (36).
#: Token-2022 mints share this prefix and append extensions after it.
MINT_ACCOUNT_LEN = 82
_DECIMALS_OFFSET = 44
_IS_INITIALIZED_OFFSET = 45
_TOKEN_PROGRAMS = (TOKEN_PROGRAM, TOKEN_2022_PROGRAM)


class MintLookupError(InvalidChallengeError):
    """The mint could not be fetched, does not exist, or is not an SPL mint."""


@dataclass(frozen=True)
class MintAccount:
    """A verified SPL mint. Build it with :func:`parse_mint_account` only."""

    address: str
    #: The owning program: always the SPL Token or the Token-2022 program.
    token_program: str
    decimals: int


def parse_mint_account(address: str, owner: str, data: bytes) -> MintAccount:
    """Validate a fetched account as an initialized SPL mint."""
    if owner not in _TOKEN_PROGRAMS:
        raise MintLookupError(
            f"mint '{address}' is owned by unexpected program '{owner}'; expected the SPL Token or Token-2022 program"
        )
    if len(data) < MINT_ACCOUNT_LEN:
        raise MintLookupError(f"account '{address}' is not an SPL mint ({len(data)} bytes)")
    if data[_IS_INITIALIZED_OFFSET] != 1:
        raise MintLookupError(f"mint '{address}' is not initialized")
    return MintAccount(address=address, token_program=owner, decimals=data[_DECIMALS_OFFSET])


def _account_fields(result: Any) -> tuple[str, bytes] | None:
    """Normalize the RPC client shapes this SDK is used with to ``(owner, data)``.

    ``solana_pay_kit._paycore.rpc.SolanaRpc.get_account_info`` returns
    ``(data, owner)`` or ``None``; solana-py's ``AsyncClient`` returns a response
    whose ``.value`` is ``None`` or an ``Account`` with ``.owner`` / ``.data``.
    """
    if result is None:
        return None
    if isinstance(result, tuple):
        raw, owner = result  # pyright: ignore[reportUnknownVariableType]
        return str(owner), bytes(raw)  # pyright: ignore[reportUnknownArgumentType]
    value = getattr(result, "value", result)
    if value is None:
        return None
    owner = getattr(value, "owner", None)
    data = getattr(value, "data", None)
    if owner is None or data is None:
        raise MintLookupError("mint lookup returned an account without owner or data")
    return str(owner), bytes(data)


async def fetch_mint_account(rpc: Any, mint: str) -> MintAccount:
    """Fetch and verify ``mint`` through an async RPC client."""
    from solana_pay_kit._paycore.rpc import SolanaRpc

    if rpc is None:
        raise MintLookupError(f"cannot look up mint '{mint}': no RPC client configured")
    try:
        if isinstance(rpc, SolanaRpc):
            result = await rpc.get_account_info(mint)
        else:
            from solders.pubkey import Pubkey

            result = await rpc.get_account_info(Pubkey.from_string(mint))
        fields = _account_fields(result)
    except MintLookupError:
        raise
    except Exception as exc:  # noqa: BLE001 - any lookup failure rejects the challenge
        raise MintLookupError(f"mint lookup for '{mint}' failed: {exc}") from exc
    if fields is None:
        raise MintLookupError(f"mint account '{mint}' not found")
    owner, data = fields
    return parse_mint_account(mint, owner, data)


def fetch_mint_account_sync(rpc_url: str | None, mint: str) -> MintAccount:
    """Fetch and verify ``mint`` with one blocking ``getAccountInfo`` call.

    Used at server construction, which is synchronous.
    """
    if not rpc_url:
        raise MintLookupError(f"cannot look up mint '{mint}': no rpc_url configured")
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
    except Exception as exc:  # noqa: BLE001 - surface any RPC failure
        raise MintLookupError(f"failed to fetch mint '{mint}' from {rpc_url}: {exc}") from exc
    if "error" in body:
        raise MintLookupError(f"failed to fetch mint '{mint}' from {rpc_url}: {body['error']}")
    value = (body.get("result") or {}).get("value")
    if not value:
        raise MintLookupError(f"mint account '{mint}' not found on chain")
    owner = value.get("owner")
    data_field = value.get("data")
    if not isinstance(owner, str) or not isinstance(data_field, list) or not data_field:
        raise MintLookupError(f"mint account '{mint}' response has no owner or data")
    try:
        data = base64.b64decode(data_field[0])
    except Exception as exc:  # noqa: BLE001
        raise MintLookupError(f"mint account '{mint}' data is not base64") from exc
    return parse_mint_account(mint, owner, data)
