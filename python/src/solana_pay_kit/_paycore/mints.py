"""Stablecoin mint resolution and ATA derivation over the shared Solana tables.

Mirrors PHP ``PayCore/Solana/Mints.php``. All mint/program tables live in
``solana_pay_kit._paycore.solana`` and are reused here rather than duplicated, so the
x402 and MPP adapters always agree on wire values.
"""

from __future__ import annotations

from solders.pubkey import Pubkey

from solana_pay_kit._paycore.solana import (
    ASSOCIATED_TOKEN_PROGRAM,
    SYSTEM_PROGRAM,
    TOKEN_2022_PROGRAM,
    TOKEN_PROGRAM,
    default_token_program_for_currency,
    resolve_mint,
    stablecoin_symbol,
)

__all__ = [
    "ASSOCIATED_TOKEN_PROGRAM",
    "SYSTEM_PROGRAM",
    "TOKEN_PROGRAM",
    "TOKEN_2022_PROGRAM",
    "resolve_stablecoin_mint",
    "resolve",
    "token_program_for",
    "symbol_for",
    "derive_ata",
]


def resolve_stablecoin_mint(currency: str, network: str = "mainnet") -> str | None:
    """Resolve a stablecoin symbol or raw mint to a concrete mint pubkey.

    Native ``SOL`` returns ``None`` (no mint). Unknown networks fall back to the
    mainnet row, so ``localnet`` resolves to the mainnet mint (caveat #1:
    Surfpool clones mainnet state).
    """
    if currency.upper() == "SOL":
        return None
    mint = resolve_mint(currency, network)
    return mint or None


# Alias matching the blueprint's `resolve` contract for sibling modules.
def resolve(currency: str, network: str = "mainnet") -> str | None:
    """Alias for :func:`resolve_stablecoin_mint`."""
    return resolve_stablecoin_mint(currency, network)


def token_program_for(currency: str, network: str = "mainnet") -> str:
    """Return the SPL token program that owns the currency's mint."""
    return default_token_program_for_currency(currency, network)


def symbol_for(currency: str, network: str = "mainnet") -> str | None:
    """Reverse lookup: symbol for a stablecoin symbol or known mint, else None."""
    symbol = stablecoin_symbol(currency)
    if symbol is not None:
        return symbol
    resolved = resolve_stablecoin_mint(currency, network)
    if resolved is None or resolved == currency:
        return None
    return stablecoin_symbol(resolved)


def derive_ata(owner: str, mint: str, token_program: str) -> str:
    """Derive the Associated Token Account address for (owner, mint, program)."""
    ata, _ = Pubkey.find_program_address(
        [
            bytes(Pubkey.from_string(owner)),
            bytes(Pubkey.from_string(token_program)),
            bytes(Pubkey.from_string(mint)),
        ],
        Pubkey.from_string(ASSOCIATED_TOKEN_PROGRAM),
    )
    return str(ata)
