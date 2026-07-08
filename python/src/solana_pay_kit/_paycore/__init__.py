"""Shared payment-core primitives used by both protocol packages.

The analog of the Rust ``core`` crate: enums, mints, RPC, replay store, network
check, transaction helpers, and the wire error model. x402 and MPP both depend
on ``_paycore``; neither protocol depends on the other.
"""

from __future__ import annotations

from solana_pay_kit._paycore.currency import Currency
from solana_pay_kit._paycore.mints import (
    ASSOCIATED_TOKEN_PROGRAM,
    TOKEN_2022_PROGRAM,
    TOKEN_PROGRAM,
    derive_ata,
    resolve,
    resolve_stablecoin_mint,
    symbol_for,
    token_program_for,
)
from solana_pay_kit._paycore.network import (
    AUTOFUND_LAMPORTS,
    MIN_FEE_PAYER_LAMPORTS,
    PUBLIC_RPC_URLS,
    SOLANA_DEVNET_CAIP2,
    SOLANA_MAINNET_CAIP2,
    Network,
)
from solana_pay_kit._paycore.stablecoin import Stablecoin

__all__ = [
    "Currency",
    "Stablecoin",
    "Network",
    "PUBLIC_RPC_URLS",
    "SOLANA_MAINNET_CAIP2",
    "SOLANA_DEVNET_CAIP2",
    "MIN_FEE_PAYER_LAMPORTS",
    "AUTOFUND_LAMPORTS",
    "resolve_stablecoin_mint",
    "resolve",
    "token_program_for",
    "symbol_for",
    "derive_ata",
    "ASSOCIATED_TOKEN_PROGRAM",
    "TOKEN_PROGRAM",
    "TOKEN_2022_PROGRAM",
]
