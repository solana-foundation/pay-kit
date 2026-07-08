"""Backwards-compatible re-export of the payment-channels core.

The implementation moved to :mod:`solana_pay_kit._paycore.paymentchannels` so the MPP
session flow and the x402 ``upto`` scheme can share it without either protocol
package depending on the other (mirrors the Go ``paycore/paymentchannels``
layout). This shim preserves the historical import path
``solana_pay_kit.protocols.mpp._paymentchannels`` for existing callers and tests; new
code should import from :mod:`solana_pay_kit._paycore.paymentchannels` directly.
"""

from __future__ import annotations

from solana_pay_kit._paycore.paymentchannels import (
    ED25519_PROGRAM_ID,
    PAYMENT_CHANNELS_PROGRAM_ID,
    PROGRAM_ID,
    SYSVAR_INSTRUCTIONS,
    VOUCHER_MAGIC,
    Distribution,
    OpenChannelParams,
    TopUpParams,
    build_distribute_instruction,
    build_ed25519_verify_instruction,
    build_open_instruction,
    build_reclaim_instruction,
    build_settle_and_seal_instructions,
    build_top_up_instruction,
    find_associated_token_address,
    find_channel_pda,
    find_event_authority_pda,
    treasury_owner,
    voucher_message_bytes,
)

__all__ = [
    "ED25519_PROGRAM_ID",
    "PAYMENT_CHANNELS_PROGRAM_ID",
    "PROGRAM_ID",
    "SYSVAR_INSTRUCTIONS",
    "VOUCHER_MAGIC",
    "Distribution",
    "OpenChannelParams",
    "TopUpParams",
    "build_distribute_instruction",
    "build_ed25519_verify_instruction",
    "build_open_instruction",
    "build_reclaim_instruction",
    "build_settle_and_seal_instructions",
    "build_top_up_instruction",
    "find_associated_token_address",
    "find_channel_pda",
    "find_event_authority_pda",
    "treasury_owner",
    "voucher_message_bytes",
]
