"""Hand-written on-chain glue for the payment-channels program.

This module is the Python counterpart of
``rust/crates/mpp/src/program/payment_channels.rs`` and
``go/paycore/paymentchannels/paymentchannels.go``: PDA derivation, associated
token derivation, voucher preimage bytes, and convenience instruction builders
for the push-mode session flow (``open`` + ``topUp``).

Everything here mirrors the Rust spine so the wire format and on-chain paths
stay byte-identical across the language SDKs. In particular the production
program id pinned here (``GuoKrza...``) overrides the IDL placeholder
(``CQAyft83tN1w2bRofB5PZ79eVDU2xZUVo43LU1qL4zRg``), which is not the deployed
program; every PDA derivation and instruction built here uses ``GuoKrza...``.

There is no Borsh library in the Python stack, so the instruction data and the
voucher preimage are hand-packed with :mod:`struct`. The payment-channels
program uses a single-byte instruction discriminator (``open`` = 1,
``topUp`` = 3), not the 8-byte Anchor discriminator.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from solders.instruction import AccountMeta, Instruction  # type: ignore[import-untyped]
from solders.pubkey import Pubkey  # type: ignore[import-untyped]

from pay_kit._paycore.solana import (
    ASSOCIATED_TOKEN_PROGRAM,
    SYSTEM_PROGRAM,
    TOKEN_PROGRAM,
)

__all__ = [
    "PAYMENT_CHANNELS_PROGRAM_ID",
    "PROGRAM_ID",
    "Distribution",
    "OpenChannelParams",
    "TopUpParams",
    "build_open_instruction",
    "build_top_up_instruction",
    "find_associated_token_address",
    "find_channel_pda",
    "find_event_authority_pda",
    "voucher_message_bytes",
]

# Canonical payment-channels program id deployed to the network. The IDL
# placeholder ``CQAyft83tN1w2bRofB5PZ79eVDU2xZUVo43LU1qL4zRg`` is NOT the
# production deployment; mirrors ``PAYMENT_CHANNELS_PROGRAM_ID`` in the Rust
# spine and ``ProgramID`` in the Go port.
PAYMENT_CHANNELS_PROGRAM_ID = "GuoKrzaBiZnW5DvJ3yZVE7xHqbcBvaX9SH6P6Cn9gNvc"

#: Parsed production program id used for derivation and instruction emission.
PROGRAM_ID = Pubkey.from_string(PAYMENT_CHANNELS_PROGRAM_ID)

# Channel PDA seed prefix. Mirrors ``CHANNEL_SEED`` in the Rust spine.
_CHANNEL_SEED = b"channel"

# Event-authority PDA seed prefix. Mirrors ``EVENT_AUTHORITY_SEED`` in Rust.
_EVENT_AUTHORITY_SEED = b"event_authority"

# Single-byte instruction discriminators (NOT 8-byte Anchor). Mirrors the
# discriminator constants in the payment-channels program.
_OPEN_DISCRIMINATOR = 1
_TOP_UP_DISCRIMINATOR = 3

# Rent sysvar id. Mirrors ``RENT_SYSVAR_ID`` in the Rust spine.
_RENT_SYSVAR_ID = "SysvarRent111111111111111111111111111111111"


@dataclass(frozen=True)
class Distribution:
    """A single payout recipient and its basis-point share.

    Mirrors the ``Distribution`` struct in the Rust spine.
    """

    recipient: Pubkey
    bps: int


@dataclass
class OpenChannelParams:
    """Inputs required to build an ``open`` instruction.

    Mirrors ``OpenChannelParams`` in the Rust spine. ``token_program`` defaults
    to the SPL Token program; pass the Token-2022 program id for Token-2022
    mints.
    """

    payer: Pubkey
    payee: Pubkey
    mint: Pubkey
    authorized_signer: Pubkey
    salt: int
    deposit: int
    grace_period: int
    recipients: list[Distribution] = field(default_factory=list)
    token_program: Pubkey = field(default_factory=lambda: Pubkey.from_string(TOKEN_PROGRAM))


@dataclass
class TopUpParams:
    """Inputs required to build a ``topUp`` instruction.

    Mirrors the ``build_top_up_instruction`` arguments in the Rust spine.
    """

    payer: Pubkey
    channel: Pubkey
    mint: Pubkey
    amount: int
    token_program: Pubkey = field(default_factory=lambda: Pubkey.from_string(TOKEN_PROGRAM))


def voucher_message_bytes(channel_id: Pubkey, cumulative: int, expires_at: int) -> bytes:
    """Return the 48-byte voucher preimage signed by the authorized signer.

    Layout: ``channelId`` (32) || ``cumulativeAmount`` as little-endian u64
    (offset 32) || ``expiresAt`` as little-endian i64 (offset 40). This is the
    exact Borsh layout of ``VoucherArgs``. Mirrors ``voucher_message_bytes`` in
    the Rust spine.

    Raises:
        ValueError: if ``channel_id`` does not encode to exactly 32 bytes.
    """
    channel_bytes = bytes(channel_id)
    if len(channel_bytes) != 32:
        raise ValueError(f"channel id must be exactly 32 bytes, got {len(channel_bytes)}")
    return channel_bytes + struct.pack("<Q", cumulative) + struct.pack("<q", expires_at)


def find_channel_pda(
    payer: Pubkey,
    payee: Pubkey,
    mint: Pubkey,
    authorized_signer: Pubkey,
    salt: int,
) -> tuple[Pubkey, int]:
    """Derive the channel PDA against the production program id.

    Seeds: ``["channel", payer, payee, mint, authorizedSigner, salt u64 LE]``.
    Mirrors ``find_channel_pda`` in the Rust spine.
    """
    return Pubkey.find_program_address(
        [
            _CHANNEL_SEED,
            bytes(payer),
            bytes(payee),
            bytes(mint),
            bytes(authorized_signer),
            struct.pack("<Q", salt),
        ],
        PROGRAM_ID,
    )


def find_event_authority_pda() -> tuple[Pubkey, int]:
    """Derive the event-authority PDA against the production program id.

    Seeds: ``["event_authority"]``. Mirrors ``find_event_authority_pda`` in the
    Rust spine.
    """
    return Pubkey.find_program_address([_EVENT_AUTHORITY_SEED], PROGRAM_ID)


def find_associated_token_address(
    owner: Pubkey,
    mint: Pubkey,
    token_program: Pubkey,
) -> tuple[Pubkey, int]:
    """Derive the associated token account address for ``(owner, mint, program)``.

    Seeds: ``[owner, token_program, mint]`` under the associated-token program.
    Mirrors ``find_associated_token_address`` in the Rust spine and ``derive_ata``
    in :mod:`pay_kit._paycore.mints`.
    """
    return Pubkey.find_program_address(
        [bytes(owner), bytes(token_program), bytes(mint)],
        Pubkey.from_string(ASSOCIATED_TOKEN_PROGRAM),
    )


def build_open_instruction(params: OpenChannelParams) -> Instruction:
    """Build the ``open`` instruction with accounts in the exact Rust order.

    Derives the channel PDA, the payer and channel ATAs, and the event-authority
    PDA, then emits 13 account metas in the canonical order against the
    production program id. Mirrors ``build_open_instruction`` in the Rust spine.

    Instruction data (single-byte discriminator ``1`` + hand-packed Borsh):
    ``\\x01`` || ``salt`` u64 LE || ``deposit`` u64 LE || ``grace_period`` u32 LE
    || ``len(recipients)`` u32 LE || for each recipient: pubkey (32) || ``bps``
    u16 LE.
    """
    channel, _ = find_channel_pda(
        params.payer,
        params.payee,
        params.mint,
        params.authorized_signer,
        params.salt,
    )
    payer_token_account, _ = find_associated_token_address(params.payer, params.mint, params.token_program)
    channel_token_account, _ = find_associated_token_address(channel, params.mint, params.token_program)
    event_authority, _ = find_event_authority_pda()

    system_program = Pubkey.from_string(SYSTEM_PROGRAM)
    rent = Pubkey.from_string(_RENT_SYSVAR_ID)
    associated_token_program = Pubkey.from_string(ASSOCIATED_TOKEN_PROGRAM)

    accounts = [
        AccountMeta(params.payer, True, True),
        AccountMeta(params.payee, False, False),
        AccountMeta(params.mint, False, False),
        AccountMeta(params.authorized_signer, False, False),
        AccountMeta(channel, False, True),
        AccountMeta(payer_token_account, False, True),
        AccountMeta(channel_token_account, False, True),
        AccountMeta(params.token_program, False, False),
        AccountMeta(system_program, False, False),
        AccountMeta(rent, False, False),
        AccountMeta(associated_token_program, False, False),
        AccountMeta(event_authority, False, False),
        AccountMeta(PROGRAM_ID, False, False),
    ]

    data = bytearray()
    data.append(_OPEN_DISCRIMINATOR)
    data += struct.pack("<Q", params.salt)
    data += struct.pack("<Q", params.deposit)
    data += struct.pack("<I", params.grace_period)
    data += struct.pack("<I", len(params.recipients))
    for entry in params.recipients:
        data += bytes(entry.recipient)
        data += struct.pack("<H", entry.bps)

    return Instruction(PROGRAM_ID, bytes(data), accounts)


def build_top_up_instruction(params: TopUpParams) -> Instruction:
    """Build the ``topUp`` instruction with accounts in the exact Rust order.

    Derives the payer and channel ATAs, then emits 6 account metas in the
    canonical order against the production program id. Mirrors
    ``build_top_up_instruction`` in the Rust spine.

    Instruction data (single-byte discriminator ``3`` + hand-packed Borsh):
    ``\\x03`` || ``amount`` u64 LE.
    """
    payer_token_account, _ = find_associated_token_address(params.payer, params.mint, params.token_program)
    channel_token_account, _ = find_associated_token_address(params.channel, params.mint, params.token_program)

    accounts = [
        AccountMeta(params.payer, True, True),
        AccountMeta(params.channel, False, True),
        AccountMeta(payer_token_account, False, True),
        AccountMeta(channel_token_account, False, True),
        AccountMeta(params.mint, False, False),
        AccountMeta(params.token_program, False, False),
    ]

    data = bytes([_TOP_UP_DISCRIMINATOR]) + struct.pack("<Q", params.amount)

    return Instruction(PROGRAM_ID, data, accounts)
