"""On-chain glue for the payment-channels program.

This module is the Python counterpart of
``rust/crates/mpp/src/program/payment_channels.rs`` and
``go/paycore/paymentchannels/paymentchannels.go``: PDA derivation, associated
token derivation, voucher preimage bytes, and convenience instruction builders
for the push-mode session flow (``open`` + ``topUp``).

Instruction data and account metas are produced by the codama-py generated
client under :mod:`pay_kit.protocols.programs.paymentchannels` (rendered from
``idl/payment-channels.json`` by ``skills/pay-sdk-implementation/codegen``),
the same architecture as the Rust and Go ports. This module only adds what the
IDL cannot express:

- The production program id (``GuoKrza...``) overrides the IDL placeholder
  (``CQAyft83tN1w2bRofB5PZ79eVDU2xZUVo43LU1qL4zRg``), which is not the deployed
  program; every PDA derivation and instruction built here uses ``GuoKrza...``.
  The generated PDA helpers pin the placeholder and take no program id
  parameter, so the event-authority derivation stays here.
- The channel PDA is not declared in the IDL's ``pdas`` section, so its
  derivation is hand-written, mirroring ``find_channel_pda`` in the Rust spine.

The payment-channels program uses a single-byte instruction discriminator
(``open`` = 1, ``topUp`` = 3), not the 8-byte Anchor discriminator; the
generated builders encode it.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from solders.instruction import Instruction  # type: ignore[import-untyped]
from solders.pubkey import Pubkey  # type: ignore[import-untyped]

from pay_kit._paycore.solana import (
    ASSOCIATED_TOKEN_PROGRAM,
    SYSTEM_PROGRAM,
    TOKEN_PROGRAM,
)
from pay_kit.protocols.programs.paymentchannels.instructions.open import Open
from pay_kit.protocols.programs.paymentchannels.instructions.topUp import TopUp
from pay_kit.protocols.programs.paymentchannels.types.distributionEntry import (
    DistributionEntry,
)
from pay_kit.protocols.programs.paymentchannels.types.openArgs import (
    OpenArgs as _OpenArgs,
)
from pay_kit.protocols.programs.paymentchannels.types.topUpArgs import (
    TopUpArgs as _TopUpArgs,
)
from pay_kit.protocols.programs.paymentchannels.types.voucherArgs import VoucherArgs

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
    program_id: Pubkey = field(default_factory=lambda: PROGRAM_ID)


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
    (offset 32) || ``expiresAt`` as little-endian i64 (offset 40). Encoded by
    the generated ``VoucherArgs`` Borsh layout, the exact counterpart of the
    Rust spine delegating to its generated ``VoucherArgs``.

    Raises:
        ValueError: if ``channel_id`` does not encode to exactly 32 bytes.
    """
    channel_bytes = bytes(channel_id)
    if len(channel_bytes) != 32:
        raise ValueError(f"channel id must be exactly 32 bytes, got {len(channel_bytes)}")
    return bytes(
        VoucherArgs.layout.build(
            {
                "channelId": channel_id,
                "cumulativeAmount": cumulative,
                "expiresAt": expires_at,
            }
        )
    )


def find_channel_pda(
    payer: Pubkey,
    payee: Pubkey,
    mint: Pubkey,
    authorized_signer: Pubkey,
    salt: int,
    program_id: Pubkey = PROGRAM_ID,
) -> tuple[Pubkey, int]:
    """Derive the channel PDA, defaulting to the production program id.

    Seeds: ``["channel", payer, payee, mint, authorizedSigner, salt u64 LE]``.
    Mirrors ``find_channel_pda`` in the Rust spine, which takes the program id
    as its final parameter.
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
        program_id,
    )


def find_event_authority_pda(program_id: Pubkey = PROGRAM_ID) -> tuple[Pubkey, int]:
    """Derive the event-authority PDA, defaulting to the production program id.

    Seeds: ``["event_authority"]``. Mirrors ``find_event_authority_pda`` in the
    Rust spine. Stays hand-written because the generated helper derives against
    the IDL placeholder program id and takes no override.
    """
    return Pubkey.find_program_address([_EVENT_AUTHORITY_SEED], program_id)


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
    PDA, then delegates encoding and the 13 account metas to the generated
    ``Open`` builder against the production program id. Mirrors
    ``build_open_instruction`` in the Rust spine.
    """
    channel, _ = find_channel_pda(
        params.payer,
        params.payee,
        params.mint,
        params.authorized_signer,
        params.salt,
        params.program_id,
    )
    payer_token_account, _ = find_associated_token_address(params.payer, params.mint, params.token_program)
    channel_token_account, _ = find_associated_token_address(channel, params.mint, params.token_program)
    event_authority, _ = find_event_authority_pda(params.program_id)

    args = _OpenArgs(
        salt=params.salt,
        deposit=params.deposit,
        gracePeriod=params.grace_period,
        recipients=[DistributionEntry(recipient=entry.recipient, bps=entry.bps) for entry in params.recipients],
    )
    return Open(
        {"openArgs": args},
        {
            "payer": params.payer,
            "payee": params.payee,
            "mint": params.mint,
            "authorizedSigner": params.authorized_signer,
            "channel": channel,
            "payerTokenAccount": payer_token_account,
            "channelTokenAccount": channel_token_account,
            "tokenProgram": params.token_program,
            "systemProgram": Pubkey.from_string(SYSTEM_PROGRAM),
            "rent": Pubkey.from_string(_RENT_SYSVAR_ID),
            "associatedTokenProgram": Pubkey.from_string(ASSOCIATED_TOKEN_PROGRAM),
            "eventAuthority": event_authority,
            "selfProgram": params.program_id,
        },
        program_id=params.program_id,
    )


def build_top_up_instruction(params: TopUpParams) -> Instruction:
    """Build the ``topUp`` instruction with accounts in the exact Rust order.

    Derives the payer and channel ATAs, then delegates encoding and the 6
    account metas to the generated ``TopUp`` builder against the production
    program id. Mirrors ``build_top_up_instruction`` in the Rust spine.
    """
    payer_token_account, _ = find_associated_token_address(params.payer, params.mint, params.token_program)
    channel_token_account, _ = find_associated_token_address(params.channel, params.mint, params.token_program)

    return TopUp(
        {"topUpArgs": _TopUpArgs(amount=params.amount)},
        {
            "payer": params.payer,
            "channel": params.channel,
            "payerTokenAccount": payer_token_account,
            "channelTokenAccount": channel_token_account,
            "mint": params.mint,
            "tokenProgram": params.token_program,
        },
        program_id=PROGRAM_ID,
    )
