"""On-chain glue for the payment-channels program.

Provides PDA derivation, associated token derivation, voucher preimage bytes,
and convenience instruction builders for the push-mode session flow
(``open`` + ``topUp``).

Instruction data and account metas are produced by the codama-py generated
client under :mod:`pay_kit.protocols.programs.paymentchannels` (rendered from
``idl/payment-channels.json`` by ``skills/pay-sdk-implementation/codegen``).
This module only adds what the IDL cannot express:

- The production program id (``GuoKrza...``) overrides the IDL placeholder
  (``CQAyft83tN1w2bRofB5PZ79eVDU2xZUVo43LU1qL4zRg``), which is not the deployed
  program; every PDA derivation and instruction built here uses ``GuoKrza...``.
  The generated PDA helpers pin the placeholder and take no program id
  parameter, so the event-authority derivation stays here.
- The channel PDA is not declared in the IDL's ``pdas`` section, so its
  derivation is hand-written here.

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
# production deployment and must not be used for derivation or instruction
# emission.
PAYMENT_CHANNELS_PROGRAM_ID = "GuoKrzaBiZnW5DvJ3yZVE7xHqbcBvaX9SH6P6Cn9gNvc"

#: Parsed production program id used for derivation and instruction emission.
PROGRAM_ID = Pubkey.from_string(PAYMENT_CHANNELS_PROGRAM_ID)

# Channel PDA seed prefix.
_CHANNEL_SEED = b"channel"

# Event-authority PDA seed prefix.
_EVENT_AUTHORITY_SEED = b"event_authority"

# Rent sysvar id.
_RENT_SYSVAR_ID = "SysvarRent111111111111111111111111111111111"


@dataclass(frozen=True)
class Distribution:
    """A single payout recipient and its basis-point share.

    Attributes:
        recipient: The account that receives this share of channel payouts.
        bps: The recipient's share expressed in basis points (1/100th of a
            percent).
    """

    recipient: Pubkey
    bps: int


@dataclass
class OpenChannelParams:
    """Inputs required to build an ``open`` instruction.

    ``token_program`` defaults to the SPL Token program; pass the Token-2022
    program id for Token-2022 mints.

    Attributes:
        payer: The account funding the channel and signing the open.
        payee: The counterparty the channel pays out to.
        mint: The SPL token mint the channel is denominated in.
        authorized_signer: The key authorized to sign vouchers that redeem
            funds from the channel.
        salt: A caller-chosen u64 that disambiguates channels sharing the same
            payer, payee, mint, and signer; part of the channel PDA seeds.
        deposit: The initial token amount deposited into the channel.
        grace_period: Seconds the payee retains to redeem after the channel
            closes before funds are reclaimable by the payer.
        recipients: Optional payout split; each entry's basis points apportion
            the channel's payouts. Empty means a single implicit payee.
        token_program: The token program owning the mint (SPL Token or
            Token-2022).
        program_id: The payment-channels program the instruction targets;
            defaults to the production deployment.
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

    Attributes:
        payer: The account adding funds to the channel and signing the top-up.
        channel: The channel PDA being funded.
        mint: The SPL token mint the channel is denominated in.
        amount: The token amount to add to the channel's balance.
        token_program: The token program owning the mint (SPL Token or
            Token-2022).
    """

    payer: Pubkey
    channel: Pubkey
    mint: Pubkey
    amount: int
    token_program: Pubkey = field(default_factory=lambda: Pubkey.from_string(TOKEN_PROGRAM))


def voucher_message_bytes(channel_id: Pubkey, cumulative: int, expires_at: int) -> bytes:
    """Return the 48-byte voucher preimage signed by the authorized signer.

    The signer signs this exact byte string to authorize redeeming
    ``cumulative`` lamports from the channel up to ``expires_at``.

    Layout: ``channelId`` (32) || ``cumulativeAmount`` as little-endian u64
    (offset 32) || ``expiresAt`` as little-endian i64 (offset 40). Encoded by
    the generated ``VoucherArgs`` Borsh layout.

    Args:
        channel_id: The channel PDA the voucher authorizes spending from.
        cumulative: The running total amount the voucher authorizes, encoded as
            a little-endian u64.
        expires_at: Unix timestamp after which the voucher is no longer valid,
            encoded as a little-endian i64.

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

    The channel address is fully determined by its payer, payee, mint,
    authorized signer, and salt, so the same inputs always resolve to the same
    channel.

    Seeds: ``["channel", payer, payee, mint, authorizedSigner, salt u64 LE]``.

    Args:
        payer: The account funding the channel.
        payee: The counterparty the channel pays out to.
        mint: The SPL token mint the channel is denominated in.
        authorized_signer: The key authorized to sign vouchers for the channel.
        salt: A caller-chosen u64 disambiguating channels with otherwise
            identical seeds, packed little-endian into the seeds.
        program_id: The payment-channels program to derive against; defaults to
            the production deployment.

    Returns:
        A ``(pubkey, bump)`` pair for the derived channel PDA.
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

    The event authority is the program-signed account the program uses to emit
    its CPI event log.

    Seeds: ``["event_authority"]``. Derived here rather than via the generated
    helper because that helper pins the IDL placeholder program id and accepts
    no override.

    Args:
        program_id: The payment-channels program to derive against; defaults to
            the production deployment.

    Returns:
        A ``(pubkey, bump)`` pair for the derived event-authority PDA.
    """
    return Pubkey.find_program_address([_EVENT_AUTHORITY_SEED], program_id)


def find_associated_token_address(
    owner: Pubkey,
    mint: Pubkey,
    token_program: Pubkey,
) -> tuple[Pubkey, int]:
    """Derive the associated token account address for ``(owner, mint, program)``.

    Seeds: ``[owner, token_program, mint]`` under the associated-token program.

    Args:
        owner: The account that owns the token account.
        mint: The SPL token mint the account holds.
        token_program: The token program owning the mint (SPL Token or
            Token-2022).

    Returns:
        A ``(pubkey, bump)`` pair for the derived associated token account.
    """
    return Pubkey.find_program_address(
        [bytes(owner), bytes(token_program), bytes(mint)],
        Pubkey.from_string(ASSOCIATED_TOKEN_PROGRAM),
    )


def build_open_instruction(params: OpenChannelParams) -> Instruction:
    """Build the ``open`` instruction that creates and funds a channel.

    Derives the channel PDA, the payer and channel ATAs, and the event-authority
    PDA, then delegates encoding and the 13 account metas to the generated
    ``Open`` builder against the target program id. The account metas are
    emitted in the fixed order the program expects.

    Args:
        params: The payer, payee, mint, signer, salt, deposit, grace period,
            recipient split, token program, and target program id for the
            channel to open.

    Returns:
        The assembled ``open`` instruction ready to add to a transaction.
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
    """Build the ``topUp`` instruction that adds funds to an open channel.

    Derives the payer and channel ATAs, then delegates encoding and the 6
    account metas to the generated ``TopUp`` builder against the production
    program id. The account metas are emitted in the fixed order the program
    expects.

    Args:
        params: The payer, channel, mint, amount, and token program for the
            top-up.

    Returns:
        The assembled ``topUp`` instruction ready to add to a transaction.
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
