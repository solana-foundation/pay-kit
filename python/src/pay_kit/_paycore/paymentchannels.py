"""On-chain glue for the payment-channels program (shared core).

Canonical home for payment-channel PDA derivation, associated-token derivation,
voucher preimage bytes, and the convenience instruction builders (``open``,
``topUp``, ``settleAndFinalize``, ``distribute``, plus the Ed25519 voucher
precompile). Shared by the MPP session flow and the x402 ``upto`` scheme; it
lives in :mod:`pay_kit._paycore` so neither protocol package depends on the
other, mirroring the Go ``paycore/paymentchannels`` layout.

Instruction data and account metas are produced by the codama-py generated
client under :mod:`pay_kit.protocols.programs.paymentchannels` (rendered from
``idl/payment-channels.json`` by ``skills/pay-sdk-implementation/codegen``).
This module only adds what the IDL cannot express:

- The production program id (``CHNLxY...``) - matching the generated client's
  default - is used for every PDA derivation and instruction built here.
  The generated PDA helpers take no program id parameter, so the
  event-authority derivation stays here.
- The channel PDA is not declared in the IDL's ``pdas`` section, so its
  derivation is hand-written here.

The payment-channels program uses a single-byte instruction discriminator
(``open`` = 1, ``topUp`` = 3), not the 8-byte Anchor discriminator; the
generated builders encode it.
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
from pay_kit.protocols.programs.paymentchannels.instructions.distribute import Distribute
from pay_kit.protocols.programs.paymentchannels.instructions.open import Open
from pay_kit.protocols.programs.paymentchannels.instructions.settleAndFinalize import SettleAndFinalize
from pay_kit.protocols.programs.paymentchannels.instructions.topUp import TopUp
from pay_kit.protocols.programs.paymentchannels.types.distributeArgs import DistributeArgs
from pay_kit.protocols.programs.paymentchannels.types.distributionEntry import (
    DistributionEntry,
)
from pay_kit.protocols.programs.paymentchannels.types.openArgs import (
    OpenArgs as _OpenArgs,
)
from pay_kit.protocols.programs.paymentchannels.types.settleAndFinalizeArgs import SettleAndFinalizeArgs
from pay_kit.protocols.programs.paymentchannels.types.topUpArgs import (
    TopUpArgs as _TopUpArgs,
)
from pay_kit.protocols.programs.paymentchannels.types.voucherArgs import VoucherArgs

__all__ = [
    "ED25519_PROGRAM_ID",
    "PAYMENT_CHANNELS_PROGRAM_ID",
    "PROGRAM_ID",
    "SYSVAR_INSTRUCTIONS",
    "Distribution",
    "OpenChannelParams",
    "TopUpParams",
    "build_distribute_instruction",
    "build_ed25519_verify_instruction",
    "build_open_instruction",
    "build_settle_and_finalize_instructions",
    "build_top_up_instruction",
    "find_associated_token_address",
    "find_channel_pda",
    "find_event_authority_pda",
    "treasury_owner",
    "voucher_message_bytes",
]

#: The Ed25519 native signature-verification precompile program id. A settle
#: that redeems a voucher must place this instruction immediately before
#: settle_and_finalize so the program confirms the voucher signature by index.
ED25519_PROGRAM_ID = "Ed25519SigVerify111111111111111111111111111"

#: The Solana instructions sysvar, read by settle_and_finalize to locate the
#: preceding Ed25519 precompile by index.
SYSVAR_INSTRUCTIONS = "Sysvar1nstructions1111111111111111111111111"

# Canonical payment-channels program id deployed to the network. Matches the
# generated client's default; used for every PDA derivation and instruction.
PAYMENT_CHANNELS_PROGRAM_ID = "CHNLxYvVA28MJP9PrFuDXccuoGXAx7jBacfLEkahyGsX"

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
        rent_payer: The operator / fee payer that funds the channel PDA +
            escrow ATA rent at open (and reclaims it at finalize); a SIGNER on
            the open instruction. It is always the same key used as the
            transaction fee payer, so a single operator signature covers both
            roles. Not a wire/payload field. ``None`` defaults to ``payer``
            (the payer is its own rent payer / fee payer).
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
    rent_payer: Pubkey | None = None


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
    # Validate the integer fields against their on-chain widths up front so an
    # out-of-range value raises a clear ValueError here rather than a low-level
    # struct/Borsh error from PDA derivation or the generated encoder.
    if not 0 <= params.salt <= 0xFFFF_FFFF_FFFF_FFFF:
        raise ValueError(f"salt {params.salt} does not fit in u64")
    if not 0 <= params.deposit <= 0xFFFF_FFFF_FFFF_FFFF:
        raise ValueError(f"deposit {params.deposit} does not fit in u64")
    if not 0 <= params.grace_period <= 0xFFFF_FFFF:
        raise ValueError(f"grace_period {params.grace_period} does not fit in u32")
    for entry in params.recipients:
        if not 0 <= entry.bps <= 0xFFFF:
            raise ValueError(f"recipient bps {entry.bps} does not fit in u16")

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
    # rentPayer is the operator / fee payer that funds the channel rent. It is
    # required: server-side verify_open_tx rejects an open whose rentPayer is
    # not the operator, so there is no valid silent fallback to params.payer.
    if params.rent_payer is None:
        raise ValueError(
            "OpenChannelParams.rent_payer is required to build the open instruction "
            "(the operator / fee payer that funds the channel rent)"
        )
    return Open(
        {"openArgs": args},
        {
            "payer": params.payer,
            "rentPayer": params.rent_payer,
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


def build_ed25519_verify_instruction(authorized_signer: Pubkey, signature: bytes, message: bytes) -> Instruction:
    """Build the Ed25519 precompile instruction that verifies a voucher signature.

    The on-chain settle reads the voucher's Ed25519 signature from a sibling
    instruction; this precompile must sit immediately before ``settleAndFinalize``
    in the transaction. The public key, signature, and message all live in this
    instruction's own data, so the three offset fields point here (the ``0xffff``
    markers mean "current instruction"). Layout mirrors the Rust/Go builders:
    pubkey at byte 16, signature at 48, message at 112.

    Args:
        authorized_signer: The voucher's signer pubkey (verified key).
        signature: The 64-byte Ed25519 signature over ``message``.
        message: The signed voucher preimage (see :func:`voucher_message_bytes`).
    """
    if len(signature) != 64:
        raise ValueError(f"ed25519 signature must be 64 bytes, got {len(signature)}")
    public_key_offset = 16
    signature_offset = 48
    message_data_offset = 112
    current_instruction = 0xFFFF
    if len(message) > 0xFFFF:
        raise ValueError(f"voucher message too long: {len(message)} bytes")

    data = bytearray(message_data_offset + len(message))
    data[0] = 1  # num_signatures
    data[1] = 0  # padding
    struct.pack_into("<H", data, 2, signature_offset)
    struct.pack_into("<H", data, 4, current_instruction)
    struct.pack_into("<H", data, 6, public_key_offset)
    struct.pack_into("<H", data, 8, current_instruction)
    struct.pack_into("<H", data, 10, message_data_offset)
    struct.pack_into("<H", data, 12, len(message))
    struct.pack_into("<H", data, 14, current_instruction)
    data[public_key_offset : public_key_offset + 32] = bytes(authorized_signer)
    data[signature_offset : signature_offset + 64] = signature
    data[message_data_offset:] = message

    return Instruction(Pubkey.from_string(ED25519_PROGRAM_ID), bytes(data), [])


def treasury_owner() -> Pubkey:
    """Treasury owner baked into the deployed (mainnet-build) payment-channels
    program; the treasury ATA is ATA(treasury_owner, mint, token_program).
    Mirrors the Rust/Go ``TreasuryOwner``."""
    return Pubkey.from_string("Cs2zdfUNonRdRGsiZUQQLdTxzxVvJZmgiX2mpLYKuEqP")


def build_settle_and_finalize_instructions(
    *,
    merchant: Pubkey,
    channel: Pubkey,
    authorized_signer: Pubkey,
    signature: bytes | None,
    cumulative: int,
    expires_at: int,
    program_id: Pubkey = PROGRAM_ID,
) -> list[Instruction]:
    """Build the settle-and-finalize instruction set.

    When a voucher was recorded, prepend the Ed25519 precompile that verifies it
    (the program reads the signature from the sibling instruction by index) and
    set ``hasVoucher``. Returns ``[ed25519?, settleAndFinalize]`` in the order
    the program expects.
    """
    instructions: list[Instruction] = []
    has_voucher = 0
    if signature is not None:
        message = voucher_message_bytes(channel, cumulative, expires_at)
        instructions.append(build_ed25519_verify_instruction(authorized_signer, signature, message))
        has_voucher = 1

    settle = SettleAndFinalize(
        {
            # The program reads the voucher from the preceding ed25519 precompile;
            # settle_and_finalize carries only the hasVoucher flag.
            "settleAndFinalizeArgs": SettleAndFinalizeArgs(hasVoucher=has_voucher),
        },
        {
            "merchant": merchant,
            "channel": channel,
            "instructionsSysvar": Pubkey.from_string(SYSVAR_INSTRUCTIONS),
        },
        program_id=program_id,
    )
    instructions.append(settle)
    return instructions


def build_distribute_instruction(
    *,
    channel: Pubkey,
    payer: Pubkey,
    payee: Pubkey,
    mint: Pubkey,
    recipients: list[Distribution],
    token_program: Pubkey,
    program_id: Pubkey = PROGRAM_ID,
    treasury: Pubkey | None = None,
    rent_payer: Pubkey | None = None,
) -> Instruction:
    """Build the distribute instruction that pays out a settled channel.

    Derives the channel / payer / payee / treasury ATAs and one ATA per split
    recipient (appended as writable remaining accounts, mirroring the Rust/Go
    builders).

    ``rent_payer`` is the operator recorded at open; it reclaims the channel
    PDA + escrow ATA rent at finalize (writable, not a signer). It is required.
    """
    if rent_payer is None:
        raise ValueError("rent_payer is required (the operator recorded at open)")
    owner = treasury if treasury is not None else treasury_owner()
    channel_token, _ = find_associated_token_address(channel, mint, token_program)
    payer_token, _ = find_associated_token_address(payer, mint, token_program)
    payee_token, _ = find_associated_token_address(payee, mint, token_program)
    treasury_token, _ = find_associated_token_address(owner, mint, token_program)
    event_authority, _ = find_event_authority_pda(program_id)

    entries: list[DistributionEntry] = []
    remaining: list[AccountMeta] = []
    for entry in recipients:
        recipient_token, _ = find_associated_token_address(entry.recipient, mint, token_program)
        remaining.append(AccountMeta(pubkey=recipient_token, is_signer=False, is_writable=True))
        entries.append(DistributionEntry(recipient=entry.recipient, bps=entry.bps))

    return Distribute(
        {"distributeArgs": DistributeArgs(recipients=entries)},
        {
            "channel": channel,
            "payer": payer,
            "rentPayer": rent_payer,
            "channelTokenAccount": channel_token,
            "payerTokenAccount": payer_token,
            "payeeTokenAccount": payee_token,
            "treasuryTokenAccount": treasury_token,
            "mint": mint,
            "tokenProgram": token_program,
            "eventAuthority": event_authority,
            "selfProgram": program_id,
        },
        program_id=program_id,
        remaining_accounts=remaining or None,
    )
