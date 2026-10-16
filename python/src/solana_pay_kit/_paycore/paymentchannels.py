"""On-chain glue for the payment-channels program (shared core).

Canonical home for payment-channel PDA derivation, associated-token derivation,
voucher preimage bytes, and the convenience instruction builders (``open``,
``topUp``, ``settleAndSeal``, ``distribute``, ``reclaim``, plus the Ed25519
voucher precompile). Shared by the MPP session flow and the x402 ``upto``
scheme; it
lives in :mod:`solana_pay_kit._paycore` so neither protocol package depends on the
other, mirroring the Go ``paycore/paymentchannels`` layout.

Instruction data and account metas are produced by the Codama-generated
client under :mod:`solana_pay_kit.protocols.programs.paymentchannels` (rendered from
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

from solana_pay_kit._paycore.solana import (
    ASSOCIATED_TOKEN_PROGRAM,
    SYSTEM_PROGRAM,
    TOKEN_PROGRAM,
)
from solana_pay_kit.protocols.programs.paymentchannels.accounts.channel import Channel
from solana_pay_kit.protocols.programs.paymentchannels.instructions.distribute import distribute
from solana_pay_kit.protocols.programs.paymentchannels.instructions.open import open as open_channel
from solana_pay_kit.protocols.programs.paymentchannels.instructions.reclaim import reclaim
from solana_pay_kit.protocols.programs.paymentchannels.instructions.settle_and_seal import settle_and_seal
from solana_pay_kit.protocols.programs.paymentchannels.instructions.top_up import top_up
from solana_pay_kit.protocols.programs.paymentchannels.shared.instruction import AccountMeta as ProgramAccountMeta
from solana_pay_kit.protocols.programs.paymentchannels.shared.instruction import Instruction as ProgramInstruction
from solana_pay_kit.protocols.programs.paymentchannels.shared.pubkey import Pubkey as ProgramPubkey
from solana_pay_kit.protocols.programs.paymentchannels.types.account_discriminator import AccountDiscriminator
from solana_pay_kit.protocols.programs.paymentchannels.types.distribute_args import DistributeArgs
from solana_pay_kit.protocols.programs.paymentchannels.types.distribution_entry import (
    DistributionEntry,
)
from solana_pay_kit.protocols.programs.paymentchannels.types.open_args import (
    OpenArgs as _OpenArgs,
)
from solana_pay_kit.protocols.programs.paymentchannels.types.settle_and_seal_args import SettleAndSealArgs
from solana_pay_kit.protocols.programs.paymentchannels.types.top_up_args import (
    TopUpArgs as _TopUpArgs,
)
from solana_pay_kit.protocols.programs.paymentchannels.types.voucher_args import VoucherArgs

__all__ = [
    "ED25519_PROGRAM_ID",
    "OPEN_SLOT_WINDOW",
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
    "decode_channel_account",
    "find_associated_token_address",
    "find_channel_pda",
    "find_event_authority_pda",
    "treasury_owner",
    "voucher_message_bytes",
]

#: The Ed25519 native signature-verification precompile program id. A settle
#: that redeems a voucher must place this instruction immediately before
#: settle_and_seal so the program confirms the voucher signature by index.
ED25519_PROGRAM_ID = "Ed25519SigVerify111111111111111111111111111"

#: The Solana instructions sysvar, read by settle_and_seal to locate the
#: preceding Ed25519 precompile by index.
SYSVAR_INSTRUCTIONS = "Sysvar1nstructions1111111111111111111111111"

#: Constant 2-byte magic prefixed to every signed voucher payload
#: (``[0x56, 0x01]``). Signers prepend it; verifiers (and the program, which
#: rejects a bad prefix with ``voucherBadMagic``) check it. It lives only in
#: the signed byte payload, never in voucher wire JSON.
VOUCHER_MAGIC = bytes([0x56, 0x01])

# Canonical payment-channels program id deployed to the network. Matches the
# generated client's default; used for every PDA derivation and instruction.
PAYMENT_CHANNELS_PROGRAM_ID = "CHNLxYvVA28MJP9PrFuDXccuoGXAx7jBacfLEkahyGsX"

#: Parsed production program id used for derivation and instruction emission.
PROGRAM_ID = Pubkey.from_string(PAYMENT_CHANNELS_PROGRAM_ID)

#: The program's channel-open freshness window, in slots: an open is accepted
#: only while ``openSlot <= clock.slot`` and ``clock.slot - openSlot <= 1500``
#: (~10 minutes). Servers bind an open to its challenge with the same window:
#: ``openSlot <= recentSlot`` and ``recentSlot - openSlot <= OPEN_SLOT_WINDOW``.
OPEN_SLOT_WINDOW = 1500

#: Phantom/Solflare Lighthouse program id. Both wallets inject assertion
#: instructions after what a dapp asked them to sign, so an open signed through
#: them arrives with a Lighthouse suffix a verifier must tolerate rather than
#: treat as a smuggled instruction.
LIGHTHOUSE_PROGRAM = "L2TExMFKdjpN9kozasaurPirfHy9P8sbXoAN1qA3S95"

#: ``SetComputeUnitLimit`` / ``SetComputeUnitPrice`` instruction type bytes.
COMPUTE_BUDGET_SET_UNIT_LIMIT = 2
COMPUTE_BUDGET_SET_UNIT_PRICE = 3

#: Ceiling on ``SetComputeUnitLimit`` in a channel-``open`` transaction. An
#: observed open consumes ~51,000 CU; the ceiling is the runtime's own
#: per-transaction reservation for the open + memo pair.
OPEN_MAX_COMPUTE_UNIT_LIMIT = 400_000

#: Ceiling on ``SetComputeUnitPrice`` in a channel-``open`` transaction. The
#: operator is the fee payer, so the payer picks a priority fee the operator
#: pays; 5,000,000 microlamports (5 lamports/CU) is the spec ceiling.
MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS = 5_000_000

#: Maximum Lighthouse assertions accepted after ``open``.
OPEN_MAX_LIGHTHOUSE_INSTRUCTIONS = 3

#: Maximum optional instructions accepted after ``open`` (3 Lighthouse + 1 Memo).
OPEN_MAX_OPTIONAL_SUFFIX = 4

#: Maximum byte length of a memo emitted after ``open``. Narrower than the SPL
#: Memo program's own limit: it is the cap the canonical x402 client enforces on
#: ``extra.memo``, so a longer memo would only be rejected by the facilitator.
OPEN_MAX_MEMO_BYTES = 256

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
            escrow ATA rent at open (and recovers it at distribute/reclaim); a
            SIGNER on the open instruction. It is always the same key used as
            the transaction fee payer, so a single operator signature covers
            both roles. Not a wire/payload field. ``None`` defaults to
            ``payer`` (the payer is its own rent payer / fee payer).
        payee: The counterparty the channel pays out to.
        mint: The SPL token mint the channel is denominated in.
        authorized_signer: The key authorized to sign vouchers that redeem
            funds from the channel.
        salt: A caller-chosen u64 that disambiguates channels sharing the same
            payer, payee, mint, and signer; part of the channel PDA seeds.
        deposit: The initial token amount deposited into the channel.
        grace_period: Seconds the payee retains to redeem after the channel
            closes before funds are reclaimable by the payer.
        open_slot: The slot the channel is opened at (part of the channel PDA
            seeds, so the address is per-incarnation). The program requires
            ``open_slot <= clock.slot`` and ``clock.slot - open_slot <= 1500``,
            so callers should fetch the current slot via RPC ``getSlot`` and
            pass it here.
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
    open_slot: int
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
    program_id: Pubkey = field(default_factory=lambda: PROGRAM_ID)


def decode_channel_account(data: bytes) -> Channel:
    """Decode a live channel, rejecting closed or unrelated account layouts."""
    channel = Channel.deserialize(data)
    if channel.discriminator != AccountDiscriminator.CHANNEL:
        raise ValueError(f"invalid channel account discriminator: {channel.discriminator}")
    return channel


def _program_key(key: Pubkey) -> ProgramPubkey:
    """Convert only at the generated-client boundary; callers keep solders types."""
    return ProgramPubkey(bytes(key))


def _solders_instruction(instruction: ProgramInstruction, program_id: Pubkey) -> Instruction:
    """Keep generated bytes/metas, but honor the caller's target deployment.

    The renderer pins the instruction program ID to the IDL. Pay Kit also
    supports explicitly configured deployments, whose PDA/self-program accounts
    are resolved by the builders below.
    """
    return Instruction(
        program_id,
        instruction.data,
        [
            AccountMeta(Pubkey.from_bytes(bytes(meta.pubkey)), meta.is_signer, meta.is_writable)
            for meta in instruction.accounts
        ],
    )


def _validate_integer(value: int, name: str, bits: int, *, signed: bool = False) -> None:
    """Reject lossy coercions before passing amounts to generated serializers."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer")
    minimum = -(1 << (bits - 1)) if signed else 0
    maximum = (1 << (bits - int(signed))) - 1
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} {value} does not fit in {'i' if signed else 'u'}{bits}")


def voucher_message_bytes(channel_id: Pubkey, cumulative: int, expires_at: int) -> bytes:
    """Return the 50-byte voucher preimage signed by the authorized signer.

    The signer signs this exact byte string to authorize redeeming
    ``cumulative`` lamports from the channel up to ``expires_at``.

    Layout: ``magic`` :data:`VOUCHER_MAGIC` (2) || ``channelId`` (32, offset 2)
    || ``cumulativeAmount`` as little-endian u64 (offset 34) || ``expiresAt``
    as little-endian i64 (offset 42). Encoded by the generated ``VoucherArgs``
    Borsh layout; the program rejects a missing/mismatched magic with
    ``voucherBadMagic``.

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
    _validate_integer(cumulative, "cumulative", 64)
    _validate_integer(expires_at, "expires_at", 64, signed=True)
    return VoucherArgs(
        magic=list(VOUCHER_MAGIC),
        channel_id=_program_key(channel_id),
        cumulative_amount=cumulative,
        expires_at=expires_at,
    ).serialize()


def find_channel_pda(
    payer: Pubkey,
    payee: Pubkey,
    mint: Pubkey,
    authorized_signer: Pubkey,
    salt: int,
    open_slot: int,
    program_id: Pubkey = PROGRAM_ID,
) -> tuple[Pubkey, int]:
    """Derive the channel PDA, defaulting to the production program id.

    The channel address is fully determined by its payer, payee, mint,
    authorized signer, salt, and open slot, so the same inputs always resolve
    to the same channel. The open slot makes the address per-incarnation: the
    same parameters opened at a different slot derive a different channel.

    Seeds: ``["channel", payer, payee, mint, authorizedSigner, salt u64 LE,
    openSlot u64 LE]``.

    Args:
        payer: The account funding the channel.
        payee: The counterparty the channel pays out to.
        mint: The SPL token mint the channel is denominated in.
        authorized_signer: The key authorized to sign vouchers for the channel.
        salt: A caller-chosen u64 disambiguating channels with otherwise
            identical seeds, packed little-endian into the seeds.
        open_slot: The slot the channel is opened at, packed little-endian
            into the seeds.
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
            struct.pack("<Q", open_slot),
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
    _validate_integer(params.salt, "salt", 64)
    _validate_integer(params.deposit, "deposit", 64)
    _validate_integer(params.grace_period, "grace_period", 32)
    _validate_integer(params.open_slot, "open_slot", 64)
    for entry in params.recipients:
        _validate_integer(entry.bps, "recipient bps", 16)

    channel, _ = find_channel_pda(
        params.payer,
        params.payee,
        params.mint,
        params.authorized_signer,
        params.salt,
        params.open_slot,
        params.program_id,
    )
    payer_token_account, _ = find_associated_token_address(params.payer, params.mint, params.token_program)
    channel_token_account, _ = find_associated_token_address(channel, params.mint, params.token_program)
    event_authority, _ = find_event_authority_pda(params.program_id)

    args = _OpenArgs(
        salt=params.salt,
        deposit=params.deposit,
        grace_period=params.grace_period,
        open_slot=params.open_slot,
        recipients=[
            DistributionEntry(recipient=_program_key(entry.recipient), bps=entry.bps) for entry in params.recipients
        ],
    )
    # rentPayer is the operator / fee payer that funds the channel rent. It is
    # required: server-side verify_open_tx rejects an open whose rentPayer is
    # not the operator, so there is no valid silent fallback to params.payer.
    if params.rent_payer is None:
        raise ValueError(
            "OpenChannelParams.rent_payer is required to build the open instruction "
            "(the operator / fee payer that funds the channel rent)"
        )
    return _solders_instruction(
        open_channel(
            open_args=args,
            payer=_program_key(params.payer),
            rent_payer=_program_key(params.rent_payer),
            payee=_program_key(params.payee),
            mint=_program_key(params.mint),
            authorized_signer=_program_key(params.authorized_signer),
            channel=_program_key(channel),
            payer_token_account=_program_key(payer_token_account),
            channel_token_account=_program_key(channel_token_account),
            token_program=_program_key(params.token_program),
            system_program=ProgramPubkey.from_base58(SYSTEM_PROGRAM),
            rent=ProgramPubkey.from_base58(_RENT_SYSVAR_ID),
            associated_token_program=ProgramPubkey.from_base58(ASSOCIATED_TOKEN_PROGRAM),
            event_authority=_program_key(event_authority),
            self_program=_program_key(params.program_id),
        ),
        params.program_id,
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
    _validate_integer(params.amount, "amount", 64)
    payer_token_account, _ = find_associated_token_address(params.payer, params.mint, params.token_program)
    channel_token_account, _ = find_associated_token_address(params.channel, params.mint, params.token_program)

    return _solders_instruction(
        top_up(
            top_up_args=_TopUpArgs(amount=params.amount),
            payer=_program_key(params.payer),
            channel=_program_key(params.channel),
            payer_token_account=_program_key(payer_token_account),
            channel_token_account=_program_key(channel_token_account),
            mint=_program_key(params.mint),
            token_program=_program_key(params.token_program),
        ),
        params.program_id,
    )


def build_ed25519_verify_instruction(authorized_signer: Pubkey, signature: bytes, message: bytes) -> Instruction:
    """Build the Ed25519 precompile instruction that verifies a voucher signature.

    The on-chain settle reads the voucher's Ed25519 signature from a sibling
    instruction; this precompile must sit immediately before ``settleAndSeal``
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


def build_settle_and_seal_instructions(
    *,
    payee: Pubkey,
    channel: Pubkey,
    authorized_signer: Pubkey,
    signature: bytes | None,
    cumulative: int,
    expires_at: int,
    program_id: Pubkey = PROGRAM_ID,
) -> list[Instruction]:
    """Build the settle-and-seal instruction set.

    When a voucher was recorded, prepend the Ed25519 precompile that verifies it
    (the program reads the signature from the sibling instruction by index) and
    set ``hasVoucher``. Returns ``[ed25519?, settleAndSeal]`` in the order
    the program expects.
    """
    instructions: list[Instruction] = []
    has_voucher = 0
    if signature is not None:
        message = voucher_message_bytes(channel, cumulative, expires_at)
        instructions.append(build_ed25519_verify_instruction(authorized_signer, signature, message))
        has_voucher = 1

    settle = _solders_instruction(
        settle_and_seal(
            # The voucher is read from the preceding ed25519 precompile.
            settle_and_seal_args=SettleAndSealArgs(has_voucher=has_voucher),
            payee=_program_key(payee),
            channel=_program_key(channel),
            instructions_sysvar=ProgramPubkey.from_base58(SYSVAR_INSTRUCTIONS),
        ),
        program_id,
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

    ``rent_payer`` is the operator recorded at open; it recovers the channel
    PDA + escrow ATA rent at distribute (or via ``reclaim`` once the reclaim
    gate unlocks; writable, not a signer). It is required.
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
    remaining: list[ProgramAccountMeta] = []
    for entry in recipients:
        _validate_integer(entry.bps, "recipient bps", 16)
        recipient_token, _ = find_associated_token_address(entry.recipient, mint, token_program)
        remaining.append(ProgramAccountMeta(pubkey=_program_key(recipient_token), is_signer=False, is_writable=True))
        entries.append(DistributionEntry(recipient=_program_key(entry.recipient), bps=entry.bps))

    return _solders_instruction(
        distribute(
            distribute_args=DistributeArgs(recipients=entries),
            channel=_program_key(channel),
            payer=_program_key(payer),
            rent_payer=_program_key(rent_payer),
            channel_token_account=_program_key(channel_token),
            payer_token_account=_program_key(payer_token),
            payee_token_account=_program_key(payee_token),
            treasury_token_account=_program_key(treasury_token),
            mint=_program_key(mint),
            token_program=_program_key(token_program),
            event_authority=_program_key(event_authority),
            self_program=_program_key(program_id),
            remaining_accounts=remaining or None,
        ),
        program_id,
    )


def build_reclaim_instruction(
    *,
    channel: Pubkey,
    rent_payer: Pubkey,
    program_id: Pubkey = PROGRAM_ID,
) -> Instruction:
    """Build the permissionless ``reclaim`` instruction that recovers channel rent.

    The program allows it only once the channel status is ``distributed`` AND
    ``clock.slot > open_slot + 1500``; it closes the channel PDA and sends its
    lamports to ``rent_payer`` (which must be the rent payer recorded at open).
    """
    return _solders_instruction(
        reclaim(channel=_program_key(channel), rent_payer=_program_key(rent_payer)),
        program_id,
    )
