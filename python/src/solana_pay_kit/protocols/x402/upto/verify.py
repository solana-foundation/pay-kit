"""Pure verification for the x402 ``upto`` payment-channel asset transfer method.

No I/O: these functions validate already-decoded structures and raise
:class:`~solana_pay_kit.errors.InvalidProofError` on rejection. The ordered payload
checks and the 14-account open-instruction validation mirror the Rust spine
(``protocol/schemes/upto/verify.rs``) and the Go reference
(``go/protocols/x402/upto.go`` - ``VerifyUptoPayload`` and
``validateUptoOpenInstruction``).
"""

from __future__ import annotations

import struct
from typing import Any

from solders.pubkey import Pubkey  # type: ignore[import-untyped]

from solana_pay_kit._paycore.paymentchannels import (
    find_associated_token_address,
    find_channel_pda,
    find_event_authority_pda,
)
from solana_pay_kit._paycore.solana import (
    ASSOCIATED_TOKEN_PROGRAM,
    SYSTEM_PROGRAM,
)
from solana_pay_kit.errors import InvalidProofError
from solana_pay_kit.protocols.x402.upto.types import (
    UPTO_ERROR_SETTLEMENT_EXCEEDS_AMOUNT,
    UptoPayload,
    UptoRequirements,
)

__all__ = [
    "verify_upto_payload",
    "assert_settlement_within_ceiling",
    "validate_upto_open_instruction",
    "parse_base_units",
]

# Payment-channels open instruction discriminator (single-byte Anchor-numeric
# form, not the 8-byte sha256 convention).
_OPEN_INSTRUCTION_DISCRIMINATOR = 1

#: The program's openSlot freshness window (slots): open requires
#: ``openSlot <= clock.slot`` and ``clock.slot - openSlot <= 1500``. Applied
#: here against the challenged ``extra.recentSlot`` so a stale open fails
#: before the fee payer co-signs and broadcasts.
OPEN_SLOT_WINDOW = 1500

# Rent sysvar id (slot 10 of the open instruction account layout).
_RENT_SYSVAR_ID = "SysvarRent111111111111111111111111111111111"


def parse_base_units(value: str, label: str) -> int:
    """Parse a base-10 u64 amount string, raising on malformed/out-of-range input."""
    try:
        parsed = int(value, 10)
    except (TypeError, ValueError) as exc:
        raise InvalidProofError(f"invalid upto {label} {value!r}", code="payment_invalid") from exc
    if not 0 <= parsed <= 0xFFFF_FFFF_FFFF_FFFF:
        raise InvalidProofError(f"upto {label} {parsed} does not fit in u64", code="payment_invalid")
    return parsed


def verify_upto_payload(
    payload: UptoPayload,
    requirements: UptoRequirements,
    receiver_authorizer: str,
    now: int,
) -> None:
    """Validate the client payload against the route-pinned requirement.

    Ordered checks (mirroring the Rust/Go spine): ``maxAmount`` equals the
    verification ceiling; ``deposit`` equals ``maxAmount``;
    ``validAfter <= now < expiresAt``; the ``authorizedSigner`` is the advertised
    receiver authorizer.
    """
    max_amount = parse_base_units(requirements["amount"], "amount")
    signed_max = parse_base_units(payload.get("maxAmount", ""), "maxAmount")
    if signed_max != max_amount:
        raise InvalidProofError(f"amount mismatch: expected {max_amount}, got {signed_max}", code="payment_invalid")

    deposit = parse_base_units(payload.get("deposit", ""), "deposit")
    if deposit != max_amount:
        raise InvalidProofError(
            f"channel deposit {deposit} must equal the authorized maximum {max_amount}",
            code="payment_invalid",
        )

    valid_after = int(payload.get("validAfter", 0))
    expires_at = int(payload.get("expiresAt", 0))
    if now < valid_after:
        raise InvalidProofError(
            f"authorization not yet active (validAfter {valid_after} > now {now})", code="payment_invalid"
        )
    if expires_at == 0 or now >= expires_at:
        raise InvalidProofError(f"authorization expired (expiresAt {expires_at} < now {now})", code="payment_invalid")

    if payload.get("authorizedSigner") != receiver_authorizer:
        raise InvalidProofError(
            "voucher authorized_signer must be the advertised receiver authorizer",
            code="payment_invalid",
        )


def assert_settlement_within_ceiling(actual: int, max_amount: int) -> None:
    """Enforce ``actual <= max`` at settlement; raise the canonical upto error otherwise."""
    if actual > max_amount:
        raise InvalidProofError(
            UPTO_ERROR_SETTLEMENT_EXCEEDS_AMOUNT,
            code=UPTO_ERROR_SETTLEMENT_EXCEEDS_AMOUNT,
        )


def validate_upto_open_instruction(
    account_keys: list[str],
    instructions: list[Any],
    *,
    program_id: Pubkey,
    fee_payer: Pubkey,
    receiver_authorizer: Pubkey,
    payer: Pubkey,
    payee: Pubkey,
    mint: Pubkey,
    token_program: Pubkey,
    channel_id: Pubkey,
    max_amount: int,
    withdraw_delay: int,
    payload_nonce: str,
    payload_open_slot: str,
    recent_slot: int | None,
) -> None:
    """Validate the client-built channel-open instruction byte-for-byte.

    The open transaction must contain exactly one instruction targeting the
    payment-channels program with the channel-open discriminator and the 14
    accounts in the fixed order the program expects. ``fee_payer`` is the
    ``rentPayer`` (slot 1), ``payee`` is the zero-share channel payee seat
    (slot 2, the fee payer for ``upto``), and ``receiver_authorizer`` is the
    ``authorizedSigner`` (slot 4, the voucher signer only). Mirrors Go's
    ``validateUptoOpenInstruction``.

    The instruction's own ``openArgs`` are decoded and bound too: the channel
    account must equal the PDA re-derived from the args' ``salt``/``openSlot``
    (the slot-addressed channel invariant), the args' ``deposit`` must equal
    the authorized maximum ``max_amount``, and — when the challenged
    ``extra.recentSlot`` is known — ``openSlot`` must not be in its future and
    must sit inside the program's freshness window, so a stale or forged slot
    fails before the fee payer co-signs and broadcasts.
    """
    if len(instructions) != 1:
        raise InvalidProofError(
            f"open transaction must contain exactly one instruction, found {len(instructions)}",
            code="payment_invalid",
        )
    ix = instructions[0]
    program_index = int(ix.program_id_index)
    if program_index >= len(account_keys):
        raise InvalidProofError("open instruction program id out of range", code="payment_invalid")
    if account_keys[program_index] != str(program_id):
        raise InvalidProofError("open transaction targets an unexpected program", code="payment_invalid")
    data = bytes(ix.data)
    if len(data) == 0 or data[0] != _OPEN_INSTRUCTION_DISCRIMINATOR:
        raise InvalidProofError("open transaction is not a channel-open instruction", code="payment_invalid")

    indices = [int(i) for i in ix.accounts]

    def account_at(pos: int, label: str) -> str:
        if pos >= len(indices) or indices[pos] >= len(account_keys):
            raise InvalidProofError(
                f"open transaction {label} mismatch: expected account at slot {pos}, got <none>",
                code="payment_invalid",
            )
        return account_keys[indices[pos]]

    def expect(pos: int, want: Pubkey, label: str) -> None:
        got = account_at(pos, label)
        if got != str(want):
            raise InvalidProofError(
                f"open transaction {label} mismatch: expected {want}, got {got}", code="payment_invalid"
            )

    payer_token, _ = find_associated_token_address(payer, mint, token_program)
    channel_token, _ = find_associated_token_address(channel_id, mint, token_program)
    event_authority, _ = find_event_authority_pda(program_id)

    expect(0, payer, "payer")
    expect(1, fee_payer, "rent_payer")
    expect(2, payee, "payee")
    expect(3, mint, "mint")
    expect(4, receiver_authorizer, "authorized_signer")
    expect(5, channel_id, "channel")
    expect(6, payer_token, "payer_token_account")
    expect(7, channel_token, "channel_token_account")
    expect(8, token_program, "token_program")
    expect(9, Pubkey.from_string(SYSTEM_PROGRAM), "system_program")
    expect(10, Pubkey.from_string(_RENT_SYSVAR_ID), "rent_sysvar")
    expect(11, Pubkey.from_string(ASSOCIATED_TOKEN_PROGRAM), "associated_token_program")
    expect(12, event_authority, "event_authority")
    expect(13, program_id, "self_program")

    # openArgs layout:
    # [discriminator u8][salt u64][deposit u64][grace u32][openSlot u64][recipients].
    if len(data) < 1 + 8 + 8 + 4 + 8:
        raise InvalidProofError(f"open instruction data too short ({len(data)} bytes)", code="payment_invalid")
    salt = struct.unpack_from("<Q", data, 1)[0]
    deposit = struct.unpack_from("<Q", data, 9)[0]
    grace_period = struct.unpack_from("<I", data, 17)[0]
    open_slot = struct.unpack_from("<Q", data, 21)[0]
    if payload_nonce != str(salt):
        raise InvalidProofError(
            f"open salt {salt} does not match payload nonce {payload_nonce!r}", code="payment_invalid"
        )
    if payload_open_slot != str(open_slot):
        raise InvalidProofError(
            f"open slot {open_slot} does not match payload openSlot {payload_open_slot!r}", code="payment_invalid"
        )
    if grace_period != withdraw_delay:
        raise InvalidProofError(
            f"open withdraw delay {grace_period} must equal the advertised withdrawDelay {withdraw_delay}",
            code="payment_invalid",
        )

    # Slot-addressed channel invariant: the channel account must be the PDA
    # actually derived with the args' salt + openSlot, not just any account
    # the payload named.
    derived_channel, _ = find_channel_pda(payer, payee, mint, receiver_authorizer, salt, open_slot, program_id)
    if derived_channel != channel_id:
        raise InvalidProofError(f"open channel PDA {channel_id} != derived {derived_channel}", code="payment_invalid")
    if deposit != max_amount:
        raise InvalidProofError(
            f"open deposit {deposit} must equal the authorized maximum {max_amount}",
            code="payment_invalid",
        )
    if recent_slot is not None:
        if open_slot > recent_slot:
            raise InvalidProofError(
                f"open openSlot {open_slot} is ahead of the challenged recentSlot {recent_slot}",
                code="payment_invalid",
            )
        if recent_slot - open_slot > OPEN_SLOT_WINDOW:
            raise InvalidProofError(
                f"open openSlot {open_slot} is outside the {OPEN_SLOT_WINDOW}-slot freshness "
                f"window of the challenged recentSlot {recent_slot}",
                code="payment_invalid",
            )
