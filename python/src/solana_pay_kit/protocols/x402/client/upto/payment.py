"""x402 ``upto`` client builder - ``payment-channel`` asset transfer method.

Parses an ``upto`` 402 challenge and builds the client authorization: a signed
channel ``open`` transaction (the deposit is the ceiling) plus the
``PAYMENT-SIGNATURE`` envelope. The client signs only its own (payer) slot in the
pull-style open; the advertised fee payer completes the fee-payer signature and
broadcasts. Mirrors the Go reference
(``go/protocols/x402/client/upto.go``).
"""

from __future__ import annotations

import base64
import json
import secrets
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, cast

from solders.hash import Hash  # type: ignore[import-untyped]
from solders.message import Message  # type: ignore[import-untyped]
from solders.pubkey import Pubkey  # type: ignore[import-untyped]

from solana_pay_kit._paycore.paymentchannels import (
    PAYMENT_CHANNELS_PROGRAM_ID,
    Distribution,
    OpenChannelParams,
    build_open_instruction,
    find_channel_pda,
)
from solana_pay_kit._paycore.solana import TOKEN_PROGRAM
from solana_pay_kit.protocols.x402.exact.verify import X402_VERSION
from solana_pay_kit.protocols.x402.upto.types import (
    UPTO_SCHEME,
    UptoPayload,
    UptoRequirements,
)

if TYPE_CHECKING:
    from solana_pay_kit.signer import LocalSigner

__all__ = [
    "parse_upto_challenge",
    "build_upto_payload",
    "encode_upto_header",
    "build_upto_header",
]

_U64_MAX = (1 << 64) - 1


def _parse_recent_slot(raw: Any) -> int:
    """Parse the server-provided ``extra.recentSlot`` (decimal string or number).

    The slot is emitted as a u64-as-string (matching the session challenge
    convention) but a plain JSON number is accepted too. Missing, negative, or
    out-of-range values raise ``ValueError``.
    """
    if raw is None or raw == "":
        raise ValueError("x402 client: requirement missing extra.recentSlot")
    if isinstance(raw, bool):
        raise ValueError(f"x402 client: invalid extra.recentSlot {raw!r}")
    if isinstance(raw, int):
        value = raw
    elif isinstance(raw, str) and raw.isascii() and raw.isdigit():
        value = int(raw, 10)
    else:
        raise ValueError(f"x402 client: invalid extra.recentSlot {raw!r}")
    if not 0 <= value <= _U64_MAX:
        raise ValueError(f"x402 client: extra.recentSlot {value} does not fit in u64")
    return value


def parse_upto_challenge(headers: Mapping[str, str], body: str | None = None) -> UptoRequirements | None:
    """Extract the ``upto`` requirement from a 402 challenge.

    Reads the base64 ``payment-required`` header, falling back to a JSON body,
    and returns the first ``accepts[]`` entry whose ``scheme`` is ``upto``.
    """
    envelope: Any = None
    raw = headers.get("payment-required") or headers.get("Payment-Required")
    if raw:
        try:
            envelope = json.loads(base64.b64decode(raw, validate=True))
        except Exception:  # noqa: BLE001
            return None
    elif body:
        try:
            envelope = json.loads(body)
        except Exception:  # noqa: BLE001
            return None
    else:
        return None
    if not isinstance(envelope, dict):
        return None
    accepts = cast("dict[str, Any]", envelope).get("accepts")
    if not isinstance(accepts, list):
        return None
    for entry in cast("list[Any]", accepts):
        if isinstance(entry, dict) and cast("dict[str, Any]", entry).get("scheme") == UPTO_SCHEME:
            return cast("UptoRequirements", entry)
    return None


def build_upto_payload(
    signer: LocalSigner,
    requirements: UptoRequirements,
    expires_at: int,
    nonce: str | None = None,
) -> UptoPayload:
    """Build the ``upto`` payload: a partially-signed channel ``open`` + metadata.

    The client (``signer``) is the channel payer. ``extra.feePayer`` is the
    transaction fee payer, rent payer, and zero-share channel payee (lifecycle
    authority); ``extra.receiverAuthorizer`` is the authorized voucher signer
    only. The open transaction is signed only in the client's payer slot
    (pull-style); the fee-payer slot is completed server-side.
    """
    extra = requirements["extra"]
    max_amount = int(requirements["amount"], 10)
    beneficiary = Pubkey.from_string(requirements["payTo"])
    mint = Pubkey.from_string(requirements["asset"])
    fee_payer_str = extra.get("feePayer")
    if not fee_payer_str:
        raise ValueError("x402 client: requirement missing extra.feePayer")
    fee_payer = Pubkey.from_string(fee_payer_str)
    receiver_authorizer_str = extra.get("receiverAuthorizer")
    if not receiver_authorizer_str:
        raise ValueError("x402 client: requirement missing extra.receiverAuthorizer")
    receiver_authorizer = Pubkey.from_string(receiver_authorizer_str)
    withdraw_delay = int(extra.get("withdrawDelay", 0))
    if withdraw_delay <= 0:
        raise ValueError("x402 client: requirement missing extra.withdrawDelay")
    # Always explicit: the payee seat is held by the facilitator (feePayer)
    # with a zero implicit remainder, so 100% of settled funds must be
    # assigned to payTo through the recipients list.
    recipients: list[Distribution] = [Distribution(recipient=beneficiary, bps=10_000)]
    program_id = Pubkey.from_string(PAYMENT_CHANNELS_PROGRAM_ID)
    token_program = Pubkey.from_string(extra.get("tokenProgram") or TOKEN_PROGRAM)

    blockhash_str = extra.get("recentBlockhash")
    if not blockhash_str:
        raise ValueError("x402 client: requirement missing extra.recentBlockhash")
    blockhash = Hash.from_string(blockhash_str)
    # The channel openSlot is server-provided as the challenge recentSlot
    # (like recentBlockhash); the client never fetches the slot itself. It is
    # a channel PDA seed and an openArgs field, so the requirement must carry it.
    open_slot = _parse_recent_slot(extra.get("recentSlot"))

    payer = Pubkey.from_string(signer.pubkey())
    salt = secrets.randbits(64)
    channel, _ = find_channel_pda(payer, fee_payer, mint, receiver_authorizer, salt, open_slot, program_id)
    open_ix = build_open_instruction(
        OpenChannelParams(
            payer=payer,
            rent_payer=fee_payer,
            payee=fee_payer,
            mint=mint,
            authorized_signer=receiver_authorizer,
            salt=salt,
            deposit=max_amount,
            grace_period=withdraw_delay,
            open_slot=open_slot,
            recipients=recipients,
            token_program=token_program,
            program_id=program_id,
        )
    )
    open_tx = _build_payer_signed_open(open_ix, fee_payer, payer, blockhash, signer)

    valid_after = int(extra.get("validAfter", 0))
    payload: UptoPayload = {
        "from": signer.pubkey(),
        "maxAmount": str(max_amount),
        "expiresAt": expires_at,
        "validAfter": valid_after,
        "nonce": str(salt),
        "channelId": str(channel),
        "deposit": str(max_amount),
        "authorizedSigner": receiver_authorizer_str,
        "openSlot": str(open_slot),
        "openTransaction": open_tx,
    }
    return payload


def encode_upto_header(requirements: UptoRequirements, payload: UptoPayload) -> str:
    """Encode the ``PAYMENT-SIGNATURE`` header (base64 JSON envelope)."""
    envelope = {
        "x402Version": X402_VERSION,
        "accepted": requirements,
        "payload": payload,
    }
    raw = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
    return base64.b64encode(raw).decode("ascii")


def build_upto_header(
    signer: LocalSigner,
    requirements: UptoRequirements,
    expires_at: int,
    nonce: str | None = None,
) -> str:
    """Build the full ``PAYMENT-SIGNATURE`` header value for an ``upto`` retry."""
    payload = build_upto_payload(signer, requirements, expires_at, nonce)
    return encode_upto_header(requirements, payload)


def _build_payer_signed_open(
    open_ix: Any,
    fee_payer: Pubkey,
    payer: Pubkey,
    blockhash: Hash,
    signer: LocalSigner,
) -> str:
    """Assemble the open transaction with the advertised fee payer, signed only
    in the client's (payer) slot. Returns base64 wire."""
    message = Message.new_with_blockhash([open_ix], fee_payer, blockhash)
    account_keys = list(message.account_keys)
    num_required = int(message.header.num_required_signatures)
    try:
        payer_idx = account_keys.index(payer)
    except ValueError as exc:  # pragma: no cover - the open instruction always includes the payer
        raise ValueError("x402 client: payer not present in open transaction accounts") from exc
    message_bytes = bytes(message)
    payer_sig = bytes(signer.sign(message_bytes))
    signatures = bytearray(64 * num_required)
    signatures[payer_idx * 64 : payer_idx * 64 + 64] = payer_sig
    # Single-byte shortvec count (num_required is always small).
    wire = bytes([num_required]) + bytes(signatures) + message_bytes
    return base64.b64encode(wire).decode("ascii")
