"""x402 ``upto`` client builder - ``payment-channel`` profile.

Parses an ``upto`` 402 challenge and builds the client authorization: a signed
channel ``open`` transaction (the deposit is the ceiling, the operator is the
fee payer and authorized signer) plus the ``PAYMENT-SIGNATURE`` envelope. The
client signs only its own (payer) slot in the pull-style open; the facilitator
completes the fee-payer signature and broadcasts. Mirrors the Go reference
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
    OpenChannelParams,
    build_open_instruction,
    find_channel_pda,
)
from solana_pay_kit._paycore.solana import TOKEN_PROGRAM
from solana_pay_kit.protocols.x402.exact.verify import X402_VERSION
from solana_pay_kit.protocols.x402.upto.types import (
    PROFILE_PAYMENT_CHANNEL,
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

#: Default channel grace period (seconds) the client requests at open; mirrors
#: the Go client's defaultGracePeriodSeconds.
_DEFAULT_GRACE_PERIOD_SECONDS = 900


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

    The client (``signer``) is the channel payer; the operator (``extra.feePayer``)
    is the fee payer, rent payer, and authorized signer. The open transaction is
    built with the operator as fee payer and signed only in the client's payer
    slot (pull-style); the operator slot is left empty for the facilitator.
    """
    extra = requirements["extra"]
    profiles = extra.get("profiles", [])
    if PROFILE_PAYMENT_CHANNEL not in profiles:
        raise ValueError("x402 client: requirement does not advertise the payment-channel profile")

    max_amount = int(requirements["amount"], 10)
    payee = Pubkey.from_string(requirements["payTo"])
    mint = Pubkey.from_string(requirements["asset"])
    # Spec uses extra.facilitator; Go uses extra.feePayer. Accept either.
    operator_str = extra.get("facilitator") or extra.get("feePayer")
    if not operator_str:
        raise ValueError("x402 client: requirement missing extra.facilitator/feePayer")
    operator = Pubkey.from_string(operator_str)
    program_id = Pubkey.from_string(extra.get("channelProgram") or PAYMENT_CHANNELS_PROGRAM_ID)
    token_program = Pubkey.from_string(extra.get("tokenProgram") or TOKEN_PROGRAM)

    blockhash_str = extra.get("recentBlockhash")
    if not blockhash_str:
        raise ValueError("x402 client: requirement missing extra.recentBlockhash")
    blockhash = Hash.from_string(blockhash_str)

    payer = Pubkey.from_string(signer.pubkey())
    salt = secrets.randbits(64)
    channel, _ = find_channel_pda(payer, payee, mint, operator, salt, program_id)
    open_ix = build_open_instruction(
        OpenChannelParams(
            payer=payer,
            rent_payer=operator,
            payee=payee,
            mint=mint,
            authorized_signer=operator,
            salt=salt,
            deposit=max_amount,
            grace_period=_DEFAULT_GRACE_PERIOD_SECONDS,
            token_program=token_program,
            program_id=program_id,
        )
    )
    open_tx = _build_payer_signed_open(open_ix, operator, payer, blockhash, signer)

    valid_after = int(extra.get("validAfter", 0))
    payload: UptoPayload = {
        "profile": PROFILE_PAYMENT_CHANNEL,
        "from": signer.pubkey(),
        "maxAmount": str(max_amount),
        "expiresAt": expires_at,
        "validAfter": valid_after,
        "nonce": nonce if nonce is not None else secrets.token_hex(16),
        "channelId": str(channel),
        "deposit": str(max_amount),
        "authorizedSigner": operator_str,
        "openTransaction": open_tx,
    }
    return payload


def encode_upto_header(requirements: UptoRequirements, payload: UptoPayload) -> str:
    """Encode the ``PAYMENT-SIGNATURE`` header (base64 JSON envelope)."""
    envelope = {
        "x402Version": X402_VERSION,
        "scheme": UPTO_SCHEME,
        "network": requirements["network"],
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
    operator: Pubkey,
    payer: Pubkey,
    blockhash: Hash,
    signer: LocalSigner,
) -> str:
    """Assemble the open transaction with the operator as fee payer, signed only
    in the client's (payer) slot. Returns base64 wire."""
    message = Message.new_with_blockhash([open_ix], operator, blockhash)
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
