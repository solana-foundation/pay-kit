"""Signed-message encodings for the SVM x402 ``batch-settlement`` scheme.

Three Ed25519-signed byte strings, each frozen against its reference encoder:

- **Voucher** (50 bytes): ``0x56 0x01 || channelId || u64 LE || i64 LE``, the
  payment-channels program layout shared with Rust and MPP sessions.
- **Payer authorization** (server-signed mode): ``"x402-batch-authorization-v2"
  || channelId || payer || operator || u16 LE len || requestId ||
  u64 LE amount || i64 LE expiresAt``, signed raw by the payer (PR #23
  ``authorization.ts``).
- **Close authorization**: the SHA-256 of ``"x402:batch-settlement:svm:close:v1"
  || 0x00 || u16 LE len || network || programId || feePayer || channelId ||
  u64 LE || i64 LE voucherExpiresAt || i64 LE validBefore``, signed by the
  receiver authorizer (PR #23 ``closeAuthorization.ts``).

Encoders raise ``ValueError`` on out-of-range input; verifiers never raise and
return ``False`` for anything malformed, so a caller maps one outcome to one
wire code.
"""

from __future__ import annotations

import hashlib
import struct
from typing import TYPE_CHECKING

from solders.pubkey import Pubkey  # type: ignore[import-untyped]
from solders.signature import Signature  # type: ignore[import-untyped]

from solana_pay_kit._paycore.paymentchannels import PAYMENT_CHANNELS_PROGRAM_ID, voucher_message_bytes
from solana_pay_kit.protocols.x402.batch_settlement.types import (
    VOUCHER_EXPIRES_AT,
    BatchAuthorization,
    BatchVoucher,
    CloseAuthorization,
)

if TYPE_CHECKING:
    from solana_pay_kit.signer import LocalSigner

__all__ = [
    "authorization_message",
    "close_authorization_digest",
    "sign_authorization",
    "sign_close_authorization",
    "sign_voucher",
    "verify_authorization",
    "verify_close_authorization",
    "verify_ed25519",
    "verify_voucher",
    "voucher_message",
]

_AUTHORIZATION_DOMAIN = b"x402-batch-authorization-v2"
_CLOSE_DOMAIN = b"x402:batch-settlement:svm:close:v1"
_MAX_REQUEST_ID_BYTES = 256
_U64_MAX = 0xFFFF_FFFF_FFFF_FFFF
_I64_MIN = -(2**63)
_I64_MAX = 2**63 - 1


def _key(value: str, field: str) -> bytes:
    try:
        return bytes(Pubkey.from_string(value))
    except (ValueError, TypeError) as exc:
        raise ValueError(f"{field} must be a base58 32-byte key: {exc}") from exc


def verify_ed25519(message: bytes, signature: str, signer: str) -> bool:
    """Whether ``signature`` (base58) is ``signer``'s (base58) Ed25519 signature over ``message``."""
    try:
        return bool(Signature.from_string(signature).verify(Pubkey.from_string(signer), message))
    except (ValueError, TypeError):
        return False


def voucher_message(channel_id: str, max_claimable: int, expires_at: int) -> bytes:
    """The 50-byte voucher preimage the payer authorizer (or operator) signs."""
    return voucher_message_bytes(Pubkey.from_bytes(_key(channel_id, "channelId")), max_claimable, expires_at)


def sign_voucher(signer: LocalSigner, channel_id: str, max_claimable: int) -> BatchVoucher:
    """Sign a non-expiring cumulative voucher for ``channel_id``."""
    signature = signer.sign(voucher_message(channel_id, max_claimable, VOUCHER_EXPIRES_AT))
    return {
        "channelId": channel_id,
        "maxClaimableAmount": str(max_claimable),
        "expiresAt": VOUCHER_EXPIRES_AT,
        "signature": str(Signature.from_bytes(signature)),
    }


def verify_voucher(voucher: BatchVoucher, signer: str) -> bool:
    """Whether ``voucher`` carries ``signer``'s signature over its own channel, amount and expiry."""
    try:
        message = voucher_message(voucher["channelId"], int(voucher["maxClaimableAmount"]), voucher["expiresAt"])
    except ValueError:
        return False
    return verify_ed25519(message, voucher["signature"], signer)


def authorization_message(
    *,
    channel_id: str,
    payer: str,
    operator: str,
    request_id: str,
    authorized_amount: int,
    expires_at: int,
) -> bytes:
    """The raw bytes a payer signs to let ``operator`` meter one request on ``channel_id``."""
    request = request_id.encode("utf-8")
    if not 1 <= len(request) <= _MAX_REQUEST_ID_BYTES:
        raise ValueError(f"requestId must encode to 1 through {_MAX_REQUEST_ID_BYTES} bytes")
    if not 0 <= authorized_amount <= _U64_MAX:
        raise ValueError("authorizedAmount must fit in a u64")
    if not 1 <= expires_at <= _I64_MAX:
        raise ValueError("expiresAt must be a positive i64")
    return b"".join(
        [
            _AUTHORIZATION_DOMAIN,
            _key(channel_id, "channelId"),
            _key(payer, "payer"),
            _key(operator, "operator"),
            struct.pack("<H", len(request)),
            request,
            struct.pack("<Qq", authorized_amount, expires_at),
        ]
    )


def sign_authorization(
    payer: LocalSigner,
    *,
    channel_id: str,
    operator: str,
    request_id: str,
    authorized_amount: int,
    expires_at: int,
) -> BatchAuthorization:
    """Sign an expiring, single-request payer proof for a server-signed channel."""
    message = authorization_message(
        channel_id=channel_id,
        payer=payer.pubkey(),
        operator=operator,
        request_id=request_id,
        authorized_amount=authorized_amount,
        expires_at=expires_at,
    )
    return {
        "type": "proof",
        "channelId": channel_id,
        "payer": payer.pubkey(),
        "requestId": request_id,
        "authorizedAmount": str(authorized_amount),
        "expiresAt": expires_at,
        "signature": str(Signature.from_bytes(payer.sign(message))),
    }


def verify_authorization(authorization: BatchAuthorization, operator: str, now: int) -> bool:
    """Whether the proof is unexpired (``now < expiresAt``) and signed by its ``payer`` for ``operator``."""
    if authorization["expiresAt"] <= now:
        return False
    try:
        message = authorization_message(
            channel_id=authorization["channelId"],
            payer=authorization["payer"],
            operator=operator,
            request_id=authorization["requestId"],
            authorized_amount=int(authorization["authorizedAmount"]),
            expires_at=authorization["expiresAt"],
        )
    except ValueError:
        return False
    return verify_ed25519(message, authorization["signature"], authorization["payer"])


def close_authorization_digest(
    *,
    network: str,
    fee_payer: str,
    channel_id: str,
    max_claimable_amount: int,
    voucher_expires_at: int,
    valid_before: int,
    program_id: str = PAYMENT_CHANNELS_PROGRAM_ID,
) -> bytes:
    """The 32-byte SHA-256 digest a receiver authorizer signs to authorize exactly one close."""
    network_bytes = network.encode("utf-8")
    if not 1 <= len(network_bytes) <= 0xFFFF:
        raise ValueError("network must encode to 1 through 65535 bytes")
    if not 0 <= max_claimable_amount <= _U64_MAX:
        raise ValueError("maxClaimableAmount must fit in a u64")
    if not _I64_MIN <= voucher_expires_at <= _I64_MAX:
        raise ValueError("voucherExpiresAt must fit in an i64")
    if not 1 <= valid_before <= _I64_MAX:
        raise ValueError("validBefore must be a positive i64")
    message = b"".join(
        [
            _CLOSE_DOMAIN,
            b"\x00",
            struct.pack("<H", len(network_bytes)),
            network_bytes,
            _key(program_id, "programId"),
            _key(fee_payer, "feePayer"),
            _key(channel_id, "channelId"),
            struct.pack("<Qqq", max_claimable_amount, voucher_expires_at, valid_before),
        ]
    )
    return hashlib.sha256(message).digest()


def sign_close_authorization(
    authorizer: LocalSigner,
    *,
    network: str,
    fee_payer: str,
    channel_id: str,
    max_claimable_amount: int,
    voucher_expires_at: int,
    valid_before: int,
    program_id: str = PAYMENT_CHANNELS_PROGRAM_ID,
) -> CloseAuthorization:
    """Sign the close digest with the receiver authorizer."""
    digest = close_authorization_digest(
        network=network,
        fee_payer=fee_payer,
        channel_id=channel_id,
        max_claimable_amount=max_claimable_amount,
        voucher_expires_at=voucher_expires_at,
        valid_before=valid_before,
        program_id=program_id,
    )
    return {"validBefore": valid_before, "signature": str(Signature.from_bytes(authorizer.sign(digest)))}


def verify_close_authorization(
    authorization: CloseAuthorization,
    *,
    network: str,
    fee_payer: str,
    channel_id: str,
    max_claimable_amount: int,
    voucher_expires_at: int,
    receiver_authorizer: str,
    max_timeout_seconds: int,
    now: int,
    program_id: str = PAYMENT_CHANNELS_PROGRAM_ID,
) -> bool:
    """Whether ``now < validBefore <= now + max_timeout_seconds`` and the receiver authorizer signed this close."""
    valid_before = authorization["validBefore"]
    if not now < valid_before <= now + max_timeout_seconds:
        return False
    try:
        digest = close_authorization_digest(
            network=network,
            fee_payer=fee_payer,
            channel_id=channel_id,
            max_claimable_amount=max_claimable_amount,
            voucher_expires_at=voucher_expires_at,
            valid_before=valid_before,
            program_id=program_id,
        )
    except ValueError:
        return False
    return verify_ed25519(digest, authorization["signature"], receiver_authorizer)
