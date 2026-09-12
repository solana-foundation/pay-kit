"""Shared Solana transaction-wire helpers used by both protocol adapters.

Lives in ``_paycore`` (the shared core, mirroring the Rust ``core`` crate) so
neither protocol package depends on the other: x402 and MPP both import the v0
detector and the v0 client builder from here rather than reaching across into
each other.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any

#: Exact rejection text shared by every server-side decode boundary; the Rust
#: servers emit the same string.
LEGACY_TRANSACTION_REJECTED = "legacy transactions are not supported; use a version 0 or version 1 message"


def _message_offset(raw: bytes) -> int | None:
    """Offset of the first message byte on the wire, or ``None`` when truncated.

    Wire format: ``[compact-u16 sig_count] [64 * sig_count signatures] [message]``.
    We accept multi-byte compact-u16 lengths but cap at three bytes (Solana
    hard caps signatures well below ``128 * 128``).
    """
    sig_count = 0
    shift = 0
    offset = 0
    for _ in range(3):  # compact-u16 is at most 3 bytes
        if offset >= len(raw):
            return None
        byte = raw[offset]
        offset += 1
        sig_count |= (byte & 0x7F) << shift
        if (byte & 0x80) == 0:
            break
        shift += 7
    msg_start = offset + sig_count * 64
    if msg_start >= len(raw):
        return None
    return msg_start


def is_v0_wire_bytes(raw: bytes) -> bool:
    """Best-effort detection of a versioned ``VersionedTransaction`` on the wire.

    Legacy messages start with the header byte ``num_required_signatures``
    which is always ``< 0x80`` in practice; versioned messages start with
    ``0x80 | version`` so the high bit is set. ``solders`` parses either shape
    through ``Transaction.from_bytes`` (leniently, mis-reading v0 bytes as a
    degenerate legacy transaction) or ``VersionedTransaction.from_bytes``, so
    callers peek at the prefix instead of trusting a parse to fail.
    """
    msg_start = _message_offset(raw)
    return msg_start is not None and (raw[msg_start] & 0x80) != 0


def require_versioned_wire(raw: bytes, error: Callable[[str], Exception] = ValueError) -> None:
    """Reject a legacy (unversioned) transaction wire before it is decoded.

    Every server-side decode of a client-supplied transaction calls this first:
    legacy messages are not supported anywhere in pay-kit, and both ``solders``
    parsers would otherwise accept one. Raises ``error(LEGACY_TRANSACTION_REJECTED)``
    when the message byte carries no version prefix, so each boundary maps the
    rejection onto the error code it already uses for a malformed payload. A
    wire too short to reach the message byte is left to the caller's decoder,
    which reports it as malformed. Version 1 (``0x81``) passes the guard and is
    rejected by ``VersionedTransaction.from_bytes`` until solders implements it.
    """
    msg_start = _message_offset(raw)
    if msg_start is not None and (raw[msg_start] & 0x80) == 0:
        raise error(LEGACY_TRANSACTION_REJECTED)


def build_partially_signed_v0_transaction(
    instructions: Sequence[Any],
    fee_payer: Any,
    blockhash: Any,
    signer_pubkey: Any,
    sign: Callable[[bytes], bytes],
) -> bytes:
    """Compile a v0 message, sign only ``signer_pubkey``'s slot, return the wire.

    ``fee_payer`` becomes ``account_keys[0]``; every other required-signer slot
    is left as the zero placeholder for a server-side cosign. The signature
    covers ``to_bytes_versioned(message)`` (``0x80`` prefix + v0 body), which
    is what the wire carries. Legacy ``Message`` encodings are rejected by the
    Rust servers, so every client path emits through here.
    """
    from solders.message import MessageV0, to_bytes_versioned  # type: ignore[import-untyped]
    from solders.signature import Signature  # type: ignore[import-untyped]
    from solders.transaction import VersionedTransaction  # type: ignore[import-untyped]

    message = MessageV0.try_compile(fee_payer, list(instructions), [], blockhash)
    num_required = int(message.header.num_required_signatures)
    signer_keys = list(message.account_keys)[:num_required]
    try:
        signer_index = signer_keys.index(signer_pubkey)
    except ValueError as exc:
        raise ValueError("solana_pay_kit: signer is not a required signer of the transaction") from exc
    sig = bytes(sign(bytes(to_bytes_versioned(message))))
    if len(sig) != 64:
        raise ValueError(f"solana_pay_kit: signature length {len(sig)}, want 64")
    signatures = [Signature.default() for _ in range(num_required)]
    signatures[signer_index] = Signature.from_bytes(sig)
    return bytes(VersionedTransaction.populate(message, signatures))
