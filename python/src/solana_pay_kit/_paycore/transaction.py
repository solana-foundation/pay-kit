"""Shared Solana transaction-wire helpers used by both protocol adapters.

Lives in ``_paycore`` (the shared core, mirroring the Rust ``core`` crate) so
neither protocol package depends on the other: x402 and MPP both import the v0
detector and the v0 client builder from here rather than reaching across into
each other.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any


def is_v0_wire_bytes(raw: bytes) -> bool:
    """Best-effort detection of a v0 ``VersionedTransaction`` on the wire.

    SECURITY: ``solders.transaction.Transaction.from_bytes`` is lenient on
    v0 wire bytes today: it can mis-parse a signed v0 transaction as a
    degenerate legacy transaction whose ``instructions`` list points at
    random ``account_keys`` entries. The downstream allowlist then rejects
    a legitimate v0 payment with a misleading
    ``unexpected program instruction in payment transaction: <pubkey>``
    error sourced from the mis-parsed junk. This helper peeks at the
    message-version prefix so callers can route v0 wire bytes straight to
    ``VersionedTransaction.from_bytes`` instead of trusting the lenient
    legacy parser.

    Wire format: ``[shortvec sig_count] [64 * sig_count signatures] [message]``.
    Legacy messages start with the header byte ``num_required_signatures``
    which is always ``< 0x80`` in practice (the MSB encodes a version
    prefix on v0). v0 messages start with ``0x80 | version`` so the high
    bit is set. We accept multi-byte compact-u16 lengths but cap at three
    bytes (Solana hard caps signatures well below ``128 * 128``).
    """
    if not raw:
        return False
    # Parse compact-u16 sig_count.
    sig_count = 0
    shift = 0
    offset = 0
    for _ in range(3):  # compact-u16 is at most 3 bytes
        if offset >= len(raw):
            return False
        byte = raw[offset]
        offset += 1
        sig_count |= (byte & 0x7F) << shift
        if (byte & 0x80) == 0:
            break
        shift += 7
    msg_start = offset + sig_count * 64
    if msg_start >= len(raw):
        return False
    # MessageV0 prefix is 0x80 | version; legacy header byte
    # (num_required_signatures) never sets the MSB for any realistic tx.
    return (raw[msg_start] & 0x80) != 0


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
