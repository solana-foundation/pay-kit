"""Shared Solana transaction-wire helpers used by both protocol adapters.

Lives in ``_paycore`` (the shared core, mirroring the Rust ``core`` crate) so
neither protocol package depends on the other: x402 and MPP both import the v0
detector and the v0 client builder from here rather than reaching across into
each other.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence

from solana_keychain import TransactionSigner
from solders.hash import Hash
from solders.instruction import Instruction
from solders.pubkey import Pubkey
from solders.signature import Signature
from solders.transaction import VersionedTransaction


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
    """Best-effort detection of a versioned (prefixed) message on the wire.

    Legacy messages start with the header byte ``num_required_signatures``
    which is always ``< 0x80`` in practice; versioned messages start with
    ``0x80 | version`` so the high bit is set. Servers decode both shapes
    through ``solders.transaction.VersionedTransaction.from_bytes``, which
    dispatches on this prefix itself and yields a legacy ``Message`` or a
    ``MessageV0``; this helper only lets tests and clients name the shape.
    """
    msg_start = _message_offset(raw)
    return msg_start is not None and (raw[msg_start] & 0x80) != 0


#: Rejection text when a transaction fetched by signature carries no top-level
#: ``version``; the Rust servers emit the same string.
TRANSACTION_VERSION_NOT_REPORTED = "RPC did not report the transaction version"


def require_reported_version(version: object, error: Callable[[str], Exception] = ValueError) -> None:
    """Version policy for a transaction read back from the RPC by signature.

    ``maxSupportedTransactionVersion`` only bounds what the node returns; the
    server applies the same policy as at the decode boundary. ``version`` is
    the top-level ``getTransaction`` result field: ``0`` and ``1`` are
    accepted, and so is ``"legacy"`` (a legacy message is policed as version
    0 and kept for existing clients); a missing field (``None``) is refused
    with ``TRANSACTION_VERSION_NOT_REPORTED`` (nodes report one for every
    transaction once asked), and any other value as an unaccepted version.
    Mirrors ``core::tx::check_reported_version``.
    """
    if version is None:
        raise error(TRANSACTION_VERSION_NOT_REPORTED)
    if version == "legacy":
        return
    if isinstance(version, bool) or not isinstance(version, int) or version not in (0, 1):
        raise error(f"transaction version {version!r} is not accepted; accepted versions: 0, 1")


class SignatureCheckError(ValueError):
    """A wire transaction whose signatures do not authorize its message."""


def verify_required_signatures(transaction: VersionedTransaction, *, unsigned: Pubkey | None = None) -> None:
    """Refuse a transaction unless every required signer has signed its message.

    The signature list must hold exactly ``header.num_required_signatures``
    entries, one per required signer, and each must verify against the
    account key in its slot over the exact signed message bytes. Checking only
    the signatures present is not enough: a landed two-signer transaction cut
    down to its first signature still verifies slot for slot, yet it names
    the landed transaction, so a server that claimed it and then reconciled
    on that signature's status would grant a payment it never received.

    ``unsigned`` is the one key whose slot may still be the all-zero
    placeholder: the server's own fee payer before it co-signs. Its slot must
    still exist, and a non-placeholder signature in it must verify. Every
    other slot must verify. Call this on the exact bytes that are claimed or
    sent, before either.

    Raises :class:`SignatureCheckError`; callers map it to their protocol's
    reject code.
    """
    from solders.message import to_bytes_versioned  # type: ignore[import-untyped]

    message = transaction.message
    required = int(message.header.num_required_signatures)
    signatures = list(transaction.signatures)
    if required == 0 or len(signatures) != required:
        raise SignatureCheckError(
            f"transaction carries {len(signatures)} signatures but its message requires {required}"
        )
    account_keys = list(message.account_keys)
    if len(account_keys) < required:
        raise SignatureCheckError("transaction message lists fewer account keys than required signers")
    signed_bytes = bytes(to_bytes_versioned(message))
    placeholder = Signature.default()
    for key, signature in zip(account_keys[:required], signatures, strict=True):
        if unsigned is not None and key == unsigned and signature == placeholder:
            continue
        if not signature.verify(key, signed_bytes):
            raise SignatureCheckError(f"signature for required signer {key} does not verify")


async def build_partially_signed_v0_transaction(
    instructions: Sequence[Instruction],
    fee_payer: Pubkey,
    blockhash: Hash,
    signer: TransactionSigner,
) -> bytes:
    """Compile a v0 transaction and sign it through solana-keychain.

    ``fee_payer`` becomes ``account_keys[0]``; every other required-signer slot
    is left as a zero placeholder for a server-side cosign. Transaction
    signing does not require access to secret keys or raw-message signing,
    so remote transaction-only signers use the same path as local signers.
    """
    from solders.message import MessageV0  # type: ignore[import-untyped]

    message = MessageV0.try_compile(fee_payer, list(instructions), [], blockhash)
    num_required = int(message.header.num_required_signatures)
    if signer.pubkey not in message.account_keys[:num_required]:
        raise ValueError("solana_pay_kit: signer is not a required signer of the transaction")
    signatures = [Signature.default() for _ in range(num_required)]
    transaction = VersionedTransaction.populate(message, signatures)
    result = await signer.sign_transaction(transaction)
    return bytes(result.transaction)
