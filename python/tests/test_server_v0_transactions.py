"""V0 (versioned) transaction coverage for ``solana_pay_kit.protocols.mpp.server.charge``.

Every server-side decode boundary hands the wire bytes to
``VersionedTransaction.from_bytes``, which dispatches on the message-version
prefix: v0 (``0x80``) and legacy (unprefixed) messages both decode, so
``_decode_legacy_payment_instructions``, ``_co_sign_with_fee_payer``, and
``_validate_instruction_allowlist`` verify a pre-cutover client's legacy wire
under the same rules as v0. Clients never build legacy any more. This file
covers the prefix detector, the v0 allowlist happy path under repeated random
keypairs (which used to be a probabilistic mis-parse through the lenient
legacy parser), cosign on an unsigned v0 wire form, the multi-signer
rogue-fee-payer slot rejection, the missing-account-keys rejection, the
reported-version policy, and legacy acceptance on each helper. These mirror
the Rust spine's invariants in
``rust/crates/mpp/src/server/charge.rs``.
"""

from __future__ import annotations

import base64

import pytest
from solana_keychain import MemorySigner
from solders.hash import Hash
from solders.keypair import Keypair
from solders.message import MessageV0, to_bytes_versioned
from solders.system_program import TransferParams, transfer
from solders.transaction import VersionedTransaction

from solana_pay_kit._paycore.errors import PaymentError
from solana_pay_kit._paycore.solana import MethodDetails
from solana_pay_kit._paycore.transaction import (
    TRANSACTION_VERSION_NOT_REPORTED,
    is_v0_wire_bytes,
    require_reported_version,
)
from solana_pay_kit.protocols.mpp.intents.charge import ChargeRequest
from solana_pay_kit.protocols.mpp.server import charge as M

TEST_BLOCKHASH = "4vJ9JU1bJJQpUgJ8V6hYz7xXKz4F2tN6aBrZEcD3xKhs"


def _v0_tx_b64(payer: Keypair, instructions, signers=None) -> str:
    msg = MessageV0.try_compile(payer.pubkey(), instructions, [], Hash.from_string(TEST_BLOCKHASH))
    signers = signers or [payer]
    vtx = VersionedTransaction(msg, signers)
    return base64.b64encode(bytes(vtx)).decode("ascii")


def _v0_tx_unsigned_b64(payer: Keypair, instructions) -> str:
    """V0 with all-zero signature slots, suitable for cosign splice tests."""
    msg = MessageV0.try_compile(payer.pubkey(), instructions, [], Hash.from_string(TEST_BLOCKHASH))
    num_required = int(msg.header.num_required_signatures)
    # Hand-encode wire form: [num_sigs (compact-u16, <128 so 1 byte)]
    # [num_required * 64 zero bytes] [0x80 version prefix + message body].
    payload = bytearray()
    payload.append(num_required)
    payload.extend(bytes(64) * num_required)
    payload.extend(bytes(to_bytes_versioned(msg)))
    return base64.b64encode(bytes(payload)).decode("ascii")


# ---------------------------------------------------------------------------
# _decode_legacy_payment_instructions: v0 SOL transfer is decoded
# ---------------------------------------------------------------------------


def test_decode_v0_sol_transfer_is_surfaced():
    """A signed v0 SOL transfer is decoded and its transfer surfaced."""
    payer = Keypair()
    dst = Keypair()
    ix = transfer(TransferParams(from_pubkey=payer.pubkey(), to_pubkey=dst.pubkey(), lamports=42))
    tx_b64 = _v0_tx_b64(payer, [ix])

    out = M._decode_legacy_payment_instructions(tx_b64)
    assert [item["parsed"]["info"]["destination"] for item in out] == [str(dst.pubkey())]
    assert out[0]["parsed"]["info"]["lamports"] == "42"


# ---------------------------------------------------------------------------
# _co_sign_with_fee_payer v0 branches
# ---------------------------------------------------------------------------


async def test_cosign_v0_unsigned_happy_path_fills_signature_slot():
    """V0 unsigned wire form (zeroed signature slots): cosign splices the
    fee-payer signature in and returns valid bytes that re-parse."""
    fee_payer = Keypair()
    recipient = Keypair()
    ix = transfer(
        TransferParams(
            from_pubkey=fee_payer.pubkey(),
            to_pubkey=recipient.pubkey(),
            lamports=1000,
        )
    )
    tx_b64 = _v0_tx_unsigned_b64(fee_payer, [ix])

    signed_b64 = await M._co_sign_with_fee_payer(tx_b64, MemorySigner(fee_payer))
    signed_bytes = base64.b64decode(signed_b64)
    # Skip the 1-byte num_sigs prefix; first 64 bytes are the fee-payer
    # signature slot, which must no longer be all zeros.
    assert signed_bytes[1:65] != b"\x00" * 64
    # And the result is still a valid v0 transaction.
    reparsed = VersionedTransaction.from_bytes(signed_bytes)
    assert reparsed.message.account_keys[0] == fee_payer.pubkey()


async def test_cosign_uses_native_returned_transaction_and_preserves_payer_signature():
    fee_payer = Keypair()
    payer = Keypair()
    recipient = Keypair()
    ix = transfer(TransferParams(from_pubkey=payer.pubkey(), to_pubkey=recipient.pubkey(), lamports=1000))
    unsigned = VersionedTransaction.from_bytes(base64.b64decode(_v0_tx_unsigned_b64(fee_payer, [ix])))
    partially_signed = (await MemorySigner(payer).sign_transaction(unsigned)).transaction
    payer_index = list(partially_signed.message.account_keys).index(payer.pubkey())
    payer_signature = partially_signed.signatures[payer_index]

    class RemoteTransactionSigner(MemorySigner):
        async def sign_message(self, message: bytes):
            raise AssertionError("transaction signing must not use the message-signing API")

        async def sign_transaction(self, transaction: VersionedTransaction):
            # Remote signers can return a new object rather than mutating input.
            return await super().sign_transaction(VersionedTransaction.from_bytes(bytes(transaction)))

    signed_b64 = await M._co_sign_with_fee_payer(
        base64.b64encode(bytes(partially_signed)).decode(), RemoteTransactionSigner(fee_payer)
    )
    signed = VersionedTransaction.from_bytes(base64.b64decode(signed_b64))
    assert signed.signatures[payer_index] == payer_signature
    assert all(signed.verify_with_results())


async def test_cosign_v0_fee_payer_at_non_zero_slot_rejected():
    """V0 with the rogue fee-payer pubkey at slot 1: rejected.

    Mirrors the legacy-tx test in test_server.py for the v0 path. The
    rogue keypair appears in the required-signers block at slot 1 (slot
    0 belongs to the real payer), so cosign must refuse to produce a
    signature for it.
    """
    real_payer = Keypair()
    rogue_fee_payer = Keypair()
    recipient = Keypair()
    ix = transfer(
        TransferParams(
            from_pubkey=rogue_fee_payer.pubkey(),
            to_pubkey=recipient.pubkey(),
            lamports=1000,
        )
    )
    tx_b64 = _v0_tx_b64(real_payer, [ix], signers=[real_payer, rogue_fee_payer])

    with pytest.raises(PaymentError, match="must occupy account index 0"):
        await M._co_sign_with_fee_payer(tx_b64, MemorySigner(rogue_fee_payer))


async def test_cosign_v0_fee_payer_not_in_account_keys_rejected():
    """V0 with a fee-payer pubkey absent from the account keys: rejected."""
    payer = Keypair()
    recipient = Keypair()
    outsider = Keypair()
    ix = transfer(TransferParams(from_pubkey=payer.pubkey(), to_pubkey=recipient.pubkey(), lamports=1))
    tx_b64 = _v0_tx_b64(payer, [ix], signers=[payer])

    with pytest.raises(PaymentError, match="not present in transaction accounts"):
        await M._co_sign_with_fee_payer(tx_b64, MemorySigner(outsider))


async def test_cosign_invalid_bytes_rejected_with_invalid_payload_type():
    """Random bytes that never reach a message byte: invalid-payload-type."""
    bogus = base64.b64encode(b"\x00\x01\x02\x03").decode()
    with pytest.raises(PaymentError) as exc:
        await M._co_sign_with_fee_payer(bogus, MemorySigner(Keypair()))
    assert exc.value.code == "invalid-payload-type"


# ---------------------------------------------------------------------------
# _validate_instruction_allowlist: v0 happy path + invalid bytes
# ---------------------------------------------------------------------------


def _native_charge(recipient_pubkey, amount: int) -> tuple[ChargeRequest, MethodDetails]:
    request = ChargeRequest(
        amount=str(amount),
        currency="SOL",
        recipient=str(recipient_pubkey),
    )
    details = MethodDetails(network="solana-devnet")
    return request, details


def test_allowlist_v0_native_transfer_accepted():
    """A signed v0 SOL transfer matches the expected amount: no leftovers."""
    payer = Keypair()
    recipient = Keypair()
    ix = transfer(TransferParams(from_pubkey=payer.pubkey(), to_pubkey=recipient.pubkey(), lamports=1000))
    tx_b64 = _v0_tx_b64(payer, [ix])

    request, details = _native_charge(recipient.pubkey(), 1000)
    # No exception: the helper walks instructions, matches the expected
    # System transfer, and finishes with no leftovers.
    M._validate_instruction_allowlist(tx_b64, request, details)


def test_allowlist_v0_native_transfer_accepted_no_lenient_misparse():
    """Regression: signed v0 wire bytes must route to VersionedTransaction.

    ``solders.transaction.Transaction.from_bytes`` is lenient on v0 wire
    bytes and can mis-parse a signed v0 transaction as a degenerate legacy
    transaction whose instructions point at random ``account_keys`` slots.
    The allowlist would then reject the legitimate v0 payment with a
    misleading ``unexpected program instruction in payment transaction:
    <random pubkey>`` error. ``is_v0_wire_bytes`` detects the v0 message
    prefix and forces ``VersionedTransaction.from_bytes`` to take the
    parse, so the allowlist sees the real System transfer.

    A single iteration of the previous test can pass by chance; this loop
    hammers the mis-parse path with fresh keypairs so any regression
    surfaces with high probability.
    """
    for _ in range(200):
        payer = Keypair()
        recipient = Keypair()
        ix = transfer(TransferParams(from_pubkey=payer.pubkey(), to_pubkey=recipient.pubkey(), lamports=1000))
        tx_b64 = _v0_tx_b64(payer, [ix])

        request, details = _native_charge(recipient.pubkey(), 1000)
        M._validate_instruction_allowlist(tx_b64, request, details)


def test_is_v0_wire_bytes_classifies_correctly():
    """The v0-wire detector classifies v0 bytes as versioned and legacy bytes as not."""
    from solders.message import Message
    from solders.transaction import Transaction

    payer = Keypair()
    recipient = Keypair()
    ix = transfer(TransferParams(from_pubkey=payer.pubkey(), to_pubkey=recipient.pubkey(), lamports=1))

    v0_raw = base64.b64decode(_v0_tx_b64(payer, [ix]))
    assert is_v0_wire_bytes(v0_raw) is True

    blockhash = Hash.from_string(TEST_BLOCKHASH)
    legacy_msg = Message.new_with_blockhash([ix], payer.pubkey(), blockhash)
    legacy_tx = Transaction.new_unsigned(legacy_msg)
    legacy_tx.sign([payer], blockhash)
    legacy_raw = bytes(legacy_tx)
    assert is_v0_wire_bytes(legacy_raw) is False

    assert is_v0_wire_bytes(b"") is False
    assert is_v0_wire_bytes(b"\x01") is False


def _duplicate_memo_split_charge(recipient, vendor) -> tuple[ChargeRequest, MethodDetails]:
    from solana_pay_kit._paycore.solana import Split

    request = ChargeRequest(amount="1000", currency="SOL", recipient=str(recipient))
    details = MethodDetails(
        network="solana-devnet",
        splits=[
            Split(recipient=str(vendor), amount="100", memo="fee"),
            Split(recipient=str(vendor), amount="100", memo="fee"),
        ],
    )
    return request, details


def _memo_ix(text: str):
    from solders.instruction import Instruction
    from solders.pubkey import Pubkey

    from solana_pay_kit._paycore.solana import MEMO_PROGRAM

    return Instruction(Pubkey.from_string(MEMO_PROGRAM), text.encode("utf-8"), [])


def test_allowlist_accepts_one_memo_per_duplicate_split():
    """draft-solana-charge-00 Method Details: a recipient repeated in splits is
    a distinct payment leg that "MUST be verified separately", so two splits
    with the same memo text each admit their own Memo instruction."""
    payer, recipient, vendor = Keypair(), Keypair(), Keypair()
    ixs = [
        transfer(TransferParams(from_pubkey=payer.pubkey(), to_pubkey=recipient.pubkey(), lamports=800)),
        transfer(TransferParams(from_pubkey=payer.pubkey(), to_pubkey=vendor.pubkey(), lamports=100)),
        _memo_ix("fee"),
        transfer(TransferParams(from_pubkey=payer.pubkey(), to_pubkey=vendor.pubkey(), lamports=100)),
        _memo_ix("fee"),
    ]
    request, details = _duplicate_memo_split_charge(recipient.pubkey(), vendor.pubkey())
    M._validate_instruction_allowlist(_v0_tx_b64(payer, ixs), request, details)


def test_allowlist_rejects_memo_beyond_duplicate_split_count():
    """Negative control: the multiset still caps each memo at its leg count."""
    payer, recipient, vendor = Keypair(), Keypair(), Keypair()
    ixs = [
        transfer(TransferParams(from_pubkey=payer.pubkey(), to_pubkey=recipient.pubkey(), lamports=800)),
        transfer(TransferParams(from_pubkey=payer.pubkey(), to_pubkey=vendor.pubkey(), lamports=100)),
        _memo_ix("fee"),
        transfer(TransferParams(from_pubkey=payer.pubkey(), to_pubkey=vendor.pubkey(), lamports=100)),
        _memo_ix("fee"),
        _memo_ix("fee"),
    ]
    request, details = _duplicate_memo_split_charge(recipient.pubkey(), vendor.pubkey())
    with pytest.raises(PaymentError, match="unexpected Memo Program instruction"):
        M._validate_instruction_allowlist(_v0_tx_b64(payer, ixs), request, details)


def test_allowlist_invalid_bytes_rejected_with_invalid_payload_type():
    """Random bytes that never reach a message byte fail the allowlist decode."""
    bogus = base64.b64encode(b"\x00\x01\x02\x03").decode()
    request, details = _native_charge(Keypair().pubkey(), 1)
    with pytest.raises(PaymentError) as exc:
        M._validate_instruction_allowlist(bogus, request, details)
    assert exc.value.code == "invalid-payload-type"


# ---------------------------------------------------------------------------
# Legacy (unversioned) wires are accepted at every charge decode boundary
# ---------------------------------------------------------------------------


def _legacy_tx(payer: Keypair, instructions, signers=None) -> tuple[bytes, str]:
    from solders.message import Message
    from solders.transaction import Transaction

    blockhash = Hash.from_string(TEST_BLOCKHASH)
    tx = Transaction.new_unsigned(Message.new_with_blockhash(instructions, payer.pubkey(), blockhash))
    tx.sign(signers or [payer], blockhash)
    raw = bytes(tx)
    return raw, base64.b64encode(raw).decode("ascii")


def test_versioned_transaction_from_bytes_decodes_legacy_and_v0():
    from solders.message import Message

    payer = Keypair()
    ix = transfer(TransferParams(from_pubkey=payer.pubkey(), to_pubkey=Keypair().pubkey(), lamports=1))
    legacy_raw, _ = _legacy_tx(payer, [ix])
    assert not is_v0_wire_bytes(legacy_raw)
    legacy = VersionedTransaction.from_bytes(legacy_raw)
    assert isinstance(legacy.message, Message)
    assert bytes(legacy) == legacy_raw

    v0_raw = base64.b64decode(_v0_tx_b64(payer, [ix]))
    assert is_v0_wire_bytes(v0_raw)
    assert isinstance(VersionedTransaction.from_bytes(v0_raw).message, MessageV0)

    # A v1 prefix (0x81) is refused by solders until it implements v1.
    v1_raw = bytearray(v0_raw)
    v1_raw[1 + 64] = 0x81
    with pytest.raises(Exception):  # noqa: B017 - solders has no v1 parser yet
        VersionedTransaction.from_bytes(bytes(v1_raw))


def test_require_reported_version_mirrors_check_reported_version():
    """Signature credentials are fetched by ``getTransaction``; the top-level
    ``version`` of the result is policed like the wire prefix is for
    transaction credentials (Rust ``core::tx::check_reported_version``):
    0, 1 and legacy (policed as 0) are accepted, a missing version is not."""
    require_reported_version(0)
    require_reported_version(1)
    require_reported_version("legacy")

    with pytest.raises(ValueError) as exc:
        require_reported_version(None)
    assert str(exc.value) == TRANSACTION_VERSION_NOT_REPORTED

    for unaccepted in (2, 7, -1, True, "0", 0.0):
        with pytest.raises(ValueError, match="is not accepted; accepted versions: 0, 1"):
            require_reported_version(unaccepted)

    # The caller-supplied error factory shapes the raised exception.
    with pytest.raises(PaymentError) as perr:
        require_reported_version(None, error=lambda m: PaymentError(m, code="invalid-payload"))
    assert perr.value.code == "invalid-payload"


async def test_cosign_accepts_legacy_transaction():
    from solders.transaction import Transaction

    fee_payer = Keypair()
    ix = transfer(TransferParams(from_pubkey=fee_payer.pubkey(), to_pubkey=Keypair().pubkey(), lamports=1))
    _, tx_b64 = _legacy_tx(fee_payer, [ix])
    signed = Transaction.from_bytes(base64.b64decode(await M._co_sign_with_fee_payer(tx_b64, MemorySigner(fee_payer))))
    signed.verify()


def test_allowlist_accepts_legacy_transaction():
    payer = Keypair()
    recipient = Keypair()
    ix = transfer(TransferParams(from_pubkey=payer.pubkey(), to_pubkey=recipient.pubkey(), lamports=1000))
    _, tx_b64 = _legacy_tx(payer, [ix])
    request, details = _native_charge(recipient.pubkey(), 1000)
    # No exception: the legacy SOL transfer is matched under the v0 rules.
    M._validate_instruction_allowlist(tx_b64, request, details)
