"""Acceptance policy for client-supplied transactions the sponsor co-signs.

A ``deposit`` or ``refund`` payload carries a transaction the *client* built
and signed. The sponsor adds the fee-payer signature and broadcasts it, so its
signature authorizes whatever that transaction does. Every transaction is
therefore validated statically and exactly: an advertised message version, no
address lookup tables, a fixed signer set, a bounded ComputeBudget prefix,
exactly one canonical payment-channels instruction with a pinned account table
and fully decoded arguments, and a Memo/Lighthouse suffix that may not name the
fee payer (spec section 5). Mirrors the Rust kit
(``x402/protocol/schemes/batch_settlement/tx_policy.rs`` and the shared
``core::payment_channel::scan_channel_tx_layout``).
"""

from __future__ import annotations

import base64
import binascii
import struct
from collections.abc import Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Any

from solders.pubkey import Pubkey  # type: ignore[import-untyped]

from solana_pay_kit._paycore import txv1
from solana_pay_kit._paycore.paymentchannels import (
    LIGHTHOUSE_PROGRAM,
    MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS,
    OPEN_MAX_COMPUTE_UNIT_LIMIT,
    OPEN_MAX_LIGHTHOUSE_INSTRUCTIONS,
    OPEN_MAX_MEMO_BYTES,
    OPEN_MAX_OPTIONAL_SUFFIX,
    OPEN_SLOT_WINDOW,
    find_associated_token_address,
    find_channel_pda,
    find_event_authority_pda,
)
from solana_pay_kit._paycore.solana import (
    ASSOCIATED_TOKEN_PROGRAM,
    COMPUTE_BUDGET_PROGRAM,
    MEMO_PROGRAM,
    SYSTEM_PROGRAM,
)
from solana_pay_kit.protocols.x402.batch_settlement.errors import (
    INVALID_CHANNEL_ID_MISMATCH,
    INVALID_FEE_PAYER_MISMATCH,
    INVALID_RECEIVER_AUTHORIZER_MISMATCH,
    INVALID_REFUND_TRANSACTION,
    INVALID_SETUP_TRANSACTION,
    INVALID_WITHDRAW_DELAY_MISMATCH,
    UNSUPPORTED_TRANSACTION_VERSION,
    BatchSettlementError,
)
from solana_pay_kit.protocols.x402.batch_settlement.types import BatchChannelConfig
from solana_pay_kit.protocols.x402.batch_settlement.verify import (
    RECEIVER_BINDING_MEMO_PREFIX,
    parse_pubkey,
    parse_receiver_binding_memo,
)

__all__ = [
    "MemoPolicy",
    "SetupForm",
    "TransactionExpectations",
    "ValidatedTransaction",
    "decode_transaction",
    "payer_signature",
    "scan_channel_tx_layout",
    "setup_form_from_transaction",
    "validate_request_close_transaction",
    "validate_setup_transaction",
]

_OPEN_DISCRIMINATOR = 1
_TOP_UP_DISCRIMINATOR = 3
_REQUEST_CLOSE_DISCRIMINATOR = 5
#: One ``DistributionEntry``: 32-byte recipient plus a little-endian ``u16`` share.
_DISTRIBUTION_ENTRY_LEN = 34
#: ``open`` args before the recipients vector: discriminator, salt, deposit, grace_period, open_slot.
_OPEN_ARGS_PREFIX_LEN = 1 + 8 + 8 + 4 + 8
_FULL_SHARE_BPS = 10_000
#: Minimum random Memo nonce, in bytes, before hex encoding.
MIN_MEMO_NONCE_BYTES = 16
_RENT_SYSVAR = "SysvarRent111111111111111111111111111111111"


class SetupForm(Enum):
    """Which setup instruction a ``deposit`` payload carries."""

    OPEN = "open"
    TOP_UP = "top_up"

    @property
    def discriminator(self) -> int:
        return _OPEN_DISCRIMINATOR if self is SetupForm.OPEN else _TOP_UP_DISCRIMINATOR


@dataclass(frozen=True)
class MemoPolicy:
    """How :func:`scan_channel_tx_layout` polices the Memo suffix.

    ``kind`` is ``"optional"`` (not inspected), ``"required"`` (exactly one
    Memo: ``memo`` when declared, else a hex nonce) or ``"binding"``
    (``required`` plus exactly one Memo starting with ``binding_prefix``).
    """

    kind: str
    memo: str | None = None
    binding_prefix: str | None = None

    @property
    def max_memos(self) -> int:
        return 2 if self.kind == "binding" else 1


@dataclass(frozen=True)
class TransactionExpectations:
    """What a client-supplied transaction is checked against (never the
    transaction itself)."""

    program_id: Pubkey
    fee_payer: Pubkey
    config: BatchChannelConfig
    channel_id: Pubkey
    token_program: Pubkey
    receiver: Pubkey
    receiver_authorizer: Pubkey
    accepted_versions: Sequence[int]
    memo: str | None = None


@dataclass(frozen=True)
class ValidatedTransaction:
    """A validated client transaction: only the fee-payer slot is missing."""

    transaction: Any
    payer: Pubkey


def _err(detail: str, code: str = INVALID_SETUP_TRANSACTION) -> BatchSettlementError:
    return BatchSettlementError(code, detail)


def decode_transaction(transaction_b64: str) -> Any:
    """Decode a base64 legacy, version-0 or version-1 transaction in canonical
    encoding (re-encoding must reproduce the bytes exactly)."""
    try:
        raw = base64.b64decode(transaction_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"invalid base64 transaction: {exc}") from exc
    try:
        tx = txv1.decode_transaction(raw)
    except Exception as exc:  # noqa: BLE001 - solders raises its own error types
        raise ValueError(f"invalid transaction: {exc}") from exc
    if bytes(tx) != raw:
        raise ValueError("invalid transaction: non-canonical encoding or trailing bytes")
    return tx


def _decode(transaction_b64: str, label: str) -> Any:
    try:
        return decode_transaction(transaction_b64)
    except ValueError as exc:
        raise _err(f"{label} transaction could not be decoded: {exc}") from exc


def payer_signature(transaction: Any) -> str | None:
    """The channel payer's signature (slot 1), which identifies a setup across retries."""
    signatures = list(transaction.signatures)
    return str(signatures[1]) if len(signatures) > 1 else None


def _keys(tx: Any) -> list[Pubkey]:
    return list(tx.message.account_keys)


def _program_of(ix: Any, keys: list[Pubkey]) -> Pubkey | None:
    index = int(ix.program_id_index)
    return keys[index] if index < len(keys) else None


def setup_form_from_transaction(transaction_b64: str, program_id: Pubkey) -> SetupForm:
    """Read the setup form from the signed transaction (not from stored state)."""
    tx = _decode(transaction_b64, "setup")
    keys = _keys(tx)
    forms: list[SetupForm] = []
    for ix in tx.message.instructions:
        data = bytes(ix.data)
        if _program_of(ix, keys) != program_id or not data:
            continue
        if data[0] == _OPEN_DISCRIMINATOR:
            forms.append(SetupForm.OPEN)
        elif data[0] == _TOP_UP_DISCRIMINATOR:
            forms.append(SetupForm.TOP_UP)
    if len(forms) != 1:
        raise _err("transaction must contain exactly one open or top_up instruction")
    return forms[0]


# ── envelope ──────────────────────────────────────────────────────────────


def _check_envelope(tx: Any, expected: TransactionExpectations, label: str) -> Pubkey:
    """Version, lookup tables, size, budget caps, fee payer, signer set and the
    payer's signature. Returns the channel payer."""
    message = tx.message
    version = txv1.policy_version(message)
    if version not in expected.accepted_versions:
        raise _err(
            f"{label} transaction is version {version}, which this sponsor does not accept",
            UNSUPPORTED_TRANSACTION_VERSION,
        )
    try:
        txv1.check_envelope(tx, expected.accepted_versions)
        txv1.check_v1_budget_caps(
            message,
            OPEN_MAX_COMPUTE_UNIT_LIMIT,
            MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS,
            loaded_rule="present",
        )
        txv1.reject_v1_heap_request(message)
    except txv1.TransactionVersionError as exc:
        raise _err(f"{label} transaction: {exc}") from exc

    try:
        payer = parse_pubkey(expected.config.payer)
    except ValueError as exc:
        raise _err(f"channelConfig.payer: {exc}") from exc
    if payer == expected.fee_payer:
        raise _err("channelConfig.payer must not equal extra.feePayer", INVALID_FEE_PAYER_MISMATCH)
    keys = _keys(tx)
    if not keys or keys[0] != expected.fee_payer:
        raise _err(f"{label} transaction fee payer must be {expected.fee_payer}")
    required = int(message.header.num_required_signatures)
    if required != 2:
        raise _err(f"{label} transaction must require exactly 2 signatures, got {required}")
    if len(keys) < 2 or keys[1] != payer:
        raise _err(f"{label} transaction second signer must be the channel payer {payer}")
    signatures = list(tx.signatures)
    if len(signatures) != required:
        raise _err(f"{label} transaction has {len(signatures)} signature slots but requires {required}")
    if not signatures[1].verify(payer, txv1.signed_message_bytes(message)):
        raise _err(f"{label} transaction is missing a valid channel-payer signature")
    return payer


# ── layout scan ───────────────────────────────────────────────────────────


def _memo_text(data: bytes, label: str) -> str:
    if len(data) > OPEN_MAX_MEMO_BYTES:
        raise ValueError(f"{label} transaction memo is {len(data)} bytes, over the {OPEN_MAX_MEMO_BYTES}-byte maximum")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{label} transaction memo is not valid UTF-8") from exc


def _check_memo_data(data: bytes, label: str, policy: MemoPolicy) -> None:
    if policy.kind == "optional":
        return
    text = _memo_text(data, label)
    if policy.memo is not None:
        if text != policy.memo:
            raise ValueError(f"{label} transaction memo does not match the declared extra.memo")
        return
    hexdigits = set("0123456789abcdefABCDEF")
    if len(text) < MIN_MEMO_NONCE_BYTES * 2 or not all(ch in hexdigits for ch in text):
        raise ValueError(f"{label} transaction memo must be a hex nonce of at least {MIN_MEMO_NONCE_BYTES} bytes")


def scan_channel_tx_layout(tx: Any, program_id: Pubkey, discriminator: int, label: str, policy: MemoPolicy) -> Any:
    """Enforce the sponsor's top-level instruction allowlist; return the single
    payment-channels instruction it wraps. Raises ``ValueError``.

    Layout: an optional ComputeBudget prefix (at most one limit then at most
    one price, each within its cap), exactly one ``program_id`` instruction
    starting with ``discriminator``, then at most
    ``OPEN_MAX_OPTIONAL_SUFFIX`` (+1 for a binding memo) Lighthouse/Memo
    instructions. No wrapper instruction may name the fee payer.
    """
    keys = _keys(tx)
    instructions = list(tx.message.instructions)
    if not keys:
        raise ValueError(f"{label} transaction has no fee payer")
    fee_payer = keys[0]

    def program_of(ix: Any) -> Pubkey:
        program = _program_of(ix, keys)
        if program is None:
            raise ValueError(f"{label} instruction program id out of range")
        return program

    def reject_fee_payer(ix: Any, wrapper: str) -> None:
        if any(int(i) < len(keys) and keys[int(i)] == fee_payer for i in bytes(ix.accounts)):
            raise ValueError(f"{wrapper} instruction must not reference the fee payer")

    compute_budget = Pubkey.from_string(COMPUTE_BUDGET_PROGRAM)
    index = 0
    seen_limit = seen_price = False
    while index < len(instructions) and program_of(instructions[index]) == compute_budget:
        ix = instructions[index]
        reject_fee_payer(ix, "ComputeBudget")
        data = bytes(ix.data)
        tag = data[0] if data else None
        if tag == txv1.SET_UNIT_LIMIT_TAG and len(data) == 5:
            if seen_limit:
                raise ValueError(f"{label} transaction has a duplicate SetComputeUnitLimit instruction")
            if seen_price:
                raise ValueError(f"{label} transaction SetComputeUnitLimit must precede SetComputeUnitPrice")
            units = int.from_bytes(data[1:5], "little")
            if units > OPEN_MAX_COMPUTE_UNIT_LIMIT:
                raise ValueError(
                    f"{label} transaction compute unit limit {units} exceeds maximum {OPEN_MAX_COMPUTE_UNIT_LIMIT}"
                )
            seen_limit = True
        elif tag == txv1.SET_UNIT_PRICE_TAG and len(data) == 9:
            if seen_price:
                raise ValueError(f"{label} transaction has a duplicate SetComputeUnitPrice instruction")
            price = int.from_bytes(data[1:9], "little")
            if price > MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS:
                raise ValueError(
                    f"{label} transaction compute unit price {price} exceeds maximum "
                    f"{MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS}"
                )
            seen_price = True
        else:
            raise ValueError(f"{label} transaction has an unsupported ComputeBudget instruction")
        index += 1

    if index >= len(instructions):
        raise ValueError(f"{label} transaction contains no payment-channels instruction")
    primary = instructions[index]
    if program_of(primary) != program_id:
        raise ValueError(f"{label} transaction targets an unexpected program")
    primary_data = bytes(primary.data)
    if not primary_data or primary_data[0] != discriminator:
        raise ValueError(f"{label} transaction is not a payment-channels {label} instruction")
    index += 1

    memo_program = Pubkey.from_string(MEMO_PROGRAM)
    lighthouse = Pubkey.from_string(LIGHTHOUSE_PROGRAM)
    lighthouse_count = optional_count = memo_count = binding_count = 0
    max_suffix = OPEN_MAX_OPTIONAL_SUFFIX + policy.max_memos - 1
    while index < len(instructions):
        ix = instructions[index]
        optional_count += 1
        if optional_count > max_suffix:
            raise ValueError(f"{label} transaction allows at most {max_suffix} instructions after {label}")
        program = program_of(ix)
        data = bytes(ix.data)
        if program == lighthouse:
            lighthouse_count += 1
            if lighthouse_count > OPEN_MAX_LIGHTHOUSE_INSTRUCTIONS:
                raise ValueError(
                    f"{label} transaction allows at most {OPEN_MAX_LIGHTHOUSE_INSTRUCTIONS} Lighthouse "
                    f"instructions after {label}"
                )
            reject_fee_payer(ix, "Lighthouse")
        elif program == memo_program:
            reject_fee_payer(ix, "Memo")
            if policy.kind == "binding" and data.startswith((policy.binding_prefix or "").encode()):
                binding_count += 1
                if binding_count > 1:
                    raise ValueError(f"{label} transaction must carry exactly one binding Memo")
                _memo_text(data, label)
            elif policy.kind == "binding":
                memo_count += 1
                if memo_count > 1:
                    raise ValueError(
                        f"{label} transaction allows at most one Memo instruction besides the binding Memo"
                    )
                _check_memo_data(data, label, policy)
            else:
                memo_count += 1
                if memo_count > 1 and policy.kind == "required":
                    raise ValueError(f"{label} transaction allows at most one Memo instruction")
                _check_memo_data(data, label, policy)
        else:
            raise ValueError(
                f"{label} transaction instruction after {label} must be Lighthouse or Memo, found {program}"
            )
        index += 1
    if memo_count == 0 and policy.kind != "optional":
        raise ValueError(f"{label} transaction must carry exactly one Memo instruction")
    if binding_count == 0 and policy.kind == "binding":
        raise ValueError(f"{label} transaction must carry exactly one binding Memo")
    try:
        txv1.check_priority_fee(tx.message, txv1.MAX_SPONSORED_PRIORITY_FEE_LAMPORTS)
    except txv1.TransactionVersionError as exc:
        raise ValueError(f"{label} transaction compute unit price exceeds the sponsored fee maximum: {exc}") from exc
    return primary


# ── account tables ────────────────────────────────────────────────────────


def _account_at(ix: Any, keys: list[Pubkey], position: int) -> Pubkey | None:
    accounts = bytes(ix.accounts)
    if position >= len(accounts) or accounts[position] >= len(keys):
        return None
    return keys[accounts[position]]


def _expect_account(ix: Any, keys: list[Pubkey], position: int, want: Pubkey, role: str, label: str) -> None:
    got = _account_at(ix, keys, position)
    if got != want:
        raise _err(f"{label} {role} mismatch: expected {want}, got {got if got is not None else '<none>'}")


def _reject_fee_payer_account(ix: Any, keys: list[Pubkey], fee_payer: Pubkey, label: str) -> None:
    if any(i < len(keys) and keys[i] == fee_payer for i in bytes(ix.accounts)):
        raise _err(f"{label} instruction must not reference the fee payer")


def _is_writable(tx: Any, index: int) -> bool:
    header = tx.message.header
    signers = int(header.num_required_signatures)
    total = len(tx.message.account_keys)
    if index < signers:
        return index < signers - int(header.num_readonly_signed_accounts)
    return index < max(total - int(header.num_readonly_unsigned_accounts), 0)


def _check_writable(tx: Any, ix: Any, position: int, role: str, label: str) -> None:
    accounts = bytes(ix.accounts)
    if position >= len(accounts):
        raise _err(f"{label} {role} account position {position} is missing")
    if not _is_writable(tx, accounts[position]):
        raise _err(f"{label} {role} must be writable")


def _config_key(value: str, field: str) -> Pubkey:
    try:
        return parse_pubkey(value)
    except ValueError as exc:
        raise _err(f"{field}: {exc}") from exc


def _check_open_accounts(ix: Any, keys: list[Pubkey], payer: Pubkey, expected: TransactionExpectations) -> None:
    label = "open"
    if len(bytes(ix.accounts)) != 14:
        raise _err(f"open must have exactly 14 accounts and no remaining accounts, got {len(bytes(ix.accounts))}")
    mint = _config_key(expected.config.token, "channelConfig.token")
    authorized_signer = _config_key(expected.config.payer_authorizer, "channelConfig.payerAuthorizer")
    payer_token, _ = find_associated_token_address(payer, mint, expected.token_program)
    channel_token, _ = find_associated_token_address(expected.channel_id, mint, expected.token_program)
    table = [
        (payer, "payer"),
        (expected.fee_payer, "rent_payer"),
        (expected.fee_payer, "payee"),
        (mint, "mint"),
        (authorized_signer, "authorized_signer"),
        (expected.channel_id, "channel"),
        (payer_token, "payer_token_account"),
        (channel_token, "channel_token_account"),
        (expected.token_program, "token_program"),
        (Pubkey.from_string(SYSTEM_PROGRAM), "system_program"),
        (Pubkey.from_string(_RENT_SYSVAR), "rent"),
        (Pubkey.from_string(ASSOCIATED_TOKEN_PROGRAM), "associated_token_program"),
        (find_event_authority_pda(expected.program_id)[0], "event_authority"),
        (expected.program_id, "self_program"),
    ]
    for position, (want, role) in enumerate(table):
        _expect_account(ix, keys, position, want, role, label)


def _check_top_up_accounts(ix: Any, keys: list[Pubkey], payer: Pubkey, expected: TransactionExpectations) -> None:
    label = "top_up"
    if len(bytes(ix.accounts)) != 6:
        raise _err(f"top_up must have exactly 6 accounts and no remaining accounts, got {len(bytes(ix.accounts))}")
    mint = _config_key(expected.config.token, "channelConfig.token")
    payer_token, _ = find_associated_token_address(payer, mint, expected.token_program)
    channel_token, _ = find_associated_token_address(expected.channel_id, mint, expected.token_program)
    table = [
        (payer, "payer"),
        (expected.channel_id, "channel"),
        (payer_token, "payer_token_account"),
        (channel_token, "channel_token_account"),
        (mint, "mint"),
        (expected.token_program, "token_program"),
    ]
    for position, (want, role) in enumerate(table):
        _expect_account(ix, keys, position, want, role, label)


def _check_open_args(ix: Any, expected: TransactionExpectations, deposit_amount: int, recent_slot: int | None) -> None:
    data = bytes(ix.data)
    want_len = _OPEN_ARGS_PREFIX_LEN + 4 + _DISTRIBUTION_ENTRY_LEN
    if len(data) != want_len:
        raise _err(f"open args must be exactly {want_len} bytes for a single-recipient distribution, got {len(data)}")
    salt, deposit, grace_period, open_slot = struct.unpack_from("<QQIQ", data, 1)
    try:
        want_salt = expected.config.salt_value()
    except ValueError as exc:
        raise _err(f"channelConfig.salt: {exc}") from exc
    if salt != want_salt:
        raise _err(f"open salt {salt} does not match channelConfig.salt {want_salt}")
    if deposit != deposit_amount:
        raise _err(f"open deposit {deposit} does not match deposit.amount {deposit_amount}")
    if grace_period != expected.config.withdraw_delay:
        raise _err(
            f"open grace_period {grace_period} does not match withdrawDelay {expected.config.withdraw_delay}",
            INVALID_WITHDRAW_DELAY_MISMATCH,
        )
    if open_slot != expected.config.open_slot:
        raise _err(f"open open_slot {open_slot} does not match channelConfig.openSlot {expected.config.open_slot}")
    (count,) = struct.unpack_from("<I", data, _OPEN_ARGS_PREFIX_LEN)
    if count != 1:
        raise _err(f"open distribution must have exactly one recipient, got {count}")
    entry = data[_OPEN_ARGS_PREFIX_LEN + 4 :]
    recipient = Pubkey.from_bytes(entry[:32])
    (bps,) = struct.unpack_from("<H", entry, 32)
    if recipient != expected.receiver or bps != _FULL_SHARE_BPS:
        raise _err(f"open distribution must pay 100% to {expected.receiver}, got {recipient} at {bps} bps")
    payer = _config_key(expected.config.payer, "channelConfig.payer")
    mint = _config_key(expected.config.token, "channelConfig.token")
    authorized_signer = _config_key(expected.config.payer_authorizer, "channelConfig.payerAuthorizer")
    derived, _ = find_channel_pda(
        payer, expected.fee_payer, mint, authorized_signer, salt, open_slot, expected.program_id
    )
    if derived != expected.channel_id:
        raise _err(
            f"open channel {expected.channel_id} is not the PDA derived from its own args ({derived})",
            INVALID_CHANNEL_ID_MISMATCH,
        )
    if recent_slot is not None:
        if open_slot > recent_slot:
            raise _err(f"open open_slot {open_slot} is ahead of the current slot {recent_slot}")
        if recent_slot - open_slot > OPEN_SLOT_WINDOW:
            raise _err(
                f"open open_slot {open_slot} is outside the {OPEN_SLOT_WINDOW}-slot window of the current slot "
                f"{recent_slot}"
            )


def _check_receiver_binding(tx: Any, keys: list[Pubkey], expected: TransactionExpectations) -> None:
    memo_program = Pubkey.from_string(MEMO_PROGRAM)
    bound: list[Pubkey] = []
    for ix in tx.message.instructions:
        if _program_of(ix, keys) != memo_program:
            continue
        key = parse_receiver_binding_memo(bytes(ix.data))
        if key is not None:
            bound.append(key)
    if len(bound) != 1:
        raise _err("open transaction must carry exactly one receiver-binding Memo")
    if bound[0] != expected.receiver_authorizer:
        raise _err(
            f"open binds receiver authorizer {bound[0]}, not extra.receiverAuthorizer {expected.receiver_authorizer}",
            INVALID_RECEIVER_AUTHORIZER_MISMATCH,
        )


def validate_setup_transaction(
    transaction_b64: str,
    form: SetupForm,
    expected: TransactionExpectations,
    deposit_amount: int,
    recent_slot: int | None,
) -> ValidatedTransaction:
    """Validate a client-signed ``open`` or ``top_up`` transaction.

    The decoded instruction must fund exactly ``deposit_amount``;
    ``recent_slot``, when known, bounds an open's ``open_slot`` to the program's
    freshness window.
    """
    label = form.value
    tx = _decode(transaction_b64, label)
    payer = _check_envelope(tx, expected, label)
    keys = _keys(tx)
    policy = (
        MemoPolicy("binding", expected.memo, RECEIVER_BINDING_MEMO_PREFIX)
        if form is SetupForm.OPEN
        else MemoPolicy("required", expected.memo)
    )
    try:
        ix = scan_channel_tx_layout(tx, expected.program_id, form.discriminator, label, policy)
    except ValueError as exc:
        raise _err(str(exc)) from exc
    if form is SetupForm.OPEN:
        _check_receiver_binding(tx, keys, expected)
        _check_open_accounts(ix, keys, payer, expected)
        _check_open_args(ix, expected, deposit_amount, recent_slot)
        # Positions 2 (payee) and 4 (authorized_signer) are deliberately not
        # checked: message compilation unions their privileges with the
        # rent_payer and payer they coincide with.
        for position, role in (
            (0, "payer"),
            (1, "rent_payer"),
            (5, "channel"),
            (6, "payer_token_account"),
            (7, "channel_token_account"),
        ):
            _check_writable(tx, ix, position, role, label)
    else:
        _check_top_up_accounts(ix, keys, payer, expected)
        data = bytes(ix.data)
        if len(data) != 9:
            raise _err(f"{label} args must be exactly 9 bytes, got {len(data)}")
        (amount,) = struct.unpack_from("<Q", data, 1)
        if amount != deposit_amount:
            raise _err(f"{label} amount {amount} does not match deposit.amount {deposit_amount}")
        for position, role in ((0, "payer"), (1, "channel"), (2, "payer_token_account"), (3, "channel_token_account")):
            _check_writable(tx, ix, position, role, label)
        _reject_fee_payer_account(ix, keys, expected.fee_payer, label)
    return ValidatedTransaction(transaction=tx, payer=payer)


def validate_request_close_transaction(transaction_b64: str, expected: TransactionExpectations) -> ValidatedTransaction:
    """Validate a client-signed ``request_close``: nothing but the close (plus
    the allowlisted prefix and suffix) may ride along."""
    label = "request_close"

    def refund_err(detail: str) -> BatchSettlementError:
        return _err(detail, INVALID_REFUND_TRANSACTION)

    try:
        tx = _decode(transaction_b64, label)
    except BatchSettlementError as exc:
        raise refund_err(exc.detail) from exc
    try:
        payer = _check_envelope(tx, expected, label)
    except BatchSettlementError as exc:
        if exc.code == UNSUPPORTED_TRANSACTION_VERSION:
            raise
        raise refund_err(exc.detail) from exc
    keys = _keys(tx)
    try:
        ix = scan_channel_tx_layout(
            tx, expected.program_id, _REQUEST_CLOSE_DISCRIMINATOR, label, MemoPolicy("required", expected.memo)
        )
    except ValueError as exc:
        raise refund_err(str(exc)) from exc
    accounts = bytes(ix.accounts)
    if len(accounts) != 2:
        raise refund_err(f"request_close must have exactly 2 accounts, got {len(accounts)}")
    try:
        _expect_account(ix, keys, 0, payer, "payer", label)
        _expect_account(ix, keys, 1, expected.channel_id, "channel", label)
        if len(bytes(ix.data)) != 1:
            raise _err(f"request_close takes no arguments, got {len(bytes(ix.data))} data bytes")
        _check_writable(tx, ix, 1, "channel", label)
        _reject_fee_payer_account(ix, keys, expected.fee_payer, label)
    except BatchSettlementError as exc:
        raise refund_err(exc.detail) from exc
    return ValidatedTransaction(transaction=tx, payer=payer)
