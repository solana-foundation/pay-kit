"""Acceptance policy for the client-built transactions the sponsor co-signs.

A ``deposit`` (``open``/``top_up``) or ``refund`` (``request_close``) payload
carries a transaction the *client* built and signed; the sponsor adds only the
fee-payer signature and broadcasts. Its signature authorizes whatever the
transaction does, and simulation runs only after that authorization, so every
transaction is validated statically and exactly first: legacy or version 0
with no address lookup tables, the signer set exactly ``{feePayer, payer}``
with a valid payer signature, a bounded ComputeBudget prefix, exactly one
canonical payment-channels instruction with a pinned account table and fully
decoded arguments, and a Memo/Lighthouse suffix that never names the fee payer.

The rules are the ones the SVM ``batch-settlement`` spec puts on the setup and
refund transactions (spec section 5, phase 1): the instruction shape, the
signer set, the ComputeBudget bound and the Memo requirement. Cross-check for
byte parity: the Rust ``protocol/schemes/batch_settlement/tx_policy.rs`` and
the ``core::payment_channels::scan_channel_tx_layout`` allowlist it uses. Where
the two differ on the refund suffix, the spec wins (at most one Memo, not
exactly one); a Memo that is present is held to the same content rule either
way.
"""

from __future__ import annotations

import base64
import binascii
import struct
from dataclasses import dataclass, field
from typing import Literal

from solders.instruction import CompiledInstruction  # type: ignore[import-untyped]
from solders.message import to_bytes_versioned  # type: ignore[import-untyped]
from solders.pubkey import Pubkey  # type: ignore[import-untyped]
from solders.transaction import VersionedTransaction  # type: ignore[import-untyped]

from solana_pay_kit._paycore.paymentchannels import (
    COMPUTE_BUDGET_SET_UNIT_LIMIT,
    COMPUTE_BUDGET_SET_UNIT_PRICE,
    LIGHTHOUSE_PROGRAM,
    MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS,
    OPEN_MAX_COMPUTE_UNIT_LIMIT,
    OPEN_MAX_LIGHTHOUSE_INSTRUCTIONS,
    OPEN_MAX_MEMO_BYTES,
    OPEN_SLOT_WINDOW,
    PROGRAM_ID,
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
from solana_pay_kit.protocols.x402.batch_settlement import errors
from solana_pay_kit.protocols.x402.batch_settlement.errors import BatchSettlementError
from solana_pay_kit.protocols.x402.batch_settlement.types import BatchChannelConfig

__all__ = [
    "SetupForm",
    "TransactionExpectations",
    "ValidatedTransaction",
    "setup_form",
    "validate_request_close",
    "validate_setup",
]

#: Which setup a ``deposit`` carries: a new channel or more escrow for one.
SetupForm = Literal["open", "top_up"]

_OPEN = 1
_TOP_UP = 3
_REQUEST_CLOSE = 5
_DISCRIMINATORS: dict[SetupForm, int] = {"open": _OPEN, "top_up": _TOP_UP}
# discriminator + salt u64 + deposit u64 + grace u32 + openSlot u64, then a u32
# recipient count and one 34-byte (pubkey + u16 bps) entry: 67 bytes in total.
_OPEN_ARGS_PREFIX = 1 + 8 + 8 + 4 + 8
_OPEN_DATA_LEN = _OPEN_ARGS_PREFIX + 4 + 34
_FULL_SHARE_BPS = 10_000
_MIN_MEMO_NONCE_BYTES = 16
# Legacy and version-0 packet limit (1280 - 40 - 8), as in the Rust core::tx.
_PACKET_DATA_SIZE = 1232
_RENT_SYSVAR = "SysvarRent111111111111111111111111111111111"


@dataclass(frozen=True)
class TransactionExpectations:
    """What a client transaction is checked against: the advertised terms and the echoed channel config.

    Never taken from the transaction itself. ``token_program`` is the mint's
    on-chain owner, already confirmed against ``extra.tokenProgram``;
    ``receiver`` is ``payTo``; ``memo`` is the seller-declared ``extra.memo``.
    """

    fee_payer: str
    config: BatchChannelConfig
    channel_id: str
    token_program: str
    receiver: str
    memo: str | None = None
    program_id: Pubkey = field(default_factory=lambda: PROGRAM_ID)


@dataclass(frozen=True)
class ValidatedTransaction:
    """A policy-clean client transaction; only the fee-payer signature slot is left to fill."""

    transaction: VersionedTransaction
    payer: str


def _reject(detail: str, code: str = errors.INVALID_SETUP_TRANSACTION) -> BatchSettlementError:
    return BatchSettlementError(code, detail)


def _decode(transaction_b64: str, label: str) -> VersionedTransaction:
    try:
        raw = base64.b64decode(transaction_b64, validate=True)
        tx = VersionedTransaction.from_bytes(raw)
    except (binascii.Error, ValueError) as exc:
        raise _reject(f"{label} transaction could not be decoded: {exc}") from None
    if len(raw) > _PACKET_DATA_SIZE:
        raise _reject(f"{label} transaction is {len(raw)} bytes, over the {_PACKET_DATA_SIZE}-byte limit")
    return tx


def setup_form(transaction_b64: str, program_id: Pubkey = PROGRAM_ID) -> SetupForm:
    """Read which setup a client transaction performs from its single ``open`` or ``top_up``.

    The form is a property of the signed bytes, not of whether a channel
    record exists: a retried ``open`` whose first attempt landed stays an open.
    """
    message = _decode(transaction_b64, "setup").message
    keys = [str(key) for key in message.account_keys]
    forms: list[SetupForm] = []
    for ix in message.instructions:
        data = bytes(ix.data)
        if ix.program_id_index < len(keys) and keys[ix.program_id_index] == str(program_id) and data[:1]:
            forms.extend(form for form, disc in _DISCRIMINATORS.items() if data[0] == disc)
    if len(forms) != 1:
        raise _reject("transaction must contain exactly one open or top_up instruction")
    return forms[0]


def validate_setup(
    transaction_b64: str,
    form: SetupForm,
    expected: TransactionExpectations,
    *,
    deposit_amount: int,
    recent_slot: int | None,
) -> ValidatedTransaction:
    """Validate a client-signed ``open`` or ``top_up`` before the sponsor co-signs it.

    The instruction must fund exactly ``deposit_amount``. ``recent_slot``, when
    known, bounds an open's ``openSlot`` to the program's freshness window so a
    stale transaction is refused before the sponsor pays to learn it.
    """
    tx = _decode(transaction_b64, form)
    payer = _check_envelope(tx, expected, form)
    keys = [str(key) for key in tx.message.account_keys]
    ix = _scan_layout(keys, list(tx.message.instructions), expected, _DISCRIMINATORS[form], form, memo_required=True)
    accounts = list(bytes(ix.accounts))
    data = bytes(ix.data)
    if form == "open":
        _check_open_accounts(accounts, keys, payer, expected)
        _check_open_args(data, expected, deposit_amount, recent_slot)
        # Positions 2 (payee) and 4 (authorized_signer) are left out: message
        # compilation merges equal keys and unions their privileges, so they
        # are legitimately writable when they coincide with rent_payer / payer.
        writable = ((0, "payer"), (1, "rent_payer"), (5, "channel"), (6, "payer_token"), (7, "channel_token"))
    else:
        _check_top_up_accounts(accounts, keys, payer, expected)
        if len(data) != 9:
            raise _reject(f"top_up args must be exactly 9 bytes, got {len(data)}")
        amount = struct.unpack_from("<Q", data, 1)[0]
        if amount != deposit_amount:
            raise _reject(f"top_up amount {amount} does not match deposit.amount {deposit_amount}")
        # The sponsor is no account of a top-up: its signature covers the fee only.
        if any(keys[i] == expected.fee_payer for i in accounts):
            raise _reject("top_up instruction must not reference the fee payer")
        writable = ((0, "payer"), (1, "channel"), (2, "payer_token"), (3, "channel_token"))
    for position, role in writable:
        if not _is_writable(tx, accounts[position]):
            raise _reject(f"{form} {role} must be writable")
    return ValidatedTransaction(transaction=tx, payer=payer)


def validate_request_close(transaction_b64: str, expected: TransactionExpectations) -> ValidatedTransaction:
    """Validate a client-signed ``request_close`` refund before the sponsor co-signs it.

    Nothing may ride along: no ``seal``, ``settle_and_seal``, ``distribute``
    or token movement, since the sponsor's signature would authorize those too.
    Every failure is ``refund_transaction``.
    """
    try:
        tx = _decode(transaction_b64, "request_close")
        payer = _check_envelope(tx, expected, "request_close")
        keys = [str(key) for key in tx.message.account_keys]
        ix = _scan_layout(
            keys, list(tx.message.instructions), expected, _REQUEST_CLOSE, "request_close", memo_required=False
        )
        accounts = list(bytes(ix.accounts))
        if len(accounts) != 2:
            raise _reject(f"request_close must have exactly 2 accounts, got {len(accounts)}")
        _expect(accounts, keys, 0, payer, "payer", "request_close")
        _expect(accounts, keys, 1, expected.channel_id, "channel", "request_close")
        if len(bytes(ix.data)) != 1:
            raise _reject("request_close takes no arguments")
        if _is_writable(tx, accounts[0]) or not _is_writable(tx, accounts[1]):
            raise _reject("request_close payer must be read-only and the channel writable")
    except BatchSettlementError as exc:
        raise _reject(exc.detail, errors.INVALID_REFUND_TRANSACTION) from None
    return ValidatedTransaction(transaction=tx, payer=payer)


# -- envelope ------------------------------------------------------------------


def _check_envelope(tx: VersionedTransaction, expected: TransactionExpectations, label: str) -> str:
    """Check no lookup tables, sponsor fee payer, signers exactly {feePayer, payer}, a valid payer signature.

    Returns the channel payer.
    """
    message = tx.message
    # A lookup table resolves accounts this validator cannot see, so every
    # account guard below could pass while the real instruction touched
    # something else. Legacy messages have no lookups at all.
    if list(getattr(message, "address_table_lookups", [])):
        raise _reject(f"{label} transaction must not use address lookup tables")
    payer = expected.config["payer"]
    if payer == expected.fee_payer:
        raise _reject("channelConfig.payer must not equal extra.feePayer", errors.INVALID_FEE_PAYER_MISMATCH)
    keys = [str(key) for key in message.account_keys]
    if not keys or keys[0] != expected.fee_payer:
        raise _reject(f"{label} transaction fee payer must be {expected.fee_payer}")
    required = int(message.header.num_required_signatures)
    if required != 2:
        raise _reject(f"{label} transaction must require exactly 2 signatures, got {required}")
    if keys[1] != payer:
        raise _reject(f"{label} transaction second signer must be the channel payer {payer}")
    signatures = list(tx.signatures)
    if len(signatures) != required:
        raise _reject(f"{label} transaction has {len(signatures)} signature slots but requires {required}")
    # The sponsor fills only its own slot; co-signing a transaction the payer
    # never authorized would let anyone spend the payer's escrow.
    if not signatures[1].verify(Pubkey.from_string(payer), bytes(to_bytes_versioned(message))):
        raise _reject(f"{label} transaction is missing a valid channel-payer signature")
    return payer


def _is_writable(tx: VersionedTransaction, index: int) -> bool:
    """Whether static account ``index`` is writable, from the positional header layout."""
    header = tx.message.header
    signers = int(header.num_required_signatures)
    if index < signers:
        return index < signers - int(header.num_readonly_signed_accounts)
    return index < len(tx.message.account_keys) - int(header.num_readonly_unsigned_accounts)


# -- the top-level instruction allowlist -------------------------------------------


def _scan_layout(
    keys: list[str],
    instructions: list[CompiledInstruction],
    expected: TransactionExpectations,
    discriminator: int,
    label: str,
    *,
    memo_required: bool,
) -> CompiledInstruction:
    """Enforce ``[ComputeBudget prefix] + one channel instruction + [Memo/Lighthouse suffix]``; return that instruction.

    The prefix holds at most one ``SetComputeUnitLimit`` then at most one
    ``SetComputeUnitPrice``, each capped. The suffix holds at most three
    Lighthouse assertions and one Memo (required when ``memo_required``).
    No wrapper may name the fee payer.
    """

    def program_of(ix: CompiledInstruction) -> str:
        if ix.program_id_index >= len(keys):
            raise _reject(f"{label} instruction program id out of range")
        return keys[ix.program_id_index]

    def reject_fee_payer(ix: CompiledInstruction, wrapper: str) -> None:
        if any(i < len(keys) and keys[i] == expected.fee_payer for i in bytes(ix.accounts)):
            raise _reject(f"{wrapper} instruction must not reference the fee payer")

    index = 0
    seen_limit = seen_price = False
    while index < len(instructions) and program_of(instructions[index]) == COMPUTE_BUDGET_PROGRAM:
        ix = instructions[index]
        reject_fee_payer(ix, "ComputeBudget")
        data = bytes(ix.data)
        if data[:1] == bytes([COMPUTE_BUDGET_SET_UNIT_LIMIT]) and len(data) == 5:
            units = struct.unpack_from("<I", data, 1)[0]
            if seen_limit or seen_price:
                raise _reject(f"{label} SetComputeUnitLimit must appear once, before SetComputeUnitPrice")
            if units > OPEN_MAX_COMPUTE_UNIT_LIMIT:
                raise _reject(f"{label} compute unit limit {units} exceeds {OPEN_MAX_COMPUTE_UNIT_LIMIT}")
            seen_limit = True
        elif data[:1] == bytes([COMPUTE_BUDGET_SET_UNIT_PRICE]) and len(data) == 9:
            price = struct.unpack_from("<Q", data, 1)[0]
            if seen_price:
                raise _reject(f"{label} transaction has a duplicate SetComputeUnitPrice")
            if price > MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS:
                raise _reject(f"{label} compute unit price {price} exceeds {MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS}")
            seen_price = True
        else:
            raise _reject(f"{label} transaction has an unsupported ComputeBudget instruction")
        index += 1

    if index >= len(instructions):
        raise _reject(f"{label} transaction contains no payment-channels instruction")
    primary = instructions[index]
    if program_of(primary) != str(expected.program_id):
        raise _reject(f"{label} transaction targets an unexpected program")
    if bytes(primary.data)[:1] != bytes([discriminator]):
        raise _reject(f"{label} transaction is not a payment-channels {label} instruction")

    # Three Lighthouse plus one Memo is the whole suffix: the per-kind caps
    # already bound it to OPEN_MAX_OPTIONAL_SUFFIX instructions.
    lighthouse = memos = 0
    for ix in instructions[index + 1 :]:
        program = program_of(ix)
        if program == LIGHTHOUSE_PROGRAM:
            lighthouse += 1
            if lighthouse > OPEN_MAX_LIGHTHOUSE_INSTRUCTIONS:
                raise _reject(f"{label} transaction allows at most {OPEN_MAX_LIGHTHOUSE_INSTRUCTIONS} Lighthouse")
            reject_fee_payer(ix, "Lighthouse")
        elif program == MEMO_PROGRAM:
            memos += 1
            if memos > 1:
                raise _reject(f"{label} transaction allows at most one Memo instruction")
            reject_fee_payer(ix, "Memo")
            _check_memo(bytes(ix.data), expected.memo, label)
        else:
            raise _reject(f"{label} instruction after {label} must be Lighthouse or Memo, found {program}")
    if memo_required and memos == 0:
        raise _reject(f"{label} transaction must carry exactly one Memo instruction")
    return primary


def _check_memo(data: bytes, declared: str | None, label: str) -> None:
    """A Memo is the declared ``extra.memo`` verbatim, or else a hex nonce of at least 16 bytes."""
    if len(data) > OPEN_MAX_MEMO_BYTES:
        raise _reject(f"{label} memo is {len(data)} bytes, over the {OPEN_MAX_MEMO_BYTES}-byte maximum")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise _reject(f"{label} memo is not valid UTF-8") from None
    if declared is not None:
        if text != declared:
            raise _reject(f"{label} memo does not match the declared extra.memo")
    elif len(text) < _MIN_MEMO_NONCE_BYTES * 2 or not all(c in "0123456789abcdefABCDEF" for c in text):
        # A nonce correlates the transaction without letting it carry a payload
        # the sponsor never agreed to.
        raise _reject(f"{label} memo must be a hex nonce of at least {_MIN_MEMO_NONCE_BYTES} bytes")


# -- account tables and arguments ------------------------------------------------


def _expect(accounts: list[int], keys: list[str], position: int, want: str, role: str, label: str) -> None:
    got = keys[accounts[position]] if position < len(accounts) and accounts[position] < len(keys) else "<none>"
    if got != want:
        raise _reject(f"{label} {role} mismatch: expected {want}, got {got}")


def _atas(payer: str, expected: TransactionExpectations) -> tuple[str, str]:
    mint = Pubkey.from_string(expected.config["token"])
    program = Pubkey.from_string(expected.token_program)
    payer_token, _ = find_associated_token_address(Pubkey.from_string(payer), mint, program)
    channel_token, _ = find_associated_token_address(Pubkey.from_string(expected.channel_id), mint, program)
    return str(payer_token), str(channel_token)


def _check_open_accounts(accounts: list[int], keys: list[str], payer: str, expected: TransactionExpectations) -> None:
    if len(accounts) != 14:
        raise _reject(f"open must have exactly 14 accounts and no remaining accounts, got {len(accounts)}")
    payer_token, channel_token = _atas(payer, expected)
    program_id = expected.program_id
    table = (
        (payer, "payer"),
        # The sponsor holds both rent_payer and the zero-share payee seat: it can
        # seal and reclaim an abandoned channel, never advance its settled amount.
        (expected.fee_payer, "rent_payer"),
        (expected.fee_payer, "payee"),
        (expected.config["token"], "mint"),
        (expected.config["payerAuthorizer"], "authorized_signer"),
        (expected.channel_id, "channel"),
        (payer_token, "payer_token_account"),
        (channel_token, "channel_token_account"),
        (expected.token_program, "token_program"),
        (SYSTEM_PROGRAM, "system_program"),
        (_RENT_SYSVAR, "rent"),
        (ASSOCIATED_TOKEN_PROGRAM, "associated_token_program"),
        (str(find_event_authority_pda(program_id)[0]), "event_authority"),
        (str(program_id), "self_program"),
    )
    for position, (want, role) in enumerate(table):
        _expect(accounts, keys, position, want, role, "open")


def _check_top_up_accounts(accounts: list[int], keys: list[str], payer: str, expected: TransactionExpectations) -> None:
    if len(accounts) != 6:
        raise _reject(f"top_up must have exactly 6 accounts and no remaining accounts, got {len(accounts)}")
    payer_token, channel_token = _atas(payer, expected)
    table = (
        (payer, "payer"),
        (expected.channel_id, "channel"),
        (payer_token, "payer_token_account"),
        (channel_token, "channel_token_account"),
        (expected.config["token"], "mint"),
        (expected.token_program, "token_program"),
    )
    for position, (want, role) in enumerate(table):
        _expect(accounts, keys, position, want, role, "top_up")


def _check_open_args(
    data: bytes, expected: TransactionExpectations, deposit_amount: int, recent_slot: int | None
) -> None:
    # Exactly one recipient, so the length is fixed: a short read would leave
    # undecoded argument bytes, a long one trailing bytes the program may read.
    if len(data) != _OPEN_DATA_LEN:
        raise _reject(f"open args must be exactly {_OPEN_DATA_LEN} bytes for one recipient, got {len(data)}")
    salt, deposit, grace_period, open_slot, count = struct.unpack_from("<QQIQI", data, 1)
    config = expected.config
    if salt != int(config["salt"]):
        raise _reject(f"open salt {salt} does not match channelConfig.salt {config['salt']}")
    if deposit != deposit_amount:
        raise _reject(f"open deposit {deposit} does not match deposit.amount {deposit_amount}")
    if grace_period != config["withdrawDelay"]:
        raise _reject(
            f"open grace_period {grace_period} does not match withdrawDelay {config['withdrawDelay']}",
            errors.INVALID_WITHDRAW_DELAY_MISMATCH,
        )
    if open_slot != config["openSlot"]:
        raise _reject(f"open open_slot {open_slot} does not match channelConfig.openSlot {config['openSlot']}")
    recipient = str(Pubkey.from_bytes(data[_OPEN_ARGS_PREFIX + 4 : _OPEN_ARGS_PREFIX + 36]))
    bps = struct.unpack_from("<H", data, _OPEN_ARGS_PREFIX + 36)[0]
    # The split is committed at open and only re-checked at distribute: this is
    # the one moment the payout destination can be pinned to all of payTo.
    if count != 1 or recipient != expected.receiver or bps != _FULL_SHARE_BPS:
        raise _reject(f"open distribution must pay 100% to {expected.receiver}, got {count} entries")
    # The channel must be the PDA these exact args derive, not merely the
    # account the payload named.
    derived, _ = find_channel_pda(
        Pubkey.from_string(config["payer"]),
        Pubkey.from_string(expected.fee_payer),
        Pubkey.from_string(config["token"]),
        Pubkey.from_string(config["payerAuthorizer"]),
        salt,
        open_slot,
        expected.program_id,
    )
    if str(derived) != expected.channel_id:
        raise _reject(
            f"open channel {expected.channel_id} is not the PDA its args derive ({derived})",
            errors.INVALID_CHANNEL_ID_MISMATCH,
        )
    if recent_slot is not None:
        if open_slot > recent_slot:
            raise _reject(f"open open_slot {open_slot} is ahead of the current slot {recent_slot}")
        if recent_slot - open_slot > OPEN_SLOT_WINDOW:
            raise _reject(f"open open_slot {open_slot} is outside the {OPEN_SLOT_WINDOW}-slot window of {recent_slot}")
