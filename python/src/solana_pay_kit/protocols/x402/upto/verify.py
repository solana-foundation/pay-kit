"""Pure verification for the x402 ``upto`` payment-channel asset transfer method.

No I/O: these functions validate already-decoded structures and raise
:class:`~solana_pay_kit.errors.InvalidProofError` on rejection. They mirror the
Rust kit (``x402/protocol/schemes/upto/{types,verify}.rs`` for the payload,
``x402/server/upto.rs`` ``validate_open_instruction`` and
``core/payment_channel/v1.rs`` ``scan_channel_tx_layout`` for the open), check
for check and in the same order, and word their errors the same way so every
SDK refuses a tampered authorization for the same reason
(``specs/schemes/upto/scheme_upto_svm.md`` Phase 3 and its
“Client-supplied openTransaction acceptance policy”).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, cast

from solders.pubkey import Pubkey  # type: ignore[import-untyped]

from solana_pay_kit._paycore import txv1
from solana_pay_kit._paycore.paymentchannels import (
    COMPUTE_BUDGET_SET_UNIT_LIMIT,
    COMPUTE_BUDGET_SET_UNIT_PRICE,
    LIGHTHOUSE_PROGRAM,
    MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS,
    OPEN_MAX_COMPUTE_UNIT_LIMIT,
    OPEN_MAX_LIGHTHOUSE_INSTRUCTIONS,
    OPEN_MAX_MEMO_BYTES,
    OPEN_MAX_OPTIONAL_SUFFIX,
    OPEN_SLOT_WINDOW,
    Distribution,
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
from solana_pay_kit.errors import InvalidProofError
from solana_pay_kit.protocols.programs.paymentchannels.shared.borsh import Reader
from solana_pay_kit.protocols.programs.paymentchannels.types.open_args import OpenArgs
from solana_pay_kit.protocols.x402.upto.types import (
    UPTO_ERROR_SETTLEMENT_EXCEEDS_AMOUNT,
    UptoRequirements,
)

__all__ = [
    "DEFAULT_MAX_CHANNEL_LIFETIME_SECONDS",
    "ERR_CHANNEL_ALREADY_OPEN",
    "ERR_CHANNEL_LIFETIME_EXCEEDED",
    "ERR_EXPIRES_AT_MISMATCH",
    "ERR_PAYLOAD_TYPE",
    "ERR_UNEXPECTED_VOUCHER",
    "EXPIRES_AT_CLOCK_SKEW_SECONDS",
    "MIN_MEMO_NONCE_BYTES",
    "OPEN_SLOT_WINDOW",
    "ParsedUptoPayload",
    "assert_settlement_within_ceiling",
    "decimal_u64",
    "parse_base_units",
    "parse_upto_payload",
    "slot_from_value",
    "validate_upto_open_instruction",
    "verify_payer_signature",
    "verify_upto_payload",
]

#: A client payload carrying the claim-only, server-owned ``voucherSignature``.
ERR_UNEXPECTED_VOUCHER = "invalid_upto_svm_payload_unexpected_voucher"
#: A client payload carrying the per-settle ``type``.
ERR_PAYLOAD_TYPE = "invalid_upto_svm_payload_type"
#: ``maxTimeoutSeconds`` or ``expiresAt - now`` over ``maxChannelLifetimeSecs``.
ERR_CHANNEL_LIFETIME_EXCEEDED = "invalid_upto_svm_payload_channel_lifetime_exceeded"
#: ``expiresAt`` later than ``now + maxTimeoutSeconds`` plus clock skew.
ERR_EXPIRES_AT_MISMATCH = "invalid_upto_svm_payload_expires_at_mismatch"
#: An account already sits at the channel PDA (Phase 3 step 4).
ERR_CHANNEL_ALREADY_OPEN = "invalid_upto_svm_channel_already_open"

#: Skew allowed on ``expiresAt`` against ``now + maxTimeoutSeconds`` and
#: ``now + maxChannelLifetimeSecs`` (Phase 3 step 7 “plus clock skew”).
EXPIRES_AT_CLOCK_SKEW_SECONDS = 60
#: The reference facilitator's ``maxChannelLifetimeSecs``.
DEFAULT_MAX_CHANNEL_LIFETIME_SECONDS = 3600
#: Minimum random memo nonce, in bytes before hex encoding.
MIN_MEMO_NONCE_BYTES = 16

_U64_MAX = (1 << 64) - 1
_I64_MIN = -(1 << 63)
_I64_MAX = (1 << 63) - 1

# Payment-channels open instruction discriminator (single-byte form).
_OPEN_INSTRUCTION_DISCRIMINATOR = 1
_SET_LOADED_ACCOUNTS_DATA_SIZE_LIMIT = 4
# Rent sysvar id (position 10 of the open instruction account layout).
_RENT_SYSVAR_ID = "SysvarRent111111111111111111111111111111111"
# The canonical open (scheme_upto_svm.md “Canonical open instruction”).
_OPEN_ACCOUNT_COUNT = 14
_OPEN_WRITABLE_POSITIONS = (0, 1, 5, 6, 7)
_OPEN_SIGNER_POSITIONS = (0, 1)


def _invalid(message: str) -> InvalidProofError:
    return InvalidProofError(message, code="payment_invalid")


# -- scalar parsing -----------------------------------------------------------


def decimal_u64(value: Any) -> int | None:
    """A non-empty run of ASCII digits that fits in a u64, else ``None``."""
    if not isinstance(value, str) or not value or not value.isascii() or not value.isdigit():
        return None
    parsed = int(value, 10)
    return parsed if parsed <= _U64_MAX else None


def slot_from_value(value: Any) -> int | None:
    """A slot: a JSON integer or its decimal-string form (RULINGS U1)."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if 0 <= value <= _U64_MAX else None
    return decimal_u64(value)


def parse_base_units(value: Any, label: str) -> int:
    """Parse a base-10 u64 amount string, raising on malformed/out-of-range input."""
    parsed = decimal_u64(value)
    if parsed is None:
        raise _invalid(f"invalid upto {label}: {value}")
    return parsed


# -- payload ------------------------------------------------------------------


@dataclass(frozen=True)
class ParsedUptoPayload:
    """A client ``UptoPayload`` after the scheme's Phase 3 step 0 parse."""

    from_: str
    max_amount: str
    expires_at: int
    valid_after: int
    nonce: int
    channel_id: str
    deposit: str
    authorized_signer: str
    open_slot: int
    open_transaction: str | None


def _string_field(raw: dict[str, Any], key: str) -> str:
    if key not in raw:
        raise _invalid(f"invalid upto payload: missing field `{key}`")
    value = raw[key]
    if not isinstance(value, str):
        raise _invalid(f"invalid upto payload: {key} must be a string")
    return value


def _i64_field(raw: dict[str, Any], key: str) -> int:
    if key not in raw:
        raise _invalid(f"invalid upto payload: missing field `{key}`")
    value = raw[key]
    if isinstance(value, bool) or not isinstance(value, int) or not _I64_MIN <= value <= _I64_MAX:
        raise _invalid(f"invalid upto payload: {key} {value!r} is not an integer")
    return value


def parse_upto_payload(raw: Any) -> ParsedUptoPayload:
    """Parse ``PAYMENT-SIGNATURE.payload`` (``UptoPayload`` deserialization).

    Every field is required except ``openTransaction``; ``expiresAt`` and
    ``validAfter`` are integers, ``nonce`` a decimal u64 string and
    ``openSlot`` a u64 number or decimal string. A payload that carries the
    claim-only ``voucherSignature`` or the per-settle ``type`` (present at
    all, even empty or ``null``) is refused (Phase 3 step 0).
    """
    if not isinstance(raw, dict):
        raise _invalid("invalid upto payload: payload must be an object")
    payload = cast("dict[str, Any]", raw)
    from_ = _string_field(payload, "from")
    max_amount = _string_field(payload, "maxAmount")
    expires_at = _i64_field(payload, "expiresAt")
    valid_after = _i64_field(payload, "validAfter")
    if "nonce" not in payload:
        raise _invalid("invalid upto payload: missing field `nonce`")
    channel_id = _string_field(payload, "channelId")
    deposit = _string_field(payload, "deposit")
    authorized_signer = _string_field(payload, "authorizedSigner")
    if "openSlot" not in payload:
        raise _invalid("invalid upto payload: missing field `openSlot`")
    open_transaction = payload.get("openTransaction")
    if open_transaction is not None and not isinstance(open_transaction, str):
        raise _invalid("invalid upto payload: openTransaction must be a string")
    if "voucherSignature" in payload:
        raise _invalid(
            f"{ERR_UNEXPECTED_VOUCHER}: voucherSignature is claim-only and server-owned; "
            "a client payload must not carry it"
        )
    if "type" in payload:
        raise _invalid(
            f"{ERR_PAYLOAD_TYPE}: type is set per settle by the resource server; a client payload must not carry it"
        )
    nonce = decimal_u64(payload["nonce"])
    if nonce is None:
        raise _invalid(f"invalid payload: nonce {payload['nonce']!r} is not a decimal u64")
    open_slot = slot_from_value(payload["openSlot"])
    if open_slot is None:
        raise _invalid(f"invalid payload: openSlot {payload['openSlot']!r} is not a u64")
    return ParsedUptoPayload(
        from_=from_,
        max_amount=max_amount,
        expires_at=expires_at,
        valid_after=valid_after,
        nonce=nonce,
        channel_id=channel_id,
        deposit=deposit,
        authorized_signer=authorized_signer,
        open_slot=open_slot,
        open_transaction=open_transaction,
    )


def verify_upto_payload(
    payload: ParsedUptoPayload | Any,
    requirements: UptoRequirements,
    receiver_authorizer: str,
    now: int,
    *,
    max_channel_lifetime_seconds: int = DEFAULT_MAX_CHANNEL_LIFETIME_SECONDS,
) -> None:
    """Validate the client payload against the route-pinned requirement.

    Ordered checks: ``maxAmount`` equals the verification ceiling;
    ``deposit`` equals ``maxAmount``; ``validAfter <= now < expiresAt``; the
    channel lifetime and completion window (Phase 3 step 7); the
    ``authorizedSigner`` is the advertised receiver authorizer. A raw payload
    dict is parsed first (:func:`parse_upto_payload`).
    """
    parsed = payload if isinstance(payload, ParsedUptoPayload) else parse_upto_payload(payload)
    max_amount = parse_base_units(requirements["amount"], "amount")
    signed_max = parse_base_units(parsed.max_amount, "maxAmount")
    if signed_max != max_amount:
        raise _invalid(f"Amount mismatch: expected {max_amount}, got {signed_max}")

    deposit = parse_base_units(parsed.deposit, "deposit")
    if deposit != max_amount:
        raise _invalid(
            f"channel deposit {deposit} != authorized maximum {max_amount}: the deposit is the "
            "enforced ceiling and `topUp` can raise it, so it must equal the authorized amount exactly"
        )

    if now < parsed.valid_after:
        raise _invalid(f"authorization not yet active (validAfter {parsed.valid_after} > now {now})")
    if parsed.expires_at == 0 or now >= parsed.expires_at:
        raise _invalid(f"authorization expired (expiresAt {parsed.expires_at} < now {now})")

    _verify_lifetime(parsed, requirements, max_channel_lifetime_seconds, now)

    if parsed.authorized_signer != receiver_authorizer:
        raise _invalid("voucher authorized_signer must be the advertised receiver authorizer")


def _verify_lifetime(payload: ParsedUptoPayload, requirements: UptoRequirements, lifetime: int, now: int) -> None:
    """Phase 3 step 7: the channel cannot outlive ``maxChannelLifetimeSecs``,
    and ``expiresAt`` stays inside the challenge's completion window."""
    if lifetime <= 0:
        raise _invalid("maxChannelLifetimeSecs must be positive")
    timeout = int(requirements["maxTimeoutSeconds"])
    if timeout > lifetime:
        raise _invalid(
            f"{ERR_CHANNEL_LIFETIME_EXCEEDED}: maxTimeoutSeconds {timeout} exceeds maxChannelLifetimeSecs {lifetime}"
        )
    remaining = payload.expires_at - now
    if remaining > lifetime + EXPIRES_AT_CLOCK_SKEW_SECONDS:
        raise _invalid(
            f"{ERR_CHANNEL_LIFETIME_EXCEEDED}: expiresAt is {remaining}s away, over maxChannelLifetimeSecs {lifetime}"
        )
    if payload.expires_at > now + timeout + EXPIRES_AT_CLOCK_SKEW_SECONDS:
        raise _invalid(
            f"{ERR_EXPIRES_AT_MISMATCH}: expiresAt {payload.expires_at} is later than now + maxTimeoutSeconds "
            f"({timeout}) plus {EXPIRES_AT_CLOCK_SKEW_SECONDS}s skew"
        )


def assert_settlement_within_ceiling(actual: int, max_amount: int) -> None:
    """Enforce ``actual <= max`` at settlement; raise the canonical upto error otherwise."""
    if actual > max_amount:
        raise InvalidProofError(
            UPTO_ERROR_SETTLEMENT_EXCEEDS_AMOUNT,
            code=UPTO_ERROR_SETTLEMENT_EXCEEDS_AMOUNT,
        )


# -- open transaction -----------------------------------------------------------


def _memo_text(data: bytes, label: str) -> str:
    if len(data) > OPEN_MAX_MEMO_BYTES:
        raise _invalid(f"{label} transaction memo is {len(data)} bytes, over the {OPEN_MAX_MEMO_BYTES}-byte maximum")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _invalid(f"{label} transaction memo is not valid UTF-8") from exc


def _check_memo_data(data: bytes, label: str, expected: str | None) -> None:
    """A memo under a declared ``extra.memo``: exactly that text."""
    text = _memo_text(data, label)
    if expected is not None and text != expected:
        raise _invalid(f"{label} transaction memo does not match the declared extra.memo")


def scan_channel_tx_layout(
    tx: Any,
    keys: Sequence[Pubkey],
    program_id: Pubkey,
    discriminator: int,
    label: str,
    expected_memo: str | None,
) -> Any:
    """Enforce the sponsor's top-level instruction allowlist; return the open.

    An optional ComputeBudget prefix (at most one ``SetComputeUnitLimit`` then
    at most one ``SetComputeUnitPrice``, within the spec ceilings), exactly
    one payment-channels instruction with ``discriminator``, then a suffix of
    at most ``OPEN_MAX_LIGHTHOUSE_INSTRUCTIONS`` Lighthouse assertions plus
    Memos, capped at ``OPEN_MAX_OPTIONAL_SUFFIX`` instructions. No wrapper
    instruction may name the fee payer. A declared ``expected_memo`` admits
    exactly one Memo carrying it; without one any Memos are acceptable. The
    priority fee the sponsor pays is bounded last.
    """
    instructions = list(tx.message.instructions)
    if not keys:
        raise _invalid(f"{label} transaction has no fee payer")
    fee_payer = keys[0]

    def program_of(ix: Any) -> Pubkey:
        index = int(ix.program_id_index)
        if index >= len(keys):
            raise _invalid(f"{label} instruction program id out of range")
        return keys[index]

    def reject_fee_payer(ix: Any, wrapper: str) -> None:
        for raw in bytes(ix.accounts):
            if raw < len(keys) and keys[raw] == fee_payer:
                raise _invalid(f"{wrapper} instruction must not reference the fee payer")

    compute_budget = Pubkey.from_string(COMPUTE_BUDGET_PROGRAM)
    index = 0
    seen_limit = seen_price = False
    while index < len(instructions) and program_of(instructions[index]) == compute_budget:
        ix = instructions[index]
        reject_fee_payer(ix, "ComputeBudget")
        data = bytes(ix.data)
        tag = data[0] if data else None
        if tag == COMPUTE_BUDGET_SET_UNIT_LIMIT and len(data) == 5:
            if seen_limit:
                raise _invalid(f"{label} transaction has a duplicate SetComputeUnitLimit instruction")
            if seen_price:
                raise _invalid(f"{label} transaction SetComputeUnitLimit must precede SetComputeUnitPrice")
            units = int.from_bytes(data[1:5], "little")
            if units > OPEN_MAX_COMPUTE_UNIT_LIMIT:
                raise _invalid(
                    f"{label} transaction compute unit limit {units} exceeds maximum {OPEN_MAX_COMPUTE_UNIT_LIMIT}"
                )
            seen_limit = True
        elif tag == COMPUTE_BUDGET_SET_UNIT_PRICE and len(data) == 9:
            if seen_price:
                raise _invalid(f"{label} transaction has a duplicate SetComputeUnitPrice instruction")
            price = int.from_bytes(data[1:9], "little")
            if price > MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS:
                raise _invalid(
                    f"{label} transaction compute unit price {price} exceeds maximum "
                    f"{MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS}"
                )
            seen_price = True
        else:
            # SetLoadedAccountsDataSizeLimit, RequestHeapFrame and malformed
            # data are outside the accepted prefix.
            raise _invalid(f"{label} transaction has an unsupported ComputeBudget instruction")
        index += 1

    if index >= len(instructions):
        raise _invalid(f"{label} transaction contains no payment-channels instruction")
    primary = instructions[index]
    if program_of(primary) != program_id:
        raise _invalid(f"{label} transaction targets an unexpected program")
    primary_data = bytes(primary.data)
    if not primary_data or primary_data[0] != discriminator:
        raise _invalid(f"{label} transaction is not a payment-channels {label} instruction")
    index += 1

    memo_program = Pubkey.from_string(MEMO_PROGRAM)
    lighthouse = Pubkey.from_string(LIGHTHOUSE_PROGRAM)
    lighthouse_count = optional_count = memo_count = 0
    while index < len(instructions):
        ix = instructions[index]
        optional_count += 1
        if optional_count > OPEN_MAX_OPTIONAL_SUFFIX:
            raise _invalid(f"{label} transaction allows at most {OPEN_MAX_OPTIONAL_SUFFIX} instructions after {label}")
        program = program_of(ix)
        if program == lighthouse:
            lighthouse_count += 1
            if lighthouse_count > OPEN_MAX_LIGHTHOUSE_INSTRUCTIONS:
                raise _invalid(
                    f"{label} transaction allows at most {OPEN_MAX_LIGHTHOUSE_INSTRUCTIONS} "
                    f"Lighthouse instructions after {label}"
                )
            reject_fee_payer(ix, "Lighthouse")
        elif program == memo_program:
            reject_fee_payer(ix, "Memo")
            memo_count += 1
            # An unbound route may carry several Memos; a declared memo
            # admits exactly one.
            if expected_memo is not None:
                if memo_count > 1:
                    raise _invalid(f"{label} transaction allows at most one Memo instruction")
                _check_memo_data(bytes(ix.data), label, expected_memo)
        else:
            raise _invalid(f"{label} transaction instruction after {label} must be Lighthouse or Memo, found {program}")
        index += 1
    if memo_count == 0 and expected_memo is not None:
        raise _invalid(f"{label} transaction must carry exactly one Memo instruction")

    try:
        txv1.check_priority_fee(tx.message, txv1.MAX_SPONSORED_PRIORITY_FEE_LAMPORTS)
    except txv1.TransactionVersionError as exc:
        raise _invalid(f"{label} transaction compute unit price exceeds the sponsored fee maximum: {exc}") from exc
    return primary


def _check_open_privileges(
    tx: Any, keys: Sequence[Pubkey], indices: list[int], payer: Pubkey, fee_payer: Pubkey
) -> None:
    """The required signers are exactly ``{payload.from, extra.feePayer}``,
    the open's writable and signer roles carry their privileges, and no key
    outside the writable roles is writable anywhere in the message."""
    header = tx.message.header
    signed = int(header.num_required_signatures)
    readonly_signed = int(header.num_readonly_signed_accounts)
    readonly_unsigned = int(header.num_readonly_unsigned_accounts)
    if signed > len(keys) or readonly_signed > signed or readonly_unsigned > len(keys) - signed:
        raise _invalid("invalid open transaction header: signer counts exceed the account keys")

    def is_signer(i: int) -> bool:
        return i < signed

    def is_writable(i: int) -> bool:
        return i < signed - readonly_signed if i < signed else i < len(keys) - readonly_unsigned

    for key in keys[:signed]:
        if key not in (payer, fee_payer):
            raise _invalid(
                f"open requires an unexpected signer {key}: the required signers must be exactly "
                "payload.from and extra.feePayer"
            )
    for pos in _OPEN_SIGNER_POSITIONS:
        if not is_signer(indices[pos]):
            raise _invalid(f"open instruction account #{pos} must be a signer")
    for pos in _OPEN_WRITABLE_POSITIONS:
        if not is_writable(indices[pos]):
            raise _invalid(f"open instruction account #{pos} must be writable")
    writable_roles = {indices[pos] for pos in _OPEN_WRITABLE_POSITIONS}
    for i in range(len(keys)):
        if is_writable(i) and i not in writable_roles:
            raise _invalid(f"open instruction leaves {keys[i]} writable outside the open's writable roles")


def _decode_open_args(data: bytes) -> OpenArgs:
    """``[discriminator u8][OpenArgs]`` decoded whole: truncated or trailing
    bytes are refused."""
    if len(data) < 1:
        raise _invalid("open instruction data is empty")
    reader = Reader(data[1:])
    try:
        args = OpenArgs.deserialize_reader(reader)
    except Exception as exc:  # noqa: BLE001 - any decode failure is a malformed open
        raise _invalid(f"open instruction args are malformed: {exc}") from exc
    if reader.remaining:
        raise _invalid(f"open instruction args are malformed: {reader.remaining} trailing bytes")
    return args


def validate_upto_open_instruction(
    tx: Any,
    *,
    accepted_versions: Sequence[int],
    program_id: Pubkey,
    rent_payer: Pubkey,
    authorized_signer: Pubkey,
    payer: Pubkey,
    payee: Pubkey,
    mint: Pubkey,
    token_program: Pubkey,
    channel_id: Pubkey,
    max_amount: int,
    withdraw_delay: int,
    payload_nonce: int,
    payload_open_slot: int,
    recent_slot: int | None,
    expected_memo: str | None,
    expected_recipients: Sequence[Distribution],
) -> None:
    """Assert ``tx`` carries the expected channel ``open`` before co-signing.

    Envelope first (an accepted version, static accounts only, the version's
    size limit), then the version-1 header budget (``loadedAccountsDataSizeLimit``
    present), the top-level layout (:func:`scan_channel_tx_layout`), the 14
    canonical accounts and their privileges, and the fully decoded
    ``openArgs`` bound to the payload, the challenge and the derived channel
    PDA. ``recent_slot`` (the challenged slot at verify time) bounds
    ``openSlot`` to the program's freshness window when known.
    """
    try:
        txv1.check_envelope(tx, accepted_versions)
        txv1.check_v1_budget_caps(
            tx.message,
            OPEN_MAX_COMPUTE_UNIT_LIMIT,
            MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS,
            loaded_rule="present",
        )
        txv1.reject_v1_heap_request(tx.message)
    except txv1.TransactionVersionError as exc:
        raise _invalid(str(exc)) from exc

    keys = list(tx.message.account_keys)
    ix = scan_channel_tx_layout(tx, keys, program_id, _OPEN_INSTRUCTION_DISCRIMINATOR, "open", expected_memo)
    indices = list(bytes(ix.accounts))
    if len(indices) != _OPEN_ACCOUNT_COUNT:
        raise _invalid(
            f"open instruction has {len(indices)} accounts; it must have exactly {_OPEN_ACCOUNT_COUNT} "
            "and no remaining accounts"
        )

    def expect(pos: int, want: Pubkey, label: str) -> None:
        index = indices[pos]
        got = keys[index] if index < len(keys) else None
        if got != want:
            raise _invalid(
                f"open transaction {label} mismatch: expected {want}, got {got if got is not None else '<none>'}"
            )

    expect(0, payer, "payer")
    expect(1, rent_payer, "rent_payer")
    expect(2, payee, "payee")
    expect(3, mint, "mint")
    expect(4, authorized_signer, "authorized_signer")
    expect(5, channel_id, "channel")
    expect(6, find_associated_token_address(payer, mint, token_program)[0], "payer_token_account")
    expect(7, find_associated_token_address(channel_id, mint, token_program)[0], "channel_token_account")
    expect(8, token_program, "token_program")
    expect(9, Pubkey.from_string(SYSTEM_PROGRAM), "system_program")
    expect(10, Pubkey.from_string(_RENT_SYSVAR_ID), "rent_sysvar")
    expect(11, Pubkey.from_string(ASSOCIATED_TOKEN_PROGRAM), "associated_token_program")
    expect(12, find_event_authority_pda(program_id)[0], "event_authority")
    expect(13, program_id, "self_program")
    _check_open_privileges(tx, keys, indices, payer, rent_payer)

    args = _decode_open_args(bytes(ix.data))
    recipients = [
        Distribution(recipient=Pubkey.from_bytes(bytes(entry.recipient)), bps=entry.bps) for entry in args.recipients
    ]
    if recipients != list(expected_recipients):
        raise _invalid("open distribution does not match the expected recipient split")
    if payload_nonce != args.salt:
        raise _invalid(f"open salt {args.salt} does not match payload nonce {payload_nonce}")
    if payload_open_slot != args.open_slot:
        raise _invalid(f"open slot {args.open_slot} does not match payload openSlot {payload_open_slot}")
    if args.grace_period != withdraw_delay:
        raise _invalid(
            f"open withdraw delay {args.grace_period} must equal the advertised withdrawDelay {withdraw_delay}"
        )

    # Slot-addressed channel invariant: the channel account must be the PDA
    # actually derived with the args' salt + openSlot.
    derived, _ = find_channel_pda(payer, payee, mint, authorized_signer, args.salt, args.open_slot, program_id)
    if derived != channel_id:
        raise _invalid(f"open channel PDA {channel_id} != derived {derived}")
    if args.deposit != max_amount:
        raise _invalid(f"open deposit {args.deposit} must equal the authorized maximum {max_amount}")
    if recent_slot is not None:
        if args.open_slot > recent_slot:
            raise _invalid(f"open openSlot {args.open_slot} is ahead of the challenged recentSlot {recent_slot}")
        if recent_slot - args.open_slot > OPEN_SLOT_WINDOW:
            raise _invalid(
                f"open openSlot {args.open_slot} is outside the {OPEN_SLOT_WINDOW}-slot freshness window of the "
                f"challenged recentSlot {recent_slot}"
            )


def verify_payer_signature(tx: Any, payer: Pubkey) -> None:
    """The ``payload.from`` signature must be present and valid before the fee
    payer co-signs (“Message and signer rules”)."""
    keys = list(tx.message.account_keys)
    signed = int(tx.message.header.num_required_signatures)
    try:
        index = keys[:signed].index(payer)
    except ValueError as exc:
        raise _invalid("invalid payload: payload.from does not sign the open") from exc
    signatures = list(tx.signatures)
    if index >= len(signatures) or not signatures[index].verify(payer, txv1.signed_message_bytes(tx.message)):
        raise _invalid("invalid payload: the payload.from signature on the open is missing or invalid")
