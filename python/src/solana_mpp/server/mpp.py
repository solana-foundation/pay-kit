"""Main server-side Solana charge handler."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import logging
from dataclasses import dataclass, field
from typing import Any

from solana_mpp._base64url import encode_json
from solana_mpp._errors import (
    ChallengeExpiredError,
    ChallengeMismatchError,
    PaymentError,
    ReplayError,
)
from solana_mpp._types import PaymentChallenge, PaymentCredential, Receipt
from solana_mpp.protocol.intents import ChargeRequest, parse_units
from solana_mpp.protocol.solana import (
    ASSOCIATED_TOKEN_PROGRAM,
    MEMO_PROGRAM,
    TOKEN_2022_PROGRAM,
    TOKEN_PROGRAM,
    CredentialPayload,
    MethodDetails,
    default_rpc_url,
    default_token_program_for_currency,
    is_native_sol,
    resolve_mint,
    stablecoin_symbol,
)
from solana_mpp.server.network_check import check_network_blockhash
from solana_mpp.store import Store

logger = logging.getLogger(__name__)

_DEFAULT_REALM = "MPP Payment"
_SECRET_KEY_ENV_VAR = "MPP_SECRET_KEY"
_CONSUMED_PREFIX = "solana-charge:consumed:"
_SYSTEM_PROGRAM = "11111111111111111111111111111111"
_SYSTEM_TRANSFER_INSTRUCTION = 2
_TOKEN_TRANSFER_CHECKED_INSTRUCTION = 12

# Compute-budget program allowlist caps. These must stay in sync with the
# canonical Rust reference at ``rust/src/server/charge.rs`` constants
# ``MAX_COMPUTE_UNIT_LIMIT`` and ``MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS``,
# and the mirrored caps on Ruby, PHP, Lua, Go server SDKs. A challenge
# carrying a SetComputeUnitLimit / SetComputeUnitPrice instruction over
# these caps is rejected before broadcast so the payer cannot drain the
# fee payer with an unbounded priority fee.
_COMPUTE_BUDGET_PROGRAM = "ComputeBudget111111111111111111111111111111"
_COMPUTE_BUDGET_SET_LIMIT_DISCRIMINATOR = 2
_COMPUTE_BUDGET_SET_PRICE_DISCRIMINATOR = 3
MAX_COMPUTE_UNIT_LIMIT = 200_000
MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS = 5_000_000

# Maximum number of additional split recipients on a single charge.
# Matches Rust ``splits.len() > 8`` guard in
# ``rust/src/server/charge.rs::verify_versioned_transaction_pre_broadcast``
# and the equivalent ``count($splits) > 8`` / ``splits.length > 8`` guards
# in PHP and Ruby. A high split count balloons the transaction size and
# the per-recipient ATA verification cost, so we reject early at the
# pre-broadcast stage.
MAX_SPLITS = 8

# Legacy Solana memo program (v1). MPP charge transactions MUST use memo v2
# (``MEMO_PROGRAM`` from :mod:`solana_mpp.protocol.solana`). v1 had a different
# instruction shape and is rejected to match the L2 lock landed on PHP fde0efb
# and mirrored in Ruby, Rust, Lua.
_MEMO_V1_PROGRAM = "Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo"


def _build_expected_transfers(request: ChargeRequest, details: MethodDetails) -> list[tuple[str, int]]:
    # Reject over-bound splits up-front. Mirrors the Rust pre-broadcast
    # guard at ``rust/src/server/charge.rs::verify_versioned_transaction_pre_broadcast``
    # (``splits.len() > 8``) and the equivalent PHP / Ruby guards. A
    # high split count balloons transaction size and per-recipient ATA
    # verification cost, so we surface the limit + observed count in
    # the error so the client can repair the challenge.
    if len(details.splits) > MAX_SPLITS:
        raise PaymentError(
            f"too many splits: {len(details.splits)} exceeds limit {MAX_SPLITS}",
            code="too-many-splits",
        )

    total_amount = int(request.amount)
    split_total = sum(int(split.amount) for split in details.splits)
    primary_amount = total_amount - split_total
    if primary_amount <= 0:
        raise PaymentError(
            "splits consume the entire amount — primary recipient must receive a positive amount",
            code="splits-exceed-amount",
        )

    expected = [(request.recipient, primary_amount)]
    for split in details.splits:
        expected.append((split.recipient, int(split.amount)))
    return expected


def _verify_parsed_sol_transfers(
    instructions: list[dict[str, Any]],
    request: ChargeRequest,
    details: MethodDetails,
) -> None:
    expected = _build_expected_transfers(request, details)
    transfers = [
        instruction
        for instruction in instructions
        if instruction.get("program") == "system" and (instruction.get("parsed") or {}).get("type") == "transfer"
    ]

    for recipient, amount in expected:
        match_index = next(
            (
                index
                for index, transfer in enumerate(transfers)
                if ((transfer.get("parsed") or {}).get("info") or {}).get("destination") == recipient
                and str(((transfer.get("parsed") or {}).get("info") or {}).get("lamports")) == str(amount)
            ),
            -1,
        )
        if match_index == -1:
            raise PaymentError(f"no matching SOL transfer for {recipient}", code="no-transfer")
        transfers.pop(match_index)


def _verify_parsed_spl_transfers(
    instructions: list[dict[str, Any]],
    request: ChargeRequest,
    details: MethodDetails,
) -> None:
    expected = _build_expected_transfers(request, details)
    program_id = details.token_program or default_token_program_for_currency(request.currency, details.network)
    mint = resolve_mint(request.currency, details.network)
    transfers = [
        instruction
        for instruction in instructions
        if instruction.get("programId") == program_id
        and (instruction.get("parsed") or {}).get("type") == "transferChecked"
    ]

    for recipient, amount in expected:
        match_index = next(
            (
                index
                for index, transfer in enumerate(transfers)
                if ((transfer.get("parsed") or {}).get("info") or {}).get("mint") == mint
                and str((((transfer.get("parsed") or {}).get("info") or {}).get("tokenAmount") or {}).get("amount"))
                == str(amount)
                and _verify_ata_owner(
                    ((transfer.get("parsed") or {}).get("info") or {}).get("destination", ""),
                    recipient,
                    mint,
                    program_id,
                )
            ),
            -1,
        )
        if match_index == -1:
            raise PaymentError(f"no matching token transfer for {recipient}", code="no-transfer")
        transfers.pop(match_index)


def _verify_ata_owner(ata_address: str, expected_owner: str, mint: str, token_program: str) -> bool:
    """Verify that an ATA address belongs to the expected owner by deriving it."""
    try:
        from solders.pubkey import Pubkey

        owner_pk = Pubkey.from_string(expected_owner)
        mint_pk = Pubkey.from_string(mint)
        tp_pk = Pubkey.from_string(token_program)
        ata_program = Pubkey.from_string(ASSOCIATED_TOKEN_PROGRAM)
        expected_ata, _bump = Pubkey.find_program_address(
            [bytes(owner_pk), bytes(tp_pk), bytes(mint_pk)],
            ata_program,
        )
        return str(expected_ata) == ata_address
    except Exception:
        return False


def _parsed_program_id(instruction: dict[str, Any]) -> str:
    program_id = instruction.get("programId") or instruction.get("program_id")
    if isinstance(program_id, str):
        return program_id
    if instruction.get("program") == "spl-memo":
        return MEMO_PROGRAM
    return ""


def _parsed_memo_text(instruction: dict[str, Any]) -> str | None:
    parsed = instruction.get("parsed")
    if isinstance(parsed, str):
        return parsed
    if isinstance(parsed, dict):
        info = parsed.get("info")
        if isinstance(info, dict):
            memo = info.get("memo")
            if isinstance(memo, str):
                return memo
            data = info.get("data")
            if isinstance(data, str):
                return data
    return None


def _expected_memos(request: ChargeRequest, details: MethodDetails) -> list[tuple[str, str]]:
    expected: list[tuple[str, str]] = []
    if request.external_id:
        expected.append(("externalId", request.external_id))
    for split in details.splits:
        if split.memo:
            expected.append(("split", split.memo))
    return expected


def _verify_parsed_memo_instructions(
    instructions: list[dict[str, Any]],
    request: ChargeRequest,
    details: MethodDetails,
) -> None:
    matched: set[int] = set()
    for label, memo in _expected_memos(request, details):
        if len(memo.encode("utf-8")) > 566:
            raise PaymentError("memo cannot exceed 566 bytes", code="invalid-payload")

        match_index = next(
            (
                index
                for index, instruction in enumerate(instructions)
                if index not in matched
                and _parsed_program_id(instruction) == MEMO_PROGRAM
                and _parsed_memo_text(instruction) == memo
            ),
            -1,
        )
        if match_index == -1:
            raise PaymentError(f'No memo instruction found for {label} memo "{memo}"', code="invalid-payload")
        matched.add(match_index)

    for index, instruction in enumerate(instructions):
        program_id = _parsed_program_id(instruction)
        if index not in matched and program_id == MEMO_PROGRAM:
            raise PaymentError("unexpected Memo Program instruction in payment transaction", code="invalid-payload")
        # L2 lock parity with the pull-mode pre-broadcast decoder
        # (_decode_legacy_payment_instructions). Push-mode signature
        # credentials reach this verifier without going through
        # _decode_legacy_payment_instructions; without an explicit Memo
        # v1 program-id check here, a confirmed on-chain transaction
        # carrying a Memo v1 instruction would slip past the v2-only
        # matcher above, leaving the L2 guard partial. Reject the
        # credential so push-mode matches pull-mode behaviour.
        if program_id == _MEMO_V1_PROGRAM:
            raise PaymentError(
                "memo v1 program is not supported (use Memo v2)",
                code="invalid-payload",
            )


def _rpc_value(response: Any) -> Any:
    if response is None:
        return None
    if isinstance(response, dict):
        return response.get("value", response)
    return getattr(response, "value", response)


def _json_like(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, dict):
        return {k: _json_like(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_json_like(item) for item in value]
    if hasattr(value, "to_json"):
        return json.loads(value.to_json())
    if hasattr(value, "__dict__"):
        return {key: _json_like(val) for key, val in vars(value).items()}
    return value


def _transaction_dict(response: Any) -> dict[str, Any] | None:
    value = _rpc_value(response)
    if value is None:
        return None
    data = _json_like(value)
    if isinstance(data, dict) and "transaction" in data:
        return data
    return None


def _status_ok(response: Any) -> bool:
    value = _rpc_value(response)
    data = _json_like(value)
    if isinstance(data, list):
        return any(entry and entry.get("err") is None for entry in data)
    return data is not None


def _extract_recent_blockhash(transaction_b64: str) -> str:
    """Decode a base64 transaction and return its recent blockhash (base58).

    Tries the legacy ``Transaction`` first (the most common shape from our
    SDK clients) and falls back to ``VersionedTransaction``. Kept thin so
    the surrounding network check can be exercised by tests without a full
    verification pipeline in place.
    """
    import base64

    from solders.transaction import Transaction, VersionedTransaction

    raw = base64.b64decode(transaction_b64)
    try:
        tx = Transaction.from_bytes(raw)
        return str(tx.message.recent_blockhash)
    except Exception:
        vtx = VersionedTransaction.from_bytes(raw)
        return str(vtx.message.recent_blockhash)


def _validate_compute_budget_instruction(data: bytes, account_count: int) -> None:
    """Validate a single ComputeBudget program instruction.

    Mirrors ``validate_compute_budget_instruction`` in
    ``rust/src/server/charge.rs``: SetComputeUnitLimit (discriminator 2,
    u32 LE units in ``data[1..5]``) and SetComputeUnitPrice (discriminator
    3, u64 LE microlamports in ``data[1..9]``) are the only accepted
    shapes, both must carry zero account references, and each value is
    capped at the per-instruction maximum. Anything else is rejected as
    an invalid payload to keep the on-wire allowlist tight.
    """
    if account_count != 0:
        raise PaymentError(
            "compute budget instruction must not have accounts",
            code="compute-budget-invalid",
        )
    if not data:
        raise PaymentError(
            "compute budget instruction has empty data",
            code="compute-budget-invalid",
        )
    discriminator = data[0]
    if discriminator == _COMPUTE_BUDGET_SET_LIMIT_DISCRIMINATOR and len(data) == 5:
        units = int.from_bytes(data[1:5], "little")
        if units > MAX_COMPUTE_UNIT_LIMIT:
            raise PaymentError(
                f"compute unit limit {units} exceeds cap {MAX_COMPUTE_UNIT_LIMIT}",
                code="compute-budget-cap-exceeded",
            )
        return
    if discriminator == _COMPUTE_BUDGET_SET_PRICE_DISCRIMINATOR and len(data) == 9:
        price = int.from_bytes(data[1:9], "little")
        if price > MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS:
            raise PaymentError(
                f"compute unit price {price} exceeds cap {MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS}",
                code="compute-budget-cap-exceeded",
            )
        return
    raise PaymentError(
        "unsupported compute budget instruction",
        code="compute-budget-invalid",
    )


def _is_v0_wire_bytes(raw: bytes) -> bool:
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


def _decode_legacy_payment_instructions(transaction_b64: str) -> list[dict[str, Any]]:
    """Decode local transfer and memo instructions from a legacy or v0 transaction.

    Accepts both legacy ``Transaction`` and ``VersionedTransaction``. For v0
    we only inspect the static account keys; address lookup tables are
    rejected up-front (a v0 tx with a non-empty ALT list would let an
    instruction reference accounts the verifier cannot see). Mirrors the
    Rust spine's ``verify_versioned_transaction_pre_broadcast`` policy.
    """
    from solders.transaction import Transaction, VersionedTransaction

    raw = base64.b64decode(transaction_b64)
    message: Any = None
    message_instructions: list[Any] = []
    # Route v0 wire bytes straight to VersionedTransaction; the legacy
    # parser in solders is lenient and can mis-parse a signed v0 tx as a
    # degenerate legacy tx with bogus instructions (see _is_v0_wire_bytes).
    parsed = False
    if _is_v0_wire_bytes(raw):
        try:
            vtx = VersionedTransaction.from_bytes(raw)
        except Exception:
            vtx = None
        if vtx is not None:
            lookups = getattr(vtx.message, "address_table_lookups", None)
            if lookups:
                raise PaymentError(
                    "v0 transactions with address lookup tables are not supported",
                    code="invalid-payload",
                ) from None
            message = vtx.message
            message_instructions = list(vtx.message.instructions)
            parsed = True
    if not parsed:
        try:
            tx = Transaction.from_bytes(raw)
            message = tx.message
            message_instructions = list(tx.message.instructions)
        except Exception:
            try:
                vtx = VersionedTransaction.from_bytes(raw)
            except Exception as exc:
                raise PaymentError(
                    "unsupported transaction shape for pre-broadcast verification",
                    code="invalid-payload-type",
                ) from exc
            # Reject v0 transactions that reference address lookup tables; the
            # pre-broadcast verifier only sees static account keys.
            lookups = getattr(vtx.message, "address_table_lookups", None)
            if lookups:
                raise PaymentError(
                    "v0 transactions with address lookup tables are not supported",
                    code="invalid-payload",
                ) from None
            message = vtx.message
            message_instructions = list(vtx.message.instructions)

    account_keys = [str(key) for key in message.account_keys]
    instructions: list[dict[str, Any]] = []
    for instruction in message_instructions:
        try:
            program_id = account_keys[int(instruction.program_id_index)]
        except IndexError as exc:
            raise PaymentError("transaction instruction references an unknown program", code="invalid-payload") from exc
        data = bytes(instruction.data)
        if program_id == _SYSTEM_PROGRAM:
            if len(data) < 12:
                continue
            kind = int.from_bytes(data[:4], "little")
            if kind != _SYSTEM_TRANSFER_INSTRUCTION or len(instruction.accounts) < 2:
                continue
            try:
                destination = account_keys[int(instruction.accounts[1])]
            except IndexError as exc:
                raise PaymentError(
                    "transaction transfer references an unknown account", code="invalid-payload"
                ) from exc
            lamports = int.from_bytes(data[4:12], "little")
            instructions.append(
                {
                    "program": "system",
                    "parsed": {
                        "type": "transfer",
                        "info": {
                            "destination": destination,
                            "lamports": str(lamports),
                        },
                    },
                }
            )
        elif program_id in {TOKEN_PROGRAM, TOKEN_2022_PROGRAM}:
            if len(data) < 10:
                continue
            kind = data[0]
            if kind != _TOKEN_TRANSFER_CHECKED_INSTRUCTION or len(instruction.accounts) < 3:
                continue
            try:
                mint = account_keys[int(instruction.accounts[1])]
                destination = account_keys[int(instruction.accounts[2])]
            except IndexError as exc:
                raise PaymentError(
                    "transaction token transfer references an unknown account", code="invalid-payload"
                ) from exc
            amount = int.from_bytes(data[1:9], "little")
            instructions.append(
                {
                    "programId": program_id,
                    "parsed": {
                        "type": "transferChecked",
                        "info": {
                            "destination": destination,
                            "mint": mint,
                            "tokenAmount": {"amount": str(amount)},
                        },
                    },
                }
            )
        elif program_id == MEMO_PROGRAM:
            try:
                memo = data.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise PaymentError("memo instruction is not valid UTF-8", code="invalid-payload") from exc
            instructions.append({"programId": MEMO_PROGRAM, "parsed": memo})
        elif program_id == _COMPUTE_BUDGET_PROGRAM:
            # Validate compute-budget instructions inline so an over-cap
            # SetComputeUnitLimit / SetComputeUnitPrice is rejected with a
            # structured error before broadcast. The instruction itself
            # carries no transfer semantics, so we do not append it to
            # the parsed instruction list consumed downstream.
            _validate_compute_budget_instruction(data, len(instruction.accounts))
        elif program_id == _MEMO_V1_PROGRAM:
            # L2 lock: MPP charge requires memo v2. Memo v1 has a different
            # instruction shape (UTF-8 directly in data with no signer check)
            # and would let a tampered transaction slip past the v2-only
            # ``_verify_parsed_memo_instructions`` matcher.
            raise PaymentError(
                "memo v1 program is not supported (use Memo v2)",
                code="invalid-payload",
            )

    return instructions


def _co_sign_with_fee_payer(transaction_b64: str, fee_payer: Any) -> str:
    """Co-sign a client transaction with the server's fee payer keypair.

    The fee payer occupies the first signer slot in Solana transactions. We
    serialize the message in the correct shape for its version (legacy uses
    ``bytes(msg)``; v0 uses ``to_bytes_versioned(msg)`` which prepends the
    ``0x80`` version tag), sign with the fee-payer private key, and splice
    the resulting signature into the signature array at the slot matching
    the fee-payer pubkey.

    Mirrors the cosign step in rust/src/server/charge.rs verify_pull.
    """
    from solders.message import to_bytes_versioned
    from solders.transaction import Transaction, VersionedTransaction

    raw = base64.b64decode(transaction_b64)
    fee_payer_pubkey = fee_payer.pubkey()

    # Try legacy transaction first (the common path); fall back to versioned.
    try:
        tx = Transaction.from_bytes(raw)
    except Exception:
        try:
            vtx = VersionedTransaction.from_bytes(raw)
        except Exception as exc:
            raise PaymentError(
                f"could not decode transaction for fee payer co-sign: {exc}",
                code="invalid-payload-type",
            ) from exc
        account_keys = list(vtx.message.account_keys)
        try:
            idx = account_keys.index(fee_payer_pubkey)
        except ValueError as exc:
            raise PaymentError(
                "fee payer pubkey not present in transaction accounts",
                code="invalid-payload",
            ) from exc
        num_required = int(vtx.message.header.num_required_signatures)
        _assert_signature_slot(idx, num_required)
        # v0 messages are signed over ``to_bytes_versioned(msg)`` which
        # prepends the 0x80 version byte.
        message_bytes = bytes(to_bytes_versioned(vtx.message))
        sig_bytes = bytes(fee_payer.sign_message(message_bytes))
        # Manual splice in the on-wire bytes preserves the rest of the
        # transaction exactly. Wire format: [num_sigs (compact-u16)] [sigs]
        # [message...]. num_sigs < 128 so it is a 1-byte prefix.
        serialized = bytearray(raw)
        sig_start = 1 + idx * 64
        serialized[sig_start : sig_start + 64] = sig_bytes
        return base64.b64encode(bytes(serialized)).decode("ascii")

    account_keys = list(tx.message.account_keys)
    try:
        idx = account_keys.index(fee_payer_pubkey)
    except ValueError as exc:
        raise PaymentError(
            "fee payer pubkey not present in transaction accounts",
            code="invalid-payload",
        ) from exc
    num_required = int(tx.message.header.num_required_signatures)
    _assert_signature_slot(idx, num_required)

    # Legacy Transaction: sign ``bytes(msg)`` directly.
    message_bytes = bytes(tx.message)
    sig_bytes = bytes(fee_payer.sign_message(message_bytes))
    serialized = bytearray(raw)
    sig_start = 1 + idx * 64
    serialized[sig_start : sig_start + 64] = sig_bytes
    return base64.b64encode(bytes(serialized)).decode("ascii")


def _assert_signature_slot(idx: int, num_required: int) -> None:
    """Validate that the fee payer occupies the canonical slot 0.

    The Solana protocol requires the fee payer to be ``account_keys[0]``:
    the runtime debits the first required signer for transaction fees. If
    we accepted a fee-payer pubkey at any slot inside the required-signers
    block, a client could craft a transaction that includes a benign
    payment transfer plus an extra instruction that *also* needs the
    server's key as a required signer (for example, at slot 1). The
    pre-broadcast decoder would still accept the transfer half, and the
    server would happily produce its signature, letting the client
    co-opt the server's private key to authorize arbitrary on-chain
    intents. Enforcing ``idx == 0`` matches the Rust spine's
    ``expected_fee_payer`` invariant (``account_keys.first() == fee_payer``)
    and closes that escalation path before any sign call is made.
    """
    if idx < 0 or idx >= num_required:
        raise PaymentError(
            f"fee payer pubkey at account index {idx} is outside the "
            f"required-signers block (num_required_signatures={num_required}); "
            "a client must place the fee payer inside the signer header",
            code="invalid-payload",
        )
    if idx != 0:
        raise PaymentError(
            "fee payer pubkey must occupy account index 0 (the transaction "
            f"fee-payer slot); found at index {idx}. The Solana runtime "
            "always debits the first required signer for fees, so any other "
            "placement would cause the server's key to sign for an "
            "instruction outside the fee-payment role.",
            code="invalid-payload",
        )


def _expected_ata_creation_policy(
    details: MethodDetails,
    fee_payer_pubkey: str | None,
) -> tuple[set[str], set[str]]:
    """Return ``(allowed_ata_owners, required_ata_owners)`` per Rust spine.

    Mirrors ``expected_ata_creation_policy`` in
    ``rust/src/server/charge.rs``:

    - ``required_ata_owners`` is the set of split recipients with
      ``ataCreationRequired=true``.
    - ``allowed_ata_owners`` is ``required_ata_owners`` when the route
      advertises ``feePayer=true`` (the server only sponsors ATA creates
      that the route explicitly demanded), and the set of every split
      recipient when no fee-payer co-sign is in play (client pays its
      own ATA rent so it may opportunistically create ATAs for any
      declared split).

    The primary recipient is NEVER in ``allowed_ata_owners``. Including
    it would let a sponsored route co-sign an ATA create for the top-level
    recipient even though no split asked for it, spending fee-payer SOL
    on rent the route did not authorize.
    """
    required_owners: set[str] = set()
    split_owners: set[str] = set()
    for split in details.splits:
        split_owners.add(split.recipient)
        if split.ata_creation_required:
            required_owners.add(split.recipient)

    allowed_owners = set(required_owners) if fee_payer_pubkey is not None else split_owners
    return allowed_owners, required_owners


def _validate_ata_create_idempotent(
    instruction: Any,
    account_keys: list[str],
    expected_mint: str | None,
    allowed_ata_owners: set[str],
    expected_token_program: str | None,
    expected_payer: str,
) -> None:
    """Validate an AssociatedTokenAccount create-idempotent instruction.

    Mirrors ``validate_create_ata_idempotent_instruction`` in
    ``rust/src/server/charge.rs``. The only ATA program instruction the
    fee-payer co-sign path may include is the idempotent create variant
    (discriminator byte ``0x01``) and only for an ATA whose payer is the
    transaction fee payer, whose owner is a recipient declared by the
    charge, whose mint matches the challenge currency, and whose token
    program is the one the challenge selected. Any deviation is rejected
    so an attacker cannot trick the server into co-signing an ATA create
    that funds an attacker-controlled mint or owner with fee-payer SOL.
    """
    if expected_mint is None:
        raise PaymentError(
            "ATA creation is not allowed for native SOL payments",
            code="invalid-payload",
        )
    data = bytes(instruction.data)
    if data != b"\x01":
        raise PaymentError(
            "only idempotent ATA creation is allowed",
            code="invalid-payload",
        )
    accounts = list(instruction.accounts)
    if len(accounts) != 6:
        raise PaymentError(
            "unexpected ATA creation account layout",
            code="invalid-payload",
        )
    try:
        payer = account_keys[int(accounts[0])]
        ata = account_keys[int(accounts[1])]
        owner = account_keys[int(accounts[2])]
        mint = account_keys[int(accounts[3])]
        sys_program = account_keys[int(accounts[4])]
        token_program = account_keys[int(accounts[5])]
    except IndexError as exc:
        raise PaymentError(
            "ATA creation references an unknown account index",
            code="invalid-payload",
        ) from exc

    if payer != expected_payer:
        raise PaymentError(
            "ATA payer must match the transaction fee payer",
            code="invalid-payload",
        )
    if mint != expected_mint:
        raise PaymentError(
            "ATA creation mint does not match the charge currency",
            code="invalid-payload",
        )
    if owner not in allowed_ata_owners:
        raise PaymentError(
            "ATA creation owner is not authorized by the challenge",
            code="invalid-payload",
        )
    if sys_program != _SYSTEM_PROGRAM:
        raise PaymentError(
            "ATA creation must reference the System Program",
            code="invalid-payload",
        )
    if token_program not in {TOKEN_PROGRAM, TOKEN_2022_PROGRAM}:
        raise PaymentError(
            "ATA creation uses an unsupported token program",
            code="invalid-payload",
        )
    if expected_token_program is not None and token_program != expected_token_program:
        raise PaymentError(
            "ATA creation token program does not match methodDetails.tokenProgram",
            code="invalid-payload",
        )
    # Verify the derived ATA matches owner/mint/token_program so a caller
    # cannot funnel the create to an attacker-controlled address.
    try:
        from solders.pubkey import Pubkey

        owner_pk = Pubkey.from_string(owner)
        mint_pk = Pubkey.from_string(mint)
        tp_pk = Pubkey.from_string(token_program)
        ata_program = Pubkey.from_string(ASSOCIATED_TOKEN_PROGRAM)
        derived, _ = Pubkey.find_program_address(
            [bytes(owner_pk), bytes(tp_pk), bytes(mint_pk)],
            ata_program,
        )
        if str(derived) != ata:
            raise PaymentError(
                "ATA creation address does not match owner/mint/token program",
                code="invalid-payload",
            )
    except PaymentError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise PaymentError(
            f"could not validate ATA creation address: {exc}",
            code="invalid-payload",
        ) from exc


def _validate_instruction_allowlist(
    transaction_b64: str,
    request: ChargeRequest,
    details: MethodDetails,
    expected_fee_payer_pubkey: str | None = None,
) -> None:
    """Reject any instruction not on the strict fee-payer co-sign allowlist.

    SECURITY: this is the no-leftovers check that protects the server's
    fee-payer keypair from being co-opted into signing attacker-supplied
    transfers. The lossy parsed-instruction verifier
    (``_verify_parsed_sol_transfers`` /
    ``_verify_parsed_spl_transfers`` / ``_verify_parsed_memo_instructions``)
    only checks that the required transfers / memos are present; it does
    not reject extra instructions. Without this allowlist a malicious
    client could include the expected payment plus a System Program
    transfer from the fee payer to the attacker, and the server would
    co-sign the entire transaction.

    The allowlist mirrors ``validate_instruction_allowlist`` in
    ``rust/src/server/charge.rs``: only ComputeBudget (validated),
    Memo v2 (must match an expected memo), System Program transfer (must
    match an expected payment transfer), SPL Token / Token-2022
    transferChecked (must match an expected payment transfer), and
    AssociatedTokenAccount create-idempotent (validated) are accepted.
    Anything else (including SOL transfers that do not match a required
    transfer, SPL transfers to unrelated mints, raw token approve /
    burn, BPF program calls, sysvar reads, etc.) is rejected before
    broadcast with a ``payment-invalid`` canonical code.
    """
    from solders.transaction import Transaction, VersionedTransaction

    raw = base64.b64decode(transaction_b64)
    message: Any = None
    message_instructions: list[Any] = []
    # Route v0 wire bytes straight to VersionedTransaction; the legacy
    # parser in solders is lenient and can mis-parse a signed v0 tx as a
    # degenerate legacy tx whose instructions point at random account
    # keys. The allowlist would then reject the legitimate v0 payment
    # with a misleading "unexpected program instruction" error sourced
    # from junk bytes. See _is_v0_wire_bytes.
    parsed = False
    if _is_v0_wire_bytes(raw):
        try:
            vtx = VersionedTransaction.from_bytes(raw)
        except Exception:
            vtx = None
        if vtx is not None:
            if getattr(vtx.message, "address_table_lookups", None):
                raise PaymentError(
                    "v0 transactions with address lookup tables are not supported",
                    code="invalid-payload",
                ) from None
            message = vtx.message
            message_instructions = list(vtx.message.instructions)
            parsed = True
    if not parsed:
        try:
            tx = Transaction.from_bytes(raw)
            message = tx.message
            message_instructions = list(tx.message.instructions)
        except Exception:
            try:
                vtx = VersionedTransaction.from_bytes(raw)
            except Exception as exc:
                raise PaymentError(
                    "unsupported transaction shape for instruction allowlist",
                    code="invalid-payload-type",
                ) from exc
            if getattr(vtx.message, "address_table_lookups", None):
                raise PaymentError(
                    "v0 transactions with address lookup tables are not supported",
                    code="invalid-payload",
                ) from None
            message = vtx.message
            message_instructions = list(vtx.message.instructions)

    account_keys = [str(key) for key in message.account_keys]
    if not account_keys:
        raise PaymentError("transaction has no accounts", code="invalid-payload")
    fee_payer_account = account_keys[0]
    # SECURITY: when the charge advertises feePayer=true the protective
    # pubkey used for drain detection MUST come from the server-side
    # signing context (``Mpp._fee_payer_signer.pubkey()``), NOT from
    # client-echoed ``methodDetails.feePayerKey``. A malicious client can
    # tamper the echoed key to a pubkey it controls, pass the source-account
    # checks below (because they compare against the tampered value), and
    # still get the real server keypair to co-sign and broadcast a transfer
    # sourced from the actual server fee-payer.
    #
    # The client-echoed ``details.fee_payer_key`` is cross-checked against
    # the server pubkey above this allowlist (in ``_verify_local_transaction_intent``)
    # so a mismatch is rejected up-front with ``payment_invalid``. Here we
    # only consume the server-supplied pubkey. If no server pubkey was
    # threaded (e.g. unit tests that call the helper directly), we fall
    # back to the echoed value for backward compatibility; production
    # callers always thread the server pubkey.
    fee_payer_pubkey: str | None
    if expected_fee_payer_pubkey is not None:
        fee_payer_pubkey = expected_fee_payer_pubkey
    elif details.fee_payer and details.fee_payer_key:
        fee_payer_pubkey = details.fee_payer_key
    else:
        fee_payer_pubkey = None

    expected_transfers = _build_expected_transfers(request, details)
    native = is_native_sol(request.currency)
    expected_mint = None if native else resolve_mint(request.currency, details.network)
    expected_token_program: str | None = None
    if not native:
        expected_token_program = details.token_program or default_token_program_for_currency(
            request.currency, details.network
        )
    allowed_ata_owners, _required_ata_owners = _expected_ata_creation_policy(details, fee_payer_pubkey)
    expected_memos = {memo for _label, memo in _expected_memos(request, details)}

    # Track which required transfers / memos have been satisfied so each
    # required entry can only be matched once; an attacker cannot replay
    # a single transfer to cover two required legs.
    remaining_transfers: list[tuple[str, int]] = list(expected_transfers)
    remaining_memos: set[str] = set(expected_memos)

    for instruction in message_instructions:
        try:
            program_id = account_keys[int(instruction.program_id_index)]
        except IndexError as exc:
            raise PaymentError(
                "instruction references an unknown program index",
                code="invalid-payload",
            ) from exc
        data = bytes(instruction.data)
        accounts = list(instruction.accounts)

        if program_id == _COMPUTE_BUDGET_PROGRAM:
            _validate_compute_budget_instruction(data, len(accounts))
            continue

        if program_id == MEMO_PROGRAM:
            try:
                memo_text = data.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise PaymentError(
                    "memo instruction is not valid UTF-8",
                    code="invalid-payload",
                ) from exc
            if memo_text not in remaining_memos:
                raise PaymentError(
                    "unexpected Memo Program instruction in payment transaction",
                    code="invalid-payload",
                )
            remaining_memos.discard(memo_text)
            continue

        if program_id == _MEMO_V1_PROGRAM:
            raise PaymentError(
                "memo v1 program is not supported (use Memo v2)",
                code="invalid-payload",
            )

        if program_id == _SYSTEM_PROGRAM:
            if not native:
                raise PaymentError(
                    "unexpected System Program instruction in token payment transaction",
                    code="invalid-payload",
                )
            if len(data) < 12 or len(accounts) < 2:
                raise PaymentError(
                    "unexpected System Program instruction in payment transaction",
                    code="invalid-payload",
                )
            kind = int.from_bytes(data[:4], "little")
            if kind != _SYSTEM_TRANSFER_INSTRUCTION:
                raise PaymentError(
                    "unexpected System Program instruction in payment transaction",
                    code="invalid-payload",
                )
            try:
                source = account_keys[int(accounts[0])]
                destination = account_keys[int(accounts[1])]
            except IndexError as exc:
                raise PaymentError(
                    "transfer references an unknown account",
                    code="invalid-payload",
                ) from exc
            # SECURITY: reject any System transfer that sources lamports from
            # the configured fee-payer (mirrors rust spine ``verify_sol_transfer_instructions``).
            # Without this guard a malicious client can satisfy the required
            # payment with a transfer FROM the fee-payer, draining server SOL
            # on top of the network fee already debited from account_keys[0].
            if fee_payer_pubkey is not None and source == fee_payer_pubkey:
                raise PaymentError(
                    "fee payer cannot fund the SOL payment transfer",
                    code="invalid-payload",
                )
            lamports = int.from_bytes(data[4:12], "little")
            match_idx = next(
                (i for i, (rcpt, amt) in enumerate(remaining_transfers) if rcpt == destination and amt == lamports),
                -1,
            )
            if match_idx == -1:
                raise PaymentError(
                    "unexpected System Program transfer in payment transaction",
                    code="invalid-payload",
                )
            remaining_transfers.pop(match_idx)
            continue

        if program_id in {TOKEN_PROGRAM, TOKEN_2022_PROGRAM}:
            if native:
                raise PaymentError(
                    "unexpected Token Program instruction in native SOL payment",
                    code="invalid-payload",
                )
            if expected_token_program is not None and program_id != expected_token_program:
                raise PaymentError(
                    "token program does not match methodDetails.tokenProgram",
                    code="invalid-payload",
                )
            if len(data) < 10 or len(accounts) < 4:
                raise PaymentError(
                    "unexpected Token Program instruction in payment transaction",
                    code="invalid-payload",
                )
            if data[0] != _TOKEN_TRANSFER_CHECKED_INSTRUCTION:
                raise PaymentError(
                    "unexpected Token Program instruction in payment transaction",
                    code="invalid-payload",
                )
            try:
                source_ata = account_keys[int(accounts[0])]
                mint = account_keys[int(accounts[1])]
                destination = account_keys[int(accounts[2])]
                authority = account_keys[int(accounts[3])]
            except IndexError as exc:
                raise PaymentError(
                    "token transfer references an unknown account",
                    code="invalid-payload",
                ) from exc
            if expected_mint is not None and mint != expected_mint:
                raise PaymentError(
                    "token transfer mint does not match the charge currency",
                    code="invalid-payload",
                )
            # SECURITY: reject any SPL transferChecked authorized by the
            # configured fee-payer or sourced from the fee-payer's ATA for
            # this mint / token program. Mirrors rust spine
            # ``verify_spl_transfer_instructions``. Without these checks a
            # malicious client can present a transferChecked FROM the
            # fee-payer ATA TO the recipient ATA matching the required
            # amount; the allowlist would pass and the server would
            # co-sign, draining fee-payer tokens.
            if fee_payer_pubkey is not None:
                if authority == fee_payer_pubkey:
                    raise PaymentError(
                        "fee payer cannot authorize the SPL payment transfer",
                        code="invalid-payload",
                    )
                if _verify_ata_owner(source_ata, fee_payer_pubkey, mint, program_id):
                    raise PaymentError(
                        "fee payer token account cannot fund the SPL payment transfer",
                        code="invalid-payload",
                    )
            amount = int.from_bytes(data[1:9], "little")
            match_idx = next(
                (
                    i
                    for i, (rcpt, amt) in enumerate(remaining_transfers)
                    if amt == amount and _verify_ata_owner(destination, rcpt, mint, program_id)
                ),
                -1,
            )
            if match_idx == -1:
                raise PaymentError(
                    "unexpected Token Program transfer in payment transaction",
                    code="invalid-payload",
                )
            remaining_transfers.pop(match_idx)
            continue

        if program_id == ASSOCIATED_TOKEN_PROGRAM:
            _validate_ata_create_idempotent(
                instruction,
                account_keys,
                expected_mint,
                allowed_ata_owners,
                expected_token_program,
                fee_payer_account,
            )
            continue

        raise PaymentError(
            f"unexpected program instruction in payment transaction: {program_id}",
            code="invalid-payload",
        )


def _verify_local_transaction_intent(
    transaction_b64: str,
    request: ChargeRequest,
    details: MethodDetails,
    expected_fee_payer_pubkey: str | None = None,
) -> None:
    """Verify locally-decodable payment intent before broadcasting.

    ``expected_fee_payer_pubkey`` is the AUTHORITATIVE server-side fee-payer
    pubkey (``Mpp._fee_payer_signer.pubkey()``). It is threaded by
    ``_verify_transaction`` so the no-leftovers allowlist can detect drain
    attempts against the real server key, not against a client-echoed
    ``methodDetails.feePayerKey`` value (which an attacker controls). When
    both are present and ``details.fee_payer`` is true we also reject any
    mismatch up-front with the canonical ``payment_invalid`` code so a
    tampered echoed key cannot silently slip through.
    """
    if (
        expected_fee_payer_pubkey is not None
        and details.fee_payer
        and details.fee_payer_key
        and details.fee_payer_key != expected_fee_payer_pubkey
    ):
        raise PaymentError(
            "methodDetails.feePayerKey does not match the server fee-payer signer",
            code="invalid-payload",
        )
    instructions = _decode_legacy_payment_instructions(transaction_b64)
    if is_native_sol(request.currency):
        _verify_parsed_sol_transfers(instructions, request, details)
    else:
        _verify_parsed_spl_transfers(instructions, request, details)
    _verify_parsed_memo_instructions(instructions, request, details)
    # SECURITY: strict no-leftovers allowlist. Runs after the parsed
    # verifiers so a missing-required-transfer fails with the canonical
    # ``no-transfer`` code; this final pass rejects ANY extra instruction
    # (especially System Program transfers from the fee payer) so the
    # fee-payer co-sign path cannot be tricked into draining the
    # server's SOL.
    _validate_instruction_allowlist(
        transaction_b64,
        request,
        details,
        expected_fee_payer_pubkey=expected_fee_payer_pubkey,
    )


@dataclass
class ChargeOptions:
    """Options for charge challenge generation."""

    description: str = ""
    external_id: str = ""
    expires: str = ""
    fee_payer: bool = False
    splits: list[dict] = field(default_factory=list)


@dataclass
class Config:
    """Server-side configuration."""

    recipient: str = ""
    currency: str = "USDC"
    decimals: int = 6
    network: str = "mainnet"
    rpc_url: str = ""
    secret_key: str = ""
    realm: str = ""
    html: bool = False
    fee_payer_signer: Any = None
    store: Store | None = None
    # The RPC client MUST expose at least the methods on
    # :class:`solana_mpp._rpc.SolanaRpc`: ``send_raw_transaction``,
    # ``get_signature_statuses``, ``await_confirmation``,
    # ``get_recent_blockhash`` and ``get_transaction``. The previous
    # ``# solana.rpc.async_api.AsyncClient`` comment suggested the legacy
    # solana-py client was a drop-in replacement; it is not, because it
    # lacks ``await_confirmation`` and would AttributeError between the
    # broadcast and the confirmation poll, AFTER the consume marker is
    # durable. ``Mpp.__init__`` validates the contract at config time so
    # the failure surfaces before any 402 traffic.
    rpc: Any = None


class Mpp:
    """Server-side Solana charge handler.

    Follows the same logic as the Go server.go implementation.
    """

    def __init__(self, config: Config) -> None:
        if not config.recipient or not config.recipient.strip():
            raise PaymentError("recipient is required", code="invalid-config")

        import os

        secret_key = config.secret_key or os.environ.get(_SECRET_KEY_ENV_VAR, "")
        if not secret_key:
            raise PaymentError("missing secret key", code="invalid-config")

        self._secret_key = secret_key
        self._realm = config.realm or _DEFAULT_REALM
        self._recipient = config.recipient
        self._currency = config.currency or "USDC"
        self._decimals = config.decimals or 6
        from solana_mpp.protocol.solana import _canonical_network as _canonical_net

        self._network = _canonical_net(config.network or "mainnet")
        self._rpc_url = config.rpc_url or default_rpc_url(self._network)
        self._html = config.html
        self._fee_payer_signer = config.fee_payer_signer
        if config.store is None:
            # L4 lock: a missing replay store is a server misconfiguration.
            # Silently falling back to MemoryStore() used to leave a window
            # where a credential could replay after restart. Mirrors the
            # required-explicit-store contract on Ruby and PHP after #96 / #102.
            raise PaymentError(
                "replay store is required; pass MemoryStore() or FileReplayStore(path) explicitly",
                code="invalid-config",
            )
        self._store: Store = config.store
        # Validate the RPC client contract up-front. The settlement path
        # calls ``send_raw_transaction``, ``await_confirmation`` and
        # ``get_transaction`` after the durable consume marker is
        # written; a missing method on the rpc instance would surface
        # only after that consume, stranding the user. Reject at config
        # time instead.
        if config.rpc is not None:
            for method_name in ("send_raw_transaction", "await_confirmation", "get_transaction"):
                if not callable(getattr(config.rpc, method_name, None)):
                    raise PaymentError(
                        f"rpc client missing required method '{method_name}'; "
                        "use solana_mpp._rpc.SolanaRpc or a compatible client",
                        code="invalid-config",
                    )
        self._rpc = config.rpc
        # Held by ``using_rpc`` to serialize per-request RPC swaps when
        # the interop adapter (or any embedder) wants a fresh client
        # bound to the current event loop. The async lock is created
        # lazily on first use so construction does not require a
        # running loop.
        self._rpc_swap_lock = asyncio.Lock()

    @contextlib.asynccontextmanager
    async def using_rpc(self, rpc: Any):
        """Scope an RPC client to the surrounding async block.

        Swaps ``self._rpc`` for the duration of the body and always
        restores the prior value on exit, even if the body raises.

        Concurrency caveat: the underlying lock is an ``asyncio.Lock``,
        which serialises only coroutines running on the SAME event
        loop. Embedders that share one ``Mpp`` instance across multiple
        OS threads (each running its own ``asyncio.run`` loop) MUST
        provide their own thread-level coordination. The interop
        adapter ships a sequential ``HTTPServer`` (not ThreadingMixIn),
        so this lock is sufficient there; a ThreadingHTTPServer or
        Gunicorn-style worker pool would require either thread-local
        ``Mpp`` instances or a ``threading.Lock`` wrapping the swap.
        """
        async with self._rpc_swap_lock:
            previous = self._rpc
            self._rpc = rpc
            try:
                yield
            finally:
                self._rpc = previous

    @property
    def realm(self) -> str:
        return self._realm

    @property
    def rpc_url(self) -> str:
        return self._rpc_url

    @property
    def html_enabled(self) -> bool:
        return self._html

    def charge(self, amount: str) -> PaymentChallenge:
        """Create a charge challenge from a human-readable amount."""
        return self.charge_with_options(amount, ChargeOptions())

    def charge_with_options(self, amount: str, options: ChargeOptions) -> PaymentChallenge:
        """Create a charge challenge with optional fields."""
        base_units = parse_units(amount, self._decimals)

        details: dict[str, Any] = {"network": self._network}
        if not is_native_sol(self._currency):
            details["decimals"] = self._decimals
            if stablecoin_symbol(self._currency):
                details["tokenProgram"] = default_token_program_for_currency(self._currency, self._network)
        if options.fee_payer or self._fee_payer_signer is not None:
            details["feePayer"] = True
            if self._fee_payer_signer is not None:
                details["feePayerKey"] = str(self._fee_payer_signer.pubkey())
        if options.splits:
            details["splits"] = options.splits

        request_obj: dict[str, Any] = {
            "amount": base_units,
            "currency": self._currency,
            "recipient": self._recipient,
        }
        if options.description:
            request_obj["description"] = options.description
        if options.external_id:
            request_obj["externalId"] = options.external_id
        if details:
            request_obj["methodDetails"] = details

        request_b64 = encode_json(request_obj)

        from solana_mpp._expires import minutes

        default_expires = minutes(5)
        return PaymentChallenge.with_secret_key(
            secret_key=self._secret_key,
            realm=self._realm,
            method="solana",
            intent="charge",
            request=request_b64,
            expires=options.expires or default_expires,
            description=options.description,
        )

    async def verify_credential(self, credential: PaymentCredential) -> Receipt:
        """Verify either a transaction or signature credential payload.

        This is the simple API and is appropriate for servers that only gate a
        single route. Servers that gate multiple routes at different prices on
        the same secret key MUST use ``verify_credential_with_expected`` so the
        route's expected amount is compared to the credential's claimed amount;
        otherwise a credential issued for a cheaper route can be replayed at
        an expensive one.

        Even on the simple API, a Tier-2 pinned-field check enforces that the
        credential's method/intent/realm/currency/recipient match this Mpp's
        configuration, so cross-route replay across instances with different
        recipients/currencies is blocked.
        """
        request, details, payload = self._verify_challenge_and_decode(credential)
        return await self._verify_payload(credential, request, details, payload)

    async def verify_credential_with_expected(
        self,
        credential: PaymentCredential,
        expected: ChargeRequest,
    ) -> Receipt:
        """Verify a credential against the route's expected charge request.

        The amount, currency, and recipient on the credential's claimed
        challenge must match ``expected``. Settlement (transaction broadcast,
        on-chain checks) then runs against ``expected`` — not the credential's
        claims — so a credential built for a different route's request cannot
        succeed even if its other fields line up.
        """
        cred_request, _details, payload = self._verify_challenge_and_decode(credential)

        if cred_request.amount != expected.amount:
            raise PaymentError(
                f"amount mismatch: credential has {cred_request.amount} but endpoint expects {expected.amount}",
                code="amount-mismatch",
            )
        if cred_request.currency != expected.currency:
            raise PaymentError(
                f"currency mismatch: credential has {cred_request.currency} but endpoint expects {expected.currency}",
                code="currency-mismatch",
            )
        if cred_request.recipient != expected.recipient:
            raise PaymentError(
                "recipient mismatch: credential was issued for a different recipient",
                code="recipient-mismatch",
            )

        expected_details = MethodDetails()
        if expected.method_details:
            expected_details = MethodDetails.from_dict(expected.method_details)

        return await self._verify_payload(credential, expected, expected_details, payload)

    def _verify_challenge_and_decode(
        self, credential: PaymentCredential
    ) -> tuple[ChargeRequest, MethodDetails, CredentialPayload]:
        """Run Tier-1 (HMAC + expiry) and Tier-2 (pinned-field) checks.

        Returns the credential-decoded request, parsed method details, and the
        credential payload for downstream settlement.
        """
        challenge = PaymentChallenge(
            id=credential.challenge.id,
            realm=credential.challenge.realm,
            method=credential.challenge.method,
            intent=credential.challenge.intent,
            request=credential.challenge.request,
            expires=credential.challenge.expires,
            digest=credential.challenge.digest,
            opaque=credential.challenge.opaque,
        )

        if not challenge.verify(self._secret_key):
            raise ChallengeMismatchError()

        if challenge.is_expired():
            raise ChallengeExpiredError(f"challenge expired at {challenge.expires}")

        request = ChargeRequest.from_dict(challenge.decode_request())

        # Tier-2: pinned-field backstop. Even if the simple verify_credential
        # path is used, fields that are fixed at Mpp construction time must
        # match the credential.
        self._verify_pinned_fields(credential, request)

        details = MethodDetails()
        if request.method_details:
            details = MethodDetails.from_dict(request.method_details)

        payload = CredentialPayload.from_dict(credential.payload)
        return request, details, payload

    def _verify_pinned_fields(self, credential: PaymentCredential, request: ChargeRequest) -> None:
        # L6 lock: pinned-field mismatches are route mismatches, NOT HMAC
        # verification failures. A validly signed credential for a different
        # route or with a tampered echoed field reaches this path. Emitting
        # ``challenge_route_mismatch`` lets clients distinguish a bad HMAC
        # (``challenge_verification_failed``) from a signed credential
        # replayed against the wrong endpoint.
        method_name = "solana"
        if credential.challenge.method != method_name:
            raise PaymentError(
                f"credential method '{credential.challenge.method}' does not match this server "
                f"(expected '{method_name}')",
                code="method-mismatch",
            )
        # IntentName equivalent: case-insensitive "charge" comparison.
        if credential.challenge.intent.lower() != "charge":
            raise PaymentError(
                f"credential intent '{credential.challenge.intent}' is not a charge",
                code="intent-mismatch",
            )
        # The HMAC ID is computed using the server's own realm (not the echoed
        # one), so a tampered echoed realm passes HMAC unless re-signed. Pin it.
        if credential.challenge.realm != self._realm:
            raise PaymentError(
                f"credential realm '{credential.challenge.realm}' does not match this server "
                f"(expected '{self._realm}')",
                code="realm-mismatch",
            )
        if request.currency != self._currency:
            raise PaymentError(
                f"credential currency '{request.currency}' does not match this server (expected '{self._currency}')",
                code="currency-mismatch",
            )
        if request.recipient != self._recipient:
            raise PaymentError(
                "credential recipient does not match this server",
                code="recipient-mismatch",
            )

    async def _verify_payload(
        self,
        credential: PaymentCredential,
        request: ChargeRequest,
        details: MethodDetails,
        payload: CredentialPayload,
    ) -> Receipt:
        if payload.type == "transaction":
            return await self._verify_transaction(credential, request, details, payload)
        elif payload.type == "signature":
            if details.fee_payer:
                raise PaymentError(
                    'type="signature" credentials cannot be used with fee sponsorship',
                    code="invalid-payload-type",
                )
            return await self._verify_signature(credential, request, details, payload)
        else:
            raise PaymentError("missing or invalid payload type", code="invalid-payload-type")

    async def _verify_transaction(
        self,
        credential: PaymentCredential,
        request: ChargeRequest,
        details: MethodDetails,
        payload: CredentialPayload,
    ) -> Receipt:
        """Verify a pull-mode transaction credential."""
        if not payload.transaction:
            raise PaymentError("missing transaction data in credential payload", code="missing-transaction")
        if self._rpc is None:
            raise PaymentError("rpc client is required for transaction verification", code="invalid-config")
        if details.fee_payer and self._fee_payer_signer is None:
            raise PaymentError(
                "challenge advertises feePayer=true but server has no fee payer configured",
                code="invalid-config",
            )

        # Reject up-front if the client signed against the wrong network
        # (e.g. mainnet keypair pointed at a sandbox-configured server, or
        # vice versa). Cheaper and clearer than letting the broadcast fail.
        # Done here in the entry path so it runs even while the rest of the
        # pipeline below is still a stub.
        try:
            blockhash_b58 = _extract_recent_blockhash(payload.transaction)
        except Exception as exc:  # noqa: BLE001 — propagate decode failures as invalid payload
            raise PaymentError(
                f"could not decode transaction to read blockhash: {exc}",
                code="invalid-payload-type",
            ) from exc
        check_network_blockhash(self._network, blockhash_b58)
        # SECURITY: pass the SERVER-side fee-payer pubkey (not the
        # client-echoed ``details.fee_payer_key``) so the allowlist's
        # drain-detection check matches against the actual signing key.
        # A tampered echoed key is rejected up-front by
        # ``_verify_local_transaction_intent``.
        server_fee_payer_pubkey: str | None = None
        if self._fee_payer_signer is not None:
            server_fee_payer_pubkey = str(self._fee_payer_signer.pubkey())
        _verify_local_transaction_intent(
            payload.transaction,
            request,
            details,
            expected_fee_payer_pubkey=server_fee_payer_pubkey,
        )

        # If the challenge advertises a server-side fee payer, co-sign the
        # client's transaction now (after pre-broadcast verification, before
        # broadcast). Mirrors rust/src/server/charge.rs verify_pull cosign
        # step. The fee payer signature occupies the slot for the fee-payer
        # account in the wire transaction.
        signed_b64 = payload.transaction
        if details.fee_payer:
            signed_b64 = _co_sign_with_fee_payer(payload.transaction, self._fee_payer_signer)

        # L8 lock: broadcast first, then consume_signature, then await
        # confirmation. The previous order (consume → broadcast → await,
        # with a rollback in the except block) had a fatal flaw: a
        # confirmation timeout after a successful broadcast triggered the
        # rollback path which DELETED the consume marker, so a retry of the
        # same credential could re-broadcast the same signed transaction
        # and re-issue a receipt for it. Mirrors the canonical L8 order
        # documented in lua/mpp/server/charge_handler.lua and the fix that
        # landed on Ruby + PHP + Rust in PR #96 / #102. This is the same
        # confirmation-timeout double-pay window Ludo found on the Rust
        # spine; closing it here brings Python into parity.

        raw_tx = base64.b64decode(signed_b64)
        send_resp = await self._rpc.send_raw_transaction(raw_tx)
        signature = str(_rpc_value(send_resp))

        # CONSUME the signature now that we know it has been accepted by the
        # cluster. Keying by signature (not by the credential bytes) means a
        # retry of the same credential always tries to insert the same key,
        # so the second attempt fails fast and the network is never asked
        # to settle the same transaction twice.
        consumed_key = _CONSUMED_PREFIX + signature
        inserted = await self._store.put_if_absent(consumed_key, True)
        if not inserted:
            raise ReplayError()

        # AWAIT confirmation. A timeout here MUST NOT roll back the consume:
        # the signature is on the wire and may finalize asynchronously.
        # Use ``await_confirmation`` (not ``confirm_transaction``) so an
        # on-chain failure surfaces as ``transaction-failed`` while a
        # polling timeout surfaces as ``transaction-not-found``; the
        # canonical code mapping in ``_errors`` collapses both to the
        # same client-facing 402 body, so the discrimination is purely
        # diagnostic.
        # Pass the raw signature string straight through. The previous
        # ``Signature.from_string(signature)`` call sat between the
        # durable consume marker (above) and the get_transaction call;
        # if that parse ever raised (malformed RPC response, future
        # solders API change), the consume would be durable but no
        # receipt would be issued, stranding the user. ``get_transaction``
        # already calls ``str(signature)`` internally on the wire, so the
        # conversion is redundant work on the post-consume critical path.
        await self._rpc.await_confirmation(signature)

        tx_resp = await self._rpc.get_transaction(signature, encoding="jsonParsed", max_supported_transaction_version=0)
        tx = _transaction_dict(tx_resp)
        if tx is None:
            raise PaymentError("transaction not found or not yet confirmed", code="transaction-not-found")
        self._verify_confirmed_transaction(tx, request, details)
        return Receipt.success(
            method="solana",
            reference=signature,
            challenge_id=credential.challenge.id,
            external_id=request.external_id,
        )

    async def _verify_signature(
        self,
        credential: PaymentCredential,
        request: ChargeRequest,
        details: MethodDetails,
        payload: CredentialPayload,
    ) -> Receipt:
        """Verify a push-mode signature credential."""
        if not payload.signature:
            raise PaymentError("missing signature in credential payload", code="missing-signature")
        if self._rpc is None:
            raise PaymentError("rpc client is required for signature verification", code="invalid-config")

        # L8 push-mode lock: fetch the on-chain transaction and verify its
        # shape BEFORE consuming the signature. If the client lied about the
        # signature (or sent a signature that does not match the route), we
        # do not want a permanent replay-store entry for it. Only after the
        # on-chain shape is known to be correct do we mark the signature
        # consumed. Mirrors lua/mpp/server/charge_handler.lua push-mode
        # steps 2-4 and the cross-SDK lock from PR #96 / #102.
        from solders.signature import Signature

        sig = Signature.from_string(payload.signature)
        tx_resp = await self._rpc.get_transaction(sig, encoding="jsonParsed", max_supported_transaction_version=0)
        tx = _transaction_dict(tx_resp)
        if tx is None:
            raise PaymentError("transaction not found or not yet confirmed", code="transaction-not-found")
        self._verify_confirmed_transaction(tx, request, details)

        consumed_key = _CONSUMED_PREFIX + payload.signature
        inserted = await self._store.put_if_absent(consumed_key, True)
        if not inserted:
            raise ReplayError()

        return Receipt.success(
            method="solana",
            reference=payload.signature,
            challenge_id=credential.challenge.id,
            external_id=request.external_id,
        )

    def _verify_confirmed_transaction(self, tx: dict[str, Any], request: ChargeRequest, details: MethodDetails) -> None:
        """Post-confirmation verification of the on-chain transaction
        shape (transfers, memos, instruction allowlist).

        L8 contract: this runs AFTER the durable replay marker is
        written by ``_verify_transaction`` (broadcast → consume →
        await → verify). The pre-broadcast verifier
        ``_verify_local_transaction_intent`` already enforces the same
        invariants on the raw signed bytes before any RPC call, so a
        malicious credential never broadcasts; this confirmed-tx
        verifier is defense-in-depth that re-checks the artifact the
        cluster actually accepted, catching any cluster-side
        rewriting / replay-attack the pre-broadcast verifier could
        not see. Both layers must accept the same shape, otherwise the
        receipt is rejected and the consume marker stays written
        (the credential is single-use either way).
        """
        meta = tx.get("meta") or {}
        if meta.get("err") is not None:
            raise PaymentError(f"transaction failed on-chain: {meta['err']}", code="transaction-failed")

        instructions = ((tx.get("transaction") or {}).get("message") or {}).get("instructions") or []
        if is_native_sol(request.currency):
            _verify_parsed_sol_transfers(instructions, request, details)
        else:
            _verify_parsed_spl_transfers(instructions, request, details)
        _verify_parsed_memo_instructions(instructions, request, details)
