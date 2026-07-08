"""Transaction decoding and parsed-instruction verification for MPP charge.

Pure, RPC-free helpers shared by the server charge flow: module constants
mirrored from the Rust spine, the local transfer/memo decoders for legacy and
v0 transactions, the lossy parsed-instruction verifiers, and the small
RPC-response coercion utilities. These never touch the replay store or the
network; the orchestration and the strict no-leftovers allowlist live in
:mod:`solana_pay_kit.protocols.mpp.server._verify` and
:mod:`solana_pay_kit.protocols.mpp.server.charge`.
"""

from __future__ import annotations

import base64
import json
from typing import Any

from solana_pay_kit._paycore.errors import PaymentError
from solana_pay_kit._paycore.solana import (
    ASSOCIATED_TOKEN_PROGRAM,
    MAX_SPLITS,
    MEMO_PROGRAM,
    TOKEN_2022_PROGRAM,
    TOKEN_PROGRAM,
    MethodDetails,
    default_token_program_for_currency,
    resolve_mint,
)
from solana_pay_kit._paycore.transaction import is_v0_wire_bytes
from solana_pay_kit.protocols.mpp.intents.charge import ChargeRequest

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
# Audit #25: in fee-sponsored pull mode the server co-signs (and pays the
# priority fee) before broadcast, so a client could set the price up to the
# general cap and drain the merchant. Apply a tight cap when the server is the
# fee payer. Worst-case priority fee = ceil(10_000 * 200_000 / 1_000_000) =
# 2_000 lamports (~20% of the per-signature base fee) — enough room for honest
# clients to bump priority during congestion. Mirrors Rust
# ``MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS_FEE_SPONSORED``.
MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS_FEE_SPONSORED = 10_000

# ``MAX_SPLITS`` (the split-recipient cap) is imported from
# :mod:`solana_pay_kit._paycore.solana` and re-exported here so the server verifier and
# the client fail-fast check share one source of truth pinned to the Rust spine.

# Legacy Solana memo program (v1). MPP charge transactions MUST use memo v2
# (``MEMO_PROGRAM`` from :mod:`solana_pay_kit._paycore.solana`). v1 had a different
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
    # transferChecked carries the token decimals inline; the challenge pins
    # the expected decimals (6 for stablecoins). A transfer that encodes a
    # different decimals byte targets a different on-chain mint precision and
    # must not match, mirroring the TS reference verifier
    # (server/Charge.ts verifySplTransferPreBroadcast: ``data[9] !== decimals``
    # skips the instruction) and the Rust spine. Without this an attacker can
    # encode decimals=9 against a decimals=6 challenge and the lossy matcher
    # would accept it.
    expected_decimals = details.decimals
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
                and _decimals_match(
                    (((transfer.get("parsed") or {}).get("info") or {}).get("tokenAmount") or {}).get("decimals"),
                    expected_decimals,
                )
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


def _decimals_match(actual: Any, expected: int | None) -> bool:
    """Return True unless a present transfer decimals contradicts the challenge.

    transferChecked encodes the token decimals inline; the pre-broadcast
    decoder and the Solana jsonParsed RPC format both surface it under
    ``tokenAmount.decimals``. We reject only a *present* decimals that
    disagrees with the challenge so a decimals=9 transfer cannot satisfy a
    decimals=6 challenge (mirrors the TS reference verifier). When either
    side is absent we do not constrain on decimals, so confirmed-transaction
    fixtures that omit the field still match on mint / amount / destination.
    """
    if expected is None or actual is None:
        return True
    return int(actual) == int(expected)


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
    from solders.transaction import Transaction, VersionedTransaction

    raw = base64.b64decode(transaction_b64)
    try:
        tx = Transaction.from_bytes(raw)
        return str(tx.message.recent_blockhash)
    except Exception:
        vtx = VersionedTransaction.from_bytes(raw)
        return str(vtx.message.recent_blockhash)


def _validate_compute_budget_instruction(
    data: bytes, account_count: int, fee_sponsored: bool = False
) -> None:
    """Validate a single ComputeBudget program instruction.

    Mirrors ``validate_compute_budget_instruction`` in
    ``rust/src/server/charge.rs``: SetComputeUnitLimit (discriminator 2,
    u32 LE units in ``data[1..5]``) and SetComputeUnitPrice (discriminator
    3, u64 LE microlamports in ``data[1..9]``) are the only accepted
    shapes, both must carry zero account references, and each value is
    capped at the per-instruction maximum. Anything else is rejected as
    an invalid payload to keep the on-wire allowlist tight.

    Audit #25: when ``fee_sponsored`` is True (the server is the fee payer and
    co-signs before broadcast), the compute-unit price is held to the tight
    ``MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS_FEE_SPONSORED`` cap so a client
    cannot inflate the priority fee the merchant pays. Client-paid mode keeps
    the general cap.
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
        price_cap = (
            MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS_FEE_SPONSORED
            if fee_sponsored
            else MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS
        )
        if price > price_cap:
            raise PaymentError(
                f"compute unit price {price} exceeds cap {price_cap}",
                code="compute-budget-cap-exceeded",
            )
        return
    raise PaymentError(
        "unsupported compute budget instruction",
        code="compute-budget-invalid",
    )


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
    # degenerate legacy tx with bogus instructions (see is_v0_wire_bytes).
    parsed = False
    if is_v0_wire_bytes(raw):
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
            # transferChecked encodes the token decimals as the trailing
            # byte (data[9]); surface it so the verifier can reject a
            # decimals mismatch against the challenge.
            decimals = data[9]
            instructions.append(
                {
                    "programId": program_id,
                    "parsed": {
                        "type": "transferChecked",
                        "info": {
                            "destination": destination,
                            "mint": mint,
                            "tokenAmount": {"amount": str(amount), "decimals": decimals},
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
