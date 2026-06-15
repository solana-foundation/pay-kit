"""x402 ``exact`` self-hosted 11-rule structural verifier and constants.

``ExactVerifier`` follows the Rust spine rule-for-rule and reject-code-for-
reject-code (``rust/crates/x402/src/protocol/schemes/exact/verify.rs`` and the
server backstops at ``rust/crates/x402/src/server/exact.rs``), adding only
strictly-stronger defensive rejects; cross-checked against the PHP port at
``php/src/Protocols/X402/Exact/Verifier.php``.
"""

from __future__ import annotations

import base64
import struct
from typing import Any, cast

from pay_kit._paycore.mints import derive_ata
from pay_kit.errors import InvalidProofError

__all__ = [
    "ExactVerifier",
    "EXACT_SCHEME",
    "X402_VERSION",
    "X402_VERSION_V1",
    "X402_VERSION_V2",
    "COMPUTE_BUDGET_PROGRAM",
    "MEMO_PROGRAM",
    "LIGHTHOUSE_PROGRAM",
    "TOKEN_2022_PROGRAM",
    "MAX_COMPUTE_UNIT_PRICE",
]

#: x402 ``exact`` scheme identifier (rust ``EXACT_SCHEME``, types.rs:6).
EXACT_SCHEME = "exact"

#: Legacy x402 protocol version. Mirrors the rust spine constant
#: ``X402_VERSION_V1`` (rust/crates/x402/src/constants.rs:10).
X402_VERSION_V1 = 1
#: Canonical x402 protocol version used by current payments. Mirrors the rust
#: spine ``X402_VERSION_V2`` (constants.rs:13).
X402_VERSION_V2 = 2
#: Default x402 protocol version emitted in challenges and required on the
#: canonical credential path. Aliases the canonical (v2) version so existing
#: call sites keep emitting/expecting the default producer's wire.
X402_VERSION = X402_VERSION_V2

#: ComputeBudget program id (instruction[0]/[1] guard).
COMPUTE_BUDGET_PROGRAM = "ComputeBudget111111111111111111111111111111"
#: SPL Memo program id (allowlisted optional instruction + memo binding).
MEMO_PROGRAM = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"
#: Lighthouse assertion program id (allowlisted optional instruction).
#: Must match the rust spine constant ``LIGHTHOUSE_PROGRAM`` in
#: ``rust/crates/x402/src/protocol/schemes/exact/types.rs``.
LIGHTHOUSE_PROGRAM = "L2TExMFKdjpN9kozasaurPirfHy9P8sbXoAN1qA3S95"
#: Token-2022 program id (accepted transfer program alongside the route's).
TOKEN_2022_PROGRAM = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
#: Maximum SetComputeUnitPrice in microlamports. Matches the Rust spine
#: constant ``MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS`` in verify.rs.
MAX_COMPUTE_UNIT_PRICE = 5_000_000


def _u64_le(data: bytes, offset: int) -> int:
    """Read a little-endian u64 at ``offset``; reject on a short buffer."""
    if len(data) < offset + 8:
        raise InvalidProofError(
            "invalid_exact_svm_payload_no_transfer_instruction",
            code="invalid_exact_svm_payload_no_transfer_instruction",
        )
    return struct.unpack_from("<Q", data, offset)[0]


class ExactVerifier:
    """Structural 11-rule verifier for the x402 SVM ``exact`` scheme.

    Decodes a standard-base64 (padded) versioned transaction and confirms it
    matches the route's advertised requirement. Each failure raises
    :class:`InvalidProofError` carrying the canonical reject string the
    cross-language harness substring-matches against. Mirrors the
    rust ``verify_exact_instructions`` ordering exactly.
    """

    @staticmethod
    def verify(
        transaction_base64: str,
        requirement: dict[str, Any],
        managed_signers: list[str],
    ) -> dict[str, Any]:
        """Verify a base64 transaction against the route's x402 requirement.

        ``requirement`` is one ``accepts[]`` entry (the server offer).
        ``managed_signers`` lists server-managed pubkeys (typically the
        facilitator fee payer) that must never be the transfer authority.
        Returns a dict describing the matched transfer on success.
        """
        from solders.transaction import VersionedTransaction

        try:
            raw = base64.b64decode(transaction_base64, validate=True)
        except Exception as exc:  # noqa: BLE001 - any decode failure is a reject
            raise InvalidProofError(
                "invalid_exact_svm_payload_base64",
                code="invalid_exact_svm_payload_base64",
            ) from exc
        if not raw:
            raise InvalidProofError(
                "invalid_exact_svm_payload_base64",
                code="invalid_exact_svm_payload_base64",
            )

        try:
            tx = VersionedTransaction.from_bytes(raw)
        except Exception as exc:  # noqa: BLE001
            raise InvalidProofError(
                "invalid_exact_svm_payload_transaction_parse",
                code="invalid_exact_svm_payload_transaction_parse",
            ) from exc

        message = tx.message
        instructions = list(message.instructions)
        account_keys = [str(key) for key in message.account_keys]

        # Rule 1: instruction count 3..=6.
        n = len(instructions)
        if n < 3 or n > 6:
            raise InvalidProofError(
                "invalid_exact_svm_payload_transaction_instructions_length",
                code="invalid_exact_svm_payload_transaction_instructions_length",
            )

        # Rule 2: ix[0] = ComputeBudget SetComputeUnitLimit (disc 2, 5 bytes).
        ExactVerifier._verify_compute_limit(instructions[0], account_keys)
        # Rule 3: ix[1] = ComputeBudget SetComputeUnitPrice (disc 3, 9 bytes, <= MAX).
        ExactVerifier._verify_compute_price(instructions[1], account_keys)
        # Rules 4 + 5 + 6 + 7 + 8 + 11: transferChecked.
        transfer = ExactVerifier._verify_transfer(instructions[2], account_keys, requirement, managed_signers)

        # Rule 9: ix[3:] allowlist. Per the official x402 SVM exact contract
        # (specs/schemes/exact/scheme_exact_svm.md), the only permitted optional
        # instructions are Lighthouse (wallet-injected user-protection asserts,
        # Phantom=1 / Solflare=2) and SPL Memo. A Create-ATA / Associated Token
        # Program instruction is NOT allowed: the destination ATA MUST pre-exist
        # (Rule 7 derives and pins the destination ATA). This matches the
        # Rust/Go verifiers, which accept Lighthouse or Memo in ANY optional
        # slot (rust verify.rs iter().skip(3); go verify.go case Memo/Lighthouse
        # for all i>=3) and never accept ATA-create in this shape. Lighthouse is
        # not slot-restricted because wallets inject a variable number of guards.
        reasons = (
            "invalid_exact_svm_payload_unknown_fourth_instruction",
            "invalid_exact_svm_payload_unknown_fifth_instruction",
            "invalid_exact_svm_payload_unknown_sixth_instruction",
        )
        for i in range(3, n):
            ix = instructions[i]
            program = ExactVerifier._program_of(account_keys, ix)
            slot_index = i - 3
            allowed = program in (MEMO_PROGRAM, LIGHTHOUSE_PROGRAM)
            if not allowed:
                reason = (
                    reasons[slot_index]
                    if slot_index < len(reasons)
                    else "invalid_exact_svm_payload_unknown_optional_instruction"
                )
                raise InvalidProofError(reason, code=reason)

        # Rule 10: memo binding (exactly one Memo == extra.memo if set).
        expected_memo = ExactVerifier._string_extra(requirement, "memo", required=False)
        if expected_memo:
            ExactVerifier._find_memo_match(account_keys, instructions, expected_memo)

        # The destination ATA must pre-exist; ATA-create is never accepted.
        transfer["destinationCreateAta"] = False
        return transfer

    @staticmethod
    def _verify_compute_limit(ix: Any, account_keys: list[str]) -> None:
        program = ExactVerifier._program_of(account_keys, ix)
        data = bytes(ix.data)
        if program != COMPUTE_BUDGET_PROGRAM or len(data) != 5 or data[0] != 2:
            raise InvalidProofError(
                "invalid_exact_svm_payload_transaction_instructions_compute_limit_instruction",
                code="invalid_exact_svm_payload_transaction_instructions_compute_limit_instruction",
            )

    @staticmethod
    def _verify_compute_price(ix: Any, account_keys: list[str]) -> None:
        program = ExactVerifier._program_of(account_keys, ix)
        data = bytes(ix.data)
        if program != COMPUTE_BUDGET_PROGRAM or len(data) != 9 or data[0] != 3:
            raise InvalidProofError(
                "invalid_exact_svm_payload_transaction_instructions_compute_price_instruction",
                code="invalid_exact_svm_payload_transaction_instructions_compute_price_instruction",
            )
        micro = _u64_le(data, 1)
        if micro > MAX_COMPUTE_UNIT_PRICE:
            reason = "invalid_exact_svm_payload_transaction_instructions_compute_price_instruction_too_high"
            raise InvalidProofError(reason, code=reason)

    @staticmethod
    def _verify_transfer(
        ix: Any,
        account_keys: list[str],
        requirement: dict[str, Any],
        managed_signers: list[str],
    ) -> dict[str, Any]:
        program = ExactVerifier._program_of(account_keys, ix)
        # Rule 11: token program strict bind to extra.tokenProgram.
        token_program_extra = ExactVerifier._string_extra(requirement, "tokenProgram", required=True)
        if program != token_program_extra and program != TOKEN_2022_PROGRAM:
            raise InvalidProofError(
                "invalid_exact_svm_payload_no_transfer_instruction",
                code="invalid_exact_svm_payload_no_transfer_instruction",
            )
        data = bytes(ix.data)
        # solders CompiledInstruction.accounts is a list of u8 account indices;
        # solders ships no stubs, so annotate the shape explicitly at the boundary.
        accounts: list[int] = [int(a) for a in ix.accounts]
        # Rule 4: transferChecked shape (disc 12, 10-byte data, >= 4 accounts).
        if len(accounts) < 4 or len(data) != 10 or data[0] != 12:
            raise InvalidProofError(
                "invalid_exact_svm_payload_no_transfer_instruction",
                code="invalid_exact_svm_payload_no_transfer_instruction",
            )

        source = ExactVerifier._account_at(account_keys, ix, 0)
        mint = ExactVerifier._account_at(account_keys, ix, 1)
        destination = ExactVerifier._account_at(account_keys, ix, 2)
        authority = ExactVerifier._account_at(account_keys, ix, 3)

        # Rule 5: authority guard (no managed signer as authority/source/account).
        for managed in managed_signers:
            if managed in (authority, source):
                raise InvalidProofError(
                    "invalid_exact_svm_payload_transaction_fee_payer_transferring_funds",
                    code="invalid_exact_svm_payload_transaction_fee_payer_transferring_funds",
                )
        for idx in accounts:
            key = account_keys[idx] if 0 <= idx < len(account_keys) else None
            if key is None:
                continue
            for managed in managed_signers:
                if managed == key:
                    raise InvalidProofError(
                        "invalid_exact_svm_payload_transaction_fee_payer_in_instruction_accounts",
                        code="invalid_exact_svm_payload_transaction_fee_payer_in_instruction_accounts",
                    )

        # Rule 6: mint match (offer carries the resolved on-chain mint on `asset`).
        expected_mint = ExactVerifier._b58_field(requirement, "asset")
        if mint != expected_mint:
            raise InvalidProofError(
                "invalid_exact_svm_payload_mint_mismatch",
                code="invalid_exact_svm_payload_mint_mismatch",
            )

        # Rule 7: destination ATA match (re-derive owner+mint+token_program).
        pay_to = ExactVerifier._b58_field(requirement, "payTo")
        expected_destination = derive_ata(pay_to, expected_mint, program)
        if destination != expected_destination:
            raise InvalidProofError(
                "invalid_exact_svm_payload_recipient_mismatch",
                code="invalid_exact_svm_payload_recipient_mismatch",
            )

        # Rule 8: amount match (u64 LE at data[1:9]).
        amount = _u64_le(data, 1)
        expected_amount = ExactVerifier._amount_field(requirement)
        if amount != expected_amount:
            raise InvalidProofError(
                "invalid_exact_svm_payload_amount_mismatch",
                code="invalid_exact_svm_payload_amount_mismatch",
            )

        return {
            "program": program,
            "source": source,
            "mint": mint,
            "destination": destination,
            "authority": authority,
            "amount": amount,
        }

    @staticmethod
    def _find_memo_match(account_keys: list[str], instructions: list[Any], expected_memo: str) -> None:
        count = 0
        last_data: bytes | None = None
        for i in range(3, len(instructions)):
            ix = instructions[i]
            if ExactVerifier._program_of(account_keys, ix) == MEMO_PROGRAM:
                count += 1
                last_data = bytes(ix.data)
        if count != 1:
            raise InvalidProofError(
                "invalid_exact_svm_payload_memo_count",
                code="invalid_exact_svm_payload_memo_count",
            )
        if last_data is None or last_data.decode("utf-8", "replace") != expected_memo:
            raise InvalidProofError(
                "invalid_exact_svm_payload_memo_mismatch",
                code="invalid_exact_svm_payload_memo_mismatch",
            )

    @staticmethod
    def _program_of(account_keys: list[str], ix: Any) -> str:
        idx = int(ix.program_id_index)
        return account_keys[idx] if 0 <= idx < len(account_keys) else ""

    @staticmethod
    def _account_at(account_keys: list[str], ix: Any, slot: int) -> str:
        accounts = list(ix.accounts)
        if slot >= len(accounts):
            raise InvalidProofError(
                "invalid_exact_svm_payload_no_transfer_instruction",
                code="invalid_exact_svm_payload_no_transfer_instruction",
            )
        idx = int(accounts[slot])
        return account_keys[idx] if 0 <= idx < len(account_keys) else ""

    @staticmethod
    def _b58_field(requirement: dict[str, Any], key: str) -> str:
        value = requirement.get(key)
        if not isinstance(value, str) or value == "":
            raise InvalidProofError(
                f"invalid_exact_svm_payload_missing_field_{key}",
                code=f"invalid_exact_svm_payload_missing_field_{key}",
            )
        return value

    @staticmethod
    def _string_extra(requirement: dict[str, Any], key: str, *, required: bool) -> str | None:
        extra = requirement.get("extra")
        value = cast("dict[str, object]", extra).get(key) if isinstance(extra, dict) else None
        if (value is None or value == "") and required:
            raise InvalidProofError(
                f"invalid_exact_svm_payload_missing_extra_{key}",
                code=f"invalid_exact_svm_payload_missing_extra_{key}",
            )
        return value if isinstance(value, str) else None

    @staticmethod
    def _amount_field(requirement: dict[str, Any]) -> int:
        value = requirement.get("amount")
        if value is None:
            value = requirement.get("maxAmountRequired")
        if not isinstance(value, (str, int)):
            raise InvalidProofError(
                "invalid_exact_svm_payload_missing_field_amount",
                code="invalid_exact_svm_payload_missing_field_amount",
            )
        return int(value)
