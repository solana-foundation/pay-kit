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

from solana_pay_kit._paycore import txv1
from solana_pay_kit._paycore.mints import derive_ata
from solana_pay_kit._paycore.solana import TOKEN_PROGRAM as SPL_TOKEN_PROGRAM
from solana_pay_kit.errors import InvalidProofError

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
    "MAX_COMPUTE_UNIT_LIMIT",
    "accepted_transaction_versions",
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
#: Maximum compute unit limit the sponsor pays for (scheme_exact_svm.md
#: §2.2.1). Matches the Rust spine constant ``MAX_COMPUTE_UNIT_LIMIT``.
MAX_COMPUTE_UNIT_LIMIT = 400_000

_LIMIT_TOO_HIGH = "invalid_exact_svm_payload_transaction_instructions_compute_limit_instruction_too_high"
_PRICE_TOO_HIGH = "invalid_exact_svm_payload_transaction_instructions_compute_price_instruction_too_high"
_UNSUPPORTED_VERSION = "unsupported_transaction_version"


def _invalid(reason: str) -> InvalidProofError:
    return InvalidProofError(reason, code=reason)


def accepted_transaction_versions(requirement: dict[str, Any]) -> tuple[int, ...]:
    """The message versions the route accepts, from its ``extra.transactionVersions``.

    Absent means ``[0]`` (scheme_exact_svm.md §1.5); a present list is the
    accepted set verbatim. The route's own offer is server configuration, so
    a malformed list is a configuration error, not a payer error.
    """
    extra = requirement.get("extra")
    advertised = cast("dict[str, object]", extra).get("transactionVersions") if isinstance(extra, dict) else None
    try:
        return txv1.accepted_versions(txv1.parse_transaction_versions(advertised))
    except txv1.TransactionVersionError as exc:
        raise ValueError(f"solana_pay_kit: the route's extra.transactionVersions is invalid: {exc}") from exc


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
        try:
            raw = base64.b64decode(transaction_base64, validate=True)
        except Exception as exc:  # noqa: BLE001 - any decode failure is a reject
            raise _invalid("invalid_exact_svm_payload_base64") from exc
        if not raw:
            raise _invalid("invalid_exact_svm_payload_base64")

        # Legacy, version 0 and version 1 wires all decode; legacy is policed
        # as version 0 (scheme_exact_svm.md §1.5).
        try:
            tx = txv1.decode_transaction(raw)
        except Exception as exc:  # noqa: BLE001
            raise _invalid("invalid_exact_svm_payload_transaction_parse") from exc

        # §1.5: a version outside the accepted set is refused before any
        # instruction is inspected; then the per-version wire limits.
        accepted = accepted_transaction_versions(requirement)
        version = txv1.policy_version(tx.message)
        if version not in accepted:
            listed = ", ".join(str(v) for v in accepted)
            raise InvalidProofError(
                f"{_UNSUPPORTED_VERSION}: transaction version {version} is not accepted; accepted versions: {listed}",
                code=_UNSUPPORTED_VERSION,
            )
        try:
            txv1.check_envelope(tx, accepted)
        except txv1.TransactionVersionError as exc:
            raise InvalidProofError(
                f"invalid_exact_svm_payload_transaction: {exc}",
                code="invalid_exact_svm_payload_transaction",
            ) from exc

        message = tx.message
        instructions = list(message.instructions)
        account_keys = [str(key) for key in message.account_keys]
        # Version 1 carries its compute budget in the header, so its static
        # layout has no ComputeBudget prefix (rust ``verify_exact_versioned_transaction``).
        header_budget = version == 1
        if header_budget:
            ExactVerifier._verify_v1_config(message)

        # Rule 1: version 0 is [limit, price, transfer, <=4 optional] (3 to 7
        # instructions); version 1 is [transfer, <=4 optional].
        prefix = 0 if header_budget else 2
        n = len(instructions)
        if n < prefix + 1 or n > prefix + 5:
            raise _invalid("invalid_exact_svm_payload_transaction_instructions_length")

        if not header_budget:
            # Rule 2: ix[0] = ComputeBudget SetComputeUnitLimit (disc 2, 5 bytes, <= MAX).
            ExactVerifier._verify_compute_limit(instructions[0], account_keys)
            # Rule 3: ix[1] = ComputeBudget SetComputeUnitPrice (disc 3, 9 bytes, <= MAX).
            ExactVerifier._verify_compute_price(instructions[1], account_keys)
        # Rules 4 + 5 + 6 + 7 + 8 + 11: transferChecked.
        transfer = ExactVerifier._verify_transfer(instructions[prefix], account_keys, requirement, managed_signers)

        # §2.1.1: the fee payer (any managed signer) MUST NOT appear in the
        # accounts of ANY instruction, nor be invoked as a program. Checked
        # before the optional-instruction allowlist, as the Rust spine does, so
        # a sponsor-drain instruction is named for the fee payer it abuses.
        for ix in instructions:
            indexes = [int(ix.program_id_index), *(int(idx) for idx in bytes(ix.accounts))]
            for idx in indexes:
                key = account_keys[idx] if 0 <= idx < len(account_keys) else None
                if key is not None and key in managed_signers:
                    raise _invalid("invalid_exact_svm_payload_transaction_fee_payer_in_instruction_accounts")

        # Rule 9: optional-slot allowlist (scheme_exact_svm.md §3.1). Slots
        # 4-6 take Lighthouse (wallet-injected user-protection asserts) or SPL
        # Memo; slot 7 takes Memo only. A Create-ATA instruction is never
        # accepted: the destination ATA MUST pre-exist (Rule 7 pins it).
        reasons = (
            "invalid_exact_svm_payload_unknown_fourth_instruction",
            "invalid_exact_svm_payload_unknown_fifth_instruction",
            "invalid_exact_svm_payload_unknown_sixth_instruction",
            "invalid_exact_svm_payload_unknown_seventh_instruction",
        )
        for slot_index, ix in enumerate(instructions[prefix + 1 :]):
            program = ExactVerifier._program_of(account_keys, ix)
            if program == MEMO_PROGRAM or (slot_index < 3 and program == LIGHTHOUSE_PROGRAM):
                continue
            reason = (
                reasons[slot_index]
                if slot_index < len(reasons)
                else "invalid_exact_svm_payload_unknown_optional_instruction"
            )
            raise _invalid(reason)

        # Rule 10: memo binding (exactly one Memo == extra.memo if set).
        expected_memo = ExactVerifier._string_extra(requirement, "memo", required=False)
        if expected_memo:
            ExactVerifier._find_memo_match(account_keys, instructions[prefix + 1 :], expected_memo)

        # The sponsor pays whatever priority fee the client's limit and price
        # add up to: bound the product, not each factor (RULINGS S6).
        try:
            txv1.check_priority_fee(message, txv1.MAX_SPONSORED_PRIORITY_FEE_LAMPORTS)
        except txv1.TransactionVersionError as exc:
            raise InvalidProofError(f"{_PRICE_TOO_HIGH}: {exc}", code=_PRICE_TOO_HIGH) from exc

        # Only the fee payer and the transfer authority may sign: every extra
        # required signature is a base fee the sponsor pays (§2.1.4).
        required = int(message.header.num_required_signatures)
        allowed_signers: set[str] = {account_keys[0], str(transfer["authority"])} if account_keys else set()
        if any(key not in allowed_signers for key in account_keys[:required]):
            raise _invalid("invalid_exact_svm_payload_transaction_unexpected_signer")

        # The destination ATA must pre-exist; ATA-create is never accepted.
        transfer["destinationCreateAta"] = False
        transfer["transactionVersion"] = version
        return transfer

    @staticmethod
    def _verify_v1_config(message: Any) -> None:
        """Version-1 header budget rules (scheme_exact_svm.md §1.5, §2.2.1).

        Each rule with its own reason is checked first, in the Rust spine's
        order (``verify_v1_config_presence``): no ComputeBudget instruction
        (the runtime ignores them on version 1, so bounding one bounds
        nothing), no heap request, the compute unit limit and the
        loaded-account-data budget both set. Then the limit and price caps,
        and the remaining header bounds (a zero value, one over the runtime
        maximum). The loaded-data budget must be set, not the maximum.
        """
        keys = message.account_keys
        if any(
            int(ix.program_id_index) < len(keys) and keys[int(ix.program_id_index)] == txv1.COMPUTE_BUDGET_PROGRAM
            for ix in message.instructions
        ):
            raise _invalid("invalid_exact_svm_payload_transaction_v1_compute_budget_instruction")
        config = message.config
        if config.heap_size is not None:
            raise _invalid("invalid_exact_svm_payload_transaction_v1_heap_size")
        if config.compute_unit_limit is None:
            raise _invalid("invalid_exact_svm_payload_transaction_instructions_compute_limit_instruction")
        if config.loaded_accounts_data_size_limit is None:
            raise _invalid("invalid_exact_svm_payload_transaction_loaded_accounts_data_size_limit_missing")
        declared = txv1.declared_budget(message)
        if declared.unit_limit is not None and declared.unit_limit > MAX_COMPUTE_UNIT_LIMIT:
            raise _invalid(_LIMIT_TOO_HIGH)
        if (
            declared.unit_price_micro_lamports is not None
            and declared.unit_price_micro_lamports > MAX_COMPUTE_UNIT_PRICE
        ):
            raise _invalid(_PRICE_TOO_HIGH)
        try:
            txv1.check_v1_budget_caps(message, MAX_COMPUTE_UNIT_LIMIT, MAX_COMPUTE_UNIT_PRICE, loaded_rule="present")
        except txv1.TransactionVersionError as exc:
            raise InvalidProofError(
                f"invalid_exact_svm_payload_transaction: {exc}",
                code="invalid_exact_svm_payload_transaction",
            ) from exc

    @staticmethod
    def _verify_compute_limit(ix: Any, account_keys: list[str]) -> None:
        program = ExactVerifier._program_of(account_keys, ix)
        data = bytes(ix.data)
        if program != COMPUTE_BUDGET_PROGRAM or len(data) != 5 or data[0] != 2:
            raise InvalidProofError(
                "invalid_exact_svm_payload_transaction_instructions_compute_limit_instruction",
                code="invalid_exact_svm_payload_transaction_instructions_compute_limit_instruction",
            )
        if int.from_bytes(data[1:5], "little") > MAX_COMPUTE_UNIT_LIMIT:
            raise _invalid(_LIMIT_TOO_HIGH)

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
        # Rule 11: the transfer runs under an SPL token program (scheme §1.2:
        # "spl-token or token-2022"). A server that pins the non-spec
        # ``extra.tokenProgram`` hint binds it strictly; without the hint
        # either SPL program is accepted and the destination ATA (Rule 7) is
        # derived under the program actually used.
        token_program_extra = ExactVerifier._string_extra(requirement, "tokenProgram", required=False)
        allowed_programs = (
            (token_program_extra, TOKEN_2022_PROGRAM)
            if token_program_extra
            else (SPL_TOKEN_PROGRAM, TOKEN_2022_PROGRAM)
        )
        if program not in allowed_programs:
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

        # Rule 8: amount (u64 LE at data[1:9]) covers the requirement.
        # scheme_exact_svm.md §1.4: "A matching transfer MAY exceed
        # PaymentRequirements.amount ... it MUST NOT be less." Default
        # verifiers accept overpayment (RULINGS S5).
        amount = _u64_le(data, 1)
        expected_amount = ExactVerifier._amount_field(requirement)
        if amount < expected_amount:
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
    def _find_memo_match(account_keys: list[str], optional: list[Any], expected_memo: str) -> None:
        count = 0
        last_data: bytes | None = None
        for ix in optional:
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
