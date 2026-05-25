from __future__ import annotations

import json
import os
import signal
import sys
import base64
import binascii
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from solders.message import to_bytes_versioned
from solders.pubkey import Pubkey
from solders.transaction import VersionedTransaction
from spl.token.constants import TOKEN_2022_PROGRAM_ID, TOKEN_PROGRAM_ID
from spl.token.instructions import get_associated_token_address

from x402.interop.exact import keypair_from_json_secret

CAPABILITY_PAYLOAD = {
    "implementation": "python",
    "role": "server",
    "capabilities": ["exact"],
}

DEFAULT_RESOURCE_PATH = "/protected"
DEFAULT_PRICE = "$0.001"
DEFAULT_SETTLEMENT_HEADER = "x-fixture-settlement"
DEFAULT_TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
DEFAULT_TOKEN_2022_PROGRAM = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
DEFAULT_TOKEN_DECIMALS = 6
DEFAULT_MAX_TIMEOUT_SECONDS = 60
MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS = 5_000_000
SETTLEMENT_CACHE_TTL_SECONDS = 120
COMPUTE_BUDGET_PROGRAM_ID = Pubkey.from_string("ComputeBudget111111111111111111111111111111")
MEMO_PROGRAM_ID = Pubkey.from_string("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr")
LIGHTHOUSE_PROGRAM_ID = Pubkey.from_string("L2TExMFKdjpN9kozasaurPirfHy9P8sbXoAN1qA3S95")
TOKEN_2022_STABLECOIN_MINTS = {
    "2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo",
    "CXk2AMBfi3TwaEL2468s6zP8xq9NxTXjp9gjMgzeUynM",
    "2u1tszSeqZ3qBWF3uNGPFc8TzMk2tdiwknnRMWGWjGWH",
    "4F6PM96JJxngmHnZLBh9n58RH4aTVNWvDs2nuwrT5BP7",
    "CASHx9KJUStyftLFWGvEVf59SGeG9sh5FfcnZMVPCASH",
}

def _required_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


def _normalize_amount(price: str) -> str:
    amount = price.strip().removeprefix("$").split()[0]
    whole, dot, fraction = amount.partition(".")
    if len(fraction) > DEFAULT_TOKEN_DECIMALS:
        raise RuntimeError(f"X402_INTEROP_PRICE has too many decimal places: {price}")
    fraction = fraction.ljust(DEFAULT_TOKEN_DECIMALS, "0")
    return str((int(whole) * 1_000_000) + int(fraction or "0"))


class ServerState:
    def __init__(self) -> None:
        self.rpc_url = _required_env("X402_INTEROP_RPC_URL")
        self.network = os.environ.get(
            "X402_INTEROP_NETWORK",
            "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
        )
        self.mint = os.environ.get(
            "X402_INTEROP_MINT",
            "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
        )
        self.pay_to = _required_env("X402_INTEROP_PAY_TO")
        self.fee_payer = keypair_from_json_secret(
            _required_env("X402_INTEROP_FACILITATOR_SECRET_KEY")
        )
        self.amount = _normalize_amount(os.environ.get("X402_INTEROP_PRICE", DEFAULT_PRICE))
        self.extra_offered_mints = [
            mint.strip()
            for mint in os.environ.get("X402_INTEROP_EXTRA_OFFERED_MINTS", "").split(",")
            if mint.strip()
        ]
        self.settlement_cache: dict[str, float] = {}
        self.settlement_cache_lock = threading.Lock()


def exact_requirement(state: ServerState) -> dict[str, Any]:
    return exact_requirement_for_mint(state, state.mint)


def exact_requirement_for_mint(state: ServerState, mint: str) -> dict[str, Any]:
    return {
        "scheme": "exact",
        "network": state.network,
        "asset": mint,
        "amount": state.amount,
        "payTo": state.pay_to,
        "maxTimeoutSeconds": DEFAULT_MAX_TIMEOUT_SECONDS,
        "extra": {
            "feePayer": str(state.fee_payer.pubkey()),
            "decimals": DEFAULT_TOKEN_DECIMALS,
            "tokenProgram": _default_token_program_for_mint(mint),
        },
    }


def exact_requirements(state: ServerState) -> list[dict[str, Any]]:
    return [
        exact_requirement_for_mint(state, mint)
        for mint in [state.mint, *getattr(state, "extra_offered_mints", [])]
    ]


def exact_challenge(state: ServerState) -> dict[str, Any]:
    return {
        "x402Version": 2,
        "resource": {
            "type": "http",
            "uri": DEFAULT_RESOURCE_PATH,
        },
        "accepts": exact_requirements(state),
    }


def _default_token_program_for_mint(mint: str) -> str:
    return (
        DEFAULT_TOKEN_2022_PROGRAM
        if mint in TOKEN_2022_STABLECOIN_MINTS
        else DEFAULT_TOKEN_PROGRAM
    )


def _header_value(headers: dict[str, str], name: str) -> str | None:
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return None


def _payment_requirement_matches(left: dict[str, Any], right: dict[str, Any]) -> bool:
    # Canonical v2 matching is structural: the client must echo one offered
    # accepted object without adding, dropping, or rewriting fields.
    return left == right


def _decode_payment_signature_header(payment_header: str) -> dict[str, Any]:
    try:
        decoded = base64.b64decode(payment_header, validate=True)
    except (binascii.Error, ValueError) as error:
        raise RuntimeError("invalid PAYMENT-SIGNATURE: invalid base64") from error

    try:
        loaded = json.loads(decoded.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("invalid PAYMENT-SIGNATURE: invalid json") from error

    if not isinstance(loaded, dict):
        raise RuntimeError("invalid PAYMENT-SIGNATURE: expected object")
    return loaded


def _decode_versioned_transaction(encoded_transaction: str) -> VersionedTransaction:
    try:
        transaction_bytes = base64.b64decode(encoded_transaction, validate=True)
        return VersionedTransaction.from_bytes(transaction_bytes)
    except Exception as error:
        raise RuntimeError("invalid_exact_svm_payload_transaction_could_not_be_decoded") from error


def _instruction_program(instruction: Any, account_keys: list[Pubkey]) -> Pubkey:
    try:
        return account_keys[instruction.program_id_index]
    except IndexError as error:
        raise RuntimeError("invalid_exact_svm_payload_no_transfer_instruction") from error


def _instruction_account(index: int, instruction: Any, account_keys: list[Pubkey]) -> Pubkey:
    try:
        return account_keys[instruction.accounts[index]]
    except IndexError as error:
        raise RuntimeError("invalid_exact_svm_payload_no_transfer_instruction") from error


def _verify_compute_limit_instruction(instruction: Any, account_keys: list[Pubkey]) -> None:
    # Parity note: the compute-unit *limit* value itself is intentionally NOT
    # bounded here. Only the program id, payload length (5 bytes) and the
    # SetComputeUnitLimit discriminator (0x02) are validated. This matches the
    # canonical spine implementations:
    #   - Rust:       rust/src/protocol/schemes/exact/verify.rs (verify_compute_limit_instruction, ~L317)
    #   - TypeScript: typescript/packages/x402/src/facilitator/exact/scheme.ts (verifyComputeLimitInstruction, ~L444)
    # Both only enforce program/length/discriminator and leave the CU limit
    # itself unbounded; only the compute *price* is capped (see
    # MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS below). Diverging here would break
    # cross-implementation parity. A protocol-wide CU-limit cap is tracked as a
    # follow-up to be decided in the Rust spine first.
    if (
        _instruction_program(instruction, account_keys) != COMPUTE_BUDGET_PROGRAM_ID
        or len(instruction.data) != 5
        or instruction.data[0] != 2
    ):
        raise RuntimeError(
            "invalid_exact_svm_payload_transaction_instructions_compute_limit_instruction"
        )


def _verify_compute_price_instruction(instruction: Any, account_keys: list[Pubkey]) -> None:
    if (
        _instruction_program(instruction, account_keys) != COMPUTE_BUDGET_PROGRAM_ID
        or len(instruction.data) != 9
        or instruction.data[0] != 3
    ):
        raise RuntimeError(
            "invalid_exact_svm_payload_transaction_instructions_compute_price_instruction"
        )
    micro_lamports = int.from_bytes(bytes(instruction.data[1:9]), "little")
    if micro_lamports > MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS:
        raise RuntimeError(
            "invalid_exact_svm_payload_transaction_instructions_compute_price_instruction_too_high"
        )


def _expected_memo(requirement: dict[str, Any]) -> str | None:
    extra = requirement.get("extra")
    memo = extra.get("memo") if isinstance(extra, dict) else None
    return memo if isinstance(memo, str) else None


def _verify_transfer_instruction(
    instruction: Any,
    account_keys: list[Pubkey],
    requirement: dict[str, Any],
    fee_payer: Pubkey,
) -> None:
    program = _instruction_program(instruction, account_keys)
    if program not in (TOKEN_PROGRAM_ID, TOKEN_2022_PROGRAM_ID):
        raise RuntimeError("invalid_exact_svm_payload_no_transfer_instruction")
    if len(instruction.accounts) < 4 or len(instruction.data) != 10 or instruction.data[0] != 12:
        raise RuntimeError("invalid_exact_svm_payload_no_transfer_instruction")

    source = _instruction_account(0, instruction, account_keys)
    mint = _instruction_account(1, instruction, account_keys)
    destination = _instruction_account(2, instruction, account_keys)
    authority = _instruction_account(3, instruction, account_keys)

    if fee_payer in (source, authority):
        raise RuntimeError("invalid_exact_svm_payload_transaction_fee_payer_transferring_funds")

    expected_mint = Pubkey.from_string(str(requirement["asset"]))
    if mint != expected_mint:
        raise RuntimeError("invalid_exact_svm_payload_mint_mismatch")

    expected_destination = get_associated_token_address(
        Pubkey.from_string(str(requirement["payTo"])),
        expected_mint,
        program,
    )
    if destination != expected_destination:
        raise RuntimeError("invalid_exact_svm_payload_recipient_mismatch")

    amount = int.from_bytes(bytes(instruction.data[1:9]), "little")
    if amount != int(str(requirement["amount"])):
        raise RuntimeError("invalid_exact_svm_payload_amount_mismatch")


def _verify_optional_instructions(
    instructions: list[Any],
    account_keys: list[Pubkey],
    requirement: dict[str, Any],
) -> None:
    invalid_reason_by_index = [
        "invalid_exact_svm_payload_unknown_fourth_instruction",
        "invalid_exact_svm_payload_unknown_fifth_instruction",
        "invalid_exact_svm_payload_unknown_sixth_instruction",
    ]
    memo_instructions = []
    for index, instruction in enumerate(instructions):
        program = _instruction_program(instruction, account_keys)
        if program == MEMO_PROGRAM_ID:
            memo_instructions.append(instruction)
            continue
        if program == LIGHTHOUSE_PROGRAM_ID:
            # Parity note: Lighthouse instructions are accepted *unconditionally*
            # (no discriminator allowlist, no account-count bound). This matches
            # the canonical spine implementations:
            #   - Rust:       rust/src/protocol/schemes/exact/verify.rs L260-272
            #                 (`program == programs::LIGHTHOUSE_PROGRAM` -> continue)
            #   - TypeScript: typescript/packages/x402/src/facilitator/exact/scheme.ts L289-296
            #                 (`programAddress === LIGHTHOUSE_PROGRAM_ADDRESS` -> continue)
            # A bounded Lighthouse discriminator/account allowlist would be a
            # protocol-wide hardening (the facilitator co-signs and therefore
            # pays compute fees for any Lighthouse payload); diverging unilaterally
            # would break cross-implementation parity. Tracked separately for the
            # Rust spine in notes/lighthouse-allowlist-tracking.md.
            continue
        raise RuntimeError(
            invalid_reason_by_index[index]
            if index < len(invalid_reason_by_index)
            else "invalid_exact_svm_payload_unknown_optional_instruction"
        )

    expected_memo = _expected_memo(requirement)
    if expected_memo is None:
        return
    if len(memo_instructions) != 1:
        raise RuntimeError("invalid_exact_svm_payload_memo_count")
    try:
        actual_memo = bytes(memo_instructions[0].data).decode("utf-8")
    except UnicodeDecodeError as error:
        raise RuntimeError("invalid_exact_svm_payload_memo_mismatch") from error
    if actual_memo != expected_memo:
        raise RuntimeError("invalid_exact_svm_payload_memo_mismatch")


def _verify_exact_transaction(
    transaction: VersionedTransaction,
    requirement: dict[str, Any],
    fee_payer: Pubkey,
) -> None:
    account_keys = list(transaction.message.account_keys)
    instructions = list(transaction.message.instructions)
    if not 3 <= len(instructions) <= 6:
        raise RuntimeError("invalid_exact_svm_payload_transaction_instructions_length")
    for instruction in instructions:
        for account_index in instruction.accounts:
            try:
                account = account_keys[account_index]
            except IndexError as error:
                raise RuntimeError("invalid_exact_svm_payload_no_transfer_instruction") from error
            if account == fee_payer:
                raise RuntimeError(
                    "invalid_exact_svm_payload_transaction_fee_payer_transferring_funds"
                )

    _verify_compute_limit_instruction(instructions[0], account_keys)
    _verify_compute_price_instruction(instructions[1], account_keys)
    _verify_transfer_instruction(instructions[2], account_keys, requirement, fee_payer)
    _verify_optional_instructions(instructions[3:], account_keys, requirement)


def _settlement_cache(state: ServerState) -> dict[str, float]:
    cache = getattr(state, "settlement_cache", None)
    if not isinstance(cache, dict):
        raise RuntimeError(
            "server_state_missing_settlement_cache: state must eagerly initialise"
            " 'settlement_cache' as a dict (see ServerState.__init__)"
        )
    return cache


def _settlement_cache_lock(state: ServerState) -> threading.Lock:
    lock = getattr(state, "settlement_cache_lock", None)
    if lock is None or not hasattr(lock, "acquire") or not hasattr(lock, "release"):
        raise RuntimeError(
            "server_state_missing_settlement_cache_lock: state must eagerly"
            " initialise 'settlement_cache_lock' as a threading.Lock (see"
            " ServerState.__init__)"
        )
    return lock


def _claim_settlement_payload(state: ServerState, transaction_payload: str) -> None:
    with _settlement_cache_lock(state):
        now = time.monotonic()
        cache = _settlement_cache(state)
        expired = [
            key
            for key, claimed_at in cache.items()
            if now - claimed_at > SETTLEMENT_CACHE_TTL_SECONDS
        ]
        for key in expired:
            del cache[key]
        if transaction_payload in cache:
            raise RuntimeError("duplicate_settlement")
        cache[transaction_payload] = now


def _release_settlement_payload(state: ServerState, transaction_payload: str) -> None:
    with _settlement_cache_lock(state):
        _settlement_cache(state).pop(transaction_payload, None)


def _send_transaction(state: ServerState, transaction: VersionedTransaction) -> str:
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "sendTransaction",
            "params": [
                base64.b64encode(bytes(transaction)).decode("ascii"),
                {
                    "encoding": "base64",
                    "skipPreflight": False,
                    "preflightCommitment": "processed",
                    "maxRetries": 3,
                },
            ],
        },
        separators=(",", ":"),
    ).encode("utf-8")
    request = urllib.request.Request(
        state.rpc_url,
        data=body,
        headers={"content-type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        payload = json.loads(response.read().decode("utf-8"))
    if payload.get("error"):
        raise RuntimeError(f"sendTransaction RPC error: {payload['error']}")
    result = payload.get("result")
    if not isinstance(result, str) or not result:
        raise RuntimeError("sendTransaction returned empty signature")
    return result


def settle_exact_payment(state: ServerState, payment_header: str) -> str:
    decoded = _decode_payment_signature_header(payment_header)
    if decoded.get("x402Version") != 2:
        raise RuntimeError(f"unsupported x402Version: {decoded.get('x402Version')}")
    accepted = decoded.get("accepted")
    requirement = None
    if isinstance(accepted, dict):
        requirement = next(
            (
                offered
                for offered in exact_requirements(state)
                if _payment_requirement_matches(accepted, offered)
            ),
            None,
        )
    if requirement is None:
        # Canonical cross-server reject token. Mirrors the Go interop server's
        # reject-body shape (go/cmd/interop-server/main.go ~L856:
        # `{"error": "payment_invalid", "message": err.Error()}`) and the
        # canonical phrase enumerated in tests/interop cross-server-scenarios.
        # Surfacing "No matching payment requirements" lets cross-server replay
        # tests detect that a credential issued for a different server's
        # accepted requirements was correctly rejected by this server.
        raise RuntimeError(
            "No matching payment requirements: accepted credential does not"
            " match any offered payment option for this server"
        )
    payload = decoded.get("payload")
    if (
        not isinstance(payload, dict)
        or not isinstance(payload.get("transaction"), str)
        or not payload.get("transaction")
    ):
        raise RuntimeError("payment payload is missing transaction")

    transaction_payload = payload["transaction"]
    transaction = _decode_versioned_transaction(transaction_payload)
    fee_payer = Pubkey.from_string(str(state.fee_payer.pubkey()))
    _verify_exact_transaction(transaction, requirement, fee_payer)
    _claim_settlement_payload(state, transaction_payload)
    signatures = list(transaction.signatures)
    account_keys = list(transaction.message.account_keys)
    if fee_payer not in account_keys:
        _release_settlement_payload(state, transaction_payload)
        raise RuntimeError("fee payer not found in transaction accounts")
    signer_index = account_keys.index(fee_payer)
    if signer_index >= len(signatures):
        _release_settlement_payload(state, transaction_payload)
        raise RuntimeError("fee payer is not a required transaction signer")

    signatures[signer_index] = state.fee_payer.sign_message(
        to_bytes_versioned(transaction.message)
    )
    signed = VersionedTransaction.populate(transaction.message, signatures)
    try:
        signed.verify_and_hash_message()
        return _send_transaction(state, signed)
    except Exception:
        _release_settlement_payload(state, transaction_payload)
        raise


class InteropHandler(BaseHTTPRequestHandler):
    @staticmethod
    def payment_error_body(error: Exception) -> dict[str, object]:
        # Mirrors the Go interop server reject body shape
        # (go/cmd/interop-server/main.go ~L855-L858): use `payment_invalid` as
        # the canonical error key so cross-server reject scenarios in
        # tests/interop can match the body against the canonical token list
        # (`payment_invalid`, `No matching payment requirements`, ...).
        reason = str(error)
        return {
            "error": "payment_invalid",
            "message": reason,
            "invalidReason": reason,
        }

    def do_GET(self) -> None:
        if self.path == "/health":
            self._write_json(200, {"ok": True})
            return

        if self.path == "/capabilities":
            self._write_json(200, CAPABILITY_PAYLOAD)
            return

        if self.path == "/exact":
            self._write_json(
                402,
                {
                    "error": "payment_required",
                },
                payment_required=exact_challenge(self.server.state),
            )
            return

        if self.path != DEFAULT_RESOURCE_PATH:
            self._write_json(404, {"error": "not_found"})
            return

        payment_signature = _header_value(dict(self.headers.items()), "PAYMENT-SIGNATURE")
        if not payment_signature:
            self._write_json(
                402,
                {"error": "payment_required"},
                payment_required=exact_challenge(self.server.state),
            )
            return

        try:
            settlement = settle_exact_payment(self.server.state, payment_signature)
        except Exception as error:
            self._write_json(
                402,
                self.payment_error_body(error),
                payment_required=exact_challenge(self.server.state),
            )
            return

        self._write_json(
            200,
            {
                "ok": True,
                "paid": True,
                "settlement": {
                    "success": True,
                    "transaction": settlement,
                    "network": self.server.state.network,
                },
            },
            headers={DEFAULT_SETTLEMENT_HEADER: settlement},
        )

    def log_message(self, format: str, *args: object) -> None:
        return

    def _write_json(
        self,
        status: int,
        body: dict[str, object],
        payment_required: dict[str, object] | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        encoded = json.dumps(body, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(encoded)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        if payment_required is not None:
            header = base64.b64encode(
                json.dumps(payment_required, separators=(",", ":")).encode("utf-8")
            ).decode("ascii")
            self.send_header("PAYMENT-REQUIRED", header)
        self.end_headers()
        self.wfile.write(encoded)


def main() -> int:
    state = ServerState()
    server = ThreadingHTTPServer(("127.0.0.1", 0), InteropHandler)
    server.state = state

    def shutdown(_signum: int, _frame: object) -> None:
        server.shutdown()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    print(
        json.dumps(
            {
                "type": "ready",
                "implementation": "python",
                "role": "server",
                "port": server.server_port,
                **CAPABILITY_PAYLOAD,
            }
        ),
        flush=True,
    )
    server.serve_forever()
    server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
