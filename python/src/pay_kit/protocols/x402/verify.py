"""x402 ``exact`` (Solana) adapter and self-hosted 11-rule verifier.

Self-hosted x402 ``exact`` scheme for the Solana SVM. ``X402Adapter`` issues
402 challenges, runs the structural 11-rule verifier on submitted credentials,
cosigns as the facilitator fee payer, broadcasts via the configured RPC, and
namespaces the consumed signature in the replay store. ``ExactVerifier``
follows the Rust spine rule-for-rule and reject-code-for-reject-code
(``rust/crates/x402/src/protocol/schemes/exact/verify.rs`` and the server
backstops at ``rust/crates/x402/src/server/exact.rs``), adding only
strictly-stronger defensive rejects; cross-checked against the PHP port at
``php/src/Protocols/X402/{Adapter,Exact/Verifier}.php``.

Delegated mode (``X402Config.facilitator_url`` set) is reserved in the config
schema but not yet wired; the adapter raises ``NotImplementedError`` when a
facilitator URL is configured. Self-hosted is the only x402 path that ships.
"""

from __future__ import annotations

import base64
import json
import struct
from collections.abc import Callable
from typing import TYPE_CHECKING, Any, TypedDict, cast

from pay_kit._paycore.mints import derive_ata, resolve, token_program_for
from pay_kit._paycore.network_check import check_network_blockhash
from pay_kit._paycore.protocol import Protocol
from pay_kit._paycore.rpc import SolanaRpc
from pay_kit._paycore.solana import ASSOCIATED_TOKEN_PROGRAM
from pay_kit._paycore.store import MemoryStore, Store
from pay_kit.errors import InvalidProofError
from pay_kit.payment import Payment

if TYPE_CHECKING:
    from pay_kit.config import Config
    from pay_kit.gate import Gate

__all__ = ["X402Adapter", "ExactVerifier", "X402_VERSION"]


# --- x402 wire shapes -------------------------------------------------------
# TypedDicts describing the exact JSON dicts the adapter builds for challenges/
# offers and parses from inbound credentials. They give the adapter precise
# static types over the wire payloads and never change the serialized bytes.
# Optional keys use ``total=False``. Inbound payloads are validated field-by-
# field at runtime and then narrowed to these shapes with ``cast``.


class X402ExtraRequired(TypedDict):
    """The always-present keys of an x402 ``accepts[].extra`` block."""

    feePayer: str
    decimals: int
    tokenProgram: str
    memo: str


class X402Extra(X402ExtraRequired, total=False):
    """An x402 ``accepts[].extra`` block; ``recentBlockhash`` is optional."""

    recentBlockhash: str


class X402Resource(TypedDict):
    """The ``resource`` block inside an x402 challenge."""

    type: str
    url: str


class X402AcceptsEntry(TypedDict):
    """One x402 ``accepts[]`` offer entry (the server requirement)."""

    protocol: str
    scheme: str
    network: str
    asset: str
    amount: str
    maxAmountRequired: str
    payTo: str
    maxTimeoutSeconds: int
    extra: X402Extra


class X402Challenge(TypedDict):
    """The base64-encoded ``payment-required`` challenge body."""

    x402Version: int
    resource: X402Resource
    accepts: list[X402AcceptsEntry]


class X402PayloadField(TypedDict, total=False):
    """The ``payload`` block of an inbound X-PAYMENT envelope."""

    transaction: str
    transactionHash: str


class X402Envelope(TypedDict, total=False):
    """An inbound X-PAYMENT envelope (decoded from the proof header).

    All keys optional because the structure is attacker-controlled and validated
    field-by-field at runtime before any value is trusted.
    """

    x402Version: int
    accepted: X402AcceptsEntry
    payload: X402PayloadField


class X402ResponseEnvelope(TypedDict):
    """The base64-encoded ``payment-response`` settlement receipt."""

    success: bool
    transaction: str
    network: str
    payer: str


#: x402 protocol version emitted in challenges and required on credentials.
X402_VERSION = 2

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

_SETTLEMENT_HEADER = "x-payment-settlement-signature"
_RESPONSE_HEADER = "payment-response"
_REPLAY_PREFIX = "x402-svm-exact:consumed:"


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
    cross-language interop harness substring-matches against. Mirrors the
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

        # Rule 9: ix[3:] allowlist (memo, lighthouse(<2 slots), ata-create(<2 slots)).
        destination_create_ata = False
        reasons = (
            "invalid_exact_svm_payload_unknown_fourth_instruction",
            "invalid_exact_svm_payload_unknown_fifth_instruction",
            "invalid_exact_svm_payload_unknown_sixth_instruction",
        )
        for i in range(3, n):
            ix = instructions[i]
            program = ExactVerifier._program_of(account_keys, ix)
            slot_index = i - 3
            allowed = program == MEMO_PROGRAM or (slot_index < 2 and program == LIGHTHOUSE_PROGRAM)
            if (
                not allowed
                and slot_index < 2
                and ExactVerifier._valid_ata_create(ix, account_keys, requirement, transfer)
            ):
                destination_create_ata = True
                allowed = True
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

        transfer["destinationCreateAta"] = destination_create_ata
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
    def _valid_ata_create(
        ix: Any,
        account_keys: list[str],
        requirement: dict[str, Any],
        transfer: dict[str, Any],
    ) -> bool:
        if ExactVerifier._program_of(account_keys, ix) != ASSOCIATED_TOKEN_PROGRAM:
            return False
        data = bytes(ix.data)
        if len(data) < 1 or (data[0] != 0 and data[0] != 1):
            return False
        if len(list(ix.accounts)) < 6:
            return False
        ata = ExactVerifier._account_at(account_keys, ix, 1)
        owner = ExactVerifier._account_at(account_keys, ix, 2)
        mint = ExactVerifier._account_at(account_keys, ix, 3)
        if owner != requirement.get("payTo"):
            return False
        if mint != transfer["mint"]:
            return False
        return ata == transfer["destination"]

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


class X402Adapter:
    """Self-hosted server adapter for the x402 ``exact`` Solana scheme."""

    def __init__(
        self,
        config: Config,
        replay_store: Store | None = None,
        recent_blockhash_provider: Callable[[], str | None] | None = None,
    ) -> None:
        """Build an adapter bound to ``config``; raise for delegated mode."""
        if config.x402.is_delegated():
            raise NotImplementedError(
                "pay_kit: x402 delegated mode is not yet implemented; "
                "leave X402Config.facilitator_url None for self-hosted"
            )
        self._config = config
        self._store: Store = replay_store if replay_store is not None else MemoryStore()
        self._recent_blockhash_provider = recent_blockhash_provider

    def accepts_entry(self, gate: Gate, request: Any) -> X402AcceptsEntry:
        """Build one ``accepts[]`` entry (the server x402 offer for ``gate``)."""
        coin = gate.amount.primary_coin()
        coin_value = coin.value if coin is not None else self._config.stablecoins[0].value
        label = self._config.network.mints_label()
        # x402 puts the on-chain mint pubkey on `asset`, not the ticker.
        # resolve() falls back to the mainnet row when the network row is
        # absent (caveat #1).
        asset = resolve(coin_value, label) or coin_value
        token_program = token_program_for(coin_value, label)
        pay_to = gate.pay_to or self._config.effective_recipient()
        amount = str(int(gate.total().amount * 1_000_000))
        signer = self._config.x402.effective_signer(self._config.operator)
        extra: X402Extra = {
            "feePayer": signer.pubkey() if signer is not None else "",
            "decimals": 6,
            "tokenProgram": token_program,
            "memo": _request_path(request),
        }
        # caveat #5: stamp the server's recent blockhash into accepted.extra
        # so pay-kit Rust clients sign against the same chain state the server
        # broadcasts to. Canonical TS/Go clients ignore it; harmless on real
        # networks. The provider keeps unit tests offline.
        blockhash = self._fetch_recent_blockhash()
        if blockhash is not None:
            extra["recentBlockhash"] = blockhash
        return {
            "protocol": "x402",
            "scheme": "exact",
            "network": self._caip2(),
            "asset": asset,
            "amount": amount,
            "maxAmountRequired": amount,
            "payTo": pay_to,
            "maxTimeoutSeconds": 60,
            "extra": extra,
        }

    def challenge_headers(self, gate: Gate, request: Any) -> dict[str, str]:
        """Build the ``payment-required`` header (base64 JSON challenge)."""
        challenge: X402Challenge = {
            "x402Version": X402_VERSION,
            "resource": {"type": "http", "url": _request_path(request)},
            "accepts": [self.accepts_entry(gate, request)],
        }
        payload = json.dumps(challenge, separators=(",", ":")).encode("utf-8")
        return {"payment-required": base64.b64encode(payload).decode("ascii")}

    async def verify_and_settle(self, gate: Gate, request: Any) -> Payment:
        """Verify the submitted x402 credential, cosign, broadcast, settle."""
        signer = self._config.x402.effective_signer(self._config.operator)
        if signer is None:
            raise InvalidProofError("pay_kit: x402 requires operator.signer", code="payment_invalid")

        header = _payment_signature_header(request)
        if not header:
            raise InvalidProofError("pay_kit: payment required", code="payment_required")

        try:
            decoded = base64.b64decode(header, validate=True)
        except Exception as exc:  # noqa: BLE001
            raise InvalidProofError(
                "invalid_exact_svm_payload_signature_base64",
                code="invalid_exact_svm_payload_signature_base64",
            ) from exc
        try:
            envelope = json.loads(decoded)
        except Exception as exc:  # noqa: BLE001
            raise InvalidProofError(
                "invalid_exact_svm_payload_signature_json",
                code="invalid_exact_svm_payload_signature_json",
            ) from exc

        if not isinstance(envelope, dict):
            raise InvalidProofError("unsupported_x402_version", code="unsupported_x402_version")
        # The envelope is attacker-controlled; it is validated field-by-field
        # below, then narrowed to the typed wire shape for the rest of the flow.
        envelope_map = cast("dict[str, object]", envelope)
        if envelope_map.get("x402Version") != X402_VERSION:
            raise InvalidProofError("unsupported_x402_version", code="unsupported_x402_version")
        accepted_raw = envelope_map.get("accepted")
        payload_raw = envelope_map.get("payload")
        if not isinstance(accepted_raw, dict) or not isinstance(payload_raw, dict):
            raise InvalidProofError(
                "invalid_exact_svm_payload_envelope",
                code="invalid_exact_svm_payload_envelope",
            )
        accepted = cast("dict[str, object]", accepted_raw)
        payload = cast("X402PayloadField", payload_raw)

        # Tier-2 identity-key match: the credential's accepted requirement must
        # match the server's freshly built offer for this route. x402 has no
        # HMAC-bound challenge id, so the offer is the source of truth and the
        # credential's `accepted` is never trusted for the route's parameters
        # (mirrors rust verify_pinned_fields + the targeted deepEqual gate).
        offer = self.accepts_entry(gate, request)
        offer_map = cast("dict[str, object]", offer)
        for key in ("scheme", "network", "asset", "payTo"):
            if accepted.get(key) != offer_map.get(key):
                raise InvalidProofError(
                    "pay_kit: charge_request_mismatch: accepted payment requirement does not match server challenge",
                    code="charge_request_mismatch",
                )
        if accepted.get("amount") != offer_map.get("amount") and accepted.get("maxAmountRequired") != offer_map.get(
            "maxAmountRequired"
        ):
            raise InvalidProofError(
                "pay_kit: charge_request_mismatch (amount)",
                code="charge_request_mismatch",
            )
        offer_extra = cast("dict[str, object]", offer_map.get("extra") or {})
        accepted_extra_raw = accepted.get("extra")
        accepted_extra = cast("dict[str, object]", accepted_extra_raw if isinstance(accepted_extra_raw, dict) else {})
        for key in ("feePayer", "tokenProgram", "memo"):
            if key in offer_extra and accepted_extra.get(key) != offer_extra[key]:
                raise InvalidProofError(
                    f"pay_kit: charge_request_mismatch (extra.{key})",
                    code="charge_request_mismatch",
                )

        tx_base64 = payload.get("transaction")
        if not isinstance(tx_base64, str) or tx_base64 == "":
            raise InvalidProofError(
                "invalid_exact_svm_payload_missing_transaction",
                code="invalid_exact_svm_payload_missing_transaction",
            )

        # Structural shape (11 rules) against the server offer.
        ExactVerifier.verify(tx_base64, cast("dict[str, Any]", offer), [signer.pubkey()])

        # Reject up-front if the client signed against the wrong cluster.
        # Skip on a loopback RPC where a Surfpool blockhash is expected.
        rpc_url = self._config.effective_rpc_url()
        if not _is_loopback_rpc(rpc_url):
            blockhash = _recent_blockhash_of(tx_base64)
            if blockhash is not None:
                check_network_blockhash(self._config.network.mints_label(), blockhash)

        # Cosign as the facilitator fee payer (slot-splice, version aware).
        cosigned_wire = _co_sign(tx_base64, signer)

        rpc = SolanaRpc(rpc_url)
        try:
            response = await rpc.send_raw_transaction(cosigned_wire)
            signature = str(response.value if hasattr(response, "value") else response)
        except Exception as exc:  # noqa: BLE001
            raise InvalidProofError(f"pay_kit: invalid proof: broadcast failed: {exc}", code="payment_invalid") from exc
        finally:
            await rpc.aclose()
        if not signature:
            raise InvalidProofError("pay_kit: empty broadcast result", code="payment_invalid")

        # Replay reservation. Namespace is distinct from the MPP charge key so
        # an x402 signature can never satisfy an MPP route and vice versa.
        if not await self._store.put_if_absent(_REPLAY_PREFIX + signature, True):
            raise InvalidProofError("pay_kit: signature_consumed", code="signature_consumed")

        accepted_network = accepted.get("network")
        response_body: X402ResponseEnvelope = {
            "success": True,
            "transaction": signature,
            "network": accepted_network if isinstance(accepted_network, str) and accepted_network else self._caip2(),
            "payer": payload.get("transactionHash", ""),
        }
        response_envelope = base64.b64encode(json.dumps(response_body, separators=(",", ":")).encode("utf-8")).decode(
            "ascii"
        )

        return Payment(
            protocol=Protocol.X402,
            transaction=signature,
            gate_name=gate.name,
            settlement_headers={
                _RESPONSE_HEADER: response_envelope,
                _SETTLEMENT_HEADER: signature,
            },
            raw=header,
        )

    def _fetch_recent_blockhash(self) -> str | None:
        if self._recent_blockhash_provider is not None:
            try:
                value = self._recent_blockhash_provider()
            except Exception:  # noqa: BLE001 - provider failures are non-fatal
                return None
            return value if isinstance(value, str) and value != "" else None
        return None

    def _caip2(self) -> str:
        return self._config.network.caip2()


def _co_sign(transaction_b64: str, signer: Any) -> bytes:
    """Splice the facilitator signature into the fee-payer slot, return wire.

    Legacy messages are signed over ``bytes(msg)``, v0 over
    ``to_bytes_versioned(msg)`` (0x80 prefix). The fee payer must occupy a
    signature slot. The v0-wire detector lives in the shared
    :mod:`pay_kit._paycore.transaction` core so neither protocol depends on the
    other.
    """
    from solders.message import to_bytes_versioned
    from solders.pubkey import Pubkey
    from solders.transaction import Transaction, VersionedTransaction

    from pay_kit._paycore.transaction import is_v0_wire_bytes

    raw = base64.b64decode(transaction_b64)
    fee_payer_pubkey = Pubkey.from_string(signer.pubkey())

    # SECURITY: ``solders.transaction.Transaction.from_bytes`` is lenient and
    # silently MIS-PARSES v0 ``VersionedTransaction`` wire bytes as a legacy
    # transaction (it does not raise), yielding a bogus header and garbage
    # account keys. The rust x402 client (and the canonical PaymentProof
    # builder) emit v0 messages, so we must route on the message-version
    # prefix byte rather than trusting a legacy parse to fail. Reuses the
    # shared ``is_v0_wire_bytes`` guard from ``pay_kit._paycore.transaction``
    # (no parallel detection logic; same routing as the MPP charge cosign).
    if is_v0_wire_bytes(raw):
        try:
            vtx = VersionedTransaction.from_bytes(raw)
        except Exception as exc:  # noqa: BLE001
            raise InvalidProofError(
                "invalid_exact_svm_payload_transaction_parse",
                code="invalid_exact_svm_payload_transaction_parse",
            ) from exc
        account_keys = list(vtx.message.account_keys)
        message_bytes = bytes(to_bytes_versioned(vtx.message))
        num_required = int(vtx.message.header.num_required_signatures)
    else:
        try:
            tx = Transaction.from_bytes(raw)
        except Exception:  # noqa: BLE001 - fall back to versioned
            try:
                vtx = VersionedTransaction.from_bytes(raw)
            except Exception as exc:  # noqa: BLE001
                raise InvalidProofError(
                    "invalid_exact_svm_payload_transaction_parse",
                    code="invalid_exact_svm_payload_transaction_parse",
                ) from exc
            account_keys = list(vtx.message.account_keys)
            message_bytes = bytes(to_bytes_versioned(vtx.message))
            num_required = int(vtx.message.header.num_required_signatures)
        else:
            account_keys = list(tx.message.account_keys)
            message_bytes = bytes(tx.message)
            num_required = int(tx.message.header.num_required_signatures)

    try:
        idx = account_keys.index(fee_payer_pubkey)
    except ValueError as exc:
        raise InvalidProofError(
            "pay_kit: fee payer pubkey not present in transaction accounts",
            code="payment_invalid",
        ) from exc
    if idx >= num_required:
        raise InvalidProofError("pay_kit: fee payer is not a required signer", code="payment_invalid")

    sig_bytes = bytes(signer.sign(message_bytes))
    serialized = bytearray(raw)
    sig_start = 1 + idx * 64
    serialized[sig_start : sig_start + 64] = sig_bytes
    return bytes(serialized)


def _recent_blockhash_of(transaction_b64: str) -> str | None:
    """Best-effort extract of the recent blockhash for the network check."""
    from solders.transaction import VersionedTransaction

    try:
        raw = base64.b64decode(transaction_b64)
        tx = VersionedTransaction.from_bytes(raw)
        return str(tx.message.recent_blockhash)
    except Exception:  # noqa: BLE001 - the verifier already validated shape
        return None


def _is_loopback_rpc(rpc_url: str) -> bool:
    """True if ``rpc_url`` points at a loopback host (mirror rust)."""
    stripped = rpc_url.strip()
    for prefix in ("http://", "https://", "ws://", "wss://"):
        if stripped.startswith(prefix):
            stripped = stripped[len(prefix) :]
            break
    host_and_rest = stripped.split("/", 1)[0]
    host = host_and_rest[1:].split("]", 1)[0] if host_and_rest.startswith("[") else host_and_rest.split(":", 1)[0]
    return host in {"127.0.0.1", "localhost", "::1", "0.0.0.0"}


def _request_path(request: Any) -> str:
    """Resolve the request path across framework request shapes."""
    path = getattr(request, "path", None)
    if isinstance(path, str):
        return path
    url = getattr(request, "url", None)
    if url is not None:
        url_path = getattr(url, "path", None)
        if isinstance(url_path, str):
            return url_path
    if isinstance(request, dict):
        candidate = cast("dict[str, object]", request).get("path")
        if isinstance(candidate, str):
            return candidate
    return "/"


def _payment_signature_header(request: Any) -> str:
    """Read the ``Payment-Signature`` header across framework request shapes."""
    headers = getattr(request, "headers", None)
    if headers is not None:
        getter = getattr(headers, "get", None)
        if callable(getter):
            for name in ("payment-signature", "Payment-Signature", "PAYMENT-SIGNATURE"):
                value: object = getter(name)
                if value:
                    return str(value)
    if isinstance(request, dict):
        raw_headers = cast("dict[str, object]", request).get("headers")
        if isinstance(raw_headers, dict):
            for key, header_value in cast("dict[object, object]", raw_headers).items():
                if isinstance(key, str) and key.lower() == "payment-signature" and header_value:
                    return str(header_value)
    return ""
