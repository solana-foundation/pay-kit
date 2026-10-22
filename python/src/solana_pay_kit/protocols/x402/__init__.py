"""x402 ``exact`` (Solana) adapter package.

Self-hosted x402 ``exact`` scheme for the Solana SVM. ``X402Adapter`` (this
module) issues 402 challenges, runs the structural 11-rule verifier on
submitted credentials, cosigns as the facilitator fee payer, broadcasts via
the configured RPC, and reserves the consumed signature in the replay store
under the ledger key it shares with MPP charge.
The verifier, module constants, and ``X402*`` wire TypedDicts live under
:mod:`solana_pay_kit.protocols.x402.exact`; the client builder lives under
:mod:`solana_pay_kit.protocols.x402.client`.

Delegated mode (``X402Config.facilitator_url`` set) is reserved in the config
schema but not yet wired; the adapter raises ``NotImplementedError`` when a
facilitator URL is configured. Self-hosted is the only x402 path that ships.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, cast

from solana_pay_kit._paycore.currency import parse_units
from solana_pay_kit._paycore.mints import resolve, token_program_for
from solana_pay_kit._paycore.network_check import check_network_blockhash
from solana_pay_kit._paycore.protocol import Protocol
from solana_pay_kit._paycore.rpc import (
    PreflightRejectedError,
    SolanaRpc,
    _RpcError,  # pyright: ignore[reportPrivateUsage]
    proves_settlement_failed,
)
from solana_pay_kit._paycore.store import (
    ConsumedSignatures,
    MemoryStore,
    Store,
    consumed_before_ledger,
    consumed_signature_key,
)
from solana_pay_kit._paycore.transaction import SignatureCheckError, verify_required_signatures
from solana_pay_kit.errors import ConfigurationError, InvalidProofError, SettlementInProgressError
from solana_pay_kit.payment import Payment
from solana_pay_kit.protocols.x402.exact.extensions import PaymentIdentifierError, verify_payment_identifier
from solana_pay_kit.protocols.x402.exact.legacy import (
    X402_LEGACY_PAYMENT_HEADER,
    caip2_for_network,
)
from solana_pay_kit.protocols.x402.exact.types import (
    X402AcceptsEntry,
    X402Challenge,
    X402Extra,
    X402PayloadField,
    X402ResponseEnvelope,
)
from solana_pay_kit.protocols.x402.exact.verify import (
    EXACT_SCHEME,
    X402_VERSION,
    X402_VERSION_V1,
    X402_VERSION_V2,
    ExactVerifier,
)

if TYPE_CHECKING:
    from solana_keychain import TransactionSigner

    from solana_pay_kit.config import Config
    from solana_pay_kit.gate import Gate

__all__ = ["X402Adapter", "ExactVerifier", "VerifiedExactCredential", "X402_VERSION", "verify_exact_credential"]


_SETTLEMENT_HEADER = "x-payment-settlement-signature"
_RESPONSE_HEADER = "payment-response"
# Legacy v1 clients read the settlement receipt under X-PAYMENT-RESPONSE; the
# server must echo it there when it accepted a v1 credential (rust
# X402_V1_PAYMENT_RESPONSE_HEADER, constants.rs:22).
_RESPONSE_HEADER_LEGACY = "x-payment-response"
# `SolanaRpc.await_confirmation` performs at most 40 requests, each with the
# client's 30-second timeout, plus polling delays. Keep the recovery lease past
# that complete worst-case window so a takeover cannot overlap the original
# confirmation coroutine.
_PENDING_LEASE_SECONDS = 21 * 60


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
                "solana_pay_kit: x402 delegated mode is not yet implemented; "
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
        # Exact 6-decimal base-unit conversion. ``int(amount * 1_000_000)``
        # silently truncated sub-microunit precision (usd("0.0000009") -> "0"),
        # which would have the verifier accept a zero-amount transfer. Reuse the
        # shared core ``parse_units`` helper so over-precision is rejected the
        # same way MPP rejects it; surface it as a ConfigurationError at
        # offer-build time.
        try:
            amount = parse_units(gate.total().amount_string(), 6)
        except ValueError as exc:
            raise ConfigurationError(
                f"solana_pay_kit: x402 price {gate.total().amount_string()!r} "
                "exceeds 6-decimal (micro-unit) precision; USDC settles in micro-units"
            ) from exc
        signer = self._config.x402.effective_signer(self._config.operator)
        extra: X402Extra = {
            "feePayer": str(signer.pubkey) if signer is not None else "",
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
            raise InvalidProofError("solana_pay_kit: x402 requires operator.signer", code="payment_invalid")

        # Dual-accept: read the canonical (v2) ``Payment-Signature`` header
        # FIRST, then fall back to the legacy ``X-PAYMENT`` header. Mirrors rust
        # ``parse_payment_signature`` being driven from both header names
        # (server/exact.rs) and the dual-accept rule: a v2 server must NOT reject
        # a legacy credential, but still rejects genuinely-unknown versions.
        header = _payment_signature_header(request)
        if not header:
            header = _legacy_payment_header(request)
        if not header:
            raise InvalidProofError("solana_pay_kit: payment required", code="payment_required")

        # The server's freshly built offer for this route is the source of truth
        # for the route's parameters in BOTH wire shapes; the credential is never
        # trusted for them.
        offer = self.accepts_entry(gate, request)
        verified = await verify_exact_credential(header, offer, signer, require_payment_identifier=False)
        version = verified.version
        accepted = verified.accepted
        payload = verified.payload
        tx_base64 = verified.transaction
        cosigned_wire = verified.cosigned_wire

        # Reject up-front if the client signed against the wrong cluster.
        # Skip on a loopback RPC where a Surfpool blockhash is expected.
        rpc_url = self._config.effective_rpc_url()
        if not _is_loopback_rpc(rpc_url):
            blockhash = _recent_blockhash_of(tx_base64)
            if blockhash is not None:
                check_network_blockhash(self._config.network.mints_label(), blockhash)

        signature = _transaction_signature(cosigned_wire)
        # The ledger shared with MPP charge, so a payment settled through either
        # protocol cannot authorize a second request through the other.
        replay_key = consumed_signature_key(signature)
        binding = hashlib.sha256(cosigned_wire).hexdigest()
        now = time.time()
        replay_record: dict[str, object] = {
            "binding": binding,
            "leaseUntil": now + _PENDING_LEASE_SECONDS,
            "state": "pending",
        }

        if await consumed_before_ledger(self._store, signature):
            raise InvalidProofError("solana_pay_kit: signature_consumed", code="signature_consumed")
        current = await self._store.get(replay_key)
        should_broadcast = current is None
        skip_confirmation = False
        if current is not None:
            skip_confirmation = await _recover_replay_record(
                self._store, replay_key, binding, replay_record, current, now
            )

        rpc: SolanaRpc | None = None
        sent_here = False
        try:
            if should_broadcast:
                ledger = ConsumedSignatures(self._store)
                # Record the pending settlement with the claim, before anything
                # is sent. Written only after the send, a store failure would
                # leave a payment that may have landed with no record, and the
                # retry would find it already processed and refuse it.
                if not await ledger.claim(signature, replay_record):
                    current = await self._store.get(replay_key)
                    skip_confirmation = await _recover_replay_record(
                        self._store, replay_key, binding, replay_record, current, now
                    )
                else:
                    rpc = SolanaRpc(rpc_url)
                    try:
                        response = await rpc.send_raw_transaction(cosigned_wire)
                        broadcast_signature = str(response.value if hasattr(response, "value") else response)
                    except PreflightRejectedError as exc:
                        # The one send failure that proves no node was handed
                        # the transaction: the claim is given back, the payer
                        # may retry.
                        await ledger.release(signature)
                        raise InvalidProofError(
                            f"solana_pay_kit: invalid proof: broadcast failed: {exc}", code="payment_invalid"
                        ) from exc
                    except _RpcError as exc:
                        if exc.code != "signature_consumed":
                            raise _settlement_in_progress(signature, f"broadcast outcome unknown: {exc}") from exc
                        # The node already processed this exact transaction,
                        # yet this store held no settlement of it: it was
                        # settled somewhere this store cannot see (another
                        # instance or store, or before a restart). Serving it
                        # again would grant one payment twice: refuse it, and
                        # keep it consumed here.
                        await self._store.put(replay_key, True)
                        raise InvalidProofError(
                            "solana_pay_kit: signature_consumed: the transaction was already processed",
                            code="signature_consumed",
                        ) from exc
                    except Exception as exc:  # noqa: BLE001
                        # A lost response, a timeout, a refusal other than a
                        # preflight rejection: the transaction may still land,
                        # and its pending record is already kept.
                        raise _settlement_in_progress(signature, f"broadcast outcome unknown: {exc}") from exc
                    if not broadcast_signature:
                        raise _settlement_in_progress(signature, "empty broadcast result")
                    sent_here = True

            # Await on-chain confirmation BEFORE returning success. Without this
            # the adapter returned a settlement header for a transaction that
            # may have been dropped by the cluster or reverted on-chain, granting
            # the client access without payment. ``await_confirmation`` raises
            # ``transaction-failed`` (included but reverted) or
            # ``transaction-not-found`` (never confirmed inside the window).
            #
            if not skip_confirmation:
                if rpc is None:
                    rpc = SolanaRpc(rpc_url)
                try:
                    # A request that did not send it is reconciling a payment
                    # an earlier one sent, which may have left the node's
                    # recent status cache: search the history.
                    await rpc.await_confirmation(signature, search_transaction_history=not sent_here)
                    await self._store.put(
                        replay_key,
                        {"binding": binding, "leaseUntil": replay_record["leaseUntil"], "state": "confirmed"},
                    )
                except Exception as exc:  # noqa: BLE001
                    # Keep the pending lease after a failure. A retry can
                    # atomically take over after expiry and determine whether
                    # the transaction landed, without permitting two concurrent
                    # requests to return successful fulfillment.
                    if proves_settlement_failed(exc):
                        # It landed and failed: it moved nothing.
                        raise InvalidProofError(
                            f"solana_pay_kit: invalid proof: confirmation failed: {exc}", code="payment_invalid"
                        ) from exc
                    # No status yet is never proof it did not execute.
                    raise _settlement_in_progress(signature, f"not confirmed yet: {exc}") from exc
        finally:
            if rpc is not None:
                await rpc.aclose()

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

        # v1 credentials get the legacy X-PAYMENT-RESPONSE receipt header; v2
        # uses PAYMENT-RESPONSE. Mirrors the rust v1/v2 settlement-response
        # split (constants.rs:22/31) and the go/lua/ruby/swift behavior.
        response_header = _RESPONSE_HEADER_LEGACY if version == X402_VERSION_V1 else _RESPONSE_HEADER
        return Payment(
            protocol=Protocol.X402,
            transaction=signature,
            gate_name=gate.name,
            settlement_headers={
                response_header: response_envelope,
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


@dataclass(frozen=True)
class VerifiedExactCredential:
    """An x402 ``exact`` credential that passed every pre-broadcast check.

    Only :func:`verify_exact_credential` builds one; settlement takes its
    ``cosigned_wire``, so a transaction cannot be broadcast unverified.
    """

    version: int
    accepted: dict[str, object]
    payload: X402PayloadField
    #: The client's partially signed transaction (standard base64).
    transaction: str
    #: The same transaction with the fee payer's signature spliced in.
    cosigned_wire: bytes


async def verify_exact_credential(
    header: str,
    offer: X402AcceptsEntry,
    fee_payer: TransactionSigner,
    *,
    require_payment_identifier: bool,
) -> VerifiedExactCredential:
    """Run the x402 ``exact`` server checks that precede broadcast.

    Decodes the ``PAYMENT-SIGNATURE`` / ``X-PAYMENT`` value, dispatches on
    ``x402Version`` (v1 legacy or v2), binds the credential to ``offer`` (the
    route's own requirements), enforces a required ``payment-identifier`` id,
    runs the structural :class:`ExactVerifier` on the transaction (exactly one
    matching ``TransferChecked``, fee payer kept out of every instruction, memo
    when ``extra.memo`` is set), and cosigns the fee-payer slot. Nothing is
    sent to the network.
    """
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
    version = envelope_map.get("x402Version")
    offer_map = cast("dict[str, object]", offer)

    if version == X402_VERSION_V2:
        accepted, payload = _bind_canonical(envelope_map, offer_map)
    elif version == X402_VERSION_V1:
        accepted, payload = _bind_legacy(envelope_map, offer_map)
    else:
        # A genuinely-unknown version is rejected on the dual-accept path,
        # exactly like the catch-all arm in rust ``parse_payment_signature``.
        raise InvalidProofError("unsupported_x402_version", code="unsupported_x402_version")

    extensions = envelope_map.get("extensions")
    try:
        verify_payment_identifier(
            cast("dict[str, Any]", extensions) if isinstance(extensions, dict) else None,
            required=require_payment_identifier,
        )
    except PaymentIdentifierError as exc:
        raise InvalidProofError(str(exc), code="payment_identifier_required") from exc

    tx_base64 = payload.get("transaction")
    if not isinstance(tx_base64, str) or tx_base64 == "":
        raise InvalidProofError(
            "invalid_exact_svm_payload_missing_transaction",
            code="invalid_exact_svm_payload_missing_transaction",
        )

    ExactVerifier.verify(tx_base64, cast("dict[str, Any]", offer), [str(fee_payer.pubkey)])
    cosigned_wire = await _co_sign(tx_base64, fee_payer)
    return VerifiedExactCredential(
        version=cast("int", version),
        accepted=accepted,
        payload=payload,
        transaction=tx_base64,
        cosigned_wire=cosigned_wire,
    )


def _bind_canonical(
    envelope: dict[str, object],
    offer: dict[str, object],
) -> tuple[dict[str, object], X402PayloadField]:
    """Bind a canonical (v2) credential to the route's offer.

    The v2 envelope carries an ``accepted`` requirement the client echoed
    back; it is matched field-by-field against the server's freshly built
    offer (x402 has no HMAC-bound challenge id, so the offer is the source
    of truth). Mirrors the v2 arm of rust ``parse_payment_signature`` plus
    ``verify_pinned_fields`` (server/exact.rs:328-341).
    """
    accepted_raw = envelope.get("accepted")
    payload_raw = envelope.get("payload")
    if not isinstance(accepted_raw, dict) or not isinstance(payload_raw, dict):
        raise InvalidProofError(
            "invalid_exact_svm_payload_envelope",
            code="invalid_exact_svm_payload_envelope",
        )
    accepted = cast("dict[str, object]", accepted_raw)
    # Tier-2 identity-key match: scheme/network/asset/payTo must match.
    for key in ("scheme", "network", "asset", "payTo"):
        if accepted.get(key) != offer.get(key):
            raise InvalidProofError(
                "solana_pay_kit: charge_request_mismatch: accepted payment requirement does not match server challenge",
                code="charge_request_mismatch",
            )
    # Reject if EITHER the exact ``amount`` or the ``maxAmountRequired``
    # ceiling drifts from the server offer.
    if accepted.get("amount") != offer.get("amount") or accepted.get("maxAmountRequired") != offer.get(
        "maxAmountRequired"
    ):
        raise InvalidProofError(
            "solana_pay_kit: charge_request_mismatch (amount)",
            code="charge_request_mismatch",
        )
    offer_extra = cast("dict[str, object]", offer.get("extra") or {})
    accepted_extra_raw = accepted.get("extra")
    accepted_extra = cast("dict[str, object]", accepted_extra_raw if isinstance(accepted_extra_raw, dict) else {})
    for key in ("feePayer", "tokenProgram", "memo"):
        if key in offer_extra and accepted_extra.get(key) != offer_extra[key]:
            raise InvalidProofError(
                f"solana_pay_kit: charge_request_mismatch (extra.{key})",
                code="charge_request_mismatch",
            )
    return accepted, cast("X402PayloadField", payload_raw)


def _bind_legacy(
    envelope: dict[str, object],
    offer: dict[str, object],
) -> tuple[dict[str, object], X402PayloadField]:
    """Bind a legacy (x402Version=1) credential to the route's offer.

    The legacy envelope has NO ``accepted`` object: it commits only to
    ``scheme`` + a plain ``network`` slug at the top level. The server binds
    exactly those two fields (scheme must be ``exact``; the plain network
    slug, normalized via ``caip2_for_network``, must match the route's CAIP-2
    network), then runs the IDENTICAL structural verifier and facilitator
    MUST-checks against the route's offer as the v2 path. Mirrors the v1 arm
    of rust ``parse_payment_signature`` (server/exact.rs:316-327).
    """
    scheme = envelope.get("scheme")
    if scheme != EXACT_SCHEME:
        raise InvalidProofError(
            "invalid_exact_svm_payload_scheme",
            code="invalid_exact_svm_payload_scheme",
        )
    network = envelope.get("network")
    network_slug = network if isinstance(network, str) else ""
    expected = cast("str", offer.get("network"))
    if caip2_for_network(network_slug) != expected:
        raise InvalidProofError(
            f"Network mismatch: expected {expected}, got {network_slug}",
            code="charge_request_mismatch",
        )
    payload_raw = envelope.get("payload")
    if not isinstance(payload_raw, dict):
        raise InvalidProofError(
            "invalid_exact_svm_payload_envelope",
            code="invalid_exact_svm_payload_envelope",
        )
    # The legacy wire carries no ``accepted`` body, so the response receipt
    # reports the route's CAIP-2 network rather than echoing the credential.
    synthetic_accepted: dict[str, object] = {"network": expected}
    return synthetic_accepted, cast("X402PayloadField", payload_raw)


async def _co_sign(transaction_b64: str, signer: TransactionSigner) -> bytes:
    """Sign the facilitator slot while preserving existing client signatures.

    The signature covers ``to_bytes_versioned(msg)``: the 0x80 prefix plus
    the v0 body, or the bare legacy message. ``VersionedTransaction.from_bytes``
    dispatches on the prefix, so a pre-cutover client's legacy wire is
    co-signed like a v0 one. The fee payer must occupy a signature slot.
    """
    from solders.transaction import VersionedTransaction

    raw = base64.b64decode(transaction_b64)
    fee_payer_pubkey = signer.pubkey

    try:
        vtx = VersionedTransaction.from_bytes(raw)
    except Exception as exc:  # noqa: BLE001
        raise _transaction_parse_error("invalid_exact_svm_payload_transaction_parse") from exc
    account_keys = list(vtx.message.account_keys)
    num_required = int(vtx.message.header.num_required_signatures)

    try:
        idx = account_keys.index(fee_payer_pubkey)
    except ValueError as exc:
        raise InvalidProofError(
            "solana_pay_kit: fee payer pubkey not present in transaction accounts",
            code="payment_invalid",
        ) from exc
    if idx >= num_required:
        raise InvalidProofError("solana_pay_kit: fee payer is not a required signer", code="payment_invalid")

    signed = await signer.sign_transaction(vtx)
    cosigned = bytes(signed.transaction)
    # Every required signer, the payer included, must have signed before the
    # signature is claimed or the transaction sent: a landed multi-signer
    # transaction cut down to its first signature would otherwise be claimed
    # and reconciled on the landed transaction's status.
    try:
        verify_required_signatures(VersionedTransaction.from_bytes(cosigned))
    except SignatureCheckError as exc:
        raise InvalidProofError(
            f"solana_pay_kit: transaction signature verification failed: {exc}", code="payment_invalid"
        ) from exc
    return cosigned


def _transaction_parse_error(message: str) -> InvalidProofError:
    """The canonical exact-scheme reject for an undecodable transaction."""
    return InvalidProofError(message, code="invalid_exact_svm_payload_transaction_parse")


def _transaction_signature(transaction_wire: bytes) -> str:
    """Return the deterministic first signature from a signed wire transaction."""
    from solders.transaction import VersionedTransaction

    try:
        signatures = VersionedTransaction.from_bytes(transaction_wire).signatures
    except Exception as exc:  # noqa: BLE001
        raise _transaction_parse_error("invalid_exact_svm_payload_transaction_parse") from exc
    if not signatures:
        raise InvalidProofError("solana_pay_kit: transaction has no signature", code="payment_invalid")
    return str(signatures[0])


def _settlement_in_progress(signature: str, detail: str) -> SettlementInProgressError:
    """The payment may already be broadcast: retry it, never pay again."""
    return SettlementInProgressError(
        f"solana_pay_kit: settlement of transaction {signature} is in progress ({detail}); "
        "retry the same payment, do not pay again"
    )


async def _recover_replay_record(
    store: Store,
    replay_key: str,
    binding: str,
    replay_record: dict[str, object],
    current: object,
    now: float,
) -> bool:
    """Claim an expired settlement for confirmation, or return a confirmed replay."""
    if not isinstance(current, dict):
        raise InvalidProofError("solana_pay_kit: signature_consumed", code="signature_consumed")
    current_record = cast("dict[str, object]", current)
    if current_record.get("binding") != binding:
        raise InvalidProofError("solana_pay_kit: signature_consumed", code="signature_consumed")
    if current_record.get("state") == "confirmed":
        return True
    if current_record.get("state") != "pending" or not isinstance(current_record.get("leaseUntil"), int | float):
        raise InvalidProofError("solana_pay_kit: signature_consumed", code="signature_consumed")

    lease_until = float(cast("int | float", current_record["leaseUntil"]))
    signature = replay_key.rsplit(":", 1)[-1]
    if lease_until > now:
        raise _settlement_in_progress(signature, "settlement confirmation is pending")
    recovery_key = f"{replay_key}:recovery:{lease_until}"
    if not await store.put_if_absent(recovery_key, True):
        raise _settlement_in_progress(signature, "settlement recovery is in progress")

    latest = await store.get(replay_key)
    if not isinstance(latest, dict):
        raise InvalidProofError("solana_pay_kit: signature_consumed", code="signature_consumed")
    latest_record = cast("dict[str, object]", latest)
    if latest_record.get("binding") != binding:
        raise InvalidProofError("solana_pay_kit: signature_consumed", code="signature_consumed")
    if latest_record.get("state") == "confirmed":
        return True
    if latest_record.get("state") == "pending" and latest_record.get("leaseUntil") == lease_until:
        await store.put(replay_key, replay_record)
        return False
    raise InvalidProofError(
        "solana_pay_kit: signature_consumed: settlement recovery state changed",
        code="signature_consumed",
    )


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


def _legacy_payment_header(request: Any) -> str:
    """Read the legacy ``X-PAYMENT`` header across framework request shapes.

    The legacy x402 credential travels in ``X-PAYMENT`` (rust
    ``X402_V1_PAYMENT_HEADER``), not ``Payment-Signature``. Read it only after
    the canonical (v2) header is absent so the v2 path stays the default.
    """
    target = X402_LEGACY_PAYMENT_HEADER.lower()
    headers = getattr(request, "headers", None)
    if headers is not None:
        getter = getattr(headers, "get", None)
        if callable(getter):
            for name in (target, X402_LEGACY_PAYMENT_HEADER, X402_LEGACY_PAYMENT_HEADER.upper()):
                value: object = getter(name)
                if value:
                    return str(value)
    if isinstance(request, dict):
        raw_headers = cast("dict[str, object]", request).get("headers")
        if isinstance(raw_headers, dict):
            for key, header_value in cast("dict[object, object]", raw_headers).items():
                if isinstance(key, str) and key.lower() == target and header_value:
                    return str(header_value)
    return ""
