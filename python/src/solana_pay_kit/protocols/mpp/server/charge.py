"""Main server-side Solana charge handler.

The ``Mpp`` orchestration lives here. The pre-broadcast transaction decoders
and parsed-instruction verifiers live in
:mod:`solana_pay_kit.protocols.mpp.server._tx_decode`; the fee-payer cosign and the
strict no-leftovers instruction allowlist live in
:mod:`solana_pay_kit.protocols.mpp.server._verify`. Both are re-exported below so the
``solana_pay_kit.protocols.mpp.server.charge`` import path stays stable for callers
and tests that reach into the helpers directly.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import logging
from dataclasses import dataclass, field
from typing import Any

from solana_pay_kit._paycore.errors import (
    ChallengeExpiredError,
    ChallengeMismatchError,
    PaymentError,
    ReplayError,
)
from solana_pay_kit._paycore.network_check import check_network_blockhash
from solana_pay_kit._paycore.solana import (
    MIN_SECRET_KEY_BYTES,
    CredentialPayload,
    MethodDetails,
    Split,
    default_rpc_url,
    derive_default_realm,
    is_native_sol,
    resolve_server_token_program,
    validate_network,
    validate_splits,
)
from solana_pay_kit._paycore.store import Store
from solana_pay_kit.protocols.mpp.core.base64url import encode_json
from solana_pay_kit.protocols.mpp.core.types import PaymentChallenge, PaymentCredential, Receipt
from solana_pay_kit.protocols.mpp.intents.charge import ChargeRequest, parse_units
from solana_pay_kit.protocols.mpp.server._tx_decode import (
    _SYSTEM_PROGRAM,
    MAX_COMPUTE_UNIT_LIMIT,
    MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS,
    MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS_FEE_SPONSORED,
    MAX_SPLITS,
    _build_expected_transfers,
    _decode_legacy_payment_instructions,
    _extract_recent_blockhash,
    _json_like,
    _rpc_value,
    _status_ok,
    _transaction_dict,
    _validate_compute_budget_instruction,
    _verify_parsed_memo_instructions,
    _verify_parsed_sol_transfers,
    _verify_parsed_spl_transfers,
)
from solana_pay_kit.protocols.mpp.server._verify import (
    _assert_signature_slot,
    _co_sign_with_fee_payer,
    _expected_ata_creation_policy,
    _validate_ata_create_idempotent,
    _validate_instruction_allowlist,
    _verify_local_transaction_intent,
)

logger = logging.getLogger(__name__)

_SECRET_KEY_ENV_VAR = "MPP_SECRET_KEY"
_CONSUMED_PREFIX = "solana-charge:consumed:"

# Re-exported from the decoder / verifier modules so the historical
# ``solana_pay_kit.protocols.mpp.server.charge`` import surface stays intact.
__all__ = [
    "ChargeOptions",
    "Config",
    "Mpp",
    "MAX_COMPUTE_UNIT_LIMIT",
    "MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS",
    "MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS_FEE_SPONSORED",
    "MAX_SPLITS",
    "_assert_signature_slot",
    "_build_expected_transfers",
    "_co_sign_with_fee_payer",
    "_decode_legacy_payment_instructions",
    "_expected_ata_creation_policy",
    "_extract_recent_blockhash",
    "_json_like",
    "_rpc_value",
    "_status_ok",
    "_SYSTEM_PROGRAM",
    "_transaction_dict",
    "_validate_ata_create_idempotent",
    "_validate_compute_budget_instruction",
    "_validate_instruction_allowlist",
    "_verify_local_transaction_intent",
    "_verify_parsed_memo_instructions",
    "_verify_parsed_sol_transfers",
    "_verify_parsed_spl_transfers",
]


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
    # ``None`` (the default) means "derive a per-recipient default realm"
    # (Audit #15). An explicit empty string is a misconfiguration and is
    # rejected at construction; a non-empty string is used verbatim.
    realm: str | None = None
    html: bool = False
    # Audit #5: push-mode (``type="signature"``) credentials are accepted only
    # when this is opted in. Default OFF reduces attack surface; the pull-mode
    # (``type="transaction"``) path is unaffected. Spec §13.5 permits push as a
    # shape-matching mode, but it is off by default to match the Rust posture.
    accept_push_mode: bool = False
    fee_payer_signer: Any = None
    store: Store | None = None
    # The RPC client MUST expose at least the methods on
    # :class:`solana_pay_kit._paycore.rpc.SolanaRpc`: ``send_raw_transaction``,
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
        # Audit #24: enforce a >=32-byte HMAC-SHA256 secret on BOTH the config
        # and env-var paths (the value is already resolved from either above).
        # The key length is measured in bytes (UTF-8) so multi-byte secrets are
        # not over-counted by character length.
        if len(secret_key.encode("utf-8")) < MIN_SECRET_KEY_BYTES:
            raise PaymentError(
                f"secret key must be at least {MIN_SECRET_KEY_BYTES} bytes; "
                "use cryptographically-random key material (e.g. `openssl rand -base64 32`)",
                code="invalid-config",
            )

        self._secret_key = secret_key
        self._recipient = config.recipient
        # Audit #15: derive a per-recipient default realm instead of sharing the
        # static "MPP Payment" namespace across every server on the same secret.
        # An explicitly supplied empty realm is a misconfig and is rejected so an
        # operator cannot accidentally re-introduce the shared namespace.
        if config.realm == "":
            raise PaymentError(
                "realm must not be empty; omit it to derive a per-recipient default",
                code="invalid-config",
            )
        self._realm = config.realm if config.realm else derive_default_realm(self._recipient)
        self._currency = config.currency or "USDC"
        self._decimals = config.decimals or 6
        from solana_pay_kit._paycore.solana import _canonical_network as _canonical_net

        # Audit #37: reject any network outside {mainnet, devnet, localnet} at
        # boot, before any RPC client is built, instead of silently resolving
        # unknown slugs to the mainnet RPC host.
        try:
            validate_network(config.network or "mainnet")
        except ValueError as exc:
            raise PaymentError(str(exc), code="invalid-config") from exc
        self._network = _canonical_net(config.network or "mainnet")
        self._rpc_url = config.rpc_url or default_rpc_url(self._network)
        # Audit #28: resolve the token program ONCE at boot. Known stablecoins
        # resolve from the static table (Token vs Token-2022 correctly); an
        # arbitrary mint address has its on-chain owner fetched and validated;
        # a currency that is neither a known symbol nor a valid pubkey is
        # rejected. The result is emitted on every SPL challenge instead of a
        # silent legacy-Token fallback for arbitrary mints.
        try:
            self._token_program: str | None = resolve_server_token_program(self._currency, self._network, self._rpc_url)
        except ValueError as exc:
            raise PaymentError(str(exc), code="invalid-config") from exc
        self._html = config.html
        self._accept_push_mode = config.accept_push_mode
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
                        "use solana_pay_kit._paycore.rpc.SolanaRpc or a compatible client",
                        code="invalid-config",
                    )
        self._rpc = config.rpc
        # Held by ``using_rpc`` to serialize per-request RPC swaps when
        # the harness adapter (or any embedder) wants a fresh client
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
        provide their own thread-level coordination. The harness
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

        # Audit #21 / #38: validate splits at ISSUANCE (count/parse/positive/
        # dedup) and reject the fee-sponsored drain shape — a split paying the
        # primary recipient with ataCreationRequired=true — before the splits
        # are embedded into a signed challenge. Previously invalid splits were
        # only caught at verify / on-chain time.
        split_objs = [Split.from_dict(s) for s in options.splits]
        try:
            validate_splits(split_objs)
        except ValueError as exc:
            raise PaymentError(str(exc), code="invalid-config") from exc
        is_fee_sponsored = options.fee_payer or self._fee_payer_signer is not None
        if is_fee_sponsored:
            for split in split_objs:
                if split.recipient == self._recipient and split.ata_creation_required:
                    raise PaymentError(
                        "fee-sponsored challenge must not create the primary recipient's ATA "
                        "via a split (drain risk); remove ataCreationRequired on the primary "
                        "recipient's split",
                        code="invalid-config",
                    )

        details: dict[str, Any] = {"network": self._network}
        if not is_native_sol(self._currency):
            details["decimals"] = self._decimals
            # Audit #28: emit the boot-resolved token program for every SPL
            # challenge (including arbitrary mints resolved on-chain), not just
            # known stablecoin symbols.
            if self._token_program is not None:
                details["tokenProgram"] = self._token_program
        if is_fee_sponsored:
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

        from solana_pay_kit.protocols.mpp.core.expires import minutes

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
            # Audit #5: push mode is opt-in (spec §13.5). Reject unless the
            # server explicitly enabled it via Config.accept_push_mode.
            if not self._accept_push_mode:
                raise PaymentError(
                    'type="signature" (push mode) credentials are not accepted; '
                    "set Config.accept_push_mode=True to opt in (spec §13.5)",
                    code="invalid-payload-type",
                )
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
        # vice versa). Done first in the entry path so the cheap, unambiguous
        # check fails fast before the full verification + broadcast pipeline.
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
