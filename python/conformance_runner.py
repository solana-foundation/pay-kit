"""Python cross-SDK conformance-vector runner.

Honors the same stdin/stdout contract as the TypeScript reference runner
(harness/src/conformance/ts-runner.ts) and the Go runner
(go/cmd/conformance/main.go): read one conformance vector as JSON on stdin,
drive the real Python pay_kit SDK (the MPP client build, the server
RPC-free pre-broadcast verify, and the wire canonical-JSON / base64url
encoders) for the requested mode, and emit one RunnerResult line as JSON on
stdout.

The oracle for build/verify vectors is the DECODED SEMANTIC SHAPE of the
transaction (fee payer, transfer set, compute caps, memos) rather than raw
bytes, because signatures and account ordering can legitimately differ
across SDKs. The canonical-bytes mode pins exact bytes for the JCS /
base64url vectors where byte-for-byte agreement is the whole point.

The run is deterministic and RPC-free: build/verify vectors pin a recent
blockhash and either an explicit token program or one resolvable by
currency, so no live validator is contacted. The injected RPC client
refuses every network call so an under-specified vector surfaces as a clear
reject rather than a silent live fetch.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import sys
from typing import Any

from pay_kit._paycore.solana import (
    COMPUTE_BUDGET_PROGRAM,
    MEMO_PROGRAM,
    SYSTEM_PROGRAM,
    TOKEN_2022_PROGRAM,
    TOKEN_PROGRAM,
    MethodDetails,
    default_token_program_for_currency,
    is_native_sol,
    resolve_mint,
)
from pay_kit.protocols.mpp.client.charge import build_charge_transaction
from pay_kit.protocols.mpp.core import json as wire_json
from pay_kit.protocols.mpp.core.base64url import encode as base64url_encode
from pay_kit.protocols.mpp.intents.charge import ChargeRequest
from pay_kit.protocols.mpp.server._verify import _verify_local_transaction_intent
from pay_kit.protocols.x402.client.exact.payment import (
    _caip2_for_selection,
    build_payment_header,
    build_payment_header_legacy,
)
from pay_kit.protocols.x402.exact.extensions import (
    PAYMENT_IDENTIFIER_KEY,
    verify_payment_identifier,
)
from pay_kit.protocols.x402.exact.legacy import caip2_for_network
from pay_kit.protocols.x402.exact.verify import (
    EXACT_SCHEME,
    X402_VERSION_V1,
    X402_VERSION_V2,
)
from pay_kit.signer import LocalSigner

DEFAULT_NETWORK = "mainnet"
DEFAULT_SPL_DECIMALS = 6

# x402-exact build determinism: the conformance oracle is the DECODED
# ENVELOPE shape, never the signed-transaction bytes inside
# payload.transaction (that is the harness matrix's job). So the build path
# is pinned with a fixed blockhash + memo nonce and an ephemeral signer; the
# resulting transaction is real and well-formed but its bytes are not
# asserted. Mirrors the rust spine x402 client and the TS reference oracle
# (harness/src/conformance/x402.ts).
_X402_PINNED_BLOCKHASH = "4vJ9JU1bJJQpUgJ8V6hYz7xXKz4F2tN6aBrZEcD3xKhs"
_X402_PINNED_MEMO_NONCE = "00112233445566778899aabbccddeeff"

_PROGRAMS = {
    TOKEN_PROGRAM,
    TOKEN_2022_PROGRAM,
}


class OfflineRPC:
    """Refuses every network call.

    Build/verify vectors pin a recent blockhash and resolve the token
    program ahead of time, so a real RPC call here signals the vector was
    under-specified rather than a determinism gap to paper over. Every
    method raises so the failure surfaces as a clear runner reject. Mirrors
    offlineRPC in go/cmd/conformance/offline_rpc.go.
    """

    async def _refuse(self, method: str) -> Any:
        raise RuntimeError(
            f"offline conformance runner refused RPC call {method}: vector must pin blockhash and token program"
        )

    async def get_latest_blockhash(self, *args: Any, **kwargs: Any) -> Any:
        return await self._refuse("getLatestBlockhash")

    async def get_account(self, *args: Any, **kwargs: Any) -> Any:
        return await self._refuse("getAccountInfo")


def _local_signer(secret: list[int]) -> Any:
    """Adapt a 64-byte ed25519 secret key to a solders Keypair.

    The vectors carry the signer as the transfer authority / fee payer; the
    Python client build path consumes ``signer.pubkey()`` and
    ``tx.partial_sign([signer], ...)``, both satisfied by a solders Keypair.
    """
    from solders.keypair import Keypair  # type: ignore[import-untyped]

    if len(secret) != 64:
        raise ValueError(f"signerSecretKey must be 64 bytes, got {len(secret)}")
    return Keypair.from_bytes(bytes(secret))


def _flatten_request(
    request: dict[str, Any],
    mint_owners: dict[str, str] | None,
) -> tuple[str, str, str, str, MethodDetails]:
    """Apply the precedence rules the vectors probe.

    Top-level ``asset`` / ``payTo`` win over ``currency`` / ``recipient``;
    the methodDetails carry network / decimals / tokenProgram /
    recentBlockhash / feePayer / splits. The token program resolves
    explicit methodDetails -> rpc-fixture mint owner -> default-by-currency
    so the build path stays RPC-free. Mirrors flattenRequest in the TS
    reference runner and the Go runner.

    Returns ``(amount, currency, recipient, external_id, details)``.
    """
    currency = request.get("asset") or request.get("currency") or ""
    recipient = request.get("payTo") or request.get("recipient") or ""
    if not recipient:
        raise ValueError("vector request is missing recipient/payTo")

    md = request.get("methodDetails") or {}
    network = md.get("network") or DEFAULT_NETWORK

    details = MethodDetails(
        network=network,
        decimals=md.get("decimals"),
        token_program=md.get("tokenProgram"),
        fee_payer=bool(md.get("feePayer", False)),
        fee_payer_key=md.get("feePayerKey", "") or "",
        recent_blockhash=md.get("recentBlockhash", "") or "",
    )
    splits = md.get("splits")
    if splits:
        from pay_kit._paycore.solana import Split

        details.splits = [Split.from_dict(s) for s in splits]

    is_sol = is_native_sol(currency)

    if not details.token_program and not is_sol:
        resolved_mint = resolve_mint(currency, network) or currency
        if mint_owners and resolved_mint in mint_owners:
            details.token_program = mint_owners[resolved_mint]
        else:
            details.token_program = default_token_program_for_currency(currency, network)

    if details.decimals is None and not is_sol:
        details.decimals = DEFAULT_SPL_DECIMALS

    external_id = request.get("externalId", "") or ""
    return request.get("amount", ""), currency, recipient, external_id, details


async def _build_transaction(vector: dict[str, Any]) -> str:
    """Drive the real client build path and return the base64 wire transaction.

    recentBlockhash and the resolved token program keep the build RPC-free;
    the OfflineRPC stub ensures a missing blockhash surfaces as a clear
    failure rather than a live fetch.
    """
    inp = vector.get("input") or {}
    request = inp.get("request")
    if not request:
        raise ValueError("build/verify vector is missing input.request")
    secret = inp.get("signerSecretKey")
    if not secret:
        raise ValueError("build/verify vector is missing input.signerSecretKey")

    signer = _local_signer(secret)
    fixtures = inp.get("rpcFixtures") or {}
    mint_owners = fixtures.get("mintOwners")
    amount, currency, recipient, external_id, details = _flatten_request(request, mint_owners)

    # Build-time compute overrides: reject vectors carry these to exercise
    # the server cap. ``computeUnitPrice`` arrives as a string (u64).
    compute_unit_limit = request.get("computeUnitLimit")
    compute_unit_price_raw = request.get("computeUnitPrice")
    compute_unit_price = int(compute_unit_price_raw) if compute_unit_price_raw is not None else None

    payload = await build_charge_transaction(
        signer=signer,
        rpc_client=OfflineRPC(),
        amount=amount,
        currency=currency,
        recipient=recipient,
        method_details=details,
        external_id=external_id,
        compute_unit_limit=compute_unit_limit,
        compute_unit_price=compute_unit_price,
    )
    if not payload.transaction:
        raise ValueError("build produced no transaction payload")
    return payload.transaction


def _verify_transaction(vector: dict[str, Any], transaction_b64: str) -> None:
    """Drive the Python server's RPC-free pre-broadcast verify.

    ``_verify_local_transaction_intent`` runs the parsed-transfer / memo
    checks, the compute-budget cap, and the strict no-leftovers allowlist
    without any RPC or HMAC, exactly the pure pre-broadcast surface the
    conformance vectors target.
    """
    inp = vector.get("input") or {}
    request = inp.get("request")
    if not request:
        raise ValueError("verify vector is missing input.request")
    fixtures = inp.get("rpcFixtures") or {}
    mint_owners = fixtures.get("mintOwners")
    amount, currency, recipient, external_id, details = _flatten_request(request, mint_owners)

    charge = ChargeRequest(
        amount=amount,
        currency=currency,
        recipient=recipient,
        external_id=external_id,
    )
    expected_fee_payer = details.fee_payer_key if (details.fee_payer and details.fee_payer_key) else None
    _verify_local_transaction_intent(transaction_b64, charge, details, expected_fee_payer)


def _read_u32_le(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 4], "little")


def _read_u64_le(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 8], "little")


def _shape_from_transaction(transaction_b64: str) -> dict[str, Any]:
    """Decode a base64 wire transaction into the semantic shape the driver asserts.

    Mirrors the TS reference decoder (harness/src/conformance/decode.ts) and
    the Go runner shapeFromTransaction: fee payer is account[0], SPL
    transfers come from transferChecked (discriminator 12), SOL transfers
    from the System Program transfer (discriminator 2), memos from the Memo
    Program, and compute caps from the ComputeBudget program.
    """
    from solders.transaction import Transaction, VersionedTransaction  # type: ignore[import-untyped]

    raw = base64.b64decode(transaction_b64)
    try:
        message = Transaction.from_bytes(raw).message
    except Exception:
        message = VersionedTransaction.from_bytes(raw).message

    keys = [str(k) for k in message.account_keys]
    if not keys:
        raise ValueError("transaction has no account keys")

    transfers: list[dict[str, Any]] = []
    memos: list[str] = []
    compute_unit_limit: int | None = None
    compute_unit_price: str | None = None

    for ix in message.instructions:
        program = keys[int(ix.program_id_index)]
        data = bytes(ix.data)
        accounts = list(ix.accounts)

        if program == COMPUTE_BUDGET_PROGRAM:
            if len(data) == 5 and data[0] == 2:
                compute_unit_limit = _read_u32_le(data, 1)
            elif len(data) == 9 and data[0] == 3:
                compute_unit_price = str(_read_u64_le(data, 1))
            continue

        if program == MEMO_PROGRAM:
            memos.append(data.decode("utf-8"))
            continue

        if program == SYSTEM_PROGRAM:
            if len(data) >= 12 and _read_u32_le(data, 0) == 2 and len(accounts) >= 2:
                transfers.append(
                    {
                        "amount": str(_read_u64_le(data, 4)),
                        "destination": keys[int(accounts[1])],
                        "kind": "sol",
                    }
                )
            continue

        if program in _PROGRAMS:
            if len(data) >= 10 and data[0] == 12 and len(accounts) >= 4:
                transfers.append(
                    {
                        "amount": str(_read_u64_le(data, 1)),
                        "decimals": data[9],
                        "destination": keys[int(accounts[2])],
                        "kind": "spl",
                        "mint": keys[int(accounts[1])],
                        "tokenProgram": program,
                    }
                )
            continue

    shape: dict[str, Any] = {
        "feePayer": keys[0],
        "forbiddenPrograms": [],
        "memo": memos,
        "transfers": transfers,
    }
    if compute_unit_limit is not None:
        shape["maxComputeUnitLimit"] = compute_unit_limit
    if compute_unit_price is not None:
        shape["maxComputeUnitPrice"] = compute_unit_price
    return shape


def _run_canonical_bytes(vector: dict[str, Any]) -> dict[str, Any]:
    """Drive the wire canonical-JSON / base64url encoders."""
    inp = vector.get("input") or {}
    exact: dict[str, Any] = {}

    if "value" in inp and inp["value"] is not None:
        canonical = wire_json.encode_canonical(inp["value"])
        exact["canonicalJson"] = canonical.decode("utf-8")
        exact["base64Url"] = base64url_encode(canonical)

    enc = inp.get("encodeBase64Url")
    if enc:
        if enc.get("hexBytes"):
            raw = bytes.fromhex(enc["hexBytes"])
            exact["bytes"] = list(raw)
            exact["base64Url"] = base64url_encode(raw)
        elif enc.get("utf8"):
            exact["base64Url"] = base64url_encode(enc["utf8"].encode("utf-8"))

    cid = inp.get("challengeId")
    if cid:
        # base64url(HMAC-SHA256(secret, realm|method|intent|request|expires|
        # digest|opaque)); absent optionals join as empty strings. Mirrors
        # rust compute_challenge_id (protocol/core/challenge.rs).
        hmac_input = "|".join(
            [
                cid["realm"],
                cid["method"],
                cid["intent"],
                cid["request"],
                cid.get("expires", ""),
                cid.get("digest", ""),
                cid.get("opaque", ""),
            ]
        )
        mac = hmac.new(
            cid["secretKey"].encode("utf-8"),
            hmac_input.encode("utf-8"),
            hashlib.sha256,
        ).digest()
        exact["base64Url"] = base64url_encode(mac)

    return exact


# ── x402-exact intent ──────────────────────────────────────────────────────
#
# The x402 charge is HTTP-shaped, not transaction-shaped: a CLIENT build
# produces a base64(JSON) payment header and a SERVER verify consumes one.
# So the cross-SDK oracle is the DECODED ENVELOPE shape (x402Version, v1
# top-level scheme/network vs v2 accepted, payloadHasTransaction), never the
# signed Solana transaction inside payload.transaction. This mirrors the
# rust spine and the TS reference oracle (harness/src/conformance/x402.ts):
#   - build v2 -> pay_kit build_payment_header    (PAYMENT-SIGNATURE)
#   - verify   -> the envelope-level version dispatch + network gate + the
#                 v2 accepted-vs-route field comparison from the pay_kit
#                 X402Adapter.verify_and_settle pre-broadcast surface.


def _decode_envelope_shape(header_b64: str) -> dict[str, Any]:
    """Decode a base64(JSON) payment header into the X402EnvelopeShape oracle.

    Mirrors decodeEnvelopeShape in harness/src/conformance/x402.ts: presence
    of top-level scheme/network is meaningful (v1 carries them, v2 must not
    leak them); hasAccepted is true iff a v2 ``accepted`` object is present;
    payloadHasTransaction is true iff payload carries a non-empty transaction.
    """
    env = json.loads(base64.b64decode(header_b64, validate=True))
    accepted = env.get("accepted")
    payload = env.get("payload") or {}
    transaction = payload.get("transaction") if isinstance(payload, dict) else None
    shape: dict[str, Any] = {
        "x402Version": env.get("x402Version"),
        "hasAccepted": isinstance(accepted, dict),
        "payloadHasTransaction": isinstance(transaction, str) and transaction != "",
    }
    if "scheme" in env:
        shape["scheme"] = env["scheme"]
    if "network" in env:
        shape["network"] = env["network"]
    if isinstance(accepted, dict):
        shape["acceptedScheme"] = accepted.get("scheme")
        shape["acceptedNetwork"] = accepted.get("network")
        shape["acceptedAsset"] = accepted.get("asset")
        shape["acceptedPayTo"] = accepted.get("payTo")
        shape["acceptedAmount"] = accepted.get("amount")

    # Surface the v2 extensions object. ``hasExtensions`` is false when the key
    # is absent OR present-but-empty (the echo-and-omit rule means a conforming
    # build never emits an empty ``extensions: {}``, but a decoder must still
    # classify a stray ``{}`` as "no extensions"). Mirrors decodeEnvelopeShape
    # in harness/src/conformance/x402.ts.
    extensions = env.get("extensions")
    if isinstance(extensions, dict):
        keys = sorted(extensions.keys())
        shape["hasExtensions"] = len(keys) > 0
        shape["extensionKeys"] = keys
        pid = extensions.get(PAYMENT_IDENTIFIER_KEY)
        shape["hasPaymentIdentifier"] = isinstance(pid, dict)
        if isinstance(pid, dict):
            info = pid.get("info")
            if isinstance(info, dict):
                if "required" in info:
                    shape["paymentIdentifierRequired"] = info.get("required")
                if "id" in info:
                    shape["paymentIdentifierId"] = info.get("id")
    else:
        shape["hasExtensions"] = False
        shape["hasPaymentIdentifier"] = False
        shape["extensionKeys"] = []
    return shape


async def _x402_build_header(vector: dict[str, Any]) -> str:
    """Drive the real pay_kit x402 client to build a payment header.

    The offer is the vector's ``x402Offer``. An ephemeral signer + pinned
    blockhash + pinned memo nonce keep the build deterministic and RPC-free;
    the resulting transaction is real but its bytes are not asserted (the
    envelope shape is the oracle). The default producer stays the canonical (v2)
    ``PAYMENT-SIGNATURE`` wire; when the vector pins ``x402Version: 1`` the
    runner drives the legacy ``X-PAYMENT`` producer instead.
    """
    inp = vector.get("input") or {}
    offer = inp.get("x402Offer")
    if not offer:
        raise ValueError("x402 build vector is missing input.x402Offer")

    # Echo-and-append (x402 v2 §5.1.2): the server's advertised extensions are
    # echoed back onto the credential, with payment-identifier.info.id filled
    # when required. A pinned id keeps the build deterministic for byte-asserted
    # vectors; otherwise the client generates a fresh pay_ id.
    advertised_extensions = inp.get("x402AdvertisedExtensions")
    payment_identifier_id = inp.get("x402PaymentIdentifierId")

    signer = LocalSigner.generate()
    # The legacy v1 producer has no `extensions` concept, so it does not accept
    # the echo-and-append kwargs; only the v2 producer does.
    if inp.get("x402Version") == X402_VERSION_V1:
        return await build_payment_header_legacy(
            signer,
            OfflineRPC(),
            offer,
            recent_blockhash_provider=lambda: _X402_PINNED_BLOCKHASH,
            memo_nonce=lambda: _X402_PINNED_MEMO_NONCE,
        )
    return await build_payment_header(
        signer,
        OfflineRPC(),
        offer,
        recent_blockhash_provider=lambda: _X402_PINNED_BLOCKHASH,
        memo_nonce=lambda: _X402_PINNED_MEMO_NONCE,
        advertised_extensions=advertised_extensions,
        payment_identifier_id=payment_identifier_id,
    )


def _x402_verify(vector: dict[str, Any]) -> dict[str, Any]:
    """Drive the envelope-level x402 server verify against the route.

    Mirrors the pre-broadcast surface of pay_kit X402Adapter.verify_and_settle
    and the rust spine ``parse_payment_signature`` + ``verify_envelope_payload``:
    version dispatch, the network gate (v1 legacy slug / v2 accepted.network),
    and the v2 accepted-vs-route field comparison. The signed-transaction
    settlement inside payload.transaction is intentionally out of scope (the
    harness matrix's job), so a structurally valid, route-matching envelope is
    accepted here. Returns the decoded envelope shape on accept; raises with a
    classifiable message on reject.
    """
    inp = vector.get("input") or {}
    header = inp.get("x402PaymentHeader")
    if not header:
        raise ValueError("x402 verify vector is missing input.x402PaymentHeader")

    try:
        env = json.loads(base64.b64decode(header, validate=True))
    except Exception as exc:  # noqa: BLE001 - any decode failure is invalid payload
        raise ValueError(f"invalid payload: undecodable payment header ({exc})") from exc
    if not isinstance(env, dict):
        raise ValueError("invalid payload: payment header is not a JSON object")

    expected_network = _caip2_for_selection(inp.get("x402ServerNetwork") or DEFAULT_NETWORK)
    version = env.get("x402Version")

    if version == X402_VERSION_V2:
        accepted = env.get("accepted")
        if not isinstance(accepted, dict):
            raise ValueError("invalid payload: v2 envelope missing accepted")
        accepted_network = accepted.get("network") or ""
        if accepted_network != expected_network:
            raise ValueError(f"Network mismatch: expected {expected_network}, got {accepted_network}")
        # accepted-vs-route field comparison (rust verify_envelope_payload).
        if (accepted.get("amount") or "") != (inp.get("x402ServerAmount") or ""):
            raise ValueError(f"Amount mismatch: expected {inp.get('x402ServerAmount')}, got {accepted.get('amount')}")
        if (accepted.get("payTo") or "") != (inp.get("x402ServerRecipient") or ""):
            raise ValueError("Recipient mismatch: credential claims a different recipient")
        if (accepted.get("asset") or "") != (inp.get("x402ServerCurrency") or ""):
            raise ValueError(
                f"Currency mismatch: expected {inp.get('x402ServerCurrency')}, got {accepted.get('asset')}"
            )
        # Extensions reject gate: when the route requires a payment-identifier,
        # the echoed credential must carry a valid pay_-shaped id. Missing,
        # empty, or pattern-violating ids are rejected (coinbase spec: HTTP 400).
        # Layered after the accepted-vs-route checks, mirroring the rust spine
        # and the TS reference verifyPaymentHeader gate.
        extensions = env.get("extensions")
        verify_payment_identifier(
            extensions if isinstance(extensions, dict) else None,
            required=bool(inp.get("x402ServerRequiresPaymentIdentifier")),
        )
    elif version == X402_VERSION_V1:
        # Legacy arm: no ``accepted`` object. Bind only scheme + the plain
        # network slug (normalized to CAIP-2) against the route. Mirrors the v1
        # arm of rust parse_payment_signature (server/exact.rs:316-327).
        if env.get("scheme") != EXACT_SCHEME:
            raise ValueError(f"invalid payload: legacy scheme {env.get('scheme')!r} is not exact")
        network_slug = env.get("network") or ""
        if caip2_for_network(network_slug) != expected_network:
            raise ValueError(f"Network mismatch: expected {expected_network}, got {network_slug}")
    else:
        raise ValueError(f"invalid payload: Unsupported x402 version: {version}")

    payload = env.get("payload") or {}
    transaction = payload.get("transaction") if isinstance(payload, dict) else None
    if not isinstance(transaction, str) or transaction == "":
        raise ValueError("invalid payload: missing transaction proof")

    return _decode_envelope_shape(header)


def _run_x402(vector: dict[str, Any]) -> dict[str, Any]:
    vector_id = vector.get("id", "")
    mode = vector.get("mode")

    if mode == "build-transaction":
        header = asyncio.run(_x402_build_header(vector))
        return {
            "id": vector_id,
            "outcome": "accept",
            "x402EnvelopeShape": _decode_envelope_shape(header),
        }

    if mode == "verify-transaction":
        shape = _x402_verify(vector)
        return {"id": vector_id, "outcome": "accept", "x402EnvelopeShape": shape}

    # Any other mode for the x402 intent has no Python equivalent.
    raise ValueError(f"unsupported-mode: {mode}")


def _run_vector(vector: dict[str, Any]) -> dict[str, Any]:
    vector_id = vector.get("id", "")
    mode = vector.get("mode")

    if vector.get("intent") == "x402-exact":
        return _run_x402(vector)

    if mode == "canonical-bytes":
        return {"id": vector_id, "outcome": "accept", "exactBytes": _run_canonical_bytes(vector)}

    if mode == "build-transaction":
        tx = asyncio.run(_build_transaction(vector))
        return {"id": vector_id, "outcome": "accept", "transactionShape": _shape_from_transaction(tx)}

    if mode == "verify-transaction":
        inp = vector.get("input") or {}
        tx = inp.get("transaction")
        if not tx:
            tx = asyncio.run(_build_transaction(vector))
        _verify_transaction(vector, tx)
        return {"id": vector_id, "outcome": "accept", "transactionShape": _shape_from_transaction(tx)}

    raise ValueError(f"unsupported-mode: {mode}")


# Map the Python SDK's native reject message onto the shared RejectCode
# vocabulary (see harness/src/conformance/reject.ts). The harness asserts
# this category so a guard that fires for the wrong reason is flagged rather
# than passing on outcome alone. Decimals mismatch is enforced through the
# transfer match key, so it honestly surfaces as `no-matching-transfer`.
_REJECT_PATTERNS: list[tuple[str, str]] = [
    (r"compute unit price .* exceeds (cap|maximum)", "compute-price-over-cap"),
    (r"compute unit limit .* exceeds (cap|maximum)", "compute-limit-over-cap"),
    (r"fee payer cannot authorize", "fee-payer-not-authority"),
    (r"fee payer .* (funding source|funds source)", "fee-payer-is-funds-source"),
    (r"splits consume the entire amount", "splits-exceed-amount"),
    (r"too many splits", "too-many-splits"),
    (r"no matching (spl )?(token )?transfer", "no-matching-transfer"),
    (r"unexpected .* (instruction|transfer)", "unexpected-instruction"),
    (r"amount .* (mismatch|does not match)", "amount-mismatch"),
    # x402-exact reject categories. ``unsupported x402 version`` must be
    # matched before the generic invalid/payload fallback (the message reads
    # "invalid payload: Unsupported x402 version"); ``network mismatch``
    # likewise precedes the fallback. Mirrors harness/src/conformance/reject.ts.
    (r"unsupported x402 version", "unsupported-version"),
    (r"network mismatch", "wrong-network"),
    # x402-exact extensions: the route required a payment-identifier id but the
    # credential echoed none / an invalid one. Must precede the generic
    # invalid/payload fallback. Mirrors harness/src/conformance/reject.ts.
    (r"payment.identifier .*(required|missing|invalid)", "payment-identifier-required"),
]


def _classify_reject(message: str) -> str | None:
    import re

    for pattern, code in _REJECT_PATTERNS:
        if re.search(pattern, message, re.IGNORECASE):
            return code
    if re.search(r"invalid|malformed|decode|payload", message, re.IGNORECASE):
        return "invalid-payload"
    return None


def main() -> None:
    raw = sys.stdin.read().strip()
    if not raw:
        raise SystemExit("python conformance runner received empty stdin")
    vector = json.loads(raw)

    try:
        result = _run_vector(vector)
    except Exception as exc:  # noqa: BLE001
        message = str(exc)
        result = {"id": vector.get("id", ""), "outcome": "reject", "error": message}
        code = _classify_reject(message)
        if code is not None:
            result["rejectCode"] = code

    sys.stdout.write(json.dumps(result) + "\n")


if __name__ == "__main__":
    main()
