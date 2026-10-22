"""Python cross-SDK conformance-vector runner.

Honors the same stdin/stdout contract as the TypeScript reference runner
(harness/src/conformance/ts-runner.ts) and the Go runner
(go/cmd/conformance/main.go): read one conformance vector as JSON on stdin,
drive the real Python solana_pay_kit SDK (the MPP client build, the server
RPC-free pre-broadcast verify, and the wire canonical-JSON / base64url
encoders) for the requested mode, and emit one RunnerResult line as JSON on
stdout.

The oracle for build/verify vectors is the DECODED SEMANTIC SHAPE of the
transaction (fee payer, transfer set, compute caps, memos) rather than raw
bytes, because signatures and account ordering can legitimately differ
across SDKs. The canonical-bytes mode pins exact bytes for the JCS /
base64url vectors where byte-for-byte agreement is the whole point.

Chain state comes from the driver's fixture JSON-RPC (``input.rpcUrl``),
handed to the SDK's own ``SolanaRpc``. The runner passes each request to the
SDK verbatim: it never fills defaults (decimals, token program), applies
field precedence, or resolves chain state itself
(harness/expectations/RULINGS.md).
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import sys
from typing import Any

from solana_keychain import MemorySigner
from solders.keypair import Keypair

from solana_pay_kit._paycore.errors import InvalidChallengeError
from solana_pay_kit._paycore.rpc import SolanaRpc
from solana_pay_kit._paycore.solana import (
    COMPUTE_BUDGET_PROGRAM,
    MEMO_PROGRAM,
    SYSTEM_PROGRAM,
    TOKEN_2022_PROGRAM,
    TOKEN_PROGRAM,
    MethodDetails,
)
from solana_pay_kit.protocols.mpp.client.charge import build_charge_transaction
from solana_pay_kit.protocols.mpp.core import json as wire_json
from solana_pay_kit.protocols.mpp.core.base64url import encode as base64url_encode
from solana_pay_kit.protocols.mpp.intents.charge import ChargeRequest
from solana_pay_kit.protocols.mpp.intents.session import (
    SessionAction,
    SessionAuthentication,
    SessionRequest,
    SignedVoucher,
    VoucherData,
)
from solana_pay_kit.protocols.mpp.server._verify import _verify_local_transaction_intent
from solana_pay_kit.protocols.mpp.server.session_voucher import (
    ChannelState,
    VerifyVoucherArgs,
    VoucherRejectReason,
    VoucherVerifyStatus,
    verify_voucher_for_channel,
)
from solana_pay_kit.protocols.x402 import verify_exact_credential
from solana_pay_kit.protocols.x402.client.exact.payment import (
    _caip2_for_selection,
    build_payment_header,
    build_payment_header_legacy,
)
from solana_pay_kit.protocols.x402.exact.extensions import PAYMENT_IDENTIFIER_KEY
from solana_pay_kit.protocols.x402.exact.types import X402AcceptsEntry
from solana_pay_kit.protocols.x402.exact.verify import EXACT_SCHEME, X402_VERSION_V1

_PROGRAMS = {
    TOKEN_PROGRAM,
    TOKEN_2022_PROGRAM,
}


def _rpc(vector: dict[str, Any]) -> SolanaRpc:
    """The SDK's own RPC client, pointed at the driver's fixture JSON-RPC."""
    url = (vector.get("input") or {}).get("rpcUrl")
    if not url:
        raise ValueError("driver did not inject input.rpcUrl")
    return SolanaRpc(url)


def _local_signer(secret: list[int]) -> MemorySigner:
    """Adapt a vector's 64-byte Ed25519 secret to the native async signer."""
    if len(secret) != 64:
        raise ValueError(f"signerSecretKey must be 64 bytes, got {len(secret)}")
    return MemorySigner(Keypair.from_bytes(bytes(secret)))


def _sdk_request(vector: dict[str, Any]) -> tuple[ChargeRequest, MethodDetails]:
    """Parse the vector's charge request with the SDK's own wire parsers.

    The request is handed over verbatim: whatever the SDK does with an
    omitted field (decimals, tokenProgram) is what the vector judges.
    """
    raw = (vector.get("input") or {}).get("request")
    if not raw:
        raise ValueError("build/verify vector is missing input.request")
    request = ChargeRequest.from_dict(raw)
    details = MethodDetails.from_dict(request.method_details) if request.method_details else MethodDetails()
    return request, details


async def _build_transaction(vector: dict[str, Any]) -> str:
    """Drive the real client build path and return the base64 wire transaction."""
    inp = vector.get("input") or {}
    secret = inp.get("signerSecretKey")
    if not secret:
        raise ValueError("build/verify vector is missing input.signerSecretKey")

    signer = _local_signer(secret)
    request, details = _sdk_request(vector)

    # Build-time compute overrides: reject vectors carry these to exercise
    # the server cap. ``computeUnitPrice`` arrives as a string (u64).
    compute_unit_limit = inp["request"].get("computeUnitLimit")
    compute_unit_price_raw = inp["request"].get("computeUnitPrice")
    compute_unit_price = int(compute_unit_price_raw) if compute_unit_price_raw is not None else None

    rpc = _rpc(vector)
    try:
        payload = await build_charge_transaction(
            signer=signer,
            rpc_client=rpc,
            amount=request.amount,
            currency=request.currency,
            recipient=request.recipient,
            method_details=details,
            external_id=request.external_id,
            compute_unit_limit=compute_unit_limit,
            compute_unit_price=compute_unit_price,
        )
    finally:
        await rpc.aclose()
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
    request, details = _sdk_request(vector)
    expected_fee_payer = details.fee_payer_key if (details.fee_payer and details.fee_payer_key) else None
    _verify_local_transaction_intent(transaction_b64, request, details, expected_fee_payer)


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
    # Versioned first: the legacy parser accepts a v0 wire and misreads it
    # (the 0x80 prefix lands in the header), so it is only the fallback.
    try:
        message = VersionedTransaction.from_bytes(raw).message
    except Exception:
        message = Transaction.from_bytes(raw).message

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

    vp = inp.get("voucherPreimage")
    if vp:
        # The 50-byte session voucher preimage,
        # magic(0x56,0x01) || channelId(32, base58) || cumulativeAmount LE u64
        # || expiresAt LE i64, computed by the production SDK packer
        # (VoucherData.message_bytes -> _paymentchannels.voucher_message_bytes)
        # so a byte mismatch is caught cross-SDK rather than behind a live
        # channel. Mirrors the Go runner (paymentchannels.VoucherMessageBytes).
        # An omitted expiresAt exercises the SDK's never-expires default
        # (None -> encoded verbatim as 0), the exact path the session voucher
        # signer uses.
        voucher = VoucherData(
            channel_id=vp["channelId"],
            cumulative_amount=str(vp["cumulativeAmount"]),
            expires_at=(int(vp["expiresAt"]) if vp.get("expiresAt") is not None else None),
        )
        preimage = voucher.message_bytes()
        exact["bytes"] = list(preimage)
        exact["base64Url"] = base64url_encode(preimage)

    sam = inp.get("sessionAuthenticationMessage")
    if sam:
        # The UTF-8 JSON message a payer signs to mint a reusable
        # SessionAuthentication proof, built by the PRODUCTION SDK
        # (SessionAuthentication.message_bytes) so a domain/field/ordering
        # drift is caught byte-for-byte.
        message = SessionAuthentication(
            challenge_id=sam["challengeId"],
            payer=sam["payer"],
            signature="",
        ).message_bytes(sam["channelId"])
        exact["canonicalJson"] = message.decode("utf-8")
        exact["base64Url"] = base64url_encode(message)

    sw = inp.get("sessionWire")
    if sw:
        # Round-trip the session wire shape through the PRODUCTION parser and
        # serializer, then JCS-canonicalize. A field the SDK renamed, dropped,
        # or retyped either fails the parse (reject) or diverges from the
        # frozen canonical bytes.
        try:
            if sw["shape"] == "request":
                decoded = SessionRequest.from_dict(sw["value"]).to_dict()
            elif sw["shape"] == "action":
                decoded = SessionAction.from_dict(sw["value"]).to_dict()
            else:
                raise ValueError(f"unknown sessionWire shape {sw['shape']!r}")
        except Exception as exc:
            raise ValueError(f"invalid session payload: {exc}") from exc
        canonical = wire_json.encode_canonical(decoded)
        exact["canonicalJson"] = canonical.decode("utf-8")
        exact["base64Url"] = base64url_encode(canonical)

    return exact


# ── x402-exact intent ──────────────────────────────────────────────────────
#
# The x402 charge is HTTP-shaped, not transaction-shaped: a CLIENT build
# produces a base64(JSON) payment header and a SERVER verify consumes one.
# The cross-SDK oracle is the DECODED ENVELOPE shape (x402Version, v1
# top-level scheme/network vs v2 accepted, payloadHasTransaction):
#   - build  -> solana_pay_kit build_payment_header(_legacy), which reads the
#               mint through the fixture RPC and signs a real transfer.
#   - verify -> solana_pay_kit verify_exact_credential, the server's full
#               pre-broadcast check (envelope binding, payment-identifier,
#               ExactVerifier on the transaction, fee-payer cosign).


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
    """Drive the real solana_pay_kit x402 client to build a payment header.

    The offer is the vector's ``x402Offer``, passed verbatim. The client
    fetches the blockhash and the mint (token program, decimals) through the
    fixture RPC and signs a real transfer with the vector's signer; the memo
    is the client's own random nonce. ``x402Version: 1`` drives the legacy
    ``X-PAYMENT`` producer, anything else the canonical v2 one.
    """
    inp = vector.get("input") or {}
    offer = inp.get("x402Offer")
    if not offer:
        raise ValueError("x402 build vector is missing input.x402Offer")

    secret = inp.get("signerSecretKey")
    if not secret:
        raise ValueError("x402 build vector is missing input.signerSecretKey")
    # The vector's signer, not an ephemeral one: pkc compares the built
    # transaction with the Rust kit's build for the same key.
    signer = _local_signer(secret)
    rpc = _rpc(vector)
    try:
        if inp.get("x402Version") == X402_VERSION_V1:
            # The legacy v1 producer has no `extensions` concept.
            return await build_payment_header_legacy(signer, rpc, offer)
        return await build_payment_header(
            signer,
            rpc,
            offer,
            advertised_extensions=inp.get("x402AdvertisedExtensions"),
            payment_identifier_id=inp.get("x402PaymentIdentifierId"),
        )
    finally:
        await rpc.aclose()


def _x402_route_offer(inp: dict[str, Any]) -> X402AcceptsEntry:
    """The server's own x402 requirements for the vector's route.

    This is configuration, not chain state: scheme, network, amount, asset,
    payTo and the sponsor in ``extra.feePayer``. The SDK verifier binds the
    credential to it and checks the transaction against it.
    """
    for key in ("x402ServerNetwork", "x402ServerRecipient", "x402ServerCurrency", "x402ServerAmount"):
        if inp.get(key) is None:
            raise ValueError(f"x402 verify vector is missing input.{key}")
    fee_payer = inp.get("x402ServerFeePayer")
    if not fee_payer:
        raise ValueError("x402 verify vector is missing input.x402ServerFeePayer")
    extra: dict[str, Any] = {"feePayer": fee_payer}
    # The route's extra.memo, which the verifier must enforce (§3.1).
    if inp.get("x402ServerMemo"):
        extra["memo"] = inp["x402ServerMemo"]
    return {
        "scheme": EXACT_SCHEME,
        "network": _caip2_for_selection(inp["x402ServerNetwork"]),
        "amount": inp["x402ServerAmount"],
        "asset": inp["x402ServerCurrency"],
        "payTo": inp["x402ServerRecipient"],
        "maxTimeoutSeconds": 300,
        "extra": extra,
    }


async def _x402_verify(vector: dict[str, Any]) -> dict[str, Any]:
    """Drive the SDK's real x402 server verification (no broadcast).

    Returns the decoded envelope shape on accept; raises the SDK's error on
    reject.
    """
    inp = vector.get("input") or {}
    header = inp.get("x402PaymentHeader")
    if not header:
        raise ValueError("x402 verify vector is missing input.x402PaymentHeader")
    secret = inp.get("x402ServerFeePayerSecretKey")
    if not secret:
        raise ValueError("x402 verify vector is missing input.x402ServerFeePayerSecretKey")
    fee_payer = _local_signer(secret)
    offer = _x402_route_offer(inp)
    if str(fee_payer.pubkey) != offer["extra"].get("feePayer"):
        raise ValueError("x402ServerFeePayerSecretKey does not match x402ServerFeePayer")
    await verify_exact_credential(
        header,
        offer,
        fee_payer,
        require_payment_identifier=bool(inp.get("x402ServerRequiresPaymentIdentifier")),
    )
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
            # The built header, so pkc can verify it with the Rust kit.
            "x402PaymentHeader": header,
        }

    if mode == "verify-transaction":
        shape = asyncio.run(_x402_verify(vector))
        return {"id": vector_id, "outcome": "accept", "x402EnvelopeShape": shape}

    # Any other mode for the x402 intent has no Python equivalent.
    raise ValueError(f"unsupported-mode: {mode}")


_VOUCHER_REJECT_CODES = {
    VoucherRejectReason.EXPIRED: "voucher-expired",
    VoucherRejectReason.EXPIRES_BEFORE_SETTLEMENT: "voucher-expires-before-settlement",
}


def _run_session_voucher_verify(vector: dict[str, Any]) -> dict[str, Any]:
    """Sign one voucher with the vector key and drive the production verifier
    against a fresh channel at the pinned clock."""
    vector_id = vector.get("id", "")
    inp = vector["input"]
    params = inp["sessionVoucherVerify"]
    keypair = Keypair.from_bytes(bytes(inp["signerSecretKey"]))
    data = VoucherData(
        channel_id=params["channelId"],
        cumulative_amount=str(params["cumulativeAmount"]),
        expires_at=int(params["expiresAt"]),
    )
    signed = SignedVoucher(
        data=data, signer=str(keypair.pubkey()), signature=str(keypair.sign_message(data.message_bytes()))
    )
    deposit = int(params["deposit"])
    result = verify_voucher_for_channel(
        VerifyVoucherArgs(
            state=ChannelState(
                channel_id=params["channelId"], authorized_signer=str(keypair.pubkey()), deposit=deposit
            ),
            signed=signed,
            deposit=deposit,
            now_seconds=int(params["nowSeconds"]),
            settlement_window=int(params["settlementWindowSeconds"]),
        )
    )
    if result.status == VoucherVerifyStatus.ACCEPTED:
        return {"id": vector_id, "outcome": "accept"}
    out: dict[str, Any] = {"id": vector_id, "outcome": "reject", "error": f"{result.reason}: {result.detail}"}
    code = _VOUCHER_REJECT_CODES.get(result.reason) if result.reason is not None else None
    if code is not None:
        out["rejectCode"] = code
    return out


def _run_vector(vector: dict[str, Any]) -> dict[str, Any]:
    vector_id = vector.get("id", "")
    mode = vector.get("mode")

    if vector.get("intent") == "x402-exact":
        return _run_x402(vector)

    if vector.get("intent") == "session" and mode == "verify-transaction":
        if not (vector.get("input") or {}).get("sessionVoucherVerify"):
            return {"id": vector_id, "outcome": "unsupported-mode", "error": "unsupported-mode: session verify input"}
        return _run_session_voucher_verify(vector)

    if vector.get("intent") == "session" and mode == "build-transaction":
        return {
            "id": vector_id,
            "outcome": "unsupported-mode",
            "error": "unsupported-mode: no session client open builder path (input.sessionOpenBuild)",
        }

    if mode == "canonical-bytes":
        return {"id": vector_id, "outcome": "accept", "exactBytes": _run_canonical_bytes(vector)}

    if mode == "build-transaction":
        tx = asyncio.run(_build_transaction(vector))
        # The built transaction, so pkc can verify it with the Rust kit.
        return {
            "id": vector_id,
            "outcome": "accept",
            "transactionShape": _shape_from_transaction(tx),
            "transaction": tx,
        }

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
    # Charge verification policy and client challenge checks (mirrors the
    # block at the top of harness/src/conformance/reject.ts).
    # RULINGS SIG1: a client signature that does not verify over the
    # message, or a signature list short of the required signers.
    (r"signature verification failed", "invalid-payload"),
    (r"fee payer (token account )?cannot fund", "fee-payer-is-funds-source"),
    (r"primary amount is zero after splits|split amounts exceed", "splits-exceed-amount"),
    (r"splits exceed maximum", "too-many-splits"),
    (r"ata creation owner is not authorized|unsupported compute budget|unexpected_signer", "unexpected-instruction"),
    (
        r"atacreationrequired requires|unsupported challenge network|invalid amount|requires feepayerkey",
        "invalid-challenge",
    ),
    (r"ata creation|ata payer|transaction fee payer (must be|mismatch)|memo cannot exceed", "invalid-payload"),
    # x402 v2: the credential's `accepted` matches none of the route's
    # requirements (the SDK's offer match). Before the amount pattern.
    (r"charge_request_mismatch|accepted payment requirement does not match", "accepted-mismatch"),
    # x402 exact SVM verifier reasons.
    (r"fee_payer_transferring_funds|fee_payer_in_instruction_accounts", "fee-payer-not-authority"),
    (r"unknown_(fourth|fifth|sixth|optional)_instruction|instructions_length", "unexpected-instruction"),
    (r"no_transfer_instruction|recipient_mismatch|mint_mismatch", "no-matching-transfer"),
    (r"_amount_mismatch", "amount-mismatch"),
    (r"no memo instruction found|memo_mismatch|memo_count", "invalid-payload"),
    (r"no matching sol transfer", "no-matching-transfer"),
    (r"compute unit price .* exceeds (cap|maximum)", "compute-price-over-cap"),
    (r"compute unit limit .* exceeds (cap|maximum)", "compute-limit-over-cap"),
    (r"fee payer cannot authorize", "fee-payer-not-authority"),
    (r"fee payer .* (funding source|funds source)", "fee-payer-is-funds-source"),
    (r"splits consume the entire amount", "splits-exceed-amount"),
    (r"too many splits", "too-many-splits"),
    (r"no matching (spl )?(token )?transfer", "no-matching-transfer"),
    (r"share one funding authority", "mixed-funding-authority"),
    (r"unexpected signer", "unexpected-signer"),
    (r"unexpected .* (instruction|transfer)", "unexpected-instruction"),
    (r"amount .* (mismatch|does not match)", "amount-mismatch"),
    # x402-exact reject categories. ``unsupported x402 version`` must be
    # matched before the generic invalid/payload fallback (the message reads
    # "invalid payload: Unsupported x402 version"); ``network mismatch``
    # likewise precedes the fallback. Mirrors harness/src/conformance/reject.ts.
    (r"unsupported[ _]x402[ _]version", "unsupported-version"),
    (r"network mismatch", "wrong-network"),
    # x402-exact extensions: the route required a payment-identifier id but the
    # credential echoed none / an invalid one. Must precede the generic
    # invalid/payload fallback. Mirrors harness/src/conformance/reject.ts.
    (r"payment.identifier .*(required|missing|invalid)", "payment-identifier-required"),
]


def _classify_reject(exc: Exception) -> str | None:
    import re

    # A client refusing a challenge that violates the method spec (decimals
    # missing for a mint, a token program that cannot be read from the mint).
    if isinstance(exc, InvalidChallengeError):
        return "invalid-challenge"
    message = str(exc)

    for pattern, code in _REJECT_PATTERNS:
        if re.search(pattern, message, re.IGNORECASE):
            return code
    if re.search(r"invalid|malformed|decode|payload", message, re.IGNORECASE):
        return "invalid-payload"
    return None


def _result_for(vector: dict[str, Any]) -> dict[str, Any]:
    try:
        return _run_vector(vector)
    except Exception as exc:  # noqa: BLE001
        message = str(exc)
        result = {"id": vector.get("id", ""), "outcome": "reject", "error": message}
        code = _classify_reject(exc)
        if code is not None:
            result["rejectCode"] = code
        return result


# Intents this runner implements; pkc checks them against
# harness/expectations/python.toml.
_INTENTS = ["charge", "x402-exact", "session"]


def _serve() -> None:
    """Testee ABI v2 (harness/README.md): newline JSON ``{id, op, input}`` in,
    ``{id, ok, result | error}`` out, one long-lived process. ``input`` is the
    v1 vector and ``result`` the v1 RunnerResult."""
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            request = json.loads(line)
        except ValueError as exc:
            response: dict[str, Any] = {"id": None, "ok": False, "error": "bad-request", "detail": str(exc)}
        else:
            rid, op = request.get("id"), request.get("op")
            if op == "capabilities":
                result = {"abi": 2, "language": "python", "intents": _INTENTS, "honoursClock": True}
                response = {"id": rid, "ok": True, "result": result}
            elif op in ("build", "verify", "canonical-bytes"):
                response = {"id": rid, "ok": True, "result": _result_for(request.get("input") or {})}
            else:
                response = {"id": rid, "ok": False, "error": "unknown-op", "detail": str(op)}
        sys.stdout.write(json.dumps(response) + "\n")
        sys.stdout.flush()


def main() -> None:
    if "--serve" in sys.argv[1:]:
        _serve()
        return
    raw = sys.stdin.read().strip()
    if not raw:
        raise SystemExit("python conformance runner received empty stdin")
    sys.stdout.write(json.dumps(_result_for(json.loads(raw))) + "\n")


if __name__ == "__main__":
    main()
