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
    OpenPayload,
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


# ── session server and client (draft-solana-session-00) ────────────────────
#
# Mirrors rust/crates/kit/examples/vector_runner/session.rs: the vector's
# server configuration and stored channel are handed to the SDK's own
# SessionServer and channel store, the credential is parsed with the SDK's
# wire types, and the SDK's checks decide. Nothing here re-implements them.


def _u64(value: Any, key: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        raise ValueError(f"invalid {key}")
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"invalid {key}") from exc


def _session_server(
    server: dict[str, Any],
    inp: dict[str, Any],
    store: Any,
) -> Any:
    """The SDK SessionServer the vector's ``server`` block configures."""
    from solana_pay_kit.protocols.mpp.server.session import SessionConfig, SessionServer, Split

    fee_payer_key = server.get("feePayer")
    fee_payer_signer = None
    if fee_payer_key is not None:
        secret = inp.get("sessionServerFeePayerSecretKey")
        if not secret:
            raise ValueError("server.feePayer without its secret key")
        fee_payer_signer = _local_signer(secret)
        if str(fee_payer_signer.pubkey) != fee_payer_key:
            raise ValueError("sessionServerFeePayerSecretKey is not server.feePayer")
    operator_secret = inp.get("sessionServerOperatorSecretKey")
    # Only what the vector sets; everything else stays the SDK's default.
    optional: dict[str, Any] = {}
    if server.get("gracePeriodSeconds") is not None:
        optional["grace_period_seconds"] = _u64(server["gracePeriodSeconds"], "gracePeriodSeconds")
    if server.get("idleTimeoutSeconds") is not None:
        optional["idle_timeout_seconds"] = _u64(server["idleTimeoutSeconds"], "idleTimeoutSeconds")
    if server.get("voucherSigner") is not None:
        optional["voucher_signer"] = server["voucherSigner"]
    config = SessionConfig(
        operator=server["operator"],
        recipient=server["recipient"],
        amount=_u64(server["amount"], "amount") or 0,
        currency=server["currency"],
        decimals=int(server["decimals"]),
        network=server["network"],
        splits=[
            Split(recipient=e["recipient"], bps=int(e["shareBps"])) for e in server.get("distributionSplits") or []
        ],
        token_program=server.get("tokenProgram"),
        suggested_deposit=_u64(server.get("suggestedDeposit"), "suggestedDeposit"),
        minimum_deposit=_u64(server.get("minimumDeposit"), "minimumDeposit"),
        fee_payer=fee_payer_key is not None,
        fee_payer_key=fee_payer_key,
        fee_payer_signer=fee_payer_signer,
        operator_signer=_local_signer(operator_secret) if operator_secret else None,
        idle_timeout_options_seconds=server.get("idleTimeoutOptionsSeconds"),
        transaction_versions=server.get("transactionVersions"),
        **optional,
    )
    return SessionServer(config, store)


def _stored_channel(channel: dict[str, Any]) -> Any:
    """The server's per-channel record (``channel``) as the SDK store keeps it."""
    from solana_pay_kit.protocols.mpp.server.session_store import ChannelState as StoredChannel
    from solana_pay_kit.protocols.mpp.server.session_store import ProcessedUse

    highest = channel.get("highestVoucher")
    proof = channel.get("authentication")
    return StoredChannel(
        channel_id=channel["channelId"],
        authorized_signer=channel["authorizedSigner"],
        deposit=_u64(channel["escrowedAmount"], "escrowedAmount") or 0,
        cumulative=_u64(channel["acceptedCumulative"], "acceptedCumulative") or 0,
        sealed=channel["status"] == "closed",
        open_slot=_u64(channel.get("openSlot"), "openSlot") or 0,
        payer=channel["payer"],
        rent_payer=channel["rentPayer"],
        opening_challenge_id=channel.get("openingChallengeId") or "",
        authentication=SessionAuthentication.from_dict(proof).to_dict() if proof else None,
        voucher_signer=channel["voucherSigner"],
        idle_timeout_seconds=_u64(channel.get("idleTimeoutSeconds"), "idleTimeoutSeconds"),
        spent_amount=_u64(channel["spentAmount"], "spentAmount") or 0,
        settled_on_chain=_u64(channel["settledOnChain"], "settledOnChain") or 0,
        processed_uses=[
            ProcessedUse(
                challenge_id=entry["challengeId"],
                idempotency_key=entry["idempotencyKey"],
                cumulative=_u64(entry["cumulativeAmount"], "cumulativeAmount") or 0,
                voucher_signature=entry["voucherSignature"],
                amount=_u64(entry.get("amount"), "amount"),
            )
            for entry in channel.get("processedUses") or []
        ],
        highest_voucher_signature=highest.get("signature") if highest else None,
        highest_voucher_expires_at=(int((highest.get("voucher") or {}).get("expiresAt") or 0) if highest else None),
        close_requested_at=_u64(channel.get("closureStartedAt"), "closureStartedAt"),
    )


async def _session_server_verify(vector: dict[str, Any]) -> dict[str, Any]:
    from solana_pay_kit.protocols.mpp.server import session_testkit
    from solana_pay_kit.protocols.mpp.server.session import SessionOpenContext
    from solana_pay_kit.protocols.mpp.server.session_store import MemoryChannelStore

    vector_id = vector.get("id", "")
    inp = vector["input"]
    params = inp["sessionServerVerify"]
    store = MemoryChannelStore()
    if params.get("channel"):
        state = _stored_channel(params["channel"])
        await store.update_channel(state.channel_id, lambda _current: state)
    server_json = params.get("server") or {}
    server = _session_server(server_json, inp, store)
    try:
        action = SessionAction.from_dict(params["credential"])
    except Exception as exc:
        raise ValueError(f"invalid payload: session credential: {exc}") from exc
    out: dict[str, Any] = {"id": vector_id, "outcome": "accept"}
    if action.open is not None:
        challenge = params.get("challenge") or {}
        recent_slot = _u64(challenge.get("recentSlot"), "recentSlot")
        if recent_slot is None:
            raise ValueError("challenge.recentSlot missing")
        context = SessionOpenContext(
            challenge_id=challenge.get("id", ""),
            expires="",
            recent_blockhash=challenge.get("recentBlockhash", ""),
            recent_slot=recent_slot,
        )
        await session_testkit.verify_open_pre_broadcast(server, action.open, context)
    elif action.voucher is not None:
        await server.verify_voucher(action.voucher, _u64(server_json.get("amount"), "amount"))
    elif action.top_up is not None:
        await session_testkit.verify_topup_pre_broadcast(server, action.top_up)
    elif action.close is not None:
        await server.process_close(action.close)
    elif action.use is not None:
        operator = _local_signer(inp["sessionServerOperatorSecretKey"])
        challenge_id = (params.get("challenge") or {}).get("id", "")
        idempotency_key = params.get("idempotencyKey", "")
        metered = _u64(params.get("meteredAmount"), "meteredAmount")
        if metered is None:
            voucher = await server.process_use(action.use, challenge_id, idempotency_key)
        else:
            authenticated = await server.authenticate_use(action.use, challenge_id, idempotency_key)
            voucher = (await server.charge_operator_request(authenticated, operator, metered)).voucher
        stored = await store.get_channel(voucher.data.channel_id)
        # Read back from the store: a voucher the SDK returns but does not
        # persist fails here.
        if (
            stored is None
            or stored.highest_voucher_signature != voucher.signature
            or str(stored.cumulative) != voucher.data.cumulative_amount
        ):
            raise RuntimeError("the returned use voucher is not the persisted one")
        out["sessionVoucher"] = {
            "channelId": stored.channel_id,
            "cumulativeAmount": str(stored.cumulative),
            "spentAmount": str(stored.spent_amount),
            "signer": voucher.signer,
        }
    else:
        raise ValueError("invalid payload: session credential carries no action")
    return out


async def _session_open_verify(vector: dict[str, Any]) -> dict[str, Any]:
    """``input.sessionOpenVerify``: the open parameters and transaction checks
    against the challenged blockhash (Rust ``session_open::verify``)."""
    from solana_pay_kit.protocols.mpp.server import session_testkit
    from solana_pay_kit.protocols.mpp.server.session_store import MemoryChannelStore

    inp = vector["input"]
    params = inp["sessionOpenVerify"]
    server = _session_server(params.get("server") or {}, inp, MemoryChannelStore())
    try:
        open_payload = OpenPayload.from_dict(params["open"])
    except Exception as exc:
        raise ValueError(f"invalid payload: open: {exc}") from exc
    await session_testkit.verify_open_transaction_pre_broadcast(server, open_payload, params["challengedBlockhash"])
    return {"id": vector.get("id", ""), "outcome": "accept"}


async def _session_open_build(vector: dict[str, Any]) -> dict[str, Any]:
    """``input.sessionOpenBuild``: the SDK client's open for the challenge,
    over a blockhash the client checked against its own cluster."""
    from solana_pay_kit.protocols.mpp.client.payment_channels import (
        PaymentChannelOpenOptions,
        PaymentChannelSessionOpenOptions,
        create_payment_channel_session_opener,
        verify_open_blockhash,
    )

    inp = vector["input"]
    params = inp["sessionOpenBuild"]
    try:
        request = SessionRequest.from_dict(params["request"])
    except Exception as exc:
        raise InvalidChallengeError(f"invalid challenge: {exc}") from exc
    payer = _local_signer(inp["signerSecretKey"])
    session_signer = _local_signer(inp["sessionSignerSecretKey"])
    rpc = _rpc(vector)
    try:
        blockhash = await verify_open_blockhash(rpc, request)
    finally:
        await rpc.aclose()
    opened = await create_payment_channel_session_opener(
        request,
        payer,
        session_signer,
        recent_blockhash=blockhash,
        options=PaymentChannelSessionOpenOptions(
            open=PaymentChannelOpenOptions(
                deposit=_u64(params.get("deposit"), "deposit"),
                salt=_u64(params.get("salt"), "salt"),
            )
        ),
    )
    assert opened.action.open is not None
    return {
        "id": vector.get("id", ""),
        "outcome": "accept",
        "sessionCredential": json.dumps(opened.action.to_dict()),
    }


# The shared reject codes for the SDK's session server refusals (mirrors
# ``code_for`` in rust/crates/kit/examples/vector_runner/session.rs, matched
# on the Python SDK's messages). First match wins.
_SESSION_REJECT_PATTERNS: list[tuple[str, str]] = [
    (r"transaction version .*not accepted", "unsupported-version"),
    (r"used for a different request", "invalid-challenge"),
    (r"compute unit price .*(exceed|maximum)", "compute-price-over-cap"),
    (r"compute unit limit .*(exceed|maximum)", "compute-limit-over-cap"),
    (
        r"must not contain computebudget|unsupported computebudget|computebudget instructions must",
        "unexpected-instruction",
    ),
    (
        r"invalid payload|unknown field|missing field|^decode |"
        r"transaction signature verification failed|config must set",
        "invalid-payload",
    ),
    (
        r"client close requires a final voucher|client close must|operator close must|operator close requires",
        "close-authorization",
    ),
    (
        r"authentication|does not authenticate|only valid for (an )?operator-signed|only valid for a client-signed",
        "authentication-invalid",
    ),
    (r"fee payer does not match|fee payer must be", "fee-payer-mismatch"),
    (
        r"does not match (the )?derived channel pda|action channelid .*does not match|"
        r"close voucher channelid .*does not match|do not match the stored channel|"
        r"open channel pda .* != derived|channelid .* != transaction channel",
        "channel-id-mismatch",
    ),
    (
        r"unexpected instruction|does not contain the expected open instruction|top-up instruction not found|"
        r"exactly one open instruction|no payment-channels open instruction",
        "unexpected-instruction",
    ),
    (
        r"below minimumdeposit|deposit must be greater than zero|additionalamount must be|"
        r"does not match additionalamount|insufficient authorized voucher availability|"
        r"charge amount must be positive|amount_below_price",
        "amount-mismatch",
    ),
    (
        r"open transaction|open instruction|payment-channel open|opensl|idletimeoutseconds|authorizedsigner|"
        r"privileges|open payee|open mint|open renpayer|open rentpayer|open tokenprogram|transaction deposit|"
        r"transaction salt|transaction grace period|transaction open slot|payment-channel payer",
        "open-binding-mismatch",
    ),
    (
        r"signature verification failed|signer does not match|invalid voucher signature|invalid_signature",
        "voucher-signature",
    ),
    (r"must exceed watermark|already accepted|non_monotonic|replay", "cumulative-amount-mismatch"),
    (r"exceeds deposit|insufficient channel availability|exceeds_deposit", "cumulative-exceeds-deposit"),
    (r"voucher has expired|\bexpired\b", "voucher-expired"),
    (r"settlement window|expires_before_settlement", "voucher-expires-before-settlement"),
    (r"close is pending|close already requested|closing", "channel-closing"),
    (r"already sealed|closed or close|sealed", "close-state"),
    (r"not found", "channel-state"),
    (r"address lookup tables|byte limit|session transaction|invalid|decode|signature", "invalid-payload"),
]

# Client refusals of an out-of-spec challenge (mirrors ``build_code_for``).
_SESSION_BUILD_REJECT = (
    r"challenge|network|program|tokenprogram|feepayerkey|operator|spl token|graceperiod|decimals|invalid"
)


def _session_reject(vector: dict[str, Any], exc: Exception) -> dict[str, Any]:
    import re

    message = str(exc)
    result: dict[str, Any] = {"id": vector.get("id", ""), "outcome": "reject", "error": message}
    if vector.get("mode") == "build-transaction":
        if re.search(_SESSION_BUILD_REJECT, message, re.IGNORECASE):
            result["rejectCode"] = "invalid-challenge"
        return result
    for pattern, code in _SESSION_REJECT_PATTERNS:
        if re.search(pattern, message, re.IGNORECASE):
            result["rejectCode"] = code
            break
    return result


def _run_session(vector: dict[str, Any]) -> dict[str, Any] | None:
    """The session server and client vectors, or ``None`` for the others."""
    inp = vector.get("input") or {}
    mode = vector.get("mode")
    if mode == "verify-transaction" and inp.get("sessionServerVerify"):
        run = _session_server_verify
    elif mode == "verify-transaction" and inp.get("sessionOpenVerify"):
        run = _session_open_verify
    elif mode == "build-transaction" and inp.get("sessionOpenBuild"):
        run = _session_open_build
    else:
        return None
    try:
        return asyncio.run(run(vector))
    except Exception as exc:  # noqa: BLE001
        return _session_reject(vector, exc)


def _run_vector(vector: dict[str, Any]) -> dict[str, Any]:
    vector_id = vector.get("id", "")
    mode = vector.get("mode")

    if vector.get("intent") == "x402-exact":
        return _run_x402(vector)

    if vector.get("intent") == "session" and mode in ("verify-transaction", "build-transaction"):
        session_result = _run_session(vector)
        if session_result is not None:
            return session_result
        if mode == "verify-transaction" and (vector.get("input") or {}).get("sessionVoucherVerify"):
            return _run_session_voucher_verify(vector)
        return {"id": vector_id, "outcome": "unsupported-mode", "error": f"unsupported-mode: session {mode} input"}

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
