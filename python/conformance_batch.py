"""``x402-batch-settlement`` vectors for the Python conformance runner.

The testee passes each vector's input to the SDK unchanged, mirroring the Rust
testee (``rust/crates/kit/examples/vector_runner/batch.rs``):

- canonical-bytes: the SDK's voucher layout, payer-proof message, channel PDA,
  CloseAuthorization digest, receiver-binding memo and wire types;
- verify-transaction: ``X402BatchSettlement`` configured from ``batchServer``,
  its store seeded with the record ``batchServerChannel`` describes, runs
  ``verify_and_reserve_payment`` against ``input.rpcUrl``; ``batchCorrective``
  runs the client's ``adopt_corrective_state``;
- build-transaction: the SDK client (``resolve_terms`` on ``input.rpcUrl``,
  then ``build_deposit`` / ``voucher_payload`` / ``build_top_up`` /
  ``build_refund``, then ``encode_payment_header``).

Rejections carry the spec's error code mapped onto the shared vocabulary.
"""

from __future__ import annotations

import asyncio
from typing import Any

from solana_keychain import MemorySigner
from solders.hash import Hash
from solders.keypair import Keypair

from solana_pay_kit._paycore.paymentchannels import PROGRAM_ID, voucher_message_bytes
from solana_pay_kit._paycore.rpc import SolanaRpc
from solana_pay_kit.protocols.mpp.core import json as wire_json
from solana_pay_kit.protocols.mpp.core.base64url import encode as base64url_encode
from solana_pay_kit.protocols.x402.batch_settlement import errors as codes
from solana_pay_kit.protocols.x402.batch_settlement.server import (
    BatchAccessKind,
    BatchConfig,
    InvalidPaymentRequiredError,
    UnsupportedSchemeError,
    X402BatchSettlement,
)
from solana_pay_kit.protocols.x402.batch_settlement.store import BatchChannelRecord, MemoryBatchChannelStore
from solana_pay_kit.protocols.x402.batch_settlement.types import (
    BatchChannelConfig,
    BatchRequirements,
    BatchVoucher,
    wire_roundtrip,
)
from solana_pay_kit.protocols.x402.batch_settlement.verify import (
    CloseAuthorizationScope,
    authorization_message_bytes,
    close_authorization_digest,
    derive_channel_id,
    parse_pubkey,
    receiver_binding_memo,
)
from solana_pay_kit.protocols.x402.client.batch_settlement import (
    BatchChannel,
    build_deposit,
    build_refund,
    build_top_up,
    channel_id_for,
    encode_payment_header,
    resolve_terms,
)

INTENT = "x402-batch-settlement"

_CODES = {
    codes.INVALID_PAYLOAD_TYPE: "payload-type",
    codes.INVALID_PAYMENT_FLOW: "payment-flow",
    codes.INVALID_TOKEN_PROGRAM: "token-program",
    codes.INVALID_VOUCHER_SIGNATURE: "voucher-signature",
    codes.INVALID_CHANNEL_ID_MISMATCH: "channel-id-mismatch",
    codes.INVALID_FEE_PAYER_MISMATCH: "fee-payer-mismatch",
    codes.INVALID_RECEIVER_AUTHORIZER_MISMATCH: "receiver-authorizer-mismatch",
    codes.INVALID_CLOSE_AUTHORIZATION: "close-authorization",
    codes.INVALID_CLOSE_AMOUNT_UNSUPPORTED: "close-amount-unsupported",
    codes.INVALID_CLOSE_STATE: "close-state",
    codes.INVALID_WITHDRAW_DELAY_MISMATCH: "withdraw-delay-mismatch",
    codes.INVALID_WITHDRAW_DELAY_OUT_OF_RANGE: "withdraw-delay-out-of-range",
    codes.INVALID_CUMULATIVE_AMOUNT_MISMATCH: "cumulative-amount-mismatch",
    codes.INVALID_CUMULATIVE_EXCEEDS_DEPOSIT: "cumulative-exceeds-deposit",
    codes.INVALID_VOUCHER_EXPIRY: "voucher-expiry",
    codes.INVALID_SETUP_TRANSACTION: "setup-transaction",
    codes.INVALID_SETTLEMENT_SIMULATION: "settlement-simulation",
    codes.INVALID_CHANNEL_STATE: "channel-state",
    codes.INVALID_REFUND_TRANSACTION: "refund-transaction",
    codes.INVALID_CHANNEL_CLOSING: "channel-closing",
    codes.INVALID_RECEIVER_BINDING_UNAVAILABLE: "receiver-binding-unavailable",
    codes.INVALID_X402_VERSION: "unsupported-version",
    codes.UNSUPPORTED_TRANSACTION_VERSION: "unsupported-version",
    codes.INVALID_PAYMENT_REQUIREMENTS: "accepted-mismatch",
    codes.DUPLICATE_SETTLEMENT: "duplicate-settlement",
}


class _Unsupported(Exception):
    pass


def _reject(vector_id: str, message: str, code: str | None) -> dict[str, Any]:
    out: dict[str, Any] = {"id": vector_id, "outcome": "reject", "error": message}
    if code is not None:
        out["rejectCode"] = code
    return out


def _kit_code(exc: BaseException) -> str | None:
    code = _CODES.get(codes.classify(str(exc)))
    if code is not None:
        return code
    if isinstance(exc, UnsupportedSchemeError):
        return "unsupported-scheme"
    if isinstance(exc, InvalidPaymentRequiredError):
        return "invalid-payload"
    return None


def _client_code(exc: BaseException) -> str:
    code = _CODES.get(codes.classify(str(exc)))
    if code is not None:
        return code
    if "the server accepts transaction versions" in str(exc):
        return "unsupported-version"
    return "invalid-challenge"


def _bytes_outcome(vector_id: str, raw: bytes) -> dict[str, Any]:
    return {"id": vector_id, "outcome": "accept", "exactBytes": {"bytes": list(raw), "base64Url": base64url_encode(raw)}}


def _str(obj: dict[str, Any], key: str) -> str:
    value = obj.get(key)
    return value if isinstance(value, str) else ""


def _u64(obj: dict[str, Any], key: str) -> int:
    value = obj.get(key)
    if isinstance(value, str) and value.isdigit():
        return int(value)
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    raise ValueError(f"invalid {key}")


def _signer(obj: dict[str, Any], key: str) -> MemorySigner:
    return MemorySigner(Keypair.from_bytes(bytes(obj[key])))


def _canonical(vector_id: str, inp: dict[str, Any]) -> dict[str, Any]:
    def invalid(message: str) -> dict[str, Any]:
        return _reject(vector_id, message, "invalid-payload")

    if "batchVoucherMessage" in inp:
        vm = inp["batchVoucherMessage"]
        try:
            voucher = BatchVoucher.from_dict(
                {
                    "channelId": vm.get("channelId"),
                    "maxClaimableAmount": vm.get("maxClaimableAmount"),
                    "expiresAt": vm.get("expiresAt"),
                    "signature": "",
                }
            )
            raw = voucher_message_bytes(parse_pubkey(voucher.channel_id), voucher.max_claimable(), voucher.expires_at)
        except ValueError as exc:
            return invalid(f"invalid voucher: {exc}")
        return _bytes_outcome(vector_id, raw)
    if "batchAuthorizationMessage" in inp:
        am = inp["batchAuthorizationMessage"]
        try:
            raw = authorization_message_bytes(
                parse_pubkey(_str(am, "channelId")),
                parse_pubkey(_str(am, "payer")),
                parse_pubkey(_str(am, "operator")),
                _str(am, "requestId"),
                _u64(am, "authorizedAmount"),
                am.get("expiresAt") if isinstance(am.get("expiresAt"), int) else 0,
            )
        except ValueError as exc:
            return invalid(str(exc))
        return _bytes_outcome(vector_id, raw)
    if "batchCloseAuthorizationDigest" in inp:
        cd = inp["batchCloseAuthorizationDigest"]
        try:
            scope = CloseAuthorizationScope(
                network=_str(cd, "network"),
                program_id=parse_pubkey(_str(cd, "programId")),
                fee_payer=parse_pubkey(_str(cd, "feePayer")),
                channel_id=parse_pubkey(_str(cd, "channelId")),
                max_claimable_amount=_u64(cd, "maxClaimableAmount"),
                voucher_expires_at=int(cd["voucherExpiresAt"]),
            )
            raw = close_authorization_digest(scope, int(cd["validBefore"]))
        except (ValueError, KeyError, codes.BatchSettlementError) as exc:
            return invalid(str(exc))
        return _bytes_outcome(vector_id, raw)
    if "batchReceiverBindingMemo" in inp:
        try:
            key = parse_pubkey(_str(inp["batchReceiverBindingMemo"], "receiverAuthorizer"))
        except ValueError as exc:
            return invalid(str(exc))
        return _bytes_outcome(vector_id, receiver_binding_memo(key).encode("utf-8"))
    if "batchChannelId" in inp:
        ci = inp["batchChannelId"]
        try:
            config = BatchChannelConfig.from_dict(ci.get("channelConfig"))
            channel = derive_channel_id(config, _str(ci, "feePayer"), PROGRAM_ID)
        except (ValueError, codes.BatchSettlementError) as exc:
            return invalid(f"invalid channelConfig: {exc}")
        return _bytes_outcome(vector_id, bytes(channel))
    if "batchWire" in inp:
        wire = inp["batchWire"]
        shape = _str(wire, "shape")
        if shape not in ("requirements", "paymentPayload", "payload", "redemption", "settlementResponse", "paymentRequired"):
            raise _Unsupported(f"batchWire shape {shape!r}")
        try:
            value = wire_roundtrip(shape, wire.get("value"))
        except ValueError as exc:
            return invalid(f"invalid batch-settlement wire object: {exc}")
        canonical = wire_json.encode_canonical(value)
        return {
            "id": vector_id,
            "outcome": "accept",
            "exactBytes": {"canonicalJson": canonical.decode("utf-8"), "base64Url": base64url_encode(canonical)},
        }
    raise _Unsupported("no batch-settlement canonical-bytes key in input")


def _server(server: dict[str, Any], rpc_url: str, store: MemoryBatchChannelStore) -> X402BatchSettlement:
    versions = server.get("transactionVersions")
    v1 = isinstance(versions, list) and 1 in versions
    config = BatchConfig(
        pay_to=_str(server, "payTo"),
        cluster=_str(server, "cluster"),
        fee_payer_signer=_signer(server, "feePayerSecretKey"),
        currency=_str(server, "currency"),
        decimals=int(server["decimals"]),
        max_timeout_seconds=_u64(server, "maxTimeoutSeconds"),
        withdraw_delay=_u64(server, "withdrawDelay"),
        memo=server.get("memo") if isinstance(server.get("memo"), str) else None,
        receiver_authorizer=server.get("receiverAuthorizer") if isinstance(server.get("receiverAuthorizer"), str) else None,
        rpc_url=rpc_url,
        transaction_versions=(0, 1) if v1 else (0,),
    )
    return X402BatchSettlement(config, store)


async def _seed(server: X402BatchSettlement, store: MemoryBatchChannelStore, record: dict[str, Any]) -> None:
    close_requested = record.get("closeRequestedAt")
    await store.put(
        BatchChannelRecord(
            channel_id=_str(record, "channelId"),
            payer_authorizer=_str(record, "payerAuthorizer"),
            payer=_str(record, "payer"),
            rent_payer=server.fee_payer,
            deposit=_u64(record, "deposit"),
            cumulative=_u64(record, "chargedCumulativeAmount"),
            open_slot=_u64(record, "openSlot"),
            settled_on_chain=_u64(record, "settled") if "settled" in record else 0,
            close_requested_at=close_requested if isinstance(close_requested, int) else None,
            sealed=record.get("sealed") is True,
            binding=server.binding(),
        )
    )


async def _server_verify(vector_id: str, inp: dict[str, Any]) -> dict[str, Any]:
    server_json = inp["batchServer"]
    store = MemoryBatchChannelStore()
    server = _server(server_json, inp["rpcUrl"], store)
    if "batchServerChannel" in inp:
        await _seed(server, store, inp["batchServerChannel"])
    try:
        access = await server.verify_and_reserve_payment(_str(inp, "x402PaymentHeader"), _str(server_json, "price"))
    except Exception as exc:  # noqa: BLE001
        return _reject(vector_id, str(exc), _kit_code(exc))
    if access.outcome is not None:
        access.outcome.release()
    if access.kind in (BatchAccessKind.SERVE, BatchAccessKind.CONTROL):
        return {"id": vector_id, "outcome": "accept"}
    return _reject(vector_id, "verify did not serve the request (replay or in progress)", None)


def _tracker(channel: dict[str, Any], requirements: BatchRequirements) -> BatchChannel:
    config = BatchChannelConfig.from_dict(channel.get("channelConfig"))
    return BatchChannel(
        channel_id_for(config, requirements), config, _u64(channel, "chargedCumulativeAmount"), _u64(channel, "deposit")
    )


def _corrective(vector_id: str, inp: dict[str, Any]) -> dict[str, Any]:
    c = inp["batchCorrective"]
    requirements = BatchRequirements.from_dict(c["requirements"])
    channel = _tracker(c["channel"], requirements)
    try:
        channel.adopt_corrective_state(requirements)
    except Exception as exc:  # noqa: BLE001
        return _reject(vector_id, str(exc), _kit_code(exc))
    return {"id": vector_id, "outcome": "accept"}


async def _client_build(vector_id: str, inp: dict[str, Any]) -> dict[str, Any]:
    c = inp["batchClient"]
    try:
        requirements = BatchRequirements.from_dict(c.get("requirements"))
    except ValueError as exc:
        return _reject(vector_id, str(exc), _client_code(exc))
    payer = _signer(c, "secretKey")
    rpc = SolanaRpc(inp["rpcUrl"])
    raw_max = c.get("maxTransactionVersion")
    max_version = None if not isinstance(raw_max, int) else (0 if raw_max == 0 else 1)
    try:
        terms = await resolve_terms(rpc, requirements, max_version)
    except Exception as exc:  # noqa: BLE001
        return _reject(vector_id, str(exc), _client_code(exc))
    operation = _str(c, "operation")
    if operation not in ("deposit", "voucher", "topUp", "refund"):
        raise _Unsupported(f"batchClient.operation {operation!r}")
    try:
        if operation == "deposit":
            _, payload = await build_deposit(
                payer, requirements, terms, _u64(c, "depositAmount"), Hash.from_string(_str(c, "blockhash")), _u64(c, "openSlot")
            )
        elif operation == "voucher":
            payload = await _tracker(c["channel"], requirements).voucher_payload(payer, terms.amount)
        elif operation == "topUp":
            payload = await build_top_up(
                payer, _tracker(c["channel"], requirements), terms, _u64(c, "depositAmount"), Hash.from_string(_str(c, "blockhash"))
            )
        else:
            payload = await build_refund(payer, _tracker(c["channel"], requirements), terms)
        header = encode_payment_header(requirements, payload)
    except Exception as exc:  # noqa: BLE001
        return _reject(vector_id, str(exc), _client_code(exc))
    return {"id": vector_id, "outcome": "accept", "x402PaymentHeader": header}


def run(vector: dict[str, Any]) -> dict[str, Any]:
    """Run one ``x402-batch-settlement`` vector through the SDK."""
    vector_id = vector.get("id", "")
    mode = vector.get("mode")
    inp = vector.get("input") or {}
    try:
        if mode == "canonical-bytes":
            return _canonical(vector_id, inp)
        if mode == "verify-transaction" and "batchCorrective" in inp:
            return _corrective(vector_id, inp)
        if mode == "verify-transaction":
            return asyncio.run(_server_verify(vector_id, inp))
        if mode == "build-transaction":
            return asyncio.run(_client_build(vector_id, inp))
    except _Unsupported as exc:
        return {"id": vector_id, "outcome": "unsupported-mode", "error": f"unsupported-mode: {exc}"}
    return {"id": vector_id, "outcome": "unsupported-mode", "error": f"unsupported-mode: {mode}"}
