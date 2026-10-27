"""``x402-upto`` vectors for the Python conformance runner.

The vector input goes to the SDK unchanged (harness/AGENTS.md):

  build  -> ``solana_pay_kit.protocols.x402.client.upto.build_upto_header``,
            with the vector's offer, signer, ``x402UptoExpiresAt`` and
            ``x402UptoRequestNonce``, ``x402ClientMaxTransactionVersion`` and
            the fixture RPC (read only when the offer omits a hint).
  verify -> ``verify_upto_open_preflight``, every check ``X402Upto.verify_open``
            makes before it broadcasts the open (co-signature included), against
            the requirement ``upto_requirements`` builds for the ``x402Server*``
            route, at the vector's clock, reading the fixture RPC.
  canonical bytes -> the voucher message (``voucher_message_bytes``), the
            distribution hash and the channel PDA the SDK binds a channel to.

Reject categories come from the SDK's error message, mirroring the Rust kit's
``code_for`` (rust/crates/conformance/src/realize/upto.rs).
"""

from __future__ import annotations

import asyncio
from typing import Any

from solana_keychain import MemorySigner
from solders.keypair import Keypair  # type: ignore[import-untyped]
from solders.pubkey import Pubkey  # type: ignore[import-untyped]

from solana_pay_kit._paycore.paymentchannels import (
    PROGRAM_ID,
    Distribution,
    distribution_hash,
    find_channel_pda,
    voucher_message_bytes,
)
from solana_pay_kit._paycore.rpc import SolanaRpc
from solana_pay_kit._paycore.txv1 import parse_transaction_versions
from solana_pay_kit.protocols.mpp.core.base64url import encode as base64url_encode
from solana_pay_kit.protocols.x402.client.exact.payment import _caip2_for_selection
from solana_pay_kit.protocols.x402.client.upto import build_upto_header
from solana_pay_kit.protocols.x402.upto import (
    UptoRoute,
    route_memo,
    upto_requirements,
    verify_upto_open_preflight,
)


class Reject(Exception):
    def __init__(self, message: str, code: str | None) -> None:
        super().__init__(message)
        self.code = code


def code_for(message: str) -> str | None:
    """The shared reject code for an SDK upto error message (the Rust kit's
    ``code_for``, check for check)."""
    m = message.lower()

    def has(needle: str) -> bool:
        return needle in m

    if has("invalid_upto_svm_payload_unexpected_voucher"):
        return "unexpected-voucher"
    if has("invalid_upto_svm_payload_type"):
        return "unexpected-type"
    if has("invalid_upto_svm_channel_already_open"):
        return "channel-already-open"
    if has("invalid_upto_svm_payload_channel_lifetime_exceeded"):
        return "channel-lifetime-exceeded"
    if has("invalid_upto_svm_payload_expires_at_mismatch"):
        return "expires-at-mismatch"
    if has("unexpected signer"):
        return "unexpected-instruction"
    if has("is not accepted; accepted versions") or has("signer signs up to version"):
        return "unsupported-version"
    if has("compute unit price") and (has("exceed") or has("maximum")):
        return "compute-price-over-cap"
    if has("compute unit limit") and (has("exceed") or has("maximum")):
        return "compute-limit-over-cap"
    if has("must not reference the fee payer"):
        return "fee-payer-not-authority"
    if (
        has("fee payer must be the advertised fee payer")
        or has("loaded accounts data size")
        or has("must set computeunitlimit")
    ):
        return "invalid-payload"
    if any(
        has(n)
        for n in (
            "computebudget",
            "setcomputeunit",
            "compute unit limit must be positive",
            "no payment-channels instruction",
            "targets an unexpected program",
            "is not a payment-channels",
            "instructions after",
            "lighthouse instructions",
            "must be lighthouse or memo",
        )
    ):
        return "unexpected-instruction"
    if has("memo"):
        return "invalid-payload"
    if has("open transaction channel mismatch") or has("open channel pda"):
        return "channel-id-mismatch"
    if any(
        has(n)
        for n in (
            "open transaction",
            "open salt",
            "open slot",
            "open withdraw delay",
            "open deposit",
            "open distribution",
            "open instruction",
        )
    ):
        return "open-binding-mismatch"
    if has("amount mismatch"):
        return "amount-mismatch"
    if has("channel deposit") and has("authorized maximum"):
        return "deposit-not-ceiling"
    if has("not yet active"):
        return "not-yet-active"
    if has("authorization expired"):
        return "voucher-expired"
    if has("advertised receiver authorizer"):
        return "receiver-authorizer-mismatch"
    if has("network mismatch") or has("does not match any offered") or has("invalid payload type"):
        return "accepted-mismatch"
    if any(
        has(n)
        for n in ("address lookup tables", "byte limit", "exceeds", "invalid", "requires opentransaction", "decode")
    ):
        return "invalid-payload"
    if has("withdrawdelay") or has("missing field"):
        return "invalid-challenge"
    return None


def _signer(secret: Any, key: str) -> MemorySigner:
    if not isinstance(secret, list) or len(secret) != 64:
        raise ValueError(f"input.{key} must be a 64-byte secret key")
    return MemorySigner(Keypair.from_bytes(bytes(secret)))


def _rpc(inp: dict[str, Any]) -> SolanaRpc:
    url = inp.get("rpcUrl")
    if not url:
        raise ValueError("driver did not inject input.rpcUrl")
    return SolanaRpc(url)


async def _build(inp: dict[str, Any]) -> dict[str, Any]:
    offer = inp.get("x402Offer")
    if not isinstance(offer, dict):
        raise ValueError("upto build vector is missing input.x402Offer")
    signer = _signer(inp.get("signerSecretKey"), "signerSecretKey")
    expires_at = inp.get("x402UptoExpiresAt")
    if not isinstance(expires_at, int):
        raise ValueError("upto build vector is missing input.x402UptoExpiresAt")
    rpc = _rpc(inp)
    try:
        header = await build_upto_header(
            signer,
            offer,  # type: ignore[arg-type]
            expires_at,
            inp.get("x402UptoRequestNonce") or None,
            rpc=rpc,
            max_transaction_version=inp.get("x402ClientMaxTransactionVersion"),
        )
    except Exception as exc:  # noqa: BLE001 - the build input is the challenge alone
        message = str(exc)
        code = "unsupported-version" if code_for(message) == "unsupported-version" else "invalid-challenge"
        raise Reject(message, code) from exc
    finally:
        await rpc.aclose()
    return {"outcome": "accept", "x402PaymentHeader": header}


def _route(inp: dict[str, Any]) -> UptoRoute:
    def required(key: str) -> Any:
        if inp.get(key) is None:
            raise ValueError(f"upto verify vector is missing input.{key}")
        return inp[key]

    memo = route_memo(inp["x402ServerRoute"]) if inp.get("x402ServerRoute") else inp.get("x402ServerMemo")
    return UptoRoute(
        network=_caip2_for_selection(required("x402ServerNetwork")),
        amount=int(required("x402ServerAmount")),
        asset=required("x402ServerCurrency"),
        token_program=required("x402ServerTokenProgram"),
        pay_to=required("x402ServerRecipient"),
        fee_payer=required("x402ServerFeePayer"),
        receiver_authorizer=required("x402ServerReceiverAuthorizer"),
        withdraw_delay=int(required("x402ServerWithdrawDelay")),
        max_timeout_seconds=int(required("x402ServerMaxTimeoutSeconds")),
        memo=memo,
        transaction_versions=parse_transaction_versions(inp.get("x402ServerTransactionVersions")),
    )


async def _verify(inp: dict[str, Any]) -> dict[str, Any]:
    header = inp.get("x402PaymentHeader")
    if not header:
        raise ValueError("upto verify vector is missing input.x402PaymentHeader")
    fee_payer = _signer(inp.get("x402ServerFeePayerSecretKey"), "x402ServerFeePayerSecretKey")
    receiver = _signer(inp.get("x402ServerReceiverAuthorizerSecretKey"), "x402ServerReceiverAuthorizerSecretKey")
    route = _route(inp)
    if str(fee_payer.pubkey) != route.fee_payer or str(receiver.pubkey) != route.receiver_authorizer:
        raise ValueError("x402Server* keys do not match their secret keys")
    now = inp.get("nowSeconds")
    if not isinstance(now, int):
        raise ValueError("upto verify vector is missing input.nowSeconds")
    rpc = _rpc(inp)
    try:
        await verify_upto_open_preflight(
            header,
            [upto_requirements(route)],
            fee_payer_signer=fee_payer,
            receiver_authorizer=route.receiver_authorizer,
            rpc=rpc,
            now=now,
            accepted_versions=route.accepted_versions(),
            max_channel_lifetime_seconds=int(inp.get("x402ServerMaxChannelLifetimeSeconds") or 3600),
        )
    except Exception as exc:  # noqa: BLE001 - every SDK refusal is a reject
        raise Reject(str(exc), code_for(str(exc))) from exc
    finally:
        await rpc.aclose()
    return {"outcome": "accept", "x402PaymentHeader": header}


def _exact(raw: bytes) -> dict[str, Any]:
    return {"bytes": list(raw), "base64Url": base64url_encode(raw)}


def _canonical(inp: dict[str, Any]) -> dict[str, Any]:
    exact: dict[str, Any] = {}
    voucher = inp.get("x402UptoVoucher")
    if voucher is not None:
        try:
            channel = Pubkey.from_string(voucher.get("channelId", ""))
            exact.update(
                _exact(
                    voucher_message_bytes(channel, int(voucher["cumulativeAmount"]), int(voucher.get("expiresAt") or 0))
                )
            )
        except (ValueError, TypeError) as exc:
            raise Reject(f"invalid payload: {exc}", "invalid-payload") from exc
    dist = inp.get("x402UptoDistribution")
    if dist is not None:
        recipients = [
            Distribution(recipient=Pubkey.from_string(entry["recipient"]), bps=int(entry["bps"]))
            for entry in dist["recipients"]
        ]
        exact.update(_exact(distribution_hash(recipients)))
    pda = inp.get("x402UptoChannelPda")
    if pda is not None:
        channel, _ = find_channel_pda(
            Pubkey.from_string(pda["payer"]),
            Pubkey.from_string(pda["payee"]),
            Pubkey.from_string(pda["mint"]),
            Pubkey.from_string(pda["authorizedSigner"]),
            int(pda["salt"]),
            int(pda["openSlot"]),
            PROGRAM_ID,
        )
        exact.update(_exact(bytes(channel)))
    return {"outcome": "accept", "exactBytes": exact}


def run(vector: dict[str, Any]) -> dict[str, Any]:
    """Drive one ``x402-upto`` vector; return its RunnerResult."""
    vector_id = vector.get("id", "")
    inp = vector.get("input") or {}
    mode = vector.get("mode")
    try:
        if mode == "canonical-bytes":
            result = _canonical(inp)
        elif mode == "build-transaction":
            result = asyncio.run(_build(inp))
        elif mode == "verify-transaction":
            result = asyncio.run(_verify(inp))
        else:
            return {"id": vector_id, "outcome": "unsupported-mode", "error": f"unsupported-mode: {mode}"}
    except Reject as exc:
        out: dict[str, Any] = {"id": vector_id, "outcome": "reject", "error": str(exc)}
        if exc.code is not None:
            out["rejectCode"] = exc.code
        return out
    return {"id": vector_id, **result}
