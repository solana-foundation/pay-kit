"""Cross-language harness adapter for the Python solana_pay_kit x402 ``batch-settlement`` client.

Same env contract and result line as the Rust ``x402_harness_batch_client``: GET
the target, pay the first ``batch-settlement`` accept with a deposit, pay each
later request with a cumulative voucher, top up when the deposit cannot cover
the next one, then redeem or refund when the flow asks. Prints exactly one
result JSON line to stdout; diagnostics go to stderr.

Env (shared with the Rust client):

* ``X402_HARNESS_TARGET_URL``, ``X402_HARNESS_RPC_URL``, ``X402_HARNESS_CLIENT_SECRET_KEY`` - required.
* ``X402_HARNESS_BATCH_FLOW`` - basic (default) | top-up | redeem | refund, plus the
  Python-only server-signed (trust ``X402_HARNESS_TRUSTED_OPERATORS``, pay the
  metered accept, then redeem) and untrusted-fallback (no trust: a dual-accept
  route is paid through its client-signed accept).
* ``X402_HARNESS_BATCH_REQUESTS`` (default 3), ``X402_HARNESS_BATCH_DEPOSIT`` (atomic;
  default price x requests, one price for top-up; a top-up adds price x remaining).
* ``X402_HARNESS_SETTLEMENT_HEADER`` (default x-payment-settlement-signature).
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit


def _find_repo_root(start: Path) -> Path:
    for candidate in [start, *start.parents]:
        if (candidate / ".git").exists() or (candidate / "python" / "pyproject.toml").is_file():
            return candidate
    return start.parents[-1]


_repo_root = _find_repo_root(Path(__file__).resolve())
_python_src = _repo_root / "python" / "src"
if _python_src.is_dir():
    sys.path.insert(0, str(_python_src))

import httpx  # noqa: E402

from solana_pay_kit.protocols.x402.batch_settlement import errors  # noqa: E402
from solana_pay_kit.protocols.x402.batch_settlement.errors import BatchSettlementError  # noqa: E402
from solana_pay_kit.protocols.x402.client.batch_settlement import (  # noqa: E402
    BatchSettlementClient,
    MemoryClientChannelStore,
    ServerSignedChannelsPolicy,
    is_server_signed_accept,
    parse_payment_required,
)
from solana_pay_kit.signer import Signer  # noqa: E402

PAYMENT_SIGNATURE_HEADER = "payment-signature"
PAYMENT_RESPONSE_HEADER = "payment-response"
REDEEM_PATH = "/__harness/batch/redeem"
FLOWS = ("basic", "top-up", "redeem", "refund", "server-signed", "untrusted-fallback")


def _require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise SystemExit(f"{name} is required")
    return value


def _u64_env(name: str) -> int | None:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return None
    if not raw.isdigit():
        raise SystemExit(f"{name} must be an unsigned integer, got {raw}")
    return int(raw)


def _json_or_text(raw: str) -> Any:
    try:
        return json.loads(raw)
    except ValueError:
        return raw


def _payment_response(reply: httpx.Response) -> Any:
    value = reply.headers.get(PAYMENT_RESPONSE_HEADER)
    if not value:
        return None
    try:
        decoded = json.loads(base64.b64decode(value, validate=True))
    except ValueError:
        return None
    return decoded if isinstance(decoded, dict) else None


def _encode(payment: Any) -> str:
    return base64.b64encode(json.dumps(payment).encode()).decode("ascii")


def _emit(result: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(result) + "\n")
    sys.stdout.flush()


async def _run() -> dict[str, Any]:
    target_url = _require_env("X402_HARNESS_TARGET_URL")
    rpc_url = _require_env("X402_HARNESS_RPC_URL")
    signer = Signer.json(_require_env("X402_HARNESS_CLIENT_SECRET_KEY"))
    flow = os.environ.get("X402_HARNESS_BATCH_FLOW") or "basic"
    if flow not in FLOWS:
        raise SystemExit(f"unsupported X402_HARNESS_BATCH_FLOW={flow}; expected one of {', '.join(FLOWS)}")
    requests = _u64_env("X402_HARNESS_BATCH_REQUESTS") or 3
    settlement_header = os.environ.get("X402_HARNESS_SETTLEMENT_HEADER") or "x-payment-settlement-signature"
    trust = None
    if flow == "server-signed":
        operators = [key.strip() for key in _require_env("X402_HARNESS_TRUSTED_OPERATORS").split(",") if key.strip()]
        trust = ServerSignedChannelsPolicy(allowed_operators=tuple(operators))

    def client(deposit_amount: int) -> BatchSettlementClient:
        # One client per request over a shared store, so each top-up can be
        # sized like the Rust client's (price x remaining requests).
        return BatchSettlementClient(
            signer,
            rpc_url=rpc_url,
            channel_store=store,
            deposit_amount=deposit_amount,
            discover_channels=False,
            server_signed_channels_policy=trust,
        )

    store = MemoryClientChannelStore()
    async with httpx.AsyncClient(timeout=120.0) as http:
        challenge = await http.get(target_url)
        required = parse_payment_required(challenge.headers, challenge.text)
        if required is None:
            raise SystemExit("server did not return an x402 batch-settlement challenge")
        accepts = required["accepts"]
        if trust is not None:
            accepts = client(1).payment_policy(accepts)
        if flow == "untrusted-fallback":
            # The untrusted server-signed accept goes first, so only the
            # fallback can pay the route (a pay-kit server lists it second).
            accepts = sorted(accepts, key=lambda a: not is_server_signed_accept(a))
            if not is_server_signed_accept(accepts[0]):
                raise SystemExit("untrusted-fallback needs a route that offers a server-signed accept")
        accept = next(a for a in accepts if a.get("scheme") == "batch-settlement")
        price = int(accept["amount"])
        deposit = _u64_env("X402_HARNESS_BATCH_DEPOSIT")
        if deposit is None:
            deposit = price if flow == "top-up" else price * requests

        def channel() -> Any:
            return next(iter(store.records.values()), None)

        records: list[dict[str, Any]] = []
        last: tuple[httpx.Response, str] | None = None
        open_signature: str | None = None
        ok = True
        for index in range(1, requests + 1):
            opened = channel() is not None
            paying = client(price * (requests - index + 1) if opened else deposit)
            corrected = False
            while True:
                if flow == "untrusted-fallback":
                    payment, paid = await paying.create_payment_header({"accepts": accepts})
                    if is_server_signed_accept(paid):
                        raise SystemExit("the untrusted server-signed accept was paid instead of the fallback")
                else:
                    payment = await paying.create_payment_payload(accept)
                payload = payment["payload"]
                kind = {"deposit": "topUp" if opened else "deposit"}.get(payload["type"], payload["type"])
                header = _encode(payment)
                reply = await http.get(target_url, headers={PAYMENT_SIGNATURE_HEADER: header})
                # A cumulative mismatch answers with a corrective 402: adopt the
                # server's proven watermark and retry this request once.
                if reply.status_code == 402 and opened and not corrected:
                    corrective = parse_payment_required(reply.headers, reply.text)
                    mismatch = (
                        corrective is not None and corrective.get("error") == errors.INVALID_CUMULATIVE_AMOUNT_MISMATCH
                    )
                    if mismatch and await paying.handle_payment_response(
                        payment, response=None, payment_required=corrective
                    ):
                        corrected = True
                        continue
                break
            settled = _payment_response(reply)
            error: str | None = None
            if reply.status_code == 200 and settled is not None:
                try:
                    await paying.handle_payment_response(payment, response=settled)
                except BatchSettlementError as exc:
                    error = str(exc)
                else:
                    confirmed = channel()
                    voucher = (settled.get("extra") or {}).get("voucher") or payload.get("voucher") or {}
                    if confirmed is None or str(confirmed.charged_cumulative) != voucher.get("maxClaimableAmount"):
                        error = "PAYMENT-RESPONSE was not accepted"
            else:
                await paying.handle_payment_response(payment, response=None)  # restore the confirmed state
                error = (
                    "200 without a PAYMENT-RESPONSE"
                    if reply.status_code == 200
                    else f"paid request returned {reply.status_code}"
                )
            transaction = None if settled is None else settled.get("transaction")
            if kind == "deposit" and error is None and transaction:
                open_signature = transaction
            confirmed = channel()
            records.append(
                {
                    "index": index,
                    "kind": kind,
                    "status": reply.status_code,
                    "chargedCumulativeAmount": None if confirmed is None else str(confirmed.charged_cumulative),
                    "transaction": transaction,
                    "settlementSignature": reply.headers.get(settlement_header),
                    "paymentResponse": settled,
                    "corrected": corrected,
                    "error": error,
                    "body": _json_or_text(reply.text),
                }
            )
            last = (reply, header)
            if error is not None:
                ok = False
                break

        confirmed = channel()
        body: dict[str, Any] = {
            "flow": flow,
            "channelId": None if confirmed is None else confirmed.channel_id,
            "openSignature": open_signature,
            "deposit": str(deposit),
            "price": str(price),
            "requests": records,
        }

        if ok and flow in ("redeem", "server-signed"):
            scheme, netloc, *_ = urlsplit(target_url)
            response = await http.post(urlunsplit((scheme, netloc, REDEEM_PATH, "", "")))
            ok = response.status_code == 200
            body["redeem"] = {"status": response.status_code, "body": _json_or_text(response.text)}

        if ok and flow == "refund":
            header = _encode(await paying.create_refund_payload(accept))
            reply = await http.get(target_url, headers={PAYMENT_SIGNATURE_HEADER: header})
            settled = _payment_response(reply)
            ok = reply.status_code == 200
            body["refund"] = {
                "status": reply.status_code,
                "transaction": None if settled is None else settled.get("transaction"),
                "settlementSignature": reply.headers.get(settlement_header),
                "paymentResponse": settled,
                "body": _json_or_text(reply.text),
            }

    if last is not None:
        reply, header = last
        status = reply.status_code
        headers = dict(reply.headers)
        headers[f"{PAYMENT_SIGNATURE_HEADER}-sent"] = header
    else:
        status, headers = challenge.status_code, dict(challenge.headers)
    return {
        "type": "result",
        "implementation": "python",
        "role": "client",
        "ok": ok and status == 200,
        "status": status,
        "responseHeaders": headers,
        "responseBody": body,
        "settlement": open_signature,
    }


def main() -> None:
    try:
        result = asyncio.run(_run())
    except (Exception, SystemExit) as exc:  # noqa: BLE001 - one structured failure line
        print(f"harness python batch client error: {exc}", file=sys.stderr)
        result = {
            "type": "result",
            "implementation": "python",
            "role": "client",
            "ok": False,
            "status": 0,
            "responseHeaders": {},
            "responseBody": None,
            "settlement": None,
            "error": str(exc),
        }
    _emit(result)


if __name__ == "__main__":
    main()
