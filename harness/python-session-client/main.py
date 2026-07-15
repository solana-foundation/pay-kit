from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen


def _find_repo_root(start: Path) -> Path:
    for candidate in [start, *start.parents]:
        if (candidate / ".git").exists() or (candidate / "python" / "pyproject.toml").is_file():
            return candidate
    return start.parents[-1]


_repo_root = _find_repo_root(Path(__file__).resolve())
_python_src = _repo_root / "python" / "src"
if _python_src.is_dir():
    sys.path.insert(0, str(_python_src))

from solders.hash import Hash  # type: ignore[import-untyped]  # noqa: E402
from solders.keypair import Keypair  # type: ignore[import-untyped]  # noqa: E402
from solders.transaction import Transaction  # type: ignore[import-untyped]  # noqa: E402

from solana_pay_kit._paycore.rpc import SolanaRpc  # noqa: E402
from solana_pay_kit.protocols.mpp._paymentchannels import (  # noqa: E402
    TopUpParams,
    build_top_up_instruction,
)
from solana_pay_kit.protocols.mpp.client.payment_channels import (  # noqa: E402
    PaymentChannelOpenOptions,
    PaymentChannelSessionOpenOptions,
    create_payment_channel_session_opener,
)
from solana_pay_kit.protocols.mpp.client.session import serialize_session_credential  # noqa: E402
from solana_pay_kit.protocols.mpp.core.headers import parse_www_authenticate  # noqa: E402
from solana_pay_kit.protocols.mpp.intents.session import (  # noqa: E402
    ClosePayload,
    SessionAction,
    SessionRequest,
)


def _request(method: str, url: str, body: dict | None = None, auth: str = ""):
    data = None if body is None else json.dumps(body).encode("utf-8")
    req = Request(url, data=data, method=method)
    if data is not None:
        req.add_header("content-type", "application/json")
    if auth:
        req.add_header("authorization", auth)
    try:
        response = urlopen(req, timeout=30)
        raw = response.read()
        return response.status, {k.lower(): v for k, v in response.headers.items()}, raw
    except HTTPError as err:
        raw = err.read()
        return err.code, {k.lower(): v for k, v in err.headers.items()}, raw


def _json(raw: bytes):
    if not raw:
        return None
    try:
        return json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError:
        return raw.decode("utf-8", errors="replace")


def _positive_base_units(raw: str | None, name: str) -> int:
    if raw is None or not raw.isascii() or not raw.isdigit() or int(raw) <= 0:
        raise ValueError(f"{name} must be a positive base-unit integer")
    return int(raw)


def _require_supported_top_up_mode(request: SessionRequest) -> None:
    if request.modes != ["pull"] or request.pull_voucher_strategy != "clientVoucher":
        raise ValueError("python session top-up harness requires exactly pull/clientVoucher mode")


def _submit_top_up(
    payer_signer: Keypair,
    channel_id,
    mint,
    token_program,
    amount: int,
) -> str:
    async def _send() -> str:
        rpc = SolanaRpc(os.environ["MPP_HARNESS_RPC_URL"])
        try:
            latest_blockhash = await rpc.get_latest_blockhash()
            instruction = build_top_up_instruction(
                TopUpParams(
                    payer=payer_signer.pubkey(),
                    channel=channel_id,
                    mint=mint,
                    amount=amount,
                    token_program=token_program,
                )
            )
            transaction = Transaction.new_signed_with_payer(
                [instruction],
                payer_signer.pubkey(),
                [payer_signer],
                Hash.from_string(latest_blockhash.value.blockhash),
            )
            submitted = await rpc.send_raw_transaction(bytes(transaction))
            signature = str(submitted.value)
            await rpc.await_confirmation(signature)
            return signature
        finally:
            await rpc.aclose()

    return asyncio.run(_send())


def _result(status: int, headers: dict[str, str], body, settlement: str = "", top_up: dict | None = None) -> None:
    print(
        json.dumps(
            {
                "type": "result",
                "implementation": "python-session",
                "role": "client",
                "ok": 200 <= status < 300,
                "status": status,
                "responseHeaders": headers,
                "responseBody": body,
                **({"settlement": settlement} if settlement else {}),
                **({"topUp": top_up} if top_up is not None else {}),
            }
        ),
        flush=True,
    )


def main() -> None:
    target = os.environ["MPP_HARNESS_TARGET_URL"]
    reserve_url = target.rsplit("/", 1)[0] + "/__402/session/deliveries"
    commit_url = target.rsplit("/", 1)[0] + "/__402/session/commit"
    close_url = target.rsplit("/", 1)[0] + "/__402/session/close"
    amount = os.environ.get("MPP_HARNESS_AMOUNT", "700")

    status, headers, raw = _request("GET", target)
    if status != 402:
        _result(status, headers, _json(raw))
        return
    challenge = parse_www_authenticate(headers.get("www-authenticate", ""))
    try:
        request = SessionRequest.from_dict(challenge.decode_request())
        _require_supported_top_up_mode(request)
        initial_deposit = _positive_base_units(amount, "MPP_HARNESS_AMOUNT")
        top_up_amount = _positive_base_units(
            os.environ.get("MPP_HARNESS_SESSION_TOP_UP_AMOUNT"),
            "MPP_HARNESS_SESSION_TOP_UP_AMOUNT",
        )
        cap = _positive_base_units(request.cap, "challenge cap")
    except ValueError as exc:
        _result(500, headers, {"error": str(exc)})
        return

    new_deposit = initial_deposit + top_up_amount
    if new_deposit > cap:
        _result(
            500,
            headers,
            {"error": f"top-up deposit {new_deposit} exceeds challenge cap {cap}"},
        )
        return

    # The client funds the channel: build a payer-signed open transaction (payer
    # = the funded harness client wallet, fee payer = the challenge operator) and
    # ship it in the open action. With openTxSubmitter=server the operator
    # completes the fee-payer signature and broadcasts it, so the payment channel
    # is actually created on-chain (escrow funded from the client's ATA) before
    # any voucher. The challenge carries the operator-prefetched recentBlockhash.
    payer_signer = Keypair.from_bytes(bytes(json.loads(os.environ["MPP_HARNESS_CLIENT_SECRET_KEY"])))
    session_signer = Keypair()
    recent_blockhash = request.recent_blockhash
    if not recent_blockhash:
        _result(500, headers, {"error": "challenge did not carry a recentBlockhash for the open transaction"})
        return
    opener = create_payment_channel_session_opener(
        request,
        payer_signer,
        session_signer,
        recent_blockhash,
        PaymentChannelSessionOpenOptions(open=PaymentChannelOpenOptions(deposit=initial_deposit)),
    )
    open_auth = serialize_session_credential(challenge, opener.action)
    status, headers, raw = _request("GET", target, auth=open_auth)
    if status != 200:
        _result(status, headers, _json(raw))
        return

    channel_id = opener.session.channel_id_string
    try:
        top_up_signature = _submit_top_up(
            payer_signer,
            opener.open.channel_id,
            opener.open.mint,
            opener.open.token_program,
            top_up_amount,
        )
    except Exception as exc:  # noqa: BLE001 - surface RPC failures through the harness result
        _result(500, headers, {"error": f"top-up transaction failed: {exc}"})
        return

    top_up_auth = serialize_session_credential(
        challenge,
        opener.session.top_up_action(new_deposit, top_up_signature),
    )
    status, top_up_headers, top_up_raw = _request("GET", target, auth=top_up_auth)
    top_up_body = _json(top_up_raw)
    if status != 200 or not isinstance(top_up_body, dict):
        _result(status, top_up_headers, top_up_body)
        return
    server_top_up = top_up_body.get("topUp")
    if server_top_up != {"channelId": channel_id, "deposit": str(new_deposit)}:
        _result(500, top_up_headers, {"error": "server did not expose accepted top-up state", "topUp": server_top_up})
        return
    top_up = {
        "signature": top_up_signature,
        "channelId": channel_id,
        "amount": str(top_up_amount),
        "newDeposit": str(new_deposit),
        "server": server_top_up,
    }

    status, reserve_headers, reserve_raw = _request(
        "POST",
        reserve_url,
        {"sessionId": channel_id, "amount": amount},
    )
    reserve_body = _json(reserve_raw)
    if status != 200 or not isinstance(reserve_body, dict):
        _result(status, reserve_headers, reserve_body)
        return

    voucher = opener.session.prepare_increment(int(amount))
    status, commit_headers, commit_raw = _request(
        "POST",
        commit_url,
        {"deliveryId": reserve_body["deliveryId"], "voucher": voucher.to_dict()},
    )
    commit_body = _json(commit_raw)
    if status != 200:
        _result(status, commit_headers, commit_body)
        return
    opener.session.record_voucher(voucher)

    close_auth = serialize_session_credential(
        challenge,
        SessionAction.close_action(ClosePayload(channel_id=channel_id, voucher=voucher)),
    )
    status, close_headers, close_raw = _request("POST", close_url, auth=close_auth)
    close_body = _json(close_raw)
    settlement = ""
    if isinstance(close_body, dict):
        settlement = str(close_body.get("reference") or close_body.get("settledSignature") or "")
    _result(status, close_headers, close_body, settlement, top_up)


if __name__ == "__main__":
    main()
