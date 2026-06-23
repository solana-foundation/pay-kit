from __future__ import annotations

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

from solders.keypair import Keypair  # type: ignore[import-untyped]  # noqa: E402

from pay_kit.protocols.mpp.client.payment_channels import (  # noqa: E402
    create_server_opened_payment_channel_session_opener,
)
from pay_kit.protocols.mpp.client.session import serialize_session_credential  # noqa: E402
from pay_kit.protocols.mpp.core.headers import parse_www_authenticate  # noqa: E402
from pay_kit.protocols.mpp.intents.session import (  # noqa: E402
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


def _result(status: int, headers: dict[str, str], body, settlement: str = "") -> None:
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
    request = SessionRequest.from_dict(challenge.decode_request())

    session_signer = Keypair()
    opener = create_server_opened_payment_channel_session_opener(request, session_signer)
    open_auth = serialize_session_credential(challenge, opener.action)
    status, headers, raw = _request("GET", target, auth=open_auth)
    if status != 200:
        _result(status, headers, _json(raw))
        return

    channel_id = opener.session.channel_id_string
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
    _result(status, close_headers, close_body, settlement)


if __name__ == "__main__":
    main()
