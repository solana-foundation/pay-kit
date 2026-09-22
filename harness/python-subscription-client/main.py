"""Harness client adapter for the MPP ``subscription`` intent (Python solana_pay_kit).

GET the resource for a 402, build and sign the activation with
``build_subscription_activation`` (the authority is initialized in the same
transaction when missing), GET again with it for a 200 plus receipt, then GET
once more with the reusable bearer proof and expect the same subscription in
period 0 without a new charge. Prints one ``result`` line whose ``settlement``
is the activation signature, so the harness checks the on-chain transfer.
"""

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

from solders.keypair import Keypair  # type: ignore[import-untyped]  # noqa: E402

from solana_pay_kit._paycore.rpc import SolanaRpc  # noqa: E402
from solana_pay_kit.protocols.mpp.client.subscription import (  # noqa: E402
    SubscriptionActivation,
    build_subscription_access_credential,
    build_subscription_activation,
)
from solana_pay_kit.protocols.mpp.core.headers import (  # noqa: E402
    format_authorization,
    parse_receipt,
    parse_www_authenticate,
)
from solana_pay_kit.protocols.mpp.core.types import PaymentChallenge  # noqa: E402


def _request(url: str, auth: str = "") -> tuple[int, dict[str, str], bytes]:
    req = Request(url, method="GET")
    if auth:
        req.add_header("authorization", auth)
    try:
        response = urlopen(req, timeout=60)
        return response.status, {k.lower(): v for k, v in response.headers.items()}, response.read()
    except HTTPError as err:
        return err.code, {k.lower(): v for k, v in err.headers.items()}, err.read()


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
                "implementation": "python-subscription",
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


async def _activate(signer: Keypair, rpc_url: str, challenge: PaymentChallenge) -> SubscriptionActivation:
    rpc = SolanaRpc(rpc_url)
    try:
        return await build_subscription_activation(signer, rpc, challenge)
    finally:
        await rpc.aclose()


def main() -> None:
    target = os.environ["MPP_HARNESS_TARGET_URL"]
    signer = Keypair.from_bytes(bytes(json.loads(os.environ["MPP_HARNESS_CLIENT_SECRET_KEY"])))

    status, headers, raw = _request(target)
    if status != 402:
        _result(status, headers, _json(raw))
        return
    challenge = parse_www_authenticate(headers.get("www-authenticate", ""))
    activation = asyncio.run(_activate(signer, os.environ["MPP_HARNESS_RPC_URL"], challenge))

    status, headers, raw = _request(target, format_authorization(activation.credential))
    if status != 200:
        _result(status, headers, _json(raw))
        return
    activated = parse_receipt(headers["payment-receipt"])

    access = build_subscription_access_credential(
        challenge.to_echo(), activation.subscription_delegation, activation.authentication
    )
    status, headers, raw = _request(target, format_authorization(access))
    body = _json(raw)
    if status == 200:
        receipt = parse_receipt(headers["payment-receipt"])
        same = (receipt.reference, receipt.subscription_id, receipt.period_index) == (
            activated.reference,
            activated.subscription_id,
            0,
        )
        if not same:
            _result(500, headers, {"error": "access receipt does not match the activation", "receipt": body})
            return
    _result(status, headers, body, activated.reference)


if __name__ == "__main__":
    main()
