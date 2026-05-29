"""Cross-language harness adapter for the Python pay_kit x402 ``exact`` client.

Mirrors the Rust spine interop client
(``rust/crates/x402/src/bin/interop_client.rs``): GET the target, parse the
x402 challenge with the client's network + currency-preference selection, build
the ``PAYMENT-SIGNATURE`` header, GET again with it, then print exactly one
result JSON line to stdout. All diagnostics go to stderr.

Env contract (shared with the rust/ts clients):

* ``X402_INTEROP_TARGET_URL``        - required, the gated resource URL.
* ``X402_INTEROP_RPC_URL``           - required, Solana RPC (blockhash fallback).
* ``X402_INTEROP_NETWORK``           - CAIP-2 / slug; default devnet CAIP-2.
* ``X402_INTEROP_CLIENT_SECRET_KEY`` - required, JSON int array (Signer.bytes).
* ``X402_INTEROP_PREFER_CURRENCIES`` - optional, comma-separated preference list.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any


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

from pay_kit.signer import Signer  # noqa: E402
from pay_kit.protocols.x402.client.exact import (  # noqa: E402
    ChallengeSelection,
    build_payment_header,
    parse_x402_challenge,
)

DEFAULT_NETWORK = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"
SETTLEMENT_HEADER = "x-fixture-settlement"
PAYMENT_SIGNATURE_HEADER = "Payment-Signature"


def _require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        print(f"{name} is required", file=sys.stderr)
        sys.exit(2)
    return value


class _BlockhashRpc:
    """Minimal RPC exposing ``get_latest_blockhash`` for the build fallback.

    Only used when an offer omits ``extra.recentBlockhash``; the pay_kit x402
    server stamps the blockhash so this is the rare path.
    """

    def __init__(self, endpoint: str) -> None:
        self._endpoint = endpoint

    async def get_latest_blockhash(self) -> Any:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                self._endpoint,
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "getLatestBlockhash",
                    "params": [{"commitment": "confirmed"}],
                },
            )
            response.raise_for_status()
            data = response.json()
        blockhash = data["result"]["value"]["blockhash"]

        class _Value:
            def __init__(self, bh: str) -> None:
                self.blockhash = bh

        class _Resp:
            def __init__(self, bh: str) -> None:
                self.value = _Value(bh)

        return _Resp(blockhash)


def _emit(result: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(result) + "\n")
    sys.stdout.flush()


async def _run() -> None:
    target_url = _require_env("X402_INTEROP_TARGET_URL")
    rpc_url = _require_env("X402_INTEROP_RPC_URL")
    network = os.environ.get("X402_INTEROP_NETWORK") or DEFAULT_NETWORK
    secret = _require_env("X402_INTEROP_CLIENT_SECRET_KEY")
    signer = Signer.json(secret)

    prefer_raw = os.environ.get("X402_INTEROP_PREFER_CURRENCIES")
    currencies = None
    if prefer_raw:
        currencies = [entry.strip() for entry in prefer_raw.split(",") if entry.strip()] or None

    async with httpx.AsyncClient(timeout=60.0) as http:
        first = await http.get(target_url)
        first_headers = {k: v for k, v in first.headers.items()}
        first_body = first.text

        selection = ChallengeSelection(network=network, currencies=currencies)
        requirement = parse_x402_challenge(first_headers, first_body, selection)
        if requirement is None:
            _emit(
                {
                    "type": "result",
                    "implementation": "python",
                    "role": "client",
                    "ok": False,
                    "status": first.status_code,
                    "responseHeaders": first_headers,
                    "responseBody": _parse_body(first_body),
                    "settlement": None,
                    "error": "server did not return a supported SVM x402 challenge",
                }
            )
            return

        rpc = _BlockhashRpc(rpc_url)
        payment_header = await build_payment_header(signer, rpc, requirement)

        paid = await http.get(target_url, headers={PAYMENT_SIGNATURE_HEADER: payment_header})

    paid_headers = {k: v for k, v in paid.headers.items()}
    paid_headers[f"{PAYMENT_SIGNATURE_HEADER}-sent"] = payment_header
    settlement = paid_headers.get(SETTLEMENT_HEADER)

    _emit(
        {
            "type": "result",
            "implementation": "python",
            "role": "client",
            "ok": paid.is_success,
            "status": paid.status_code,
            "responseHeaders": paid_headers,
            "responseBody": _parse_body(paid.text),
            "settlement": settlement,
        }
    )


def _parse_body(raw: str) -> Any:
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return raw


def main() -> None:
    try:
        asyncio.run(_run())
    except Exception as exc:  # noqa: BLE001 - emit a structured failure line
        _emit(
            {
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
        )


if __name__ == "__main__":
    main()
