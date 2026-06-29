"""Cross-language harness adapter for the Python solana_pay_kit x402 ``upto`` client.

Mirrors the Rust/Go upto harness clients: GET the target, parse the ``upto`` 402
challenge, build the ``PAYMENT-SIGNATURE`` header (a partially-signed channel
``open`` + the upto payload), GET again with it, then print exactly one result
JSON line to stdout. All diagnostics go to stderr.

Env contract (shared with the rust/go upto clients):

* ``X402_HARNESS_TARGET_URL``        - required, the gated resource URL.
* ``X402_HARNESS_NETWORK``           - CAIP-2 / slug; default devnet CAIP-2.
* ``X402_HARNESS_CLIENT_SECRET_KEY`` - required, JSON int array (Signer.bytes).
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time
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

from solana_pay_kit.protocols.x402.client.upto import build_upto_header, parse_upto_challenge  # noqa: E402
from solana_pay_kit.signer import Signer  # noqa: E402

SETTLEMENT_HEADER = "x-payment-settlement-signature"
PAYMENT_SIGNATURE_HEADER = "Payment-Signature"


def _require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        print(f"{name} is required", file=sys.stderr)
        sys.exit(2)
    return value


def _emit(result: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(result) + "\n")
    sys.stdout.flush()


def _parse_body(raw: str) -> Any:
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return raw


async def _run() -> None:
    target_url = _require_env("X402_HARNESS_TARGET_URL")
    secret = _require_env("X402_HARNESS_CLIENT_SECRET_KEY")
    signer = Signer.json(secret)

    async with httpx.AsyncClient(timeout=120.0) as http:
        first = await http.get(target_url)
        first_headers = {k: v for k, v in first.headers.items()}
        first_body = first.text

        requirement = parse_upto_challenge(first_headers, first_body)
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
                    "error": "server did not return a supported x402 upto challenge",
                }
            )
            return

        expires_at = int(time.time()) + int(requirement.get("maxTimeoutSeconds", 300))
        payment_header = build_upto_header(signer, requirement, expires_at)

        paid = await http.get(target_url, headers={PAYMENT_SIGNATURE_HEADER: payment_header})

    paid_headers = {k: v for k, v in paid.headers.items()}
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
