"""Interop adapter: Python HTTP charge server.

Mirrors the contract in skills/pay-sdk-implementation/references/interop-harness.md
and the Ruby adapter at tests/interop/ruby-server/server.rb. The harness
launches this process, reads one ``ready`` JSON line from stdout, then sends
HTTP requests to the protected resource.

Stdout discipline: ONLY the ``ready`` JSON line is written to stdout. All
diagnostics (logging, traceback) go to stderr.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

# Ensure the local Python SDK is importable when run from tests/interop.
_repo_root = Path(__file__).resolve().parents[2]
_python_src = _repo_root / "python" / "src"
if _python_src.is_dir():
    sys.path.insert(0, str(_python_src))

from solana.rpc.async_api import AsyncClient  # noqa: E402

from solana_mpp._errors import (  # noqa: E402
    PaymentError,
    canonical_code,
)
from solana_mpp._headers import (  # noqa: E402
    format_www_authenticate,
    parse_authorization,
)
from solana_mpp.protocol.intents import ChargeRequest  # noqa: E402
from solana_mpp.server.mpp import ChargeOptions, Config, Mpp  # noqa: E402
from solana_mpp.store import MemoryStore  # noqa: E402


def require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        print(f"Missing required env: {name}", file=sys.stderr)
        sys.exit(2)
    return value


def optional_env(name: str, default: str) -> str:
    value = os.environ.get(name)
    return value if value else default


def _decode_keypair_env(name: str) -> bytes:
    """Decode the Solana JSON-array keypair format used by the harness."""
    raw = require_env(name)
    arr = json.loads(raw)
    if not isinstance(arr, list) or not all(isinstance(b, int) for b in arr):
        print(f"{name} must be a JSON array of integers", file=sys.stderr)
        sys.exit(2)
    return bytes(arr)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _build_mpp() -> tuple[Mpp, dict[str, Any]]:
    """Construct the MPP server handler from the harness environment.

    Returns the handler plus a dict carrying per-route protected amounts.
    """
    rpc_url = require_env("MPP_INTEROP_RPC_URL")
    network = optional_env("MPP_INTEROP_NETWORK", "localnet")
    mint = require_env("MPP_INTEROP_MINT")
    amount = require_env("MPP_INTEROP_AMOUNT")
    pay_to = require_env("MPP_INTEROP_PAY_TO")
    secret_key = optional_env("MPP_INTEROP_SECRET_KEY", "mpp-interop-secret-key")
    resource_path = optional_env("MPP_INTEROP_RESOURCE_PATH", "/paid")
    settlement_header = optional_env(
        "MPP_INTEROP_SETTLEMENT_HEADER", "x-payment-settlement-signature"
    )
    splits_raw = optional_env("MPP_INTEROP_SPLITS", "[]")
    splits = json.loads(splits_raw)
    if not isinstance(splits, list):
        print("MPP_INTEROP_SPLITS must decode to a JSON array", file=sys.stderr)
        sys.exit(2)

    # Fee-payer keypair is optional in the harness but always present when
    # the scenario uses server-side fee sponsorship.
    fee_payer_bytes = _decode_keypair_env("MPP_INTEROP_FEE_PAYER_SECRET_KEY")
    from solders.keypair import Keypair

    fee_payer = Keypair.from_bytes(fee_payer_bytes)

    rpc = AsyncClient(rpc_url)
    config = Config(
        recipient=pay_to,
        currency=mint,
        decimals=int(optional_env("MPP_INTEROP_DECIMALS", "6")),
        network=network,
        rpc_url=rpc_url,
        secret_key=secret_key,
        realm=optional_env("MPP_INTEROP_REALM", "MPP Interop"),
        fee_payer_signer=fee_payer,
        store=MemoryStore(),
        rpc=rpc,
    )
    handler = Mpp(config)

    routes = {
        resource_path: amount,
    }
    replay_path = os.environ.get("MPP_INTEROP_REPLAY_SOURCE_PATH") or ""
    if replay_path:
        routes[replay_path] = (
            os.environ.get("MPP_INTEROP_REPLAY_SOURCE_AMOUNT") or amount
        )

    return handler, {
        "routes": routes,
        "settlement_header": settlement_header.lower(),
        "splits": splits,
    }


class InteropHandler(BaseHTTPRequestHandler):
    server_version = "mpp-python-interop/1.0"

    # Suppress access log; everything we say goes to stderr explicitly.
    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        return

    @property
    def mpp(self) -> Mpp:
        return self.server.mpp  # type: ignore[attr-defined]

    @property
    def cfg(self) -> dict[str, Any]:
        return self.server.cfg  # type: ignore[attr-defined]

    def _send_json(self, status: int, body: dict, extra_headers: dict | None = None) -> None:
        payload = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(payload)))
        self.send_header("connection", "close")
        if extra_headers:
            for name, value in extra_headers.items():
                self.send_header(name, value)
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/health":
            self._send_json(200, {"ok": True})
            return

        routes = self.cfg["routes"]
        protected_amount = routes.get(self.path)
        if protected_amount is None:
            self._send_json(404, {"error": "not_found"})
            return

        auth = self.headers.get("Authorization", "")
        splits = self.cfg["splits"]
        options = ChargeOptions(
            description="Python interop protected content",
            splits=splits or [],
        )

        if not auth:
            self._issue_challenge(protected_amount, options, message="missing authorization")
            return

        try:
            credential = parse_authorization(auth)
        except Exception as exc:  # noqa: BLE001 (parse errors map to 402)
            self._issue_challenge(
                protected_amount,
                options,
                message=f"could not parse Authorization: {exc}",
                code="payment_invalid",
            )
            return

        try:
            challenge = self.mpp.charge_with_options(protected_amount, options)
            expected = ChargeRequest.from_dict(challenge.decode_request())
            receipt = asyncio.run(
                self.mpp.verify_credential_with_expected(credential, expected)
            )
        except PaymentError as err:
            self._issue_challenge(
                protected_amount, options, message=str(err) or "verification failed", code=err.code
            )
            return
        except Exception as err:  # noqa: BLE001 framework guard
            print(f"interop python server error: {err}", file=sys.stderr)
            self._issue_challenge(protected_amount, options, message=str(err))
            return

        settlement_header = self.cfg["settlement_header"]
        self._send_json(
            200,
            {"ok": True, "paid": True},
            extra_headers={
                "payment-receipt": receipt.reference,
                settlement_header: receipt.reference,
            },
        )

    def _issue_challenge(
        self,
        amount: str,
        options: ChargeOptions,
        *,
        message: str = "Payment required",
        code: str = "payment_invalid",
    ) -> None:
        challenge = self.mpp.charge_with_options(amount, options)
        www_auth = format_www_authenticate(challenge)
        canonical = canonical_code(code) if code else "payment_invalid"
        body = {
            "type": f"https://paymentauth.org/problems/{canonical}",
            "title": "Payment Required",
            "status": 402,
            "code": canonical,
            "error": canonical,
            "message": message,
        }
        self._send_json(
            402,
            body,
            extra_headers={
                "www-authenticate": www_auth,
                "cache-control": "no-store",
            },
        )


class _ThreadedHTTPServer(HTTPServer):
    pass


def _fund_recipient_via_surfpool(rpc_url: str, pay_to: str, mint: str) -> None:
    """Best-effort Surfpool seeding; mirrors Ruby adapter behavior."""
    try:
        import httpx

        httpx.post(
            rpc_url,
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "surfnet_setAccount",
                "params": [
                    pay_to,
                    {
                        "lamports": 1_000_000_000,
                        "data": "",
                        "executable": False,
                        "owner": "11111111111111111111111111111111",
                        "rentEpoch": 0,
                    },
                ],
            },
            timeout=5,
        )
        httpx.post(
            rpc_url,
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "surfnet_setTokenAccount",
                "params": [
                    pay_to,
                    mint,
                    {"amount": 0, "state": "initialized"},
                    "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
                ],
            },
            timeout=5,
        )
    except Exception as err:  # noqa: BLE001
        print(f"interop python surfpool seed failed: {err}", file=sys.stderr)


def main() -> None:
    handler, cfg = _build_mpp()
    port = _free_port()
    server = _ThreadedHTTPServer(("127.0.0.1", port), InteropHandler)
    server.mpp = handler  # type: ignore[attr-defined]
    server.cfg = cfg  # type: ignore[attr-defined]

    if os.environ.get("MPP_INTEROP_NETWORK", "localnet") == "localnet":
        _fund_recipient_via_surfpool(
            require_env("MPP_INTEROP_RPC_URL"),
            require_env("MPP_INTEROP_PAY_TO"),
            require_env("MPP_INTEROP_MINT"),
        )

    ready = {
        "type": "ready",
        "implementation": "python",
        "role": "server",
        "port": port,
        "capabilities": ["charge"],
    }
    sys.stdout.write(json.dumps(ready) + "\n")
    sys.stdout.flush()

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        thread.join()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()
