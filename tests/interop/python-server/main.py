#!/usr/bin/env python3
"""Process adapter for exercising the Python MPP server in the TS interop harness."""

from __future__ import annotations

import asyncio
import json
import os
import signal
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT / "python" / "src"))

from solana.rpc.async_api import AsyncClient  # noqa: E402

from solana_mpp._errors import PaymentError  # noqa: E402
from solana_mpp._headers import format_receipt, format_www_authenticate, parse_authorization  # noqa: E402
from solana_mpp.protocol.intents import ChargeRequest  # noqa: E402
from solana_mpp.server.mpp import ChargeOptions, Config, Mpp  # noqa: E402


class InteropServer(ThreadingHTTPServer):
    environment: dict[str, Any]


class Handler(BaseHTTPRequestHandler):
    server: InteropServer

    def do_GET(self) -> None:
        environment = self.server.environment

        if self.path == "/health":
            self.write_json(200, {"ok": True})
            return

        if not self.is_protected_path(self.path, environment):
            self.write_json(404, {"error": "not_found"})
            return

        challenge = build_challenge(environment, self.price_for_path(self.path, environment))
        authorization = self.headers.get("Authorization", "")
        if not authorization:
            self.write_payment_required(challenge, "Payment is required (Python interop server).")
            return

        try:
            receipt = asyncio.run(verify_credential(environment, authorization, challenge))
        except PaymentError as error:
            self.write_payment_required(challenge, str(error))
            return
        except Exception as error:  # noqa: BLE001
            self.write_json(500, {"error": str(error)})
            return

        receipt_header = format_receipt(receipt)
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("payment-receipt", receipt_header)
        self.send_header(environment["settlement_header"], receipt.reference)
        self.end_headers()
        self.wfile.write(b'{"ok":true,"paid":true}')

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        return

    def write_payment_required(self, challenge: Any, detail: str) -> None:
        self.send_response(402)
        self.send_header("cache-control", "no-store")
        self.send_header("content-type", "application/problem+json")
        self.send_header("www-authenticate", format_www_authenticate(challenge))
        self.end_headers()
        self.wfile.write(
            json.dumps(
                {
                    "detail": detail,
                    "status": 402,
                    "title": "Payment Required",
                    "type": "https://paymentauth.org/problems/payment-required",
                },
                separators=(",", ":"),
            ).encode("utf-8")
        )

    def write_json(self, status: int, body: dict[str, Any]) -> None:
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(body, separators=(",", ":")).encode("utf-8"))

    @staticmethod
    def is_protected_path(path: str, environment: dict[str, Any]) -> bool:
        replay_source = environment.get("replay_source")
        return path == environment["resource_path"] or (
            replay_source is not None and path == replay_source["resource_path"]
        )

    @staticmethod
    def price_for_path(path: str, environment: dict[str, Any]) -> str:
        replay_source = environment.get("replay_source")
        if replay_source is not None and path == replay_source["resource_path"]:
            return replay_source["price"]
        return environment["price"]


def build_challenge(environment: dict[str, Any], price: str) -> Any:
    handler = Mpp(
        Config(
            recipient=environment["pay_to"],
            currency=environment["mint"],
            decimals=6,
            network=environment["network"],
            rpc_url=environment["rpc_url"],
            secret_key=environment["secret_key"],
            realm="MPP Interop",
        )
    )
    return handler.charge_with_options(
        price,
        ChargeOptions(
            description="Python interop protected content",
            splits=environment["splits"],
        ),
    )


async def verify_credential(environment: dict[str, Any], authorization: str, challenge: Any) -> Any:
    rpc_client = AsyncClient(environment["rpc_url"])
    try:
        handler = Mpp(
            Config(
                recipient=environment["pay_to"],
                currency=environment["mint"],
                decimals=6,
                network=environment["network"],
                rpc_url=environment["rpc_url"],
                secret_key=environment["secret_key"],
                realm="MPP Interop",
                rpc=rpc_client,
            )
        )
        credential = parse_authorization(authorization)
        expected = ChargeRequest.from_dict(challenge.decode_request())
        return await handler.verify_credential_with_expected(credential, expected)
    finally:
        await rpc_client.close()


def read_environment() -> dict[str, Any]:
    replay_source = None
    if os.environ.get("MPP_INTEROP_REPLAY_SOURCE_PATH") and os.environ.get("MPP_INTEROP_REPLAY_SOURCE_PRICE"):
        replay_source = {
            "price": os.environ["MPP_INTEROP_REPLAY_SOURCE_PRICE"],
            "resource_path": os.environ["MPP_INTEROP_REPLAY_SOURCE_PATH"],
        }

    return {
        "rpc_url": required_env("MPP_INTEROP_RPC_URL"),
        "network": os.environ.get("MPP_INTEROP_NETWORK", "localnet"),
        "mint": os.environ.get("MPP_INTEROP_MINT", "USDC"),
        "price": os.environ.get("MPP_INTEROP_PRICE", "0.001"),
        "resource_path": os.environ.get("MPP_INTEROP_RESOURCE_PATH", "/protected"),
        "settlement_header": os.environ.get("MPP_INTEROP_SETTLEMENT_HEADER", "x-fixture-settlement"),
        "pay_to": required_env("MPP_INTEROP_PAY_TO"),
        "secret_key": os.environ.get("MPP_INTEROP_SECRET_KEY", "mpp-interop-secret-key"),
        "splits": json.loads(os.environ.get("MPP_INTEROP_SPLITS", "[]")),
        "replay_source": replay_source,
    }


def required_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


def main() -> None:
    environment = read_environment()
    server = InteropServer(("127.0.0.1", 0), Handler)
    try:
        server.environment = environment
        port = server.server_address[1]
        print(
            json.dumps(
                {
                    "type": "ready",
                    "implementation": "python",
                    "role": "server",
                    "port": port,
                    "capabilities": ["charge"],
                }
            ),
            flush=True,
        )

        def shutdown(_signum: int, _frame: Any) -> None:
            threading.Thread(target=server.shutdown, daemon=True).start()

        signal.signal(signal.SIGTERM, shutdown)
        signal.signal(signal.SIGINT, shutdown)
        server.serve_forever()
    finally:
        server.server_close()


if __name__ == "__main__":
    try:
        main()
    except Exception as error:  # noqa: BLE001
        print(f"FAIL: {error}", file=sys.stderr)
        raise SystemExit(1) from error
