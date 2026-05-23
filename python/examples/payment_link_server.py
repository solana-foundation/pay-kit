"""Minimal payment link server for interop testing.

Listens on port 3004. Requires Surfpool on localhost:8899.
"""

from __future__ import annotations

import asyncio
import json
import os
import random
from http.server import BaseHTTPRequestHandler, HTTPServer

from solana_mpp._headers import format_www_authenticate, parse_authorization
from solana_mpp._rpc import SolanaRpc
from solana_mpp.server.mpp import ChargeOptions, Config, Mpp
from solana_mpp.server.payment_page import (
    accepts_html,
    challenge_to_html,
    is_service_worker_request,
    service_worker_js,
)
from solana_mpp.store import MemoryStore

RECIPIENT = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY"
USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
SECRET = "interop-test-secret-key-long-enough-for-hmac-sha256-operations"
RPC_URL = os.environ.get("RPC_URL", "http://localhost:8899")

FORTUNES = [
    "A smooth long journey!",
    "Good news will come to you by mail.",
    "Curiosity kills boredom.",
]

mpp = Mpp(
    Config(
        recipient=RECIPIENT,
        secret_key=SECRET,
        currency="USDC",
        decimals=6,
        network="localnet",
        rpc_url=RPC_URL,
        html=True,
        store=MemoryStore(),
        rpc=SolanaRpc(RPC_URL),
    )
)

# Fund recipient at startup
try:
    import httpx

    httpx.post(
        RPC_URL,
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "surfnet_setAccount",
            "params": [
                RECIPIENT,
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
        RPC_URL,
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "surfnet_setTokenAccount",
            "params": [
                RECIPIENT,
                USDC_MINT,
                {"amount": 0, "state": "initialized"},
                "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
            ],
        },
        timeout=5,
    )
except Exception:
    pass


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # Suppress request logging

    def do_GET(self):
        if self.path == "/health":
            self._json(200, {"ok": True})
            return

        if not self.path.startswith("/fortune"):
            self._json(404, {"error": "not found"})
            return

        # Service worker
        if is_service_worker_request(self.path):
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.send_header("Service-Worker-Allowed", "/")
            self.end_headers()
            self.wfile.write(service_worker_js().encode())
            return

        # Check for credential
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Payment "):
            try:
                credential = parse_authorization(auth)
                receipt = asyncio.run(mpp.verify_credential(credential))
                fortune = random.choice(FORTUNES)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Payment-Receipt", receipt.reference)
                self.end_headers()
                self.wfile.write(json.dumps({"fortune": fortune}).encode())
                return
            except Exception:
                pass  # Fall through to challenge

        # Issue challenge
        challenge = mpp.charge_with_options("0.01", ChargeOptions(description="Open a fortune cookie"))
        www_auth = format_www_authenticate(challenge)

        if accepts_html(self.headers.get("Accept")):
            html = challenge_to_html(challenge, RPC_URL, "localnet")
            self.send_response(402)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("WWW-Authenticate", www_auth)
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(html.encode())
        else:
            body = json.dumps(
                {
                    "type": "https://paymentauth.org/problems/payment-required",
                    "title": "Payment Required",
                    "status": 402,
                }
            )
            self.send_response(402)
            self.send_header("Content-Type", "application/json")
            self.send_header("WWW-Authenticate", www_auth)
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body.encode())

    def _json(self, status: int, data: dict):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    port = 3004
    server = HTTPServer(("0.0.0.0", port), Handler)
    print(f"Python payment-link-server listening on http://localhost:{port}")
    server.serve_forever()
