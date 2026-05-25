"""Merchant server for the Swift iOSDemo app.

Runs the same 402 -> charge -> 200 flow as `python/examples/payment_link_server.py`,
but pre-funds the Swift iOSDemo's seeded keypair
(`B8pEG2UVbzLLSaZnN15UHVza7Ugk3HtfDaxUB4FbZ2xm`) with SOL and USDC on
Surfpool so the on-device app can sign a real charge transaction
end-to-end on first launch.

Listens on http://0.0.0.0:3004 by default; iOS Simulator can reach
this on http://127.0.0.1:3004. Requires:

  - Surfpool running on http://127.0.0.1:8899 (default)
  - The repo's `python/` package installed (see ../README.md).

Usage:

    python3 serve.py [--port 3004] [--rpc-url http://127.0.0.1:8899]
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import random
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

try:
    import httpx
except ImportError:  # pragma: no cover
    sys.exit(
        "httpx is required. Install with `pip install -e ../../../python`."
    )

try:
    # Stable public re-export added in PR #106.
    from solana_mpp import SolanaRpc
except ImportError:  # pragma: no cover - pre-#106 installs only
    # Fall back to the underscore-prefixed path so the demo merchant
    # boots against either tree until #106 lands.
    from solana_mpp._rpc import SolanaRpc
from solana_mpp._headers import format_www_authenticate, parse_authorization
from solana_mpp.server.mpp import ChargeOptions, Config, Mpp
from solana_mpp.store import MemoryStore

# Merchant recipient (separate from the demo signer). Same value as
# python/examples/payment_link_server.py so interop fixtures keep
# working.
RECIPIENT = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY"

# USDC mainnet mint. Surfpool fork serves the same mint locally.
USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"

# Demo signer pubkey derived from the seed in iOSDemo/DemoSigner.swift.
# Updating one without the other will surface as `InsufficientFunds`
# from Surfpool on charge.
DEMO_SIGNER = "B8pEG2UVbzLLSaZnN15UHVza7Ugk3HtfDaxUB4FbZ2xm"

# HMAC secret for the credential framing. Demo-only.
SECRET = "ios-demo-secret-key-long-enough-for-hmac-sha256-operations"

FORTUNES = [
    "A smooth long journey!",
    "Good news will come to you by mail.",
    "Curiosity kills boredom.",
    "Your code shall compile on the first try.",
    "A new opportunity is just around the corner.",
]


def _rpc_post(rpc_url: str, payload: dict) -> None:
    """POST a JSON-RPC payload to surfpool and fail loudly on HTTP errors.

    Without `raise_for_status`, a 4xx/5xx from surfpool (or a missing
    `surfnet_*` method on a non-Surfpool RPC) would silently no-op the
    funding step and the first charge would surface as
    `InsufficientFunds` with no breadcrumb back to the funding step.
    Surface boot-time failures instead.
    """
    response = httpx.post(rpc_url, json=payload, timeout=10)
    response.raise_for_status()


def fund_demo_signer(rpc_url: str) -> None:
    """Seed SOL + USDC on the demo signer so the iOS app can charge."""
    # 1 SOL of lamports.
    _rpc_post(rpc_url, {
        "jsonrpc": "2.0", "id": 1, "method": "surfnet_setAccount",
        "params": [
            DEMO_SIGNER,
            {
                "lamports": 1_000_000_000,
                "data": "",
                "executable": False,
                "owner": "11111111111111111111111111111111",
                "rentEpoch": 0,
            },
        ],
    })
    # 1000 USDC (6 decimals) on the demo signer's USDC ATA.
    _rpc_post(rpc_url, {
        "jsonrpc": "2.0", "id": 1, "method": "surfnet_setTokenAccount",
        "params": [
            DEMO_SIGNER, USDC_MINT,
            {"amount": 1_000_000_000, "state": "initialized"},
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
        ],
    })
    # Initialize recipient's ATA so the first charge doesn't have to.
    _rpc_post(rpc_url, {
        "jsonrpc": "2.0", "id": 1, "method": "surfnet_setAccount",
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
    })
    _rpc_post(rpc_url, {
        "jsonrpc": "2.0", "id": 1, "method": "surfnet_setTokenAccount",
        "params": [
            RECIPIENT, USDC_MINT,
            {"amount": 0, "state": "initialized"},
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
        ],
    })


def make_handler(mpp: Mpp, rpc_url: str):
    async def _verify_with_fresh_rpc(credential):
        # `BaseHTTPRequestHandler` is synchronous, so each request runs
        # `asyncio.run(...)`, which creates a new event loop and closes
        # it on exit. The `SolanaRpc` instance built at startup binds
        # its `httpx.AsyncClient` to whichever loop first touches it;
        # subsequent `asyncio.run` calls then hit `RuntimeError: Event
        # loop is closed` once that loop is torn down. Build a fresh
        # per-request RPC inside the current loop, scope it via
        # `Mpp.using_rpc`, and let it live and die with this loop. The
        # `HTTPServer` here is single-threaded so the `using_rpc`
        # asyncio.Lock is sufficient synchronisation.
        rpc = SolanaRpc(rpc_url)
        async with mpp.using_rpc(rpc):
            return await mpp.verify_credential(credential)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):  # noqa: A002 - matches BaseHTTPRequestHandler
            sys.stderr.write("[merchant] " + (format % args) + "\n")

        def do_GET(self):  # noqa: N802 - http.server hook name
            if self.path == "/health":
                self._json(200, {"ok": True})
                return
            if not self.path.startswith("/fortune"):
                self._json(404, {"error": "not found"})
                return

            auth = self.headers.get("Authorization", "")
            if auth.startswith("Payment "):
                try:
                    credential = parse_authorization(auth)
                    receipt = asyncio.run(_verify_with_fresh_rpc(credential))
                    fortune = random.choice(FORTUNES)
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Payment-Receipt", receipt.reference)
                    self.end_headers()
                    self.wfile.write(json.dumps({
                        "fortune": fortune,
                        "settlement": receipt.reference,
                    }).encode())
                    return
                except Exception as exc:
                    sys.stderr.write(f"[merchant] credential rejected: {exc}\n")
                    # Fall through to challenge.

            challenge = mpp.charge_with_options(
                "0.01",
                ChargeOptions(description="iOS demo fortune"),
            )
            www_auth = format_www_authenticate(challenge)
            body = json.dumps({
                "type": "https://paymentauth.org/problems/payment-required",
                "title": "Payment Required",
                "status": 402,
            }).encode()
            self.send_response(402)
            self.send_header("Content-Type", "application/json")
            self.send_header("WWW-Authenticate", www_auth)
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, status: int, data: dict) -> None:
            body = json.dumps(data).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)

    return Handler


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=3004)
    parser.add_argument(
        "--rpc-url",
        default=os.environ.get("RPC_URL", "http://127.0.0.1:8899"),
        help="Surfpool RPC URL",
    )
    parser.add_argument(
        "--skip-funding",
        action="store_true",
        help="Do not call surfnet_setAccount / surfnet_setTokenAccount.",
    )
    args = parser.parse_args()

    if not args.skip_funding:
        try:
            fund_demo_signer(args.rpc_url)
            print(
                f"[merchant] funded demo signer {DEMO_SIGNER} on {args.rpc_url}",
                flush=True,
            )
        except Exception as exc:
            print(f"[merchant] funding step failed: {exc}", file=sys.stderr)

    mpp = Mpp(Config(
        recipient=RECIPIENT,
        secret_key=SECRET,
        currency=USDC_MINT,
        decimals=6,
        network="localnet",
        rpc_url=args.rpc_url,
        html=False,
        store=MemoryStore(),
        rpc=SolanaRpc(args.rpc_url),
    ))

    server = HTTPServer(("0.0.0.0", args.port), make_handler(mpp, args.rpc_url))
    print(
        f"[merchant] listening on http://0.0.0.0:{args.port} (RPC {args.rpc_url})",
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("[merchant] shutting down", flush=True)


if __name__ == "__main__":
    main()
