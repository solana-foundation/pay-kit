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
import json
import os
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

# Ensure the local Python SDK is importable when run from tests/interop.
# Walk parents looking for the repo root marker (pyproject.toml at python/
# or .git) so the adapter stays self-contained regardless of how deep this
# file lives inside ``tests/``. The harness invokes us from
# ``tests/interop`` (parents[0]=python-server, parents[1]=interop,
# parents[2]=tests, parents[3]=repo root); the previous ``parents[2]``
# resolved to ``<repo>/tests`` and silently fell through to a global
# ``solana-mpp`` install, hiding local SDK regressions.
def _find_repo_root(start: Path) -> Path:
    for candidate in [start, *start.parents]:
        if (candidate / ".git").exists() or (candidate / "python" / "pyproject.toml").is_file():
            return candidate
    return start.parents[-1]


_repo_root = _find_repo_root(Path(__file__).resolve())
_python_src = _repo_root / "python" / "src"
if _python_src.is_dir():
    sys.path.insert(0, str(_python_src))

from solana_mpp._errors import (  # noqa: E402
    PaymentError,
    canonical_code,
)
from solana_mpp._rpc import SolanaRpc  # noqa: E402
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


def _base_units_to_human(base_units: str, decimals: int) -> str:
    """Convert a base-units string back into a fixed-decimal human string.

    The harness passes amounts in base units (e.g. ``"1000"`` for 0.001
    USDC at 6 decimals). The SDK's ``charge_with_options`` re-applies
    ``parse_units`` on the value, so we must hand it a human-readable
    decimal string to round-trip back to the same base units.
    """
    if decimals <= 0:
        return str(int(base_units))
    units = int(base_units)
    sign = "-" if units < 0 else ""
    units = abs(units)
    quotient, remainder = divmod(units, 10 ** decimals)
    fraction = f"{remainder:0{decimals}d}".rstrip("0")
    if not fraction:
        return f"{sign}{quotient}"
    return f"{sign}{quotient}.{fraction}"


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

    # Fee-payer keypair is optional in the harness. Only scenarios that
    # exercise server-side fee sponsorship export
    # ``MPP_INTEROP_FEE_PAYER_SECRET_KEY``; absence must not crash the
    # adapter at startup, and the challenge must not unconditionally
    # advertise ``feePayer=true`` when there is no fee payer to sign.
    fee_payer = None
    fee_payer_raw = os.environ.get("MPP_INTEROP_FEE_PAYER_SECRET_KEY")
    if fee_payer_raw:
        try:
            arr = json.loads(fee_payer_raw)
        except json.JSONDecodeError as exc:
            print(
                f"MPP_INTEROP_FEE_PAYER_SECRET_KEY must be JSON: {exc}",
                file=sys.stderr,
            )
            sys.exit(2)
        if not isinstance(arr, list) or not all(isinstance(b, int) for b in arr):
            print(
                "MPP_INTEROP_FEE_PAYER_SECRET_KEY must be a JSON array of integers",
                file=sys.stderr,
            )
            sys.exit(2)
        from solders.keypair import Keypair

        fee_payer = Keypair.from_bytes(bytes(arr))

    # Greptile P1 (follow-up): do NOT construct a SolanaRpc /
    # httpx.AsyncClient at adapter boot. Each ``BaseHTTPRequestHandler``
    # request runs inside its own ``asyncio.run()`` event loop, and
    # ``httpx.AsyncClient`` anchors its connection-pool primitives to
    # the loop it is first used in. A boot-time client created on the
    # main thread (no running loop) and then handed off to multiple
    # per-request loops relies on httpx's undocumented reconnection
    # behavior. We construct a fresh ``SolanaRpc`` inside every
    # ``do_GET`` instead and ``aclose()`` it immediately after the
    # verify call returns; the Mpp handler boots with ``rpc=None`` and
    # the per-request client is plugged in just-in-time.
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
        rpc=None,
    )
    handler = Mpp(config)

    decimals = int(optional_env("MPP_INTEROP_DECIMALS", "6"))
    routes = {
        resource_path: _base_units_to_human(amount, decimals),
    }
    replay_path = os.environ.get("MPP_INTEROP_REPLAY_SOURCE_PATH") or ""
    if replay_path:
        replay_amount = os.environ.get("MPP_INTEROP_REPLAY_SOURCE_AMOUNT") or amount
        routes[replay_path] = _base_units_to_human(replay_amount, decimals)

    return handler, {
        "routes": routes,
        "settlement_header": settlement_header.lower(),
        "splits": splits,
        "rpc_url": rpc_url,
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
        # Allow callers to override the default ``application/json`` by
        # putting ``content-type`` in ``extra_headers``. The 402 path uses
        # this to emit ``application/problem+json`` per RFC 7807 §3.
        headers = {"content-type": "application/json"}
        if extra_headers:
            for name, value in extra_headers.items():
                headers[name.lower()] = value
        headers["content-length"] = str(len(payload))
        headers["connection"] = "close"
        for name, value in headers.items():
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
            # Build a per-request SolanaRpc tied to this request's event loop
            # (Greptile P1). The httpx.AsyncClient inside SolanaRpc anchors
            # its connection-pool primitives to the loop it is first used
            # in; reusing one across multiple ``asyncio.run`` calls is
            # fragile. We close the request-scoped client immediately
            # after the verify call returns.
            async def _verify_with_fresh_rpc():
                # Use the explicit ``using_rpc`` context manager rather
                # than mutating ``self.mpp._rpc`` directly. The previous
                # in-place mutation was safe under a sequential
                # HTTPServer, but it is a race waiting to happen the
                # moment anyone swaps in ThreadingMixIn or runs two
                # ``asyncio.run`` invocations concurrently. ``using_rpc``
                # serializes the swap under a per-instance lock and
                # always restores the prior RPC on exit.
                fresh_rpc = SolanaRpc(self.cfg["rpc_url"])
                try:
                    async with self.mpp.using_rpc(fresh_rpc):
                        return await self.mpp.verify_credential_with_expected(credential, expected)
                finally:
                    await fresh_rpc.aclose()

            receipt = asyncio.run(_verify_with_fresh_rpc())
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
                # RFC 7807 §3: problem detail responses use
                # ``application/problem+json``. The L6 canonical body shape
                # is exactly the RFC 7807 ``type/title/status`` envelope
                # plus our ``code`` field, so this is the correct media
                # type for every 402 the adapter emits.
                "content-type": "application/problem+json",
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

    # NOTE: do NOT pre-seed recipient ATA via surfnet_setTokenAccount in the
    # interop harness. The harness funds payTo via Surfnet.fundToken before
    # starting the adapter and captures ``initialBalance``; an unconditional
    # reset would zero that balance and break the post-settlement delta
    # assertion. The standalone example server still seeds because it is
    # not under harness control.

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
