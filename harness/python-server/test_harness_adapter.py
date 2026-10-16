"""Subprocess integration regressions for the Python harness adapters.

Exercise the MPP challenge media type, the complete session open/commit/close
flow, and x402 exact/upto retries with cryptographically verified signatures.
RPC state and x402 settlement responses are local fixtures; signing and the
session client/server protocol run through the real SDK, without mocks.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
_ADAPTER = _REPO_ROOT / "harness" / "python-server" / "server.py"


def _wait_for_port(port: int, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.connect(("127.0.0.1", port))
                return
            except OSError:
                time.sleep(0.05)
    raise TimeoutError(f"port {port} did not open within {timeout}s")


def _fake_keypair_json() -> str:
    # A valid keypair: native keychain validates both halves at load time.
    from solders.keypair import Keypair

    kp = Keypair()
    return json.dumps(list(bytes(kp)))


@pytest.fixture
def adapter_env() -> dict[str, str]:
    return {
        **os.environ,
        "PAY_KIT_HARNESS_PROTOCOL": "mpp",
        "MPP_HARNESS_RPC_URL": "http://127.0.0.1:8899",
        "MPP_HARNESS_NETWORK": "localnet",
        "MPP_HARNESS_MINT": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
        "MPP_HARNESS_AMOUNT": "1000",
        "MPP_HARNESS_PAY_TO": "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
        "MPP_HARNESS_FEE_PAYER_SECRET_KEY": _fake_keypair_json(),
    }


def test_402_emits_problem_json_content_type(adapter_env: dict[str, str]):
    """RFC 7807 §3: a problem+json body MUST use
    ``application/problem+json``. The L6 canonical 402 body is exactly
    the RFC 7807 ``type/title/status`` envelope plus our ``code`` field,
    so the adapter MUST advertise the correct media type.
    """
    proc = subprocess.Popen(  # noqa: S603 (test-only subprocess of a known script)
        [sys.executable, "-u", str(_ADAPTER)],
        env=adapter_env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        # The adapter writes one ready line to stdout, then serves.
        ready_line = proc.stdout.readline() if proc.stdout else ""
        assert ready_line, f"adapter did not emit ready handshake; stderr={proc.stderr.read() if proc.stderr else ''}"
        ready = json.loads(ready_line)
        assert ready["type"] == "ready"
        assert ready["role"] == "server"
        port = int(ready["port"])
        _wait_for_port(port)

        req = urllib.request.Request(f"http://127.0.0.1:{port}/paid", method="GET")
        try:
            urllib.request.urlopen(req, timeout=2)  # noqa: S310 (loopback test request)
            raise AssertionError("expected 402 from unauthenticated request")
        except urllib.error.HTTPError as exc:
            assert exc.code == 402
            content_type = exc.headers.get("content-type", "")
            assert content_type.startswith("application/problem+json"), (
                f"402 Content-Type must be application/problem+json per RFC 7807; got {content_type!r}"
            )
            # The body must still parse as JSON and carry the canonical L6
            # code field.
            body = json.loads(exc.read())
            assert body["status"] == 402
            assert body["code"]
            assert body["type"].startswith("https://paymentauth.org/problems/")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=2)


@contextmanager
def _http_server(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


class _RecentStateRpc(BaseHTTPRequestHandler):
    """Only chain state is faked; adapters and signing run in real processes."""

    def log_message(self, *_args):
        pass

    def do_POST(self):
        request = json.loads(self.rfile.read(int(self.headers["content-length"])))
        result = {
            "context": {"slot": 123},
            "value": {
                "blockhash": "11111111111111111111111111111111",
                "lastValidBlockHeight": 1000,
            },
        }
        body = json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.end_headers()
        self.wfile.write(body)


def test_session_client_open_commit_close(adapter_env):
    """Exercise native transaction and voucher signing through both launchers."""
    with _http_server(_RecentStateRpc) as rpc_url:
        env = {
            **adapter_env,
            "PAY_KIT_HARNESS_PROTOCOL": "session",
            "MPP_HARNESS_RPC_URL": rpc_url,
        }
        proc = subprocess.Popen(
            [sys.executable, "-u", str(_ADAPTER)],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            ready_line = proc.stdout.readline()
            assert ready_line, proc.stderr.read()
            ready = json.loads(ready_line)
            client = subprocess.run(
                [sys.executable, str(_REPO_ROOT / "harness/python-session-client/main.py")],
                env={**env, "MPP_HARNESS_TARGET_URL": f"http://127.0.0.1:{ready['port']}/session"},
                capture_output=True,
                text=True,
                timeout=30,
            )
            assert client.returncode == 0, client.stderr
            result = json.loads(client.stdout)
            assert result["ok"], result
            assert result["status"] == 200
            assert "was never awaited" not in client.stderr
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=2)


@pytest.mark.parametrize("scheme", ["exact", "upto"])
def test_x402_client_signs_retry_transaction(adapter_env, scheme):
    """Real client processes must await signing and emit verifiable wire bytes."""
    import base64

    from solders.keypair import Keypair
    from solders.transaction import VersionedTransaction

    payer = Keypair()
    facilitator = Keypair()
    network = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"
    requirement = {
        "scheme": scheme,
        "network": network,
        "asset": adapter_env["MPP_HARNESS_MINT"],
        "amount": "1000",
        "payTo": adapter_env["MPP_HARNESS_PAY_TO"],
        "maxTimeoutSeconds": 300,
        "extra": {
            "feePayer": str(facilitator.pubkey()),
            "receiverAuthorizer": str(facilitator.pubkey()),
            "withdrawDelay": 900,
            "recentBlockhash": "11111111111111111111111111111111",
            "recentSlot": "123",
        },
    }
    payments = []

    class ChallengeServer(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            payment = self.headers.get("payment-signature")
            if payment is None:
                body = json.dumps({"x402Version": 2, "accepts": [requirement]}).encode()
                self.send_response(402)
                self.send_header("payment-required", base64.b64encode(body).decode())
            else:
                payments.append(json.loads(base64.b64decode(payment)))
                body = b'{"ok":true}'
                self.send_response(200)
            self.send_header("content-type", "application/json")
            self.end_headers()
            self.wfile.write(body)

    folder = "python-x402-client" if scheme == "exact" else "python-x402-upto-client"
    with _http_server(_RecentStateRpc) as rpc_url, _http_server(ChallengeServer) as target:
        client = subprocess.run(
            [sys.executable, str(_REPO_ROOT / "harness" / folder / "main.py")],
            env={
                **os.environ,
                "X402_HARNESS_TARGET_URL": target,
                "X402_HARNESS_RPC_URL": rpc_url,
                "X402_HARNESS_NETWORK": network,
                "X402_HARNESS_CLIENT_SECRET_KEY": json.dumps(list(bytes(payer))),
            },
            capture_output=True,
            text=True,
            timeout=30,
        )
    assert client.returncode == 0, client.stderr
    result = json.loads(client.stdout)
    assert result["ok"], result
    assert "was never awaited" not in client.stderr
    assert len(payments) == 1
    payload = payments[0]["payload"]
    wire = payload["transaction" if scheme == "exact" else "openTransaction"]
    transaction = VersionedTransaction.from_bytes(base64.b64decode(wire))
    payer_index = list(transaction.message.account_keys).index(payer.pubkey())
    assert transaction.verify_with_results()[payer_index]
    # The facilitator slot must remain unsigned until server settlement.
    assert not transaction.verify_with_results()[0]
