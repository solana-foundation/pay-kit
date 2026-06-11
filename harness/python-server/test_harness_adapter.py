"""Regression tests for the Python harness adapter at
``harness/python-server/server.py``.

Spawns the adapter as a subprocess, reads the ``ready`` handshake JSON
from stdout, hits the protected resource without credentials, and
asserts the 402 response shape (Content-Type MUST be
``application/problem+json`` per RFC 7807 §3, not
``application/json``).
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
from pathlib import Path

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
    # Deterministic 64-byte keypair the adapter can deserialize at boot.
    # The secret key half does not have to match the public key for the
    # 402-only path (we never sign anything in this test).
    from solders.keypair import Keypair

    kp = Keypair()
    return json.dumps(list(bytes(kp)))


@pytest.fixture
def adapter_env() -> dict[str, str]:
    return {
        **os.environ,
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
