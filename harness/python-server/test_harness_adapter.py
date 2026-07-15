"""Regression tests for the Python harness adapter at
``harness/python-server/server.py``.

Spawns the adapter as a subprocess, reads the ``ready`` handshake JSON
from stdout, hits the protected resource without credentials, and
asserts the 402 response shape (Content-Type MUST be
``application/problem+json`` per RFC 7807 §3, not
``application/json``).
"""

from __future__ import annotations

import importlib.util
import json
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from solders.keypair import Keypair
from solders.pubkey import Pubkey

from solana_pay_kit._paycore.solana import TOKEN_PROGRAM
from solana_pay_kit.protocols.mpp._paymentchannels import TopUpParams, build_top_up_instruction
from solana_pay_kit.protocols.mpp.core.headers import format_authorization
from solana_pay_kit.protocols.mpp.core.types import PaymentCredential
from solana_pay_kit.protocols.mpp.intents.session import OpenPayload, SessionAction, TopUpPayload

_REPO_ROOT = Path(__file__).resolve().parents[2]
_ADAPTER = _REPO_ROOT / "harness" / "python-server" / "server.py"


@pytest.fixture(scope="module")
def server_module() -> ModuleType:
    """Load the harness module in-process so the RPC seam can be deterministic."""
    spec = importlib.util.spec_from_file_location("pay_kit_python_harness_server", _ADAPTER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


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
        # The charge server enforces a >=32-byte HMAC secret at boot, so the
        # adapter must be given one explicitly rather than falling back to the
        # short default (matches the session default in server.py).
        "MPP_HARNESS_SECRET_KEY": "mpp-harness-secret-key-with-32b-pad",
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


# --- IO-cap regression coverage (L-3) ----------------------------------------
#
# The hand-rolled harness HTTP server must clamp what it reads: an
# oversized request body is rejected with 413 *before* the server
# allocates/streams the declared Content-Length, and a request whose
# headers exceed the size cap is rejected with 431. These caps mirror the
# 16 KiB per-header / 1 MiB body limits the Ruby harness server uses so the
# two behave identically, and comfortably clear every legitimate harness
# payload (a base64 Solana transaction is ~1.6 KiB; the MPP token cap is
# itself 16 KiB).

# Well beyond the 1 MiB body cap: proves the server refuses without reading
# the full declared length.
_OVERSIZED_BODY_LEN = 4 * 1024 * 1024
# One header value past the 16 KiB per-header cap.
_OVERSIZED_HEADER_VALUE = "A" * (32 * 1024)


def _x402_env() -> dict[str, str]:
    """Env for a clean x402 boot (no live RPC, no 32-byte-secret gate)."""
    return {
        **os.environ,
        "PAY_KIT_HARNESS_PROTOCOL": "x402",
        "X402_HARNESS_RPC_URL": "http://127.0.0.1:8899",
        "X402_HARNESS_PAY_TO": "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
        "X402_HARNESS_FACILITATOR_SECRET_KEY": _fake_keypair_json(),
        "X402_HARNESS_RESOURCE_PATH": "/protected",
        # This process-local server is an explicit devnet harness fixture.
        # Production adapters still require a durable shared replay store.
        "PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE": "1",
    }


def _session_env() -> dict[str, str]:
    """Env for a clean session boot (the POST body path lives here)."""
    from solders.keypair import Keypair

    # The session server pins operator == recipient == settle signer, so the
    # merchant signer's pubkey must equal MPP_HARNESS_PAY_TO or the boot guard
    # exits. Mint one merchant keypair and use its pubkey as the recipient.
    merchant = Keypair()
    return {
        **os.environ,
        "PAY_KIT_HARNESS_PROTOCOL": "session",
        "MPP_HARNESS_RPC_URL": "http://127.0.0.1:8899",
        "MPP_HARNESS_NETWORK": "localnet",
        "MPP_HARNESS_PAY_TO": str(merchant.pubkey()),
        "MPP_HARNESS_AMOUNT": "1000",
        "MPP_HARNESS_FEE_PAYER_SECRET_KEY": _fake_keypair_json(),
        "MPP_HARNESS_SESSION_MERCHANT_SECRET_KEY": json.dumps(list(bytes(merchant))),
    }


def _base58_encode(data: bytes) -> str:
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    number = int.from_bytes(data, "big")
    encoded = ""
    while number:
        number, remainder = divmod(number, 58)
        encoded = alphabet[remainder] + encoded
    leading_zeros = len(data) - len(data.lstrip(b"\0"))
    return "1" * leading_zeros + (encoded or "1")


def _confirmed_top_up_transaction(channel_id: str, amount: int) -> dict[str, Any]:
    """Build the parsed RPC shape consumed by the real top-up verifier."""
    instruction = build_top_up_instruction(
        TopUpParams(
            payer=Keypair.from_seed(bytes([37] * 32)).pubkey(),
            channel=Pubkey.from_string(channel_id),
            mint=Pubkey.from_string("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"),
            amount=amount,
            token_program=Pubkey.from_string(TOKEN_PROGRAM),
        )
    )
    return {
        "meta": {"err": None},
        "transaction": {
            "message": {
                "instructions": [
                    {
                        "programId": str(instruction.program_id),
                        "accounts": [str(account.pubkey) for account in instruction.accounts],
                        "data": _base58_encode(bytes(instruction.data)),
                    }
                ]
            }
        },
    }


class _MismatchedTopUpRpc:
    """A confirmed RPC transaction whose top-up amount is intentionally wrong."""

    def __init__(self, signature: str, transaction: dict[str, Any]) -> None:
        self.signature = signature
        self.transaction = transaction
        self.get_transaction_kwargs: list[dict[str, Any]] = []
        self.closed = False

    async def get_account_info(self, *_args: Any, **_kwargs: Any) -> None:
        return None

    async def get_signature_statuses(
        self,
        signatures: list[str],
        *,
        search_transaction_history: bool = False,
    ) -> list[dict[str, str | None]]:
        del search_transaction_history
        return [
            {"err": None, "confirmationStatus": "confirmed"} if signature == self.signature else {"err": "not found"}
            for signature in signatures
        ]

    async def get_transaction(self, signature: str, **kwargs: Any) -> dict[str, Any] | None:
        self.get_transaction_kwargs.append(kwargs)
        return self.transaction if signature == self.signature else None

    async def aclose(self) -> None:
        self.closed = True


class _Server:
    """Spawn the adapter, expose its port, and reap it on exit."""

    def __init__(self, env: dict[str, str]) -> None:
        self.proc = subprocess.Popen(  # noqa: S603 (test-only subprocess of a known script)
            [sys.executable, "-u", str(_ADAPTER)],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        ready_line = self.proc.stdout.readline() if self.proc.stdout else ""
        if not ready_line:
            stderr = self.proc.stderr.read() if self.proc.stderr else ""
            raise AssertionError(f"adapter did not emit ready handshake; stderr={stderr}")
        self.port = int(json.loads(ready_line)["port"])
        _wait_for_port(self.port)

    def __enter__(self) -> _Server:
        return self

    def __exit__(self, *exc: object) -> None:
        self.proc.terminate()
        try:
            self.proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=2)


def _read_status_line(port: int, raw: bytes, *, after_headers: bytes = b"", timeout: float = 4.0) -> bytes:
    """Send a raw HTTP request; return the status line the server replies with.

    ``after_headers`` is sent *after* the header block so an oversized
    Content-Length can be declared while only a tiny body is actually
    transmitted -- a fixed server must answer from the headers alone rather
    than block waiting for the full declared body.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        sock.connect(("127.0.0.1", port))
        sock.sendall(raw)
        if after_headers:
            sock.sendall(after_headers)
        chunk = sock.recv(4096)
        return chunk.split(b"\r\n", 1)[0]


def test_oversized_header_rejected_with_431():
    """A single header value beyond the per-header cap is rejected with 431
    *before* the request reaches protocol handling (which would otherwise
    answer 402/200)."""
    with _Server(_x402_env()) as server:
        raw = (
            b"GET /protected HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"X-Overflow: " + _OVERSIZED_HEADER_VALUE.encode("ascii") + b"\r\n"
            b"Connection: close\r\n\r\n"
        )
        status = _read_status_line(server.port, raw)
        assert b" 431 " in status, f"expected 431 for oversized headers, got {status!r}"


def test_oversized_body_rejected_with_413_without_reading_body():
    """A POST declaring a Content-Length past the body cap is rejected with
    413 from the headers alone. The client sends only a two-byte body, so a
    server that blindly ``rfile.read(Content-Length)`` would block waiting
    for ~4 MiB that never arrives; the fixed server must answer promptly."""
    with _Server(_session_env()) as server:
        raw = (
            b"POST /__402/session/deliveries HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Content-Length: " + str(_OVERSIZED_BODY_LEN).encode("ascii") + b"\r\n"
            b"Connection: close\r\n\r\n"
        )
        # Send the header block, then only a two-byte partial body. A server
        # that clamps before reading answers 413 from the headers; one that
        # trusts Content-Length blocks until the socket timeout fires.
        status = _read_status_line(server.port, raw, after_headers=b"{}")
        assert b" 413 " in status, f"expected 413 for oversized body, got {status!r}"


@pytest.mark.asyncio
async def test_session_top_up_rejects_confirmed_transaction_with_mismatched_delta(
    monkeypatch: pytest.MonkeyPatch, server_module: ModuleType
) -> None:
    """The HTTP session path must install the RPC-backed top-up verifier.

    The RPC says the transaction succeeded and returns a genuine payment-channels
    top-up for this channel, but its +999 delta cannot justify the claimed
    1,000 -> 2,000 deposit. Before request-scoped construction, the harness
    mutated only ``Session._rpc`` and accepted this payload because the core
    verifier was permanently configured as ``None``.
    """
    environment = _session_env()
    environment["MPP_HARNESS_AMOUNT"] = "5000"
    for key, value in environment.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(server_module, "_fetch_recent_state_sync", lambda _rpc_url: (None, None))

    adapter = server_module._Adapter()
    channel_id = str(Keypair.from_seed(bytes([38] * 32)).pubkey())
    authorized_signer = str(Keypair.from_seed(bytes([39] * 32)).pubkey())
    owner = str(Keypair.from_seed(bytes([41] * 32)).pubkey())
    await adapter.session_method.core().process_open(
        OpenPayload.pull(channel_id, "1000", owner, authorized_signer, "trusted-open")
    )

    signature = str(Keypair.from_seed(bytes([40] * 32)).sign_message(b"mismatched-top-up"))
    rpc = _MismatchedTopUpRpc(signature, _confirmed_top_up_transaction(channel_id, 999))
    monkeypatch.setattr(server_module, "SolanaRpc", lambda _rpc_url: rpc)

    challenge = await adapter.session_method.challenge(adapter.session_challenge)
    credential = PaymentCredential(
        challenge=challenge.to_echo(),
        payload=SessionAction.top_up_action(TopUpPayload(channel_id, "2000", signature)).to_dict(),
    )

    httpd = server_module.HTTPServer(("127.0.0.1", 0), server_module.HarnessHandler)
    httpd.adapter = adapter
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    response_body: dict[str, Any]
    try:
        request = urllib.request.Request(
            f"http://127.0.0.1:{httpd.server_port}{adapter.resource_path}",
            headers={"Authorization": format_authorization(credential)},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as excinfo:
            urllib.request.urlopen(request, timeout=2)  # noqa: S310 (loopback harness request)
        assert excinfo.value.code == 402
        response_body = json.loads(excinfo.value.read())
        assert response_body["status"] == 402
        assert "amount" in response_body["message"]
    finally:
        httpd.shutdown()
        thread.join(timeout=3)
        httpd.server_close()

    assert rpc.get_transaction_kwargs == [
        {"commitment": "confirmed", "encoding": "jsonParsed", "max_supported_transaction_version": 0}
    ], response_body
    assert rpc.closed
    state = await adapter.session_method.core().store().get_channel(channel_id)
    assert state is not None
    assert state.deposit == 1000
