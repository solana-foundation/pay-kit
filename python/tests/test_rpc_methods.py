"""Exhaustive coverage for SolanaRpc methods.

Hits every branch in :mod:`solana_pay_kit._paycore.rpc` so the JSON-RPC wrapper meets
the 90 percent line coverage gate: the error branch in ``_call``, both
``get_signature_statuses`` return shapes, ``get_transaction``,
``confirm_transaction`` legacy shim (success and timeout), and
``await_confirmation`` (success, on-chain failure, timeout).
"""

from __future__ import annotations

from typing import Any

import pytest

from solana_pay_kit._paycore.errors import PaymentError
from solana_pay_kit._paycore.rpc import RpcResponseError, SolanaRpc, _RpcError, _RpcResponse


class _FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def json(self):
        return self._payload

    def raise_for_status(self):
        return None


class _ScriptedClient:
    """Returns the next payload on each post() call."""

    def __init__(self, payloads):
        self._payloads = list(payloads)
        self.calls = 0
        self.last_body = None

    async def post(self, _url, json):
        self.calls += 1
        self.last_body = json
        if len(self._payloads) == 1:
            return _FakeResponse(self._payloads[0])
        return _FakeResponse(self._payloads.pop(0))

    async def aclose(self):
        return None


def _rpc(payloads) -> SolanaRpc:
    rpc = SolanaRpc("http://localhost:9999", timeout=1.0)
    rpc._client = _ScriptedClient(payloads if isinstance(payloads, list) else [payloads])  # type: ignore[assignment]
    return rpc


@pytest.mark.asyncio
async def test_rpc_response_value_attr():
    r = _RpcResponse(42)
    assert r.value == 42


@pytest.mark.asyncio
async def test_call_raises_rpc_error_with_message():
    rpc = _rpc({"error": {"code": -32000, "message": "boom"}, "id": 1})
    with pytest.raises(_RpcError) as exc:
        await rpc._call("foo", [])
    assert "boom" in str(exc.value)
    assert exc.value.code == "payment_invalid"


@pytest.mark.asyncio
async def test_call_raises_rpc_error_without_message():
    rpc = _rpc({"error": {"code": -1}, "id": 1})
    with pytest.raises(_RpcError):
        await rpc._call("foo", [])


@pytest.mark.asyncio
async def test_get_signature_statuses_returns_value_list():
    payload = {"result": {"value": [{"confirmationStatus": "confirmed", "err": None}]}, "id": 1}
    rpc = _rpc(payload)
    out = await rpc.get_signature_statuses(["sig1"])
    assert out == [{"confirmationStatus": "confirmed", "err": None}]


@pytest.mark.asyncio
async def test_get_signature_statuses_returns_empty_on_null_result():
    rpc = _rpc({"result": None, "id": 1})
    assert await rpc.get_signature_statuses(["s"]) == []


@pytest.mark.asyncio
async def test_get_signature_statuses_returns_empty_on_null_value():
    rpc = _rpc({"result": {"value": None}, "id": 1})
    assert await rpc.get_signature_statuses(["s"]) == []


@pytest.mark.asyncio
async def test_get_signature_statuses_searches_history_only_when_asked():
    client = _ScriptedClient([{"result": {"value": [None]}, "id": 1}])
    rpc = SolanaRpc("http://localhost:9999", timeout=1.0)
    rpc._client = client  # type: ignore[assignment]
    await rpc.get_signature_statuses(["s"])
    assert client.last_body == {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getSignatureStatuses",
        "params": [["s"], {"searchTransactionHistory": False}],
    }
    await rpc.get_signature_statuses(["s"], search_history=True)
    assert client.last_body == {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "getSignatureStatuses",
        "params": [["s"], {"searchTransactionHistory": True}],
    }


@pytest.mark.asyncio
async def test_get_transaction_returns_wrapped_value():
    rpc = _rpc({"result": {"slot": 100}, "id": 1})
    resp = await rpc.get_transaction("sig")
    assert resp.value == {"slot": 100}
    # Confirm parameters were sent with jsonParsed + commitment.
    body = rpc._client.last_body  # type: ignore[attr-defined]
    assert body["method"] == "getTransaction"
    assert body["params"][1]["encoding"] == "jsonParsed"
    assert body["params"][1]["maxSupportedTransactionVersion"] == 1


@pytest.mark.asyncio
async def test_confirm_transaction_success():
    payload = {"result": {"value": [{"confirmationStatus": "finalized", "err": None}]}, "id": 1}
    rpc = _rpc(payload)
    resp = await rpc.confirm_transaction("sig")
    assert resp.value == [{"err": None}]


@pytest.mark.asyncio
async def test_confirm_transaction_timeout():
    # Returns processed (not confirmed/finalized) — caller should exit on max attempts.
    rpc = SolanaRpc("http://localhost:9999")
    # Always returns "processed" status so confirm_transaction loops 40x and returns timeout.
    rpc._client = _ScriptedClient([{"result": {"value": [{"confirmationStatus": "processed"}]}, "id": 1}])  # type: ignore[assignment]
    # Speed up: monkeypatch asyncio.sleep on the module
    import solana_pay_kit._paycore.rpc as rpc_mod

    async def _noop_sleep(_s):
        return None

    original = rpc_mod.asyncio.sleep
    rpc_mod.asyncio.sleep = _noop_sleep  # type: ignore[assignment]
    try:
        resp = await rpc.confirm_transaction("sig")
    finally:
        rpc_mod.asyncio.sleep = original  # type: ignore[assignment]
    assert resp.value == [{"err": "timeout"}]


@pytest.mark.asyncio
async def test_await_confirmation_success_confirmed():
    rpc = _rpc({"result": {"value": [{"confirmationStatus": "confirmed", "err": None}]}, "id": 1})
    await rpc.await_confirmation("sig", attempts=1, delay_seconds=0)


@pytest.mark.asyncio
async def test_await_confirmation_success_finalized():
    rpc = _rpc({"result": {"value": [{"confirmationStatus": "finalized", "err": None}]}, "id": 1})
    await rpc.await_confirmation("sig", attempts=1, delay_seconds=0)


@pytest.mark.asyncio
async def test_await_confirmation_raises_on_onchain_err():
    rpc = _rpc(
        {
            "result": {
                "value": [
                    {
                        "confirmationStatus": "confirmed",
                        "err": {"InstructionError": [0, "BorshIoError"]},
                    }
                ]
            },
            "id": 1,
        }
    )
    with pytest.raises(PaymentError) as exc:
        await rpc.await_confirmation("sig", attempts=1, delay_seconds=0)
    assert exc.value.code == "transaction-failed"
    assert "failed on-chain" in str(exc.value)


@pytest.mark.asyncio
async def test_await_confirmation_timeout():
    # Status always None inside list => never confirmed; raises transaction-not-found.
    rpc = _rpc({"result": {"value": [None]}, "id": 1})
    with pytest.raises(PaymentError) as exc:
        await rpc.await_confirmation("sig", attempts=2, delay_seconds=0)
    assert exc.value.code == "transaction-not-found"


@pytest.mark.asyncio
async def test_await_confirmation_timeout_with_processed_status():
    # Status dict but not yet confirmed.
    rpc = _rpc({"result": {"value": [{"confirmationStatus": "processed", "err": None}]}, "id": 1})
    with pytest.raises(PaymentError) as exc:
        await rpc.await_confirmation("sig", attempts=2, delay_seconds=0)
    assert exc.value.code == "transaction-not-found"


@pytest.mark.asyncio
async def test_aclose_calls_underlying_client():
    rpc = _rpc({"result": None, "id": 1})
    await rpc.aclose()
    # Survives without error.


@pytest.mark.asyncio
async def test_get_latest_blockhash_returns_value_blockhash():
    # Regression: the x402 client's blockhash fallback calls
    # rpc.get_latest_blockhash() and reads resp.value.blockhash. Manual DX
    # caught that SolanaRpc lacked this method entirely.
    payload = {
        "result": {
            "context": {"slot": 1},
            "value": {"blockhash": "Bh11111111111111111111111111111111111111111", "lastValidBlockHeight": 200},
        },
        "id": 1,
    }
    rpc = _rpc(payload)
    resp = await rpc.get_latest_blockhash()
    assert resp.value.blockhash == "Bh11111111111111111111111111111111111111111"
    # The envelope's current slot is surfaced as context.slot so challenge
    # issuance stamps recentSlot without a separate getSlot round-trip.
    assert resp.context is not None and resp.context.slot == 1


@pytest.mark.asyncio
async def test_get_latest_blockhash_tolerates_missing_context_slot():
    payload = {
        "result": {"value": {"blockhash": "Bh11111111111111111111111111111111111111111"}},
        "id": 1,
    }
    resp = await _rpc(payload).get_latest_blockhash()
    assert resp.context is not None and resp.context.slot is None


@pytest.mark.asyncio
async def test_get_latest_blockhash_rejects_missing_blockhash():
    rpc = _rpc({"result": {"value": {}}, "id": 1})
    with pytest.raises(_RpcError):
        await rpc.get_latest_blockhash()


@pytest.mark.asyncio
async def test_get_slot_returns_integer_and_rejects_garbage():
    assert await _rpc({"result": 12345, "id": 1}).get_slot() == 12345
    with pytest.raises(_RpcError):
        await _rpc({"result": "not-a-slot", "id": 1}).get_slot()


@pytest.mark.asyncio
async def test_is_blockhash_valid_reads_value_and_rejects_garbage():
    client = _ScriptedClient([{"result": {"context": {"slot": 1}, "value": False}}])
    rpc = SolanaRpc("http://localhost:9999", timeout=1.0)
    rpc._client = client  # type: ignore[assignment]
    assert await rpc.is_blockhash_valid("hash") is False
    assert client.last_body == {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "isBlockhashValid",
        "params": ["hash", {"commitment": "confirmed"}],
    }
    with pytest.raises(PaymentError, match="no boolean"):
        await _rpc({"result": {"value": "yes"}}).is_blockhash_valid("hash")


@pytest.mark.asyncio
async def test_send_rejection_is_a_response_error_but_a_null_signature_is_not():
    # A JSON-RPC error means the node refused the transaction before forwarding it;
    # a null result is ambiguous, so it must not look like a rejection.
    with pytest.raises(RpcResponseError):
        await _rpc({"error": {"code": -32002, "message": "Transaction simulation failed"}}).send_raw_transaction(b"x")
    with pytest.raises(_RpcError) as exc:
        await _rpc({"result": None}).send_raw_transaction(b"x")
    assert not isinstance(exc.value, RpcResponseError)


class _KeepAliveRpcServer:
    """A local JSON-RPC server that holds the connection open between calls.

    The per-loop client bug only shows with a pooled connection: the second
    request reuses a socket the first loop opened, and httpx then touches a
    closed loop. A keep-alive HTTP/1.1 server is what makes that reuse happen.
    """

    def __init__(self, result: Any) -> None:
        import http.server
        import json as _json
        import threading as _threading

        payload = _json.dumps({"jsonrpc": "2.0", "id": 1, "result": result}).encode()

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler's name
                self.rfile.read(int(self.headers.get("content-length", 0)))
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - the base signature
                return  # keep the test output clean

        self._server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self._server.server_address[1]}"
        self._thread = _threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()


def test_rpc_client_is_per_event_loop() -> None:
    """Two asyncio.run calls, one shared SolanaRpc: the second must not hit a closed loop."""
    import asyncio

    from solana_pay_kit._paycore.rpc import SolanaRpc

    server = _KeepAliveRpcServer({"value": {"blockhash": "4vJ9JU1bJJQpUgJ8V6hYz7xXKz4F2tN6aBrZEcD3xKhs"}})
    try:
        rpc = SolanaRpc(server.url)

        async def call() -> tuple[str, int]:
            response = await rpc.get_latest_blockhash()
            return response.value.blockhash, id(rpc._client)  # pyright: ignore[reportPrivateUsage]

        first_hash, first_client = asyncio.run(call())
        second_hash, second_client = asyncio.run(call())
        assert first_hash == second_hash
        assert first_client != second_client  # a fresh client for the fresh loop
    finally:
        server.close()
