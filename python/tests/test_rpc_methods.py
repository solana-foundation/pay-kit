"""Exhaustive coverage for SolanaRpc methods.

Hits every branch in :mod:`solana_pay_kit._paycore.rpc` so the JSON-RPC wrapper meets
the 90 percent line coverage gate: the error branch in ``_call``, both
``get_signature_statuses`` return shapes, ``get_transaction``,
``confirm_transaction`` legacy shim (success and timeout), and
``await_confirmation`` (success, on-chain failure, timeout).
"""

from __future__ import annotations

import pytest

from solana_pay_kit._paycore.errors import PaymentError
from solana_pay_kit._paycore.rpc import SolanaRpc, _RpcError, _RpcResponse


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
async def test_get_transaction_returns_wrapped_value():
    rpc = _rpc({"result": {"slot": 100}, "id": 1})
    resp = await rpc.get_transaction("sig")
    assert resp.value == {"slot": 100}
    # Confirm parameters were sent with jsonParsed + commitment.
    body = rpc._client.last_body  # type: ignore[attr-defined]
    assert body["method"] == "getTransaction"
    assert body["params"][1]["encoding"] == "jsonParsed"
    assert body["params"][1]["maxSupportedTransactionVersion"] == 0


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


@pytest.mark.asyncio
async def test_get_latest_blockhash_rejects_missing_blockhash():
    rpc = _rpc({"result": {"value": {}}, "id": 1})
    with pytest.raises(_RpcError):
        await rpc.get_latest_blockhash()
