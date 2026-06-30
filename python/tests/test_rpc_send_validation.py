"""Regression for send_raw_transaction signature validation.

A non-compliant RPC proxy can return {"result": null} on sendTransaction. If
that null leaks into the durable replay store as the consume key, a "None"
entry persists forever as garbage. SolanaRpc.send_raw_transaction must reject
empty or non-string signatures before the caller writes to the store.
"""

import pytest

from solana_pay_kit._paycore.rpc import SolanaRpc, _RpcError


class _FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def json(self):
        return self._payload

    def raise_for_status(self):
        return None


class _FakeClient:
    def __init__(self, payload):
        self._payload = payload
        self.calls = 0

    async def post(self, _url, json):
        self.calls += 1
        return _FakeResponse(self._payload)

    async def aclose(self):
        return None


def _rpc_with(payload) -> SolanaRpc:
    rpc = SolanaRpc("http://localhost:9999")
    rpc._client = _FakeClient(payload)  # pyright: ignore[reportAttributeAccessIssue]
    return rpc


@pytest.mark.asyncio
async def test_send_raw_transaction_rejects_null_result():
    rpc = _rpc_with({"result": None, "id": 1, "jsonrpc": "2.0"})
    with pytest.raises(_RpcError) as exc:
        await rpc.send_raw_transaction(b"raw")
    assert "empty or non-string signature" in str(exc.value)
    assert exc.value.code == "payment_invalid"


@pytest.mark.asyncio
async def test_send_raw_transaction_rejects_empty_string():
    rpc = _rpc_with({"result": "   ", "id": 1, "jsonrpc": "2.0"})
    with pytest.raises(_RpcError):
        await rpc.send_raw_transaction(b"raw")


@pytest.mark.asyncio
async def test_send_raw_transaction_rejects_non_string():
    rpc = _rpc_with({"result": 12345, "id": 1, "jsonrpc": "2.0"})
    with pytest.raises(_RpcError):
        await rpc.send_raw_transaction(b"raw")


@pytest.mark.asyncio
async def test_send_raw_transaction_accepts_valid_signature():
    sig = "5mNJ9Z2aRealLookingSignatureBase58CharactersAbcdefghijklmnopqrs"
    rpc = _rpc_with({"result": sig, "id": 1, "jsonrpc": "2.0"})
    resp = await rpc.send_raw_transaction(b"raw")
    assert resp.value == sig
