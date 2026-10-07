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


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("message", "code"),
    [
        ("Transaction simulation failed: This transaction has already been processed", "signature_consumed"),
        (
            "Transaction verification failed for transaction Internal error: "
            '"Transaction error: This transaction has already been processed"',
            "signature_consumed",
        ),
        ("Transaction already processed", "signature_consumed"),
        ("TRANSACTION ALREADY PROCESSED", "signature_consumed"),
        ("Transaction simulation failed: Blockhash not found", "payment_invalid"),
        ("Transaction signature verification failure", "payment_invalid"),
        ("Transaction simulation failed: insufficient funds", "payment_invalid"),
        ("node is unhealthy", "payment_invalid"),
    ],
)
async def test_send_error_classifies_only_explicit_rpc_duplicates(message, code):
    # -32002 is shared by duplicate and unrelated preflight failures; it alone
    # must never identify a replay.
    rpc = _rpc_with({"error": {"code": -32002, "message": message}})
    with pytest.raises(_RpcError) as exc:
        await rpc.send_raw_transaction(b"raw")
    assert exc.value.code == code
    assert str(exc.value) == message
    assert isinstance(rpc._client, _FakeClient)
    assert rpc._client.calls == 1


@pytest.mark.asyncio
async def test_duplicate_message_on_non_broadcast_rpc_is_not_a_replay():
    rpc = _rpc_with({"error": {"code": -32002, "message": "This transaction has already been processed"}})
    with pytest.raises(_RpcError) as exc:
        await rpc.get_transaction("signature")
    assert exc.value.code == "payment_invalid"
