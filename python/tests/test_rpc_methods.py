"""Exhaustive coverage for SolanaRpc methods.

Hits every branch in :mod:`solana_pay_kit._paycore.rpc` so the JSON-RPC wrapper meets
the 90 percent line coverage gate: the error branch in ``_call``, both
``get_signature_statuses`` return shapes, ``get_transaction``,
``confirm_transaction`` legacy shim (success and timeout), and
``await_confirmation`` (success, on-chain failure, timeout).
"""

from __future__ import annotations

import base64

import pytest

from solana_pay_kit._paycore.errors import PaymentError
from solana_pay_kit._paycore.rpc import (
    MalformedAccountError,
    SolanaRpc,
    _RpcError,
    _RpcResponse,
    read_with_replica_retry,
    resolve_channel_read_policy,
)


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


# -- batch-settlement RPC additions --------------------------------------------


async def test_simulate_transaction_sends_exact_bytes_unverified_and_returns_value() -> None:
    rpc = _rpc({"result": {"context": {"slot": 1}, "value": {"err": None, "logs": ["ok"]}}, "id": 1})
    assert await rpc.simulate_transaction(b"\x01\x02") == {"err": None, "logs": ["ok"]}
    body = rpc._client.last_body  # type: ignore[attr-defined]
    assert body["method"] == "simulateTransaction"
    assert body["params"][0] == base64.b64encode(b"\x01\x02").decode()
    # Unsigned fee-payer slot must not fail simulation, and the client's own
    # blockhash is what gets simulated.
    assert body["params"][1]["sigVerify"] is False
    assert body["params"][1]["replaceRecentBlockhash"] is False
    with pytest.raises(_RpcError):
        await _rpc({"result": {"value": None}, "id": 1}).simulate_transaction(b"\x01")


async def test_get_multiple_accounts_keeps_order_and_none_only_for_absent() -> None:
    encoded = base64.b64encode(b"chan").decode()
    rpc = _rpc({"result": {"value": [None, {"owner": "Prog", "data": [encoded, "base64"]}]}, "id": 1})
    assert await rpc.get_multiple_accounts(["A", "B"]) == [None, (b"chan", "Prog")]
    # A visible but unreadable account (even an empty object) is an answer,
    # never the retryable None.
    rpc = _rpc({"result": {"value": [{}]}, "id": 1})
    with pytest.raises(MalformedAccountError):
        await rpc.get_multiple_accounts(["A"])
    # A value list that does not line up with the request cannot be mapped back.
    with pytest.raises(_RpcError):
        await _rpc({"result": {"value": [None]}, "id": 1}).get_multiple_accounts(["A", "B"])


async def test_get_multiple_accounts_chunks_at_the_rpc_address_cap() -> None:
    rpc = _rpc([{"result": {"value": [None] * 100}, "id": 1}, {"result": {"value": [None]}, "id": 2}])
    out = await rpc.get_multiple_accounts([f"A{i}" for i in range(101)])
    assert len(out) == 101
    assert rpc._client.calls == 2  # type: ignore[attr-defined]
    assert rpc._client.last_body["params"][0] == ["A100"]  # type: ignore[attr-defined]


async def test_get_program_accounts_sends_filters_and_skips_unreadable_entries() -> None:
    encoded = base64.b64encode(b"chan").decode()
    rpc = _rpc(
        {
            "result": [
                {"pubkey": "Good", "account": {"owner": "Prog", "data": [encoded, "base64"]}},
                {"pubkey": "Bad", "account": {"owner": "Prog", "data": {"parsed": {}}}},
                {"account": {"owner": "Prog", "data": [encoded, "base64"]}},
            ],
            "id": 1,
        }
    )
    assert await rpc.get_program_accounts("Prog", data_size=256, memcmp=[(216, "Payee")]) == [("Good", b"chan")]
    params = rpc._client.last_body["params"]  # type: ignore[attr-defined]
    assert params[0] == "Prog"
    assert params[1]["filters"] == [{"dataSize": 256}, {"memcmp": {"offset": 216, "bytes": "Payee"}}]
    with pytest.raises(_RpcError):
        await _rpc({"result": None, "id": 1}).get_program_accounts("Prog", data_size=256, memcmp=[])


# -- channel-read replica-lag retry (carried verbatim from PR #310) ----------


async def test_read_with_replica_retry_uses_linear_backoff_schedule(monkeypatch) -> None:
    # The contract: 6 attempts, 200ms step, the wait before attempt N+1 is
    # step * N, and no sleep after the final attempt. Linear, not exponential:
    # replica lag is a small multiple of the ~400ms slot time, so doubling
    # would spend the budget on single waits far longer than the lag absorbed.
    import asyncio

    real_sleep = asyncio.sleep
    delays: list[float] = []

    async def _fake_sleep(seconds: float) -> None:
        delays.append(seconds)
        await real_sleep(0)

    monkeypatch.setattr(asyncio, "sleep", _fake_sleep)

    reads = 0

    async def _read() -> object | None:
        nonlocal reads
        reads += 1
        return None

    assert await read_with_replica_retry(_read) is None
    assert reads == 6
    assert delays == pytest.approx([0.2, 0.4, 0.6, 0.8, 1.0])
    assert sum(delays) == pytest.approx(3.0)
    assert max(delays) == pytest.approx(1.0)


async def test_read_with_replica_retry_stops_at_the_first_visible_read() -> None:
    values = [None, None, "channel"]

    async def _read() -> object | None:
        return values.pop(0)

    assert await read_with_replica_retry(_read, backoff_step_seconds=0.001) == "channel"
    assert values == []


async def test_read_with_replica_retry_never_retries_a_visible_value() -> None:
    # A visible value is an answer, not lag: returned on the first read, even
    # when the caller is about to reject it.
    reads = 0

    async def _read() -> int:
        nonlocal reads
        reads += 1
        return 1_500

    assert await read_with_replica_retry(_read, backoff_step_seconds=0.001) == 1_500
    assert reads == 1


async def test_read_with_replica_retry_propagates_read_errors_without_retrying() -> None:
    reads = 0

    async def _read() -> object:
        nonlocal reads
        reads += 1
        raise PaymentError("wrong owner", code="invalid-payload")

    with pytest.raises(PaymentError, match="wrong owner"):
        await read_with_replica_retry(_read, backoff_step_seconds=0.001)
    assert reads == 1


def test_resolve_channel_read_policy_defaults_on_unset_or_non_positive() -> None:
    # Unset or non-positive resolves to the default, so a caller may pass a
    # zero value without disabling the retry.
    assert resolve_channel_read_policy(None, None) == (6, 0.2)
    assert resolve_channel_read_policy(0, 0) == (6, 0.2)
    assert resolve_channel_read_policy(-1, -5) == (6, 0.2)
    assert resolve_channel_read_policy(3, 50) == (3, 0.05)


async def test_is_blockhash_valid_reads_the_value_and_rejects_garbage() -> None:
    rpc = _rpc([{"result": {"context": {"slot": 1}, "value": False}}, {"result": {"value": "yes"}}])
    assert await rpc.is_blockhash_valid("hash") is False
    assert rpc._client.last_body["method"] == "isBlockhashValid"  # type: ignore[attr-defined]
    with pytest.raises(_RpcError):
        await rpc.is_blockhash_valid("hash")
