"""x402 ``verify_and_settle`` full-flow coverage with a stubbed broadcast.

Exercises the credential-envelope path: version / shape checks, the Tier-2
pinned-field gate against the freshly built offer, cosign + broadcast (RPC
stubbed, never live), the replay reservation (``signature_consumed`` on a
second submit), and the response-envelope assembly. Also covers the module
helpers (``_co_sign``, ``_is_loopback_rpc``, ``_request_path``, header reader).
"""

from __future__ import annotations

import base64
import json
import struct

import httpx
import pytest
from solana_keychain import MemorySigner, SignedTransaction
from solders.hash import Hash
from solders.instruction import AccountMeta, Instruction
from solders.keypair import Keypair
from solders.message import MessageV0, to_bytes_versioned
from solders.pubkey import Pubkey
from solders.signature import Signature
from solders.transaction import VersionedTransaction

import solana_pay_kit.protocols.x402 as xmod
from solana_pay_kit import Gate as GateCls
from solana_pay_kit import (
    MemoryStore,
    Operator,
    Price,
    Protocol,
    Stablecoin,
    configure,
)
from solana_pay_kit._paycore.errors import PaymentError
from solana_pay_kit._paycore.mints import derive_ata, resolve, token_program_for
from solana_pay_kit._paycore.rpc import _RpcError
from solana_pay_kit._paycore.store import ConsumedSignatures, consumed_signature_key
from solana_pay_kit.config import reset
from solana_pay_kit.errors import InvalidProofError, SettlementInProgressError
from solana_pay_kit.protocols.x402 import (
    X402_VERSION,
    X402Adapter,
    _co_sign,
    _is_loopback_rpc,
    _request_path,
    _transaction_signature,
)
from solana_pay_kit.protocols.x402.exact.verify import (
    COMPUTE_BUDGET_PROGRAM,
    MEMO_PROGRAM,
)

BH = "4vJ9JU1bJJQpUgJ8V6hYz7xXKz4F2tN6aBrZEcD3xKhs"
_MINT = resolve("USDC", "mainnet")
assert _MINT is not None
MINT: str = _MINT
TP = token_program_for("USDC", "mainnet")


class _FakeRpc:
    """Stub matching solana_pay_kit.protocols.mpp.SolanaRpc's async send/close surface."""

    def __init__(
        self,
        *_a,
        fail: bool | Exception = False,
        confirm_error: Exception | None = None,
        **_k,
    ):
        self._fail = fail
        self._confirm_error = confirm_error
        self.confirm_calls = 0
        self.confirm_history: list[bool] = []
        self.send_calls = 0
        self.aclose_calls = 0

    async def send_raw_transaction(self, _raw):
        self.send_calls += 1
        if isinstance(self._fail, Exception):
            raise self._fail
        if self._fail:
            raise RuntimeError("broadcast boom")

        class _Resp:
            value = ""

        _Resp.value = _transaction_signature(bytes(_raw))
        return _Resp()

    async def await_confirmation(self, _signature, *_a, search_transaction_history: bool = False, **_k):
        self.confirm_calls += 1
        self.confirm_history.append(search_transaction_history)
        if self._confirm_error is not None:
            raise self._confirm_error
        return None

    async def aclose(self):
        self.aclose_calls += 1
        return None


class _ConfirmDuringRecoveryStore(MemoryStore):
    """Simulate the original request confirming as a retry claims recovery."""

    confirm_during_recovery = False

    async def put_if_absent(self, key, value):
        inserted = await super().put_if_absent(key, value)
        if inserted and self.confirm_during_recovery and ":recovery:" in key:
            replay_key = key.split(":recovery:", 1)[0]
            current = await self.get(replay_key)
            assert isinstance(current, dict)
            await self.put(replay_key, {**current, "state": "confirmed"})
        return inserted


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    reset()
    monkeypatch.setenv("PAY_KIT_DISABLE_PREFLIGHT", "1")
    yield
    reset()


def _adapter(store=None, fail: bool | Exception = False, confirm_error=None, monkeypatch=None, rpcs=None):
    op_kp = Keypair()
    op = Operator(signer=MemorySigner(op_kp), recipient=str(Keypair().pubkey()))
    cfg = configure(
        network="solana_localnet",
        preflight=False,
        accept=(Protocol.X402,),
        operator=op,
        rpc_url="http://127.0.0.1:8899",  # loopback skips the blockhash net check
    )
    gate = GateCls.build(
        name="report",
        amount=Price.usd("0.10", Stablecoin.USDC),
        default_pay_to=cfg.effective_recipient(),
        accept=(Protocol.X402,),
    )
    adapter = X402Adapter(cfg, replay_store=store or MemoryStore())

    def _factory(*_a, **_k):
        rpc = _FakeRpc(fail=fail, confirm_error=confirm_error)
        if rpcs is not None:
            rpcs.append(rpc)
        return rpc

    if monkeypatch is not None:
        monkeypatch.setattr(xmod, "SolanaRpc", _factory)
    return adapter, gate, op_kp


def _build_envelope(adapter, gate, op_kp, *, amount_override=None, memo_override=None):
    offer = adapter.accepts_entry(gate, {"path": "/report"})
    amt = amount_override if amount_override is not None else int(offer["amount"])
    authority = Keypair()
    dest = derive_ata(offer["payTo"], MINT, TP)
    src = derive_ata(str(authority.pubkey()), MINT, TP)
    cl = Instruction(Pubkey.from_string(COMPUTE_BUDGET_PROGRAM), bytes([2]) + struct.pack("<I", 200_000), [])
    cp = Instruction(Pubkey.from_string(COMPUTE_BUDGET_PROGRAM), bytes([3]) + struct.pack("<Q", 1_000), [])
    data = bytes([12]) + struct.pack("<Q", amt) + bytes([6])
    metas = [
        AccountMeta(Pubkey.from_string(src), False, True),
        AccountMeta(Pubkey.from_string(MINT), False, False),
        AccountMeta(Pubkey.from_string(dest), False, True),
        AccountMeta(authority.pubkey(), True, False),
    ]
    transfer = Instruction(Pubkey.from_string(TP), data, metas)
    memo_text = memo_override if memo_override is not None else offer["extra"]["memo"]
    memo = Instruction(Pubkey.from_string(MEMO_PROGRAM), memo_text.encode(), [])
    msg = MessageV0.try_compile(op_kp.pubkey(), [cl, cp, transfer, memo], [], Hash.from_string(BH))
    # The v0 wire form a client sends: the transfer authority's slot signed,
    # the fee payer's slot left as a zero placeholder for the server to co-sign.
    num = int(msg.header.num_required_signatures)
    signed_bytes = bytes(to_bytes_versioned(msg))
    sigs = [
        authority.sign_message(signed_bytes) if key == authority.pubkey() else Signature.default()
        for key in msg.account_keys[:num]
    ]
    tx_b64 = base64.b64encode(bytes(VersionedTransaction.populate(msg, sigs))).decode()
    envelope = {
        "x402Version": X402_VERSION,
        "accepted": offer,
        "payload": {"transaction": tx_b64, "transactionHash": "h"},
    }
    return base64.b64encode(json.dumps(envelope).encode()).decode()


async def _settlement_signature(header: str, op_kp: Keypair) -> str:
    envelope = json.loads(base64.b64decode(header))
    wire = await _co_sign(envelope["payload"]["transaction"], MemorySigner(op_kp))
    return _transaction_signature(wire)


class _Req:
    def __init__(self, header, path="/report"):
        self.headers = {"payment-signature": header}
        self.path = path


# -- happy path + replay -----------------------------------------------------


@pytest.mark.asyncio
async def test_verify_and_settle_happy_path(monkeypatch):
    adapter, gate, op_kp = _adapter(monkeypatch=monkeypatch)
    header = _build_envelope(adapter, gate, op_kp)
    signature = await _settlement_signature(header, op_kp)
    payment = await adapter.verify_and_settle(gate, _Req(header))
    assert payment.protocol is Protocol.X402
    assert payment.transaction == signature
    assert payment.settlement_headers["x-payment-settlement-signature"] == signature
    assert "payment-response" in payment.settlement_headers


@pytest.mark.asyncio
async def test_replay_same_transaction_recovers_confirmed_settlement(monkeypatch):
    store = MemoryStore()
    rpcs: list = []
    adapter, gate, op_kp = _adapter(store=store, monkeypatch=monkeypatch, rpcs=rpcs)
    header = _build_envelope(adapter, gate, op_kp)
    first = await adapter.verify_and_settle(gate, _Req(header))
    recovered = await adapter.verify_and_settle(gate, _Req(header))
    assert recovered.transaction == first.transaction
    assert rpcs[0].confirm_calls == 1
    assert rpcs[0].send_calls == 1
    assert len(rpcs) == 1


@pytest.mark.asyncio
async def test_replay_same_signature_with_different_transaction_rejected(monkeypatch):
    store = MemoryStore()
    adapter, gate, op_kp = _adapter(store=store, monkeypatch=monkeypatch)
    header = _build_envelope(adapter, gate, op_kp)
    signature = await _settlement_signature(header, op_kp)
    await store.put(
        consumed_signature_key(signature),
        {"binding": "different-wire", "leaseUntil": 0, "state": "confirmed"},
    )
    with pytest.raises(InvalidProofError) as exc:
        await adapter.verify_and_settle(gate, _Req(header))
    assert exc.value.code == "signature_consumed"


@pytest.mark.asyncio
async def test_signature_settled_through_mpp_is_rejected_by_x402(monkeypatch):
    """MPP charge and x402 share one consumed-signature ledger: a transaction
    already settled through MPP cannot be presented again as an x402 proof."""
    store = MemoryStore()
    rpcs: list = []
    adapter, gate, op_kp = _adapter(store=store, monkeypatch=monkeypatch, rpcs=rpcs)
    header = _build_envelope(adapter, gate, op_kp)
    signature = await _settlement_signature(header, op_kp)
    assert await ConsumedSignatures(store).claim(signature) is True  # MPP settled it

    with pytest.raises(InvalidProofError) as exc:
        await adapter.verify_and_settle(gate, _Req(header))
    assert exc.value.code == "signature_consumed"
    assert not rpcs or rpcs[0].send_calls == 0


@pytest.mark.asyncio
async def test_signature_settled_through_x402_is_consumed_for_mpp(monkeypatch):
    store = MemoryStore()
    adapter, gate, op_kp = _adapter(store=store, monkeypatch=monkeypatch)
    header = _build_envelope(adapter, gate, op_kp)
    payment = await adapter.verify_and_settle(gate, _Req(header))
    # The claim MPP charge makes before granting a receipt now fails.
    assert await ConsumedSignatures(store).claim(payment.transaction) is False
    # An unrelated payment is still accepted.
    assert await ConsumedSignatures(store).claim("other-signature") is True


@pytest.mark.parametrize("legacy_prefix", ["solana-charge:consumed:", "x402-svm-exact:consumed:"])
@pytest.mark.asyncio
async def test_pre_ledger_consumed_record_stays_consumed(monkeypatch, legacy_prefix):
    """A signature claimed under a pre-ledger MPP or x402 key (by an older
    replica, or just before an upgrade) stays consumed for both protocols; the
    legacy record is only read, never rewritten."""
    store = MemoryStore()
    rpcs: list = []
    adapter, gate, op_kp = _adapter(store=store, monkeypatch=monkeypatch, rpcs=rpcs)
    header = _build_envelope(adapter, gate, op_kp)
    signature = await _settlement_signature(header, op_kp)
    await store.put(legacy_prefix + signature, True)

    with pytest.raises(InvalidProofError) as exc:
        await adapter.verify_and_settle(gate, _Req(header))
    assert exc.value.code == "signature_consumed"
    assert not rpcs or rpcs[0].send_calls == 0
    assert await ConsumedSignatures(store).claim(signature) is False
    assert await store.get(consumed_signature_key(signature)) is None
    assert await store.get(legacy_prefix + signature) is True

    # Signatures without a legacy record settle normally.
    await store.delete(legacy_prefix + signature)
    payment = await adapter.verify_and_settle(gate, _Req(header))
    assert payment.transaction == signature


@pytest.mark.asyncio
async def test_preflight_rejection_is_invalid_proof_and_records_nothing(monkeypatch):
    from solana_pay_kit._paycore.rpc import PreflightRejectedError

    store = MemoryStore()
    adapter, gate, op_kp = _adapter(
        store=store, fail=PreflightRejectedError("simulation failed"), monkeypatch=monkeypatch
    )
    header = _build_envelope(adapter, gate, op_kp)
    signature = await _settlement_signature(header, op_kp)
    with pytest.raises(InvalidProofError, match="broadcast failed") as exc:
        await adapter.verify_and_settle(gate, _Req(header))
    assert not isinstance(exc.value, SettlementInProgressError)
    # No node was handed it: the payer may present it again.
    assert await store.get(consumed_signature_key(signature)) is None


@pytest.mark.asyncio
async def test_ambiguous_broadcast_failure_keeps_the_payment_pending(monkeypatch):
    store = MemoryStore()
    now = [1_000.0]
    monkeypatch.setattr(xmod.time, "time", lambda: now[0])
    adapter, gate, op_kp = _adapter(store=store, fail=True, monkeypatch=monkeypatch)
    header = _build_envelope(adapter, gate, op_kp)
    signature = await _settlement_signature(header, op_kp)
    # A lost response: it may have landed. Never a plain rejection.
    with pytest.raises(SettlementInProgressError):
        await adapter.verify_and_settle(gate, _Req(header))
    record = await store.get(consumed_signature_key(signature))
    assert isinstance(record, dict)
    assert record["state"] == "pending"
    with pytest.raises(SettlementInProgressError):
        await adapter.verify_and_settle(gate, _Req(header))

    # Once the lease lapses a retry reconciles it from the chain, without
    # broadcasting it again, and is granted once.
    now[0] += 21 * 60 + 1
    recovered: list = []

    def _recovery_factory(*_a, **_k):
        rpc = _FakeRpc()
        recovered.append(rpc)
        return rpc

    monkeypatch.setattr(xmod, "SolanaRpc", _recovery_factory)
    payment = await adapter.verify_and_settle(gate, _Req(header))
    assert payment.transaction == signature
    assert recovered[0].send_calls == 0


@pytest.mark.asyncio
async def test_recovery_after_the_lease_reads_status_with_history(monkeypatch):
    """A retry long after the broadcast reconciles a payment that may have
    left the node's recent status cache: its confirmation read searches the
    transaction history. The first confirmation, right after the send, does
    not need to."""
    store = MemoryStore()
    now = [1_000.0]
    monkeypatch.setattr(xmod.time, "time", lambda: now[0])
    first: list = []
    adapter, gate, op_kp = _adapter(
        store=store,
        confirm_error=PaymentError("timed out", code="transaction-not-found"),
        monkeypatch=monkeypatch,
        rpcs=first,
    )
    header = _build_envelope(adapter, gate, op_kp)
    with pytest.raises(SettlementInProgressError):
        await adapter.verify_and_settle(gate, _Req(header))
    assert first[0].confirm_history == [False]

    now[0] += 21 * 60 + 1
    recovered: list = []

    def _recovery_factory(*_a, **_k):
        rpc = _FakeRpc()
        recovered.append(rpc)
        return rpc

    monkeypatch.setattr(xmod, "SolanaRpc", _recovery_factory)
    await adapter.verify_and_settle(gate, _Req(header))
    assert recovered[0].send_calls == 0
    assert recovered[0].confirm_history == [True]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error",
    [
        _RpcError("Node is unhealthy", code="payment_invalid"),
        httpx.ConnectError("connection refused"),
    ],
)
async def test_failed_status_read_after_the_send_keeps_the_payment_pending(monkeypatch, error):
    """A node outage while confirming is never proof the payment did not land."""
    store = MemoryStore()
    adapter, gate, op_kp = _adapter(store=store, confirm_error=error, monkeypatch=monkeypatch)
    header = _build_envelope(adapter, gate, op_kp)
    signature = await _settlement_signature(header, op_kp)
    with pytest.raises(SettlementInProgressError):
        await adapter.verify_and_settle(gate, _Req(header))
    record = await store.get(consumed_signature_key(signature))
    assert isinstance(record, dict) and record["state"] == "pending"


# -- confirmation gate (149-2 BLOCKER) ---------------------------------------


@pytest.mark.asyncio
async def test_success_path_awaits_confirmation_before_returning(monkeypatch):
    rpcs: list = []
    adapter, gate, op_kp = _adapter(monkeypatch=monkeypatch, rpcs=rpcs)
    header = _build_envelope(adapter, gate, op_kp)
    signature = await _settlement_signature(header, op_kp)
    payment = await adapter.verify_and_settle(gate, _Req(header))
    assert payment.transaction == signature
    # The adapter must poll confirmation, then close the RPC after the poll.
    assert rpcs[0].confirm_calls == 1
    assert rpcs[0].aclose_calls == 1


@pytest.mark.asyncio
async def test_confirmation_timeout_raises_and_keeps_replay_reservation(monkeypatch):
    from solana_pay_kit._paycore.errors import PaymentError

    store = MemoryStore()
    now = [1_000.0]
    monkeypatch.setattr(xmod.time, "time", lambda: now[0])
    adapter, gate, op_kp = _adapter(
        store=store,
        confirm_error=PaymentError("timed out", code="transaction-not-found"),
        monkeypatch=monkeypatch,
    )
    header = _build_envelope(adapter, gate, op_kp)
    signature = await _settlement_signature(header, op_kp)
    with pytest.raises(SettlementInProgressError) as exc:
        await adapter.verify_and_settle(gate, _Req(header))
    assert exc.value.code == "settlement_in_progress"
    # Broadcast was accepted, so a timeout is ambiguous: the transaction may
    # still land. Keep the reservation to prevent a later duplicate fulfillment.
    record = await store.get(consumed_signature_key(signature))
    assert isinstance(record, dict)
    assert record["state"] == "pending"

    with pytest.raises(SettlementInProgressError):
        await adapter.verify_and_settle(gate, _Req(header))

    now[0] += 21 * 60 + 1
    recovered_rpcs: list = []

    def _recovery_factory(*_a, **_k):
        rpc = _FakeRpc()
        recovered_rpcs.append(rpc)
        return rpc

    monkeypatch.setattr(xmod, "SolanaRpc", _recovery_factory)
    payment = await adapter.verify_and_settle(gate, _Req(header))
    assert payment.transaction == signature
    assert recovered_rpcs[0].confirm_calls == 1
    assert recovered_rpcs[0].send_calls == 0
    confirmed_record = await store.get(consumed_signature_key(signature))
    assert isinstance(confirmed_record, dict)
    assert confirmed_record["state"] == "confirmed"


@pytest.mark.asyncio
async def test_recovery_does_not_replace_concurrently_confirmed_state(monkeypatch):
    from solana_pay_kit._paycore.errors import PaymentError

    now = [1_000.0]
    monkeypatch.setattr(xmod.time, "time", lambda: now[0])
    store = _ConfirmDuringRecoveryStore()
    adapter, gate, op_kp = _adapter(
        store=store,
        confirm_error=PaymentError("timed out", code="transaction-not-found"),
        monkeypatch=monkeypatch,
    )
    header = _build_envelope(adapter, gate, op_kp)
    signature = await _settlement_signature(header, op_kp)
    with pytest.raises(InvalidProofError):
        await adapter.verify_and_settle(gate, _Req(header))

    now[0] += 21 * 60 + 1
    store.confirm_during_recovery = True
    recovery_rpcs: list = []

    def _recovery_factory(*_a, **_k):
        rpc = _FakeRpc()
        recovery_rpcs.append(rpc)
        return rpc

    monkeypatch.setattr(xmod, "SolanaRpc", _recovery_factory)
    payment = await adapter.verify_and_settle(gate, _Req(header))
    assert payment.transaction == signature
    assert recovery_rpcs == []
    record = await store.get(consumed_signature_key(signature))
    assert isinstance(record, dict)
    assert record["state"] == "confirmed"


@pytest.mark.asyncio
async def test_confirmation_onchain_failure_keeps_replay_reservation(monkeypatch):
    from solana_pay_kit._paycore.errors import PaymentError

    store = MemoryStore()
    adapter, gate, op_kp = _adapter(
        store=store,
        confirm_error=PaymentError("reverted", code="transaction-failed"),
        monkeypatch=monkeypatch,
    )
    header = _build_envelope(adapter, gate, op_kp)
    signature = await _settlement_signature(header, op_kp)
    with pytest.raises(InvalidProofError) as exc:
        await adapter.verify_and_settle(gate, _Req(header))
    # It landed and failed: a rejection, not an unresolved settlement.
    assert not isinstance(exc.value, SettlementInProgressError)
    record = await store.get(consumed_signature_key(signature))
    assert isinstance(record, dict)
    assert record["state"] == "pending"


# -- sub-microunit price truncation (149-2) ----------------------------------


def _x402_adapter_for_price(price):
    op = Operator(signer=MemorySigner(Keypair()), recipient=str(Keypair().pubkey()))
    cfg = configure(
        network="solana_localnet",
        preflight=False,
        accept=(Protocol.X402,),
        operator=op,
        rpc_url="http://127.0.0.1:8899",
    )
    gate = GateCls.build(
        name="report",
        amount=price,
        default_pay_to=cfg.effective_recipient(),
        accept=(Protocol.X402,),
    )
    return X402Adapter(cfg, replay_store=MemoryStore()), gate


def test_x402_sub_microunit_price_rejected():
    # Regression: usd("0.0000009") truncated to "0" via int(amount * 1e6),
    # which would have the verifier accept a zero-amount transfer. It must now
    # raise instead of producing "0".
    from solana_pay_kit.errors import ConfigurationError

    adapter, gate = _x402_adapter_for_price(Price.usd("0.0000009", Stablecoin.USDC))
    with pytest.raises(ConfigurationError, match="precision"):
        adapter.accepts_entry(gate, {"path": "/report"})


def test_x402_six_decimal_price_yields_micro_units():
    # A normal 6-dp price still converts exactly.
    adapter, gate = _x402_adapter_for_price(Price.usd("0.10", Stablecoin.USDC))
    offer = adapter.accepts_entry(gate, {"path": "/report"})
    assert offer["amount"] == "100000"
    assert offer["maxAmountRequired"] == "100000"


# -- accepted-echo amount drift (149-1) --------------------------------------


@pytest.mark.asyncio
async def test_amount_drift_one_sided_rejected(monkeypatch):
    """One-sided amount drift must be rejected (AND -> OR fix).

    Tamper only `amount`, leaving `maxAmountRequired` intact. The previous
    AND check passed because maxAmountRequired still matched; the OR check
    rejects on either field drifting.
    """
    adapter, gate, op_kp = _adapter(monkeypatch=monkeypatch)
    header = _build_envelope(adapter, gate, op_kp)
    decoded = json.loads(base64.b64decode(header))
    decoded["accepted"]["amount"] = str(int(decoded["accepted"]["amount"]) + 1)
    tampered = base64.b64encode(json.dumps(decoded).encode()).decode()
    with pytest.raises(InvalidProofError) as exc:
        await adapter.verify_and_settle(gate, _Req(tampered))
    assert exc.value.code == "charge_request_mismatch"


@pytest.mark.asyncio
async def test_max_amount_required_one_sided_drift_rejected(monkeypatch):
    adapter, gate, op_kp = _adapter(monkeypatch=monkeypatch)
    header = _build_envelope(adapter, gate, op_kp)
    decoded = json.loads(base64.b64decode(header))
    decoded["accepted"]["maxAmountRequired"] = str(int(decoded["accepted"]["maxAmountRequired"]) + 5)
    tampered = base64.b64encode(json.dumps(decoded).encode()).decode()
    with pytest.raises(InvalidProofError) as exc:
        await adapter.verify_and_settle(gate, _Req(tampered))
    assert exc.value.code == "charge_request_mismatch"


# -- envelope reject branches ------------------------------------------------


@pytest.mark.asyncio
async def test_missing_signature_header_is_payment_required(monkeypatch):
    adapter, gate, _op = _adapter(monkeypatch=monkeypatch)

    class _Empty:
        headers = {}

    with pytest.raises(InvalidProofError) as exc:
        await adapter.verify_and_settle(gate, _Empty())
    assert exc.value.code == "payment_required"


@pytest.mark.asyncio
async def test_non_base64_signature_header(monkeypatch):
    adapter, gate, _op = _adapter(monkeypatch=monkeypatch)
    with pytest.raises(InvalidProofError) as exc:
        await adapter.verify_and_settle(gate, _Req("!!!notb64!!!"))
    assert exc.value.code == "invalid_exact_svm_payload_signature_base64"


@pytest.mark.asyncio
async def test_non_json_signature_payload(monkeypatch):
    adapter, gate, _op = _adapter(monkeypatch=monkeypatch)
    header = base64.b64encode(b"\xff\xfenot json").decode()
    with pytest.raises(InvalidProofError) as exc:
        await adapter.verify_and_settle(gate, _Req(header))
    assert exc.value.code == "invalid_exact_svm_payload_signature_json"


@pytest.mark.asyncio
async def test_wrong_version_rejected(monkeypatch):
    adapter, gate, _op = _adapter(monkeypatch=monkeypatch)
    header = base64.b64encode(json.dumps({"x402Version": 99}).encode()).decode()
    with pytest.raises(InvalidProofError) as exc:
        await adapter.verify_and_settle(gate, _Req(header))
    assert exc.value.code == "unsupported_x402_version"


@pytest.mark.asyncio
async def test_malformed_envelope_rejected(monkeypatch):
    adapter, gate, _op = _adapter(monkeypatch=monkeypatch)
    bad = {"x402Version": X402_VERSION, "accepted": "x", "payload": 1}
    header = base64.b64encode(json.dumps(bad).encode()).decode()
    with pytest.raises(InvalidProofError) as exc:
        await adapter.verify_and_settle(gate, _Req(header))
    assert exc.value.code == "invalid_exact_svm_payload_envelope"


@pytest.mark.asyncio
async def test_tier2_accepted_mismatch_rejected(monkeypatch):
    adapter, gate, op_kp = _adapter(monkeypatch=monkeypatch)
    header = _build_envelope(adapter, gate, op_kp)
    decoded = json.loads(base64.b64decode(header))
    decoded["accepted"]["payTo"] = str(Keypair().pubkey())  # tamper a pinned field
    tampered = base64.b64encode(json.dumps(decoded).encode()).decode()
    with pytest.raises(InvalidProofError) as exc:
        await adapter.verify_and_settle(gate, _Req(tampered))
    assert exc.value.code == "charge_request_mismatch"


@pytest.mark.asyncio
async def test_missing_transaction_in_payload(monkeypatch):
    adapter, gate, op_kp = _adapter(monkeypatch=monkeypatch)
    header = _build_envelope(adapter, gate, op_kp)
    decoded = json.loads(base64.b64decode(header))
    decoded["payload"]["transaction"] = ""
    tampered = base64.b64encode(json.dumps(decoded).encode()).decode()
    with pytest.raises(InvalidProofError) as exc:
        await adapter.verify_and_settle(gate, _Req(tampered))
    assert exc.value.code == "invalid_exact_svm_payload_missing_transaction"


@pytest.mark.asyncio
async def test_no_operator_signer_rejected(monkeypatch):
    # MPP-only operator path: signer present but x402 still needs a cosigner.
    # Force the effective x402 signer to None by clearing operator signer.
    reset()
    monkeypatch.setenv("PAY_KIT_DISABLE_PREFLIGHT", "1")
    cfg = configure(network="solana_localnet", preflight=False, accept=(Protocol.X402,))
    adapter = X402Adapter(cfg)
    gate = GateCls.build(
        name="report",
        amount=Price.usd("0.10", Stablecoin.USDC),
        default_pay_to=cfg.effective_recipient(),
        accept=(Protocol.X402,),
    )
    # Monkeypatch the config's effective signer to None for this assertion.
    object.__setattr__(cfg.operator, "signer", None)
    with pytest.raises(InvalidProofError, match="requires operator.signer"):
        await adapter.verify_and_settle(gate, _Req("anything"))


# -- helpers -----------------------------------------------------------------


def test_is_loopback_rpc():
    assert _is_loopback_rpc("http://127.0.0.1:8899") is True
    assert _is_loopback_rpc("http://localhost:8899") is True
    assert _is_loopback_rpc("https://[::1]:8899") is True
    assert _is_loopback_rpc("https://api.mainnet-beta.solana.com") is False


def test_request_path_variants():
    class _UrlReq:
        class url:
            path = "/from-url"

    class _PathReq:
        path = "/from-path"

    assert _request_path(_PathReq()) == "/from-path"
    assert _request_path(_UrlReq()) == "/from-url"
    assert _request_path({"path": "/dict"}) == "/dict"
    assert _request_path(object()) == "/"


async def test_co_sign_fee_payer_not_present_rejected():
    payer = Keypair()
    outsider = MemorySigner(Keypair())
    from solders.system_program import TransferParams, transfer

    ix = transfer(TransferParams(from_pubkey=payer.pubkey(), to_pubkey=Keypair().pubkey(), lamports=1))
    msg = MessageV0.try_compile(payer.pubkey(), [ix], [], Hash.from_string(BH))
    vtx = VersionedTransaction(msg, [payer])
    tx_b64 = base64.b64encode(bytes(vtx)).decode()
    with pytest.raises(InvalidProofError):
        await _co_sign(tx_b64, outsider)


async def test_co_sign_unparseable_bytes_rejected():
    bogus = base64.b64encode(b"\x00\x01\x02").decode()
    with pytest.raises(InvalidProofError) as exc:
        await _co_sign(bogus, MemorySigner(Keypair()))
    assert exc.value.code == "invalid_exact_svm_payload_transaction_parse"


async def test_co_sign_accepts_legacy_transaction():
    """A pre-cutover client's legacy (unprefixed) wire is co-signed over the
    bare message bytes, exactly as the runtime verifies it."""
    from solders.message import Message
    from solders.system_program import TransferParams, transfer
    from solders.transaction import Transaction

    op_kp = Keypair()
    ix = transfer(TransferParams(from_pubkey=op_kp.pubkey(), to_pubkey=Keypair().pubkey(), lamports=1))
    tx = Transaction.new_unsigned(Message.new_with_blockhash([ix], op_kp.pubkey(), Hash.from_string(BH)))
    tx_b64 = base64.b64encode(bytes(tx)).decode()
    wire = await _co_sign(tx_b64, MemorySigner(op_kp))
    signed = Transaction.from_bytes(wire)
    assert signed.message == tx.message
    signed.verify()
    assert _transaction_signature(wire) == str(signed.signatures[0])


@pytest.mark.parametrize("scheme", ["exact", "upto"])
@pytest.mark.parametrize("legacy", [False, True])
async def test_cosign_preserves_client_signature_and_uses_returned_transaction(scheme, legacy):
    """A backend may return a signed copy rather than mutate the input."""
    from solders.message import Message
    from solders.signature import Signature
    from solders.system_program import TransferParams, transfer

    from solana_pay_kit.protocols.x402.upto import _cosign_fee_payer

    class CopyingSigner(MemorySigner):
        async def sign_transaction(self, transaction: VersionedTransaction) -> SignedTransaction:
            copy = VersionedTransaction.from_bytes(bytes(transaction))
            result = await super().sign_transaction(copy)
            assert transaction.signatures[0] == Signature.default()
            return result

    operator = CopyingSigner(Keypair())
    client = MemorySigner(Keypair())
    instruction = transfer(TransferParams(from_pubkey=client.pubkey, to_pubkey=Keypair().pubkey(), lamports=1))
    blockhash = Hash.from_string(BH)
    message = (
        Message.new_with_blockhash([instruction], operator.pubkey, blockhash)
        if legacy
        else MessageV0.try_compile(operator.pubkey, [instruction], [], blockhash)
    )
    unsigned = VersionedTransaction.populate(message, [Signature.default(), Signature.default()])
    partial = (await client.sign_transaction(unsigned)).transaction
    assert partial.signatures[0] == Signature.default()
    client_signature = partial.signatures[1]
    cosign = _co_sign if scheme == "exact" else _cosign_fee_payer
    wire = await cosign(base64.b64encode(bytes(partial)).decode(), operator)
    signed = VersionedTransaction.from_bytes(wire)
    assert signed.message == partial.message
    assert signed.signatures[1] == client_signature
    assert signed.verify_with_results() == [True, True]


@pytest.mark.parametrize("legacy_prefix", ["solana-charge:consumed:", "x402-svm-exact:consumed:"])
@pytest.mark.asyncio
async def test_settled_payment_is_visible_to_replicas_on_the_previous_release(monkeypatch, legacy_prefix):
    """Rolling upgrade: a replica on the previous release claims and checks only
    its own legacy key. Every claim takes those keys too, so such a replica
    refuses a payment this release accepted; a release gives them back."""
    store = MemoryStore()
    adapter, gate, op_kp = _adapter(store=store, monkeypatch=monkeypatch)
    header = _build_envelope(adapter, gate, op_kp)
    payment = await adapter.verify_and_settle(gate, _Req(header))
    assert await store.put_if_absent(legacy_prefix + payment.transaction, True) is False

    ledger = ConsumedSignatures(store)
    assert await ledger.claim("sig-released") is True
    await ledger.release("sig-released")
    assert await store.get(legacy_prefix + "sig-released") is None
    assert await ledger.claim("sig-released") is True


@pytest.mark.asyncio
async def test_refused_claim_gives_back_the_legacy_keys_it_took():
    store = MemoryStore()
    await store.put("x402-svm-exact:consumed:sig-held", True)
    assert await ConsumedSignatures(store).claim("sig-held") is False
    assert await store.get("solana-charge:consumed:sig-held") is None
    assert await store.get(consumed_signature_key("sig-held")) is None


@pytest.mark.asyncio
async def test_already_processed_with_no_record_here_is_a_replay(monkeypatch):
    """A payment settled by another instance (its own store) lands first; the
    node then refuses this broadcast as already processed. That is a replay,
    never a pending settlement, and it stays consumed here."""
    from solana_pay_kit._paycore.rpc import _RpcError

    store = MemoryStore()
    adapter, gate, op_kp = _adapter(
        store=store,
        fail=_RpcError("Transaction error: This transaction has already been processed", code="signature_consumed"),
        monkeypatch=monkeypatch,
    )
    header = _build_envelope(adapter, gate, op_kp)
    signature = await _settlement_signature(header, op_kp)
    for _ in range(2):
        with pytest.raises(InvalidProofError) as exc:
            await adapter.verify_and_settle(gate, _Req(header))
        assert not isinstance(exc.value, SettlementInProgressError)
        assert exc.value.code == "signature_consumed"
    assert await store.get(consumed_signature_key(signature)) is True


@pytest.mark.asyncio
async def test_pending_record_is_claimed_before_sending(monkeypatch):
    """Recorded only after the send, a store failure would leave a payment
    that may have landed with nothing to reconcile; the retry would then find
    it already processed and refuse it. A failed claim sends nothing."""

    class _FailingStore(MemoryStore):
        fail = True

        async def put_if_absent(self, key, value):
            if self.fail and key.startswith("solana:consumed-signature:"):
                raise RuntimeError("injected store outage")
            return await super().put_if_absent(key, value)

    store = _FailingStore()
    rpcs: list = []
    adapter, gate, op_kp = _adapter(store=store, monkeypatch=monkeypatch, rpcs=rpcs)
    header = _build_envelope(adapter, gate, op_kp)
    with pytest.raises(RuntimeError, match="injected store outage"):
        await adapter.verify_and_settle(gate, _Req(header))
    assert all(rpc.send_calls == 0 for rpc in rpcs)
    store.fail = False
    payment = await adapter.verify_and_settle(gate, _Req(header))
    assert payment.transaction == await _settlement_signature(header, op_kp)


# -- every required signer must have signed ------------------------------------


def _with_client_signatures(header: str, op_kp: Keypair, build) -> tuple[str, VersionedTransaction]:
    """Re-sign the envelope's transaction as a landed payment would carry it
    (fee payer and transfer authority both signed), then hand ``build`` that
    landed transaction to derive the wire the client actually submits."""
    envelope = json.loads(base64.b64decode(header))
    vtx = VersionedTransaction.from_bytes(base64.b64decode(envelope["payload"]["transaction"]))
    signed_bytes = bytes(to_bytes_versioned(vtx.message))
    landed = VersionedTransaction.populate(vtx.message, [op_kp.sign_message(signed_bytes), *list(vtx.signatures)[1:]])
    assert all(landed.verify_with_results())
    submitted = build(landed)
    envelope["payload"]["transaction"] = base64.b64encode(bytes(submitted)).decode()
    return base64.b64encode(json.dumps(envelope).encode()).decode(), landed


@pytest.mark.asyncio
async def test_landed_two_signer_payment_truncated_to_its_first_signature_is_refused_before_it_is_claimed(
    monkeypatch,
):
    """Every present signature verifies, but the message requires two: the
    truncated wire names the landed transaction without the payer's
    authorization. It is refused before any claim or send."""
    store = MemoryStore()
    rpcs: list = []
    adapter, gate, op_kp = _adapter(store=store, monkeypatch=monkeypatch, rpcs=rpcs)
    header, landed = _with_client_signatures(
        _build_envelope(adapter, gate, op_kp),
        op_kp,
        lambda tx: VersionedTransaction.populate(tx.message, [tx.signatures[0]]),
    )
    for _ in range(2):
        with pytest.raises(InvalidProofError) as exc:
            await adapter.verify_and_settle(gate, _Req(header))
        assert exc.value.code == "payment_invalid"
    assert all(rpc.send_calls == 0 for rpc in rpcs)
    assert await store.get(consumed_signature_key(str(landed.signatures[0]))) is None


@pytest.mark.asyncio
async def test_unsigned_transfer_authority_is_refused_before_it_is_claimed(monkeypatch):
    """The server co-signs only the fee payer: a transfer authority slot left
    empty authorizes nothing and is refused before any claim or send."""
    store = MemoryStore()
    rpcs: list = []
    adapter, gate, op_kp = _adapter(store=store, monkeypatch=monkeypatch, rpcs=rpcs)
    header, landed = _with_client_signatures(
        _build_envelope(adapter, gate, op_kp),
        op_kp,
        lambda tx: VersionedTransaction.populate(tx.message, [Signature.default()] * len(tx.signatures)),
    )
    with pytest.raises(InvalidProofError) as exc:
        await adapter.verify_and_settle(gate, _Req(header))
    assert exc.value.code == "payment_invalid"
    assert all(rpc.send_calls == 0 for rpc in rpcs)
    assert await store.get(consumed_signature_key(str(landed.signatures[0]))) is None


@pytest.mark.asyncio
async def test_fully_signed_two_signer_payment_settles(monkeypatch):
    """Positive control: the landed shape, both slots signed, settles once."""
    adapter, gate, op_kp = _adapter(monkeypatch=monkeypatch)
    header, landed = _with_client_signatures(_build_envelope(adapter, gate, op_kp), op_kp, lambda tx: tx)
    payment = await adapter.verify_and_settle(gate, _Req(header))
    assert payment.transaction == str(landed.signatures[0])
