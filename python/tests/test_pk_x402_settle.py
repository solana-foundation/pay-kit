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

import pytest
from solders.hash import Hash
from solders.instruction import AccountMeta, Instruction
from solders.keypair import Keypair
from solders.message import MessageV0
from solders.pubkey import Pubkey
from solders.transaction import VersionedTransaction

import solana_pay_kit.protocols.x402 as xmod
from solana_pay_kit import Gate as GateCls
from solana_pay_kit import (
    LocalSigner,
    MemoryStore,
    Operator,
    Price,
    Protocol,
    Stablecoin,
    configure,
)
from solana_pay_kit._paycore.mints import derive_ata, resolve, token_program_for
from solana_pay_kit.config import reset
from solana_pay_kit.errors import InvalidProofError
from solana_pay_kit.protocols.x402 import (
    X402_VERSION,
    X402Adapter,
    _co_sign,
    _is_loopback_rpc,
    _request_path,
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
        signature: str = "SIG-broadcast",
        fail: bool = False,
        confirm_error: Exception | None = None,
        **_k,
    ):
        self._signature = signature
        self._fail = fail
        self._confirm_error = confirm_error
        self.confirm_calls = 0
        self.aclose_calls = 0

    async def send_raw_transaction(self, _raw):
        if self._fail:
            raise RuntimeError("broadcast boom")

        class _Resp:
            value = self._signature  # type: ignore[assignment]

        _Resp.value = self._signature
        return _Resp()

    async def await_confirmation(self, _signature, *_a, **_k):
        self.confirm_calls += 1
        if self._confirm_error is not None:
            raise self._confirm_error
        return None

    async def aclose(self):
        self.aclose_calls += 1
        return None


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    reset()
    monkeypatch.setenv("PAY_KIT_DISABLE_PREFLIGHT", "1")
    yield
    reset()


def _adapter(store=None, signature="SIG-broadcast", fail=False, confirm_error=None, monkeypatch=None, rpcs=None):
    op_kp = Keypair()
    op = Operator(signer=LocalSigner.from_keypair(op_kp), recipient=str(Keypair().pubkey()))
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
        rpc = _FakeRpc(signature=signature, fail=fail, confirm_error=confirm_error)
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
    # Unsigned v0 wire form (zeroed sig slots) so cosign takes its v0 branch.
    num = int(msg.header.num_required_signatures)
    wire = bytearray()
    wire.append(num)
    wire.extend(bytes(64) * num)
    wire.extend(bytes(msg))
    tx_b64 = base64.b64encode(bytes(wire)).decode()
    envelope = {
        "x402Version": X402_VERSION,
        "accepted": offer,
        "payload": {"transaction": tx_b64, "transactionHash": "h"},
    }
    return base64.b64encode(json.dumps(envelope).encode()).decode()


class _Req:
    def __init__(self, header, path="/report"):
        self.headers = {"payment-signature": header}
        self.path = path


# -- happy path + replay -----------------------------------------------------


@pytest.mark.asyncio
async def test_verify_and_settle_happy_path(monkeypatch):
    adapter, gate, op_kp = _adapter(signature="SIG-1", monkeypatch=monkeypatch)
    header = _build_envelope(adapter, gate, op_kp)
    payment = await adapter.verify_and_settle(gate, _Req(header))
    assert payment.protocol is Protocol.X402
    assert payment.transaction == "SIG-1"
    assert payment.settlement_headers["x-payment-settlement-signature"] == "SIG-1"
    assert "payment-response" in payment.settlement_headers


@pytest.mark.asyncio
async def test_replay_same_signature_rejected(monkeypatch):
    store = MemoryStore()
    adapter, gate, op_kp = _adapter(store=store, signature="SIG-dupe", monkeypatch=monkeypatch)
    header = _build_envelope(adapter, gate, op_kp)
    await adapter.verify_and_settle(gate, _Req(header))
    # Second submit of a credential that broadcasts the same signature: consumed.
    header2 = _build_envelope(adapter, gate, op_kp)
    with pytest.raises(InvalidProofError) as exc:
        await adapter.verify_and_settle(gate, _Req(header2))
    assert exc.value.code == "signature_consumed"


@pytest.mark.asyncio
async def test_broadcast_failure_is_invalid_proof(monkeypatch):
    adapter, gate, op_kp = _adapter(fail=True, monkeypatch=monkeypatch)
    header = _build_envelope(adapter, gate, op_kp)
    with pytest.raises(InvalidProofError, match="broadcast failed"):
        await adapter.verify_and_settle(gate, _Req(header))


# -- confirmation gate (149-2 BLOCKER) ---------------------------------------


@pytest.mark.asyncio
async def test_success_path_awaits_confirmation_before_returning(monkeypatch):
    rpcs: list = []
    adapter, gate, op_kp = _adapter(signature="SIG-ok", monkeypatch=monkeypatch, rpcs=rpcs)
    header = _build_envelope(adapter, gate, op_kp)
    payment = await adapter.verify_and_settle(gate, _Req(header))
    assert payment.transaction == "SIG-ok"
    # The adapter must poll confirmation, then close the RPC after the poll.
    assert rpcs[0].confirm_calls == 1
    assert rpcs[0].aclose_calls == 1


@pytest.mark.asyncio
async def test_confirmation_timeout_raises_and_does_not_return_success(monkeypatch):
    from solana_pay_kit._paycore.errors import PaymentError

    store = MemoryStore()
    adapter, gate, op_kp = _adapter(
        store=store,
        signature="SIG-timeout",
        confirm_error=PaymentError("timed out", code="transaction-not-found"),
        monkeypatch=monkeypatch,
    )
    header = _build_envelope(adapter, gate, op_kp)
    with pytest.raises(InvalidProofError) as exc:
        await adapter.verify_and_settle(gate, _Req(header))
    assert exc.value.code == "payment_invalid"
    assert "confirmation failed" in str(exc.value)
    # Reservation must be rolled back so an honest retry can replay.
    assert await store.get("x402-svm-exact:consumed:SIG-timeout") is None


@pytest.mark.asyncio
async def test_confirmation_onchain_failure_rolls_back_reservation(monkeypatch):
    from solana_pay_kit._paycore.errors import PaymentError

    store = MemoryStore()
    adapter, gate, op_kp = _adapter(
        store=store,
        signature="SIG-revert",
        confirm_error=PaymentError("reverted", code="transaction-failed"),
        monkeypatch=monkeypatch,
    )
    header = _build_envelope(adapter, gate, op_kp)
    with pytest.raises(InvalidProofError):
        await adapter.verify_and_settle(gate, _Req(header))
    assert await store.get("x402-svm-exact:consumed:SIG-revert") is None


# -- sub-microunit price truncation (149-2) ----------------------------------


def _x402_adapter_for_price(price):
    op = Operator(signer=LocalSigner.from_keypair(Keypair()), recipient=str(Keypair().pubkey()))
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


def test_co_sign_fee_payer_not_present_rejected():
    payer = Keypair()
    outsider = LocalSigner.from_keypair(Keypair())
    from solders.system_program import TransferParams, transfer

    ix = transfer(TransferParams(from_pubkey=payer.pubkey(), to_pubkey=Keypair().pubkey(), lamports=1))
    msg = MessageV0.try_compile(payer.pubkey(), [ix], [], Hash.from_string(BH))
    vtx = VersionedTransaction(msg, [payer])
    tx_b64 = base64.b64encode(bytes(vtx)).decode()
    with pytest.raises(InvalidProofError):
        _co_sign(tx_b64, outsider)


def test_co_sign_unparseable_bytes_rejected():
    bogus = base64.b64encode(b"\x00\x01\x02").decode()
    with pytest.raises(InvalidProofError) as exc:
        _co_sign(bogus, LocalSigner.from_keypair(Keypair()))
    assert exc.value.code == "invalid_exact_svm_payload_transaction_parse"
