"""PayCore middleware, Pricing registry, the request-scoped trio, kms, errors.

Covers gate-reference coercion (inline Gate, name via Pricing, bare Price,
plain callable, DynamicGate), adapter detection in accept order (x402 wins,
fees disable x402, MPP scheme matching), the 402 build path, and the
``require_payment`` / ``is_paid`` / ``is_paid_for`` / ``payment`` trio over
attribute / mapping / ``.state`` request shapes.
"""

from __future__ import annotations

import gc
import threading
import weakref
from typing import Any

import pytest

import solana_pay_kit._middleware as mw
from solana_pay_kit import (
    Gate,
    MppConfig,
    Payment,
    Price,
    Pricing,
    Protocol,
    Stablecoin,
    configure,
    is_paid,
    is_paid_for,
    kms,
    payment,
    require_payment,
)
from solana_pay_kit._middleware import PAYMENT_ATTR, PayCore
from solana_pay_kit._paycore.errors import PaymentError
from solana_pay_kit._paycore.store import MemoryStore, ProductionReplayStore
from solana_pay_kit.config import reset
from solana_pay_kit.errors import (
    ChallengeExpiredError,
    ConfigurationError,
    InvalidProofError,
    PaymentRequiredError,
    ProtocolNotSupportedError,
)
from solana_pay_kit.pricing import coerce

SECRET = "challenge-binding-secret-long-enough-for-hmac"
FEE_A = "9xAXssX9j7vuK99c7cFwqbixzL3bFrzPy9PUhCtDPAYJ"


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    reset()
    monkeypatch.setenv("PAY_KIT_DISABLE_PREFLIGHT", "1")
    yield
    reset()


def _cfg(accept=(Protocol.X402, Protocol.MPP), *, network="solana_localnet"):
    return configure(
        network=network,
        preflight=False,
        accept=accept,
        mpp=MppConfig(challenge_binding_secret=SECRET),
    )


def _gate(cfg, **kw):
    kw.setdefault("name", "report")
    kw.setdefault("amount", Price.usd("0.10", Stablecoin.USDC))
    kw.setdefault("default_pay_to", cfg.effective_recipient())
    return Gate.build(**kw)


class _Req:
    """Minimal request bag: attribute headers + path."""

    def __init__(self, headers=None, path="/report"):
        self.headers = headers or {}
        self.path = path


class _ProductionStore(ProductionReplayStore):
    """In-memory test double for an externally verified production backend.

    The nominal base class is the SDK's explicit trust boundary. This class is
    deliberately test-only; production users must provide a backend that
    really coordinates atomic writes across workers and survives restarts.
    """

    def __init__(self) -> None:
        self._delegate = MemoryStore()

    async def get(self, key: str) -> Any | None:
        return await self._delegate.get(key)

    async def put(self, key: str, value: Any) -> None:
        await self._delegate.put(key, value)

    async def delete(self, key: str) -> None:
        await self._delegate.delete(key)

    async def put_if_absent(self, key: str, value: Any) -> bool:
        return await self._delegate.put_if_absent(key, value)


# -- per-config core cache (replay-store persistence) ------------------------


def test_for_config_returns_same_core_per_config():
    """Regression: shims built a fresh PayCore per request, so each request got
    a fresh in-memory replay store and a settled MPP signature could be
    replayed. for_config() must hand back the same core (and thus the same
    replay store) for a given Config."""
    cfg = _cfg()
    first = PayCore.for_config(cfg)
    second = PayCore.for_config(cfg)
    assert first is second
    # The MPP adapter (and its replay store) is shared, not rebuilt per call.
    assert first._mpp is not None
    assert second._mpp is not None
    assert first._mpp is second._mpp
    assert first._mpp._replay_store is second._mpp._replay_store


def test_for_config_distinct_cores_for_distinct_configs():
    """Configs that differ get distinct cores (and thus distinct replay stores)."""
    cfg_a = _cfg(accept=(Protocol.MPP,))
    reset()
    import os

    os.environ["PAY_KIT_DISABLE_PREFLIGHT"] = "1"
    cfg_b = _cfg(accept=(Protocol.X402, Protocol.MPP))
    assert cfg_a != cfg_b
    assert PayCore.for_config(cfg_a) is not PayCore.for_config(cfg_b)


def test_for_config_does_not_merge_equal_distinct_configs():
    """Equal frozen Config values still own separate replay stores by identity."""
    cfg_a = _cfg(accept=(Protocol.MPP,))
    cfg_b = _cfg(accept=(Protocol.MPP,))

    assert cfg_a is not cfg_b
    assert cfg_a == cfg_b

    core_a = PayCore.for_config(cfg_a)
    core_b = PayCore.for_config(cfg_b)

    assert core_a is not core_b
    assert core_a.config is cfg_a
    assert core_b.config is cfg_b
    assert core_a._mpp is not None
    assert core_b._mpp is not None
    assert core_a._mpp._replay_store is not core_b._mpp._replay_store


def test_for_config_constructs_once_across_threads(monkeypatch):
    """First concurrent requests share one atomically bound core and store."""
    cfg = _cfg(accept=(Protocol.MPP,))
    original_init = PayCore.__init__
    first_init_started = threading.Event()
    second_lock_attempted = threading.Event()
    release_first_init = threading.Event()
    init_count = 0
    init_count_lock = threading.Lock()

    class _SignallingLock:
        def __init__(self) -> None:
            self._lock = threading.RLock()
            self._attempts = 0
            self._attempts_lock = threading.Lock()

        def __enter__(self):
            with self._attempts_lock:
                self._attempts += 1
                if self._attempts == 2:
                    second_lock_attempted.set()
            self._lock.acquire()
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            self._lock.release()

    def delayed_init(self, config, *, mpp=None, x402=None, replay_store=None, _source_config_ref=None):  # noqa: ANN001
        nonlocal init_count
        with init_count_lock:
            init_count += 1
            is_first = init_count == 1
        if is_first:
            first_init_started.set()
            assert release_first_init.wait(timeout=5)
        original_init(
            self,
            config,
            mpp=mpp,
            x402=x402,
            replay_store=replay_store,
            _source_config_ref=_source_config_ref,
        )

    monkeypatch.setattr(mw._CORE_CACHE, "_lock", _SignallingLock())
    monkeypatch.setattr(PayCore, "__init__", delayed_init)
    cores: list[PayCore] = []
    failures: list[BaseException] = []

    def lookup() -> None:
        try:
            cores.append(PayCore.for_config(cfg))
        except BaseException as exc:  # pragma: no cover - assertion below reports it.
            failures.append(exc)

    first = threading.Thread(target=lookup)
    second = threading.Thread(target=lookup)
    second_started = False
    first.start()
    try:
        assert first_init_started.wait(timeout=5)
        second.start()
        second_started = True
        assert second_lock_attempted.wait(timeout=5)
    finally:
        release_first_init.set()
        first.join(timeout=5)
        if second_started:
            second.join(timeout=5)

    assert not first.is_alive()
    assert not second.is_alive()
    assert not failures
    assert init_count == 1
    assert len(cores) == 2
    assert cores[0] is cores[1]
    assert cores[0]._mpp is not None
    assert cores[1]._mpp is not None
    assert cores[0]._mpp._replay_store is cores[1]._mpp._replay_store


def test_for_config_rejects_rebinding_a_config_to_a_different_store():
    """A Config may reuse its bound durable store but cannot be rebound."""
    cfg = _cfg(accept=(Protocol.MPP,), network="solana_devnet")
    first_store = _ProductionStore()
    second_store = _ProductionStore()

    core = PayCore.for_config(cfg, replay_store=first_store)

    assert PayCore.for_config(cfg, replay_store=first_store) is core
    with pytest.raises(ConfigurationError, match="different replay_store is already bound"):
        PayCore.for_config(cfg, replay_store=second_store)


def test_equal_nonlocal_configs_bind_independent_durable_stores():
    """One nonlocal Config cannot borrow another equal Config's durable store."""
    cfg_a = _cfg(accept=(Protocol.MPP,), network="solana_devnet")
    cfg_b = _cfg(accept=(Protocol.MPP,), network="solana_devnet")
    store_a = _ProductionStore()
    store_b = _ProductionStore()

    assert cfg_a is not cfg_b
    assert cfg_a == cfg_b

    core_a = PayCore.for_config(cfg_a, replay_store=store_a)
    core_b = PayCore.for_config(cfg_b, replay_store=store_b)

    assert core_a is not core_b
    assert core_a._mpp is not None
    assert core_b._mpp is not None
    assert core_a._mpp._replay_store is store_a
    assert core_b._mpp._replay_store is store_b


def test_for_config_cache_releases_dropped_config_and_core():
    """The identity cache must not retain a Config after reset drops it."""
    cfg = _cfg(accept=(Protocol.MPP,))
    core = PayCore.for_config(cfg)
    config_ref = weakref.ref(cfg)
    core_ref = weakref.ref(core)

    reset()
    del cfg
    del core
    gc.collect()

    assert config_ref() is None
    assert core_ref() is None


@pytest.mark.asyncio
async def test_settled_signature_not_replayable_across_requests(monkeypatch):
    """End-to-end of the cache: a signature consumed on the shared replay store
    by one request's core stays consumed for the next request's core."""
    cfg = _cfg(accept=(Protocol.MPP,))
    core = PayCore.for_config(cfg)
    assert core._mpp is not None
    store = core._mpp._replay_store
    key = "solana-charge:consumed:sig-xyz"
    # First request settles the signature (marks it consumed).
    assert await store.put_if_absent(key, True) is True
    # A later request resolves the SAME core/store, so the marker persists and
    # a replay of the same signature is rejected (put_if_absent returns False).
    next_core = PayCore.for_config(cfg)
    assert next_core._mpp is not None
    store_again = next_core._mpp._replay_store
    assert store_again is store
    assert await store_again.put_if_absent(key, True) is False


def test_for_config_injects_durable_replay_store_outside_localnet():
    """Framework callers can supply one durable MPP replay store at startup."""
    cfg = _cfg(accept=(Protocol.MPP,), network="solana_devnet")
    store = _ProductionStore()

    core = PayCore.for_config(cfg, replay_store=store)

    assert core._mpp is not None
    assert core._mpp._replay_store is store
    assert PayCore.for_config(cfg) is core


def test_nonlocal_mpp_without_replay_store_fails_closed():
    """MPP does not fall back to process-local replay state in production."""
    cfg = _cfg(accept=(Protocol.MPP,), network="solana_devnet")

    with pytest.raises(PaymentError, match="ProductionReplayStore"):
        PayCore(cfg)


def test_x402_only_nonlocal_config_does_not_construct_mpp_adapter():
    """An x402-only deployment does not need an unused MPP replay store."""
    cfg = _cfg(accept=(Protocol.X402,), network="solana_devnet")
    store = _ProductionStore()

    core = PayCore.for_config(cfg, replay_store=store)

    assert core._mpp is None
    assert core._x402 is not None


# -- gate resolution ---------------------------------------------------------


def test_resolve_inline_gate_passthrough():
    cfg = _cfg()
    core = PayCore(cfg)
    g = _gate(cfg, accept=(Protocol.MPP,))
    assert core.resolve_gate(g, None, _Req()) is g


def test_resolve_bare_price_wraps_with_defaults():
    cfg = _cfg()
    core = PayCore(cfg)
    g = core.resolve_gate(Price.usd("0.10", Stablecoin.USDC), None, _Req())
    assert isinstance(g, Gate)
    assert g.pay_to == cfg.effective_recipient()


def test_resolve_name_via_pricing_registry():
    cfg = _cfg()
    core = PayCore(cfg)

    class Catalog(Pricing):
        def __init__(self):
            self.report = _gate(cfg, accept=(Protocol.MPP,))

    g = core.resolve_gate("report", Catalog(), _Req())
    assert g.name == "report"


def test_resolve_plain_callable_returning_price():
    cfg = _cfg()
    core = PayCore(cfg)

    def builder(request):
        return Price.usd("0.20", Stablecoin.USDC)

    g = core.resolve_gate(builder, None, _Req())  # type: ignore[arg-type]
    assert g.amount.amount_string() == "0.20"


def test_resolve_plain_callable_returning_gate():
    cfg = _cfg()
    core = PayCore(cfg)
    concrete = _gate(cfg, accept=(Protocol.MPP,))
    g = core.resolve_gate(lambda r: concrete, None, _Req())
    assert g is concrete


def test_resolve_callable_bad_return_raises():
    cfg = _cfg()
    core = PayCore(cfg)
    with pytest.raises(ProtocolNotSupportedError, match="expected Gate or Price"):
        core.resolve_gate(lambda r: 5, None, _Req())  # type: ignore[arg-type]


def test_resolve_dynamic_gate_injects_defaults():
    from solana_pay_kit import gate as dynamic

    cfg = _cfg()
    core = PayCore(cfg)

    @dynamic("by_units", accept=(Protocol.MPP,))  # type: ignore[arg-type]
    def builder(request):
        return Price.usd("0.10", Stablecoin.USDC)

    g = core.resolve_gate(builder, None, _Req())
    assert g.pay_to == cfg.effective_recipient()


def test_coerce_unknown_name_without_registry_raises():
    cfg = _cfg()
    with pytest.raises(ConfigurationError, match="no Pricing registry"):
        coerce("report", registry=None, config=cfg)


def test_coerce_bad_type_raises():
    cfg = _cfg()
    with pytest.raises(ConfigurationError, match="cannot coerce"):
        coerce(42, config=cfg)  # type: ignore[arg-type]


# -- adapter detection -------------------------------------------------------


def test_detect_mpp_when_payment_authorization_present():
    cfg = _cfg(accept=(Protocol.MPP,))
    core = PayCore(cfg)
    g = _gate(cfg, accept=(Protocol.MPP,))
    adapter = core.detect_adapter(g, {"authorization": "Payment abc"})
    assert core._mpp is not None
    assert adapter is core._mpp


def test_detect_x402_wins_when_both_proofs_present():
    cfg = _cfg()
    core = PayCore(cfg)
    g = _gate(cfg, accept=(Protocol.X402, Protocol.MPP))
    headers = {"authorization": "Payment abc", "payment-signature": "deadbeef"}
    assert core.detect_adapter(g, headers) is core._x402


def test_detect_none_when_no_proof():
    cfg = _cfg()
    core = PayCore(cfg)
    g = _gate(cfg, accept=(Protocol.X402, Protocol.MPP))
    assert core.detect_adapter(g, {}) is None


def test_detect_x402_disabled_on_fee_gate():
    cfg = _cfg()
    core = PayCore(cfg)
    g = _gate(cfg, fee_on_top={FEE_A: Price.usd("0.02", Stablecoin.USDC)})
    # x402 signature present but fees disable x402; no MPP auth -> None.
    assert core.detect_adapter(g, {"payment-signature": "deadbeef"}) is None
    # MPP still works on the fee gate.
    assert core._mpp is not None
    assert core.detect_adapter(g, {"authorization": "Payment x"}) is core._mpp


def test_x402_adapter_absent_when_not_accepted():
    cfg = _cfg(accept=(Protocol.MPP,))
    core = PayCore(cfg)
    assert core._x402 is None


# -- 402 assembly ------------------------------------------------------------


def test_build_402_offers_both_protocols():
    cfg = _cfg()
    core = PayCore(cfg)
    g = _gate(cfg, accept=(Protocol.X402, Protocol.MPP))
    headers, body = core.build_402(g, _Req())
    protocols = {a["protocol"] for a in body["accepts"]}
    assert protocols == {"x402", "mpp"}
    assert "payment-required" in headers
    assert "www-authenticate" in headers
    assert body["error"] == "payment_required"


def test_build_402_fee_gate_omits_x402():
    cfg = _cfg()
    core = PayCore(cfg)
    g = _gate(cfg, fee_on_top={FEE_A: Price.usd("0.02", Stablecoin.USDC)})
    _headers, body = core.build_402(g, _Req())
    protocols = {a["protocol"] for a in body["accepts"]}
    assert protocols == {"mpp"}


# -- process -----------------------------------------------------------------


@pytest.mark.asyncio
async def test_process_no_proof_raises_payment_required_with_challenge():
    cfg = _cfg()
    core = PayCore(cfg)
    g = _gate(cfg, accept=(Protocol.X402, Protocol.MPP))
    with pytest.raises(PaymentRequiredError) as exc:
        await core.process(g, None, _Req())
    assert hasattr(exc.value, "challenge_headers")
    assert hasattr(exc.value, "body")


@pytest.mark.asyncio
async def test_process_dispatches_to_adapter(monkeypatch):
    cfg = _cfg(accept=(Protocol.MPP,))
    core = PayCore(cfg)
    g = _gate(cfg, accept=(Protocol.MPP,))

    sentinel = Payment(protocol=Protocol.MPP, transaction="sig123", gate_name="report")

    async def fake_verify(gate, request):
        return sentinel

    assert core._mpp is not None
    monkeypatch.setattr(core._mpp, "verify_and_settle", fake_verify)
    out = await core.process(g, None, _Req(headers={"authorization": "Payment abc"}))
    assert out is sentinel


def test_resolve_registry_dynamic_gate_uses_request():
    """A registry-returned DynamicGate resolves against the request.

    Regression: a prior round raised ProtocolNotSupportedError here, so a
    registered name pointing at a @dynamic gate was unusable. resolve_gate()
    has the request, so it must inject the Config defaults and resolve the
    dynamic gate instead of rejecting it.
    """
    from solana_pay_kit import gate as dynamic

    cfg = _cfg(accept=(Protocol.MPP,))
    core = PayCore(cfg)

    @dynamic("by_units", accept=(Protocol.MPP,))  # type: ignore[arg-type]
    def builder(request):
        return Price.usd("0.10", Stablecoin.USDC)

    class Catalog(Pricing):
        def __init__(self):
            self.by_units = builder

    g = core.resolve_gate("by_units", Catalog(), _Req())
    assert isinstance(g, Gate)
    assert g.name == "by_units"
    assert g.amount.amount_string() == "0.10"
    assert g.pay_to == cfg.effective_recipient()


# -- request-scoped trio -----------------------------------------------------


def _paid_request(gate_name="report"):
    req = _Req()
    setattr(req, PAYMENT_ATTR, Payment(protocol=Protocol.MPP, transaction="sig", gate_name=gate_name))
    return req


def test_payment_reads_attribute():
    req = _paid_request()
    settled = payment(req)
    assert settled is not None and settled.transaction == "sig"


def test_payment_none_when_absent():
    assert payment(_Req()) is None


def test_payment_from_mapping():
    settled = Payment(protocol=Protocol.MPP, transaction="sig")
    assert payment({PAYMENT_ATTR: settled}) is settled


def test_payment_from_state_namespace():
    class State:
        pass

    class StateReq:
        def __init__(self):
            self.state = State()

    req = StateReq()
    settled = Payment(protocol=Protocol.MPP, transaction="sig")
    setattr(req.state, PAYMENT_ATTR, settled)
    assert payment(req) is settled


def test_is_paid_true_false():
    assert is_paid(_paid_request()) is True
    assert is_paid(_Req()) is False


def test_is_paid_for_gate_instance_trusts_middleware():
    cfg = _cfg()
    g = _gate(cfg, accept=(Protocol.MPP,))
    assert is_paid_for(_paid_request(), g) is True


def test_is_paid_for_string_matches_gate_name():
    assert is_paid_for(_paid_request("report"), "report") is True
    assert is_paid_for(_paid_request("report"), "other") is False


def test_is_paid_for_unpaid_is_false():
    assert is_paid_for(_Req(), "report") is False


def test_require_payment_returns_payment():
    assert require_payment(_paid_request()).transaction == "sig"


def test_require_payment_raises_when_unpaid():
    with pytest.raises(PaymentRequiredError):
        require_payment(_Req())


# -- kms reserved namespace --------------------------------------------------


def test_kms_gcp_not_implemented():
    with pytest.raises(NotImplementedError, match="follow-up"):
        kms.gcp(key_name="k", pubkey="p")


def test_kms_aws_not_implemented():
    with pytest.raises(NotImplementedError, match="follow-up"):
        kms.aws(key_id="k", region="us", pubkey="p")


def test_kms_vault_not_implemented():
    with pytest.raises(NotImplementedError, match="follow-up"):
        kms.vault(addr="a", path="p", pubkey="k")


# -- errors ------------------------------------------------------------------


def test_invalid_proof_error_http_status_and_code():
    err = InvalidProofError("bad", code="signature_consumed")
    assert err.http_status == 402
    assert err.code == "signature_consumed"


def test_challenge_expired_defaults():
    err = ChallengeExpiredError()
    assert err.code == "challenge_expired"
    assert err.http_status == 402


def test_protocol_not_supported_http_status():
    assert ProtocolNotSupportedError("x").http_status == 406


def test_payment_required_http_status():
    assert PaymentRequiredError("x").http_status == 402


# -- top-level shorthands ----------------------------------------------------


def test_usd_and_eur_shorthands():
    import solana_pay_kit

    assert solana_pay_kit.usd("1.00", Stablecoin.USDC).currency.value == "USD"
    assert solana_pay_kit.eur("2.00").currency.value == "EUR"
