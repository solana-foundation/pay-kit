"""PayCore middleware, Pricing registry, the request-scoped trio, kms, errors.

Covers gate-reference coercion (inline Gate, name via Pricing, bare Price,
plain callable, DynamicGate), adapter detection in accept order (x402 wins,
fees disable x402, MPP scheme matching), the 402 build path, and the
``require_payment`` / ``is_paid`` / ``is_paid_for`` / ``payment`` trio over
attribute / mapping / ``.state`` request shapes.
"""

from __future__ import annotations

import pytest

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


def _cfg(accept=(Protocol.X402, Protocol.MPP)):
    return configure(
        network="solana_localnet",
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


@pytest.mark.asyncio
async def test_settled_signature_not_replayable_across_requests(monkeypatch):
    """End-to-end of the cache: a signature consumed on the shared replay store
    by one request's core stays consumed for the next request's core."""
    cfg = _cfg(accept=(Protocol.MPP,))
    store = PayCore.for_config(cfg)._mpp._replay_store
    key = "solana-charge:consumed:sig-xyz"
    # First request settles the signature (marks it consumed).
    assert await store.put_if_absent(key, True) is True
    # A later request resolves the SAME core/store, so the marker persists and
    # a replay of the same signature is rejected (put_if_absent returns False).
    store_again = PayCore.for_config(cfg)._mpp._replay_store
    assert store_again is store
    assert await store_again.put_if_absent(key, True) is False


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
