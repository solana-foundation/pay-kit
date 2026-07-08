"""Pricing registry, header/attr helpers, mint reverse-lookup, flask is_paid.

Fills the remaining branch gaps the larger suites do not reach: Pricing's
attribute introspection (gate/contains/iter and the error paths), the
middleware header proxy + path/attr readers over odd request shapes, the mints
``symbol_for`` reverse lookup, and the flask ``is_paid`` gate-object branch.
"""

from __future__ import annotations

import pytest

from solana_pay_kit import Gate, MppConfig, Price, Pricing, Protocol, Stablecoin, configure
from solana_pay_kit._middleware import _HeaderProxy, _read_attr, _read_header, _request_headers, _request_path
from solana_pay_kit._paycore import mints
from solana_pay_kit.config import reset
from solana_pay_kit.errors import ConfigurationError

SECRET = "challenge-binding-secret-long-enough-for-hmac"


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    reset()
    monkeypatch.setenv("PAY_KIT_DISABLE_PREFLIGHT", "1")
    yield
    reset()


def _cfg():
    return configure(
        network="solana_localnet",
        preflight=False,
        accept=(Protocol.MPP,),
        mpp=MppConfig(challenge_binding_secret=SECRET),
    )


# -- Pricing -----------------------------------------------------------------


class _Catalog(Pricing):
    def __init__(self, cfg):
        self.report = Gate.build(
            name="report",
            amount=Price.usd("0.10", Stablecoin.USDC),
            default_pay_to=cfg.effective_recipient(),
            accept=(Protocol.MPP,),
        )
        self._private = "ignored"


def test_pricing_gate_lookup():
    cat = _Catalog(_cfg())
    assert cat.gate("report").name == "report"


def test_pricing_gate_unknown_raises():
    cat = _Catalog(_cfg())
    with pytest.raises(ConfigurationError, match="has no gate"):
        cat.gate("missing")


def test_pricing_gate_non_gate_attribute_raises():
    cfg = _cfg()
    cat = _Catalog(cfg)
    cat.not_a_gate = 123  # type: ignore[attr-defined]
    with pytest.raises(ConfigurationError, match="is not a Gate"):
        cat.gate("not_a_gate")


def test_pricing_contains_and_iter():
    cat = _Catalog(_cfg())
    assert "report" in cat
    assert "missing" not in cat
    assert 5 not in cat  # non-string short-circuits
    names = [g.name for g in cat]
    assert names == ["report"]


# -- middleware helpers ------------------------------------------------------


def test_read_header_case_insensitive():
    headers = {"Authorization": "Payment x"}
    assert _read_header(headers, "authorization") == "Payment x"


def test_read_header_upper_fallback():
    headers = {"PAYMENT-SIGNATURE": "sig"}
    assert _read_header(headers, "payment-signature") == "sig"


def test_read_header_absent_returns_empty():
    assert _read_header({}, "authorization") == ""


def test_read_header_no_getter_returns_empty():
    assert _read_header(object(), "authorization") == ""  # type: ignore[arg-type]


def test_request_headers_from_attribute():
    class Req:
        headers = {"a": "b"}

    assert _request_headers(Req())["a"] == "b"


def test_request_headers_from_mapping():
    out = _request_headers({"headers": {"a": "b"}})
    assert out["a"] == "b"


def test_request_headers_proxy_over_get_object():
    class Headers:
        def __init__(self):
            self._d = {"authorization": "Payment x"}

        def get(self, k, default=None):
            return self._d.get(k, default)

        def keys(self):
            return self._d.keys()

        def __len__(self):
            return len(self._d)

    class Req:
        headers = Headers()

    proxy = _request_headers(Req())
    assert isinstance(proxy, _HeaderProxy)
    assert proxy.get("authorization") == "Payment x"
    assert proxy["authorization"] == "Payment x"
    assert proxy.get("missing", "d") == "d"
    assert "authorization" in list(iter(proxy))
    assert len(proxy) == 1


def test_header_proxy_keyerror_on_missing():
    class H:
        def get(self, k, default=None):
            return None

    proxy = _HeaderProxy(H())
    with pytest.raises(KeyError):
        proxy["nope"]


def test_header_proxy_len_typeerror_returns_zero():
    class H:
        def get(self, k, default=None):
            return None

    proxy = _HeaderProxy(H())  # no __len__ on H
    assert len(proxy) == 0


def test_request_headers_none_returns_empty():
    assert _request_headers(object()) == {}


def test_read_attr_from_mapping():
    assert _read_attr({"k": "v"}, "k") == "v"


def test_read_attr_missing_returns_none():
    assert _read_attr(object(), "k") is None


def test_request_path_mapping_path_info():
    assert _request_path({"PATH_INFO": "/wsgi"}) == "/wsgi"


# -- mints reverse lookup ----------------------------------------------------


def test_symbol_for_known_symbol():
    assert mints.symbol_for("USDC", "mainnet") == "USDC"


def test_symbol_for_known_mint():
    mint = mints.resolve("USDC", "mainnet")
    assert mint is not None
    assert mints.symbol_for(mint, "mainnet") == "USDC"


def test_symbol_for_unknown_returns_none():
    assert mints.symbol_for("DEFINITELYNOTACOIN", "mainnet") is None


# -- flask is_paid gate-object branch ----------------------------------------


def test_flask_is_paid_with_gate_object(monkeypatch):
    import flask

    import solana_pay_kit._middleware as mw
    import solana_pay_kit.flask as pk_flask
    from solana_pay_kit import Payment

    cfg = _cfg()
    gate = Gate.build(
        name="report",
        amount=Price.usd("0.10", Stablecoin.USDC),
        default_pay_to=cfg.effective_recipient(),
        accept=(Protocol.MPP,),
    )

    async def fake(self, gate_ref, pricing, request):
        return Payment(protocol=Protocol.MPP, transaction="sig", gate_name="report")

    monkeypatch.setattr(mw.PayCore, "process", fake)

    app = flask.Flask(__name__)

    @app.get("/report")
    @pk_flask.require_payment(gate)
    def view():
        return {
            "by_gate": pk_flask.is_paid(gate),
            "by_name": pk_flask.is_paid("report"),
            "wrong_name": pk_flask.is_paid("other"),
        }

    resp = app.test_client().get("/report")
    assert resp.get_json() == {"by_gate": True, "by_name": True, "wrong_name": False}
