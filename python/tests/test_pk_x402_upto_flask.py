"""Flask require_usage challenge path (offline) + charge wiring.

The settle-after-handler path needs a live validator (verify_open broadcasts the
channel open), so it is exercised by the harness matrix; here we cover the
offline public surface: the 402 upto challenge a missing credential produces,
and that a non-usage route passes through untouched.
"""

from __future__ import annotations

import pytest
from solders.keypair import Keypair  # type: ignore[import-untyped]

pytest.importorskip("flask")

import flask  # noqa: E402

from solana_pay_kit import (  # noqa: E402
    Gate,
    LocalSigner,
    Operator,
    Price,
    Protocol,
    Stablecoin,
    configure,
)
from solana_pay_kit.config import reset  # noqa: E402
from solana_pay_kit.flask import Charge, require_usage  # noqa: E402


@pytest.fixture(autouse=True)
def _clean(monkeypatch: pytest.MonkeyPatch):
    reset()
    monkeypatch.setenv("PAY_KIT_DISABLE_PREFLIGHT", "1")
    yield
    reset()


def _app() -> flask.Flask:
    cfg = configure(
        network="solana_localnet",
        # Loopback RPC so the engine's recentBlockhash pre-fetch fast-fails
        # offline (these tests assert the challenge shape, not the blockhash).
        rpc_url="http://127.0.0.1:1",
        preflight=False,
        accept=(Protocol.X402,),
        operator=Operator(signer=LocalSigner.from_keypair(Keypair()), recipient=str(Keypair().pubkey())),
    )
    app = flask.Flask(__name__)
    gate = Gate.build(
        name="usage",
        amount=Price.usd("0.10", Stablecoin.USDC),
        default_pay_to=cfg.effective_recipient(),
        accept=(Protocol.X402,),
    )

    @app.get("/usage")
    @require_usage(gate, config=cfg)
    def usage() -> dict[str, object]:
        meter = flask.g.paykit_charge
        assert isinstance(meter, Charge)
        meter.charge(50000)
        return {"ok": True, "max": meter.max_base_units}

    @app.get("/free")
    def free() -> dict[str, bool]:
        return {"ok": True}

    return app


def test_require_usage_challenges_without_credential() -> None:
    client = _app().test_client()
    resp = client.get("/usage")
    assert resp.status_code == 402
    assert "payment-required" in resp.headers
    body = resp.get_json()
    assert body["error"] == "payment_required"
    assert body["accepts"][0]["scheme"] == "upto"
    assert body["accepts"][0]["extra"]["profiles"] == ["payment-channel"]


def test_non_usage_route_passes_through() -> None:
    client = _app().test_client()
    resp = client.get("/free")
    assert resp.status_code == 200
    assert resp.get_json() == {"ok": True}
