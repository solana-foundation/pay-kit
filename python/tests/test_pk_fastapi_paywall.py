"""Django/DRF-style FastAPI paywall coverage.

The paywall middleware should enforce payment from route metadata and default
policy, without requiring applications to duplicate endpoint paths in a payment
allowlist.
"""

from __future__ import annotations

import pytest

import solana_pay_kit._middleware as mw
from solana_pay_kit import Config, MppConfig, Network, Payment, Price, Protocol, Stablecoin, X402Config, configure
from solana_pay_kit.config import config as get_config
from solana_pay_kit.config import reset
from solana_pay_kit.errors import PaymentRequiredError

pytest.importorskip("fastapi")

from fastapi import FastAPI, Request  # noqa: E402
from starlette.testclient import TestClient  # noqa: E402

import solana_pay_kit.fastapi as pk_fastapi  # noqa: E402

SECRET = "challenge-binding-secret-long-enough-for-hmac"


@pytest.fixture(autouse=True)
def _clean(monkeypatch: pytest.MonkeyPatch):
    reset()
    monkeypatch.setenv("PAY_KIT_DISABLE_PREFLIGHT", "1")
    configure(
        network="solana_localnet",
        preflight=False,
        accept=(Protocol.MPP,),
        mpp=MppConfig(challenge_binding_secret=SECRET),
    )
    yield
    reset()


def _payment() -> Payment:
    return Payment(
        protocol=Protocol.MPP,
        transaction="sig-abc",
        gate_name="inference",
        settlement_headers={"x-payment-settlement-signature": "sig-abc"},
    )


def _payment_required() -> PaymentRequiredError:
    err = PaymentRequiredError("solana_pay_kit: payment required")
    err.challenge_headers = {"www-authenticate": "Payment realm=App"}  # type: ignore[attr-defined]
    err.body = {"error": "payment_required", "resource": "/paid", "accepts": []}  # type: ignore[attr-defined]
    return err


def _patch_process(monkeypatch: pytest.MonkeyPatch, *, paid: bool) -> list[str]:
    calls: list[str] = []

    async def fake_process(self, gate_ref, pricing, request):  # noqa: ANN001
        calls.append(request.url.path)
        if paid:
            return _payment()
        raise _payment_required()

    monkeypatch.setattr(mw.PayCore, "process", fake_process)
    return calls


def test_paywall_default_public_gates_only_marked_routes(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _patch_process(monkeypatch, paid=False)
    app = FastAPI()
    pk_fastapi.install_paywall_from_config(
        app,
        pk_fastapi.PaywallConfig(
            gate_ref=Price.usd("0.10", Stablecoin.USDC),
            default_policy="public",
        ),
        cors_origins=None,
    )

    @app.get("/paid")
    @pk_fastapi.pay_required()
    async def paid() -> dict[str, bool]:
        return {"ok": True}

    @app.get("/free")
    async def free() -> dict[str, bool]:
        return {"ok": True}

    client = TestClient(app, raise_server_exceptions=False)
    paid_resp = client.get("/paid")
    free_resp = client.get("/free")

    assert paid_resp.status_code == 402
    assert paid_resp.json()["error"] == "payment_required"
    assert paid_resp.headers.get("www-authenticate") == "Payment realm=App"
    assert free_resp.status_code == 200
    assert free_resp.json() == {"ok": True}
    assert calls == ["/paid"]


def test_paywall_402_response_includes_cors_headers(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _patch_process(monkeypatch, paid=False)
    app = FastAPI()
    pk_fastapi.install_paywall_from_config(
        app,
        pk_fastapi.PaywallConfig(
            gate_ref=Price.usd("0.10", Stablecoin.USDC),
            default_policy="public",
        ),
        cors_origins=("https://app.example",),
    )

    @app.get("/paid")
    @pk_fastapi.pay_required()
    async def paid() -> dict[str, bool]:
        return {"ok": True}

    resp = TestClient(app, raise_server_exceptions=False).get(
        "/paid",
        headers={"origin": "https://app.example"},
    )

    assert resp.status_code == 402
    assert resp.headers.get("access-control-allow-origin") == "https://app.example"
    exposed_headers = resp.headers.get("access-control-expose-headers", "")
    assert "www-authenticate" in exposed_headers
    assert "x-payment-required" in exposed_headers
    assert resp.headers.get("www-authenticate") == "Payment realm=App"
    assert calls == ["/paid"]


def test_paywall_success_attaches_payment_and_settlement(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_process(monkeypatch, paid=True)
    app = FastAPI()
    pk_fastapi.install_paywall_from_config(
        app,
        pk_fastapi.PaywallConfig(
            gate_ref=Price.usd("0.10", Stablecoin.USDC),
            default_policy="public",
        ),
        cors_origins=None,
    )

    @app.get("/paid")
    @pk_fastapi.pay_required("inference")
    async def paid(request: Request) -> dict[str, object]:
        verified = pk_fastapi.payment(request)
        return {"ok": True, "tx": verified.transaction if verified else None}

    resp = TestClient(app, raise_server_exceptions=False).get("/paid")

    assert resp.status_code == 200
    assert resp.json() == {"ok": True, "tx": "sig-abc"}
    assert resp.headers.get("x-payment-settlement-signature") == "sig-abc"


def test_paywall_default_paid_allows_explicit_public_routes(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _patch_process(monkeypatch, paid=False)
    app = FastAPI()
    pk_fastapi.install_paywall_from_config(
        app,
        pk_fastapi.PaywallConfig(
            gate_ref=Price.usd("0.10", Stablecoin.USDC),
            default_policy="paid",
        ),
        cors_origins=None,
    )

    @app.get("/paid")
    async def paid() -> dict[str, bool]:
        return {"ok": True}

    @app.get("/health")
    @pk_fastapi.pay_not_required()
    async def health() -> dict[str, bool]:
        return {"ok": True}

    client = TestClient(app, raise_server_exceptions=False)

    assert client.get("/paid").status_code == 402
    health_resp = client.get("/health")
    assert health_resp.status_code == 200
    assert health_resp.json() == {"ok": True}
    assert calls == ["/paid"]


def test_paywall_default_paid_leaves_unknown_routes_as_404(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _patch_process(monkeypatch, paid=False)
    app = FastAPI()
    pk_fastapi.install_paywall_from_config(
        app,
        pk_fastapi.PaywallConfig(
            gate_ref=Price.usd("0.10", Stablecoin.USDC),
            default_policy="paid",
        ),
        cors_origins=None,
    )

    resp = TestClient(app, raise_server_exceptions=False).get("/missing")

    assert resp.status_code == 404
    assert calls == []


def test_paywall_can_gate_fastapi_tags(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _patch_process(monkeypatch, paid=False)
    app = FastAPI()
    pk_fastapi.install_paywall_from_config(
        app,
        pk_fastapi.PaywallConfig(
            gate_ref=Price.usd("0.10", Stablecoin.USDC),
            default_policy="public",
            paid_tags=("paid",),
        ),
        cors_origins=None,
    )

    @app.get("/tagged", tags=["paid"])
    async def tagged() -> dict[str, bool]:
        return {"ok": True}

    resp = TestClient(app, raise_server_exceptions=False).get("/tagged")

    assert resp.status_code == 402
    assert calls == ["/tagged"]


def test_pay_required_takes_precedence_over_public_tags(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _patch_process(monkeypatch, paid=False)
    app = FastAPI()
    pk_fastapi.install_paywall_from_config(
        app,
        pk_fastapi.PaywallConfig(
            gate_ref=Price.usd("0.10", Stablecoin.USDC),
            default_policy="public",
            public_tags=("public",),
        ),
        cors_origins=None,
    )

    @app.get("/explicit", tags=["public"])
    @pk_fastapi.pay_required()
    async def explicit() -> dict[str, bool]:
        return {"ok": True}

    resp = TestClient(app, raise_server_exceptions=False).get("/explicit")

    assert resp.status_code == 402
    assert calls == ["/explicit"]


def test_paywall_gates_mounted_fastapi_child_routes(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _patch_process(monkeypatch, paid=False)
    app = FastAPI()
    pk_fastapi.install_paywall_from_config(
        app,
        pk_fastapi.PaywallConfig(
            gate_ref=Price.usd("0.10", Stablecoin.USDC),
            default_policy="public",
        ),
        cors_origins=None,
    )
    child = FastAPI()

    @child.get("/paid")
    @pk_fastapi.pay_required()
    async def paid() -> dict[str, bool]:
        return {"ok": True}

    @child.get("/free")
    async def free() -> dict[str, bool]:
        return {"ok": True}

    app.mount("/api", child)
    client = TestClient(app, raise_server_exceptions=False)

    paid_resp = client.get("/api/paid")
    free_resp = client.get("/api/free")

    assert paid_resp.status_code == 402
    assert free_resp.status_code == 200
    assert calls == ["/api/paid"]


def test_install_paywall_accepts_app_config_mapping(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _patch_process(monkeypatch, paid=False)
    monkeypatch.setenv("EXO_PAY_ENABLED", "true")
    monkeypatch.setenv("EXO_PAY_NO_PREFLIGHT", "true")
    app = FastAPI()
    pk_fastapi.install_paywall(
        app,
        {
            "enabled": False,
            "network": "solana_localnet",
            "price_usd": "0.10",
            "protocols": ["mpp"],
            "stablecoins": ["USDC"],
            "preflight": False,
            "signer_env": None,
        },
        env_prefix="EXO_PAY_",
        paid_tags=("paid",),
        cors_origins=None,
    )

    @app.get("/tagged", tags=["paid"])
    async def tagged() -> dict[str, bool]:
        return {"ok": True}

    resp = TestClient(app, raise_server_exceptions=False).get("/tagged")

    assert resp.status_code == 402
    assert calls == ["/tagged"]


def test_install_paywall_preserves_global_config_subconfigs(monkeypatch: pytest.MonkeyPatch) -> None:
    seen_configs: list[Config] = []

    async def fake_process(
        self: mw.PayCore,
        gate_ref: object,
        pricing: object,
        request: Request,
    ) -> Payment:
        seen_configs.append(self.config)
        raise _payment_required()

    monkeypatch.setattr(mw.PayCore, "process", fake_process)
    base = configure(
        network=Network.SOLANA_DEVNET,
        preflight=False,
        accept=(Protocol.MPP,),
        mpp=MppConfig(challenge_binding_secret=SECRET),
        x402=X402Config(facilitator_url="https://facilitator.example"),
    )
    app = FastAPI()
    pk_fastapi.install_paywall(
        app,
        {
            "enabled": True,
            "network": "solana_localnet",
            "price_usd": "0.10",
            "protocols": ["mpp"],
            "stablecoins": ["USDC"],
            "preflight": False,
            "signer_env": None,
        },
        paid_tags=("paid",),
        cors_origins=None,
    )

    @app.get("/tagged", tags=["paid"])
    async def tagged() -> dict[str, bool]:
        return {"ok": True}

    resp = TestClient(app, raise_server_exceptions=False).get("/tagged")

    assert resp.status_code == 402
    assert get_config() is base
    assert seen_configs[0].network is Network.SOLANA_LOCALNET
    assert seen_configs[0].mpp.challenge_binding_secret == SECRET
    assert seen_configs[0].x402.facilitator_url == "https://facilitator.example"
