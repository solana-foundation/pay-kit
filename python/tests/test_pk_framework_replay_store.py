"""Replay-store injection coverage for the Python framework shims."""

from __future__ import annotations

from collections.abc import Generator
from pathlib import Path
from types import SimpleNamespace

import pytest

import solana_pay_kit._middleware as mw
from solana_pay_kit import MppConfig, Network, Payment, Price, Protocol, Stablecoin, configure
from solana_pay_kit._paycore.errors import PaymentError
from solana_pay_kit._paycore.store import FileReplayStore
from solana_pay_kit.config import reset
from solana_pay_kit.errors import ConfigurationError

pytest.importorskip("fastapi")
pytest.importorskip("flask")
pytest.importorskip("django")

from fastapi import FastAPI  # noqa: E402
from starlette.testclient import TestClient  # noqa: E402

import solana_pay_kit.django as pk_django  # noqa: E402
import solana_pay_kit.fastapi as pk_fastapi  # noqa: E402
import solana_pay_kit.flask as pk_flask  # noqa: E402

SECRET = "challenge-binding-secret-long-enough-for-hmac"


@pytest.fixture(scope="module", autouse=True)
def _django_settings() -> None:
    import django
    from django.conf import settings

    if not settings.configured:
        settings.configure(
            DEBUG=True,
            ALLOWED_HOSTS=["*"],
            ROOT_URLCONF=None,
            DATABASES={},
            INSTALLED_APPS=[],
        )
        django.setup()


@pytest.fixture(autouse=True)
def _clean(monkeypatch: pytest.MonkeyPatch) -> Generator[None, None, None]:
    reset()
    monkeypatch.setenv("PAY_KIT_DISABLE_PREFLIGHT", "1")
    monkeypatch.delenv("PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE", raising=False)
    yield
    reset()


def _config(label: str):
    return configure(
        network=Network.SOLANA_DEVNET,
        rpc_url=f"https://{label}.example.invalid",
        preflight=False,
        accept=(Protocol.MPP,),
        mpp=MppConfig(challenge_binding_secret=SECRET),
    )


def _payment() -> Payment:
    return Payment(protocol=Protocol.MPP, transaction="sig-abc", gate_name="report")


def _patch_paid_process(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_process(self, gate_ref, pricing, request):  # noqa: ANN001
        return _payment()

    monkeypatch.setattr(mw.PayCore, "process", fake_process)


def _spy_for_config(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[list[FileReplayStore | None], list[mw.PayCore]]:
    calls: list[FileReplayStore | None] = []
    cores: list[mw.PayCore] = []
    original = mw.PayCore.for_config

    def spy(cls, config, *, replay_store=None):  # noqa: ANN001
        calls.append(replay_store)
        core = original(config, replay_store=replay_store)
        cores.append(core)
        return core

    monkeypatch.setattr(mw.PayCore, "for_config", classmethod(spy))
    return calls, cores


@pytest.mark.asyncio
async def test_fastapi_dependency_forwards_durable_store(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _patch_paid_process(monkeypatch)
    calls, cores = _spy_for_config(monkeypatch)
    cfg = _config("fastapi-dependency")
    first_store = FileReplayStore(tmp_path / "first.json")
    dependency = pk_fastapi.RequirePayment(
        Price.usd("0.10", Stablecoin.USDC),
        config=cfg,
        replay_store=first_store,
    )

    payment = await dependency(SimpleNamespace(state=SimpleNamespace()))

    assert payment.transaction == "sig-abc"
    assert calls == [first_store]

    second_store = FileReplayStore(tmp_path / "second.json")
    later_dependency = pk_fastapi.RequirePayment(
        Price.usd("0.10", Stablecoin.USDC),
        config=cfg,
        replay_store=second_store,
    )
    with pytest.raises(ConfigurationError, match="different replay_store is already bound"):
        await later_dependency(SimpleNamespace(state=SimpleNamespace()))
    assert calls == [first_store, second_store]
    assert len(cores) == 1


@pytest.mark.asyncio
async def test_fastapi_dependency_fails_closed_without_durable_store() -> None:
    cfg = _config("fastapi-missing-store")
    dependency = pk_fastapi.RequirePayment(Price.usd("0.10", Stablecoin.USDC), config=cfg)

    with pytest.raises(PaymentError, match="durable replay_store is required"):
        await dependency(SimpleNamespace(state=SimpleNamespace()))


def test_fastapi_paywall_uses_durable_store(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _patch_paid_process(monkeypatch)
    calls, _ = _spy_for_config(monkeypatch)
    cfg = _config("fastapi-paywall")
    store = FileReplayStore(tmp_path / "paywall.json")
    app = FastAPI()
    pk_fastapi.install_paywall_from_config(
        app,
        pk_fastapi.PaywallConfig(gate_ref=Price.usd("0.10", Stablecoin.USDC), config=cfg),
        cors_origins=None,
        replay_store=store,
    )

    @app.get("/report")
    @pk_fastapi.pay_required()
    async def report() -> dict[str, bool]:
        return {"ok": True}

    assert TestClient(app).get("/report").status_code == 200
    assert calls == [store]


def test_fastapi_install_paywall_forwards_replay_store(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    store = FileReplayStore(tmp_path / "install.json")
    received: list[FileReplayStore | None] = []

    def fake_install(app, paywall, *, cors_origins, replay_store):  # noqa: ANN001
        received.append(replay_store)

    monkeypatch.setattr(pk_fastapi, "install_paywall_from_config", fake_install)

    pk_fastapi.install_paywall(
        FastAPI(),
        {
            "enabled": True,
            "network": "solana_localnet",
            "price_usd": "0.10",
            "preflight": False,
            "signer_env": None,
        },
        replay_store=store,
    )

    assert received == [store]


def test_flask_decorator_uses_durable_store(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    import flask

    _patch_paid_process(monkeypatch)
    calls, _ = _spy_for_config(monkeypatch)
    cfg = _config("flask")
    store = FileReplayStore(tmp_path / "flask.json")
    app = flask.Flask(__name__)

    @app.get("/report")
    @pk_flask.require_payment(Price.usd("0.10", Stablecoin.USDC), config=cfg, replay_store=store)
    def report() -> dict[str, bool]:
        return {"ok": True}

    assert app.test_client().get("/report").status_code == 200
    assert calls == [store]


def test_django_decorator_and_middleware_use_durable_store(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from django.http import JsonResponse
    from django.test import RequestFactory

    _patch_paid_process(monkeypatch)
    calls, _ = _spy_for_config(monkeypatch)
    decorator_cfg = _config("django-decorator")
    decorator_store = FileReplayStore(tmp_path / "decorator.json")

    @pk_django.require_payment(
        Price.usd("0.10", Stablecoin.USDC),
        config=decorator_cfg,
        replay_store=decorator_store,
    )
    def decorated_view(request):
        return JsonResponse({"ok": True})

    assert decorated_view(RequestFactory().get("/decorator")).status_code == 200
    assert calls == [decorator_store]

    _config("django-middleware")
    middleware_store = FileReplayStore(tmp_path / "middleware.json")
    middleware = pk_django.PaymentMiddleware(
        lambda request: JsonResponse({"ok": True}),
        replay_store=middleware_store,
    )
    request = RequestFactory().get("/middleware")
    request.paykit_gate = Price.usd("0.10", Stablecoin.USDC)  # type: ignore[attr-defined]

    assert middleware(request).status_code == 200
    assert calls == [decorator_store, middleware_store]
