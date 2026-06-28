"""Django require_usage challenge path (offline) + charge wiring.

The settle-after-handler path needs a live validator (verify_open broadcasts the
channel open), so it is exercised by the harness matrix; here we cover the
offline public surface: the 402 upto challenge a missing credential produces,
and that a non-usage route passes through untouched.
"""

from __future__ import annotations

import json

import pytest
from solders.keypair import Keypair  # type: ignore[import-untyped]

pytest.importorskip("django")

from pay_kit import (  # noqa: E402
    Gate,
    LocalSigner,
    Operator,
    Price,
    Protocol,
    Stablecoin,
    configure,
)
from pay_kit.config import reset  # noqa: E402


@pytest.fixture(scope="module", autouse=True)
def _django_settings():
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
    yield


@pytest.fixture(autouse=True)
def _clean(monkeypatch: pytest.MonkeyPatch):
    reset()
    monkeypatch.setenv("PAY_KIT_DISABLE_PREFLIGHT", "1")
    yield
    reset()


def _gate(cfg):
    return Gate.build(
        name="usage",
        amount=Price.usd("0.10", Stablecoin.USDC),
        default_pay_to=cfg.effective_recipient(),
        accept=(Protocol.X402,),
    )


def _config():
    return configure(
        network="solana_localnet",
        # Loopback RPC so the engine's recentBlockhash pre-fetch fast-fails
        # offline (these tests assert the challenge shape, not the blockhash).
        rpc_url="http://127.0.0.1:1",
        preflight=False,
        accept=(Protocol.X402,),
        operator=Operator(signer=LocalSigner.from_keypair(Keypair()), recipient=str(Keypair().pubkey())),
    )


def test_require_usage_challenges_without_credential() -> None:
    from django.http import JsonResponse
    from django.test import RequestFactory

    import pay_kit.django as pk_django

    cfg = _config()

    @pk_django.require_usage(_gate(cfg), config=cfg)
    def view(request):
        request.charge.charge(50000)
        return JsonResponse({"ok": True})

    resp = view(RequestFactory().get("/usage"))
    assert resp.status_code == 402
    assert "payment-required" in resp.headers
    body = json.loads(resp.content)
    assert body["error"] == "payment_required"
    assert body["accepts"][0]["scheme"] == "upto"
    assert body["accepts"][0]["extra"]["profiles"] == ["payment-channel"]


def test_non_usage_route_passes_through() -> None:
    from django.http import JsonResponse
    from django.test import RequestFactory

    _config()

    # A view without the usage decorator runs untouched (no channel, no charge).
    def free(request):
        return JsonResponse({"ok": True})

    resp = free(RequestFactory().get("/free"))
    assert resp.status_code == 200
    assert json.loads(resp.content) == {"ok": True}
