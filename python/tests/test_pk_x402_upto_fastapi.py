"""FastAPI RequireUsage challenge path (offline) + charge_from wiring.

The settle-after-handler path needs a live validator (verify_open broadcasts the
channel open), so it is exercised by the harness matrix; here we cover the
offline public surface: the 402 upto challenge a missing credential produces,
and that a non-usage route passes through the usage middleware untouched.
"""

from __future__ import annotations

import pytest
from solders.keypair import Keypair  # type: ignore[import-untyped]

pytest.importorskip("fastapi")

from fastapi import Depends, FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

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
from solana_pay_kit.fastapi import Charge, RequireUsage, install  # noqa: E402


@pytest.fixture(autouse=True)
def _clean(monkeypatch: pytest.MonkeyPatch):
    reset()
    monkeypatch.setenv("PAY_KIT_DISABLE_PREFLIGHT", "1")
    yield
    reset()


def _app() -> TestClient:
    cfg = configure(
        network="solana_localnet",
        # Loopback RPC so the engine's recentBlockhash pre-fetch fast-fails
        # offline (these tests assert the challenge shape, not the blockhash).
        rpc_url="http://127.0.0.1:1",
        preflight=False,
        accept=(Protocol.X402,),
        operator=Operator(signer=LocalSigner.from_keypair(Keypair()), recipient=str(Keypair().pubkey())),
    )
    app = FastAPI()
    install(app)
    gate = Gate.build(
        name="usage",
        amount=Price.usd("0.10", Stablecoin.USDC),
        default_pay_to=cfg.effective_recipient(),
        accept=(Protocol.X402,),
    )

    @app.get("/usage")
    async def usage(charge: Charge = Depends(RequireUsage(gate, config=cfg))) -> dict[str, object]:  # noqa: B008
        charge.charge(50000)
        return {"ok": True, "max": charge.max_base_units}

    @app.get("/free")
    async def free() -> dict[str, bool]:
        return {"ok": True}

    return TestClient(app, raise_server_exceptions=False)


def test_requireusage_challenges_without_credential() -> None:
    client = _app()
    resp = client.get("/usage")
    assert resp.status_code == 402
    assert any(k.lower() == "payment-required" for k in resp.headers)
    body = resp.json()
    assert body["error"] == "payment_required"
    assert body["accepts"][0]["scheme"] == "upto"
    assert body["accepts"][0]["extra"]["assetTransferMethod"] == "payment-channel"
    assert body["accepts"][0]["extra"]["facilitatorAddress"]


def test_requireusage_without_install_refuses_to_open() -> None:
    """Without install()/install_exception_handler the settle-after middleware is
    absent, so RequireUsage must refuse rather than open a channel that never
    settles (P2 regression)."""
    cfg = configure(
        network="solana_localnet",
        # Loopback RPC so the engine's recentBlockhash pre-fetch fast-fails
        # offline (these tests assert the challenge shape, not the blockhash).
        rpc_url="http://127.0.0.1:1",
        preflight=False,
        accept=(Protocol.X402,),
        operator=Operator(signer=LocalSigner.from_keypair(Keypair()), recipient=str(Keypair().pubkey())),
    )
    app = FastAPI()  # deliberately NOT install(app)
    gate = Gate.build(
        name="usage",
        amount=Price.usd("0.10", Stablecoin.USDC),
        default_pay_to=cfg.effective_recipient(),
        accept=(Protocol.X402,),
    )

    @app.get("/usage")
    async def usage(charge: Charge = Depends(RequireUsage(gate, config=cfg))) -> dict[str, bool]:  # noqa: B008
        charge.charge(1)
        return {"ok": True}

    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get("/usage")
    assert resp.status_code == 500  # guard fires before any channel is opened


def test_non_usage_route_passes_through_middleware() -> None:
    client = _app()
    resp = client.get("/free")
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}
