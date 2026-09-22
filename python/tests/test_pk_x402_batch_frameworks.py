"""x402 ``batch-settlement`` framework wiring: the FastAPI, Flask and Django shims, and ``x402_batch()``.

Every case runs against all three shims over one engine on the fake chain,
paid by the real client.
"""

from __future__ import annotations

import asyncio
import base64
import json
import threading
from collections.abc import Callable
from typing import Any

import pytest
from solders.keypair import Keypair

pytest.importorskip("fastapi")
pytest.importorskip("flask")
pytest.importorskip("django")

from solana_pay_kit import X402Config, configure, x402_batch  # noqa: E402
from solana_pay_kit._paycore.loops import run_blocking  # noqa: E402
from solana_pay_kit.config import BatchSettlementConfig  # noqa: E402
from solana_pay_kit.errors import ConfigurationError  # noqa: E402
from solana_pay_kit.protocols.x402.batch_settlement import (  # noqa: E402  # pyright: ignore[reportPrivateUsage]
    _ENGINES,
    batch_engine,
    errors,  # noqa: E402
)
from solana_pay_kit.protocols.x402.batch_settlement.engine import X402BatchSettlement  # noqa: E402
from solana_pay_kit.protocols.x402.batch_settlement.store import StoreInvariantError  # noqa: E402
from solana_pay_kit.protocols.x402.batch_settlement.types import (  # noqa: E402
    MAX_WITHDRAW_DELAY_SECONDS,
    MIN_WITHDRAW_DELAY_SECONDS,
)
from solana_pay_kit.protocols.x402.client.batch_settlement import (  # noqa: E402
    BatchSettlementClient,
    ServerSignedChannelsPolicy,
)
from solana_pay_kit.signer import LocalSigner  # noqa: E402
from tests.batch_chain import BLOCKHASH, CLOSING, PRICE, SLOT, World, make_world  # noqa: E402

pytestmark = pytest.mark.usefixtures("reset_batch_globals")

NOW = 1_700_000_000.0
#: What a failing handler says; no response may repeat it.
_SECRET = "secret detail from the handler"
OPERATOR = LocalSigner.from_keypair(Keypair.from_seed(bytes([4] * 32)))

Get = Callable[[str, dict[str, str]], tuple[int, dict[str, str], bytes]]
# The shims run their own loops (Flask and Django views are synchronous), so
# these tests are synchronous and drive the async client with asyncio.run.
run = asyncio.run


@pytest.fixture(scope="module", autouse=True)
def _django_settings() -> None:
    import django
    from django.conf import settings

    if not settings.configured:
        settings.configure(DEBUG=True, ALLOWED_HOSTS=["*"], ROOT_URLCONF=None, DATABASES={}, INSTALLED_APPS=[])
        django.setup()


@pytest.fixture
def world(monkeypatch: pytest.MonkeyPatch) -> World:
    world = make_world(monkeypatch)
    engine = X402BatchSettlement(
        world.config,
        settings=BatchSettlementConfig(operator=OPERATOR),
        rpc=world.chain,  # type: ignore[arg-type]
        recent_state_provider=lambda: (BLOCKHASH, SLOT),
        clock=lambda: NOW,
    )
    monkeypatch.setitem(_ENGINES, world.config, engine)
    return world


def _fastapi(world: World, served: list[str]) -> Get:
    from fastapi import Depends, FastAPI
    from fastapi.responses import JSONResponse
    from fastapi.testclient import TestClient

    from solana_pay_kit.fastapi import Charge, RequireBatch, install

    app = FastAPI()
    install(app)
    unconfigured = world.config.model_copy(update={"rpc_url": "http://127.0.0.1:1"})

    @app.get("/r")
    async def fixed(act: str = "ok", _: Charge = Depends(RequireBatch(world.gate, config=world.config))) -> Any:  # noqa: B008
        served.append("r")
        if act == "raise":
            raise RuntimeError(_SECRET)
        return {"ok": True} if act == "ok" else JSONResponse({"ok": False}, status_code=500)

    @app.get("/m")
    async def metered(
        charge: int | None = None,
        meter: Charge = Depends(RequireBatch(world.gate, config=world.config, voucher_signer="server")),  # noqa: B008
    ) -> Any:
        served.append("m")
        if charge is not None:
            meter.charge(charge)
        return {"ok": True}

    @app.get("/x")
    async def misconfigured(
        _: Charge = Depends(RequireBatch(world.gate, config=unconfigured, voucher_signer="server")),  # noqa: B008
    ) -> Any:
        served.append("x")
        return {"ok": True}

    client = TestClient(app, raise_server_exceptions=False)

    def get(path: str, headers: dict[str, str]) -> tuple[int, dict[str, str], bytes]:
        response = client.get(path, headers=headers)
        return response.status_code, dict(response.headers), response.content

    return get


def _flask(world: World, served: list[str]) -> Get:
    import flask

    from solana_pay_kit.flask import charge, require_batch

    app = flask.Flask("batch")
    unconfigured = world.config.model_copy(update={"rpc_url": "http://127.0.0.1:1"})

    @app.get("/r")
    @require_batch(world.gate, config=world.config)
    def fixed() -> Any:
        served.append("r")
        act = flask.request.args.get("act", "ok")
        if act == "raise":
            raise RuntimeError(_SECRET)
        return {"ok": True} if act == "ok" else ({"ok": False}, 500)

    @app.get("/m")
    @require_batch(world.gate, config=world.config, voucher_signer="server")
    def metered() -> Any:
        served.append("m")
        amount = flask.request.args.get("charge")
        meter = charge()
        if amount is not None and meter is not None:
            meter.charge(int(amount))
        return {"ok": True}

    @app.get("/x")
    @require_batch(world.gate, config=unconfigured, voucher_signer="server")
    def misconfigured() -> Any:
        served.append("x")
        return {"ok": True}

    client = app.test_client()

    def get(path: str, headers: dict[str, str]) -> tuple[int, dict[str, str], bytes]:
        response = client.get(path, headers=headers)
        return response.status_code, dict(response.headers), response.data

    return get


def _django(world: World, served: list[str]) -> Get:
    from django.http import HttpRequest, JsonResponse
    from django.test import RequestFactory

    import solana_pay_kit.django as pk

    unconfigured = world.config.model_copy(update={"rpc_url": "http://127.0.0.1:1"})

    @pk.require_batch(world.gate, config=world.config)
    def fixed(request: HttpRequest) -> Any:
        served.append("r")
        act = request.GET.get("act", "ok")
        if act == "raise":
            raise RuntimeError(_SECRET)
        return JsonResponse({"ok": act == "ok"}, status=200 if act == "ok" else 500)

    @pk.require_batch(world.gate, config=world.config, voucher_signer="server")
    def metered(request: HttpRequest) -> Any:
        served.append("m")
        amount = str(request.GET.get("charge", ""))
        meter = pk.charge(request)
        if amount and meter is not None:
            meter.charge(int(amount))
        return JsonResponse({"ok": True})

    @pk.require_batch(world.gate, config=unconfigured, voucher_signer="server")
    def misconfigured(request: HttpRequest) -> Any:
        served.append("x")
        return JsonResponse({"ok": True})

    views = {"/r": fixed, "/m": metered, "/x": misconfigured}

    def get(path: str, headers: dict[str, str]) -> tuple[int, dict[str, str], bytes]:
        request = RequestFactory().get(path, headers=headers)
        try:
            response = views[path.partition("?")[0]](request)
        except Exception:  # noqa: BLE001 - what Django's handler renders as a 500
            return 500, {}, b""
        return response.status_code, dict(response.headers), response.content

    return get


FRAMEWORKS = {"fastapi": _fastapi, "flask": _flask, "django": _django}


@pytest.fixture(params=FRAMEWORKS)
def app(request: pytest.FixtureRequest, world: World) -> tuple[Get, list[str]]:
    served: list[str] = []
    return FRAMEWORKS[request.param](world, served), served


def _engine(world: World) -> X402BatchSettlement:
    return batch_engine(world.config)


def _client(world: World, **kwargs: Any) -> BatchSettlementClient:
    return BatchSettlementClient(world.payer, rpc=world.chain, discover_channels=False, clock=lambda: NOW, **kwargs)  # type: ignore[arg-type]


def _header(payment: Any) -> dict[str, str]:
    return {"payment-signature": base64.b64encode(json.dumps(payment).encode()).decode()}


def _decode(headers: dict[str, str], name: str) -> Any:
    lowered = {k.lower(): v for k, v in headers.items()}
    return json.loads(base64.b64decode(lowered[name]))


def _open(world: World, get: Get, client: BatchSettlementClient, index: int = 0, path: str = "/r") -> Any:
    accept = _engine(world).accepts_entries(world.gate, {})[index]
    payment: Any = run(client.create_payment_payload(accept))
    status, headers, _ = get(path, _header(payment))
    assert status == 200
    run(client.handle_payment_response(payment, response=_decode(headers, "payment-response")))
    return accept


def test_challenges_an_unpaid_request_client_signed_first(app: tuple[Get, list[str]]) -> None:
    get, served = app
    status, headers, _ = get("/r", {})
    required = _decode(headers, "payment-required")
    assert status == 402 and served == []
    assert [a["extra"].get("voucherSigner", "client") for a in required["accepts"]] == ["client", "server"]


def test_pays_and_commits_each_request(world: World, app: tuple[Get, list[str]]) -> None:
    get, served = app
    world.lands_as_channel(deposit=10 * PRICE)
    client = _client(world)
    accept = _open(world, get, client)
    payment: Any = run(client.create_payment_payload(accept))
    status, headers, body = get("/r", _header(payment))
    settled = _decode(headers, "payment-response")
    assert (status, json.loads(body)) == (200, {"ok": True})
    assert settled["extra"]["channelState"]["chargedCumulativeAmount"] == str(2 * PRICE)
    assert served == ["r", "r"] and len(world.chain.sent) == 1


@pytest.mark.parametrize("act", ["raise", "fail"])
def test_a_failed_handler_charges_nothing_and_frees_the_reservation(
    world: World, app: tuple[Get, list[str]], act: str
) -> None:
    get, served = app
    world.lands_as_channel(deposit=10 * PRICE)
    accept = _engine(world).accepts_entries(world.gate, {})[0]
    payment: Any = run(_client(world).create_payment_payload(accept))
    status, _, body = get(f"/r?act={act}", _header(payment))
    assert status == 500 and world.chain.sent == []  # the open was never broadcast
    assert _SECRET.encode() not in body  # the handler's own words stay server-side
    # Released, not held: the same payment serves now.
    status, headers, _ = get("/r", _header(payment))
    assert status == 200 and _decode(headers, "payment-response")["success"]
    assert served == ["r", "r"]


def _server_client(world: World) -> BatchSettlementClient:
    return _client(
        world, server_signed_channels_policy=ServerSignedChannelsPolicy(allowed_operators=(OPERATOR.pubkey(),))
    )


def _lands_server_channel(world: World) -> None:
    config = world.channel_config(payerAuthorizer=OPERATOR.pubkey(), voucherSigner="server")
    world.lands_as_channel(config, deposit=3 * PRICE)


def test_a_server_signed_route_charges_the_metered_amount(world: World, app: tuple[Get, list[str]]) -> None:
    get, _ = app
    _lands_server_channel(world)
    accept = _engine(world).accepts_entries(world.gate, {})[1]
    payment: Any = run(_server_client(world).create_payment_payload(accept))
    status, headers, _ = get("/m?charge=4000", _header(payment))
    settled = _decode(headers, "payment-response")
    assert status == 200 and settled["extra"]["voucher"]["maxClaimableAmount"] == "4000"


def test_a_missing_meter_withholds_the_body_and_charges_nothing(world: World, app: tuple[Get, list[str]]) -> None:
    get, served = app
    _lands_server_channel(world)
    accept = _engine(world).accepts_entries(world.gate, {})[1]
    payment: Any = run(_server_client(world).create_payment_payload(accept))
    status, headers, body = get("/m", _header(payment))
    assert status == 402 and b'"ok"' not in body and "settlement_failed" in body.decode()
    assert _decode(headers, "payment-required")["error"] == "settlement_failed"
    assert served == ["m"] and world.chain.sent == []


def test_a_refund_bypasses_the_handler(world: World, app: tuple[Get, list[str]]) -> None:
    get, served = app
    world.lands_as_channel(deposit=10 * PRICE)
    client = _client(world)
    accept = _open(world, get, client)
    world.lands_as_channel(deposit=10 * PRICE, settled=PRICE)  # the claim
    world.lands_as_channel(deposit=10 * PRICE, settled=PRICE, status=CLOSING, closure_started_at=int(NOW))
    status, headers, body = get("/r", _header(run(client.create_refund_payload(accept))))
    assert status == 200 and b"channel close initiated" in body
    assert _decode(headers, "payment-response")["success"] and served == ["r"]


def test_a_stale_voucher_gets_the_corrective_state(world: World, app: tuple[Get, list[str]]) -> None:
    get, _ = app
    world.lands_as_channel(deposit=10 * PRICE)
    client = _client(world)
    accept = _open(world, get, client)
    for cumulative in (2 * PRICE, 3 * PRICE):  # the same wallet pays from another process
        status, _, _ = get(
            "/r", _header({"x402Version": 2, "accepted": accept, "payload": world.voucher_payload(cumulative)})
        )
        assert status == 200
    status, headers, _ = get("/r", _header(run(client.create_payment_payload(accept))))
    required = _decode(headers, "payment-required")
    assert status == 402 and required["error"] == errors.INVALID_CUMULATIVE_AMOUNT_MISMATCH
    assert required["accepts"][0]["extra"]["channelState"]["chargedCumulativeAmount"] == str(3 * PRICE)


def test_an_invalid_payment_gets_a_challenge_naming_the_code(world: World, app: tuple[Get, list[str]]) -> None:
    get, served = app
    accept = _engine(world).accepts_entries(world.gate, {})[0]
    unknown = {"x402Version": 2, "accepted": accept, "payload": world.voucher_payload(PRICE)}  # no such channel
    status, headers, body = get("/r", _header(unknown))
    required = _decode(headers, "payment-required")
    assert status == 402 and required["error"] == errors.INVALID_CHANNEL_STATE
    assert required["error"] in body.decode() and served == []


def test_a_misconfigured_route_answers_500_not_a_challenge(app: tuple[Get, list[str]]) -> None:
    get, served = app
    status, _, _ = get("/x", {})
    assert status == 500 and served == []


def _blocking_app(world: World, framework: str, handler: Callable[[], None]) -> Get:
    """The same gated route in Flask or Django, whose handler blocks until released."""
    if framework == "flask":
        import flask

        from solana_pay_kit.flask import require_batch

        app = flask.Flask("concurrent")

        @app.get("/r")
        @require_batch(world.gate, config=world.config)
        def view() -> Any:
            handler()
            return {"ok": True}

        def flask_get(path: str, headers: dict[str, str]) -> tuple[int, dict[str, str], bytes]:
            response = app.test_client().get(path, headers=headers)
            return response.status_code, dict(response.headers), response.data

        return flask_get

    from django.http import HttpRequest, JsonResponse
    from django.test import RequestFactory

    import solana_pay_kit.django as pk

    @pk.require_batch(world.gate, config=world.config)
    def django_view(request: HttpRequest) -> Any:
        handler()
        return JsonResponse({"ok": True})

    def django_get(path: str, headers: dict[str, str]) -> tuple[int, dict[str, str], bytes]:
        response = django_view(RequestFactory().get(path, headers=headers))
        return response.status_code, dict(response.headers), response.content

    return django_get


@pytest.mark.parametrize("framework", ["flask", "django"])
def test_two_threads_on_one_channel_charge_it_once(world: World, framework: str) -> None:
    # Each request thread runs its own event loop, so the channel's exclusivity
    # rule has to hold across loops: while one request holds the channel the
    # other is refused, and the charge moves exactly once.
    armed, inside, release = threading.Event(), threading.Event(), threading.Event()

    def handler() -> None:
        if armed.is_set() and not inside.is_set():
            inside.set()
            release.wait(5)

    get = _blocking_app(world, framework, handler)
    world.lands_as_channel(deposit=10 * PRICE)
    client = _client(world)
    accept = _open(world, get, client)  # the open, sequential and unblocked
    armed.set()
    payment: Any = run(client.create_payment_payload(accept))
    statuses: list[int] = []
    codes: list[str] = []
    lock = threading.Lock()

    def pay() -> None:
        status, headers, _ = get("/r", _header(payment))
        with lock:
            statuses.append(status)
            if status == 402:
                codes.append(_decode(headers, "payment-required")["error"])

    threads = [threading.Thread(target=pay) for _ in range(2)]
    threads[0].start()
    assert inside.wait(5)  # the first request is inside the handler, holding the channel
    threads[1].start()
    threads[1].join(5)
    release.set()
    for thread in threads:
        thread.join(5)
    assert sorted(statuses) == [200, 402] and codes == [errors.DUPLICATE_SETTLEMENT]
    record = run(_engine(world)._store.get(world.channel_id()))  # noqa: SLF001
    assert record is not None and record.charged_cumulative == 2 * PRICE


def test_django_gates_a_batch_route_through_url_resolution(world: World) -> None:
    # The other Django cases call the decorated view directly; this one goes
    # through the URLconf and the test client, so the request the shim reads is
    # the one Django builds.
    import types

    from django.http import HttpRequest, JsonResponse
    from django.test import Client, override_settings
    from django.urls import path

    import solana_pay_kit.django as pk

    @pk.require_batch(world.gate, config=world.config)
    def view(request: HttpRequest) -> Any:
        return JsonResponse({"ok": True})

    urlconf = types.ModuleType("batch_urls")
    urlconf.urlpatterns = [path("r", view)]  # type: ignore[attr-defined]
    with override_settings(ROOT_URLCONF=urlconf):
        client: Any = Client()  # the Django stubs type get() as its request
        unpaid: Any = client.get("/r")
        assert unpaid.status_code == 402
        assert _decode(dict(unpaid.headers), "payment-required")["accepts"][0]["scheme"] == "batch-settlement"
        world.lands_as_channel(deposit=10 * PRICE)
        accept = _engine(world).accepts_entries(world.gate, {})[0]
        payment: Any = run(_client(world).create_payment_payload(accept))
        paid: Any = client.get("/r", **{"HTTP_PAYMENT_SIGNATURE": _header(payment)["payment-signature"]})
    assert (paid.status_code, json.loads(paid.content)) == (200, {"ok": True})
    assert _decode(dict(paid.headers), "payment-response")["success"]


def test_django_renders_a_failed_handler_without_its_words(world: World) -> None:
    # The other Django cases call the view directly, so the 500 is the test's.
    # This one lets Django render it, with DEBUG off as a deployment has it.
    import types

    from django.http import HttpRequest, JsonResponse
    from django.test import Client, override_settings
    from django.urls import path

    import solana_pay_kit.django as pk

    @pk.require_batch(world.gate, config=world.config)
    def view(request: HttpRequest) -> Any:
        raise RuntimeError(_SECRET)
        return JsonResponse({"ok": True})  # pragma: no cover - unreachable

    urlconf = types.ModuleType("failing_urls")
    urlconf.urlpatterns = [path("r", view)]  # type: ignore[attr-defined]
    world.lands_as_channel(deposit=10 * PRICE)
    accept = _engine(world).accepts_entries(world.gate, {})[0]
    payment: Any = run(_client(world).create_payment_payload(accept))
    with override_settings(ROOT_URLCONF=urlconf, DEBUG=False):
        client: Any = Client(raise_request_exception=False)
        response: Any = client.get("/r", **{"HTTP_PAYMENT_SIGNATURE": _header(payment)["payment-signature"]})
    assert response.status_code == 500 and _SECRET.encode() not in response.content
    assert world.chain.sent == []  # nothing was broadcast for a request that failed


def test_the_shim_bridge_runs_a_coroutine_from_inside_a_running_loop() -> None:
    # The ASGI case: a synchronous view is called while a loop is running, so
    # the coroutine gets a fresh loop on a fresh thread, and an error from it
    # still reaches the caller as itself.
    async def value() -> str:
        return "ok"

    async def fails() -> str:
        raise StoreInvariantError("refused")

    async def inside() -> str:
        return run_blocking(value())

    assert run(inside()) == "ok"
    assert run_blocking(value()) == "ok"  # and with no loop running

    async def inside_failing() -> str:
        return run_blocking(fails())

    with pytest.raises(StoreInvariantError, match="refused"):
        run(inside_failing())


def test_flask_surfaces_a_store_invariant_instead_of_a_reused_coroutine(world: World) -> None:
    # StoreInvariantError subclasses RuntimeError. Catching RuntimeError around
    # asyncio.run and re-running the coroutine turned a refused write into
    # "cannot reuse already awaited coroutine", losing the real error.
    import flask

    from solana_pay_kit.flask import require_batch

    engine = _engine(world)

    async def refuse(channel_id: str, mutator: Any) -> Any:
        raise StoreInvariantError(f"channel {channel_id} deposit would drop")

    engine._store.update = refuse  # type: ignore[method-assign]  # noqa: SLF001
    app = flask.Flask("invariant")
    app.testing = True  # let the exception out instead of rendering a 500

    @app.get("/r")
    @require_batch(world.gate, config=world.config)
    def fixed() -> Any:  # pragma: no cover - the gate refuses before the handler
        return {"ok": True}

    accept = engine.accepts_entries(world.gate, {})[0]
    payment: Any = run(_client(world).create_payment_payload(accept))
    with pytest.raises(StoreInvariantError, match="deposit would drop"):
        app.test_client().get("/r", headers=_header(payment))


def test_two_equal_configs_share_one_engine(world: World) -> None:
    # The engine cache is keyed by the Config value, so a config rebuilt with
    # the same fields finds the same channel store rather than a fresh one.
    twin = world.config.model_copy()  # a new object, the same field values
    assert twin == world.config and twin is not world.config
    assert batch_engine(twin) is batch_engine(world.config)


def test_x402_batch_shares_the_engine_the_shims_use(world: World) -> None:
    worker = x402_batch(world.config)
    assert worker is _engine(world).redemption() and x402_batch() is worker  # the configured Config by default


def test_the_configured_batch_settings_reach_the_engine(monkeypatch: pytest.MonkeyPatch, world: World) -> None:
    config = configure(
        network="solana_localnet",
        preflight=False,
        operator=world.config.operator,
        rpc_url="http://127.0.0.1:1",
        x402=X402Config(batch=BatchSettlementConfig(min_deposit="$0.5")),
    )
    engine = X402BatchSettlement(config, recent_state_provider=lambda: (BLOCKHASH, SLOT))
    assert engine.accepts_entries(world.gate, {})[0]["extra"].get("minDeposit") == "500000"
    # config.py keeps its own copy of the scheme bounds so it never loads the protocol package.
    for delay in (MIN_WITHDRAW_DELAY_SECONDS, MAX_WITHDRAW_DELAY_SECONDS):
        assert BatchSettlementConfig(withdraw_delay=delay).effective_withdraw_delay() == delay
    for delay in (MIN_WITHDRAW_DELAY_SECONDS - 1, MAX_WITHDRAW_DELAY_SECONDS + 1):
        with pytest.raises(ConfigurationError):
            BatchSettlementConfig(withdraw_delay=delay)
