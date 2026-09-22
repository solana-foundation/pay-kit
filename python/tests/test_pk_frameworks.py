"""Framework-shim coverage (caveat #6): FastAPI, Flask, Django.

Each shim is exercised end to end through its native test client: a missing
proof yields a 402 carrying the challenge headers, and a valid proof attaches
the verified :class:`Payment` and echoes settlement headers. ``PayCore.process``
is stubbed at the class level so no adapter / RPC runs; the shims own only the
host-quirk translation these tests assert on.
"""

from __future__ import annotations

from typing import Any

import pytest

import solana_pay_kit._middleware as mw
from solana_pay_kit import MppConfig, Payment, Price, Protocol, Stablecoin, configure
from solana_pay_kit.config import reset
from solana_pay_kit.errors import PaymentRequiredError, ProtocolNotSupportedError

SECRET = "challenge-binding-secret-long-enough-for-hmac"


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
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


def _valid_payment():
    return Payment(
        protocol=Protocol.MPP,
        transaction="sig-abc",
        gate_name="report",
        settlement_headers={"x-payment-settlement-signature": "sig-abc"},
    )


def _stub_402():
    err = PaymentRequiredError("solana_pay_kit: payment required")
    err.challenge_headers = {"www-authenticate": "Payment realm=App", "content-type": "application/json"}  # type: ignore[attr-defined]
    err.body = {"error": "payment_required", "resource": "/report", "accepts": []}  # type: ignore[attr-defined]
    return err


def _patch_process(monkeypatch, *, paid: bool):
    async def fake_process(self, gate_ref, pricing, request):
        if paid:
            return _valid_payment()
        raise _stub_402()

    monkeypatch.setattr(mw.PayCore, "process", fake_process)


# ---------------------------------------------------------------------------
# FastAPI
# ---------------------------------------------------------------------------


def _fastapi_app():
    from fastapi import Depends, FastAPI

    import solana_pay_kit.fastapi as pk_fastapi

    app = FastAPI()
    pk_fastapi.install_exception_handler(app)

    dep = Depends(pk_fastapi.RequirePayment(Price.usd("0.10", Stablecoin.USDC)))

    @app.get("/report")
    async def report(payment=dep):
        return {"ok": True, "tx": payment.transaction}

    return app


def test_fastapi_402_on_missing_payment(monkeypatch):
    from starlette.testclient import TestClient

    _patch_process(monkeypatch, paid=False)
    client = TestClient(_fastapi_app())
    resp = client.get("/report")
    assert resp.status_code == 402
    assert resp.headers.get("www-authenticate") == "Payment realm=App"
    # FastAPI's HTTPException nests the rendered challenge body under "detail".
    assert resp.json()["detail"]["error"] == "payment_required"


def test_fastapi_success_attaches_payment_and_settlement(monkeypatch):
    from starlette.testclient import TestClient

    _patch_process(monkeypatch, paid=True)
    client = TestClient(_fastapi_app())
    resp = client.get("/report")
    assert resp.status_code == 200
    assert resp.json() == {"ok": True, "tx": "sig-abc"}
    assert resp.headers.get("x-payment-settlement-signature") == "sig-abc"


def test_fastapi_exception_handler_renders_pay_kit_error(monkeypatch):
    from fastapi import FastAPI
    from starlette.testclient import TestClient

    import solana_pay_kit.fastapi as pk_fastapi

    app = FastAPI()
    pk_fastapi.install_exception_handler(app)

    @app.get("/imperative")
    async def imperative():
        raise ProtocolNotSupportedError("nope")

    resp = TestClient(app, raise_server_exceptions=False).get("/imperative")
    assert resp.status_code == 406


def test_fastapi_payment_reexport():
    import solana_pay_kit.fastapi as pk_fastapi

    assert pk_fastapi.payment is not None
    assert pk_fastapi.Payment is Payment


def test_fastapi_install_bundles_cors_and_bare_dict_errors():
    from fastapi import FastAPI, HTTPException
    from starlette.testclient import TestClient

    import solana_pay_kit.fastapi as pk_fastapi

    app = FastAPI()
    pk_fastapi.install(app)

    @app.get("/guard")
    async def guard():
        raise HTTPException(status_code=400, detail={"error": "bad"})

    resp = TestClient(app, raise_server_exceptions=False).get("/guard", headers={"Origin": "https://x.test"})
    # Bare-dict HTTPException shape, not Starlette's {"detail": {...}} wrapper.
    assert resp.json() == {"error": "bad"}
    # CORS exposes the payment headers so a browser client can read them.
    exposed = resp.headers.get("access-control-expose-headers", "").lower()
    assert "www-authenticate" in exposed and "payment-receipt" in exposed


def test_fastapi_install_renders_pay_kit_error():
    from fastapi import FastAPI
    from starlette.testclient import TestClient

    import solana_pay_kit.fastapi as pk_fastapi

    app = FastAPI()
    pk_fastapi.install(app)

    @app.get("/imperative")
    async def imperative():
        raise ProtocolNotSupportedError("nope")

    resp = TestClient(app, raise_server_exceptions=False).get("/imperative")
    assert resp.status_code == 406


# ---------------------------------------------------------------------------
# Flask
# ---------------------------------------------------------------------------


def _flask_app():
    import flask

    import solana_pay_kit.flask as pk_flask

    app = flask.Flask(__name__)

    @app.get("/report")
    @pk_flask.require_payment(Price.usd("0.10", Stablecoin.USDC))
    def report():
        current = pk_flask.payment()
        assert current is not None
        return {"ok": True, "tx": current.transaction, "paid": pk_flask.is_paid("report")}

    return app


def test_flask_402_on_missing_payment(monkeypatch):
    _patch_process(monkeypatch, paid=False)
    client = _flask_app().test_client()
    resp = client.get("/report")
    assert resp.status_code == 402
    assert resp.headers.get("www-authenticate") == "Payment realm=App"
    assert resp.get_json()["error"] == "payment_required"


def test_flask_success_attaches_g_and_settlement(monkeypatch):
    _patch_process(monkeypatch, paid=True)
    client = _flask_app().test_client()
    resp = client.get("/report")
    assert resp.status_code == 200
    assert resp.get_json() == {"ok": True, "tx": "sig-abc", "paid": True}
    assert resp.headers.get("x-payment-settlement-signature") == "sig-abc"


def test_flask_non_402_pay_kit_error(monkeypatch):
    import flask

    import solana_pay_kit.flask as pk_flask

    async def boom(self, gate_ref, pricing, request):
        raise ProtocolNotSupportedError("unsupported")

    monkeypatch.setattr(mw.PayCore, "process", boom)

    app = flask.Flask(__name__)

    @app.get("/x")
    @pk_flask.require_payment(Price.usd("0.10", Stablecoin.USDC))
    def view():
        return {"ok": True}

    resp = app.test_client().get("/x")
    assert resp.status_code == 406


def test_flask_is_paid_without_payment():
    import flask

    import solana_pay_kit.flask as pk_flask

    app = flask.Flask(__name__)

    @app.get("/probe")
    def probe():
        return {"paid": pk_flask.is_paid(), "payment_none": pk_flask.payment() is None}

    resp = app.test_client().get("/probe")
    assert resp.get_json() == {"paid": False, "payment_none": True}


# ---------------------------------------------------------------------------
# Django
# ---------------------------------------------------------------------------


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


def test_django_decorator_402_on_missing_payment(monkeypatch):
    from django.test import RequestFactory

    import solana_pay_kit.django as pk_django

    _patch_process(monkeypatch, paid=False)

    @pk_django.require_payment(Price.usd("0.10", Stablecoin.USDC))
    def view(request):
        from django.http import JsonResponse

        return JsonResponse({"ok": True})

    resp = view(RequestFactory().get("/report"))
    assert resp.status_code == 402
    assert resp["www-authenticate"] == "Payment realm=App"


def test_django_decorator_success_attaches_and_settles(monkeypatch):
    from django.http import JsonResponse
    from django.test import RequestFactory

    import solana_pay_kit.django as pk_django

    _patch_process(monkeypatch, paid=True)

    @pk_django.require_payment(Price.usd("0.10", Stablecoin.USDC))
    def view(request):
        assert pk_django.payment(request) is not None
        return JsonResponse({"ok": True, "tx": request.payment.transaction})

    resp = view(RequestFactory().get("/report"))
    assert resp.status_code == 200
    assert resp["x-payment-settlement-signature"] == "sig-abc"


def test_django_decorator_non_402_error(monkeypatch):
    from django.test import RequestFactory

    import solana_pay_kit.django as pk_django

    async def boom(self, gate_ref, pricing, request):
        raise ProtocolNotSupportedError("unsupported")

    monkeypatch.setattr(mw.PayCore, "process", boom)

    @pk_django.require_payment(Price.usd("0.10", Stablecoin.USDC))
    def view(request):
        from django.http import JsonResponse

        return JsonResponse({"ok": True})

    resp = view(RequestFactory().get("/x"))
    assert resp.status_code == 406


def test_django_middleware_passthrough_when_no_gate(monkeypatch):
    from django.http import JsonResponse
    from django.test import RequestFactory

    import solana_pay_kit.django as pk_django

    def get_response(request):
        return JsonResponse({"passthrough": True})

    middleware = pk_django.PaymentMiddleware(get_response)
    resp = middleware(RequestFactory().get("/open"))
    assert resp.status_code == 200
    assert resp.content == b'{"passthrough": true}'


def test_django_middleware_gates_when_gate_attribute_set(monkeypatch):
    from django.http import JsonResponse
    from django.test import RequestFactory

    import solana_pay_kit.django as pk_django

    _patch_process(monkeypatch, paid=True)

    def get_response(request):
        return JsonResponse({"ok": True, "tx": request.payment.transaction})

    middleware = pk_django.PaymentMiddleware(get_response)
    request = RequestFactory().get("/report")
    request.paykit_gate = Price.usd("0.10", Stablecoin.USDC)  # type: ignore[attr-defined]
    resp = middleware(request)
    assert resp.status_code == 200
    assert resp["x-payment-settlement-signature"] == "sig-abc"


def test_django_middleware_402_when_unpaid(monkeypatch):
    from django.http import JsonResponse
    from django.test import RequestFactory

    import solana_pay_kit.django as pk_django

    _patch_process(monkeypatch, paid=False)

    def get_response(request):
        return JsonResponse({"ok": True})

    middleware = pk_django.PaymentMiddleware(get_response)
    request = RequestFactory().get("/report")
    request.paykit_gate = Price.usd("0.10", Stablecoin.USDC)  # type: ignore[attr-defined]
    resp = middleware(request)
    assert resp.status_code == 402


def test_require_subscription_402_then_200(monkeypatch):
    import asyncio

    from fastapi import Depends, FastAPI, HTTPException
    from starlette.testclient import TestClient

    from solana_pay_kit.fastapi import RequireSubscription, install_exception_handler
    from solana_pay_kit.protocols.mpp.client.subscription import (
        build_subscription_access_credential,
        build_subscription_activation,
    )
    from solana_pay_kit.protocols.mpp.core.headers import (
        format_authorization,
        parse_receipt,
        parse_www_authenticate,
    )
    from tests._subscription_fixtures import SUBSCRIBER
    from tests.test_subscription_server import Harness

    h = Harness(monkeypatch)
    app = FastAPI()
    install_exception_handler(app)

    @app.get("/feed")
    async def feed(receipt=Depends(RequireSubscription(h.server))):  # noqa: B008
        return {"ok": True}

    client = TestClient(app)
    denied = client.get("/feed")
    assert denied.status_code == 402
    assert denied.headers["cache-control"] == "no-store" and "payment-receipt" not in denied.headers
    challenge = parse_www_authenticate(denied.headers["www-authenticate"])
    activation = asyncio.run(build_subscription_activation(SUBSCRIBER, h.rpc, challenge))
    ok = client.get("/feed", headers={"authorization": format_authorization(activation.credential)})
    assert ok.status_code == 200 and ok.json() == {"ok": True}
    assert ok.headers["cache-control"] == "private"
    assert parse_receipt(ok.headers["payment-receipt"]).period_index == 0

    # The bearer proof grants the same period again without a second charge.
    access = format_authorization(
        build_subscription_access_credential(
            challenge.to_echo(), activation.subscription_delegation, activation.authentication
        )
    )
    reused = client.get("/feed", headers={"authorization": access})
    assert reused.status_code == 200 and len(h.rpc.sent) == 1
    assert parse_receipt(reused.headers["payment-receipt"]).period_index == 0

    @app.get("/boom")
    async def boom(receipt=Depends(RequireSubscription(h.server))):  # noqa: B008
        raise HTTPException(status_code=500, detail={"error": "handler"})

    # The subscriber paid: a handler that fails afterwards still returns the receipt.
    broke = TestClient(app, raise_server_exceptions=False).get("/boom", headers={"authorization": access})
    assert broke.status_code == 500 and broke.headers["cache-control"] == "private"
    assert parse_receipt(broke.headers["payment-receipt"]).period_index == 0


# --- subscription gate (flask / django) ------------------------------------


def _subscription_legs(monkeypatch):
    """A harness plus the three credentials a gated route sees: none, activation, bearer."""
    import asyncio

    from solana_pay_kit.protocols.mpp.client.subscription import (
        build_subscription_access_credential,
        build_subscription_activation,
    )
    from solana_pay_kit.protocols.mpp.core.headers import format_authorization
    from tests._subscription_fixtures import SUBSCRIBER
    from tests.test_subscription_server import Harness

    h = Harness(monkeypatch)
    challenge = asyncio.run(h.server.challenge())
    activation = asyncio.run(build_subscription_activation(SUBSCRIBER, h.rpc, challenge))
    access = build_subscription_access_credential(
        challenge.to_echo(), activation.subscription_delegation, activation.authentication
    )
    return h, format_authorization(activation.credential), format_authorization(access)


def test_flask_require_subscription_402_then_activation_then_proof(monkeypatch):
    import flask

    import solana_pay_kit.flask as pk_flask
    from solana_pay_kit.protocols.mpp.core.headers import parse_receipt

    h, activation_auth, access_auth = _subscription_legs(monkeypatch)
    app = flask.Flask(__name__)

    @app.get("/feed")
    @pk_flask.require_subscription(h.server)
    def feed():
        return {"ok": True}

    @app.get("/boom")
    @pk_flask.require_subscription(h.server)
    def boom():
        flask.abort(500)

    client = app.test_client()
    denied = client.get("/feed")
    assert denied.status_code == 402
    assert denied.headers["cache-control"] == "no-store"
    assert denied.headers["content-type"] == "application/problem+json"
    assert denied.headers["www-authenticate"].startswith("Payment ")

    activated = client.get("/feed", headers={"authorization": activation_auth})
    assert activated.status_code == 200 and activated.headers["cache-control"] == "private"
    assert parse_receipt(activated.headers["payment-receipt"]).period_index == 0

    reused = client.get("/feed", headers={"authorization": access_auth})
    assert reused.status_code == 200 and len(h.rpc.sent) == 1
    assert parse_receipt(reused.headers["payment-receipt"]).period_index == 0

    # The subscriber paid: a view that aborts afterwards still carries the receipt.
    broke = client.get("/boom", headers={"authorization": access_auth})
    assert broke.status_code == 500 and broke.headers["cache-control"] == "private"
    assert parse_receipt(broke.headers["payment-receipt"]).period_index == 0


def test_django_require_subscription_402_then_activation_then_proof(monkeypatch):
    from django.http import Http404, JsonResponse
    from django.test import RequestFactory

    import solana_pay_kit.django as pk_django
    from solana_pay_kit.protocols.mpp.core.headers import parse_receipt

    h, activation_auth, access_auth = _subscription_legs(monkeypatch)

    @pk_django.require_subscription(h.server)
    def feed(request):
        return JsonResponse({"ok": True})

    @pk_django.require_subscription(h.server)
    def boom(request):
        raise Http404("gone")

    factory = RequestFactory()
    denied = feed(factory.get("/feed"))
    assert denied.status_code == 402
    assert denied["cache-control"] == "no-store" and denied["content-type"] == "application/problem+json"
    assert denied["www-authenticate"].startswith("Payment ")

    activated = feed(factory.get("/feed", headers={"authorization": activation_auth}))
    assert activated.status_code == 200 and activated["cache-control"] == "private"
    assert parse_receipt(activated["payment-receipt"]).period_index == 0

    reused = feed(factory.get("/feed", headers={"authorization": access_auth}))
    assert reused.status_code == 200 and len(h.rpc.sent) == 1
    assert parse_receipt(reused["payment-receipt"]).period_index == 0

    broke = boom(factory.get("/boom", headers={"authorization": access_auth}))
    assert broke.status_code == 404 and broke["cache-control"] == "private"
    assert parse_receipt(broke["payment-receipt"]).period_index == 0


@pytest.mark.parametrize("framework", ["flask", "django"])
def test_require_subscription_renews_once_under_two_threads(monkeypatch, framework):
    """Two requests in their own loops and threads must produce one renewal charge.

    Each shim drives the gate with its own asyncio.run, so the store locks have
    to be loop-independent; the renewal claim is what keeps the second request
    from charging the period twice.
    """
    import asyncio
    import threading
    from concurrent.futures import ThreadPoolExecutor

    from solana_pay_kit.protocols.mpp.core.headers import parse_authorization
    from tests._subscription_fixtures import NOW, PERIOD_SECONDS

    h, activation_auth, access_auth = _subscription_legs(monkeypatch)
    asyncio.run(h.server.verify_credential(parse_authorization(activation_auth)))
    h.now = NOW + PERIOD_SECONDS + 10  # the period has rolled over: access renews

    if framework == "flask":
        import flask

        import solana_pay_kit.flask as pk_flask

        app = flask.Flask(__name__)

        @app.get("/feed")
        @pk_flask.require_subscription(h.server)
        def feed():
            return {"ok": True}

        client = app.test_client()

        def call() -> int:
            return client.get("/feed", headers={"authorization": access_auth}).status_code
    else:
        from django.http import JsonResponse
        from django.test import RequestFactory

        import solana_pay_kit.django as pk_django

        @pk_django.require_subscription(h.server)
        def view(request):
            return JsonResponse({"ok": True})

        factory = RequestFactory()

        def call() -> int:
            return view(factory.get("/feed", headers={"authorization": access_auth})).status_code

    start = threading.Barrier(2, timeout=30)

    def request() -> int:
        start.wait()  # both threads leave at the same instant
        return call()

    with ThreadPoolExecutor(max_workers=2) as pool:
        statuses = [future.result(timeout=30) for future in [pool.submit(request) for _ in range(2)]]

    # Exactly one renewal transaction, whatever the two requests were told.
    assert len(h.rpc.sent) == 2  # the activation plus one renewal
    assert statuses.count(200) >= 1 and set(statuses) <= {200, 402}


class _ChainServer:
    """A keep-alive JSON-RPC server serving the reads a subscription challenge makes.

    A real ``SolanaRpc`` against it pools a connection, which is what makes the
    second request in a second event loop meaningful.
    """

    def __init__(self, accounts: dict[str, tuple[bytes, str]], blockhash: str) -> None:
        import base64
        import http.server
        import json
        import threading

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler's name
                request = json.loads(self.rfile.read(int(self.headers.get("content-length", 0))) or b"{}")
                method, params = request.get("method"), request.get("params") or []
                if method == "getLatestBlockhash":
                    result: Any = {"context": {"slot": 1}, "value": {"blockhash": blockhash}}
                elif method == "getAccountInfo":
                    found = accounts.get(str(params[0]))
                    result = {
                        "context": {"slot": 1},
                        "value": None
                        if found is None
                        else {"data": [base64.b64encode(found[0]).decode(), "base64"], "owner": found[1]},
                    }
                else:
                    result = {"context": {"slot": 1}, "value": None}
                body = json.dumps({"jsonrpc": "2.0", "id": request.get("id", 1), "result": result}).encode()
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - the base signature
                return  # keep the test output clean

        self._server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self._server.server_address[1]}"
        threading.Thread(target=self._server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()


@pytest.mark.parametrize("framework", ["flask", "django"])
def test_require_subscription_serves_a_second_event_loop(monkeypatch, framework):
    """Each shim runs its own asyncio.run per request, so request two must still work.

    A shared SolanaRpc used to keep one httpx client (and its pooled socket)
    from the first loop, and the second request died on "Event loop is closed".
    """
    from solana_pay_kit._paycore.paymentchannels import find_associated_token_address
    from solana_pay_kit._paycore.rpc import SolanaRpc
    from solana_pay_kit._paycore.solana import TOKEN_PROGRAM
    from solana_pay_kit.protocols.mpp.core.headers import parse_www_authenticate
    from tests._subscription_fixtures import (
        BLOCKHASH,
        MINT,
        PLAN,
        PROGRAM_ID,
        RECIPIENT,
        SERVER,
        TOKEN,
        mint_bytes,
        plan_bytes,
    )
    from tests.test_subscription_server import Harness

    chain = _ChainServer(
        {
            str(PLAN): (
                plan_bytes(owner=SERVER.pubkey(), mint=MINT, destinations=[RECIPIENT], pullers=[SERVER.pubkey()]),
                PROGRAM_ID,
            ),
            str(MINT): (mint_bytes(), TOKEN_PROGRAM),
            str(find_associated_token_address(RECIPIENT, MINT, TOKEN)[0]): (bytes(165), TOKEN_PROGRAM),
        },
        BLOCKHASH,
    )
    try:
        h = Harness(monkeypatch, rpc=SolanaRpc(chain.url))

        if framework == "flask":
            import flask

            import solana_pay_kit.flask as pk_flask

            app = flask.Flask(__name__)

            @app.get("/feed")
            @pk_flask.require_subscription(h.server)
            def feed():
                return {"ok": True}

            client = app.test_client()
            answers = [client.get("/feed") for _ in range(2)]
            statuses = [answer.status_code for answer in answers]
            challenges = [answer.headers.get("www-authenticate", "") for answer in answers]
        else:
            from django.http import JsonResponse
            from django.test import RequestFactory

            import solana_pay_kit.django as pk_django

            @pk_django.require_subscription(h.server)
            def view(request):
                return JsonResponse({"ok": True})

            factory = RequestFactory()
            answers = [view(factory.get("/feed")) for _ in range(2)]
            statuses = [answer.status_code for answer in answers]
            challenges = [answer["www-authenticate"] for answer in answers]

        # Both requests answered with a challenge, and both reached the RPC: the
        # pre-fetched blockhash is only in the challenge when the fetch worked,
        # and a client stuck on the first loop cannot fetch it a second time.
        assert statuses == [402, 402]
        for header in challenges:
            request = parse_www_authenticate(header).decode_request()
            assert request["methodDetails"]["recentBlockhash"] == BLOCKHASH
    finally:
        chain.close()


@pytest.mark.parametrize("framework", ["flask", "django", "fastapi"])
def test_require_subscription_never_echoes_exception_text(monkeypatch, framework, caplog):
    """An exception's text is log material, never response material (CodeQL: information exposure)."""
    h, _activation_auth, access_auth = _subscription_legs(monkeypatch)

    async def boom(_credential):
        raise RuntimeError("secret detail")

    monkeypatch.setattr(h.server, "verify_credential", boom)
    headers = {"authorization": access_auth}

    if framework == "flask":
        import flask

        import solana_pay_kit.flask as pk_flask

        app = flask.Flask(__name__)

        @app.get("/feed")
        @pk_flask.require_subscription(h.server)
        def feed():
            return {"ok": True}

        answer = app.test_client().get("/feed", headers=headers)
        status, text = answer.status_code, answer.get_data(as_text=True)
    elif framework == "django":
        from django.http import JsonResponse
        from django.test import RequestFactory

        import solana_pay_kit.django as pk_django

        @pk_django.require_subscription(h.server)
        def view(request):
            return JsonResponse({"ok": True})

        answer = view(RequestFactory().get("/feed", headers=headers))
        status, text = answer.status_code, answer.content.decode()
    else:
        from fastapi import Depends, FastAPI
        from starlette.testclient import TestClient

        from solana_pay_kit.fastapi import RequireSubscription, install_exception_handler

        app = FastAPI()
        install_exception_handler(app)

        @app.get("/feed")
        async def served(_receipt=Depends(RequireSubscription(h.server))):  # noqa: B008
            return {"ok": True}

        answer = TestClient(app, raise_server_exceptions=False).get("/feed", headers=headers)
        status, text = answer.status_code, answer.text

    assert status == 402  # the gate still answers a challenge
    assert "secret detail" not in text


def test_django_subscription_view_error_is_not_echoed(monkeypatch, caplog):
    """A view's Http404 message is internal too: the body says only what happened."""
    import asyncio

    from django.http import Http404
    from django.test import RequestFactory

    import solana_pay_kit.django as pk_django
    from solana_pay_kit.protocols.mpp.core.headers import parse_authorization

    h, activation_auth, access_auth = _subscription_legs(monkeypatch)
    asyncio.run(h.server.verify_credential(parse_authorization(activation_auth)))

    @pk_django.require_subscription(h.server)
    def view(request):
        raise Http404("secret detail")

    answer = view(RequestFactory().get("/feed", headers={"authorization": access_auth}))
    assert answer.status_code == 404
    assert "secret detail" not in answer.content.decode()
    assert "payment-receipt" in {key.lower() for key in answer.headers}
