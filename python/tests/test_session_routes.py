"""Metering side-channel route coverage.

Ports the ``Routes()`` behaviors from ``go/protocols/mpp/server/session_routes.go``
exercised by ``session_method_test.go`` (``TestSessionRoutesValidation``,
``TestSessionRoutesCommitReplayStatus``, ``TestSessionRoutesShareStoreWithMethod``,
``TestSessionCommitForReservedDelivery``).

The Go ``Routes()`` is a method on the HTTP-facing ``Session``; the routes only
ever touch the lower-level ``SessionServer`` (``s.core``) plus an idle-close
``touch`` hook, so this port builds the two handlers over a ``SessionServer``
directly. Handlers are framework-agnostic: each takes the HTTP method and the
raw request body and returns a :class:`RouteResponse` (status + JSON-ready
body), mirroring the existing dict-based server modules.
"""

from __future__ import annotations

import json
import time

from solders.keypair import Keypair  # type: ignore[import-untyped]

from solana_pay_kit.protocols.mpp.intents.session import SignedVoucher, VoucherData
from solana_pay_kit.protocols.mpp.server.session import SessionConfig, SessionServer
from solana_pay_kit.protocols.mpp.server.session_routes import session_routes
from solana_pay_kit.protocols.mpp.server.session_store import MemoryChannelStore

SESSION_TEST_RECIPIENT = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY"


def _config() -> SessionConfig:
    return SessionConfig(
        operator=SESSION_TEST_RECIPIENT,
        recipient=SESSION_TEST_RECIPIENT,
        max_cap=10_000_000,
        currency="USDC",
        decimals=6,
        network="localnet",
        modes=["push"],
    )


class _Signer:
    def __init__(self, seed: int = 7) -> None:
        self._kp = Keypair.from_seed(bytes([seed] * 32))

    def address(self) -> str:
        return str(self._kp.pubkey())

    def sign_voucher(self, channel_id: str, cumulative: int, expires_at: int) -> SignedVoucher:
        data = VoucherData(channel_id=channel_id, cumulative=str(cumulative), expires_at=expires_at)
        return SignedVoucher(data=data, signature=str(self._kp.sign_message(data.message_bytes())))


def _far_future() -> int:
    return int(time.time()) + 3600


async def _open(server: SessionServer) -> tuple[_Signer, str]:
    from solana_pay_kit.protocols.mpp.intents.session import OpenPayload

    signer = _Signer()
    channel_id = str(Keypair().pubkey())
    await server.process_open(OpenPayload.push(channel_id, "1000", signer.address(), "dummy_tx_sig"))
    return signer, channel_id


def _body(obj: dict) -> str:
    return json.dumps(obj)


# -- deliveries route --


async def test_deliveries_requires_post() -> None:
    """Mirrors the GET deliveries arm of TestSessionRoutesValidation."""
    routes = session_routes(SessionServer(_config(), MemoryChannelStore()))
    resp = await routes.deliveries("GET", _body({"amount": "10", "sessionId": "x"}))
    assert resp.status == 405


async def test_deliveries_invalid_body_rejected() -> None:
    """Mirrors the invalid-body arm of TestSessionRoutesValidation."""
    routes = session_routes(SessionServer(_config(), MemoryChannelStore()))
    resp = await routes.deliveries("POST", "not-json")
    assert resp.status == 400
    assert resp.body["error"] == "invalid request body"


async def test_deliveries_missing_session_id_rejected() -> None:
    """Mirrors the missing-sessionId arm of TestSessionRoutesValidation."""
    routes = session_routes(SessionServer(_config(), MemoryChannelStore()))
    resp = await routes.deliveries("POST", _body({"amount": "10"}))
    assert resp.status == 400
    assert resp.body["error"] == "sessionId required"


async def test_deliveries_non_numeric_amount_rejected() -> None:
    """Mirrors the non-numeric amount arm of TestSessionRoutesValidation."""
    routes = session_routes(SessionServer(_config(), MemoryChannelStore()))
    resp = await routes.deliveries("POST", _body({"amount": "ten", "sessionId": "x"}))
    assert resp.status == 400


async def test_deliveries_zero_amount_rejected() -> None:
    """Mirrors the zero-amount arm of TestSessionRoutesValidation."""
    routes = session_routes(SessionServer(_config(), MemoryChannelStore()))
    resp = await routes.deliveries("POST", _body({"amount": "0", "sessionId": "x"}))
    assert resp.status == 400
    assert resp.body["error"] == "amount must be positive"


async def test_deliveries_unknown_channel_rejected() -> None:
    """Mirrors the unknown-channel arm of TestSessionRoutesValidation."""
    routes = session_routes(SessionServer(_config(), MemoryChannelStore()))
    resp = await routes.deliveries("POST", _body({"amount": "10", "sessionId": "ghost"}))
    assert resp.status == 400


async def test_deliveries_reserves_and_shares_store() -> None:
    """Mirrors TestSessionRoutesShareStoreWithMethod / TestSessionCommitForReservedDelivery reserve."""
    server = SessionServer(_config(), MemoryChannelStore())
    _, channel_id = await _open(server)
    routes = session_routes(server)

    resp = await routes.deliveries("POST", _body({"amount": "200", "sessionId": channel_id}))
    assert resp.status == 200
    assert resp.body["deliveryId"] == f"{channel_id}:1"
    assert resp.body["sequence"] == 1
    assert resp.body["currency"] == "USDC"
    assert resp.body["amount"] == "200"


async def test_deliveries_touches_session() -> None:
    """The Deliveries handler calls touch(sessionId) after a successful reserve."""
    server = SessionServer(_config(), MemoryChannelStore())
    _, channel_id = await _open(server)
    touched: list[str] = []
    routes = session_routes(server, touch=touched.append)

    await routes.deliveries("POST", _body({"amount": "100", "sessionId": channel_id}))
    assert touched == [channel_id]


# -- commit route --


async def test_commit_requires_post() -> None:
    """Mirrors the GET commit arm of TestSessionRoutesValidation."""
    routes = session_routes(SessionServer(_config(), MemoryChannelStore()))
    resp = await routes.commit("GET", _body({}))
    assert resp.status == 405


async def test_commit_invalid_body_rejected() -> None:
    """Mirrors the invalid-body commit arm (session_method_branch_test.go)."""
    routes = session_routes(SessionServer(_config(), MemoryChannelStore()))
    resp = await routes.commit("POST", "not-json")
    assert resp.status == 400
    assert resp.body["error"] == "invalid request body"


async def test_commit_missing_delivery_id_rejected() -> None:
    """Mirrors the missing-deliveryId arm of TestSessionRoutesValidation."""
    routes = session_routes(SessionServer(_config(), MemoryChannelStore()))
    resp = await routes.commit("POST", _body({"voucher": {}}))
    assert resp.status == 400
    assert resp.body["error"] == "deliveryId required"


async def test_commit_missing_voucher_rejected() -> None:
    """Mirrors the missing-voucher arm of TestSessionRoutesValidation."""
    routes = session_routes(SessionServer(_config(), MemoryChannelStore()))
    resp = await routes.commit("POST", _body({"deliveryId": "d-1"}))
    assert resp.status == 400
    assert resp.body["error"] == "voucher required"


async def test_commit_replay_status() -> None:
    """Mirrors TestSessionRoutesCommitReplayStatus."""
    server = SessionServer(_config(), MemoryChannelStore())
    signer, channel_id = await _open(server)
    routes = session_routes(server)

    reserve = await routes.deliveries("POST", _body({"amount": "50", "sessionId": channel_id}))
    delivery_id = reserve.body["deliveryId"]
    voucher = signer.sign_voucher(channel_id, 50, _far_future())

    commit_body = _body({"deliveryId": delivery_id, "voucher": voucher.to_dict()})
    first = await routes.commit("POST", commit_body)
    assert first.status == 200
    assert first.body["status"] == "committed"
    assert first.body["amount"] == "50"

    replay = await routes.commit("POST", commit_body)
    assert replay.status == 200
    assert replay.body["status"] == "replayed"


async def test_commit_touches_session() -> None:
    """The Commit handler calls touch(receipt.sessionId) after a successful commit."""
    server = SessionServer(_config(), MemoryChannelStore())
    signer, channel_id = await _open(server)
    touched: list[str] = []
    routes = session_routes(server, touch=touched.append)

    reserve = await routes.deliveries("POST", _body({"amount": "50", "sessionId": channel_id}))
    delivery_id = reserve.body["deliveryId"]
    voucher = signer.sign_voucher(channel_id, 50, _far_future())
    await routes.commit("POST", _body({"deliveryId": delivery_id, "voucher": voucher.to_dict()}))
    assert touched[-1] == channel_id


# -- strict decode parity --
#
# Go decodes the request body into a typed struct (sessionDeliveryRequestBody /
# sessionCommitRequestBody) before any processing. A JSON value whose type does
# not match the Go field type fails json.Decode up front, which the handlers map
# to HTTP 400 "invalid request body". The Python port must reject the same
# mismatches at the decode layer, before any store access. Each test below
# pins a divergence where Python was previously too lenient.


async def test_deliveries_expires_at_float_rejected() -> None:
    """Go expiresAt is int64; a JSON float fails json.Decode -> 400 invalid body."""
    routes = session_routes(SessionServer(_config(), MemoryChannelStore()))
    resp = await routes.deliveries("POST", _body({"amount": "10", "sessionId": "x", "expiresAt": 10.5}))
    assert resp.status == 400
    assert resp.body["error"] == "invalid request body"


async def test_deliveries_expires_at_numeric_string_rejected() -> None:
    """Go expiresAt is int64; a numeric JSON string fails json.Decode -> 400 invalid body."""
    routes = session_routes(SessionServer(_config(), MemoryChannelStore()))
    resp = await routes.deliveries("POST", _body({"amount": "10", "sessionId": "x", "expiresAt": "10"}))
    assert resp.status == 400
    assert resp.body["error"] == "invalid request body"


async def test_deliveries_expires_at_non_numeric_string_rejected() -> None:
    """Go expiresAt is int64; a non-numeric JSON string fails json.Decode -> 400 invalid body,
    not a raw ValueError from int()."""
    routes = session_routes(SessionServer(_config(), MemoryChannelStore()))
    resp = await routes.deliveries("POST", _body({"amount": "10", "sessionId": "x", "expiresAt": "soon"}))
    assert resp.status == 400
    assert resp.body["error"] == "invalid request body"


async def test_deliveries_amount_number_rejected() -> None:
    """Go amount is string; a JSON number fails json.Decode -> 400 invalid body."""
    routes = session_routes(SessionServer(_config(), MemoryChannelStore()))
    resp = await routes.deliveries("POST", _body({"amount": 10, "sessionId": "x"}))
    assert resp.status == 400
    assert resp.body["error"] == "invalid request body"


async def test_deliveries_session_id_number_rejected() -> None:
    """Go sessionId is string; a JSON number fails json.Decode -> 400 invalid body,
    instead of passing the truthiness guard and hitting the store."""
    routes = session_routes(SessionServer(_config(), MemoryChannelStore()))
    resp = await routes.deliveries("POST", _body({"amount": "10", "sessionId": 5}))
    assert resp.status == 400
    assert resp.body["error"] == "invalid request body"


async def test_deliveries_delivery_id_number_rejected() -> None:
    """Go deliveryId is string; a JSON number fails json.Decode -> 400 invalid body."""
    routes = session_routes(SessionServer(_config(), MemoryChannelStore()))
    resp = await routes.deliveries("POST", _body({"amount": "10", "sessionId": "x", "deliveryId": 7}))
    assert resp.status == 400
    assert resp.body["error"] == "invalid request body"


async def test_commit_delivery_id_number_rejected() -> None:
    """Go commit deliveryId is string; a JSON number fails json.Decode -> 400 invalid body."""
    routes = session_routes(SessionServer(_config(), MemoryChannelStore()))
    resp = await routes.commit("POST", _body({"deliveryId": 7, "voucher": {}}))
    assert resp.status == 400
    assert resp.body["error"] == "invalid request body"


async def test_deliveries_expires_at_integer_accepted() -> None:
    """A JSON integer expiresAt still decodes (Go int64 accepts integers)."""
    server = SessionServer(_config(), MemoryChannelStore())
    _, channel_id = await _open(server)
    routes = session_routes(server)
    resp = await routes.deliveries(
        "POST", _body({"amount": "200", "sessionId": channel_id, "expiresAt": _far_future()})
    )
    assert resp.status == 200


async def test_commit_non_dict_voucher_rejected() -> None:
    """A non-dict voucher makes SignedVoucher.from_dict raise AttributeError; the
    handler must catch it as 400, matching Go's strict json.Decode (not a 500)."""
    routes = session_routes(SessionServer(_config(), MemoryChannelStore()))
    for bad in ("a-string", [1, 2], 7):
        resp = await routes.commit("POST", _body({"deliveryId": "d-1", "voucher": bad}))
        assert resp.status == 400
        assert resp.body["error"] == "invalid request body"


async def test_commit_non_numeric_expires_at_rejected() -> None:
    """A non-numeric voucher.data.expiresAt makes VoucherData.from_dict raise
    ValueError; it must surface as 400, not escape as a 500."""
    routes = session_routes(SessionServer(_config(), MemoryChannelStore()))
    voucher = {"data": {"channelId": "x", "cumulativeAmount": "1", "expiresAt": "2025-01-01"}, "signature": "s"}
    resp = await routes.commit("POST", _body({"deliveryId": "d-1", "voucher": voucher}))
    assert resp.status == 400
    assert resp.body["error"] == "invalid request body"


async def test_commit_non_dict_voucher_data_rejected() -> None:
    """voucher is a dict but voucher.data is a string/list: VoucherData.from_dict
    calls .get on it and raises AttributeError, which must surface as 400 (not a
    500), matching Go's strict json.Decode."""
    routes = session_routes(SessionServer(_config(), MemoryChannelStore()))
    for bad_data in ("a-string", [1, 2]):
        voucher = {"data": bad_data, "signature": "x"}
        resp = await routes.commit("POST", _body({"deliveryId": "d-1", "voucher": voucher}))
        assert resp.status == 400
        assert resp.body["error"] == "invalid request body"
