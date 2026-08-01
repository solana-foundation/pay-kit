"""Tests for the metered SSE streaming helpers.

Mirrors the ``#[cfg(test)] mod tests`` in
``rust/crates/mpp/src/client/http_stream.rs``: incremental SSE decoding across
split chunks, CRLF/comment/id/retry handling, invalid UTF-8 rejection, metered
event classification (metering/usage/message/done/[DONE]/other plus malformed
JSON), the metered session state machine (final usage amount overrides the
reserved amount but never the deliveryId, usage before the directive is
accepted, missing metering errors), the HTTP commit transport, and the
chunk-iterator stream wrapper.
"""

from __future__ import annotations

import json

import httpx
import pytest
from solders.keypair import Keypair  # type: ignore[import-untyped]
from solders.pubkey import Pubkey  # type: ignore[import-untyped]

from solana_pay_kit.protocols.mpp.client.http_stream import (
    HttpCommitTransport,
    MeteredSseSession,
    MeteredSseStream,
    SseDecoder,
    SseEvent,
    parse_metered_sse_event,
)
from solana_pay_kit.protocols.mpp.client.session import ActiveSession
from solana_pay_kit.protocols.mpp.client.session_consumer import SessionConsumer
from solana_pay_kit.protocols.mpp.intents.session import (
    DEFAULT_SESSION_EXPIRES_AT,
    CommitPayload,
    CommitReceipt,
    MeteringDirective,
)


class _RecordingTransport:
    """In-process commit transport that records payloads and echoes a receipt."""

    def __init__(self) -> None:
        self.commits: list[CommitPayload] = []

    def commit(self, directive: MeteringDirective, payload: CommitPayload) -> CommitReceipt:
        self.commits.append(payload)
        return CommitReceipt(
            delivery_id=directive.delivery_id,
            session_id=directive.session_id,
            amount=directive.amount,
            cumulative=payload.voucher.data.cumulative_amount,
            status="committed",
        )


def _consumer() -> SessionConsumer:
    channel = Pubkey.from_string("11111111111111111111111111111112")
    session = ActiveSession(channel, Keypair.from_seed(bytes([9] * 32)))
    return SessionConsumer(session, _RecordingTransport())


def _directive(session_id: str, delivery_id: str = "stream-1", amount: str = "1000") -> MeteringDirective:
    return MeteringDirective(
        delivery_id=delivery_id,
        session_id=session_id,
        amount=amount,
        currency="USDC",
        sequence=1,
        expires_at=DEFAULT_SESSION_EXPIRES_AT,
    )


def _event(event: str | None, data: str) -> SseEvent:
    return SseEvent(event=event, data=data)


# -- SseDecoder ----------------------------------------------------------------


def test_sse_decoder_handles_split_chunks() -> None:
    decoder = SseDecoder()
    assert decoder.push_chunk(b'event: message\ndata: {"delta"') == []
    events = decoder.push_chunk(b':"hi"}\n\n')
    assert events == [SseEvent(event="message", data='{"delta":"hi"}')]


def test_sse_decoder_handles_metadata_crlf_comments_and_finish() -> None:
    decoder = SseDecoder()
    events = decoder.push_chunk(b": keepalive\r\nid: evt-1\r\nretry: 250\r\ndata: hello\r\ndata: world\r\n\r\n")
    assert events == [SseEvent(event=None, data="hello\nworld", id="evt-1", retry=250)]

    # Unparseable retry values and unknown fields are ignored.
    assert decoder.push_chunk(b"retry: nope\nunknown\n\n") == []
    assert decoder.push_chunk(b"event: message\ndata: tail") == []
    events = decoder.finish()
    assert events == [SseEvent(event="message", data="tail")]
    assert decoder.finish() == []


def test_sse_decoder_rejects_invalid_utf8() -> None:
    with pytest.raises(ValueError, match="valid UTF-8"):
        SseDecoder().push_chunk(b"\xff")


# -- parse_metered_sse_event -----------------------------------------------------


def test_parse_metered_sse_events() -> None:
    directive = _directive("chan")
    parsed = parse_metered_sse_event(_event("mpp.metering", json.dumps(directive.to_dict())))
    assert parsed.kind == "metering"
    assert parsed.metering is not None
    assert parsed.metering.amount == "1000"

    parsed = parse_metered_sse_event(_event("message", '{"delta":"hello"}'))
    assert parsed.kind == "message"
    assert parsed.message == {"delta": "hello"}

    # The short event names are accepted too.
    assert parse_metered_sse_event(_event("metering", json.dumps(directive.to_dict()))).kind == "metering"


def test_parse_metered_sse_usage_done_other_and_errors() -> None:
    parsed = parse_metered_sse_event(_event("mpp.usage", '{"deliveryId":"stream-1","amount":"17"}'))
    assert parsed.kind == "usage"
    assert parsed.usage is not None
    assert parsed.usage.amount_base_units() == 17
    assert parse_metered_sse_event(_event("usage", '{"deliveryId":"d","amount":"1"}')).kind == "usage"

    assert parse_metered_sse_event(_event("done", "")).kind == "done"
    assert parse_metered_sse_event(_event(None, " [DONE] ")).kind == "done"
    other = parse_metered_sse_event(_event("trace", "ignored"))
    assert other.kind == "other"
    assert other.other == _event("trace", "ignored")

    with pytest.raises(ValueError, match="invalid mpp.metering event"):
        parse_metered_sse_event(_event("metering", "{"))
    with pytest.raises(ValueError, match="invalid mpp.usage event"):
        parse_metered_sse_event(_event("usage", "{"))
    with pytest.raises(ValueError, match="invalid SSE message event"):
        parse_metered_sse_event(_event(None, "{"))


# -- MeteredSseSession -----------------------------------------------------------


def test_metered_sse_ack_uses_final_usage_amount() -> None:
    consumer = _consumer()
    stream = MeteredSseSession(consumer)
    directive = _directive(consumer.session.channel_id_string)

    assert stream.accept_event(_event("mpp.metering", json.dumps(directive.to_dict()))) is None
    delta = stream.accept_event(_event("message", '{"delta":"hello"}'))
    assert delta == {"delta": "hello"}
    stream.accept_event(_event("mpp.usage", '{"deliveryId":"stream-1","amount":"425"}'))

    receipt = stream.ack()
    assert receipt.amount == "425"
    assert receipt.cumulative == "425"
    assert consumer.session.cumulative == 425


def test_metered_sse_ack_uses_reserved_amount_without_usage_and_tracks_done() -> None:
    consumer = _consumer()
    stream = MeteredSseSession(consumer)
    directive = _directive(consumer.session.channel_id_string)

    stream.accept_event(_event("mpp.metering", json.dumps(directive.to_dict())))
    assert not stream.is_done
    stream.accept_event(_event("done", ""))
    assert stream.is_done

    receipt = stream.ack()
    assert receipt.amount == "1000"
    assert receipt.cumulative == "1000"
    assert stream.consumer is consumer


def test_metered_sse_reports_missing_metering_and_usage_mismatch() -> None:
    consumer = _consumer()
    stream = MeteredSseSession(consumer)
    with pytest.raises(ValueError, match="mpp.metering"):
        stream.ack()

    stream = MeteredSseSession(consumer)
    directive = _directive(consumer.session.channel_id_string)
    stream.accept_event(_event("mpp.metering", json.dumps(directive.to_dict())))
    with pytest.raises(ValueError, match="does not match directive"):
        stream.accept_event(_event("mpp.usage", '{"deliveryId":"other","amount":"1"}'))


def test_metered_sse_usage_overrides_amount_never_delivery_id() -> None:
    consumer = _consumer()
    stream = MeteredSseSession(consumer)
    directive = _directive(consumer.session.channel_id_string)
    stream.accept_event(_event("mpp.metering", json.dumps(directive.to_dict())))
    stream.accept_event(_event("mpp.usage", '{"deliveryId":"stream-1","amount":"7"}'))
    receipt = stream.ack()
    assert receipt.amount == "7"
    transport = consumer.transport
    assert isinstance(transport, _RecordingTransport)
    assert transport.commits[0].delivery_id == "stream-1"


def test_metered_sse_accepts_usage_before_directive() -> None:
    # The usage event may arrive before the directive (rust state-machine
    # parity): it cannot be validated yet and still overrides the amount.
    consumer = _consumer()
    stream = MeteredSseSession(consumer)
    stream.accept_event(_event("mpp.usage", '{"deliveryId":"stream-1","amount":"33"}'))
    directive = _directive(consumer.session.channel_id_string)
    stream.accept_event(_event("mpp.metering", json.dumps(directive.to_dict())))
    receipt = stream.ack()
    assert receipt.amount == "33"


# -- HttpCommitTransport ---------------------------------------------------------


def _http_transport(handler: httpx.MockTransport, **kwargs: str) -> HttpCommitTransport:
    return HttpCommitTransport(client=httpx.Client(transport=handler), **kwargs)


def _commit_fixture() -> tuple[MeteringDirective, CommitPayload]:
    consumer = _consumer()
    directive = _directive(consumer.session.channel_id_string)
    voucher = consumer.session.prepare_increment(88)
    return directive, CommitPayload(delivery_id=directive.delivery_id, voucher=voucher)


def test_http_commit_transport_success_and_errors() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.path == "/commit":
            if request.headers.get("authorization") != "Bearer sdk-test":
                return httpx.Response(401, text="missing auth")
            body = json.loads(request.content)
            return httpx.Response(
                200,
                json={
                    "deliveryId": body["deliveryId"],
                    "sessionId": body["voucher"]["voucher"]["channelId"],
                    "amount": body["voucher"]["voucher"]["cumulativeAmount"],
                    "cumulative": body["voucher"]["voucher"]["cumulativeAmount"],
                    "status": "committed",
                },
            )
        if request.url.path == "/commit-error":
            return httpx.Response(500, text="commit failed")
        return httpx.Response(200, text="not json")

    directive, payload = _commit_fixture()
    transport = _http_transport(
        httpx.MockTransport(handler),
        default_commit_url="http://test/commit",
        authorization="Bearer sdk-test",
    )
    receipt = transport.commit(directive, payload)
    assert receipt.cumulative == "88"
    assert len(seen) == 1

    with pytest.raises(ValueError, match="missing commitUrl"):
        HttpCommitTransport(client=httpx.Client(transport=httpx.MockTransport(handler))).commit(directive, payload)

    with pytest.raises(ValueError, match="500"):
        _http_transport(httpx.MockTransport(handler), default_commit_url="http://test/commit-error").commit(
            directive, payload
        )

    with pytest.raises(ValueError, match="invalid commit receipt"):
        _http_transport(httpx.MockTransport(handler), default_commit_url="http://test/commit-invalid-json").commit(
            directive, payload
        )


def test_http_commit_transport_prefers_directive_commit_url() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/directive-url"
        body = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "deliveryId": body["deliveryId"],
                "sessionId": "chan",
                "amount": "88",
                "cumulative": body["voucher"]["voucher"]["cumulativeAmount"],
                "status": "committed",
            },
        )

    directive, payload = _commit_fixture()
    directive.commit_url = "http://test/directive-url"
    transport = _http_transport(httpx.MockTransport(handler), default_commit_url="http://test/default-url")
    assert transport.commit(directive, payload).cumulative == "88"


def test_http_commit_transport_surfaces_transport_failures() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom", request=request)

    directive, payload = _commit_fixture()
    transport = _http_transport(httpx.MockTransport(handler), default_commit_url="http://test/commit")
    with pytest.raises(ValueError, match="commit request failed"):
        transport.commit(directive, payload)


# -- MeteredSseStream ------------------------------------------------------------


def test_metered_sse_stream_reads_messages_and_ack_drains() -> None:
    consumer = _consumer()
    directive = _directive(consumer.session.channel_id_string)
    body = (
        f"event: mpp.metering\ndata: {json.dumps(directive.to_dict())}\n\n"
        'event: message\ndata: {"delta":"first"}\n\n'
        'event: message\ndata: {"delta":"second"}\n\n'
        'event: mpp.usage\ndata: {"deliveryId":"stream-1","amount":"275"}\n\n'
        "data: [DONE]"
    ).encode()
    chunks = [body[i : i + 17] for i in range(0, len(body), 17)]
    stream = MeteredSseStream(consumer, chunks)

    assert stream.next() == {"delta": "first"}
    receipt = stream.ack()
    assert receipt.amount == "275"
    assert receipt.cumulative == "275"
    assert consumer.session.cumulative == 275


def test_metered_sse_stream_iterates_and_returns_consumer() -> None:
    consumer = _consumer()
    directive = _directive(consumer.session.channel_id_string)
    body = (
        f"event: mpp.metering\ndata: {json.dumps(directive.to_dict())}\n\n"
        'event: message\ndata: {"delta":"only"}\n\ndata: [DONE]\n\n'
    ).encode()
    stream = MeteredSseStream(consumer, [body])
    assert list(stream) == [{"delta": "only"}]
    assert stream.next() is None
    assert stream.into_consumer() is consumer
