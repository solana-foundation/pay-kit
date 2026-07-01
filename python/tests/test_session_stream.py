"""Round-trips the server-side metered SSE writer through the client metered
SSE decoder (:class:`SseDecoder` + :func:`parse_metered_sse_event`), proving the
emitted frames carry the event names and payloads the metered session clients
consume.

Port of ``go/protocols/mpp/server/session_stream_test.go``.
"""

from __future__ import annotations

import io

import pytest

from solana_pay_kit.protocols.mpp.client.http_stream import (
    MeteredSseEvent,
    SseDecoder,
    parse_metered_sse_event,
)
from solana_pay_kit.protocols.mpp.intents.session import (
    DEFAULT_SESSION_EXPIRES_AT,
    MeteringDirective,
    MeteringUsage,
)
from solana_pay_kit.protocols.mpp.server.session_stream import (
    new_metered_stream,
    new_metered_stream_writer,
)


def decode_metered_events(raw: str) -> list[MeteredSseEvent]:
    decoder = SseDecoder()
    events = decoder.push_chunk(raw.encode("utf-8"))
    events.extend(decoder.finish())
    return [parse_metered_sse_event(event) for event in events]


class _Recorder:
    """Minimal duck-typed HTTP response: a mutable header mapping, a body
    buffer, and a flush flag, mirroring ``httptest.ResponseRecorder``."""

    def __init__(self) -> None:
        self.headers: dict[str, str] = {}
        self.body = io.StringIO()
        self.flushed = False

    def write(self, data: str) -> None:
        self.body.write(data)

    def flush(self) -> None:
        self.flushed = True

    def body_string(self) -> str:
        return self.body.getvalue()


def test_metered_stream_splits_multi_line_data() -> None:
    """Mirrors Go ``TestMeteredStreamSplitsMultiLineData``: one ``data:`` line
    per logical line, terminating blank line, and a clean decoder round-trip."""
    buffer = io.StringIO()
    stream = new_metered_stream_writer(buffer)
    stream.write_event("note", b"line-1\nline-2")
    raw = buffer.getvalue()
    assert raw == "event: note\ndata: line-1\ndata: line-2\n\n"

    decoder = SseDecoder()
    events = decoder.push_chunk(raw.encode("utf-8"))
    assert len(events) == 1
    assert events[0].data == "line-1\nline-2"


def test_metered_stream_rejects_empty_data() -> None:
    """Mirrors Go ``TestMeteredStreamRejectsEmptyData``: empty data is an error."""
    stream = new_metered_stream_writer(io.StringIO())
    with pytest.raises(ValueError, match="must not be empty"):
        stream.write_event("note", None)


def test_metered_stream_write_json_marshal_error() -> None:
    """Mirrors Go ``TestMeteredStreamWriteJSONMarshalError``: an unserializable
    payload surfaces a marshal error."""
    stream = new_metered_stream_writer(io.StringIO())
    with pytest.raises(TypeError):
        stream.write_json(lambda: None)


def test_metered_stream_done_event_variant() -> None:
    """Mirrors Go ``TestMeteredStreamDoneEventVariant``: an explicit ``done``
    event decodes to a single done event."""
    recorder = _Recorder()
    stream = new_metered_stream(recorder)
    stream.write_done_event()
    events = decode_metered_events(recorder.body_string())
    assert len(events) == 1
    assert events[0].kind == "done"


def test_metered_stream_round_trips_through_client_decoder() -> None:
    """Mirrors Go ``TestMeteredStreamRoundTripsThroughClientDecoder``: an
    envelope + usage + done sequence sets the SSE headers, flushes, and decodes
    to message / metering / usage / done through the client decoder."""
    recorder = _Recorder()
    stream = new_metered_stream(recorder)

    directive = MeteringDirective(
        delivery_id="session-1:1",
        session_id="session-1",
        amount="100",
        currency="USDC",
        sequence=1,
        expires_at=DEFAULT_SESSION_EXPIRES_AT,
    )
    usage = MeteringUsage(delivery_id="session-1:1", amount="80")

    stream.write_envelope({"chunk": "A payment channel "}, directive)
    stream.write_usage(usage)
    stream.write_done()

    assert recorder.headers["Content-Type"] == "text/event-stream"
    assert recorder.headers["Cache-Control"] == "no-cache"
    assert recorder.flushed

    events = decode_metered_events(recorder.body_string())
    assert len(events) == 4

    assert events[0].kind == "message"
    assert events[0].message == {"chunk": "A payment channel "}

    assert events[1].kind == "metering"
    assert events[1].metering is not None
    assert events[1].metering.delivery_id == directive.delivery_id
    assert events[1].metering.amount == "100"
    assert events[1].metering.sequence == 1

    assert events[2].kind == "usage"
    assert events[2].usage is not None
    assert events[2].usage.amount == "80"

    assert events[3].kind == "done"
