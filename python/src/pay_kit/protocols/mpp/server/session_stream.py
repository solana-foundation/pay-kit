"""Server-side metered SSE stream writer.

Emits the Server-Sent Event frames the metered session clients decode:
``mpp.metering`` directives, ``mpp.usage`` final-usage events, plain data
payload messages, and the terminal ``[DONE]`` sentinel. The event names are
canonical: they are the ones the SDK session clients parse (this package's
:class:`~pay_kit.protocols.mpp.client.http_stream.SseDecoder` and
:func:`~pay_kit.protocols.mpp.client.http_stream.parse_metered_sse_event`
among them).

The stream writes to any object exposing a ``write`` method and flushes any
that also expose a ``flush`` method, the duck-typed shape the rest of the
Python server surface uses for HTTP responses.
"""

from __future__ import annotations

import json
from typing import Any, Protocol, runtime_checkable

from pay_kit.protocols.mpp.intents.session import MeteringDirective, MeteringUsage

__all__ = [
    "DONE_SENTINEL",
    "MeteredStream",
    "new_metered_stream",
    "new_metered_stream_writer",
]

# DONE_SENTINEL is the terminal data-only message recognized by the metered SSE
# decoders alongside the ``done`` event name.
DONE_SENTINEL = "[DONE]"


@runtime_checkable
class _Writer(Protocol):
    """Anything that accepts encoded SSE frames via ``write``."""

    def write(self, data: str, /) -> Any: ...


@runtime_checkable
class _HttpResponse(Protocol):
    """A duck-typed HTTP response: a mutable ``headers`` mapping and ``write``."""

    headers: Any

    def write(self, data: str, /) -> Any: ...


class MeteredStream:
    """Writes metered Server-Sent Events to a writer.

    Build with :func:`new_metered_stream` (HTTP responses) or
    :func:`new_metered_stream_writer` (raw writers). Every write flushes when
    the underlying writer supports it so chunks reach the client as they are
    produced.
    """

    def __init__(self, writer: _Writer, flush: bool = False) -> None:
        """Wrap ``writer``. When ``flush`` is true and the writer exposes a
        ``flush`` method, that method is called after every frame."""
        self._writer = writer
        self._flush = flush and callable(getattr(writer, "flush", None))

    def write_event(self, event: str, data: bytes | None) -> None:
        """Write one SSE frame with an explicit event name.

        Empty event names emit a default (message) frame. ``data`` must not be
        empty; multi-line data is split into one ``data:`` line per line per the
        SSE format.
        """
        if not data:
            raise ValueError("SSE event data must not be empty")
        frame = ""
        if event:
            frame = "event: " + event + "\n"
        for line in data.split(b"\n"):
            frame += "data: " + line.decode("utf-8") + "\n"
        frame += "\n"
        self._writer.write(frame)
        if self._flush:
            self._writer.flush()  # type: ignore[attr-defined]

    def write_json(self, value: Any) -> None:
        """Write a default (message) frame whose data is the JSON encoding of
        ``value``. Use for application payload chunks."""
        data = json.dumps(value, separators=(",", ":")).encode("utf-8")
        self.write_event("", data)

    def write_metering(self, directive: MeteringDirective) -> None:
        """Emit an ``mpp.metering`` event carrying the metering directive the
        client must commit after processing the paired payload."""
        data = json.dumps(directive.to_dict(), separators=(",", ":")).encode("utf-8")
        self.write_event("mpp.metering", data)

    def write_usage(self, usage: MeteringUsage) -> None:
        """Emit an ``mpp.usage`` event reporting the final amount owed for a
        streamed delivery. The amount must not exceed the amount reserved by the
        original directive."""
        data = json.dumps(usage.to_dict(), separators=(",", ":")).encode("utf-8")
        self.write_event("mpp.usage", data)

    def write_envelope(self, payload: Any, directive: MeteringDirective) -> None:
        """Emit the payload as a default data frame followed by its
        ``mpp.metering`` directive, the pairing the metered session consumers
        expect."""
        self.write_json(payload)
        self.write_metering(directive)

    def write_done(self) -> None:
        """Emit the terminal ``[DONE]`` sentinel message."""
        self.write_event("", DONE_SENTINEL.encode("utf-8"))

    def write_done_event(self) -> None:
        """Emit an explicit ``done`` event, the alternative terminal frame the
        decoders accept."""
        self.write_event("done", DONE_SENTINEL.encode("utf-8"))


def new_metered_stream(response: _HttpResponse) -> MeteredStream:
    """Prepare ``response`` for Server-Sent Events (Content-Type
    ``text/event-stream``, no caching) and return the stream writer.

    The response does not need to support flushing, but streaming is only
    incremental when it exposes a ``flush`` method.
    """
    response.headers["Content-Type"] = "text/event-stream"
    response.headers["Cache-Control"] = "no-cache"
    response.headers["Connection"] = "keep-alive"
    return MeteredStream(response, flush=True)


def new_metered_stream_writer(writer: _Writer) -> MeteredStream:
    """Wrap a raw writer (no header handling) for transports other than HTTP."""
    return MeteredStream(writer)
