"""HTTP streaming helpers for metered sessions.

LLM APIs commonly stream responses over Server-Sent Events (SSE) or chunked
HTTP. This module keeps the parser transport-neutral (an incremental
:class:`SseDecoder` plus the metered event state machine), then layers a small
httpx adapter on top for applications that want batteries included.

Two metering invariants are enforced while folding a stream: a usage event's
``deliveryId`` must match the live metering directive, and a usage event may
override only the committed amount, never the ``deliveryId``.
"""

from __future__ import annotations

import contextlib
import json
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, replace
from typing import Any, Literal

from solana_pay_kit.protocols.mpp.client.session_consumer import SessionConsumer
from solana_pay_kit.protocols.mpp.intents.session import (
    CommitPayload,
    CommitReceipt,
    MeteringDirective,
    MeteringUsage,
)

__all__ = [
    "SseEvent",
    "SseDecoder",
    "MeteredSseEvent",
    "parse_metered_sse_event",
    "MeteredSseSession",
    "MeteredSseStream",
    "HttpCommitTransport",
]


@dataclass
class SseEvent:
    """A parsed Server-Sent Event frame."""

    #: Event name from the ``event:`` field, or ``None`` for a default message.
    event: str | None = None
    #: Concatenated ``data:`` field payload (lines joined with newlines).
    data: str = ""
    #: Last-event-id from the ``id:`` field, if present.
    id: str | None = None
    #: Reconnection delay in milliseconds from the ``retry:`` field, if present.
    retry: int | None = None


class SseDecoder:
    """Incremental SSE decoder.

    Feed raw HTTP chunks with :meth:`push_chunk`. It returns all complete
    events decoded from that chunk and retains partial data internally.
    """

    def __init__(self) -> None:
        """Create an empty decoder."""
        self._buffer = ""
        self._current = SseEvent()

    def push_chunk(self, chunk: bytes) -> list[SseEvent]:
        """Decode a raw chunk, returning every event completed by it."""
        try:
            text = chunk.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError(f"SSE chunk is not valid UTF-8: {exc}") from exc
        self._buffer += text

        events: list[SseEvent] = []
        while True:
            index = self._buffer.find("\n")
            if index == -1:
                break
            line = self._buffer[:index]
            self._buffer = self._buffer[index + 1 :]
            if line.endswith("\r"):
                line = line[:-1]
            event = self._process_line(line)
            if event is not None:
                events.append(event)
        return events

    def finish(self) -> list[SseEvent]:
        """Flush an incomplete final event, if any, at EOF."""
        events: list[SseEvent] = []
        if self._buffer:
            line = self._buffer
            self._buffer = ""
            event = self._process_line(line.rstrip("\r"))
            if event is not None:
                events.append(event)
        event = self._dispatch_current()
        if event is not None:
            events.append(event)
        return events

    def _process_line(self, line: str) -> SseEvent | None:
        if not line:
            return self._dispatch_current()
        if line.startswith(":"):
            return None

        if ":" in line:
            field_name, value = line.split(":", 1)
            if value.startswith(" "):
                value = value[1:]
        else:
            field_name, value = line, ""

        if field_name == "event":
            self._current.event = value
        elif field_name == "data":
            if self._current.data:
                self._current.data += "\n"
            self._current.data += value
        elif field_name == "id":
            self._current.id = value
        elif field_name == "retry":
            with contextlib.suppress(ValueError):
                self._current.retry = int(value, 10)
        return None

    def _dispatch_current(self) -> SseEvent | None:
        current = self._current
        if current.event is None and not current.data and current.id is None and current.retry is None:
            return None
        self._current = SseEvent()
        return current


@dataclass
class MeteredSseEvent:
    """A parsed metered SSE event, tagged by ``kind``.

    Exactly one payload field is set for the matching ``kind``; a ``done`` event
    carries no payload.
    """

    #: Which kind of event this is, selecting the populated payload field.
    kind: Literal["metering", "usage", "message", "done", "other"]
    #: Metering directive payload, set when ``kind`` is ``"metering"``.
    metering: MeteringDirective | None = None
    #: Usage payload, set when ``kind`` is ``"usage"``.
    usage: MeteringUsage | None = None
    #: Decoded JSON message payload, set when ``kind`` is ``"message"``.
    message: Any = None
    #: Raw passthrough frame, set when ``kind`` is ``"other"``.
    other: SseEvent | None = None


def parse_metered_sse_event(event: SseEvent) -> MeteredSseEvent:
    """Classify an SSE frame as metering, usage, message, done, or other.

    Recognizes the canonical event names ``mpp.metering``/``metering`` and
    ``mpp.usage``/``usage``, the ``done`` event, and the ``[DONE]`` sentinel on
    a plain message. Message payloads are decoded as JSON values; any other
    event name passes through unchanged as an ``"other"`` frame.
    """
    event_name = event.event if event.event is not None else "message"
    if event_name in ("mpp.metering", "metering"):
        try:
            directive = MeteringDirective.from_dict(json.loads(event.data))
        except (ValueError, TypeError, AttributeError) as exc:
            raise ValueError(f"invalid mpp.metering event: {exc}") from exc
        return MeteredSseEvent(kind="metering", metering=directive)
    if event_name in ("mpp.usage", "usage"):
        try:
            usage = MeteringUsage.from_dict(json.loads(event.data))
        except (ValueError, TypeError, AttributeError) as exc:
            raise ValueError(f"invalid mpp.usage event: {exc}") from exc
        return MeteredSseEvent(kind="usage", usage=usage)
    if event_name == "done":
        return MeteredSseEvent(kind="done")
    if event_name == "message":
        if event.data.strip() == "[DONE]":
            return MeteredSseEvent(kind="done")
        try:
            message = json.loads(event.data)
        except ValueError as exc:
            raise ValueError(f"invalid SSE message event: {exc}") from exc
        return MeteredSseEvent(kind="message", message=message)
    return MeteredSseEvent(kind="other", other=event)


class _MeteredStreamState:
    """Directive/usage/done bookkeeping shared by the stream wrappers.

    Tracks the live metering directive, the final usage amount once one
    arrives, and whether the stream has ended.
    """

    def __init__(self) -> None:
        self.directive: MeteringDirective | None = None
        self.final_amount: int | None = None
        self.done = False

    def apply_event(self, event: SseEvent) -> Any | None:
        """Fold one SSE frame into the state, returning a message payload."""
        parsed = parse_metered_sse_event(event)
        if parsed.kind == "metering":
            self.directive = parsed.metering
            return None
        if parsed.kind == "usage":
            usage = parsed.usage
            if usage is None:  # pragma: no cover - parse always sets it
                raise ValueError("invalid mpp.usage event: missing payload")
            if self.directive is not None and usage.delivery_id != self.directive.delivery_id:
                raise ValueError(
                    f"usage delivery {usage.delivery_id} does not match directive {self.directive.delivery_id}"
                )
            self.final_amount = usage.amount_base_units()
            return None
        if parsed.kind == "message":
            return parsed.message
        if parsed.kind == "done":
            self.done = True
        return None

    def directive_for_commit(self) -> MeteringDirective:
        """Return the directive to commit, with usage overriding the amount.

        Usage overrides only the amount, never the ``deliveryId``.
        """
        if self.directive is None:
            raise ValueError("stream did not include mpp.metering event")
        if self.final_amount is not None:
            return replace(self.directive, amount=str(self.final_amount))
        return self.directive


class MeteredSseSession:
    """Borrowed state machine for a metered SSE stream.

    Feed decoded frames with :meth:`accept_event`; call :meth:`ack` after the
    stream ends to sign and commit a voucher for the metered amount (the
    reserved directive amount, or the final usage amount when one arrived).
    This wrapper does not own its frame source: the caller decodes and feeds
    frames in.
    """

    def __init__(self, consumer: SessionConsumer) -> None:
        """Wrap a session consumer with fresh metering state."""
        self._consumer = consumer
        self._state = _MeteredStreamState()

    @property
    def consumer(self) -> SessionConsumer:
        """The wrapped consumer."""
        return self._consumer

    def accept_event(self, event: SseEvent) -> Any | None:
        """Fold one SSE frame in, returning a message payload when present."""
        return self._state.apply_event(event)

    @property
    def is_done(self) -> bool:
        """True once a ``done`` event or ``[DONE]`` sentinel arrived."""
        return self._state.done

    def ack(self) -> CommitReceipt:
        """Sign and commit a voucher for the streamed delivery."""
        directive = self._state.directive_for_commit()
        return self._consumer.commit_directive(directive)


class MeteredSseStream:
    """A metered SSE stream over any iterable of raw byte chunks.

    Works with ``httpx.Response.iter_bytes()`` or any other source of raw byte
    chunks; the stream stays transport-neutral and owns its own decoder and
    metering state. Iterate with :meth:`next` (or as an iterator) and call
    :meth:`ack` once to commit.
    """

    def __init__(self, consumer: SessionConsumer, chunks: Iterable[bytes]) -> None:
        """Wrap a consumer and a raw chunk source."""
        self._consumer = consumer
        self._chunks = iter(chunks)
        self._decoder = SseDecoder()
        self._pending: list[Any] = []
        self._state = _MeteredStreamState()

    def next(self) -> Any | None:
        """Return the next message payload, or ``None`` at end of stream."""
        while True:
            if self._pending:
                return self._pending.pop(0)
            if self._state.done:
                return None
            chunk = next(self._chunks, None)
            if chunk is None:
                for event in self._decoder.finish():
                    message = self._state.apply_event(event)
                    if message is not None:
                        self._pending.append(message)
                self._state.done = True
                continue
            for event in self._decoder.push_chunk(chunk):
                message = self._state.apply_event(event)
                if message is not None:
                    self._pending.append(message)

    def __iter__(self) -> Iterator[Any]:
        """Yield message payloads until the stream ends."""
        while True:
            message = self.next()
            if message is None:
                return
            yield message

    def ack(self) -> CommitReceipt:
        """Drain the stream if needed, then sign and commit the delivery."""
        if not self._state.done:
            while self.next() is not None:
                pass
        directive = self._state.directive_for_commit()
        return self._consumer.commit_directive(directive)

    def into_consumer(self) -> SessionConsumer:
        """Return the wrapped consumer for reuse on the next request."""
        return self._consumer


class HttpCommitTransport:
    """Minimal HTTP transport for commit endpoints.

    Posts the :class:`CommitPayload` JSON to the directive ``commitUrl`` (or a
    default), optionally with an Authorization header, and decodes the
    :class:`CommitReceipt`. Pass an ``httpx.Client`` to control timeouts or to
    inject a mock transport in tests; one is created lazily when omitted.
    """

    def __init__(
        self,
        client: Any | None = None,
        default_commit_url: str | None = None,
        authorization: str | None = None,
    ) -> None:
        """Create a transport over an optional httpx client and defaults."""
        if client is None:
            import httpx

            client = httpx.Client()
        self._client = client
        self._default_commit_url = default_commit_url
        self._authorization = authorization

    def commit(self, directive: MeteringDirective, payload: CommitPayload) -> CommitReceipt:
        """POST the commit payload and decode the receipt."""
        url = directive.commit_url if directive.commit_url is not None else self._default_commit_url
        if url is None:
            raise ValueError("metering directive missing commitUrl")

        headers: dict[str, str] = {}
        if self._authorization is not None:
            headers["authorization"] = self._authorization
        try:
            response = self._client.post(url, json=payload.to_dict(), headers=headers)
        except Exception as exc:  # noqa: BLE001 - transport errors surface as commit failures
            raise ValueError(f"commit request failed: {exc}") from exc
        if response.status_code < 200 or response.status_code >= 300:
            raise ValueError(f"commit endpoint returned {response.status_code}: {response.text}")
        try:
            return CommitReceipt.from_dict(response.json())
        except (ValueError, TypeError) as exc:
            raise ValueError(f"invalid commit receipt: {exc}") from exc
