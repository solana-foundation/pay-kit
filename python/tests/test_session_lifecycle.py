"""Unit coverage of the SessionLifecycle idle-close watchdog.

Mirrors ``go/protocols/mpp/server/session_lifecycle_test.go``: zero-delay
disablement, idle firing, touch resets, channel removal, and shutdown.

The Go watchdog uses ``time.AfterFunc`` on background goroutines; the Python
port uses ``asyncio`` single-shot timers, so each test drives an event loop
and the handler is an async coroutine. Delays are expressed in seconds (Go
uses ``time.Duration``); the millisecond-scale fixtures translate directly.
"""

from __future__ import annotations

import asyncio

import pytest

from pay_kit.protocols.mpp.server.session_lifecycle import SessionLifecycle


class _IdleRecorder:
    """Collects ``close_on_idle`` invocations, mirroring the Go ``idleRecorder``."""

    def __init__(self) -> None:
        self.fired: list[str] = []
        self.event = asyncio.Event()

    async def handler(self, channel_id: str) -> None:
        self.fired.append(channel_id)
        self.event.set()

    def count(self) -> int:
        return len(self.fired)


async def test_zero_delay_disables_timers() -> None:
    """Mirrors TestSessionLifecycleZeroDelayDisablesTimers."""
    recorder = _IdleRecorder()
    lifecycle = SessionLifecycle(recorder.handler, 0)
    lifecycle.touch("c1")

    await asyncio.sleep(0.03)
    assert recorder.count() == 0


async def test_fires_after_idle() -> None:
    """Mirrors TestSessionLifecycleFiresAfterIdle."""
    recorder = _IdleRecorder()
    lifecycle = SessionLifecycle(recorder.handler, 0.01)
    try:
        lifecycle.touch("c1")
        await asyncio.wait_for(recorder.event.wait(), timeout=2.0)
        assert recorder.fired[0] == "c1"
    finally:
        lifecycle.shutdown()


async def test_touch_resets_timer() -> None:
    """Mirrors TestSessionLifecycleTouchResetsTimer."""
    recorder = _IdleRecorder()
    lifecycle = SessionLifecycle(recorder.handler, 0.08)
    try:
        lifecycle.touch("c1")
        for _ in range(3):
            await asyncio.sleep(0.03)
            lifecycle.touch("c1")
            assert recorder.count() == 0
        await asyncio.wait_for(recorder.event.wait(), timeout=2.0)
        assert recorder.count() == 1
    finally:
        lifecycle.shutdown()


async def test_remove_channel_cancels_timer() -> None:
    """Mirrors TestSessionLifecycleRemoveChannelCancelsTimer."""
    recorder = _IdleRecorder()
    lifecycle = SessionLifecycle(recorder.handler, 0.02)
    try:
        lifecycle.touch("c1")
        lifecycle.remove_channel("c1")

        await asyncio.sleep(0.06)
        assert recorder.count() == 0
    finally:
        lifecycle.shutdown()


async def test_shutdown_cancels_all_timers_and_disables_touch() -> None:
    """Mirrors TestSessionLifecycleShutdownCancelsAllTimersAndDisablesTouch."""
    recorder = _IdleRecorder()
    lifecycle = SessionLifecycle(recorder.handler, 0.02)

    lifecycle.touch("c1")
    lifecycle.touch("c2")
    lifecycle.shutdown()
    lifecycle.touch("c3")

    await asyncio.sleep(0.06)
    assert recorder.count() == 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
