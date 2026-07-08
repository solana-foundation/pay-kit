"""Per-channel idle-close lifecycle.

When the server accepts an open, it arms a single-shot timer keyed on the
channel id. Every voucher / commit / topUp :meth:`SessionLifecycle.touch`
resets the timer. When the timer fires, the ``close_on_idle`` handler is
invoked with the channel id so the server can run its close-and-settle path
without waiting for a client close action.

The idle-close watchdog is an extension beyond the draft MPP spec; without
it, hosts drive close explicitly.

Single-shot ``asyncio`` timers are scheduled on the running event loop, and the
handler is an async coroutine to match the rest of the async server surface.
``close_delay`` is a duration in seconds.
"""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Callable, Coroutine

CloseOnIdle = Callable[[str], Coroutine[None, None, None]]


class SessionLifecycle:
    """The idle-close watchdog.

    :meth:`touch` resets the per-channel timer, :meth:`remove_channel` cancels
    it, and :meth:`shutdown` cancels everything.
    """

    def __init__(self, close_on_idle: CloseOnIdle, close_delay: float) -> None:
        """Create an idle-close watchdog.

        ``close_delay`` <= 0 disables the timer entirely (all operations become
        no-ops), the right default for tests and for callers that drive close
        explicitly.

        ``close_on_idle`` is awaited with the channel id when a timer fires.
        Errors during idle close have no synchronous caller to report to; the
        handler is expected to log internally.
        """
        # _lock guards _timers and _shutdown.
        self._lock = threading.Lock()
        # _timers holds the armed single-shot idle timer handle per channel id.
        self._timers: dict[str, asyncio.TimerHandle] = {}
        # _close_delay is the idle duration before a channel is auto-closed;
        # <= 0 disables the watchdog entirely.
        self._close_delay = close_delay
        # _close_on_idle is awaited with the channel id when its timer fires.
        self._close_on_idle = close_on_idle
        # _shutdown, once True, turns every later touch into a no-op and stops
        # already-fired timers from invoking close_on_idle.
        self._shutdown = False

    def touch(self, channel_id: str) -> None:
        """Reset the idle timer for ``channel_id``.

        No-op when the close delay is disabled or the lifecycle is shut down.
        """
        if self._close_delay <= 0:
            return
        loop = asyncio.get_running_loop()
        with self._lock:
            if self._shutdown:
                return
            self._cancel_locked(channel_id)
            self._timers[channel_id] = loop.call_later(
                self._close_delay,
                self._fire,
                channel_id,
            )

    def remove_channel(self, channel_id: str) -> None:
        """Cancel the idle timer for ``channel_id``."""
        with self._lock:
            self._cancel_locked(channel_id)

    def shutdown(self) -> None:
        """Cancel every outstanding timer and disable future touches."""
        with self._lock:
            self._shutdown = True
            for timer in self._timers.values():
                timer.cancel()
            self._timers.clear()

    def _fire(self, channel_id: str) -> None:
        """Timer callback: drop the timer and schedule the idle-close handler.

        Forget the timer, bail if a shutdown raced in, otherwise dispatch
        ``close_on_idle``.
        """
        with self._lock:
            self._timers.pop(channel_id, None)
            stopped = self._shutdown
        if stopped:
            return
        loop = asyncio.get_running_loop()
        loop.create_task(self._close_on_idle(channel_id))

    def _cancel_locked(self, channel_id: str) -> None:
        """Stop and forget the timer for ``channel_id``. Callers hold ``_lock``."""
        timer = self._timers.pop(channel_id, None)
        if timer is not None:
            timer.cancel()
