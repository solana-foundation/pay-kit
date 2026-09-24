"""Drive an async coroutine to completion from synchronous framework code.

The Flask and Django shims are called from synchronous view code, which may or
may not sit inside a running event loop (WSGI never does, an ASGI handler
always does). Both cases end in one call here so the shims never have to guess:
no loop means :func:`asyncio.run` on this thread, and a running loop means a
fresh loop on a fresh thread, because a coroutine can only be awaited once and
the running loop cannot be re-entered.
"""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Coroutine
from typing import Any, TypeVar

__all__ = ["run_blocking"]

_T = TypeVar("_T")


def run_blocking(coro: Coroutine[Any, Any, _T]) -> _T:
    """Run ``coro`` to completion and return its result, whatever this thread is doing.

    Exceptions propagate unchanged: a scheme error raised inside ``coro`` must
    reach the caller as itself, never as a loop-management error.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)

    result: dict[str, _T] = {}
    error: dict[str, BaseException] = {}

    def runner() -> None:
        try:
            result["value"] = asyncio.run(coro)
        except BaseException as exc:  # re-raised on the calling thread below
            error["error"] = exc

    thread = threading.Thread(target=runner)
    thread.start()
    thread.join()
    raised = error.get("error")
    if raised is not None:
        raise raised
    return result["value"]
