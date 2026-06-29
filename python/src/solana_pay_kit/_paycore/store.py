"""Pluggable key-value store for replay protection.

The Mpp server holds onto a :class:`Store` to track which charge credentials
it has already settled. The store is the canonical fence between a successful
broadcast and a duplicate retry (audit gap L4 / G05).

Two implementations ship with the SDK:

* :class:`MemoryStore` is fast and process-local. Suitable for tests and
  single-instance deployments where a restart is acceptable.
* :class:`FileReplayStore` is a JSON file under a configurable path. Survives
  process restarts. Mirrors the Ruby ``Mpp::Store::FileStore`` shape so
  cross-language deployments stay swap-compatible.

The :class:`Mpp` constructor requires the caller to pass a store explicitly.
There is no silent default. A missing store is a server misconfiguration that
would let any credential replay after restart. Mirrors the Ruby and PHP L4
locks that landed in PR #96 / #102.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class Store(Protocol):
    """Async key-value store interface."""

    async def get(self, key: str) -> Any | None: ...
    async def put(self, key: str, value: Any) -> None: ...
    async def delete(self, key: str) -> None: ...
    async def put_if_absent(self, key: str, value: Any) -> bool: ...


class MemoryStore:
    """Thread-safe in-memory store for development and tests.

    State lives in this process only. A restart drops every consumed-signature
    record, which is fine for single-process tests but unsafe in production.
    """

    def __init__(self) -> None:
        self._data: dict[str, Any] = {}
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> Any | None:
        return self._data.get(key)

    async def put(self, key: str, value: Any) -> None:
        async with self._lock:
            self._data[key] = value

    async def delete(self, key: str) -> None:
        async with self._lock:
            self._data.pop(key, None)

    async def put_if_absent(self, key: str, value: Any) -> bool:
        async with self._lock:
            if key in self._data:
                return False
            self._data[key] = value
            return True


class FileReplayStore:
    """File-backed replay store.

    Persists the consumed-signature set to a JSON file under ``path``. Survives
    process restarts so a credential cannot replay across a server bounce.
    Mirrors :class:`Mpp::Store::FileStore` in the Ruby SDK.

    The on-disk layout is a single JSON object ``{"<key>": <value>}``. Writes
    are write-temp-then-rename so a crash mid-write cannot leave a torn file.

    Intentionally simple: no TTL, no compaction. For deployments that need
    either, plug in your own :class:`Store` (e.g. a Redis-backed one).
    """

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self._path = Path(path)
        self._lock = asyncio.Lock()
        self._data: dict[str, Any] = self._load()

    def _load(self) -> dict[str, Any]:
        try:
            raw = self._path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return {}
        if not raw.strip():
            return {}
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            # L4 lock: fail closed by raising. Silently overwriting a
            # corrupted store would drop every consumed-signature marker
            # and let previously settled credentials replay across the
            # next restart. The operator must repair or remove the file
            # before the server can resume verification.
            raise RuntimeError(
                f"FileReplayStore at {self._path} is corrupted; refusing to start with empty replay evidence: {exc}"
            ) from exc
        if not isinstance(value, dict):
            raise RuntimeError(f"FileReplayStore at {self._path} is not a JSON object; refusing to start")
        return value

    def _flush(self, data: dict[str, Any]) -> None:
        """Atomically persist ``data`` to ``self._path``.

        Writes go to a temp file in the same directory, then rename. Raises
        on any IO error so callers can roll back their in-memory state
        before exposing the write as committed.
        """
        self._path.parent.mkdir(parents=True, exist_ok=True)
        # NamedTemporaryFile with delete=False then explicit close + replace
        # is the atomic-rename pattern; a `with` block would close the file
        # before os.replace runs and lose the atomicity. SIM115 ignored.
        tmp = tempfile.NamedTemporaryFile(  # noqa: SIM115
            mode="w",
            encoding="utf-8",
            dir=str(self._path.parent),
            prefix=self._path.name + ".",
            suffix=".tmp",
            delete=False,
        )
        try:
            try:
                json.dump(data, tmp, separators=(",", ":"), ensure_ascii=False)
                tmp.flush()
                os.fsync(tmp.fileno())
            finally:
                tmp.close()
            os.replace(tmp.name, self._path)
        except Exception:
            # Best-effort cleanup of the temp file on any IO failure so a
            # failed flush does not litter the parent directory.
            with contextlib.suppress(OSError):
                os.unlink(tmp.name)
            raise

    async def get(self, key: str) -> Any | None:
        return self._data.get(key)

    async def _flush_off_loop(self, data: dict[str, Any]) -> None:
        """Run the blocking ``_flush`` in a worker thread.

        ``_flush`` performs synchronous file IO and ``os.fsync()``; both
        block the event loop if called directly from an async coroutine
        and degrade tail latency for the whole server under load.
        ``asyncio.to_thread`` offloads the call to the default executor
        so other coroutines stay responsive while the page-cache
        flushes to disk.
        """
        await asyncio.to_thread(self._flush, data)

    async def put(self, key: str, value: Any) -> None:
        # Greptile P1 (follow-up): flush BEFORE committing to
        # ``self._data``. If ``_flush`` raises (disk full mid-fsync, IO
        # error during ``os.replace``), the in-memory state would
        # otherwise diverge from the on-disk store, so a subsequent
        # ``get`` would report a key that was never durably persisted.
        # We build the next dict, flush it, then swap.
        async with self._lock:
            next_data = {**self._data, key: value}
            await self._flush_off_loop(next_data)
            self._data = next_data

    async def delete(self, key: str) -> None:
        async with self._lock:
            if key not in self._data:
                return
            next_data = {k: v for k, v in self._data.items() if k != key}
            await self._flush_off_loop(next_data)
            self._data = next_data

    async def put_if_absent(self, key: str, value: Any) -> bool:
        async with self._lock:
            if key in self._data:
                return False
            next_data = {**self._data, key: value}
            await self._flush_off_loop(next_data)
            self._data = next_data
            return True
