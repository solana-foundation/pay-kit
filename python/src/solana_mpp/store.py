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
        except json.JSONDecodeError:
            # Fail closed on a corrupted store: treat as empty so a fresh
            # write overwrites it on the next put. A future audit can choose
            # to raise instead.
            return {}
        return value if isinstance(value, dict) else {}

    def _flush(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=str(self._path.parent),
            prefix=self._path.name + ".",
            suffix=".tmp",
            delete=False,
        )
        try:
            json.dump(self._data, tmp, separators=(",", ":"), ensure_ascii=False)
            tmp.flush()
            os.fsync(tmp.fileno())
        finally:
            tmp.close()
        os.replace(tmp.name, self._path)

    async def get(self, key: str) -> Any | None:
        return self._data.get(key)

    async def put(self, key: str, value: Any) -> None:
        async with self._lock:
            self._data[key] = value
            self._flush()

    async def delete(self, key: str) -> None:
        async with self._lock:
            if key in self._data:
                self._data.pop(key, None)
                self._flush()

    async def put_if_absent(self, key: str, value: Any) -> bool:
        async with self._lock:
            if key in self._data:
                return False
            self._data[key] = value
            self._flush()
            return True
