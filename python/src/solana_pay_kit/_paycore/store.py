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
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

try:  # POSIX advisory locking; see FileReplayStore for the platform note.
    import fcntl
except ImportError:  # pragma: no cover - not exercised on the POSIX CI matrix
    fcntl = None  # type: ignore[assignment]


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

    Safe to share between processes: every read-modify-write re-reads the file
    while holding an exclusive ``flock`` on a ``.lock`` sidecar, so two workers
    on one path cannot both win the same ``put_if_absent`` (the fence the
    replay keys and the subscription renewal claims stand on) or erase each
    other's keys. Nothing is cached in memory, so a ``get`` sees another
    process's write; that costs one file read per call, which is the trade
    this store makes. POSIX only: there is no ``fcntl.flock`` on Windows, and
    the constructor refuses to run rather than pretend the fence holds.

    Intentionally simple: no TTL, no compaction. For deployments that need
    either, plug in your own :class:`Store` (e.g. a Redis-backed one).
    """

    def __init__(self, path: str | os.PathLike[str]) -> None:
        if fcntl is None:  # pragma: no cover - not exercised on the POSIX CI matrix
            raise RuntimeError("FileReplayStore needs POSIX fcntl.flock; pass another Store on this platform")
        self._path = Path(path)
        self._lock_path = self._path.with_name(self._path.name + ".lock")
        self._lock = asyncio.Lock()  # serializes this process; flock serializes the rest
        self._load()  # fail closed at boot on a corrupted or non-object file

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

    @contextlib.contextmanager
    def _flocked(self) -> Iterator[None]:
        """Hold the exclusive cross-process lock for one read-modify-write."""
        posix = fcntl
        if posix is None:  # pragma: no cover - the constructor already refused this platform
            raise RuntimeError("FileReplayStore needs POSIX fcntl.flock")
        self._path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self._lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            posix.flock(fd, posix.LOCK_EX)
            yield
        finally:
            os.close(fd)  # closing the descriptor releases the lock

    def _write(self, key: str, value: Any, *, only_if_absent: bool) -> bool:
        """Persist ``key`` under the lock; return whether this call is the one that wrote it.

        The file is re-read inside the lock, so the decision is made against
        what other processes have already committed, and ``_flush`` renames the
        replacement into place before the lock is released.
        """
        with self._flocked():
            data = self._load()
            if only_if_absent and key in data:
                return False
            self._flush({**data, key: value})
            return True

    def _remove(self, key: str) -> None:
        """Drop ``key`` under the lock, keeping every key another process added."""
        with self._flocked():
            data = self._load()
            if key in data:
                self._flush({k: v for k, v in data.items() if k != key})

    async def get(self, key: str) -> Any | None:
        # Read the file, never a cached copy: another process may have written it.
        return (await asyncio.to_thread(self._load)).get(key)

    async def put(self, key: str, value: Any) -> None:
        async with self._lock:
            await asyncio.to_thread(self._write, key, value, only_if_absent=False)

    async def delete(self, key: str) -> None:
        async with self._lock:
            await asyncio.to_thread(self._remove, key)

    async def put_if_absent(self, key: str, value: Any) -> bool:
        async with self._lock:
            return await asyncio.to_thread(self._write, key, value, only_if_absent=True)
