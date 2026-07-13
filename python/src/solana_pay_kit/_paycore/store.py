"""Pluggable key-value store for replay protection.

The Mpp server holds onto a :class:`Store` to track which charge credentials
it has already settled. The store is the canonical fence between a successful
broadcast and a duplicate retry (audit gap L4 / G05).

Two implementations ship with the SDK:

* :class:`MemoryStore` is fast and process-local. Suitable for tests and
  single-instance deployments where a restart is acceptable.
* :class:`FileReplayStore` is a JSON file under a configurable path for local,
  single-host development. It survives process restarts, but does not provide
  an interprocess replay fence and is not a production replay store.

Production deployments must provide an explicit :class:`ProductionReplayStore`
implementation. That nominal contract is reserved for backends whose
``put_if_absent`` operation is atomic across all writers, shared by all
replicas, and durably committed before it reports success.

The :class:`Mpp` constructor requires the caller to pass a store explicitly.
There is no silent default. A missing store is a server misconfiguration that
would let any credential replay after restart. Mirrors the Ruby and PHP L4
locks that landed in PR #96 / #102.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import tempfile
import threading
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from solana_pay_kit._paycore.solana import _canonical_network, validate_network

logger = logging.getLogger(__name__)

_ALLOW_INMEMORY_REPLAY_STORE_ENV = "PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE"


@runtime_checkable
class Store(Protocol):
    """Async key-value store interface."""

    async def get(self, key: str) -> Any | None: ...
    async def put(self, key: str, value: Any) -> None: ...
    async def delete(self, key: str) -> None: ...
    async def put_if_absent(self, key: str, value: Any) -> bool: ...


class ProductionReplayStore(ABC):
    """Nominal contract for an external production replay-store backend.

    Subclass this only when every read-modify-write operation is coordinated
    across processes and replicas, ``put_if_absent`` is atomic, and successful
    writes are durable. This is intentionally a nominal contract rather than
    mutable ``is_atomic``/``is_shared``/``is_durable`` instance flags.
    """

    @abstractmethod
    async def get(self, key: str) -> Any | None: ...

    @abstractmethod
    async def put(self, key: str, value: Any) -> None: ...

    @abstractmethod
    async def delete(self, key: str) -> None: ...

    @abstractmethod
    async def put_if_absent(self, key: str, value: Any) -> bool: ...


class ReplayStoreConfigurationError(ValueError):
    """Raised when a replay store violates the deployment safety policy."""


def is_production_replay_store(store: Store) -> bool:
    """Return whether ``store`` explicitly implements the production contract.

    The SDK's bundled stores are known local implementations. Check them
    before the nominal contract so a multiple-inheritance class cannot label
    ``MemoryStore`` or ``FileReplayStore`` as production-safe.
    """
    return not isinstance(store, (MemoryStore, FileReplayStore)) and isinstance(store, ProductionReplayStore)


class MemoryStore:
    """Thread-safe in-memory store for development and tests.

    State lives in this process only. A restart drops every consumed-signature
    record, which is fine for single-process tests but unsafe in production.
    """

    def __init__(self) -> None:
        self._data: dict[str, Any] = {}
        self._lock = threading.Lock()

    async def get(self, key: str) -> Any | None:
        return await asyncio.to_thread(self._get, key)

    def _get(self, key: str) -> Any | None:
        with self._lock:
            return self._data.get(key)

    async def put(self, key: str, value: Any) -> None:
        await asyncio.to_thread(self._put, key, value)

    def _put(self, key: str, value: Any) -> None:
        with self._lock:
            self._data[key] = value

    async def delete(self, key: str) -> None:
        await asyncio.to_thread(self._delete, key)

    def _delete(self, key: str) -> None:
        with self._lock:
            self._data.pop(key, None)

    async def put_if_absent(self, key: str, value: Any) -> bool:
        return await asyncio.to_thread(self._put_if_absent, key, value)

    def _put_if_absent(self, key: str, value: Any) -> bool:
        with self._lock:
            if key in self._data:
                return False
            self._data[key] = value
            return True


class FileReplayStore:
    """File-backed replay store.

    Persists the consumed-signature set to a JSON file under ``path`` for a
    single local process. It survives process restarts, but separate instances
    cache stale data and only coordinate with their own local lock. It is never
    safe as a replay fence outside localnet.

    The on-disk layout is a single JSON object ``{"<key>": <value>}``. Writes
    are write-temp-then-rename so a crash mid-write cannot leave a torn file.

    Intentionally simple: no TTL, no compaction. For deployments that need
    either, plug in your own :class:`Store` (e.g. a Redis-backed one).
    """

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self._path = Path(path)
        self._lock = threading.Lock()
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
        return await asyncio.to_thread(self._get, key)

    def _get(self, key: str) -> Any | None:
        with self._lock:
            return self._data.get(key)

    async def put(self, key: str, value: Any) -> None:
        await asyncio.to_thread(self._put, key, value)

    def _put(self, key: str, value: Any) -> None:
        # Greptile P1 (follow-up): flush BEFORE committing to
        # ``self._data``. If ``_flush`` raises (disk full mid-fsync, IO
        # error during ``os.replace``), the in-memory state would
        # otherwise diverge from the on-disk store, so a subsequent
        # ``get`` would report a key that was never durably persisted.
        # We build the next dict, flush it, then swap.
        with self._lock:
            next_data = {**self._data, key: value}
            self._flush(next_data)
            self._data = next_data

    async def delete(self, key: str) -> None:
        await asyncio.to_thread(self._delete, key)

    def _delete(self, key: str) -> None:
        with self._lock:
            if key not in self._data:
                return
            next_data = {k: v for k, v in self._data.items() if k != key}
            self._flush(next_data)
            self._data = next_data

    async def put_if_absent(self, key: str, value: Any) -> bool:
        return await asyncio.to_thread(self._put_if_absent, key, value)

    def _put_if_absent(self, key: str, value: Any) -> bool:
        with self._lock:
            if key in self._data:
                return False
            next_data = {**self._data, key: value}
            self._flush(next_data)
            self._data = next_data
            return True


def resolve_replay_store(network: str, replay_store: Store | None, *, protocol: str) -> Store:
    """Apply the shared replay-store policy for raw servers and adapters.

    The existing server network allowlist validates and canonicalizes
    ``network`` before policy selection. Localnet may use either bundled store.
    Outside localnet, only a caller's explicit :class:`ProductionReplayStore`
    is accepted, except for the existing explicit devnet ``MemoryStore``
    escape. The nominal contract is a deployment assertion: callers remain
    responsible for providing an atomic, shared, durable backend.
    """
    validate_network(network)
    network = _canonical_network(network)
    is_localnet = network == "localnet"
    is_devnet = network == "devnet"
    is_mainnet = network == "mainnet"
    inmemory_opt_in = os.getenv(_ALLOW_INMEMORY_REPLAY_STORE_ENV) == "1"
    allow_inmemory = is_devnet and inmemory_opt_in

    if is_mainnet and inmemory_opt_in:
        raise ReplayStoreConfigurationError(
            f"{_ALLOW_INMEMORY_REPLAY_STORE_ENV}=1 is forbidden on mainnet; "
            "inject a ProductionReplayStore backed by atomic, shared, durable storage"
        )

    if replay_store is not None:
        if is_localnet:
            return replay_store
        # Built-ins are checked before the nominal contract. A class that
        # inherits MemoryStore and ProductionReplayStore is still memory-only.
        if isinstance(replay_store, FileReplayStore):
            raise ReplayStoreConfigurationError(
                "FileReplayStore is limited to single-host localnet development; "
                "inject a ProductionReplayStore backed by atomic, shared, durable storage"
            )
        if isinstance(replay_store, MemoryStore):
            if allow_inmemory:
                logger.warning(
                    "solana_pay_kit: %s is using a process-local MemoryStore on devnet because %s=1; "
                    "replay protection will not survive restarts or span replicas",
                    protocol,
                    _ALLOW_INMEMORY_REPLAY_STORE_ENV,
                )
                return replay_store
            raise ReplayStoreConfigurationError(
                f"{protocol} requires a ProductionReplayStore outside localnet; its put_if_absent must be atomic, "
                "shared, and durable. Set "
                f"{_ALLOW_INMEMORY_REPLAY_STORE_ENV}=1 only for explicit devnet MemoryStore development."
            )
        if is_production_replay_store(replay_store):
            return replay_store
        raise ReplayStoreConfigurationError(
            f"{protocol} requires a ProductionReplayStore outside localnet; its put_if_absent must be atomic, "
            "shared, and durable. Set "
            f"{_ALLOW_INMEMORY_REPLAY_STORE_ENV}=1 only for explicit devnet MemoryStore development."
        )

    if is_localnet:
        return MemoryStore()
    if allow_inmemory:
        logger.warning(
            "solana_pay_kit: %s is using a process-local MemoryStore on devnet because %s=1; "
            "replay protection will not survive restarts or span replicas",
            protocol,
            _ALLOW_INMEMORY_REPLAY_STORE_ENV,
        )
        return MemoryStore()
    raise ReplayStoreConfigurationError(
        f"{protocol} requires an injected ProductionReplayStore outside localnet; its put_if_absent must be atomic, "
        "shared, and durable. Set "
        f"{_ALLOW_INMEMORY_REPLAY_STORE_ENV}=1 only for explicit devnet MemoryStore development."
    )
