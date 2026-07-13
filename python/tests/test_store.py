"""Tests for store module."""

from __future__ import annotations

import asyncio
import threading
from pathlib import Path
from queue import Queue
from typing import Any, Literal

import pytest

from solana_pay_kit._paycore.store import (
    FileReplayStore,
    MemoryStore,
    ProductionReplayStore,
    ReplayStoreConfigurationError,
    Store,
    is_production_replay_store,
    resolve_replay_store,
)


class _ProductionStore(ProductionReplayStore):
    """Test double for an application-asserted production backend."""

    def __init__(self) -> None:
        self._delegate = MemoryStore()

    async def get(self, key: str) -> Any | None:
        return await self._delegate.get(key)

    async def put(self, key: str, value: Any) -> None:
        await self._delegate.put(key, value)

    async def delete(self, key: str) -> None:
        await self._delegate.delete(key)

    async def put_if_absent(self, key: str, value: Any) -> bool:
        return await self._delegate.put_if_absent(key, value)


class _ProductionMemoryStore(MemoryStore, ProductionReplayStore):
    """Attempts to relabel the known unsafe in-memory store as production."""


def test_replay_store_canonicalizes_mainnet_alias_before_opt_in(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE", "1")

    with pytest.raises(ReplayStoreConfigurationError, match="forbidden on mainnet"):
        resolve_replay_store("mainnet-beta", MemoryStore(), protocol="test")


def test_replay_store_rejects_unknown_network_before_constructing_memory_store(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE", "1")

    with pytest.raises(ValueError, match="unknown network"):
        resolve_replay_store("solana:unknown-network", None, protocol="test")


def test_replay_store_allows_implicit_memory_only_for_explicit_devnet_opt_in(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE", "1")

    assert isinstance(resolve_replay_store("devnet", None, protocol="test"), MemoryStore)


@pytest.mark.parametrize("store_kind", ["memory", "file"])
def test_put_if_absent_is_atomic_across_event_loops(tmp_path: Path, store_kind: Literal["memory", "file"]):
    """A shared store is safe when sync frameworks create independent loops."""
    store: Store = MemoryStore() if store_kind == "memory" else FileReplayStore(tmp_path / "replay.json")
    start = threading.Barrier(3)
    results: Queue[bool] = Queue()
    errors: Queue[BaseException] = Queue()

    def put_from_own_loop() -> None:
        loop = asyncio.new_event_loop()
        try:
            asyncio.set_event_loop(loop)
            start.wait(timeout=5)
            results.put(loop.run_until_complete(store.put_if_absent("credential", True)))
        except BaseException as exc:
            errors.put(exc)
        finally:
            loop.close()
            asyncio.set_event_loop(None)

    threads = [threading.Thread(target=put_from_own_loop, daemon=True) for _ in range(2)]
    for thread in threads:
        thread.start()
    start.wait(timeout=5)
    for thread in threads:
        thread.join(timeout=5)

    assert all(not thread.is_alive() for thread in threads)
    assert errors.empty(), [repr(errors.get_nowait()) for _ in range(errors.qsize())]
    assert sorted(results.get_nowait() for _ in range(2)) == [False, True]
    assert asyncio.run(store.get("credential")) is True


def test_production_replay_store_contract_rejects_mutable_capability_flags():
    store = MemoryStore()
    for capability in ("is_atomic", "is_shared", "is_durable"):
        setattr(store, capability, True)

    assert not is_production_replay_store(store)


def test_production_replay_store_contract_rejects_memory_multiple_inheritance_spoof():
    store = _ProductionMemoryStore()

    assert isinstance(store, ProductionReplayStore)
    assert not is_production_replay_store(store)


def test_production_replay_store_contract_is_public():
    from solana_pay_kit import ProductionReplayStore as PublicProductionReplayStore

    assert PublicProductionReplayStore is ProductionReplayStore


class TestMemoryStore:
    @pytest.fixture
    def store(self) -> MemoryStore:
        return MemoryStore()

    async def test_get_missing(self, store: MemoryStore):
        assert await store.get("missing") is None

    async def test_put_and_get(self, store: MemoryStore):
        await store.put("key", "value")
        assert await store.get("key") == "value"

    async def test_put_overwrites(self, store: MemoryStore):
        await store.put("key", "v1")
        await store.put("key", "v2")
        assert await store.get("key") == "v2"

    async def test_delete(self, store: MemoryStore):
        await store.put("key", "value")
        await store.delete("key")
        assert await store.get("key") is None

    async def test_delete_missing(self, store: MemoryStore):
        # Should not raise
        await store.delete("missing")

    async def test_put_if_absent_new_key(self, store: MemoryStore):
        result = await store.put_if_absent("key", "value")
        assert result is True
        assert await store.get("key") == "value"

    async def test_put_if_absent_existing_key(self, store: MemoryStore):
        await store.put("key", "v1")
        result = await store.put_if_absent("key", "v2")
        assert result is False
        assert await store.get("key") == "v1"

    def test_implements_store_protocol(self, store: MemoryStore):
        assert isinstance(store, Store)


class TestFileReplayStore:
    @pytest.fixture
    def store_path(self, tmp_path: Path) -> Path:
        return tmp_path / "replay.json"

    @pytest.fixture
    def store(self, store_path: Path) -> FileReplayStore:
        return FileReplayStore(store_path)

    async def test_implements_store_protocol(self, store: FileReplayStore):
        assert isinstance(store, Store)

    async def test_get_missing(self, store: FileReplayStore):
        assert await store.get("missing") is None

    async def test_put_and_get(self, store: FileReplayStore):
        await store.put("key", "value")
        assert await store.get("key") == "value"

    async def test_put_if_absent(self, store: FileReplayStore):
        assert await store.put_if_absent("k", "v1") is True
        assert await store.put_if_absent("k", "v2") is False
        assert await store.get("k") == "v1"

    async def test_persistence_across_instances(self, store_path: Path):
        # Survives across construction: the on-disk JSON file is loaded into
        # the in-memory dict each time. The L4 lock requires this so a
        # credential cannot replay after the server restarts.
        first = FileReplayStore(store_path)
        await first.put_if_absent("sig", True)

        second = FileReplayStore(store_path)
        assert await second.get("sig") is True
        assert await second.put_if_absent("sig", True) is False

    async def test_delete_persists(self, store_path: Path):
        first = FileReplayStore(store_path)
        await first.put("k", "v")
        await first.delete("k")

        second = FileReplayStore(store_path)
        assert await second.get("k") is None

    def test_init_creates_parent_directory_lazily(self, tmp_path: Path):
        # The parent dir does not have to exist at construction time; it gets
        # created on the first write.
        path = tmp_path / "nested" / "subdir" / "replay.json"
        assert not path.parent.exists()
        FileReplayStore(path)
        assert not path.parent.exists()

    def test_corrupted_json_refuses_to_start(self, tmp_path: Path):
        # L4 lock: a corrupted on-disk store must fail closed at boot so a
        # restart cannot silently let previously settled credentials replay.
        # Codex P2 fix.
        path = tmp_path / "replay.json"
        path.write_text("not json {", encoding="utf-8")
        with pytest.raises(RuntimeError, match="corrupted"):
            FileReplayStore(path)

    def test_non_object_json_refuses_to_start(self, tmp_path: Path):
        path = tmp_path / "replay.json"
        path.write_text("[1, 2, 3]", encoding="utf-8")
        with pytest.raises(RuntimeError, match="not a JSON object"):
            FileReplayStore(path)

    async def test_flush_failure_rolls_back_in_memory_state(self, tmp_path: Path):
        """Greptile P1 follow-up: a flush IO error MUST NOT leave the
        in-memory state holding a key that was never persisted to disk.
        Otherwise a ``get`` after a failed ``put_if_absent`` would report
        a stored marker and silently skip the replay-store fence on a
        subsequent retry."""
        path = tmp_path / "replay.json"
        store = FileReplayStore(path)

        # Inject a flush failure by replacing the internal helper.
        def _boom(_data):
            raise OSError("simulated disk failure")

        store._flush = _boom  # type: ignore[assignment]

        with pytest.raises(OSError, match="simulated disk failure"):
            await store.put_if_absent("sig-123", True)

        # In-memory state must NOT contain the half-written key.
        assert await store.get("sig-123") is None

        # And a fresh instance loading from disk also must not see it.
        store2 = FileReplayStore(path)
        assert await store2.get("sig-123") is None

    async def test_failed_put_keeps_previous_committed_state(self, tmp_path: Path):
        path = tmp_path / "replay.json"
        store = FileReplayStore(path)
        await store.put("sig-old", True)

        def _boom(_data):
            raise OSError("simulated disk failure")

        store._flush = _boom  # type: ignore[assignment]

        with pytest.raises(OSError):
            await store.put("sig-new", True)

        # The previously committed value must survive a failed follow-up
        # write; only the new key should be missing.
        assert await store.get("sig-old") is True
        assert await store.get("sig-new") is None


class TestMppRequiresExplicitStore:
    """L4 lock: ``Mpp.__init__`` MUST refuse to start without an explicit store."""

    def test_missing_store_raises(self):
        from solana_pay_kit._paycore.errors import PaymentError
        from solana_pay_kit.protocols.mpp.server.charge import Config, Mpp

        with pytest.raises(PaymentError, match="replay store is required"):
            Mpp(
                Config(
                    recipient="11111111111111111111111111111112",
                    secret_key="long-enough-secret-key-for-hmac-sha256-tests",
                )
            )

    @pytest.mark.parametrize("network", ["mainnet", "devnet"])
    def test_nonlocal_memory_store_is_rejected(self, network: str):
        from solana_pay_kit._paycore.errors import PaymentError
        from solana_pay_kit.protocols.mpp.server.charge import Config, Mpp

        with pytest.raises(PaymentError, match="ProductionReplayStore"):
            Mpp(
                Config(
                    recipient="11111111111111111111111111111112",
                    network=network,
                    secret_key="long-enough-secret-key-for-hmac-sha256-tests",
                    store=MemoryStore(),
                )
            )

    @pytest.mark.parametrize("network", ["mainnet", "devnet"])
    def test_nonlocal_file_store_is_rejected(self, tmp_path: Path, network: str):
        from solana_pay_kit._paycore.errors import PaymentError
        from solana_pay_kit.protocols.mpp.server.charge import Config, Mpp

        with pytest.raises(PaymentError, match="FileReplayStore.*localnet"):
            Mpp(
                Config(
                    recipient="11111111111111111111111111111112",
                    network=network,
                    secret_key="long-enough-secret-key-for-hmac-sha256-tests",
                    store=FileReplayStore(tmp_path / "replay.json"),
                )
            )

    @pytest.mark.parametrize("network", ["mainnet", "devnet"])
    def test_nonlocal_accepts_nominal_production_store(self, network: str):
        from solana_pay_kit.protocols.mpp.server.charge import Config, Mpp

        store = _ProductionStore()
        mpp = Mpp(
            Config(
                recipient="11111111111111111111111111111112",
                network=network,
                secret_key="long-enough-secret-key-for-hmac-sha256-tests",
                store=store,
            )
        )

        assert mpp._store is store

    @pytest.mark.parametrize("network", ["mainnet", "devnet"])
    def test_nonlocal_rejects_memory_production_multiple_inheritance_spoof(self, network: str):
        from solana_pay_kit._paycore.errors import PaymentError
        from solana_pay_kit.protocols.mpp.server.charge import Config, Mpp

        with pytest.raises(PaymentError, match="ProductionReplayStore"):
            Mpp(
                Config(
                    recipient="11111111111111111111111111111112",
                    network=network,
                    secret_key="long-enough-secret-key-for-hmac-sha256-tests",
                    store=_ProductionMemoryStore(),
                )
            )

    def test_devnet_allows_explicit_memory_store_escape(self, monkeypatch: pytest.MonkeyPatch):
        from solana_pay_kit.protocols.mpp.server.charge import Config, Mpp

        monkeypatch.setenv("PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE", "1")
        store = MemoryStore()
        mpp = Mpp(
            Config(
                recipient="11111111111111111111111111111112",
                network="devnet",
                secret_key="long-enough-secret-key-for-hmac-sha256-tests",
                store=store,
            )
        )

        assert mpp._store is store

    def test_mainnet_rejects_inmemory_store_escape(self, monkeypatch: pytest.MonkeyPatch):
        from solana_pay_kit._paycore.errors import PaymentError
        from solana_pay_kit.protocols.mpp.server.charge import Config, Mpp

        monkeypatch.setenv("PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE", "1")

        with pytest.raises(PaymentError, match="forbidden on mainnet"):
            Mpp(
                Config(
                    recipient="11111111111111111111111111111112",
                    network="mainnet",
                    secret_key="long-enough-secret-key-for-hmac-sha256-tests",
                    store=MemoryStore(),
                )
            )
