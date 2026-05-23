"""Tests for store module."""

from __future__ import annotations

from pathlib import Path

import pytest

from solana_mpp.store import FileReplayStore, MemoryStore, Store


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


class TestMppRequiresExplicitStore:
    """L4 lock: ``Mpp.__init__`` MUST refuse to start without an explicit store."""

    def test_missing_store_raises(self):
        from solana_mpp._errors import PaymentError
        from solana_mpp.server.mpp import Config, Mpp

        with pytest.raises(PaymentError, match="replay store is required"):
            Mpp(
                Config(
                    recipient="11111111111111111111111111111112",
                    secret_key="long-enough-secret-key-for-hmac-sha256-tests",
                )
            )
