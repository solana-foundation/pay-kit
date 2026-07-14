"""Shared nominal replay-store double for non-localnet unit tests."""

from __future__ import annotations

from typing import Any

from solana_pay_kit._paycore.store import MemoryStore, ProductionReplayStore


class NominalProductionReplayStore(ProductionReplayStore):
    """Represents an application-asserted production backend in unit tests."""

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
