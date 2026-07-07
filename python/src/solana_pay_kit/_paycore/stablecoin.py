"""Stablecoin symbols MPP charge and x402 exact can settle in."""

from __future__ import annotations

from enum import StrEnum

__all__ = ["Stablecoin"]


class Stablecoin(StrEnum):
    """SPL stablecoin symbol used as a settlement asset."""

    USDC = "USDC"
    USDT = "USDT"
    USDG = "USDG"
    PYUSD = "PYUSD"
    CASH = "CASH"
