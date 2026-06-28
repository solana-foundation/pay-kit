"""Charge meter + fail-closed usage-settlement policy (offline, stub engine)."""

from __future__ import annotations

from typing import Any

import pytest

from pay_kit.usage import CHARGE_ATTR, Charge, charge_from, finalize_usage


class _StubEngine:
    def __init__(self, *, settle_error: bool = False) -> None:
        self.settled: list[int] = []
        self._settle_error = settle_error

    async def settle_actual(self, _verified: Any, actual: int) -> dict[str, Any]:
        self.settled.append(actual)
        if self._settle_error:
            raise RuntimeError("settle boom")
        return {"success": True, "transaction": "SIG" if actual else "", "amount": str(actual)}

    def settlement_headers(self, settlement: dict[str, Any]) -> dict[str, str]:
        return {"x-payment-settlement-signature": settlement["transaction"]}


class _Verified:
    def __init__(self) -> None:
        self.released = 0

    def release(self) -> None:
        self.released += 1


# -- Charge meter -----------------------------------------------------------


def test_charge_clamps_to_ceiling() -> None:
    c = Charge(100)
    c.charge(150)
    assert c.settled_base_units() == 100


def test_charge_floors_negatives() -> None:
    c = Charge(100)
    c.charge(-5)
    assert c.settled_base_units() == 0
    assert c.was_charged() is True


def test_charge_records_value_and_flag() -> None:
    c = Charge(100)
    assert c.was_charged() is False
    c.charge(42)
    assert c.settled_base_units() == 42
    assert c.was_charged() is True
    assert c.max_base_units == 100


# -- finalize_usage ---------------------------------------------------------


@pytest.mark.asyncio
async def test_finalize_usage_happy() -> None:
    engine = _StubEngine()
    charge = Charge(100)
    charge.charge(50)
    out = await finalize_usage(engine, _Verified(), charge)
    assert out.ok is True
    assert out.status == 200
    assert out.transaction == "SIG"
    assert out.settlement_headers["x-payment-settlement-signature"] == "SIG"
    assert engine.settled == [50]


@pytest.mark.asyncio
async def test_finalize_usage_fail_closed_on_zero() -> None:
    engine = _StubEngine()
    charge = Charge(100)
    charge.charge(0)
    out = await finalize_usage(engine, _Verified(), charge)
    assert out.ok is False
    assert out.status == 402
    assert out.code == "settlement_failed"
    # still settled 0 on-chain (finalize + refund) before withholding the body
    assert engine.settled == [0]


@pytest.mark.asyncio
async def test_finalize_usage_fail_closed_when_uncharged() -> None:
    engine = _StubEngine()
    out = await finalize_usage(engine, _Verified(), Charge(100))
    assert out.ok is False
    assert out.status == 402
    assert engine.settled == [0]
    assert "must be called" in (out.detail or "")


@pytest.mark.asyncio
async def test_finalize_usage_swallows_zero_settle_error() -> None:
    engine = _StubEngine(settle_error=True)
    out = await finalize_usage(engine, _Verified(), Charge(100))
    assert out.ok is False
    assert out.status == 402


# -- charge_from ------------------------------------------------------------


def test_charge_from_state() -> None:
    class _State:
        pass

    class _Req:
        def __init__(self) -> None:
            self.state = _State()

    req = _Req()
    meter = Charge(10)
    setattr(req.state, CHARGE_ATTR, meter)
    assert charge_from(req) is meter


def test_charge_from_mapping_and_missing() -> None:
    meter = Charge(10)
    assert charge_from({CHARGE_ATTR: meter}) is meter
    assert charge_from({}) is None
    assert charge_from(object()) is None
