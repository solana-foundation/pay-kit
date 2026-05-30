"""Price / Fee / Gate value-object coverage for pay_kit.

Covers the Decimal-only money contract (float + bool rejection, format
parsing), settlement preference resolution, the gate total/payout math, the
``sum(fee_within) <= amount`` validator, the x402-vs-fees auto-disable rule
(silent strip on inherited accept, raise on explicit ``accept=[X402]`` with
fees, raise on a collapsed-empty accept), and the ``@gate.dynamic`` factory.
"""

from __future__ import annotations

from decimal import Decimal

import pytest

from pay_kit import Gate, Price, Protocol, Stablecoin, gate
from pay_kit._paycore.currency import Currency
from pay_kit.errors import (
    ConfigurationError,
    MixedCurrenciesError,
    ProtocolIncompatibleError,
)
from pay_kit.fee import Fee
from pay_kit.gate import DynamicGate

PAY_TO = "ALtYSsZuYyKrNSe6GnVCzxj1T2RPMTPzXMe51xhbmXEq"
FEE_A = "9xAXssX9j7vuK99c7cFwqbixzL3bFrzPy9PUhCtDPAYJ"
FEE_B = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"


# -- Price: Decimal-only money -----------------------------------------------


def test_price_accepts_str_int_decimal():
    assert Price.usd("0.10").amount == Decimal("0.10")
    assert Price.usd(2).amount == Decimal(2)
    assert Price.usd(Decimal("1.5")).amount == Decimal("1.5")


def test_price_rejects_float():
    with pytest.raises(ConfigurationError, match="not float"):
        Price.usd(0.10)  # type: ignore[arg-type]


def test_price_rejects_bool():
    # bool is an int subclass; the guard rejects it explicitly so True != 1.
    with pytest.raises(ConfigurationError, match="not bool"):
        Price.usd(True)


def test_price_rejects_malformed_string():
    with pytest.raises(ConfigurationError, match="invalid Price amount"):
        Price.usd("1.2.3")
    with pytest.raises(ConfigurationError, match="invalid Price amount"):
        Price.usd("abc")


def test_price_rejects_negative_int_and_decimal():
    # Regression: the str path rejected negatives via _AMOUNT_RE, but the int
    # and Decimal paths returned unguarded, building an invalid Price.
    with pytest.raises(ConfigurationError, match="must not be negative"):
        Price.usd(-1)
    with pytest.raises(ConfigurationError, match="must not be negative"):
        Price.usd(Decimal("-0.01"))


def test_price_allows_zero():
    # Zero is a valid (free) gate amount and must still build.
    assert Price.usd(0).amount == Decimal(0)
    assert Price.usd("0").amount == Decimal("0")


def test_price_currency_factories():
    assert Price.usd("1").currency is Currency.USD
    assert Price.eur("1").currency is Currency.EUR
    assert Price.gbp("1").currency is Currency.GBP


def test_price_settlement_preference_order():
    p = Price.usd("0.10", Stablecoin.USDT, Stablecoin.USDC)
    assert p.settlements == (Stablecoin.USDT, Stablecoin.USDC)
    assert p.primary_coin() is Stablecoin.USDT


def test_price_primary_coin_none_defers_to_config():
    assert Price.usd("0.10").primary_coin() is None


def test_price_amount_string_preserves_trailing_zeros():
    assert Price.usd("0.10").amount_string() == "0.10"
    assert Price.usd("1").amount_string() == "1"


def test_price_with_amount_keeps_currency_and_settlements():
    base = Price.eur("0.10", Stablecoin.USDC)
    out = base.with_amount("0.25")
    assert out.amount == Decimal("0.25")
    assert out.currency is Currency.EUR
    assert out.settlements == (Stablecoin.USDC,)


def test_price_plus_same_currency():
    out = Price.usd("0.10").plus(Price.usd("0.05"))
    assert out.amount == Decimal("0.15")


def test_price_plus_mixed_currency_raises():
    with pytest.raises(MixedCurrenciesError):
        Price.usd("0.10").plus(Price.eur("0.05"))


def test_price_is_frozen():
    p = Price.usd("0.10")
    with pytest.raises(Exception):  # noqa: B017 - pydantic frozen raises ValidationError
        p.amount = Decimal("1")  # type: ignore[misc]


# -- Fee ---------------------------------------------------------------------


def test_fee_within_and_on_top_flags():
    within = Fee(recipient=FEE_A, price=Price.usd("0.01"), kind="within")
    on_top = Fee(recipient=FEE_A, price=Price.usd("0.01"), kind="on_top")
    assert within.is_within() and not within.is_on_top()
    assert on_top.is_on_top() and not on_top.is_within()


def test_fee_rejects_empty_recipient():
    with pytest.raises(ConfigurationError, match="non-empty"):
        Fee(recipient="", price=Price.usd("0.01"), kind="within")


# -- Gate construction + validation ------------------------------------------


def test_gate_build_minimal():
    g = Gate.build(name="r", amount=Price.usd("0.10"), default_pay_to=PAY_TO)
    assert g.name == "r"
    assert g.pay_to == PAY_TO
    assert not g.has_fees()


def test_gate_pay_to_override_beats_default():
    g = Gate.build(name="r", amount=Price.usd("0.10"), pay_to=FEE_A, default_pay_to=PAY_TO)
    assert g.pay_to == FEE_A


def test_gate_requires_a_recipient():
    with pytest.raises(ConfigurationError, match="pay_to is required"):
        Gate.build(name="r", amount=Price.usd("0.10"))


def test_gate_rejects_empty_name():
    with pytest.raises(ConfigurationError, match="name must be"):
        Gate.build(name="", amount=Price.usd("0.10"), default_pay_to=PAY_TO)


def test_gate_rejects_non_price_amount():
    with pytest.raises(ConfigurationError, match="must be a Price"):
        Gate.build(name="r", amount="0.10", default_pay_to=PAY_TO)  # type: ignore[arg-type]


def test_gate_total_adds_on_top_fees_only():
    g = Gate.build(
        name="r",
        amount=Price.usd("0.10"),
        default_pay_to=PAY_TO,
        fee_on_top={FEE_A: Price.usd("0.02")},
        fee_within={FEE_B: Price.usd("0.01")},
        accept=(Protocol.MPP,),
    )
    # customer pays base + on_top, never the within fee.
    assert g.total().amount == Decimal("0.12")


def test_gate_payout_math_pay_to_nets_minus_within():
    g = Gate.build(
        name="r",
        amount=Price.usd("0.10"),
        default_pay_to=PAY_TO,
        fee_within={FEE_A: Price.usd("0.03")},
        fee_on_top={FEE_B: Price.usd("0.05")},
        accept=(Protocol.MPP,),
    )
    payout_main = g.payout(PAY_TO)
    payout_a = g.payout(FEE_A)
    payout_b = g.payout(FEE_B)
    assert payout_main is not None and payout_a is not None and payout_b is not None
    assert payout_main.amount == Decimal("0.07")  # 0.10 - 0.03 within
    assert payout_a.amount == Decimal("0.03")
    assert payout_b.amount == Decimal("0.05")
    assert g.payout("unknownaddr") is None


def test_gate_within_sum_exceeds_amount_raises():
    with pytest.raises(ConfigurationError, match="exceeds amount"):
        Gate.build(
            name="r",
            amount=Price.usd("0.10"),
            default_pay_to=PAY_TO,
            fee_within={FEE_A: Price.usd("0.20")},
            accept=(Protocol.MPP,),
        )


def test_gate_within_sum_equal_to_amount_ok():
    g = Gate.build(
        name="r",
        amount=Price.usd("0.10"),
        default_pay_to=PAY_TO,
        fee_within={FEE_A: Price.usd("0.10")},
        accept=(Protocol.MPP,),
    )
    payout_main = g.payout(PAY_TO)
    assert payout_main is not None
    assert payout_main.amount == Decimal("0")


def test_gate_fee_recipient_equal_pay_to_raises():
    with pytest.raises(ConfigurationError, match="duplicates"):
        Gate.build(
            name="r",
            amount=Price.usd("0.10"),
            default_pay_to=PAY_TO,
            fee_within={PAY_TO: Price.usd("0.01")},
            accept=(Protocol.MPP,),
        )


def test_gate_duplicate_fee_recipient_raises():
    with pytest.raises(ConfigurationError, match="duplicate fee recipient"):
        Gate.build(
            name="r",
            amount=Price.usd("0.10"),
            default_pay_to=PAY_TO,
            fee_within={FEE_A: Price.usd("0.01")},
            fee_on_top={FEE_A: Price.usd("0.01")},
            accept=(Protocol.MPP,),
        )


def test_gate_mixed_currency_fee_raises():
    with pytest.raises(MixedCurrenciesError):
        Gate.build(
            name="r",
            amount=Price.usd("0.10"),
            default_pay_to=PAY_TO,
            fee_within={FEE_A: Price.eur("0.01")},
            accept=(Protocol.MPP,),
        )


def test_gate_fee_price_must_be_price_instance():
    with pytest.raises(ConfigurationError, match="must be a Price"):
        Gate.build(
            name="r",
            amount=Price.usd("0.10"),
            default_pay_to=PAY_TO,
            fee_within={FEE_A: "0.01"},  # type: ignore[dict-item]
        )


def test_gate_fee_map_must_be_dict():
    with pytest.raises(ConfigurationError, match="must be a dict"):
        Gate.build(
            name="r",
            amount=Price.usd("0.10"),
            default_pay_to=PAY_TO,
            fee_within=[(FEE_A, Price.usd("0.01"))],  # type: ignore[arg-type]
        )


def test_gate_fee_recipient_empty_in_map_raises():
    with pytest.raises(ConfigurationError, match="non-empty string"):
        Gate.build(
            name="r",
            amount=Price.usd("0.10"),
            default_pay_to=PAY_TO,
            fee_within={"": Price.usd("0.01")},
        )


# -- x402-vs-fees rule (Gate rule 6) -----------------------------------------


def test_gate_no_fees_keeps_accept_as_given():
    g = Gate.build(name="r", amount=Price.usd("0.10"), default_pay_to=PAY_TO, accept=(Protocol.X402, Protocol.MPP))
    assert g.x402_accepted() and g.mpp_accepted()


def test_gate_inherited_accept_with_fees_leaves_none():
    # accept omitted -> inherited; resolver leaves None so Config strips x402.
    g = Gate.build(
        name="r",
        amount=Price.usd("0.10"),
        default_pay_to=PAY_TO,
        fee_within={FEE_A: Price.usd("0.01")},
    )
    assert g.accept is None
    assert g.has_fees()


def test_gate_explicit_x402_with_fees_raises():
    with pytest.raises(ProtocolIncompatibleError, match="x402 cannot be combined with fees"):
        Gate.build(
            name="r",
            amount=Price.usd("0.10"),
            default_pay_to=PAY_TO,
            accept=(Protocol.X402, Protocol.MPP),
            fee_within={FEE_A: Price.usd("0.01")},
        )


def test_gate_empty_accept_with_fees_raises():
    with pytest.raises(ProtocolIncompatibleError, match="no remaining accepted protocols"):
        Gate.build(
            name="r",
            amount=Price.usd("0.10"),
            default_pay_to=PAY_TO,
            accept=(),
            fee_within={FEE_A: Price.usd("0.01")},
        )


def test_gate_empty_accept_default_no_fees_raises():
    with pytest.raises(ConfigurationError, match="resolved to an empty list"):
        Gate.build(name="r", amount=Price.usd("0.10"), default_pay_to=PAY_TO, accept_default=())


def test_gate_accept_default_used_when_accept_omitted():
    g = Gate.build(
        name="r",
        amount=Price.usd("0.10"),
        default_pay_to=PAY_TO,
        accept_default=(Protocol.MPP,),
    )
    assert g.accept == (Protocol.MPP,)


# -- DynamicGate / @gate.dynamic ---------------------------------------------


def test_dynamic_decorator_returns_dynamic_gate():
    @gate("by_size")  # type: ignore[arg-type]
    def builder(request):  # noqa: ANN001
        return Price.usd("0.10")

    assert isinstance(builder, DynamicGate)
    assert builder.name == "by_size"


def test_dynamic_resolve_from_price_applies_defaults():
    @gate("by_size", accept=(Protocol.MPP,))  # type: ignore[arg-type]
    def builder(request):  # noqa: ANN001
        cents = request["units"]
        return Price.usd(str(cents))

    builder._defaults.update({"pay_to": PAY_TO, "accept": (Protocol.MPP,)})
    g = builder.resolve({"units": "2"})
    assert g.amount.amount == Decimal("2")
    assert g.pay_to == PAY_TO
    assert g.accept == (Protocol.MPP,)


def test_dynamic_resolve_returns_gate_directly():
    concrete = Gate.build(name="x", amount=Price.usd("0.10"), default_pay_to=PAY_TO)

    @gate("x")
    def builder(request):  # noqa: ANN001
        return concrete

    assert builder.resolve({}) is concrete


def test_dynamic_resolve_bad_return_raises():
    @gate("x")  # type: ignore[arg-type]
    def builder(request):  # noqa: ANN001
        return 123  # type: ignore[return-value]

    with pytest.raises(ConfigurationError, match="must return a Gate or a Price"):
        builder.resolve({})
