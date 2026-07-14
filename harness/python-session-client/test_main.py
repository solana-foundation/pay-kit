from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import cast

import pytest

from solana_pay_kit.protocols.mpp.intents.session import (
    SessionMode,
    SessionPullVoucherStrategy,
    SessionRequest,
)

_MODULE_PATH = Path(__file__).with_name("main.py")
_SPEC = importlib.util.spec_from_file_location("python_session_client_main", _MODULE_PATH)
assert _SPEC is not None
assert _SPEC.loader is not None
_CLIENT = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_CLIENT)


def _request(*, modes: list[SessionMode], strategy: SessionPullVoucherStrategy | None) -> SessionRequest:
    return SessionRequest(
        cap="1400",
        currency="USDC",
        operator="operator",
        recipient="recipient",
        modes=modes,
        pull_voucher_strategy=strategy,
    )


def test_top_up_requires_exactly_the_supported_pull_client_voucher_mode() -> None:
    _CLIENT._require_supported_top_up_mode(_request(modes=["pull"], strategy="clientVoucher"))

    unsupported_modes: list[tuple[list[SessionMode], SessionPullVoucherStrategy | None]] = [
        ([], None),
        (["push"], None),
        (["pull", "push"], "clientVoucher"),
    ]
    for modes, strategy in unsupported_modes:
        with pytest.raises(ValueError, match="requires exactly pull/clientVoucher mode"):
            _CLIENT._require_supported_top_up_mode(_request(modes=modes, strategy=strategy))

    with pytest.raises(ValueError, match="unknown mode"):
        SessionRequest.from_dict(
            {
                "cap": "1400",
                "currency": "USDC",
                "operator": "operator",
                "recipient": "recipient",
                "modes": cast(list[str], ["unknown"]),
            }
        )


@pytest.mark.parametrize("value", [None, "", "0", "-1", "1.5", "invalid"])
def test_top_up_amount_requires_a_positive_base_unit_integer(value: str | None) -> None:
    with pytest.raises(ValueError, match="positive base-unit integer"):
        _CLIENT._positive_base_units(value, "MPP_HARNESS_SESSION_TOP_UP_AMOUNT")
