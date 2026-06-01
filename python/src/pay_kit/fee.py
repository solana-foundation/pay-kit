"""A single recipient line on a Gate.

Either taken ``within`` the gate amount (the payTo recipient nets less) or
``on_top`` of it (the customer pays more, payTo nets the full amount). Frozen
at construction; Gate builds these from its ``fee_within`` / ``fee_on_top``
arguments.
"""

from __future__ import annotations

from typing import Literal

import pydantic

from pay_kit.errors import ConfigurationError
from pay_kit.price import Price

__all__ = ["Fee"]


class Fee(pydantic.BaseModel):
    """A recipient address and the price they receive, within or on top."""

    model_config = pydantic.ConfigDict(frozen=True, extra="forbid")

    recipient: str
    price: Price
    kind: Literal["within", "on_top"]

    @pydantic.field_validator("recipient")
    @classmethod
    def _non_empty_recipient(cls, value: str) -> str:
        if not value:
            raise ConfigurationError("pay_kit: Fee recipient must be a non-empty string")
        return value

    def is_within(self) -> bool:
        """Whether this fee is taken out of the gate's amount."""
        return self.kind == "within"

    def is_on_top(self) -> bool:
        """Whether this fee is added on top of the gate's amount."""
        return self.kind == "on_top"
