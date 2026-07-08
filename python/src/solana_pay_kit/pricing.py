"""Catalogue-style gate registry plus a coercion helper.

:class:`Pricing` is an optional base class for declaring a named catalogue of
gates. Two equally supported shapes:

1. Subclass :class:`Pricing` and assign :class:`~solana_pay_kit.gate.Gate` (or
   :class:`~solana_pay_kit.gate.DynamicGate`) instances as attributes in
   ``__init__``. Container- and IDE-friendly::

       class Catalog(Pricing):
           def __init__(self) -> None:
               self.report = Gate.build(name="report", amount=Price.usd("0.10"), ...)

   then ``catalog.gate("report")`` resolves by string handle (used by the
   framework middleware alias forms that are string-only).

2. Build gates inline and pass them straight to the middleware without ever
   touching this class.

:func:`coerce` funnels the assorted middleware argument shapes (a registered
name, an inline :class:`~solana_pay_kit.gate.Gate` / :class:`~solana_pay_kit.gate.DynamicGate`,
or a bare :class:`~solana_pay_kit.price.Price`) through one resolution path, applying
Config defaults to inline prices.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import TYPE_CHECKING

from solana_pay_kit._paycore.protocol import Protocol
from solana_pay_kit.errors import ConfigurationError
from solana_pay_kit.gate import DynamicGate, Gate
from solana_pay_kit.price import Price

if TYPE_CHECKING:
    from solana_pay_kit.config import Config

__all__ = ["Pricing", "coerce"]

#: Argument shapes the middleware accepts and :func:`coerce` resolves.
GateRef = "Gate | DynamicGate | Price | str"


class Pricing:
    """A named registry of gates resolvable by string handle.

    The default :meth:`gate` introspects public attributes: subclass and
    assign :class:`~solana_pay_kit.gate.Gate` / :class:`~solana_pay_kit.gate.DynamicGate`
    instances in ``__init__``. Iteration and membership operate over those
    declared gate attributes.
    """

    def gate(self, name: str) -> Gate | DynamicGate:
        """Resolve a gate by attribute name; raise on an unknown or non-gate name."""
        if not hasattr(self, name):
            raise ConfigurationError(f"solana_pay_kit: Pricing has no gate {name!r}")
        value = getattr(self, name)
        if not isinstance(value, (Gate, DynamicGate)):
            raise ConfigurationError(f"solana_pay_kit: Pricing attribute {name!r} is not a Gate")
        return value

    def _gate_attrs(self) -> dict[str, Gate | DynamicGate]:
        """The public attributes that hold gates, keyed by attribute name."""
        attrs: dict[str, Gate | DynamicGate] = {}
        for key, value in vars(self).items():
            if key.startswith("_"):
                continue
            if isinstance(value, (Gate, DynamicGate)):
                attrs[key] = value
        return attrs

    def __contains__(self, name: object) -> bool:
        """Whether ``name`` resolves to a declared gate attribute."""
        if not isinstance(name, str):
            return False
        return isinstance(getattr(self, name, None), (Gate, DynamicGate))

    def __iter__(self) -> Iterator[Gate | DynamicGate]:
        """Iterate over the declared gate instances."""
        return iter(self._gate_attrs().values())


def coerce(
    arg: object,
    *,
    registry: Pricing | None = None,
    config: Config | None = None,
) -> Gate | DynamicGate:
    """Coerce a middleware gate reference into a Gate or DynamicGate.

    A ``str`` is looked up in ``registry`` (raising if none is configured); a
    :class:`~solana_pay_kit.gate.Gate` / :class:`~solana_pay_kit.gate.DynamicGate` passes
    through; a bare :class:`~solana_pay_kit.price.Price` is wrapped into an inline
    Gate using the Config-resolved default recipient and accept list. ``arg`` is
    typed as ``object`` so the isinstance ladder stays a load-bearing runtime
    guard for untyped callers (the trailing ``raise`` is reachable).
    """
    if isinstance(arg, (Gate, DynamicGate)):
        return arg
    if isinstance(arg, str):
        if registry is None:
            raise ConfigurationError(f"solana_pay_kit: no Pricing registry configured to resolve gate {arg!r}")
        return registry.gate(arg)
    if isinstance(arg, Price):
        default_pay_to, accept_default = _config_defaults(config)
        return Gate.build(
            name="_inline",
            amount=arg,
            default_pay_to=default_pay_to,
            accept_default=accept_default,
        )
    raise ConfigurationError(f"solana_pay_kit: cannot coerce {arg!r} to a Gate")


def _config_defaults(config: Config | None) -> tuple[str | None, tuple[Protocol, ...] | None]:
    """Pull the default recipient and accept list off Config, lazily if absent."""
    resolved = config
    if resolved is None:
        from solana_pay_kit import config as config_accessor  # local import: avoids cycle

        resolved = config_accessor()
    return resolved.effective_recipient(), resolved.accept
