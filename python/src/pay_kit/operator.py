"""Merchant identity bundle: recipient, signer, and fee-payer flag."""

from __future__ import annotations

import pydantic

from pay_kit.errors import ConfigurationError
from pay_kit.signer import LocalSigner, Signer

__all__ = ["Operator"]


class Operator(pydantic.BaseModel):
    """Where settled funds land, who signs, and whether the signer pays fees.

    Mirrors the Ruby/PHP ``nil``-as-default-marker convention: a freshly
    constructed ``Operator()`` carries ``recipient=None`` / ``signer=None``,
    and :meth:`with_defaults` resolves those into the demo signer and the
    signer's own pubkey. ``recipient`` then falls back to ``signer.pubkey()``
    via :meth:`effective_recipient`, so a zero-config boot still has a
    settlement destination. ``Config`` layers the mainnet-refusal rule on top.
    """

    model_config = pydantic.ConfigDict(frozen=True, arbitrary_types_allowed=True, extra="forbid")

    recipient: str | None = None
    signer: LocalSigner | None = None
    fee_payer: bool = True

    @pydantic.field_validator("recipient", mode="before")
    @classmethod
    def _validate_recipient(cls, value: object) -> object:
        """Reject non-string recipients (``None`` stays as the default marker)."""
        if value is None:
            return None
        if not isinstance(value, str):
            raise ConfigurationError(f"operator.recipient must be a str, got {type(value).__name__}")
        return value

    @pydantic.field_validator("fee_payer", mode="before")
    @classmethod
    def _validate_fee_payer(cls, value: object) -> bool:
        """Require an exact ``bool``; truthy coercion would mask config bugs."""
        if not isinstance(value, bool):
            raise ConfigurationError(f"operator.fee_payer must be true or false, got {value!r}")
        return value

    def with_defaults(self) -> Operator:
        """Resolve ``None`` markers into shipped defaults.

        ``signer`` defaults to :meth:`Signer.demo`; ``recipient`` defaults to
        the resolved signer's pubkey. Returns a new frozen instance.
        """
        signer = self.signer if self.signer is not None else Signer.demo()
        recipient = self.recipient if self.recipient is not None else signer.pubkey()
        return Operator(recipient=recipient, signer=signer, fee_payer=self.fee_payer)

    def effective_recipient(self) -> str:
        """The settlement address: explicit ``recipient`` or the signer's pubkey."""
        if self.recipient is not None:
            return self.recipient
        signer = self.signer if self.signer is not None else Signer.demo()
        return signer.pubkey()

    def __eq__(self, other: object) -> bool:
        """Equal when resolved recipient, signer pubkey, and fee_payer all match."""
        if not isinstance(other, Operator):
            return NotImplemented
        return (
            self.effective_recipient() == other.effective_recipient()
            and self._signer_pubkey() == other._signer_pubkey()
            and self.fee_payer == other.fee_payer
        )

    def __hash__(self) -> int:
        """Hash over the resolved identity tuple (matches :meth:`__eq__`)."""
        return hash((Operator, self.effective_recipient(), self._signer_pubkey(), self.fee_payer))

    def _signer_pubkey(self) -> str:
        signer = self.signer if self.signer is not None else Signer.demo()
        return signer.pubkey()
