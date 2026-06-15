"""Exception hierarchy for pay_kit.

Two families share the :class:`PayKitError` root:

* Boot-time configuration errors (:class:`ConfigurationError` and friends)
  surface invalid gate registries, fee math, signer secrets, or network
  config before any request is served.
* Request-time errors (:class:`PaymentRequiredError`, :class:`InvalidProofError`,
  :class:`ProtocolNotSupportedError`) carry an :attr:`http_status` so framework
  adapters can render the right HTTP response (402 for missing/invalid proof,
  406 for an unsupported protocol).

``InvalidProofError.code`` carries the canonical cross-SDK L6 error string
(e.g. ``charge_request_mismatch``, ``signature_consumed``). Adapters map the
underlying ``pay_kit.protocols.mpp`` ``PaymentError.code`` to these at the boundary via
``pay_kit._paycore.errors.canonical_code``.
"""

from __future__ import annotations

__all__ = [
    "PayKitError",
    "ConfigurationError",
    "DemoSignerOnMainnetError",
    "InvalidKeyError",
    "MixedCurrenciesError",
    "ProtocolIncompatibleError",
    "InvalidProofError",
    "ChallengeExpiredError",
    "PaymentRequiredError",
    "ProtocolNotSupportedError",
]


class PayKitError(Exception):
    """Root of every pay_kit exception; catch this for a generic handler."""


class ConfigurationError(PayKitError):
    """Boot-time misconfiguration the operator must resolve before serving."""


class DemoSignerOnMainnetError(ConfigurationError):
    """The package-shipped demo signer was paired with solana_mainnet."""


class InvalidKeyError(PayKitError):
    """A signer secret could not be parsed (bad JSON/byte length/base58/hex)."""


class MixedCurrenciesError(ConfigurationError):
    """A gate or price sum mixed amounts denominated in different currencies."""


class ProtocolIncompatibleError(ConfigurationError):
    """A gate explicitly accepts a protocol that cannot settle its shape."""


class InvalidProofError(PayKitError):
    """A submitted payment proof is structurally valid but failed verification."""

    def __init__(self, message: str, code: str = "payment_invalid") -> None:
        super().__init__(message)
        self.code = code

    @property
    def http_status(self) -> int:
        """HTTP status framework adapters render for an invalid proof."""
        return 402


class ChallengeExpiredError(InvalidProofError):
    """A credential's challenge aged past its expiry; re-issue a fresh one."""

    def __init__(self, message: str = "challenge expired", code: str = "challenge_expired") -> None:
        super().__init__(message, code=code)


class PaymentRequiredError(PayKitError):
    """A request reached a gated route without a valid payment."""

    @property
    def http_status(self) -> int:
        """HTTP status framework adapters render when payment is required."""
        return 402


class ProtocolNotSupportedError(PayKitError):
    """The client requested a protocol the server's config does not accept."""

    @property
    def http_status(self) -> int:
        """HTTP status framework adapters render for an unsupported protocol."""
        return 406
