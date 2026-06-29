"""Local Ed25519 signer family and the ``Signer`` factory namespace.

Every factory returns a :class:`LocalSigner` that satisfies the solana_pay_kit signer
duck-type contract used by the protocol adapters:

* ``pubkey()``      -> base58 ``str`` (the 32-byte public key)
* ``sign(message)`` -> 64-byte signature ``bytes``
* ``is_fee_payer()``-> ``bool`` (``True`` for in-process local signers)
* ``is_demo()``     -> ``bool`` (only ``True`` for :meth:`Signer.demo`)

Mirrors Ruby ``PayKit::Signer`` and PHP ``PayKit\\Signer`` exactly, including the
auto-detecting :meth:`Signer.env` loader (returns ``None`` when unset/empty so
the Operator null-as-default contract composes, raises on malformed input).

Remote enclave signers (GCP/AWS KMS, HashiCorp Vault) are reserved under
:mod:`solana_pay_kit.kms` and are not part of this release.
"""

from __future__ import annotations

import json
import logging
import os
import warnings
from typing import TYPE_CHECKING, cast

from solders.keypair import Keypair

from .errors import InvalidKeyError

if TYPE_CHECKING:
    from collections.abc import Sequence

__all__ = ["DEMO_PUBKEY", "InvalidKeyError", "LocalSigner", "Signer"]

logger = logging.getLogger("solana_pay_kit")

# The package-shipped demo keypair. Same identity across every solana_pay_kit SDK
# (Ruby PayKit::Signer::Demo, PHP PayKit\Signer\Demo, Lua solana_pay_kit.signer.demo)
# so a process running one SDK can exchange traffic with another during local
# dev. Verified: base58(pubkey) of _DEMO_SECRET_BYTES below.
DEMO_PUBKEY = "ALtYSsZuYyKrNSe6GnVCzxj1T2RPMTPzXMe51xhbmXEq"

# 64-byte secret matching the Ruby / PHP / Lua demo signer byte-for-byte.
_DEMO_SECRET_BYTES: tuple[int, ...] = (
    26,
    61,
    117,
    192,
    9,
    232,
    24,
    51,
    89,
    135,
    105,
    182,
    47,
    9,
    83,
    244,
    11,
    214,
    85,
    170,
    227,
    83,
    170,
    26,
    55,
    129,
    58,
    114,
    89,
    160,
    195,
    51,
    138,
    209,
    127,
    35,
    54,
    41,
    202,
    166,
    199,
    166,
    97,
    238,
    181,
    63,
    254,
    185,
    45,
    16,
    174,
    102,
    250,
    198,
    30,
    191,
    232,
    236,
    147,
    167,
    41,
    178,
    151,
    26,
)

_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")

# Cached demo singleton + one-time-warning guard.
_demo_instance: LocalSigner | None = None
_demo_warned = False


class LocalSigner:
    """In-process Ed25519 signer over a solders ``Keypair``; no I/O on sign()."""

    __slots__ = ("_is_demo", "_is_fee_payer", "_keypair")

    def __init__(
        self,
        keypair: Keypair,
        *,
        is_demo: bool = False,
        is_fee_payer: bool = True,
    ) -> None:
        """Wrap a solders ``Keypair`` with demo / fee-payer flags."""
        self._keypair = keypair
        self._is_demo = is_demo
        self._is_fee_payer = is_fee_payer

    @property
    def keypair(self) -> Keypair:
        """The underlying solders ``Keypair`` (used by cosign paths)."""
        return self._keypair

    def pubkey(self) -> str:
        """Base58-encoded 32-byte public key."""
        return str(self._keypair.pubkey())

    def sign(self, message: bytes) -> bytes:
        """Return the 64-byte Ed25519 signature over ``message``."""
        return bytes(self._keypair.sign_message(message))

    def is_fee_payer(self) -> bool:
        """Whether this signer acts as the transaction fee payer."""
        return self._is_fee_payer

    def is_demo(self) -> bool:
        """Whether this is the shipped demo keypair."""
        return self._is_demo

    def secret_key(self) -> bytes:
        """Raw 64-byte secret. Reserved for internal cosign paths.

        @internal
        """
        return bytes(self._keypair)

    @classmethod
    def from_keypair(cls, kp: Keypair, *, is_demo: bool = False) -> LocalSigner:
        """Build a signer from an existing solders ``Keypair``."""
        return cls(kp, is_demo=is_demo)

    @classmethod
    def from_bytes(cls, secret: bytes | Sequence[int]) -> LocalSigner:
        """Build a signer from a 64-byte secret (``bytes`` or 64 ints in [0,255])."""
        raw = _coerce_secret_bytes(secret)
        return cls.from_keypair(_keypair_from_bytes(raw))

    @classmethod
    def from_base58(cls, s: str) -> LocalSigner:
        """Build a signer from a base58-encoded 64-byte secret (Phantom/Solflare)."""
        # isinstance guard is load-bearing against untyped callers; the public
        # ``str`` annotation is the typed-caller contract, so silence the rule.
        if not isinstance(s, str) or s == "":  # pyright: ignore[reportUnnecessaryIsInstance]
            raise InvalidKeyError("solana_pay_kit: Signer.base58 expects a non-empty string")
        try:
            kp = Keypair.from_base58_string(s)
        except (KeyboardInterrupt, SystemExit):
            raise
        except BaseException as exc:  # noqa: BLE001 - solders raises a non-Exception base on bad input
            raise InvalidKeyError(f"solana_pay_kit: Signer.base58 invalid base58: {exc}") from (
                exc if isinstance(exc, Exception) else None
            )
        return cls.from_keypair(kp)

    @classmethod
    def from_hex(cls, s: str) -> LocalSigner:
        """Build a signer from a 128-character hex string (64 bytes hex-encoded)."""
        # isinstance guards are load-bearing against untyped callers; keep the
        # public ``str`` contract and silence the redundancy rule per line.
        if not isinstance(s, str) or len(s) != 128:  # pyright: ignore[reportUnnecessaryIsInstance]
            length = len(s) if isinstance(s, str) else 0  # pyright: ignore[reportUnnecessaryIsInstance]
            raise InvalidKeyError(f"solana_pay_kit: Signer.hex expects 128 chars, got {length}")
        if any(ch not in _HEX_DIGITS for ch in s):
            raise InvalidKeyError("solana_pay_kit: Signer.hex contains non-hex characters")
        try:
            raw = bytes.fromhex(s)
        except ValueError as exc:
            raise InvalidKeyError("solana_pay_kit: Signer.hex decode failed") from exc
        return cls.from_keypair(_keypair_from_bytes(raw))

    @classmethod
    def generate(cls) -> LocalSigner:
        """Generate a fresh ephemeral keypair (test-only utility)."""
        return cls.from_keypair(Keypair())


class Signer:
    """Factory namespace for local Ed25519 signers (static methods only)."""

    def __init__(self) -> None:  # pragma: no cover - factory is not instantiated
        raise TypeError("Signer is a factory namespace and cannot be instantiated")

    @staticmethod
    def demo() -> LocalSigner:
        """Return the cached shipped demo signer; warns once per process."""
        global _demo_instance, _demo_warned
        if _demo_instance is None:
            _demo_instance = LocalSigner(
                _keypair_from_bytes(bytes(_DEMO_SECRET_BYTES)),
                is_demo=True,
            )
        if not _demo_warned:
            _demo_warned = True
            warnings.warn(
                f"solana_pay_kit: using the shipped demo signer ({DEMO_PUBKEY}); never use it on solana_mainnet",
                stacklevel=2,
            )
            logger.warning(
                "solana_pay_kit: using the shipped demo signer (%s); never use it on solana_mainnet",
                DEMO_PUBKEY,
            )
        return _demo_instance

    @staticmethod
    def bytes(secret: bytes | Sequence[int]) -> LocalSigner:
        """Build a signer from a 64-byte secret (``bytes`` or 64 ints)."""
        return LocalSigner.from_bytes(secret)

    @staticmethod
    def json(json_array: str) -> LocalSigner:
        """Build a signer from a Solana-CLI JSON-array string ``"[1,2,...,64]"``."""
        # isinstance guard is load-bearing against untyped callers; keep the
        # public ``str`` contract and silence the redundancy rule per line.
        if not isinstance(json_array, str):  # pyright: ignore[reportUnnecessaryIsInstance]
            raise InvalidKeyError("solana_pay_kit: Signer.json expects a string")
        trimmed = json_array.strip()
        if trimmed == "":
            raise InvalidKeyError("solana_pay_kit: Signer.json received empty input")
        try:
            decoded = json.loads(trimmed)
        except (json.JSONDecodeError, ValueError) as exc:
            raise InvalidKeyError(f"solana_pay_kit: malformed Solana CLI JSON-array keypair: {exc}") from exc
        if not isinstance(decoded, list):
            raise InvalidKeyError("solana_pay_kit: Signer.json expected a JSON array")
        # json.loads yields list[Any]; element types (int in [0,255], length 64)
        # are validated inside _coerce_secret_bytes, so cast to the declared shape.
        return LocalSigner.from_bytes(cast("Sequence[int]", decoded))

    @staticmethod
    def base58(s: str) -> LocalSigner:
        """Build a signer from a base58-encoded 64-byte secret."""
        return LocalSigner.from_base58(s)

    @staticmethod
    def hex(s: str) -> LocalSigner:
        """Build a signer from a 128-character hex string."""
        return LocalSigner.from_hex(s)

    @staticmethod
    def file(path: str) -> LocalSigner:
        """Read a Solana-CLI JSON-array keypair file and build a signer."""
        # isinstance guard is load-bearing against untyped callers; keep the
        # public ``str`` contract and silence the redundancy rule per line.
        if not isinstance(path, str) or path == "":  # pyright: ignore[reportUnnecessaryIsInstance]
            raise InvalidKeyError("solana_pay_kit: Signer.file expects a non-empty path")
        try:
            with open(path, encoding="utf-8") as handle:
                raw = handle.read()
        except (OSError, ValueError) as exc:
            raise InvalidKeyError(f"solana_pay_kit: Signer.file cannot read {path}: {exc}") from exc
        return Signer.json(raw)

    @staticmethod
    def env(name: str) -> LocalSigner | None:
        """Auto-detect a keypair from env var ``name``.

        Returns ``None`` when the variable is unset or empty so the caller's
        default (typically :meth:`Signer.demo`) survives the assignment chain.
        Raises :class:`InvalidKeyError` when the variable IS set but cannot be
        parsed as JSON-array / hex / base58, because silent fallback would mask
        a real misconfiguration.
        """
        # isinstance guard is load-bearing against untyped callers; keep the
        # public ``str`` contract and silence the redundancy rule per line.
        if not isinstance(name, str) or name == "":  # pyright: ignore[reportUnnecessaryIsInstance]
            raise InvalidKeyError("solana_pay_kit: Signer.env expects a non-empty name")
        raw = os.environ.get(name)
        if raw is None or raw == "":
            return None
        trimmed = raw.strip()
        if trimmed == "":
            return None
        if trimmed.startswith("["):
            return Signer.json(trimmed)
        if len(trimmed) == 128 and all(ch in _HEX_DIGITS for ch in trimmed):
            return Signer.hex(trimmed)
        return Signer.base58(trimmed)

    @staticmethod
    def generate() -> LocalSigner:
        """Generate a fresh ephemeral keypair (test-only utility)."""
        return LocalSigner.generate()


def _coerce_secret_bytes(secret: bytes | Sequence[int]) -> bytes:
    """Validate and coerce a secret into exactly 64 raw bytes."""
    if isinstance(secret, bytes | bytearray):
        if len(secret) != 64:
            raise InvalidKeyError(f"solana_pay_kit: Signer.bytes expects a 64-byte secret, got {len(secret)} bytes")
        return bytes(secret)
    if isinstance(secret, str):
        raise InvalidKeyError("solana_pay_kit: Signer.bytes expects bytes or a sequence of ints, not str")
    try:
        items = list(secret)
    except TypeError as exc:
        raise InvalidKeyError("solana_pay_kit: Signer.bytes expects bytes or a sequence of ints") from exc
    if len(items) != 64:
        raise InvalidKeyError(f"solana_pay_kit: Signer.bytes expects 64 integers, got {len(items)}")
    for i, value in enumerate(items):
        # The declared element type is int, but a JSON-array secret (Signer.json)
        # may carry non-int / float / bool elements at runtime, so the per-element
        # isinstance check is load-bearing; silence the redundancy rule here.
        if not isinstance(value, int) or isinstance(value, bool) or value < 0 or value > 255:  # pyright: ignore[reportUnnecessaryIsInstance]
            raise InvalidKeyError(f"solana_pay_kit: Signer.bytes[{i}] must be an int in [0,255]")
    return bytes(items)


def _keypair_from_bytes(raw: bytes) -> Keypair:
    """Build a solders ``Keypair`` from 64 raw secret bytes."""
    try:
        return Keypair.from_bytes(raw)
    except (KeyboardInterrupt, SystemExit):
        raise
    except BaseException as exc:  # noqa: BLE001 - solders raises non-Exception on bad bytes
        raise InvalidKeyError(f"solana_pay_kit: invalid 64-byte Ed25519 keypair: {exc}") from (
            exc if isinstance(exc, Exception) else None
        )


def _reset_demo_for_tests() -> None:  # pyright: ignore[reportUnusedFunction]  # external test hook (test_pk_signer_operator)
    """Reset the cached demo singleton + warning guard so the next call rebuilds.

    @internal
    """
    global _demo_instance, _demo_warned
    _demo_instance = None
    _demo_warned = False
