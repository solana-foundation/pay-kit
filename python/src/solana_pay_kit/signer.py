"""PayKit key-loading conveniences over native asynchronous keychain signers."""

from __future__ import annotations

import logging
import os
import warnings
from collections.abc import Callable, Sequence

from solana_keychain import MemorySigner, SignerError, SolanaSigner
from solana_keychain.memory.keypair_util import keypair_from_json_keypair
from solders.keypair import Keypair

from .errors import InvalidKeyError

__all__ = ["DEMO_PUBKEY", "Signer", "is_demo_signer"]

logger = logging.getLogger("solana_pay_kit")
DEMO_PUBKEY = "ALtYSsZuYyKrNSe6GnVCzxj1T2RPMTPzXMe51xhbmXEq"
# Public development fixture shared by the PayKit SDKs, never a production key.
_DEMO_SECRET_BYTES = bytes.fromhex(
    "1a3d75c009e81833598769b62f0953f40bd655aae353aa1a37813a7259a0c333"
    "8ad17f233629caa6c7a661eeb53ffeb92d10ae66fac61ebfe8ec93a729b2971a"
)
_demo_instance: MemorySigner | None = None
_demo_warned = False


def is_demo_signer(signer: SolanaSigner) -> bool:
    """Recognize the public demo identity, including explicitly loaded keys."""
    return str(signer.pubkey) == DEMO_PUBKEY


def _load(factory: Callable[[], MemorySigner]) -> MemorySigner:
    """Preserve PayKit's error boundary; keychain owns key validation."""
    try:
        return factory()
    except (SignerError, TypeError, ValueError):
        raise InvalidKeyError("solana_pay_kit: invalid or unreadable private key") from None


class Signer:
    """Synchronous factories returning native asynchronous ``MemorySigner``s."""

    def __init__(self) -> None:
        raise TypeError("Signer is a factory namespace and cannot be instantiated")

    @staticmethod
    def demo() -> MemorySigner:
        """Return the public development signer, warning once per process."""
        global _demo_instance, _demo_warned
        if _demo_instance is None:
            _demo_instance = MemorySigner.from_bytes(_DEMO_SECRET_BYTES)
        if not _demo_warned:
            _demo_warned = True
            warnings.warn(
                f"solana_pay_kit: using the shipped demo signer ({DEMO_PUBKEY}); never use it on solana_mainnet",
                stacklevel=2,
            )
            logger.warning(
                "solana_pay_kit: using the shipped demo signer (%s); never use it on solana_mainnet", DEMO_PUBKEY
            )
        return _demo_instance

    @staticmethod
    def bytes(secret: bytes | Sequence[int]) -> MemorySigner:
        """Load a 32-byte seed or 64-byte keypair using keychain validation."""
        if not isinstance(secret, bytes | bytearray):
            if not isinstance(secret, Sequence) or isinstance(secret, str):  # pyright: ignore[reportUnnecessaryIsInstance]
                raise InvalidKeyError("solana_pay_kit: invalid or unreadable private key")
            if any(type(value) is not int for value in secret):
                raise InvalidKeyError("solana_pay_kit: invalid or unreadable private key")
        return _load(lambda: MemorySigner.from_bytes(bytes(secret)))

    @staticmethod
    def json(json_array: str) -> MemorySigner:
        """Load a Solana CLI JSON keypair."""
        return _load(lambda: MemorySigner(keypair_from_json_keypair(json_array)))

    @staticmethod
    def base58(secret: str) -> MemorySigner:
        """Load a base58 keypair using keychain's private-key string loader."""
        return _load(lambda: MemorySigner.from_private_key_string(secret))

    @staticmethod
    def hex(secret: str) -> MemorySigner:
        """Decode hexadecimal bytes, then let keychain validate the key."""
        return _load(lambda: MemorySigner.from_bytes(bytes.fromhex(secret)))

    @staticmethod
    def file(path: str) -> MemorySigner:
        """Load a Solana CLI keypair file using keychain."""
        return _load(lambda: MemorySigner.from_private_key_file(path))

    @staticmethod
    def env(name: str) -> MemorySigner | None:
        """Load JSON, hex or base58; absent/blank values preserve defaults."""
        if not name:
            raise InvalidKeyError("solana_pay_kit: Signer.env expects a non-empty name")
        raw = os.environ.get(name, "").strip()
        if not raw:
            return None
        if raw.startswith("["):
            return Signer.json(raw)
        if len(raw) == 128 and all(ch in "0123456789abcdefABCDEF" for ch in raw):
            return Signer.hex(raw)
        return Signer.base58(raw)

    @staticmethod
    def generate() -> MemorySigner:
        """Generate a native in-memory signer for development and testing."""
        return MemorySigner(Keypair())


def _reset_demo_for_tests() -> None:  # pyright: ignore[reportUnusedFunction]
    """Reset the demo cache and warning guard."""
    global _demo_instance, _demo_warned
    _demo_instance = None
    _demo_warned = False
