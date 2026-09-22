"""solana_pay_kit: unified payment surface over x402 and MPP on Solana.

Public entry point. Configure once with :func:`configure`, declare priced
routes with :class:`Gate` (or the :func:`gate` dynamic factory), and guard
handlers with the framework-agnostic trio :func:`require_payment`,
:func:`is_paid`, and :func:`payment`. Framework shims live in optional
submodules (``solana_pay_kit.fastapi``, ``solana_pay_kit.flask``, ``solana_pay_kit.django``) and are
imported on demand so the base install carries no web-framework dependency.

This package ships alongside :mod:`solana_pay_kit.protocols.mpp`, whose wire internals it reuses
rather than reimplements.
"""

from __future__ import annotations

from decimal import Decimal
from typing import TYPE_CHECKING

from solana_pay_kit import errors, kms
from solana_pay_kit._middleware import (
    PayCore,
    is_paid,
    is_paid_for,
    payment,
    require_payment,
)
from solana_pay_kit._paycore.currency import Currency
from solana_pay_kit._paycore.network import Network
from solana_pay_kit._paycore.protocol import Protocol
from solana_pay_kit._paycore.stablecoin import Stablecoin
from solana_pay_kit._paycore.store import FileReplayStore, MemoryStore, Store
from solana_pay_kit.config import (
    BatchSettlementConfig,
    Config,
    MppConfig,
    PayConfig,
    X402Config,
    config,
    configure,
    configure_from,
    reset,
)
from solana_pay_kit.errors import (
    ChallengeExpiredError,
    ConfigurationError,
    DemoSignerOnMainnetError,
    InvalidKeyError,
    InvalidProofError,
    MixedCurrenciesError,
    PayKitError,
    PaymentRequiredError,
    ProtocolIncompatibleError,
    ProtocolNotSupportedError,
)
from solana_pay_kit.fee import Fee
from solana_pay_kit.gate import Gate
from solana_pay_kit.gate import dynamic as gate
from solana_pay_kit.operator import Operator
from solana_pay_kit.payment import Payment
from solana_pay_kit.price import Price
from solana_pay_kit.pricing import Pricing
from solana_pay_kit.protocols.mpp.core.expires import days, hours, minutes, seconds, weeks
from solana_pay_kit.signer import LocalSigner, Signer

if TYPE_CHECKING:
    from solana_pay_kit.protocols.x402.batch_settlement.redemption import BatchRedemption

__all__ = [
    # enums / paycore
    "Protocol",
    "Currency",
    "Network",
    "Stablecoin",
    # value objects
    "Price",
    "Fee",
    "Gate",
    "gate",
    "Operator",
    "Pricing",
    "usd",
    "eur",
    "gbp",
    # signer
    "Signer",
    "LocalSigner",
    "InvalidKeyError",
    "kms",
    # config
    "Config",
    "PayConfig",
    "X402Config",
    "BatchSettlementConfig",
    "MppConfig",
    "configure",
    "configure_from",
    "config",
    "reset",
    # payment + store
    "Payment",
    "Store",
    "MemoryStore",
    "FileReplayStore",
    # middleware trio (framework-agnostic)
    "require_payment",
    "is_paid",
    "is_paid_for",
    "payment",
    # framework-agnostic umbrella core
    "PayCore",
    # x402 batch-settlement redemption
    "x402_batch",
    # errors
    "errors",
    "PayKitError",
    "ConfigurationError",
    "DemoSignerOnMainnetError",
    "MixedCurrenciesError",
    "ProtocolIncompatibleError",
    "InvalidProofError",
    "ChallengeExpiredError",
    "PaymentRequiredError",
    "ProtocolNotSupportedError",
    # expiry helpers (re-exported from solana_pay_kit.protocols.mpp)
    "seconds",
    "minutes",
    "hours",
    "days",
    "weeks",
]


def usd(amount: str | int | Decimal, *settlements: Stablecoin) -> Price:
    """Build a USD-denominated :class:`Price` (top-level shorthand)."""
    return Price.usd(amount, *settlements)


def eur(amount: str | int | Decimal, *settlements: Stablecoin) -> Price:
    """Build a EUR-denominated :class:`Price` (top-level shorthand)."""
    return Price.eur(amount, *settlements)


def gbp(amount: str | int | Decimal, *settlements: Stablecoin) -> Price:
    """Build a GBP-denominated :class:`Price` (top-level shorthand)."""
    return Price.gbp(amount, *settlements)


def x402_batch(config: Config | None = None) -> BatchRedemption:
    """The x402 ``batch-settlement`` redemption worker for ``config`` (default: the configured one).

    It shares the channel store of the engine the framework shims use, so a
    ``claim()``/``settle()`` here redeems what they served. Run it on a
    schedule (``start(interval)``) or call its passes directly.
    """
    from solana_pay_kit.config import config as _current
    from solana_pay_kit.protocols.x402.batch_settlement import batch_engine

    return batch_engine(config if config is not None else _current()).redemption()
