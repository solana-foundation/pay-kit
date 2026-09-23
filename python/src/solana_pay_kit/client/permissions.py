"""Protocol-neutral permissions for automatic client payments.

Policies are immutable once built and are evaluated before PayKit constructs or
signs an MPP or x402 transaction. The default is intentionally conservative:
known stablecoins, mainnet only, any HTTP(S) origin, and USD 1 per payment.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import Literal, Self
from urllib.parse import urlsplit

from solders.pubkey import Pubkey

from solana_pay_kit._paycore.mints import resolve_stablecoin_mint, symbol_for
from solana_pay_kit._paycore.solana import stablecoin_decimals

SolanaNetwork = Literal["mainnet", "devnet", "localnet"]
PermissionDeniedCode = Literal[
    "amount_exceeds_limit",
    "asset_not_allowed",
    "invalid_challenge_terms",
    "network_not_allowed",
    "origin_not_allowed",
]

_NETWORKS = frozenset({"mainnet", "devnet", "localnet"})
_USD_RE = re.compile(r"^\$?(\d+)(?:\.(\d{0,6}))?$")


class PermissionConfigurationError(ValueError):
    """Raised when a client permission policy is malformed."""


@dataclass(frozen=True)
class PermissionRejection:
    """One payment candidate rejected by the policy."""

    code: PermissionDeniedCode
    message: str
    actual: int | None = None
    limit: int | None = None


class PermissionDeniedError(Exception):
    """Raised when no server payment challenge is permitted."""

    def __init__(self, rejections: tuple[PermissionRejection, ...]) -> None:
        self.rejections = rejections
        super().__init__("no server payment challenge is permitted")


@dataclass(frozen=True)
class UsdAmount:
    """A positive USD value stored exactly as integer micro-dollars."""

    micro_usd: int

    @classmethod
    def parse(cls, value: str) -> UsdAmount:
        """Parse a positive USD value with at most six decimal places."""
        match = _USD_RE.fullmatch(value)
        if match is None:
            raise PermissionConfigurationError(f"invalid USD amount: {value!r}")
        fraction = (match.group(2) or "").ljust(6, "0")
        amount = int(match.group(1)) * 1_000_000 + int(fraction or "0")
        if amount <= 0:
            raise PermissionConfigurationError("USD limits must be greater than zero")
        return cls(amount)


def usd(value: str) -> UsdAmount:
    """Parse an exact USD permission cap."""
    return UsdAmount.parse(value)


@dataclass(frozen=True)
class AssetPermission:
    """One explicitly permitted SPL asset and its optional atomic cap."""

    network: SolanaNetwork
    mint: str
    max_amount_per_payment: int | None = None

    @classmethod
    def allow(cls, network: SolanaNetwork, asset: str) -> AssetPermission:
        """Allow one symbol or mint without an atomic cap."""
        return cls(_network(network), _mint(network, asset))

    @classmethod
    def with_cap(cls, network: SolanaNetwork, asset: str, cap: int) -> AssetPermission:
        """Allow one symbol or mint with an atomic per-payment cap."""
        if cap <= 0:
            raise PermissionConfigurationError("atomic caps must be greater than zero")
        return cls(_network(network), _mint(network, asset), cap)


@dataclass(frozen=True)
class OriginPermissionOverride:
    """An exact-origin cap override; it never grants access to the origin."""

    origin: str
    max_amount_per_payment: UsdAmount | Literal[False] | None
    asset_caps: tuple[AssetPermission, ...]

    @classmethod
    def builder(cls, origin: str) -> OriginPermissionOverrideBuilder:
        """Start an override for one HTTP(S) origin."""
        return OriginPermissionOverrideBuilder(origin)


class OriginPermissionOverrideBuilder:
    """Fluent builder for :class:`OriginPermissionOverride`."""

    def __init__(self, origin: str) -> None:
        self._origin = _origin(origin)
        self._max: UsdAmount | Literal[False] | None = None
        self._asset_caps: list[AssetPermission] = []

    def max_amount_per_payment(self, cap: UsdAmount) -> Self:
        """Replace the global stablecoin cap at this origin."""
        self._max = cap
        return self

    def without_amount_cap(self) -> Self:
        """Remove the stablecoin cap at this origin."""
        self._max = False
        return self

    def asset_cap(self, permission: AssetPermission) -> Self:
        """Replace an asset's global atomic cap at this origin."""
        self._asset_caps.append(permission)
        return self

    def build(self) -> OriginPermissionOverride:
        """Build the immutable exact-origin override."""
        return OriginPermissionOverride(self._origin, self._max, tuple(self._asset_caps))


@dataclass(frozen=True)
class PaymentCandidate:
    """Normalized immutable payment terms derived from a server challenge."""

    amount: int
    mint: str
    network: SolanaNetwork
    origin: str


@dataclass(frozen=True)
class AuthorizedPayment:
    """A permitted payment and its resolved atomic signing cap."""

    max_amount_atomic: int | None


class ClientPermissions:
    """Immutable permissions checked before automatic payment signing."""

    def __init__(
        self,
        *,
        allow_any_asset: bool,
        allowed_assets: tuple[AssetPermission, ...],
        allowed_networks: frozenset[SolanaNetwork],
        allowed_origins: frozenset[str] | None,
        max_amount_per_payment: UsdAmount | None,
        origin_overrides: dict[str, OriginPermissionOverride],
    ) -> None:
        self._allow_any_asset = allow_any_asset
        self._allowed_assets = allowed_assets
        self._allowed_networks = allowed_networks
        self._allowed_origins = allowed_origins
        self._max_amount_per_payment = max_amount_per_payment
        self._origin_overrides = MappingProxyType(dict(origin_overrides))

    @classmethod
    def builder(cls) -> ClientPermissionsBuilder:
        """Start with mainnet, known stablecoins, any origin, and a USD 1 cap."""
        return ClientPermissionsBuilder()

    @classmethod
    def unrestricted(cls) -> ClientPermissions:
        """Permit every payment type supported by the high-level client."""
        return cls(
            allow_any_asset=True,
            allowed_assets=(),
            allowed_networks=frozenset(),
            allowed_origins=None,
            max_amount_per_payment=None,
            origin_overrides={},
        )

    def authorize(self, candidate: PaymentCandidate) -> AuthorizedPayment:
        """Authorize normalized challenge terms or raise ``PermissionDeniedError``."""
        origin = _origin(candidate.origin)
        if self._allowed_origins is not None and origin not in self._allowed_origins:
            raise _denial("origin_not_allowed", f"origin {origin} is not allowed")
        if self._allowed_networks and candidate.network not in self._allowed_networks:
            raise _denial("network_not_allowed", f"network {candidate.network} is not allowed")
        if candidate.amount < 0:
            raise _denial("invalid_challenge_terms", "challenge amount is not a non-negative integer")
        try:
            mint = _mint(candidate.network, candidate.mint)
        except PermissionConfigurationError as exc:
            raise _denial("invalid_challenge_terms", str(exc)) from exc

        global_asset = next((item for item in self._allowed_assets if _matches(item, candidate.network, mint)), None)
        known_asset = symbol_for(mint, candidate.network) is not None
        if not known_asset and not self._allow_any_asset and global_asset is None:
            raise _denial("asset_not_allowed", f"asset {mint} is not allowed on {candidate.network}")

        override = self._origin_overrides.get(origin)
        origin_asset = next(
            (item for item in (override.asset_caps if override else ()) if _matches(item, candidate.network, mint)),
            None,
        )
        cap: int | None = None
        if origin_asset is not None and origin_asset.max_amount_per_payment is not None:
            cap = origin_asset.max_amount_per_payment
        elif known_asset and override is not None and override.max_amount_per_payment is not None:
            cap = (
                None if override.max_amount_per_payment is False else _usd_atomic(override.max_amount_per_payment, mint)
            )
        elif global_asset is not None and global_asset.max_amount_per_payment is not None:
            cap = global_asset.max_amount_per_payment
        elif known_asset and self._max_amount_per_payment is not None:
            cap = _usd_atomic(self._max_amount_per_payment, mint)

        if cap is not None and candidate.amount > cap:
            raise PermissionDeniedError(
                (
                    PermissionRejection(
                        "amount_exceeds_limit", f"payment amount exceeds cap {cap}", candidate.amount, cap
                    ),
                )
            )
        return AuthorizedPayment(cap)


class ClientPermissionsBuilder:
    """Fluent builder for :class:`ClientPermissions`."""

    def __init__(self) -> None:
        self._allow_any_asset = False
        self._allowed_assets: list[AssetPermission] = []
        self._allowed_networks: set[SolanaNetwork] = {"mainnet"}
        self._allowed_origins: set[str] | None = None
        self._max: UsdAmount | None = usd("1")
        self._origin_overrides: dict[str, OriginPermissionOverride] = {}

    def allow_origin(self, origin: str) -> Self:
        """Restrict payments to an exact origin; the first call creates an allowlist."""
        if self._allowed_origins is None:
            self._allowed_origins = set()
        self._allowed_origins.add(_origin(origin))
        return self

    def allow_any_origin(self) -> Self:
        """Permit challenges from any HTTP(S) origin."""
        self._allowed_origins = None
        return self

    def allow_network(self, network: SolanaNetwork) -> Self:
        """Add a permitted Solana cluster."""
        self._allowed_networks.add(_network(network))
        return self

    def only_network(self, network: SolanaNetwork) -> Self:
        """Replace the default network set with one Solana cluster."""
        self._allowed_networks = {_network(network)}
        return self

    def max_amount_per_payment(self, cap: UsdAmount) -> Self:
        """Set the global per-payment cap for known stablecoins."""
        self._max = cap
        return self

    def without_amount_cap(self) -> Self:
        """Remove the global stablecoin cap."""
        self._max = None
        return self

    def allow_any_asset(self) -> Self:
        """Permit every SPL mint; unknown assets remain uncapped unless listed."""
        self._allow_any_asset = True
        return self

    def allow_asset(self, permission: AssetPermission) -> Self:
        """Add one permitted asset and optional atomic cap."""
        self._allowed_assets.append(permission)
        return self

    def override_origin(self, permission: OriginPermissionOverride) -> Self:
        """Add an exact-origin cap override; this does not grant the origin."""
        self._origin_overrides[permission.origin] = permission
        return self

    def build(self) -> ClientPermissions:
        """Build an immutable permission policy snapshot."""
        return ClientPermissions(
            allow_any_asset=self._allow_any_asset,
            allowed_assets=tuple(self._allowed_assets),
            allowed_networks=frozenset(self._allowed_networks),
            allowed_origins=None if self._allowed_origins is None else frozenset(self._allowed_origins),
            max_amount_per_payment=self._max,
            origin_overrides=self._origin_overrides,
        )


def _network(value: SolanaNetwork) -> SolanaNetwork:
    if value not in _NETWORKS:
        raise PermissionConfigurationError(f"invalid Solana network: {value}")
    return value


def _origin(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise PermissionConfigurationError(f"invalid HTTP(S) origin: {value}")
    try:
        port = parsed.port
    except ValueError as exc:
        raise PermissionConfigurationError(f"invalid HTTP(S) origin: {value}") from exc
    host = parsed.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    default_port = (
        port is None or (parsed.scheme == "http" and port == 80) or (parsed.scheme == "https" and port == 443)
    )
    return f"{parsed.scheme}://{host}" if default_port else f"{parsed.scheme}://{host}:{port}"


def _mint(network: SolanaNetwork, asset: str) -> str:
    mint = resolve_stablecoin_mint(asset, network) or asset
    try:
        return str(Pubkey.from_string(mint))
    except ValueError as exc:
        raise PermissionConfigurationError(f"invalid Solana asset: {asset}") from exc


def _matches(permission: AssetPermission, network: SolanaNetwork, mint: str) -> bool:
    return permission.network == network and permission.mint == mint


def _usd_atomic(amount: UsdAmount, mint: str) -> int:
    decimals = stablecoin_decimals(mint)
    return amount.micro_usd * (10**decimals) // 1_000_000


def _denial(code: PermissionDeniedCode, message: str) -> PermissionDeniedError:
    return PermissionDeniedError((PermissionRejection(code, message),))


__all__ = [
    "AssetPermission",
    "AuthorizedPayment",
    "ClientPermissions",
    "ClientPermissionsBuilder",
    "OriginPermissionOverride",
    "OriginPermissionOverrideBuilder",
    "PaymentCandidate",
    "PermissionConfigurationError",
    "PermissionDeniedCode",
    "PermissionDeniedError",
    "PermissionRejection",
    "SolanaNetwork",
    "UsdAmount",
    "usd",
]
