"""Client-side trust policy for server-signed x402 ``batch-settlement`` channels.

In server-signed mode the channel's on-chain ``authorized_signer`` is the
resource operator, so the operator can sign a voucher for the whole unspent
deposit without another client signature. A client therefore never enters that
mode because a 402 asked for it: only for operator keys it trusts out of band,
and only up to an escrow it chose. That is what the SVM ``batch-settlement``
spec requires of a client in server-signed mode (sections 4.1 and 8); the cap
itself is a client-side policy, shaped like the one in x402 PR #23
``client/trust.ts``.

The cap is a USD amount for known stablecoins (floored to atomic units with
``Decimal``), ``False`` to lift it, or an integer atomic cap per opted-in asset.
Mint addresses are compared exactly (base58 is case-sensitive); only stablecoin
symbols such as ``"usdc"`` match case-insensitively.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from decimal import ROUND_FLOOR, Decimal, InvalidOperation
from typing import Any, Literal, NotRequired, TypedDict, cast

from solana_pay_kit._paycore.solana import KNOWN_MINTS, STABLECOIN_DECIMALS, stablecoin_symbol
from solana_pay_kit.errors import ConfigurationError, PayKitError
from solana_pay_kit.protocols.x402.batch_settlement.types import BATCH_SETTLEMENT_SCHEME

__all__ = [
    "DEFAULT_SERVER_SIGNED_MAX_DEPOSIT",
    "ServerSignedChannelsAsset",
    "ServerSignedChannelsPolicy",
    "ServerSignedGrant",
    "ServerSignedTrust",
    "UntrustedOperatorError",
    "client_signed_fallback",
    "is_server_signed_accept",
]

#: Default escrow cap for known stablecoins under a trusted operator.
DEFAULT_SERVER_SIGNED_MAX_DEPOSIT = "$1"

_ATOMIC = re.compile(r"[1-9][0-9]*")
_USD = re.compile(r"\$?([0-9]+(\.[0-9]+)?)")
_U64 = re.compile(r"[0-9]+")


class ServerSignedChannelsAsset(TypedDict):
    """An opted-in non-default asset; ``maxDeposit`` is an integer atomic cap, omitted to leave it uncapped."""

    network: str
    asset: str
    maxDeposit: NotRequired[str]


@dataclass(frozen=True)
class ServerSignedChannelsPolicy:
    """Which operators may hold this client's voucher-signing authority, and how much escrow to lock under them."""

    allowed_operators: tuple[str, ...]
    #: USD cap on one channel's total escrow for known stablecoins; ``False`` lifts it.
    max_deposit: str | Literal[False] = DEFAULT_SERVER_SIGNED_MAX_DEPOSIT
    allowed_assets: tuple[ServerSignedChannelsAsset, ...] = ()


@dataclass(frozen=True)
class ServerSignedGrant:
    """A matched grant: the operator and the atomic escrow cap for the accept's asset (``None`` = uncapped)."""

    operator: str
    max_deposit: int | None


class UntrustedOperatorError(PayKitError):
    """A server-signed accept this client will not act on; ``operator`` names the advertised key."""

    def __init__(self, message: str, operator: str | None) -> None:
        super().__init__(message)
        self.operator = operator


def is_server_signed_accept(accept: Mapping[str, Any]) -> bool:
    """Whether an accept asks the client to delegate voucher signing to the operator."""
    extra = accept.get("extra")
    return (
        accept.get("scheme") == BATCH_SETTLEMENT_SCHEME
        and isinstance(extra, dict)
        and cast("dict[str, Any]", extra).get("voucherSigner") == "server"
    )


def _untrusted_message(*operators: str | None) -> str:
    who = ", ".join(key for key in operators if key) or "<unknown>"
    return (
        f"batch-settlement: this resource requires a server-signed channel whose operator ({who}) "
        "can claim up to the full channel deposit without further client signatures. "
        "Trust it explicitly by listing the key in ServerSignedChannelsPolicy.allowed_operators, "
        "and bound what it could take with ServerSignedChannelsPolicy.max_deposit."
    )


def _network_matches(pattern: str, network: str) -> bool:
    return pattern == network or (pattern.endswith(":*") and network.startswith(pattern[:-1]))


def _usd_to_atomic(usd: str, decimals: int) -> int:
    return int((Decimal(usd) * 10**decimals).to_integral_value(rounding=ROUND_FLOOR))


class ServerSignedTrust:
    """Decides which server-signed accepts the client may act on, and up to what escrow."""

    def __init__(self, policy: ServerSignedChannelsPolicy | None) -> None:
        """Validate the policy; ``None`` trusts no operator."""
        policy = policy or ServerSignedChannelsPolicy(allowed_operators=())
        for index, operator in enumerate(policy.allowed_operators):
            if not isinstance(operator, str) or not operator:  # pyright: ignore[reportUnnecessaryIsInstance]
                raise ConfigurationError(f"allowed_operators[{index}] must be a non-empty base58 key")
        self._operators = frozenset(policy.allowed_operators)
        self._usd_cap: str | None = None
        if policy.max_deposit is not False:
            match = _USD.fullmatch(policy.max_deposit)
            try:
                positive = match is not None and Decimal(match.group(1)) > 0
            except InvalidOperation:  # pragma: no cover - the pattern admits only plain decimals
                positive = False
            if match is None or not positive:
                raise ConfigurationError(f"max_deposit must be a positive USD amount, got {policy.max_deposit!r}")
            self._usd_cap = match.group(1)
        for index, entry in enumerate(policy.allowed_assets):
            cap = entry.get("maxDeposit")
            if cap is not None and _ATOMIC.fullmatch(cap) is None:
                raise ConfigurationError(
                    f"allowed_assets[{index}].maxDeposit must be a positive integer atomic amount, "
                    f"not a dollar value; got {cap!r}"
                )
        self._assets = policy.allowed_assets

    def grant_for(self, requirements: Mapping[str, Any]) -> ServerSignedGrant:
        """The grant for a server-signed accept; raises :class:`UntrustedOperatorError` when not allowed."""
        extra = cast("Mapping[str, Any]", requirements.get("extra") or {})
        operator = extra.get("operator")
        if not isinstance(operator, str) or operator not in self._operators:
            name = operator if isinstance(operator, str) else None
            raise UntrustedOperatorError(_untrusted_message(name), name)
        asset = str(requirements.get("asset", ""))
        network = str(requirements.get("network", ""))
        # Known stablecoin mints are recognized on any network: a localnet fork
        # keeps the mainnet mints under the devnet CAIP-2.
        symbol = None if asset.upper() in KNOWN_MINTS else stablecoin_symbol(asset)
        for entry in self._assets:
            same_asset = entry["asset"] == asset or (symbol is not None and entry["asset"].upper() == symbol)
            if _network_matches(entry["network"], network) and same_asset:
                cap = entry.get("maxDeposit")
                return ServerSignedGrant(operator, None if cap is None else int(cap))
        if symbol is None:
            raise UntrustedOperatorError(
                f"batch-settlement: {asset} on {network} is not a known stablecoin. Add it to "
                "ServerSignedChannelsPolicy.allowed_assets with an atomic maxDeposit before locking "
                f"escrow under operator {operator}.",
                operator,
            )
        if self._usd_cap is None:
            return ServerSignedGrant(operator, None)
        return ServerSignedGrant(operator, _usd_to_atomic(self._usd_cap, STABLECOIN_DECIMALS[symbol]))

    def filter_accepts(self, accepts: Sequence[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
        """Drop untrusted server-signed accepts and move trusted ones ahead of the same network's batch accepts.

        Accepts of other schemes keep their places. Raises
        :class:`UntrustedOperatorError` when every accept needed an untrusted operator.
        """
        trusted: list[Mapping[str, Any]] = []
        refused: list[str | None] = []
        remaining: list[Mapping[str, Any]] = []
        for accept in accepts:
            if not is_server_signed_accept(accept):
                remaining.append(accept)
                continue
            try:
                self.grant_for(accept)
            except UntrustedOperatorError as exc:
                refused.append(exc.operator or "<missing>")
                continue
            trusted.append(accept)
            remaining.append(accept)
        if not remaining and refused:
            raise UntrustedOperatorError(_untrusted_message(*refused), refused[0])
        if not trusted:
            return remaining
        reordered: list[Mapping[str, Any]] = []
        seen: set[str] = set()
        for accept in remaining:
            network = str(accept.get("network"))
            if accept.get("scheme") == BATCH_SETTLEMENT_SCHEME and network not in seen:
                seen.add(network)
                reordered.extend(c for c in trusted if c.get("network") == network)
            if not any(accept is t for t in trusted):
                reordered.append(accept)
        return reordered


def client_signed_fallback(payment_required: Mapping[str, Any], refused: Mapping[str, Any]) -> Mapping[str, Any] | None:
    """The same resource's client-signed accept to pay instead of an untrusted server-signed one.

    Only a ``batch-settlement`` accept on the same network and asset, in client
    mode, for no more than the refused amount: a fallback never widens what the
    client already agreed to pay.
    """
    refused_amount = refused.get("amount")
    if not isinstance(refused_amount, str) or _U64.fullmatch(refused_amount) is None:
        return None
    for accept in cast("list[Mapping[str, Any]]", payment_required.get("accepts") or []):
        amount = accept.get("amount")
        extra = cast("Mapping[str, Any]", accept.get("extra") or {})
        if (
            accept is not refused
            and accept.get("scheme") == BATCH_SETTLEMENT_SCHEME
            and accept.get("network") == refused.get("network")
            and accept.get("asset") == refused.get("asset")
            and extra.get("voucherSigner", "client") == "client"
            and isinstance(amount, str)
            and _U64.fullmatch(amount) is not None
            and int(amount) <= int(refused_amount)
        ):
            return accept
    return None
