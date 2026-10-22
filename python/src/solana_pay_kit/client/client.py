"""High-level permissioned client for MPP and x402 HTTP challenges."""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable, Sequence
from typing import Any, Literal, Self, cast
from urllib.parse import urlsplit

import httpx
from solana_keychain import TransactionSigner

from solana_pay_kit._paycore.mints import resolve_stablecoin_mint
from solana_pay_kit._paycore.network import SOLANA_DEVNET_CAIP2, SOLANA_MAINNET_CAIP2
from solana_pay_kit.client.permissions import (
    ClientPermissions,
    PaymentCandidate,
    PaymentDestination,
    PermissionDeniedError,
    PermissionRejection,
    SolanaNetwork,
)
from solana_pay_kit.protocols.mpp.client.charge import build_credential_header
from solana_pay_kit.protocols.mpp.core.headers import parse_www_authenticate_all
from solana_pay_kit.protocols.x402.client.exact.payment import (
    ChallengeSelection,
    build_payment_header,
    build_payment_header_legacy,
    parse_x402_challenge_with_version,
    x402_exact_pay_to,
)
from solana_pay_kit.protocols.x402.client.exact.transport import PAYMENT_SIGNATURE_HEADER
from solana_pay_kit.protocols.x402.exact.legacy import X402_LEGACY_PAYMENT_HEADER
from solana_pay_kit.protocols.x402.exact.verify import X402_VERSION_V1

logger = logging.getLogger("solana_pay_kit")


class PermissionedPaymentTransport(httpx.AsyncBaseTransport):
    """Transport that authorizes MPP/x402 challenges before signing."""

    def __init__(
        self,
        signer: TransactionSigner,
        rpc: Any,
        *,
        network: SolanaNetwork,
        permissions: ClientPermissions,
        protocols: Sequence[str],
        base_transport: httpx.AsyncBaseTransport | None = None,
        recent_blockhash_provider: Callable[[], Awaitable[str] | str] | None = None,
    ) -> None:
        self._signer = signer
        self._rpc = rpc
        self._network: SolanaNetwork = network
        self._permissions = permissions
        self._protocols = frozenset(protocols)
        self._inner = base_transport or httpx.AsyncHTTPTransport()
        self._recent_blockhash_provider = recent_blockhash_provider

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        """Send a request and perform at most one permissioned payment retry."""
        # Buffer once so the same body can be replayed on the single paid
        # retry. ``Request.aread`` replaces the incoming stream with a
        # replayable byte stream in httpx.
        await request.aread()
        response = await self._inner.handle_async_request(request)
        if response.status_code != 402:
            return response
        await response.aread()
        origin = _request_origin(request.url)
        rejections: list[PermissionRejection] = []

        if "mpp" in self._protocols:
            challenges = parse_www_authenticate_all(response.headers.get_list("www-authenticate"))
            challenge = next(
                (item for item in challenges if item.method == "solana" and item.intent == "charge"),
                None,
            )
            if challenge is not None:
                try:
                    raw = challenge.decode_request()
                    amount = _amount(raw.get("amount"))
                    currency: object = raw.get("currency")
                    details_value: object = raw.get("methodDetails")
                    invalid_details = details_value is not None and not isinstance(details_value, dict)
                    if not isinstance(currency, str) or invalid_details:
                        raise _invalid("invalid MPP charge terms")
                    details = {} if details_value is None else cast("dict[str, object]", details_value)
                    challenge_network = details.get("network")
                    if challenge_network is not None and not isinstance(challenge_network, str):
                        raise _invalid("invalid MPP network")
                    # draft-solana-charge-00: methodDetails.network "Defaults to
                    # "mainnet" if omitted". x402 has no such default.
                    network = _network(challenge_network or "mainnet", self._network)
                    mint = resolve_stablecoin_mint(currency, network) or currency
                    destinations = _charge_destinations(raw.get("recipient"), amount, details.get("splits"))
                    authorized = self._permissions.authorize(
                        PaymentCandidate(amount, mint, network, origin, destinations=destinations)
                    )
                    header = await build_credential_header(
                        signer=self._signer,
                        rpc_client=self._rpc,
                        challenge=challenge,
                        max_amount_base_units=authorized.max_amount_atomic,
                        expected_network=challenge_network,
                    )
                    return await self._retry(request, "authorization", header)
                except PermissionDeniedError as exc:
                    rejections.extend(exc.rejections)
                except Exception:  # noqa: BLE001 - an unusable MPP offer may fall back to x402
                    logger.warning("failed to build MPP payment credential", exc_info=True)

        if "x402" in self._protocols:
            body = response.text if response.content else None
            requirement, version = parse_x402_challenge_with_version(
                dict(response.headers),
                body,
                ChallengeSelection(network=self._network),
            )
            if requirement is not None:
                try:
                    network = _network(requirement.get("network"), self._network)
                    # The same fields build_payment signs (RULINGS X1): payTo
                    # and asset come from their x402 fields only, so a legacy
                    # alias such as recipient is ignored. The amount alone
                    # falls back to the v1 maxAmountRequired, exactly as the
                    # builder reads it, so approval and transfer agree.
                    terms = cast("dict[str, object]", requirement)
                    raw_amount = terms.get("amount")
                    if raw_amount is None:
                        raw_amount = terms.get("maxAmountRequired")
                    amount = _amount(raw_amount)
                    asset = requirement.get("asset")
                    destinations = (PaymentDestination(x402_exact_pay_to(requirement), amount),)
                    self._permissions.authorize(
                        PaymentCandidate(amount, asset, network, origin, destinations=destinations)
                    )
                    legacy = version == X402_VERSION_V1
                    builder = build_payment_header_legacy if legacy else build_payment_header
                    header = await builder(
                        self._signer,
                        self._rpc,
                        requirement,
                        recent_blockhash_provider=self._recent_blockhash_provider,
                    )
                    name = X402_LEGACY_PAYMENT_HEADER if legacy else PAYMENT_SIGNATURE_HEADER
                    return await self._retry(request, name, header)
                except PermissionDeniedError as exc:
                    rejections.extend(exc.rejections)
                except Exception:  # noqa: BLE001 - preserve the original 402 on build failure
                    logger.warning("failed to build x402 payment credential", exc_info=True)

        if rejections:
            raise PermissionDeniedError(tuple(rejections))
        return response

    async def _retry(self, request: httpx.Request, name: str, value: str) -> httpx.Response:
        headers = dict(request.headers)
        headers[name] = value
        retry = httpx.Request(
            request.method,
            request.url,
            headers=headers,
            content=request.content,
            extensions=request.extensions,
        )
        return await self._inner.handle_async_request(retry)

    async def aclose(self) -> None:
        """Close the wrapped transport."""
        await self._inner.aclose()


class PayKitClient:
    """Permissioned async HTTP client that pays supported 402 challenges."""

    def __init__(self, client: httpx.AsyncClient) -> None:
        self._client = client

    @classmethod
    def builder(cls) -> PayKitClientBuilder:
        """Start a fluent client builder."""
        return PayKitClientBuilder()

    async def request(self, method: str, url: httpx.URL | str, **kwargs: Any) -> httpx.Response:
        """Send a payment-aware HTTP request."""
        return await self._client.request(method, url, **kwargs)

    async def get(self, url: httpx.URL | str, **kwargs: Any) -> httpx.Response:
        """Send a payment-aware GET request."""
        return await self._client.get(url, **kwargs)

    async def post(self, url: httpx.URL | str, **kwargs: Any) -> httpx.Response:
        """Send a payment-aware POST request."""
        return await self._client.post(url, **kwargs)

    async def aclose(self) -> None:
        """Close the underlying HTTP client."""
        await self._client.aclose()

    async def __aenter__(self) -> PayKitClient:
        return self

    async def __aexit__(self, *_args: object) -> None:
        await self.aclose()


class PayKitClientBuilder:
    """Fluent builder for :class:`PayKitClient`."""

    def __init__(self) -> None:
        self._signer: TransactionSigner | None = None
        self._rpc: Any = None
        self._network: SolanaNetwork = "mainnet"
        self._permissions: ClientPermissions | Literal[False] | None = None
        self._protocols: tuple[str, ...] = ("mpp", "x402")
        self._base_transport: httpx.AsyncBaseTransport | None = None
        self._client_kwargs: dict[str, Any] = {}
        self._recent_blockhash_provider: Callable[[], Awaitable[str] | str] | None = None

    def signer(self, signer: TransactionSigner) -> Self:
        """Set the payer signer."""
        self._signer = signer
        return self

    def rpc(self, rpc: Any) -> Self:
        """Set the async Solana RPC client used to build transactions."""
        self._rpc = rpc
        return self

    def network(self, network: SolanaNetwork) -> Self:
        """Set the Solana cluster; defaults to ``mainnet``."""
        self._network = network
        return self

    def permissions(self, permissions: ClientPermissions | Literal[False]) -> Self:
        """Replace the safe default policy; ``False`` explicitly disables it."""
        self._permissions = permissions
        return self

    def accept(self, protocols: Sequence[str]) -> Self:
        """Restrict accepted protocols to ``mpp`` and/or ``x402``."""
        values = tuple(protocols)
        if not values or any(value not in {"mpp", "x402"} for value in values):
            raise ValueError("accept must contain mpp and/or x402")
        self._protocols = values
        return self

    def base_transport(self, transport: httpx.AsyncBaseTransport) -> Self:
        """Set the underlying HTTP transport, primarily for proxies and tests."""
        self._base_transport = transport
        return self

    def httpx_options(self, **kwargs: Any) -> Self:
        """Set keyword arguments forwarded to ``httpx.AsyncClient``."""
        self._client_kwargs.update(kwargs)
        return self

    def recent_blockhash_provider(self, provider: Callable[[], Awaitable[str] | str]) -> Self:
        """Override x402 blockhash lookup."""
        self._recent_blockhash_provider = provider
        return self

    def build(self) -> PayKitClient:
        """Validate configuration and build the async client."""
        if self._signer is None:
            raise ValueError("PayKitClient requires a signer")
        if self._rpc is None:
            raise ValueError("PayKitClient requires an RPC client")
        permissions = (
            ClientPermissions.unrestricted()
            if self._permissions is False
            else self._permissions or ClientPermissions.builder().only_network(self._network).build()
        )
        transport = PermissionedPaymentTransport(
            self._signer,
            self._rpc,
            network=self._network,
            permissions=permissions,
            protocols=self._protocols,
            base_transport=self._base_transport,
            recent_blockhash_provider=self._recent_blockhash_provider,
        )
        return PayKitClient(httpx.AsyncClient(transport=transport, **self._client_kwargs))


def _amount(value: object) -> int:
    if not isinstance(value, str) or not value.isdigit():
        raise _invalid(f"invalid payment amount: {value!r}")
    return int(value)


def _charge_destinations(recipient: object, amount: int, splits: object) -> tuple[PaymentDestination, ...]:
    """Every transfer leg of an MPP charge, as the charge builder pays it.

    The primary ``recipient`` receives ``amount`` minus the splits, followed by
    each ``methodDetails.splits`` entry in order.
    """
    if not isinstance(recipient, str):
        raise _invalid("MPP charge names no recipient")
    if splits is not None and not isinstance(splits, list):
        raise _invalid("invalid MPP splits")
    legs: list[PaymentDestination] = []
    for split in cast("list[object]", splits or []):
        if not isinstance(split, dict):
            raise _invalid("invalid MPP split")
        entry = cast("dict[str, object]", split)
        split_recipient = entry.get("recipient")
        if not isinstance(split_recipient, str):
            raise _invalid("invalid MPP split recipient")
        legs.append(PaymentDestination(split_recipient, _amount(entry.get("amount"))))
    primary = amount - sum(leg.amount for leg in legs)
    if primary <= 0:
        raise _invalid("MPP splits leave nothing for the recipient")
    return (PaymentDestination(recipient, primary), *legs)


def _network(value: object, configured: SolanaNetwork) -> SolanaNetwork:
    # Never default a missing network: an offer that names no ledger would
    # otherwise be approved and signed as a mainnet payment.
    if value is None:
        raise _invalid("payment offer is missing network")
    if value in {"mainnet", "mainnet-beta", SOLANA_MAINNET_CAIP2}:
        return "mainnet"
    if value == "localnet":
        return "localnet"
    if value in {"devnet", SOLANA_DEVNET_CAIP2}:
        return "localnet" if configured == "localnet" else "devnet"
    raise _invalid(f"unsupported Solana network: {value!r}")


def _request_origin(url: httpx.URL) -> str:
    parsed = urlsplit(str(url))
    return f"{parsed.scheme}://{parsed.netloc}"


def _invalid(message: str) -> PermissionDeniedError:
    return PermissionDeniedError((PermissionRejection("invalid_challenge_terms", message),))


__all__ = ["PayKitClient", "PayKitClientBuilder", "PermissionedPaymentTransport"]
