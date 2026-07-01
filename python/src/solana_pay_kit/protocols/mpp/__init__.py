"""MPP charge adapter wrapping the solana_pay_kit.protocols.mpp server wire layer.

Mirrors PHP ``Protocols/Mpp/{Adapter,SecretResolver}`` and the Ruby
reference. The adapter never reimplements canonical JSON, header parsing,
challenge HMAC binding, or the on-chain Solana verifier; those all live in
:mod:`solana_pay_kit.protocols.mpp` and are reused per the blueprint reuse map. This module
only translates a unified :class:`solana_pay_kit.gate.Gate` into the wire request,
builds the 402 challenge, and runs cross-route-safe verification through
``solana_pay_kit.protocols.mpp.server.charge.Mpp.verify_credential_with_expected``.
"""

from __future__ import annotations

import contextlib
import logging
import os
import secrets
from collections.abc import Callable
from decimal import Decimal
from typing import TYPE_CHECKING, Any, TypedDict, cast

from solana_pay_kit._paycore.errors import PaymentError, canonical_code
from solana_pay_kit._paycore.protocol import Protocol
from solana_pay_kit._paycore.rpc import SolanaRpc
from solana_pay_kit._paycore.store import MemoryStore, Store
from solana_pay_kit.errors import InvalidProofError
from solana_pay_kit.payment import Payment
from solana_pay_kit.protocols.mpp.core.headers import format_receipt, format_www_authenticate, parse_authorization
from solana_pay_kit.protocols.mpp.intents.charge import ChargeRequest
from solana_pay_kit.protocols.mpp.server.charge import ChargeOptions, Mpp
from solana_pay_kit.protocols.mpp.server.charge import Config as MppServerConfig

if TYPE_CHECKING:
    from solana_pay_kit.config import Config
    from solana_pay_kit.gate import Gate
    from solana_pay_kit.price import Price

__all__ = ["MppAdapter", "SecretResolver"]


# --- MPP wire shapes --------------------------------------------------------
# TypedDicts describing the MPP offer/charge-request JSON dicts the adapter
# builds. They give precise static types over the wire payloads and never
# change the serialized bytes. Optional keys use ``total=False``.


class MppSplit(TypedDict):
    """A single fee split on an MPP offer or charge request."""

    recipient: str
    amount: str


class MppAcceptsEntryRequired(TypedDict):
    """The always-present keys of an MPP ``accepts[]`` offer entry."""

    protocol: str
    scheme: str
    network: str
    amount: str
    currency: str
    payTo: str
    realm: str


class MppAcceptsEntry(MppAcceptsEntryRequired, total=False):
    """One MPP ``accepts[]`` offer entry; ``splits`` present only with fees."""

    splits: list[MppSplit]


class MppMethodDetails(TypedDict, total=False):
    """The MPP ``request.methodDetails`` block (network always set)."""

    network: str
    splits: list[MppSplit]
    feePayer: bool
    feePayerKey: str
    recentBlockhash: str


logger = logging.getLogger(__name__)

# USDC/USDT/USDG/PYUSD/CASH are all 6-decimal mints; base units = amount * 1e6.
# Matches the PHP adapter's ``multipliedBy(1_000_000)`` conversion.
_BASE_UNIT_SCALE = 1_000_000

_DEFAULT_MPP_SECRET_ENV = "PAY_KIT_MPP_CHALLENGE_BINDING_SECRET"


class SecretResolver:
    """Auto-resolves the MPP HMAC challenge-binding secret (caveat #4).

    Mirrors PHP ``SecretResolver`` and Ruby PR #142. Resolution chain so the
    example apps boot without the operator setting anything:

      1. ``ENV[env_var]`` -- production pattern (orchestrator-supplied).
      2. ``./.env`` parsed for the same key -- sticky across restarts.
      3. Generate ``secrets.token_hex(32)`` and append to ``./.env`` (mode
         0600 when the file is created) so later boots reuse the value.

    If ``./.env`` is unwritable the in-memory generated value is kept and
    ``persisted`` is ``False``; the caller is expected to warn because the
    secret rotates per process and invalidates in-flight challenges on
    restart. The dotenv parser is intentionally a tolerant ~10-line reader so
    no dotenv dependency is pulled in for this one feature.
    """

    @staticmethod
    def resolve_mpp_secret(
        env_var: str = _DEFAULT_MPP_SECRET_ENV,
        dotenv_path: str | None = None,
    ) -> tuple[str, str, bool]:
        """Return ``(secret, source, persisted)`` for the binding secret."""
        path = dotenv_path if dotenv_path is not None else os.path.join(os.getcwd(), ".env")

        from_env = os.environ.get(env_var)
        if from_env:
            return (from_env, "env", True)

        from_dotenv = SecretResolver._read_dotenv(path, env_var)
        if from_dotenv is not None:
            return (from_dotenv, "dotenv", True)

        generated = secrets.token_hex(32)
        persisted = SecretResolver._append_to_dotenv(path, env_var, generated)
        if not persisted:
            logger.warning(
                "solana_pay_kit: could not persist MPP challenge-binding secret to %s; "
                "using an in-memory value that rotates per process and invalidates "
                "in-flight challenges on restart",
                path,
            )
        return (generated, "generated+persisted" if persisted else "generated", persisted)

    @staticmethod
    def _read_dotenv(path: str, key: str) -> str | None:
        """Tolerant dotenv reader: blanks, ``#`` comments, KEY=value, quotes."""
        try:
            with open(path, encoding="utf-8") as handle:
                for line in handle:
                    trimmed = line.strip()
                    if not trimmed or trimmed.startswith("#"):
                        continue
                    eq = trimmed.find("=")
                    if eq == -1:
                        continue
                    name = trimmed[:eq].strip()
                    if name != key:
                        continue
                    value = trimmed[eq + 1 :].strip()
                    if len(value) >= 2 and (
                        (value[0] == '"' and value[-1] == '"') or (value[0] == "'" and value[-1] == "'")
                    ):
                        value = value[1:-1]
                    return value or None
        except OSError:
            return None
        return None

    @staticmethod
    def _append_to_dotenv(path: str, key: str, value: str) -> bool:
        """Append ``KEY=value``; create at 0600 if absent. Returns success."""
        existed = os.path.isfile(path)
        try:
            with open(path, "a", encoding="utf-8") as handle:
                if not existed:
                    with contextlib.suppress(OSError):
                        os.chmod(path, 0o600)
                handle.write(f"{key}={value}\n")
            return True
        except OSError:
            return False


class MppAdapter:
    """Bridges a unified gate to ``solana_pay_kit.protocols.mpp.server.charge.Mpp`` charge flow."""

    def __init__(
        self,
        config: Config,
        replay_store: Store | None = None,
        recent_blockhash_provider: Callable[[], str | None] | None = None,
    ) -> None:
        self._config = config
        self._replay_store: Store = replay_store if replay_store is not None else MemoryStore()
        self._recent_blockhash_provider = recent_blockhash_provider
        # Cache one solana_pay_kit.protocols.mpp.Mpp per (payTo|coin) key, like the PHP
        # handlerCache, so the HMAC secret and RPC client are reused.
        self._handler_cache: dict[str, Mpp] = {}
        self._secret = self._resolve_secret()

    def _resolve_secret(self) -> str:
        """Resolve the HMAC binding secret: config override else caveat #4."""
        configured = self._config.mpp.challenge_binding_secret
        if configured:
            return configured
        secret, _source, _persisted = SecretResolver.resolve_mpp_secret()
        return secret

    # -- offer / challenge --------------------------------------------------

    def accepts_entry(self, gate: Gate, request: Any) -> MppAcceptsEntry:
        """Build one ``accepts[]`` entry advertising the MPP charge offer."""
        coin = self._settlement_coin(gate)
        pay_to = gate.pay_to or self._config.effective_recipient()
        entry: MppAcceptsEntry = {
            "protocol": "mpp",
            "scheme": "charge",
            "network": self._config.network.caip2(),
            "amount": str(self._price_units(gate.total())),
            "currency": coin,
            "payTo": pay_to,
            "realm": self._config.mpp.realm,
        }
        if gate.has_fees():
            entry["splits"] = [
                MppSplit(recipient=fee.recipient, amount=str(self._price_units(fee.price))) for fee in gate.fees
            ]
        return entry

    def challenge_headers(self, gate: Gate, request: Any) -> dict[str, str]:
        """Return the WWW-Authenticate header for the 402 MPP challenge."""
        mpp = self._server_for(gate)
        challenge = mpp.charge_with_options(self._human_amount(gate), self._charge_options(gate))
        return {"www-authenticate": format_www_authenticate(challenge)}

    # -- verify + settle ----------------------------------------------------

    async def verify_and_settle(self, gate: Gate, request: Any) -> Payment:
        """Verify the MPP credential and settle, pinning amount/currency/recipient.

        Cross-route replay protection: the route's expected
        :class:`ChargeRequest` is rebuilt here and passed to
        ``verify_credential_with_expected`` so a credential issued for a
        cheaper route fails on this route with a canonical mismatch code.
        """
        authorization = self._header(request, "authorization")
        if not authorization or not authorization.strip():
            raise InvalidProofError("solana_pay_kit: payment required", code=canonical_code(""))

        try:
            credential = parse_authorization(authorization)
        except Exception as exc:  # noqa: BLE001 - parse failures are 402s
            raise InvalidProofError(
                f"solana_pay_kit: could not parse Authorization: {exc}",
                code="payment_invalid",
            ) from exc

        mpp = self._server_for(gate)
        expected = self._charge_request_for(gate)

        # The cached ``solana_pay_kit.protocols.mpp.Mpp`` is built with ``rpc=None`` (the
        # adapter is constructed at boot, before any event loop exists).
        # Transaction verification + broadcast need a live RPC, so scope a
        # request-lifetime ``SolanaRpc`` to this verify via ``using_rpc``
        # and close it immediately afterwards. Mirrors the X402Adapter's
        # own-RPC pattern and the standalone harness python-server. The
        # ``using_rpc`` lock serialises the swap on this event loop.
        rpc = SolanaRpc(self._config.effective_rpc_url())
        try:
            async with mpp.using_rpc(rpc):
                receipt = await mpp.verify_credential_with_expected(credential, expected)
        except PaymentError as err:
            raise InvalidProofError(
                str(err) or "verification failed",
                code=canonical_code(err.code),
            ) from err
        finally:
            await rpc.aclose()

        # `payment-receipt` carries the canonical base64url-encoded MPP receipt
        # (clients parse it for the settle signature / Broadcast + Settled steps);
        # `x-payment-settlement-signature` is the raw tx signature for convenience.
        settlement_headers = {
            "payment-receipt": format_receipt(receipt),
            "x-payment-settlement-signature": receipt.reference,
        }
        return Payment(
            protocol=Protocol.MPP,
            transaction=receipt.reference,
            gate_name=gate.name,
            settlement_headers=settlement_headers,
            raw=authorization,
        )

    # -- internals ----------------------------------------------------------

    def _charge_request_for(self, gate: Gate) -> ChargeRequest:
        """Build the route's expected charge request from the gate."""
        coin = self._settlement_coin(gate)
        pay_to = gate.pay_to or self._config.effective_recipient()
        # Top-level amount is the total the customer pays (base + on-top fees),
        # matching accepts_entry()'s advertised gate.total(). The MPP wire
        # subtracts sum(splits) to get the primary recipient's share, so using
        # the bare base here would let a fee_on_top gate accept an underpayment.
        amount = str(self._price_units(gate.total()))
        # Pay's MPP client filters challenges by the short network slug
        # ("mainnet"/"devnet"/"localnet") in request.methodDetails.network
        # (rust/crates/core/src/client/mpp.rs). Advertise the same slug
        # Mints::resolve uses so `pay --sandbox --mpp curl` matches.
        method_details: MppMethodDetails = {"network": self._config.network.mints_label()}
        if gate.has_fees():
            method_details["splits"] = [
                MppSplit(recipient=fee.recipient, amount=str(self._price_units(fee.price))) for fee in gate.fees
            ]
        signer = self._config.operator.signer
        if self._config.operator.fee_payer and signer is not None:
            method_details["feePayer"] = True
            method_details["feePayerKey"] = signer.pubkey()
        # Embed the server's recent blockhash when a provider is wired
        # (caveat #5). Injected via kwarg so unit tests stay offline; the
        # pull-mode MPP verifier ignores an unused blockhash on real nets.
        if self._recent_blockhash_provider is not None:
            blockhash = self._recent_blockhash_provider()
            if blockhash:
                method_details["recentBlockhash"] = blockhash
        # ChargeRequest.method_details is the untyped solana_pay_kit.protocols.mpp wire shape
        # (dict[str, Any] | None); cast the precise TypedDict at the boundary.
        return ChargeRequest(
            amount=amount,
            currency=coin,
            recipient=pay_to,
            description=gate.description or "",
            external_id=gate.external_id or "",
            method_details=cast("dict[str, Any]", method_details) or None,
        )

    def _charge_options(self, gate: Gate) -> ChargeOptions:
        """Build ChargeOptions mirroring the route's charge request."""
        from solana_pay_kit.protocols.mpp.core.expires import seconds

        # Derive the challenge expiry from MppConfig.expires_in; without this
        # the wire layer falls back to its hard-coded 5-minute default and
        # MppConfig(expires_in=...) is silently ignored.
        options = ChargeOptions(
            description=gate.description or "",
            external_id=gate.external_id or "",
            expires=seconds(self._config.mpp.expires_in),
        )
        if gate.has_fees():
            # ChargeOptions.splits is the untyped solana_pay_kit.protocols.mpp list[dict]; build the
            # precise MppSplit shape and cast at the boundary.
            splits: list[MppSplit] = [
                MppSplit(recipient=fee.recipient, amount=str(self._price_units(fee.price))) for fee in gate.fees
            ]
            options.splits = cast("list[dict[str, Any]]", splits)
        signer = self._config.operator.signer
        if self._config.operator.fee_payer and signer is not None:
            options.fee_payer = True
        return options

    def _server_for(self, gate: Gate) -> Mpp:
        """Return a cached ``solana_pay_kit.protocols.mpp.Mpp`` keyed on (payTo|coin)."""
        coin = self._settlement_coin(gate)
        pay_to = gate.pay_to or self._config.effective_recipient()
        key = f"{pay_to}|{coin}"
        cached = self._handler_cache.get(key)
        if cached is not None:
            return cached

        fee_payer_signer = self._fee_payer_keypair()
        server_config = MppServerConfig(
            recipient=pay_to,
            currency=coin,
            decimals=6,
            network=self._config.network.mints_label(),
            rpc_url=self._config.effective_rpc_url(),
            secret_key=self._secret,
            realm=self._config.mpp.realm,
            fee_payer_signer=fee_payer_signer,
            store=self._replay_store,
            rpc=None,
        )
        mpp = Mpp(server_config)
        self._handler_cache[key] = mpp
        return mpp

    def _fee_payer_keypair(self) -> Any:
        """Materialize a solders Keypair fee payer when the operator sponsors."""
        signer = self._config.operator.signer
        if not self._config.operator.fee_payer or signer is None:
            return None
        from solders.keypair import Keypair

        return Keypair.from_bytes(signer.secret_key())

    def _settlement_coin(self, gate: Gate) -> str:
        """Pick the settlement coin: gate primary coin else config default."""
        primary = gate.amount.primary_coin()
        if primary is not None:
            return primary.value
        return self._config.stablecoins[0].value

    def _human_amount(self, gate: Gate) -> str:
        """Charge amount as a human decimal string the wire re-parses.

        Uses ``gate.total()`` (base + on-top fees) so the issued challenge's
        top-level ``request.amount`` is the total the customer pays. The MPP
        wire derives the primary recipient's share as ``amount - sum(splits)``
        (rust client charge.rs), so advertising the base here would let a
        fee_on_top gate accept an underpayment that matched ``accepts_entry``'s
        advertised total.
        """
        return gate.total().amount_string()

    def _price_units(self, price: Price) -> int:
        """Convert a Decimal price to 6-decimal base units (no float)."""
        return int((Decimal(price.amount) * _BASE_UNIT_SCALE).to_integral_value())

    @staticmethod
    def _header(request: Any, name: str) -> str:
        """Read a header off a generic request bag (dict-like or .headers)."""
        headers: object = getattr(request, "headers", None)
        if headers is None and isinstance(request, dict):
            request_map = cast("dict[str, object]", request)
            headers = request_map.get("headers", request_map)
        if headers is None:
            return ""
        getter = getattr(headers, "get", None)
        if callable(getter):
            value: object = getter(name)
            if value is None:
                value = getter(name.title())
            return str(value) if value else ""
        return ""
