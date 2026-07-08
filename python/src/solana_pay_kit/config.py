"""Boot-time configuration: ``configure`` builder, sub-configs, and singleton.

The public ``configure(**kwargs)`` entry point builds a frozen :class:`Config`,
runs the operator default-resolution, applies the boot-time safety rules
(demo-signer-on-mainnet refusal, public-mainnet-RPC warning), auto-resolves the
MPP HMAC challenge-binding secret when unset, and runs the live-RPC preflight
unless disabled. It then stores the result in a module-level singleton readable
through :func:`config`. ``configure_from`` drives the same builder from
environment variables via pydantic-settings.

Mirrors Ruby ``PayKit::Config`` (``VALID_NETWORKS``, ``PUBLIC_RPC_URLS``,
``deprecation_warning_for`` warn-once) and PHP ``PayKit\\Config``. Deprecated
field/env names route to the new surface and emit a one-time ``DeprecationWarning``
plus a ``logging`` record per key.
"""

from __future__ import annotations

import logging
import warnings
from typing import Annotated, Any, Literal

import pydantic
import pydantic_settings
from pydantic import Strict

from solana_pay_kit._paycore.network import Network
from solana_pay_kit._paycore.protocol import Protocol
from solana_pay_kit._paycore.stablecoin import Stablecoin
from solana_pay_kit.errors import ConfigurationError, DemoSignerOnMainnetError
from solana_pay_kit.operator import Operator
from solana_pay_kit.signer import LocalSigner

__all__ = [
    "Config",
    "X402Config",
    "MppConfig",
    "configure",
    "configure_from",
    "config",
    "reset",
]

logger = logging.getLogger("solana_pay_kit")

# Module-level singleton. ``None`` until the first ``configure``/``config`` call.
_config: Config | None = None

# Warn-once memo for deprecated kwarg/field/env names. Keyed by the canonical
# deprecation key so a setter used in a loop logs at most one warning per process
# (mirrors Ruby ``Config.deprecation_warning_for``).
_warned_deprecations: set[str] = set()

# Old kwarg name -> (canonical key, human-readable migration suggestion). Routed
# by the builder before constructing the immutable Config.
_DEPRECATED_KWARGS: dict[str, tuple[str, str]] = {
    "pay_to": (
        "pay_to",
        "use operator=Operator(recipient=...)",
    ),
    "facilitator": (
        "x402.facilitator",
        "this field historically held the Solana RPC URL; use rpc_url instead. "
        "The new x402.facilitator_url is for facilitator delegation only.",
    ),
    "facilitator_secret_key": (
        "x402.facilitator_secret_key",
        "use operator=Operator(signer=Signer.json(...)) or x402=X402Config(signer=...)",
    ),
    "secret": (
        "mpp.secret",
        "use mpp=MppConfig(challenge_binding_secret=...) (matches draft-httpauth-payment-00 spec vocabulary)",
    ),
}


def _deprecation_warning_for(key: str, suggestion: str) -> None:
    """Emit a one-time ``DeprecationWarning`` + log record for a deprecated key."""
    if key in _warned_deprecations:
        return
    _warned_deprecations.add(key)
    message = f"solana_pay_kit: configure({key}=...) is deprecated; {suggestion}"
    warnings.warn(message, DeprecationWarning, stacklevel=3)
    logger.warning(message)


class X402Config(pydantic.BaseModel):
    """x402-protocol knobs: facilitator delegation, scheme, and signer override."""

    model_config = pydantic.ConfigDict(frozen=True, arbitrary_types_allowed=True, extra="forbid")

    facilitator_url: str | None = None
    scheme: Literal["exact"] = "exact"
    signer: LocalSigner | None = None

    def is_delegated(self) -> bool:
        """``True`` when a non-empty facilitator URL routes verify/settle off-host."""
        return self.facilitator_url is not None and self.facilitator_url != ""

    def effective_signer(self, operator: Operator) -> LocalSigner | None:
        """The x402 cosigner: the explicit override or the operator's signer."""
        return self.signer if self.signer is not None else operator.signer


class MppConfig(pydantic.BaseModel):
    """MPP-protocol knobs: realm label, challenge-binding secret, expiry window."""

    model_config = pydantic.ConfigDict(frozen=True, extra="forbid")

    realm: str = "App"
    challenge_binding_secret: str | None = None
    # Strict: reject bool (an int subclass) and float coercion; an expiry window
    # must be a real int. Existing valid int inputs are unaffected.
    expires_in: Annotated[int, Strict()] = 120

    @pydantic.field_validator("expires_in")
    @classmethod
    def _validate_expires_in(cls, value: int) -> int:
        """Reject a non-positive expiry window (the challenge would never be valid)."""
        if value <= 0:
            raise ConfigurationError(f"mpp.expires_in must be a positive number of seconds, got {value}")
        return value

    def with_challenge_binding_secret(self, secret: str) -> MppConfig:
        """Return a copy carrying the resolved HMAC challenge-binding secret."""
        return self.model_copy(update={"challenge_binding_secret": secret})


class Config(pydantic.BaseModel):
    """Immutable boot-time configuration; build via :func:`configure`."""

    model_config = pydantic.ConfigDict(frozen=True, arbitrary_types_allowed=True, extra="forbid")

    network: Network = Network.SOLANA_LOCALNET
    accept: tuple[Protocol, ...] = (Protocol.X402, Protocol.MPP)
    stablecoins: tuple[Stablecoin, ...] = (Stablecoin.USDC,)
    rpc_url: str | None = None
    operator: Operator = Operator()
    x402: X402Config = X402Config()
    mpp: MppConfig = MppConfig()
    preflight: bool = True

    @pydantic.field_validator("accept", mode="before")
    @classmethod
    def _coerce_accept(cls, value: object) -> object:
        """Accept a single ``Protocol`` or any iterable; normalise to a tuple."""
        if value is None:
            return value
        if isinstance(value, Protocol | str):
            return (value,)
        return tuple(value)  # type: ignore[arg-type]

    @pydantic.field_validator("stablecoins", mode="before")
    @classmethod
    def _coerce_stablecoins(cls, value: object) -> object:
        """Accept a single ``Stablecoin`` or any iterable; normalise to a tuple."""
        if value is None:
            return value
        if isinstance(value, Stablecoin | str):
            return (value,)
        return tuple(value)  # type: ignore[arg-type]

    @pydantic.field_validator("accept")
    @classmethod
    def _validate_accept(cls, value: tuple[Protocol, ...]) -> tuple[Protocol, ...]:
        """Require a non-empty, de-duplicated accept preference list."""
        if not value:
            raise ConfigurationError("solana_pay_kit: accept must not be empty")
        seen: list[Protocol] = []
        for protocol in value:
            if protocol not in seen:
                seen.append(protocol)
        return tuple(seen)

    @pydantic.field_validator("stablecoins")
    @classmethod
    def _validate_stablecoins(cls, value: tuple[Stablecoin, ...]) -> tuple[Stablecoin, ...]:
        """Require a non-empty, de-duplicated settlement preference list."""
        if not value:
            raise ConfigurationError("solana_pay_kit: stablecoins must not be empty")
        seen: list[Stablecoin] = []
        for coin in value:
            if coin not in seen:
                seen.append(coin)
        return tuple(seen)

    def effective_rpc_url(self) -> str:
        """The active Solana RPC URL: explicit override or the network default."""
        if self.rpc_url is not None and self.rpc_url != "":
            return self.rpc_url
        return self.network.default_rpc_url()

    def effective_recipient(self) -> str:
        """The operator's settlement address, post default-resolution."""
        return self.operator.effective_recipient()

    def effective_x402_signer(self) -> LocalSigner | None:
        """The x402 cosigner: x402 override falling back to the operator signer."""
        return self.x402.effective_signer(self.operator)

    def using_public_rpc_default(self) -> bool:
        """``True`` when no explicit ``rpc_url`` was set (public RPC in use)."""
        return self.rpc_url is None or self.rpc_url == ""


def _resolve_mpp_secret_if_needed(cfg: Config) -> Config:
    """Auto-resolve the MPP challenge-binding secret when the caller left it unset.

    Mirrors PHP ``Config::__construct`` caveat #4: env -> ./.env -> generate +
    persist. Skipped when preflight is off (tests / read-only deploys) so the
    suite does not leak a generated ``.env`` file. The resolution chain itself
    lives in ``protocols.mpp.SecretResolver``; imported lazily so this layer-C
    module does not hard-depend on the layer-D adapter at import time.
    """
    secret = cfg.mpp.challenge_binding_secret
    if secret is not None and secret != "":
        return cfg
    if not cfg.preflight:
        return cfg

    from solana_pay_kit import preflight  # noqa: I001
    from solana_pay_kit.protocols.mpp import SecretResolver  # noqa: I001

    if preflight.is_disabled_by_env():
        return cfg

    resolved, _source, _persisted = SecretResolver.resolve_mpp_secret()
    return cfg.model_copy(update={"mpp": cfg.mpp.with_challenge_binding_secret(resolved)})


def _enforce_demo_signer_on_mainnet(cfg: Config) -> None:
    """Refuse to boot the shipped demo signer against solana_mainnet.

    Checks both the operator signer and, when x402 is an accepted protocol, the
    x402 cosigner. The x402 adapter signs as the facilitator fee payer with
    ``cfg.x402.effective_signer(cfg.operator)``, which can carry its own
    ``X402Config(signer=Signer.demo())`` override while the operator runs a real
    key. Without the x402 leg the shipped demo public key could still be the
    mainnet facilitator signer, bypassing the documented refusal.
    """
    if cfg.network is not Network.SOLANA_MAINNET:
        return
    signer = cfg.operator.signer
    if signer is not None and signer.is_demo():
        raise DemoSignerOnMainnetError(
            "solana_pay_kit: the package-shipped demo signer "
            f"({signer.pubkey()}) refuses to start on solana_mainnet. "
            "Load a real keypair via Signer.file() or Signer.env()."
        )
    if Protocol.X402 in cfg.accept:
        x402_signer = cfg.effective_x402_signer()
        if x402_signer is not None and x402_signer.is_demo():
            raise DemoSignerOnMainnetError(
                "solana_pay_kit: the package-shipped demo signer "
                f"({x402_signer.pubkey()}) refuses to start as the x402 facilitator "
                "signer on solana_mainnet. Load a real keypair via "
                "x402=X402Config(signer=Signer.file()/Signer.env()) or operator=Operator(signer=...)."
            )


def _warn_about_public_mainnet_rpc(cfg: Config) -> None:
    """Warn when mainnet silently falls back to the rate-limited public RPC."""
    if cfg.network is not Network.SOLANA_MAINNET:
        return
    if not cfg.using_public_rpc_default():
        return
    logger.warning(
        "solana_pay_kit: network=solana_mainnet uses the public Solana RPC by default. "
        "Public mainnet RPC is rate-limited and unsuitable for production traffic. "
        "Set rpc_url to a dedicated endpoint (Helius, QuickNode, your own validator)."
    )


def _run_preflight(cfg: Config) -> None:
    """Run the live-RPC boot preflight unless disabled by kwarg or env (caveat #3)."""
    if not cfg.preflight:
        return
    from solana_pay_kit import preflight

    if preflight.is_disabled_by_env():
        return
    preflight.run(cfg)


def _apply_deprecated_kwargs(kwargs: dict[str, Any]) -> None:
    """Route deprecated kwarg names onto the new surface, warning once per key.

    Mutates ``kwargs`` in place: pops each legacy key, emits its deprecation
    warning, and folds the value into the modern ``operator`` / ``rpc_url`` /
    ``mpp`` / ``x402`` shape without clobbering an explicit modern value.
    """
    if "pay_to" in kwargs:
        key, suggestion = _DEPRECATED_KWARGS["pay_to"]
        _deprecation_warning_for(key, suggestion)
        pay_to = kwargs.pop("pay_to")
        if "operator" not in kwargs and pay_to is not None and pay_to != "":
            kwargs["operator"] = Operator(recipient=pay_to)

    if "facilitator" in kwargs:
        key, suggestion = _DEPRECATED_KWARGS["facilitator"]
        _deprecation_warning_for(key, suggestion)
        facilitator = kwargs.pop("facilitator")
        if "rpc_url" not in kwargs and facilitator is not None and facilitator != "":
            kwargs["rpc_url"] = facilitator

    if "facilitator_secret_key" in kwargs:
        key, suggestion = _DEPRECATED_KWARGS["facilitator_secret_key"]
        _deprecation_warning_for(key, suggestion)
        raw = kwargs.pop("facilitator_secret_key")
        # The legacy field used "[]" / "" as a "boot without a real signer"
        # sentinel (mpp-only demos). The modern operator default is the demo
        # signer, so an empty literal is a no-op rather than a parse failure.
        stripped = raw.strip() if isinstance(raw, str) else raw
        if "operator" not in kwargs and raw is not None and stripped not in ("", "[]"):
            from solana_pay_kit.signer import Signer

            kwargs["operator"] = Operator(signer=Signer.json(raw))

    if "secret" in kwargs:
        key, suggestion = _DEPRECATED_KWARGS["secret"]
        _deprecation_warning_for(key, suggestion)
        secret = kwargs.pop("secret")
        if "mpp" not in kwargs and secret is not None and secret != "":
            kwargs["mpp"] = MppConfig(challenge_binding_secret=secret)


def _build_config(**kwargs: Any) -> Config:
    """Construct, default-resolve, validate, and finalize an immutable Config."""
    _apply_deprecated_kwargs(kwargs)

    operator = kwargs.pop("operator", None)
    if operator is None:
        operator = Operator()
    elif not isinstance(operator, Operator):
        raise ConfigurationError(
            f"solana_pay_kit: operator must be a solana_pay_kit.Operator, got {type(operator).__name__}"
        )
    resolved_operator = operator.with_defaults()

    cfg = Config(operator=resolved_operator, **kwargs)

    _enforce_demo_signer_on_mainnet(cfg)
    _warn_about_public_mainnet_rpc(cfg)
    cfg = _resolve_mpp_secret_if_needed(cfg)
    _run_preflight(cfg)
    return cfg


def configure(**kwargs: Any) -> Config:
    """Build the global config, run boot safety checks, and store the singleton.

    Accepts the modern surface (``network``, ``accept``, ``stablecoins``,
    ``rpc_url``, ``operator``, ``x402``, ``mpp``, ``preflight``) plus one-release
    deprecation shims (``pay_to``, ``facilitator``, ``facilitator_secret_key``,
    ``secret``) that warn once and route onto the modern fields. Returns the
    frozen :class:`Config`, also readable via :func:`config`.
    """
    global _config
    cfg = _build_config(**kwargs)
    _config = cfg
    return cfg


class _Settings(pydantic_settings.BaseSettings):
    """Environment-driven view of the modern Config scalar knobs."""

    model_config = pydantic_settings.SettingsConfigDict(
        env_prefix="PAY_KIT_",
        extra="ignore",
        case_sensitive=False,
    )

    network: Network | None = None
    rpc_url: str | None = None
    accept: tuple[Protocol, ...] | None = None
    stablecoins: tuple[Stablecoin, ...] | None = None
    preflight: bool | None = None
    mpp_realm: str | None = None
    mpp_challenge_binding_secret: str | None = None
    mpp_expires_in: int | None = None
    x402_facilitator_url: str | None = None


def configure_from(env_prefix: str = "PAY_KIT_") -> Config:
    """Build and store the global config from ``{env_prefix}``-prefixed env vars.

    Reads scalar knobs (network, rpc_url, accept, stablecoins, preflight) and the
    nested ``MPP_*`` / ``X402_*`` overrides via pydantic-settings, then funnels
    them through :func:`configure` so the same validation and boot checks apply.
    """
    settings = _Settings(_env_prefix=env_prefix)  # type: ignore[call-arg]

    kwargs: dict[str, Any] = {}
    if settings.network is not None:
        kwargs["network"] = settings.network
    if settings.rpc_url is not None:
        kwargs["rpc_url"] = settings.rpc_url
    if settings.accept is not None:
        kwargs["accept"] = settings.accept
    if settings.stablecoins is not None:
        kwargs["stablecoins"] = settings.stablecoins
    if settings.preflight is not None:
        kwargs["preflight"] = settings.preflight

    mpp_updates: dict[str, Any] = {}
    if settings.mpp_realm is not None:
        mpp_updates["realm"] = settings.mpp_realm
    if settings.mpp_challenge_binding_secret is not None:
        mpp_updates["challenge_binding_secret"] = settings.mpp_challenge_binding_secret
    if settings.mpp_expires_in is not None:
        mpp_updates["expires_in"] = settings.mpp_expires_in
    if mpp_updates:
        kwargs["mpp"] = MppConfig(**mpp_updates)

    if settings.x402_facilitator_url is not None:
        kwargs["x402"] = X402Config(facilitator_url=settings.x402_facilitator_url)

    return configure(**kwargs)


def config() -> Config:
    """Return the global config, lazily constructing the zero-config default once."""
    global _config
    if _config is None:
        _config = _build_config()
    return _config


def reset() -> None:
    """Drop the global config and the deprecation warn-once memo (test hook)."""
    global _config
    _config = None
    _warned_deprecations.clear()
