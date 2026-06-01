"""Config builder, env loader, deprecation shims, and preflight-knob coverage.

Covers: ``configure`` / ``configure_from`` happy paths, the warn-once
deprecation shims (``pay_to`` / ``facilitator`` / ``facilitator_secret_key`` /
``secret``), the demo-signer-on-mainnet refusal, rpc_url defaults per network
(caveat #2), the localnet->mainnet mint fallback (caveat #1), and BOTH preflight
opt-out knobs (caveat #7): ``configure(preflight=False)`` and
``PAY_KIT_DISABLE_PREFLIGHT=1``, each asserted against a stubbed
``pay_kit.preflight.run`` so no live RPC runs.
"""

from __future__ import annotations

import warnings

import pytest

import pay_kit.preflight as preflight_mod
from pay_kit import (
    Config,
    MppConfig,
    Network,
    Operator,
    Protocol,
    Signer,
    Stablecoin,
    X402Config,
    configure,
    configure_from,
)
from pay_kit._paycore import mints
from pay_kit.config import config as get_config
from pay_kit.config import reset
from pay_kit.errors import ConfigurationError, DemoSignerOnMainnetError
from pay_kit.signer import DEMO_PUBKEY


@pytest.fixture(autouse=True)
def _clean_config(monkeypatch):
    """Reset the singleton + deprecation memo and disable real preflight/RPC."""
    reset()
    monkeypatch.setenv("PAY_KIT_DISABLE_PREFLIGHT", "1")
    # Belt-and-braces: also stub run so nothing can hit the network.
    monkeypatch.setattr(preflight_mod, "run", lambda cfg: None)
    yield
    reset()


# -- configure happy paths ---------------------------------------------------


def test_configure_zero_config_defaults():
    cfg = configure()
    assert cfg.network is Network.SOLANA_LOCALNET
    assert cfg.accept == (Protocol.X402, Protocol.MPP)
    assert cfg.stablecoins == (Stablecoin.USDC,)
    assert get_config() is cfg


def test_configure_stores_singleton():
    cfg = configure(network="solana_devnet")
    assert get_config() is cfg


def test_config_accessor_lazily_builds_default():
    reset()
    cfg = get_config()
    assert isinstance(cfg, Config)


def test_configure_accept_single_protocol_coerced():
    cfg = configure(accept=Protocol.MPP)
    assert cfg.accept == (Protocol.MPP,)


def test_configure_stablecoins_single_coerced_and_deduped():
    cfg = configure(stablecoins=[Stablecoin.USDC, Stablecoin.USDC, Stablecoin.USDT])
    assert cfg.stablecoins == (Stablecoin.USDC, Stablecoin.USDT)


def test_configure_empty_accept_raises():
    with pytest.raises(ConfigurationError, match="accept must not be empty"):
        configure(accept=())


def test_configure_empty_stablecoins_raises():
    with pytest.raises(ConfigurationError, match="stablecoins must not be empty"):
        configure(stablecoins=())


def test_configure_rejects_non_operator():
    with pytest.raises(ConfigurationError, match="operator must be"):
        configure(operator={"recipient": "x"})


# -- rpc_url defaults (caveat #2) --------------------------------------------


def test_localnet_default_rpc_is_hosted_surfnet():
    cfg = configure(network="solana_localnet")
    assert cfg.effective_rpc_url() == "https://402.surfnet.dev:8899"
    assert cfg.using_public_rpc_default() is True


def test_devnet_default_rpc():
    cfg = configure(network="solana_devnet")
    assert cfg.effective_rpc_url() == "https://api.devnet.solana.com"


def test_explicit_rpc_url_overrides_default():
    cfg = configure(network="solana_devnet", rpc_url="https://my.rpc")
    assert cfg.effective_rpc_url() == "https://my.rpc"
    assert cfg.using_public_rpc_default() is False


# -- demo-signer-on-mainnet refusal ------------------------------------------


def test_demo_signer_on_mainnet_refused():
    with pytest.raises(DemoSignerOnMainnetError, match="refuses to start"):
        configure(network="solana_mainnet")  # operator defaults to demo signer


def test_real_signer_on_mainnet_allowed():
    op = Operator(signer=Signer.generate(), recipient="R1111111111111111111111111111111111111111")
    cfg = configure(network="solana_mainnet", operator=op, rpc_url="https://helius")
    assert cfg.network is Network.SOLANA_MAINNET


def test_x402_demo_signer_on_mainnet_refused_even_with_real_operator():
    # Regression: the operator signer is real, but the x402 override is the
    # shipped demo signer. The adapter cosigns with the x402 effective signer,
    # so booting must refuse the demo facilitator key on mainnet.
    op = Operator(signer=Signer.generate(), recipient="R1111111111111111111111111111111111111111")
    with pytest.raises(DemoSignerOnMainnetError, match="x402 facilitator"):
        configure(
            network="solana_mainnet",
            operator=op,
            rpc_url="https://helius",
            x402=X402Config(signer=Signer.demo()),
        )


def test_x402_demo_signer_allowed_on_devnet():
    # The same config must NOT raise off mainnet.
    op = Operator(signer=Signer.generate(), recipient="R1111111111111111111111111111111111111111")
    cfg = configure(
        network="solana_devnet",
        operator=op,
        x402=X402Config(signer=Signer.demo()),
    )
    assert cfg.network is Network.SOLANA_DEVNET


def test_real_x402_signer_on_mainnet_allowed():
    # A real x402 override on mainnet must NOT raise.
    op = Operator(signer=Signer.generate(), recipient="R1111111111111111111111111111111111111111")
    cfg = configure(
        network="solana_mainnet",
        operator=op,
        rpc_url="https://helius",
        x402=X402Config(signer=Signer.generate()),
    )
    assert cfg.network is Network.SOLANA_MAINNET


def test_x402_demo_signer_on_mainnet_allowed_when_x402_not_accepted():
    # When x402 is not an accepted protocol, the x402 leg must not gate boot.
    op = Operator(signer=Signer.generate(), recipient="R1111111111111111111111111111111111111111")
    cfg = configure(
        network="solana_mainnet",
        operator=op,
        rpc_url="https://helius",
        accept=Protocol.MPP,
        x402=X402Config(signer=Signer.demo()),
    )
    assert cfg.network is Network.SOLANA_MAINNET


def test_public_mainnet_rpc_warns(caplog):
    op = Operator(signer=Signer.generate(), recipient="R1111111111111111111111111111111111111111")
    with caplog.at_level("WARNING", logger="pay_kit"):
        configure(network="solana_mainnet", operator=op)  # no rpc_url -> public default
    assert any("public Solana RPC" in r.message for r in caplog.records)


# -- mint localnet -> mainnet fallback (caveat #1) ---------------------------


def test_mint_localnet_falls_back_to_mainnet_row():
    mainnet = mints.resolve("USDC", "mainnet")
    localnet = mints.resolve("USDC", "localnet")
    assert localnet == mainnet
    assert localnet is not None


def test_mint_sol_returns_none():
    assert mints.resolve("SOL", "mainnet") is None


# -- effective accessors -----------------------------------------------------


def test_effective_recipient_from_operator():
    cfg = configure()
    assert cfg.effective_recipient() == DEMO_PUBKEY


def test_effective_x402_signer_falls_back_to_operator_signer():
    cfg = configure()
    s = cfg.effective_x402_signer()
    assert s is not None and s.is_demo()


def test_x402_config_override_signer_wins():
    override = Signer.generate()
    cfg = configure(x402=X402Config(signer=override))
    signer = cfg.effective_x402_signer()
    assert signer is not None
    assert signer.pubkey() == override.pubkey()


def test_x402_is_delegated_flag():
    assert X402Config(facilitator_url="https://f").is_delegated() is True
    assert X402Config().is_delegated() is False


def test_mpp_config_expires_in_must_be_positive():
    with pytest.raises(ConfigurationError, match="positive"):
        MppConfig(expires_in=0)


def test_mpp_config_with_secret_copy():
    base = MppConfig()
    updated = base.with_challenge_binding_secret("abc")
    assert updated.challenge_binding_secret == "abc"
    assert base.challenge_binding_secret is None  # original untouched


# -- deprecation shims (warn-once) -------------------------------------------


def test_deprecated_pay_to_routes_to_operator():
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        cfg = configure(pay_to="LegacyRecipient1111111111111111111111111111")
    assert cfg.effective_recipient() == "LegacyRecipient1111111111111111111111111111"
    assert any(issubclass(w.category, DeprecationWarning) for w in caught)


def test_deprecated_pay_to_warns_once():
    reset()  # clears the warn-once memo
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        configure(pay_to="R1111111111111111111111111111111111111111")
        configure(pay_to="R2222222222222222222222222222222222222222")
    pay_to_warnings = [w for w in caught if w.category is DeprecationWarning and "pay_to" in str(w.message)]
    assert len(pay_to_warnings) == 1


def test_deprecated_facilitator_routes_to_rpc_url():
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        cfg = configure(network="solana_devnet", facilitator="https://legacy.rpc")
    assert cfg.effective_rpc_url() == "https://legacy.rpc"


def test_deprecated_facilitator_secret_key_routes_to_signer():
    import json

    from solders.keypair import Keypair

    kp = Keypair()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        cfg = configure(facilitator_secret_key=json.dumps(list(bytes(kp))))
    assert cfg.operator.signer is not None
    assert cfg.operator.signer.pubkey() == str(kp.pubkey())


def test_deprecated_facilitator_secret_key_empty_sentinel_is_noop():
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        cfg = configure(facilitator_secret_key="[]")  # legacy "boot without signer"
    assert cfg.operator.signer is not None and cfg.operator.signer.is_demo()


def test_deprecated_secret_routes_to_mpp():
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        cfg = configure(secret="legacy-binding-secret")
    assert cfg.mpp.challenge_binding_secret == "legacy-binding-secret"


# -- configure_from (env) ----------------------------------------------------


def test_configure_from_reads_scalars(monkeypatch):
    monkeypatch.setenv("PAY_KIT_NETWORK", "solana_devnet")
    monkeypatch.setenv("PAY_KIT_RPC_URL", "https://env.rpc")
    monkeypatch.setenv("PAY_KIT_PREFLIGHT", "false")
    cfg = configure_from()
    assert cfg.network is Network.SOLANA_DEVNET
    assert cfg.effective_rpc_url() == "https://env.rpc"
    assert cfg.preflight is False


def test_configure_from_reads_mpp_and_x402(monkeypatch):
    monkeypatch.setenv("PAY_KIT_MPP_REALM", "MyRealm")
    monkeypatch.setenv("PAY_KIT_MPP_CHALLENGE_BINDING_SECRET", "envsecret")
    monkeypatch.setenv("PAY_KIT_MPP_EXPIRES_IN", "300")
    monkeypatch.setenv("PAY_KIT_X402_FACILITATOR_URL", "https://fac")
    cfg = configure_from()
    assert cfg.mpp.realm == "MyRealm"
    assert cfg.mpp.challenge_binding_secret == "envsecret"
    assert cfg.mpp.expires_in == 300
    assert cfg.x402.facilitator_url == "https://fac"


def test_configure_from_no_env_uses_defaults(monkeypatch):
    for key in ("NETWORK", "RPC_URL", "ACCEPT", "STABLECOINS", "MPP_REALM"):
        monkeypatch.delenv(f"PAY_KIT_{key}", raising=False)
    cfg = configure_from()
    assert cfg.network is Network.SOLANA_LOCALNET


# -- preflight knobs (caveat #7) ---------------------------------------------


def test_preflight_false_skips_run(monkeypatch):
    """configure(preflight=False) must not invoke preflight.run at all."""
    calls = []
    monkeypatch.setattr(preflight_mod, "run", lambda cfg: calls.append(cfg))
    # Clear the env kill-switch so only the kwarg governs this path.
    monkeypatch.delenv("PAY_KIT_DISABLE_PREFLIGHT", raising=False)
    configure(preflight=False)
    assert calls == []


def test_preflight_env_kill_switch_skips_run(monkeypatch):
    """PAY_KIT_DISABLE_PREFLIGHT=1 short-circuits even when preflight=True."""
    calls = []
    monkeypatch.setattr(preflight_mod, "run", lambda cfg: calls.append(cfg))
    monkeypatch.setenv("PAY_KIT_DISABLE_PREFLIGHT", "1")
    configure(preflight=True)
    assert calls == []


def test_preflight_fires_when_enabled(monkeypatch):
    """With the env switch cleared and preflight=True, run() fires exactly once."""
    calls = []
    monkeypatch.setattr(preflight_mod, "run", lambda cfg: calls.append(cfg))
    monkeypatch.delenv("PAY_KIT_DISABLE_PREFLIGHT", raising=False)
    cfg = configure(
        preflight=True,
        mpp=MppConfig(challenge_binding_secret="set-so-no-dotenv-write"),
    )
    assert calls == [cfg]


def test_is_disabled_by_env_true_values(monkeypatch):
    for value in ("1", "true"):
        monkeypatch.setenv("PAY_KIT_DISABLE_PREFLIGHT", value)
        assert preflight_mod.is_disabled_by_env() is True
    monkeypatch.setenv("PAY_KIT_DISABLE_PREFLIGHT", "0")
    assert preflight_mod.is_disabled_by_env() is False
    monkeypatch.delenv("PAY_KIT_DISABLE_PREFLIGHT", raising=False)
    assert preflight_mod.is_disabled_by_env() is False
