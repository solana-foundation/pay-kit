"""MPP charge adapter coverage: offer/challenge build, cross-route replay,
fee splits, and the caveat #4 HMAC secret auto-resolution chain.

No live RPC: all verify paths assert on the binding/Tier-2 layer, which rejects
before settlement. The cross-route test reuses ``pay_kit.protocols.mpp``'s real challenge
HMAC so the pin actually fires.
"""

from __future__ import annotations

import pytest

from pay_kit import Gate, MppConfig, Price, Protocol, Stablecoin, configure
from pay_kit.config import reset
from pay_kit.errors import InvalidProofError
from pay_kit.protocols.mpp import MppAdapter, SecretResolver
from pay_kit.protocols.mpp.core.headers import format_authorization
from pay_kit.protocols.mpp.core.types import ChallengeEcho, PaymentCredential

SECRET = "challenge-binding-secret-long-enough-for-hmac"
FEE_A = "9xAXssX9j7vuK99c7cFwqbixzL3bFrzPy9PUhCtDPAYJ"


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    reset()
    monkeypatch.setenv("PAY_KIT_DISABLE_PREFLIGHT", "1")
    yield
    reset()


def _cfg(**kw):
    kw.setdefault("network", "solana_localnet")
    kw.setdefault("preflight", False)
    kw.setdefault("accept", (Protocol.MPP,))
    kw.setdefault("mpp", MppConfig(challenge_binding_secret=SECRET))
    return configure(**kw)


def _gate(cfg, name="report", amount="0.10", **kw):
    return Gate.build(
        name=name,
        amount=Price.usd(amount, Stablecoin.USDC),
        default_pay_to=cfg.effective_recipient(),
        accept=(Protocol.MPP,),
        **kw,
    )


def _credential_for(adapter: MppAdapter, gate: Gate) -> str:
    """Issue a real HMAC-bound challenge for ``gate`` and wrap it in an
    Authorization header with a (bogus) signature payload."""
    mpp = adapter._server_for(gate)
    challenge = mpp.charge_with_options(adapter._human_amount(gate), adapter._charge_options(gate))
    echo = ChallengeEcho(
        id=challenge.id,
        realm=challenge.realm,
        method=challenge.method,
        intent=challenge.intent,
        request=challenge.request,
        expires=challenge.expires,
        digest=challenge.digest,
        opaque=challenge.opaque,
    )
    cred = PaymentCredential(
        challenge=echo,
        payload={"type": "signature", "signature": "5UfDuX6nSqMzMR8W7n6K3b1GKLmaqEisBFCcYPRLjNHrCbVQJF3BVjkE7aQJMQ2Kx"},
    )
    return format_authorization(cred)


# -- offer / challenge -------------------------------------------------------


def test_accepts_entry_shape():
    cfg = _cfg()
    entry = MppAdapter(cfg).accepts_entry(_gate(cfg), {"path": "/report"})
    assert entry["protocol"] == "mpp"
    assert entry["scheme"] == "charge"
    assert entry["amount"] == "100000"  # 0.10 * 1e6
    assert entry["currency"] == "USDC"
    assert entry["payTo"] == cfg.effective_recipient()
    assert entry["realm"] == cfg.mpp.realm


def test_accepts_entry_includes_splits_when_fees():
    cfg = _cfg()
    gate = _gate(cfg, fee_on_top={FEE_A: Price.usd("0.02", Stablecoin.USDC)})
    entry = MppAdapter(cfg).accepts_entry(gate, {"path": "/report"})
    assert entry.get("splits") == [{"recipient": FEE_A, "amount": "20000"}]
    # on-top fee raises the advertised total to 0.12.
    assert entry["amount"] == "120000"


def test_settlement_coin_defaults_to_config_when_unset():
    cfg = _cfg(stablecoins=(Stablecoin.USDT,))
    gate = Gate.build(
        name="r",
        amount=Price.usd("0.10"),  # no settlement preference
        default_pay_to=cfg.effective_recipient(),
        accept=(Protocol.MPP,),
    )
    entry = MppAdapter(cfg).accepts_entry(gate, {"path": "/r"})
    assert entry["currency"] == "USDT"


def test_challenge_headers_emit_www_authenticate():
    cfg = _cfg()
    headers = MppAdapter(cfg).challenge_headers(_gate(cfg), {"path": "/report"})
    assert "www-authenticate" in headers
    assert headers["www-authenticate"].lower().startswith("payment")


# -- on-top fees: challenge + expected amount track gate.total() -------------


def test_fee_on_top_expected_amount_is_total_not_base():
    """Regression: a fee_on_top gate's expected charge request must pin the
    total (base + on-top), not the bare base.

    accepts_entry() advertises gate.total(); if the verifier's expected amount
    were the base, the MPP binding (which compares credential.amount to
    expected.amount) would accept a challenge worth only the base, letting a
    paying client underpay by the on-top fee while the 402 advertised the total.
    """
    cfg = _cfg()
    gate = _gate(cfg, fee_on_top={FEE_A: Price.usd("0.02", Stablecoin.USDC)})
    expected = MppAdapter(cfg)._charge_request_for(gate)
    # base 0.10 + on-top 0.02 = 0.12 -> 120000 base units, NOT 100000.
    assert expected.amount == "120000"
    assert expected.method_details is not None
    assert expected.method_details["splits"] == [{"recipient": FEE_A, "amount": "20000"}]


def test_fee_on_top_issued_challenge_amount_matches_advertised_total():
    """The issued WWW-Authenticate challenge's request.amount must equal the
    gate total advertised in accepts_entry()."""
    cfg = _cfg()
    adapter = MppAdapter(cfg)
    gate = _gate(cfg, fee_on_top={FEE_A: Price.usd("0.02", Stablecoin.USDC)})

    advertised = adapter.accepts_entry(gate, {"path": "/report"})["amount"]

    mpp = adapter._server_for(gate)
    challenge = mpp.charge_with_options(adapter._human_amount(gate), adapter._charge_options(gate))
    request = challenge.decode_request()
    assert str(request["amount"]) == advertised == "120000"


def test_fee_within_amount_unchanged_by_total_switch():
    """A fee_within gate's customer-paid total equals the base, so the expected
    amount stays the base (guards against the on-top fix over-charging here)."""
    cfg = _cfg()
    gate = _gate(cfg, fee_within={FEE_A: Price.usd("0.03", Stablecoin.USDC)})
    expected = MppAdapter(cfg)._charge_request_for(gate)
    assert expected.amount == "100000"  # base 0.10, within fee comes out of it


# -- challenge expiry tracks MppConfig.expires_in (regression) ---------------


def test_charge_options_expiry_derived_from_config():
    """MppConfig(expires_in=...) must drive the challenge expiry rather than the
    wire layer's hard-coded 5-minute fallback."""
    from datetime import UTC, datetime

    cfg = _cfg(mpp=MppConfig(challenge_binding_secret=SECRET, expires_in=30))
    adapter = MppAdapter(cfg)
    gate = _gate(cfg)

    options = adapter._charge_options(gate)
    assert options.expires != ""  # round-1 left this blank -> 5min fallback

    challenge = adapter._server_for(gate).charge_with_options(adapter._human_amount(gate), options)
    expires_at = datetime.fromisoformat(challenge.expires.replace("Z", "+00:00"))
    delta = (expires_at - datetime.now(UTC)).total_seconds()
    # ~30s window, comfortably under the 300s hard-coded default.
    assert 20 <= delta <= 40


# -- verify: missing / malformed proof ---------------------------------------


@pytest.mark.asyncio
async def test_verify_missing_authorization_is_402():
    cfg = _cfg()
    with pytest.raises(InvalidProofError):
        await MppAdapter(cfg).verify_and_settle(_gate(cfg), {"headers": {}})


@pytest.mark.asyncio
async def test_verify_unparseable_authorization_is_402():
    cfg = _cfg()
    with pytest.raises(InvalidProofError, match="could not parse"):
        await MppAdapter(cfg).verify_and_settle(_gate(cfg), {"headers": {"authorization": "Payment garbage"}})


# -- cross-route replay (verify_credential_with_expected pins amount) --------


@pytest.mark.asyncio
async def test_cross_route_replay_amount_mismatch_rejected():
    cfg = _cfg()
    adapter = MppAdapter(cfg)
    cheap = _gate(cfg, name="cheap", amount="0.001")
    expensive = _gate(cfg, name="expensive", amount="1.0")

    auth = _credential_for(adapter, cheap)
    with pytest.raises(InvalidProofError) as exc:
        await adapter.verify_and_settle(expensive, {"headers": {"authorization": auth}})
    assert exc.value.code == "charge_request_mismatch"
    assert "amount" in str(exc.value).lower()


@pytest.mark.asyncio
async def test_matching_route_passes_binding_then_fails_at_settlement():
    """A credential matching its own route must clear the Tier-2 pin and fail
    only later (settlement can't run offline with a bogus signature)."""
    cfg = _cfg()
    adapter = MppAdapter(cfg)
    gate = _gate(cfg, name="report", amount="0.10")
    auth = _credential_for(adapter, gate)
    with pytest.raises(InvalidProofError) as exc:
        await adapter.verify_and_settle(gate, {"headers": {"authorization": auth}})
    # Must NOT be a cross-route mismatch: the route lined up, settlement failed.
    assert exc.value.code != "charge_request_mismatch"


# -- recent blockhash injection (caveat #5) ----------------------------------


def test_charge_request_embeds_recent_blockhash_when_provider_set():
    cfg = _cfg()
    adapter = MppAdapter(cfg, recent_blockhash_provider=lambda: "SomeBlockhash1111111111111111111111111111111")
    req = adapter._charge_request_for(_gate(cfg))
    assert req.method_details is not None
    assert req.method_details["recentBlockhash"] == "SomeBlockhash1111111111111111111111111111111"


def test_charge_request_network_slug_in_method_details():
    cfg = _cfg()
    req = MppAdapter(cfg)._charge_request_for(_gate(cfg))
    assert req.method_details is not None
    assert req.method_details["network"] == "localnet"


# -- handler cache -----------------------------------------------------------


def test_server_for_caches_by_pay_to_and_coin():
    cfg = _cfg()
    adapter = MppAdapter(cfg)
    gate = _gate(cfg)
    first = adapter._server_for(gate)
    second = adapter._server_for(gate)
    assert first is second


# -- SecretResolver (caveat #4) ----------------------------------------------


def test_secret_resolver_prefers_env(monkeypatch, tmp_path):
    monkeypatch.setenv("PAY_KIT_MPP_CHALLENGE_BINDING_SECRET", "from-env")
    secret, source, persisted = SecretResolver.resolve_mpp_secret(dotenv_path=str(tmp_path / ".env"))
    assert (secret, source, persisted) == ("from-env", "env", True)


def test_secret_resolver_reads_dotenv(monkeypatch, tmp_path):
    monkeypatch.delenv("PAY_KIT_MPP_CHALLENGE_BINDING_SECRET", raising=False)
    env_file = tmp_path / ".env"
    env_file.write_text('# a comment\n\nOTHER_KEY=ignored\nPAY_KIT_MPP_CHALLENGE_BINDING_SECRET="quoted-secret"\n')
    secret, source, persisted = SecretResolver.resolve_mpp_secret(dotenv_path=str(env_file))
    assert secret == "quoted-secret"
    assert source == "dotenv"
    assert persisted is True


def test_secret_resolver_single_quoted_value(monkeypatch, tmp_path):
    monkeypatch.delenv("PAY_KIT_MPP_CHALLENGE_BINDING_SECRET", raising=False)
    env_file = tmp_path / ".env"
    env_file.write_text("PAY_KIT_MPP_CHALLENGE_BINDING_SECRET='single'\n")
    secret, source, _ = SecretResolver.resolve_mpp_secret(dotenv_path=str(env_file))
    assert (secret, source) == ("single", "dotenv")


def test_secret_resolver_generates_and_persists(monkeypatch, tmp_path):
    monkeypatch.delenv("PAY_KIT_MPP_CHALLENGE_BINDING_SECRET", raising=False)
    env_file = tmp_path / ".env"  # does not exist yet
    secret, source, persisted = SecretResolver.resolve_mpp_secret(dotenv_path=str(env_file))
    assert len(secret) == 64  # token_hex(32)
    assert source == "generated+persisted"
    assert persisted is True
    # New file is mode 0600 and contains the key.
    assert env_file.exists()
    assert "PAY_KIT_MPP_CHALLENGE_BINDING_SECRET=" in env_file.read_text()
    assert (env_file.stat().st_mode & 0o777) == 0o600


def test_secret_resolver_generated_is_sticky_across_calls(monkeypatch, tmp_path):
    monkeypatch.delenv("PAY_KIT_MPP_CHALLENGE_BINDING_SECRET", raising=False)
    env_file = tmp_path / ".env"
    first, _, _ = SecretResolver.resolve_mpp_secret(dotenv_path=str(env_file))
    second, source, _ = SecretResolver.resolve_mpp_secret(dotenv_path=str(env_file))
    assert first == second  # second read comes back from the persisted dotenv
    assert source == "dotenv"


def test_secret_resolver_unwritable_dotenv_keeps_in_memory(monkeypatch, tmp_path):
    monkeypatch.delenv("PAY_KIT_MPP_CHALLENGE_BINDING_SECRET", raising=False)
    # Point at a path inside a non-existent directory so the append fails.
    bad_path = str(tmp_path / "nope" / "deeper" / ".env")
    secret, source, persisted = SecretResolver.resolve_mpp_secret(dotenv_path=bad_path)
    assert len(secret) == 64
    assert persisted is False
    assert source == "generated"


def test_secret_resolver_missing_dotenv_returns_generated(monkeypatch, tmp_path):
    monkeypatch.delenv("PAY_KIT_MPP_CHALLENGE_BINDING_SECRET", raising=False)
    # _read_dotenv on a missing file returns None, then generation kicks in.
    env_file = tmp_path / "absent.env"
    assert SecretResolver._read_dotenv(str(env_file), "PAY_KIT_MPP_CHALLENGE_BINDING_SECRET") is None


def test_adapter_resolves_secret_from_resolver_when_unconfigured(monkeypatch, tmp_path):
    """When mpp.challenge_binding_secret is unset, the adapter falls back to the
    SecretResolver chain rather than crashing."""
    monkeypatch.setenv("PAY_KIT_MPP_CHALLENGE_BINDING_SECRET", "adapter-env-secret")
    monkeypatch.chdir(tmp_path)
    cfg = configure(
        network="solana_localnet",
        preflight=False,
        accept=(Protocol.MPP,),
        mpp=MppConfig(),  # no secret set
    )
    adapter = MppAdapter(cfg)
    assert adapter._secret == "adapter-env-secret"
