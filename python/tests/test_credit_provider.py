"""Musebook credit-provider parity with the Rust kit (PRs #411/#414):
pinned devnet deployment resolution, per-payer hook derivation, the
client fail-closed matrix, server challenge emission + config
validation, and the credit authorization instruction pair.

Mirrors ``rust/crates/kit/src/core/credit_provider/musebook.rs``,
``rust/crates/kit/src/mpp/client/session.rs`` (``credit_channel_hooks``,
``credit_authorization_instructions``) and
``rust/crates/kit/src/mpp/server/session.rs`` (``credit_deployment``,
challenge ``methodDetails``).
"""

from __future__ import annotations

import struct

import pytest
from solana_keychain import MemorySigner
from solders.keypair import Keypair  # type: ignore[import-untyped]
from solders.pubkey import Pubkey  # type: ignore[import-untyped]

from solana_pay_kit._paycore.credit_provider import (
    MUSEBOOK_DEVNET_DEPLOYMENT,
    MUSEBOOK_DEVNET_PROGRAM_ID,
    PAYMENT_CHANNELS_V2_PROGRAM_ID,
    SPL_TOKEN_PROGRAM_ID,
    ChannelHooks,
    CreditProviderError,
    deployment_for_network,
    devnet_with_program,
    encode_authorization,
    hooks_for_deployment,
    is_credit_channel,
    ledger_address,
    resolve_deployment,
    validate_credit_providers,
    validate_credit_providers_for_network,
)
from solana_pay_kit._paycore.paymentchannels import distribution_hash
from solana_pay_kit._paycore.paymentchannels import Distribution as PaycoreDistribution
from solana_pay_kit._paycore.solana import TOKEN_2022_PROGRAM
from solana_pay_kit.protocols.mpp._paymentchannels import find_channel_pda
from solana_pay_kit.protocols.mpp.client.payment_channels import (
    PaymentChannelOpenOptions,
    build_open_payment_channel_transaction,
    credit_authorization_instructions,
    derive_payment_channel_open,
)
from solana_pay_kit.protocols.mpp.intents.session import SessionMethodDetails, SessionRequest
from solana_pay_kit.protocols.mpp.server.session import SessionConfig, SessionServer
from solana_pay_kit.protocols.mpp.server.session_store import MemoryChannelStore

USDC_DEVNET_MINT = Pubkey.from_string("4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU")
RECENT_BLOCKHASH = "EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N"


def _kp(seed: int) -> Keypair:
    return Keypair.from_seed(bytes([seed] * 32))


def _credit_request(**detail_overrides: object) -> SessionRequest:
    details = SessionMethodDetails(
        network="devnet",
        channel_program=PAYMENT_CHANNELS_V2_PROGRAM_ID,
        channel_version=2,
        credit_issuer=str(_kp(8).pubkey()),
        credit_provider="musebook",
        decimals=6,
        token_program=SPL_TOKEN_PROGRAM_ID,
        grace_period_seconds=900,
        recent_blockhash=RECENT_BLOCKHASH,
        recent_slot=314,
    )
    for key, value in detail_overrides.items():
        setattr(details, key, value)
    return SessionRequest(
        amount="100",
        currency="USDC",
        recipient=str(_kp(2).pubkey()),
        suggested_deposit="5000",
        method_details=details,
    )


# ---------------------------------------------------------------------------
# Deployment resolution + gate
# ---------------------------------------------------------------------------


def test_deployment_resolution() -> None:
    assert deployment_for_network("devnet") == MUSEBOOK_DEVNET_DEPLOYMENT
    assert deployment_for_network("solana:devnet") == MUSEBOOK_DEVNET_DEPLOYMENT
    assert MUSEBOOK_DEVNET_DEPLOYMENT.program_id == MUSEBOOK_DEVNET_PROGRAM_ID
    assert MUSEBOOK_DEVNET_DEPLOYMENT.channel_program_id == PAYMENT_CHANNELS_V2_PROGRAM_ID
    for network in ("mainnet", "solana:mainnet", "testnet", "localnet", "Devnet", ""):
        assert deployment_for_network(network) is None


def test_resolve_deployment_override_is_devnet_only() -> None:
    other = str(_kp(5).pubkey())
    assert resolve_deployment("devnet") == MUSEBOOK_DEVNET_DEPLOYMENT
    assert resolve_deployment("devnet", MUSEBOOK_DEVNET_PROGRAM_ID) == MUSEBOOK_DEVNET_DEPLOYMENT
    resolved = resolve_deployment("devnet", other)
    assert resolved is not None and resolved.program_id == other
    assert resolved.channel_program_id == PAYMENT_CHANNELS_V2_PROGRAM_ID
    assert resolve_deployment("mainnet", other) is None
    assert resolve_deployment("devnet", "not-a-pubkey") is None
    override = devnet_with_program(other)
    assert override is not None and override.program_id == other and override.cluster == "devnet"
    assert devnet_with_program("not-a-pubkey") is None


def test_provider_gate() -> None:
    for provider in ("coinflow", "musebook"):
        with pytest.raises(CreditProviderError) as excinfo:
            validate_credit_providers([provider])  # type: ignore[list-item]
        assert excinfo.value.provider == provider
    validate_credit_providers([])
    validate_credit_providers_for_network(["musebook"], "devnet")
    validate_credit_providers_for_network(["musebook"], "solana:devnet")
    with pytest.raises(CreditProviderError):
        validate_credit_providers_for_network(["musebook"], "mainnet")
    with pytest.raises(CreditProviderError):
        validate_credit_providers_for_network(["coinflow"], "devnet")


# ---------------------------------------------------------------------------
# Hooks + wire forms
# ---------------------------------------------------------------------------


def test_hooks_derivation_and_detection() -> None:
    owner = _kp(3).pubkey()
    hooks = hooks_for_deployment(MUSEBOOK_DEVNET_DEPLOYMENT, owner, USDC_DEVNET_MINT)
    assert hooks.post_fund is None and hooks.pre_distribute is None
    assert hooks.pre_fund is not None and hooks.pre_fund == hooks.post_distribute
    descriptor = hooks.pre_fund
    assert descriptor.program_id == MUSEBOOK_DEVNET_PROGRAM_ID
    assert descriptor.entrypoint == b"musebook"
    assert descriptor.static_data == b""
    assert len(descriptor.accounts) == 4
    ledger = ledger_address(MUSEBOOK_DEVNET_DEPLOYMENT, owner, USDC_DEVNET_MINT)
    assert descriptor.accounts[0].address == str(ledger) and descriptor.accounts[0].writable
    assert descriptor.accounts[1].writable and descriptor.accounts[2].writable
    assert descriptor.accounts[3].address == SPL_TOKEN_PROGRAM_ID and not descriptor.accounts[3].writable

    assert is_credit_channel(MUSEBOOK_DEVNET_DEPLOYMENT, hooks, owner, USDC_DEVNET_MINT)
    other_program = ChannelHooks(
        pre_fund=type(descriptor)(program_id=str(owner), entrypoint=descriptor.entrypoint,
                                  accounts=descriptor.accounts, static_data=b""),
        post_distribute=descriptor,
    )
    assert not is_credit_channel(MUSEBOOK_DEVNET_DEPLOYMENT, other_program, owner, USDC_DEVNET_MINT)
    extra_slot = ChannelHooks(pre_fund=descriptor, post_fund=descriptor, post_distribute=descriptor)
    assert not is_credit_channel(MUSEBOOK_DEVNET_DEPLOYMENT, extra_slot, owner, USDC_DEVNET_MINT)


def test_hooks_wire_round_trip() -> None:
    owner = _kp(3).pubkey()
    hooks = hooks_for_deployment(MUSEBOOK_DEVNET_DEPLOYMENT, owner, USDC_DEVNET_MINT)
    wire = hooks.to_dict()
    assert wire["preFund"]["entrypoint"] == [109, 117, 115, 101, 98, 111, 111, 107]  # "musebook"
    assert "postFund" not in wire and "preDistribute" not in wire
    assert ChannelHooks.from_dict(wire) == hooks


def test_method_details_credit_wire_round_trip() -> None:
    request = _credit_request()
    wire = request.method_details.to_dict()
    assert wire["creditProvider"] == "musebook"
    assert wire["creditIssuer"] == str(_kp(8).pubkey())
    assert wire["channelVersion"] == 2
    parsed = SessionMethodDetails.from_dict(wire)
    assert parsed.credit_provider == "musebook"
    assert parsed.channel_version == 2
    with pytest.raises(ValueError, match="unknown creditProvider"):
        SessionMethodDetails.from_dict({**wire, "creditProvider": "acme"})


def test_encode_authorization_layout() -> None:
    payee, authorized = _kp(2).pubkey(), _kp(4).pubkey()
    digest = distribution_hash([PaycoreDistribution(recipient=payee, bps=10_000)])
    body = encode_authorization(
        payee=payee,
        authorized_signer=authorized,
        distribution_hash_bytes=digest,
        salt=42,
        open_slot=314,
        cap=7_500,
        nonce=3,
        expires_at_slot=9_314,
    )
    assert len(body) == 136
    assert body[:32] == bytes(payee)
    assert body[32:64] == bytes(authorized)
    assert body[64:96] == digest
    assert struct.unpack_from("<QQQQQ", body, 96) == (42, 314, 7_500, 3, 9_314)


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------


def test_derive_credit_open_returns_hooks_and_v2_channel() -> None:
    request = _credit_request()
    payer, authorized = _kp(3).pubkey(), _kp(4).pubkey()
    open_ = derive_payment_channel_open(
        request, payer, authorized, PaymentChannelOpenOptions(salt=42, open_slot=314)
    )
    assert open_.channel_hooks is not None
    assert open_.channel_hooks.pre_fund is not None
    assert open_.channel_hooks.pre_fund.program_id == MUSEBOOK_DEVNET_PROGRAM_ID
    expected, _ = find_channel_pda(
        payer,
        _kp(2).pubkey(),
        USDC_DEVNET_MINT,
        authorized,
        42,
        314,
        Pubkey.from_string(PAYMENT_CHANNELS_V2_PROGRAM_ID),
    )
    assert open_.channel_id == expected
    assert open_.program_id == Pubkey.from_string(PAYMENT_CHANNELS_V2_PROGRAM_ID)


def test_client_fail_closed_matrix() -> None:
    payer, authorized = _kp(3).pubkey(), _kp(4).pubkey()
    cases: list[tuple[dict[str, object], str]] = [
        ({"credit_provider": "coinflow"}, "credit provider coinflow: unavailable"),
        (
            {
                "channel_hooks": ChannelHooks.from_dict(
                    {"preFund": {"programId": "x", "entrypoint": [], "accounts": [], "staticData": []}}
                )
            },
            "must not also carry channelHooks",
        ),
        ({"channel_version": 1}, "pinned V2 channel program"),
        ({"channel_version": None}, "pinned V2 channel program"),
        ({"channel_program": "CHNLxYvVA28MJP9PrFuDXccuoGXAx7jBacfLEkahyGsX"}, "pinned V2 channel program"),
        ({"token_program": TOKEN_2022_PROGRAM}, "token program must be SPL Token"),
        ({"fee_payer": True, "fee_payer_key": str(_kp(8).pubkey())}, "sponsored opens are not supported"),
        ({"network": "mainnet"}, "unavailable on this network"),
    ]
    for overrides, pattern in cases:
        request = _credit_request(**overrides)
        with pytest.raises(ValueError, match=pattern):
            derive_payment_channel_open(request, payer, authorized, PaymentChannelOpenOptions(salt=42))


async def test_build_open_refuses_credit_challenges() -> None:
    request = _credit_request()
    with pytest.raises(ValueError, match="V2 hooked channel program"):
        await build_open_payment_channel_transaction(
            request,
            MemorySigner(_kp(3)),
            _kp(4).pubkey(),
        )


def test_credit_authorization_instructions() -> None:
    request = _credit_request()
    payer, authorized = _kp(3).pubkey(), _kp(4).pubkey()
    open_ = derive_payment_channel_open(
        request, payer, authorized, PaymentChannelOpenOptions(salt=42, open_slot=314)
    )
    instructions = credit_authorization_instructions(
        request, open_, cap=5_000, nonce=0, expires_at_slot=9_314
    )
    assert len(instructions) == 2
    approve, authorize = instructions
    assert str(approve.program_id) == SPL_TOKEN_PROGRAM_ID
    assert approve.data[0] == 4  # SPL Token Approve
    assert struct.unpack_from("<Q", approve.data, 1)[0] == 5_000
    assert str(authorize.program_id) == MUSEBOOK_DEVNET_PROGRAM_ID
    assert authorize.data[0] == 2  # provider authorize
    assert len(authorize.data) == 137
    ledger = ledger_address(MUSEBOOK_DEVNET_DEPLOYMENT, payer, USDC_DEVNET_MINT)
    assert authorize.accounts[0].pubkey == payer
    assert authorize.accounts[1].pubkey == _kp(8).pubkey()
    assert authorize.accounts[2].pubkey == ledger
    with pytest.raises(ValueError, match="cap is below the channel deposit"):
        credit_authorization_instructions(request, open_, cap=4_999, nonce=0, expires_at_slot=9_314)


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------


def _credit_config(**overrides: object) -> SessionConfig:
    config = SessionConfig(
        recipient=str(_kp(2).pubkey()),
        amount=100,
        currency="USDC",
        decimals=6,
        network="devnet",
        channel_program=PAYMENT_CHANNELS_V2_PROGRAM_ID,
        credit_provider="musebook",
        credit_issuer_signer=MemorySigner(_kp(8)),
        credit_max_cap=1_000_000,
    )
    for key, value in overrides.items():
        setattr(config, key, value)
    return config


def _server(config: SessionConfig) -> SessionServer:
    return SessionServer(config, MemoryChannelStore()).with_blockhash_cache(
        lambda: (RECENT_BLOCKHASH, 314)
    )


async def test_server_challenge_advertises_credit() -> None:
    server = _server(_credit_config())
    assert server.credit_deployment == MUSEBOOK_DEVNET_DEPLOYMENT
    request = await server.build_challenge_request()
    details = request.method_details
    assert details.channel_program == PAYMENT_CHANNELS_V2_PROGRAM_ID
    assert details.channel_version == 2
    assert details.credit_provider == "musebook"
    assert details.credit_issuer == str(_kp(8).pubkey())
    assert details.fee_payer is None


def test_server_config_fails_closed() -> None:
    cases: list[tuple[dict[str, object], str]] = [
        ({"credit_issuer_signer": None}, "creditIssuerSigner is required"),
        ({"channel_program": ""}, "pinned V2 channel program"),
        ({"channel_program": "CHNLxYvVA28MJP9PrFuDXccuoGXAx7jBacfLEkahyGsX"}, "pinned V2 channel program"),
        ({"network": "mainnet"}, 'unavailable on network "mainnet"'),
        ({"token_program": TOKEN_2022_PROGRAM}, "tokenProgram must be SPL Token"),
        ({"credit_provider": "coinflow"}, "credit provider coinflow is unavailable"),
        ({"fee_payer": True}, "sponsored sessions are not supported"),
    ]
    for overrides, pattern in cases:
        with pytest.raises(ValueError, match=pattern):
            _server(_credit_config(**overrides))
