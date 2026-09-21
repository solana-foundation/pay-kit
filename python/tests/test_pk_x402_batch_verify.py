"""Pure verification rules for x402 ``batch-settlement``.

Test names follow the Rust ``batch_settlement/verify.rs`` tests and the x402
PR #23 server-signer / facilitator lifecycle tests they mirror.
"""

from __future__ import annotations

from typing import Any, cast

import pytest
from solders.keypair import Keypair
from solders.pubkey import Pubkey

from solana_pay_kit._paycore.paymentchannels import (
    PAYMENT_CHANNELS_PROGRAM_ID,
    PROGRAM_ID,
    Distribution,
    distribution_hash,
    find_channel_pda,
)
from solana_pay_kit._paycore.solana import SYSTEM_PROGRAM, TOKEN_2022_PROGRAM, TOKEN_PROGRAM
from solana_pay_kit.protocols.programs.paymentchannels.accounts.channel import Channel
from solana_pay_kit.protocols.x402.batch_settlement import errors
from solana_pay_kit.protocols.x402.batch_settlement.errors import BatchSettlementError
from solana_pay_kit.protocols.x402.batch_settlement.signatures import sign_authorization, sign_voucher
from solana_pay_kit.protocols.x402.batch_settlement.types import (
    BatchChannelConfig,
    BatchPayload,
    BatchRequirements,
)
from solana_pay_kit.protocols.x402.batch_settlement.verify import (
    CHANNEL_STATUS_CLOSING,
    CHANNEL_STATUS_OPEN,
    check_authorization,
    check_capacity,
    check_channel_binding,
    check_channel_config,
    check_cumulative,
    check_no_cooperative_close,
    check_terms,
    check_voucher,
    check_withdraw_delay,
    decode_channel,
    derive_channel_id,
)
from solana_pay_kit.signer import LocalSigner

MINT = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"
NOW = 1_700_000_000


def _signer(seed: int) -> LocalSigner:
    return LocalSigner.from_keypair(Keypair.from_seed(bytes([seed] * 32)))


PAYER = _signer(1)
FEE_PAYER = _signer(2).pubkey()
PAY_TO = _signer(3).pubkey()
OPERATOR = _signer(4)


def _requirements(**extra: Any) -> BatchRequirements:
    return cast(
        "BatchRequirements",
        {
            "scheme": "batch-settlement",
            "network": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
            "amount": "10000",
            "asset": MINT,
            "payTo": PAY_TO,
            "maxTimeoutSeconds": 300,
            "extra": {"feePayer": FEE_PAYER, "withdrawDelay": 3600, "tokenProgram": TOKEN_PROGRAM, **extra},
        },
    )


def _config(**overrides: Any) -> BatchChannelConfig:
    config: dict[str, Any] = {
        "payer": PAYER.pubkey(),
        "payerAuthorizer": PAYER.pubkey(),
        "receiver": PAY_TO,
        "token": MINT,
        "withdrawDelay": 3600,
        "salt": "42",
        "openSlot": 341_000_000,
    }
    config.update(overrides)
    return cast("BatchChannelConfig", config)


def _server_config(**overrides: Any) -> BatchChannelConfig:
    return _config(payerAuthorizer=OPERATOR.pubkey(), voucherSigner="server", **overrides)


def _code(exc: pytest.ExceptionInfo[BatchSettlementError]) -> str:
    return exc.value.code


# -- terms -------------------------------------------------------------------


def test_payment_flow_accepts_only_the_authorization_default() -> None:
    check_terms(_requirements(), fee_payer=FEE_PAYER)
    check_terms(_requirements(paymentFlow="authorization"), fee_payer=FEE_PAYER)
    with pytest.raises(BatchSettlementError) as exc:
        check_terms(_requirements(paymentFlow="upfront"), fee_payer=FEE_PAYER)
    assert _code(exc) == errors.INVALID_PAYMENT_FLOW


def test_withdraw_delay_enforces_the_conformance_range_and_the_http_window() -> None:
    check_withdraw_delay(900, 300)
    check_withdraw_delay(2_592_000, 300)
    check_withdraw_delay(900, 900)  # exactly the completion window is fine
    for delay, timeout in ((899, 300), (2_592_001, 300), (900, 901)):
        with pytest.raises(BatchSettlementError) as exc:
            check_withdraw_delay(delay, timeout)
        assert _code(exc) == errors.INVALID_WITHDRAW_DELAY_OUT_OF_RANGE, (delay, timeout)


def test_token_program_accepts_both_spl_programs_and_nothing_else() -> None:
    check_terms(_requirements(tokenProgram=TOKEN_2022_PROGRAM), fee_payer=FEE_PAYER)
    with pytest.raises(BatchSettlementError) as exc:
        check_terms(_requirements(tokenProgram=SYSTEM_PROGRAM), fee_payer=FEE_PAYER)
    assert _code(exc) == errors.INVALID_TOKEN_PROGRAM


def test_terms_require_this_servers_fee_payer() -> None:
    with pytest.raises(BatchSettlementError) as exc:
        check_terms(_requirements(), fee_payer=PAY_TO)
    assert _code(exc) == errors.INVALID_FEE_PAYER_MISMATCH


# -- channel config and PDA ------------------------------------------------------


def test_channel_id_derivation_matches_the_program_seeds() -> None:
    config = _config()
    derived = derive_channel_id(config, FEE_PAYER)
    expected, _ = find_channel_pda(
        Pubkey.from_string(PAYER.pubkey()),
        Pubkey.from_string(FEE_PAYER),
        Pubkey.from_string(MINT),
        Pubkey.from_string(PAYER.pubkey()),
        42,
        341_000_000,
        PROGRAM_ID,
    )
    assert derived == str(expected)
    # salt and openSlot are seeds: changing either moves the channel.
    assert derive_channel_id(_config(salt="43"), FEE_PAYER) != derived
    assert derive_channel_id(_config(openSlot=341_000_001), FEE_PAYER) != derived
    with pytest.raises(BatchSettlementError) as exc:
        derive_channel_id(_config(payer="not-a-key"), FEE_PAYER)
    assert _code(exc) == errors.INVALID_CHANNEL_STATE


@pytest.mark.parametrize(
    ("overrides", "code"),
    [
        ({"receiver": FEE_PAYER}, errors.INVALID_CHANNEL_STATE),
        ({"token": PAY_TO}, errors.INVALID_CHANNEL_STATE),
        ({"withdrawDelay": 1800}, errors.INVALID_WITHDRAW_DELAY_MISMATCH),
        ({"receiverAuthorizer": PAY_TO}, errors.INVALID_RECEIVER_AUTHORIZER_MISMATCH),
        ({"payer": FEE_PAYER}, errors.INVALID_FEE_PAYER_MISMATCH),
        ({"payerAuthorizer": FEE_PAYER}, errors.INVALID_FEE_PAYER_MISMATCH),
        ({"voucherSigner": "server"}, errors.INVALID_CHANNEL_STATE),
    ],
    ids=["receiver", "token", "withdraw-delay", "receiver-authorizer", "payer", "payer-authorizer", "mode"],
)
def test_channel_config_binds_every_field_to_the_requirements(overrides: dict[str, Any], code: str) -> None:
    check_channel_config(_config(), _requirements(), fee_payer=FEE_PAYER, operator=None)
    with pytest.raises(BatchSettlementError) as exc:
        check_channel_config(_config(**overrides), _requirements(), fee_payer=FEE_PAYER, operator=None)
    assert _code(exc) == code


def test_receiver_authorizer_must_be_named_on_both_sides_or_neither() -> None:
    advertised = _requirements(receiverAuthorizer=PAY_TO)
    check_channel_config(_config(receiverAuthorizer=PAY_TO), advertised, fee_payer=FEE_PAYER, operator=None)
    with pytest.raises(BatchSettlementError) as exc:
        check_channel_config(_config(), advertised, fee_payer=FEE_PAYER, operator=None)
    assert _code(exc) == errors.INVALID_RECEIVER_AUTHORIZER_MISMATCH


@pytest.mark.parametrize(
    ("config", "extra", "operator"),
    [
        (_config(payerAuthorizer=OPERATOR.pubkey()), {"voucherSigner": "server", "operator": OPERATOR.pubkey()}, None),
        (_server_config(), {"voucherSigner": "server"}, OPERATOR.pubkey()),
        (_server_config(), {"voucherSigner": "server", "operator": OPERATOR.pubkey()}, PAY_TO),
        (_server_config(), {"voucherSigner": "server", "operator": PAY_TO}, PAY_TO),
        (_config(), {"operator": OPERATOR.pubkey()}, OPERATOR.pubkey()),
    ],
    ids=[
        "config-in-client-mode",
        "operator-missing",
        "not-our-operator",
        "payer-authorizer-is-not-operator",
        "operator-in-client-mode",
    ],
)
def test_server_mode_rejects_every_operator_term_mismatch(
    config: BatchChannelConfig, extra: dict[str, Any], operator: str | None
) -> None:
    good = _requirements(voucherSigner="server", operator=OPERATOR.pubkey())
    check_channel_config(_server_config(), good, fee_payer=FEE_PAYER, operator=OPERATOR.pubkey())
    with pytest.raises(BatchSettlementError) as exc:
        check_channel_config(config, _requirements(**extra), fee_payer=FEE_PAYER, operator=operator)
    assert _code(exc) == errors.INVALID_CHANNEL_STATE


def test_channel_config_runs_the_terms_first() -> None:
    with pytest.raises(BatchSettlementError) as exc:
        check_channel_config(_config(), _requirements(withdrawDelay=100), fee_payer=FEE_PAYER, operator=None)
    assert _code(exc) == errors.INVALID_WITHDRAW_DELAY_OUT_OF_RANGE


# -- voucher and payer proof ---------------------------------------------------


def test_voucher_check_binds_channel_expiry_and_signer() -> None:
    config = _config()
    channel = derive_channel_id(config, FEE_PAYER)
    good = sign_voucher(PAYER, channel, 5000)
    assert check_voucher(good, config, channel) == 5000

    cases: list[tuple[Any, BatchChannelConfig, str]] = [
        ({**good, "channelId": PAY_TO}, config, errors.INVALID_CHANNEL_ID_MISMATCH),
        ({**good, "expiresAt": 4_102_444_800}, config, errors.INVALID_VOUCHER_EXPIRY),
        ({**good, "maxClaimableAmount": "6000"}, config, errors.INVALID_VOUCHER_SIGNATURE),
        (good, _config(payerAuthorizer=_signer(8).pubkey()), errors.INVALID_VOUCHER_SIGNATURE),
        # Malformed base58 is still a voucher-signature failure, not a crash.
        ({**good, "signature": "0OIl"}, config, errors.INVALID_VOUCHER_SIGNATURE),
    ]
    for voucher, cfg, code in cases:
        with pytest.raises(BatchSettlementError) as exc:
            check_voucher(voucher, cfg, channel)
        assert _code(exc) == code


def test_payer_proof_binds_channel_payer_amount_expiry_and_operator() -> None:
    config = _server_config()
    channel = derive_channel_id(config, FEE_PAYER)
    proof = sign_authorization(
        PAYER,
        channel_id=channel,
        operator=OPERATOR.pubkey(),
        request_id="r-1",
        authorized_amount=10000,
        expires_at=NOW + 60,
    )
    check_authorization(proof, config, channel, amount="10000", now=NOW)

    other_channel = derive_channel_id(_server_config(salt="43"), FEE_PAYER)
    signed_elsewhere = sign_authorization(
        PAYER,
        channel_id=other_channel,
        operator=OPERATOR.pubkey(),
        request_id="r",
        authorized_amount=10000,
        expires_at=NOW + 60,
    )
    cases: list[tuple[Any, BatchChannelConfig, str, int]] = [
        (signed_elsewhere, config, "10000", NOW),  # a proof for another channel
        (proof, _server_config(payer=FEE_PAYER), "10000", NOW),
        (proof, config, "10001", NOW),  # a different price
        (proof, config, "010000", NOW),  # same number, different wire string
        (proof, config, "10000", NOW + 60),  # expired at expiresAt
        (proof, _config(), "10000", NOW),  # signed for the operator, not the payer authorizer
        ({**proof, "signature": str(Keypair().sign_message(b"x"))}, config, "10000", NOW),
    ]
    for auth, cfg, amount, now in cases:
        with pytest.raises(BatchSettlementError) as exc:
            check_authorization(auth, cfg, channel, amount=amount, now=now)
        assert _code(exc) == errors.INVALID_VOUCHER_SIGNATURE


def test_cooperative_close_hints_are_refused_but_plain_refunds_pass() -> None:
    plain = cast("BatchPayload", {"type": "refund", "channelConfig": _config(), "transaction": "tx"})
    check_no_cooperative_close(plain)
    for hint in (
        {"voucher": {"channelId": PAY_TO, "maxClaimableAmount": "1", "expiresAt": 0, "signature": "s"}},
        {"closeAuthorization": {"validBefore": NOW, "signature": "s"}},
    ):
        with pytest.raises(BatchSettlementError) as exc:
            check_no_cooperative_close(cast("BatchPayload", {**plain, **hint}))
        assert _code(exc) == errors.INVALID_CLOSE_AUTHORIZATION
    # Paid-request payloads are unaffected by the refund-only rule.
    voucher = {"channelId": PAY_TO, "maxClaimableAmount": "1", "expiresAt": 0, "signature": "s"}
    check_no_cooperative_close(
        cast("BatchPayload", {"type": "voucher", "channelConfig": _config(), "voucher": voucher})
    )


# -- cumulative and capacity -----------------------------------------------------


def test_exact_replay_is_duplicate_settlement_and_other_amounts_mismatch() -> None:
    check_cumulative(30_000, "sig-3", charged=20_000, amount=10_000, signed_signature="sig-2")
    check_cumulative(10_000, "sig-1", charged=0, amount=10_000, signed_signature=None)  # first voucher on open
    with pytest.raises(BatchSettlementError) as exc:
        check_cumulative(20_000, "sig-2", charged=20_000, amount=10_000, signed_signature="sig-2")
    assert _code(exc) == errors.DUPLICATE_SETTLEMENT
    # Same amount, different signature: not a replay, just behind.
    for submitted, signature in ((20_000, "sig-other"), (29_999, "s"), (30_001, "s"), (40_000, "s")):
        with pytest.raises(BatchSettlementError) as exc:
            check_cumulative(submitted, signature, charged=20_000, amount=10_000, signed_signature="sig-2")
        assert _code(exc) == errors.INVALID_CUMULATIVE_AMOUNT_MISMATCH


def test_capacity_counts_live_ceilings_against_the_deposit() -> None:
    check_capacity(max_claimable=30_000, charged=20_000, reserved=0, ceiling=10_000, deposit=30_000)
    # A top-up validated in the same request is added to the deposit by the caller.
    check_capacity(max_claimable=40_000, charged=30_000, reserved=0, ceiling=10_000, deposit=30_000 + 10_000)
    for kwargs in (
        {"max_claimable": 30_001, "charged": 0, "reserved": 0, "ceiling": 0, "deposit": 30_000},
        # Concurrent server-signed ceilings share the escrow.
        {"max_claimable": 0, "charged": 10_000, "reserved": 10_000, "ceiling": 10_001, "deposit": 30_000},
    ):
        with pytest.raises(BatchSettlementError) as exc:
            check_capacity(**kwargs)
        assert _code(exc) == errors.INVALID_CUMULATIVE_EXCEEDS_DEPOSIT


# -- confirmed on-chain channel --------------------------------------------------


def _channel_account(config: BatchChannelConfig, **overrides: Any) -> bytes:
    fields: dict[str, Any] = {
        "version": 1,
        "bump": 255,
        "status": CHANNEL_STATUS_OPEN,
        "salt": int(config["salt"]),
        "deposit": 100_000,
        "settlement": {"settled": 0, "payoutWatermark": 0},
        "closureStartedAt": 0,
        "payerWithdrawnAt": 0,
        "gracePeriod": config["withdrawDelay"],
        "distributionHash": list(distribution_hash([Distribution(Pubkey.from_string(PAY_TO), 10_000)])),
        "payer": Pubkey.from_string(config["payer"]),
        "payee": Pubkey.from_string(FEE_PAYER),
        "authorizedSigner": Pubkey.from_string(config["payerAuthorizer"]),
        "mint": Pubkey.from_string(config["token"]),
        "rentPayer": Pubkey.from_string(FEE_PAYER),
        "openSlot": config["openSlot"],
    }
    fields.update(overrides)
    return bytes([1]) + bytes(Channel.layout.build(fields))


def test_channel_account_decode_refuses_a_foreign_owner_size_or_discriminator() -> None:
    account = _channel_account(_config())
    assert decode_channel(account, PAYMENT_CHANNELS_PROGRAM_ID).deposit == 100_000
    for data, owner in (
        (account, SYSTEM_PROGRAM),
        (account[:-1], PAYMENT_CHANNELS_PROGRAM_ID),
        (bytes([2]) + account[1:], PAYMENT_CHANNELS_PROGRAM_ID),  # a ClosedChannel
    ):
        with pytest.raises(BatchSettlementError) as exc:
            decode_channel(data, owner)
        assert _code(exc) == errors.INVALID_CHANNEL_STATE


@pytest.mark.parametrize(
    "overrides",
    [
        {"status": CHANNEL_STATUS_CLOSING},
        {"payer": Pubkey.from_string(PAY_TO)},
        {"payee": Pubkey.from_string(PAY_TO)},
        {"rentPayer": Pubkey.from_string(PAY_TO)},
        {"authorizedSigner": Pubkey.from_string(FEE_PAYER)},
        {"mint": Pubkey.from_string(PAY_TO)},
        {"gracePeriod": 1800},
        {"salt": 43},
        {"openSlot": 341_000_001},
        {"distributionHash": [0] * 32},
    ],
    ids=lambda o: next(iter(o)),
)
def test_onchain_binding_checks_every_immutable_field(overrides: dict[str, Any]) -> None:
    config = _config()
    good = decode_channel(_channel_account(config), PAYMENT_CHANNELS_PROGRAM_ID)
    check_channel_binding(good, config, _requirements())
    bad = decode_channel(_channel_account(config, **overrides), PAYMENT_CHANNELS_PROGRAM_ID)
    with pytest.raises(BatchSettlementError) as exc:
        check_channel_binding(bad, config, _requirements())
    assert _code(exc) == errors.INVALID_CHANNEL_STATE


def test_onchain_binding_admits_the_statuses_the_caller_allows() -> None:
    # A refund reads a channel that may already be Closing.
    config = _config()
    closing = decode_channel(_channel_account(config, status=CHANNEL_STATUS_CLOSING), PAYMENT_CHANNELS_PROGRAM_ID)
    check_channel_binding(closing, config, _requirements(), statuses=(CHANNEL_STATUS_OPEN, CHANNEL_STATUS_CLOSING))
