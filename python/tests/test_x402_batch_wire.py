"""x402 ``batch-settlement`` wire types, error codes and stateless checks."""

from __future__ import annotations

import dataclasses
from typing import Any

import pytest
from solders.pubkey import Pubkey

from solana_pay_kit._paycore.paymentchannels import PROGRAM_ID, voucher_message_bytes
from solana_pay_kit.protocols.x402.batch_settlement import errors as codes
from solana_pay_kit.protocols.x402.batch_settlement.errors import BatchSettlementError, classify, leading_code
from solana_pay_kit.protocols.x402.batch_settlement.types import (
    BatchChannelConfig,
    BatchClaim,
    BatchPayload,
    BatchRequirements,
    BatchSettle,
    BatchSettlementResponse,
    BatchVoucher,
    BatchWireError,
    VoucherState,
    parse_amount,
    parse_redemption,
    wire_roundtrip,
)
from solana_pay_kit.protocols.x402.batch_settlement.verify import (
    CloseAuthorizationScope,
    authorization_message_bytes,
    check_channel_config,
    check_client_signed_payload,
    check_corrective_voucher_state,
    check_no_client_close_authorization,
    check_no_refund_amount,
    check_payment_flow,
    check_token_program,
    check_voucher,
    check_withdraw_delay,
    close_authorization_digest,
    derive_channel_id,
    parse_pubkey,
    parse_receiver_binding_memo,
    receiver_binding_memo,
    sign_close_authorization,
    verify_close_authorization,
)
from tests._batch_fixture import FEE_PAYER, MINT, NETWORK, PAY_TO, PAYER, RECEIVER_AUTHORIZER, STRANGER, requirements, signer

CONFIG: dict[str, Any] = {
    "openSlot": 341000000,
    "payer": str(PAYER.pubkey()),
    "payerAuthorizer": str(PAYER.pubkey()),
    "receiver": str(PAY_TO),
    "receiverAuthorizer": str(RECEIVER_AUTHORIZER.pubkey()),
    "salt": "42",
    "token": str(MINT),
    "withdrawDelay": 3600,
}


def _config(**overrides: Any) -> BatchChannelConfig:
    raw = dict(CONFIG)
    raw.update(overrides)
    return BatchChannelConfig.from_dict(raw)


def _voucher(channel: Pubkey, amount: int, expires_at: int = 0, key: Any = PAYER) -> BatchVoucher:
    signature = key.sign_message(voucher_message_bytes(channel, amount, expires_at))
    return BatchVoucher(str(channel), str(amount), expires_at, str(signature))


def _code(exc: pytest.ExceptionInfo[BaseException]) -> str:
    assert isinstance(exc.value, BatchSettlementError)
    return exc.value.code


# ── errors ──


def test_classify_prefers_the_leading_code_over_quoted_text() -> None:
    message = f"{codes.INVALID_CLOSE_STATE}: refund quoted {codes.INVALID_PAYLOAD_TYPE}"
    assert leading_code(message) == codes.INVALID_CLOSE_STATE
    assert classify(message) == codes.INVALID_CLOSE_STATE
    assert leading_code(f"wrapped {codes.INVALID_PAYLOAD_TYPE}") is None
    assert classify(f"wrapped {codes.INVALID_PAYLOAD_TYPE}") == codes.INVALID_PAYLOAD_TYPE
    assert classify("something else") == "transaction_failed"
    error = BatchSettlementError(codes.INVALID_CHANNEL_STATE, "detail")
    assert str(error) == f"{codes.INVALID_CHANNEL_STATE}: detail"
    assert (error.code, error.detail) == (codes.INVALID_CHANNEL_STATE, "detail")


# ── wire ──


def test_requirements_round_trip_drops_absent_options_and_unknown_fields() -> None:
    raw = requirements(transaction_versions=[0, 1], max_claim_channels=18).to_dict()
    raw["extra"]["unknownField"] = True
    raw["extra"]["recentSlot"] = None
    out = wire_roundtrip("requirements", raw)
    assert "unknownField" not in out["extra"] and "recentSlot" not in out["extra"]
    assert out["extra"]["transactionVersions"] == [0, 1]
    assert out["extra"]["maxClaimChannels"] == 18
    del raw["scheme"]
    assert BatchRequirements.from_dict(raw).scheme == "batch-settlement"


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda r: r["extra"].update(withdrawDelay=900.5), codes.INVALID_WITHDRAW_DELAY_OUT_OF_RANGE),
        (lambda r: r["extra"].update(withdrawDelay=-1), codes.INVALID_WITHDRAW_DELAY_OUT_OF_RANGE),
        (lambda r: r["extra"].update(withdrawDelay="900"), "must be a number"),
        (lambda r: r["extra"].update(transactionVersions=[0, 2]), "unsupported transaction version"),
        (lambda r: r["extra"].update(transactionVersions="0"), "must be an array"),
        (lambda r: r.update(scheme=None), "scheme must be a string"),
        (lambda r: r.update(maxTimeoutSeconds=True), "maxTimeoutSeconds"),
        (lambda r: r.update(amount=1000), "amount must be a string"),
        (lambda r: r.pop("payTo"), "missing field `payTo`"),
        (lambda r: r["extra"].update(memo=7), "memo must be a string"),
    ],
)
def test_requirements_refuse_malformed_fields(mutate: Any, message: str) -> None:
    raw = requirements().to_dict()
    mutate(raw)
    with pytest.raises(BatchWireError, match=message):
        BatchRequirements.from_dict(raw)


def test_payload_variants_round_trip() -> None:
    channel = derive_channel_id(_config(), str(FEE_PAYER.pubkey()))
    voucher = _voucher(channel, 1000).to_dict()
    deposit = {"type": "deposit", "channelConfig": CONFIG, "voucher": voucher, "deposit": {"amount": "1", "transaction": "AQID"}}
    assert wire_roundtrip("payload", deposit)["deposit"] == {"amount": "1", "transaction": "AQID"}
    refund = {"type": "refund", "channelConfig": CONFIG, "voucher": voucher, "transaction": "AQID", "amount": "5"}
    assert wire_roundtrip("payload", refund)["amount"] == "5"
    authorization = {
        "type": "proof",
        "channelId": str(channel),
        "payer": str(PAYER.pubkey()),
        "requestId": "r",
        "authorizedAmount": "1",
        "expiresAt": 5,
        "signature": "x",
    }
    payload = BatchPayload.from_dict({"type": "authorization", "channelConfig": CONFIG, "authorization": authorization})
    assert payload.charge_voucher() is None
    assert payload.to_dict()["authorization"]["type"] == "proof"
    envelope = {"x402Version": 2, "accepted": requirements().to_dict(), "payload": deposit}
    assert wire_roundtrip("paymentPayload", envelope)["x402Version"] == 2
    assert BatchPayload.from_dict(deposit).charge_voucher() is not None


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        ({"type": "refund", "channelConfig": CONFIG}, codes.INVALID_PAYLOAD_TYPE),
        ({"type": "withdraw", "channelConfig": CONFIG}, "unknown variant"),
        ({"type": "voucher", "channelId": "x"}, "missing field `channelConfig`"),
        ({"type": "voucher", "channelConfig": CONFIG, "voucher": {"channelId": "a", "maxClaimableAmount": 1, "expiresAt": 0, "signature": "s"}}, "maxClaimableAmount must be a string"),
        ({"type": "voucher", "channelConfig": {**CONFIG, "withdrawDelay": 1.5}}, "withdrawDelay"),
        ([], "must be a JSON object"),
    ],
)
def test_payload_refusals(payload: Any, message: str) -> None:
    with pytest.raises(BatchWireError, match=message):
        BatchPayload.from_dict(payload)


def test_refund_with_voucher_and_authorization_is_refused() -> None:
    channel = derive_channel_id(_config(), str(FEE_PAYER.pubkey()))
    authorization = {
        "type": "proof",
        "channelId": "c",
        "payer": "p",
        "requestId": "r",
        "authorizedAmount": "0",
        "expiresAt": 1,
        "signature": "s",
    }
    raw = {"type": "refund", "channelConfig": CONFIG, "voucher": _voucher(channel, 0).to_dict(), "authorization": authorization}
    with pytest.raises(BatchWireError, match="not both"):
        BatchPayload.from_dict(raw)


def test_redemptions_bound_their_batch_sizes() -> None:
    channel = derive_channel_id(_config(), str(FEE_PAYER.pubkey()))
    claim = {"channelId": str(channel), "channelConfig": CONFIG, "voucher": _voucher(channel, 5).to_dict()}
    assert wire_roundtrip("redemption", {"type": "claim", "claims": [claim] * 18})["type"] == "claim"
    with pytest.raises(BatchWireError, match="1 through 18"):
        parse_redemption({"type": "claim", "claims": [claim] * 19})
    with pytest.raises(BatchWireError, match="1 through 18"):
        parse_redemption({"type": "claim", "claims": []})
    settle = {"channelId": str(channel), "channelConfig": CONFIG}
    assert len(parse_redemption({"type": "settle", "channels": [settle] * 13}).to_dict()["channels"]) == 13
    with pytest.raises(BatchWireError, match="1 through 13"):
        parse_redemption({"type": "settle", "channels": [settle] * 14})
    with pytest.raises(BatchWireError, match="must be an array"):
        parse_redemption({"type": "settle", "channels": {}})
    seal = {**claim, "type": "seal", "closeAuthorization": {"validBefore": 5, "signature": "s"}}
    assert wire_roundtrip("redemption", seal)["closeAuthorization"]["validBefore"] == 5
    with pytest.raises(BatchWireError, match="unknown variant"):
        parse_redemption({"type": "drain"})
    with pytest.raises(BatchWireError):
        BatchClaim([])
    with pytest.raises(BatchWireError):
        BatchSettle([])


def test_responses_and_envelopes() -> None:
    response = {"success": True, "network": NETWORK, "transaction": "", "extra": {"commitmentId": "c:1", "chargedAmount": "1"}}
    out = wire_roundtrip("settlementResponse", response)
    assert out["amount"] == ""
    assert BatchSettlementResponse.from_dict(response).channel_state() is None
    with pytest.raises(BatchWireError, match="amount must be a string"):
        BatchSettlementResponse.from_dict({**response, "amount": 1})
    with pytest.raises(BatchWireError, match="success must be a boolean"):
        BatchSettlementResponse.from_dict({**response, "success": "yes"})
    failure = BatchSettlementResponse.failure(NETWORK, codes.INVALID_CHANNEL_STATE, "p").to_dict()
    assert failure["errorReason"] == codes.INVALID_CHANNEL_STATE
    corrective = requirements(
        channel_state=None,
        voucher_state=VoucherState("3000", 0, "sig"),
    ).to_dict()
    corrective["extra"]["channelState"] = {
        "channelId": "c",
        "balance": "1",
        "totalClaimed": "0",
        "withdrawRequestedAt": 0,
        "chargedCumulativeAmount": "1",
    }
    envelope = {"x402Version": 2, "accepts": [corrective], "error": "e", "resource": {"url": "/r", "mimeType": "x"}}
    out = wire_roundtrip("paymentRequired", envelope)
    assert out["resource"] == {"url": "/r", "mimeType": "x"}
    assert BatchRequirements.from_dict(corrective).is_corrective()
    assert wire_roundtrip("paymentRequired", {"x402Version": 2})["accepts"] == []
    with pytest.raises(BatchWireError, match="accepts must be an array"):
        wire_roundtrip("paymentRequired", {"x402Version": 2, "accepts": {}})
    with pytest.raises(ValueError, match="unknown batch-settlement wire shape"):
        wire_roundtrip("bogus", {})


def test_parse_amount_is_a_strict_decimal_u64() -> None:
    assert parse_amount("18446744073709551615", "x") == (1 << 64) - 1
    for bad in ("", "0x1", "-1", "1.0", "18446744073709551616", "١"):
        with pytest.raises(ValueError):
            parse_amount(bad, "x")
    assert VoucherState("7", 0, "s").signed_max_claimable_amount() == 7
    with pytest.raises(ValueError):
        _config(salt="0x2a").salt_value()


# ── stateless checks ──


def test_receiver_binding_memo() -> None:
    key = RECEIVER_AUTHORIZER.pubkey()
    memo = receiver_binding_memo(key)
    assert memo == f"x402:batch-settlement:svm:rcvauth:v1:{key}"
    assert parse_receiver_binding_memo(memo.encode()) == key
    assert parse_receiver_binding_memo(b"invoice-42") is None
    with pytest.raises(BatchSettlementError) as exc:
        parse_receiver_binding_memo(b"x402:batch-settlement:svm:rcvauth:v1:not-a-key")
    assert _code(exc) == codes.INVALID_RECEIVER_AUTHORIZER_MISMATCH


def test_terms_checks() -> None:
    check_payment_flow(None)
    check_payment_flow("authorization")
    with pytest.raises(BatchSettlementError) as exc:
        check_payment_flow("upfront")
    assert _code(exc) == codes.INVALID_PAYMENT_FLOW
    check_withdraw_delay(900, 900)
    for delay, timeout in ((899, 1), (2_592_001, 1), (900, 901)):
        with pytest.raises(BatchSettlementError) as exc:
            check_withdraw_delay(delay, timeout)
        assert _code(exc) == codes.INVALID_WITHDRAW_DELAY_OUT_OF_RANGE
    with pytest.raises(BatchSettlementError) as exc:
        check_token_program("11111111111111111111111111111111")
    assert _code(exc) == codes.INVALID_TOKEN_PROGRAM
    with pytest.raises(ValueError, match="invalid pubkey"):
        parse_pubkey("nope")


@pytest.mark.parametrize(
    ("config", "extra", "code"),
    [
        ({"payer": str(FEE_PAYER.pubkey())}, {}, codes.INVALID_FEE_PAYER_MISMATCH),
        ({"payerAuthorizer": str(FEE_PAYER.pubkey())}, {}, codes.INVALID_FEE_PAYER_MISMATCH),
        ({"receiver": str(STRANGER.pubkey())}, {}, codes.INVALID_CHANNEL_STATE),
        ({"token": str(STRANGER.pubkey())}, {}, codes.INVALID_CHANNEL_STATE),
        ({"withdrawDelay": 7200}, {}, codes.INVALID_WITHDRAW_DELAY_MISMATCH),
        ({"receiverAuthorizer": None}, {}, codes.INVALID_RECEIVER_AUTHORIZER_MISMATCH),
        ({}, {"receiver_authorizer": None}, codes.INVALID_RECEIVER_AUTHORIZER_MISMATCH),
        ({"voucherSigner": "server"}, {}, codes.INVALID_CHANNEL_STATE),
        ({"voucherSigner": "server"}, {"voucher_signer": "server"}, codes.INVALID_CHANNEL_STATE),
        ({}, {"operator": str(STRANGER.pubkey())}, codes.INVALID_CHANNEL_STATE),
        ({}, {"payment_flow": "upfront"}, codes.INVALID_PAYMENT_FLOW),
    ],
)
def test_channel_config_bindings(config: dict[str, Any], extra: dict[str, Any], code: str) -> None:
    with pytest.raises(BatchSettlementError) as exc:
        check_channel_config(_config(**config), requirements(**extra))
    assert _code(exc) == code


def test_channel_config_accepts_the_challenge_it_answers() -> None:
    check_channel_config(_config(), requirements())


def test_derive_channel_id_rejects_bad_inputs() -> None:
    assert derive_channel_id(_config(), str(FEE_PAYER.pubkey()), PROGRAM_ID) == derive_channel_id(
        _config(receiver=str(STRANGER.pubkey())), str(FEE_PAYER.pubkey())
    )
    with pytest.raises(BatchSettlementError) as exc:
        derive_channel_id(_config(salt="0x2a"), str(FEE_PAYER.pubkey()))
    assert _code(exc) == codes.INVALID_CHANNEL_STATE
    with pytest.raises(BatchSettlementError):
        derive_channel_id(_config(payer="bad"), str(FEE_PAYER.pubkey()))


def test_payload_type_policies() -> None:
    channel = derive_channel_id(_config(), str(FEE_PAYER.pubkey()))
    voucher = _voucher(channel, 1000)
    config = _config()
    check_client_signed_payload(BatchPayload("voucher", config, voucher=voucher))
    for payload in (
        BatchPayload("authorization", config),
        BatchPayload("deposit", config),
        BatchPayload("refund", config, authorization=object()),  # type: ignore[arg-type]
    ):
        with pytest.raises(BatchSettlementError) as exc:
            check_client_signed_payload(payload)
        assert _code(exc) == codes.INVALID_PAYLOAD_TYPE
    with pytest.raises(BatchSettlementError) as exc:
        check_no_refund_amount(BatchPayload("refund", config, voucher=voucher, amount="1"))
    assert _code(exc) == codes.INVALID_CLOSE_AMOUNT_UNSUPPORTED
    check_no_refund_amount(BatchPayload("voucher", config, voucher=voucher, amount="1"))
    with pytest.raises(BatchSettlementError) as exc:
        check_no_client_close_authorization(BatchPayload("refund", config, voucher=voucher, close_authorization=object()))  # type: ignore[arg-type]
    assert _code(exc) == codes.INVALID_CLOSE_AUTHORIZATION


def test_check_voucher() -> None:
    config = _config()
    channel = derive_channel_id(config, str(FEE_PAYER.pubkey()))
    assert check_voucher(_voucher(channel, 1000), config, channel) == 1000
    other = derive_channel_id(_config(salt="43"), str(FEE_PAYER.pubkey()))
    cases = [
        (_voucher(other, 1000), codes.INVALID_CHANNEL_ID_MISMATCH),
        (_voucher(channel, 1000, expires_at=5), codes.INVALID_VOUCHER_EXPIRY),
        (_voucher(channel, 1000, key=STRANGER), codes.INVALID_VOUCHER_SIGNATURE),
        (BatchVoucher(str(channel), "1x", 0, "s"), codes.INVALID_VOUCHER_SIGNATURE),
        (BatchVoucher(str(channel), "1", 0, "not-a-signature"), codes.INVALID_VOUCHER_SIGNATURE),
    ]
    for voucher, code in cases:
        with pytest.raises(BatchSettlementError) as exc:
            check_voucher(voucher, config, channel)
        assert _code(exc) == code
    with pytest.raises(BatchSettlementError, match="authorized_signer"):
        check_voucher(_voucher(channel, 1000), _config(payerAuthorizer="bad"), channel)


async def test_close_authorization_sign_and_verify() -> None:
    channel = derive_channel_id(_config(), str(FEE_PAYER.pubkey()))
    scope = CloseAuthorizationScope(NETWORK, PROGRAM_ID, FEE_PAYER.pubkey(), channel, 5000, 0)
    digest = close_authorization_digest(scope, 100)
    assert len(digest) == 32
    assert close_authorization_digest(CloseAuthorizationScope("solana:x", PROGRAM_ID, FEE_PAYER.pubkey(), channel, 5000, 0), 100) != digest
    authorization = await sign_close_authorization(signer(RECEIVER_AUTHORIZER), scope, 100)
    verify_close_authorization(authorization, RECEIVER_AUTHORIZER.pubkey(), scope, now=50, max_timeout_seconds=300)
    for now, timeout, key in ((100, 300, RECEIVER_AUTHORIZER), (0, 50, RECEIVER_AUTHORIZER), (50, 300, STRANGER)):
        with pytest.raises(BatchSettlementError) as exc:
            verify_close_authorization(authorization, key.pubkey(), scope, now=now, max_timeout_seconds=timeout)
        assert _code(exc) == codes.INVALID_CLOSE_AUTHORIZATION
    bad = dataclasses.replace(authorization, signature="nope")
    with pytest.raises(BatchSettlementError, match="64 base58 bytes"):
        verify_close_authorization(bad, RECEIVER_AUTHORIZER.pubkey(), scope, now=50, max_timeout_seconds=300)
    with pytest.raises(BatchSettlementError):
        close_authorization_digest(CloseAuthorizationScope("n" * 70_000, PROGRAM_ID, FEE_PAYER.pubkey(), channel, 1, 0), 1)
    with pytest.raises(BatchSettlementError):
        close_authorization_digest(CloseAuthorizationScope(NETWORK, PROGRAM_ID, FEE_PAYER.pubkey(), channel, -1, 0), 1)

    class Broken:
        async def sign_message(self, message: bytes) -> Any:
            raise RuntimeError("hsm offline")

    with pytest.raises(BatchSettlementError, match="hsm offline"):
        await sign_close_authorization(Broken(), scope, 100)  # type: ignore[arg-type]


def test_corrective_voucher_state() -> None:
    channel = derive_channel_id(_config(), str(FEE_PAYER.pubkey()))
    proof = _voucher(channel, 3000)
    state = VoucherState(proof.max_claimable_amount, 0, proof.signature)
    assert check_corrective_voucher_state(state, str(channel), str(PAYER.pubkey()), 3000) == 3000
    with pytest.raises(BatchSettlementError) as exc:
        check_corrective_voucher_state(state, str(channel), str(PAYER.pubkey()), 3001)
    assert _code(exc) == codes.INVALID_CUMULATIVE_AMOUNT_MISMATCH
    with pytest.raises(BatchSettlementError) as exc:
        check_corrective_voucher_state(VoucherState("x", 0, "s"), str(channel), str(PAYER.pubkey()), 0)
    assert _code(exc) == codes.INVALID_CUMULATIVE_AMOUNT_MISMATCH
    with pytest.raises(BatchSettlementError) as exc:
        check_corrective_voucher_state(state, str(channel), str(STRANGER.pubkey()), 0)
    assert _code(exc) == codes.INVALID_VOUCHER_SIGNATURE
    with pytest.raises(BatchSettlementError, match="invalid channelId"):
        check_corrective_voucher_state(state, "bad", str(PAYER.pubkey()), 0)


def test_authorization_message_layout() -> None:
    channel, payer, operator = PAYER.pubkey(), FEE_PAYER.pubkey(), STRANGER.pubkey()
    message = authorization_message_bytes(channel, payer, operator, "é", 1000, 5)
    assert message.startswith(b"x402-batch-authorization-v2")
    assert len(message) == 27 + 96 + 2 + 2 + 16
    for request_id, amount, expires in (("", 1, 1), ("x" * 257, 1, 1), ("x", 1, 0), ("x", 1 << 64, 1)):
        with pytest.raises(ValueError):
            authorization_message_bytes(channel, payer, operator, request_id, amount, expires)
