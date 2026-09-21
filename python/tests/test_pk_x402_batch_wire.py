"""Wire types, error codes and signed-message encodings for x402 ``batch-settlement``.

Byte vectors are frozen literals, never re-derived in-test: the voucher from
the Rust ``voucher_message_is_program_borsh_layout`` layout, the payer
authorization and close digest from running the x402 PR #23 TypeScript
encoders (``authorization.ts``, ``closeAuthorization.ts``) once on the inputs
below.
"""

from __future__ import annotations

import copy
from typing import Any

import pytest
from solders.keypair import Keypair
from solders.pubkey import Pubkey

from solana_pay_kit.protocols.x402.batch_settlement import errors
from solana_pay_kit.protocols.x402.batch_settlement.errors import BatchSettlementError, classify
from solana_pay_kit.protocols.x402.batch_settlement.signatures import (
    authorization_message,
    close_authorization_digest,
    sign_authorization,
    sign_close_authorization,
    sign_voucher,
    verify_authorization,
    verify_close_authorization,
    verify_voucher,
    voucher_message,
)
from solana_pay_kit.protocols.x402.batch_settlement.types import (
    commitment_id,
    parse_payment_payload,
    parse_requirements,
    parse_u64,
)
from solana_pay_kit.signer import LocalSigner

PK1 = "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi"  # 32 x 0x01
PK2 = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR"  # 32 x 0x02
PK3 = "CktRuQ2mttgRGkXJtyksdKHjUdc2C4TgDzyB98oEzy8"  # 32 x 0x03
PK9 = "cGfHiC6Kgg3FpFZvgwGcswsCRtp4aBP2fzuXRQPizuN"  # 32 x 0x09
NETWORK = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"
NOW = 1_700_000_000


def _signer(seed: int) -> LocalSigner:
    return LocalSigner.from_keypair(Keypair.from_seed(bytes([seed] * 32)))


def _requirements() -> dict[str, Any]:
    return {
        "scheme": "batch-settlement",
        "network": NETWORK,
        "amount": "10000",
        "asset": "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
        "payTo": PK3,
        "maxTimeoutSeconds": 300,
        "extra": {"feePayer": PK2, "withdrawDelay": 900, "tokenProgram": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"},
    }


def _config(**overrides: Any) -> dict[str, Any]:
    config: dict[str, Any] = {
        "payer": PK1,
        "payerAuthorizer": PK1,
        "receiver": PK3,
        "token": "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
        "withdrawDelay": 900,
        "salt": "0",
        "openSlot": 341_000_000,
    }
    config.update(overrides)
    return config


_VOUCHER = {"channelId": PK9, "maxClaimableAmount": "10000", "expiresAt": 0, "signature": "sig"}
_PROOF = {
    "type": "proof",
    "channelId": PK9,
    "payer": PK1,
    "requestId": "req-1",
    "authorizedAmount": "10000",
    "expiresAt": NOW + 60,
    "signature": "sig",
}


def _envelope(payload: dict[str, Any]) -> dict[str, Any]:
    return {"x402Version": 2, "accepted": _requirements(), "payload": payload}


# -- error codes -----------------------------------------------------------


def test_every_code_is_prefixed_and_none_shadows_another() -> None:
    # classify() returns the first code found in a message, so a code that is
    # a substring of another would be reported in its place.
    for code in errors.ALL_CODES:
        assert code.startswith("invalid_batch_settlement_svm_") or code == errors.DUPLICATE_SETTLEMENT
        assert not any(code != other and code in other for other in errors.ALL_CODES), code
    assert len(errors.ALL_CODES) == 23


def test_classify_recovers_the_code_from_a_formatted_error() -> None:
    err = BatchSettlementError(errors.INVALID_VOUCHER_EXPIRY, "expiresAt was 42")
    assert err.code == errors.INVALID_VOUCHER_EXPIRY
    assert classify(str(err)) == errors.INVALID_VOUCHER_EXPIRY
    assert "expiresAt was 42" in str(err)
    assert classify("something else entirely") == "transaction_failed"


# -- wire parsing ------------------------------------------------------------


def test_payload_union_parses_every_variant_and_drops_unknown_keys() -> None:
    deposit = {"type": "deposit", "channelConfig": _config(), "deposit": {"amount": "50000", "transaction": "tx"}}
    variants = [
        {**deposit, "voucher": _VOUCHER},
        {"type": "voucher", "channelConfig": _config(), "voucher": _VOUCHER},
        {"type": "authorization", "channelConfig": _config(voucherSigner="server"), "authorization": _PROOF},
        {"type": "refund", "channelConfig": _config(), "transaction": "tx"},
    ]
    for payload in variants:
        parsed = parse_payment_payload(_envelope({**payload, "smuggled": 1}))
        assert parsed["payload"] == payload
        assert parsed["accepted"] == _requirements()


def test_client_voucher_signer_is_canonicalized_to_omitted() -> None:
    # "client" and absent both mean client mode; one spelling keeps stored
    # channel configs comparable, and the Rust client never sends the key.
    payload = {"type": "voucher", "channelConfig": _config(voucherSigner="client"), "voucher": _VOUCHER}
    parsed = parse_payment_payload(_envelope(payload))
    assert "voucherSigner" not in parsed["payload"]["channelConfig"]


@pytest.mark.parametrize(
    ("payload", "code"),
    [
        # A deposit authorizes by voucher in client mode, by payer proof in server mode.
        (
            {"type": "deposit", "channelConfig": _config(), "deposit": {"amount": "1", "transaction": "t"}},
            errors.INVALID_PAYLOAD_TYPE,
        ),
        (
            {
                "type": "deposit",
                "channelConfig": _config(),
                "deposit": {"amount": "1", "transaction": "t"},
                "voucher": _VOUCHER,
                "authorization": _PROOF,
            },
            errors.INVALID_PAYLOAD_TYPE,
        ),
        (
            {
                "type": "deposit",
                "channelConfig": _config(voucherSigner="server"),
                "deposit": {"amount": "1", "transaction": "t"},
                "voucher": _VOUCHER,
            },
            errors.INVALID_PAYLOAD_TYPE,
        ),
        (
            {"type": "voucher", "channelConfig": _config(voucherSigner="server"), "voucher": _VOUCHER},
            errors.INVALID_PAYLOAD_TYPE,
        ),
        ({"type": "authorization", "channelConfig": _config(), "authorization": _PROOF}, errors.INVALID_PAYLOAD_TYPE),
        (
            {
                "type": "authorization",
                "channelConfig": _config(voucherSigner="server"),
                "authorization": _PROOF,
                "requestId": "top-level",
            },
            errors.INVALID_PAYLOAD_TYPE,
        ),
        (
            {"type": "refund", "channelConfig": _config(), "transaction": "t", "amount": "5"},
            errors.INVALID_CLOSE_AMOUNT_UNSUPPORTED,
        ),
        ({"type": "claim", "channelConfig": _config()}, errors.INVALID_PAYLOAD_TYPE),
    ],
    ids=[
        "deposit-without-proof",
        "deposit-with-both",
        "server-deposit-with-voucher",
        "voucher-in-server-mode",
        "authorization-in-client-mode",
        "top-level-request-id",
        "refund-amount",
        "server-only-type",
    ],
)
def test_payload_union_rules_are_enforced(payload: dict[str, Any], code: str) -> None:
    with pytest.raises(BatchSettlementError) as exc:
        parse_payment_payload(_envelope(payload))
    assert exc.value.code == code


def test_envelope_requires_x402_version_2_and_the_scheme() -> None:
    payload = {"type": "voucher", "channelConfig": _config(), "voucher": _VOUCHER}
    with pytest.raises(BatchSettlementError):
        parse_payment_payload({**_envelope(payload), "x402Version": 1})
    with pytest.raises(BatchSettlementError):
        parse_payment_payload({**_envelope(payload), "accepted": {**_requirements(), "scheme": "upto"}})


@pytest.mark.parametrize("value", ["+5", "-1", "1e3", " 5", "5\n", "", "18446744073709551616", "٥"])
def test_u64_strings_are_strict(value: str) -> None:
    # "+5" is what Rust's u64::from_str would take; the wire is ^[0-9]+$.
    with pytest.raises(BatchSettlementError):
        parse_u64(value, "amount")
    bad = _requirements()
    bad["amount"] = value
    with pytest.raises(BatchSettlementError):
        parse_requirements(bad)
    assert parse_u64("18446744073709551615", "amount") == 2**64 - 1


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("extra", "withdrawDelay"), True),
        (("extra", "withdrawDelay"), 900.0),
        (("extra", "withdrawDelay"), 2**32),
        (("extra", "recentSlot"), "341000000"),
        (("extra", "receiverAuthorizer"), None),
        (("maxTimeoutSeconds",), -1),
    ],
    ids=["bool", "float", "u32-overflow", "string-slot", "null-optional", "negative"],
)
def test_integers_are_json_integers_and_optionals_are_never_null(path: tuple[str, ...], value: Any) -> None:
    bad = _requirements()
    target = bad
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    with pytest.raises(BatchSettlementError):
        parse_requirements(bad)


def test_corrective_requirements_carry_the_snapshot_and_voucher_proof() -> None:
    corrective = _requirements()
    corrective["extra"]["channelState"] = {
        "channelId": PK9,
        "balance": "100000",
        "totalClaimed": "2000",
        "withdrawRequestedAt": 0,
        "chargedCumulativeAmount": "3000",
    }
    corrective["extra"]["voucherState"] = {"signedMaxClaimable": "3000", "expiresAt": 0, "signature": "sig"}
    assert parse_requirements(copy.deepcopy(corrective)) == corrective


def test_commitment_id_pairs_the_channel_with_its_watermark() -> None:
    # The Rust client checks this string verbatim.
    assert commitment_id(PK9, "5000") == f"{PK9}:5000"


# -- voucher -----------------------------------------------------------------


def test_voucher_preimage_matches_the_frozen_program_layout() -> None:
    expected = bytes.fromhex(
        "5601" + "09" * 32 + "2a00000000000000" + "d204000000000000"  # magic, channel, u64 42, i64 1234
    )
    assert voucher_message(PK9, 42, 1234) == expected


def test_voucher_signature_binds_channel_amount_expiry_and_signer() -> None:
    signer = _signer(7)
    voucher = sign_voucher(signer, PK9, 5000)
    assert voucher["expiresAt"] == 0
    assert verify_voucher(voucher, signer.pubkey())
    for tampered in (
        {**voucher, "channelId": PK1},
        {**voucher, "maxClaimableAmount": "5001"},
        {**voucher, "expiresAt": 1},
        {**voucher, "signature": "not-base58!"},
        {**voucher, "channelId": "short"},
    ):
        assert not verify_voucher(tampered, signer.pubkey())  # type: ignore[arg-type]
    assert not verify_voucher(voucher, _signer(8).pubkey())


# -- payer authorization (server-signed mode) --------------------------------


def test_authorization_message_matches_the_pr23_encoder() -> None:
    ascii_id = authorization_message(
        channel_id=PK9, payer=PK1, operator=PK2, request_id="req-1", authorized_amount=10000, expires_at=NOW
    )
    assert ascii_id.hex() == (
        "783430322d62617463682d617574686f72697a6174696f6e2d7632"
        + "09" * 32
        + "01" * 32
        + "02" * 32
        + "05007265712d31102700000000000000f1536500000000"
    )
    # requestId length is its UTF-8 byte length, not its character count.
    utf8_id = authorization_message(
        channel_id=PK9, payer=PK1, operator=PK2, request_id="éü", authorized_amount=2**64 - 1, expires_at=1
    )
    assert utf8_id.hex() == (
        "783430322d62617463682d617574686f72697a6174696f6e2d7632"
        + "09" * 32
        + "01" * 32
        + "02" * 32
        + "0400c3a9c3bcffffffffffffffff0100000000000000"
    )


@pytest.mark.parametrize(
    "overrides",
    [
        {"channel_id": "short"},
        {"operator": "0OIl"},
        {"request_id": ""},
        {"request_id": "x" * 257},
        {"authorized_amount": 2**64},
        {"expires_at": 0},
    ],
)
def test_authorization_message_rejects_malformed_keys_and_request_ids(overrides: dict[str, Any]) -> None:
    args: dict[str, Any] = {
        "channel_id": PK9,
        "payer": PK1,
        "operator": PK2,
        "request_id": "req-1",
        "authorized_amount": 1,
        "expires_at": NOW,
    }
    args.update(overrides)
    with pytest.raises(ValueError):
        authorization_message(**args)


def test_authorization_binds_the_channel_the_operator_and_expiry() -> None:
    payer, operator = _signer(1), _signer(2)
    proof = sign_authorization(
        payer, channel_id=PK9, operator=operator.pubkey(), request_id="r", authorized_amount=10, expires_at=NOW + 60
    )
    assert verify_authorization(proof, operator.pubkey(), NOW)
    assert not verify_authorization(proof, PK3, NOW)  # another operator
    assert not verify_authorization({**proof, "channelId": PK3}, operator.pubkey(), NOW)
    assert not verify_authorization({**proof, "authorizedAmount": "11"}, operator.pubkey(), NOW)
    assert not verify_authorization(proof, operator.pubkey(), NOW + 60)  # now == expiresAt is expired
    assert not verify_authorization({**proof, "requestId": ""}, operator.pubkey(), NOW)


# -- close authorization -------------------------------------------------------


def _binding(**overrides: Any) -> dict[str, Any]:
    binding: dict[str, Any] = {
        "network": NETWORK,
        "fee_payer": PK3,
        "channel_id": PK9,
        "max_claimable_amount": 30000,
        "voucher_expires_at": 0,
        "valid_before": NOW + 300,
    }
    binding.update(overrides)
    return binding


def test_close_digest_matches_the_pr23_encoder_and_binds_every_field() -> None:
    base = close_authorization_digest(**_binding())
    assert base.hex() == "a7e8dcc824d2eb9adc80497e172f36400bbabd415100bfd8da0558ef21ce2ea5"
    for variant in (
        {"channel_id": PK1},
        {"fee_payer": PK1},
        {"max_claimable_amount": 30001},
        {"voucher_expires_at": 1},
        {"valid_before": NOW + 301},
        {"network": "solana:other"},
        {"program_id": PK2},
    ):
        assert close_authorization_digest(**_binding(**variant)) != base, variant
    for malformed in ({"channel_id": "short"}, {"valid_before": 0}, {"max_claimable_amount": -1}, {"network": ""}):
        with pytest.raises(ValueError):
            close_authorization_digest(**_binding(**malformed))


def test_close_authorization_verifies_within_the_validity_window_only() -> None:
    authorizer = _signer(4)
    signed = sign_close_authorization(authorizer, **_binding(valid_before=NOW + 120))
    fields = {k: v for k, v in _binding().items() if k != "valid_before"}

    def verify(auth: Any = signed, *, key: str = authorizer.pubkey(), window: int = 300, now: int = NOW, **kw: Any):
        return verify_close_authorization(
            auth, **{**fields, **kw}, receiver_authorizer=key, max_timeout_seconds=window, now=now
        )

    assert verify()
    assert not verify(key=_signer(5).pubkey())  # not the trusted receiver authorizer
    assert not verify(max_claimable_amount=29_999)  # a different final voucher
    assert not verify(now=NOW + 120)  # expired: now == validBefore
    assert not verify(window=60)  # validBefore further out than maxTimeoutSeconds
    assert not verify({**signed, "signature": "nope"})
    assert not verify(channel_id="short")


def test_pubkey_constants_are_the_expected_byte_patterns() -> None:
    # The frozen vectors above were produced from these exact keys.
    for text, byte in ((PK1, 1), (PK2, 2), (PK3, 3), (PK9, 9)):
        assert bytes(Pubkey.from_string(text)) == bytes([byte] * 32)
