"""x402 ``upto`` pure-verifier + client-builder coverage (fully offline).

Covers the ordered payload checks, the settlement-ceiling assertion, the
14-account open-instruction validator, and the client builder - including a
client↔engine wire cross-check: the open transaction the client builds must pass
the engine's open-instruction validator with the matching expected pubkeys.
"""

from __future__ import annotations

import time

import pytest
from solders.keypair import Keypair  # type: ignore[import-untyped]
from solders.pubkey import Pubkey  # type: ignore[import-untyped]

from solana_pay_kit import LocalSigner
from solana_pay_kit._paycore.solana import TOKEN_PROGRAM
from solana_pay_kit.errors import InvalidProofError
from solana_pay_kit.protocols.x402.client.upto import (
    build_upto_header,
    build_upto_payload,
    encode_upto_header,
    parse_upto_challenge,
)
from solana_pay_kit.protocols.x402.upto import _decode_transaction
from solana_pay_kit.protocols.x402.upto.types import (
    UPTO_ASSET_TRANSFER_METHOD,
    UPTO_ERROR_SETTLEMENT_EXCEEDS_AMOUNT,
    UPTO_SCHEME,
    UptoPayload,
    UptoRequirements,
)
from solana_pay_kit.protocols.x402.upto.verify import (
    assert_settlement_within_ceiling,
    parse_base_units,
    validate_upto_open_instruction,
    verify_upto_payload,
)

BH = "4vJ9JU1bJJQpUgJ8V6hYz7xXKz4F2tN6aBrZEcD3xKhs"
MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"  # USDC mainnet
MAX = 100000


def _operator() -> tuple[LocalSigner, str]:
    signer = LocalSigner.from_keypair(Keypair())
    return signer, signer.pubkey()


def _requirements(operator: str, payee: str, *, amount: int = MAX) -> UptoRequirements:
    return {
        "scheme": UPTO_SCHEME,
        "network": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
        "amount": str(amount),
        "asset": MINT,
        "payTo": payee,
        "maxTimeoutSeconds": 300,
        "extra": {
            "assetTransferMethod": UPTO_ASSET_TRANSFER_METHOD,
            "decimals": 6,
            "tokenProgram": TOKEN_PROGRAM,
            "facilitatorAddress": operator,
            "recentBlockhash": BH,
        },
    }


def _payload(operator: str, *, channel_id: str = "11111111111111111111111111111112") -> UptoPayload:
    now = int(time.time())
    return {
        "from": str(Keypair().pubkey()),
        "maxAmount": str(MAX),
        "expiresAt": now + 300,
        "validAfter": now - 10,
        "nonce": "n1",
        "channelId": channel_id,
        "deposit": str(MAX),
        "authorizedSigner": operator,
    }


# -- parse_base_units -------------------------------------------------------


def test_parse_base_units_ok() -> None:
    assert parse_base_units("100000", "amount") == 100000


@pytest.mark.parametrize("bad", ["", "abc", "-1", "1.5", str(2**64)])
def test_parse_base_units_rejects(bad: str) -> None:
    with pytest.raises(InvalidProofError):
        parse_base_units(bad, "amount")


# -- verify_upto_payload ----------------------------------------------------


def test_verify_payload_happy() -> None:
    _, op = _operator()
    verify_upto_payload(_payload(op), _requirements(op, str(Keypair().pubkey())), op, int(time.time()))


def test_verify_payload_wrong_asset_transfer_method() -> None:
    _, op = _operator()
    req = _requirements(op, str(Keypair().pubkey()))
    req["extra"]["assetTransferMethod"] = "permit"
    with pytest.raises(InvalidProofError, match="assetTransferMethod"):
        verify_upto_payload(_payload(op), req, op, int(time.time()))


def test_verify_payload_amount_mismatch() -> None:
    _, op = _operator()
    p = _payload(op)
    p["maxAmount"] = "999"
    p["deposit"] = "999"
    with pytest.raises(InvalidProofError, match="amount mismatch"):
        verify_upto_payload(p, _requirements(op, str(Keypair().pubkey())), op, int(time.time()))


def test_verify_payload_deposit_not_equal_max() -> None:
    _, op = _operator()
    p = _payload(op)
    p["deposit"] = "50000"
    with pytest.raises(InvalidProofError, match="deposit"):
        verify_upto_payload(p, _requirements(op, str(Keypair().pubkey())), op, int(time.time()))


def test_verify_payload_not_yet_active() -> None:
    _, op = _operator()
    p = _payload(op)
    now = int(time.time())
    p["validAfter"] = now + 100
    with pytest.raises(InvalidProofError, match="not yet active"):
        verify_upto_payload(p, _requirements(op, str(Keypair().pubkey())), op, now)


def test_verify_payload_expired() -> None:
    _, op = _operator()
    p = _payload(op)
    now = int(time.time())
    p["expiresAt"] = now - 1
    with pytest.raises(InvalidProofError, match="expired"):
        verify_upto_payload(p, _requirements(op, str(Keypair().pubkey())), op, now)


def test_verify_payload_authorized_signer_not_operator() -> None:
    _, op = _operator()
    p = _payload(op)
    p["authorizedSigner"] = str(Keypair().pubkey())
    with pytest.raises(InvalidProofError, match="authorized_signer must be the operator"):
        verify_upto_payload(p, _requirements(op, str(Keypair().pubkey())), op, int(time.time()))


# -- assert_settlement_within_ceiling ---------------------------------------


def test_ceiling_ok() -> None:
    assert_settlement_within_ceiling(50000, 100000)
    assert_settlement_within_ceiling(100000, 100000)
    assert_settlement_within_ceiling(0, 100000)


def test_ceiling_exceeded() -> None:
    with pytest.raises(InvalidProofError) as exc:
        assert_settlement_within_ceiling(100001, 100000)
    assert exc.value.code == UPTO_ERROR_SETTLEMENT_EXCEEDS_AMOUNT


# -- client builder + wire cross-check --------------------------------------


def test_parse_upto_challenge_from_header() -> None:
    _, op = _operator()
    from solana_pay_kit.protocols.x402.upto import X402Upto  # noqa: PLC0415

    req = _requirements(op, str(Keypair().pubkey()))
    import base64
    import json

    envelope = {"x402Version": 2, "accepts": [req]}
    header = base64.b64encode(json.dumps(envelope).encode()).decode()
    parsed = parse_upto_challenge({"payment-required": header})
    assert parsed is not None and parsed["scheme"] == UPTO_SCHEME
    assert X402Upto  # imported for symmetry


def test_parse_upto_challenge_from_body() -> None:
    _, op = _operator()
    import json

    req = _requirements(op, str(Keypair().pubkey()))
    body = json.dumps({"accepts": [req]})
    parsed = parse_upto_challenge({}, body)
    assert parsed is not None and parsed["payTo"] == req["payTo"]


def test_parse_upto_challenge_none_when_absent() -> None:
    assert parse_upto_challenge({}) is None
    assert parse_upto_challenge({}, "{}") is None


def test_build_payload_requires_asset_transfer_method() -> None:
    _, op = _operator()
    client = LocalSigner.from_keypair(Keypair())
    req = _requirements(op, str(Keypair().pubkey()))
    req["extra"]["assetTransferMethod"] = "permit"
    with pytest.raises(ValueError, match="payment-channel asset transfer method"):
        build_upto_payload(client, req, int(time.time()) + 300)


def test_build_payload_requires_blockhash() -> None:
    _, op = _operator()
    client = LocalSigner.from_keypair(Keypair())
    req = _requirements(op, str(Keypair().pubkey()))
    del req["extra"]["recentBlockhash"]
    with pytest.raises(ValueError, match="recentBlockhash"):
        build_upto_payload(client, req, int(time.time()) + 300)


def test_client_open_tx_passes_engine_validator() -> None:
    """The open transaction the client builds must satisfy the engine's
    14-account open-instruction validator with the matching expected pubkeys -
    proving the client and server agree on the wire."""
    _, op = _operator()
    payee = str(Keypair().pubkey())
    client = LocalSigner.from_keypair(Keypair())
    req = _requirements(op, payee)
    payload = build_upto_payload(client, req, int(time.time()) + 300, nonce="n")

    open_tx = payload.get("openTransaction", "")
    account_keys, instructions = _decode_transaction(open_tx)
    # Fee payer slot 0 is the operator; the client signed only its own slot.
    assert account_keys[0] == op
    validate_upto_open_instruction(
        account_keys,
        instructions,
        program_id=_default_program(),
        operator=Pubkey.from_string(op),
        payer=Pubkey.from_string(client.pubkey()),
        payee=Pubkey.from_string(op),
        mint=Pubkey.from_string(MINT),
        token_program=Pubkey.from_string(TOKEN_PROGRAM),
        channel_id=Pubkey.from_string(payload["channelId"]),
    )

    # Encode/decode the header round-trips and carries the payment-channel payload.
    import base64
    import json

    header = encode_upto_header(req, payload)
    decoded = json.loads(base64.b64decode(header))
    assert decoded["accepted"]["scheme"] == UPTO_SCHEME
    assert "profile" not in decoded["payload"]
    assert decoded["payload"]["deposit"] == str(MAX)
    # build_upto_header is the one-shot equivalent of build + encode.
    assert build_upto_header(client, req, int(time.time()) + 300, nonce="n")


def test_client_open_tx_validator_rejects_wrong_payee() -> None:
    _, op = _operator()
    payee = str(Keypair().pubkey())
    client = LocalSigner.from_keypair(Keypair())
    req = _requirements(op, payee)
    payload = build_upto_payload(client, req, int(time.time()) + 300, nonce="n")
    account_keys, instructions = _decode_transaction(payload.get("openTransaction", ""))
    with pytest.raises(InvalidProofError, match="payee mismatch"):
        validate_upto_open_instruction(
            account_keys,
            instructions,
            program_id=_default_program(),
            operator=Pubkey.from_string(op),
            payer=Pubkey.from_string(client.pubkey()),
            payee=Pubkey.from_string(str(Keypair().pubkey())),  # wrong payee
            mint=Pubkey.from_string(MINT),
            token_program=Pubkey.from_string(TOKEN_PROGRAM),
            channel_id=Pubkey.from_string(payload["channelId"]),
        )


def _default_program() -> Pubkey:
    from solana_pay_kit._paycore.paymentchannels import PROGRAM_ID

    return PROGRAM_ID
