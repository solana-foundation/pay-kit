"""``verify_exact_credential``: the x402 server's pre-broadcast checks (RULINGS S3/S4).

A credential is accepted only after its transaction is decoded and verified,
never on the envelope alone.
"""

from __future__ import annotations

import base64
import json
from typing import Any, cast

import pytest
from solana_keychain import MemorySigner
from solders.keypair import Keypair
from solders.transaction import VersionedTransaction

from solana_pay_kit._paycore.mints import derive_ata
from solana_pay_kit._paycore.solana import TOKEN_PROGRAM
from solana_pay_kit.errors import InvalidProofError
from solana_pay_kit.protocols.x402 import verify_exact_credential
from solana_pay_kit.protocols.x402.client.exact import build_payment_header, build_payment_header_legacy
from solana_pay_kit.protocols.x402.exact.types import X402AcceptsEntry

DEVNET = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"
MINT = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"
BH = "11111111111111111111111111111111"
PAYMENT_ID = "pay_abcdef1234567890abcdef1234567890"


class _MintAccount:
    def __init__(self) -> None:
        data = bytearray(82)
        data[44] = 6
        data[45] = 1
        self.owner = TOKEN_PROGRAM
        self.data = bytes(data)


class _MintResp:
    value = _MintAccount()


class _Rpc:
    async def get_account_info(self, _pubkey: Any) -> _MintResp:
        return _MintResp()


def _offer(fee_payer: str, pay_to: str, **extra: object) -> X402AcceptsEntry:
    return cast(
        "X402AcceptsEntry",
        {
            "scheme": "exact",
            "network": DEVNET,
            "amount": "1000",
            "asset": MINT,
            "payTo": pay_to,
            "maxTimeoutSeconds": 300,
            "extra": {"feePayer": fee_payer, "recentBlockhash": BH, **extra},
        },
    )


@pytest.fixture
def route() -> tuple[MemorySigner, X402AcceptsEntry]:
    fee_payer = MemorySigner(Keypair())
    return fee_payer, _offer(str(fee_payer.pubkey), str(Keypair().pubkey()))


async def _header(offer: X402AcceptsEntry, **kwargs: Any) -> str:
    return await build_payment_header(MemorySigner(Keypair()), _Rpc(), offer, **kwargs)


def _rewrite(header: str, mutate: Any) -> str:
    env = json.loads(base64.b64decode(header))
    mutate(env)
    return base64.b64encode(json.dumps(env).encode()).decode()


async def test_accepts_and_cosigns_a_real_credential(route):
    fee_payer, offer = route
    verified = await verify_exact_credential(await _header(offer), offer, fee_payer, require_payment_identifier=False)
    tx = VersionedTransaction.from_bytes(verified.cosigned_wire)
    assert str(tx.message.account_keys[0]) == str(fee_payer.pubkey)
    assert bytes(tx.signatures[0]) != bytes(64)


async def test_accepts_a_legacy_v1_credential(route):
    fee_payer, offer = route
    header = await build_payment_header_legacy(MemorySigner(Keypair()), _Rpc(), offer)
    verified = await verify_exact_credential(header, offer, fee_payer, require_payment_identifier=False)
    assert verified.version == 1


async def test_rejects_an_envelope_whose_transaction_is_not_a_payment(route):
    fee_payer, offer = route
    header = _rewrite(await _header(offer), lambda env: env["payload"].update(transaction="AA=="))
    with pytest.raises(InvalidProofError, match="transaction_parse"):
        await verify_exact_credential(header, offer, fee_payer, require_payment_identifier=False)


async def test_rejects_a_transfer_to_another_recipient(route):
    fee_payer, offer = route
    # Same envelope, but the transaction pays someone else.
    other = _offer(str(fee_payer.pubkey), str(Keypair().pubkey()))
    paid_other = json.loads(base64.b64decode(await _header(other)))["payload"]["transaction"]
    header = _rewrite(await _header(offer), lambda env: env["payload"].update(transaction=paid_other))
    with pytest.raises(InvalidProofError, match="recipient_mismatch"):
        await verify_exact_credential(header, offer, fee_payer, require_payment_identifier=False)
    assert derive_ata(offer["payTo"], MINT, TOKEN_PROGRAM) != derive_ata(other["payTo"], MINT, TOKEN_PROGRAM)


async def test_rejects_a_memo_that_does_not_match_extra_memo():
    fee_payer = MemorySigner(Keypair())
    pay_to = str(Keypair().pubkey())
    offer = _offer(str(fee_payer.pubkey), pay_to, memo="inv-1")
    header = await _header(_offer(str(fee_payer.pubkey), pay_to, memo="inv-2"))
    header = _rewrite(header, lambda env: env["accepted"]["extra"].update(memo="inv-1"))
    with pytest.raises(InvalidProofError, match="memo_mismatch"):
        await verify_exact_credential(header, offer, fee_payer, require_payment_identifier=False)


async def test_rejects_an_unknown_version(route):
    fee_payer, offer = route
    header = _rewrite(await _header(offer), lambda env: env.update(x402Version=3))
    with pytest.raises(InvalidProofError, match="unsupported_x402_version"):
        await verify_exact_credential(header, offer, fee_payer, require_payment_identifier=False)


async def test_required_payment_identifier_is_enforced(route):
    fee_payer, offer = route
    advertised = {"payment-identifier": {"info": {"required": True}}}
    without_id = _rewrite(
        await _header(offer, advertised_extensions=advertised, payment_identifier_id=PAYMENT_ID),
        lambda env: env["extensions"]["payment-identifier"]["info"].pop("id"),
    )
    with pytest.raises(InvalidProofError, match="payment-identifier required") as exc:
        await verify_exact_credential(without_id, offer, fee_payer, require_payment_identifier=True)
    assert exc.value.code == "payment_identifier_required"
    # Positive control: the same credential with its id is accepted.
    with_id = await _header(offer, advertised_extensions=advertised, payment_identifier_id=PAYMENT_ID)
    await verify_exact_credential(with_id, offer, fee_payer, require_payment_identifier=True)
