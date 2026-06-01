"""Edge-case coverage for pay_kit.protocols.mpp.client.charge."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest
from solders.hash import Hash
from solders.keypair import Keypair

from pay_kit._paycore.solana import MethodDetails, Split
from pay_kit.protocols.mpp.client.charge import (
    build_charge_transaction,
    build_credential_header,
)
from pay_kit.protocols.mpp.core.base64url import encode_json
from pay_kit.protocols.mpp.core.headers import parse_authorization
from pay_kit.protocols.mpp.core.types import PaymentChallenge

BLOCKHASH = "11111111111111111111111111111111"


@dataclass
class _BlockhashValue:
    blockhash: Any


@dataclass
class _Resp:
    value: Any


class _FakeRpcClient:
    """Minimal async RPC that returns a fixed blockhash via get_latest_blockhash."""

    def __init__(self) -> None:
        self.calls = 0

    async def get_latest_blockhash(self):
        self.calls += 1
        return _Resp(_BlockhashValue(Hash.default()))


async def test_build_charge_transaction_fetches_blockhash_when_unset():
    signer = Keypair()
    recipient = str(Keypair().pubkey())
    rpc = _FakeRpcClient()
    payload = await build_charge_transaction(
        signer=signer,
        rpc_client=rpc,
        amount="100",
        currency="sol",
        recipient=recipient,
        external_id="",
        method_details=MethodDetails(),
    )
    assert rpc.calls == 1
    assert payload.type == "transaction"


async def test_build_charge_transaction_spl_raw_mint_builds_transfer_checked():
    # currency given as a raw mint address (not a known symbol): resolve_mint
    # passes it through and the client builds an SPL TransferChecked to the
    # recipient ATA. Guards against regressing the SPL client path back to a stub.
    import base64

    from solders.transaction import Transaction

    signer = Keypair()
    recipient = str(Keypair().pubkey())
    payload = await build_charge_transaction(
        signer=signer,
        rpc_client=None,
        amount="100",
        currency="EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
        recipient=recipient,
        external_id="",
        method_details=MethodDetails(recent_blockhash=BLOCKHASH, decimals=6),
    )

    tx = Transaction.from_bytes(base64.b64decode(payload.transaction))
    transfer_checked = [bytes(ix.data) for ix in tx.message.instructions if bytes(ix.data)[:1] == b"\x0c"]
    assert len(transfer_checked) == 1
    data = transfer_checked[0]
    assert int.from_bytes(data[1:9], "little") == 100  # amount
    assert data[9] == 6  # decimals


async def test_build_charge_transaction_splits_consume_entire_amount_raises():
    signer = Keypair()
    recipient = str(Keypair().pubkey())
    split_recipient = str(Keypair().pubkey())
    with pytest.raises(ValueError):
        await build_charge_transaction(
            signer=signer,
            rpc_client=None,
            amount="100",
            currency="sol",
            recipient=recipient,
            method_details=MethodDetails(
                recent_blockhash=BLOCKHASH,
                splits=[Split(recipient=split_recipient, amount="100")],
            ),
        )


async def test_build_charge_transaction_rejects_long_split_memo():
    signer = Keypair()
    recipient = str(Keypair().pubkey())
    split_recipient = str(Keypair().pubkey())
    long_memo = "x" * 600
    with pytest.raises(ValueError):
        await build_charge_transaction(
            signer=signer,
            rpc_client=None,
            amount="1000",
            currency="sol",
            recipient=recipient,
            method_details=MethodDetails(
                recent_blockhash=BLOCKHASH,
                splits=[Split(recipient=split_recipient, amount="100", memo=long_memo)],
            ),
        )


async def test_build_credential_header_wraps_charge_transaction():
    signer = Keypair()
    recipient = str(Keypair().pubkey())
    request = encode_json(
        {
            "amount": "100",
            "currency": "sol",
            "recipient": recipient,
            "methodDetails": {"recentBlockhash": BLOCKHASH},
        }
    )
    challenge = PaymentChallenge(id="c1", realm="api", method="solana", intent="charge", request=request)
    header = await build_credential_header(
        challenge=challenge,
        signer=signer,
        rpc_client=None,
    )
    assert header.startswith("Payment ")
    # Round-trip the Authorization header to confirm structure.
    cred = parse_authorization(header)
    assert cred.challenge.id == "c1"
    assert cred.payload["type"] == "transaction"


async def test_build_credential_header_without_method_details():
    signer = Keypair()
    recipient = str(Keypair().pubkey())
    request = encode_json({"amount": "100", "currency": "sol", "recipient": recipient})
    challenge = PaymentChallenge(id="c1", realm="api", method="solana", intent="charge", request=request)
    rpc = _FakeRpcClient()
    header = await build_credential_header(
        challenge=challenge,
        signer=signer,
        rpc_client=rpc,
    )
    assert "Payment " in header
    assert rpc.calls == 1
