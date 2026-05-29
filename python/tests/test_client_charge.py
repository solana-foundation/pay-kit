"""Tests for client-side charge transaction building."""

from __future__ import annotations

import base64

import pytest
from solders.keypair import Keypair
from solders.transaction import Transaction

from pay_kit._paycore.solana import MEMO_PROGRAM, MethodDetails, Split
from pay_kit.protocols.mpp.client.charge import build_charge_transaction

BLOCKHASH = "11111111111111111111111111111111"


def _memo_texts(transaction_b64: str) -> list[str]:
    tx = Transaction.from_bytes(base64.b64decode(transaction_b64))
    account_keys = tx.message.account_keys
    memos: list[str] = []
    for instruction in tx.message.instructions:
        if str(account_keys[instruction.program_id_index]) == MEMO_PROGRAM:
            memos.append(bytes(instruction.data).decode("utf-8"))
    return memos


async def test_build_charge_transaction_includes_external_id_and_split_memos():
    signer = Keypair()
    recipient = str(Keypair().pubkey())
    split_recipient = str(Keypair().pubkey())

    payload = await build_charge_transaction(
        signer=signer,
        rpc_client=None,
        amount="1000",
        currency="sol",
        recipient=recipient,
        external_id="order-123",
        method_details=MethodDetails(
            recent_blockhash=BLOCKHASH,
            splits=[Split(recipient=split_recipient, amount="200", memo="platform fee")],
        ),
    )

    assert payload.type == "transaction"
    assert _memo_texts(payload.transaction) == ["order-123", "platform fee"]


async def test_build_charge_transaction_rejects_long_external_id_memo():
    signer = Keypair()
    recipient = str(Keypair().pubkey())

    with pytest.raises(ValueError, match="memo cannot exceed 566 bytes"):
        await build_charge_transaction(
            signer=signer,
            rpc_client=None,
            amount="1000",
            currency="sol",
            recipient=recipient,
            external_id="x" * 567,
            method_details=MethodDetails(recent_blockhash=BLOCKHASH),
        )


async def test_build_charge_transaction_rejects_splits_that_exhaust_total():
    signer = Keypair()
    recipient = str(Keypair().pubkey())
    split_recipient = str(Keypair().pubkey())

    with pytest.raises(ValueError, match="splits consume the entire amount"):
        await build_charge_transaction(
            signer=signer,
            rpc_client=None,
            amount="1000",
            currency="sol",
            recipient=recipient,
            method_details=MethodDetails(
                recent_blockhash=BLOCKHASH,
                splits=[Split(recipient=split_recipient, amount="1000")],
            ),
        )
