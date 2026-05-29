"""Tests for client-side charge transaction building."""

from __future__ import annotations

import base64

import pytest
from solders.keypair import Keypair
from solders.transaction import Transaction

from pay_kit._paycore.mints import derive_ata, resolve, token_program_for
from pay_kit._paycore.solana import (
    ASSOCIATED_TOKEN_PROGRAM,
    MEMO_PROGRAM,
    MethodDetails,
    Split,
)
from pay_kit.protocols.mpp.client.charge import build_charge_transaction

BLOCKHASH = "11111111111111111111111111111111"


def _spl_transfers(transaction_b64: str, token_program: str) -> list[tuple[str, int, int]]:
    """Return (dest_ata, amount, decimals) for each TransferChecked (disc 12)."""
    tx = Transaction.from_bytes(base64.b64decode(transaction_b64))
    keys = tx.message.account_keys
    out: list[tuple[str, int, int]] = []
    for ix in tx.message.instructions:
        if str(keys[ix.program_id_index]) != token_program:
            continue
        data = bytes(ix.data)
        if not data or data[0] != 12:
            continue
        amount = int.from_bytes(data[1:9], "little")
        decimals = data[9]
        dest_ata = str(keys[ix.accounts[2]])
        out.append((dest_ata, amount, decimals))
    return out


def _has_create_ata(transaction_b64: str) -> bool:
    tx = Transaction.from_bytes(base64.b64decode(transaction_b64))
    keys = tx.message.account_keys
    return any(
        str(keys[ix.program_id_index]) == ASSOCIATED_TOKEN_PROGRAM and bytes(ix.data) == bytes([1])
        for ix in tx.message.instructions
    )


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


async def test_build_charge_transaction_spl_token_transfers_checked_to_atas():
    signer = Keypair()
    recipient = str(Keypair().pubkey())
    split_recipient = str(Keypair().pubkey())
    mint = resolve("USDC", "mainnet")
    assert mint is not None
    tp = token_program_for("USDC", "mainnet")

    payload = await build_charge_transaction(
        signer=signer,
        rpc_client=None,
        amount="1000",
        currency="USDC",
        recipient=recipient,
        external_id="order-9",
        method_details=MethodDetails(
            network="mainnet",
            decimals=6,
            recent_blockhash=BLOCKHASH,
            splits=[Split(recipient=split_recipient, amount="200", ata_creation_required=True)],
        ),
    )

    transfers = _spl_transfers(payload.transaction, tp)
    # Primary nets 800, split 200; each TransferChecked targets the recipient ATA.
    assert (derive_ata(recipient, mint, tp), 800, 6) in transfers
    assert (derive_ata(split_recipient, mint, tp), 200, 6) in transfers
    # The split flagged ata_creation_required, so an idempotent create-ATA is prepended.
    assert _has_create_ata(payload.transaction)
    # The root memo still rides along.
    assert "order-9" in _memo_texts(payload.transaction)


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
