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

    # ataCreationRequired requires the charge currency to be a raw mint address
    # (rust charge.rs:113-128); pass the resolved mint rather than the symbol.
    payload = await build_charge_transaction(
        signer=signer,
        rpc_client=None,
        amount="1000",
        currency=mint,
        recipient=recipient,
        external_id="order-9",
        method_details=MethodDetails(
            network="mainnet",
            decimals=6,
            token_program=tp,
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


# -- rust-parity regressions -------------------------------------------------

COMPUTE_BUDGET_PROGRAM = "ComputeBudget111111111111111111111111111111"


def _instructions(transaction_b64: str) -> tuple[Transaction, list]:
    tx = Transaction.from_bytes(base64.b64decode(transaction_b64))
    return tx, list(tx.message.instructions)


async def test_build_charge_transaction_prepends_compute_budget_prelude():
    # Rust charge.rs:108-110 prepends SetComputeUnitPrice(1) (disc 3, u64 LE)
    # then SetComputeUnitLimit(200_000) (disc 2, u32 LE), both zero-account.
    signer = Keypair()
    recipient = str(Keypair().pubkey())
    payload = await build_charge_transaction(
        signer=signer,
        rpc_client=None,
        amount="1000",
        currency="sol",
        recipient=recipient,
        method_details=MethodDetails(recent_blockhash=BLOCKHASH),
    )
    tx, ixs = _instructions(payload.transaction)
    keys = tx.message.account_keys
    assert str(keys[ixs[0].program_id_index]) == COMPUTE_BUDGET_PROGRAM
    assert str(keys[ixs[1].program_id_index]) == COMPUTE_BUDGET_PROGRAM
    price_data = bytes(ixs[0].data)
    assert price_data[0] == 3
    assert int.from_bytes(price_data[1:9], "little") == 1
    limit_data = bytes(ixs[1].data)
    assert limit_data[0] == 2
    assert int.from_bytes(limit_data[1:5], "little") == 200_000
    assert len(ixs[0].accounts) == 0
    assert len(ixs[1].accounts) == 0


async def test_build_charge_transaction_sponsored_fee_payer_is_message_slot_zero():
    # Rust charge.rs:96-104,162-163: when feePayer+feePayerKey are set, the
    # server fee payer is the message fee payer (account[0]) and the client
    # signs only its own slot, leaving the fee-payer slot for the server cosign.
    signer = Keypair()
    fee_payer = str(Keypair().pubkey())
    recipient = str(Keypair().pubkey())
    payload = await build_charge_transaction(
        signer=signer,
        rpc_client=None,
        amount="1000",
        currency="sol",
        recipient=recipient,
        method_details=MethodDetails(
            recent_blockhash=BLOCKHASH,
            fee_payer=True,
            fee_payer_key=fee_payer,
        ),
    )
    tx = Transaction.from_bytes(base64.b64decode(payload.transaction))
    keys = [str(k) for k in tx.message.account_keys]
    assert keys[0] == fee_payer
    # Two required signers (fee payer slot + client); the client slot is signed,
    # the fee-payer slot (account[0]) is left blank for the server cosign.
    header = tx.message.header
    assert int(header.num_required_signatures) == 2
    sigs = list(tx.signatures)
    fee_payer_index = keys.index(fee_payer)
    client_index = keys.index(str(signer.pubkey()))
    assert sigs[fee_payer_index] == sigs[fee_payer_index].default()
    assert sigs[client_index] != sigs[client_index].default()


async def test_build_charge_transaction_unsponsored_signs_signer_at_slot_zero():
    # No feePayer toggle: the client signer is the message fee payer (slot 0).
    signer = Keypair()
    recipient = str(Keypair().pubkey())
    payload = await build_charge_transaction(
        signer=signer,
        rpc_client=None,
        amount="1000",
        currency="sol",
        recipient=recipient,
        method_details=MethodDetails(recent_blockhash=BLOCKHASH),
    )
    tx = Transaction.from_bytes(base64.b64decode(payload.transaction))
    keys = [str(k) for k in tx.message.account_keys]
    assert keys[0] == str(signer.pubkey())
    assert int(tx.message.header.num_required_signatures) == 1


async def test_build_charge_transaction_rejects_more_than_eight_splits():
    # Rust charge.rs:76-78 rejects > 8 splits with TooManySplits.
    signer = Keypair()
    recipient = str(Keypair().pubkey())
    splits = [Split(recipient=str(Keypair().pubkey()), amount="1") for _ in range(9)]
    with pytest.raises(ValueError, match="too many splits"):
        await build_charge_transaction(
            signer=signer,
            rpc_client=None,
            amount="1000",
            currency="sol",
            recipient=recipient,
            method_details=MethodDetails(recent_blockhash=BLOCKHASH, splits=splits),
        )


async def test_build_charge_transaction_rejects_unsupported_token_program():
    # Rust resolve_token_program (charge.rs:457-463) rejects any token program
    # outside the {TOKEN, TOKEN_2022} allowlist.
    signer = Keypair()
    recipient = str(Keypair().pubkey())
    mint = resolve("USDC", "mainnet")
    assert mint is not None
    with pytest.raises(ValueError, match="Unsupported token program"):
        await build_charge_transaction(
            signer=signer,
            rpc_client=None,
            amount="1000",
            currency=mint,
            recipient=recipient,
            method_details=MethodDetails(
                network="mainnet",
                decimals=6,
                token_program=str(Keypair().pubkey()),
                recent_blockhash=BLOCKHASH,
            ),
        )


async def test_build_charge_transaction_resolves_token_program_via_rpc_owner():
    # Rust resolve_token_program fetches the mint account owner via RPC when
    # methodDetails.tokenProgram is absent (charge.rs:450-454). An unknown mint
    # owned by Token-2022 must build with the Token-2022 program.
    from pay_kit._paycore.solana import TOKEN_2022_PROGRAM

    class _Owner:
        owner = TOKEN_2022_PROGRAM

    class _Resp:
        value = _Owner()

    class _Rpc:
        async def get_account(self, _pubkey):
            return _Resp()

    signer = Keypair()
    recipient = str(Keypair().pubkey())
    unknown_mint = str(Keypair().pubkey())
    payload = await build_charge_transaction(
        signer=signer,
        rpc_client=_Rpc(),
        amount="1000",
        currency=unknown_mint,
        recipient=recipient,
        method_details=MethodDetails(network="mainnet", decimals=6, recent_blockhash=BLOCKHASH),
    )
    tx, ixs = _instructions(payload.transaction)
    keys = tx.message.account_keys
    transfer_ix = next(ix for ix in ixs if bytes(ix.data)[:1] == bytes([12]))
    assert str(keys[transfer_ix.program_id_index]) == TOKEN_2022_PROGRAM
