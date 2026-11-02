"""MPP charge transaction versions (mpp-specs-txv1) and the challenge-shape rules.

Covers ``methodDetails.transactionVersions`` parsing, the client's version
negotiation and version-1 build, the server's version admission and
version-1 budget rules, and the client / server challenge checks that the
conformance vectors pin (``charge-build-*-reject``, ``charge-verify-*``).
"""

from __future__ import annotations

import base64
from typing import Any

import pytest
from solana_keychain import MemorySigner
from solders.hash import Hash
from solders.instruction import Instruction
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.signature import Signature

from solana_pay_kit._paycore.errors import InvalidChallengeError, PaymentError
from solana_pay_kit._paycore.solana import COMPUTE_BUDGET_PROGRAM, MethodDetails, Split
from solana_pay_kit._paycore.txv1 import (
    MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES,
    MessageV1,
    TransactionConfig,
    TransactionV1,
    TransactionVersionError,
    decode_transaction,
    signed_message_bytes,
)
from solana_pay_kit.protocols.mpp.client.charge import build_charge_transaction
from solana_pay_kit.protocols.mpp.intents.charge import ChargeRequest
from solana_pay_kit.protocols.mpp.server._verify import (
    _co_sign_with_fee_payer,
    _verify_local_transaction_intent,
)

BLOCKHASH = "11111111111111111111111111111111"
MINT = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"
TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"


def _details(**overrides: Any) -> MethodDetails:
    values: dict[str, Any] = {
        "network": "localnet",
        "decimals": 6,
        "token_program": TOKEN_PROGRAM,
        "recent_blockhash": BLOCKHASH,
    }
    values.update(overrides)
    return MethodDetails(**values)


async def _build(
    signer: MemorySigner,
    recipient: str,
    details: MethodDetails,
    *,
    currency: str = MINT,
    amount: str = "1000",
    max_transaction_version: int | None = None,
) -> str:
    payload = await build_charge_transaction(
        signer=signer,
        rpc_client=None,
        amount=amount,
        currency=currency,
        recipient=recipient,
        method_details=details,
        max_transaction_version=max_transaction_version,
    )
    return payload.transaction


def _request(recipient: str, details: MethodDetails, currency: str = MINT) -> ChargeRequest:
    return ChargeRequest(amount="1000", currency=currency, recipient=recipient, method_details=details.to_dict())


# --- methodDetails.transactionVersions ------------------------------------


def test_transaction_versions_round_trip_and_default_to_absent():
    details = MethodDetails.from_dict({"network": "devnet", "transactionVersions": [0, 1]})
    assert details.transaction_versions == [0, 1]
    assert details.to_dict()["transactionVersions"] == [0, 1]
    absent = MethodDetails.from_dict({"network": "devnet"})
    assert absent.transaction_versions is None
    assert "transactionVersions" not in absent.to_dict()
    # Present and empty is not absent: it survives the round trip.
    assert MethodDetails.from_dict({"transactionVersions": []}).to_dict()["transactionVersions"] == []


@pytest.mark.parametrize("value", [["legacy"], [0, 2], ["1"], 1, [True]])
def test_transaction_versions_refuse_entries_that_are_not_versions(value: Any):
    with pytest.raises(TransactionVersionError):
        MethodDetails.from_dict({"transactionVersions": value})


# --- client: negotiation and the version-1 build ---------------------------


async def test_client_builds_version_1_with_the_budget_in_the_header():
    signer = MemorySigner(Keypair())
    recipient = str(Keypair().pubkey())
    tx = decode_transaction(base64.b64decode(await _build(signer, recipient, _details(transaction_versions=[0, 1]))))

    assert isinstance(tx, TransactionV1)
    keys = tx.message.account_keys
    programs = {str(keys[ix.program_id_index]) for ix in tx.message.instructions}
    assert COMPUTE_BUDGET_PROGRAM not in programs
    assert tx.message.config == TransactionConfig(
        priority_fee=1,
        compute_unit_limit=200_000,
        loaded_accounts_data_size_limit=MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES,
    )
    assert tx.signatures[0].verify(signer.pubkey, signed_message_bytes(tx.message))


async def test_client_builds_version_0_when_only_0_is_advertised_or_nothing_is():
    signer = MemorySigner(Keypair())
    recipient = str(Keypair().pubkey())
    for versions in ([0], None):
        raw = base64.b64decode(await _build(signer, recipient, _details(transaction_versions=versions)))
        assert not isinstance(decode_transaction(raw), TransactionV1)


async def test_client_builds_the_highest_version_its_signer_signs():
    signer = MemorySigner(Keypair())
    recipient = str(Keypair().pubkey())
    raw = await _build(signer, recipient, _details(transaction_versions=[0, 1]), max_transaction_version=0)
    assert not isinstance(decode_transaction(base64.b64decode(raw)), TransactionV1)

    with pytest.raises(TransactionVersionError, match="signs up to version 0"):
        await _build(signer, recipient, _details(transaction_versions=[1]), max_transaction_version=0)
    with pytest.raises(TransactionVersionError, match="advertises no transaction version"):
        await _build(signer, recipient, _details(transaction_versions=[]))


async def test_client_version_1_carries_memos_past_the_version_0_size_limit():
    signer = MemorySigner(Keypair())
    recipient = str(Keypair().pubkey())
    splits = [Split(recipient=str(Keypair().pubkey()), amount="1", memo="m" * 500) for _ in range(3)]
    details = _details(transaction_versions=[0, 1], splits=splits)

    raw = base64.b64decode(await _build(signer, recipient, details))
    assert isinstance(decode_transaction(raw), TransactionV1)
    assert len(raw) > 1232

    with pytest.raises(TransactionVersionError, match="1232-byte limit"):
        await _build(signer, recipient, _details(splits=splits))


# --- client: challenge-shape rules -----------------------------------------


@pytest.mark.parametrize(
    ("currency", "details", "amount", "match"),
    [
        ("sol", _details(decimals=None), "1000", "tokenProgram MUST NOT be present"),
        (MINT, _details(fee_payer=True), "1000", "names no feePayerKey"),
        (MINT, _details(network="testnet"), "1000", "unsupported challenge network"),
        (MINT, _details(), str(1 << 64), "does not fit in a u64"),
        (MINT, _details(), "-1", "invalid amount"),
    ],
)
async def test_client_refuses_out_of_spec_challenges(currency: str, details: MethodDetails, amount: str, match: str):
    with pytest.raises(InvalidChallengeError, match=match):
        await _build(MemorySigner(Keypair()), str(Keypair().pubkey()), details, currency=currency, amount=amount)


# --- server: version admission and version-1 rules -------------------------


async def test_server_accepts_only_the_versions_it_advertised():
    signer = MemorySigner(Keypair())
    recipient = str(Keypair().pubkey())
    both = _details(transaction_versions=[0, 1])
    v1 = await _build(signer, recipient, both)
    _verify_local_transaction_intent(v1, _request(recipient, both), both)

    for advertised in (None, [0]):
        details = _details(transaction_versions=advertised)
        with pytest.raises(PaymentError, match="transaction version 1 is not accepted"):
            _verify_local_transaction_intent(v1, _request(recipient, details), details)

    v0 = await _build(signer, recipient, _details())
    only_v1 = _details(transaction_versions=[1])
    with pytest.raises(PaymentError, match="transaction version 0 is not accepted"):
        _verify_local_transaction_intent(v0, _request(recipient, only_v1), only_v1)


async def test_server_refuses_a_legacy_message():
    from solders.message import Message
    from solders.transaction import VersionedTransaction

    payer = Keypair()
    message = Message.new_with_blockhash(
        [Instruction(Pubkey.from_string("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"), b"x", [])],
        payer.pubkey(),
        Hash.from_string(BLOCKHASH),
    )
    legacy = VersionedTransaction(message, [payer])
    details = _details(transaction_versions=[0, 1])
    with pytest.raises(PaymentError, match="legacy transaction version is not accepted"):
        _verify_local_transaction_intent(
            base64.b64encode(bytes(legacy)).decode(), _request(str(Keypair().pubkey()), details), details
        )


def _v1_wire(payer: Keypair, instructions: list[Instruction], config: TransactionConfig) -> str:
    message = MessageV1.try_compile(payer.pubkey(), instructions, Hash.from_string(BLOCKHASH), config)
    signature = payer.sign_message(bytes(message))
    return base64.b64encode(bytes(TransactionV1.populate(message, [signature]))).decode()


@pytest.mark.parametrize(
    ("config", "extra_compute_budget", "match"),
    [
        (
            TransactionConfig(priority_fee=1, loaded_accounts_data_size_limit=1 << 26),
            False,
            "must set computeUnitLimit",
        ),
        (TransactionConfig(priority_fee=1, compute_unit_limit=200_000), False, "loaded accounts data size limit"),
        (
            TransactionConfig(priority_fee=1, compute_unit_limit=200_000, loaded_accounts_data_size_limit=1 << 26),
            True,
            "must not contain ComputeBudget instructions",
        ),
        (
            TransactionConfig(priority_fee=10**9, compute_unit_limit=200_000, loaded_accounts_data_size_limit=1 << 26),
            False,
            "compute unit price .* exceeds maximum",
        ),
    ],
)
def test_server_holds_the_version_1_header_budget_to_the_caps(
    config: TransactionConfig, extra_compute_budget: bool, match: str
):
    payer = Keypair()
    instructions = [Instruction(Pubkey.from_string("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"), b"x", [])]
    if extra_compute_budget:
        unit_limit = bytes([2]) + (200_000).to_bytes(4, "little")
        instructions.insert(0, Instruction(Pubkey.from_string(COMPUTE_BUDGET_PROGRAM), unit_limit, []))
    details = _details(transaction_versions=[0, 1])
    with pytest.raises(PaymentError, match=match):
        _verify_local_transaction_intent(
            _v1_wire(payer, instructions, config), _request(str(Keypair().pubkey()), details), details
        )


async def test_server_refuses_a_sponsored_transaction_whose_fee_payer_is_not_fee_payer_key():
    signer = MemorySigner(Keypair())
    recipient = str(Keypair().pubkey())
    client_paid = await _build(signer, recipient, _details())
    sponsored = _details(fee_payer=True, fee_payer_key=str(Keypair().pubkey()))
    with pytest.raises(PaymentError, match="transaction fee payer must be"):
        _verify_local_transaction_intent(client_paid, _request(recipient, sponsored), sponsored)


async def test_server_refuses_ata_creation_on_a_sol_charge():
    signer = MemorySigner(Keypair())
    recipient = str(Keypair().pubkey())
    sol = _details(decimals=None, token_program=None)
    wire = await _build(signer, recipient, sol, currency="sol")
    flagged = _details(
        decimals=None,
        token_program=None,
        splits=[Split(recipient=str(Keypair().pubkey()), amount="100", ata_creation_required=True)],
    )
    with pytest.raises(PaymentError, match="ataCreationRequired requires an SPL token charge"):
        _verify_local_transaction_intent(wire, _request(recipient, flagged, currency="sol"), flagged)


async def test_server_co_signs_a_version_1_transaction_in_the_fee_payer_slot():
    client = MemorySigner(Keypair())
    sponsor = MemorySigner(Keypair())
    recipient = str(Keypair().pubkey())
    details = _details(transaction_versions=[0, 1], fee_payer=True, fee_payer_key=str(sponsor.pubkey))
    wire = await _build(client, recipient, details)
    assert decode_transaction(base64.b64decode(wire)).signatures[0] == Signature.default()

    cosigned = decode_transaction(base64.b64decode(await _co_sign_with_fee_payer(wire, sponsor)))
    message_bytes = signed_message_bytes(cosigned.message)
    assert cosigned.signatures[0].verify(sponsor.pubkey, message_bytes)
    assert cosigned.signatures[1].verify(client.pubkey, message_bytes)
