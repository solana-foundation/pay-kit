"""Version-1 transaction codec and shared version policy (``_paycore.txv1``)."""

from __future__ import annotations

import pytest
from solders.hash import Hash  # type: ignore[import-untyped]
from solders.instruction import AccountMeta, Instruction  # type: ignore[import-untyped]
from solders.keypair import Keypair  # type: ignore[import-untyped]
from solders.message import MessageV0  # type: ignore[import-untyped]
from solders.pubkey import Pubkey  # type: ignore[import-untyped]
from solders.signature import Signature  # type: ignore[import-untyped]
from solders.transaction import VersionedTransaction  # type: ignore[import-untyped]

from solana_pay_kit._paycore import txv1
from solana_pay_kit._paycore.transaction import (
    SignatureCheckError,
    build_partially_signed_transaction,
    verify_required_signatures,
)
from solana_pay_kit._paycore.txv1 import (
    COMPUTE_BUDGET_PROGRAM,
    MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES,
    MessageV1,
    TransactionConfig,
    TransactionV1,
    TransactionVersionError,
)

BLOCKHASH = Hash.from_string("4vJ9JU1bJJQpUgJ8V6hYz7xXKz4F2tN6aBrZEcD3xKhs")
MAX_CONFIG = TransactionConfig(
    priority_fee=2_000, compute_unit_limit=200_000, loaded_accounts_data_size_limit=MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES
)


def _transfer(payer: Pubkey, data: bytes = b"\x02\x00\x00\x00" + bytes(8)) -> Instruction:
    program = Pubkey.from_string("11111111111111111111111111111111")
    return Instruction(program, data, [AccountMeta(payer, True, True), AccountMeta(Pubkey.new_unique(), False, True)])


def _message(payer: Pubkey, config: TransactionConfig = MAX_CONFIG, instructions=None) -> MessageV1:
    return MessageV1.try_compile(payer, instructions or [_transfer(payer)], BLOCKHASH, config)


def _signed(config: TransactionConfig = MAX_CONFIG) -> tuple[TransactionV1, Keypair]:
    kp = Keypair()
    message = _message(kp.pubkey(), config)
    return TransactionV1.populate(message, [kp.sign_message(bytes(message))]), kp


def test_round_trip_every_config_field() -> None:
    config = TransactionConfig(
        priority_fee=7, compute_unit_limit=9, loaded_accounts_data_size_limit=11, heap_size=32768
    )
    tx, _ = _signed(config)
    raw = bytes(tx)
    assert raw[0] == txv1.V1_PREFIX
    decoded = txv1.decode_transaction(raw)
    assert isinstance(decoded, TransactionV1)
    assert decoded.message.config == config
    assert bytes(decoded) == raw
    assert txv1.is_v1(decoded) and txv1.message_version(decoded.message) == 1
    assert MessageV1.from_bytes(bytes(decoded.message)) == decoded.message


def test_decode_refuses_malformed_wires() -> None:
    tx, _ = _signed()
    raw = bytes(tx)
    with pytest.raises(TransactionVersionError, match="signature section"):
        txv1.decode_transaction(raw[:-1])
    with pytest.raises(TransactionVersionError, match="truncated"):
        txv1.decode_transaction(raw[:20])
    with pytest.raises(TransactionVersionError, match="unsupported transaction version prefix"):
        txv1.decode_transaction(bytes([0x82]) + raw[1:])
    bad_mask = bytearray(raw)
    bad_mask[4] = 0b01  # half a priority-fee bit pair
    with pytest.raises(TransactionVersionError, match="config mask"):
        txv1.decode_transaction(bytes(bad_mask))
    with pytest.raises(TransactionVersionError, match="trailing"):
        MessageV1.from_bytes(bytes(tx.message) + b"\x00")
    with pytest.raises(TransactionVersionError, match="not a version-1"):
        MessageV1.from_bytes(b"\x80" + bytes(tx.message)[1:])


def test_legacy_and_v0_still_decode_through_solders() -> None:
    kp = Keypair()
    message = MessageV0.try_compile(kp.pubkey(), [_transfer(kp.pubkey())], [], BLOCKHASH)
    tx = VersionedTransaction(message, [kp])
    decoded = txv1.decode_transaction(bytes(tx))
    assert isinstance(decoded, VersionedTransaction)
    assert txv1.message_version(decoded.message) == 0
    assert txv1.policy_version(decoded.message) == 0
    assert txv1.signed_message_bytes(decoded.message)
    assert isinstance(txv1.populate(message, [Signature.default()]), VersionedTransaction)


def test_signatures_cover_the_prefixed_message() -> None:
    tx, kp = _signed()
    verify_required_signatures(tx)
    forged = TransactionV1.populate(tx.message, [Keypair().sign_message(bytes(tx.message))])
    with pytest.raises(SignatureCheckError):
        verify_required_signatures(forged)
    unsigned = txv1.populate(tx.message, [Signature.default()])
    verify_required_signatures(unsigned, unsigned=kp.pubkey())


@pytest.mark.asyncio
async def test_builder_signs_version_one_over_the_message() -> None:
    from solana_keychain import MemorySigner

    kp = Keypair()
    raw = await build_partially_signed_transaction(
        [_transfer(kp.pubkey())], kp.pubkey(), BLOCKHASH, MemorySigner(kp), version=1, config=MAX_CONFIG
    )
    tx = txv1.decode_transaction(raw)
    assert isinstance(tx, TransactionV1)
    verify_required_signatures(tx)
    v0 = await build_partially_signed_transaction([_transfer(kp.pubkey())], kp.pubkey(), BLOCKHASH, MemorySigner(kp))
    assert isinstance(txv1.decode_transaction(v0), VersionedTransaction)
    with pytest.raises(ValueError, match="cannot build"):
        await build_partially_signed_transaction([], kp.pubkey(), BLOCKHASH, MemorySigner(kp), version=2)
    with pytest.raises(ValueError, match="not a required signer"):
        await build_partially_signed_transaction(
            [_transfer(kp.pubkey())], kp.pubkey(), BLOCKHASH, MemorySigner(Keypair()), version=1
        )


def test_advertisement_parsing_and_negotiation() -> None:
    assert txv1.parse_transaction_versions(None) is None
    assert txv1.parse_transaction_versions([1, 0]) == [1, 0]
    for bad in ("x", ["legacy"], [True], [2], ["0"]):
        with pytest.raises(TransactionVersionError):
            txv1.parse_transaction_versions(bad)
    assert txv1.accepted_versions(None) == (0,)
    assert txv1.accepted_versions([]) == ()
    assert txv1.negotiate(None) == 0
    assert txv1.negotiate([0, 1]) == 1
    assert txv1.negotiate([0, 1], max_signable=0) == 0
    with pytest.raises(TransactionVersionError, match="advertises no transaction version"):
        txv1.negotiate([])
    with pytest.raises(TransactionVersionError, match="signs up to version 0"):
        txv1.negotiate([1], max_signable=0)


def test_envelope_admission() -> None:
    tx, _ = _signed()
    assert txv1.check_envelope(tx, (0, 1)) == 1
    with pytest.raises(TransactionVersionError, match="version 1 is not accepted"):
        txv1.check_envelope(tx, (0,))
    kp = Keypair()
    from solders.message import Message  # type: ignore[import-untyped]

    legacy_tx = VersionedTransaction(Message.new_with_blockhash([_transfer(kp.pubkey())], kp.pubkey(), BLOCKHASH), [kp])
    assert txv1.check_envelope(legacy_tx, (0,)) == 0
    with pytest.raises(TransactionVersionError, match="legacy transaction version"):
        txv1.check_envelope(legacy_tx, (0,), allow_legacy=False)
    big = _message(kp.pubkey(), instructions=[_transfer(kp.pubkey(), bytes(1300))])
    with pytest.raises(TransactionVersionError, match="over the 1232-byte limit"):
        txv1.check_limits(
            VersionedTransaction(
                MessageV0.try_compile(kp.pubkey(), [_transfer(kp.pubkey(), bytes(1300))], [], BLOCKHASH), [kp]
            ),
            0,
        )
    assert txv1.check_limits(TransactionV1.populate(big, [Signature.default()]), 1) > 1232
    noop = Instruction(Pubkey.from_string("11111111111111111111111111111111"), b"", [])
    too_many = _message(kp.pubkey(), instructions=[noop] * 65)
    with pytest.raises(TransactionVersionError, match="instructions"):
        txv1.check_limits(TransactionV1.populate(too_many, [Signature.default()]), 1)


def test_v1_budget_caps_and_priority_fee() -> None:
    kp = Keypair()
    message = _message(kp.pubkey())
    declared = txv1.check_v1_budget_caps(message, 200_000, 10_000)
    assert declared is not None and declared.unit_limit == 200_000
    assert (
        txv1.check_v1_budget_caps(MessageV0.try_compile(kp.pubkey(), [_transfer(kp.pubkey())], [], BLOCKHASH), 1, 1)
        is None
    )
    assert txv1.priority_fee_of(message) == 2_000
    assert txv1.check_priority_fee(message, 2_000) == 2_000
    with pytest.raises(TransactionVersionError, match="sponsored maximum"):
        txv1.check_priority_fee(message, 1_999)
    cases = [
        (
            TransactionConfig(
                compute_unit_limit=0, loaded_accounts_data_size_limit=MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES
            ),
            "positive",
        ),
        (
            TransactionConfig(
                compute_unit_limit=300_000, loaded_accounts_data_size_limit=MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES
            ),
            "exceeds maximum",
        ),
        (
            TransactionConfig(
                priority_fee=10**9,
                compute_unit_limit=1,
                loaded_accounts_data_size_limit=MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES,
            ),
            "price",
        ),
        (TransactionConfig(compute_unit_limit=1), "loaded accounts data size limit must be"),
        (TransactionConfig(loaded_accounts_data_size_limit=1), "must set computeUnitLimit"),
    ]
    for config, needle in cases:
        with pytest.raises(TransactionVersionError, match=needle):
            txv1.check_v1_budget_caps(_message(kp.pubkey(), config), 200_000, 10_000)
    small = _message(kp.pubkey(), TransactionConfig(compute_unit_limit=1, loaded_accounts_data_size_limit=1024))
    assert txv1.check_v1_budget_caps(small, 200_000, 10_000, loaded_rule="present") is not None
    with pytest.raises(TransactionVersionError, match="present, nonzero"):
        txv1.check_v1_budget_caps(
            _message(kp.pubkey(), TransactionConfig(compute_unit_limit=1)), 1, 1, loaded_rule="present"
        )
    with pytest.raises(TransactionVersionError, match="heap size"):
        txv1.reject_v1_heap_request(_message(kp.pubkey(), TransactionConfig(heap_size=65536)))
    budget_ix = Instruction(COMPUTE_BUDGET_PROGRAM, bytes([2]) + (1).to_bytes(4, "little"), [])
    with pytest.raises(TransactionVersionError, match="must not contain ComputeBudget"):
        txv1.declared_budget(_message(kp.pubkey(), instructions=[budget_ix, _transfer(kp.pubkey())]))
    assert txv1.v1_config(200_000, 10_000) == MAX_CONFIG


def test_v0_declared_budget() -> None:
    kp = Keypair()
    limit = Instruction(COMPUTE_BUDGET_PROGRAM, bytes([2]) + (100).to_bytes(4, "little"), [])
    price = Instruction(COMPUTE_BUDGET_PROGRAM, bytes([3]) + (10_000).to_bytes(8, "little"), [])
    loaded = Instruction(COMPUTE_BUDGET_PROGRAM, bytes([4]) + (5).to_bytes(4, "little"), [])

    def v0(*ixs):
        return MessageV0.try_compile(kp.pubkey(), [*ixs, _transfer(kp.pubkey())], [], BLOCKHASH)

    declared = txv1.declared_budget(v0(limit, price, loaded))
    assert (declared.unit_limit, declared.unit_price_micro_lamports, declared.loaded_accounts_data_size_limit) == (
        100,
        10_000,
        5,
    )
    assert declared.instruction_indexes == [0, 1, 2]
    assert txv1.priority_fee_of(v0(limit, price)) == 1
    assert txv1.priority_fee_of(v0(price)) == 2_000
    for dup in (limit, price, loaded):
        with pytest.raises(TransactionVersionError, match="duplicate"):
            txv1.declared_budget(v0(dup, dup))
    with pytest.raises(TransactionVersionError, match="unsupported ComputeBudget"):
        txv1.declared_budget(v0(Instruction(COMPUTE_BUDGET_PROGRAM, b"\x09", [])))
    assert txv1.runtime_default_unit_limit(10) == 1_400_000
