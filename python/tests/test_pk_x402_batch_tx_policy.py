"""Sponsor acceptance policy for client-built x402 ``batch-settlement`` transactions.

Transactions are compiled and payer-signed for real (v0 and legacy). Test
names follow the Rust ``batch_settlement/tx_policy.rs`` tests and the x402
PR #23 ``payment-channels.close.envelope`` tests they mirror.
"""

from __future__ import annotations

import base64
import struct
from dataclasses import replace
from typing import Any, cast

import pytest
from solders.hash import Hash
from solders.instruction import AccountMeta, Instruction
from solders.keypair import Keypair
from solders.message import Message, MessageAddressTableLookup, MessageV0, to_bytes_versioned
from solders.pubkey import Pubkey
from solders.signature import Signature
from solders.system_program import TransferParams, transfer
from solders.transaction import VersionedTransaction

from solana_pay_kit._paycore.paymentchannels import (
    LIGHTHOUSE_PROGRAM,
    OPEN_SLOT_WINDOW,
    PROGRAM_ID,
    Distribution,
    OpenChannelParams,
    TopUpParams,
    build_open_instruction,
    build_request_close_instruction,
    build_seal_instruction,
    build_top_up_instruction,
    find_channel_pda,
)
from solana_pay_kit._paycore.solana import COMPUTE_BUDGET_PROGRAM, MEMO_PROGRAM, TOKEN_PROGRAM
from solana_pay_kit.protocols.x402.batch_settlement import errors
from solana_pay_kit.protocols.x402.batch_settlement.errors import BatchSettlementError
from solana_pay_kit.protocols.x402.batch_settlement.tx_policy import (
    TransactionExpectations,
    setup_form,
    validate_request_close,
    validate_setup,
)
from solana_pay_kit.protocols.x402.batch_settlement.types import BatchChannelConfig

pytestmark = pytest.mark.usefixtures("reset_batch_globals")

PAY_TO = Pubkey.from_string("CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY")
MINT = Pubkey.from_string("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v")
TOKEN = Pubkey.from_string(TOKEN_PROGRAM)
PAYER = Keypair.from_seed(bytes([3] * 32))
FEE_PAYER = Keypair.from_seed(bytes([6] * 32)).pubkey()
OPEN_SLOT = 341_000_000
CHANNEL, _ = find_channel_pda(PAYER.pubkey(), FEE_PAYER, MINT, PAYER.pubkey(), 42, OPEN_SLOT)
NONCE = "0123456789abcdef0123456789abcdef"


def _expected(**overrides: Any) -> TransactionExpectations:
    config = cast(
        "BatchChannelConfig",
        {
            "payer": str(PAYER.pubkey()),
            "payerAuthorizer": str(PAYER.pubkey()),
            "receiver": str(PAY_TO),
            "token": str(MINT),
            "withdrawDelay": 3600,
            "salt": "42",
            "openSlot": OPEN_SLOT,
        },
    )
    base = TransactionExpectations(
        fee_payer=str(FEE_PAYER),
        config=config,
        channel_id=str(CHANNEL),
        token_program=TOKEN_PROGRAM,
        receiver=str(PAY_TO),
    )
    return replace(base, **overrides)


def _open(deposit: int = 100_000, **overrides: Any) -> Instruction:
    params: dict[str, Any] = {
        "payer": PAYER.pubkey(),
        "rent_payer": FEE_PAYER,
        "payee": FEE_PAYER,
        "mint": MINT,
        "authorized_signer": PAYER.pubkey(),
        "salt": 42,
        "deposit": deposit,
        "grace_period": 3600,
        "open_slot": OPEN_SLOT,
        "recipients": [Distribution(PAY_TO, 10_000)],
        "token_program": TOKEN,
    }
    params.update(overrides)
    return build_open_instruction(OpenChannelParams(**params))


def _top_up(amount: int = 25_000) -> Instruction:
    return build_top_up_instruction(TopUpParams(payer=PAYER.pubkey(), channel=CHANNEL, mint=MINT, amount=amount))


def _close(channel: Pubkey = CHANNEL) -> Instruction:
    return build_request_close_instruction(payer=PAYER.pubkey(), channel=channel)


def _memo(text: str = NONCE, accounts: list[AccountMeta] | None = None) -> Instruction:
    return Instruction(Pubkey.from_string(MEMO_PROGRAM), text.encode(), accounts or [])


def _budget(tag: int, value: int) -> Instruction:
    data = bytes([tag]) + struct.pack("<I" if tag == 2 else "<Q", value)
    return Instruction(Pubkey.from_string(COMPUTE_BUDGET_PROGRAM), data, [])


def _lighthouse(accounts: list[AccountMeta] | None = None) -> Instruction:
    return Instruction(Pubkey.from_string(LIGHTHOUSE_PROGRAM), b"\x00", accounts or [])


def _sign(message: Any, *, sign_payer: bool = True) -> str:
    num = int(message.header.num_required_signatures)
    signatures = [Signature.default()] * num
    signers = list(message.account_keys)[:num]
    if sign_payer and PAYER.pubkey() in signers:
        signatures[signers.index(PAYER.pubkey())] = PAYER.sign_message(bytes(to_bytes_versioned(message)))
    return base64.b64encode(bytes(VersionedTransaction.populate(message, signatures))).decode()


def _v0(instructions: list[Instruction], fee_payer: Pubkey = FEE_PAYER, **kw: Any) -> str:
    return _sign(MessageV0.try_compile(fee_payer, instructions, [], Hash.new_unique()), **kw)


def _legacy(instructions: list[Instruction]) -> str:
    return _sign(Message.new_with_blockhash(instructions, FEE_PAYER, Hash.new_unique()))


def _setup_code(tx: str, form: Any = "open", deposit: int = 100_000, **kw: Any) -> str:
    expected = kw.pop("expected", _expected())
    with pytest.raises(BatchSettlementError) as exc:
        validate_setup(tx, form, expected, deposit_amount=deposit, recent_slot=kw.pop("recent_slot", None))
    return exc.value.code


def _close_code(tx: str, expected: TransactionExpectations | None = None) -> str:
    with pytest.raises(BatchSettlementError) as exc:
        validate_request_close(tx, expected or _expected())
    return exc.value.code


# -- open --------------------------------------------------------------------------


def test_accepts_a_canonical_open() -> None:
    tx = _v0([_budget(2, 90_000), _budget(3, 1_000), _open(), _memo()])
    validated = validate_setup(tx, "open", _expected(), deposit_amount=100_000, recent_slot=OPEN_SLOT + 100)
    assert validated.payer == str(PAYER.pubkey())
    assert setup_form(tx) == "open"


def test_accepts_a_legacy_envelope_as_version_zero() -> None:
    # Pre-cutover clients still send legacy bytes; they are held to the same rules.
    tx = _legacy([_budget(2, 90_000), _open(), _memo()])
    assert validate_setup(tx, "open", _expected(), deposit_amount=100_000, recent_slot=None).payer == str(
        PAYER.pubkey()
    )


def test_open_requires_a_memo_the_sponsor_can_correlate() -> None:
    assert _setup_code(_v0([_open()])) == errors.INVALID_SETUP_TRANSACTION
    for text in ("hello", NONCE[:-2], "0123456789abcdef0123456789abcdeg"):
        assert _setup_code(_v0([_open(), _memo(text)])) == errors.INVALID_SETUP_TRANSACTION
    declared = _expected(memo="invoice-123")
    assert _setup_code(_v0([_open(), _memo("invoice-124")]), expected=declared) == errors.INVALID_SETUP_TRANSACTION
    validate_setup(_v0([_open(), _memo("invoice-123")]), "open", declared, deposit_amount=100_000, recent_slot=None)
    # One memo, not two.
    assert _setup_code(_v0([_open(), _memo(), _memo(NONCE + "00")])) == errors.INVALID_SETUP_TRANSACTION


def test_open_binds_the_declared_deposit_and_channel_args() -> None:
    tx = _v0([_open(), _memo()])
    # The voucher cap is computed from deposit.amount, so it must be what lands.
    assert _setup_code(tx, deposit=99_999) == errors.INVALID_SETUP_TRANSACTION
    # The client's escape hatch is exactly the advertised withdrawDelay.
    assert _setup_code(_v0([_open(grace_period=1800), _memo()])) == errors.INVALID_WITHDRAW_DELAY_MISMATCH
    # The salt the open encodes must be the one channelConfig declares.
    other = _expected(config={**_expected().config, "salt": "43"})
    assert _setup_code(tx, expected=other) == errors.INVALID_SETUP_TRANSACTION


def test_open_args_must_derive_the_named_channel() -> None:
    # An open whose account table names channel X but whose salt derives Y: the
    # program would create Y, so the server must not bind vouchers to X.
    ix = _open()
    data = bytearray(bytes(ix.data))
    struct.pack_into("<Q", data, 1, 7)  # salt 7 in the args, channel account still salt 42
    forged = Instruction(ix.program_id, bytes(data), ix.accounts)
    expected = _expected(config={**_expected().config, "salt": "7"})
    assert _setup_code(_v0([forged, _memo()]), expected=expected) == errors.INVALID_CHANNEL_ID_MISMATCH


def test_open_rejects_a_distribution_that_diverts_settled_funds() -> None:
    for recipients in (
        [Distribution(Pubkey.new_unique(), 10_000)],
        [Distribution(PAY_TO, 9_000), Distribution(Pubkey.new_unique(), 1_000)],
        [Distribution(PAY_TO, 9_999)],
    ):
        assert _setup_code(_v0([_open(recipients=recipients), _memo()])) == errors.INVALID_SETUP_TRANSACTION


def test_open_rejects_a_stale_or_future_open_slot() -> None:
    tx = _v0([_open(), _memo()])
    validate_setup(tx, "open", _expected(), deposit_amount=100_000, recent_slot=OPEN_SLOT + OPEN_SLOT_WINDOW)
    assert _setup_code(tx, recent_slot=OPEN_SLOT - 1) == errors.INVALID_SETUP_TRANSACTION
    assert _setup_code(tx, recent_slot=OPEN_SLOT + OPEN_SLOT_WINDOW + 1) == errors.INVALID_SETUP_TRANSACTION


def _swap(ix: Instruction, position: int, key: Pubkey) -> Instruction:
    metas = list(ix.accounts)
    metas[position] = AccountMeta(key, metas[position].is_signer, metas[position].is_writable)
    return Instruction(ix.program_id, bytes(ix.data), metas)


@pytest.mark.parametrize("position", range(14))
def test_open_account_table_is_pinned(position: int) -> None:
    # Every seat, including the zero-share payee (2), the voucher signer (4)
    # and the token program (8) that the PDA or ATAs would not catch here.
    forged = _swap(_open(), position, Pubkey.new_unique())
    assert _setup_code(_v0([forged, _memo()])) == errors.INVALID_SETUP_TRANSACTION


def test_open_carries_no_remaining_accounts() -> None:
    ix = _open()
    extra_account = Instruction(ix.program_id, bytes(ix.data), [*ix.accounts, AccountMeta(PAY_TO, False, False)])
    assert _setup_code(_v0([extra_account, _memo()])) == errors.INVALID_SETUP_TRANSACTION


def test_open_args_are_decoded_exactly() -> None:
    ix = _open()
    trailing = Instruction(ix.program_id, bytes(ix.data) + b"\x00", ix.accounts)
    assert _setup_code(_v0([trailing, _memo()])) == errors.INVALID_SETUP_TRANSACTION
    # An openSlot arg that disagrees with channelConfig is refused as a setup
    # error before the PDA comparison would report it as a channel mismatch.
    data = bytearray(bytes(ix.data))
    struct.pack_into("<Q", data, 21, OPEN_SLOT + 1)
    assert _setup_code(_v0([Instruction(ix.program_id, bytes(data), ix.accounts), _memo()])) == (
        errors.INVALID_SETUP_TRANSACTION
    )


def test_open_channel_accounts_must_be_writable() -> None:
    ix = _open()
    metas = list(ix.accounts)
    metas[5] = AccountMeta(metas[5].pubkey, False, False)  # channel demoted to read-only
    assert _setup_code(_v0([Instruction(ix.program_id, bytes(ix.data), metas), _memo()])) == (
        errors.INVALID_SETUP_TRANSACTION
    )


# -- the instruction allowlist -------------------------------------------------------


def test_rejects_a_smuggled_instruction_or_a_foreign_program() -> None:
    drain = transfer(TransferParams(from_pubkey=FEE_PAYER, to_pubkey=PAYER.pubkey(), lamports=1_000_000))
    assert _setup_code(_v0([_open(), _memo(), drain])) == errors.INVALID_SETUP_TRANSACTION
    assert _setup_code(_v0([drain, _open(), _memo()])) == errors.INVALID_SETUP_TRANSACTION
    assert _setup_code(_v0([_open(), _open(), _memo()])) == errors.INVALID_SETUP_TRANSACTION
    foreign = Instruction(Pubkey.new_unique(), bytes(_open().data), _open().accounts)
    assert _setup_code(_v0([foreign, _memo()])) == errors.INVALID_SETUP_TRANSACTION
    assert _setup_code(_v0([_top_up(), _memo()])) == errors.INVALID_SETUP_TRANSACTION  # wrong form


@pytest.mark.parametrize(
    "prefix",
    [
        [_budget(2, 400_001)],
        [_budget(3, 5_000_001)],
        [_budget(2, 1), _budget(2, 1)],
        [_budget(3, 1), _budget(2, 1)],
        [_budget(3, 1), _budget(3, 1)],
        [Instruction(Pubkey.from_string(COMPUTE_BUDGET_PROGRAM), bytes([4]) + struct.pack("<I", 1), [])],
    ],
    ids=["limit-cap", "price-cap", "duplicate-limit", "price-before-limit", "duplicate-price", "unsupported-op"],
)
def test_compute_budget_prefix_is_bounded(prefix: list[Instruction]) -> None:
    assert _setup_code(_v0([*prefix, _open(), _memo()])) == errors.INVALID_SETUP_TRANSACTION


def test_suffix_is_bounded_and_never_names_the_fee_payer() -> None:
    validate_setup(
        _v0([_open(), _lighthouse(), _lighthouse(), _lighthouse(), _memo()]),
        "open",
        _expected(),
        deposit_amount=100_000,
        recent_slot=None,
    )
    four = _v0([_open(), _lighthouse(), _lighthouse(), _lighthouse(), _lighthouse(), _memo()])
    assert _setup_code(four) == errors.INVALID_SETUP_TRANSACTION
    oversized = _v0([_open(), _memo(), Instruction(Pubkey.from_string(LIGHTHOUSE_PROGRAM), bytes(700), [])])
    assert _setup_code(oversized) == errors.INVALID_SETUP_TRANSACTION  # over the 1232-byte packet
    names_sponsor = [AccountMeta(FEE_PAYER, False, True)]
    assert _setup_code(_v0([_open(), _lighthouse(names_sponsor), _memo()])) == errors.INVALID_SETUP_TRANSACTION
    assert _setup_code(_v0([_open(), _memo(accounts=names_sponsor)])) == errors.INVALID_SETUP_TRANSACTION


# -- envelope ----------------------------------------------------------------------------


def test_rejects_an_envelope_the_sponsor_cannot_account_for() -> None:
    ixs = [_open(), _memo()]
    # Fee payer is not the sponsor.
    assert _setup_code(_v0(ixs, fee_payer=PAYER.pubkey())) == errors.INVALID_SETUP_TRANSACTION
    # Valid layout, but the payer never signed: never co-sign that.
    assert _setup_code(_v0(ixs, sign_payer=False)) == errors.INVALID_SETUP_TRANSACTION
    # A third required signer the sponsor cannot account for.
    third = Keypair().pubkey()
    extra_signer = _lighthouse([AccountMeta(third, True, False)])
    assert _setup_code(_v0([_open(), extra_signer, _memo()])) == errors.INVALID_SETUP_TRANSACTION
    # The payer seat must not be the sponsor itself.
    same = _expected(config={**_expected().config, "payer": str(FEE_PAYER)})
    assert _setup_code(_v0(ixs), expected=same) == errors.INVALID_FEE_PAYER_MISMATCH
    assert _setup_code("not base64!") == errors.INVALID_SETUP_TRANSACTION
    assert _setup_code(base64.b64encode(b"\x01\x02").decode()) == errors.INVALID_SETUP_TRANSACTION


def test_rejects_address_lookup_tables() -> None:
    # A lookup table would resolve accounts this validator never sees.
    message = MessageV0.try_compile(FEE_PAYER, [_open(), _memo()], [], Hash.new_unique())
    with_lookup = MessageV0(
        message.header,
        list(message.account_keys),
        message.recent_blockhash,
        list(message.instructions),
        [MessageAddressTableLookup(Pubkey.new_unique(), bytes([0]), b"")],
    )
    assert _setup_code(_sign(with_lookup)) == errors.INVALID_SETUP_TRANSACTION


# -- top_up ----------------------------------------------------------------------------------


def test_accepts_a_canonical_top_up_and_binds_its_amount() -> None:
    tx = _v0([_top_up(), _memo()])
    assert setup_form(tx) == "top_up"
    validate_setup(tx, "top_up", _expected(), deposit_amount=25_000, recent_slot=None)
    assert _setup_code(tx, "top_up", deposit=24_000) == errors.INVALID_SETUP_TRANSACTION
    # The fee payer must be the sponsor. A top-up does not name it, so only
    # the envelope check can catch a transaction paid by someone else.
    assert _setup_code(_v0([_top_up(), _memo()], fee_payer=PAY_TO), "top_up", 25_000) == (
        errors.INVALID_SETUP_TRANSACTION
    )
    ix = _top_up()
    remaining = Instruction(ix.program_id, bytes(ix.data), [*ix.accounts, AccountMeta(PAY_TO, False, False)])
    assert _setup_code(_v0([remaining, _memo()]), "top_up", 25_000) == errors.INVALID_SETUP_TRANSACTION
    # A top-up naming the sponsor would put its signature behind a token authority.
    smuggled = Instruction(ix.program_id, bytes(ix.data), [*ix.accounts, AccountMeta(FEE_PAYER, False, True)])
    assert _setup_code(_v0([smuggled, _memo()]), "top_up", 25_000) == errors.INVALID_SETUP_TRANSACTION


@pytest.mark.parametrize("position", range(6))
def test_top_up_account_table_is_pinned(position: int) -> None:
    forged = _swap(_top_up(), position, Pubkey.new_unique())
    assert _setup_code(_v0([forged, _memo()]), "top_up", 25_000) == errors.INVALID_SETUP_TRANSACTION


def test_setup_form_requires_exactly_one_setup_instruction() -> None:
    for ixs in ([_memo()], [_open(), _top_up(), _memo()]):
        with pytest.raises(BatchSettlementError) as exc:
            setup_form(_v0(ixs))
        assert exc.value.code == errors.INVALID_SETUP_TRANSACTION


# -- request_close (refund) -----------------------------------------------------------------------


def test_accepts_a_canonical_request_close_and_rejects_extra_instructions() -> None:
    assert validate_request_close(_v0([_close(), _memo()]), _expected()).payer == str(PAYER.pubkey())
    # A seal riding along would finalize the channel at a watermark never claimed.
    assert _close_code(_v0([_close(), build_seal_instruction(channel=CHANNEL), _memo()])) == (
        errors.INVALID_REFUND_TRANSACTION
    )


def test_accepts_a_capped_compute_budget_prefix_and_a_lighthouse_suffix() -> None:
    validate_request_close(_v0([_budget(2, 50_000), _budget(3, 10), _close(), _lighthouse(), _memo()]), _expected())
    # The spec allows at most one Memo on a refund, so none is fine too.
    validate_request_close(_v0([_close()]), _expected())


def test_rejects_compute_budget_instructions_outside_the_sponsors_policy() -> None:
    assert _close_code(_v0([_budget(2, 400_001), _close()])) == errors.INVALID_REFUND_TRANSACTION


def test_rejects_a_prefix_only_transaction_that_never_reaches_request_close() -> None:
    # The payer still signs (through the prefix), so only the missing close fails.
    signed_prefix = Instruction(
        Pubkey.from_string(COMPUTE_BUDGET_PROGRAM),
        bytes([2]) + struct.pack("<I", 1),
        [AccountMeta(PAYER.pubkey(), True, False)],
    )
    assert _close_code(_v0([signed_prefix])) == errors.INVALID_REFUND_TRANSACTION


def test_rejects_a_suffix_the_sponsor_does_not_allow() -> None:
    drain = transfer(TransferParams(from_pubkey=PAYER.pubkey(), to_pubkey=PAY_TO, lamports=1))
    assert _close_code(_v0([_close(), drain])) == errors.INVALID_REFUND_TRANSACTION
    assert _close_code(_v0([_close(), _memo(), _memo(NONCE + "00")])) == errors.INVALID_REFUND_TRANSACTION


def test_rejects_a_memo_that_is_neither_declared_nor_a_nonce() -> None:
    assert _close_code(_v0([_close(), _memo("refund please")])) == errors.INVALID_REFUND_TRANSACTION


def test_rejects_a_transaction_whose_fee_payer_slot_is_not_the_sponsor() -> None:
    assert _close_code(_v0([_close(), _memo()], fee_payer=PAYER.pubkey())) == errors.INVALID_REFUND_TRANSACTION


def test_rejects_a_missing_or_forged_payer_signature() -> None:
    assert _close_code(_v0([_close(), _memo()], sign_payer=False)) == errors.INVALID_REFUND_TRANSACTION


def test_request_close_must_be_authorized_by_the_channel_payer() -> None:
    # The payer still signs the transaction (through the Memo), but the close
    # names someone else as its payer: the program would refuse it after the
    # sponsor paid the fee.
    ix = _close()
    forged = Instruction(
        ix.program_id, bytes(ix.data), [AccountMeta(Pubkey.new_unique(), False, False), ix.accounts[1]]
    )
    payer_signed_memo = _memo(accounts=[AccountMeta(PAYER.pubkey(), True, False)])
    assert _close_code(_v0([forged, payer_signed_memo])) == errors.INVALID_REFUND_TRANSACTION


def test_request_close_binds_the_derived_channel_and_payer_privileges() -> None:
    assert _close_code(_v0([_close(Pubkey.new_unique()), _memo()])) == errors.INVALID_REFUND_TRANSACTION
    ix = _close()
    writable_payer = Instruction(
        ix.program_id, bytes(ix.data), [AccountMeta(PAYER.pubkey(), True, True), ix.accounts[1]]
    )
    assert _close_code(_v0([writable_payer, _memo()])) == errors.INVALID_REFUND_TRANSACTION
    remaining = Instruction(ix.program_id, bytes(ix.data), [*ix.accounts, AccountMeta(PAY_TO, False, False)])
    assert _close_code(_v0([remaining, _memo()])) == errors.INVALID_REFUND_TRANSACTION
    with_args = Instruction(ix.program_id, bytes(ix.data) + b"\x00", ix.accounts)
    assert _close_code(_v0([with_args, _memo()])) == errors.INVALID_REFUND_TRANSACTION


def test_program_id_is_the_canonical_deployment_by_default() -> None:
    assert _expected().program_id == PROGRAM_ID
