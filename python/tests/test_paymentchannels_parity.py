"""Renderer-independent payment-channel wire contracts.

Expected bytes and account order are manually transcribed from
idl/payment-channels.json, not computed by generated serializers or glue
helpers. PDA expectations use only solders and the protocol's literal seeds.
These are serialization tests: they do not imply on-chain economic validity.
"""

import struct
from dataclasses import replace

import pytest
from solders.instruction import Instruction
from solders.pubkey import Pubkey

from solana_pay_kit._paycore import paymentchannels as pc
from solana_pay_kit.protocols.programs.paymentchannels.accounts.channel import Channel


def key(value: int) -> Pubkey:
    return Pubkey.from_bytes(bytes([value]) * 32)


PROGRAM = Pubkey.from_string("CHNLxYvVA28MJP9PrFuDXccuoGXAx7jBacfLEkahyGsX")
ATA_PROGRAM = Pubkey.from_string("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")
SYSTEM = Pubkey.from_string("11111111111111111111111111111111")
RENT = Pubkey.from_string("SysvarRent111111111111111111111111111111111")
INSTRUCTIONS = Pubkey.from_string("Sysvar1nstructions1111111111111111111111111")
ED25519 = Pubkey.from_string("Ed25519SigVerify111111111111111111111111111")
TREASURY = Pubkey.from_string("Cs2zdfUNonRdRGsiZUQQLdTxzxVvJZmgiX2mpLYKuEqP")
PROGRAMS = [PROGRAM, key(201)]
SALT = 0x0102030405060708
AMOUNT = 0x1020304050607080
SLOT = 0x1122334455667788


def ata(owner: Pubkey) -> Pubkey:
    return Pubkey.find_program_address([bytes(owner), bytes(key(7)), bytes(key(3))], ATA_PROGRAM)[0]


def event(program: Pubkey) -> Pubkey:
    return Pubkey.find_program_address([b"event_authority"], program)[0]


def assert_instruction(
    instruction: Instruction,
    program: Pubkey,
    data: bytes,
    accounts: list[tuple[Pubkey, bool, bool]],
) -> None:
    assert isinstance(instruction, Instruction)
    assert instruction.program_id == program
    assert bytes(instruction.data) == data
    assert [(a.pubkey, a.is_signer, a.is_writable) for a in instruction.accounts] == accounts


def open_params(program: Pubkey = PROGRAM) -> pc.OpenChannelParams:
    return pc.OpenChannelParams(
        payer=key(1),
        payee=key(2),
        mint=key(3),
        authorized_signer=key(4),
        salt=SALT,
        deposit=AMOUNT,
        grace_period=0x12345678,
        open_slot=SLOT,
        token_program=key(7),
        rent_payer=key(8),
        program_id=program,
    )


@pytest.mark.parametrize("program", PROGRAMS)
@pytest.mark.parametrize("with_splits", [False, True])
def test_open_complete_wire_contract(program: Pubkey, with_splits: bool) -> None:
    params = open_params(program)
    if with_splits:
        params.recipients = [pc.Distribution(key(5), 7500), pc.Distribution(key(6), 2500)]
    channel = Pubkey.find_program_address(
        [
            b"channel",
            bytes(key(1)),
            bytes(key(2)),
            bytes(key(3)),
            bytes(key(4)),
            struct.pack("<Q", SALT),
            struct.pack("<Q", SLOT),
        ],
        program,
    )[0]
    splits = (
        struct.pack("<I", 2) + bytes(key(5)) + struct.pack("<H", 7500) + bytes(key(6)) + struct.pack("<H", 2500)
        if with_splits
        else b"\0\0\0\0"
    )
    assert_instruction(
        pc.build_open_instruction(params),
        program,
        b"\x01" + struct.pack("<QQIQ", SALT, AMOUNT, 0x12345678, SLOT) + splits,
        [
            (key(1), True, True),
            (key(8), True, True),
            (key(2), False, False),
            (key(3), False, False),
            (key(4), False, False),
            (channel, False, True),
            (ata(key(1)), False, True),
            (ata(channel), False, True),
            (key(7), False, False),
            (SYSTEM, False, False),
            (RENT, False, False),
            (ATA_PROGRAM, False, False),
            (event(program), False, False),
            (program, False, False),
        ],
    )


@pytest.mark.parametrize("program", PROGRAMS)
@pytest.mark.parametrize("amount", [0, AMOUNT, 2**64 - 1])
def test_top_up_complete_wire_contract(program: Pubkey, amount: int) -> None:
    assert_instruction(
        pc.build_top_up_instruction(
            pc.TopUpParams(
                payer=key(1),
                channel=key(9),
                mint=key(3),
                amount=amount,
                token_program=key(7),
                program_id=program,
            )
        ),
        program,
        b"\x03" + struct.pack("<Q", amount),
        [
            (key(1), True, True),
            (key(9), False, True),
            (ata(key(1)), False, True),
            (ata(key(9)), False, True),
            (key(3), False, False),
            (key(7), False, False),
        ],
    )


@pytest.mark.parametrize("program", PROGRAMS)
def test_reclaim_complete_wire_contract(program: Pubkey) -> None:
    assert_instruction(
        pc.build_reclaim_instruction(channel=key(9), rent_payer=key(8), program_id=program),
        program,
        b"\x09",
        [(key(9), False, True), (key(8), False, True)],
    )


@pytest.mark.parametrize("program", PROGRAMS)
@pytest.mark.parametrize("with_voucher", [False, True])
def test_settle_and_seal_complete_wire_contract(program: Pubkey, with_voucher: bool) -> None:
    signature = bytes(range(64))
    instructions = pc.build_settle_and_seal_instructions(
        payee=key(2),
        channel=key(9),
        authorized_signer=key(4),
        signature=signature if with_voucher else None,
        cumulative=AMOUNT,
        expires_at=-0x0102030405060708,
        program_id=program,
    )
    assert len(instructions) == (2 if with_voucher else 1)
    assert_instruction(
        instructions[-1],
        program,
        b"\x04\x01" if with_voucher else b"\x04\x00",
        [(key(2), True, False), (key(9), False, True), (INSTRUCTIONS, False, False)],
    )
    if with_voucher:
        message = b"\x56\x01" + bytes(key(9)) + struct.pack("<Qq", AMOUNT, -0x0102030405060708)
        # Ed25519 header: signature offset/index, key offset/index,
        # message offset/size/index; 0xffff always means this instruction.
        header = bytes.fromhex("01003000ffff1000ffff70003200ffff")
        assert_instruction(instructions[0], ED25519, header + bytes(key(4)) + signature + message, [])
        data = bytes(instructions[0].data)
        assert data[16:48] == bytes(key(4))
        assert data[48:112] == signature
        assert data[112:162] == message


@pytest.mark.parametrize("program", PROGRAMS)
@pytest.mark.parametrize("treasury", [None, key(19)])
@pytest.mark.parametrize("with_splits", [False, True])
def test_distribute_complete_wire_contract(
    program: Pubkey,
    treasury: Pubkey | None,
    with_splits: bool,
) -> None:
    # Deliberately non-sorted recipients catch sorting/reordering of remaining accounts.
    recipients = [pc.Distribution(key(6), 2500), pc.Distribution(key(5), 7500)] if with_splits else []
    data = b"\x07" + (
        struct.pack("<I", 2) + bytes(key(6)) + struct.pack("<H", 2500) + bytes(key(5)) + struct.pack("<H", 7500)
        if with_splits
        else struct.pack("<I", 0)
    )
    accounts = [
        (key(9), False, True),
        (key(1), False, True),
        (key(8), False, True),
        (ata(key(9)), False, True),
        (ata(key(1)), False, True),
        (ata(key(2)), False, True),
        (ata(TREASURY if treasury is None else treasury), False, True),
        (key(3), False, False),
        (key(7), False, False),
        (event(program), False, False),
        (program, False, False),
    ]
    if with_splits:
        accounts += [(ata(key(6)), False, True), (ata(key(5)), False, True)]
    assert_instruction(
        pc.build_distribute_instruction(
            channel=key(9),
            payer=key(1),
            payee=key(2),
            mint=key(3),
            recipients=recipients,
            token_program=key(7),
            program_id=program,
            treasury=treasury,
            rent_payer=key(8),
        ),
        program,
        data,
        accounts,
    )


@pytest.mark.parametrize(
    ("field", "width"),
    [("salt", 64), ("deposit", 64), ("grace_period", 32), ("open_slot", 64)],
)
@pytest.mark.parametrize("upper", [False, True])
def test_open_rejects_both_integer_boundaries(field: str, width: int, upper: bool) -> None:
    with pytest.raises(ValueError, match=field):
        pc.build_open_instruction(replace(open_params(), **{field: 2**width if upper else -1}))


@pytest.mark.parametrize("bps", [-1, 2**16])
def test_open_rejects_recipient_integer_boundaries(bps: int) -> None:
    with pytest.raises(ValueError, match="bps"):
        pc.build_open_instruction(replace(open_params(), recipients=[pc.Distribution(key(5), bps)]))


@pytest.mark.parametrize("bps", [-1, 2**16])
def test_distribute_rejects_recipient_integer_boundaries(bps: int) -> None:
    with pytest.raises(ValueError):
        pc.build_distribute_instruction(
            channel=key(9),
            payer=key(1),
            payee=key(2),
            mint=key(3),
            recipients=[pc.Distribution(key(5), bps)],
            token_program=key(7),
            rent_payer=key(8),
        )


@pytest.mark.parametrize("amount", [-1, 2**64])
def test_top_up_rejects_integer_overflow(amount: int) -> None:
    with pytest.raises((ValueError, OverflowError, struct.error)):
        pc.build_top_up_instruction(pc.TopUpParams(key(1), key(9), key(3), amount))


@pytest.mark.parametrize(
    ("cumulative", "expires_at"),
    [(-1, 0), (2**64, 0), (0, -(2**63) - 1), (0, 2**63)],
)
def test_voucher_rejects_integer_overflow(cumulative: int, expires_at: int) -> None:
    with pytest.raises((ValueError, OverflowError, struct.error)):
        pc.voucher_message_bytes(key(9), cumulative, expires_at)


@pytest.mark.parametrize("size", [0, 1, 63, 65])
def test_settle_rejects_malformed_signature(size: int) -> None:
    with pytest.raises(ValueError, match="signature"):
        pc.build_settle_and_seal_instructions(
            payee=key(2),
            channel=key(9),
            authorized_signer=key(4),
            signature=bytes(size),
            cumulative=1,
            expires_at=2,
        )


def test_ed25519_rejects_message_offset_overflow() -> None:
    with pytest.raises(ValueError, match="too long"):
        pc.build_ed25519_verify_instruction(key(4), bytes(64), bytes(2**16))


def test_missing_rent_payer_is_not_silently_replaced() -> None:
    with pytest.raises(ValueError, match="rent_payer"):
        pc.build_open_instruction(replace(open_params(), rent_payer=None))
    with pytest.raises(ValueError, match="rent_payer"):
        pc.build_distribute_instruction(
            channel=key(9),
            payer=key(1),
            payee=key(2),
            mint=key(3),
            recipients=[],
            token_program=key(7),
        )


def channel_fixture() -> bytes:
    """IDL channel: 256 packed bytes, including its explicit u8 discriminator.

    Offsets: header 0, salt 4, deposit 12, settlement 20/28, timestamps
    36/44, grace 52, hash 56, five public keys 88..248, open slot 248.
    No generated builder/serializer participates in constructing this fixture.
    """
    return (
        bytes([1, 2, 253, 3])
        + struct.pack("<QQQQqqI", SALT, AMOUNT, 0x2132435465768798, 0x31425364758697A8, -(2**63), 2**63 - 1, 0x12345678)
        + bytes(range(32))
        + bytes(key(1))
        + bytes(key(2))
        + bytes(key(4))
        + bytes(key(3))
        + bytes(key(8))
        + struct.pack("<Q", SLOT)
    )


def test_generated_channel_deserializes_independent_account_fixture() -> None:
    data = channel_fixture()
    assert len(data) == 256
    channel = Channel.deserialize(data)
    assert (channel.discriminator, channel.version, channel.bump, channel.status) == (1, 2, 253, 3)
    assert channel.salt == SALT
    assert channel.deposit == AMOUNT
    assert channel.settlement.settled == 0x2132435465768798
    assert channel.settlement.payout_watermark == 0x31425364758697A8
    assert channel.closure_started_at == -(2**63)
    assert channel.payer_withdrawn_at == 2**63 - 1
    assert channel.grace_period == 0x12345678
    assert bytes(channel.distribution_hash) == bytes(range(32))
    assert bytes(channel.payer) == bytes(key(1))
    assert bytes(channel.payee) == bytes(key(2))
    assert bytes(channel.authorized_signer) == bytes(key(4))
    assert bytes(channel.mint) == bytes(key(3))
    assert bytes(channel.rent_payer) == bytes(key(8))
    assert channel.open_slot == SLOT
    # Secondary assertion only: deserialization above is checked field-by-field
    # against an independent fixture, never only via a serializer round trip.
    assert channel.serialize() == data


@pytest.mark.parametrize("size", [0, 1, 4, 20, 36, 56, 88, 120, 248, 255])
def test_generated_channel_rejects_truncated_account(size: int) -> None:
    with pytest.raises(ValueError):
        Channel.deserialize(channel_fixture()[:size])


def test_public_channel_decoder_accepts_live_channel_fixture() -> None:
    channel = pc.decode_channel_account(channel_fixture())
    assert channel.discriminator == 1
    assert channel.open_slot == SLOT
    assert bytes(channel.rent_payer) == bytes(key(8))


@pytest.mark.parametrize("discriminator", [0, 2, 7, 255])
def test_public_channel_decoder_rejects_closed_or_unknown_accounts(discriminator: int) -> None:
    with pytest.raises(ValueError):
        pc.decode_channel_account(bytes([discriminator]) + channel_fixture()[1:])


def test_account_discriminator_uses_explicit_idl_values_not_variant_indices() -> None:
    from solana_pay_kit.protocols.programs.paymentchannels.types.account_discriminator import AccountDiscriminator

    # idl/payment-channels.json and the program's state/common.rs explicitly
    # assign Channel = 1 and ClosedChannel = 2; these are NOT indices 0 and 1.
    assert AccountDiscriminator.CHANNEL == 1
    assert AccountDiscriminator.CLOSED_CHANNEL == 2
    assert AccountDiscriminator.CHANNEL.serialize() == b"\x01"
    assert AccountDiscriminator.CLOSED_CHANNEL.serialize() == b"\x02"
    assert AccountDiscriminator.deserialize(b"\x01") is AccountDiscriminator.CHANNEL
    assert AccountDiscriminator.deserialize(b"\x02") is AccountDiscriminator.CLOSED_CHANNEL
    for invalid in (b"\x00", b"\x03", b"\xff"):
        with pytest.raises(ValueError):
            AccountDiscriminator.deserialize(invalid)


@pytest.mark.parametrize("size", [0, 1, 20, 248, 255])
def test_public_channel_decoder_rejects_truncated_accounts(size: int) -> None:
    with pytest.raises(ValueError):
        pc.decode_channel_account(channel_fixture()[:size])


@pytest.mark.parametrize("invalid", [1.5, "12", True])
@pytest.mark.parametrize("field", ["salt", "deposit", "grace_period", "open_slot"])
def test_open_does_not_coerce_non_integer_fields(field: str, invalid: object) -> None:
    with pytest.raises((ValueError, TypeError)):
        pc.build_open_instruction(replace(open_params(), **{field: invalid}))


@pytest.mark.parametrize("invalid", [1.5, "12", True])
def test_amounts_and_splits_do_not_coerce_non_integer_values(invalid: object) -> None:
    with pytest.raises((ValueError, TypeError)):
        pc.build_top_up_instruction(pc.TopUpParams(key(1), key(9), key(3), invalid))  # type: ignore[arg-type]
    with pytest.raises((ValueError, TypeError)):
        pc.voucher_message_bytes(key(9), invalid, 0)  # type: ignore[arg-type]
    with pytest.raises((ValueError, TypeError)):
        pc.voucher_message_bytes(key(9), 0, invalid)  # type: ignore[arg-type]
    recipients = [pc.Distribution(key(5), invalid)]  # type: ignore[arg-type]
    with pytest.raises((ValueError, TypeError)):
        pc.build_open_instruction(replace(open_params(), recipients=recipients))
    with pytest.raises((ValueError, TypeError)):
        pc.build_distribute_instruction(
            channel=key(9),
            payer=key(1),
            payee=key(2),
            mint=key(3),
            recipients=recipients,
            token_program=key(7),
            rent_payer=key(8),
        )
