"""Tests for the payment-channels on-chain glue.

Parity is verified against the Rust spine
(``rust/crates/mpp/src/program/payment_channels.rs``) and the CI-green Go port.
All tests are RPC-free: PDA derivation and instruction packing are pure.
"""

from __future__ import annotations

import struct
from dataclasses import replace

import pytest
from solders.pubkey import Pubkey

from pay_kit.protocols.mpp._paymentchannels import (
    PAYMENT_CHANNELS_PROGRAM_ID,
    PROGRAM_ID,
    Distribution,
    OpenChannelParams,
    TopUpParams,
    build_open_instruction,
    build_top_up_instruction,
    find_associated_token_address,
    find_channel_pda,
    find_event_authority_pda,
    voucher_message_bytes,
)


def pk(byte: int) -> Pubkey:
    """A pubkey whose 32 bytes are all ``byte`` (mirrors the Rust test helper)."""
    return Pubkey.from_bytes(bytes([byte] * 32))


def test_program_id_is_canonical() -> None:
    assert PAYMENT_CHANNELS_PROGRAM_ID == "CHNLxYvVA28MJP9PrFuDXccuoGXAx7jBacfLEkahyGsX"
    assert str(PROGRAM_ID) == PAYMENT_CHANNELS_PROGRAM_ID


def test_voucher_message_length_and_offsets() -> None:
    out = voucher_message_bytes(pk(9), 42, 1234)
    assert len(out) == 48
    assert out[:32] == bytes([9] * 32)
    assert out[32:40] == struct.pack("<Q", 42)
    assert out[40:48] == struct.pack("<q", 1234)


def test_voucher_message_frozen_cross_language_vector() -> None:
    # Frozen rust/Go vector: channel_id = 32 bytes of 9, cumulative 42, expires 1234.
    out = voucher_message_bytes(pk(9), 42, 1234)
    expected = bytes([9] * 32) + (42).to_bytes(8, "little") + (1234).to_bytes(8, "little", signed=True)
    assert out == expected


def test_voucher_message_negative_expires_at() -> None:
    out = voucher_message_bytes(pk(7), 0, -1)
    assert len(out) == 48
    assert out[40:48] == struct.pack("<q", -1)
    assert out[40:48] == (-1).to_bytes(8, "little", signed=True)


@pytest.mark.parametrize(
    ("cumulative", "expires_at"),
    [
        (0, 0),
        (1, 1),
        (42, 1234),
        (2**64 - 1, 2**63 - 1),
        (123456789, -(2**63)),
    ],
)
def test_voucher_message_roundtrip(cumulative: int, expires_at: int) -> None:
    out = voucher_message_bytes(pk(3), cumulative, expires_at)
    assert out[32:40] == struct.pack("<Q", cumulative)
    assert out[40:48] == struct.pack("<q", expires_at)


def test_voucher_message_rejects_non_32_byte_channel_id() -> None:
    class FakeKey:
        def __bytes__(self) -> bytes:
            return b"\x01\x02\x03"

    with pytest.raises(ValueError, match="exactly 32 bytes"):
        voucher_message_bytes(FakeKey(), 1, 1)  # type: ignore[arg-type]


def test_find_channel_pda_is_deterministic_and_off_curve() -> None:
    addr1, bump1 = find_channel_pda(pk(1), pk(2), pk(3), pk(4), 99)
    addr2, bump2 = find_channel_pda(pk(1), pk(2), pk(3), pk(4), 99)
    assert addr1 == addr2
    assert bump1 == bump2
    assert 0 <= bump1 <= 255


def test_find_channel_pda_matches_create_program_address() -> None:
    addr, bump = find_channel_pda(pk(1), pk(2), pk(3), pk(4), 99)
    expected = Pubkey.create_program_address(
        [
            b"channel",
            bytes(pk(1)),
            bytes(pk(2)),
            bytes(pk(3)),
            bytes(pk(4)),
            struct.pack("<Q", 99),
            bytes([bump]),
        ],
        PROGRAM_ID,
    )
    assert addr == expected


def test_find_channel_pda_salt_changes_address() -> None:
    addr_a, _ = find_channel_pda(pk(1), pk(2), pk(3), pk(4), 1)
    addr_b, _ = find_channel_pda(pk(1), pk(2), pk(3), pk(4), 2)
    assert addr_a != addr_b


def test_find_event_authority_pda_is_deterministic() -> None:
    addr1, bump1 = find_event_authority_pda()
    addr2, bump2 = find_event_authority_pda()
    assert addr1 == addr2
    assert bump1 == bump2
    expected = Pubkey.create_program_address([b"event_authority", bytes([bump1])], PROGRAM_ID)
    assert addr1 == expected


def test_find_associated_token_address_matches_seed_layout() -> None:
    owner, mint, token_program = pk(1), pk(2), pk(5)
    addr, _ = find_associated_token_address(owner, mint, token_program)
    ata_program = Pubkey.from_string("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")
    expected, _ = Pubkey.find_program_address(
        [bytes(owner), bytes(token_program), bytes(mint)],
        ata_program,
    )
    assert addr == expected


def _open_params() -> OpenChannelParams:
    return OpenChannelParams(
        payer=pk(1),
        payee=pk(2),
        mint=pk(3),
        authorized_signer=pk(4),
        salt=99,
        deposit=1_000_000,
        grace_period=3600,
        recipients=[Distribution(pk(5), 7_500), Distribution(pk(6), 2_500)],
        token_program=pk(7),
    )


def test_build_open_instruction_program_id_and_account_count() -> None:
    ix = build_open_instruction(_open_params())
    assert ix.program_id == PROGRAM_ID
    assert str(ix.program_id) == PAYMENT_CHANNELS_PROGRAM_ID
    assert len(ix.accounts) == 13


def test_build_open_instruction_rejects_out_of_range_fields() -> None:
    """Out-of-range integer fields raise a clear ValueError before the generated
    Borsh encoder would fail with a low-level construct error."""
    base = _open_params()
    with pytest.raises(ValueError, match="grace_period"):
        build_open_instruction(replace(base, grace_period=0x1_0000_0000))
    with pytest.raises(ValueError, match="salt"):
        build_open_instruction(replace(base, salt=0x1_0000_0000_0000_0000))
    with pytest.raises(ValueError, match="deposit"):
        build_open_instruction(replace(base, deposit=-1))
    with pytest.raises(ValueError, match="bps"):
        build_open_instruction(replace(base, recipients=[Distribution(pk(5), 0x1_0000)]))


def test_build_open_instruction_account_order_and_flags() -> None:
    params = _open_params()
    ix = build_open_instruction(params)
    accounts = ix.accounts

    channel, _ = find_channel_pda(params.payer, params.payee, params.mint, params.authorized_signer, params.salt)
    payer_ata, _ = find_associated_token_address(params.payer, params.mint, params.token_program)
    channel_ata, _ = find_associated_token_address(channel, params.mint, params.token_program)
    event_authority, _ = find_event_authority_pda()

    # 0 payer: signer + writable.
    assert accounts[0].pubkey == params.payer
    assert accounts[0].is_signer is True
    assert accounts[0].is_writable is True
    # 1 payee, 2 mint, 3 authorized_signer: read-only.
    assert accounts[1].pubkey == params.payee
    assert accounts[2].pubkey == params.mint
    assert accounts[3].pubkey == params.authorized_signer
    # 4 channel PDA: writable.
    assert accounts[4].pubkey == channel
    assert accounts[4].is_writable is True
    assert accounts[4].is_signer is False
    # 5 payer ATA, 6 channel ATA: writable.
    assert accounts[5].pubkey == payer_ata
    assert accounts[5].is_writable is True
    assert accounts[6].pubkey == channel_ata
    assert accounts[6].is_writable is True
    # 7 token_program, 8 system_program, 9 rent, 10 associated_token_program.
    assert accounts[7].pubkey == params.token_program
    assert str(accounts[8].pubkey) == "11111111111111111111111111111111"
    assert str(accounts[9].pubkey) == "SysvarRent111111111111111111111111111111111"
    assert str(accounts[10].pubkey) == "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"
    # 11 event_authority PDA.
    assert accounts[11].pubkey == event_authority
    # 12 self/program == the payment-channels program id.
    assert accounts[12].pubkey == PROGRAM_ID
    # No account other than payer is a signer.
    assert [a.is_signer for a in accounts] == [True] + [False] * 12


def test_build_open_instruction_data_layout_roundtrip() -> None:
    params = _open_params()
    ix = build_open_instruction(params)
    data = bytes(ix.data)

    assert data[0] == 1
    off = 1
    assert struct.unpack_from("<Q", data, off)[0] == params.salt
    off += 8
    assert struct.unpack_from("<Q", data, off)[0] == params.deposit
    off += 8
    assert struct.unpack_from("<I", data, off)[0] == params.grace_period
    off += 4
    count = struct.unpack_from("<I", data, off)[0]
    off += 4
    assert count == len(params.recipients)
    for entry in params.recipients:
        assert data[off : off + 32] == bytes(entry.recipient)
        off += 32
        assert struct.unpack_from("<H", data, off)[0] == entry.bps
        off += 2
    assert off == len(data)


def test_build_open_instruction_empty_recipients() -> None:
    params = _open_params()
    params.recipients = []
    ix = build_open_instruction(params)
    data = bytes(ix.data)
    # disc(1) + salt(8) + deposit(8) + grace(4) + len(4) == 25 bytes, count 0.
    assert len(data) == 25
    assert struct.unpack_from("<I", data, 21)[0] == 0


def test_open_params_default_token_program_is_spl_token() -> None:
    params = OpenChannelParams(
        payer=pk(1),
        payee=pk(2),
        mint=pk(3),
        authorized_signer=pk(4),
        salt=1,
        deposit=1,
        grace_period=1,
    )
    assert str(params.token_program) == "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
    assert params.recipients == []


def test_build_top_up_instruction_program_id_and_account_order() -> None:
    params = TopUpParams(payer=pk(1), channel=pk(2), mint=pk(3), amount=500_000, token_program=pk(7))
    ix = build_top_up_instruction(params)
    assert ix.program_id == PROGRAM_ID
    assert len(ix.accounts) == 6

    payer_ata, _ = find_associated_token_address(params.payer, params.mint, params.token_program)
    channel_ata, _ = find_associated_token_address(params.channel, params.mint, params.token_program)

    accounts = ix.accounts
    assert accounts[0].pubkey == params.payer
    assert accounts[0].is_signer is True
    assert accounts[0].is_writable is True
    assert accounts[1].pubkey == params.channel
    assert accounts[1].is_writable is True
    assert accounts[2].pubkey == payer_ata
    assert accounts[2].is_writable is True
    assert accounts[3].pubkey == channel_ata
    assert accounts[3].is_writable is True
    assert accounts[4].pubkey == params.mint
    assert accounts[5].pubkey == params.token_program
    assert [a.is_signer for a in accounts] == [True] + [False] * 5


def test_build_top_up_instruction_data_roundtrip() -> None:
    params = TopUpParams(payer=pk(1), channel=pk(2), mint=pk(3), amount=987_654_321)
    ix = build_top_up_instruction(params)
    data = bytes(ix.data)
    assert data[0] == 3
    assert len(data) == 9
    assert struct.unpack_from("<Q", data, 1)[0] == 987_654_321


def test_top_up_params_default_token_program_is_spl_token() -> None:
    params = TopUpParams(payer=pk(1), channel=pk(2), mint=pk(3), amount=1)
    assert str(params.token_program) == "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
