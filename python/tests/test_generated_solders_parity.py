"""Cross-check the renderer's independent key/PDA runtime against solders."""

import random

import pytest
from solders.pubkey import Pubkey

from solana_pay_kit.protocols.programs.paymentchannels.shared import (
    PdaError,
    create_program_address,
    find_program_address,
)
from solana_pay_kit.protocols.programs.paymentchannels.shared import (
    Pubkey as GeneratedPubkey,
)


def test_generated_pubkeys_match_solders_base58() -> None:
    rng = random.Random(0xC0DA)
    # Cover leading-zero encoding as well as ordinary uniformly distributed keys.
    values = [bytes(n) + bytes([255]) * (32 - n) for n in range(33)]
    values.extend(rng.randbytes(32) for _ in range(256))
    for raw in values:
        native = Pubkey.from_bytes(raw)
        generated = GeneratedPubkey(raw)
        assert str(generated) == str(native)
        assert bytes(GeneratedPubkey.from_base58(str(native))) == bytes(native)
        assert bytes(Pubkey.from_string(str(generated))) == raw


def test_generated_pdas_match_solders() -> None:
    rng = random.Random(0xB0A5)
    bumps = set()
    for seed_count in range(16):
        for _ in range(8):
            program = Pubkey.from_bytes(rng.randbytes(32))
            seeds = [rng.randbytes(rng.randrange(33)) for _ in range(seed_count)]
            expected, expected_bump = Pubkey.find_program_address(seeds, program)
            generated, bump = find_program_address(seeds, GeneratedPubkey(bytes(program)))
            assert (bytes(generated), bump) == (bytes(expected), expected_bump)
            assert not expected.is_on_curve()
            assert create_program_address([*seeds, bytes([bump])], GeneratedPubkey(bytes(program))) == generated
            bumps.add(bump)
    # Exercise retries, not only the first off-curve candidate.
    assert len(bumps) > 1


@pytest.mark.parametrize("seeds", [[bytes(33)], [b""] * 17])
def test_generated_pdas_reject_invalid_seed_limits(seeds: list[bytes]) -> None:
    with pytest.raises(PdaError):
        create_program_address(seeds, GeneratedPubkey.default())
    with pytest.raises(PdaError):
        find_program_address(seeds, GeneratedPubkey.default())
