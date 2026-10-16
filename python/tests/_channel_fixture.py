"""Pack on-chain channel fixtures independently of the generated serializer."""

import struct

from solders.pubkey import Pubkey


def channel_account_bytes(
    *,
    payer: Pubkey,
    payee: Pubkey,
    authorized_signer: Pubkey,
    mint: Pubkey,
    rent_payer: Pubkey,
    deposit: int,
    salt: int = 0,
    grace_period: int = 900,
    open_slot: int = 0,
    status: int = 0,
    distribution_hash: bytes = bytes(32),
) -> bytes:
    """Encode the fixed 256-byte layout from the vendored payment-channels IDL.

    The four header bytes are discriminator (Channel = 1), version, bump, status.
    Settlement watermarks and closure timestamps are zero in these open fixtures.
    """
    assert len(distribution_hash) == 32
    header = struct.pack("<BBBBQQQQqqI", 1, 1, 255, status, salt, deposit, 0, 0, 0, 0, grace_period)
    keys = b"".join(bytes(key) for key in (payer, payee, authorized_signer, mint, rent_payer))
    wire = header + distribution_hash + keys + struct.pack("<Q", open_slot)
    assert len(wire) == 256
    return wire
