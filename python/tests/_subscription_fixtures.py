"""Subscriptions program account bytes, packed with ``struct`` at the program's offsets.

Independent of the codama-py layouts on purpose: these mirror the
``#[repr(C, packed)]`` structs in ``program/src/state`` at the pinned
``subscriptions_ref``, so a drift in the generated decoders shows up as a
field mismatch.
"""

from __future__ import annotations

import struct
from collections.abc import Sequence

from solders.pubkey import Pubkey

ZERO = bytes(32)


def pk(byte: int) -> Pubkey:
    """A pubkey whose 32 bytes are all ``byte``."""
    return Pubkey.from_bytes(bytes([byte] * 32))


def _slots(keys: Sequence[Pubkey]) -> bytes:
    return b"".join(bytes(key) for key in keys) + ZERO * (4 - len(keys))


def plan_bytes(
    *,
    owner: Pubkey,
    mint: Pubkey,
    destinations: Sequence[Pubkey],
    pullers: Sequence[Pubkey] = (),
    plan_id: int = 7,
    bump: int = 254,
    status: int = 1,
    amount: int = 1_000_000,
    period_hours: int = 720,
    created_at: int = 1_700_000_000,
    end_ts: int = 0,
) -> bytes:
    """491-byte ``Plan``: disc, owner, bump, status, then ``PlanData`` (456)."""
    return (
        bytes([1])
        + bytes(owner)
        + bytes([bump, status])
        + struct.pack("<Q", plan_id)
        + bytes(mint)
        + struct.pack("<QQqq", amount, period_hours, created_at, end_ts)
        + _slots(destinations)
        + _slots(pullers)
        + b"https://example.com/plan.json".ljust(128, b"\0")
    )


def delegation_bytes(
    *,
    subscriber: Pubkey,
    plan: Pubkey,
    init_id: int = 77,
    amount: int = 1_000_000,
    period_hours: int = 720,
    created_at: int = 1_700_000_000,
    amount_pulled_in_period: int = 1_000_000,
    current_period_start_ts: int = 1_700_000_100,
    expires_at_ts: int = 0,
) -> bytes:
    """155-byte v1 ``SubscriptionDelegation``: header (107), terms (24), billing state (24)."""
    return (
        bytes([4, 1, 255])
        + bytes(subscriber)
        + bytes(plan)
        + bytes(subscriber)  # header.payer
        + struct.pack("<q", init_id)
        + struct.pack("<QQq", amount, period_hours, created_at)
        + struct.pack("<Qqq", amount_pulled_in_period, current_period_start_ts, expires_at_ts)
    )


def authority_bytes(*, user: Pubkey, mint: Pubkey, init_id: int = 77) -> bytes:
    """106-byte ``SubscriptionAuthority``: disc, user, mint, payer, bump, ``init_id`` at 98."""
    return bytes([0]) + bytes(user) + bytes(mint) + bytes(user) + bytes([253]) + struct.pack("<q", init_id)
