"""A deterministic subscription world: plan, authority, keys and an in-memory RPC."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any

from solana_keychain import MemorySigner
from solders.hash import Hash
from solders.keypair import Keypair
from solders.pubkey import Pubkey

from solana_pay_kit._paycore.solana import TOKEN_PROGRAM
from solana_pay_kit.protocols.mpp.program.subscriptions import (
    SUBSCRIPTIONS_PROGRAM_ID,
    find_plan_pda,
    find_subscription_authority_pda,
    find_subscription_pda,
    plan_id_seed,
)

PROGRAM = Pubkey.from_string(SUBSCRIPTIONS_PROGRAM_ID)
MINT = Pubkey.from_string("4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU")
BLOCKHASH = "EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N"
SECRET = "subscription-test-binding-secret"
REALM = "api.example.com"
AMOUNT = 10_000_000
PLAN_ID = 7
CREATED_AT = 1_700_000_000
INIT_ID = 77
NOW = 1_900_000_000


def keypair(seed: int) -> Keypair:
    return Keypair.from_seed(bytes([seed]) * 32)


SUBSCRIBER = keypair(7)
MERCHANT = keypair(8)
RECIPIENT = keypair(9)
SPONSOR = keypair(10)
PLAN, PLAN_BUMP = find_plan_pda(MERCHANT.pubkey(), plan_id_seed(PLAN_ID), PROGRAM)


def plan_data(
    *,
    owner: Pubkey | None = None,
    discriminator: int = 1,
    status: int = 1,
    bump: int | None = None,
    plan_id: int = PLAN_ID,
    mint: Pubkey = MINT,
    amount: int = AMOUNT,
    period_hours: int = 720,
    destinations: list[Pubkey] | None = None,
    pullers: list[Pubkey] | None = None,
) -> bytes:
    owner = owner or MERCHANT.pubkey()
    dests = destinations if destinations is not None else [RECIPIENT.pubkey()]
    pulls = pullers or []
    out = bytes([discriminator]) + bytes(owner) + bytes([PLAN_BUMP if bump is None else bump, status])
    out += struct.pack("<Q", plan_id) + bytes(mint) + struct.pack("<QQqq", amount, period_hours, CREATED_AT, 0)
    for slots in (dests, pulls):
        padded = list(slots) + [Pubkey.default()] * (4 - len(slots))
        out += b"".join(bytes(key) for key in padded)
    return out + bytes(128)


def authority_data(init_id: int = INIT_ID, discriminator: int = 0) -> bytes:
    owner = SUBSCRIBER.pubkey()
    return (
        bytes([discriminator]) + bytes(owner) + bytes(MINT) + bytes(owner) + bytes([255]) + struct.pack("<q", init_id)
    )


def delegation_data(
    *,
    subscriber: Pubkey | None = None,
    plan: Pubkey = PLAN,
    init_id: int = INIT_ID,
    amount: int = AMOUNT,
    period_hours: int = 720,
    pulled: int = AMOUNT,
    period_start: int = NOW - 3600,
    expires_at: int = 0,
    discriminator: int = 4,
    version: int = 1,
) -> bytes:
    subscriber = subscriber or SUBSCRIBER.pubkey()
    out = bytes([discriminator, version, 254]) + bytes(subscriber) + bytes(plan) + bytes(subscriber)
    return out + struct.pack("<qQQqQqq", init_id, amount, period_hours, CREATED_AT, pulled, period_start, expires_at)


def authority_address(subscriber: Pubkey | None = None) -> Pubkey:
    return find_subscription_authority_pda(subscriber or SUBSCRIBER.pubkey(), MINT, PROGRAM)[0]


def delegation_address(subscriber: Pubkey | None = None) -> Pubkey:
    return find_subscription_pda(PLAN, subscriber or SUBSCRIBER.pubkey(), PROGRAM)[0]


def method_details(**overrides: Any) -> dict[str, Any]:
    details: dict[str, Any] = {
        "planAddress": str(PLAN),
        "mint": str(MINT),
        "tokenProgram": TOKEN_PROGRAM,
        "decimals": 6,
        "puller": str(MERCHANT.pubkey()),
        "subscriptionProgram": SUBSCRIPTIONS_PROGRAM_ID,
        "network": "devnet",
        "recentBlockhash": BLOCKHASH,
    }
    details.update(overrides)
    return {key: value for key, value in details.items() if value is not None}


def request(**overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "amount": str(AMOUNT),
        "currency": str(MINT),
        "periodUnit": "day",
        "periodCount": "30",
        "recipient": str(RECIPIENT.pubkey()),
        "methodDetails": method_details(),
    }
    body.update(overrides)
    return {key: value for key, value in body.items() if value is not None}


class _Value:
    def __init__(self, value: Any) -> None:
        self.value = value


class _Blockhash:
    def __init__(self, blockhash: str) -> None:
        self.blockhash = blockhash


@dataclass
class FakeRpc:
    """``get_account_info`` over a dict; a broadcast creates the authority."""

    accounts: dict[str, tuple[bytes, str]] = field(default_factory=dict)
    sent: list[bytes] = field(default_factory=list)
    create_on_send: bool = True

    async def get_account_info(self, address: str) -> tuple[bytes, str] | None:
        return self.accounts.get(address)

    async def get_latest_blockhash(self) -> Any:
        return _Value(_Blockhash(BLOCKHASH))

    async def send_raw_transaction(self, raw_tx: bytes) -> Any:
        self.sent.append(raw_tx)
        if self.create_on_send:
            self.accounts[str(authority_address())] = (authority_data(), SUBSCRIPTIONS_PROGRAM_ID)
        return _Value("5" * 64)

    async def await_confirmation(self, signature: str) -> None:
        return None


def world(*, authority: bool = True, delegation: bool = False, **plan: Any) -> FakeRpc:
    rpc = FakeRpc()
    rpc.accounts[str(PLAN)] = (plan_data(**plan), SUBSCRIPTIONS_PROGRAM_ID)
    if authority:
        rpc.accounts[str(authority_address())] = (authority_data(), SUBSCRIPTIONS_PROGRAM_ID)
    if delegation:
        rpc.accounts[str(delegation_address())] = (delegation_data(), SUBSCRIPTIONS_PROGRAM_ID)
    return rpc


def signer(kp: Keypair | None = None) -> MemorySigner:
    return MemorySigner(kp or SUBSCRIBER)


def blockhash() -> Hash:
    return Hash.from_string(BLOCKHASH)
