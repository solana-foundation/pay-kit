"""Subscriptions program account bytes and a small simulated chain for the tests.

Account bytes are packed with ``struct`` at the program's offsets,
independent of the codama-py layouts on purpose: these mirror the
``#[repr(C, packed)]`` structs in ``program/src/state`` at the pinned
``subscriptions_ref``, so a drift in the generated decoders shows up as a
field mismatch. ``FakeRpc`` stands in for ``SolanaRpc``.
"""

from __future__ import annotations

import struct
from collections.abc import Callable, Sequence
from types import SimpleNamespace
from typing import Any

from solders.hash import Hash
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.transaction import VersionedTransaction

from solana_pay_kit._paycore.errors import PaymentError
from solana_pay_kit._paycore.paymentchannels import find_associated_token_address
from solana_pay_kit._paycore.solana import TOKEN_PROGRAM
from solana_pay_kit.protocols.mpp._subscriptions import (
    SUBSCRIPTIONS_PROGRAM_ID,
    decode_authority_init_id,
    decode_delegation,
    find_plan_pda,
)
from solana_pay_kit.protocols.mpp.core.base64url import encode_json
from solana_pay_kit.protocols.mpp.core.types import PaymentChallenge

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


# -- a small simulated chain for the client and server tests -------------------

SECRET = "subscription-test-secret-that-is-long-enough"
PROGRAM_ID = SUBSCRIPTIONS_PROGRAM_ID
PROGRAM = Pubkey.from_string(PROGRAM_ID)
TOKEN = Pubkey.from_string(TOKEN_PROGRAM)
SERVER = Keypair.from_seed(bytes([1] * 32))  # plan owner, puller and fee payer
SUBSCRIBER = Keypair.from_seed(bytes([2] * 32))
MINT = pk(20)
RECIPIENT = pk(21)
PLAN_ID = 7
PLAN, PLAN_BUMP = find_plan_pda(SERVER.pubkey(), PLAN_ID, PROGRAM)
AMOUNT = 1_000_000
PERIOD_HOURS = 720
CREATED_AT = 1_700_000_000
BLOCKHASH = str(Hash(bytes([9] * 32)))


def ok_status() -> dict[str, Any]:
    """A confirmed, successful ``getSignatureStatuses`` entry."""
    return {"err": None, "confirmationStatus": "confirmed"}


class FakeRpc:
    """In-memory stand-in for :class:`SolanaRpc`: accounts, sends and signature statuses."""

    def __init__(self) -> None:
        self.accounts: dict[str, tuple[bytes, str]] = {}
        self.sent: list[bytes] = []
        self.statuses: dict[str, dict[str, Any] | None] = {}
        self.history_statuses: dict[str, dict[str, Any]] = {}  # answered only with search_history
        self.blockhash = BLOCKHASH
        self.blockhash_valid = True
        self.hidden_reads: dict[str, int] = {}
        self.on_send: Callable[[bytes], None] | None = None
        self.send_error: Exception | None = None

    def put(self, address: Pubkey | str, data: bytes, owner: Pubkey | str = PROGRAM_ID) -> None:
        self.accounts[str(address)] = (data, str(owner))

    async def get_account_info(self, address: str, commitment: str = "confirmed") -> tuple[bytes, str] | None:
        if self.hidden_reads.get(address, 0) > 0:
            self.hidden_reads[address] -= 1
            return None
        return self.accounts.get(address)

    async def get_latest_blockhash(self, commitment: str = "confirmed") -> Any:
        return SimpleNamespace(value=SimpleNamespace(blockhash=self.blockhash))

    async def send_raw_transaction(self, raw: bytes) -> Any:
        if self.send_error is not None:
            raise self.send_error
        self.sent.append(raw)
        if self.on_send is not None:
            self.on_send(raw)
        return SimpleNamespace(value=str(VersionedTransaction.from_bytes(raw).signatures[0]))

    async def await_confirmation(self, signature: str) -> None:
        self.statuses.setdefault(signature, ok_status())

    async def get_signature_statuses(self, signatures: list[str], search_history: bool = False) -> list[Any]:
        history = self.history_statuses if search_history else {}
        return [self.statuses.get(signature) or history.get(signature) for signature in signatures]

    async def is_blockhash_valid(self, blockhash: str, commitment: str = "finalized") -> bool:
        return self.blockhash_valid


def install_plan(rpc: FakeRpc, **overrides: Any) -> None:
    """Publish the default plan: owner and puller ``SERVER``, one destination ``RECIPIENT``."""
    fields: dict[str, Any] = {
        "owner": SERVER.pubkey(),
        "mint": MINT,
        "destinations": [RECIPIENT],
        "plan_id": PLAN_ID,
        "bump": PLAN_BUMP,
        "amount": AMOUNT,
        "period_hours": PERIOD_HOURS,
        "created_at": CREATED_AT,
    }
    fields.update(overrides)
    rpc.put(PLAN, plan_bytes(**fields))


def request_dict(**overrides: Any) -> dict[str, Any]:
    """The challenge request a server issues for the default plan."""
    details: dict[str, Any] = {
        "planAddress": str(PLAN),
        "mint": str(MINT),
        "decimals": 6,
        "tokenProgram": TOKEN_PROGRAM,
        "puller": str(SERVER.pubkey()),
        "subscriptionProgram": PROGRAM_ID,
        "network": "localnet",
    }
    details.update(overrides.pop("methodDetails", {}))
    request: dict[str, Any] = {
        "amount": str(AMOUNT),
        "currency": str(MINT),
        "periodUnit": "day",
        "periodCount": "30",
        "recipient": str(RECIPIENT),
        "methodDetails": details,
    }
    request.update(overrides)
    return request


def challenge_for(request: dict[str, Any], *, expires: str = "2099-01-01T00:00:00Z") -> PaymentChallenge:
    """An HMAC-bound subscription challenge for ``request``."""
    return PaymentChallenge.with_secret_key(
        secret_key=SECRET,
        realm="subscriptions.test",
        method="solana",
        intent="subscription",
        request=encode_json(request),
        expires=expires,
    )


NOW = 1_750_000_000
PERIOD_SECONDS = PERIOD_HOURS * 3600
AUTHORITY_SLOT = 555


def mint_bytes(decimals: int = 6, initialized: bool = True) -> bytes:
    """An 82-byte SPL mint with ``decimals`` at 44 and ``is_initialized`` at 45."""
    data = bytearray(82)
    data[44] = decimals
    data[45] = int(initialized)
    return bytes(data)


def install_chain(rpc: FakeRpc) -> None:
    """The default plan, its mint and the recipient's token account."""
    install_plan(rpc)
    rpc.put(MINT, mint_bytes(), TOKEN)
    rpc.put(find_associated_token_address(RECIPIENT, MINT, TOKEN)[0], bytes(165), TOKEN)


class ChainSim:
    """Applies subscriptions instructions to ``FakeRpc`` accounts the way the program does.

    ``init`` creates the authority at ``AUTHORITY_SLOT``; ``subscribe`` creates the
    delegation at ``clock()``; ``transfer_subscription`` rolls the period over by
    whole periods and enforces the per-period cap (raising like a failed preflight).
    Writes apply only when every instruction succeeds.
    """

    def __init__(self, rpc: FakeRpc, clock: Callable[[], int] = lambda: NOW) -> None:
        self.rpc = rpc
        self.clock = clock
        rpc.on_send = self

    def __call__(self, raw: bytes) -> None:
        tx = VersionedTransaction.from_bytes(raw)
        keys = list(tx.message.account_keys)
        writes: dict[str, bytes] = {}

        def current(address: Pubkey) -> tuple[bytes, str]:
            return (writes[str(address)], PROGRAM_ID) if str(address) in writes else self.rpc.accounts[str(address)]

        for ix in tx.message.instructions:
            if keys[ix.program_id_index] != PROGRAM:
                continue
            data = bytes(ix.data)
            accounts = [keys[index] for index in ix.accounts]
            if data[0] == 0:
                writes[str(accounts[1])] = authority_bytes(user=accounts[0], mint=accounts[2], init_id=AUTHORITY_SLOT)
            elif data[0] == 11:
                amount, hours, created_at = struct.unpack_from("<QQq", data, 42)
                writes[str(accounts[3])] = delegation_bytes(
                    subscriber=accounts[0],
                    plan=accounts[2],
                    init_id=decode_authority_init_id(*current(accounts[4]), PROGRAM_ID),
                    amount=amount,
                    period_hours=hours,
                    created_at=created_at,
                    amount_pulled_in_period=0,
                    current_period_start_ts=self.clock(),
                )
            elif data[0] == 10:
                state = decode_delegation(*current(accounts[0]), PROGRAM_ID)
                start, pulled = state.current_period_start_ts, state.amount_pulled_in_period
                period = state.period_hours * 3600
                if self.clock() >= start + period:
                    start += (self.clock() - start) // period * period
                    pulled = 0
                amount = struct.unpack_from("<Q", data, 1)[0]
                if pulled + amount > state.amount:
                    raise PaymentError("simulation failed: AmountExceedsPeriodLimit", code="payment_invalid")
                writes[str(accounts[0])] = delegation_bytes(
                    subscriber=state.subscriber,
                    plan=state.plan,
                    init_id=state.init_id,
                    amount=state.amount,
                    period_hours=state.period_hours,
                    created_at=state.created_at,
                    amount_pulled_in_period=pulled + amount,
                    current_period_start_ts=start,
                    expires_at_ts=state.expires_at_ts,
                )
        for address, data in writes.items():
            self.rpc.put(address, data)
