"""Typed helpers for the subscriptions program.

Program id, PDA derivations, instruction discriminators, the
``#[repr(C, packed)]`` instruction-data encoders, the instruction builders the
activation transaction is made of, and the account decoders the client
(``Plan``, ``SubscriptionAuthority``) and server (``SubscriptionDelegation``,
``SubscriptionAuthority``) read.

Mirrors ``rust/crates/kit/src/mpp/program/subscriptions.rs`` and the account
metas of the Codama-generated client it delegates to. All integers are
little-endian with no padding.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from solders.instruction import AccountMeta, Instruction  # type: ignore[import-untyped]
from solders.pubkey import Pubkey  # type: ignore[import-untyped]

#: Canonical mainnet program id of the subscriptions program.
SUBSCRIPTIONS_PROGRAM_ID = "De1egAFMkMWZSN5rYXRj9CAdheBamobVNubTsi9avR44"

SUBSCRIPTION_AUTHORITY_SEED = b"SubscriptionAuthority"
SUBSCRIPTION_DELEGATION_SEED = b"subscription"
PLAN_SEED = b"plan"
EVENT_AUTHORITY_SEED = b"event_authority"

ASSOCIATED_TOKEN_PROGRAM_ID = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"
SYSTEM_PROGRAM_ID = "11111111111111111111111111111111"
MEMO_PROGRAM_ID = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"
COMPUTE_BUDGET_PROGRAM_ID = "ComputeBudget111111111111111111111111111111"

# Single-byte instruction discriminators of the subscriptions program.
INSTRUCTION_INITIALIZE_SUBSCRIPTION_AUTHORITY = 0
INSTRUCTION_TRANSFER_SUBSCRIPTION = 10
INSTRUCTION_SUBSCRIBE = 11
INSTRUCTION_CANCEL_SUBSCRIPTION = 12

#: ``SubscribeData`` payload length (without the discriminator).
SUBSCRIBE_DATA_LEN = 8 + 1 + 32 + 8 + 8 + 8 + 8
#: ``TransferData`` payload length (without the discriminator).
TRANSFER_DATA_LEN = 8 + 32 + 32

#: ``SubscriptionAuthority``: discriminator(1) + user(32) + token_mint(32) +
#: payer(32) + bump(1) + init_id(8).
SUBSCRIPTION_AUTHORITY_LEN = 106
SUBSCRIPTION_AUTHORITY_INIT_ID_OFFSET = 98
#: ``SubscriptionDelegation``: header(107) + terms(24) + pulled(8) +
#: current_period_start_ts(8) + expires_at_ts(8).
SUBSCRIPTION_DELEGATION_LEN = 155
SUBSCRIPTION_DELEGATION_DISCRIMINATOR = 4
SUBSCRIPTION_DELEGATION_VERSION = 1

#: ``Plan`` account discriminator and ``PlanStatus::Active``.
PLAN_DISCRIMINATOR = 1
PLAN_STATUS_ACTIVE = 1
MAX_PLAN_DESTINATIONS = 4
MAX_PLAN_PULLERS = 4
PLAN_METADATA_URI_LEN = 128
#: discriminator + owner + bump + status + PlanData (plan_id, mint, terms,
#: end_ts, destinations, pullers, metadata_uri).
PLAN_ACCOUNT_MIN_LEN = 1 + 32 + 1 + 1 + 8 + 32 + 24 + 8 + 32 * 4 + 32 * 4 + 128

_ZERO_KEY = bytes(32)


class SubscriptionProgramError(ValueError):
    """A subscriptions-program value (pubkey, account data) is malformed."""


def parse_pubkey(value: str, field: str) -> Pubkey:
    """Parse a base58 pubkey, naming ``field`` in the error."""
    try:
        return Pubkey.from_string(value)
    except (TypeError, ValueError) as exc:
        raise SubscriptionProgramError(f"Invalid {field} pubkey: {exc}") from exc


def default_program_id() -> Pubkey:
    return Pubkey.from_string(SUBSCRIPTIONS_PROGRAM_ID)


def find_subscription_authority_pda(subscriber: Pubkey, mint: Pubkey, program_id: Pubkey) -> tuple[Pubkey, int]:
    """``SubscriptionAuthority`` PDA for ``(subscriber, mint)``."""
    return Pubkey.find_program_address([SUBSCRIPTION_AUTHORITY_SEED, bytes(subscriber), bytes(mint)], program_id)


def plan_id_seed(plan_id: int) -> bytes:
    """The 8-byte little-endian ``plan_id`` seed."""
    return plan_id.to_bytes(8, "little")


def find_plan_pda(owner: Pubkey, plan_id: bytes, program_id: Pubkey) -> tuple[Pubkey, int]:
    """``Plan`` PDA for ``(owner, plan_id seed)``."""
    return Pubkey.find_program_address([PLAN_SEED, bytes(owner), plan_id], program_id)


def find_event_authority_pda(program_id: Pubkey) -> tuple[Pubkey, int]:
    """The program's self-CPI ``event_authority`` PDA."""
    return Pubkey.find_program_address([EVENT_AUTHORITY_SEED], program_id)


def find_subscription_pda(plan_pda: Pubkey, subscriber: Pubkey, program_id: Pubkey) -> tuple[Pubkey, int]:
    """``SubscriptionDelegation`` PDA for ``(plan, subscriber)``."""
    return Pubkey.find_program_address([SUBSCRIPTION_DELEGATION_SEED, bytes(plan_pda), bytes(subscriber)], program_id)


def find_associated_token_address(owner: Pubkey, mint: Pubkey, token_program: Pubkey) -> Pubkey:
    """The associated token account of ``owner`` for ``mint`` under ``token_program``."""
    return Pubkey.find_program_address(
        [bytes(owner), bytes(token_program), bytes(mint)], Pubkey.from_string(ASSOCIATED_TOKEN_PROGRAM_ID)
    )[0]


# ── Instruction data ──────────────────────────────────────────────────────────


@dataclass(frozen=True)
class SubscribeData:
    """Wire shape of ``Subscribe`` instruction data."""

    plan_id: int
    plan_bump: int
    expected_mint: Pubkey
    expected_amount: int
    expected_period_hours: int
    expected_created_at: int
    expected_subscription_authority_init_id: int

    def to_bytes(self) -> bytes:
        return (
            bytes([INSTRUCTION_SUBSCRIBE])
            + struct.pack("<QB", self.plan_id, self.plan_bump)
            + bytes(self.expected_mint)
            + struct.pack(
                "<QQqq",
                self.expected_amount,
                self.expected_period_hours,
                self.expected_created_at,
                self.expected_subscription_authority_init_id,
            )
        )


@dataclass(frozen=True)
class TransferData:
    """Wire shape of ``TransferSubscription`` (and the other transfer) data."""

    amount: int
    delegator: Pubkey
    mint: Pubkey

    def to_bytes(self, discriminator: int = INSTRUCTION_TRANSFER_SUBSCRIPTION) -> bytes:
        return bytes([discriminator]) + struct.pack("<Q", self.amount) + bytes(self.delegator) + bytes(self.mint)

    @classmethod
    def from_bytes(cls, data: bytes) -> TransferData:
        """Decode discriminator-prefixed transfer data (exactly 73 bytes)."""
        if len(data) != 1 + TRANSFER_DATA_LEN:
            raise SubscriptionProgramError(f"transfer data is {len(data)} bytes, expected {1 + TRANSFER_DATA_LEN}")
        (amount,) = struct.unpack_from("<Q", data, 1)
        return cls(amount=amount, delegator=Pubkey.from_bytes(data[9:41]), mint=Pubkey.from_bytes(data[41:73]))


# ── Instruction builders ──────────────────────────────────────────────────────


def build_subscribe_ix(
    program_id: Pubkey,
    *,
    subscriber: Pubkey,
    merchant: Pubkey,
    plan_pda: Pubkey,
    subscription_pda: Pubkey,
    subscription_authority_pda: Pubkey,
    event_authority: Pubkey,
    data: SubscribeData,
    payer: Pubkey | None = None,
) -> Instruction:
    """``Subscribe``; the optional rent ``payer`` is a trailing signer."""
    accounts = [
        AccountMeta(subscriber, is_signer=True, is_writable=True),
        AccountMeta(merchant, is_signer=False, is_writable=False),
        AccountMeta(plan_pda, is_signer=False, is_writable=False),
        AccountMeta(subscription_pda, is_signer=False, is_writable=True),
        AccountMeta(subscription_authority_pda, is_signer=False, is_writable=False),
        AccountMeta(Pubkey.from_string(SYSTEM_PROGRAM_ID), is_signer=False, is_writable=False),
        AccountMeta(event_authority, is_signer=False, is_writable=False),
        AccountMeta(program_id, is_signer=False, is_writable=False),
    ]
    if payer is not None:
        accounts.append(AccountMeta(payer, is_signer=True, is_writable=True))
    return Instruction(program_id, data.to_bytes(), accounts)


def build_transfer_subscription_ix(
    program_id: Pubkey,
    *,
    subscription_pda: Pubkey,
    plan_pda: Pubkey,
    subscription_authority: Pubkey,
    delegator_ata: Pubkey,
    receiver_ata: Pubkey,
    caller: Pubkey,
    token_mint: Pubkey,
    token_program: Pubkey,
    event_authority: Pubkey,
    data: TransferData,
) -> Instruction:
    """``TransferSubscription``; ``caller`` is the signing puller."""
    accounts = [
        AccountMeta(subscription_pda, is_signer=False, is_writable=True),
        AccountMeta(plan_pda, is_signer=False, is_writable=False),
        AccountMeta(subscription_authority, is_signer=False, is_writable=False),
        AccountMeta(delegator_ata, is_signer=False, is_writable=True),
        AccountMeta(receiver_ata, is_signer=False, is_writable=True),
        AccountMeta(caller, is_signer=True, is_writable=False),
        AccountMeta(token_mint, is_signer=False, is_writable=False),
        AccountMeta(token_program, is_signer=False, is_writable=False),
        AccountMeta(event_authority, is_signer=False, is_writable=False),
        AccountMeta(program_id, is_signer=False, is_writable=False),
    ]
    return Instruction(program_id, data.to_bytes(INSTRUCTION_TRANSFER_SUBSCRIPTION), accounts)


def build_initialize_subscription_authority_ix(
    program_id: Pubkey,
    *,
    owner: Pubkey,
    subscription_authority: Pubkey,
    token_mint: Pubkey,
    user_ata: Pubkey,
    token_program: Pubkey,
) -> Instruction:
    """``InitSubscriptionAuthority``: discriminator only, the owner funds rent."""
    accounts = [
        AccountMeta(owner, is_signer=True, is_writable=True),
        AccountMeta(subscription_authority, is_signer=False, is_writable=True),
        AccountMeta(token_mint, is_signer=False, is_writable=False),
        AccountMeta(user_ata, is_signer=False, is_writable=True),
        AccountMeta(Pubkey.from_string(SYSTEM_PROGRAM_ID), is_signer=False, is_writable=False),
        AccountMeta(token_program, is_signer=False, is_writable=False),
    ]
    return Instruction(program_id, bytes([INSTRUCTION_INITIALIZE_SUBSCRIPTION_AUTHORITY]), accounts)


def build_create_idempotent_ata_ix(
    funder: Pubkey, ata: Pubkey, wallet: Pubkey, mint: Pubkey, token_program: Pubkey
) -> Instruction:
    """Associated Token Program ``CreateIdempotent`` (discriminator ``1``)."""
    accounts = [
        AccountMeta(funder, is_signer=True, is_writable=True),
        AccountMeta(ata, is_signer=False, is_writable=True),
        AccountMeta(wallet, is_signer=False, is_writable=False),
        AccountMeta(mint, is_signer=False, is_writable=False),
        AccountMeta(Pubkey.from_string(SYSTEM_PROGRAM_ID), is_signer=False, is_writable=False),
        AccountMeta(token_program, is_signer=False, is_writable=False),
    ]
    return Instruction(Pubkey.from_string(ASSOCIATED_TOKEN_PROGRAM_ID), bytes([1]), accounts)


def build_memo_ix(memo: str) -> Instruction:
    """An SPL Memo carrying ``memo`` with no signer accounts."""
    return Instruction(Pubkey.from_string(MEMO_PROGRAM_ID), memo.encode("utf-8"), [])


# ── Account decoders ──────────────────────────────────────────────────────────


@dataclass(frozen=True)
class PlanAccount:
    """A decoded ``Plan`` account (Borsh: the trailing bytes are ignored)."""

    discriminator: int
    owner: Pubkey
    bump: int
    status: int
    plan_id: int
    mint: Pubkey
    amount: int
    period_hours: int
    created_at: int
    end_ts: int
    destinations: tuple[Pubkey, ...]
    pullers: tuple[Pubkey, ...]

    @classmethod
    def from_bytes(cls, data: bytes) -> PlanAccount:
        if len(data) < PLAN_ACCOUNT_MIN_LEN:
            raise SubscriptionProgramError(
                f"Plan account is {len(data)} bytes, expected at least {PLAN_ACCOUNT_MIN_LEN}"
            )
        discriminator = data[0]
        owner = Pubkey.from_bytes(data[1:33])
        bump, status = data[33], data[34]
        (plan_id,) = struct.unpack_from("<Q", data, 35)
        mint = Pubkey.from_bytes(data[43:75])
        amount, period_hours, created_at, end_ts = struct.unpack_from("<QQqq", data, 75)
        offset = 107
        destinations = tuple(Pubkey.from_bytes(data[offset + 32 * i : offset + 32 * (i + 1)]) for i in range(4))
        offset += 128
        pullers = tuple(Pubkey.from_bytes(data[offset + 32 * i : offset + 32 * (i + 1)]) for i in range(4))
        return cls(
            discriminator=discriminator,
            owner=owner,
            bump=bump,
            status=status,
            plan_id=plan_id,
            mint=mint,
            amount=amount,
            period_hours=period_hours,
            created_at=created_at,
            end_ts=end_ts,
            destinations=destinations,
            pullers=pullers,
        )


def non_zero(keys: tuple[Pubkey, ...]) -> list[Pubkey]:
    """The set slots of a fixed-size Plan whitelist (default keys are empty)."""
    return [key for key in keys if bytes(key) != _ZERO_KEY]


def parse_subscription_authority_init_id(data: bytes) -> int:
    """``init_id`` of a ``SubscriptionAuthority`` (length-checked)."""
    if len(data) != SUBSCRIPTION_AUTHORITY_LEN:
        raise SubscriptionProgramError(
            f"Unexpected SubscriptionAuthority length: got {len(data)}, expected {SUBSCRIPTION_AUTHORITY_LEN}"
        )
    (init_id,) = struct.unpack_from("<q", data, SUBSCRIPTION_AUTHORITY_INIT_ID_OFFSET)
    return init_id


def decode_subscription_authority_init_id(data: bytes) -> int:
    """``init_id`` of a ``SubscriptionAuthority``, also checking its discriminator."""
    init_id = parse_subscription_authority_init_id(data)
    if data[0] != 0:
        raise SubscriptionProgramError(f"Invalid SubscriptionAuthority discriminator: {data[0]}")
    return init_id


@dataclass(frozen=True)
class SubscriptionDelegationView:
    """The fields of an on-chain ``SubscriptionDelegation`` the server checks."""

    subscriber: Pubkey
    plan_pda: Pubkey
    authority_init_id: int
    amount_per_period: int
    period_hours: int
    current_period_start_ts: int
    amount_pulled_in_period: int
    expires_at_ts: int


def decode_subscription_delegation(data: bytes) -> SubscriptionDelegationView:
    """Decode a ``SubscriptionDelegation`` account (exact length, v1 layout)."""
    if len(data) != SUBSCRIPTION_DELEGATION_LEN:
        raise SubscriptionProgramError(
            f"Unexpected SubscriptionDelegation length: {len(data)} bytes (expected {SUBSCRIPTION_DELEGATION_LEN})"
        )
    if data[0] != SUBSCRIPTION_DELEGATION_DISCRIMINATOR or data[1] != SUBSCRIPTION_DELEGATION_VERSION:
        raise SubscriptionProgramError(f"Invalid SubscriptionDelegation discriminator/version: {data[0]}/{data[1]}")
    subscriber = Pubkey.from_bytes(data[3:35])
    plan_pda = Pubkey.from_bytes(data[35:67])
    (init_id, amount, period_hours, _created_at, pulled, period_start, expires_at) = struct.unpack_from(
        "<qQQqQqq", data, 99
    )
    return SubscriptionDelegationView(
        subscriber=subscriber,
        plan_pda=plan_pda,
        authority_init_id=init_id,
        amount_per_period=amount,
        period_hours=period_hours,
        current_period_start_ts=period_start,
        amount_pulled_in_period=pulled,
        expires_at_ts=expires_at,
    )
