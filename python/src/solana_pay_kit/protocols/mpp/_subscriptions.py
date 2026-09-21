"""On-chain glue for the subscriptions program.

Instruction data and account metas come from the codama-py generated client
under :mod:`solana_pay_kit.protocols.programs.subscriptions` (rendered from
``idl/subscriptions.json`` by ``skills/pay-sdk-implementation/codegen``). This
module adds what the generated client cannot do safely:

- PDA derivation against a caller-supplied program id. The generated helpers
  pin the canonical deployment and accept no override.
- Dropping the optional trailing ``payer`` meta. codama-py ignores the IDL's
  ``isOptional`` and always emits it; the program reads it as the rent payer
  whenever it is present.
- Account decoding with owner, length and discriminator checks. The IDL
  declares no account discriminators, so the generated ``decode`` checks none.

Byte layouts mirror the program at the pinned ``subscriptions_ref``
(``program/src/state``): ``Plan`` is 491 bytes, ``SubscriptionAuthority`` 106
and a v1 ``SubscriptionDelegation`` 155.
"""

from __future__ import annotations

import struct
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from solders.instruction import Instruction  # type: ignore[import-untyped]
from solders.pubkey import Pubkey  # type: ignore[import-untyped]

from solana_pay_kit._paycore.paymentchannels import find_associated_token_address
from solana_pay_kit._paycore.solana import SYSTEM_PROGRAM
from solana_pay_kit.protocols.programs.subscriptions.accounts.plan import Plan
from solana_pay_kit.protocols.programs.subscriptions.accounts.subscriptionAuthority import SubscriptionAuthority
from solana_pay_kit.protocols.programs.subscriptions.accounts.subscriptionDelegation import SubscriptionDelegation
from solana_pay_kit.protocols.programs.subscriptions.instructions.createPlan import CreatePlan
from solana_pay_kit.protocols.programs.subscriptions.instructions.initSubscriptionAuthority import (
    InitSubscriptionAuthority,
)
from solana_pay_kit.protocols.programs.subscriptions.instructions.subscribe import Subscribe
from solana_pay_kit.protocols.programs.subscriptions.instructions.transferSubscription import TransferSubscription
from solana_pay_kit.protocols.programs.subscriptions.types.planData import PlanData
from solana_pay_kit.protocols.programs.subscriptions.types.planTerms import PlanTerms
from solana_pay_kit.protocols.programs.subscriptions.types.subscribeData import SubscribeData
from solana_pay_kit.protocols.programs.subscriptions.types.transferData import TransferData

__all__ = [
    "IX_INIT_SA",
    "IX_SUBSCRIBE",
    "IX_TRANSFER_SUBSCRIPTION",
    "PLAN_STATUS_ACTIVE",
    "SUBSCRIPTIONS_PROGRAM_ID",
    "UNKNOWN_INIT_ID",
    "DelegationView",
    "PlanView",
    "authority_init_id",
    "build_create_plan_ix",
    "build_init_subscription_authority_ix",
    "build_subscribe_ix",
    "build_transfer_subscription_ix",
    "decode_authority_init_id",
    "decode_delegation",
    "decode_plan",
    "find_event_authority_pda",
    "find_plan_pda",
    "find_subscription_authority_pda",
    "find_subscription_pda",
    "plan_problems",
    "sign_message",
    "signer_pubkey",
]

#: Canonical subscriptions program deployment.
SUBSCRIPTIONS_PROGRAM_ID = "De1egAFMkMWZSN5rYXRj9CAdheBamobVNubTsi9avR44"

#: ``expected_subscription_authority_init_id`` sentinel (``i64::MIN``). The
#: program then requires the authority's ``init_id`` to equal the current slot,
#: which holds only when ``InitSubscriptionAuthority`` runs in the same
#: transaction. It is rejected for an authority created in an earlier slot.
UNKNOWN_INIT_ID = -(2**63)

#: Single-byte instruction discriminators.
IX_INIT_SA = 0
IX_TRANSFER_SUBSCRIPTION = 10
IX_SUBSCRIBE = 11

#: ``PlanStatus::Active``; ``0`` is ``Sunset`` (no new subscribers).
PLAN_STATUS_ACTIVE = 1

_PLAN_LEN = 491
_AUTHORITY_LEN = 106
_DELEGATION_V1_LEN = 155
_DISC_AUTHORITY = 0
_DISC_PLAN = 1
_DISC_SUBSCRIPTION_DELEGATION = 4
_DELEGATION_VERSION = 1
_PLAN_SLOTS = 4
_ZERO_KEY = Pubkey.default()
_SYSTEM_PROGRAM_KEY = Pubkey.from_string(SYSTEM_PROGRAM)

# Account metas the program requires before the optional trailing payer.
_SUBSCRIBE_BASE_METAS = 8
_INIT_SA_BASE_METAS = 6
_CREATE_PLAN_BASE_METAS = 5


@dataclass(frozen=True)
class PlanView:
    """Decoded ``Plan`` account; ``destinations`` and ``pullers`` hold the non-zero slots only."""

    address: Pubkey
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


@dataclass(frozen=True)
class DelegationView:
    """Decoded ``SubscriptionDelegation`` account (header, terms and billing state)."""

    subscriber: Pubkey
    plan: Pubkey
    init_id: int
    amount: int
    period_hours: int
    created_at: int
    amount_pulled_in_period: int
    current_period_start_ts: int
    expires_at_ts: int


def signer_pubkey(signer: Any) -> Pubkey:
    """Return the public key of a solana_pay_kit signer (base58 ``pubkey()``) or a solders ``Keypair``."""
    return Pubkey.from_string(str(signer.pubkey()))


def sign_message(signer: Any, message: bytes) -> bytes:
    """Sign ``message`` with a solana_pay_kit signer (``sign``) or a solders ``Keypair`` (``sign_message``)."""
    if callable(getattr(signer, "sign", None)):
        return bytes(signer.sign(message))
    return bytes(signer.sign_message(message))


def find_plan_pda(owner: Pubkey, plan_id: int, program: Pubkey) -> tuple[Pubkey, int]:
    """Derive the ``Plan`` PDA: ``["plan", owner, plan_id u64 LE]``."""
    return Pubkey.find_program_address([b"plan", bytes(owner), struct.pack("<Q", plan_id)], program)


def find_subscription_pda(plan: Pubkey, subscriber: Pubkey, program: Pubkey) -> Pubkey:
    """Derive the ``SubscriptionDelegation`` PDA: ``["subscription", plan, subscriber]``."""
    return Pubkey.find_program_address([b"subscription", bytes(plan), bytes(subscriber)], program)[0]


def find_subscription_authority_pda(subscriber: Pubkey, mint: Pubkey, program: Pubkey) -> Pubkey:
    """Derive the ``SubscriptionAuthority`` PDA: ``["SubscriptionAuthority", subscriber, mint]``."""
    return Pubkey.find_program_address([b"SubscriptionAuthority", bytes(subscriber), bytes(mint)], program)[0]


def find_event_authority_pda(program: Pubkey) -> Pubkey:
    """Derive the self-CPI event authority PDA: ``["event_authority"]``."""
    return Pubkey.find_program_address([b"event_authority"], program)[0]


def _without_payer(ix: Instruction, base_metas: int) -> Instruction:
    """Drop the trailing optional ``payer`` meta codama-py always emits."""
    accounts = list(ix.accounts)
    if len(accounts) != base_metas + 1:
        raise ValueError(f"expected {base_metas + 1} generated account metas, got {len(accounts)}")
    return Instruction(ix.program_id, bytes(ix.data), accounts[:base_metas])


def build_init_subscription_authority_ix(
    *, program: Pubkey, subscriber: Pubkey, mint: Pubkey, token_program: Pubkey
) -> Instruction:
    """Build ``InitSubscriptionAuthority`` funded by the subscriber (6 metas, data ``[0]``)."""
    ix = InitSubscriptionAuthority(
        {
            "owner": subscriber,
            "subscriptionAuthority": find_subscription_authority_pda(subscriber, mint, program),
            "tokenMint": mint,
            "userAta": find_associated_token_address(subscriber, mint, token_program)[0],
            "systemProgram": _SYSTEM_PROGRAM_KEY,
            "tokenProgram": token_program,
            "payer": subscriber,
        },
        program_id=program,
    )
    return _without_payer(ix, _INIT_SA_BASE_METAS)


def build_subscribe_ix(
    *, program: Pubkey, subscriber: Pubkey, plan: PlanView, init_id: int, payer: Pubkey | None
) -> Instruction:
    """Build ``Subscribe`` binding the live plan terms and ``init_id``; ``payer`` funds the delegation rent."""
    ix = Subscribe(
        {
            "subscribeData": SubscribeData(
                planId=plan.plan_id,
                planBump=plan.bump,
                expectedMint=plan.mint,
                expectedAmount=plan.amount,
                expectedPeriodHours=plan.period_hours,
                expectedCreatedAt=plan.created_at,
                expectedSubscriptionAuthorityInitId=init_id,
            )
        },
        {
            "subscriber": subscriber,
            "merchant": plan.owner,
            "planPda": plan.address,
            "subscriptionPda": find_subscription_pda(plan.address, subscriber, program),
            "subscriptionAuthorityPda": find_subscription_authority_pda(subscriber, plan.mint, program),
            "systemProgram": _SYSTEM_PROGRAM_KEY,
            "eventAuthority": find_event_authority_pda(program),
            "selfProgram": program,
            "payer": payer if payer is not None else subscriber,
        },
        program_id=program,
    )
    return ix if payer is not None else _without_payer(ix, _SUBSCRIBE_BASE_METAS)


def build_transfer_subscription_ix(
    *,
    program: Pubkey,
    subscriber: Pubkey,
    plan: PlanView,
    recipient: Pubkey,
    puller: Pubkey,
    token_program: Pubkey,
    amount: int,
) -> Instruction:
    """Build a puller-signed ``TransferSubscription`` from the subscriber ATA to the recipient ATA."""
    return TransferSubscription(
        {"transferData": TransferData(amount=amount, delegator=subscriber, mint=plan.mint)},
        {
            "subscriptionPda": find_subscription_pda(plan.address, subscriber, program),
            "planPda": plan.address,
            "subscriptionAuthority": find_subscription_authority_pda(subscriber, plan.mint, program),
            "delegatorAta": find_associated_token_address(subscriber, plan.mint, token_program)[0],
            "receiverAta": find_associated_token_address(recipient, plan.mint, token_program)[0],
            "caller": puller,
            "tokenMint": plan.mint,
            "tokenProgram": token_program,
            "eventAuthority": find_event_authority_pda(program),
            "selfProgram": program,
        },
        program_id=program,
    )


def _slots(keys: Sequence[Pubkey], name: str) -> list[Pubkey]:
    if len(keys) > _PLAN_SLOTS:
        raise ValueError(f"at most {_PLAN_SLOTS} {name} are allowed, got {len(keys)}")
    return [*keys, *([_ZERO_KEY] * (_PLAN_SLOTS - len(keys)))]


def build_create_plan_ix(
    *,
    program: Pubkey,
    owner: Pubkey,
    plan_id: int,
    mint: Pubkey,
    token_program: Pubkey,
    amount: int,
    period_hours: int,
    created_at: int,
    destinations: Sequence[Pubkey],
    pullers: Sequence[Pubkey] = (),
    end_ts: int = 0,
) -> Instruction:
    """Build an owner-funded ``CreatePlan`` (5 metas); used to bootstrap test and harness plans."""
    ix = CreatePlan(
        {
            "planData": PlanData(
                planId=plan_id,
                mint=mint,
                terms=PlanTerms(amount=amount, periodHours=period_hours, createdAt=created_at),
                endTs=end_ts,
                destinations=_slots(destinations, "destinations"),
                pullers=_slots(pullers, "pullers"),
                # Generated as list[int], but the layout is a 128-byte zero-padded UTF-8 string.
                metadataUri="",  # pyright: ignore[reportArgumentType]
            )
        },
        {
            "merchant": owner,
            "planPda": find_plan_pda(owner, plan_id, program)[0],
            "tokenMint": mint,
            "systemProgram": _SYSTEM_PROGRAM_KEY,
            "tokenProgram": token_program,
            "payer": owner,
        },
        program_id=program,
    )
    return _without_payer(ix, _CREATE_PLAN_BASE_METAS)


def _check_account(data: bytes, owner: str, program: str, name: str, discriminator: int) -> None:
    if owner != program:
        raise ValueError(f"{name} account is owned by {owner}, not the subscriptions program {program}")
    if not data or data[0] != discriminator:
        raise ValueError(f"{name} account has the wrong discriminator")


def decode_plan(data: bytes, owner: str, program: str, address: Pubkey) -> PlanView:
    """Decode a ``Plan`` account after checking owner, exact length and discriminator ``1``."""
    _check_account(data, owner, program, "Plan", _DISC_PLAN)
    if len(data) != _PLAN_LEN:
        raise ValueError(f"Plan account is {len(data)} bytes, expected {_PLAN_LEN}")
    # A non-UTF-8 metadataUri raises UnicodeDecodeError, itself a ValueError.
    plan = Plan.decode(data)
    terms = plan.data.terms
    return PlanView(
        address=address,
        owner=plan.owner,
        bump=plan.bump,
        status=plan.status,
        plan_id=plan.data.planId,
        mint=plan.data.mint,
        amount=terms.amount,
        period_hours=terms.periodHours,
        created_at=terms.createdAt,
        end_ts=plan.data.endTs,
        destinations=tuple(key for key in plan.data.destinations if key != _ZERO_KEY),
        pullers=tuple(key for key in plan.data.pullers if key != _ZERO_KEY),
    )


def decode_delegation(data: bytes, owner: str, program: str) -> DelegationView:
    """Decode a v1 ``SubscriptionDelegation`` after checking owner, length, discriminator ``4`` and version ``1``."""
    _check_account(data, owner, program, "SubscriptionDelegation", _DISC_SUBSCRIPTION_DELEGATION)
    if len(data) < _DELEGATION_V1_LEN:
        raise ValueError(f"SubscriptionDelegation account is {len(data)} bytes, expected {_DELEGATION_V1_LEN}")
    if data[1] != _DELEGATION_VERSION:
        raise ValueError(f"SubscriptionDelegation version {data[1]} is not supported")
    delegation = SubscriptionDelegation.decode(data)
    header = delegation.header
    return DelegationView(
        subscriber=header.delegator,
        plan=header.delegatee,
        init_id=header.initId,
        amount=delegation.terms.amount,
        period_hours=delegation.terms.periodHours,
        created_at=delegation.terms.createdAt,
        amount_pulled_in_period=delegation.amountPulledInPeriod,
        current_period_start_ts=delegation.currentPeriodStartTs,
        expires_at_ts=delegation.expiresAtTs,
    )


def authority_init_id(account: tuple[bytes, str] | None, program: str) -> int | None:
    """The authority's ``init_id``, or ``None`` when it is missing.

    Missing means absent, or a system-owned account with no data: the program
    initializes an authority PDA whose data is empty even when someone
    pre-funded it with lamports (``initialize_subscription_authority``).
    """
    if account is None or (account[1] == SYSTEM_PROGRAM and not account[0]):
        return None
    return decode_authority_init_id(account[0], account[1], program)


def decode_authority_init_id(data: bytes, owner: str, program: str) -> int:
    """Return a ``SubscriptionAuthority``'s ``init_id`` after checking owner, exact length and discriminator ``0``."""
    _check_account(data, owner, program, "SubscriptionAuthority", _DISC_AUTHORITY)
    if len(data) != _AUTHORITY_LEN:
        raise ValueError(f"SubscriptionAuthority account is {len(data)} bytes, expected {_AUTHORITY_LEN}")
    return SubscriptionAuthority.decode(data).initId


def plan_problems(
    plan: PlanView, *, mint: str, amount: int, period_hours: int, recipient: str, puller: str, now: int
) -> list[str]:
    """List every way ``plan`` fails the challenge terms; empty means the plan is usable."""
    problems: list[str] = []
    if plan.status != PLAN_STATUS_ACTIVE:
        problems.append("plan is not active")
    if plan.end_ts != 0 and now >= plan.end_ts:
        problems.append("plan has ended")
    if str(plan.mint) != mint:
        problems.append(f"plan mint {plan.mint} does not match {mint}")
    if plan.amount != amount:
        problems.append(f"plan amount {plan.amount} does not match {amount}")
    if plan.period_hours != period_hours:
        problems.append(f"plan period {plan.period_hours}h does not match {period_hours}h")
    if [str(key) for key in plan.destinations] != [recipient]:
        problems.append("plan destinations must be exactly the recipient")
    if puller != str(plan.owner) and puller not in {str(key) for key in plan.pullers}:
        problems.append(f"puller {puller} is neither the plan owner nor a plan puller")
    return problems
