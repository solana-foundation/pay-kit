"""Client-side subscription activation and access credentials.

Activation builds one subscriber-signed transaction that creates the
``SubscriptionDelegation`` and collects the first period:
``[compute budget, init authority?, subscribe, transfer_subscription, memo?]``.
The on-chain ``Plan`` is read and checked against the challenge before
anything is signed, so a server cannot steer the subscriber into a plan whose
terms, destination or puller differ from what the challenge advertises.

The ``SubscriptionAuthority`` is initialized in the same transaction only when
it is missing, with the ``UNKNOWN_INIT_ID`` sentinel so ``subscribe`` binds the
authority created in that slot. No associated-token-account instruction is
emitted: the subscriber must already hold the mint.
"""

from __future__ import annotations

import base64
import time
from dataclasses import dataclass
from typing import Any

from solders.hash import Hash  # type: ignore[import-untyped]
from solders.instruction import Instruction  # type: ignore[import-untyped]
from solders.pubkey import Pubkey  # type: ignore[import-untyped]

from solana_pay_kit._paycore.solana import COMPUTE_BUDGET_PROGRAM, MEMO_PROGRAM
from solana_pay_kit._paycore.transaction import build_partially_signed_v0_transaction
from solana_pay_kit.protocols.mpp._subscriptions import (
    SUBSCRIPTIONS_PROGRAM_ID,
    UNKNOWN_INIT_ID,
    PlanView,
    authority_init_id,
    build_init_subscription_authority_ix,
    build_subscribe_ix,
    build_transfer_subscription_ix,
    decode_plan,
    find_subscription_authority_pda,
    find_subscription_pda,
    plan_problems,
    sign_message,
    signer_pubkey,
)
from solana_pay_kit.protocols.mpp.core.expires import parse_rfc3339
from solana_pay_kit.protocols.mpp.core.types import ChallengeEcho, PaymentChallenge, PaymentCredential
from solana_pay_kit.protocols.mpp.intents.subscription import (
    AccessPayload,
    ActivatePayload,
    PeriodUnit,
    SubscriptionAuthentication,
    SubscriptionMethodDetails,
    SubscriptionRequest,
    sign_subscription_authentication,
)

__all__ = [
    "SubscriptionActivation",
    "build_subscription_access_credential",
    "build_subscription_activation",
]

_MAX_MEMO_BYTES = 566


@dataclass(frozen=True)
class SubscriptionActivation:
    """An activation credential plus the bearer proof to keep for later access."""

    credential: PaymentCredential
    authentication: SubscriptionAuthentication
    subscription_delegation: str


def _same_on_the_wire(advertised: object, actual: object) -> bool:
    """Compare a methodDetails field with the chain at the precision canonical JSON keeps.

    RFC 8785 renders every JSON number as an ECMAScript double (ECMA-262 7.1.12.1),
    so a ``planIdNumeric`` above 2**53 reaches the client rounded from any server
    that canonicalizes the request. Comparing the digits would refuse those plans;
    comparing the doubles still pins about 16 significant digits, and the
    activation itself is built from the plan account, never from this number.
    """
    if isinstance(advertised, int) and isinstance(actual, int):
        return float(advertised) == float(actual)
    return advertised == actual


def _extension_problems(details: SubscriptionMethodDetails, request: SubscriptionRequest, plan: PlanView) -> list[str]:
    """Cross-check the optional Rust plan extensions against the chain; absent fields are skipped."""
    checks: list[tuple[str, object, object]] = [
        ("merchant", details.merchant, str(plan.owner)),
        ("recipient", details.recipient, request.recipient),
        ("amount", details.amount, request.amount),
        ("planIdNumeric", details.plan_id_numeric, plan.plan_id),
        ("planBump", details.plan_bump, plan.bump),
        ("expectedPeriodHours", details.expected_period_hours, plan.period_hours),
        ("expectedCreatedAt", details.expected_created_at, plan.created_at),
    ]
    return [
        f"methodDetails.{name} is {advertised!r} but the on-chain plan has {actual!r}"
        for name, advertised, actual in checks
        if advertised not in ("", None) and not _same_on_the_wire(advertised, actual)
    ]


async def build_subscription_activation(
    signer: Any,
    rpc: Any,
    challenge: PaymentChallenge,
    *,
    subscription_program: str = SUBSCRIPTIONS_PROGRAM_ID,
    compute_unit_limit: int = 400_000,
    compute_unit_price: int = 1,
    max_amount_base_units: int | None = None,
    expected_currency: str | None = None,
    expected_recipient: str | None = None,
    expected_period_unit: PeriodUnit | None = None,
    expected_period_count: int | None = None,
) -> SubscriptionActivation:
    """Check the challenge against the on-chain plan, then build and sign the activation credential.

    ``signer`` is a solana_pay_kit signer or a solders ``Keypair``; ``rpc`` is a
    :class:`~solana_pay_kit._paycore.rpc.SolanaRpc`-compatible client
    (``get_account_info`` returning ``(data, owner)`` and ``get_latest_blockhash``).
    ``subscription_program`` is the deployment the client trusts; a challenge
    naming another program is refused before any RPC call. The ``max_amount``
    and ``expected_*`` guards are the spec's amount and period verification:
    each one that is set must hold, and they are checked before any RPC call.
    A challenge whose ``subscriptionExpires`` has passed is always refused.
    """
    if challenge.method != "solana" or challenge.intent != "subscription":
        raise ValueError("challenge is not a solana subscription challenge")
    if challenge.is_expired():
        raise ValueError(f"challenge expired at {challenge.expires}")
    request = SubscriptionRequest.from_dict(challenge.decode_request())
    details = request.method_details
    if details.subscription_program != subscription_program:
        raise ValueError(f"challenge names subscriptions program {details.subscription_program}, not the trusted one")
    if len(request.external_id.encode("utf-8")) > _MAX_MEMO_BYTES:
        raise ValueError(f"externalId cannot exceed {_MAX_MEMO_BYTES} bytes")
    guards: list[tuple[str, bool]] = [
        (
            "amount exceeds max_amount_base_units",
            max_amount_base_units is not None and int(request.amount) > max_amount_base_units,
        ),
        ("currency", expected_currency is not None and request.currency != expected_currency),
        ("recipient", expected_recipient is not None and request.recipient != expected_recipient),
        ("periodUnit", expected_period_unit is not None and request.period_unit != expected_period_unit),
        ("periodCount", expected_period_count is not None and int(request.period_count) != expected_period_count),
    ]
    failed = [name for name, broken in guards if broken]
    if failed:
        raise ValueError("refusing to sign: challenge " + ", ".join(failed) + " does not match expectations")
    if request.subscription_expires and parse_rfc3339(request.subscription_expires).timestamp() <= time.time():
        raise ValueError(f"refusing to sign: subscriptionExpires {request.subscription_expires} has passed")

    program = Pubkey.from_string(subscription_program)
    subscriber = signer_pubkey(signer)
    plan_address = Pubkey.from_string(details.plan_address)
    account = await rpc.get_account_info(details.plan_address)
    if account is None:
        raise ValueError(f"plan {details.plan_address} does not exist")
    plan = decode_plan(account[0], account[1], subscription_program, plan_address)
    problems = plan_problems(
        plan,
        mint=details.mint,
        amount=int(request.amount),
        period_hours=request.period_hours(),
        recipient=request.recipient,
        puller=details.puller,
        now=int(time.time()),
    ) + _extension_problems(details, request, plan)
    if problems:
        raise ValueError(f"refusing to sign plan {details.plan_address}: " + "; ".join(problems))

    mint = Pubkey.from_string(details.mint)
    token_program = Pubkey.from_string(details.token_program)
    compute_budget = Pubkey.from_string(COMPUTE_BUDGET_PROGRAM)
    instructions = [
        Instruction(compute_budget, bytes([2]) + compute_unit_limit.to_bytes(4, "little"), []),
        Instruction(compute_budget, bytes([3]) + compute_unit_price.to_bytes(8, "little"), []),
    ]
    authority = await rpc.get_account_info(str(find_subscription_authority_pda(subscriber, mint, program)))
    init_id = authority_init_id(authority, subscription_program)
    if init_id is None:
        instructions.append(
            build_init_subscription_authority_ix(
                program=program, subscriber=subscriber, mint=mint, token_program=token_program
            )
        )
        init_id = UNKNOWN_INIT_ID

    fee_payer = Pubkey.from_string(details.fee_payer_key) if details.fee_payer else subscriber
    instructions.append(
        build_subscribe_ix(
            program=program,
            subscriber=subscriber,
            plan=plan,
            init_id=init_id,
            payer=fee_payer if details.fee_payer else None,
        )
    )
    instructions.append(
        build_transfer_subscription_ix(
            program=program,
            subscriber=subscriber,
            plan=plan,
            recipient=Pubkey.from_string(request.recipient),
            puller=Pubkey.from_string(details.puller),
            token_program=token_program,
            amount=plan.amount,
        )
    )
    if request.external_id:
        instructions.append(Instruction(Pubkey.from_string(MEMO_PROGRAM), request.external_id.encode("utf-8"), []))

    blockhash = details.recent_blockhash or (await rpc.get_latest_blockhash()).value.blockhash
    wire = build_partially_signed_v0_transaction(
        instructions,
        fee_payer,
        Hash.from_string(str(blockhash)),
        subscriber,
        lambda message: sign_message(signer, message),
    )
    delegation = str(find_subscription_pda(plan_address, subscriber, program))
    authentication = sign_subscription_authentication(challenge.id, delegation, signer)
    payload = ActivatePayload(transaction=base64.b64encode(wire).decode("ascii"), authentication=authentication)
    credential = PaymentCredential(
        challenge=challenge.to_echo(),
        payload=payload.to_dict(),
        source=f"did:pkh:solana:{details.network}:{subscriber}",
    )
    return SubscriptionActivation(
        credential=credential, authentication=authentication, subscription_delegation=delegation
    )


def build_subscription_access_credential(
    challenge: ChallengeEcho, subscription_delegation: str, authentication: SubscriptionAuthentication
) -> PaymentCredential:
    """Build the ``type="proof"`` access credential that echoes the activation challenge."""
    payload = AccessPayload(subscription_delegation=subscription_delegation, authentication=authentication)
    return PaymentCredential(challenge=challenge, payload=payload.to_dict())
