"""Client-side activation builder for the Solana subscription intent.

Builds the activation transaction of draft-solana-subscription-00::

    [compute_budget_*, create_ata_idempotent, subscribe,
     transfer_subscription, memo(externalId)?]

from the spec's request fields and the on-chain ``Plan`` only. The challenge
is parsed into :class:`SubscriptionTerms`, the Plan at
``methodDetails.planAddress`` is read and checked against those terms
(:meth:`VerifiedPlan.fetch`), and the activation is built from the
:class:`VerifiedPlan`: "Clients MUST NOT sign an activation transaction whose
on-chain Plan does not match the challenge." A missing
``SubscriptionAuthority`` is initialized in its own transaction first.

Mirrors ``rust/crates/kit/src/mpp/client/subscription.rs``.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Any, Protocol

from solana_keychain import SolanaSigner, TransactionSigner
from solders.hash import Hash  # type: ignore[import-untyped]
from solders.instruction import Instruction  # type: ignore[import-untyped]
from solders.pubkey import Pubkey  # type: ignore[import-untyped]

from solana_pay_kit._paycore.errors import InvalidChallengeError, PaymentError
from solana_pay_kit._paycore.solana import COMPUTE_BUDGET_PROGRAM
from solana_pay_kit._paycore.transaction import build_partially_signed_transaction
from solana_pay_kit._paycore.txv1 import TransactionVersionError, negotiate, v1_config
from solana_pay_kit.protocols.mpp.core.base64url import decode_json
from solana_pay_kit.protocols.mpp.core.types import PaymentChallenge, PaymentCredential
from solana_pay_kit.protocols.mpp.intents.subscription import (
    ActivatePayload,
    SubscriptionAccessPayload,
    SubscriptionAuthentication,
    SubscriptionRequest,
    SubscriptionTerms,
)
from solana_pay_kit.protocols.mpp.program.subscriptions import (
    PLAN_DISCRIMINATOR,
    PLAN_STATUS_ACTIVE,
    PlanAccount,
    SubscribeData,
    SubscriptionProgramError,
    TransferData,
    build_create_idempotent_ata_ix,
    build_initialize_subscription_authority_ix,
    build_memo_ix,
    build_subscribe_ix,
    build_transfer_subscription_ix,
    default_program_id,
    find_associated_token_address,
    find_event_authority_pda,
    find_plan_pda,
    find_subscription_authority_pda,
    find_subscription_pda,
    non_zero,
    parse_subscription_authority_init_id,
    plan_id_seed,
)

#: Default activation compute unit limit (up to three subscriptions-program
#: instructions plus token transfers) and price in micro-lamports.
DEFAULT_COMPUTE_UNIT_LIMIT = 400_000
DEFAULT_COMPUTE_UNIT_PRICE = 1


class SubscriptionRpc(Protocol):
    """The RPC surface the activation builder uses (``SolanaRpc`` satisfies it)."""

    async def get_account_info(self, address: str) -> tuple[bytes, str] | None: ...

    async def get_latest_blockhash(self) -> Any: ...

    async def send_raw_transaction(self, raw_tx: bytes) -> Any: ...

    async def await_confirmation(self, signature: str) -> None: ...


@dataclass(frozen=True)
class BuildSubscriptionActivationOptions:
    """Activation build options.

    ``max_tx_version`` caps the negotiated message version for signers that
    cannot sign version 1. ``subscription_authority_init_id`` skips the
    on-chain ``SubscriptionAuthority`` lookup (and its init broadcast).
    """

    max_tx_version: int | None = None
    compute_unit_limit: int | None = None
    compute_unit_price: int | None = None
    subscription_authority_init_id: int | None = None


def _check_trusted_program(terms: SubscriptionTerms, trusted: Pubkey | None) -> Pubkey:
    program_id = terms.subscription_program
    expected = trusted if trusted is not None else default_program_id()
    if program_id != expected:
        raise InvalidChallengeError(f"Untrusted subscription program {program_id} (expected {expected})")
    return program_id


@dataclass(frozen=True)
class VerifiedPlan:
    """The on-chain ``Plan`` a challenge names, checked against its terms.

    Only :meth:`fetch` and :meth:`verify` produce one, and the activation
    builder takes nothing else.
    """

    terms: SubscriptionTerms
    owner: Pubkey
    plan_id: int
    bump: int
    created_at: int

    @classmethod
    async def fetch(
        cls, rpc: SubscriptionRpc, terms: SubscriptionTerms, trusted_program: Pubkey | None = None
    ) -> VerifiedPlan:
        """Read the Plan at ``terms.plan_address`` and :meth:`verify` it.

        A challenge naming a program other than ``trusted_program`` (default:
        the canonical deployment) is refused before the RPC is asked anything.
        """
        _check_trusted_program(terms, trusted_program)
        account = await rpc.get_account_info(str(terms.plan_address))
        if account is None:
            raise InvalidChallengeError(
                f"Plan account not found at methodDetails.planAddress {terms.plan_address}: AccountNotFound"
            )
        data, owner = account
        return cls.verify(terms, trusted_program, Pubkey.from_string(owner), data)

    @classmethod
    def verify(
        cls, terms: SubscriptionTerms, trusted_program: Pubkey | None, owner_program: Pubkey, data: bytes
    ) -> VerifiedPlan:
        """Check a Plan account against ``terms`` (§Amount and Period Verification).

        Owned by the pinned program, active, at the PDA its owner and id
        derive, with the challenge's mint, amount and period, the puller as
        owner or listed puller, and exactly one destination equal to
        ``recipient``.
        """
        program_id = _check_trusted_program(terms, trusted_program)

        def mismatch(what: str) -> InvalidChallengeError:
            return InvalidChallengeError(f"The on-chain Plan does not match the challenge: {what}")

        if owner_program != program_id:
            raise mismatch("plan is not owned by methodDetails.subscriptionProgram")
        try:
            plan = PlanAccount.from_bytes(data)
        except SubscriptionProgramError as exc:
            raise InvalidChallengeError(f"Invalid Plan account: {exc}") from exc
        if plan.discriminator != PLAN_DISCRIMINATOR:
            raise mismatch("account is not a Plan")
        if plan.status != PLAN_STATUS_ACTIVE:
            raise mismatch("plan is not active")
        address, bump = find_plan_pda(plan.owner, plan_id_seed(plan.plan_id), program_id)
        if address != terms.plan_address or bump != plan.bump:
            raise mismatch("planAddress is not the plan's PDA")
        if plan.mint != terms.mint:
            raise mismatch("plan.mint differs from methodDetails.mint")
        if plan.amount != terms.amount:
            raise mismatch("plan amount differs from amount")
        if plan.period_hours != terms.period_hours:
            raise mismatch("plan period differs from the billing period")
        if terms.puller != plan.owner and terms.puller not in non_zero(plan.pullers):
            raise mismatch("methodDetails.puller is neither plan.owner nor in plan.pullers")
        if non_zero(plan.destinations) != [terms.recipient]:
            raise mismatch("plan.destinations must be exactly one address equal to recipient")
        return cls(terms=terms, owner=plan.owner, plan_id=plan.plan_id, bump=plan.bump, created_at=plan.created_at)


@dataclass(frozen=True)
class SubscriptionActivation:
    """The activation credential plus the proof to retain for later access."""

    credential: PaymentCredential
    authentication: SubscriptionAuthentication
    subscription_delegation: str


def solana_did(network: str, address: str) -> str:
    """``did:pkh:solana:<network>:<address>``."""
    return f"did:pkh:solana:{network}:{address}"


async def sign_subscription_authentication(
    signer: SolanaSigner, challenge_id: str, subscription_delegation: str
) -> SubscriptionAuthentication:
    """Sign the canonical reusable subscription authentication message."""
    unsigned = SubscriptionAuthentication(challenge_id=challenge_id, payer=str(signer.pubkey), signature="")
    signature = await signer.sign_message(unsigned.message_bytes(subscription_delegation))
    return SubscriptionAuthentication(challenge_id=challenge_id, payer=unsigned.payer, signature=str(signature))


def build_subscription_access_credential(
    challenge: PaymentChallenge, subscription_delegation: str, authentication: SubscriptionAuthentication
) -> PaymentCredential:
    """A later-access credential from the proof retained at activation."""
    payload = SubscriptionAccessPayload(subscription_delegation=subscription_delegation, authentication=authentication)
    return PaymentCredential(challenge=challenge.to_echo(), payload=payload.to_dict())


def parse_subscription_challenge(challenge: PaymentChallenge) -> SubscriptionTerms:
    """The challenge's request parsed into terms; any refusal is an invalid challenge."""
    try:
        return SubscriptionRequest.from_dict(decode_json(challenge.request)).terms()
    except ValueError as exc:  # SubscriptionError, malformed base64url / JSON
        raise InvalidChallengeError(str(exc)) from exc


async def build_subscription_activation_credential(
    signer: TransactionSigner,
    rpc: SubscriptionRpc,
    challenge: PaymentChallenge,
    options: BuildSubscriptionActivationOptions | None = None,
    *,
    trusted_program: Pubkey | None = None,
) -> SubscriptionActivation:
    """Build and sign the activation for ``challenge`` and bind a reusable proof.

    Parses the request, reads and verifies the on-chain Plan (trusting only
    ``trusted_program``, default the canonical deployment), then builds and
    signs. Raises :class:`InvalidChallengeError` for a challenge the client
    must refuse to sign.
    """
    terms = parse_subscription_challenge(challenge)
    plan = await VerifiedPlan.fetch(rpc, terms, trusted_program)
    delegation = str(find_subscription_pda(terms.plan_address, signer.pubkey, terms.subscription_program)[0])
    transaction = await build_subscription_activation_transaction(signer, rpc, plan, options)
    authentication = await sign_subscription_authentication(signer, challenge.id, delegation)
    payload = ActivatePayload(type="transaction", transaction=transaction, authentication=authentication)
    credential = PaymentCredential(
        challenge=challenge.to_echo(),
        payload=payload.to_dict(),
        source=solana_did(terms.network, str(signer.pubkey)),
    )
    return SubscriptionActivation(
        credential=credential, authentication=authentication, subscription_delegation=delegation
    )


def _budget_instructions(unit_limit: int, unit_price: int) -> list[Instruction]:
    program = Pubkey.from_string(COMPUTE_BUDGET_PROGRAM)
    return [
        Instruction(program, bytes([2]) + unit_limit.to_bytes(4, "little"), []),
        Instruction(program, bytes([3]) + unit_price.to_bytes(8, "little"), []),
    ]


async def build_subscription_activation_transaction(
    signer: TransactionSigner,
    rpc: SubscriptionRpc,
    plan: VerifiedPlan,
    options: BuildSubscriptionActivationOptions | None = None,
) -> str:
    """Build and sign the activation transaction; returns standard base64.

    When the challenge sets ``feePayer: true`` the transaction is partially
    signed and the server completes the fee-payer signature.
    """
    options = options or BuildSubscriptionActivationOptions()
    terms = plan.terms
    program_id = terms.subscription_program
    subscriber = signer.pubkey
    mint = terms.mint
    token_program = terms.token_program
    sponsor = terms.fee_payer

    subscription_authority = find_subscription_authority_pda(subscriber, mint, program_id)[0]
    subscription_pda = find_subscription_pda(terms.plan_address, subscriber, program_id)[0]
    event_authority = find_event_authority_pda(program_id)[0]
    subscriber_ata = find_associated_token_address(subscriber, mint, token_program)
    recipient_ata = find_associated_token_address(terms.recipient, mint, token_program)

    try:
        version = negotiate(terms.transaction_versions, options.max_tx_version)
    except TransactionVersionError as exc:
        raise InvalidChallengeError(str(exc)) from exc

    unit_limit = options.compute_unit_limit if options.compute_unit_limit is not None else DEFAULT_COMPUTE_UNIT_LIMIT
    unit_price = options.compute_unit_price if options.compute_unit_price is not None else DEFAULT_COMPUTE_UNIT_PRICE

    blockhash = terms.recent_blockhash
    if blockhash is None:
        response = await rpc.get_latest_blockhash()
        blockhash = Hash.from_string(str(response.value.blockhash))

    init_id = options.subscription_authority_init_id
    if init_id is None:
        init_id = await _ensure_subscription_authority_init_id(
            signer, rpc, program_id, mint, subscriber_ata, subscription_authority, token_program, blockhash
        )

    instructions: list[Instruction] = [
        build_create_idempotent_ata_ix(
            sponsor if sponsor is not None else subscriber, subscriber_ata, subscriber, mint, token_program
        ),
        build_subscribe_ix(
            program_id,
            subscriber=subscriber,
            merchant=plan.owner,
            plan_pda=terms.plan_address,
            subscription_pda=subscription_pda,
            subscription_authority_pda=subscription_authority,
            event_authority=event_authority,
            payer=sponsor,
            data=SubscribeData(
                plan_id=plan.plan_id,
                plan_bump=plan.bump,
                expected_mint=mint,
                expected_amount=terms.amount,
                expected_period_hours=terms.period_hours,
                expected_created_at=plan.created_at,
                expected_subscription_authority_init_id=init_id,
            ),
        ),
        build_transfer_subscription_ix(
            program_id,
            subscription_pda=subscription_pda,
            plan_pda=terms.plan_address,
            subscription_authority=subscription_authority,
            delegator_ata=subscriber_ata,
            receiver_ata=recipient_ata,
            caller=terms.puller,
            token_mint=mint,
            token_program=token_program,
            event_authority=event_authority,
            data=TransferData(amount=terms.amount, delegator=subscriber, mint=mint),
        ),
    ]
    if terms.external_id is not None:
        instructions.append(build_memo_ix(terms.external_id))

    fee_payer = sponsor if sponsor is not None else subscriber
    if version == 0:
        raw = await build_partially_signed_transaction(
            _budget_instructions(unit_limit, unit_price) + instructions, fee_payer, blockhash, signer
        )
    else:
        raw = await build_partially_signed_transaction(
            instructions, fee_payer, blockhash, signer, version=1, config=v1_config(unit_limit, unit_price)
        )
    return base64.b64encode(raw).decode("ascii")


async def _ensure_subscription_authority_init_id(
    signer: TransactionSigner,
    rpc: SubscriptionRpc,
    program_id: Pubkey,
    mint: Pubkey,
    subscriber_ata: Pubkey,
    subscription_authority: Pubkey,
    token_program: Pubkey,
    blockhash: Hash,
) -> int:
    """The ``SubscriptionAuthority::init_id`` the activation must pin.

    When the authority does not exist yet, a subscriber-paid init transaction
    is broadcast and confirmed first: its ``init_id`` is set at the landing
    slot, which a same-transaction ``Subscribe`` cannot predict.
    """
    account = await rpc.get_account_info(str(subscription_authority))
    if account is None:
        init = build_initialize_subscription_authority_ix(
            program_id,
            owner=signer.pubkey,
            subscription_authority=subscription_authority,
            token_mint=mint,
            user_ata=subscriber_ata,
            token_program=token_program,
        )
        raw = await build_partially_signed_transaction([init], signer.pubkey, blockhash, signer)
        try:
            sent = await rpc.send_raw_transaction(raw)
            await rpc.await_confirmation(str(sent.value))
        except PaymentError as exc:
            raise PaymentError(f"Failed to broadcast SubscriptionAuthority init: {exc}", code=exc.code) from exc
        account = await rpc.get_account_info(str(subscription_authority))
        if account is None:
            raise PaymentError("SubscriptionAuthority still missing after init broadcast", code="transaction-not-found")
    data, owner = account
    if owner != str(program_id):
        raise InvalidChallengeError(
            f"SubscriptionAuthority {subscription_authority} is not owned by the subscriptions program"
        )
    try:
        return parse_subscription_authority_init_id(data)
    except SubscriptionProgramError as exc:
        raise InvalidChallengeError(str(exc)) from exc
