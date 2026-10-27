"""Server-side verification for the Solana subscription intent.

Issues 402 challenges that pin the subscriber to an on-chain ``Plan`` and a
per-period cadence, verifies activation credentials offline (the challenge
binding, the route's terms, the activation payload and bearer proof, the
activation scope and the fee-payer co-signature), and checks on-chain that a
subscriber holds a live, paid subscription (the stateless active-subscription
check).

Mirrors ``rust/crates/kit/src/mpp/server/subscription.rs``. Broadcasting the
activation and keeping the bearer-proof binding store are the host's job:
:meth:`SubscriptionServer.verify_activation` returns the co-signed
transaction ready to broadcast.
"""

from __future__ import annotations

import base64
import re
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal, Protocol

from solana_keychain import TransactionSigner
from solders.pubkey import Pubkey  # type: ignore[import-untyped]

from solana_pay_kit._paycore.errors import PaymentError, VerificationError
from solana_pay_kit._paycore.network_check import check_network_blockhash
from solana_pay_kit._paycore.solana import default_rpc_url
from solana_pay_kit._paycore.txv1 import (
    DEFAULT_ACCEPTED_VERSIONS,
    AnyTransaction,
    MessageV1,
    TransactionVersionError,
    check_envelope,
    check_v1_budget_caps,
    decode_transaction,
    parse_transaction_versions,
    populate,
    signed_message_bytes,
)
from solana_pay_kit.protocols.mpp.core import expires as expires_mod
from solana_pay_kit.protocols.mpp.core.base64url import decode_json, encode_json
from solana_pay_kit.protocols.mpp.core.challenge import compute_challenge_id, constant_time_equal
from solana_pay_kit.protocols.mpp.core.types import PaymentChallenge, PaymentCredential, _parse_rfc3339
from solana_pay_kit.protocols.mpp.intents.subscription import (
    SubscriptionAccessPayload,
    SubscriptionAuthentication,
    SubscriptionError,
    SubscriptionMethodDetails,
    SubscriptionPeriodUnit,
    SubscriptionRequest,
    decode_activate_payload,
    period_hours_for,
)
from solana_pay_kit.protocols.mpp.program.subscriptions import (
    ASSOCIATED_TOKEN_PROGRAM_ID,
    COMPUTE_BUDGET_PROGRAM_ID,
    INSTRUCTION_INITIALIZE_SUBSCRIPTION_AUTHORITY,
    INSTRUCTION_SUBSCRIBE,
    INSTRUCTION_TRANSFER_SUBSCRIPTION,
    MEMO_PROGRAM_ID,
    SUBSCRIPTIONS_PROGRAM_ID,
    SYSTEM_PROGRAM_ID,
    SubscriptionDelegationView,
    SubscriptionProgramError,
    TransferData,
    decode_subscription_authority_init_id,
    decode_subscription_delegation,
    find_associated_token_address,
    find_event_authority_pda,
    find_subscription_authority_pda,
    find_subscription_pda,
    parse_pubkey,
)

METHOD_NAME = "solana"
INTENT_NAME = "subscription"

#: Activation compute caps: the unit limit, and the unit price when the
#: server sponsors fees / when the subscriber pays.
MAX_ACTIVATION_COMPUTE_UNITS = 400_000
MAX_SPONSORED_COMPUTE_UNIT_PRICE = 10_000
MAX_UNSPONSORED_COMPUTE_UNIT_PRICE = 5_000_000

_U64_TEXT = re.compile(r"\+?[0-9]+")
_U64_MAX = (1 << 64) - 1


# ── Errors ────────────────────────────────────────────────────────────────────


def _mismatch(message: str) -> VerificationError:
    """The echoed challenge or credential does not belong to this route."""
    return VerificationError(message, code="challenge-route-mismatch")


def _invalid(message: str) -> VerificationError:
    """The credential payload is malformed or out of scope."""
    return VerificationError(message, code="invalid-payload")


def _failed(message: str) -> VerificationError:
    """The on-chain state does not satisfy the subscription."""
    return VerificationError(message, code="transaction-failed")


def _not_found(message: str) -> VerificationError:
    return VerificationError(message, code="transaction-not-found")


def _internal(message: str) -> VerificationError:
    return VerificationError(message, code="invalid-config")


class SubscriptionAccountRpc(Protocol):
    """The RPC surface the active-subscription check reads (``SolanaRpc`` fits)."""

    async def get_account_info(self, address: str) -> tuple[bytes, str] | None: ...


# ── Configuration ─────────────────────────────────────────────────────────────


@dataclass
class SubscriptionConfig:
    """One subscription route.

    ``plan_id`` is the base58 ``Plan`` PDA. ``amount_base_units`` is REQUIRED:
    credentials whose challenged terms differ from the route's are refused, so
    a proof for a cheaper route sharing the Plan cannot unlock this one.
    ``challenge_binding_secret`` and ``realm`` are REQUIRED. With
    ``fee_payer`` the server sponsors activation fees as ``fee_payer_pubkey``
    (or the ``fee_payer_signer``'s key); the signer co-signs at verify time.
    """

    plan_id: str
    mint: str
    token_program: str
    puller: str
    recipient: str
    amount_base_units: str
    challenge_binding_secret: str
    realm: str
    decimals: int = 6
    period_unit: SubscriptionPeriodUnit = "day"
    period_count: int = 30
    subscription_expires: str | None = None
    network: str = "mainnet"
    program_id: str | None = None
    rpc_url: str | None = None
    rpc: SubscriptionAccountRpc | None = None
    fee_payer: bool = False
    fee_payer_signer: TransactionSigner | None = None
    fee_payer_pubkey: str | None = None
    #: Transaction message versions accepted and advertised (default ``[0]``).
    transaction_versions: Sequence[int] = DEFAULT_ACCEPTED_VERSIONS
    plan_id_numeric: int | None = None
    plan_bump: int | None = None
    plan_created_at: int | None = None
    description: str | None = None


# ── Verification results ──────────────────────────────────────────────────────


@dataclass
class PreparedActivation:
    """An activation that passed every offline check.

    ``transaction`` is co-signed by the sponsor when fee sponsorship is
    configured and is ready to broadcast.
    """

    request: SubscriptionRequest
    subscriber: Pubkey
    transaction: AnyTransaction
    authentication: SubscriptionAuthentication
    kind: Literal["activation"] = "activation"

    def transaction_base64(self) -> str:
        return base64.b64encode(bytes(self.transaction)).decode("ascii")


@dataclass
class PreparedAccess:
    """A ``type="proof"`` access payload that parsed for this route.

    Unverified: its signature, payer and binding are not checked. Only the
    private conformance hook returns it; never grant access on it.
    """

    request: SubscriptionRequest
    access: SubscriptionAccessPayload
    kind: Literal["access"] = "access"


@dataclass
class _Route:
    program_id: Pubkey
    plan: Pubkey
    mint: Pubkey
    token_program: Pubkey
    puller: Pubkey
    recipient: Pubkey
    period_hours: int
    fee_payer_key: Pubkey | None = None


def _parse_u64_text(value: str) -> int | None:
    if not _U64_TEXT.fullmatch(value):
        return None
    parsed = int(value)
    return parsed if parsed <= _U64_MAX else None


def _now_seconds() -> int:
    return int(datetime.now(UTC).timestamp())


class SubscriptionServer:
    """Server-side handler for the Solana subscription intent."""

    def __init__(self, config: SubscriptionConfig) -> None:
        for name in (
            "plan_id",
            "mint",
            "token_program",
            "puller",
            "recipient",
            "challenge_binding_secret",
            "realm",
        ):
            if not getattr(config, name):
                raise ValueError(f"{name} is required")
        plan = parse_pubkey(config.plan_id, "plan_id")
        mint = parse_pubkey(config.mint, "mint")
        token_program = parse_pubkey(config.token_program, "token_program")
        puller = parse_pubkey(config.puller, "puller")
        recipient = parse_pubkey(config.recipient, "recipient")
        period_hours = period_hours_for(config.period_unit, config.period_count)
        amount = _parse_u64_text(config.amount_base_units)
        if amount is None or amount == 0:
            raise ValueError("amount_base_units must be a positive integer")
        if config.subscription_expires is not None:
            try:
                expires_at = _parse_rfc3339(config.subscription_expires)
            except ValueError as exc:
                raise ValueError(f"subscription_expires must be RFC3339: {exc}") from exc
            if expires_at <= datetime.now(UTC):
                raise ValueError("subscription_expires must be in the future")
        self._program_id_text = config.program_id or SUBSCRIPTIONS_PROGRAM_ID
        program_id = parse_pubkey(self._program_id_text, "program_id")
        accepted = parse_transaction_versions(list(config.transaction_versions), field_name="transaction_versions")
        self._accepted: tuple[int, ...] = tuple(accepted or ())
        fee_payer_key: Pubkey | None = None
        if config.fee_payer:
            key_text = config.fee_payer_pubkey
            if key_text is None and config.fee_payer_signer is not None:
                key_text = str(config.fee_payer_signer.pubkey)
            if key_text is not None:
                fee_payer_key = parse_pubkey(key_text, "fee_payer_key")
        self._config = config
        self._route = _Route(
            program_id=program_id,
            plan=plan,
            mint=mint,
            token_program=token_program,
            puller=puller,
            recipient=recipient,
            period_hours=period_hours,
            fee_payer_key=fee_payer_key,
        )
        self._rpc: SubscriptionAccountRpc | None = config.rpc

    # ── Accessors ──

    @property
    def realm(self) -> str:
        return self._config.realm

    @property
    def program_id(self) -> str:
        return self._program_id_text

    @property
    def plan_id(self) -> str:
        return self._config.plan_id

    @property
    def accepted_versions(self) -> tuple[int, ...]:
        return self._accepted

    def _rpc_client(self) -> SubscriptionAccountRpc:
        if self._rpc is None:
            from solana_pay_kit._paycore.rpc import SolanaRpc

            self._rpc = SolanaRpc(self._config.rpc_url or default_rpc_url(self._config.network))
        return self._rpc

    # ── Challenge ──

    def subscription_challenge(
        self,
        amount_base_units: str,
        *,
        recent_blockhash: str | None = None,
        expires: str | None = None,
    ) -> PaymentChallenge:
        """A 402 challenge for this route's amount per period.

        ``recent_blockhash`` (a pre-fetched blockhash) lets the client skip its
        own ``getLatestBlockhash``; ``expires`` defaults to five minutes.
        """
        if not amount_base_units:
            raise ValueError("amount is required")
        if _parse_u64_text(amount_base_units) is None:
            raise ValueError(f"Invalid amount: {amount_base_units}")
        if amount_base_units != self._config.amount_base_units:
            raise ValueError(
                f"Amount {amount_base_units} does not match the configured amount {self._config.amount_base_units}"
            )
        config = self._config
        fee_payer_key = str(self._route.fee_payer_key) if self._route.fee_payer_key is not None else None
        advertised = None if self._accepted == DEFAULT_ACCEPTED_VERSIONS else list(self._accepted)
        details = SubscriptionMethodDetails(
            plan_address=config.plan_id,
            mint=config.mint,
            token_program=config.token_program,
            decimals=config.decimals,
            puller=config.puller,
            merchant=config.puller,
            recipient=config.recipient,
            amount=amount_base_units,
            subscription_program=self._program_id_text,
            network=config.network,
            fee_payer=config.fee_payer,
            fee_payer_key=fee_payer_key,
            transaction_versions=advertised,
            recent_blockhash=recent_blockhash,
            plan_id_numeric=config.plan_id_numeric,
            plan_bump=config.plan_bump,
            expected_period_hours=self._route.period_hours,
            expected_created_at=config.plan_created_at,
        )
        request = SubscriptionRequest(
            amount=amount_base_units,
            currency=config.mint,
            period_unit=config.period_unit,
            period_count=str(config.period_count),
            recipient=config.recipient,
            subscription_expires=config.subscription_expires,
            description=config.description,
            method_details=details.to_dict(),
        )
        return PaymentChallenge.with_secret_key(
            secret_key=config.challenge_binding_secret,
            realm=config.realm,
            method=METHOD_NAME,
            intent=INTENT_NAME,
            request=encode_json(request.to_dict()),
            expires=expires if expires is not None else expires_mod.minutes(5),
            description=config.description or "",
        )

    # ── Verify ──

    async def verify_activation(self, credential: PaymentCredential, *, now: int | None = None) -> PreparedActivation:
        """The offline half of activation verification, at ``now`` (unix seconds).

        Checks the challenge binding and expiry, the request against this
        route, the activation payload and bearer proof, the activation scope,
        the fee-payer co-signature and the fee payer's signature over the
        message. Nothing here reads the chain, consumes replay state or
        broadcasts: the host reserves the activation signature, broadcasts
        ``PreparedActivation.transaction``, confirms the landed delegation
        matches the payer, plan and terms, and stores the proof binding.

        A ``type="proof"`` access credential is refused: accepting one needs
        the binding a confirmed activation writes, which this server does not
        keep. Hosts verify access against their own binding store, then call
        :meth:`verify_active_subscription`.
        """
        prepared = await self._prepare_pre_broadcast(credential, now=now)
        if isinstance(prepared, PreparedAccess):
            raise _invalid(
                'type="proof" access credentials need the activation binding store, '
                "which this server does not keep; verify_activation accepts activations only"
            )
        return prepared

    async def _prepare_pre_broadcast(
        self, credential: PaymentCredential, *, now: int | None = None
    ) -> PreparedActivation | PreparedAccess:
        """Conformance hook (mirrors Rust ``testkit::verify_activation_pre_broadcast``).

        Not a payment verifier: a ``PreparedAccess`` result means only that a
        ``type="proof"`` payload parsed for this route; its signature, payer
        and binding are NOT checked. Never grant access on it.
        """
        moment = datetime.fromtimestamp(now if now is not None else _now_seconds(), UTC)
        prepared = await self._prepare_credential(credential, moment)
        if isinstance(prepared, PreparedActivation):
            verify_fee_payer_signature(prepared.transaction)
        return prepared

    async def _prepare_credential(
        self, credential: PaymentCredential, now: datetime
    ) -> PreparedActivation | PreparedAccess:
        config = self._config
        challenge = credential.challenge
        expected_id = compute_challenge_id(
            config.challenge_binding_secret,
            config.realm,
            challenge.method,
            challenge.intent,
            challenge.request,
            challenge.expires,
            challenge.digest,
            challenge.opaque,
        )
        if not constant_time_equal(challenge.id, expected_id):
            raise VerificationError(
                "Challenge HMAC mismatch — this server did not issue the echoed challenge",
                code="challenge-mismatch",
            )
        if challenge.method != METHOD_NAME:
            raise _mismatch(
                f"Credential method `{challenge.method}` does not match this server (expected `{METHOD_NAME}`)"
            )
        if challenge.intent != INTENT_NAME:
            raise _mismatch(f"Credential intent `{challenge.intent}` is not a subscription")
        if challenge.realm != config.realm:
            raise _mismatch(
                f"Credential realm `{challenge.realm}` does not match this server (expected `{config.realm}`)"
            )

        try:
            request = SubscriptionRequest.from_dict(decode_json(challenge.request))
        except ValueError as exc:
            raise _invalid(f"Failed to decode request: {exc}") from exc
        if request.currency != config.mint:
            raise _mismatch(
                f"Credential mint `{request.currency}` does not match this server (expected `{config.mint}`)"
            )
        if request.recipient != config.recipient:
            raise _mismatch("Credential recipient does not match this server")
        if request.method_details is None:
            raise _invalid("Subscription request is missing methodDetails")
        try:
            details = SubscriptionMethodDetails.from_json(request.method_details)
            details.validate()
        except SubscriptionError as exc:
            raise _invalid(str(exc)) from exc
        if details.subscription_program != self._program_id_text:
            raise _mismatch("methodDetails.subscriptionProgram does not match this server")
        if details.plan_address != config.plan_id:
            raise _mismatch("methodDetails.planAddress does not match this server")
        if details.network != config.network:
            raise VerificationError(
                f"methodDetails.network does not match this server (expected `{config.network}`)",
                code="wrong-network",
            )
        try:
            request_hours: int | None = request.period_hours()
        except SubscriptionError:
            request_hours = None
        if request.amount != config.amount_base_units or request_hours != self._route.period_hours:
            raise _mismatch("Subscription terms do not match this server")

        payload = credential.payload
        if isinstance(payload, dict) and payload.get("type") == "proof":
            try:
                access = SubscriptionAccessPayload.from_dict(payload)
            except SubscriptionError as exc:
                raise _invalid(f"Failed to decode proof payload: {exc}") from exc
            return PreparedAccess(request=request, access=access)

        if challenge.expires:
            try:
                expired = _parse_rfc3339(challenge.expires) <= now
            except ValueError:
                expired = True
            if expired:
                raise _invalid("Subscription activation challenge has expired")
        validate_activation_subscription_expiry(request.subscription_expires, now)

        try:
            activate = decode_activate_payload(payload)
        except SubscriptionError as exc:
            raise _invalid(str(exc)) from exc
        cosigner = config.fee_payer_signer if config.fee_payer else None
        if activate.type == "signature" and cosigner is not None:
            raise _invalid('type="signature" credentials cannot be used with fee sponsorship')
        if activate.type == "signature":
            raise _invalid(
                'Push-mode (type="signature") activation is not yet supported by this server. '
                'Use type="transaction" for v0.'
            )
        if activate.type != "transaction":
            raise _invalid(f"Unsupported payload type `{activate.type}` (expected `transaction` or `signature`)")
        if activate.transaction is None:
            raise _invalid('type="transaction" payload missing `transaction` field')

        tx = decode_base64_transaction(activate.transaction)
        check_network_blockhash(config.network, str(tx.message.recent_blockhash))
        try:
            check_envelope(tx, self._accepted)
            check_v1_budget_caps(
                tx.message,
                MAX_ACTIVATION_COMPUTE_UNITS,
                MAX_SPONSORED_COMPUTE_UNIT_PRICE if config.fee_payer else MAX_UNSPONSORED_COMPUTE_UNIT_PRICE,
            )
        except TransactionVersionError as exc:
            raise _invalid(str(exc)) from exc
        subscriber = self._extract_subscriber(tx)
        verify_credential_source(credential.source, subscriber)
        delegation = find_subscription_pda(self._route.plan, subscriber, self._route.program_id)[0]
        verify_activation_authentication(activate.authentication, challenge.id, subscriber, delegation)
        self._validate_activation_scope(tx, request, subscriber)
        if cosigner is not None:
            tx = await co_sign_as_fee_payer(tx, cosigner)
        return PreparedActivation(
            request=request, subscriber=subscriber, transaction=tx, authentication=activate.authentication
        )

    def _extract_subscriber(self, tx: AnyTransaction) -> Pubkey:
        """The subscriber: ``account_keys[0]``, or under fee sponsorship the
        first required signer that is neither the sponsor nor the puller."""
        keys = list(tx.message.account_keys)
        if not keys:
            raise _invalid("VersionedTransaction has no account keys")
        puller = self._route.puller
        if self._config.fee_payer:
            sponsor = self._route.fee_payer_key
            if sponsor is None:
                raise _invalid("fee_payer=true requires a configured fee-payer pubkey")
            if keys[0] != sponsor:
                raise _invalid(f"Activation transaction fee payer must be {sponsor}")
            required = int(tx.message.header.num_required_signatures)
            for key in keys[1:required]:
                if key not in (puller, sponsor):
                    return key
            raise _invalid("Could not identify subscriber among transaction signers")
        if keys[0] == puller:
            raise _invalid("Subscriber cannot equal the server puller")
        return keys[0]

    def _validate_activation_scope(self, tx: AnyTransaction, request: SubscriptionRequest, subscriber: Pubkey) -> None:
        """Static scope check (§Authorization Scope Verification).

        Exactly one ``subscribe`` and one ``transfer_subscription`` on the
        pinned program, in that order, bound to this route; optional compute
        budget, one idempotent subscriber ATA creation before ``subscribe``
        and the ``externalId`` memo; nothing else. The required signers are
        exactly the fee payer, the subscriber and the puller.
        """
        route = self._route
        config = self._config
        message = tx.message
        keys = list(message.account_keys)
        if config.fee_payer:
            expected = config.fee_payer_signer.pubkey if config.fee_payer_signer is not None else route.fee_payer_key
            if expected is None:
                raise _invalid("fee_payer=true requires a configured fee-payer pubkey")
            if not keys or keys[0] != expected:
                raise _invalid(f"Activation transaction fee payer must be {expected}")

        compute_budget = Pubkey.from_string(COMPUTE_BUDGET_PROGRAM_ID)
        ata_program = Pubkey.from_string(ASSOCIATED_TOKEN_PROGRAM_ID)
        memo_program = Pubkey.from_string(MEMO_PROGRAM_ID)
        system_program = Pubkey.from_string(SYSTEM_PROGRAM_ID)
        program_id = route.program_id
        expected_subscription = find_subscription_pda(route.plan, subscriber, program_id)[0]
        expected_authority = find_subscription_authority_pda(subscriber, route.mint, program_id)[0]
        sponsor = keys[0] if config.fee_payer and keys else None

        subscribe_idx: int | None = None
        transfer_idx: int | None = None
        ata_idx: int | None = None
        saw_memo = saw_limit = saw_price = False
        for index, ix in enumerate(message.instructions):
            program_index = int(ix.program_id_index)
            if program_index >= len(keys):
                raise _invalid("Activation instruction has an invalid program index")
            program = keys[program_index]
            data = bytes(ix.data)
            accounts = list(bytes(ix.accounts))

            def account(position: int, accounts: list[int] = accounts) -> Pubkey | None:
                if position >= len(accounts) or accounts[position] >= len(keys):
                    return None
                return keys[accounts[position]]

            if program == compute_budget:
                if len(data) == 5 and data[0] == 2:
                    if saw_limit:
                        raise _invalid("Activation tx contains multiple compute-unit-limit instructions")
                    saw_limit = True
                    if int.from_bytes(data[1:5], "little") > MAX_ACTIVATION_COMPUTE_UNITS:
                        raise _invalid(f"Activation compute unit limit exceeds {MAX_ACTIVATION_COMPUTE_UNITS}")
                elif len(data) == 9 and data[0] == 3:
                    if saw_price:
                        raise _invalid("Activation tx contains multiple compute-unit-price instructions")
                    saw_price = True
                    cap = MAX_SPONSORED_COMPUTE_UNIT_PRICE if config.fee_payer else MAX_UNSPONSORED_COMPUTE_UNIT_PRICE
                    if int.from_bytes(data[1:9], "little") > cap:
                        raise _invalid("Activation compute unit price exceeds cap")
                else:
                    raise _invalid("Unsupported compute-budget instruction in activation tx")
                continue

            if program == memo_program:
                try:
                    memo: str | None = data.decode("utf-8")
                except UnicodeDecodeError:
                    memo = None
                if saw_memo or request.external_id is None or request.external_id != memo:
                    raise _invalid("Activation memo does not match challenge externalId")
                saw_memo = True
                continue

            if program == ata_program:
                if ata_idx is not None or data != b"\x01" or len(accounts) != 6:
                    raise _invalid("Only one idempotent subscriber ATA creation is allowed in activation tx")
                if (
                    account(2) != subscriber
                    or account(3) != route.mint
                    or account(4) != system_program
                    or account(5) != route.token_program
                ):
                    raise _invalid("ATA creation does not match the activation subscriber and mint")
                ata_idx = index
                continue

            if program != program_id:
                raise _invalid(f"Unsupported program {program} in activation tx")
            if not data:
                raise _invalid("Activation tx contains an empty subscriptions-program instruction")
            discriminator = data[0]
            if discriminator == INSTRUCTION_INITIALIZE_SUBSCRIPTION_AUTHORITY:
                raise _invalid("initialize_subscription_authority is not allowed in an activation tx")
            if discriminator == INSTRUCTION_SUBSCRIBE:
                if subscribe_idx is not None:
                    raise _invalid("Activation tx contains multiple subscribe instructions")
                if len(accounts) == 8:
                    payer_ok = True
                elif len(accounts) == 9:
                    payer_ok = sponsor is not None and account(8) == sponsor
                else:
                    payer_ok = False
                if (
                    not payer_ok
                    or account(0) != subscriber
                    or account(2) != route.plan
                    or account(3) != expected_subscription
                    or account(4) != expected_authority
                    or account(5) != system_program
                    or account(7) != program_id
                ):
                    raise _invalid("subscribe accounts do not match the challenged activation")
                subscribe_idx = index
            elif discriminator == INSTRUCTION_TRANSFER_SUBSCRIPTION:
                if transfer_idx is not None:
                    raise _invalid("Activation tx contains multiple transfer_subscription instructions")
                if len(accounts) != 10 or len(data) != 73:
                    raise _invalid("transfer_subscription does not match the Codama v0.5 schema")
                recipient = parse_pubkey(request.recipient, "recipient")
                expected_delegator_ata = find_associated_token_address(subscriber, route.mint, route.token_program)
                expected_receiver_ata = find_associated_token_address(recipient, route.mint, route.token_program)
                if (
                    account(0) != expected_subscription
                    or account(1) != route.plan
                    or account(2) != expected_authority
                    or account(3) != expected_delegator_ata
                    or account(4) != expected_receiver_ata
                    or account(5) != route.puller
                    or account(6) != route.mint
                    or account(7) != route.token_program
                    or account(8) != find_event_authority_pda(program_id)[0]
                    or account(9) != program_id
                ):
                    raise _invalid("transfer_subscription accounts do not match the challenged activation")
                transfer = TransferData.from_bytes(data)
                expected_amount = _parse_u64_text(request.amount)
                if expected_amount is None:
                    raise _invalid("Challenge amount must be a u64")
                if (
                    transfer.amount != expected_amount
                    or transfer.delegator != subscriber
                    or transfer.mint != route.mint
                ):
                    raise _invalid("transfer_subscription data does not match the challenged activation")
                transfer_idx = index
            else:
                raise _invalid(f"Unsupported subscriptions instruction {discriminator} in activation tx")

        if subscribe_idx is None:
            raise _invalid("Activation tx is missing subscribe instruction")
        if transfer_idx is None:
            raise _invalid("Activation tx is missing transfer_subscription instruction")
        if transfer_idx < subscribe_idx:
            raise _invalid("subscribe must precede transfer_subscription in activation tx")
        if ata_idx is not None and ata_idx > subscribe_idx:
            raise _invalid("Activation setup instructions must precede subscribe")
        if (request.external_id is not None) != saw_memo:
            raise _invalid("Activation transaction memo does not match challenge externalId")
        if not keys:
            raise _invalid("VersionedTransaction has no account keys")
        fee_payer = keys[0]
        if not config.fee_payer and fee_payer != subscriber:
            raise _invalid("Activation transaction fee payer must be the subscriber")
        expected_signers = sorted({bytes(fee_payer), bytes(subscriber), bytes(route.puller)})
        required = int(message.header.num_required_signatures)
        signers = sorted(bytes(key) for key in keys[:required])
        if signers != expected_signers or len(tx.signatures) != required:
            raise _invalid("Activation transaction signers must be exactly the fee payer, subscriber and puller")

    # ── Active-subscription check ──

    async def verify_active_subscription(
        self, subscriber: Pubkey, amount_base_units: str, *, now: int | None = None
    ) -> SubscriptionDelegationView:
        """Check on-chain that ``subscriber`` holds a live, paid subscription.

        To this route's plan at ``amount_base_units`` per period, at ``now``
        (unix seconds, default the wall clock): the delegation exists, its
        authority is current, the current period is paid, and neither
        cancellation nor the configured expiry has taken effect. Use it after
        an identity-only check before serving subscription-gated work.
        """
        expected_amount = _parse_u64_text(amount_base_units)
        if expected_amount is None:
            raise _invalid("Subscription amount must be an unsigned integer")
        moment = now if now is not None else _now_seconds()
        delegation, _ = await self._active_delegation(
            subscriber, expected_amount, self._route.period_hours, self._config.subscription_expires, moment
        )
        return delegation

    async def _active_delegation(
        self,
        subscriber: Pubkey,
        expected_amount: int,
        period_hours: int,
        subscription_expires: str | None,
        now: int,
    ) -> tuple[SubscriptionDelegationView, int]:
        route = self._route
        delegation_pda = find_subscription_pda(route.plan, subscriber, route.program_id)[0]
        delegation = await self._fetch_subscription_delegation(delegation_pda)
        if delegation.plan_pda != route.plan or delegation.subscriber != subscriber:
            raise _mismatch("SubscriptionDelegation does not match the bound plan and payer")
        await self._ensure_current_authority(subscriber, delegation)
        if now < delegation.current_period_start_ts:
            raise _failed("Subscription is not paid for the current billing period")
        period_end = ensure_live_delegation(delegation, expected_amount, period_hours, subscription_expires, now)
        return delegation, period_end

    async def _ensure_current_authority(self, subscriber: Pubkey, delegation: SubscriptionDelegationView) -> None:
        route = self._route
        authority = find_subscription_authority_pda(subscriber, route.mint, route.program_id)[0]
        account = await self._rpc_client().get_account_info(str(authority))
        if account is None:
            raise _not_found(f"SubscriptionAuthority account {authority} not found: AccountNotFound")
        data, owner = account
        if owner != self._program_id_text:
            raise _mismatch(f"SubscriptionAuthority owner mismatch: expected {self._program_id_text}, got {owner}")
        try:
            init_id = decode_subscription_authority_init_id(data)
        except SubscriptionProgramError as exc:
            raise _internal(str(exc)) from exc
        if init_id != delegation.authority_init_id:
            raise _mismatch("Subscription authority has been invalidated")

    async def _fetch_subscription_delegation(self, address: Pubkey) -> SubscriptionDelegationView:
        account = await self._rpc_client().get_account_info(str(address))
        if account is None:
            raise _not_found(f"SubscriptionDelegation account {address} not found")
        data, owner = account
        if owner != self._program_id_text:
            raise _mismatch(f"SubscriptionDelegation owner mismatch: expected {self._program_id_text}, got {owner}")
        try:
            return decode_subscription_delegation(data)
        except SubscriptionProgramError as exc:
            raise _internal(str(exc)) from exc


# ── Verify helpers ────────────────────────────────────────────────────────────


def decode_base64_transaction(value: str) -> AnyTransaction:
    """Standard base64 of a version-0, version-1 or legacy transaction."""
    try:
        return decode_transaction(base64.b64decode(value, validate=True))
    except Exception as exc:  # noqa: BLE001 - every decode failure is a malformed payload
        raise _invalid(f"Tx decode: {exc}") from exc


def verify_fee_payer_signature(tx: AnyTransaction) -> None:
    """The transaction's first signature must verify against its fee payer.

    Only this signature, never a raw ``signatures[0]``, may key an
    activation's replay and binding records.
    """
    keys = list(tx.message.account_keys)
    if not tx.signatures:
        raise _invalid("Activation transaction has no signature slot")
    if not keys:
        raise _invalid("Activation transaction has no fee payer")
    if not tx.signatures[0].verify(keys[0], signed_message_bytes(tx.message)):
        raise _invalid("Activation transaction signature does not verify against its message")


async def co_sign_as_fee_payer(tx: AnyTransaction, signer: TransactionSigner) -> AnyTransaction:
    """Sign the fee-payer slot (account key zero) with the server's signer."""
    keys = list(tx.message.account_keys)
    if not keys or keys[0] != signer.pubkey:
        raise _invalid("Fee payer pubkey not present in activation transaction")
    if len(tx.signatures) != int(tx.message.header.num_required_signatures):
        raise _invalid("VersionedTransaction signatures vec is shorter than account_keys")
    try:
        if isinstance(tx.message, MessageV1):
            signatures = list(tx.signatures)
            signatures[0] = await signer.sign_message(signed_message_bytes(tx.message))
            return populate(tx.message, signatures)
        from solders.transaction import VersionedTransaction  # type: ignore[import-untyped]

        signed = await signer.sign_transaction(VersionedTransaction.from_bytes(bytes(tx)))
        return decode_transaction(bytes(signed.transaction))
    except PaymentError:
        raise
    except Exception as exc:  # noqa: BLE001 - a signer failure is a server fault
        raise VerificationError(f"Fee-payer signing failed: {exc}", code="invalid-config") from exc


def verify_activation_authentication(
    authentication: SubscriptionAuthentication, challenge_id: str, subscriber: Pubkey, delegation: Pubkey
) -> None:
    """The bearer proof must bind this challenge, the subscriber and its delegation."""
    if authentication.challenge_id != challenge_id:
        raise _mismatch("Subscription proof challengeId does not match the activation challenge")
    if authentication.payer != str(subscriber):
        raise _mismatch("Subscription proof payer does not match the activation subscriber")
    try:
        valid = authentication.verify(str(delegation))
    except SubscriptionError as exc:
        raise _invalid(str(exc)) from exc
    if not valid:
        raise _invalid("Invalid subscription authentication proof")


def verify_credential_source(source: str | None, subscriber: Pubkey) -> None:
    """§Source Verification: a present ``source`` must be the subscriber's did:pkh:solana."""
    if source is None:
        return
    prefix = "did:pkh:solana:"
    chain, sep, address = source[len(prefix) :].partition(":") if source.startswith(prefix) else ("", "", "")
    if not sep or not chain:
        raise _mismatch("Credential source must be a did:pkh:solana DID")
    try:
        matches = Pubkey.from_string(address) == subscriber
    except ValueError:
        matches = False
    if not matches:
        raise _mismatch("Credential source does not match the activation subscriber")


def validate_activation_subscription_expiry(subscription_expires: str | None, now: datetime) -> None:
    if subscription_expires is None:
        return
    try:
        expires_at = _parse_rfc3339(subscription_expires)
    except ValueError as exc:
        raise _invalid(f"Invalid subscriptionExpires: {exc}") from exc
    if expires_at <= now:
        raise _failed("Subscription has expired")


def ensure_live_delegation(
    delegation: SubscriptionDelegationView,
    expected_amount: int,
    period_hours: int,
    subscription_expires: str | None,
    now: int,
) -> int:
    """Require the delegation to be paid for the period containing ``now``.

    And not cancelled or expired. Returns the current period's end.
    """
    period_end = delegation.current_period_start_ts + period_hours * 3600
    if (
        delegation.amount_per_period != expected_amount
        or delegation.period_hours != period_hours
        or delegation.amount_pulled_in_period != expected_amount
        or now >= period_end
    ):
        raise _failed("Subscription is not paid for the current billing period")
    if delegation.expires_at_ts != 0 and now >= delegation.expires_at_ts:
        raise _failed("Subscription cancellation has taken effect")
    if subscription_expires is not None:
        try:
            expires_at = _parse_rfc3339(subscription_expires)
        except ValueError as exc:
            raise _invalid(f"Invalid subscriptionExpires: {exc}") from exc
        if int(expires_at.timestamp()) <= now:
            raise _failed("Subscription has expired")
    return period_end
