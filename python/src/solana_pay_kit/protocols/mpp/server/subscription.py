"""Server side of the Solana ``subscription`` intent: challenge, activation and access.

The challenge advertises one on-chain ``Plan`` after checking it (and its mint
and recipient token account) on chain. Activation takes a subscriber-signed
transaction, validates it with :mod:`._subscription_scope`, reserves it against
replay per challenge AND per signature, co-signs it as puller (and fee payer
when sponsored), broadcasts, then checks the resulting ``SubscriptionDelegation``
before binding the subscriber's bearer proof. Access re-checks that proof, the
delegation, its ``SubscriptionAuthority`` incarnation and the current period
against the chain on every request.

Store keys (JSON values match the Rust server where it has them):

- ``solana-subscription:challenge:{challengeId}`` = ``{"signature"}``
- ``solana-subscription:consumed:{signature}`` = ``{"challengeId"}``
- ``solana-subscription:authentication:{delegation}`` = the bearer binding
"""

from __future__ import annotations

import hashlib
import logging
import os
import secrets
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, cast

from solders.pubkey import Pubkey  # type: ignore[import-untyped]
from solders.transaction import VersionedTransaction  # type: ignore[import-untyped]

from solana_pay_kit._paycore.errors import (
    ChallengeExpiredError,
    ChallengeMismatchError,
    PaymentError,
    ReplayError,
    payment_required_response,  # pyright: ignore[reportUnknownVariableType]
)
from solana_pay_kit._paycore.network_check import check_network_blockhash
from solana_pay_kit._paycore.paymentchannels import find_associated_token_address
from solana_pay_kit._paycore.rpc import SolanaRpc, read_with_replica_retry, resolve_channel_read_policy
from solana_pay_kit._paycore.solana import (
    MIN_SECRET_KEY_BYTES,
    TOKEN_2022_PROGRAM,
    TOKEN_PROGRAM,
    default_rpc_url,
    derive_default_realm,
    validate_network,
)
from solana_pay_kit._paycore.store import Store
from solana_pay_kit.protocols.mpp._subscriptions import (
    SUBSCRIPTIONS_PROGRAM_ID,
    DelegationView,
    PlanView,
    authority_init_id,
    decode_delegation,
    decode_plan,
    find_subscription_authority_pda,
    find_subscription_pda,
    plan_problems,
    signer_pubkey,
)
from solana_pay_kit.protocols.mpp.core.base64url import encode, encode_json
from solana_pay_kit.protocols.mpp.core.expires import minutes, parse_rfc3339
from solana_pay_kit.protocols.mpp.core.headers import (
    PAYMENT_RECEIPT_HEADER,
    format_receipt,
    format_www_authenticate,
    parse_authorization,
)
from solana_pay_kit.protocols.mpp.core.types import PaymentChallenge, PaymentCredential, Receipt
from solana_pay_kit.protocols.mpp.intents.subscription import (
    AccessPayload,
    ActivatePayload,
    PeriodUnit,
    SubscriptionMethodDetails,
    SubscriptionRequest,
    parse_subscription_payload,
    period_hours,
    verify_subscription_authentication,
)
from solana_pay_kit.protocols.mpp.server._subscription_scope import (
    ActivationExpectation,
    cosign,
    validate_activation,
)
from solana_pay_kit.protocols.mpp.server.session_method import SessionGateResult

__all__ = [
    "SubscriptionChallengeOptions",
    "SubscriptionConfig",
    "SubscriptionGateResult",
    "SubscriptionServer",
]

logger = logging.getLogger(__name__)

#: Same four-field gate outcome as the session intent.
SubscriptionGateResult = SessionGateResult

_SECRET_KEY_ENV_VAR = "MPP_SECRET_KEY"
_CHALLENGE_KEY = "solana-subscription:challenge:{}"
_CONSUMED_KEY = "solana-subscription:consumed:{}"
_BINDING_KEY = "solana-subscription:authentication:{}"
_PLAN_TTL_SECONDS = 60
# The program's TIME_DRIFT_ALLOWED_SECS: a period that started up to this far
# in the local future still counts, so a fast chain clock does not lock users out.
_CLOCK_SKEW_SECONDS = 120
_MINT_MIN_LEN = 82
_MINT_DECIMALS_OFFSET = 44
_MINT_INITIALIZED_OFFSET = 45
_U64_MAX = 2**64 - 1
_LANDED = ("confirmed", "finalized")
_RPC_METHODS = (
    "get_account_info",
    "get_latest_blockhash",
    "get_signature_statuses",
    "send_raw_transaction",
    "await_confirmation",
)


def _config_error(message: str) -> PaymentError:
    return PaymentError(message, code="invalid-config")


def _invalid(message: str) -> PaymentError:
    return PaymentError(message, code="invalid-payload")


def _rfc3339(unix_seconds: int) -> str:
    return datetime.fromtimestamp(unix_seconds, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def derive_subscription_id(delegation: Pubkey, challenge_id: str) -> str:
    """Opaque receipt id: base64url of the first 18 bytes of SHA-256, byte-identical to Rust and TS."""
    digest = hashlib.sha256(f"mpp-subscription-id-v1:{challenge_id}:{delegation}".encode()).digest()
    return encode(digest[:18])


@dataclass
class SubscriptionConfig:
    """Server configuration for one subscription plan; ``amount`` is in base units."""

    plan: str
    mint: str
    recipient: str
    amount: int
    puller_signer: Any
    # Replay and bearer-binding store; required, there is no silent in-memory default.
    store: Store
    period_unit: PeriodUnit = "day"
    period_count: int = 30
    decimals: int = 6
    token_program: str = TOKEN_PROGRAM
    network: str = "mainnet"
    rpc_url: str = ""
    rpc: Any = None
    secret_key: str = ""
    # ``None`` derives a per-recipient realm; an empty string is rejected.
    realm: str | None = None
    program_id: str = SUBSCRIPTIONS_PROGRAM_ID
    # Sponsor activation fees; the fee payer defaults to the puller.
    fee_payer: bool = False
    fee_payer_signer: Any = None
    subscription_expires: str = ""
    description: str = ""
    # Post-confirmation re-read policy for replica lag; unset takes the defaults.
    read_max_attempts: int | None = None
    read_backoff_step_ms: int | None = None


@dataclass
class SubscriptionChallengeOptions:
    """Per-request challenge options."""

    description: str = ""
    external_id: str = ""
    expires: str = ""


def _pubkey(value: str, name: str) -> Pubkey:
    try:
        return Pubkey.from_string(value)
    except ValueError as exc:
        raise _config_error(f"{name} is not a base58 public key") from exc


class SubscriptionServer:
    """Issues subscription challenges and verifies activation and access credentials."""

    def __init__(self, config: SubscriptionConfig) -> None:
        if not isinstance(config.store, Store):  # pyright: ignore[reportUnnecessaryIsInstance]
            raise _config_error("replay store is required; pass MemoryStore() or FileReplayStore(path) explicitly")
        secret_key = config.secret_key or os.environ.get(_SECRET_KEY_ENV_VAR, "")
        if len(secret_key.encode("utf-8")) < MIN_SECRET_KEY_BYTES:
            raise _config_error(f"secret key must be at least {MIN_SECRET_KEY_BYTES} bytes")
        if config.realm == "":
            raise _config_error("realm must not be empty; omit it to derive a per-recipient default")
        if config.period_unit not in ("day", "week") or isinstance(config.period_count, bool):
            raise _config_error("period_unit must be 'day' or 'week' and period_count an integer")
        try:
            validate_network(config.network)
            self._hours = period_hours(config.period_unit, config.period_count)
        except ValueError as exc:
            raise _config_error(str(exc)) from exc
        if isinstance(config.amount, bool) or not 1 <= config.amount <= _U64_MAX:
            raise _config_error("amount must be a positive u64 in base units")
        if isinstance(config.decimals, bool) or not 0 <= config.decimals <= 255:
            raise _config_error("decimals must be between 0 and 255")
        if config.token_program not in (TOKEN_PROGRAM, TOKEN_2022_PROGRAM):
            raise _config_error("token_program must be the SPL Token or Token-2022 program")
        self._plan = _pubkey(config.plan, "plan")
        self._mint = _pubkey(config.mint, "mint")
        self._recipient = _pubkey(config.recipient, "recipient")
        self._program = _pubkey(config.program_id, "program_id")
        self._token_program = _pubkey(config.token_program, "token_program")
        try:
            self._puller = signer_pubkey(config.puller_signer)
        except (AttributeError, ValueError) as exc:
            raise _config_error("puller_signer must expose pubkey() and sign or sign_message") from exc
        self._fee_payer_signer = (
            config.fee_payer_signer if config.fee_payer_signer is not None else config.puller_signer
        )
        self._fee_payer = signer_pubkey(self._fee_payer_signer) if config.fee_payer else None
        if config.subscription_expires:
            try:
                parse_rfc3339(config.subscription_expires)
            except ValueError as exc:
                raise _config_error(str(exc)) from exc
        self._network = "mainnet" if config.network == "mainnet-beta" else config.network
        rpc = config.rpc if config.rpc is not None else SolanaRpc(config.rpc_url or default_rpc_url(self._network))
        for method in _RPC_METHODS:
            if not callable(getattr(rpc, method, None)):
                raise _config_error(f"rpc client is missing '{method}'; use SolanaRpc or a compatible client")
        self._rpc: Any = rpc
        self._config = config
        self._store: Store = config.store
        self._secret_key = secret_key
        self._realm = config.realm if config.realm else derive_default_realm(config.recipient)
        self._read_policy = resolve_channel_read_policy(config.read_max_attempts, config.read_backoff_step_ms)
        self._plan_cache: tuple[PlanView, float] | None = None

    @property
    def realm(self) -> str:
        """The realm every challenge is issued under."""
        return self._realm

    def _now(self) -> int:
        """Current unix time in seconds (a seam for tests)."""
        return int(time.time())

    async def _account(self, address: Pubkey) -> tuple[bytes, str] | None:
        return await self._rpc.get_account_info(str(address))

    async def _load_plan(self) -> PlanView:
        """Read and check the plan, its mint and the recipient token account; cached for 60 seconds."""
        if self._plan_cache is not None and time.monotonic() - self._plan_cache[1] < _PLAN_TTL_SECONDS:
            return self._plan_cache[0]
        account = await self._account(self._plan)
        if account is None:
            raise _config_error(f"plan {self._plan} does not exist")
        try:
            plan = decode_plan(account[0], account[1], str(self._program), self._plan)
        except ValueError as exc:
            raise _config_error(str(exc)) from exc
        problems = plan_problems(
            plan,
            mint=str(self._mint),
            amount=self._config.amount,
            period_hours=self._hours,
            recipient=str(self._recipient),
            puller=str(self._puller),
            now=self._now(),
        )
        mint = await self._account(self._mint)
        if mint is None or mint[1] != str(self._token_program) or len(mint[0]) < _MINT_MIN_LEN:
            problems.append("mint is missing or not owned by the configured token program")
        elif mint[0][_MINT_INITIALIZED_OFFSET] != 1 or mint[0][_MINT_DECIMALS_OFFSET] != self._config.decimals:
            problems.append("mint is uninitialized or its decimals differ from the configured decimals")
        recipient_ata = find_associated_token_address(self._recipient, self._mint, self._token_program)[0]
        ata = await self._account(recipient_ata)
        if ata is None or ata[1] != str(self._token_program):
            problems.append("recipient has no token account for the mint")
        if problems:
            raise _config_error("plan cannot be sold: " + "; ".join(problems))
        self._plan_cache = (plan, time.monotonic())
        return plan

    async def challenge(self, options: SubscriptionChallengeOptions | None = None) -> PaymentChallenge:
        """Issue an HMAC-bound challenge for the configured plan, with the Rust plan extensions."""
        options = options if options is not None else SubscriptionChallengeOptions()
        plan = await self._load_plan()
        try:
            blockhash = str((await self._rpc.get_latest_blockhash()).value.blockhash)
        except Exception:  # noqa: BLE001 - best effort; the client fetches its own blockhash
            blockhash = ""
        details = SubscriptionMethodDetails(
            plan_address=str(self._plan),
            mint=str(self._mint),
            decimals=self._config.decimals,
            token_program=str(self._token_program),
            puller=str(self._puller),
            subscription_program=str(self._program),
            network=self._network,
            fee_payer=self._fee_payer is not None,
            fee_payer_key=str(self._fee_payer) if self._fee_payer is not None else "",
            recent_blockhash=blockhash,
            merchant=str(plan.owner),
            recipient=str(self._recipient),
            amount=str(self._config.amount),
            plan_id_numeric=plan.plan_id,
            plan_bump=plan.bump,
            expected_period_hours=plan.period_hours,
            expected_created_at=plan.created_at,
        )
        request = SubscriptionRequest(
            amount=str(self._config.amount),
            currency=str(self._mint),
            period_unit=self._config.period_unit,
            period_count=str(self._config.period_count),
            recipient=str(self._recipient),
            method_details=details,
            subscription_expires=self._config.subscription_expires,
            description=options.description or self._config.description,
            external_id=options.external_id,
        )
        return PaymentChallenge.with_secret_key(
            secret_key=self._secret_key,
            realm=self._realm,
            method="solana",
            intent="subscription",
            request=encode_json(request.to_dict()),
            expires=options.expires or minutes(5),
            description=request.description,
            # A per-challenge nonce: two requests in the same millisecond must not get
            # the same challenge id, because an activation is single-use per challenge.
            opaque=encode_json({"nonce": secrets.token_hex(16)}),
        )

    async def verify_credential(self, credential: PaymentCredential) -> Receipt:
        """Verify an activation (``transaction``) or access (``proof``) credential and return its receipt."""
        echo = credential.challenge
        challenge = PaymentChallenge(
            id=echo.id,
            realm=echo.realm,
            method=echo.method,
            intent=echo.intent,
            request=echo.request,
            expires=echo.expires,
            digest=echo.digest,
            opaque=echo.opaque,
        )
        if not challenge.verify(self._secret_key):
            raise ChallengeMismatchError()
        request = self._pin(challenge)
        try:
            payload = parse_subscription_payload(credential.payload)
        except ValueError as exc:
            raise _invalid(str(exc)) from exc
        if isinstance(payload, AccessPayload):
            return await self._verify_access(challenge, request, payload)
        return await self._activate(credential, challenge, request, payload)

    def _pin(self, challenge: PaymentChallenge) -> SubscriptionRequest:
        """Tier-2 backstop: fields fixed at construction must match, so another route's challenge fails."""
        for name, got, want in (
            ("method", challenge.method, "solana"),
            ("intent", challenge.intent, "subscription"),
            ("realm", challenge.realm, self._realm),
        ):
            if got != want:
                raise PaymentError(f"credential {name} does not match this server", code=f"{name}-mismatch")
        try:
            request = SubscriptionRequest.from_dict(challenge.decode_request())
        except Exception as exc:  # noqa: BLE001 - any undecodable request is an invalid credential
            raise _invalid(f"challenge request does not decode: {exc}") from exc
        details = request.method_details
        for name, got, want in (
            ("currency", request.currency, str(self._mint)),
            ("recipient", request.recipient, str(self._recipient)),
            ("amount", request.amount, str(self._config.amount)),
            ("periodUnit", request.period_unit, self._config.period_unit),
            ("periodCount", request.period_count, str(self._config.period_count)),
            ("planAddress", details.plan_address, str(self._plan)),
            ("subscriptionProgram", details.subscription_program, str(self._program)),
            ("network", details.network, self._network),
        ):
            if got != want:
                raise PaymentError(f"credential {name} does not match this server", code="challenge-route-mismatch")
        return request

    def _subscription_expires_at(self, request: SubscriptionRequest) -> int | None:
        if not request.subscription_expires:
            return None
        return int(parse_rfc3339(request.subscription_expires).timestamp())

    def _verify_source(self, source: str | None, subscriber: Pubkey) -> None:
        """An optional ``source`` must be ``did:pkh:solana:<network>:<subscriber>``."""
        if source is None:
            return
        parts = source.split(":")
        if len(parts) != 5 or parts[:3] != ["did", "pkh", "solana"] or parts[4] != str(subscriber):
            raise _invalid("credential source is not the subscriber's did:pkh:solana identifier")

    async def _reserve(self, key: str, value: dict[str, str]) -> None:
        """Claim ``key``; an identical claim is an idempotent retry, anything else is a replay."""
        if await self._store.put_if_absent(key, value):
            return
        if await self._store.get(key) != value:
            raise ReplayError("subscription activation was already used with another transaction or challenge")

    async def _status(self, signature: str, *, search_history: bool = False) -> dict[str, Any]:
        """The ``getSignatureStatuses`` entry for ``signature``; empty when the cluster does not know it."""
        history: dict[str, bool] = {"search_history": True} if search_history else {}
        entries = await self._rpc.get_signature_statuses([signature], **history)
        entry = entries[0] if entries else None
        return cast("dict[str, Any]", entry) if isinstance(entry, dict) else {}

    async def _authority_init_id(self, subscriber: Pubkey) -> int | None:
        """The subscriber's live ``SubscriptionAuthority`` ``init_id``; ``None`` when missing or only pre-funded."""
        account = await self._account(find_subscription_authority_pda(subscriber, self._mint, self._program))
        try:
            return authority_init_id(account, str(self._program))
        except ValueError as exc:
            raise _invalid(str(exc)) from exc

    async def _read_delegation(self, delegation: Pubkey) -> DelegationView | None:
        account = await self._account(delegation)
        if account is None:
            return None
        try:
            return decode_delegation(account[0], account[1], str(self._program))
        except ValueError as exc:
            raise _invalid(str(exc)) from exc

    async def _activate(
        self,
        credential: PaymentCredential,
        challenge: PaymentChallenge,
        request: SubscriptionRequest,
        payload: ActivatePayload,
    ) -> Receipt:
        # The challenge expiry limits creating a binding, never using one.
        if challenge.is_expired():
            raise ChallengeExpiredError(f"challenge expired at {challenge.expires}")
        expires_at = self._subscription_expires_at(request)
        if expires_at is not None and self._now() >= expires_at:
            raise _invalid("subscription has expired")
        plan = await self._load_plan()
        parsed = validate_activation(
            payload.transaction,
            ActivationExpectation(
                program=self._program,
                plan=plan,
                token_program=self._token_program,
                puller=self._puller,
                recipient=self._recipient,
                amount=self._config.amount,
                fee_payer=self._fee_payer,
                external_id=request.external_id,
            ),
        )
        check_network_blockhash(
            self._network, str(VersionedTransaction.from_bytes(parsed.raw).message.recent_blockhash)
        )
        subscriber = parsed.subscriber
        self._verify_source(credential.source, subscriber)
        delegation = find_subscription_pda(self._plan, subscriber, self._program)
        proof = payload.authentication
        if (
            proof.challenge_id != challenge.id
            or proof.payer != str(subscriber)
            or not verify_subscription_authentication(proof, str(delegation))
        ):
            raise _invalid("activation proof does not bind this challenge, subscriber and delegation")
        # An init is allowed only while the authority is missing, unless this is a
        # retry of a reserved challenge whose own transaction created it; _reserve
        # below still requires the retry to carry that same transaction.
        retry = await self._store.get(_CHALLENGE_KEY.format(challenge.id)) is not None
        if parsed.has_init and not retry and await self._authority_init_id(subscriber) is not None:
            raise _invalid("activation initializes a SubscriptionAuthority that already exists")

        signers = [self._config.puller_signer] + ([self._fee_payer_signer] if self._fee_payer is not None else [])
        wire, signature = cosign(parsed.raw, signers, fee_payer=self._fee_payer)
        await self._reserve(_CHALLENGE_KEY.format(challenge.id), {"signature": signature})
        await self._reserve(_CONSUMED_KEY.format(signature), {"challengeId": challenge.id})
        # A reserved retry may come back after the ~2 minute status cache, so
        # it searches history; slot 0 is verified, so this is this message.
        status = await self._status(signature, search_history=retry)
        if status.get("err") is not None:
            raise PaymentError(f"activation {signature} failed on-chain: {status['err']}", code="transaction-failed")
        already_landed = status.get("confirmationStatus") in _LANDED
        if not already_landed:
            await self._rpc.send_raw_transaction(wire)
            await self._rpc.await_confirmation(signature)

        attempts, step_seconds = self._read_policy
        settled = await read_with_replica_retry(lambda: self._read_delegation(delegation), attempts, step_seconds)
        if settled is None:
            raise PaymentError("SubscriptionDelegation is not visible after confirmation", code="transaction-not-found")
        if (
            settled.subscriber != subscriber
            or settled.plan != self._plan
            or (settled.amount, settled.period_hours, settled.created_at)
            != (plan.amount, plan.period_hours, plan.created_at)
            or settled.expires_at_ts != 0
        ):
            raise PaymentError(
                "confirmed SubscriptionDelegation does not match the activation", code="transaction-failed"
            )
        if settled.amount_pulled_in_period != self._config.amount:
            raise PaymentError("activation did not collect the first period", code="transaction-failed")
        if expires_at is not None and settled.current_period_start_ts >= expires_at:
            raise _invalid("activation settled at or after subscriptionExpires")
        # An activation that landed earlier proves only its own period: a retry
        # after that period must not mint a receipt from the stale delegation.
        start = settled.current_period_start_ts
        if already_landed and not start - _CLOCK_SKEW_SECONDS <= self._now() < start + self._hours * 3600:
            raise _invalid("the confirmed activation no longer covers the current period")

        subscription_id = derive_subscription_id(delegation, challenge.id)
        binding: dict[str, Any] = {
            "activationSignature": signature,
            "authentication": proof.to_dict(),
            "challengeId": challenge.id,
            "periodStartTs": settled.current_period_start_ts,
            "subscriptionId": subscription_id,
            "subscriptionExpires": request.subscription_expires or None,
        }
        try:
            # A put, not put_if_absent: a confirmed re-activation of a revoked
            # delegation replaces the prior lifecycle's proof.
            await self._store.put(_BINDING_KEY.format(delegation), binding)
        except Exception:  # noqa: BLE001 - the charge settled; never turn a lost binding into a 402
            logger.exception(
                "ALERT subscription %s settled in %s but its proof binding was not stored", delegation, signature
            )
        return self._receipt(
            challenge_id=challenge.id,
            request=request,
            reference=signature,
            delegation=delegation,
            subscription_id=subscription_id,
            period_index=0,
            period_start=settled.current_period_start_ts,
            cancel_at=0,
            timestamp=settled.current_period_start_ts,
        )

    def _receipt(
        self,
        *,
        challenge_id: str,
        request: SubscriptionRequest,
        reference: str,
        delegation: Pubkey,
        subscription_id: str,
        period_index: int,
        period_start: int,
        cancel_at: int,
        timestamp: int,
    ) -> Receipt:
        ends = [ts for ts in (self._subscription_expires_at(request), cancel_at or None) if ts is not None]
        return Receipt(
            status="success",
            method="solana",
            intent="subscription",
            timestamp=_rfc3339(timestamp),
            reference=reference,
            challenge_id=challenge_id,
            external_id=request.external_id,
            subscription_id=subscription_id,
            subscription_delegation=str(delegation),
            period_index=period_index,
            period_start=_rfc3339(period_start),
            period_end=_rfc3339(period_start + self._hours * 3600),
            expires_at=_rfc3339(min(ends)) if ends else "",
        )

    async def _verify_access(
        self, challenge: PaymentChallenge, request: SubscriptionRequest, payload: AccessPayload
    ) -> Receipt:
        proof = payload.authentication
        try:
            payer = Pubkey.from_string(proof.payer)
        except ValueError as exc:
            raise _invalid("proof payer is not a base58 public key") from exc
        delegation = find_subscription_pda(self._plan, payer, self._program)
        # The proof's challengeId is pinned by the binding check below.
        if payload.subscription_delegation != str(delegation) or not verify_subscription_authentication(
            proof, str(delegation)
        ):
            raise _invalid("proof does not bind this payer and delegation")
        stored = await self._store.get(_BINDING_KEY.format(delegation))
        binding = cast("dict[str, Any]", stored) if isinstance(stored, dict) else {}
        if binding.get("challengeId") != challenge.id or binding.get("authentication") != proof.to_dict():
            raise _invalid("proof is not the one bound at activation")
        state = await self._read_delegation(delegation)
        if state is None or state.plan != self._plan or state.subscriber != payer:
            raise _invalid("subscription delegation is missing or bound to another plan or payer")
        init_id = await self._authority_init_id(payer)
        if init_id is None or init_id != state.init_id:
            raise _invalid("subscription authority is missing or was re-initialized")
        now = self._now()
        period = self._hours * 3600
        if (state.amount, state.period_hours) != (self._config.amount, self._hours):
            raise _invalid("subscription terms do not match this server")
        if state.expires_at_ts != 0 and now >= state.expires_at_ts:
            raise _invalid("subscription cancellation has taken effect")
        expires_at = self._subscription_expires_at(request)
        if expires_at is not None and now >= expires_at:
            raise _invalid("subscription has expired")
        paid = state.amount_pulled_in_period == self._config.amount
        if (
            not paid
            or not state.current_period_start_ts - _CLOCK_SKEW_SECONDS <= now < state.current_period_start_ts + period
        ):
            raise _invalid("subscription is not paid for the current period")
        anchor = binding.get("periodStartTs")
        if isinstance(anchor, bool) or not isinstance(anchor, int):
            raise _invalid("subscription binding is malformed")
        elapsed = state.current_period_start_ts - anchor
        if elapsed < 0 or elapsed % period:
            raise _invalid("subscription billing anchor does not align with the current period")
        return self._receipt(
            challenge_id=challenge.id,
            request=request,
            reference=str(binding.get("activationSignature", "")),
            delegation=delegation,
            subscription_id=str(binding.get("subscriptionId", "")),
            period_index=elapsed // period,
            period_start=state.current_period_start_ts,
            cancel_at=state.expires_at_ts,
            timestamp=now,
        )

    async def handle(
        self, authorization: str | None, options: SubscriptionChallengeOptions | None = None
    ) -> SubscriptionGateResult:
        """Framework-agnostic gate: 200 with a private receipt, or 402 with a fresh challenge and no receipt."""
        error: PaymentError | None = None
        if authorization:
            try:
                receipt = await self.verify_credential(parse_authorization(authorization))
                return SubscriptionGateResult(
                    ok=True,
                    status=200,
                    headers={PAYMENT_RECEIPT_HEADER: format_receipt(receipt), "cache-control": "private"},
                )
            except PaymentError as err:
                error = err
            except Exception as err:  # noqa: BLE001 - parse and framework errors map to 402
                error = _invalid(str(err))
        problem = cast(
            "dict[str, Any]",
            payment_required_response(
                str(error) if error else "Payment required",
                code=error.code if error and error.code else "payment_invalid",
                challenge_header=format_www_authenticate(await self.challenge(options)),
            ),
        )
        return SubscriptionGateResult(
            ok=False, status=problem["status_code"], headers=problem["headers"], body=problem["body"]
        )
