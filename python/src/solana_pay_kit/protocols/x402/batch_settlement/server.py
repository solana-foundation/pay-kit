"""Resource-server engine for the SVM ``batch-settlement`` scheme.

The client deposits once into an escrow payment channel, then signs a
cumulative Ed25519 voucher per request. This server verifies each voucher
offchain, serves immediately, and redeems the accumulated vouchers onchain
later, in batches, so no request waits on a Solana transaction.

It self-facilitates: one ``fee_payer_signer`` key is the transaction fee payer,
the channel ``rent_payer`` and the zero-share channel ``payee`` (a lifecycle
authority that can seal and reclaim, but never advance the settled watermark,
since only the client's ``payerAuthorizer`` signs vouchers).

Request lifecycle (the ``authorization`` flow):

1. :meth:`X402BatchSettlement.verify_and_reserve_payment` runs before the
   resource handler: it verifies the payload, refreshes the channel from
   confirmed chain state, and durably reserves the authorization.
2. On handler success, :meth:`~X402BatchSettlement.mark_handler_succeeded`
   then :meth:`~X402BatchSettlement.finish_commit` (broadcasts any deposit and
   advances the watermark); on failure,
   :meth:`~X402BatchSettlement.release_authorization`.
3. A ``refund`` is a payment-control operation: the handler is bypassed and
   :meth:`~X402BatchSettlement.settle_payment` closes the channel.

Redemption is out of band: :meth:`~X402BatchSettlement.claim` advances the
onchain watermark from stored vouchers, :meth:`~X402BatchSettlement.settle`
pays the claimed delta to ``payTo``, and
:meth:`~X402BatchSettlement.finalize_close` seals a channel the payer started
closing with the latest voucher. Mirrors the Rust kit
(``x402/server/batch_settlement.rs``).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import struct
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import TYPE_CHECKING, Any, cast

from solders.hash import Hash  # type: ignore[import-untyped]
from solders.instruction import AccountMeta, Instruction  # type: ignore[import-untyped]
from solders.pubkey import Pubkey  # type: ignore[import-untyped]
from solders.signature import Signature  # type: ignore[import-untyped]

from solana_pay_kit._paycore import txv1
from solana_pay_kit._paycore.currency import parse_units
from solana_pay_kit._paycore.network import SOLANA_DEVNET_CAIP2, SOLANA_MAINNET_CAIP2
from solana_pay_kit._paycore.paymentchannels import (
    PROGRAM_ID,
    SYSVAR_INSTRUCTIONS,
    Distribution,
    build_distribute_instruction,
    build_ed25519_verify_instruction,
    build_settle_and_seal_instructions,
    find_associated_token_address,
    voucher_message_bytes,
)
from solana_pay_kit._paycore.rpc import SolanaRpc
from solana_pay_kit._paycore.solana import default_rpc_url, default_token_program_for_currency, resolve_mint
from solana_pay_kit.protocols.programs.paymentchannels.accounts.channel import Channel
from solana_pay_kit.protocols.programs.paymentchannels.instructions.settle import SettleInstructionData
from solana_pay_kit.protocols.x402.batch_settlement.errors import (
    DUPLICATE_SETTLEMENT,
    INVALID_CHANNEL_CLOSING,
    INVALID_CHANNEL_STATE,
    INVALID_CLOSE_STATE,
    INVALID_CUMULATIVE_AMOUNT_MISMATCH,
    INVALID_CUMULATIVE_EXCEEDS_DEPOSIT,
    INVALID_PAYLOAD_TYPE,
    INVALID_PAYMENT_REQUIREMENTS,
    INVALID_RECEIVER_AUTHORIZER_MISMATCH,
    INVALID_RECEIVER_BINDING_UNAVAILABLE,
    INVALID_SETTLEMENT_SIMULATION,
    INVALID_TOKEN_PROGRAM,
    INVALID_X402_VERSION,
    BatchSettlementError,
    classify,
    leading_code,
)
from solana_pay_kit.protocols.x402.batch_settlement.store import (
    AuthorizationRequest,
    BatchChannelRecord,
    BatchChannelStore,
    BatchStoreError,
    ChannelBinding,
    MemoryBatchChannelStore,
    PendingSetup,
    Reservation,
    ReservationToken,
)
from solana_pay_kit.protocols.x402.batch_settlement.tx_policy import (
    SetupForm,
    TransactionExpectations,
    decode_transaction,
    payer_signature,
    setup_form_from_transaction,
    validate_request_close_transaction,
    validate_setup_transaction,
)
from solana_pay_kit.protocols.x402.batch_settlement.types import (
    BATCH_SETTLEMENT_SCHEME,
    MAX_CLAIMS_PER_BATCH,
    MIN_WITHDRAW_DELAY_SECONDS,
    V1_MAX_CLAIM_CHANNELS,
    V1_MAX_SETTLE_CHANNELS,
    VOUCHER_EXPIRES_AT,
    BatchChannelConfig,
    BatchExtra,
    BatchPayload,
    BatchPaymentPayload,
    BatchRequiredEnvelope,
    BatchRequirements,
    BatchSettlementExtra,
    BatchSettlementResponse,
    BatchVoucher,
    BatchWireError,
    ChannelStateSnapshot,
    ResourceInfo,
    VoucherState,
)
from solana_pay_kit.protocols.x402.batch_settlement.verify import (
    check_channel_config,
    check_client_signed_payload,
    check_no_client_close_authorization,
    check_no_refund_amount,
    check_token_program,
    check_voucher,
    check_withdraw_delay,
    derive_channel_id,
    parse_pubkey,
)

if TYPE_CHECKING:
    from solana_keychain import TransactionSigner

__all__ = [
    "PAYMENT_REQUIRED_HEADER",
    "PAYMENT_RESPONSE_HEADER",
    "BatchAccess",
    "BatchAccessKind",
    "BatchConfig",
    "BatchOutcome",
    "InvalidPaymentRequiredError",
    "UnsupportedSchemeError",
    "X402BatchSettlement",
    "caip2_network_for_cluster",
    "unusable_settlement_account",
]

PAYMENT_REQUIRED_HEADER = "PAYMENT-REQUIRED"
PAYMENT_RESPONSE_HEADER = "PAYMENT-RESPONSE"
X402_VERSION_V2 = 2

_CHANNEL_STATUS_OPEN = 0
_CHANNEL_STATUS_SEALED = 1
_CHANNEL_STATUS_CLOSING = 2
_CHANNEL_STATUS_DISTRIBUTED = 3
#: ``AccountDiscriminator::Channel``: the first byte of a live channel account.
_CHANNEL_ACCOUNT_DISCRIMINATOR = 1
#: Floor of a request's reservation lease, in seconds.
_CHARGE_RESERVATION_LEASE_SECONDS = 60
_TOKEN_ACCOUNT_LEN = 165
_TOKEN_ACCOUNT_INITIALIZED = 1
_TOKEN_ACCOUNT_FROZEN = 2
_TOKEN_ACCOUNT_TYPE = 2
_EXTENSION_IMMUTABLE_OWNER = 7
_DEVNET_TREASURY_OWNER = Pubkey.from_bytes(
    bytes.fromhex("3b4b4a4c3ecd7e59d634ae67e5debbec0ad06f204df013a695a3376a57b98d05")
)
_MAINNET_TREASURY_OWNER = Pubkey.from_bytes(
    bytes.fromhex("b041d9d337b721be57894eb69c3b6809a53a0e2b6a2399fc7d5b7eda8cac89aa")
)


class InvalidPaymentRequiredError(ValueError):
    """The ``PAYMENT-SIGNATURE`` header does not decode as a batch payment."""


class UnsupportedSchemeError(ValueError):
    """The payment's ``accepted.scheme`` is not ``batch-settlement``."""


class BatchServerError(Exception):
    """An uncoded server failure (RPC, decode, store)."""


def _now() -> int:
    return int(time.time())


def _err(code: str, detail: str) -> BatchSettlementError:
    return BatchSettlementError(code, detail)


def _closing_error(channel_id: str) -> BatchSettlementError:
    return _err(INVALID_CHANNEL_CLOSING, f"channel {channel_id} is closing; no new charge may be reserved")


def caip2_network_for_cluster(cluster: str) -> str:
    """The CAIP-2 network of a Solana cluster name (devnet/localnet share devnet's)."""
    if cluster in ("devnet", "localnet", "solana-devnet", SOLANA_DEVNET_CAIP2):
        return SOLANA_DEVNET_CAIP2
    if cluster in ("testnet", "solana-testnet", "solana:4uhcVJyU9pJkvQyS88uRDiswHXSCkY3z"):
        return "solana:4uhcVJyU9pJkvQyS88uRDiswHXSCkY3z"
    return SOLANA_MAINNET_CAIP2


def _treasury_owner_for_cluster(cluster: str) -> Pubkey:
    if cluster in ("devnet", "solana-devnet", SOLANA_DEVNET_CAIP2):
        return _DEVNET_TREASURY_OWNER
    return _MAINNET_TREASURY_OWNER


def unusable_settlement_account(
    program: Pubkey, data: bytes, owner: Pubkey, mint: Pubkey, token_program: Pubkey
) -> str | None:
    """Why the token account at an owner's ATA cannot receive a payout, or
    ``None`` when it can: an initialized, unfrozen account of the declared
    token program, for ``mint`` and ``owner``, with no extension outside the
    allowlist (``ImmutableOwner``)."""
    if program != token_program:
        return "is not owned by the declared token program"
    if len(data) < _TOKEN_ACCOUNT_LEN:
        return "is not an initialized token account"
    account_mint = Pubkey.from_bytes(data[0:32])
    account_owner = Pubkey.from_bytes(data[32:64])
    state = data[108]
    if account_mint != mint:
        return f"holds mint {account_mint} rather than {mint}"
    if account_owner != owner:
        return f"is owned by {account_owner} rather than {owner}"
    if state == _TOKEN_ACCOUNT_FROZEN:
        return "is frozen"
    extension = _unsupported_extension(data)
    if extension is not None:
        return f"carries token account extension {extension}, which this server will not settle through"
    if state != _TOKEN_ACCOUNT_INITIALIZED:
        return f"is in account state {state}"
    return None


def _unsupported_extension(data: bytes) -> int | None:
    if len(data) == _TOKEN_ACCOUNT_LEN:
        return None
    if data[_TOKEN_ACCOUNT_LEN] != _TOKEN_ACCOUNT_TYPE:
        return data[_TOKEN_ACCOUNT_LEN]
    cursor = _TOKEN_ACCOUNT_LEN + 1
    while cursor < len(data):
        if not any(data[cursor:]):
            return None
        if cursor + 4 > len(data):
            return 0xFFFF
        extension, length = struct.unpack_from("<HH", data, cursor)
        if extension != _EXTENSION_IMMUTABLE_OWNER:
            return extension
        cursor += 4 + length
        if cursor > len(data):
            return 0xFFFF
    return None


def distribution_hash(recipients: Sequence[Distribution]) -> bytes:
    """``SHA-256(u32(len).le || (recipient || u16(bps).le)*)``, as committed at ``open``."""
    hasher = hashlib.sha256()
    hasher.update(struct.pack("<I", len(recipients)))
    for entry in recipients:
        hasher.update(bytes(entry.recipient))
        hasher.update(struct.pack("<H", entry.bps))
    return hasher.digest()


def _sole_recipient(receiver: Pubkey) -> list[Distribution]:
    return [Distribution(recipient=receiver, bps=10_000)]


def _request_fingerprint(voucher_signature: str, requirements: BatchRequirements) -> str:
    """Length-prefixed digest binding an authorization to the request that reserved it."""
    extra = requirements.extra
    hasher = hashlib.sha256()
    for value in (
        voucher_signature,
        requirements.scheme,
        requirements.network,
        requirements.amount,
        requirements.asset,
        requirements.pay_to,
        str(requirements.max_timeout_seconds),
        extra.payment_flow or "",
        extra.fee_payer,
        extra.receiver_authorizer or "",
        str(extra.withdraw_delay),
        extra.token_program,
        extra.memo or "",
    ):
        encoded = value.encode("utf-8")
        hasher.update(struct.pack("<Q", len(encoded)))
        hasher.update(encoded)
    return str(Pubkey.from_bytes(hasher.digest()))


def _encode_json(value: dict[str, Any]) -> str:
    return base64.b64encode(json.dumps(value, separators=(",", ":")).encode("utf-8")).decode("ascii")


@dataclass
class BatchConfig:
    """Server configuration for the SVM ``batch-settlement`` scheme.

    ``transaction_versions`` is the set of message versions this server
    accepts and advertises (``(0,)`` by default; ``(0, 1)`` opts into
    version 1, which also builds redemptions as version 1).
    """

    pay_to: str
    cluster: str
    fee_payer_signer: TransactionSigner
    currency: str = "USDC"
    decimals: int = 6
    token_program: str | None = None
    rpc_url: str | None = None
    resource: str = ""
    description: str | None = None
    max_timeout_seconds: int = 300
    withdraw_delay: int = MIN_WITHDRAW_DELAY_SECONDS
    memo: str | None = None
    receiver_authorizer: str | None = None
    program_id: str | None = None
    channel_snapshot_max_age_seconds: int = 30
    transaction_versions: tuple[int, ...] = (0,)


@dataclass
class _Authorization:
    id: str
    fingerprint: str


@dataclass
class BatchOutcome:
    """A verified payment, carried from verification to settlement.

    It holds its channel's in-flight slot until :meth:`release` (called by the
    settlement methods).
    """

    serve: bool
    replay: bool
    channel_id: str
    payer: str
    charged_amount: int
    payload: BatchPayload
    requirements: BatchRequirements
    max_claimable: int
    deposit_signature: str | None = None
    opens_channel: bool = False
    authorization: _Authorization | None = None
    reservation: ReservationToken | None = None
    #: Frees the channel's in-flight slot; set by verification, consumed by :meth:`release`.
    release_hook: Callable[[], None] | None = field(default=None, repr=False)

    def release(self) -> None:
        """Free the channel's in-flight slot (idempotent)."""
        release, self.release_hook = self.release_hook, None
        if release is not None:
            release()


class BatchAccessKind(Enum):
    """What the caller must do with a verified request."""

    #: Reserved: run the handler exactly once, then commit or release.
    SERVE = "serve"
    #: An earlier attempt's handler succeeded: finish the commit, never re-run it.
    RESUME = "resume"
    #: Already committed: answer with ``response``; never run the handler.
    REPLAY = "replay"
    #: Another in-flight request owns this authorization: answer 409.
    IN_PROGRESS = "in_progress"
    #: A payment-control operation (``refund``): bypass the handler, call ``settle_payment``.
    CONTROL = "control"


@dataclass
class BatchAccess:
    kind: BatchAccessKind
    outcome: BatchOutcome | None = None
    response: BatchSettlementResponse | None = None


@dataclass
class _Observation:
    channel: Channel | None
    slot: int


class X402BatchSettlement:
    """Server-side handler for the SVM x402 ``batch-settlement`` scheme."""

    def __init__(
        self,
        config: BatchConfig,
        store: BatchChannelStore | None = None,
        *,
        rpc: SolanaRpc | None = None,
        clock: Callable[[], int] = _now,
    ) -> None:
        if not config.pay_to:
            raise ValueError("pay_to is required")
        parse_pubkey(config.pay_to)
        check_withdraw_delay(config.withdraw_delay, config.max_timeout_seconds)
        lease = self._lease_seconds(config.max_timeout_seconds)
        if config.channel_snapshot_max_age_seconds + lease >= config.withdraw_delay:
            raise ValueError(
                f"channel_snapshot_max_age_seconds {config.channel_snapshot_max_age_seconds} plus the {lease}s "
                f"reservation lease must be shorter than withdraw_delay {config.withdraw_delay}"
            )
        for version in config.transaction_versions:
            if version not in (0, 1):
                raise ValueError(f"unsupported transaction version {version}")
        if not config.transaction_versions:
            raise ValueError("transaction_versions must accept at least one version")
        self._config = config
        self._fee_payer: Pubkey = config.fee_payer_signer.pubkey
        self._receiver_authorizer = (
            parse_pubkey(config.receiver_authorizer) if config.receiver_authorizer else self._fee_payer
        )
        self._program_id = parse_pubkey(config.program_id) if config.program_id else PROGRAM_ID
        self._accepted_versions = tuple(sorted(set(config.transaction_versions)))
        self._store: BatchChannelStore = store if store is not None else MemoryBatchChannelStore()
        self._rpc = rpc if rpc is not None else SolanaRpc(config.rpc_url or default_rpc_url(config.cluster))
        self._clock = clock
        self._in_flight: set[str] = set()
        self._in_flight_lock = threading.Lock()
        # Validated eagerly so a misconfigured currency fails at construction.
        self.mint()
        self.token_program()

    # ── configuration ──

    @staticmethod
    def _lease_seconds(max_timeout_seconds: int) -> int:
        return max(_CHARGE_RESERVATION_LEASE_SECONDS, max_timeout_seconds)

    @property
    def store(self) -> BatchChannelStore:
        """The channel store backing this handler, for redemption workers."""
        return self._store

    @property
    def fee_payer(self) -> str:
        """The advertised ``extra.feePayer`` (base58)."""
        return str(self._fee_payer)

    @property
    def accepted_versions(self) -> tuple[int, ...]:
        return self._accepted_versions

    def _tx_version(self) -> int:
        return max(self._accepted_versions)

    def redemption_capacity(self) -> tuple[int, int]:
        """Channels per claim and per settle transaction."""
        if self._tx_version() == 1:
            return V1_MAX_CLAIM_CHANNELS, V1_MAX_SETTLE_CHANNELS
        return MAX_CLAIMS_PER_BATCH, MAX_CLAIMS_PER_BATCH

    def network(self) -> str:
        return caip2_network_for_cluster(self._config.cluster)

    def mint(self) -> Pubkey:
        mint = resolve_mint(self._config.currency, self._config.cluster)
        if not mint:
            raise ValueError("batch-settlement requires an SPL token")
        return parse_pubkey(mint)

    def token_program(self) -> Pubkey:
        declared = self._config.token_program or default_token_program_for_currency(
            self._config.currency, self._config.cluster
        )
        return check_token_program(declared)

    def _treasury_owner(self) -> Pubkey:
        if self._config.program_id is not None:
            return _MAINNET_TREASURY_OWNER
        return _treasury_owner_for_cluster(self._config.cluster)

    def binding(self) -> ChannelBinding:
        """The deployment binding stamped on and required of every record."""
        return ChannelBinding(
            scheme=BATCH_SETTLEMENT_SCHEME,
            pay_to=self._config.pay_to,
            network=self.network(),
            program_id=str(self._program_id),
        )

    # ── challenge ──

    def requirements(self, amount: str) -> BatchRequirements:
        """The route's ``batch-settlement`` requirement for a decimal price. Pure."""
        v1 = self._tx_version() == 1
        advertised = None if self._accepted_versions == (0,) else list(self._accepted_versions)
        return BatchRequirements(
            scheme=BATCH_SETTLEMENT_SCHEME,
            network=self.network(),
            amount=parse_units(amount, self._config.decimals),
            asset=str(self.mint()),
            pay_to=self._config.pay_to,
            max_timeout_seconds=self._config.max_timeout_seconds,
            extra=BatchExtra(
                fee_payer=self.fee_payer,
                receiver_authorizer=str(self._receiver_authorizer),
                withdraw_delay=self._config.withdraw_delay,
                token_program=str(self.token_program()),
                memo=self._config.memo,
                transaction_versions=advertised,
                max_claim_channels=V1_MAX_CLAIM_CHANNELS if v1 else None,
                max_settle_channels=V1_MAX_SETTLE_CHANNELS if v1 else None,
            ),
        )

    def _envelope(
        self, requirement: BatchRequirements, error: str | None, resource: str | None
    ) -> BatchRequiredEnvelope:
        url = self._config.resource or resource
        return BatchRequiredEnvelope(
            x402_version=X402_VERSION_V2,
            resource=ResourceInfo(url=url, description=self._config.description) if url else None,
            accepts=[requirement],
            error=error,
        )

    async def challenge(self, amount: str, resource: str | None = None) -> BatchRequiredEnvelope:
        """The full 402 challenge, with blockhash and slot hints from one RPC call."""
        requirement = self.requirements(amount)
        hint = await self._rpc.get_latest_blockhash()
        extra = replace(
            requirement.extra,
            recent_blockhash=str(hint.value.blockhash),
            recent_slot=hint.context.slot if hint.context is not None else None,
        )
        return self._envelope(replace(requirement, extra=extra), None, resource)

    async def corrective_challenge(
        self, amount: str, channel_id: str, resource: str | None = None
    ) -> BatchRequiredEnvelope:
        """A corrective 402 after a cumulative mismatch: the server's snapshot plus
        the client's own signature at it, so the client need not trust the server's
        word. RPC-free."""
        requirement = self.requirements(amount)
        state = await self._store.get(channel_id)
        if state is None:
            raise _err(INVALID_CHANNEL_STATE, "unknown channel")
        voucher_state = (
            VoucherState(
                signed_max_claimable=str(state.cumulative),
                expires_at=state.highest_voucher_expires_at or VOUCHER_EXPIRES_AT,
                signature=state.highest_voucher_signature,
            )
            if state.highest_voucher_signature is not None
            else None
        )
        extra = replace(requirement.extra, voucher_state=voucher_state, channel_state=self.snapshot(state))
        return self._envelope(replace(requirement, extra=extra), INVALID_CUMULATIVE_AMOUNT_MISMATCH, resource)

    async def payment_required_header(self, amount: str, resource: str | None = None) -> tuple[str, str]:
        envelope = await self.challenge(amount, resource)
        return PAYMENT_REQUIRED_HEADER, _encode_json(envelope.to_dict())

    def settlement_header(self, response: BatchSettlementResponse) -> tuple[str, str]:
        return PAYMENT_RESPONSE_HEADER, _encode_json(response.to_dict())

    async def challenge_for_failure(
        self, header: str, amount: str, error: Exception, resource: str | None = None
    ) -> tuple[str, str]:
        """The 402 answering a failed verification: the corrective challenge for a
        cumulative mismatch this server raised, else a challenge carrying the code."""
        if leading_code(str(error)) == INVALID_CUMULATIVE_AMOUNT_MISMATCH:
            channel_id = self._channel_id_for_header(header)
            if channel_id is not None:
                try:
                    envelope = await self.corrective_challenge(amount, channel_id, resource)
                except BatchSettlementError:
                    pass
                else:
                    return PAYMENT_REQUIRED_HEADER, _encode_json(envelope.to_dict())
        envelope = await self.challenge(amount, resource)
        envelope = replace(envelope, error=classify(str(error)))
        return PAYMENT_REQUIRED_HEADER, _encode_json(envelope.to_dict())

    def _channel_id_for_header(self, header: str) -> str | None:
        try:
            envelope = self.parse_payment(header)
            return str(
                derive_channel_id(envelope.payload.channel_config, envelope.accepted.extra.fee_payer, self._program_id)
            )
        except (ValueError, BatchSettlementError):
            return None

    @staticmethod
    def snapshot(state: BatchChannelRecord) -> ChannelStateSnapshot:
        return ChannelStateSnapshot(
            channel_id=state.channel_id,
            balance=str(state.deposit),
            total_claimed=str(state.settled_on_chain),
            withdraw_requested_at=state.close_requested_at or 0,
            charged_cumulative_amount=str(state.cumulative),
        )

    # ── parsing ──

    def parse_payment(self, header: str) -> BatchPaymentPayload:
        """Decode a ``PAYMENT-SIGNATURE`` header into a batch payment."""
        try:
            raw = base64.b64decode(header, validate=True)
            envelope = BatchPaymentPayload.from_dict(json.loads(raw))
        except (binascii.Error, ValueError, BatchWireError) as exc:
            raise InvalidPaymentRequiredError(str(exc)) from exc
        if envelope.accepted.scheme != BATCH_SETTLEMENT_SCHEME:
            raise UnsupportedSchemeError(f"unsupported scheme {envelope.accepted.scheme!r}")
        return envelope

    # ── in-flight guard ──

    def _acquire(self, channel_id: str) -> Callable[[], None]:
        with self._in_flight_lock:
            if channel_id in self._in_flight:
                raise _err(DUPLICATE_SETTLEMENT, f"channel {channel_id} already has a request in flight")
            self._in_flight.add(channel_id)

        def release() -> None:
            with self._in_flight_lock:
                self._in_flight.discard(channel_id)

        return release

    # ── verify ──

    async def verify_payment(self, header: str, amount: str) -> BatchOutcome:
        """Verify a payment for a route priced at ``amount``, without mutating state.

        The returned outcome holds the channel's in-flight slot.
        """
        envelope = self.parse_payment(header)
        if envelope.x402_version != X402_VERSION_V2:
            raise _err(INVALID_X402_VERSION, f"batch-settlement requires x402Version 2, got {envelope.x402_version}")
        requirements = self.requirements(amount)
        payload = envelope.payload
        config = payload.channel_config
        check_channel_config(config, requirements)
        check_client_signed_payload(payload)
        check_no_refund_amount(payload)
        check_no_client_close_authorization(payload)
        self._check_accepted_matches(envelope.accepted, requirements)
        channel = derive_channel_id(config, requirements.extra.fee_payer, self._program_id)
        channel_b58 = str(channel)
        release = self._acquire(channel_b58)
        try:
            outcome = await self._verify_variant(payload, config, requirements, channel, channel_b58)
        except BaseException:
            release()
            raise
        outcome.release_hook = release
        return outcome

    async def _verify_variant(
        self,
        payload: BatchPayload,
        config: BatchChannelConfig,
        requirements: BatchRequirements,
        channel: Pubkey,
        channel_b58: str,
    ) -> BatchOutcome:
        charge = requirements.amount_units()
        if payload.type == "refund":
            max_claimable = await self._verify_refund(payload, config, requirements, channel)
            return BatchOutcome(
                serve=False,
                replay=False,
                channel_id=channel_b58,
                payer=config.payer,
                charged_amount=0,
                payload=payload,
                requirements=requirements,
                max_claimable=max_claimable,
            )
        voucher = payload.voucher
        if payload.type not in ("voucher", "deposit") or voucher is None:
            raise _err(INVALID_PAYLOAD_TYPE, f"{payload.type} payloads carry no client voucher")
        if payload.type == "voucher":
            state = await self._store.get(channel_b58)
            if state is not None:
                self._store_check(lambda: state.check_binding(self.binding()))
            if state is None:
                raise _err(INVALID_CHANNEL_STATE, f"no channel {channel_b58}; open one with a deposit payload")
            self._check_channel_open(state.sealed, state.close_requested_at is not None)
            max_claimable = check_voucher(voucher, config, channel)
            replay = self._check_watermark(
                state.cumulative, state.highest_voucher_signature, voucher, max_claimable, charge
            )
            self._check_deposit_cap(max_claimable, state.deposit)
            return BatchOutcome(
                serve=not replay,
                replay=replay,
                channel_id=channel_b58,
                payer=state.payer,
                charged_amount=0 if replay else charge,
                payload=payload,
                requirements=requirements,
                max_claimable=max_claimable,
                authorization=self._authorization_for(channel_b58, voucher, max_claimable, requirements),
            )
        return await self._verify_deposit(payload, voucher, config, requirements, channel, channel_b58, charge)

    async def _verify_deposit(
        self,
        payload: BatchPayload,
        voucher: BatchVoucher,
        config: BatchChannelConfig,
        requirements: BatchRequirements,
        channel: Pubkey,
        channel_b58: str,
        charge: int,
    ) -> BatchOutcome:
        deposit = payload.deposit
        assert deposit is not None  # a deposit variant always carries one
        stored = await self._store.get(channel_b58)
        max_claimable = check_voucher(voucher, config, channel)
        # A channel onchain with no record here lost it: the vouchers it
        # accepted lived only in that record, so it is never rebuilt.
        onchain_without_record: bool | None = None
        if stored is None:
            onchain_without_record = await self._lookup_channel(channel) is not None
            if onchain_without_record:
                raise _err(
                    INVALID_CHANNEL_STATE,
                    f"channel {channel_b58} is open onchain but has no record in this store; its accepted vouchers "
                    "are unknown, so open a new channel",
                )
        try:
            deposit_amount = deposit.amount_units()
        except ValueError as exc:
            raise BatchServerError(str(exc)) from exc
        form = setup_form_from_transaction(deposit.transaction, self._program_id)
        if stored is not None:
            self._store_check(lambda: stored.check_binding(self.binding()))
            self._check_channel_open(stored.sealed, stored.close_requested_at is not None)
            replay = self._check_watermark(
                stored.cumulative, stored.highest_voucher_signature, voucher, max_claimable, charge
            )
        else:
            if max_claimable != charge:
                raise _err(
                    INVALID_CUMULATIVE_AMOUNT_MISMATCH,
                    f"first voucher must authorize exactly {charge}, got {max_claimable}",
                )
            replay = False
        mint = self.mint()
        token_program = self.token_program()
        receiver = parse_pubkey(requirements.pay_to)
        await self._check_mint_owner(mint, token_program)
        payer = parse_pubkey(config.payer)
        await self._check_settlement_accounts(mint, token_program, receiver, payer)
        expectations = self._expectations(config, channel, token_program, receiver)
        carried = payer_signature(decode_transaction(deposit.transaction))
        retrying = (
            stored is not None and stored.pending_setup is not None and stored.pending_setup.payer_signature == carried
        )
        if not retrying:
            retrying = (
                onchain_without_record
                if onchain_without_record is not None
                else await self._lookup_channel(channel) is not None
            )
        recent_slot: int | None = None
        if form is SetupForm.OPEN and not retrying:
            try:
                hint = await self._rpc.get_latest_blockhash()
                recent_slot = hint.context.slot if hint.context is not None else None
            except Exception:  # noqa: BLE001 - a missing hint only skips the window check
                recent_slot = None
        validated = validate_setup_transaction(deposit.transaction, form, expectations, deposit_amount, recent_slot)
        deposit_signature = payer_signature(validated.transaction)
        if not self._deposit_already_recorded(stored, deposit_signature):
            await self._check_deposit_can_land(validated.transaction, payer, mint, token_program, deposit_amount)
        deposit_after = self._deposit_ceiling(stored, deposit_amount, deposit_signature)
        self._check_deposit_cap(max_claimable, deposit_after)
        return BatchOutcome(
            serve=not replay,
            replay=replay,
            channel_id=channel_b58,
            payer=config.payer,
            charged_amount=0 if replay else charge,
            payload=payload,
            requirements=requirements,
            max_claimable=max_claimable,
            deposit_signature=deposit_signature,
            opens_channel=form is SetupForm.OPEN,
            authorization=self._authorization_for(channel_b58, voucher, max_claimable, requirements),
        )

    def _expectations(
        self, config: BatchChannelConfig, channel: Pubkey, token_program: Pubkey, receiver: Pubkey
    ) -> TransactionExpectations:
        return TransactionExpectations(
            program_id=self._program_id,
            fee_payer=self._fee_payer,
            config=config,
            channel_id=channel,
            token_program=token_program,
            receiver=receiver,
            receiver_authorizer=self._receiver_authorizer,
            accepted_versions=self._accepted_versions,
            memo=self._config.memo,
        )

    @staticmethod
    def _store_check(check: Callable[[], None]) -> None:
        try:
            check()
        except BatchStoreError as exc:
            raise _err(INVALID_CHANNEL_STATE, f"store error: {exc}") from exc

    @staticmethod
    def _authorization_for(
        channel_id: str, voucher: BatchVoucher, max_claimable: int, requirements: BatchRequirements
    ) -> _Authorization:
        return _Authorization(
            id=f"access:{channel_id}:{max_claimable}",
            fingerprint=_request_fingerprint(voucher.signature, requirements),
        )

    @staticmethod
    def _check_accepted_matches(accepted: BatchRequirements, requirements: BatchRequirements) -> None:
        a, r = accepted, requirements
        mismatched = (
            a.network != r.network
            or a.amount != r.amount
            or a.asset != r.asset
            or a.pay_to != r.pay_to
            or a.max_timeout_seconds != r.max_timeout_seconds
            or a.extra.payment_flow != r.extra.payment_flow
            or a.extra.fee_payer != r.extra.fee_payer
            or a.extra.receiver_authorizer != r.extra.receiver_authorizer
            or a.extra.withdraw_delay != r.extra.withdraw_delay
            or a.extra.token_program != r.extra.token_program
            or a.extra.memo != r.extra.memo
        )
        if mismatched:
            raise _err(
                INVALID_PAYMENT_REQUIREMENTS, "paymentPayload.accepted does not match the route's paymentRequirements"
            )

    @staticmethod
    def _check_channel_open(sealed: bool, close_requested: bool) -> None:
        if sealed:
            raise _err(INVALID_CLOSE_STATE, "channel is sealed")
        if close_requested:
            raise _err(INVALID_CHANNEL_CLOSING, "channel close is pending; open a new channel")

    @staticmethod
    def _check_watermark(
        cumulative: int, highest_signature: str | None, voucher: BatchVoucher, max_claimable: int, charge: int
    ) -> bool:
        """The fixed-price watermark rule; ``True`` for an exact replay of the
        highest accepted voucher."""
        if max_claimable == cumulative and highest_signature == voucher.signature:
            return True
        expected = cumulative + charge
        if expected >= 1 << 64:
            raise _err(INVALID_CHANNEL_STATE, "cumulative amount overflow")
        if max_claimable != expected:
            raise _err(
                INVALID_CUMULATIVE_AMOUNT_MISMATCH,
                f"voucher authorizes {max_claimable}, expected {expected} (charged {cumulative} + amount {charge})",
            )
        return False

    @staticmethod
    def _deposit_ceiling(stored: BatchChannelRecord | None, deposit_amount: int, signature: str | None) -> int:
        if stored is None:
            return deposit_amount
        if signature is not None and signature in stored.processed_topup_signatures:
            return stored.deposit
        total = stored.deposit + deposit_amount
        if total >= 1 << 64:
            raise _err(INVALID_CHANNEL_STATE, "deposit overflow")
        return total

    @staticmethod
    def _check_deposit_cap(max_claimable: int, deposit: int) -> None:
        if max_claimable > deposit:
            raise _err(
                INVALID_CUMULATIVE_EXCEEDS_DEPOSIT, f"voucher authorizes {max_claimable} over a deposit of {deposit}"
            )

    @staticmethod
    def _deposit_already_recorded(stored: BatchChannelRecord | None, signature: str | None) -> bool:
        if stored is None or signature is None:
            return False
        pending = stored.pending_setup is not None and stored.pending_setup.payer_signature == signature
        return pending or signature in stored.processed_topup_signatures

    async def _get_account(self, address: Pubkey) -> tuple[bytes, Pubkey] | None:
        found = await self._rpc.get_account_info(str(address))
        if found is None:
            return None
        data, owner = found
        return data, Pubkey.from_string(owner)

    async def _check_mint_owner(self, mint: Pubkey, token_program: Pubkey) -> None:
        try:
            account = await self._get_account(mint)
        except Exception as exc:  # noqa: BLE001
            raise BatchServerError(f"mint fetch failed: {exc}") from exc
        if account is None:
            raise BatchServerError(f"mint fetch failed: account {mint} not found")
        if account[1] != token_program:
            raise _err(INVALID_TOKEN_PROGRAM, f"tokenProgram {token_program} does not own mint {mint}")

    async def _check_settlement_accounts(
        self, mint: Pubkey, token_program: Pubkey, receiver: Pubkey, payer: Pubkey
    ) -> None:
        """Each payout destination must be a live token account for this mint,
        owned by its role, before the sponsor co-signs the escrow."""
        for role, owner in (
            ("payee", self._fee_payer),
            ("treasury", self._treasury_owner()),
            ("receiver", receiver),
            ("payer", payer),
        ):
            ata, _ = find_associated_token_address(owner, mint, token_program)
            try:
                account = await self._get_account(ata)
            except Exception as exc:  # noqa: BLE001
                raise _err(INVALID_SETTLEMENT_SIMULATION, f"{role} settlement ATA {ata} is unavailable: {exc}") from exc
            if account is None:
                raise _err(INVALID_SETTLEMENT_SIMULATION, f"{role} settlement ATA {ata} is unavailable: not found")
            problem = unusable_settlement_account(account[1], account[0], owner, mint, token_program)
            if problem is not None:
                raise _err(INVALID_SETTLEMENT_SIMULATION, f"{role} settlement ATA {ata} {problem}")

    async def _check_deposit_can_land(
        self, transaction: Any, payer: Pubkey, mint: Pubkey, token_program: Pubkey, deposit_amount: int
    ) -> None:
        """The deposit is broadcast after the handler runs, so it must be able to
        land now: a live blockhash and a payer token balance covering it."""
        blockhash = str(transaction.message.recent_blockhash)
        try:
            live = await self._rpc.is_blockhash_valid(blockhash)
        except Exception as exc:  # noqa: BLE001
            raise _err(INVALID_SETTLEMENT_SIMULATION, f"deposit blockhash check failed: {exc}") from exc
        if not live:
            raise _err(INVALID_SETTLEMENT_SIMULATION, f"deposit transaction blockhash {blockhash} is not live")
        ata, _ = find_associated_token_address(payer, mint, token_program)
        try:
            account = await self._get_account(ata)
        except Exception as exc:  # noqa: BLE001
            raise _err(INVALID_SETTLEMENT_SIMULATION, f"payer token account {ata} is unavailable: {exc}") from exc
        if account is None or len(account[0]) < 72:
            raise _err(INVALID_SETTLEMENT_SIMULATION, f"payer token account {ata} is not a token account")
        (balance,) = struct.unpack_from("<Q", account[0], 64)
        if balance < deposit_amount:
            raise _err(
                INVALID_SETTLEMENT_SIMULATION,
                f"payer token account {ata} holds {balance}, less than the {deposit_amount} deposit",
            )

    async def _verify_refund(
        self, refund: BatchPayload, config: BatchChannelConfig, requirements: BatchRequirements, channel: Pubkey
    ) -> int:
        """Verify a client-mode refund; return the watermark it closes at."""
        voucher = refund.voucher
        if voucher is None:
            raise _err(INVALID_PAYLOAD_TYPE, "server-mode refunds belong to server-signed channels")
        max_claimable = check_voucher(voucher, config, channel)
        channel_b58 = str(channel)
        state = await self._store.get(channel_b58)
        if state is None:
            raise _err(INVALID_CHANNEL_STATE, f"no channel {channel_b58}; nothing to refund")
        self._store_check(lambda: state.check_binding(self.binding()))
        if max_claimable != state.cumulative:
            raise _err(
                INVALID_CLOSE_STATE,
                f"refund voucher closes at {max_claimable}, but the accepted cumulative is {state.cumulative}",
            )
        done = state.cooperative_close
        if done is not None and done.get("cumulative") == max_claimable:
            return max_claimable
        token_program = self.token_program()
        receiver = parse_pubkey(requirements.pay_to)
        if refund.transaction is not None:
            validate_request_close_transaction(
                refund.transaction, self._expectations(config, channel, token_program, receiver)
            )
        elif state.receiver_binding is None:
            raise _err(
                INVALID_RECEIVER_BINDING_UNAVAILABLE,
                f"no receiver binding is recorded for channel {channel_b58}; retry with a payer-signed request_close",
            )
        elif state.receiver_binding != str(self._receiver_authorizer):
            raise _err(
                INVALID_RECEIVER_AUTHORIZER_MISMATCH,
                f"channel {channel_b58} is bound to receiver authorizer {state.receiver_binding}, not this server's",
            )
        payer = parse_pubkey(config.payer)
        await self._check_settlement_accounts(self.mint(), token_program, receiver, payer)
        onchain = await self._fetch_channel(channel)
        if onchain.status not in (_CHANNEL_STATUS_OPEN, _CHANNEL_STATUS_CLOSING):
            raise _err(INVALID_CLOSE_STATE, f"channel status {onchain.status} cannot be closed")
        if onchain.settlement.settled > max_claimable:
            raise _err(
                INVALID_CLOSE_STATE,
                f"refund voucher {max_claimable} is behind the onchain settled watermark {onchain.settlement.settled}",
            )
        return max_claimable

    # ── reserve ──

    async def verify_and_reserve_payment(self, header: str, amount: str) -> BatchAccess:
        """Verify a payment and durably reserve its authorization before the
        resource handler runs. This is the entry point a gate should use."""
        outcome = await self.verify_payment(header, amount)
        authorization = outcome.authorization
        if authorization is None:
            return BatchAccess(BatchAccessKind.CONTROL, outcome)
        try:
            await self._reconcile_channel(outcome.channel_id)
            await self._complete_binding(outcome)
            if outcome.replay:
                response = await self.replay_response(outcome)
                outcome.release()
                return BatchAccess(BatchAccessKind.REPLAY, outcome, response)
            reservation, token = await self._reserve(outcome, authorization)
        except BaseException:
            outcome.release()
            raise
        if reservation is Reservation.RESERVED:
            outcome.reservation = token
            return BatchAccess(BatchAccessKind.SERVE, outcome)
        if reservation is Reservation.HANDLER_SUCCEEDED:
            outcome.reservation = token
            return BatchAccess(BatchAccessKind.RESUME, outcome)
        outcome.release()
        if reservation is Reservation.COMMITTED:
            return BatchAccess(BatchAccessKind.REPLAY, outcome, await self.replay_response(outcome))
        if reservation is Reservation.IN_PROGRESS:
            return BatchAccess(BatchAccessKind.IN_PROGRESS, outcome)
        if reservation is Reservation.CLOSING:
            raise _closing_error(outcome.channel_id)
        if reservation is Reservation.STALE:
            raise _err(
                INVALID_CUMULATIVE_AMOUNT_MISMATCH,
                f"voucher authorizes {outcome.max_claimable}, which no longer steps from the channel's watermark",
            )
        if reservation is Reservation.CONFLICT:
            raise _err(DUPLICATE_SETTLEMENT, f"authorization {authorization.id} is held by a different request")
        raise _err(
            INVALID_CHANNEL_STATE,
            f"channel {outcome.channel_id} holds an authorization abandoned while it may have been served; "
            "open a new channel",
        )

    def _seed_state(self, channel_id: str, config: BatchChannelConfig) -> BatchChannelRecord:
        return BatchChannelRecord(
            channel_id=channel_id,
            payer_authorizer=config.payer_authorizer,
            payer=config.payer,
            rent_payer=self.fee_payer,
            open_slot=config.open_slot,
            last_activity_at=self._clock(),
            binding=self.binding(),
            grace_period=config.withdraw_delay,
        )

    async def _reserve(
        self, outcome: BatchOutcome, authorization: _Authorization
    ) -> tuple[Reservation, ReservationToken | None]:
        now = self._clock()
        lease = self._lease_seconds(self._config.max_timeout_seconds)
        setup: PendingSetup | None = None
        if outcome.deposit_signature is not None and outcome.payload.deposit is not None:
            setup = PendingSetup(
                payer_signature=outcome.deposit_signature,
                deposit=outcome.payload.deposit.amount_units(),
                opens_channel=outcome.opens_channel,
                expires_at=now + lease,
            )
        seed: BatchChannelRecord | None = None
        if outcome.payload.type == "deposit":
            seed = self._seed_state(outcome.channel_id, outcome.payload.channel_config)
            if outcome.opens_channel:
                seed.receiver_binding = str(self._receiver_authorizer)
        request = AuthorizationRequest(
            authorization_id=authorization.id,
            request_fingerprint=authorization.fingerprint,
            amount=outcome.charged_amount,
            cumulative=outcome.max_claimable,
            lease_seconds=lease,
            now=now,
        )
        binding = self.binding()
        withdraw_delay = self._config.withdraw_delay
        result: list[tuple[Reservation, ReservationToken | None]] = []

        def mutate(current: BatchChannelRecord | None) -> BatchChannelRecord | None:
            state = current if current is not None else seed
            if state is None:
                raise BatchStoreError(f"channel {outcome.channel_id} not found")
            refused = state.refuse_reservation(request)
            if refused is not None:
                token = state.token_for_pending(request) if refused is Reservation.HANDLER_SUCCEEDED else None
                result.append((refused, token))
                return current
            state.check_binding_complete(binding)
            state.check_grace_period(withdraw_delay)
            if setup is not None:
                if state.pending_setup is not None and state.pending_setup.payer_signature != setup.payer_signature:
                    raise BatchStoreError(f"channel {state.channel_id} already has a pending setup transaction")
                state.pending_setup = setup
            result.append((Reservation.RESERVED, state.take_reservation(request)))
            return state

        try:
            await self._store.update(outcome.channel_id, mutate)
        except BatchStoreError as exc:
            raise _err(INVALID_CHANNEL_STATE, f"store error: {exc}") from exc
        reservation, token = result[0]
        return reservation, token

    async def _complete_binding(self, outcome: BatchOutcome) -> None:
        """Complete the deployment binding (and grace period) of a record that
        predates it, from a confirmed read of its channel."""
        current = self.binding()
        state = await self._store.get(outcome.channel_id)
        if state is None:
            return
        self._store_check(lambda: state.check_binding(current))
        if state.grace_period is not None:
            self._store_check(lambda: state.check_grace_period(self._config.withdraw_delay))
            if state.binding == current and current.is_complete():
                return
        onchain = await self._lookup_channel(parse_pubkey(outcome.channel_id))
        if onchain is None:
            raise _err(
                INVALID_CHANNEL_STATE,
                f"channel {outcome.channel_id} has no complete deployment binding and is not onchain to complete "
                "it from",
            )
        self._check_channel_bindings(onchain, outcome.payload.channel_config, self._config.pay_to, 0)
        grace_period = onchain.grace_period

        def mutate(record: BatchChannelRecord | None) -> BatchChannelRecord | None:
            if record is None:
                raise BatchStoreError("channel not found")
            record.check_binding(current)
            record.adopt_binding(current)
            record.grace_period = grace_period
            return record

        try:
            await self._store.update(outcome.channel_id, mutate)
        except BatchStoreError as exc:
            raise _err(INVALID_CHANNEL_STATE, f"store error: {exc}") from exc

    async def _reconcile_channel(self, channel_b58: str) -> None:
        """Refresh a record from confirmed chain state before it authorizes
        anything, unless the snapshot is younger than the configured age."""
        now = self._clock()
        state = await self._store.get(channel_b58)
        if state is None or state.is_empty_tombstone():
            return
        if now - state.observed_at < self._config.channel_snapshot_max_age_seconds:
            return
        pending_open = (
            state.pending_setup is not None
            and state.pending_setup.opens_channel
            and state.pending_setup.expires_at >= now
        )
        observation = await self._observe_channel(parse_pubkey(channel_b58), state.observed_slot)
        onchain = observation.channel
        if onchain is None:
            if pending_open:
                return
            raise _err(INVALID_CHANNEL_STATE, f"channel {channel_b58} no longer exists onchain")
        closing = onchain.status != _CHANNEL_STATUS_OPEN or onchain.closure_started_at != 0
        started_at = max(onchain.closure_started_at if onchain.closure_started_at > 0 else now, 1) if closing else None
        if onchain.status not in (_CHANNEL_STATUS_OPEN, _CHANNEL_STATUS_CLOSING):
            lifecycle = "terminal"
        else:
            lifecycle = "closing" if closing else "open"
        fresh: list[bool] = []

        def mutate(record: BatchChannelRecord | None) -> BatchChannelRecord | None:
            if record is None:
                raise BatchStoreError("channel not found")
            record.deposit = max(record.deposit, onchain.deposit)
            record.settled_on_chain = max(record.settled_on_chain, onchain.settlement.settled)
            record.distributed_on_chain = max(record.distributed_on_chain, onchain.settlement.payout_watermark)
            fresh.append(record.record_observation(lifecycle, started_at, observation.slot, now))
            return record

        try:
            await self._store.update(channel_b58, mutate)
        except BatchStoreError as exc:
            raise BatchServerError(f"store error: {exc}") from exc
        if not fresh[0]:
            raise BatchServerError(f"channel account read at slot {observation.slot} is behind the recorded slot")
        if closing:
            raise _err(INVALID_CHANNEL_CLOSING, f"channel {channel_b58} is closing or closed onchain")

    # ── chain reads ──

    def _decode_channel_account(self, channel: Pubkey, owner: Pubkey, data: bytes) -> Channel:
        if owner != self._program_id:
            raise BatchServerError(f"channel account {channel} is owned by {owner}, not the configured program")
        if not data:
            raise BatchServerError("channel decode failed: empty account data")
        if data[0] != _CHANNEL_ACCOUNT_DISCRIMINATOR:
            raise _err(
                INVALID_CHANNEL_STATE, f"account {channel} carries discriminator {data[0]}, not an open payment channel"
            )
        try:
            return Channel.deserialize(data)
        except Exception as exc:  # noqa: BLE001
            raise BatchServerError(f"channel decode failed: {exc}") from exc

    async def _lookup_channel(self, channel: Pubkey) -> Channel | None:
        try:
            account = await self._get_account(channel)
        except Exception as exc:  # noqa: BLE001
            raise BatchServerError(f"channel account fetch failed: {exc}") from exc
        if account is None:
            return None
        return self._decode_channel_account(channel, account[1], account[0])

    async def _observe_channel(self, channel: Pubkey, min_context_slot: int) -> _Observation:
        try:
            slot, account = await self._rpc.get_account_info_with_context(
                str(channel), min_context_slot=min_context_slot or None
            )
        except Exception as exc:  # noqa: BLE001
            raise BatchServerError(f"channel account fetch failed: {exc}") from exc
        if slot is None:
            slot = 0
        if slot < min_context_slot:
            raise BatchServerError(
                f"channel account read at slot {slot} is behind the recorded slot {min_context_slot}"
            )
        if account is None:
            return _Observation(None, slot)
        return _Observation(self._decode_channel_account(channel, Pubkey.from_string(account[1]), account[0]), slot)

    async def _fetch_channel(self, channel: Pubkey) -> Channel:
        onchain = await self._lookup_channel(channel)
        if onchain is None:
            raise _err(INVALID_CHANNEL_STATE, f"channel {channel} does not exist")
        return onchain

    def _check_channel_bindings(
        self, channel: Channel, config: BatchChannelConfig, pay_to: str, min_deposit: int
    ) -> None:
        """Bind every immutable field of a confirmed channel to the payload."""

        def expect(ok: bool, what: str) -> None:
            if not ok:
                raise _err(INVALID_CHANNEL_STATE, f"confirmed channel {what} does not match the payload")

        expect(channel.status == _CHANNEL_STATUS_OPEN, "status")
        expect(channel.deposit >= min_deposit, "deposit")
        expect(str(Pubkey.from_bytes(channel.payer.to_bytes())) == config.payer, "payer")
        expect(Pubkey.from_bytes(channel.payee.to_bytes()) == self._fee_payer, "payee")
        expect(Pubkey.from_bytes(channel.rent_payer.to_bytes()) == self._fee_payer, "rent_payer")
        expect(
            str(Pubkey.from_bytes(channel.authorized_signer.to_bytes())) == config.payer_authorizer, "authorized_signer"
        )
        expect(str(Pubkey.from_bytes(channel.mint.to_bytes())) == config.token, "mint")
        expect(channel.grace_period == config.withdraw_delay, "grace_period")
        expect(channel.open_slot == config.open_slot, "open_slot")
        expected_hash = distribution_hash(_sole_recipient(parse_pubkey(pay_to)))
        expect(bytes(channel.distribution_hash) == expected_hash, "distribution")

    # ── commit ──

    @staticmethod
    def _reservation_of(outcome: BatchOutcome) -> ReservationToken:
        if outcome.reservation is None:
            raise _err(INVALID_PAYLOAD_TYPE, "payment was not reserved; only a reserved authorization commits")
        return outcome.reservation

    async def mark_handler_succeeded(self, outcome: BatchOutcome) -> None:
        """Record that the handler succeeded: past this, a retry only finishes the charge."""
        token = self._reservation_of(outcome)

        def mutate(record: BatchChannelRecord | None) -> BatchChannelRecord | None:
            if record is None:
                raise BatchStoreError("channel not found")
            record.mark_handler_succeeded(token)
            return record

        try:
            await self._store.update(outcome.channel_id, mutate)
        except BatchStoreError as exc:
            raise BatchServerError(f"store error: {exc}") from exc

    async def release_authorization(self, outcome: BatchOutcome) -> None:
        """Release an authorization whose handler failed, so the client may retry it."""
        try:
            authorization = outcome.authorization
            if authorization is None:
                raise _err(INVALID_PAYLOAD_TYPE, "payload reserves no authorization")
            deposit_signature = outcome.deposit_signature

            def mutate(record: BatchChannelRecord | None) -> BatchChannelRecord | None:
                if record is None:
                    raise BatchStoreError("channel not found")
                record.release_authorization(authorization.id, authorization.fingerprint)
                if record.pending_setup is not None and record.pending_setup.payer_signature == deposit_signature:
                    record.pending_setup = None
                return record

            try:
                await self._store.update(outcome.channel_id, mutate)
            except BatchStoreError as exc:
                raise BatchServerError(f"store error: {exc}") from exc
        finally:
            outcome.release()

    def _accepted_response(
        self, outcome: BatchOutcome, commitment_id: str, transaction: str, amount: str, state: BatchChannelRecord
    ) -> BatchSettlementResponse:
        return BatchSettlementResponse(
            success=True,
            payer=outcome.payer,
            transaction=transaction,
            network=outcome.requirements.network,
            amount=amount,
            extra=BatchSettlementExtra(
                commitment_id=commitment_id,
                charged_amount=str(outcome.charged_amount),
                channel_state=self.snapshot(state),
            ),
        )

    async def finish_commit(self, outcome: BatchOutcome) -> BatchSettlementResponse:
        """Broadcast any carried setup transaction, advance the watermark and store
        the response, in one store transition. Safe to retry."""
        try:
            return await self._finish_commit(outcome)
        finally:
            outcome.release()

    async def _finish_commit(self, outcome: BatchOutcome) -> BatchSettlementResponse:
        token = self._reservation_of(outcome)
        voucher = outcome.payload.voucher
        if voucher is None:
            raise _err(INVALID_PAYLOAD_TYPE, "payload carries no voucher")
        transaction = ""
        amount = ""
        confirmed: Channel | None = None
        deposit = outcome.payload.deposit
        if outcome.payload.type == "deposit" and deposit is not None:
            transaction = await self._broadcast_client_transaction(deposit.transaction)
            confirmed = await self._fetch_channel(parse_pubkey(outcome.channel_id))
            self._check_channel_bindings(
                confirmed, outcome.payload.channel_config, outcome.requirements.pay_to, outcome.max_claimable
            )
            amount = deposit.amount
        now = self._clock()
        binding = self.binding()
        stored: list[BatchSettlementResponse] = []

        def respond(record: BatchChannelRecord) -> dict[str, Any]:
            response = self._accepted_response(outcome, voucher.commitment_id(), transaction, amount, record)
            stored.append(response)
            return response.to_dict()

        def mutate(record: BatchChannelRecord | None) -> BatchChannelRecord | None:
            if record is None:
                raise BatchStoreError("channel not found")
            if confirmed is not None:
                record.deposit = max(record.deposit, confirmed.deposit)
                record.settled_on_chain = max(record.settled_on_chain, confirmed.settlement.settled)
                record.distributed_on_chain = max(record.distributed_on_chain, confirmed.settlement.payout_watermark)
                record.open_slot = confirmed.open_slot
                record.grace_period = confirmed.grace_period
                record.rent_payer = self.fee_payer
                record.record_observation("open", None, None, now)
                record.pending_setup = None
                if outcome.deposit_signature and outcome.deposit_signature not in record.processed_topup_signatures:
                    record.processed_topup_signatures.append(outcome.deposit_signature)
            record.check_binding_complete(binding)
            record.last_activity_at = now
            record.commit_authorization(token, voucher.signature, voucher.expires_at, respond)
            return record

        try:
            await self._store.update(outcome.channel_id, mutate)
        except BatchStoreError as exc:
            raise BatchServerError(f"store error: {exc}") from exc
        if stored:
            return stored[0]
        return await self.replay_response(outcome)

    async def replay_response(self, outcome: BatchOutcome) -> BatchSettlementResponse:
        """The accepted settlement response for an idempotent retry. No resource
        body is ever replayed."""
        state = await self._store.get(outcome.channel_id)
        if state is None:
            raise _err(INVALID_CHANNEL_STATE, "channel vanished")
        authorization = outcome.authorization
        committed = state.committed_authorization(authorization.id) if authorization is not None else None
        if committed is not None and authorization is not None:
            if committed.request_fingerprint != authorization.fingerprint:
                raise _err(
                    INVALID_CUMULATIVE_AMOUNT_MISMATCH,
                    f"authorization {authorization.id} was committed for different payment requirements",
                )
            if committed.settlement_response is not None:
                return BatchSettlementResponse.from_dict(committed.settlement_response)
        replay = replace(outcome, charged_amount=outcome.requirements.amount_units(), release_hook=None)
        return self._accepted_response(replay, f"{outcome.channel_id}:{outcome.max_claimable}", "", "", state)

    async def settle_payment(self, outcome: BatchOutcome) -> BatchSettlementResponse:
        """Commit a verified payment. A ``refund`` closes the channel; a
        ``voucher`` or ``deposit`` is charged via :meth:`finish_commit` (only
        after the handler succeeded)."""
        if outcome.payload.type in ("voucher", "deposit"):
            return await self.finish_commit(outcome)
        try:
            if outcome.payload.type != "refund":
                raise _err(INVALID_PAYLOAD_TYPE, "authorization payloads belong to server-signed channels")
            state = await self._store.get(outcome.channel_id)
            done = state.cooperative_close if state is not None else None
            if state is not None and done is not None and done.get("cumulative") == outcome.max_claimable:
                return self._close_response(
                    outcome, str(done.get("transaction", "")), str(done.get("refunded", "")), state
                )
            if outcome.payload.transaction is None:
                return await self._cooperative_close(outcome)
            return await self._request_close(outcome, outcome.payload.transaction)
        finally:
            outcome.release()

    def _close_response(
        self, outcome: BatchOutcome, transaction: str, amount: str, state: BatchChannelRecord
    ) -> BatchSettlementResponse:
        return BatchSettlementResponse(
            success=True,
            payer=outcome.payer,
            transaction=transaction,
            network=outcome.requirements.network,
            amount=amount,
            extra=BatchSettlementExtra(channel_state=self.snapshot(state)),
        )

    async def _record_close(self, channel_id: str, channel: Channel) -> BatchChannelRecord:
        closed_at = channel.closure_started_at if channel.closure_started_at >= 0 else self._clock()

        def mutate(record: BatchChannelRecord | None) -> BatchChannelRecord | None:
            if record is None:
                raise BatchStoreError("channel not found")
            record.close_requested_at = closed_at
            record.last_activity_at = self._clock()
            return record

        updated = await self._store.update(channel_id, mutate)
        assert updated is not None
        return updated

    async def _request_close(self, outcome: BatchOutcome, transaction: str) -> BatchSettlementResponse:
        channel = parse_pubkey(outcome.channel_id)
        onchain = await self._fetch_channel(channel)
        signature = ""
        if onchain.status == _CHANNEL_STATUS_OPEN:
            state = await self._store.get(outcome.channel_id)
            if state is not None and state.cumulative > onchain.settlement.settled:
                await self.claim([outcome.channel_id])
            signature = await self._broadcast_client_transaction(transaction)
        elif onchain.status != _CHANNEL_STATUS_CLOSING:
            raise _err(INVALID_CLOSE_STATE, "channel cannot be closed")
        onchain = await self._fetch_channel(channel)
        if onchain.status != _CHANNEL_STATUS_CLOSING:
            raise _err(INVALID_CLOSE_STATE, "request_close did not move the channel to Closing")
        state = await self._record_close(outcome.channel_id, onchain)
        return self._close_response(outcome, signature, "", state)

    async def _cooperative_close(self, outcome: BatchOutcome) -> BatchSettlementResponse:
        """Close at the refund voucher: ``settle_and_seal`` (with the voucher when
        above the onchain ``settled``) then the sealed ``distribute``, returning
        ``deposit - settled`` to the payer in one transaction."""
        voucher = outcome.payload.voucher
        assert voucher is not None  # verification refused a voucherless refund
        config = outcome.payload.channel_config
        cumulative = outcome.max_claimable
        channel = parse_pubkey(outcome.channel_id)
        onchain = await self._fetch_channel(channel)
        if onchain.status == _CHANNEL_STATUS_CLOSING:
            state = await self._record_close(outcome.channel_id, onchain)
            return self._close_response(outcome, "", "", state)
        if onchain.status != _CHANNEL_STATUS_OPEN:
            raise _err(INVALID_CLOSE_STATE, f"channel status {onchain.status} cannot be closed")
        self._check_channel_bindings(onchain, config, outcome.requirements.pay_to, cumulative)
        if onchain.settlement.settled > cumulative:
            raise _err(
                INVALID_CLOSE_STATE,
                f"refund voucher {cumulative} is behind the onchain settled {onchain.settlement.settled}",
            )
        await self._fence_close(outcome.channel_id, cumulative)
        instructions = self._seal_and_distribute_instructions(
            channel, onchain, parse_pubkey(config.payer_authorizer), voucher.signature, cumulative, voucher.expires_at
        )
        signatures = await self._submit_groups([instructions], 1)
        signature = signatures[0] if signatures else ""
        after = await self._lookup_channel(channel)
        if after is not None and after.status != _CHANNEL_STATUS_DISTRIBUTED:
            raise _err(INVALID_CLOSE_STATE, f"cooperative close confirmed but the channel is in status {after.status}")
        refunded = str(max(onchain.deposit - cumulative, 0))

        def mutate(record: BatchChannelRecord | None) -> BatchChannelRecord | None:
            if record is None:
                raise BatchStoreError("channel not found")
            record.sealed = True
            record.settled_on_chain = max(record.settled_on_chain, cumulative)
            record.last_activity_at = self._clock()
            record.cooperative_close = {"cumulative": cumulative, "transaction": signature, "refunded": refunded}
            return record

        state = await self._store.update(outcome.channel_id, mutate)
        assert state is not None
        return self._close_response(outcome, signature, refunded, state)

    async def _fence_close(self, channel_id: str, cumulative: int) -> None:
        """Freeze the watermark at the close, refused while a paid request is
        reserved or when the accepted cumulative moved since verification."""
        now = self._clock()

        def mutate(record: BatchChannelRecord | None) -> BatchChannelRecord | None:
            if record is None:
                raise BatchStoreError("channel not found")
            if record.pending:
                raise _err(INVALID_CLOSE_STATE, f"channel {record.channel_id} has a paid request in flight")
            if record.cumulative != cumulative:
                raise _err(
                    INVALID_CLOSE_STATE,
                    f"accepted cumulative moved to {record.cumulative} since the refund was verified",
                )
            if record.final_cumulative is not None and record.final_cumulative != cumulative:
                raise _err(
                    INVALID_CLOSE_STATE, f"channel {record.channel_id} is already closing at {record.final_cumulative}"
                )
            record.close_requested_at = record.close_requested_at or now
            record.final_cumulative = cumulative
            return record

        await self._store.update(channel_id, mutate)

    def _seal_and_distribute_instructions(
        self,
        channel: Pubkey,
        onchain: Channel,
        authorized_signer: Pubkey,
        voucher_signature: str | None,
        cumulative: int,
        expires_at: int,
    ) -> list[Instruction]:
        signature = (
            bytes(Signature.from_string(voucher_signature))
            if voucher_signature is not None and onchain.settlement.settled < cumulative
            else None
        )
        instructions = build_settle_and_seal_instructions(
            payee=self._fee_payer,
            channel=channel,
            authorized_signer=authorized_signer,
            signature=signature,
            cumulative=cumulative,
            expires_at=expires_at,
            program_id=self._program_id,
        )
        instructions.append(self._distribute_instruction(channel, onchain))
        return instructions

    def _distribute_instruction(self, channel: Pubkey, onchain: Channel) -> Instruction:
        return build_distribute_instruction(
            channel=channel,
            payer=Pubkey.from_bytes(onchain.payer.to_bytes()),
            payee=self._fee_payer,
            mint=self.mint(),
            recipients=_sole_recipient(parse_pubkey(self._config.pay_to)),
            token_program=self.token_program(),
            program_id=self._program_id,
            treasury=self._treasury_owner(),
            rent_payer=self._fee_payer,
        )

    def _settle_instructions(
        self, channel: Pubkey, authorized_signer: Pubkey, signature: str, cumulative: int, expires_at: int
    ) -> list[Instruction]:
        """The Ed25519 precompile and the program ``settle`` reading it back (adjacent)."""
        message = voucher_message_bytes(channel, cumulative, expires_at)
        precompile = build_ed25519_verify_instruction(
            authorized_signer, bytes(Signature.from_string(signature)), message
        )
        settle = Instruction(
            self._program_id,
            SettleInstructionData().serialize(),
            [
                AccountMeta(channel, is_signer=False, is_writable=True),
                AccountMeta(Pubkey.from_string(SYSVAR_INSTRUCTIONS), is_signer=False, is_writable=False),
            ],
        )
        return [precompile, settle]

    # ── broadcast ──

    async def _cosign(self, transaction_b64: str) -> bytes:
        tx = decode_transaction(transaction_b64)
        keys = list(tx.message.account_keys)
        if not keys or keys[0] != self._fee_payer:
            raise BatchServerError("setup transaction fee payer must be the advertised fee payer")
        signer = self._config.fee_payer_signer
        if txv1.is_v1(tx):
            signatures = list(tx.signatures)
            signatures[0] = await signer.sign_message(bytes(tx.message))
            return bytes(txv1.populate(tx.message, signatures))
        signed = await signer.sign_transaction(tx)
        return bytes(signed.transaction)

    async def _broadcast_client_transaction(self, transaction_b64: str) -> str:
        """Co-sign a validated client transaction as fee payer, simulate, send and
        confirm it. A transaction that already landed is reported as such."""
        wire = await self._cosign(transaction_b64)
        signature = str(txv1.decode_transaction(wire).signatures[0])
        if await self._signature_confirmed(signature):
            return signature
        simulation = await self._rpc.simulate_transaction(wire)
        error = simulation.get("err")
        if error is not None:
            if await self._signature_confirmed(signature):
                return signature
            raw_logs: Any = simulation.get("logs") or []
            logs = " | ".join(str(line) for line in cast("list[Any]", raw_logs))
            raise _err(INVALID_SETTLEMENT_SIMULATION, f"simulation failed: {error}; program logs: {logs}")
        try:
            sent = await self._rpc.send_raw_transaction(wire)
            await self._rpc.await_confirmation(str(sent.value))
        except Exception as exc:  # noqa: BLE001
            if await self._signature_confirmed(signature):
                return signature
            raise BatchServerError(f"broadcast failed: {exc}") from exc
        return str(sent.value)

    async def _signature_confirmed(self, signature: str) -> bool:
        try:
            statuses = await self._rpc.get_signature_statuses([signature])
        except Exception:  # noqa: BLE001
            return False
        raw: Any = statuses[0] if statuses else None
        if not isinstance(raw, dict):
            return False
        status = cast("dict[str, Any]", raw)
        if status.get("err") is not None:
            raise _err(INVALID_SETTLEMENT_SIMULATION, f"deposit transaction landed but failed: {status.get('err')}")
        return status.get("confirmationStatus") in ("confirmed", "finalized")

    async def _submit_groups(self, groups: list[list[Instruction]], max_per_tx: int) -> list[str]:
        """Sign and submit redemption groups, at most ``max_per_tx`` channels per
        transaction, built in this server's highest accepted version."""
        signatures: list[str] = []
        version = self._tx_version()
        for start in range(0, len(groups), max(max_per_tx, 1)):
            instructions = [ix for group in groups[start : start + max_per_tx] for ix in group]
            hint = await self._rpc.get_latest_blockhash()
            blockhash = Hash.from_string(str(hint.value.blockhash))
            wire = await self._sign_redemption(instructions, blockhash, version)
            sent = await self._rpc.send_raw_transaction(wire)
            await self._rpc.await_confirmation(str(sent.value))
            signatures.append(str(sent.value))
        return signatures

    async def _sign_redemption(self, instructions: list[Instruction], blockhash: Hash, version: int) -> bytes:
        from solders.message import MessageV0  # type: ignore[import-untyped]
        from solders.transaction import VersionedTransaction  # type: ignore[import-untyped]

        signer = self._config.fee_payer_signer
        if version == 1:
            config = txv1.v1_config(txv1.runtime_default_unit_limit(len(instructions)), 0)
            message = txv1.MessageV1.try_compile(self._fee_payer, instructions, blockhash, config)
            signature = await signer.sign_message(bytes(message))
            return bytes(txv1.TransactionV1.populate(message, [signature]))
        message = MessageV0.try_compile(self._fee_payer, instructions, [], blockhash)
        unsigned = VersionedTransaction.populate(message, [Signature.default()])
        signed = await signer.sign_transaction(unsigned)
        return bytes(signed.transaction)

    # ── redemption ──

    async def claim(self, channel_ids: Sequence[str]) -> list[str]:
        """Advance each channel's onchain ``settled`` watermark to its latest
        stored voucher (program ``settle``). The channels stay open."""
        groups: list[list[Instruction]] = []
        claimed: list[tuple[str, int]] = []
        for channel_id in channel_ids:
            onchain = await self._lookup_channel(parse_pubkey(channel_id))
            if onchain is None or onchain.status != _CHANNEL_STATUS_OPEN or onchain.closure_started_at != 0:
                continue
            settled = onchain.settlement.settled
            state = await self._update_settled(channel_id, settled)
            if state.highest_voucher_signature is None or state.cumulative <= state.settled_on_chain:
                continue
            groups.append(
                self._settle_instructions(
                    parse_pubkey(channel_id),
                    parse_pubkey(state.payer_authorizer),
                    state.highest_voucher_signature,
                    state.cumulative,
                    state.highest_voucher_expires_at or VOUCHER_EXPIRES_AT,
                )
            )
            claimed.append((channel_id, state.cumulative))
        signatures = await self._submit_groups(groups, self.redemption_capacity()[0])
        for channel_id, cumulative in claimed:
            await self._update_settled(channel_id, cumulative)
        return signatures

    async def _update_settled(
        self, channel_id: str, settled: int, distributed: int | None = None
    ) -> BatchChannelRecord:
        def mutate(record: BatchChannelRecord | None) -> BatchChannelRecord | None:
            if record is None:
                raise _err(INVALID_CHANNEL_STATE, f"unknown channel {channel_id}")
            record.settled_on_chain = max(record.settled_on_chain, settled)
            if distributed is not None:
                record.distributed_on_chain = max(record.distributed_on_chain, distributed)
            record.last_activity_at = self._clock()
            return record

        updated = await self._store.update(channel_id, mutate)
        assert updated is not None
        return updated

    async def settle(self, channel_ids: Sequence[str]) -> list[str]:
        """Pay each channel's newly claimed delta to ``payTo`` (program
        ``distribute``). The channels stay open."""
        groups: list[list[Instruction]] = []
        distributed: list[tuple[str, int]] = []
        for channel_id in channel_ids:
            channel = parse_pubkey(channel_id)
            onchain = await self._lookup_channel(channel)
            if onchain is None or onchain.status != _CHANNEL_STATUS_OPEN or onchain.closure_started_at != 0:
                continue
            if onchain.settlement.settled <= onchain.settlement.payout_watermark:
                continue
            groups.append([self._distribute_instruction(channel, onchain)])
            distributed.append((channel_id, onchain.settlement.settled))
        signatures = await self._submit_groups(groups, self.redemption_capacity()[1])
        for channel_id, settled in distributed:
            await self._update_settled(channel_id, settled, settled)
        return signatures

    async def finalize_close(self, channel_ids: Sequence[str]) -> list[str]:
        """Seal each channel its payer started closing with this server's latest
        voucher (``settle_and_seal``) and distribute it, inside the grace period.
        A channel with a paid request still reserved is skipped until it settles."""
        groups: list[list[Instruction]] = []
        sealed: list[tuple[str, int]] = []
        now = self._clock()
        for channel_id in channel_ids:
            channel = parse_pubkey(channel_id)
            onchain = await self._lookup_channel(channel)
            if onchain is None:
                continue
            if onchain.status == _CHANNEL_STATUS_SEALED:
                groups.append([self._distribute_instruction(channel, onchain)])
                continue
            if onchain.status != _CHANNEL_STATUS_CLOSING:
                continue
            state = await self._store.get(channel_id)
            if state is None or any(not p.handler_succeeded and p.expires_at > now for p in state.pending):
                continue
            cumulative = max(state.cumulative, onchain.settlement.settled)
            closed_at = max(onchain.closure_started_at, 1)

            def freeze(
                record: BatchChannelRecord | None, cumulative: int = cumulative, closed_at: int = closed_at
            ) -> BatchChannelRecord | None:
                if record is None:
                    raise BatchStoreError("channel not found")
                record.close_requested_at = record.close_requested_at or closed_at
                record.final_cumulative = cumulative
                return record

            await self._store.update(channel_id, freeze)
            groups.append(
                self._seal_and_distribute_instructions(
                    channel,
                    onchain,
                    parse_pubkey(state.payer_authorizer),
                    state.highest_voucher_signature,
                    cumulative,
                    state.highest_voucher_expires_at or VOUCHER_EXPIRES_AT,
                )
            )
            sealed.append((channel_id, cumulative))
        signatures = await self._submit_groups(groups, 1)
        for channel_id, cumulative in sealed:

            def mark(record: BatchChannelRecord | None, cumulative: int = cumulative) -> BatchChannelRecord | None:
                if record is None:
                    raise BatchStoreError("channel not found")
                record.sealed = True
                record.sealed_at = record.sealed_at or self._clock()
                record.settled_on_chain = max(record.settled_on_chain, cumulative)
                return record

            await self._store.update(channel_id, mark)
        return signatures
