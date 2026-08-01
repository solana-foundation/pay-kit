"""Client-side helpers for payment-channel open transactions.

This is the challenge-driven layer above the raw instruction builders in
:mod:`solana_pay_kit.protocols.mpp._paymentchannels`: it derives the full channel open
from a :class:`~solana_pay_kit.protocols.mpp.intents.session.SessionRequest`
challenge (mint from the currency, deposit from its advertised deposit hints,
token program from the currency, splits, salt, and the opening slot) and
assembles the partially signed open transaction the operator broadcasts.

Encoding boundary: the open transaction travels as standard-alphabet base64
WITH padding (it is an opaque transaction, not part of the canonical-JSON
credential envelope).
"""

from __future__ import annotations

import base64
import secrets
from dataclasses import dataclass, field
from typing import Any, cast

from solders.hash import Hash  # type: ignore[import-untyped]
from solders.keypair import Keypair  # type: ignore[import-untyped]
from solders.message import Message  # type: ignore[import-untyped]
from solders.pubkey import Pubkey  # type: ignore[import-untyped]
from solders.signature import Signature  # type: ignore[import-untyped]
from solders.transaction import Transaction  # type: ignore[import-untyped]

from solana_pay_kit._paycore.mints import resolve_stablecoin_mint
from solana_pay_kit._paycore.solana import default_token_program_for_currency
from solana_pay_kit.protocols.mpp._paymentchannels import (
    Distribution,
    OpenChannelParams,
    build_open_instruction,
    find_channel_pda,
)
from solana_pay_kit.protocols.mpp.client.session import ActiveSession, VoucherSigner, _pubkey_str
from solana_pay_kit.protocols.mpp.intents.session import (
    DEFAULT_SESSION_EXPIRES_AT,
    OpenPayload,
    SessionAction,
    SessionAuthentication,
    SessionRequest,
    SessionSplit,
    _parse_base_units,
)

__all__ = [
    "DEFAULT_GRACE_PERIOD_SECONDS",
    "PaymentChannelOpen",
    "PaymentChannelOpenTransaction",
    "PaymentChannelOpenOptions",
    "PaymentChannelSessionOpen",
    "PaymentChannelSessionOpenOptions",
    "build_open_payment_channel_transaction",
    "create_payment_channel_session_opener",
    "derive_payment_channel_open",
    "generate_authorized_signer",
    "unique_salt",
]

#: Default payment-channel close grace period, in seconds, applied to a derived
#: open when the caller does not override it.
DEFAULT_GRACE_PERIOD_SECONDS = 900

_U64_MAX = 2**64 - 1


def unique_salt() -> int:
    """Return a random u64 channel salt.

    Draws eight bytes from the cryptographically secure RNG and interprets them
    little-endian. The salt distinguishes channels that share the same payer,
    payee, mint, and authorized signer so each derives a distinct channel PDA.
    """
    return int.from_bytes(secrets.token_bytes(8), "little")


def generate_authorized_signer() -> Keypair:
    """Generate an ephemeral session signing key.

    The keypair's public key becomes the channel ``authorizedSigner``; pass the
    keypair to the openers (or directly to :class:`ActiveSession`) as the
    session signer. Use this when the caller does not already hold a dedicated
    signer for the session and wants one minted on the spot.
    """
    return Keypair()


@dataclass
class PaymentChannelOpen:
    """A fully derived payment-channel open: addresses plus channel parameters.

    Holds everything needed to open one channel: the derived channel PDA, the
    payer and payee, the SPL mint and its token program, the authorized session
    signer, the salt that made the PDA unique, the deposit amount and close
    grace period (both in base units / seconds), the payout split recipients,
    and the on-chain program that owns the channel.
    """

    #: Derived on-chain channel account address (the channel PDA).
    channel_id: Pubkey
    #: Account that funds the deposit and signs the open transaction.
    payer: Pubkey
    #: Account that receives the channel payouts.
    payee: Pubkey
    #: SPL token mint the channel is denominated in.
    mint: Pubkey
    #: Ephemeral public key authorized to sign vouchers against the channel.
    authorized_signer: Pubkey
    #: u64 salt that makes the channel PDA unique for a given key tuple.
    salt: int
    #: Amount, in token base units, deposited into the channel on open.
    deposit: int
    #: Close grace period, in seconds, before the channel can be torn down.
    grace_period: int
    #: Challenge-provided slot the channel is opened at (a channel PDA seed).
    open_slot: int
    #: Payout split recipients and their basis-point shares.
    recipients: list[Distribution]
    #: SPL token program owning the mint (classic Token or Token-2022).
    token_program: Pubkey
    #: On-chain program that owns the channel account.
    program_id: Pubkey

    def open_channel_params(self) -> OpenChannelParams:
        """Return the instruction-builder params for this open.

        Repackages the derived addresses and parameters into the argument
        object the low-level open-instruction builder expects.
        """
        return OpenChannelParams(
            payer=self.payer,
            payee=self.payee,
            mint=self.mint,
            authorized_signer=self.authorized_signer,
            salt=self.salt,
            deposit=self.deposit,
            grace_period=self.grace_period,
            open_slot=self.open_slot,
            recipients=list(self.recipients),
            token_program=self.token_program,
            program_id=self.program_id,
        )

    def open_payload(
        self,
        transaction: str,
        *,
        authentication: SessionAuthentication | None = None,
        idle_timeout_seconds: int | None = None,
    ) -> OpenPayload:
        """Build the open action payload carrying the full channel parameters.

        Serializes the channel's addresses, deposit, salt, grace period, and
        authorized signer into the ``open`` payload sent to the operator,
        along with the signed transaction the server must verify and submit.
        """
        return OpenPayload(
            channel_id=str(self.channel_id),
            payer=str(self.payer),
            payee=str(self.payee),
            mint=str(self.mint),
            authorized_signer=str(self.authorized_signer),
            salt=self.salt,
            deposit_amount=str(self.deposit),
            grace_period_seconds=self.grace_period,
            idle_timeout_seconds=idle_timeout_seconds,
            open_slot=self.open_slot,
            distribution_splits=[
                SessionSplit(recipient=str(split.recipient), share_bps=split.bps) for split in self.recipients
            ],
            authentication=authentication,
            transaction=transaction,
        )


@dataclass
class PaymentChannelOpenTransaction:
    """A built open transaction plus the channel it opens."""

    #: Derived on-chain channel account address the transaction opens.
    channel_id: Pubkey
    #: Serialized open transaction as standard-alphabet base64 with padding.
    transaction: str


@dataclass
class PaymentChannelOpenOptions:
    """Optional overrides for deriving a payment-channel open.

    Every field falls back to a challenge-derived default: ``deposit`` to the
    challenge ``suggestedDeposit`` or ``minimumDeposit``, ``grace_period`` to
    :data:`DEFAULT_GRACE_PERIOD_SECONDS`, ``program_id`` to nested
    ``methodDetails.channelProgram``, ``recipients`` to the nested
    ``distributionSplits``, ``salt`` to :func:`unique_salt`, and
    ``token_program`` to the program resolved from the challenge currency
    (Token-2022 for PYUSD/USDG/CASH). ``open_slot`` defaults to the
    challenge's ``methodDetails.recentSlot``.
    """

    #: Deposit in token base units; defaults to the challenge's deposit hint.
    deposit: int | None = None
    #: Close grace period in seconds; defaults to :data:`DEFAULT_GRACE_PERIOD_SECONDS`.
    grace_period: int | None = None
    #: Override for the channel's open slot (the program's ``openSlot``).
    #: Defaults to the challenge's ``recentSlot``. An override MAY be earlier
    #: (shortening the operator's post-close rent float) but never later —
    #: the server rejects an ``openSlot`` ahead of its challenged
    #: ``recentSlot``.
    open_slot: int | None = None
    #: Owning program; defaults to ``methodDetails.channelProgram``.
    program_id: Pubkey | None = None
    #: Payout split recipients; defaults to the challenge ``splits``.
    recipients: list[Distribution] | None = None
    #: Channel salt; defaults to a fresh value from :func:`unique_salt`.
    salt: int | None = None
    #: SPL token program; defaults to the program resolved from the currency.
    token_program: Pubkey | None = None


@dataclass
class PaymentChannelSessionOpen:
    """A derived open, the session tracking it, and the open action to send."""

    #: The fully derived channel open (addresses and parameters).
    open: PaymentChannelOpen
    #: Live session keyed to the derived channel, ready to issue vouchers.
    session: ActiveSession
    #: Open action to send to the operator to register the channel.
    action: SessionAction


@dataclass
class PaymentChannelSessionOpenOptions:
    """Options for :func:`create_payment_channel_session_opener`."""

    #: Overrides for deriving the channel open.
    open: PaymentChannelOpenOptions = field(default_factory=PaymentChannelOpenOptions)
    #: Payer proof required when the operator signs vouchers.
    authentication: SessionAuthentication | None = None
    #: Idle timeout selected from the challenge's advertised options.
    idle_timeout_seconds: int | None = None
    #: Initial cumulative spent amount for the session; defaults to 0.
    cumulative: int | None = None
    #: Session expiry as a Unix timestamp; defaults to the session default.
    expires_at: int | None = None


def derive_payment_channel_open(
    request: SessionRequest,
    payer: Pubkey,
    authorized_signer: Pubkey,
    options: PaymentChannelOpenOptions | None = None,
) -> PaymentChannelOpen:
    """Derive the full channel open from a session challenge.

    Resolves the mint, deposit policy, token program, distributions, channel
    program, open slot, and salt before deriving the exact channel PDA. Any
    field set on ``options`` overrides the corresponding challenge policy.
    ``open_slot`` defaults to the challenge's ``methodDetails.recentSlot``; an
    explicit earlier override is allowed, a later one is rejected (the server
    enforces the same bound).
    """
    options = options if options is not None else PaymentChannelOpenOptions()
    details = request.method_details
    network = details.network
    resolved_mint = resolve_stablecoin_mint(request.currency, network)
    if resolved_mint is None:
        raise ValueError("session payment channels require an SPL token")
    mint = _parse_pubkey(resolved_mint, "mint")
    payee = _parse_pubkey(request.recipient, "recipient")
    requested_deposit = request.suggested_deposit or request.minimum_deposit
    if options.deposit is None and requested_deposit is None:
        raise ValueError("session challenge does not provide suggestedDeposit or minimumDeposit")
    deposit = (
        options.deposit if options.deposit is not None else _parse_u64_string(cast("str", requested_deposit), "deposit")
    )
    grace_period = (
        options.grace_period
        if options.grace_period is not None
        else details.grace_period_seconds or DEFAULT_GRACE_PERIOD_SECONDS
    )
    if options.program_id is not None:
        program_id = options.program_id
    else:
        program_id = _parse_pubkey(details.channel_program, "channelProgram")
    if options.token_program is not None:
        token_program = options.token_program
    else:
        token_program = _parse_pubkey(
            details.token_program or default_token_program_for_currency(request.currency, network),
            "token program",
        )
    if options.recipients is not None:
        recipients = list(options.recipients)
    else:
        recipients = [
            Distribution(recipient=_parse_pubkey(split.recipient, "split recipient"), bps=split.share_bps)
            for split in details.distribution_splits
        ]
    salt = options.salt if options.salt is not None else unique_salt()
    open_slot = options.open_slot
    if open_slot is not None:
        # An override MAY be earlier than the challenged recentSlot, never
        # later: the server rejects an openSlot ahead of its challenge.
        if details.recent_slot is not None and open_slot > details.recent_slot:
            raise ValueError(
                f"openSlot override {open_slot} is ahead of the challenged recentSlot {details.recent_slot}"
            )
    else:
        if details.recent_slot is None:
            raise ValueError("session challenge is missing recentSlot; a new-channel challenge must provide it")
        open_slot = details.recent_slot
    channel_id, _ = find_channel_pda(payer, payee, mint, authorized_signer, salt, open_slot, program_id)

    return PaymentChannelOpen(
        channel_id=channel_id,
        payer=payer,
        payee=payee,
        mint=mint,
        authorized_signer=authorized_signer,
        salt=salt,
        deposit=deposit,
        grace_period=grace_period,
        open_slot=open_slot,
        recipients=recipients,
        token_program=token_program,
        program_id=program_id,
    )


def _resolve_open_blockhash(override: Hash | str | None, request: SessionRequest) -> Hash:
    """Resolve the open transaction's blockhash: an explicit override wins,
    otherwise the challenged ``recentBlockhash`` is required — the client
    never fetches its own (the server requires the compiled message to use
    the challenged value).
    """
    if override is not None:
        return override if isinstance(override, Hash) else Hash.from_string(override)
    challenged = request.method_details.recent_blockhash
    if not challenged:
        raise ValueError("session challenge is missing recentBlockhash; a new-channel challenge must provide it")
    try:
        return Hash.from_string(challenged)
    except Exception as exc:  # noqa: BLE001 - solders raises its own parse error type
        raise ValueError(f"invalid challenged recentBlockhash: {exc}") from exc


def build_open_payment_channel_transaction(
    request: SessionRequest,
    signer: VoucherSigner | Any,
    authorized_signer: Pubkey,
    recent_blockhash: Hash | str | None = None,
    fee_payer: Pubkey | None = None,
    options: PaymentChannelOpenOptions | None = None,
) -> PaymentChannelOpenTransaction:
    """Build the payer-signed open transaction for operator broadcast.

    ``recent_blockhash`` left ``None`` (the default) takes the challenge's
    ``methodDetails.recentBlockhash``, which the server requires the compiled
    message to use; an explicit override is for tests and custom flows that
    re-issue their own challenge binding.

    When the challenge advertises fee sponsorship, the transaction uses its
    ``feePayerKey`` and leaves that signature slot empty for the server.
    Otherwise the payer is also the fee payer.
    """
    payer = _signer_pubkey(signer)
    details = request.method_details
    advertised_fee_payer = (
        _parse_pubkey(_require_string(details.fee_payer_key, "feePayerKey"), "feePayerKey")
        if details.fee_payer
        else payer
    )
    if fee_payer is None:
        fee_payer = advertised_fee_payer
    elif fee_payer != advertised_fee_payer:
        raise ValueError("fee_payer does not match the challenge fee-payer policy")
    open_ = derive_payment_channel_open(
        request,
        payer,
        authorized_signer,
        options,
    )
    return _build_open_payment_channel_tx(signer, open_, fee_payer, _resolve_open_blockhash(recent_blockhash, request))


def create_payment_channel_session_opener(
    request: SessionRequest,
    payer_signer: VoucherSigner | Any,
    session_signer: VoucherSigner | Any,
    recent_blockhash: Hash | str | None = None,
    options: PaymentChannelSessionOpenOptions | None = None,
) -> PaymentChannelSessionOpen:
    """Build a strict session open action and its signed open transaction.

    ``recent_blockhash`` left ``None`` (the default) takes the challenge's
    ``methodDetails.recentBlockhash``; the derived ``openSlot`` likewise
    defaults to the challenged ``recentSlot`` (see
    :class:`PaymentChannelOpenOptions`).
    """
    options = options if options is not None else PaymentChannelSessionOpenOptions()
    if request.method_details.voucher_signer == "operator" and options.authentication is None:
        raise ValueError("operator voucher signing requires authentication")
    if options.idle_timeout_seconds is not None:
        from solana_pay_kit.protocols.mpp.intents.session import resolve_idle_timeout_seconds

        resolve_idle_timeout_seconds(
            request.method_details.idle_timeout_seconds or 300,
            request.method_details.idle_timeout_options_seconds,
            options.idle_timeout_seconds,
        )
    authorized_signer = (
        _parse_pubkey(_require_string(request.method_details.operator, "operator"), "operator")
        if request.method_details.voucher_signer == "operator"
        else _signer_pubkey(session_signer)
    )
    payer = _signer_pubkey(payer_signer)
    details = request.method_details
    fee_payer = (
        _parse_pubkey(_require_string(details.fee_payer_key, "feePayerKey"), "feePayerKey")
        if details.fee_payer
        else payer
    )
    open_ = derive_payment_channel_open(
        request,
        _signer_pubkey(payer_signer),
        authorized_signer,
        options.open,
    )
    blockhash = _resolve_open_blockhash(recent_blockhash, request)
    tx = _build_open_payment_channel_tx(payer_signer, open_, fee_payer, blockhash)
    session = _configured_session(open_.channel_id, session_signer, options.cumulative, options.expires_at)
    action = SessionAction.open_action(
        open_.open_payload(
            tx.transaction,
            authentication=options.authentication,
            idle_timeout_seconds=options.idle_timeout_seconds,
        )
    )
    return PaymentChannelSessionOpen(open=open_, session=session, action=action)


def _build_open_payment_channel_tx(
    signer: VoucherSigner | Any,
    open_: PaymentChannelOpen,
    fee_payer: Pubkey,
    recent_blockhash: Hash | str,
) -> PaymentChannelOpenTransaction:
    """Assemble the open message and partial-sign only the payer slot.

    Builds a legacy transaction whose fee payer is the operator (its signature
    slot left as the default placeholder) and whose payer signature slot is
    filled in, serialized as standard-alphabet base64 with padding.
    """
    blockhash = recent_blockhash if isinstance(recent_blockhash, Hash) else Hash.from_string(recent_blockhash)
    open_params = open_.open_channel_params()
    # rentPayer is pinned to the operator / fee payer already in scope.
    open_params.rent_payer = fee_payer
    ix = build_open_instruction(open_params)
    message = Message.new_with_blockhash([ix], fee_payer, blockhash)
    message_bytes = bytes(message)

    payer = _signer_pubkey(signer)
    num_required = message.header.num_required_signatures
    signer_keys = list(message.account_keys)[:num_required]
    try:
        payer_index = signer_keys.index(payer)
    except ValueError as exc:
        raise ValueError("payment-channel open signing failed: payer is not a transaction signer") from exc

    signatures = [Signature.default() for _ in range(num_required)]
    signatures[payer_index] = _sign_message(signer, message_bytes)
    tx = Transaction.populate(message, signatures)
    encoded = base64.b64encode(bytes(tx)).decode("ascii")
    return PaymentChannelOpenTransaction(channel_id=open_.channel_id, transaction=encoded)


def _configured_session(
    channel_id: Pubkey,
    session_signer: VoucherSigner | Any,
    cumulative: int | None,
    expires_at: int | None,
) -> ActiveSession:
    """Build the opener's ActiveSession with resume options applied.

    Keys the session to the derived channel and the session signer, applying
    the supplied expiry and cumulative-spent values or their defaults when
    ``None`` (useful for resuming a session at a known cumulative amount).
    """
    return ActiveSession(
        channel_id,
        session_signer,
        expires_at if expires_at is not None else DEFAULT_SESSION_EXPIRES_AT,
        cumulative=cumulative if cumulative is not None else 0,
    )


def _sign_message(signer: Any, message: bytes) -> Signature:
    """Sign raw message bytes with a solana_pay_kit signer or a solders Keypair."""
    sign = getattr(signer, "sign", None)
    if callable(sign):
        raw = cast("bytes", sign(message))
        return Signature.from_bytes(bytes(raw))
    return signer.sign_message(message)


def _signer_pubkey(signer: Any) -> Pubkey:
    """Return the signer's public key as a solders Pubkey."""
    return Pubkey.from_string(_pubkey_str(signer))


def _parse_u64_string(value: str, label: str) -> int:
    """Parse a u64 decimal string, raising a labeled ``ValueError`` on failure."""
    try:
        return _parse_base_units(value)
    except ValueError as exc:
        raise ValueError(f"invalid {label}: {value!r}") from exc


def _parse_pubkey(value: str, label: str) -> Pubkey:
    """Parse a base58 pubkey, raising a labeled ``ValueError`` on failure."""
    try:
        return Pubkey.from_string(value)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"invalid {label}: {value!r}") from exc


def _require_string(value: str | None, label: str) -> str:
    if not value:
        raise ValueError(f"{label} is required")
    return value
