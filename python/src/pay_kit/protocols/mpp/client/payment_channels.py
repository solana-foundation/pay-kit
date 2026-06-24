"""Client-side helpers for payment-channel open transactions.

This is the challenge-driven layer above the raw instruction builders in
:mod:`pay_kit.protocols.mpp._paymentchannels`: it derives the full channel open
from a :class:`~pay_kit.protocols.mpp.intents.session.SessionRequest`
challenge (mint from the currency, deposit from the cap, token program from the
currency, splits, salt) and assembles the partially signed open transaction the
operator broadcasts.

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

from pay_kit._paycore.mints import resolve_stablecoin_mint
from pay_kit._paycore.solana import default_token_program_for_currency
from pay_kit.protocols.mpp._paymentchannels import (
    PROGRAM_ID,
    Distribution,
    OpenChannelParams,
    build_open_instruction,
    find_channel_pda,
)
from pay_kit.protocols.mpp.client.session import ActiveSession, VoucherSigner, _pubkey_str
from pay_kit.protocols.mpp.intents.session import (
    DEFAULT_SESSION_EXPIRES_AT,
    OpenPayload,
    SessionAction,
    SessionMode,
    SessionRequest,
    _parse_base_units,
)

__all__ = [
    "DEFAULT_GRACE_PERIOD_SECONDS",
    "PENDING_SERVER_SIGNATURE",
    "PaymentChannelOpen",
    "PaymentChannelOpenTransaction",
    "PaymentChannelOpenOptions",
    "PaymentChannelSessionOpen",
    "PaymentChannelSessionOpenOptions",
    "ServerOpenedPaymentChannelSessionOpenOptions",
    "build_open_payment_channel_transaction",
    "create_payment_channel_session_opener",
    "create_server_opened_payment_channel_session_opener",
    "derive_payment_channel_open",
    "generate_authorized_signer",
    "unique_salt",
]

#: Default payment-channel close grace period, in seconds, applied to a derived
#: open when the caller does not override it.
DEFAULT_GRACE_PERIOD_SECONDS = 900

#: Placeholder signature carried by an open action while the operator still
#: needs to submit the server-broadcast open transaction. The all-ones base58
#: value is the default (zero) Solana signature, used as a sentinel until the
#: real on-chain signature is known.
PENDING_SERVER_SIGNATURE = "1111111111111111111111111111111111111111111111111111111111111111"

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
            recipients=list(self.recipients),
            token_program=self.token_program,
            program_id=self.program_id,
        )

    def open_payload(self, mode: SessionMode, signature: str) -> OpenPayload:
        """Build the open action payload carrying the full channel parameters.

        Serializes the channel's addresses, deposit, salt, grace period, and
        authorized signer into the ``open`` payload sent to the operator,
        tagged with the session ``mode`` and the open-transaction ``signature``.
        """
        return OpenPayload.payment_channel_with_mode(
            mode,
            str(self.channel_id),
            str(self.deposit),
            str(self.payer),
            str(self.payee),
            str(self.mint),
            self.salt,
            self.grace_period,
            str(self.authorized_signer),
            signature,
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
    challenge ``cap``, ``grace_period`` to
    :data:`DEFAULT_GRACE_PERIOD_SECONDS`, ``program_id`` to the challenge
    ``programId`` (else the production program), ``recipients`` to the
    challenge ``splits``, ``salt`` to :func:`unique_salt`, and
    ``token_program`` to the program resolved from the challenge currency
    (Token-2022 for PYUSD/USDG/CASH).
    """

    #: Deposit in token base units; defaults to the challenge cap.
    deposit: int | None = None
    #: Close grace period in seconds; defaults to :data:`DEFAULT_GRACE_PERIOD_SECONDS`.
    grace_period: int | None = None
    #: Owning program; defaults to the challenge ``programId`` or the production program.
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
    #: Open-action signature; defaults to :data:`PENDING_SERVER_SIGNATURE`.
    signature: str | None = None
    #: Initial cumulative spent amount for the session; defaults to 0.
    cumulative: int | None = None
    #: Session expiry as a Unix timestamp; defaults to the session default.
    expires_at: int | None = None


@dataclass
class ServerOpenedPaymentChannelSessionOpenOptions:
    """Options for :func:`create_server_opened_payment_channel_session_opener`."""

    #: Overrides for deriving the channel open.
    open: PaymentChannelOpenOptions = field(default_factory=PaymentChannelOpenOptions)
    #: Channel payer; defaults to the challenge ``operator`` (server-funded).
    payer: Pubkey | None = None
    #: Open-action signature; defaults to :data:`PENDING_SERVER_SIGNATURE`.
    signature: str | None = None
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

    Resolves the mint from the challenge currency (localnet falls back to the
    mainnet mint), the deposit from the cap when no explicit deposit is given,
    the token program from the currency, the recipients from the challenge
    splits, and a random salt; then derives the channel PDA. Any field set on
    ``options`` overrides the corresponding challenge-derived default.
    """
    options = options if options is not None else PaymentChannelOpenOptions()
    network = request.network if request.network is not None else "mainnet"
    resolved_mint = resolve_stablecoin_mint(request.currency, network)
    if resolved_mint is None:
        raise ValueError("session payment channels require an SPL token")
    mint = _parse_pubkey(resolved_mint, "mint")
    payee = _parse_pubkey(request.recipient, "recipient")
    deposit = options.deposit if options.deposit is not None else _parse_u64_string(request.cap, "session cap")
    grace_period = options.grace_period if options.grace_period is not None else DEFAULT_GRACE_PERIOD_SECONDS
    if options.program_id is not None:
        program_id = options.program_id
    elif request.program_id is not None:
        program_id = _parse_pubkey(request.program_id, "programId")
    else:
        program_id = PROGRAM_ID
    if options.token_program is not None:
        token_program = options.token_program
    else:
        token_program = _parse_pubkey(
            default_token_program_for_currency(request.currency, network),
            "token program",
        )
    if options.recipients is not None:
        recipients = list(options.recipients)
    else:
        recipients = [
            Distribution(recipient=_parse_pubkey(split.recipient, "split recipient"), bps=split.bps)
            for split in request.splits
        ]
    salt = options.salt if options.salt is not None else unique_salt()
    channel_id, _ = find_channel_pda(payer, payee, mint, authorized_signer, salt, program_id)

    return PaymentChannelOpen(
        channel_id=channel_id,
        payer=payer,
        payee=payee,
        mint=mint,
        authorized_signer=authorized_signer,
        salt=salt,
        deposit=deposit,
        grace_period=grace_period,
        recipients=recipients,
        token_program=token_program,
        program_id=program_id,
    )


def build_open_payment_channel_transaction(
    request: SessionRequest,
    signer: VoucherSigner | Any,
    authorized_signer: Pubkey,
    recent_blockhash: Hash | str,
    fee_payer: Pubkey | None = None,
    options: PaymentChannelOpenOptions | None = None,
) -> PaymentChannelOpenTransaction:
    """Build the payer-signed open transaction for operator broadcast.

    The fee payer defaults to the challenge ``operator`` and its signature slot
    is intentionally left empty: the payer partial-signs only its own slot and
    the server completes the fee-payer signature before broadcasting.
    """
    if fee_payer is None:
        fee_payer = _parse_pubkey(request.operator, "operator")
    open_ = derive_payment_channel_open(
        request,
        _signer_pubkey(signer),
        authorized_signer,
        options,
    )
    return _build_open_payment_channel_tx(signer, open_, fee_payer, recent_blockhash)


def create_payment_channel_session_opener(
    request: SessionRequest,
    payer_signer: VoucherSigner | Any,
    session_signer: VoucherSigner | Any,
    recent_blockhash: Hash | str,
    options: PaymentChannelSessionOpenOptions | None = None,
) -> PaymentChannelSessionOpen:
    """Open a pull/clientVoucher session with a client-built open transaction.

    Requires the challenge to advertise pull + clientVoucher; builds the
    partially signed open transaction (fee payer = operator), attaches it to
    the open action, and returns the :class:`ActiveSession` keyed to the
    derived channel. The action signature defaults to
    :data:`PENDING_SERVER_SIGNATURE` until the operator broadcasts.
    """
    options = options if options is not None else PaymentChannelSessionOpenOptions()
    _ensure_client_voucher_pull(request)
    authorized_signer = _signer_pubkey(session_signer)
    fee_payer = _parse_pubkey(request.operator, "operator")
    open_ = derive_payment_channel_open(
        request,
        _signer_pubkey(payer_signer),
        authorized_signer,
        options.open,
    )
    tx = _build_open_payment_channel_tx(payer_signer, open_, fee_payer, recent_blockhash)
    session = _configured_session(open_.channel_id, session_signer, options.cumulative, options.expires_at)
    signature = options.signature if options.signature is not None else PENDING_SERVER_SIGNATURE
    action = SessionAction.open_action(open_.open_payload("pull", signature).with_transaction(tx.transaction))
    return PaymentChannelSessionOpen(open=open_, session=session, action=action)


def create_server_opened_payment_channel_session_opener(
    request: SessionRequest,
    session_signer: VoucherSigner | Any,
    options: ServerOpenedPaymentChannelSessionOpenOptions | None = None,
) -> PaymentChannelSessionOpen:
    """Open a pull/clientVoucher session whose channel the operator funds.

    No transaction is built: the payer defaults to the challenge ``operator``
    and the server constructs, funds, and broadcasts the open itself.
    """
    options = options if options is not None else ServerOpenedPaymentChannelSessionOpenOptions()
    _ensure_client_voucher_pull(request)
    payer = options.payer if options.payer is not None else _parse_pubkey(request.operator, "operator")
    authorized_signer = _signer_pubkey(session_signer)
    open_ = derive_payment_channel_open(request, payer, authorized_signer, options.open)
    session = _configured_session(open_.channel_id, session_signer, options.cumulative, options.expires_at)
    signature = options.signature if options.signature is not None else PENDING_SERVER_SIGNATURE
    action = SessionAction.open_action(open_.open_payload("pull", signature))
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
    ix = build_open_instruction(open_.open_channel_params())
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


def _ensure_client_voucher_pull(request: SessionRequest) -> None:
    """Require the challenge to advertise pull mode with clientVoucher.

    Raises ``ValueError`` if the challenge does not list ``pull`` among its
    modes, or if its pull voucher strategy is not ``clientVoucher``.
    """
    if "pull" not in request.modes:
        raise ValueError("session challenge does not advertise pull mode")
    if request.pull_voucher_strategy != "clientVoucher":
        raise ValueError("session challenge does not advertise pull + clientVoucher")


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
    """Sign raw message bytes with a pay_kit signer or a solders Keypair."""
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
