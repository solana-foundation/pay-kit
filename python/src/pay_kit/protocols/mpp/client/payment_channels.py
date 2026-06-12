"""Client-side helpers for payment-channel open transactions.

This is the challenge-driven layer above the raw instruction builders in
:mod:`pay_kit.protocols.mpp._paymentchannels`: it derives the full channel open
from a :class:`~pay_kit.protocols.mpp.intents.session.SessionRequest`
challenge (mint from the currency, deposit from the cap, token program from the
currency, splits, salt) and assembles the partially signed open transaction the
operator broadcasts. Mirrors ``rust/crates/mpp/src/client/payment_channels.rs``
line by line; the TypeScript counterpart is
``typescript/packages/mpp/src/client/PaymentChannels.ts``.

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

#: Default payment-channel close grace period (seconds). Mirrors rust
#: ``DEFAULT_GRACE_PERIOD_SECONDS`` and the TypeScript client.
DEFAULT_GRACE_PERIOD_SECONDS = 900

#: Placeholder signature used while the operator still needs to submit the
#: server-broadcast open transaction. Mirrors rust ``PENDING_SERVER_SIGNATURE``.
PENDING_SERVER_SIGNATURE = "1111111111111111111111111111111111111111111111111111111111111111"

_U64_MAX = 2**64 - 1


def unique_salt() -> int:
    """Return a random u64 channel salt.

    Mirrors rust ``unique_salt`` (which reads eight unique bytes little-endian);
    Python draws the eight bytes from the CSPRNG.
    """
    return int.from_bytes(secrets.token_bytes(8), "little")


def generate_authorized_signer() -> Keypair:
    """Generate an ephemeral session signing key (canonical-flow step 2).

    The keypair's public key becomes the channel ``authorizedSigner``; pass the
    keypair to the openers (or directly to :class:`ActiveSession`) as the
    session signer. Mirrors the TypeScript openers' ``generateKeyPairSigner``
    call; the rust openers take an externally supplied ``SolanaSigner``.
    """
    return Keypair()


@dataclass
class PaymentChannelOpen:
    """A fully derived payment-channel open: addresses plus channel parameters.

    Mirrors rust ``PaymentChannelOpen``.
    """

    channel_id: Pubkey
    payer: Pubkey
    payee: Pubkey
    mint: Pubkey
    authorized_signer: Pubkey
    salt: int
    deposit: int
    grace_period: int
    recipients: list[Distribution]
    token_program: Pubkey
    program_id: Pubkey

    def open_channel_params(self) -> OpenChannelParams:
        """Return the instruction-builder params for this open.

        Mirrors rust ``PaymentChannelOpen::open_channel_params``.
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

        Mirrors rust ``PaymentChannelOpen::open_payload``.
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
    """A built open transaction plus the channel it opens.

    ``transaction`` is standard base64 with padding. Mirrors rust
    ``PaymentChannelOpenTransaction``.
    """

    channel_id: Pubkey
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
    (Token-2022 for PYUSD/USDG/CASH). Mirrors rust
    ``PaymentChannelOpenOptions``.
    """

    deposit: int | None = None
    grace_period: int | None = None
    program_id: Pubkey | None = None
    recipients: list[Distribution] | None = None
    salt: int | None = None
    token_program: Pubkey | None = None


@dataclass
class PaymentChannelSessionOpen:
    """A derived open, the session tracking it, and the open action to send.

    Mirrors rust ``PaymentChannelSessionOpen``.
    """

    open: PaymentChannelOpen
    session: ActiveSession
    action: SessionAction


@dataclass
class PaymentChannelSessionOpenOptions:
    """Options for :func:`create_payment_channel_session_opener`.

    Mirrors rust ``PaymentChannelSessionOpenOptions``.
    """

    open: PaymentChannelOpenOptions = field(default_factory=PaymentChannelOpenOptions)
    signature: str | None = None
    cumulative: int | None = None
    expires_at: int | None = None


@dataclass
class ServerOpenedPaymentChannelSessionOpenOptions:
    """Options for :func:`create_server_opened_payment_channel_session_opener`.

    Mirrors rust ``ServerOpenedPaymentChannelSessionOpenOptions``.
    """

    open: PaymentChannelOpenOptions = field(default_factory=PaymentChannelOpenOptions)
    payer: Pubkey | None = None
    signature: str | None = None
    cumulative: int | None = None
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
    splits, and a random salt; then derives the channel PDA. Mirrors rust
    ``derive_payment_channel_open``.
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
    the server completes the fee-payer signature before broadcasting. Mirrors
    rust ``build_open_payment_channel_transaction``.
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
    :data:`PENDING_SERVER_SIGNATURE` until the operator broadcasts. Mirrors
    rust ``create_payment_channel_session_opener``.
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
    and the server constructs, funds, and broadcasts the open itself. Mirrors
    rust ``create_server_opened_payment_channel_session_opener``.
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

    Mirrors rust ``build_open_payment_channel_tx``: a legacy transaction whose
    fee payer is the operator (signature slot left as the default placeholder)
    and whose payer signature is filled in, serialized as standard base64 with
    padding.
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

    Mirrors rust ``ensure_client_voucher_pull``.
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

    Mirrors rust ``configure_session``.
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
    """Parse a u64 decimal string, mirroring rust ``parse_u64_string``."""
    try:
        return _parse_base_units(value)
    except ValueError as exc:
        raise ValueError(f"invalid {label}: {value!r}") from exc


def _parse_pubkey(value: str, label: str) -> Pubkey:
    """Parse a base58 pubkey, mirroring rust ``parse_pubkey``."""
    try:
        return Pubkey.from_string(value)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"invalid {label}: {value!r}") from exc
