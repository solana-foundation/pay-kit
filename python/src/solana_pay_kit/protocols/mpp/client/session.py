"""Client-side session intent implementation.

:class:`ActiveSession` tracks an open payment channel and signs cumulative
vouchers for each metered API call. Vouchers are Ed25519-signed over the
on-chain Borsh voucher layout used by the payment-channels program, so the same
bytes the server verifies on the HTTP credential are the bytes the on-chain
settle instruction consumes.

Scope is client-only PUSH (payment channel) plus pull/clientVoucher: the client
signs cumulative vouchers off-chain. The challenge-driven open layer (deriving
the channel from a challenge and assembling the partially signed open
transaction) lives in :mod:`solana_pay_kit.protocols.mpp.client.payment_channels`.
Pull/operatedVoucher (the multi-delegator program) and the server verification
path are out of scope, but the wire fields stay present so the action union
round-trips.

Voucher signatures and credentials are byte-deterministic: the signed preimage
and the JCS-canonicalized credential are fully specified by the MPP session
intent, so a given session state always produces the same bytes on the wire.

The signer is duck-typed against the solana_pay_kit signer contract shared with the
charge client: ``pubkey() -> str`` (base58 public key) and
``sign(message: bytes) -> bytes`` (64-byte Ed25519 signature). A solders
``Keypair`` is also accepted because it exposes ``pubkey()`` and
``sign_message()``; both shapes are handled by :func:`_sign_base58`.
"""

from __future__ import annotations

from typing import Any, Protocol, cast, runtime_checkable

from solana_pay_kit.protocols.mpp._paymentchannels import voucher_message_bytes
from solana_pay_kit.protocols.mpp.core.base64url import decode_json
from solana_pay_kit.protocols.mpp.core.headers import format_authorization, parse_www_authenticate
from solana_pay_kit.protocols.mpp.core.types import PaymentChallenge, PaymentCredential
from solana_pay_kit.protocols.mpp.intents.session import (
    DEFAULT_SESSION_EXPIRES_AT,
    ClosePayload,
    OpenPayload,
    SessionAction,
    SessionMode,
    SessionRequest,
    SignedVoucher,
    TopUpPayload,
    VoucherData,
    VoucherPayload,
    _parse_base_units,
)

__all__ = [
    "DEFAULT_VOUCHER_EXPIRES_AT",
    "VoucherSigner",
    "ActiveSession",
    "serialize_session_credential",
    "parse_session_challenge",
    "session_request_modes",
]

#: Default voucher expiry: 2100-01-01T00:00:00Z. Stays below JavaScript's max
#: safe integer so JSON intermediaries do not round it before the credential is
#: decoded.
DEFAULT_VOUCHER_EXPIRES_AT = DEFAULT_SESSION_EXPIRES_AT

# The session intent name carried in a challenge ``intent`` field.
_SESSION_INTENT = "session"

# u64 upper bound; the cumulative watermark is a Solana base-unit amount and the
# voucher preimage packs it as a little-endian u64. A computed watermark that
# exceeds this bound is rejected rather than allowed to wrap.
_U64_MAX = (1 << 64) - 1


@runtime_checkable
class VoucherSigner(Protocol):
    """Minimal Ed25519 message-signing surface for voucher signing.

    Satisfied by the solana_pay_kit :class:`solana_pay_kit.signer.LocalSigner` duck type shared
    with the charge client. A solders ``Keypair`` also satisfies this shape via
    ``pubkey()`` plus ``sign_message()``; :func:`_sign_base58` bridges the two
    method names.
    """

    def pubkey(self) -> Any:
        """Return the signer's public key (base58 ``str`` or solders ``Pubkey``)."""
        ...

    def sign(self, message: bytes) -> bytes:
        """Return the 64-byte Ed25519 signature over ``message``."""
        ...


def _sign_base58(signer: Any, message: bytes) -> str:
    """Sign ``message`` and return the signature as base58.

    Accepts both the solana_pay_kit signer (``sign(bytes) -> bytes``) and a solders
    ``Keypair`` (``sign_message(bytes) -> Signature``). The 64-byte signature is
    normalized to its base58 string form via the solders ``Signature`` type,
    which is the encoding the credential carries on the wire.
    """
    from solders.signature import Signature  # type: ignore[import-untyped]

    sign = getattr(signer, "sign", None)
    if callable(sign):
        raw = cast("bytes", sign(message))
        return str(Signature.from_bytes(bytes(raw)))
    # solders Keypair fallback: sign_message returns a Signature directly.
    return str(signer.sign_message(message))


def _pubkey_str(signer: Any) -> str:
    """Return the signer's public key as base58, accepting str or solders Pubkey."""
    pub = signer.pubkey()
    return pub if isinstance(pub, str) else str(pub)


class ActiveSession:
    """Tracks the client-side state of an active payment session.

    Holds the session signing key and advances the cumulative watermark with
    each signed voucher. Vouchers are cumulative high-water marks: each one MUST
    strictly exceed the previous, and the signer's public key becomes the
    ``authorizedSigner`` passed to the server in the open action.

    Not safe for concurrent use; serialize access or guard it with a lock.
    """

    def __init__(
        self,
        channel_id: Any,
        signer: VoucherSigner | Any,
        expires_at: int = DEFAULT_VOUCHER_EXPIRES_AT,
        *,
        cumulative: int = 0,
    ) -> None:
        """Create a session tracker for ``channel_id`` signing with ``signer``.

        ``channel_id`` is a solders ``Pubkey`` (the on-chain channel address
        obtained after opening); ``signer`` satisfies the :class:`VoucherSigner`
        contract (or is a solders ``Keypair``, accepted via its ``sign_message``
        method); ``expires_at`` is the Unix timestamp applied to newly signed
        vouchers, defaulting to :data:`DEFAULT_VOUCHER_EXPIRES_AT`;
        ``cumulative`` seeds the watermark when resuming a known channel
        position (the payment-channel openers use it to write the starting
        ``cumulative`` value).
        """
        self._channel_id = channel_id
        self._signer = signer
        self._expires_at = expires_at
        self._cumulative = cumulative
        self._nonce = 0

    @classmethod
    def at_expiry(cls, channel_id: Any, signer: VoucherSigner | Any, expires_at: int) -> ActiveSession:
        """Create a session tracker with an explicit voucher expiry."""
        return cls(channel_id, signer, expires_at)

    @property
    def cumulative(self) -> int:
        """Current cumulative watermark (base units)."""
        return self._cumulative

    @property
    def nonce(self) -> int:
        """Current voucher nonce counter."""
        return self._nonce

    @property
    def expires_at(self) -> int:
        """Expiry timestamp applied to newly signed vouchers."""
        return self._expires_at

    @property
    def channel_id(self) -> Any:
        """On-chain channel address (solders ``Pubkey``)."""
        return self._channel_id

    @property
    def channel_id_string(self) -> str:
        """Channel address as base58."""
        return str(self._channel_id)

    @property
    def authorized_signer(self) -> str:
        """Session signing key as base58, for the open action payload."""
        return _pubkey_str(self._signer)

    def set_expires_at(self, expires_at: int) -> None:
        """Update the expiry timestamp used for subsequent vouchers."""
        self._expires_at = expires_at

    # -- voucher signing ----------------------------------------------------

    def prepare_voucher(self, cumulative: int) -> SignedVoucher:
        """Sign a voucher without advancing the local watermark.

        This keeps ack/commit transports safe to retry: a failed commit can be
        resent with the same cumulative amount without the local state drifting
        ahead of the server. ``cumulative`` MUST strictly exceed the current
        watermark.
        """
        if cumulative <= self._cumulative:
            raise ValueError(f"voucher cumulative {cumulative} must exceed current watermark {self._cumulative}")

        nonce = self._nonce + 1
        data = VoucherData(
            channel_id=self.channel_id_string,
            cumulative=str(cumulative),
            expires_at=self._expires_at,
            nonce=nonce,
        )

        preimage = voucher_message_bytes(self._channel_id, cumulative, self._expires_at)
        signature = _sign_base58(self._signer, preimage)
        return SignedVoucher(data=data, signature=signature)

    def prepare_increment(self, amount: int) -> SignedVoucher:
        """Sign a voucher adding ``amount`` to the current cumulative without
        advancing the watermark.
        """
        return self.prepare_voucher(self._add_cumulative(amount))

    def record_voucher(self, voucher: SignedVoucher) -> None:
        """Advance the local watermark to a prepared voucher the server accepted.

        The voucher's channel MUST match this session and its cumulative MUST
        strictly exceed the current watermark; the nonce advances to the larger
        of the current nonce and the voucher nonce (current nonce + 1 when the
        voucher carries none).
        """
        if voucher.data.channel_id != self.channel_id_string:
            raise ValueError(
                f"voucher channel {voucher.data.channel_id} does not match active session {self.channel_id_string}"
            )
        try:
            cumulative = _parse_base_units(voucher.data.cumulative)
        except ValueError as exc:
            raise ValueError("invalid voucher cumulative") from exc
        if cumulative <= self._cumulative:
            raise ValueError(f"voucher cumulative {cumulative} must exceed current watermark {self._cumulative}")
        self._cumulative = cumulative
        candidate = voucher.data.nonce if voucher.data.nonce is not None else self._nonce + 1
        self._nonce = max(self._nonce, candidate)

    def reconcile_settled(self, settled: int) -> None:
        """Reconcile the watermark to a server-settled cumulative, e.g. the
        ``cumulative`` of a ``replayed`` commit receipt.

        Advances to ``settled`` only when it is ahead of the current watermark
        and never regresses, so retrying a delivery the server already accepted
        (lost-response case) catches the client up without recording the freshly
        prepared higher voucher. When it advances, the request nonce advances by
        one too, so the next prepared voucher does not reuse the settled nonce.
        Mirrors the Rust/Go ``reconcile_settled``.
        """
        if settled > self._cumulative:
            self._cumulative = settled
            self._nonce += 1

    def sign_voucher(self, cumulative: int) -> SignedVoucher:
        """Sign a voucher with an absolute cumulative amount and advance the
        local watermark.

        ``cumulative`` MUST strictly exceed the current watermark.
        """
        voucher = self.prepare_voucher(cumulative)
        self.record_voucher(voucher)
        return voucher

    def sign_increment(self, amount: int) -> SignedVoucher:
        """Sign a voucher adding ``amount`` to the current cumulative."""
        return self.sign_voucher(self._add_cumulative(amount))

    # -- action builders ----------------------------------------------------

    def voucher_action(self, amount: int) -> SessionAction:
        """Sign a fresh increment and wrap it as a voucher action."""
        voucher = self.sign_increment(amount)
        return SessionAction.voucher_action(VoucherPayload(voucher=voucher))

    def close_action(self, final_increment: int = 0) -> SessionAction:
        """Build a cooperative close action.

        When ``final_increment`` is greater than zero it signs one last voucher
        for the remaining balance before closing; otherwise the close carries no
        voucher.
        """
        payload = ClosePayload(channel_id=self.channel_id_string)
        if final_increment > 0:
            payload.voucher = self.sign_increment(final_increment)
        return SessionAction.close_action(payload)

    def open_action(self, deposit: int, open_tx_signature: str) -> SessionAction:
        """Build a push-mode open action.

        Call this after the on-chain open transaction has confirmed; the session
        channel ID MUST match the confirmed channel address.
        """
        return SessionAction.open_action(
            OpenPayload.push(
                self.channel_id_string,
                str(deposit),
                self.authorized_signer,
                open_tx_signature,
            )
        )

    def open_payment_channel_action(
        self,
        deposit: int,
        payer: str,
        payee: str,
        mint: str,
        salt: int,
        grace_period: int,
        recent_slot: int,
        open_tx_signature: str,
    ) -> SessionAction:
        """Build a payment-channel push open action carrying the full channel
        parameters.

        ``recent_slot`` is the challenge-provided slot the channel was derived
        and opened at (the channel ``openSlot``, a channel PDA seed).
        """
        return self.open_payment_channel_action_with_mode(
            "push", deposit, payer, payee, mint, salt, grace_period, recent_slot, open_tx_signature
        )

    def open_payment_channel_action_with_mode(
        self,
        mode: SessionMode,
        deposit: int,
        payer: str,
        payee: str,
        mint: str,
        salt: int,
        grace_period: int,
        recent_slot: int,
        open_tx_signature: str,
    ) -> SessionAction:
        """Build a payment-channel open action with an explicit submission mode."""
        return SessionAction.open_action(
            OpenPayload.payment_channel_with_mode(
                mode,
                self.channel_id_string,
                str(deposit),
                payer,
                payee,
                mint,
                salt,
                grace_period,
                recent_slot,
                self.authorized_signer,
                open_tx_signature,
            )
        )

    def open_pull_action(
        self,
        approved_amount: int,
        owner: str,
        approve_tx_signature: str,
    ) -> SessionAction:
        """Build a pull-mode (SPL delegation) open action.

        The session channel ID is used as the token account, so callers should
        construct the :class:`ActiveSession` with the delegated token-account
        pubkey as the channel ID.
        """
        return SessionAction.open_action(
            OpenPayload.pull(
                self.channel_id_string,
                str(approved_amount),
                owner,
                self.authorized_signer,
                approve_tx_signature,
            )
        )

    def top_up_action(self, new_deposit: int, topup_tx_signature: str) -> SessionAction:
        """Build a top-up action after a top-up transaction confirms."""
        return SessionAction.top_up_action(
            TopUpPayload(
                channel_id=self.channel_id_string,
                new_deposit=str(new_deposit),
                signature=topup_tx_signature,
            )
        )

    # -- credential framing -------------------------------------------------

    def serialize_session_credential(
        self,
        challenge: PaymentChallenge,
        action: SessionAction,
    ) -> str:
        """Build the ``Payment <base64url(JCS)>`` Authorization header value.

        Echoes ``challenge`` and JCS-canonicalizes the credential, reusing the
        same core wire layer the charge client uses.
        """
        return serialize_session_credential(challenge, action)

    # -- internals ----------------------------------------------------------

    def _add_cumulative(self, amount: int) -> int:
        """Add ``amount`` to the current watermark, rejecting u64 overflow.

        Guards against a wrapped watermark ever being signed: if the sum exceeds
        the u64 range the voucher would pack, it raises instead of wrapping.
        """
        nxt = self._cumulative + amount
        if nxt > _U64_MAX:
            raise ValueError(f"voucher cumulative overflows u64: {self._cumulative} + {amount}")
        return nxt


def serialize_session_credential(
    challenge: PaymentChallenge,
    action: SessionAction,
) -> str:
    """Build an Authorization header value for a session action.

    Echoes the challenge and JCS-canonicalizes the credential, producing
    ``"Payment <base64url(JCS(PaymentCredential))>"``, the credential framing the
    MPP "Payment" HTTP auth scheme defines for session actions.
    """
    credential = PaymentCredential(
        challenge=challenge.to_echo(),
        payload=action.to_dict(),
    )
    return format_authorization(credential)


def parse_session_challenge(header: str) -> tuple[PaymentChallenge, SessionRequest]:
    """Parse a WWW-Authenticate header into the challenge and session request.

    Rejects non-session intents so callers do not accidentally treat a charge
    challenge as a session.
    """
    challenge = parse_www_authenticate(header)
    if challenge.intent != _SESSION_INTENT:
        raise ValueError(f"challenge intent {challenge.intent!r} is not a session")
    request = SessionRequest.from_dict(decode_json(challenge.request))
    return challenge, request


def session_request_modes(request: SessionRequest) -> list[SessionMode]:
    """Return the funding modes advertised by a session challenge.

    ``modes`` omitted or empty means push-only; an explicit ``[]`` therefore
    decodes the same as a missing field, yielding ``["push"]``.
    """
    return list(request.modes) if request.modes else ["push"]
