"""Session intent request and voucher types.

The session intent opens a payment channel between a client and server,
allowing incremental payments via off-chain signed vouchers backed by the
on-chain payment-channels program. The wire format is defined by the MPP
specification's session intent.

Types are plain :func:`dataclasses.dataclass` with explicit
``to_dict()``/``from_dict()`` helpers, camelCase field names on the wire, and
omit-empty behaviour implemented by conditional inclusion in ``to_dict()``.
``parse_units`` is re-exported from the charge intent so callers keep a stable
amount-parsing entry point.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Literal

from solana_pay_kit.protocols.mpp.intents.charge import parse_units

__all__ = [
    "DEFAULT_SESSION_EXPIRES_AT",
    "MAX_IDLE_TIMEOUT_SECONDS",
    "SESSION_AUTHENTICATION_DOMAIN",
    "SessionVoucherSigner",
    "SessionAuthentication",
    "resolve_idle_timeout_seconds",
    "sign_session_authentication",
    "validate_idle_timeout_options",
    "verify_session_authentication",
    "CommitStatus",
    "SessionSplit",
    "SessionMethodDetails",
    "SessionRequest",
    "SessionAction",
    "OpenPayload",
    "VoucherPayload",
    "VoucherData",
    "SignedVoucher",
    "CommitPayload",
    "CommitReceipt",
    "TopUpPayload",
    "ClosePayload",
    "UsePayload",
    "MeteringDirective",
    "MeteringUsage",
    "MeteredEnvelope",
    "parse_units",
]

# Default session voucher/directive expiry: 2100-01-01T00:00:00Z.
#
# This stays below JavaScript's max safe integer so JSON intermediaries do not
# round it before the credential is decoded.
DEFAULT_SESSION_EXPIRES_AT = 4_102_444_800
MAX_IDLE_TIMEOUT_SECONDS = 2_592_000
SESSION_AUTHENTICATION_DOMAIN = "mpp-session-auth-v1"

_U64_MAX = 2**64 - 1


def _parse_base_units(raw: object) -> int:
    """Parse a canonical unsigned base-unit decimal string into a ``u64``.

    Rejects empty, signed, fractional, non-ASCII-digit, or out-of-range values.
    The amount is validated up front as a typed ``u64`` so a malformed value
    (e.g. ``"-1"``) cannot slip past zero/max-cap checks or fail later when
    packed for Solana.
    """
    s = str(raw)
    if not (s.isascii() and s.isdigit()):
        raise ValueError(f"invalid base-unit amount {raw!r}")
    value = int(s, 10)
    if value > _U64_MAX:
        raise ValueError(f"base-unit amount {raw!r} exceeds u64 range")
    return value


# Voucher signing authority advertised by a session challenge.
SessionVoucherSigner = Literal["client", "operator"]

# Commit receipt status. Encoded on the wire as the camelCase string
# ``"committed"`` or ``"replayed"``.
CommitStatus = Literal["committed", "replayed"]

# Action discriminator values. Note ``"topUp"`` is camelCase on the wire, in
# line with the rest of the session field naming.
_SessionActionTag = Literal["open", "voucher", "use", "topUp", "close"]


@dataclass(frozen=True)
class SessionAuthentication:
    """Reusable payer proof bound to one challenge and channel."""

    challenge_id: str
    payer: str
    signature: str
    type: Literal["proof"] = "proof"

    def message_bytes(self, channel_id: str) -> bytes:
        return json.dumps(
            {
                "channelId": channel_id,
                "domain": SESSION_AUTHENTICATION_DOMAIN,
                "payer": self.payer,
                "sessionChallengeId": self.challenge_id,
            },
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()

    def to_dict(self) -> dict[str, str]:
        return {
            "type": self.type,
            "challengeId": self.challenge_id,
            "payer": self.payer,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SessionAuthentication:
        if data.get("type") != "proof":
            raise ValueError("session authentication: type must be 'proof'")
        return cls(
            challenge_id=str(data.get("challengeId", "")),
            payer=str(data.get("payer", "")),
            signature=str(data.get("signature", "")),
        )


def sign_session_authentication(challenge_id: str, channel_id: str, signer: Any) -> SessionAuthentication:
    """Create a reusable proof with a solders-compatible Ed25519 keypair."""
    payer = str(signer.pubkey())
    unsigned = SessionAuthentication(challenge_id, payer, "")
    return SessionAuthentication(
        challenge_id,
        payer,
        str(signer.sign_message(unsigned.message_bytes(channel_id))),
    )


def verify_session_authentication(authentication: SessionAuthentication, channel_id: str) -> bool:
    """Verify a reusable payer proof against its bound channel."""
    from solders.pubkey import Pubkey  # type: ignore[import-untyped]
    from solders.signature import Signature  # type: ignore[import-untyped]

    try:
        payer = Pubkey.from_string(authentication.payer)
        signature = Signature.from_string(authentication.signature)
    except (TypeError, ValueError):
        return False
    return signature.verify(payer, authentication.message_bytes(channel_id))


def validate_idle_timeout_options(options: list[int]) -> None:
    """Validate the non-empty, strictly increasing timeout offer list."""
    if not options:
        raise ValueError("idleTimeoutOptionsSeconds must not be empty")
    previous = 0
    for value in options:
        if isinstance(value, bool) or not 1 <= value <= MAX_IDLE_TIMEOUT_SECONDS:
            raise ValueError(f"idle timeout must be between 1 and {MAX_IDLE_TIMEOUT_SECONDS}")
        if value <= previous:
            raise ValueError("idleTimeoutOptionsSeconds must be strictly increasing")
        previous = value


def resolve_idle_timeout_seconds(
    default_seconds: int,
    options: list[int] | None = None,
    selected: int | None = None,
) -> int:
    """Resolve the effective timeout and reject an unsupported selection."""
    if isinstance(default_seconds, bool) or not 1 <= default_seconds <= MAX_IDLE_TIMEOUT_SECONDS:
        raise ValueError(f"default idle timeout must be between 1 and {MAX_IDLE_TIMEOUT_SECONDS}")
    if options is not None:
        validate_idle_timeout_options(options)
    if selected is not None:
        if options is None:
            raise ValueError("idleTimeoutSeconds is not allowed when no options were advertised")
        if selected not in options:
            raise ValueError("idleTimeoutSeconds was not one of the advertised options")
        return selected
    if options is not None and default_seconds not in options:
        return options[0]
    return default_seconds


@dataclass
class SessionSplit:
    """A payment split committed at channel open."""

    recipient: str
    share_bps: int

    def to_dict(self) -> dict[str, Any]:
        return {"recipient": self.recipient, "shareBps": self.share_bps}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SessionSplit:
        return cls(recipient=str(data.get("recipient", "")), share_bps=int(data.get("shareBps", 0)))


@dataclass
class SessionMethodDetails:
    """Solana-specific policy nested under ``methodDetails``."""

    network: str
    channel_program: str
    channel_id: str | None = None
    # Base58 blockhash the client MUST use as the open transaction's recent
    # blockhash, and the RPC context slot from the same getLatestBlockhash
    # response (the client's default openSlot). Conditionally REQUIRED when
    # channel_id is absent (new channel); MUST be absent when resuming.
    # recent_slot is a u64 serialized as a decimal string on the wire.
    recent_blockhash: str | None = None
    recent_slot: int | None = None
    decimals: int | None = None
    token_program: str | None = None
    fee_payer: bool | None = None
    fee_payer_key: str | None = None
    voucher_signer: SessionVoucherSigner | None = None
    operator: str | None = None
    min_voucher_delta: str | None = None
    ttl_seconds: int | None = None
    idle_timeout_options_seconds: list[int] | None = None
    idle_timeout_seconds: int | None = None
    grace_period_seconds: int | None = None
    distribution_splits: list[SessionSplit] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "network": self.network,
            "channelProgram": self.channel_program,
        }
        optional = {
            "channelId": self.channel_id,
            "recentBlockhash": self.recent_blockhash,
            "recentSlot": _u64_to_wire(self.recent_slot),
            "decimals": self.decimals,
            "tokenProgram": self.token_program,
            "feePayer": self.fee_payer,
            "feePayerKey": self.fee_payer_key,
            "voucherSigner": self.voucher_signer,
            "operator": self.operator,
            "minVoucherDelta": self.min_voucher_delta,
            "ttlSeconds": self.ttl_seconds,
            "idleTimeoutSeconds": self.idle_timeout_seconds,
            "gracePeriodSeconds": self.grace_period_seconds,
        }
        data.update({key: value for key, value in optional.items() if value is not None})
        if self.idle_timeout_options_seconds is not None:
            validate_idle_timeout_options(self.idle_timeout_options_seconds)
            data["idleTimeoutOptionsSeconds"] = list(self.idle_timeout_options_seconds)
        if self.distribution_splits:
            data["distributionSplits"] = [split.to_dict() for split in self.distribution_splits]
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SessionMethodDetails:
        voucher_signer = data.get("voucherSigner")
        if voucher_signer is not None and voucher_signer not in ("client", "operator"):
            raise ValueError(f"unknown voucherSigner {voucher_signer!r}")
        options = data.get("idleTimeoutOptionsSeconds")
        parsed_options = [int(value) for value in options] if options is not None else None
        if parsed_options is not None:
            validate_idle_timeout_options(parsed_options)
        return cls(
            network=_string_from_wire(data.get("network"), "methodDetails.network"),
            channel_program=_string_from_wire(data.get("channelProgram"), "methodDetails.channelProgram"),
            channel_id=data.get("channelId"),
            recent_blockhash=data.get("recentBlockhash"),
            recent_slot=_u64_from_wire(data.get("recentSlot"), "recentSlot"),
            decimals=int(data["decimals"]) if data.get("decimals") is not None else None,
            token_program=data.get("tokenProgram"),
            fee_payer=bool(data["feePayer"]) if data.get("feePayer") is not None else None,
            fee_payer_key=data.get("feePayerKey"),
            voucher_signer=voucher_signer,
            operator=data.get("operator"),
            min_voucher_delta=data.get("minVoucherDelta"),
            ttl_seconds=int(data["ttlSeconds"]) if data.get("ttlSeconds") is not None else None,
            idle_timeout_options_seconds=parsed_options,
            idle_timeout_seconds=(
                int(data["idleTimeoutSeconds"]) if data.get("idleTimeoutSeconds") is not None else None
            ),
            grace_period_seconds=(
                int(data["gracePeriodSeconds"]) if data.get("gracePeriodSeconds") is not None else None
            ),
            distribution_splits=[SessionSplit.from_dict(value) for value in data.get("distributionSplits", [])],
        )


@dataclass
class SessionRequest:
    """Session intent request embedded in a 402 challenge."""

    amount: str
    currency: str
    recipient: str
    method_details: SessionMethodDetails
    description: str | None = None
    external_id: str | None = None
    minimum_deposit: str | None = None
    suggested_deposit: str | None = None
    unit_type: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "amount": self.amount,
            "currency": self.currency,
            "recipient": self.recipient,
            "methodDetails": self.method_details.to_dict(),
        }
        if self.description is not None:
            d["description"] = self.description
        if self.external_id is not None:
            d["externalId"] = self.external_id
        if self.minimum_deposit is not None:
            d["minimumDeposit"] = self.minimum_deposit
        if self.suggested_deposit is not None:
            d["suggestedDeposit"] = self.suggested_deposit
        if self.unit_type is not None:
            d["unitType"] = self.unit_type
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SessionRequest:
        method_details = data.get("methodDetails")
        if not isinstance(method_details, dict):
            raise ValueError("session request requires a methodDetails object")
        return cls(
            amount=_string_from_wire(data.get("amount"), "amount"),
            currency=_string_from_wire(data.get("currency"), "currency"),
            recipient=_string_from_wire(data.get("recipient"), "recipient"),
            method_details=SessionMethodDetails.from_dict(method_details),
            description=data.get("description"),
            external_id=data.get("externalId"),
            minimum_deposit=data.get("minimumDeposit"),
            suggested_deposit=data.get("suggestedDeposit"),
            unit_type=data.get("unitType"),
        )


def _u64_to_wire(value: int | None) -> str | None:
    """Serialize an optional u64 field as a decimal string.

    Authorization headers are JSON canonicalized and an arbitrary ``u64`` is not
    a safe JSON number, so these fields always travel as decimal strings.
    """
    if value is None:
        return None
    return str(value)


def _u64_from_wire(value: Any, label: str) -> int | None:
    """Parse an optional u64 field from its required decimal-string encoding."""
    if value is None:
        return None
    if isinstance(value, str):
        try:
            return _parse_base_units(value)
        except ValueError as exc:
            raise ValueError(f"{label} must be a decimal string: {value}") from exc
    raise ValueError(f"{label} must be a decimal string")


def _string_from_wire(value: Any, label: str) -> str:
    """Require a wire string without coercing numbers or other JSON values."""
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    return value


@dataclass
class OpenPayload:
    """Exact payment-channel ``open`` credential payload."""

    channel_id: str
    payer: str
    payee: str
    mint: str
    authorized_signer: str
    salt: int
    deposit_amount: str
    grace_period_seconds: int
    open_slot: int
    transaction: str
    distribution_splits: list[SessionSplit] = field(default_factory=list)
    authorization_policy: dict[str, Any] | None = None
    authentication: SessionAuthentication | None = None
    idle_timeout_seconds: int | None = None
    capabilities: dict[str, Any] | None = None

    def session_id(self) -> str:
        return self.channel_id

    def deposit_base_units(self) -> int:
        raw = self.deposit_amount
        try:
            return _parse_base_units(raw)
        except ValueError as exc:
            raise ValueError(f"invalid deposit amount: {raw}") from exc

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "channelId": self.channel_id,
            "payer": self.payer,
            "payee": self.payee,
            "mint": self.mint,
            "authorizedSigner": self.authorized_signer,
            "salt": str(self.salt),
            "depositAmount": self.deposit_amount,
            "gracePeriodSeconds": self.grace_period_seconds,
            "openSlot": str(self.open_slot),
            "transaction": self.transaction,
        }
        if self.distribution_splits:
            d["distributionSplits"] = [split.to_dict() for split in self.distribution_splits]
        if self.authorization_policy is not None:
            d["authorizationPolicy"] = self.authorization_policy
        if self.authentication is not None:
            d["authentication"] = self.authentication.to_dict()
        if self.idle_timeout_seconds is not None:
            d["idleTimeoutSeconds"] = self.idle_timeout_seconds
        if self.capabilities is not None:
            d["capabilities"] = self.capabilities
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> OpenPayload:
        if "bump" in data:
            raise ValueError("open payload must not include bump")
        salt = _u64_from_wire(data.get("salt"), "salt")
        open_slot = _u64_from_wire(data.get("openSlot"), "openSlot")
        if salt is None or open_slot is None:
            raise ValueError("open payload requires salt and openSlot")
        return cls(
            channel_id=_string_from_wire(data.get("channelId"), "channelId"),
            payer=_string_from_wire(data.get("payer"), "payer"),
            payee=_string_from_wire(data.get("payee"), "payee"),
            mint=_string_from_wire(data.get("mint"), "mint"),
            authorized_signer=_string_from_wire(data.get("authorizedSigner"), "authorizedSigner"),
            salt=salt,
            deposit_amount=_string_from_wire(data.get("depositAmount"), "depositAmount"),
            grace_period_seconds=int(data.get("gracePeriodSeconds", 0)),
            open_slot=open_slot,
            transaction=_string_from_wire(data.get("transaction"), "transaction"),
            distribution_splits=[SessionSplit.from_dict(value) for value in data.get("distributionSplits", [])],
            authorization_policy=data.get("authorizationPolicy"),
            authentication=(
                SessionAuthentication.from_dict(data["authentication"])
                if data.get("authentication") is not None
                else None
            ),
            idle_timeout_seconds=(
                int(data["idleTimeoutSeconds"]) if data.get("idleTimeoutSeconds") is not None else None
            ),
            capabilities=data.get("capabilities"),
        )


@dataclass
class VoucherData:
    """The canonical content of a voucher, signed by the client's session key.

    Serialized as the on-chain ``VoucherArgs`` layout before signing:
    ``magic || channel_id || cumulative_amount_le || expires_at_le``. The wire
    field for the cumulative amount is ``cumulativeAmount``. ``expiresAt`` is
    optional on the wire; ``0`` or omitted means never-expires and is encoded
    verbatim as ``0`` into the signed bytes, matching the Rust/TS SDKs and the
    on-chain settle check.
    """

    channel_id: str
    cumulative_amount: str
    expires_at: int | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "channelId": self.channel_id,
            "cumulativeAmount": self.cumulative_amount,
        }
        if self.expires_at is not None:
            d["expiresAt"] = self.expires_at
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> VoucherData:
        cumulative = data.get("cumulativeAmount")
        if not isinstance(cumulative, str):
            raise ValueError("cumulativeAmount must be a decimal string")
        return cls(
            channel_id=_string_from_wire(data.get("channelId"), "voucher.channelId"),
            cumulative_amount=cumulative,
            expires_at=(int(data["expiresAt"]) if data.get("expiresAt") is not None else None),
        )

    def message_bytes(self) -> bytes:
        """Serialize to the payment-channels ``VoucherArgs`` bytes signed by
        Ed25519.

        Layout (exactly 50 bytes): the constant 2-byte voucher magic
        ``[0x56, 0x01]`` || ``channel_id``\\ (32, base58-decoded, offset 2) ||
        ``cumulative_amount`` little-endian ``u64`` (offset 34) || ``expires_at``
        little-endian ``i64`` (offset 42). The magic lives only in the signed
        bytes, never in the voucher wire JSON. Delegates to the canonical packer
        so the 50-byte layout has a single source of truth.
        """
        # Lazy import so the module imports without solders installed (no cycle:
        # the glue does not import the intent layer).
        from solders.pubkey import Pubkey  # type: ignore[import-untyped]

        from solana_pay_kit.protocols.mpp._paymentchannels import voucher_message_bytes

        try:
            channel = Pubkey.from_string(self.channel_id)
        except (ValueError, TypeError) as exc:
            raise ValueError(f"invalid channelId {self.channel_id!r}") from exc
        try:
            cumulative = _parse_base_units(self.cumulative_amount)
        except ValueError as exc:
            raise ValueError("invalid voucher cumulative") from exc
        # An omitted expiresAt is never-expires and encodes as 0, exactly as
        # the wire value would: substituting any sentinel here would make the
        # reconstructed bytes diverge from what the counterparty signed.
        return voucher_message_bytes(
            channel,
            cumulative,
            self.expires_at if self.expires_at is not None else 0,
        )


@dataclass
class SignedVoucher:
    """A signed voucher authorizing cumulative payment up to ``cumulative``.

    Vouchers are cumulative: the server always uses the latest valid voucher it
    has received. The client MUST increment ``cumulative`` with each request.
    ``signature`` is the client's Ed25519 signature over the voucher's
    ``message_bytes``.
    """

    #: The voucher content, carried on the wire as ``voucher`` per the spec's
    #: Signed Voucher table (mpp-specs e702dd8).
    data: VoucherData
    signer: str
    signature: str
    signature_type: Literal["ed25519"] = "ed25519"

    def to_dict(self) -> dict[str, Any]:
        return {
            "voucher": self.data.to_dict(),
            "signer": self.signer,
            "signature": self.signature,
            "signatureType": self.signature_type,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SignedVoucher:
        return cls(
            data=VoucherData.from_dict(data.get("voucher", {})),
            signer=str(data.get("signer", "")),
            signature=str(data.get("signature", "")),
            signature_type=_signature_type(data.get("signatureType")),
        )


def _signature_type(value: object) -> Literal["ed25519"]:
    if value != "ed25519":
        raise ValueError("signatureType must be 'ed25519'")
    return "ed25519"


@dataclass
class VoucherPayload:
    """Payload for the ``voucher`` action (per-request micropayment).

    Carries the single :class:`SignedVoucher` the client presents to authorize a
    request against an open channel.
    """

    #: REQUIRED routing key next to the signed voucher; servers MUST reject
    #: the action when it differs from the signed voucher's inner
    #: ``channelId`` — the routing key must never diverge from the signed
    #: content.
    channel_id: str
    voucher: SignedVoucher

    def to_dict(self) -> dict[str, Any]:
        return {"channelId": self.channel_id, "voucher": self.voucher.to_dict()}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> VoucherPayload:
        return cls(
            channel_id=_string_from_wire(data.get("channelId"), "channelId"),
            voucher=SignedVoucher.from_dict(data.get("voucher", {})),
        )


@dataclass
class CommitPayload:
    """Payload for the ``commit`` action.

    Acknowledges a specific delivery (``delivery_id``) by submitting the
    :class:`SignedVoucher` that pays for it.
    """

    delivery_id: str
    voucher: SignedVoucher

    def to_dict(self) -> dict[str, Any]:
        return {"deliveryId": self.delivery_id, "voucher": self.voucher.to_dict()}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CommitPayload:
        return cls(
            delivery_id=data.get("deliveryId", ""),
            voucher=SignedVoucher.from_dict(data.get("voucher", {})),
        )


@dataclass
class TopUpPayload:
    """Payload for the ``topUp`` action.

    Adds ``additional_amount`` to the deposit backing an open channel. The
    signed transaction is decoded, verified, submitted, and confirmed by the
    server.
    """

    channel_id: str
    additional_amount: str
    transaction: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "channelId": self.channel_id,
            "additionalAmount": self.additional_amount,
            "transaction": self.transaction,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TopUpPayload:
        return cls(
            channel_id=_string_from_wire(data.get("channelId"), "channelId"),
            additional_amount=_string_from_wire(data.get("additionalAmount"), "additionalAmount"),
            transaction=_string_from_wire(data.get("transaction"), "transaction"),
        )


@dataclass
class ClosePayload:
    """Payload for the ``close`` action.

    Closes the channel identified by ``channel_id``. The final
    :class:`SignedVoucher` is optional and omitted from the wire when ``None``.
    """

    channel_id: str
    authentication: SessionAuthentication | None = None
    voucher: SignedVoucher | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"channelId": self.channel_id}
        if self.authentication is not None:
            d["authentication"] = self.authentication.to_dict()
        if self.voucher is not None:
            d["voucher"] = self.voucher.to_dict()
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ClosePayload:
        voucher = data.get("voucher")
        return cls(
            channel_id=data.get("channelId", ""),
            authentication=(
                SessionAuthentication.from_dict(data["authentication"])
                if data.get("authentication") is not None
                else None
            ),
            voucher=SignedVoucher.from_dict(voucher) if voucher is not None else None,
        )


@dataclass
class UsePayload:
    """Billable request payload for an operator-signed session."""

    channel_id: str
    authentication: SessionAuthentication

    def to_dict(self) -> dict[str, Any]:
        return {"channelId": self.channel_id, "authentication": self.authentication.to_dict()}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> UsePayload:
        return cls(
            channel_id=str(data.get("channelId", "")),
            authentication=SessionAuthentication.from_dict(data.get("authentication", {})),
        )


@dataclass
class SessionAction:
    """The action submitted by the client in an Authorization header.

    Serialized as a tagged object with
    ``"action": "open" | "voucher" | "use" | "topUp" | "close"`` and the
    payload fields flattened alongside the discriminator. Exactly one payload is
    set for a valid action.
    """

    open: OpenPayload | None = None
    voucher: VoucherPayload | None = None
    use: UsePayload | None = None
    top_up: TopUpPayload | None = None
    close: ClosePayload | None = None

    @classmethod
    def open_action(cls, payload: OpenPayload) -> SessionAction:
        """Wrap an :class:`OpenPayload` as a :class:`SessionAction`."""
        return cls(open=payload)

    @classmethod
    def voucher_action(cls, payload: VoucherPayload) -> SessionAction:
        """Wrap a :class:`VoucherPayload` as a :class:`SessionAction`."""
        return cls(voucher=payload)

    @classmethod
    def use_action(cls, payload: UsePayload) -> SessionAction:
        """Wrap a :class:`UsePayload` as a :class:`SessionAction`."""
        return cls(use=payload)

    @classmethod
    def top_up_action(cls, payload: TopUpPayload) -> SessionAction:
        """Wrap a :class:`TopUpPayload` as a :class:`SessionAction`."""
        return cls(top_up=payload)

    @classmethod
    def close_action(cls, payload: ClosePayload) -> SessionAction:
        """Wrap a :class:`ClosePayload` as a :class:`SessionAction`."""
        return cls(close=payload)

    def to_dict(self) -> dict[str, Any]:
        """Flatten the active payload alongside an ``"action"`` discriminator.

        The active variant's fields are emitted at the top level next to the
        ``"action"`` tag. Exactly one variant must be set, otherwise this raises.
        """
        variants: list[tuple[_SessionActionTag, dict[str, Any]]] = []
        if self.open is not None:
            variants.append(("open", self.open.to_dict()))
        if self.voucher is not None:
            variants.append(("voucher", self.voucher.to_dict()))
        if self.use is not None:
            variants.append(("use", self.use.to_dict()))
        if self.top_up is not None:
            variants.append(("topUp", self.top_up.to_dict()))
        if self.close is not None:
            variants.append(("close", self.close.to_dict()))
        if len(variants) == 0:
            raise ValueError("session action: no variant set")
        if len(variants) > 1:
            raise ValueError("session action: multiple variants set")
        tag, payload = variants[0]
        return {"action": tag, **payload}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SessionAction:
        """Read the ``"action"`` discriminator and decode the flattened payload.

        An empty discriminator and an unknown action both raise.
        """
        action = data.get("action")
        if not action:
            raise ValueError("session action: missing action discriminator")
        if action == "open":
            return cls(open=OpenPayload.from_dict(data))
        if action == "voucher":
            return cls(voucher=VoucherPayload.from_dict(data))
        if action == "use":
            return cls(use=UsePayload.from_dict(data))
        if action == "topUp":
            return cls(top_up=TopUpPayload.from_dict(data))
        if action == "close":
            return cls(close=ClosePayload.from_dict(data))
        raise ValueError(f"session action: unknown action {action!r}")


@dataclass
class MeteringDirective:
    """Server-issued metering directive attached to a delivered message.

    Clients treat this like an offset in a message log: once the message has been
    processed successfully, ``ack``/``commit`` signs a voucher for ``amount`` and
    sends a :class:`CommitPayload` back to the server. ``commit_url`` and
    ``proof`` are optional and omitted from the wire when ``None``.
    """

    delivery_id: str
    session_id: str
    amount: str
    currency: str
    sequence: int
    expires_at: int
    commit_url: str | None = None
    proof: str | None = None

    def amount_base_units(self) -> int:
        """Parse ``amount`` as base units.

        Returns the reserved amount as a ``u64``, raising when it is malformed.
        """
        try:
            return _parse_base_units(self.amount)
        except ValueError as exc:
            raise ValueError(f"invalid metering amount: {self.amount}") from exc

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "deliveryId": self.delivery_id,
            "sessionId": self.session_id,
            "amount": self.amount,
            "currency": self.currency,
            "sequence": self.sequence,
            "expiresAt": self.expires_at,
        }
        if self.commit_url is not None:
            d["commitUrl"] = self.commit_url
        if self.proof is not None:
            d["proof"] = self.proof
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> MeteringDirective:
        return cls(
            delivery_id=data.get("deliveryId", ""),
            session_id=data.get("sessionId", ""),
            amount=data.get("amount", ""),
            currency=data.get("currency", ""),
            sequence=int(data.get("sequence", 0)),
            expires_at=int(data.get("expiresAt", 0)),
            commit_url=data.get("commitUrl"),
            proof=data.get("proof"),
        )


@dataclass
class MeteringUsage:
    """Final usage reported by a streaming response.

    The amount MUST be less than or equal to the amount reserved by the original
    :class:`MeteringDirective`. ``delivery_id`` ties the usage back to that
    directive.
    """

    delivery_id: str
    amount: str

    def amount_base_units(self) -> int:
        """Parse ``amount`` as base units.

        Returns the reported usage as a ``u64``, raising when it is malformed.
        """
        try:
            return _parse_base_units(self.amount)
        except ValueError as exc:
            raise ValueError(f"invalid metering usage amount: {self.amount}") from exc

    def to_dict(self) -> dict[str, Any]:
        return {"deliveryId": self.delivery_id, "amount": self.amount}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> MeteringUsage:
        return cls(delivery_id=data.get("deliveryId", ""), amount=data.get("amount", ""))


@dataclass
class MeteredEnvelope:
    """A payload paired with the metering directive required to acknowledge it.

    The payload is left as an opaque value (any JSON-serializable object) and
    ``metering`` carries the :class:`MeteringDirective` the client must commit
    against once the payload is processed.
    """

    payload: Any
    metering: MeteringDirective

    def to_dict(self) -> dict[str, Any]:
        return {"payload": self.payload, "metering": self.metering.to_dict()}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> MeteredEnvelope:
        return cls(
            payload=data.get("payload"),
            metering=MeteringDirective.from_dict(data.get("metering", {})),
        )


@dataclass
class CommitReceipt:
    """Result returned after a delivery commit is accepted.

    Reports the committed ``delivery_id`` and ``session_id``, the ``amount``
    charged for this commit, the running ``cumulative`` total, and a ``status``
    of ``"committed"`` (newly applied) or ``"replayed"`` (a duplicate that was
    deduplicated server-side).
    """

    delivery_id: str
    session_id: str
    amount: str
    cumulative: str
    status: CommitStatus

    def amount_base_units(self) -> int:
        """Parse ``amount`` as base units."""
        try:
            return _parse_base_units(self.amount)
        except ValueError as exc:
            raise ValueError(f"invalid commit receipt amount: {self.amount}") from exc

    def cumulative_base_units(self) -> int:
        """Parse ``cumulative`` as base units."""
        try:
            return _parse_base_units(self.cumulative)
        except ValueError as exc:
            raise ValueError(f"invalid commit receipt cumulative: {self.cumulative}") from exc

    def to_dict(self) -> dict[str, Any]:
        return {
            "deliveryId": self.delivery_id,
            "sessionId": self.session_id,
            "amount": self.amount,
            "cumulative": self.cumulative,
            "status": self.status,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CommitReceipt:
        # ``status`` is validated against the known commit statuses at decode
        # time, so a missing or unknown status fails here and a malformed
        # receipt can never advance client state.
        status = data.get("status")
        if status not in ("committed", "replayed"):
            raise ValueError(f"commit receipt: unknown status {status!r}")
        return cls(
            delivery_id=data.get("deliveryId", ""),
            session_id=data.get("sessionId", ""),
            amount=data.get("amount", ""),
            cumulative=data.get("cumulative", ""),
            status=status,
        )
