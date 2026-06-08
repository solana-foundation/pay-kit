"""Session intent request and voucher types.

The session intent opens a payment channel between a client and server,
allowing incremental payments via off-chain signed vouchers backed by the
on-chain payment-channels program. The wire format mirrors the Rust spine in
``rust/crates/mpp/src/protocol/intents/session.rs`` and the parity-verified Go
port in ``go/protocols/mpp/intents/session.go``.

The house style is plain :func:`dataclasses.dataclass` with explicit
``to_dict()``/``from_dict()`` helpers, camelCase on the wire, and omit-empty by
conditional inclusion in ``to_dict()``. ``parse_units`` is re-exported from the
charge intent so callers keep a stable amount-parsing entry point.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any, Literal

from pay_kit.protocols.mpp.intents.charge import parse_units

__all__ = [
    "DEFAULT_SESSION_EXPIRES_AT",
    "SessionMode",
    "SessionPullVoucherStrategy",
    "CommitStatus",
    "SessionSplit",
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
    "MeteringDirective",
    "MeteringUsage",
    "MeteredEnvelope",
    "parse_units",
]

# Default session voucher/directive expiry: 2100-01-01T00:00:00Z.
#
# This stays below JavaScript's max safe integer so JSON intermediaries do not
# round it before the credential is decoded. Mirrors rust
# DEFAULT_SESSION_EXPIRES_AT.
DEFAULT_SESSION_EXPIRES_AT = 4_102_444_800

# On-chain funding mechanism for a session. Advertised by the server in
# ``SessionRequest.modes``; the client picks the mode it will use in its open
# action. Mirrors rust SessionMode (rename_all="camelCase").
SessionMode = Literal["push", "pull"]

# Voucher authority used when ``"pull"`` mode is advertised. Mirrors rust
# SessionPullVoucherStrategy (rename_all="camelCase").
SessionPullVoucherStrategy = Literal["clientVoucher", "operatedVoucher"]

# Commit receipt status. Mirrors rust CommitStatus (rename_all="camelCase").
CommitStatus = Literal["committed", "replayed"]

# Action discriminator values. Note ``"topUp"`` is camelCase on the wire, just
# like rust's serde(tag="action", rename_all="camelCase").
_SessionActionTag = Literal["open", "voucher", "commit", "topUp", "close"]


@dataclass
class SessionSplit:
    """A payment split committed at channel open; distributed to a specific
    recipient when the channel closes.

    Mirrors rust ``SessionSplit``.
    """

    recipient: str
    bps: int

    def to_dict(self) -> dict[str, Any]:
        return {"recipient": self.recipient, "bps": self.bps}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SessionSplit:
        return cls(recipient=data.get("recipient", ""), bps=int(data.get("bps", 0)))


@dataclass
class SessionRequest:
    """Session intent request — the payload embedded in a 402 challenge.

    Describes the channel parameters: cap, currency, splits, network, etc.
    Mirrors rust ``SessionRequest``; optional fields are omitted from
    ``to_dict()`` when ``None`` and ``splits``/``modes`` are omitted when empty.
    """

    cap: str
    currency: str
    operator: str
    recipient: str
    decimals: int | None = None
    network: str | None = None
    splits: list[SessionSplit] = field(default_factory=list)
    program_id: str | None = None
    description: str | None = None
    external_id: str | None = None
    min_voucher_delta: str | None = None
    modes: list[SessionMode] = field(default_factory=list)
    pull_voucher_strategy: SessionPullVoucherStrategy | None = None
    recent_blockhash: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "cap": self.cap,
            "currency": self.currency,
            "operator": self.operator,
            "recipient": self.recipient,
        }
        if self.decimals is not None:
            d["decimals"] = self.decimals
        if self.network is not None:
            d["network"] = self.network
        if self.splits:
            d["splits"] = [s.to_dict() for s in self.splits]
        if self.program_id is not None:
            d["programId"] = self.program_id
        if self.description is not None:
            d["description"] = self.description
        if self.external_id is not None:
            d["externalId"] = self.external_id
        if self.min_voucher_delta is not None:
            d["minVoucherDelta"] = self.min_voucher_delta
        if self.modes:
            d["modes"] = list(self.modes)
        if self.pull_voucher_strategy is not None:
            d["pullVoucherStrategy"] = self.pull_voucher_strategy
        if self.recent_blockhash is not None:
            d["recentBlockhash"] = self.recent_blockhash
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SessionRequest:
        decimals = data.get("decimals")
        return cls(
            cap=data.get("cap", ""),
            currency=data.get("currency", ""),
            operator=data.get("operator", ""),
            recipient=data.get("recipient", ""),
            decimals=int(decimals) if decimals is not None else None,
            network=data.get("network"),
            splits=[SessionSplit.from_dict(s) for s in data.get("splits", [])],
            program_id=data.get("programId"),
            description=data.get("description"),
            external_id=data.get("externalId"),
            min_voucher_delta=data.get("minVoucherDelta"),
            modes=list(data.get("modes", [])),
            pull_voucher_strategy=data.get("pullVoucherStrategy"),
            recent_blockhash=data.get("recentBlockhash"),
        )


def _salt_to_wire(salt: int | None) -> str | None:
    """Serialize an optional salt as a decimal string.

    Mirrors rust ``serialize_optional_u64_as_string``: authorization headers are
    JSON canonicalized and arbitrary ``u64`` values are not safe JSON numbers,
    so the salt always travels as a decimal string.
    """
    if salt is None:
        return None
    return str(salt)


def _salt_from_wire(value: Any) -> int | None:
    """Parse an optional salt from a decimal string or a JSON number.

    Mirrors rust ``deserialize_optional_u64_from_string_or_number``. ``int`` is
    accepted directly (no float precision loss because Python ints are
    arbitrary precision); strings are parsed as base-10 integers.
    """
    if value is None:
        return None
    if isinstance(value, bool):
        raise ValueError("salt must be a decimal string or unsigned 64-bit integer")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 10)
        except ValueError as exc:
            raise ValueError(f"salt must be a decimal string: {value}") from exc
    raise ValueError("salt must be a decimal string or unsigned 64-bit integer")


@dataclass
class OpenPayload:
    """Payload for the ``open`` action.

    Use :meth:`push`, :meth:`payment_channel`, :meth:`payment_channel_with_mode`,
    or :meth:`pull` to construct. Inspect :attr:`mode` to distinguish variants on
    the server. ``mode`` is required: :meth:`from_dict` raises when it is absent.

    ``salt`` serializes as a decimal string and decodes from string or number.
    Mirrors rust ``OpenPayload``.
    """

    mode: SessionMode
    authorized_signer: str
    signature: str
    # Push mode
    channel_id: str | None = None
    deposit: str | None = None
    payer: str | None = None
    payee: str | None = None
    mint: str | None = None
    salt: int | None = None
    grace_period: int | None = None
    transaction: str | None = None
    # Pull mode
    token_account: str | None = None
    approved_amount: str | None = None
    owner: str | None = None
    init_multi_delegate_tx: str | None = None
    update_delegation_tx: str | None = None

    @classmethod
    def push(
        cls,
        channel_id: str,
        deposit: str,
        authorized_signer: str,
        signature: str,
    ) -> OpenPayload:
        """Construct a **push** payment-channel open payload.

        Mirrors rust ``OpenPayload::push``.
        """
        return cls(
            mode="push",
            authorized_signer=authorized_signer,
            signature=signature,
            channel_id=channel_id,
            deposit=deposit,
        )

    @classmethod
    def payment_channel(
        cls,
        channel_id: str,
        deposit: str,
        payer: str,
        payee: str,
        mint: str,
        salt: int,
        grace_period: int,
        authorized_signer: str,
        signature: str,
    ) -> OpenPayload:
        """Construct a payment-channel **push** open payload.

        Mirrors rust ``OpenPayload::payment_channel``.
        """
        return cls.payment_channel_with_mode(
            "push",
            channel_id,
            deposit,
            payer,
            payee,
            mint,
            salt,
            grace_period,
            authorized_signer,
            signature,
        )

    @classmethod
    def payment_channel_with_mode(
        cls,
        mode: SessionMode,
        channel_id: str,
        deposit: str,
        payer: str,
        payee: str,
        mint: str,
        salt: int,
        grace_period: int,
        authorized_signer: str,
        signature: str,
    ) -> OpenPayload:
        """Construct a payment-channel open payload with an explicit submission
        mode.

        Mirrors rust ``OpenPayload::payment_channel_with_mode``.
        """
        return cls(
            mode=mode,
            authorized_signer=authorized_signer,
            signature=signature,
            channel_id=channel_id,
            deposit=deposit,
            payer=payer,
            payee=payee,
            mint=mint,
            salt=salt,
            grace_period=grace_period,
        )

    @classmethod
    def pull(
        cls,
        token_account: str,
        approved_amount: str,
        owner: str,
        authorized_signer: str,
        signature: str,
    ) -> OpenPayload:
        """Construct a **pull** (SPL delegation) open payload.

        Mirrors rust ``OpenPayload::pull``.
        """
        return cls(
            mode="pull",
            authorized_signer=authorized_signer,
            signature=signature,
            token_account=token_account,
            approved_amount=approved_amount,
            owner=owner,
        )

    def with_transaction(self, tx_base64: str) -> OpenPayload:
        """Attach a signed open transaction for operator/server broadcast.

        Mirrors rust ``OpenPayload::with_transaction``.
        """
        self.transaction = tx_base64
        return self

    def with_init_tx(self, tx_base64: str) -> OpenPayload:
        """Attach a pre-signed ``InitMultiDelegate`` + ``CreateFixedDelegation``
        transaction.

        Mirrors rust ``OpenPayload::with_init_tx``.
        """
        self.init_multi_delegate_tx = tx_base64
        return self

    def with_update_tx(self, tx_base64: str) -> OpenPayload:
        """Attach a pre-signed ``CreateFixedDelegation`` (cap update)
        transaction.

        Mirrors rust ``OpenPayload::with_update_tx``.
        """
        self.update_delegation_tx = tx_base64
        return self

    def session_id(self) -> str:
        """Session identifier used as the store key.

        - Payment channel: ``channel_id``
        - Operated-voucher pull: ``token_account``

        Mirrors rust ``OpenPayload::session_id``.
        """
        if self.channel_id is not None:
            return self.channel_id
        if self.mode == "push":
            raise ValueError("push open missing channelId")
        if self.mode == "pull":
            if self.token_account is not None:
                return self.token_account
            raise ValueError("pull open missing channelId or tokenAccount")
        raise ValueError(f"open payload: unknown mode {self.mode!r}")

    def deposit_amount(self) -> int:
        """Deposit / approved amount for this open (base units).

        Mirrors rust ``OpenPayload::deposit_amount``.
        """
        if self.deposit is not None:
            raw = self.deposit
        elif self.mode == "push":
            raise ValueError("push open missing deposit")
        elif self.mode == "pull":
            if self.approved_amount is None:
                raise ValueError("pull open missing deposit or approvedAmount")
            raw = self.approved_amount
        else:
            raise ValueError(f"open payload: unknown mode {self.mode!r}")
        try:
            return int(raw, 10)
        except ValueError as exc:
            raise ValueError(f"invalid deposit amount: {raw}") from exc

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"mode": self.mode}
        if self.channel_id is not None:
            d["channelId"] = self.channel_id
        if self.deposit is not None:
            d["deposit"] = self.deposit
        if self.payer is not None:
            d["payer"] = self.payer
        if self.payee is not None:
            d["payee"] = self.payee
        if self.mint is not None:
            d["mint"] = self.mint
        salt = _salt_to_wire(self.salt)
        if salt is not None:
            d["salt"] = salt
        if self.grace_period is not None:
            d["gracePeriod"] = self.grace_period
        if self.transaction is not None:
            d["transaction"] = self.transaction
        if self.token_account is not None:
            d["tokenAccount"] = self.token_account
        if self.approved_amount is not None:
            d["approvedAmount"] = self.approved_amount
        if self.owner is not None:
            d["owner"] = self.owner
        if self.init_multi_delegate_tx is not None:
            d["initMultiDelegateTx"] = self.init_multi_delegate_tx
        if self.update_delegation_tx is not None:
            d["updateDelegationTx"] = self.update_delegation_tx
        d["authorizedSigner"] = self.authorized_signer
        d["signature"] = self.signature
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> OpenPayload:
        mode = data.get("mode")
        if not mode:
            raise ValueError("open payload: missing mode")
        return cls(
            mode=mode,
            authorized_signer=data.get("authorizedSigner", ""),
            signature=data.get("signature", ""),
            channel_id=data.get("channelId"),
            deposit=data.get("deposit"),
            payer=data.get("payer"),
            payee=data.get("payee"),
            mint=data.get("mint"),
            salt=_salt_from_wire(data.get("salt")),
            grace_period=(int(data["gracePeriod"]) if data.get("gracePeriod") is not None else None),
            transaction=data.get("transaction"),
            token_account=data.get("tokenAccount"),
            approved_amount=data.get("approvedAmount"),
            owner=data.get("owner"),
            init_multi_delegate_tx=data.get("initMultiDelegateTx"),
            update_delegation_tx=data.get("updateDelegationTx"),
        )


@dataclass
class VoucherData:
    """The canonical content of a voucher, signed by the client's session key.

    Serialized as the on-chain ``VoucherArgs`` layout before signing:
    ``channel_id || cumulative_amount_le || expires_at_le``. The wire field for
    the cumulative amount is ``cumulativeAmount`` with a ``cumulative`` decode
    alias. Mirrors rust ``VoucherData``.
    """

    channel_id: str
    cumulative: str
    expires_at: int
    nonce: int | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "channelId": self.channel_id,
            "cumulativeAmount": self.cumulative,
            "expiresAt": self.expires_at,
        }
        if self.nonce is not None:
            d["nonce"] = self.nonce
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> VoucherData:
        if "cumulativeAmount" in data:
            cumulative = data["cumulativeAmount"]
        elif "cumulative" in data:
            cumulative = data["cumulative"]
        else:
            cumulative = ""
        nonce = data.get("nonce")
        return cls(
            channel_id=data.get("channelId", ""),
            cumulative=cumulative,
            expires_at=int(data.get("expiresAt", 0)),
            nonce=int(nonce) if nonce is not None else None,
        )

    def message_bytes(self) -> bytes:
        """Serialize to the payment-channels ``VoucherArgs`` bytes signed by
        Ed25519.

        Layout (exactly 48 bytes): ``channel_id``\\ (32, base58-decoded) ||
        ``cumulative_amount`` little-endian ``u64`` (offset 32) || ``expires_at``
        little-endian ``i64`` (offset 40). The ``channel_id`` MUST decode to
        exactly 32 bytes. Mirrors rust ``VoucherData::message_bytes`` and the Go
        ``VoucherData.MessageBytes``.
        """
        # Lazy import so the module imports without solders installed, matching
        # the charge intent's discipline and avoiding an import cycle with the
        # on-chain glue module.
        from solders.pubkey import Pubkey  # type: ignore[import-untyped]

        try:
            channel = bytes(Pubkey.from_string(self.channel_id))
        except (ValueError, TypeError) as exc:
            raise ValueError(f"invalid channelId {self.channel_id!r}") from exc
        if len(channel) != 32:
            raise ValueError(f"channelId must be 32 bytes, got {len(channel)}")
        try:
            cumulative = int(self.cumulative, 10)
        except ValueError as exc:
            raise ValueError("invalid voucher cumulative") from exc
        return channel + struct.pack("<Q", cumulative) + struct.pack("<q", self.expires_at)


@dataclass
class SignedVoucher:
    """A signed voucher authorizing cumulative payment up to ``cumulative``.

    Vouchers are cumulative: the server always uses the latest valid voucher it
    has received. The client MUST increment ``cumulative`` with each request.
    Mirrors rust ``SignedVoucher``.
    """

    data: VoucherData
    signature: str

    def to_dict(self) -> dict[str, Any]:
        return {"data": self.data.to_dict(), "signature": self.signature}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SignedVoucher:
        return cls(
            data=VoucherData.from_dict(data.get("data", {})),
            signature=data.get("signature", ""),
        )


@dataclass
class VoucherPayload:
    """Payload for the ``voucher`` action (per-request micropayment).

    Mirrors rust ``VoucherPayload``.
    """

    voucher: SignedVoucher

    def to_dict(self) -> dict[str, Any]:
        return {"voucher": self.voucher.to_dict()}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> VoucherPayload:
        return cls(voucher=SignedVoucher.from_dict(data.get("voucher", {})))


@dataclass
class CommitPayload:
    """Payload for the ``commit`` action.

    Mirrors rust ``CommitPayload``.
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

    Mirrors rust ``TopUpPayload``.
    """

    channel_id: str
    new_deposit: str
    signature: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "channelId": self.channel_id,
            "newDeposit": self.new_deposit,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TopUpPayload:
        return cls(
            channel_id=data.get("channelId", ""),
            new_deposit=data.get("newDeposit", ""),
            signature=data.get("signature", ""),
        )


@dataclass
class ClosePayload:
    """Payload for the ``close`` action.

    Mirrors rust ``ClosePayload``; ``voucher`` is omitted when ``None``.
    """

    channel_id: str
    voucher: SignedVoucher | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"channelId": self.channel_id}
        if self.voucher is not None:
            d["voucher"] = self.voucher.to_dict()
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ClosePayload:
        voucher = data.get("voucher")
        return cls(
            channel_id=data.get("channelId", ""),
            voucher=SignedVoucher.from_dict(voucher) if voucher is not None else None,
        )


@dataclass
class SessionAction:
    """The action submitted by the client in an Authorization header.

    Serialized as a tagged object with
    ``"action": "open" | "voucher" | "commit" | "topUp" | "close"`` and the
    payload fields flattened alongside the discriminator. Exactly one payload is
    set for a valid action. Mirrors rust ``SessionAction``
    (serde tag="action", rename_all="camelCase").
    """

    open: OpenPayload | None = None
    voucher: VoucherPayload | None = None
    commit: CommitPayload | None = None
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
    def commit_action(cls, payload: CommitPayload) -> SessionAction:
        """Wrap a :class:`CommitPayload` as a :class:`SessionAction`."""
        return cls(commit=payload)

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

        Mirrors rust's ``#[serde(tag="action")]`` enum encoding. Exactly one
        variant must be set.
        """
        variants: list[tuple[_SessionActionTag, dict[str, Any]]] = []
        if self.open is not None:
            variants.append(("open", self.open.to_dict()))
        if self.voucher is not None:
            variants.append(("voucher", self.voucher.to_dict()))
        if self.commit is not None:
            variants.append(("commit", self.commit.to_dict()))
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

        Mirrors rust's ``#[serde(tag="action")]`` decoding: an empty discriminator
        and an unknown action both raise.
        """
        action = data.get("action")
        if not action:
            raise ValueError("session action: missing action discriminator")
        if action == "open":
            return cls(open=OpenPayload.from_dict(data))
        if action == "voucher":
            return cls(voucher=VoucherPayload.from_dict(data))
        if action == "commit":
            return cls(commit=CommitPayload.from_dict(data))
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
    sends a :class:`CommitPayload` back to the server. Mirrors rust
    ``MeteringDirective``.
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

        Mirrors rust ``MeteringDirective::amount_base_units``.
        """
        try:
            return int(self.amount, 10)
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
    :class:`MeteringDirective`. Mirrors rust ``MeteringUsage``.
    """

    delivery_id: str
    amount: str

    def amount_base_units(self) -> int:
        """Parse ``amount`` as base units.

        Mirrors rust ``MeteringUsage::amount_base_units``.
        """
        try:
            return int(self.amount, 10)
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

    The payload is left as an opaque value (any JSON-serializable object),
    mirroring rust ``MeteredEnvelope<T>``.
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

    Mirrors rust ``CommitReceipt``.
    """

    delivery_id: str
    session_id: str
    amount: str
    cumulative: str
    status: CommitStatus

    def amount_base_units(self) -> int:
        """Parse ``amount`` as base units."""
        try:
            return int(self.amount, 10)
        except ValueError as exc:
            raise ValueError(f"invalid commit receipt amount: {self.amount}") from exc

    def cumulative_base_units(self) -> int:
        """Parse ``cumulative`` as base units."""
        try:
            return int(self.cumulative, 10)
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
        return cls(
            delivery_id=data.get("deliveryId", ""),
            session_id=data.get("sessionId", ""),
            amount=data.get("amount", ""),
            cumulative=data.get("cumulative", ""),
            status=data.get("status", "committed"),
        )
