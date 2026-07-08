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

from dataclasses import dataclass, field
from typing import Any, Literal

from solana_pay_kit.protocols.mpp.intents.charge import parse_units

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
# round it before the credential is decoded.
DEFAULT_SESSION_EXPIRES_AT = 4_102_444_800

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


# On-chain funding mechanism for a session. Advertised by the server in
# ``SessionRequest.modes``; the client picks the mode it will use in its open
# action. Encoded on the wire as the camelCase string ``"push"`` or ``"pull"``.
SessionMode = Literal["push", "pull"]

# Voucher authority used when ``"pull"`` mode is advertised. Encoded on the wire
# as the camelCase string ``"clientVoucher"`` or ``"operatedVoucher"``.
SessionPullVoucherStrategy = Literal["clientVoucher", "operatedVoucher"]

# Commit receipt status. Encoded on the wire as the camelCase string
# ``"committed"`` or ``"replayed"``.
CommitStatus = Literal["committed", "replayed"]

# Action discriminator values. Note ``"topUp"`` is camelCase on the wire, in
# line with the rest of the session field naming.
_SessionActionTag = Literal["open", "voucher", "commit", "topUp", "close"]


@dataclass
class SessionSplit:
    """A payment split committed at channel open; distributed to a specific
    recipient when the channel closes.

    ``recipient`` is the destination address and ``bps`` is that recipient's
    share of the settled amount in basis points (hundredths of a percent).
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
    """Session intent request, the payload embedded in a 402 challenge.

    Describes the channel parameters the server is offering. Optional fields are
    omitted from ``to_dict()`` when ``None``; ``splits``/``modes`` are omitted
    when empty.

    Attributes:
        cap: Maximum cumulative amount the session may bill, as a canonical
            base-unit decimal string (e.g. ``"500000"`` for 0.50 USDC at 6
            decimals). Vouchers may never sign a cumulative above this.
        currency: The settlement currency: an SPL mint address or a known
            symbol (e.g. ``"USDC"``).
        operator: Base58 address of the operator that meters the session and
            co-signs settlement (the fee payer for on-chain commits).
        recipient: Base58 address that receives the settled funds.
        decimals: Token decimals for ``currency``; required to interpret
            ``cap`` and voucher amounts when ``currency`` is a mint address.
        network: Target Solana network (``"mainnet"`` / ``"devnet"`` /
            ``"localnet"``).
        splits: Payment splits committed at channel open, each taking a
            basis-point share of every settlement.
        program_id: Base58 id of the on-chain payment-channel (push) or
            delegation (pull) program the channel is opened against.
        description: Human-readable label shown on the challenge.
        external_id: Caller-supplied correlation id echoed back on settlement.
        min_voucher_delta: Minimum increase between two consecutive vouchers,
            as a base-unit decimal string; rejects dust-sized increments.
        modes: Funding modes the server accepts (``push`` payment channel,
            ``pull`` SPL delegation).
        pull_voucher_strategy: For pull mode, how vouchers are produced
            (e.g. per-delivery vs. cumulative).
        recent_blockhash: Optional blockhash the client reuses when building
            the open transaction, avoiding an extra RPC round-trip.
        recent_slot: Slot the server fetched at challenge time (alongside the
            recent blockhash). The client uses it as the channel ``openSlot``
            (a channel PDA seed and an ``openArgs`` field) and echoes it in
            the open payload; clients do not fetch the slot themselves.
            Serialized as a decimal string like ``salt``.
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
    recent_slot: int | None = None

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
        recent_slot = _u64_to_wire(self.recent_slot)
        if recent_slot is not None:
            d["recentSlot"] = recent_slot
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SessionRequest:
        decimals = data.get("decimals")
        # ``modes`` and ``pullVoucherStrategy`` are validated against their known
        # values at decode time, so an unknown variant fails here rather than
        # being deferred to a downstream consumer.
        modes: list[SessionMode] = []
        for mode in data.get("modes", []):
            if mode not in ("push", "pull"):
                raise ValueError(f"session request: unknown mode {mode!r}")
            modes.append(mode)
        strategy = data.get("pullVoucherStrategy")
        if strategy is not None and strategy not in ("clientVoucher", "operatedVoucher"):
            raise ValueError(f"session request: unknown pullVoucherStrategy {strategy!r}")
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
            modes=modes,
            pull_voucher_strategy=strategy,
            recent_blockhash=data.get("recentBlockhash"),
            recent_slot=_u64_from_wire(data.get("recentSlot"), "recentSlot"),
        )


def _u64_to_wire(value: int | None) -> str | None:
    """Serialize an optional u64 field (salt / recentSlot) as a decimal string.

    Authorization headers are JSON canonicalized and an arbitrary ``u64`` is not
    a safe JSON number, so these fields always travel as decimal strings.
    """
    if value is None:
        return None
    return str(value)


def _u64_from_wire(value: Any, label: str) -> int | None:
    """Parse an optional u64 field (salt / recentSlot) from a decimal string or a
    JSON number.

    ``int`` is accepted directly (no float precision loss because Python ints
    are arbitrary precision); strings are parsed as base-10 integers.
    """
    if value is None:
        return None
    if isinstance(value, bool):
        raise ValueError(f"{label} must be a decimal string or unsigned 64-bit integer")
    # The value is validated as a ``u64``, rejecting negative or out-of-range
    # values here rather than letting a malformed field fail later inside
    # struct.pack. Accept an int directly (no float precision loss) or a strict
    # unsigned-decimal string.
    if isinstance(value, int):
        if not 0 <= value <= _U64_MAX:
            raise ValueError(f"{label} out of u64 range: {value}")
        return value
    if isinstance(value, str):
        try:
            return _parse_base_units(value)
        except ValueError as exc:
            raise ValueError(f"{label} must be a decimal string: {value}") from exc
    raise ValueError(f"{label} must be a decimal string or unsigned 64-bit integer")


@dataclass
class OpenPayload:
    """Payload for the ``open`` action.

    Use :meth:`push`, :meth:`payment_channel`, :meth:`payment_channel_with_mode`,
    or :meth:`pull` to construct. Inspect :attr:`mode` to distinguish variants on
    the server. ``mode`` is required: :meth:`from_dict` raises when it is absent.
    The mode-specific fields are populated according to the selected mode;
    ``salt`` serializes as a decimal string and decodes from string or number.

    Attributes:
        mode: The funding variant (``push`` payment channel, ``pull`` SPL
            delegation); selects which mode-specific fields apply.
        authorized_signer: Base58 of the key the channel authorizes to sign
            vouchers against the deposit.
        signature: Signature authorizing this open payload.
        channel_id: (push) Base58 id of the opened payment channel.
        deposit: (push) Amount funding the channel, as a base-unit decimal
            string; the ceiling vouchers can draw against.
        payer: (push) Base58 address funding the channel.
        payee: (push) Base58 address the channel settles to.
        mint: (push) SPL mint of the channel's token.
        salt: (push) Numeric salt deriving the channel PDA; distinct salts let
            one payer open several channels to one payee.
        grace_period: (push) Seconds after expiry before the channel can be
            force-closed.
        recent_slot: (push) Challenge-provided slot the channel was opened at
            (the channel ``openSlot``); a channel PDA seed, so the server
            needs it to re-derive the channel address (and later to reclaim
            the channel rent). Serialized as a decimal string like ``salt``.
        transaction: (push) Base64 signed transaction that opens the channel.
        token_account: (pull) Base58 SPL token account the delegation draws
            from.
        approved_amount: (pull) Delegation cap, as a base-unit decimal string.
        owner: (pull) Base58 owner of ``token_account``.
        init_multi_delegate_tx: (pull) Base64 transaction initializing the
            multi-delegate account when one is not yet present.
        update_delegation_tx: (pull) Base64 transaction setting/updating the
            delegation to ``approved_amount``.
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
    recent_slot: int | None = None
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

        Sets ``mode`` to ``"push"`` and records the channel id and deposit along
        with the authorized signer and its signature.
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
        recent_slot: int,
        authorized_signer: str,
        signature: str,
    ) -> OpenPayload:
        """Construct a payment-channel **push** open payload with full channel
        details.

        Records the full set of payment-channel fields (channel id, deposit,
        payer, payee, mint, salt, grace period, recent slot) in ``"push"``
        mode.
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
            recent_slot,
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
        recent_slot: int,
        authorized_signer: str,
        signature: str,
    ) -> OpenPayload:
        """Construct a payment-channel open payload with an explicit submission
        mode.

        Like :meth:`payment_channel` but lets the caller choose the ``mode``
        (``"push"`` or ``"pull"``) under which the channel fields are submitted.
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
            recent_slot=recent_slot,
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

        Sets ``mode`` to ``"pull"`` and records the delegated token account, the
        approved amount, and the owner along with the authorized signer and its
        signature.
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

        Stores the base64-encoded transaction in ``transaction`` and returns
        ``self`` for chaining.
        """
        self.transaction = tx_base64
        return self

    def with_init_tx(self, tx_base64: str) -> OpenPayload:
        """Attach a pre-signed ``InitMultiDelegate`` + ``CreateFixedDelegation``
        transaction.

        Stores the base64-encoded transaction in ``init_multi_delegate_tx`` and
        returns ``self`` for chaining.
        """
        self.init_multi_delegate_tx = tx_base64
        return self

    def with_update_tx(self, tx_base64: str) -> OpenPayload:
        """Attach a pre-signed ``CreateFixedDelegation`` (cap update)
        transaction.

        Stores the base64-encoded transaction in ``update_delegation_tx`` and
        returns ``self`` for chaining.
        """
        self.update_delegation_tx = tx_base64
        return self

    def session_id(self) -> str:
        """Session identifier used as the store key.

        - Payment channel: ``channel_id``
        - Operated-voucher pull: ``token_account``

        Raises when the required identifier for the current mode is absent.
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

        Returns ``deposit`` in push mode and ``approved_amount`` in pull mode,
        parsed as a ``u64``. Raises when the required amount for the current
        mode is absent or malformed.
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
            return _parse_base_units(raw)
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
        salt = _u64_to_wire(self.salt)
        if salt is not None:
            d["salt"] = salt
        if self.grace_period is not None:
            d["gracePeriod"] = self.grace_period
        recent_slot = _u64_to_wire(self.recent_slot)
        if recent_slot is not None:
            d["recentSlot"] = recent_slot
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
        # ``mode`` is validated against the known session modes at decode time,
        # rejecting unknown variants here rather than failing later inside
        # session_id()/deposit_amount().
        if mode not in ("push", "pull"):
            raise ValueError(f"open payload: unknown mode {mode!r}")
        return cls(
            mode=mode,
            authorized_signer=data.get("authorizedSigner", ""),
            signature=data.get("signature", ""),
            channel_id=data.get("channelId"),
            deposit=data.get("deposit"),
            payer=data.get("payer"),
            payee=data.get("payee"),
            mint=data.get("mint"),
            salt=_u64_from_wire(data.get("salt"), "salt"),
            grace_period=(int(data["gracePeriod"]) if data.get("gracePeriod") is not None else None),
            recent_slot=_u64_from_wire(data.get("recentSlot"), "recentSlot"),
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
    ``magic || channel_id || cumulative_amount_le || expires_at_le``. The wire
    field for the cumulative amount is ``cumulativeAmount`` with a
    ``cumulative`` decode alias. ``nonce`` is optional and omitted from the
    wire when ``None``.
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
        # The wire value may arrive as a JSON number; coerce to str so the
        # base-unit accessors (message_bytes, record_voucher) parse it as a
        # decimal string rather than raising TypeError.
        if not isinstance(cumulative, str):
            cumulative = str(cumulative)
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
            cumulative = _parse_base_units(self.cumulative)
        except ValueError as exc:
            raise ValueError("invalid voucher cumulative") from exc
        return voucher_message_bytes(channel, cumulative, self.expires_at)


@dataclass
class SignedVoucher:
    """A signed voucher authorizing cumulative payment up to ``cumulative``.

    Vouchers are cumulative: the server always uses the latest valid voucher it
    has received. The client MUST increment ``cumulative`` with each request.
    ``signature`` is the client's Ed25519 signature over the voucher's
    ``message_bytes``.
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

    Carries the single :class:`SignedVoucher` the client presents to authorize a
    request against an open channel.
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

    Raises the deposit backing an open channel (``channel_id``) to
    ``new_deposit``, authorized by ``signature``.
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

    Closes the channel identified by ``channel_id``. The final
    :class:`SignedVoucher` is optional and omitted from the wire when ``None``.
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
    set for a valid action.
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

        The active variant's fields are emitted at the top level next to the
        ``"action"`` tag. Exactly one variant must be set, otherwise this raises.
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

        An empty discriminator and an unknown action both raise.
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
