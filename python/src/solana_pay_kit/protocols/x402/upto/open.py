"""The x402 ``upto`` deposit settle up to the broadcast.

:func:`upto_requirements` builds the route's ``PaymentRequirements``;
:func:`prepare_upto_open` runs every check a sponsor makes on a client's
``PAYMENT-SIGNATURE`` before it co-signs the channel ``open`` (Phase 3 steps 0
to 7 and the client-supplied ``openTransaction`` acceptance policy), reading
chain state only to confirm the channel PDA is free and to learn the
challenged slot; :func:`cosign_upto_open` adds the fee payer's signature.
:class:`~solana_pay_kit.protocols.x402.upto.X402Upto` runs them before it
broadcasts, and :func:`verify_upto_open_preflight` is the read-only verify
preflight (“it MAY be offered as a read-only preflight of the same static
checks below without co-signing or broadcasting open”), mirroring the Rust
kit's ``x402::server::upto`` ``prepare_open`` and its testkit.
"""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, cast

from solders.pubkey import Pubkey  # type: ignore[import-untyped]

from solana_pay_kit._paycore import txv1
from solana_pay_kit._paycore.paymentchannels import PROGRAM_ID, Distribution
from solana_pay_kit._paycore.transaction import SignatureCheckError, verify_required_signatures
from solana_pay_kit.errors import InvalidProofError
from solana_pay_kit.protocols.x402.upto.types import (
    DEFAULT_UPTO_WITHDRAW_DELAY_SECONDS,
    UPTO_SCHEME,
    UptoRequirements,
)
from solana_pay_kit.protocols.x402.upto.verify import (
    DEFAULT_MAX_CHANNEL_LIFETIME_SECONDS,
    ERR_CHANNEL_ALREADY_OPEN,
    ParsedUptoPayload,
    parse_base_units,
    parse_upto_payload,
    slot_from_value,
    validate_upto_open_instruction,
    verify_payer_signature,
    verify_upto_payload,
)

if TYPE_CHECKING:
    from solana_keychain import TransactionSigner

__all__ = [
    "DEFAULT_UPTO_MAX_TIMEOUT_SECONDS",
    "PreparedUptoOpen",
    "UptoRoute",
    "advertised_versions",
    "cosign_upto_open",
    "match_offered_requirement",
    "prepare_upto_open",
    "route_memo",
    "upto_requirements",
    "verify_upto_open_preflight",
]

#: Default completion window advertised as ``maxTimeoutSeconds``.
DEFAULT_UPTO_MAX_TIMEOUT_SECONDS = 300

# The server-provided build hints a client echoes in ``accepted`` but a
# verify-time rebuild does not carry.
_HINT_KEYS = ("recentBlockhash", "lastValidBlockHeight", "recentSlot")

_UNSET: Any = object()


def _invalid(message: str) -> InvalidProofError:
    return InvalidProofError(message, code="payment_invalid")


@dataclass(frozen=True)
class UptoRoute:
    """What a server offers on one ``upto`` route.

    ``network`` is CAIP-2 and ``amount`` the authorized maximum in base
    units. ``fee_payer`` sponsors the fee and rent and holds the zero-share
    payee seat; ``receiver_authorizer`` signs settlement vouchers.
    ``transaction_versions`` is the accepted open message-version set
    (``None`` accepts version 0 only). ``memo`` is the seller-declared
    ``extra.memo`` (see :func:`route_memo`).
    """

    network: str
    amount: int
    asset: str
    token_program: str
    pay_to: str
    fee_payer: str
    receiver_authorizer: str
    withdraw_delay: int = DEFAULT_UPTO_WITHDRAW_DELAY_SECONDS
    max_timeout_seconds: int = DEFAULT_UPTO_MAX_TIMEOUT_SECONDS
    memo: str | None = None
    transaction_versions: Sequence[int] | None = None
    decimals: int | None = None

    def accepted_versions(self) -> tuple[int, ...]:
        return txv1.accepted_versions(self.transaction_versions)


def route_memo(route: str) -> str:
    """The memo a route-bound challenge declares for ``route`` (a canonical
    request identity such as ``"GET /reports?id=7"``): the payer signs it into
    the open, so the authorization only verifies for that route. Same value as
    the Rust kit's ``X402Upto::route_memo``."""
    digest = hashlib.sha256(b"x402-upto-route\0" + route.encode("utf-8")).digest()
    return f"x402-upto:{digest[:16].hex()}"


def advertised_versions(accepted: Sequence[int]) -> list[int] | None:
    """What a server advertises: nothing when only the default version is
    accepted, so the wire shape is unchanged for version-0-only servers."""
    if tuple(accepted) == txv1.DEFAULT_ACCEPTED_VERSIONS:
        return None
    return list(accepted)


def upto_requirements(route: UptoRoute) -> UptoRequirements:
    """The route's ``upto`` ``PaymentRequirements`` without build hints
    (``recentBlockhash`` / ``recentSlot`` are stamped at challenge time)."""
    if route.withdraw_delay <= 0:
        raise ValueError("solana_pay_kit: x402 upto withdrawDelay must be greater than zero")
    requirements: dict[str, Any] = {
        "scheme": UPTO_SCHEME,
        "network": route.network,
        "amount": str(route.amount),
        "asset": route.asset,
        "payTo": route.pay_to,
        "maxTimeoutSeconds": route.max_timeout_seconds,
        "extra": {
            "tokenProgram": route.token_program,
            "feePayer": route.fee_payer,
            "receiverAuthorizer": route.receiver_authorizer,
            "withdrawDelay": route.withdraw_delay,
        },
    }
    extra = requirements["extra"]
    if route.decimals is not None:
        extra["decimals"] = route.decimals
    versions = advertised_versions(route.accepted_versions())
    if versions is not None:
        extra["transactionVersions"] = versions
    if route.memo is not None:
        extra["memo"] = route.memo
    return cast("UptoRequirements", requirements)


# -- accepted matching ----------------------------------------------------------


def _string(obj: dict[str, Any], key: str, *, optional: bool = False) -> str | None:
    value = obj.get(key)
    if value is None:
        if optional:
            return None
        raise _invalid(f"invalid accepted requirement: missing field `{key}`")
    if not isinstance(value, str):
        raise _invalid(f"invalid accepted requirement: {key} must be a string")
    return value


def _integer(obj: dict[str, Any], key: str, bits: int, *, signed: bool = False, optional: bool = False) -> int | None:
    value = obj.get(key)
    if value is None:
        if optional:
            return None
        raise _invalid(f"invalid accepted requirement: missing field `{key}`")
    low, high = (-(1 << (bits - 1)), (1 << (bits - 1)) - 1) if signed else (0, (1 << bits) - 1)
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise _invalid(f"invalid accepted requirement: {key} {value!r} is not an integer")
    return value


def _normalized(value: Any) -> dict[str, Any]:
    """A requirement reduced to the fields the scheme defines, build hints
    removed: both sides of the ``accepted`` match normalize the same way, so
    field order, informational extras and the echoed hints do not matter."""
    if not isinstance(value, dict):
        raise _invalid("invalid accepted requirement: accepted must be an object")
    obj = cast("dict[str, Any]", value)
    raw_extra = obj.get("extra")
    if not isinstance(raw_extra, dict):
        raise _invalid("invalid accepted requirement: missing field `extra`")
    extra_in = cast("dict[str, Any]", raw_extra)
    scheme = obj.get("scheme", UPTO_SCHEME)
    if not isinstance(scheme, str):
        raise _invalid("invalid accepted requirement: scheme must be a string")
    extra: dict[str, Any] = {
        "feePayer": _string(extra_in, "feePayer"),
        "receiverAuthorizer": _string(extra_in, "receiverAuthorizer"),
        "withdrawDelay": _integer(extra_in, "withdrawDelay", 32),
    }
    token_program = _string(extra_in, "tokenProgram", optional=True)
    if token_program is not None:
        extra["tokenProgram"] = token_program
    try:
        versions = txv1.parse_transaction_versions(extra_in.get("transactionVersions"))
    except txv1.TransactionVersionError as exc:
        raise _invalid(f"invalid accepted requirement: {exc}") from exc
    if versions is not None:
        extra["transactionVersions"] = versions
    valid_after = _integer(extra_in, "validAfter", 64, signed=True, optional=True)
    if valid_after is not None:
        extra["validAfter"] = valid_after
    memo = _string(extra_in, "memo", optional=True)
    if memo is not None:
        extra["memo"] = memo
    for hint in _HINT_KEYS:
        raw_hint = extra_in.get(hint)
        if raw_hint is None:
            continue
        if hint == "recentSlot" and slot_from_value(raw_hint) is None:
            raise _invalid(f"invalid accepted requirement: recentSlot {raw_hint!r} is not a u64")
        if hint != "recentSlot" and not isinstance(raw_hint, str):
            raise _invalid(f"invalid accepted requirement: {hint} must be a string")
    return {
        "scheme": scheme,
        "network": _string(obj, "network"),
        "amount": _string(obj, "amount"),
        "asset": _string(obj, "asset"),
        "payTo": _string(obj, "payTo"),
        "maxTimeoutSeconds": _integer(obj, "maxTimeoutSeconds", 64),
        "extra": extra,
    }


def match_offered_requirement(offered: Sequence[UptoRequirements], accepted: Any) -> UptoRequirements:
    """The offered requirement the client's ``accepted`` structurally matches.

    The returned requirement is always one the server offered, so the asset
    and token program the channel is bound to are never client-chosen.
    """
    wanted = _normalized(accepted)
    for requirement in offered:
        if _normalized(requirement) == wanted:
            return requirement
    raise _invalid("credential's accepted does not match any offered currency option")


# -- deposit settle ---------------------------------------------------------------


@dataclass
class PreparedUptoOpen:
    """A client authorization that passed every pre-broadcast check."""

    transaction: Any
    requirements: UptoRequirements
    payload: ParsedUptoPayload
    payer: Pubkey
    payee: Pubkey
    channel_id: Pubkey
    max_amount: int
    mint: Pubkey
    token_program: Pubkey
    program_id: Pubkey
    distribution: list[Distribution]

    @property
    def expires_at(self) -> int:
        return self.payload.expires_at


def _decode_header(header: str) -> dict[str, Any]:
    try:
        decoded = base64.b64decode(header, validate=True)
    except Exception as exc:  # noqa: BLE001
        raise _invalid(f"invalid upto payment signature: base64: {exc}") from exc
    try:
        envelope = json.loads(decoded)
    except Exception as exc:  # noqa: BLE001
        raise _invalid(f"invalid upto payment signature: {exc}") from exc
    if not isinstance(envelope, dict):
        raise _invalid("invalid upto payment signature: the envelope must be an object")
    return cast("dict[str, Any]", envelope)


def _pubkey(value: str, label: str) -> Pubkey:
    try:
        return Pubkey.from_string(value)
    except Exception as exc:  # noqa: BLE001
        raise _invalid(f"invalid {label}: {exc}") from exc


def _decode_transaction(transaction_b64: str) -> Any:
    try:
        return txv1.decode_transaction(base64.b64decode(transaction_b64, validate=True))
    except Exception as exc:  # noqa: BLE001
        raise _invalid(f"invalid transaction: {exc}") from exc


async def _challenged_slot(rpc: Any) -> int | None:
    """The cluster's slot now, from one ``getLatestBlockhash``; ``None`` when
    unknown (the PDA bind still holds and the program enforces the window)."""
    try:
        response = await rpc.get_latest_blockhash()
        slot = response.context.slot
    except Exception:  # noqa: BLE001 - a failed read skips the window check only
        return None
    return slot if isinstance(slot, int) and not isinstance(slot, bool) else None


async def _ensure_channel_absent(rpc: Any, channel_id: Pubkey) -> None:
    """Phase 3 step 4: deposit settle opens the channel itself, so an account
    already at the PDA is refused. A failed read is a refusal too."""
    try:
        existing = await rpc.get_account_info(str(channel_id))
    except Exception as exc:  # noqa: BLE001
        raise _invalid(f"channel account read failed: {exc}") from exc
    if existing is not None:
        raise _invalid(f"{ERR_CHANNEL_ALREADY_OPEN}: channel {channel_id} already exists; deposit settle must open it")


async def prepare_upto_open(
    header: str,
    offered: Sequence[UptoRequirements],
    *,
    fee_payer: str,
    receiver_authorizer: str,
    rpc: Any,
    now: int,
    accepted_versions: Sequence[int] = txv1.DEFAULT_ACCEPTED_VERSIONS,
    max_channel_lifetime_seconds: int = DEFAULT_MAX_CHANNEL_LIFETIME_SECONDS,
    program_id: Pubkey = PROGRAM_ID,
    recent_slot: int | None = _UNSET,
) -> PreparedUptoOpen:
    """Every check a sponsor makes before co-signing the client's open.

    Decode the envelope and the payload, match ``accepted`` against the
    ``offered`` requirements, verify the payload (ceiling, deposit, clock,
    lifetime, receiver authorizer), confirm the channel PDA holds no account,
    validate the open transaction and the payer's signature. ``recent_slot``
    is the challenged slot; when omitted it is read from ``rpc``.
    """
    envelope = _decode_header(header)
    version = envelope.get("x402Version")
    if isinstance(version, bool) or not isinstance(version, int) or version < 0:
        raise _invalid("invalid upto payment signature: x402Version must be an unsigned integer")
    if "accepted" not in envelope:
        raise _invalid("invalid upto payment signature: missing field `accepted`")
    if "payload" not in envelope:
        raise _invalid("invalid upto payment signature: missing field `payload`")
    payload = parse_upto_payload(envelope["payload"])
    accepted: Any = envelope["accepted"]
    scheme = accepted.get("scheme") if isinstance(accepted, dict) else None
    if scheme != UPTO_SCHEME:
        raise _invalid(f"Invalid payload type: {scheme if isinstance(scheme, str) else ''}")

    requirements = match_offered_requirement(offered, accepted)
    verify_upto_payload(
        payload,
        requirements,
        receiver_authorizer,
        now,
        max_channel_lifetime_seconds=max_channel_lifetime_seconds,
    )
    claimed_network = cast("dict[str, Any]", accepted).get("network")
    if claimed_network != requirements["network"]:
        raise _invalid(f"network mismatch: payload {claimed_network!r}, expected {requirements['network']}")

    mint = _pubkey(requirements["asset"], "matched asset mint")
    token_program_str = requirements["extra"].get("tokenProgram")
    if not token_program_str:
        raise _invalid("matched requirement missing token program")
    token_program = _pubkey(token_program_str, "matched token program")
    fee_payer_key = _pubkey(fee_payer, "feePayer")
    receiver_key = _pubkey(receiver_authorizer, "receiverAuthorizer")
    # Always explicit: the payee seat is the fee payer with a zero implicit
    # remainder, so 100% of settled funds go to payTo.
    distribution = [Distribution(recipient=_pubkey(requirements["payTo"], "payTo"), bps=10_000)]
    channel_id = _pubkey(payload.channel_id, "channelId")
    payer = _pubkey(payload.from_, "payer")
    max_amount = parse_base_units(payload.max_amount, "maxAmount")

    if payload.open_transaction is None:
        raise _invalid("payment-channel asset transfer method requires openTransaction (pull)")
    tx = _decode_transaction(payload.open_transaction)
    await _ensure_channel_absent(rpc, channel_id)
    challenged_slot = await _challenged_slot(rpc) if recent_slot is _UNSET else recent_slot
    validate_upto_open_instruction(
        tx,
        accepted_versions=accepted_versions,
        program_id=program_id,
        rent_payer=fee_payer_key,
        authorized_signer=receiver_key,
        payer=payer,
        payee=fee_payer_key,
        mint=mint,
        token_program=token_program,
        channel_id=channel_id,
        max_amount=max_amount,
        withdraw_delay=int(requirements["extra"]["withdrawDelay"]),
        payload_nonce=payload.nonce,
        payload_open_slot=payload.open_slot,
        recent_slot=challenged_slot,
        expected_memo=requirements["extra"].get("memo"),
        expected_recipients=distribution,
    )
    verify_payer_signature(tx, payer)
    return PreparedUptoOpen(
        transaction=tx,
        requirements=requirements,
        payload=payload,
        payer=payer,
        payee=fee_payer_key,
        channel_id=channel_id,
        max_amount=max_amount,
        mint=mint,
        token_program=token_program,
        program_id=program_id,
        distribution=distribution,
    )


async def cosign_upto_open(tx: Any, signer: TransactionSigner) -> bytes:
    """Sign the fee-payer slot of the client's open and return the wire.

    The fee payer must be the first account key. Legacy and version 0 are
    signed through ``sign_transaction``; version 1, which solders cannot
    represent, over its message bytes. Every required signature must then
    verify.
    """
    keys = list(tx.message.account_keys)
    if not keys or keys[0] != signer.pubkey:
        raise _invalid("open transaction fee payer must be the advertised fee payer")
    if txv1.is_v1(tx):
        signatures = list(tx.signatures)
        signatures[0] = await signer.sign_message(bytes(tx.message))
        signed: Any = txv1.TransactionV1.populate(tx.message, signatures)
        wire = bytes(signed)
    else:
        result = await signer.sign_transaction(tx)
        wire = bytes(result.transaction)
        signed = txv1.decode_transaction(wire)
    try:
        verify_required_signatures(signed)
    except SignatureCheckError as exc:
        raise _invalid(f"open transaction signature verification failed: {exc}") from exc
    return wire


async def verify_upto_open_preflight(
    header: str,
    offered: Sequence[UptoRequirements],
    *,
    fee_payer_signer: TransactionSigner,
    receiver_authorizer: str,
    rpc: Any,
    now: int,
    accepted_versions: Sequence[int] = txv1.DEFAULT_ACCEPTED_VERSIONS,
    max_channel_lifetime_seconds: int = DEFAULT_MAX_CHANNEL_LIFETIME_SECONDS,
    program_id: Pubkey = PROGRAM_ID,
) -> PreparedUptoOpen:
    """The read-only verify preflight: :func:`prepare_upto_open` plus the fee
    payer's co-signature on a copy, with nothing broadcast. Settlement
    readiness (the payout accounts) and the on-chain rebind need the
    broadcast and are left to :meth:`X402Upto.verify_open`."""
    prepared = await prepare_upto_open(
        header,
        offered,
        fee_payer=str(fee_payer_signer.pubkey),
        receiver_authorizer=receiver_authorizer,
        rpc=rpc,
        now=now,
        accepted_versions=accepted_versions,
        max_channel_lifetime_seconds=max_channel_lifetime_seconds,
        program_id=program_id,
    )
    await cosign_upto_open(prepared.transaction, fee_payer_signer)
    return prepared
