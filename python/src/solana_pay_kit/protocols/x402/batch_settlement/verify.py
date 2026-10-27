"""Stateless checks for the SVM ``batch-settlement`` scheme.

Everything here is pure: no RPC, no store. It covers the wire-level
obligations of spec section 4 and the stateless steps of the Phase 3 voucher
acceptance: the channel-config bindings, the PDA derivation, the Ed25519
voucher signature, the receiver-binding Memo, the ``CloseAuthorization``
digest, the server-mode payer proof message, and the corrective-402 proof.
Mirrors the Rust kit (``x402/protocol/schemes/batch_settlement/verify.rs``).
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from typing import TYPE_CHECKING

from solders.pubkey import Pubkey  # type: ignore[import-untyped]
from solders.signature import Signature  # type: ignore[import-untyped]

from solana_pay_kit._paycore.paymentchannels import PROGRAM_ID, find_channel_pda, voucher_message_bytes
from solana_pay_kit._paycore.solana import TOKEN_2022_PROGRAM, TOKEN_PROGRAM
from solana_pay_kit.protocols.x402.batch_settlement.errors import (
    INVALID_CHANNEL_ID_MISMATCH,
    INVALID_CHANNEL_STATE,
    INVALID_CLOSE_AMOUNT_UNSUPPORTED,
    INVALID_CLOSE_AUTHORIZATION,
    INVALID_CUMULATIVE_AMOUNT_MISMATCH,
    INVALID_FEE_PAYER_MISMATCH,
    INVALID_PAYLOAD_TYPE,
    INVALID_PAYMENT_FLOW,
    INVALID_RECEIVER_AUTHORIZER_MISMATCH,
    INVALID_TOKEN_PROGRAM,
    INVALID_VOUCHER_EXPIRY,
    INVALID_VOUCHER_SIGNATURE,
    INVALID_WITHDRAW_DELAY_MISMATCH,
    INVALID_WITHDRAW_DELAY_OUT_OF_RANGE,
    BatchSettlementError,
)
from solana_pay_kit.protocols.x402.batch_settlement.types import (
    MAX_WITHDRAW_DELAY_SECONDS,
    MIN_WITHDRAW_DELAY_SECONDS,
    PAYMENT_FLOW_AUTHORIZATION,
    VOUCHER_EXPIRES_AT,
    BatchChannelConfig,
    BatchPayload,
    BatchRequirements,
    BatchVoucher,
    CloseAuthorization,
    VoucherState,
)

if TYPE_CHECKING:
    from solana_keychain import SolanaSigner

__all__ = [
    "AUTHORIZATION_DOMAIN",
    "CLOSE_AUTHORIZATION_DOMAIN",
    "RECEIVER_BINDING_MEMO_PREFIX",
    "CloseAuthorizationScope",
    "authorization_message_bytes",
    "check_channel_config",
    "check_client_signed_payload",
    "check_corrective_voucher_state",
    "check_no_client_close_authorization",
    "check_no_refund_amount",
    "check_payment_flow",
    "check_token_program",
    "check_voucher",
    "check_voucher_expiry",
    "check_withdraw_delay",
    "close_authorization_digest",
    "derive_channel_id",
    "parse_pubkey",
    "parse_receiver_binding_memo",
    "receiver_binding_memo",
    "sign_close_authorization",
    "verify_close_authorization",
    "verify_voucher_signature",
]

#: Prefix of the receiver-binding Memo every ``open`` carries (spec section 3).
RECEIVER_BINDING_MEMO_PREFIX = "x402:batch-settlement:svm:rcvauth:v1:"
#: Domain separator of the ``CloseAuthorization`` digest (spec section 4.2).
CLOSE_AUTHORIZATION_DOMAIN = b"x402:batch-settlement:svm:close:v1"
#: Domain separator of the server-mode payer proof (spec section 4.2).
AUTHORIZATION_DOMAIN = b"x402-batch-authorization-v2"


def parse_pubkey(value: str) -> Pubkey:
    """Parse a base58 address, raising ``ValueError`` naming it."""
    try:
        return Pubkey.from_string(value)
    except Exception as exc:  # noqa: BLE001 - solders raises its own error types
        raise ValueError(f"invalid pubkey {value}: {exc}") from exc


def _key(value: str, field: str, code: str = INVALID_CHANNEL_STATE) -> Pubkey:
    try:
        return parse_pubkey(value)
    except ValueError as exc:
        raise BatchSettlementError(code, f"{field}: {exc}") from exc


def receiver_binding_memo(receiver_authorizer: Pubkey) -> str:
    """``x402:batch-settlement:svm:rcvauth:v1:<base58 receiverAuthorizer>``."""
    return f"{RECEIVER_BINDING_MEMO_PREFIX}{receiver_authorizer}"


def parse_receiver_binding_memo(data: bytes) -> Pubkey | None:
    """The key a receiver-binding Memo binds; ``None`` when ``data`` is not one.

    A memo with the binding prefix but no canonical base58 key binds nothing
    and is refused with ``receiver_authorizer_mismatch``.
    """
    prefix = RECEIVER_BINDING_MEMO_PREFIX.encode()
    if not data.startswith(prefix):
        return None
    try:
        key = Pubkey.from_string(data[len(prefix) :].decode("utf-8"))
    except Exception:  # noqa: BLE001
        key = None
    if key is None or receiver_binding_memo(key).encode() != data:
        raise BatchSettlementError(
            INVALID_RECEIVER_AUTHORIZER_MISMATCH,
            "receiver-binding memo does not name a base58 Solana address",
        )
    return key


def check_payment_flow(payment_flow: str | None) -> None:
    """``extra.paymentFlow``, when present, must be ``"authorization"``."""
    if payment_flow is not None and payment_flow != PAYMENT_FLOW_AUTHORIZATION:
        raise BatchSettlementError(
            INVALID_PAYMENT_FLOW, f'extra.paymentFlow must be "authorization", got {payment_flow!r}'
        )


def check_withdraw_delay(withdraw_delay: int, max_timeout_seconds: int) -> None:
    """The x402 bound on the forced-close grace period, which must also outlast
    the HTTP completion window."""
    if not MIN_WITHDRAW_DELAY_SECONDS <= withdraw_delay <= MAX_WITHDRAW_DELAY_SECONDS:
        raise BatchSettlementError(
            INVALID_WITHDRAW_DELAY_OUT_OF_RANGE,
            f"withdrawDelay {withdraw_delay} is outside "
            f"{MIN_WITHDRAW_DELAY_SECONDS}..={MAX_WITHDRAW_DELAY_SECONDS} seconds",
        )
    if withdraw_delay < max_timeout_seconds:
        raise BatchSettlementError(
            INVALID_WITHDRAW_DELAY_OUT_OF_RANGE,
            f"withdrawDelay {withdraw_delay} is shorter than maxTimeoutSeconds {max_timeout_seconds}",
        )


def check_token_program(token_program: str) -> Pubkey:
    """``extra.tokenProgram`` must name SPL Token or Token-2022 (shape only: the
    caller must also confirm it owns the mint onchain)."""
    if token_program not in (TOKEN_PROGRAM, TOKEN_2022_PROGRAM):
        raise BatchSettlementError(INVALID_TOKEN_PROGRAM, f"unsupported tokenProgram {token_program}")
    return _key(token_program, "extra.tokenProgram", INVALID_TOKEN_PROGRAM)


def derive_channel_id(config: BatchChannelConfig, fee_payer: str, program_id: Pubkey = PROGRAM_ID) -> Pubkey:
    """The canonical channel PDA: ``["channel", payer, feePayer, token,
    payerAuthorizer, u64(salt).le, u64(openSlot).le]``."""
    payer = _key(config.payer, "channelConfig.payer")
    payee = _key(fee_payer, "extra.feePayer")
    token = _key(config.token, "channelConfig.token")
    authorized_signer = _key(config.payer_authorizer, "channelConfig.payerAuthorizer")
    try:
        salt = config.salt_value()
    except ValueError as exc:
        raise BatchSettlementError(INVALID_CHANNEL_STATE, str(exc)) from exc
    channel, _ = find_channel_pda(payer, payee, token, authorized_signer, salt, config.open_slot, program_id)
    return channel


def check_channel_config(config: BatchChannelConfig, requirements: BatchRequirements) -> None:
    """Bind the client's channel configuration to the requirements it answers."""
    extra = requirements.extra
    check_payment_flow(extra.payment_flow)
    check_withdraw_delay(extra.withdraw_delay, requirements.max_timeout_seconds)
    check_token_program(extra.token_program)
    if extra.fee_payer in (config.payer, config.payer_authorizer):
        raise BatchSettlementError(
            INVALID_FEE_PAYER_MISMATCH,
            "channelConfig.payer and payerAuthorizer must not equal extra.feePayer",
        )
    if config.receiver != requirements.pay_to:
        raise BatchSettlementError(
            INVALID_CHANNEL_STATE,
            f"channelConfig.receiver {config.receiver} does not match payTo {requirements.pay_to}",
        )
    if config.token != requirements.asset:
        raise BatchSettlementError(
            INVALID_CHANNEL_STATE,
            f"channelConfig.token {config.token} does not match asset {requirements.asset}",
        )
    if config.withdraw_delay != extra.withdraw_delay:
        raise BatchSettlementError(
            INVALID_WITHDRAW_DELAY_MISMATCH,
            f"channelConfig.withdrawDelay {config.withdraw_delay} does not match "
            f"extra.withdrawDelay {extra.withdraw_delay}",
        )
    if config.receiver_authorizer is None or config.receiver_authorizer != extra.receiver_authorizer:
        raise BatchSettlementError(
            INVALID_RECEIVER_AUTHORIZER_MISMATCH,
            "channelConfig.receiverAuthorizer and extra.receiverAuthorizer must both be present and equal",
        )
    config_mode = config.voucher_signer or "client"
    extra_mode = extra.voucher_signer or "client"
    if config_mode != extra_mode:
        raise BatchSettlementError(
            INVALID_CHANNEL_STATE,
            f"channelConfig.voucherSigner {config_mode!r} does not match extra.voucherSigner {extra_mode!r}",
        )
    if extra_mode != "client" or extra.operator is not None:
        raise BatchSettlementError(
            INVALID_CHANNEL_STATE,
            'server-signed channels (extra.voucherSigner "server" / extra.operator) are not supported by '
            "this implementation; use client-signed vouchers",
        )


def check_client_signed_payload(payload: BatchPayload) -> None:
    """Refuse the server-mode variants this implementation does not serve."""
    if payload.type == "authorization":
        refused = True
    elif payload.type == "deposit":
        refused = payload.authorization is not None or payload.voucher is None
    elif payload.type == "refund":
        refused = payload.authorization is not None
    else:
        refused = False
    if refused:
        raise BatchSettlementError(
            INVALID_PAYLOAD_TYPE,
            f"{payload.type} payloads belong to server-signed channels, which this implementation does "
            "not offer; send a client-signed voucher",
        )


def check_no_refund_amount(payload: BatchPayload) -> None:
    """A ``refund`` naming an amount is refused: the program returns all unused escrow."""
    if payload.type == "refund" and payload.amount is not None:
        raise BatchSettlementError(
            INVALID_CLOSE_AMOUNT_UNSUPPORTED,
            f"refund carries amount {payload.amount!r}; this scheme returns the full unused escrow",
        )


def check_no_client_close_authorization(payload: BatchPayload) -> None:
    """A client-authored refund must not carry ``closeAuthorization``: the server adds it."""
    if payload.type == "refund" and payload.close_authorization is not None:
        raise BatchSettlementError(
            INVALID_CLOSE_AUTHORIZATION,
            "a client-authored refund must not carry closeAuthorization; the server adds it",
        )


def check_voucher_expiry(expires_at: int) -> None:
    """Every voucher in this scheme is non-expiring (``expiresAt == 0``)."""
    if expires_at != VOUCHER_EXPIRES_AT:
        raise BatchSettlementError(INVALID_VOUCHER_EXPIRY, f"voucher expiresAt must be 0, got {expires_at}")


def verify_voucher_signature(
    channel_id: str, max_claimable: int, expires_at: int, signature: str, payer_authorizer: str
) -> None:
    """Verify an Ed25519 voucher signature over the canonical 50-byte message."""

    def fail(detail: str) -> BatchSettlementError:
        return BatchSettlementError(INVALID_VOUCHER_SIGNATURE, detail)

    try:
        channel = Pubkey.from_string(channel_id)
    except Exception as exc:  # noqa: BLE001
        raise fail(f"invalid channelId: {exc}") from exc
    try:
        message = voucher_message_bytes(channel, max_claimable, expires_at)
    except ValueError as exc:
        raise fail(str(exc)) from exc
    try:
        parsed = Signature.from_string(signature)
    except Exception as exc:  # noqa: BLE001
        raise fail(f"Invalid signature encoding: {exc}") from exc
    try:
        key = Pubkey.from_string(payer_authorizer)
    except Exception as exc:  # noqa: BLE001
        raise fail(f"Invalid authorized_signer: {exc}") from exc
    if not parsed.verify(key, message):
        raise fail("Voucher signature verification failed")


def check_voucher(voucher: BatchVoucher, config: BatchChannelConfig, channel_id: Pubkey) -> int:
    """Verify a voucher against its channel; return the cumulative it authorizes.

    The voucher must name the derived channel, never expire, and carry a valid
    signature by ``channelConfig.payerAuthorizer``.
    """
    expected = str(channel_id)
    if voucher.channel_id != expected:
        raise BatchSettlementError(
            INVALID_CHANNEL_ID_MISMATCH,
            f"voucher.channelId {voucher.channel_id} does not match the derived PDA {expected}",
        )
    check_voucher_expiry(voucher.expires_at)
    try:
        max_claimable = voucher.max_claimable()
    except ValueError as exc:
        raise BatchSettlementError(INVALID_VOUCHER_SIGNATURE, str(exc)) from exc
    verify_voucher_signature(
        voucher.channel_id, max_claimable, voucher.expires_at, voucher.signature, config.payer_authorizer
    )
    return max_claimable


@dataclass(frozen=True)
class CloseAuthorizationScope:
    """Every field one cooperative close's receiver-authorizer signature binds."""

    network: str
    program_id: Pubkey
    fee_payer: Pubkey
    channel_id: Pubkey
    max_claimable_amount: int
    voucher_expires_at: int


def close_authorization_digest(scope: CloseAuthorizationScope, valid_before: int) -> bytes:
    """``SHA-256(domain || 0x00 || u16(len(network)).le || network || programId ||
    feePayer || channelId || u64(maxClaimableAmount).le || i64(voucherExpiresAt).le ||
    i64(validBefore).le)``."""
    network = scope.network.encode("utf-8")
    if len(network) > 0xFFFF:
        raise BatchSettlementError(INVALID_CLOSE_AUTHORIZATION, "network identifier is longer than 65535 bytes")
    try:
        tail = struct.pack("<Qqq", scope.max_claimable_amount, scope.voucher_expires_at, valid_before)
    except struct.error as exc:
        raise BatchSettlementError(
            INVALID_CLOSE_AUTHORIZATION, f"close authorization field out of range: {exc}"
        ) from exc
    hasher = hashlib.sha256()
    hasher.update(CLOSE_AUTHORIZATION_DOMAIN)
    hasher.update(b"\x00")
    hasher.update(struct.pack("<H", len(network)))
    hasher.update(network)
    hasher.update(bytes(scope.program_id))
    hasher.update(bytes(scope.fee_payer))
    hasher.update(bytes(scope.channel_id))
    hasher.update(tail)
    return hasher.digest()


async def sign_close_authorization(
    receiver_authorizer: SolanaSigner, scope: CloseAuthorizationScope, valid_before: int
) -> CloseAuthorization:
    """Sign a :class:`CloseAuthorization` for ``scope`` with the receiver authorizer."""
    digest = close_authorization_digest(scope, valid_before)
    try:
        signature = await receiver_authorizer.sign_message(digest)
    except Exception as exc:  # noqa: BLE001
        raise BatchSettlementError(INVALID_CLOSE_AUTHORIZATION, f"close authorization signing failed: {exc}") from exc
    return CloseAuthorization(valid_before=valid_before, signature=str(signature))


def verify_close_authorization(
    authorization: CloseAuthorization,
    bound_receiver_authorizer: Pubkey,
    scope: CloseAuthorizationScope,
    now: int,
    max_timeout_seconds: int,
) -> None:
    """Verify a close authorization against the channel's *bound* receiver
    authorizer, requiring ``now < validBefore <= now + maxTimeoutSeconds``."""

    def fail(detail: str) -> BatchSettlementError:
        return BatchSettlementError(INVALID_CLOSE_AUTHORIZATION, detail)

    horizon = now + max_timeout_seconds
    if authorization.valid_before <= now:
        raise fail(f"closeAuthorization expired at {authorization.valid_before} (now {now})")
    if authorization.valid_before > horizon:
        raise fail(
            f"closeAuthorization validBefore {authorization.valid_before} is beyond now + maxTimeoutSeconds ({horizon})"
        )
    digest = close_authorization_digest(scope, authorization.valid_before)
    try:
        signature = Signature.from_string(authorization.signature)
    except Exception as exc:  # noqa: BLE001
        raise fail("closeAuthorization signature is not 64 base58 bytes") from exc
    if not signature.verify(bound_receiver_authorizer, digest):
        raise fail("closeAuthorization is not signed by the bound receiver authorizer")


def check_corrective_voucher_state(
    voucher_state: VoucherState, channel_id: str, payer_authorizer: str, charged_cumulative_amount: int
) -> int:
    """Client check before adopting a corrective 402's snapshot.

    The server must prove a voucher the client itself signed at
    ``signedMaxClaimable``, and may not claim more charged than proven.
    Returns the cumulative base the client may adopt.
    """
    check_voucher_expiry(voucher_state.expires_at)
    try:
        signed = voucher_state.signed_max_claimable_amount()
    except ValueError as exc:
        raise BatchSettlementError(INVALID_CUMULATIVE_AMOUNT_MISMATCH, str(exc)) from exc
    verify_voucher_signature(channel_id, signed, voucher_state.expires_at, voucher_state.signature, payer_authorizer)
    if charged_cumulative_amount > signed:
        raise BatchSettlementError(
            INVALID_CUMULATIVE_AMOUNT_MISMATCH,
            f"corrective chargedCumulativeAmount {charged_cumulative_amount} exceeds the proven "
            f"signedMaxClaimable {signed}",
        )
    return charged_cumulative_amount


def authorization_message_bytes(
    channel_id: Pubkey,
    payer: Pubkey,
    operator: Pubkey,
    request_id: str,
    authorized_amount: int,
    expires_at: int,
) -> bytes:
    """The server-mode payer proof message (spec section 4.2):
    ``domain || channelId || payer || operator || u16(len(requestId)).le ||
    requestId || u64(authorizedAmount).le || i64(expiresAt).le``."""
    request = request_id.encode("utf-8")
    if not 1 <= len(request) <= 256:
        raise ValueError("batch authorization requestId must encode to 1 through 256 bytes")
    if expires_at <= 0:
        raise ValueError("batch authorization expiresAt must be positive")
    if not 0 <= authorized_amount < (1 << 64):
        raise ValueError("batch authorization authorizedAmount must be a u64")
    return b"".join(
        [
            AUTHORIZATION_DOMAIN,
            bytes(channel_id),
            bytes(payer),
            bytes(operator),
            struct.pack("<H", len(request)),
            request,
            struct.pack("<Qq", authorized_amount, expires_at),
        ]
    )
