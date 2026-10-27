"""x402 ``upto`` client builder - ``payment-channel`` asset transfer method.

Parses an ``upto`` 402 challenge and builds the client authorization: a signed
channel ``open`` transaction (the deposit is the ceiling) plus the
``PAYMENT-SIGNATURE`` envelope. The client signs only its own (payer) slot in the
pull-style open; the advertised fee payer completes the fee-payer signature and
broadcasts. Mirrors the Go reference
(``go/protocols/x402/client/upto.go``).
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, cast

from solders.hash import Hash  # type: ignore[import-untyped]
from solders.instruction import Instruction  # type: ignore[import-untyped]
from solders.pubkey import Pubkey  # type: ignore[import-untyped]

from solana_pay_kit._paycore import txv1
from solana_pay_kit._paycore.paymentchannels import (
    OPEN_MAX_COMPUTE_UNIT_LIMIT,
    OPEN_MAX_MEMO_BYTES,
    PAYMENT_CHANNELS_PROGRAM_ID,
    Distribution,
    OpenChannelParams,
    build_open_instruction,
    find_channel_pda,
)
from solana_pay_kit._paycore.solana import MEMO_PROGRAM, TOKEN_PROGRAM
from solana_pay_kit._paycore.transaction import build_partially_signed_transaction
from solana_pay_kit.protocols.x402.exact.verify import X402_VERSION
from solana_pay_kit.protocols.x402.upto.types import (
    UPTO_SCHEME,
    UptoPayload,
    UptoRequirements,
)
from solana_pay_kit.protocols.x402.upto.verify import MIN_MEMO_NONCE_BYTES, decimal_u64, slot_from_value

if TYPE_CHECKING:
    from solana_keychain import TransactionSigner

__all__ = [
    "parse_upto_challenge",
    "build_upto_payload",
    "encode_upto_header",
    "build_upto_header",
]

#: Maximum byte length of the memo emitted after ``open`` (``extra.memo`` is
#: “Maximum 256 bytes”).
_OPEN_MAX_MEMO_BYTES = OPEN_MAX_MEMO_BYTES


def _invalid_challenge(message: str) -> ValueError:
    return ValueError(f"x402 client: invalid upto challenge: {message}")


def _require_str(obj: Mapping[str, Any], key: str, label: str) -> str:
    value = obj.get(key)
    if not isinstance(value, str) or not value:
        raise _invalid_challenge(f"missing {label}")
    return value


def _require_uint(obj: Mapping[str, Any], key: str, label: str, bits: int) -> int:
    value = obj.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < (1 << bits):
        raise _invalid_challenge(f"{label} {value!r} must be an unsigned {bits}-bit integer")
    return value


def _salt_for_nonce(nonce: str | None) -> int:
    """The channel salt for a request ``nonce``: derived from it, so
    rebuilding the payment for the same request against the same challenge
    yields the same channel rather than a second deposit; random when the
    caller supplied none. Same derivation as the Rust kit."""
    if not nonce:
        return secrets.randbits(64)
    digest = hashlib.sha256(b"x402-upto-salt\0" + nonce.encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "little")


def _random_memo_nonce() -> str:
    """A fresh memo nonce: 16 CSPRNG bytes, hex encoded (“a random nonce (at
    least 16 bytes, hex-encoded)”)."""
    return secrets.token_hex(MIN_MEMO_NONCE_BYTES)


def parse_upto_challenge(headers: Mapping[str, str], body: str | None = None) -> UptoRequirements | None:
    """Extract the ``upto`` requirement from a 402 challenge.

    Reads the base64 ``payment-required`` header, falling back to a JSON body,
    and returns the first ``accepts[]`` entry whose ``scheme`` is ``upto``.
    """
    envelope: Any = None
    raw = headers.get("payment-required") or headers.get("Payment-Required")
    if raw:
        try:
            envelope = json.loads(base64.b64decode(raw, validate=True))
        except Exception:  # noqa: BLE001
            return None
    elif body:
        try:
            envelope = json.loads(body)
        except Exception:  # noqa: BLE001
            return None
    else:
        return None
    if not isinstance(envelope, dict):
        return None
    accepts = cast("dict[str, Any]", envelope).get("accepts")
    if not isinstance(accepts, list):
        return None
    for entry in cast("list[Any]", accepts):
        if isinstance(entry, dict) and cast("dict[str, Any]", entry).get("scheme") == UPTO_SCHEME:
            return cast("UptoRequirements", entry)
    return None


async def build_upto_payload(
    signer: TransactionSigner,
    requirements: UptoRequirements,
    expires_at: int,
    nonce: str | None = None,
    *,
    rpc: Any = None,
    max_transaction_version: int | None = None,
) -> UptoPayload:
    """Build the ``upto`` payload: a partially-signed channel ``open`` + metadata.

    The client (``signer``) is the channel payer. ``extra.feePayer`` is the
    transaction fee payer, rent payer, and zero-share channel payee (lifecycle
    authority); ``extra.receiverAuthorizer`` is the authorized voucher signer
    only. The open transaction is signed only in the client's payer slot
    (pull-style); the fee-payer slot is completed server-side.

    ``nonce`` identifies the logical request and seeds the channel salt (none
    draws a random salt). The open carries one Memo: ``extra.memo`` when the
    seller declares it, else a random hex nonce. It is built in the highest
    version ``extra.transactionVersions`` advertises that the signer signs
    (``max_transaction_version``). ``extra.recentBlockhash`` and
    ``extra.recentSlot`` are hints; when either is absent one
    ``getLatestBlockhash`` call on ``rpc`` supplies it.
    """
    extra_raw: Any = cast("dict[str, Any]", requirements).get("extra")
    if not isinstance(extra_raw, dict):
        raise _invalid_challenge("missing extra")
    extra = cast("dict[str, Any]", extra_raw)
    max_amount = decimal_u64(requirements.get("amount"))
    if max_amount is None:
        raise _invalid_challenge(f"invalid upto amount {requirements.get('amount')!r}")
    mint = _pubkey(_require_str(cast("dict[str, Any]", requirements), "asset", "asset"), "asset mint")
    beneficiary_str = _require_str(cast("dict[str, Any]", requirements), "payTo", "payTo")
    fee_payer = _pubkey(_require_str(extra, "feePayer", "extra.feePayer"), "feePayer")
    receiver_authorizer_str = _require_str(extra, "receiverAuthorizer", "extra.receiverAuthorizer")
    receiver_authorizer = _pubkey(receiver_authorizer_str, "receiverAuthorizer")
    withdraw_delay = _require_uint(extra, "withdrawDelay", "extra.withdrawDelay", 32)
    if withdraw_delay == 0:
        raise _invalid_challenge("requirement missing extra.withdrawDelay (it must be greater than zero)")
    beneficiary = _pubkey(beneficiary_str, "payTo")
    # Always explicit: the payee seat is held by the facilitator (feePayer)
    # with a zero implicit remainder, so 100% of settled funds must be
    # assigned to payTo through the recipients list.
    recipients: list[Distribution] = [Distribution(recipient=beneficiary, bps=10_000)]
    program_id = Pubkey.from_string(PAYMENT_CHANNELS_PROGRAM_ID)
    token_program_raw = extra.get("tokenProgram")
    token_program = (
        _pubkey(token_program_raw, "tokenProgram") if token_program_raw else Pubkey.from_string(TOKEN_PROGRAM)
    )
    try:
        advertised = txv1.parse_transaction_versions(extra.get("transactionVersions"))
    except txv1.TransactionVersionError as exc:
        raise _invalid_challenge(str(exc)) from exc
    raw_slot = extra.get("recentSlot")
    hint_slot = slot_from_value(raw_slot) if raw_slot is not None else None
    if raw_slot is not None and hint_slot is None:
        raise _invalid_challenge(f"extra.recentSlot {raw_slot!r} is not a u64")
    raw_valid_after = extra.get("validAfter", 0)
    if isinstance(raw_valid_after, bool) or not isinstance(raw_valid_after, int):
        raise _invalid_challenge(f"extra.validAfter {raw_valid_after!r} must be an integer")
    memo = extra.get("memo")
    if memo is not None and not isinstance(memo, str):
        raise _invalid_challenge("extra.memo must be a string")

    # The channel openSlot is a PDA seed and an openArgs field: take it (and
    # the blockhash) from the challenge, and read both from one
    # getLatestBlockhash only when the challenge omits either.
    hint_blockhash = extra.get("recentBlockhash")
    if hint_blockhash is not None and not isinstance(hint_blockhash, str):
        raise _invalid_challenge("extra.recentBlockhash must be a string")
    if hint_blockhash and hint_slot is not None:
        blockhash_str, open_slot = hint_blockhash, hint_slot
    else:
        if rpc is None:
            raise ValueError("x402 client: requirement missing extra.recentBlockhash/extra.recentSlot and no rpc")
        response = await rpc.get_latest_blockhash()
        fetched_slot = getattr(getattr(response, "context", None), "slot", None)
        if hint_slot is None and not isinstance(fetched_slot, int):
            raise ValueError("x402 client: getLatestBlockhash returned no slot for the channel openSlot")
        blockhash_str = hint_blockhash or response.value.blockhash
        open_slot = hint_slot if hint_slot is not None else cast("int", fetched_slot)
    try:
        blockhash = Hash.from_string(blockhash_str)
    except Exception as exc:  # noqa: BLE001
        raise _invalid_challenge(f"invalid extra.recentBlockhash: {exc}") from exc

    payer = signer.pubkey
    salt = _salt_for_nonce(nonce)
    # “Clients MUST include a Memo instruction containing either the value of
    # extra.memo (when present) or a random nonce”: it keeps concurrent opens
    # with identical parameters distinct transactions.
    memo_text = memo if memo else _random_memo_nonce()
    memo_data = memo_text.encode("utf-8")
    if len(memo_data) > _OPEN_MAX_MEMO_BYTES:
        raise _invalid_challenge(f"extra.memo is {len(memo_data)} bytes, over the {_OPEN_MAX_MEMO_BYTES}-byte maximum")
    version = txv1.negotiate(advertised, max_transaction_version)

    channel, _ = find_channel_pda(payer, fee_payer, mint, receiver_authorizer, salt, open_slot, program_id)
    open_ix = build_open_instruction(
        OpenChannelParams(
            payer=payer,
            rent_payer=fee_payer,
            payee=fee_payer,
            mint=mint,
            authorized_signer=receiver_authorizer,
            salt=salt,
            deposit=max_amount,
            grace_period=withdraw_delay,
            open_slot=open_slot,
            recipients=recipients,
            token_program=token_program,
            program_id=program_id,
        )
    )
    instructions = [open_ix, Instruction(Pubkey.from_string(MEMO_PROGRAM), memo_data, [])]
    config = None
    if version == 1:
        # A version-1 open carries its budget in the header: the runtime
        # default for its instructions, capped at the open's 400,000 units.
        config = txv1.v1_config(min(txv1.runtime_default_unit_limit(len(instructions)), OPEN_MAX_COMPUTE_UNIT_LIMIT), 0)
    wire = await build_partially_signed_transaction(
        instructions, fee_payer, blockhash, signer, version=version, config=config
    )

    payload: UptoPayload = {
        "from": str(signer.pubkey),
        "maxAmount": str(max_amount),
        "expiresAt": expires_at,
        "validAfter": raw_valid_after,
        "nonce": str(salt),
        "channelId": str(channel),
        "deposit": str(max_amount),
        "authorizedSigner": receiver_authorizer_str,
        "openSlot": str(open_slot),
        "openTransaction": base64.b64encode(wire).decode("ascii"),
    }
    return payload


def _pubkey(value: Any, label: str) -> Pubkey:
    try:
        return Pubkey.from_string(value)
    except Exception as exc:  # noqa: BLE001
        raise _invalid_challenge(f"invalid {label}: {exc}") from exc


def encode_upto_header(requirements: UptoRequirements, payload: UptoPayload) -> str:
    """Encode the ``PAYMENT-SIGNATURE`` header (base64 JSON envelope)."""
    envelope = {
        "x402Version": X402_VERSION,
        "accepted": requirements,
        "payload": payload,
    }
    raw = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
    return base64.b64encode(raw).decode("ascii")


async def build_upto_header(
    signer: TransactionSigner,
    requirements: UptoRequirements,
    expires_at: int,
    nonce: str | None = None,
    *,
    rpc: Any = None,
    max_transaction_version: int | None = None,
) -> str:
    """Build the full ``PAYMENT-SIGNATURE`` header value for an ``upto`` retry."""
    payload = await build_upto_payload(
        signer, requirements, expires_at, nonce, rpc=rpc, max_transaction_version=max_transaction_version
    )
    return encode_upto_header(requirements, payload)
