"""On-chain verification and settlement for the session intent.

Provides the standalone open-transaction verifier and the verifier-seam
factories the session server installs to validate client-submitted on-chain
activity.

Trust model: when no verifier is installed (the seam is ``None``), transaction
signatures and deposit amounts are trusted as provided. :func:`verify_open_tx`
always validates an attached open transaction structurally (decode, bind the
payload signature, check the open instruction against the challenge, re-derive
the channel PDA); confirming that the transaction actually landed additionally
requires an RPC client. :func:`new_top_up_tx_verifier` is purely RPC-backed (the
top-up payload carries only a signature, no transaction), so without an RPC
client the top-up seam stays ``None`` and the new deposit is trusted as
provided.
"""

from __future__ import annotations

import asyncio
import base64
import struct
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol

from solders.hash import Hash  # type: ignore[import-untyped]
from solders.keypair import Keypair  # type: ignore[import-untyped]
from solders.pubkey import Pubkey  # type: ignore[import-untyped]
from solders.signature import Signature  # type: ignore[import-untyped]
from solders.transaction import Transaction  # type: ignore[import-untyped]

from pay_kit._paycore.errors import PaymentError
from pay_kit._paycore.solana import default_token_program_for_currency, resolve_mint
from pay_kit.protocols.mpp._paymentchannels import (
    PROGRAM_ID,
    Distribution,
    build_distribute_instruction,
    build_settle_and_finalize_instructions,
    find_channel_pda,
)
from pay_kit.protocols.mpp.intents.session import OpenPayload, TopUpPayload

if TYPE_CHECKING:
    from pay_kit.protocols.mpp.server.session import SessionConfig
    from pay_kit.protocols.mpp.server.session_store import ChannelState

__all__ = [
    "VerifyOpenTxExpected",
    "VerifyOpenTxResult",
    "cosign_and_broadcast_open",
    "settle_and_finalize_channel",
    "verify_open_tx",
    "new_open_tx_verifier",
    "new_top_up_tx_verifier",
    "confirm_transaction_signature",
    "is_placeholder_signature",
]

# Payment-channel open instruction discriminator (single-byte Anchor-numeric
# form, not the 8-byte sha256 convention).
_OPEN_INSTRUCTION_DISCRIMINATOR = 1


class RpcClient(Protocol):
    """Minimal RPC seam used for the optional on-chain liveness check and the
    settle-at-close broadcast.

    ``get_signature_statuses`` returns the per-signature status list (each entry
    is a status dict with an ``err`` field, or ``None`` when unknown);
    ``get_latest_blockhash`` / ``send_raw_transaction`` back the settle path."""

    async def get_signature_statuses(self, signatures: list[str]) -> list[dict | None]: ...

    async def get_latest_blockhash(self, commitment: str = ...) -> Any: ...

    async def send_raw_transaction(self, raw_tx: bytes) -> Any: ...


#: A verifier seam installed on the session config: validates a payload (open
#: or top-up) and raises on rejection.
OpenTxVerifier = Callable[[OpenPayload], Awaitable[None]]
TopUpTxVerifier = Callable[[TopUpPayload], Awaitable[None]]


class OpenVerifierConfig(Protocol):
    """The subset of the session config :func:`new_open_tx_verifier` reads:
    the challenge currency/network/recipient, the deposit cap, and the optional
    payment-channels program id override."""

    currency: str
    network: str
    recipient: str
    max_cap: int
    operator: str
    program_id: Pubkey | None


@dataclass
class VerifyOpenTxExpected:
    """The challenge-side values a client-submitted open transaction is
    validated against."""

    authorized_signer: str
    currency: str
    recipient: str
    network: str
    max_cap: int = 0
    mint: str = ""
    # operator / fee-payer pubkey (base58) — the expected rentPayer (the
    # operator while gasless). REQUIRED: the open instruction's rentPayer
    # account (slot 1) must equal it. rentPayer is a security boundary, so
    # verify_open_tx rejects an empty/None operator rather than skipping the
    # slot-1 check.
    operator: str = ""
    program_id: Pubkey | None = None


@dataclass
class VerifyOpenTxResult:
    """The channel facts extracted from a verified open transaction."""

    channel_id: str
    deposit: int
    grace_period: int
    salt: int
    # payer is the channel funder (open instruction slot 0). The caller
    # propagates it onto the payload so settle-at-close refunds the unspent
    # balance to the opener's ATA, not the recipient's.
    payer: str


def is_placeholder_signature(signature: str) -> bool:
    """Report whether ``signature`` is the pending placeholder produced by the
    server-completed open flow (an empty string or a run of 40+ ``'1'``
    characters, the base58 encoding of the all-ones marker)."""
    if signature == "":
        return True
    if len(signature) < 40:
        return False
    return signature.count("1") == len(signature)


def _decode_transaction(transaction_b64: str) -> tuple[list[str], list, list[str]]:
    """Decode a base64 (legacy or v0) transaction into ``(account_keys,
    instructions, signatures)`` as base58 strings / compiled-instruction
    objects."""
    from solders.transaction import Transaction, VersionedTransaction

    from pay_kit._paycore.transaction import is_v0_wire_bytes

    raw = base64.b64decode(transaction_b64, validate=True)
    message = None
    signatures: list = []
    if is_v0_wire_bytes(raw):
        vtx = VersionedTransaction.from_bytes(raw)
        message = vtx.message
        signatures = list(vtx.signatures)
    else:
        try:
            tx = Transaction.from_bytes(raw)
            message = tx.message
            signatures = list(tx.signatures)
        except Exception:
            vtx = VersionedTransaction.from_bytes(raw)
            message = vtx.message
            signatures = list(vtx.signatures)
    account_keys = [str(key) for key in message.account_keys]
    instructions = list(message.instructions)
    signature_strings = [str(sig) for sig in signatures]
    return account_keys, instructions, signature_strings


async def verify_open_tx(
    expected: VerifyOpenTxExpected,
    payload: OpenPayload,
    rpc_client: RpcClient | None,
) -> VerifyOpenTxResult:
    """Decode and validate a client-submitted payment-channel open transaction
    against the session challenge.

    Both legacy and v0 transaction encodings are accepted. The embedded open
    instruction must target the configured payment-channels program, the payee
    must equal the challenge recipient, the mint must match the challenge
    currency/network, the authorizedSigner (slot 4) must match the payload, the
    rentPayer (slot 1) must equal the expected operator, the deposit must be
    positive and within the cap, and the channel account must equal the PDA
    re-derived from the instruction's own seeds.

    ``expected.operator`` is the expected rentPayer (the operator while
    gasless) and is REQUIRED: rentPayer is a security boundary, so an empty/None
    operator raises ``ValueError`` rather than letting a standalone verifier
    accept an open without proving the slot-1 rentPayer.

    When the payload carries a non-placeholder signature, it must equal the
    transaction's own fee-payer signature. If ``rpc_client`` is non-None, that
    bound signature is additionally confirmed on-chain; ``None`` skips the
    liveness check (structural validation only).

    Raises:
        ValueError: if ``expected.operator`` is empty/None.
    """
    if not expected.operator:
        raise ValueError("operator (expected rentPayer) is required to verify an open transaction")
    if not payload.transaction:
        raise PaymentError(
            "openPayload.transaction is required for push-mode open verification",
            code="invalid-payload",
        )

    try:
        account_keys, instructions, signatures = _decode_transaction(payload.transaction)
    except Exception as exc:
        raise PaymentError(f"decode open transaction: {exc}", code="invalid-payload") from exc

    # Bind the claimed signature to this transaction before trusting it.
    bound_signature = payload.signature != "" and not is_placeholder_signature(payload.signature)
    if bound_signature:
        if not signatures or signatures[0] == str(Signature.default()):
            raise PaymentError(
                "openPayload.signature is set but the transaction carries no fee-payer signature",
                code="invalid-payload",
            )
        if signatures[0] != payload.signature:
            raise PaymentError(
                f"openPayload.signature {payload.signature} != transaction signature {signatures[0]}",
                code="invalid-payload",
            )

    program_id = expected.program_id if expected.program_id is not None else PROGRAM_ID
    expected_mint = expected.mint or resolve_mint(expected.currency, expected.network)
    if not expected_mint:
        raise PaymentError(
            f"could not resolve mint from currency {expected.currency!r}",
            code="invalid-payload",
        )

    def account_at(indices: list[int], slot: int, label: str) -> Pubkey:
        if slot >= len(indices) or indices[slot] >= len(account_keys):
            raise PaymentError(
                f"open instruction is missing the {label} account at slot {slot}",
                code="invalid-payload",
            )
        return Pubkey.from_string(account_keys[indices[slot]])

    open_ix = None
    for ix in instructions:
        program_index = int(ix.program_id_index)
        if program_index >= len(account_keys) or account_keys[program_index] != str(program_id):
            continue
        data = bytes(ix.data)
        if len(data) < 1 or data[0] != _OPEN_INSTRUCTION_DISCRIMINATOR:
            continue
        open_ix = ix
        break
    if open_ix is None:
        raise PaymentError("no payment-channels open instruction found", code="invalid-payload")

    # Open instruction account layout after the rentPayer (+1) shift:
    # 0 payer, 1 rentPayer, 2 payee, 3 mint, 4 authorizedSigner, 5 channel,
    # 6 payerTokenAccount, 7 channelTokenAccount, 8 tokenProgram, ...
    # rentPayer (slot 1) is pinned to the operator / fee payer.
    accounts = [int(i) for i in open_ix.accounts]
    if len(accounts) < 8:
        raise PaymentError(
            f"open instruction has too few accounts ({len(accounts)})",
            code="invalid-payload",
        )
    payer = account_at(accounts, 0, "payer")
    rent_payer = account_at(accounts, 1, "rentPayer")
    payee = account_at(accounts, 2, "payee")
    mint = account_at(accounts, 3, "mint")
    authorized_signer = account_at(accounts, 4, "authorizedSigner")
    channel = account_at(accounts, 5, "channel")

    if str(payee) != expected.recipient:
        raise PaymentError(f"open payee {payee} != expected recipient {expected.recipient}", code="invalid-payload")
    if str(mint) != expected_mint:
        raise PaymentError(f"open mint {mint} != expected mint {expected_mint}", code="invalid-payload")
    if str(authorized_signer) != expected.authorized_signer:
        raise PaymentError(
            f"open authorizedSigner {authorized_signer} != expected {expected.authorized_signer}",
            code="invalid-payload",
        )
    if str(rent_payer) != expected.operator:
        raise PaymentError(
            f"open rentPayer {rent_payer} != expected operator {expected.operator}",
            code="invalid-payload",
        )

    # Instruction data: [discriminator u8][salt u64][deposit u64][grace u32][recipients].
    data = bytes(open_ix.data)
    if len(data) < 1 + 8 + 8 + 4:
        raise PaymentError(f"open instruction data too short ({len(data)} bytes)", code="invalid-payload")
    salt = struct.unpack_from("<Q", data, 1)[0]
    deposit = struct.unpack_from("<Q", data, 9)[0]
    grace_period = struct.unpack_from("<I", data, 17)[0]

    if deposit == 0:
        raise PaymentError("open deposit must be greater than zero", code="invalid-payload")
    if deposit > expected.max_cap:
        raise PaymentError(f"open deposit {deposit} exceeds max cap {expected.max_cap}", code="invalid-payload")

    # Re-derive the channel PDA from the instruction's own seeds.
    derived_channel, _ = find_channel_pda(payer, payee, mint, authorized_signer, salt, program_id)
    if derived_channel != channel:
        raise PaymentError(f"open channel PDA {channel} != derived {derived_channel}", code="invalid-payload")
    if payload.channel_id is not None and payload.channel_id != str(channel):
        raise PaymentError(
            f"openPayload.channelId {payload.channel_id} != transaction channel {channel}",
            code="invalid-payload",
        )

    # Optional liveness check: only when the caller provides an RPC client and
    # the client already populated the transaction signature.
    if rpc_client is not None and bound_signature:
        await confirm_transaction_signature(rpc_client, payload.signature, "open")

    return VerifyOpenTxResult(
        channel_id=str(channel),
        deposit=deposit,
        grace_period=grace_period,
        salt=salt,
        payer=str(payer),
    )


def new_open_tx_verifier(config: OpenVerifierConfig, rpc_client: RpcClient | None) -> OpenTxVerifier:
    """Return the on-chain open verifier to install on the session config.

    When the open payload carries a transaction, it is structurally validated
    against the challenge via :func:`verify_open_tx` (with an on-chain liveness
    check when ``rpc_client`` is non-None). When the payload carries only a
    confirmation signature, ``rpc_client`` is required and the signature is
    confirmed on-chain via ``getSignatureStatuses``.
    """

    async def verifier(payload: OpenPayload) -> None:
        if payload.transaction:
            expected = VerifyOpenTxExpected(
                authorized_signer=payload.authorized_signer,
                currency=config.currency,
                max_cap=config.max_cap,
                network=config.network,
                operator=config.operator,
                program_id=config.program_id,
                recipient=config.recipient,
            )
            await verify_open_tx(expected, payload, rpc_client)
            return
        if rpc_client is None:
            raise PaymentError(
                "open verification requires a transaction or an RPC client",
                code="invalid-payload",
            )
        await confirm_transaction_signature(rpc_client, payload.signature, "open")

    return verifier


def new_top_up_tx_verifier(rpc_client: RpcClient | None) -> TopUpTxVerifier | None:
    """Return the on-chain top-up verifier to install on the session config: it
    confirms the top-up transaction signature on-chain via
    ``getSignatureStatuses``.

    A ``None`` ``rpc_client`` returns ``None`` so the seam stays unset, and the
    new deposit is trusted as provided; suitable only for unit tests or
    deployments that verify transactions out of band.
    """
    if rpc_client is None:
        return None

    async def verifier(payload: TopUpPayload) -> None:
        await confirm_transaction_signature(rpc_client, payload.signature, "top-up")

    return verifier


async def confirm_transaction_signature(
    rpc_client: RpcClient,
    signature: str,
    label: str,
    *,
    timeout_seconds: float = 30.0,
    poll_interval_seconds: float = 1.0,
) -> None:
    """Poll ``getSignatureStatuses`` until ``signature`` reaches at least
    ``confirmed`` commitment, or raise.

    ``label`` names the transaction in error messages ("open", "top-up",
    "settle"). A freshly broadcast signature commonly returns ``None`` from
    ``getSignatureStatuses`` for hundreds of milliseconds to seconds, so the
    first poll returns ``None`` and this helper retries until the transaction
    lands, fails, or ``timeout_seconds`` elapses. This mirrors the TS
    ``waitForSignatureConfirmation`` helper used by ``submitOpenTx`` and the
    settle broadcast path; the single-shot predecessor raised spuriously on
    just-broadcast transactions.

    Raises ``transaction-failed`` when the signature lands with ``err`` set,
    ``transaction-not-found`` when the poll times out before any status is
    seen, and ``transaction-not-confirmed`` when a status is seen but the
    poll times out before ``confirmed``/``finalized`` is reported.
    """
    try:
        Signature.from_string(signature)
    except Exception as exc:
        raise PaymentError(f"invalid {label} tx signature {signature!r}: {exc}", code="invalid-payload") from exc

    deadline = time.monotonic() + timeout_seconds
    saw_status = False
    while True:
        try:
            statuses = await rpc_client.get_signature_statuses([signature])
        except Exception as exc:
            raise PaymentError(f"RPC error verifying {label} tx: {exc}", code="transaction-not-found") from exc

        status = statuses[0] if statuses else None
        if status is not None:
            saw_status = True
            if status.get("err") is not None:
                raise PaymentError(
                    f"{label} tx {signature!r} failed on-chain: {status['err']}", code="transaction-failed"
                )
            level = status.get("confirmationStatus")
            # RPC endpoints that omit ``confirmationStatus`` only report a
            # status once the transaction has landed; treat that as
            # confirmed, mirroring the TS helper.
            if level is None or level in ("confirmed", "finalized"):
                return

        now = time.monotonic()
        if now >= deadline:
            if saw_status:
                raise PaymentError(
                    f"{label} tx {signature!r} not confirmed within {timeout_seconds}s",
                    code="transaction-not-confirmed",
                )
            raise PaymentError(
                f"{label} tx {signature!r} not found; not yet confirmed or does not exist",
                code="transaction-not-found",
            )
        await asyncio.sleep(poll_interval_seconds)


async def settle_and_finalize_channel(
    state: ChannelState,
    *,
    merchant: Keypair,
    rpc: RpcClient,
    config: SessionConfig,
) -> str:
    """Build, sign, broadcast, and confirm the close settlement transaction;
    return the confirmed on-chain signature.

    Mirrors the Rust/Go close path: a settle_and_finalize instruction (preceded
    by the Ed25519 precompile when a voucher was recorded) plus a distribute
    instruction in one transaction whose fee payer is the merchant. The caller
    persists ``settled_signature`` on success.
    """
    channel = Pubkey.from_string(state.channel_id)
    program_id = Pubkey.from_string(config.program_id) if config.program_id else PROGRAM_ID
    merchant_pubkey = merchant.pubkey()

    voucher_signature: bytes | None = None
    authorized_signer = merchant_pubkey
    expires_at = 0
    if state.highest_voucher_signature is not None:
        voucher_signature = bytes(Signature.from_string(state.highest_voucher_signature))
        if not state.authorized_signer:
            raise PaymentError(
                f"channel {state.channel_id} has a voucher but no authorized signer", code="invalid-config"
            )
        authorized_signer = Pubkey.from_string(state.authorized_signer)
        if state.highest_voucher_expires_at is None:
            raise PaymentError(
                f"channel {state.channel_id} has a voucher signature but no expiry", code="invalid-config"
            )
        expires_at = state.highest_voucher_expires_at

    settle = build_settle_and_finalize_instructions(
        merchant=merchant_pubkey,
        channel=channel,
        authorized_signer=authorized_signer,
        signature=voucher_signature,
        cumulative=state.cumulative,
        expires_at=expires_at,
        program_id=program_id,
    )

    mint_address = resolve_mint(config.currency, config.network)
    if not mint_address:
        raise PaymentError(
            f"session settlement requires an SPL token, got currency '{config.currency}'", code="invalid-config"
        )
    payer_address = state.operator or config.recipient
    if not payer_address:
        raise PaymentError(
            f"channel {state.channel_id} payer is unknown; cannot derive the refund account", code="invalid-config"
        )
    distribute = build_distribute_instruction(
        channel=channel,
        payer=Pubkey.from_string(payer_address),
        payee=Pubkey.from_string(config.recipient),
        mint=Pubkey.from_string(mint_address),
        recipients=[Distribution(recipient=Pubkey.from_string(s.recipient), bps=s.bps) for s in config.splits],
        token_program=Pubkey.from_string(default_token_program_for_currency(config.currency, config.network)),
        program_id=program_id,
        # rentPayer reclaims the channel/escrow rent at finalize; it is the
        # operator recorded as rentPayer at open.
        rent_payer=Pubkey.from_string(config.operator) if config.operator else None,
    )

    blockhash = Hash.from_string((await rpc.get_latest_blockhash()).value.blockhash)
    tx = Transaction.new_signed_with_payer([*settle, distribute], merchant_pubkey, [merchant], blockhash)
    sent = await rpc.send_raw_transaction(bytes(tx))
    signature = str(sent.value)
    # Confirm before returning, mirroring cosign_and_broadcast_open: a dropped
    # settle tx (blockhash expiry, congestion, duplicate-settle race) must raise
    # here so the caller does NOT mark the channel finalized with an unconfirmed
    # signature, which would defeat the re-drivable-close guard.
    await confirm_transaction_signature(rpc, signature, "settle")
    return signature


async def cosign_and_broadcast_open(payload: OpenPayload, *, fee_payer: Any, rpc: RpcClient) -> str:
    """Complete the fee-payer signature on a client-built open transaction and
    broadcast it (the ``openTxSubmitter=server`` flow).

    The client builds the open with the operator as fee payer and partial-signs
    only its own (payer) slot; the server splices in the operator/fee-payer
    signature, broadcasts, and confirms. Returns the confirmed open signature.
    Mirrors Go SubmitOpenTx (and reuses the charge fee-payer co-sign).
    """
    from pay_kit.protocols.mpp.server._verify import _co_sign_with_fee_payer

    if not payload.transaction:
        raise PaymentError(
            "openTxSubmitter=server requires the client-built open transaction in the payload",
            code="invalid-payload",
        )
    cosigned = _co_sign_with_fee_payer(payload.transaction, fee_payer)
    sent = await rpc.send_raw_transaction(base64.b64decode(cosigned))
    signature = str(sent.value)
    await confirm_transaction_signature(rpc, signature, "open")
    return signature
