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

import base64
import struct
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Protocol

from solders.pubkey import Pubkey  # type: ignore[import-untyped]
from solders.signature import Signature  # type: ignore[import-untyped]

from pay_kit._paycore.errors import PaymentError
from pay_kit._paycore.solana import resolve_mint
from pay_kit.protocols.mpp._paymentchannels import PROGRAM_ID, find_channel_pda
from pay_kit.protocols.mpp.intents.session import OpenPayload, TopUpPayload

__all__ = [
    "VerifyOpenTxExpected",
    "VerifyOpenTxResult",
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
    """Minimal RPC seam used for the optional on-chain liveness check.

    ``get_signature_statuses`` returns the per-signature status list (each entry
    is a status dict with an ``err`` field, or ``None`` when unknown)."""

    async def get_signature_statuses(self, signatures: list[str]) -> list[dict | None]: ...


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
    program_id: Pubkey | None = None


@dataclass
class VerifyOpenTxResult:
    """The channel facts extracted from a verified open transaction."""

    channel_id: str
    deposit: int
    grace_period: int
    salt: int


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
    currency/network, the authorizedSigner must match the payload, the deposit
    must be positive and within the cap, and the channel account must equal the
    PDA re-derived from the instruction's own seeds.

    When the payload carries a non-placeholder signature, it must equal the
    transaction's own fee-payer signature. If ``rpc_client`` is non-None, that
    bound signature is additionally confirmed on-chain; ``None`` skips the
    liveness check (structural validation only).
    """
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

    # Open instruction account layout:
    # 0 payer, 1 payee, 2 mint, 3 authorizedSigner, 4 channel,
    # 5 payerTokenAccount, 6 channelTokenAccount, 7 tokenProgram, ...
    accounts = [int(i) for i in open_ix.accounts]
    if len(accounts) < 7:
        raise PaymentError(
            f"open instruction has too few accounts ({len(accounts)})",
            code="invalid-payload",
        )
    payer = account_at(accounts, 0, "payer")
    payee = account_at(accounts, 1, "payee")
    mint = account_at(accounts, 2, "mint")
    authorized_signer = account_at(accounts, 3, "authorizedSigner")
    channel = account_at(accounts, 4, "channel")

    if str(payee) != expected.recipient:
        raise PaymentError(f"open payee {payee} != expected recipient {expected.recipient}", code="invalid-payload")
    if str(mint) != expected_mint:
        raise PaymentError(f"open mint {mint} != expected mint {expected_mint}", code="invalid-payload")
    if str(authorized_signer) != expected.authorized_signer:
        raise PaymentError(
            f"open authorizedSigner {authorized_signer} != expected {expected.authorized_signer}",
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


async def confirm_transaction_signature(rpc_client: RpcClient, signature: str, label: str) -> None:
    """Check once via ``getSignatureStatuses`` that ``signature`` names a known,
    successful transaction. ``label`` names the transaction in error messages
    ("open", "top-up").
    """
    try:
        Signature.from_string(signature)
    except Exception as exc:
        raise PaymentError(f"invalid {label} tx signature {signature!r}: {exc}", code="invalid-payload") from exc

    try:
        statuses = await rpc_client.get_signature_statuses([signature])
    except Exception as exc:
        raise PaymentError(f"RPC error verifying {label} tx: {exc}", code="transaction-not-found") from exc

    status = statuses[0] if statuses else None
    if status is None:
        raise PaymentError(
            f"{label} tx {signature!r} not found; not yet confirmed or does not exist",
            code="transaction-not-found",
        )
    if status.get("err") is not None:
        raise PaymentError(f"{label} tx {signature!r} failed on-chain: {status['err']}", code="transaction-failed")
