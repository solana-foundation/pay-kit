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
import hashlib
import struct
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Any, Protocol, cast

from solders.hash import Hash  # type: ignore[import-untyped]
from solders.keypair import Keypair  # type: ignore[import-untyped]
from solders.pubkey import Pubkey  # type: ignore[import-untyped]
from solders.signature import Signature  # type: ignore[import-untyped]
from solders.transaction import Transaction  # type: ignore[import-untyped]
from spl.token.instructions import create_idempotent_associated_token_account  # type: ignore[import-untyped]

from solana_pay_kit._paycore.errors import PaymentError
from solana_pay_kit._paycore.solana import default_token_program_for_currency, resolve_mint
from solana_pay_kit.protocols.mpp._paymentchannels import (
    PROGRAM_ID,
    Distribution,
    OpenChannelParams,
    build_distribute_instruction,
    build_open_instruction,
    build_settle_and_seal_instructions,
    find_channel_pda,
    treasury_owner,
)
from solana_pay_kit.protocols.mpp.intents.session import OpenPayload, TopUpPayload
from solana_pay_kit.protocols.mpp.server._tx_decode import _transaction_dict
from solana_pay_kit.protocols.programs.paymentchannels.types.openArgs import OpenArgs
from solana_pay_kit.protocols.programs.paymentchannels.types.topUpArgs import TopUpArgs

if TYPE_CHECKING:
    from solana_pay_kit.protocols.mpp.server.session import SessionConfig
    from solana_pay_kit.protocols.mpp.server.session_store import ChannelState

__all__ = [
    "BoundChannel",
    "VerifyOpenTxExpected",
    "VerifyOpenTxResult",
    "cosign_and_broadcast_open",
    "settle_and_seal_channel",
    "verify_open_tx",
    "new_open_tx_verifier",
    "new_open_state_tx_verifier",
    "new_top_up_state_tx_verifier",
    "new_top_up_tx_verifier",
    "confirm_transaction_signature",
    "fetch_and_bind_channel_account",
    "is_placeholder_signature",
]

# Payment-channel open instruction discriminator (single-byte Anchor-numeric
# form, not the 8-byte sha256 convention).
_OPEN_INSTRUCTION_DISCRIMINATOR = 1
_CHANNEL_STATUS_OPEN = 0
_TOP_UP_INSTRUCTION_DISCRIMINATOR = 3


class RpcClient(Protocol):
    """Minimal RPC seam used for the optional on-chain liveness check and the
    settle-at-close broadcast.

    ``get_signature_statuses`` returns the per-signature status list (each entry
    is a status dict with an ``err`` field, or ``None`` when unknown);
    ``get_latest_blockhash`` / ``send_raw_transaction`` back the settle path."""

    async def get_signature_statuses(self, signatures: list[str]) -> list[dict | None]: ...

    async def get_transaction(
        self,
        signature: str,
        *,
        encoding: str = ...,
        commitment: str = ...,
        max_supported_transaction_version: int = ...,
    ) -> Any: ...

    async def get_latest_blockhash(self, commitment: str = ...) -> Any: ...

    async def send_raw_transaction(self, raw_tx: bytes) -> Any: ...


class AccountInfoRpc(Protocol):
    async def get_account_info(
        self, address: str, commitment: str = ..., min_context_slot: int | None = ...
    ) -> tuple[bytes, str] | None: ...


#: A verifier seam installed on the session config: validates a payload (open
#: or top-up) and raises on rejection.
OpenTxVerifier = Callable[[OpenPayload], Awaitable["VerifyOpenTxResult | None"]]
OpenStateTxVerifier = Callable[[OpenPayload], Awaitable["VerifyOpenTxResult"]]
TopUpTxVerifier = Callable[[TopUpPayload], Awaitable[None]]
TopUpStateTxVerifier = Callable[[TopUpPayload, "ChannelState"], Awaitable[None]]


class OpenVerifierConfig(Protocol):
    """The subset of the session config :func:`new_open_tx_verifier` reads:
    the challenge currency/network/recipient, the deposit cap, and the optional
    payment-channels program id override."""

    currency: str
    network: str
    recipient: str
    max_cap: int
    operator: str
    settlement_window: int
    splits: list[Any]

    @property
    def program_id(self) -> Pubkey | str | None: ...


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
    # The challenge's ordered payout split distribution. Open instruction data
    # must carry these exact entries, not merely a matching count or hash.
    splits: list[Any] = field(default_factory=list)
    # The channel grace period committed by the challenge. Session defaults to
    # the payment-channels program default when no settlement window is set.
    grace_period: int = 900
    # The challenge-issued recentSlot, when the caller has it. The open
    # instruction's own openSlot must equal it: without this bind, a payload
    # that omits recentSlot would let a transaction built against a different
    # slot through (and the decoded slot would then overwrite the payload).
    # None skips the check (offline/trust-mode challenges carry no slot).
    recent_slot: int | None = None


@dataclass
class VerifyOpenTxResult:
    """The channel facts extracted from a verified open transaction."""

    channel_id: str
    deposit: int
    grace_period: int
    salt: int
    # open_slot is the slot stamped into the open instruction (a channel PDA
    # seed). The caller propagates it onto the payload so the store persists
    # it (needed to re-derive the PDA and later reclaim the channel rent).
    open_slot: int
    # payer is the channel funder (open instruction slot 0). The caller
    # propagates it onto the payload so settle-at-close refunds the unspent
    # balance to the opener's ATA, not the recipient's.
    payer: str


@dataclass
class BoundChannel:
    """Authoritative facts decoded from an on-chain Channel account."""

    deposit: int
    payer: str
    authorized_signer: str
    payee: str
    mint: str
    salt: int
    open_slot: int


def is_placeholder_signature(signature: str) -> bool:
    """Report whether ``signature`` is the pending placeholder produced by the
    server-completed open flow (an empty string or a run of 40+ ``'1'``
    characters, the base58 encoding of the all-ones marker)."""
    if signature == "":
        return True
    if len(signature) < 40:
        return False
    return signature.count("1") == len(signature)


def _reject_address_lookup_tables(message: Any) -> None:
    """Reject a v0 message that references address lookup tables (ALTs).

    SECURITY: ``verify_open_tx`` validates the open instruction's accounts
    against the message's STATIC ``account_keys`` (payer, rentPayer, payee, mint,
    authorizedSigner, channel) and re-derives the channel PDA from them. A
    versioned transaction may instead resolve some account indices through an
    address lookup table, whose contents are NOT in the transaction and cannot be
    seen here. An attacker could hide the real rentPayer / payee / mint behind an
    ALT so the slot-based guards inspect the wrong (or out-of-range) keys, while
    the operator co-signs as fee payer and broadcasts. Reject any ALT use up
    front, mirroring the charge pre-broadcast verifier
    (``server/_tx_decode.py`` / ``server/_verify.py``).
    """
    if getattr(message, "address_table_lookups", None):
        raise PaymentError(
            "v0 transactions with address lookup tables are not supported",
            code="invalid-payload",
        )


def _decode_transaction(transaction_b64: str) -> tuple[list[str], list, list[str]]:
    """Decode a base64 (legacy or v0) transaction into ``(account_keys,
    instructions, signatures)`` as base58 strings / compiled-instruction
    objects.

    A v0 transaction that references address lookup tables is rejected: the
    open verifier only sees the static account keys, so an ALT could hide the
    accounts it validates. See :func:`_reject_address_lookup_tables`.
    """
    from solders.transaction import Transaction, VersionedTransaction  # type: ignore[import-untyped]

    from solana_pay_kit._paycore.transaction import is_v0_wire_bytes

    raw = base64.b64decode(transaction_b64, validate=True)
    message = None
    signatures: list = []
    if is_v0_wire_bytes(raw):
        vtx = VersionedTransaction.from_bytes(raw)
        message = vtx.message
        _reject_address_lookup_tables(message)
        signatures = list(vtx.signatures)
    else:
        try:
            tx = Transaction.from_bytes(raw)
            message = tx.message
            signatures = list(tx.signatures)
        except Exception:
            vtx = VersionedTransaction.from_bytes(raw)
            message = vtx.message
            _reject_address_lookup_tables(message)
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
    except PaymentError:
        # Already a structured rejection (e.g. the address-lookup-table guard);
        # surface it verbatim rather than wrapping it as a generic decode error.
        raise
    except Exception as exc:
        raise PaymentError(f"decode open transaction: {exc}", code="invalid-payload") from exc

    if len(instructions) != 1:
        raise PaymentError(
            f"open transaction must contain exactly one instruction, found {len(instructions)}",
            code="invalid-payload",
        )

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

    open_ix = instructions[0]
    program_index = int(open_ix.program_id_index)
    data = bytes(open_ix.data)
    if (
        program_index >= len(account_keys)
        or account_keys[program_index] != str(program_id)
        or len(data) < 1
        or data[0] != _OPEN_INSTRUCTION_DISCRIMINATOR
    ):
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

    # Instruction data:
    # [discriminator u8][salt u64][deposit u64][grace u32][openSlot u64][recipients].
    data = bytes(open_ix.data)
    if len(data) < 1 + 8 + 8 + 4 + 8:
        raise PaymentError(f"open instruction data too short ({len(data)} bytes)", code="invalid-payload")
    salt = struct.unpack_from("<Q", data, 1)[0]
    deposit = struct.unpack_from("<Q", data, 9)[0]
    grace_period = struct.unpack_from("<I", data, 17)[0]
    open_slot = struct.unpack_from("<Q", data, 21)[0]

    if deposit == 0:
        raise PaymentError("open deposit must be greater than zero", code="invalid-payload")
    if deposit > expected.max_cap:
        raise PaymentError(f"open deposit {deposit} exceeds max cap {expected.max_cap}", code="invalid-payload")

    # Re-derive the channel PDA from the instruction's own seeds.
    derived_channel, _ = find_channel_pda(payer, payee, mint, authorized_signer, salt, open_slot, program_id)
    if derived_channel != channel:
        raise PaymentError(f"open channel PDA {channel} != derived {derived_channel}", code="invalid-payload")
    if payload.channel_id is not None and payload.channel_id != str(channel):
        raise PaymentError(
            f"openPayload.channelId {payload.channel_id} != transaction channel {channel}",
            code="invalid-payload",
        )
    if payload.recent_slot is not None and payload.recent_slot != open_slot:
        raise PaymentError(
            f"openPayload.recentSlot {payload.recent_slot} != transaction openSlot {open_slot}",
            code="invalid-payload",
        )
    if expected.recent_slot is not None and expected.recent_slot != open_slot:
        raise PaymentError(
            f"transaction openSlot {open_slot} != challenge recentSlot {expected.recent_slot}",
            code="invalid-payload",
        )

    try:
        decoded_args = OpenArgs.from_decoded(OpenArgs.layout.parse(data[1:]))
    except Exception as exc:
        raise PaymentError(f"decode open instruction args: {exc}", code="invalid-payload") from exc
    if int(decoded_args.gracePeriod) != expected.grace_period:
        raise PaymentError(
            f"open gracePeriod {decoded_args.gracePeriod} != expected {expected.grace_period}",
            code="invalid-payload",
        )
    if len(decoded_args.recipients) != len(expected.splits):
        raise PaymentError(
            f"open recipients length {len(decoded_args.recipients)} != expected splits length {len(expected.splits)}",
            code="invalid-payload",
        )
    for index, recipient in enumerate(decoded_args.recipients):
        expected_split = expected.splits[index]
        if str(recipient.recipient) != str(expected_split.recipient) or int(recipient.bps) != int(expected_split.bps):
            raise PaymentError(f"open recipient[{index}] does not match expected split", code="invalid-payload")

    token_program = Pubkey.from_string(default_token_program_for_currency(expected.currency, expected.network))
    canonical = build_open_instruction(
        OpenChannelParams(
            payer=payer,
            rent_payer=rent_payer,
            payee=payee,
            mint=mint,
            authorized_signer=authorized_signer,
            salt=salt,
            deposit=deposit,
            grace_period=grace_period,
            open_slot=open_slot,
            recipients=[
                Distribution(recipient=entry.recipient, bps=int(entry.bps)) for entry in decoded_args.recipients
            ],
            token_program=token_program,
            program_id=program_id,
        )
    )
    if bytes(open_ix.data) != bytes(canonical.data):
        raise PaymentError("open instruction data is not canonical", code="invalid-payload")
    canonical_accounts = list(canonical.accounts)
    if len(accounts) != len(canonical_accounts):
        raise PaymentError(
            f"open instruction account count {len(accounts)} != canonical count {len(canonical_accounts)}",
            code="invalid-payload",
        )
    for index, meta in enumerate(canonical_accounts):
        account_index = accounts[index]
        if account_index < 0 or account_index >= len(account_keys):
            raise PaymentError(
                f"open instruction account[{index}] index {account_index} is out of range",
                code="invalid-payload",
            )
        if account_keys[account_index] != str(meta.pubkey):
            raise PaymentError(
                f"open instruction account[{index}] does not match canonical account {meta.pubkey}",
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
        open_slot=open_slot,
        payer=str(payer),
    )


def _confirmed_transaction_wire(transaction: dict[str, Any], label: str) -> str:
    """Return the exact base64 wire transaction from a confirmed RPC result."""
    meta = transaction.get("meta")
    if not isinstance(meta, dict):
        raise PaymentError(f"confirmed {label} transaction has malformed metadata", code="invalid-payload")
    if meta.get("err") is not None:
        raise PaymentError(f"{label} transaction failed on-chain", code="transaction-failed")
    value = transaction.get("transaction")
    if not isinstance(value, list) or len(value) < 2 or not isinstance(value[0], str) or value[1] != "base64":
        raise PaymentError(f"confirmed {label} transaction is not base64 wire data", code="invalid-payload")
    return value[0]


async def _fetch_and_verify_signature_only_open(
    expected: VerifyOpenTxExpected,
    payload: OpenPayload,
    rpc_client: RpcClient,
) -> tuple[int, VerifyOpenTxResult]:
    """Confirm and bind a signature-only open to its canonical transaction."""
    confirmed_slot = await confirm_transaction_signature(rpc_client, payload.signature, "open")
    get_transaction: Any = getattr(rpc_client, "get_transaction", None)
    if not callable(get_transaction):
        raise PaymentError(
            "signature-only open verification requires an RPC client with get_transaction",
            code="invalid-config",
        )
    try:
        pending: Any = get_transaction(
            payload.signature,
            commitment="confirmed",
            encoding="base64",
            max_supported_transaction_version=0,
        )
        response: Any = await pending
    except Exception as exc:
        raise PaymentError(f"fetch open transaction: {exc}", code="transaction-not-found") from exc
    transaction = _transaction_dict(response)
    if transaction is None:
        raise PaymentError("open transaction not found or not yet confirmed", code="transaction-not-found")

    wire_payload = replace(payload, transaction=_confirmed_transaction_wire(transaction, "open"))
    structural = await verify_open_tx(expected, wire_payload, None)
    return confirmed_slot, structural


def _assert_signature_only_deposit(
    payload: OpenPayload,
    structural: VerifyOpenTxResult,
    bound: BoundChannel,
) -> None:
    """Keep the asserted amount bound to both the open wire and Channel state."""
    try:
        asserted_deposit = payload.deposit_amount()
    except ValueError as exc:
        raise PaymentError(str(exc), code="invalid-payload") from exc
    if structural.deposit != bound.deposit:
        raise PaymentError(
            f"on-chain channel deposit {bound.deposit} != open transaction deposit {structural.deposit}",
            code="invalid-payload",
        )
    if bound.deposit != asserted_deposit:
        raise PaymentError(
            f"on-chain channel deposit {bound.deposit} != asserted deposit {asserted_deposit}",
            code="invalid-payload",
        )


def new_open_tx_verifier(config: OpenVerifierConfig, rpc_client: RpcClient | None) -> OpenTxVerifier:
    """Return the on-chain open verifier to install on the session config.

    When the open payload carries a transaction, it is structurally validated
    against the challenge via :func:`verify_open_tx` (with an on-chain liveness
    check when ``rpc_client`` is non-None). When the payload carries only a
    confirmation signature, ``rpc_client`` is required and the signature is
    confirmed on-chain via ``getSignatureStatuses``.
    """

    async def verifier(payload: OpenPayload) -> VerifyOpenTxResult | None:
        if payload.transaction:
            expected = VerifyOpenTxExpected(
                authorized_signer=payload.authorized_signer,
                currency=config.currency,
                max_cap=config.max_cap,
                network=config.network,
                operator=config.operator,
                program_id=(
                    Pubkey.from_string(config.program_id) if isinstance(config.program_id, str) else config.program_id
                ),
                recipient=config.recipient,
                splits=config.splits,
                grace_period=_expected_session_grace_period(config.settlement_window),
            )
            return await verify_open_tx(expected, payload, rpc_client)
        if rpc_client is None:
            raise PaymentError(
                "open verification requires a transaction or an RPC client",
                code="invalid-payload",
            )
        expected = VerifyOpenTxExpected(
            authorized_signer=payload.authorized_signer,
            currency=config.currency,
            max_cap=config.max_cap,
            network=config.network,
            operator=config.operator,
            program_id=(
                Pubkey.from_string(config.program_id) if isinstance(config.program_id, str) else config.program_id
            ),
            recipient=config.recipient,
            splits=config.splits,
            grace_period=_expected_session_grace_period(config.settlement_window),
            recent_slot=payload.recent_slot if payload.recent_slot not in (None, 0) else None,
        )
        confirmed_slot, structural = await _fetch_and_verify_signature_only_open(expected, payload, rpc_client)
        expected_mint = resolve_mint(config.currency, config.network)
        if not expected_mint:
            raise PaymentError(
                f"payment-channel open requires an SPL token, got currency {config.currency!r}",
                code="invalid-config",
            )
        session_id = structural.channel_id
        bound = await fetch_and_bind_channel_account(
            rpc_client,
            session_id,
            program_id=config.program_id,
            max_cap=config.max_cap,
            expected_authorized_signer=payload.authorized_signer,
            expected_payee=config.recipient,
            expected_mint=expected_mint,
            expected_operator=config.operator,
            min_context_slot=confirmed_slot,
            expected_grace_period=_expected_session_grace_period(config.settlement_window),
            expected_splits=config.splits,
            expected_open_slot=payload.recent_slot,
        )
        _assert_signature_only_deposit(payload, structural, bound)
        return VerifyOpenTxResult(
            channel_id=session_id,
            deposit=bound.deposit,
            grace_period=_expected_session_grace_period(config.settlement_window),
            salt=bound.salt,
            open_slot=bound.open_slot,
            payer=bound.payer,
        )

    return verifier


def new_open_state_tx_verifier(config: OpenVerifierConfig, rpc_client: RpcClient | None) -> OpenStateTxVerifier:
    """Return the authoritative verifier for payment-channel opens.

    This is deliberately separate from :func:`new_open_tx_verifier`: a
    placeholder signature may pass structural validation while a server is
    completing a partial transaction, but it can never authorize persisted
    channel state. Every successful path here confirms a real signature,
    fetches the current open Channel account at the confirmation slot, and
    returns only account-derived economics and PDA seeds.
    """

    async def verifier(payload: OpenPayload) -> VerifyOpenTxResult:
        if rpc_client is None:
            raise PaymentError(
                "authoritative open verification requires an RPC client",
                code="invalid-config",
            )
        if is_placeholder_signature(payload.signature):
            raise PaymentError(
                "authoritative open verification requires a real transaction signature",
                code="invalid-payload",
            )

        expected_open_slot = payload.recent_slot if payload.recent_slot not in (None, 0) else None
        expected = VerifyOpenTxExpected(
            authorized_signer=payload.authorized_signer,
            currency=config.currency,
            max_cap=config.max_cap,
            network=config.network,
            operator=config.operator,
            program_id=(
                Pubkey.from_string(config.program_id) if isinstance(config.program_id, str) else config.program_id
            ),
            recipient=config.recipient,
            splits=config.splits,
            grace_period=_expected_session_grace_period(config.settlement_window),
            recent_slot=expected_open_slot,
        )

        structural: VerifyOpenTxResult | None = None
        confirmed_slot: int | None = None
        if payload.transaction:
            # Structural validation binds the real payload signature to the
            # transaction wire, but its decoded facts are never returned.
            structural = await verify_open_tx(expected, payload, None)
            confirmed_slot = await confirm_transaction_signature(rpc_client, payload.signature, "open")
        else:
            if payload.mode == "push" and not payload.channel_id:
                raise PaymentError(
                    "signature-only push open requires channelId",
                    code="invalid-payload",
                )
            try:
                payload.session_id()
            except ValueError as exc:
                raise PaymentError(str(exc), code="invalid-payload") from exc
            if payload.mode == "push" and expected_open_slot is None:
                raise PaymentError(
                    "signature-only push open requires recentSlot",
                    code="invalid-payload",
                )
            confirmed_slot, structural = await _fetch_and_verify_signature_only_open(expected, payload, rpc_client)
        assert structural is not None and confirmed_slot is not None
        expected_mint = resolve_mint(config.currency, config.network)
        if not expected_mint:
            raise PaymentError(
                f"payment-channel open requires an SPL token, got currency {config.currency!r}",
                code="invalid-config",
            )
        bound = await fetch_and_bind_channel_account(
            rpc_client,
            structural.channel_id,
            program_id=config.program_id,
            max_cap=config.max_cap,
            expected_authorized_signer=payload.authorized_signer,
            expected_payee=config.recipient,
            expected_mint=expected_mint,
            expected_operator=config.operator,
            min_context_slot=confirmed_slot,
            expected_grace_period=_expected_session_grace_period(config.settlement_window),
            expected_splits=config.splits,
            expected_open_slot=expected_open_slot,
        )
        _assert_signature_only_deposit(payload, structural, bound)
        return VerifyOpenTxResult(
            channel_id=structural.channel_id,
            deposit=bound.deposit,
            grace_period=_expected_session_grace_period(config.settlement_window),
            salt=bound.salt,
            open_slot=bound.open_slot,
            payer=bound.payer,
        )

    return verifier


def _require_account_info_rpc(rpc_client: RpcClient) -> AccountInfoRpc:
    if not callable(getattr(rpc_client, "get_account_info", None)):
        raise PaymentError(
            "payment-channel account binding requires an RPC client with get_account_info",
            code="invalid-config",
        )
    return cast(AccountInfoRpc, rpc_client)


async def _fetch_and_validate_channel(
    rpc_client: RpcClient,
    channel_id: str,
    *,
    program_id: Pubkey | str | None,
    expected_payee: str,
    expected_mint: str,
    expected_operator: str,
    expected_grace_period: int,
    expected_distribution_hash: bytes,
    require_fresh: bool,
    min_context_slot: int,
) -> Any:
    from solana_pay_kit.protocols.programs.paymentchannels.accounts.channel import Channel

    if program_id is None:
        resolved_program = PROGRAM_ID
    elif isinstance(program_id, str):
        resolved_program = Pubkey.from_string(program_id)
    else:
        resolved_program = program_id
    account = await _require_account_info_rpc(rpc_client).get_account_info(
        channel_id, commitment="confirmed", min_context_slot=min_context_slot
    )
    if account is None:
        raise PaymentError(f"channel {channel_id} account not found on-chain", code="invalid-payload")
    data, owner = account
    if owner != str(resolved_program):
        raise PaymentError(
            f"channel {channel_id} is not owned by the payment-channels program",
            code="invalid-payload",
        )
    if len(data) != 256:
        raise PaymentError(f"channel {channel_id} account data has invalid length {len(data)}", code="invalid-payload")
    if data[0] != 1:
        raise PaymentError(f"channel {channel_id} has invalid discriminator {data[0]}", code="invalid-payload")
    try:
        channel = Channel.decode(data)
    except Exception as exc:
        raise PaymentError(f"channel {channel_id} account decode failed: {exc}", code="invalid-payload") from exc
    if int(channel.version) != 1:
        raise PaymentError(f"channel {channel_id} has unsupported version {channel.version}", code="invalid-payload")
    if int(channel.status) != _CHANNEL_STATUS_OPEN:
        raise PaymentError(
            f"channel {channel_id} is not open on-chain (status {channel.status})",
            code="invalid-payload",
        )
    if str(channel.mint) != expected_mint:
        raise PaymentError(
            f"on-chain channel mint {channel.mint} != expected mint {expected_mint}",
            code="invalid-payload",
        )
    if str(channel.payee) != expected_payee:
        raise PaymentError(
            f"on-chain channel payee {channel.payee} != expected recipient {expected_payee}",
            code="invalid-payload",
        )
    if not expected_operator or str(channel.rentPayer) != expected_operator:
        raise PaymentError(
            f"on-chain channel rentPayer {channel.rentPayer} != expected operator {expected_operator}",
            code="invalid-payload",
        )
    if require_fresh and (int(channel.settlement.settled) != 0 or int(channel.settlement.payoutWatermark) != 0):
        raise PaymentError(f"channel {channel_id} has nonzero settlement watermarks", code="invalid-payload")
    if int(channel.gracePeriod) != expected_grace_period:
        raise PaymentError(
            f"on-chain channel gracePeriod {channel.gracePeriod} != expected {expected_grace_period}",
            code="invalid-payload",
        )
    if bytes(channel.distributionHash) != expected_distribution_hash:
        raise PaymentError("on-chain channel distributionHash does not match session splits", code="invalid-payload")
    return channel


def _session_distribution_hash(splits: list[Any]) -> bytes:
    hasher = hashlib.sha256()
    hasher.update(struct.pack("<I", len(splits)))
    for split in splits:
        hasher.update(bytes(Pubkey.from_string(split.recipient)))
        hasher.update(struct.pack("<H", split.bps))
    return hasher.digest()


def _expected_session_grace_period(settlement_window: int | None) -> int:
    return settlement_window if settlement_window is not None and settlement_window > 0 else 900


async def fetch_and_bind_channel_account(
    rpc_client: RpcClient,
    channel_id: str,
    *,
    program_id: Pubkey | str | None,
    max_cap: int,
    expected_authorized_signer: str,
    expected_payee: str,
    expected_mint: str,
    expected_operator: str,
    min_context_slot: int,
    expected_grace_period: int = 900,
    expected_splits: list[Any] | None = None,
    require_fresh: bool = True,
    expected_open_slot: int | None = None,
) -> BoundChannel:
    channel = await _fetch_and_validate_channel(
        rpc_client,
        channel_id,
        program_id=program_id,
        expected_payee=expected_payee,
        expected_mint=expected_mint,
        expected_operator=expected_operator,
        expected_grace_period=expected_grace_period,
        expected_distribution_hash=_session_distribution_hash(expected_splits or []),
        require_fresh=require_fresh,
        min_context_slot=min_context_slot,
    )
    if expected_open_slot is not None and int(channel.openSlot) != expected_open_slot:
        raise PaymentError(
            f"on-chain channel openSlot {channel.openSlot} != challenge recentSlot {expected_open_slot}",
            code="invalid-payload",
        )
    if str(channel.authorizedSigner) != expected_authorized_signer:
        raise PaymentError(
            f"on-chain channel authorized_signer {channel.authorizedSigner} != expected {expected_authorized_signer}",
            code="invalid-payload",
        )
    resolved_program = (
        PROGRAM_ID
        if program_id is None
        else Pubkey.from_string(program_id)
        if isinstance(program_id, str)
        else program_id
    )
    derived_channel, _ = find_channel_pda(
        channel.payer,
        channel.payee,
        channel.mint,
        channel.authorizedSigner,
        int(channel.salt),
        int(channel.openSlot),
        resolved_program,
    )
    if str(derived_channel) != channel_id:
        raise PaymentError(
            f"channel account {channel_id} != PDA derived from authoritative state {derived_channel}",
            code="invalid-payload",
        )
    deposit = int(channel.deposit)
    if deposit == 0:
        raise PaymentError(f"on-chain channel {channel_id} deposit is zero", code="invalid-payload")
    if deposit > max_cap:
        raise PaymentError(f"on-chain channel deposit {deposit} exceeds max cap {max_cap}", code="invalid-payload")
    return BoundChannel(
        deposit=deposit,
        payer=str(channel.payer),
        authorized_signer=str(channel.authorizedSigner),
        payee=str(channel.payee),
        mint=str(channel.mint),
        salt=int(channel.salt),
        open_slot=int(channel.openSlot),
    )


class TopUpVerifierConfig(Protocol):
    currency: str
    network: str
    recipient: str
    operator: str
    settlement_window: int
    splits: list[Any]

    @property
    def program_id(self) -> Pubkey | str | None: ...


def new_top_up_tx_verifier(rpc_client: RpcClient | None) -> TopUpTxVerifier | None:
    """Return the legacy payload-only top-up confirmation callback.

    This factory remains compatible with integrations that install
    ``SessionConfig.verify_top_up_tx`` themselves. The session method uses
    :func:`new_top_up_state_tx_verifier` for account-state binding.
    """
    if rpc_client is None:
        return None

    async def verifier(payload: TopUpPayload) -> None:
        await confirm_transaction_signature(rpc_client, payload.signature, "top-up")

    return verifier


def new_top_up_state_tx_verifier(
    config: TopUpVerifierConfig, rpc_client: RpcClient | None
) -> TopUpStateTxVerifier | None:
    """Confirm and bind a top-up to the resulting on-chain Channel state."""
    if rpc_client is None:
        if config.network == "localnet":
            return None

        async def fail_closed(_payload: TopUpPayload, _current: ChannelState) -> None:
            raise PaymentError(
                "payment-channel top-up requires an rpc client to bind the on-chain channel off localnet",
                code="invalid-config",
            )

        return fail_closed

    async def verifier(payload: TopUpPayload, current: ChannelState) -> None:
        try:
            new_deposit = int(payload.new_deposit)
        except (TypeError, ValueError) as exc:
            raise PaymentError(f"invalid newDeposit: {payload.new_deposit}", code="invalid-payload") from exc
        expected_mint = resolve_mint(config.currency, config.network)
        if not expected_mint:
            raise PaymentError(
                f"payment-channel top-up requires an SPL token, got currency {config.currency!r}",
                code="invalid-config",
            )
        confirmed_slot = await confirm_transaction_signature(rpc_client, payload.signature, "top-up")
        get_transaction: Any = getattr(rpc_client, "get_transaction", None)
        if config.network != "localnet":
            if not callable(get_transaction):
                raise PaymentError(
                    "top-up verification requires an RPC client with get_transaction",
                    code="invalid-config",
                )
            pending: Any = get_transaction(
                payload.signature,
                commitment="confirmed",
                encoding="base64",
                max_supported_transaction_version=0,
            )
            response: Any = await pending
            transaction = _transaction_dict(response)
            if transaction is None:
                raise PaymentError("top-up transaction not found or not yet confirmed", code="transaction-not-found")
            _verify_confirmed_top_up(
                _confirmed_transaction_wire(transaction, "top-up"),
                payload,
                current,
                config.program_id,
            )
        channel = await _fetch_and_validate_channel(
            rpc_client,
            payload.channel_id,
            program_id=config.program_id,
            expected_payee=config.recipient,
            expected_mint=expected_mint,
            expected_operator=config.operator,
            expected_grace_period=_expected_session_grace_period(getattr(config, "settlement_window", None)),
            expected_distribution_hash=_session_distribution_hash(getattr(config, "splits", [])),
            require_fresh=False,
            min_context_slot=confirmed_slot,
        )
        if str(channel.authorizedSigner) != current.authorized_signer:
            raise PaymentError(
                "on-chain channel authorized signer does not match stored channel", code="invalid-payload"
            )
        if current.operator is None or str(channel.payer) != current.operator:
            raise PaymentError("on-chain channel payer does not match stored channel", code="invalid-payload")
        if int(channel.deposit) != new_deposit:
            raise PaymentError(
                f"on-chain channel deposit {channel.deposit} != asserted newDeposit {new_deposit}",
                code="invalid-payload",
            )

    return verifier


def _verify_confirmed_top_up(
    transaction_b64: str,
    payload: TopUpPayload,
    state: ChannelState,
    configured_program_id: Pubkey | str | None,
) -> None:
    program_id = str(PROGRAM_ID if configured_program_id is None else configured_program_id)
    try:
        account_keys, instructions, signatures = _decode_transaction(transaction_b64)
    except PaymentError:
        raise
    except Exception as exc:
        raise PaymentError(f"decode top-up transaction: {exc}", code="invalid-payload") from exc
    if not signatures or signatures[0] != payload.signature:
        raise PaymentError("top-up payload signature does not match transaction", code="invalid-payload")
    matches: list[Any] = []
    for instruction in instructions:
        program_index = int(instruction.program_id_index)
        if program_index >= len(account_keys) or account_keys[program_index] != program_id:
            continue
        decoded = bytes(instruction.data)
        if decoded and decoded[0] == _TOP_UP_INSTRUCTION_DISCRIMINATOR:
            matches.append(instruction)
    if len(matches) != 1:
        raise PaymentError(
            f"confirmed transaction must contain exactly one configured topUp instruction, found {len(matches)}",
            code="invalid-payload",
        )
    instruction = matches[0]
    accounts = [int(index) for index in instruction.accounts]
    if len(accounts) < 2 or accounts[1] >= len(account_keys) or account_keys[accounts[1]] != payload.channel_id:
        raise PaymentError("top-up instruction channel does not match the session", code="invalid-payload")
    raw_data = bytes(instruction.data)
    decoded_args = TopUpArgs.from_decoded(TopUpArgs.layout.parse(raw_data[1:]))
    if TopUpArgs.layout.build(decoded_args.to_encodable()) != raw_data[1:]:
        raise PaymentError("top-up instruction has trailing data", code="invalid-payload")
    new_deposit = int(payload.new_deposit)
    if new_deposit <= state.deposit or decoded_args.amount != new_deposit - state.deposit:
        raise PaymentError(
            f"top-up amount {decoded_args.amount} != newDeposit delta {new_deposit - state.deposit}",
            code="invalid-payload",
        )


async def confirm_transaction_signature(
    rpc_client: RpcClient,
    signature: str,
    label: str,
    *,
    timeout_seconds: float = 30.0,
    poll_interval_seconds: float = 1.0,
) -> int:
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
            if level in ("confirmed", "finalized"):
                slot = status.get("slot")
                if isinstance(slot, bool) or not isinstance(slot, int) or slot < 0:
                    raise PaymentError(
                        f"{label} tx {signature!r} confirmation response has an invalid slot",
                        code="transaction-not-confirmed",
                    )
                return slot

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


async def settle_and_seal_channel(
    state: ChannelState,
    *,
    merchant: Keypair,
    rpc: RpcClient,
    config: SessionConfig,
) -> str:
    """Build, sign, broadcast, and confirm the close settlement transaction;
    return the confirmed on-chain signature.

    Mirrors the Rust/Go close path: a settle_and_seal instruction (preceded
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

    settle = build_settle_and_seal_instructions(
        payee=merchant_pubkey,
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
    # The channel payer (opener) is the refund destination for the unsettled
    # remainder. It must be the payer recorded at open: falling back to
    # another account (e.g. the recipient) would derive the wrong refund ATA
    # and only fail after the settle transaction is built and broadcast.
    # Mirrors Go's strict payer handling.
    payer_address = state.operator
    if not payer_address:
        raise PaymentError(
            f"channel {state.channel_id} payer is unknown; cannot derive the refund account", code="invalid-config"
        )
    payee = Pubkey.from_string(config.recipient)
    mint = Pubkey.from_string(mint_address)
    token_program = Pubkey.from_string(default_token_program_for_currency(config.currency, config.network))
    recipients = [Distribution(recipient=Pubkey.from_string(split.recipient), bps=split.bps) for split in config.splits]
    treasury = treasury_owner()
    distribute = build_distribute_instruction(
        channel=channel,
        payer=Pubkey.from_string(payer_address),
        payee=payee,
        mint=mint,
        recipients=recipients,
        token_program=token_program,
        program_id=program_id,
        treasury=treasury,
        # rentPayer recovers the channel/escrow rent at distribute (or via
        # reclaim); it is the operator recorded as rentPayer at open.
        rent_payer=Pubkey.from_string(config.operator) if config.operator else None,
    )

    ata_owners = [payee, treasury, *(entry.recipient for entry in recipients)]
    seen_owners: set[str] = set()
    create_destination_atas = []
    for owner in ata_owners:
        if str(owner) in seen_owners:
            continue
        seen_owners.add(str(owner))
        create_destination_atas.append(
            create_idempotent_associated_token_account(merchant_pubkey, owner, mint, token_program)
        )

    blockhash = Hash.from_string((await rpc.get_latest_blockhash()).value.blockhash)
    tx = Transaction.new_signed_with_payer(
        [*settle, *create_destination_atas, distribute], merchant_pubkey, [merchant], blockhash
    )
    sent = await rpc.send_raw_transaction(bytes(tx))
    signature = str(sent.value)
    # Confirm before returning, mirroring cosign_and_broadcast_open: a dropped
    # settle tx (blockhash expiry, congestion, duplicate-settle race) must raise
    # here so the caller does NOT mark the channel sealed with an unconfirmed
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
    wire, expected_signature = _complete_open_transaction(payload, fee_payer)
    sent = await rpc.send_raw_transaction(wire)
    signature = str(sent.value)
    if signature != expected_signature:
        raise PaymentError(
            f"broadcast open signature {signature} != completed transaction signature {expected_signature}",
            code="invalid-payload",
        )
    # Downstream processing verifies the payload again before persisting it.
    # Keep the transaction and claimed signature bound to the same completed
    # wire bytes instead of leaving the original partially signed transaction.
    payload.transaction = base64.b64encode(wire).decode("ascii")
    await confirm_transaction_signature(rpc, signature, "open")
    return signature


def _complete_open_transaction(payload: OpenPayload, fee_payer: Any) -> tuple[bytes, str]:
    """Complete the fee-payer signature without broadcasting the transaction."""
    from solders.transaction import VersionedTransaction  # type: ignore[import-untyped]

    from solana_pay_kit.protocols.mpp.server._verify import _co_sign_with_fee_payer

    if not payload.transaction:
        raise PaymentError(
            "openTxSubmitter=server requires the client-built open transaction in the payload",
            code="invalid-payload",
        )
    wire = base64.b64decode(_co_sign_with_fee_payer(payload.transaction, fee_payer))
    try:
        signatures = Transaction.from_bytes(wire).signatures
    except Exception:
        signatures = VersionedTransaction.from_bytes(wire).signatures
    if not signatures:
        raise PaymentError("open transaction is missing the fee-payer signature", code="invalid-payload")
    return wire, str(signatures[0])
