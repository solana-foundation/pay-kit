"""On-chain verification and settlement for the session intent.

Provides the standalone open-transaction verifier and the verifier-seam
factories the session server installs to validate client-submitted on-chain
activity.

Funding verification fails closed. Open and top-up credentials carry signed
transactions whose instructions are decoded and matched exactly to the payload
and challenge. The factory verifiers submit, confirm, and then compare the
authoritative on-chain channel account before local state changes.
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

from solana_pay_kit._paycore.errors import PaymentError
from solana_pay_kit._paycore.solana import default_token_program_for_currency, resolve_mint
from solana_pay_kit.protocols.mpp._paymentchannels import (
    PROGRAM_ID,
    Distribution,
    OpenChannelParams,
    TopUpParams,
    build_distribute_instruction,
    build_open_instruction,
    build_settle_and_seal_instructions,
    build_top_up_instruction,
    find_channel_pda,
)
from solana_pay_kit.protocols.mpp.intents.session import OpenPayload, TopUpPayload

if TYPE_CHECKING:
    from solana_pay_kit.protocols.mpp.server.session import SessionConfig, SessionOpenContext
    from solana_pay_kit.protocols.mpp.server.session_store import ChannelState

__all__ = [
    "VerifyOpenTxExpected",
    "VerifyOpenTxResult",
    "cosign_and_broadcast_open",
    "settle_and_seal_channel",
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
#: or top-up) and raises on rejection. The open verifier also receives the
#: challenged :class:`~solana_pay_kit.protocols.mpp.server.session.SessionOpenContext`
#: so the transaction's recentBlockhash is bound to the challenge pre-broadcast.
OpenTxVerifier = Callable[[OpenPayload, "SessionOpenContext"], Awaitable[None]]
TopUpTxVerifier = Callable[[TopUpPayload], Awaitable[None]]


class OpenVerifierConfig(Protocol):
    """The subset of the session config :func:`new_open_tx_verifier` reads:
    the challenge currency/network/recipient, minimum deposit, and optional
    payment-channels program override."""

    currency: str
    network: str
    recipient: str
    minimum_deposit: int | None
    channel_program: str
    token_program: str | None
    grace_period_seconds: int | None
    fee_payer: bool
    fee_payer_key: str | None


@dataclass
class VerifyOpenTxExpected:
    """The challenge-side values a client-submitted open transaction is
    validated against."""

    authorized_signer: str
    currency: str
    recipient: str
    network: str
    minimum_deposit: int | None = None
    mint: str = ""
    fee_payer: str = ""
    rent_payer: str = ""
    token_program: str = ""
    grace_period_seconds: int | None = None
    program_id: Pubkey | None = None
    # The challenged ``methodDetails.recentBlockhash`` (base58). REQUIRED: the
    # compiled open transaction must use exactly this blockhash, proving it was
    # built for this challenge and not replayed from an older one.
    recent_blockhash: str = ""


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


def _decode_transaction(transaction_b64: str) -> tuple[bytes, Any, list[str], list, list[Signature]]:
    """Decode a base64 (legacy or v0) transaction into ``(account_keys,
    instructions, signatures)`` as base58 strings / compiled-instruction
    objects.

    A v0 transaction that references address lookup tables is rejected: the
    open verifier only sees the static account keys, so an ALT could hide the
    accounts it validates. See :func:`_reject_address_lookup_tables`.
    """
    from solders.transaction import Transaction, VersionedTransaction

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
    return raw, message, account_keys, instructions, signatures


def top_up_transaction_signature(transaction_b64: str) -> str | None:
    """Best-effort signature (transaction id) of a base64 top-up transaction.

    The dedupe key for exactly-once deposit crediting. Returns ``None`` when
    the payload is not a decodable wire transaction — the mandatory top-up
    verifier rejects those before any state changes, so dedupe never needs a
    key for them.
    """
    try:
        _, _, _, _, signatures = _decode_transaction(transaction_b64)
    except Exception:
        return None
    if not signatures:
        return None
    return str(signatures[0])


def _signed_message_bytes(message: Any) -> bytes:
    """Return the exact legacy or versioned bytes covered by signatures."""
    from solders.message import MessageV0, to_bytes_versioned  # type: ignore[import-untyped]

    if isinstance(message, MessageV0):
        return bytes(to_bytes_versioned(message))
    return bytes(message)


async def verify_open_tx(
    expected: VerifyOpenTxExpected,
    payload: OpenPayload,
    rpc_client: RpcClient | None,
) -> VerifyOpenTxResult:
    """Decode and validate a client-submitted payment-channel open transaction
    against the session challenge.

    Both legacy and v0 transaction encodings are accepted. The compiled
    message must use the challenged ``expected.recent_blockhash``, the embedded
    open instruction must target the configured payment-channels program, the
    payee must equal the challenge recipient, the mint must match the challenge
    currency/network, the authorizedSigner (slot 4) must match the payload, the
    rentPayer (slot 1) must equal the expected operator, the deposit must be
    positive and satisfy the advertised minimum, and the channel account must equal the PDA
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
    if not expected.fee_payer or not expected.rent_payer:
        raise ValueError("feePayer and rentPayer are required to verify an open transaction")
    if not expected.recent_blockhash:
        raise ValueError("the challenged recentBlockhash is required to verify an open transaction")
    if not payload.transaction:
        raise PaymentError(
            "openPayload.transaction is required for open verification",
            code="invalid-payload",
        )

    try:
        _raw, message, account_keys, instructions, signatures = _decode_transaction(payload.transaction)
    except PaymentError:
        # Already a structured rejection (e.g. the address-lookup-table guard);
        # surface it verbatim rather than wrapping it as a generic decode error.
        raise
    except Exception as exc:
        raise PaymentError(f"decode open transaction: {exc}", code="invalid-payload") from exc

    # The compiled message must use the challenged ``recentBlockhash``: it
    # proves the transaction was built for this challenge, not replayed from
    # an older one the server never authorized. Rejected before broadcast.
    if str(message.recent_blockhash) != expected.recent_blockhash:
        raise PaymentError(
            "open transaction does not use the challenged recentBlockhash",
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

    if not account_keys or account_keys[0] != expected.fee_payer:
        raise PaymentError("transaction fee payer does not match the challenge policy", code="invalid-payload")

    open_ix = None
    compute_budget_program = "ComputeBudget111111111111111111111111111111"
    for ix in instructions:
        program_index = int(ix.program_id_index)
        if program_index >= len(account_keys):
            raise PaymentError("instruction program index is out of bounds", code="invalid-payload")
        instruction_program = account_keys[program_index]
        if instruction_program == compute_budget_program:
            continue
        if instruction_program != str(program_id):
            raise PaymentError("open transaction contains an unexpected instruction", code="invalid-payload")
        data = bytes(ix.data)
        if len(data) < 1 or data[0] != _OPEN_INSTRUCTION_DISCRIMINATOR or open_ix is not None:
            raise PaymentError("open transaction must contain exactly one open instruction", code="invalid-payload")
        open_ix = ix
    if open_ix is None:
        raise PaymentError("no payment-channels open instruction found", code="invalid-payload")

    # Open instruction account layout after the rentPayer (+1) shift:
    # 0 payer, 1 rentPayer, 2 payee, 3 mint, 4 authorizedSigner, 5 channel,
    # 6 payerTokenAccount, 7 channelTokenAccount, 8 tokenProgram, ...
    # rentPayer (slot 1) is pinned to the operator / fee payer.
    accounts = [int(i) for i in open_ix.accounts]
    if len(accounts) < 9:
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
    token_program = account_at(accounts, 8, "tokenProgram")

    if str(payer) != payload.payer:
        raise PaymentError(f"open payer {payer} != payload payer {payload.payer}", code="invalid-payload")

    if str(payee) != expected.recipient:
        raise PaymentError(f"open payee {payee} != expected recipient {expected.recipient}", code="invalid-payload")
    if str(mint) != expected_mint:
        raise PaymentError(f"open mint {mint} != expected mint {expected_mint}", code="invalid-payload")
    if str(authorized_signer) != expected.authorized_signer:
        raise PaymentError(
            f"open authorizedSigner {authorized_signer} != expected {expected.authorized_signer}",
            code="invalid-payload",
        )
    if str(rent_payer) != expected.rent_payer:
        raise PaymentError(
            f"open rentPayer {rent_payer} != expected {expected.rent_payer}",
            code="invalid-payload",
        )
    if str(token_program) != expected.token_program:
        raise PaymentError("open tokenProgram does not match the challenge", code="invalid-payload")

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
    if expected.minimum_deposit is not None and deposit < expected.minimum_deposit:
        raise PaymentError("open deposit is below minimumDeposit", code="invalid-payload")
    if deposit != payload.deposit_base_units():
        raise PaymentError("transaction deposit does not match depositAmount", code="invalid-payload")
    if salt != payload.salt:
        raise PaymentError("transaction salt does not match payload salt", code="invalid-payload")
    if grace_period != payload.grace_period_seconds:
        raise PaymentError("transaction grace period does not match gracePeriodSeconds", code="invalid-payload")
    if expected.grace_period_seconds is not None and grace_period != expected.grace_period_seconds:
        raise PaymentError("open gracePeriodSeconds does not match the challenge", code="invalid-payload")
    if open_slot != payload.open_slot:
        raise PaymentError("transaction open slot does not match openSlot", code="invalid-payload")

    # Re-derive the channel PDA from the instruction's own seeds.
    derived_channel, _ = find_channel_pda(payer, payee, mint, authorized_signer, salt, open_slot, program_id)
    if derived_channel != channel:
        raise PaymentError(f"open channel PDA {channel} != derived {derived_channel}", code="invalid-payload")
    if payload.channel_id != str(channel):
        raise PaymentError(
            f"openPayload.channelId {payload.channel_id} != transaction channel {channel}",
            code="invalid-payload",
        )
    expected_instruction = build_open_instruction(
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
                Distribution(recipient=Pubkey.from_string(split.recipient), bps=split.share_bps)
                for split in payload.distribution_splits
            ],
            token_program=token_program,
            program_id=program_id,
        )
    )
    actual_accounts = [Pubkey.from_string(account_keys[index]) for index in accounts]
    if actual_accounts != [meta.pubkey for meta in expected_instruction.accounts] or bytes(open_ix.data) != bytes(
        expected_instruction.data
    ):
        raise PaymentError("open instruction does not exactly match the declared channel terms", code="invalid-payload")

    required_signers = account_keys[: int(message.header.num_required_signatures)]
    try:
        payer_index = required_signers.index(str(payer))
    except ValueError as exc:
        raise PaymentError("channel payer is not a required transaction signer", code="invalid-payload") from exc
    if payer_index >= len(signatures) or signatures[payer_index] == Signature.default():
        raise PaymentError("channel payer signature is missing", code="invalid-payload")
    if not signatures[payer_index].verify(payer, _signed_message_bytes(message)):
        raise PaymentError("channel payer signature is invalid", code="invalid-payload")

    return VerifyOpenTxResult(
        channel_id=str(channel),
        deposit=deposit,
        grace_period=grace_period,
        salt=salt,
        open_slot=open_slot,
        payer=str(payer),
    )


def new_open_tx_verifier(
    config: OpenVerifierConfig,
    rpc_client: RpcClient | None,
    *,
    fee_payer_signer: Any | None = None,
) -> OpenTxVerifier:
    """Return the on-chain open verifier to install on the session config.

    When the open payload carries a transaction, it is structurally validated
    against the challenge via :func:`verify_open_tx` (with an on-chain liveness
    check when ``rpc_client`` is non-None), including that the compiled message
    uses the challenged ``recentBlockhash`` carried on the
    :class:`~solana_pay_kit.protocols.mpp.server.session.SessionOpenContext` —
    rejected before broadcast. When the payload carries only a confirmation
    signature, ``rpc_client`` is required and the signature is confirmed
    on-chain via ``getSignatureStatuses``.
    """

    async def verifier(payload: OpenPayload, context: SessionOpenContext) -> None:
        if rpc_client is None:
            raise PaymentError(
                "open verification requires an RPC client",
                code="invalid-payload",
            )
        program_id = Pubkey.from_string(config.channel_program)
        fee_payer = config.fee_payer_key if config.fee_payer else payload.payer
        if not fee_payer:
            raise PaymentError("feePayerKey is required when feePayer is true", code="invalid-config")
        token_program = config.token_program or default_token_program_for_currency(config.currency, config.network)
        expected = VerifyOpenTxExpected(
            authorized_signer=payload.authorized_signer,
            currency=config.currency,
            minimum_deposit=config.minimum_deposit,
            network=config.network,
            fee_payer=fee_payer,
            rent_payer=fee_payer,
            token_program=token_program,
            grace_period_seconds=config.grace_period_seconds,
            program_id=program_id,
            recipient=config.recipient,
            recent_blockhash=context.recent_blockhash,
        )
        verified = await verify_open_tx(expected, payload, None)
        # A broadcast rejection is not authoritative: a retry of an open whose
        # first submission landed (response lost, or the store write after it
        # failed) dies at preflight with "already processed". The confirmed
        # channel account is authoritative — it matches the verified open
        # params only if this exact open succeeded — so a full field match
        # below is treated as success regardless of what the broadcast said.
        # Mirrors the Rust open retry-idempotency fix.
        broadcast_error: Exception | None = None
        if config.fee_payer:
            if fee_payer_signer is None:
                raise PaymentError("fee-payer signing requires a configured signer", code="invalid-config")
            try:
                await cosign_and_broadcast_open(payload, fee_payer=fee_payer_signer, rpc=rpc_client)
            except Exception as exc:  # noqa: BLE001 — resolved against the confirmed account below
                broadcast_error = exc
        else:
            raw = base64.b64decode(payload.transaction, validate=True)
            try:
                sent = await rpc_client.send_raw_transaction(raw)
                await confirm_transaction_signature(rpc_client, str(sent.value), "open")
            except Exception as exc:  # noqa: BLE001 — resolved against the confirmed account below
                broadcast_error = exc
        try:
            await _verify_channel_account(
                rpc_client,
                verified.channel_id,
                program_id=program_id,
                expected={
                    "authorized_signer": payload.authorized_signer,
                    "deposit": verified.deposit,
                    "grace_period": payload.grace_period_seconds,
                    "mint": expected.mint or resolve_mint(config.currency, config.network),
                    "open_slot": payload.open_slot,
                    "payee": config.recipient,
                    "payer": payload.payer,
                    "rent_payer": fee_payer,
                    "salt": payload.salt,
                },
            )
        except Exception as verify_error:
            # Anything short of a full field match keeps the broadcast
            # failure authoritative.
            if broadcast_error is not None:
                raise broadcast_error from verify_error
            raise

    return verifier


def new_top_up_tx_verifier(
    config: OpenVerifierConfig,
    store: Any,
    rpc_client: RpcClient | None,
) -> TopUpTxVerifier:
    """Return the on-chain top-up verifier to install on the session config: it
    confirms the top-up transaction signature on-chain via
    ``getSignatureStatuses``.

    The verifier fails closed without RPC and validates the exact top-up
    instruction, signature, confirmation, and resulting deposit.
    """

    async def verifier(payload: TopUpPayload) -> None:
        if rpc_client is None:
            raise PaymentError("top-up verification requires an RPC client", code="invalid-payload")
        state = await store.get_channel(payload.channel_id)
        if state is None:
            raise PaymentError(f"channel {payload.channel_id} not found", code="invalid-payload")
        amount = int(payload.additional_amount)
        raw, message, account_keys, instructions, signatures = _decode_transaction(payload.transaction)
        program_id = Pubkey.from_string(config.channel_program)
        non_compute = [
            ix
            for ix in instructions
            if account_keys[int(ix.program_id_index)] != "ComputeBudget111111111111111111111111111111"
        ]
        if len(non_compute) != 1 or account_keys[int(non_compute[0].program_id_index)] != str(program_id):
            raise PaymentError("top-up transaction must contain exactly one top-up instruction", code="invalid-payload")
        mint_address = resolve_mint(config.currency, config.network)
        if not mint_address:
            raise PaymentError("could not resolve top-up mint", code="invalid-config")
        token_program = Pubkey.from_string(
            config.token_program or default_token_program_for_currency(config.currency, config.network)
        )
        expected_ix = build_top_up_instruction(
            TopUpParams(
                payer=Pubkey.from_string(state.payer),
                channel=Pubkey.from_string(state.channel_id),
                mint=Pubkey.from_string(mint_address),
                amount=amount,
                token_program=token_program,
                program_id=program_id,
            ),
        )
        actual_ix = non_compute[0]
        actual_accounts = [Pubkey.from_string(account_keys[int(index)]) for index in actual_ix.accounts]
        if actual_accounts != [meta.pubkey for meta in expected_ix.accounts] or bytes(actual_ix.data) != bytes(
            expected_ix.data
        ):
            raise PaymentError("top-up instruction does not exactly match additionalAmount", code="invalid-payload")
        required_signers = account_keys[: int(message.header.num_required_signatures)]
        try:
            payer_index = required_signers.index(state.payer)
        except ValueError as exc:
            raise PaymentError("top-up payer is not a transaction signer", code="invalid-payload") from exc
        payer = Pubkey.from_string(state.payer)
        if payer_index >= len(signatures) or not signatures[payer_index].verify(payer, _signed_message_bytes(message)):
            raise PaymentError("top-up payer signature is invalid", code="invalid-payload")
        try:
            sent = await rpc_client.send_raw_transaction(raw)
            signature = str(sent.value)
        except Exception:  # noqa: BLE001 — resolved against the landed signature below
            # A duplicate of an already-landed top-up dies at preflight with
            # "already processed". The signature identifies this exact
            # verified transaction — an unrelated top-up cannot satisfy it —
            # so a landed clean status means escrow was funded by the first
            # submission; the post-confirm deposit re-check and the mutator's
            # signature dedupe decide whether it was already credited. A
            # landed-but-FAILED transaction (err set) keeps the broadcast
            # failure authoritative. Mirrors the TS submitTopUpTx rescue.
            if not signatures:
                raise
            landed = str(signatures[0])
            statuses = await rpc_client.get_signature_statuses([landed])
            status = statuses[0] if statuses else None
            if status is None or status.get("err") is not None:
                raise
            signature = landed
        await confirm_transaction_signature(rpc_client, signature, "top-up")
        if amount > _U64_MAX - state.deposit:
            raise PaymentError("top-up deposit overflows u64", code="invalid-payload")
        await _verify_channel_account(
            rpc_client,
            state.channel_id,
            program_id=program_id,
            expected={"deposit": state.deposit + amount},
        )

    return verifier


_U64_MAX = (1 << 64) - 1


async def _verify_channel_account(
    rpc_client: Any,
    channel_id: str,
    *,
    program_id: Pubkey,
    expected: dict[str, Any],
) -> None:
    """Fetch and compare the authoritative channel account after confirmation."""
    from solana_pay_kit.protocols.programs.paymentchannels.accounts.channel import Channel

    response = await rpc_client.get_account_info(Pubkey.from_string(channel_id), commitment="confirmed")
    info = getattr(response, "value", None)
    if info is None:
        raise PaymentError("confirmed channel account was not found", code="transaction-not-found")
    if str(info.owner) != str(program_id):
        raise PaymentError("channel account is owned by the wrong program", code="invalid-payload")
    channel = Channel.decode(bytes(info.data))
    actual = {
        "authorized_signer": str(channel.authorizedSigner),
        "deposit": channel.deposit,
        "grace_period": channel.gracePeriod,
        "mint": str(channel.mint),
        "open_slot": channel.openSlot,
        "payee": str(channel.payee),
        "payer": str(channel.payer),
        "rent_payer": str(channel.rentPayer),
        "salt": channel.salt,
    }
    if channel.status != 0:
        raise PaymentError("channel is not open after transaction confirmation", code="transaction-failed")
    for field, value in expected.items():
        if actual[field] != value:
            raise PaymentError(
                f"channel account {field} does not match confirmed transaction",
                code="transaction-failed",
            )


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
    program_id = Pubkey.from_string(config.channel_program)
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
    payer_address = state.payer
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
        # rentPayer recovers the channel/escrow rent at distribute (or via
        # reclaim). The on-chain program pins it to the account recorded at
        # open (the fee payer, or the payer in non-gasless configs) — building
        # with any other account makes the settle bundle revert forever.
        rent_payer=Pubkey.from_string(state.rent_payer) if state.rent_payer else None,
    )

    blockhash = Hash.from_string((await rpc.get_latest_blockhash()).value.blockhash)
    tx = Transaction.new_signed_with_payer([*settle, distribute], merchant_pubkey, [merchant], blockhash)
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
    broadcast it.

    The client builds the open with the operator as fee payer and partial-signs
    only its own (payer) slot; the server splices in the operator/fee-payer
    signature, broadcasts, and confirms. Returns the confirmed open signature.
    Mirrors Go SubmitOpenTx (and reuses the charge fee-payer co-sign).
    """
    from solana_pay_kit.protocols.mpp.server._verify import _co_sign_with_fee_payer

    if not payload.transaction:
        raise PaymentError(
            "server-funded open requires the client-built transaction in the payload",
            code="invalid-payload",
        )
    cosigned = _co_sign_with_fee_payer(payload.transaction, fee_payer)
    sent = await rpc.send_raw_transaction(base64.b64decode(cosigned))
    signature = str(sent.value)
    await confirm_transaction_signature(rpc, signature, "open")
    return signature
