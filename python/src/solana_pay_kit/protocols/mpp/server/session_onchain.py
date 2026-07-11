"""On-chain verification and settlement for the session intent.

Provides the standalone open-transaction verifier and the verifier-seam
factories the session server installs to validate client-submitted on-chain
activity.

Trust model: when no verifier is installed (the seam is ``None``), transaction
signatures and deposit amounts are trusted as provided. :func:`verify_open_tx`
always validates an attached open transaction structurally (decode, bind the
payload signature, check the open instruction against the challenge, re-derive
the channel PDA); confirming that the transaction actually landed additionally
requires an RPC client. :func:`new_top_up_tx_verifier` fetches the confirmed
transaction because a top-up payload carries only a signature: it binds the
configured program, channel, and Borsh-decoded amount to the stored deposit.
Without an RPC client the top-up seam stays ``None`` and the new deposit is
trusted as provided.
"""

from __future__ import annotations

import asyncio
import base64
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
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
    build_distribute_instruction,
    build_settle_and_seal_instructions,
    find_channel_pda,
    treasury_owner,
)
from solana_pay_kit.protocols.mpp.intents.session import OpenPayload, TopUpPayload
from solana_pay_kit.protocols.mpp.server._tx_decode import _transaction_dict
from solana_pay_kit.protocols.programs.paymentchannels.types.openArgs import OpenArgs
from solana_pay_kit.protocols.programs.paymentchannels.types.topUpArgs import TopUpArgs

if TYPE_CHECKING:
    from solana_pay_kit.protocols.mpp.server.session import SessionConfig, Split
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
_TOP_UP_INSTRUCTION_DISCRIMINATOR = 3
_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


class RpcClient(Protocol):
    """Minimal RPC seam used for the optional on-chain liveness check and the
    settle-at-close broadcast.

    ``get_signature_statuses`` returns the per-signature status list (each entry
    is a status dict with an ``err`` field, or ``None`` when unknown);
    ``get_latest_blockhash`` / ``send_raw_transaction`` back the settle path.
    The top-up verifier additionally requires a duck-typed ``get_transaction``
    method and fails closed when it is absent."""

    async def get_signature_statuses(self, signatures: list[str]) -> list[dict | None]: ...

    async def get_latest_blockhash(self, commitment: str = ...) -> Any: ...

    async def send_raw_transaction(self, raw_tx: bytes) -> Any: ...


#: A verifier seam installed on the session config: validates a payload (open
#: or top-up) and raises on rejection.
OpenTxVerifier = Callable[[OpenPayload], Awaitable[None]]
TopUpTxVerifier = Callable[[TopUpPayload, "ChannelState"], Awaitable[None]]


class OpenVerifierConfig(Protocol):
    """The subset of the session config :func:`new_open_tx_verifier` reads:
    the challenge currency/network/recipient, the deposit cap, and the optional
    payment-channels program id override."""

    currency: str
    network: str
    recipient: str
    max_cap: int
    operator: str
    splits: list[Split]

    @property
    def program_id(self) -> Pubkey | str | None: ...


class TopUpVerifierConfig(Protocol):
    """The subset of session config used to bind a confirmed top-up."""

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
    program_id: Pubkey | str | None = None
    # The challenge-issued recentSlot, when the caller has it. The open
    # instruction's own openSlot must equal it: without this bind, a payload
    # that omits recentSlot would let a transaction built against a different
    # slot through (and the decoded slot would then overwrite the payload).
    # None skips the check (offline/trust-mode challenges carry no slot).
    recent_slot: int | None = None
    # Ordered payout distribution encoded into the open instruction. An empty
    # vector is meaningful: it commits the channel to the implicit payee only.
    recipients: list[tuple[str, int]] = field(default_factory=list)


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


def _decode_transaction(transaction_b64: str) -> tuple[list[str], list, list[str]]:
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

    program_id = _configured_program_id(expected.program_id)
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

    # Decode the complete Borsh payload, including every recipient. The first
    # fields used to be decoded manually, which left the recipient distribution
    # decorative: a client could open a channel whose later distribute step
    # routed funds differently from the challenge. Re-encoding proves Borsh
    # consumed the complete payload rather than accepting a valid prefix.
    data = bytes(open_ix.data)
    try:
        decoded_args = OpenArgs.from_decoded(OpenArgs.layout.parse(data[1:]))
        if OpenArgs.layout.build(decoded_args.to_encodable()) != data[1:]:
            raise ValueError("open instruction has trailing or non-canonical Borsh data")
    except Exception as exc:
        raise PaymentError(f"decode open instruction args: {exc}", code="invalid-payload") from exc
    salt = decoded_args.salt
    deposit = decoded_args.deposit
    grace_period = decoded_args.gracePeriod
    open_slot = decoded_args.openSlot
    recipients = [(str(entry.recipient), entry.bps) for entry in decoded_args.recipients]
    if recipients != expected.recipients:
        raise PaymentError(
            f"open recipients {recipients!r} != expected configured splits {expected.recipients!r}",
            code="invalid-payload",
        )

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
                recipients=[(split.recipient, split.bps) for split in config.splits],
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


def new_top_up_tx_verifier(
    config: TopUpVerifierConfig,
    rpc_client: RpcClient | None,
) -> TopUpTxVerifier | None:
    """Return the top-up verifier bound to a configured payment-channel program.

    A top-up payload contains only a signature and target total, so confirming
    that signature alone proves neither that it targeted this channel nor that
    it added the claimed delta. The verifier fetches the confirmed transaction,
    locates exactly one Borsh-decoded ``topUp`` instruction for the configured
    program, binds its channel account, and compares its amount to
    ``newDeposit - state.deposit``. ``SessionServer.process_top_up`` then
    rechecks that ``state.deposit`` is unchanged in its atomic mutator after
    this network await.

    A ``None`` ``rpc_client`` returns ``None`` so the seam stays unset; that is
    suitable only for tests or deployments that verify top-ups out of band.
    """
    if rpc_client is None:
        return None
    program_id = _configured_program_id(config.program_id)

    async def verifier(payload: TopUpPayload, state: ChannelState) -> None:
        await confirm_transaction_signature(rpc_client, payload.signature, "top-up")
        get_transaction: Any = getattr(rpc_client, "get_transaction", None)
        if not callable(get_transaction):
            raise PaymentError(
                "top-up verification requires an RPC client with get_transaction",
                code="invalid-config",
            )
        try:
            pending: Any = get_transaction(
                payload.signature,
                commitment="confirmed",
                encoding="jsonParsed",
                max_supported_transaction_version=0,
            )
            response: Any = await pending
        except Exception as exc:
            raise PaymentError(f"RPC error fetching top-up tx: {exc}", code="transaction-not-found") from exc
        transaction = _transaction_dict(response)
        if transaction is None:
            raise PaymentError("top-up transaction not found or not yet confirmed", code="transaction-not-found")
        _verify_confirmed_top_up(transaction, payload, state, program_id)

    return verifier


def _configured_program_id(value: Pubkey | str | None) -> Pubkey:
    if value is None:
        return PROGRAM_ID
    if isinstance(value, Pubkey):
        return value
    try:
        return Pubkey.from_string(value)
    except (TypeError, ValueError) as exc:
        raise PaymentError(f"invalid payment-channels program id {value!r}", code="invalid-config") from exc


def _verify_confirmed_top_up(
    transaction: dict[str, Any],
    payload: TopUpPayload,
    state: ChannelState,
    program_id: Pubkey,
) -> None:
    """Bind a confirmed transaction's sole ``topUp`` to the session state."""
    meta = transaction.get("meta")
    if not isinstance(meta, dict) or meta.get("err") is not None:
        raise PaymentError("top-up transaction failed on-chain", code="transaction-failed")
    message = (transaction.get("transaction") or {}).get("message")
    instructions = message.get("instructions") if isinstance(message, dict) else None
    if not isinstance(instructions, list):
        raise PaymentError("confirmed top-up transaction has no instructions", code="invalid-payload")

    top_up_instructions: list[dict[str, Any]] = []
    for instruction in instructions:
        if not isinstance(instruction, dict) or instruction.get("programId") != str(program_id):
            continue
        data = instruction.get("data")
        if not isinstance(data, str):
            continue
        try:
            decoded = _base58_decode(data)
        except ValueError:
            continue
        if decoded and decoded[0] == _TOP_UP_INSTRUCTION_DISCRIMINATOR:
            top_up_instructions.append(instruction)

    if len(top_up_instructions) != 1:
        raise PaymentError(
            "confirmed transaction must contain exactly one configured topUp instruction, "
            f"found {len(top_up_instructions)}",
            code="invalid-payload",
        )

    instruction = top_up_instructions[0]
    accounts = instruction.get("accounts")
    if not isinstance(accounts, list) or len(accounts) < 2 or not all(isinstance(account, str) for account in accounts):
        raise PaymentError("top-up instruction has invalid account layout", code="invalid-payload")
    if accounts[1] != payload.channel_id or state.channel_id != payload.channel_id:
        raise PaymentError("top-up instruction channel does not match the session", code="invalid-payload")

    try:
        raw_data = _base58_decode(instruction["data"])
        decoded_args = TopUpArgs.from_decoded(TopUpArgs.layout.parse(raw_data[1:]))
        if TopUpArgs.layout.build(decoded_args.to_encodable()) != raw_data[1:]:
            raise ValueError("top-up instruction has trailing or non-canonical Borsh data")
        new_deposit = _parse_u64(payload.new_deposit, "newDeposit")
    except Exception as exc:
        raise PaymentError(f"decode top-up instruction: {exc}", code="invalid-payload") from exc

    if new_deposit <= state.deposit:
        raise PaymentError("top-up newDeposit must exceed the stored deposit", code="invalid-payload")
    if decoded_args.amount != new_deposit - state.deposit:
        raise PaymentError(
            f"top-up amount {decoded_args.amount} != newDeposit delta {new_deposit - state.deposit}",
            code="invalid-payload",
        )


def _parse_u64(value: str, label: str) -> int:
    if not isinstance(value, str) or not (value.isascii() and value.isdigit()):
        raise ValueError(f"{label} must be an unsigned integer string")
    parsed = int(value, 10)
    if parsed > (1 << 64) - 1:
        raise ValueError(f"{label} exceeds u64")
    return parsed


def _base58_decode(value: str) -> bytes:
    """Decode Solana's base58 RPC instruction data without a new dependency."""
    if value == "":
        raise ValueError("empty base58 data")
    number = 0
    for char in value:
        digit = _BASE58_ALPHABET.find(char)
        if digit < 0:
            raise ValueError("invalid base58 data")
        number = number * 58 + digit
    leading_zeros = len(value) - len(value.lstrip("1"))
    encoded = b"" if number == 0 else number.to_bytes((number.bit_length() + 7) // 8, "big")
    return b"\0" * leading_zeros + encoded


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
    broadcast it (the ``openTxSubmitter=server`` flow).

    The client builds the open with the operator as fee payer and partial-signs
    only its own (payer) slot; the server splices in the operator/fee-payer
    signature, broadcasts, and confirms. Returns the confirmed open signature.
    Mirrors Go SubmitOpenTx (and reuses the charge fee-payer co-sign).
    """
    from solana_pay_kit.protocols.mpp.server._verify import _co_sign_with_fee_payer

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
