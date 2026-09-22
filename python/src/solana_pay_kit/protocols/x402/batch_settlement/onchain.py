"""In-process facilitator for the SVM x402 ``batch-settlement`` server.

The pay-kit server is its own facilitator: it reads channel accounts, checks
that a channel can later pay out before sponsoring its escrow, simulates and
co-signs the client's setup transaction, and builds, signs and submits the
redemption transactions (claim, distribute, seal, reclaim). Every function
takes the RPC client explicitly so the engine can scope one per request.

Two rules hold for every broadcast here:

- A broadcast whose confirmation is ambiguous raises :class:`UnconfirmedBroadcast`
  and is never rebuilt with new bytes. The next read of the chain decides; the
  program's monotonic watermarks make a repeated claim, distribute or seal
  harmless.
- Client setup bytes are only ever re-sent verbatim: the fee-payer signature is
  deterministic, so a retry of the same bytes is the same transaction.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any, Literal, cast

from solders.hash import Hash  # type: ignore[import-untyped]
from solders.instruction import Instruction  # type: ignore[import-untyped]
from solders.message import to_bytes_versioned  # type: ignore[import-untyped]
from solders.pubkey import Pubkey  # type: ignore[import-untyped]
from solders.signature import Signature  # type: ignore[import-untyped]
from solders.transaction import VersionedTransaction  # type: ignore[import-untyped]

from solana_pay_kit._paycore.errors import PaymentError
from solana_pay_kit._paycore.paymentchannels import (
    CHANNEL_ACCOUNT_SIZE,
    CHANNEL_RENT_PAYER_OFFSET,
    Distribution,
    build_distribute_instruction,
    find_associated_token_address,
    find_channel_pda,
    treasury_owner,
)
from solana_pay_kit._paycore.rpc import SolanaRpc
from solana_pay_kit._paycore.transaction import build_partially_signed_v0_transaction
from solana_pay_kit.protocols.programs.paymentchannels.accounts.channel import Channel
from solana_pay_kit.protocols.x402.batch_settlement import errors
from solana_pay_kit.protocols.x402.batch_settlement.errors import BatchSettlementError
from solana_pay_kit.protocols.x402.batch_settlement.verify import decode_channel
from solana_pay_kit.signer import LocalSigner

__all__ = [
    "SignatureStatus",
    "TokenAccount",
    "UnconfirmedBroadcast",
    "broadcast_setup",
    "check_mint_owner",
    "check_settlement_accounts",
    "cosign",
    "decode_token_account",
    "discover",
    "distribute_instruction",
    "read_channel",
    "read_channels",
    "signature_status",
    "simulate",
    "submit",
]

SignatureStatus = Literal["confirmed", "failed", "pending"]

# SPL token account layout: 165 base bytes; Token-2022 appends an account-type
# byte (2) and a TLV extension list.
_TOKEN_ACCOUNT_LEN = 165
_TOKEN_ACCOUNT_INITIALIZED = 1
_TOKEN_ACCOUNT_FROZEN = 2
_TOKEN_ACCOUNT_TYPE = 2
_EXTENSION_IMMUTABLE_OWNER = 7
_FULL_SHARE_BPS = 10_000


class UnconfirmedBroadcast(Exception):  # noqa: N818 - an outcome, not a bug
    """A transaction was sent but not seen confirmed in the window; do not rebuild it."""

    def __init__(self, signature: str, detail: str) -> None:
        super().__init__(f"{signature}: {detail}")
        self.signature = signature


@dataclass(frozen=True)
class TokenAccount:
    """The token-account fields a payout destination is judged by."""

    mint: str
    owner: str
    state: int
    unsupported_extension: int | None


def decode_token_account(data: bytes) -> TokenAccount | None:
    """Decode an SPL / Token-2022 account, or ``None`` when too short to be one (uninitialized).

    A Token-2022 extension other than ``ImmutableOwner`` can withhold part of a
    transfer, require a memo, or block a CPI, so it is reported rather than
    silently accepted as a payout destination. A malformed TLV reports ``0xFFFF``.
    """
    if len(data) < _TOKEN_ACCOUNT_LEN:
        return None
    return TokenAccount(
        mint=str(Pubkey.from_bytes(data[0:32])),
        owner=str(Pubkey.from_bytes(data[32:64])),
        state=data[108],
        unsupported_extension=_unsupported_extension(data),
    )


def _unsupported_extension(data: bytes) -> int | None:
    if len(data) == _TOKEN_ACCOUNT_LEN:
        return None
    if data[_TOKEN_ACCOUNT_LEN] != _TOKEN_ACCOUNT_TYPE:
        return data[_TOKEN_ACCOUNT_LEN]
    cursor = _TOKEN_ACCOUNT_LEN + 1
    while cursor < len(data):
        if not any(data[cursor:]):
            return None  # zero padding ends the list
        if cursor + 4 > len(data):
            return 0xFFFF
        extension, length = struct.unpack_from("<HH", data, cursor)
        if extension != _EXTENSION_IMMUTABLE_OWNER:
            return extension
        cursor += 4 + length
        if cursor > len(data):
            return 0xFFFF
    return None


async def read_channel(rpc: SolanaRpc, channel_id: str, program_id: Pubkey) -> Channel | None:
    """The decoded channel account, or ``None`` when the account is absent."""
    account = await rpc.get_account_info(channel_id)
    return None if account is None else decode_channel(account[0], account[1], program_id)


async def read_channels(rpc: SolanaRpc, channel_ids: list[str], program_id: Pubkey) -> list[Channel | None]:
    """Decode many channel accounts in order with ``getMultipleAccounts``; ``None`` marks an absent one."""
    accounts = await rpc.get_multiple_accounts(channel_ids)
    return [None if account is None else decode_channel(account[0], account[1], program_id) for account in accounts]


async def check_mint_owner(rpc: SolanaRpc, mint: str, token_program: str) -> None:
    """Refuse a declared token program that does not own the mint on chain; every ATA derivation depends on it."""
    account = await rpc.get_account_info(mint)
    if account is None or account[1] != token_program:
        raise BatchSettlementError(errors.INVALID_TOKEN_PROGRAM, f"tokenProgram {token_program} does not own {mint}")


async def check_settlement_accounts(rpc: SolanaRpc, *, mint: str, token_program: str, owners: dict[str, str]) -> None:
    """Refuse the escrow unless every payout destination is a live, unfrozen ATA of this mint.

    ``owners`` maps a role (``payee``, ``treasury``, ``receiver``, ``payer``) to
    the wallet that owns it. An unusable destination would fail ``distribute``
    only after the escrow is locked and the request already served.
    """
    mint_key, program_key = Pubkey.from_string(mint), Pubkey.from_string(token_program)
    atas = {
        role: str(find_associated_token_address(Pubkey.from_string(owner), mint_key, program_key)[0])
        for role, owner in owners.items()
    }
    accounts = await rpc.get_multiple_accounts(list(atas.values()))
    for (role, ata), account in zip(atas.items(), accounts, strict=True):
        decoded = None if account is None or account[1] != token_program else decode_token_account(account[0])
        problem = _payout_problem(decoded, mint, owners[role])
        if problem is not None:
            raise BatchSettlementError(errors.INVALID_SETTLEMENT_SIMULATION, f"{role} settlement ATA {ata} {problem}")


def _payout_problem(account: TokenAccount | None, mint: str, owner: str) -> str | None:
    if account is None:
        return "is missing or not owned by the token program"
    if account.mint != mint:
        return f"holds mint {account.mint}"
    if account.owner != owner:
        return f"is owned by {account.owner}"
    if account.state == _TOKEN_ACCOUNT_FROZEN:
        return "is frozen"
    if account.unsupported_extension is not None:
        return f"carries unsupported extension {account.unsupported_extension}"
    if account.state != _TOKEN_ACCOUNT_INITIALIZED:
        return "is not initialized"
    return None


def cosign(transaction: VersionedTransaction, signer: LocalSigner) -> VersionedTransaction:
    """Fill the fee-payer slot (index 0) of a policy-validated client transaction."""
    message = transaction.message
    signatures = list(transaction.signatures)
    signatures[0] = Signature.from_bytes(signer.sign(bytes(to_bytes_versioned(message))))
    return VersionedTransaction.populate(message, signatures)


async def signature_status(rpc: SolanaRpc, signature: str) -> tuple[SignatureStatus, Any]:
    """Whether a signature landed (``confirmed``), landed and failed, or is not visible yet."""
    statuses = await rpc.get_signature_statuses([signature])
    status: Any = statuses[0] if statuses else None
    if not isinstance(status, dict):
        return "pending", None
    fields: dict[str, Any] = status  # pyright: ignore[reportUnknownVariableType]
    if fields.get("err") is not None:
        return "failed", fields.get("err")
    if fields.get("confirmationStatus") in ("confirmed", "finalized"):
        return "confirmed", None
    return "pending", None


async def simulate(rpc: SolanaRpc, transaction: VersionedTransaction) -> None:
    """Simulate the exact setup bytes before they are sponsored; a failure is ``settlement_simulation``."""
    try:
        value = await rpc.simulate_transaction(bytes(transaction))
    except PaymentError as exc:
        raise BatchSettlementError(errors.INVALID_SETTLEMENT_SIMULATION, f"simulation unavailable: {exc}") from None
    if value.get("err") is not None:
        logs = " | ".join(str(line) for line in cast("list[Any]", value.get("logs") or []))
        raise BatchSettlementError(errors.INVALID_SETTLEMENT_SIMULATION, f"simulation failed: {value['err']}; {logs}")


async def _confirm(rpc: SolanaRpc, signature: str) -> None:
    try:
        await rpc.await_confirmation(signature)
    except PaymentError as exc:
        if exc.code == "transaction-failed":
            raise BatchSettlementError("transaction_failed", str(exc)) from None
        raise UnconfirmedBroadcast(signature, str(exc)) from None


async def broadcast_setup(rpc: SolanaRpc, transaction: VersionedTransaction) -> str:
    """Send a co-signed setup transaction and wait for it; return its signature.

    A signature that already landed is not re-sent. A send rejection is not
    final on its own (a retry of landed bytes dies at preflight), so the
    signature status decides.
    """
    signature = str(transaction.signatures[0])
    status, err = await signature_status(rpc, signature)
    if status == "failed":
        raise BatchSettlementError(errors.INVALID_SETTLEMENT_SIMULATION, f"setup landed but failed: {err}")
    if status == "confirmed":
        return signature
    try:
        await rpc.send_raw_transaction(bytes(transaction))
    except PaymentError as exc:
        status, err = await signature_status(rpc, signature)
        if status == "confirmed":
            return signature
        raise BatchSettlementError(errors.INVALID_SETTLEMENT_SIMULATION, f"setup broadcast refused: {exc}") from None
    await _confirm(rpc, signature)
    return signature


async def submit(rpc: SolanaRpc, signer: LocalSigner, instructions: list[Instruction]) -> str:
    """Build, fee-payer-sign and send a server-authored transaction; return its confirmed signature.

    Raises :class:`UnconfirmedBroadcast` when it was sent but not seen confirmed.
    """
    fee_payer = Pubkey.from_string(signer.pubkey())
    blockhash = Hash.from_string((await rpc.get_latest_blockhash()).value.blockhash)
    wire = build_partially_signed_v0_transaction(instructions, fee_payer, blockhash, fee_payer, signer.sign)
    signature = str(VersionedTransaction.from_bytes(wire).signatures[0])
    try:
        await rpc.send_raw_transaction(wire)
    except PaymentError as exc:
        raise BatchSettlementError("transaction_failed", f"redemption broadcast refused: {exc}") from None
    await _confirm(rpc, signature)
    return signature


def distribute_instruction(
    *, channel_id: str, channel: Channel, fee_payer: str, pay_to: str, token_program: str, program_id: Pubkey
) -> Instruction:
    """``distribute`` paying the settled delta 100% to ``payTo``; the sponsor is payee and rent payer."""
    sponsor = Pubkey.from_string(fee_payer)
    return build_distribute_instruction(
        channel=Pubkey.from_string(channel_id),
        payer=channel.payer,
        payee=sponsor,
        mint=channel.mint,
        recipients=[Distribution(Pubkey.from_string(pay_to), _FULL_SHARE_BPS)],
        token_program=Pubkey.from_string(token_program),
        program_id=program_id,
        treasury=treasury_owner(),
        rent_payer=sponsor,
    )


async def discover(rpc: SolanaRpc, program_id: Pubkey, fee_payer: str) -> list[tuple[str, Channel]]:
    """Every channel whose rent ``fee_payer`` fronted, each re-derived to its PDA before it is trusted.

    Rebuilds the lifecycle work queue after a lost store. It never recovers a
    charge watermark or voucher: those exist only in the store.
    """
    rows = await rpc.get_program_accounts(
        str(program_id), data_size=CHANNEL_ACCOUNT_SIZE, memcmp=[(CHANNEL_RENT_PAYER_OFFSET, fee_payer)]
    )
    found: list[tuple[str, Channel]] = []
    for address, data in rows:
        try:
            channel = decode_channel(data, str(program_id), program_id)
        except BatchSettlementError:
            continue
        derived, _ = find_channel_pda(
            channel.payer,
            channel.payee,
            channel.mint,
            channel.authorizedSigner,
            int(channel.salt),
            int(channel.openSlot),
            program_id,
        )
        if str(derived) == address and str(channel.rentPayer) == fee_payer and str(channel.payee) == fee_payer:
            found.append((address, channel))
    return found
