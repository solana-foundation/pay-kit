"""Shared offline fixtures for the x402 ``batch-settlement`` tests: fixed keys,
an in-memory Solana RPC double, and builders for token / mint / channel
account bytes the server reads."""

from __future__ import annotations

import base64
import struct
from dataclasses import dataclass, field
from typing import Any

from solana_keychain import MemorySigner
from solders.hash import Hash
from solders.keypair import Keypair
from solders.pubkey import Pubkey

from solana_pay_kit._paycore.paymentchannels import PROGRAM_ID, find_associated_token_address
from solana_pay_kit._paycore.solana import TOKEN_PROGRAM
from solana_pay_kit.protocols.programs.paymentchannels.accounts.channel import Channel
from solana_pay_kit.protocols.programs.paymentchannels.shared.pubkey import Pubkey as ProgramPubkey
from solana_pay_kit.protocols.programs.paymentchannels.types.settlement_watermarks import SettlementWatermarks
from solana_pay_kit.protocols.x402.batch_settlement.server import (
    BatchConfig,
    X402BatchSettlement,
    _treasury_owner_for_cluster,
    distribution_hash,
)
from solana_pay_kit.protocols.x402.batch_settlement.store import MemoryBatchChannelStore
from solana_pay_kit.protocols.x402.batch_settlement.types import BatchExtra, BatchRequirements

PAYER = Keypair.from_seed(bytes([7] * 32))
FEE_PAYER = Keypair.from_seed(bytes([9] * 32))
RECEIVER_AUTHORIZER = Keypair.from_seed(bytes([11] * 32))
STRANGER = Keypair.from_seed(bytes([13] * 32))
PAY_TO = Keypair.from_seed(bytes([15] * 32)).pubkey()
MINT = Pubkey.from_string("4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU")
TOKEN = Pubkey.from_string(TOKEN_PROGRAM)
BLOCKHASH = Hash.from_string("11111111111111111111111111111111")
NETWORK = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"
SLOT = 341_000_100
OPEN_SLOT = 341_000_000


def signer(keypair: Keypair = PAYER) -> MemorySigner:
    return MemorySigner(keypair)


def requirements(**extra: Any) -> BatchRequirements:
    defaults: dict[str, Any] = {
        "fee_payer": str(FEE_PAYER.pubkey()),
        "withdraw_delay": 3600,
        "token_program": TOKEN_PROGRAM,
        "receiver_authorizer": str(RECEIVER_AUTHORIZER.pubkey()),
        "memo": "invoice-42",
    }
    defaults.update(extra)
    return BatchRequirements(
        network=NETWORK,
        amount="1000",
        asset=str(MINT),
        pay_to=str(PAY_TO),
        max_timeout_seconds=300,
        extra=BatchExtra(**defaults),
    )


def token_account(mint: Pubkey, owner: Pubkey, amount: int, state: int = 1, extra: bytes = b"") -> bytes:
    data = bytearray(165)
    data[0:32] = bytes(mint)
    data[32:64] = bytes(owner)
    struct.pack_into("<Q", data, 64, amount)
    data[108] = state
    return bytes(data) + extra


def mint_account() -> bytes:
    data = bytearray(82)
    data[44] = 6
    data[45] = 1
    return bytes(data)


def channel_account(
    *,
    payer: Pubkey | None = None,
    payee: Pubkey | None = None,
    deposit: int = 10_000,
    settled: int = 0,
    payout: int = 0,
    status: int = 0,
    closure_started_at: int = 0,
    grace_period: int = 3600,
    open_slot: int = OPEN_SLOT,
    salt: int = 42,
    discriminator: int = 1,
    receiver: Pubkey = PAY_TO,
) -> bytes:
    from solana_pay_kit._paycore.paymentchannels import Distribution

    fee_payer = FEE_PAYER.pubkey()
    return Channel(
        discriminator=discriminator,
        version=1,
        bump=255,
        status=status,
        salt=salt,
        deposit=deposit,
        settlement=SettlementWatermarks(settled=settled, payout_watermark=payout),
        closure_started_at=closure_started_at,
        payer_withdrawn_at=0,
        grace_period=grace_period,
        distribution_hash=list(distribution_hash([Distribution(receiver, 10_000)])),
        payer=ProgramPubkey(bytes(payer or PAYER.pubkey())),
        payee=ProgramPubkey(bytes(payee or fee_payer)),
        authorized_signer=ProgramPubkey(bytes(payer or PAYER.pubkey())),
        mint=ProgramPubkey(bytes(MINT)),
        rent_payer=ProgramPubkey(bytes(fee_payer)),
        open_slot=open_slot,
    ).serialize()


class _Value:
    def __init__(self, blockhash: str) -> None:
        self.blockhash = blockhash


class _Context:
    def __init__(self, slot: int | None) -> None:
        self.slot = slot


class _Response:
    def __init__(self, value: Any, context: Any = None) -> None:
        self.value = value
        self.context = context


@dataclass
class FakeRpc:
    """An in-memory stand-in for :class:`SolanaRpc`."""

    accounts: dict[str, tuple[bytes, str]] = field(default_factory=lambda: {})
    slot: int = SLOT
    blockhash_valid: bool = True
    simulation: dict[str, Any] = field(default_factory=lambda: {"err": None, "logs": []})
    statuses: dict[str, Any] = field(default_factory=lambda: {})
    sent: list[bytes] = field(default_factory=lambda: [])
    on_send: Any = None
    fail: set[str] = field(default_factory=lambda: set())

    def _check(self, method: str) -> None:
        if method in self.fail:
            raise RuntimeError(f"{method} unavailable")

    async def get_account_info(self, address: str, commitment: str = "confirmed") -> tuple[bytes, str] | None:
        self._check("getAccountInfo")
        return self.accounts.get(address)

    async def get_account_info_with_context(
        self, address: str, *, min_context_slot: int | None = None, commitment: str = "confirmed"
    ) -> tuple[int | None, tuple[bytes, str] | None]:
        self._check("getAccountInfo")
        return self.slot, self.accounts.get(address)

    async def get_latest_blockhash(self, commitment: str = "confirmed") -> _Response:
        self._check("getLatestBlockhash")
        return _Response(_Value(str(BLOCKHASH)), _Context(self.slot))

    async def is_blockhash_valid(self, blockhash: str, commitment: str = "confirmed") -> bool:
        self._check("isBlockhashValid")
        return self.blockhash_valid

    async def simulate_transaction(self, raw_tx: bytes, commitment: str = "confirmed") -> dict[str, Any]:
        return self.simulation

    async def send_raw_transaction(self, raw_tx: bytes) -> _Response:
        self._check("sendTransaction")
        self.sent.append(raw_tx)
        if self.on_send is not None:
            self.on_send(raw_tx)
        from solders.transaction import VersionedTransaction

        try:
            signature = str(VersionedTransaction.from_bytes(raw_tx).signatures[0])
        except Exception:  # noqa: BLE001 - version-1 wires
            from solana_pay_kit._paycore.txv1 import decode_transaction

            signature = str(decode_transaction(raw_tx).signatures[0])
        return _Response(signature)

    async def await_confirmation(self, signature: str, *args: Any, **kwargs: Any) -> None:
        self._check("confirm")

    async def get_signature_statuses(self, signatures: list[str], **kwargs: Any) -> list[Any]:
        self._check("getSignatureStatuses")
        return [self.statuses.get(sig) for sig in signatures]

    # helpers

    def put(self, address: Pubkey, data: bytes, owner: Pubkey | str) -> None:
        self.accounts[str(address)] = (data, str(owner))

    def put_settlement_accounts(self, payer: Pubkey, balance: int = 1_000_000, cluster: str = "devnet") -> None:
        self.put(MINT, mint_account(), TOKEN)
        for owner in (FEE_PAYER.pubkey(), _treasury_owner_for_cluster(cluster), PAY_TO, payer):
            ata, _ = find_associated_token_address(owner, MINT, TOKEN)
            self.put(ata, token_account(MINT, owner, balance), TOKEN)


def server(
    rpc: FakeRpc,
    *,
    store: MemoryBatchChannelStore | None = None,
    versions: tuple[int, ...] = (0,),
    clock: Any = None,
    **overrides: Any,
) -> X402BatchSettlement:
    kwargs: dict[str, Any] = {
        "pay_to": str(PAY_TO),
        "cluster": "devnet",
        "fee_payer_signer": signer(FEE_PAYER),
        "currency": str(MINT),
        "withdraw_delay": 3600,
        "memo": "invoice-42",
        "receiver_authorizer": str(RECEIVER_AUTHORIZER.pubkey()),
        "transaction_versions": versions,
    }
    kwargs.update(overrides)
    extra: dict[str, Any] = {}
    if clock is not None:
        extra["clock"] = clock
    return X402BatchSettlement(BatchConfig(**kwargs), store, rpc=rpc, **extra)  # type: ignore[arg-type]


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


__all__ = [
    "BLOCKHASH",
    "FEE_PAYER",
    "MINT",
    "NETWORK",
    "OPEN_SLOT",
    "PAYER",
    "PAY_TO",
    "PROGRAM_ID",
    "RECEIVER_AUTHORIZER",
    "SLOT",
    "STRANGER",
    "TOKEN",
    "FakeRpc",
    "b64",
    "channel_account",
    "mint_account",
    "requirements",
    "server",
    "signer",
    "token_account",
]
