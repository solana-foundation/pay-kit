"""A fake Solana chain and client builders for the x402 ``batch-settlement`` server tests.

``FakeChain`` implements the ``SolanaRpc`` surface the engine and redemption
worker use, over an in-memory account map. Sending a transaction marks its
signature confirmed and runs the scripted effect for it, so tests control
exactly what "landed" means. Channel accounts use the program's account-type
byte 1 (``state/common.rs``: ``Channel = 1``).
"""

from __future__ import annotations

import base64
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, cast

from solders.hash import Hash
from solders.instruction import Instruction
from solders.keypair import Keypair
from solders.message import MessageV0, to_bytes_versioned
from solders.pubkey import Pubkey
from solders.signature import Signature
from solders.transaction import VersionedTransaction

from solana_pay_kit import Gate, LocalSigner, Operator, Price, Protocol, Stablecoin, configure
from solana_pay_kit._paycore.errors import PaymentError
from solana_pay_kit._paycore.paymentchannels import (
    PAYMENT_CHANNELS_PROGRAM_ID,
    Distribution,
    OpenChannelParams,
    TopUpParams,
    build_open_instruction,
    build_request_close_instruction,
    build_top_up_instruction,
    distribution_hash,
    find_associated_token_address,
    find_channel_pda,
    treasury_owner,
)
from solana_pay_kit._paycore.solana import MEMO_PROGRAM, TOKEN_PROGRAM
from solana_pay_kit.config import Config
from solana_pay_kit.protocols.programs.paymentchannels.accounts.channel import Channel
from solana_pay_kit.protocols.x402.batch_settlement.signatures import sign_voucher
from solana_pay_kit.protocols.x402.batch_settlement.types import BatchChannelConfig, BatchRequirements

BLOCKHASH = str(Hash.new_unique())
SLOT = 341_000_000
MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"  # localnet resolves USDC to the mainnet mint
NONCE = "0123456789abcdef0123456789abcdef"
PRICE = 10_000  # $0.01 in USDC atomic units

OPEN, SEALED, CLOSING, DISTRIBUTED = 0, 1, 2, 3


def token_account(mint: str, owner: str, *, state: int = 1, extra: bytes = b"") -> bytes:
    """An SPL token account (165 bytes) plus an optional Token-2022 tail."""
    data = bytearray(165)
    data[0:32] = bytes(Pubkey.from_string(mint))
    data[32:64] = bytes(Pubkey.from_string(owner))
    data[108] = state
    return bytes(data) + extra


def channel_account(
    config: BatchChannelConfig,
    fee_payer: str,
    pay_to: str,
    *,
    deposit: int,
    settled: int = 0,
    payout: int = 0,
    status: int = OPEN,
    closure_started_at: int = 0,
) -> bytes:
    """A ``Channel`` account matching ``config`` (account-type byte 1)."""
    body = Channel.layout.build(
        {
            "version": 1,
            "bump": 255,
            "status": status,
            "salt": int(config["salt"]),
            "deposit": deposit,
            "settlement": {"settled": settled, "payoutWatermark": payout},
            "closureStartedAt": closure_started_at,
            "payerWithdrawnAt": 0,
            "gracePeriod": config["withdrawDelay"],
            "distributionHash": list(distribution_hash([Distribution(Pubkey.from_string(pay_to), 10_000)])),
            "payer": Pubkey.from_string(config["payer"]),
            "payee": Pubkey.from_string(fee_payer),
            "authorizedSigner": Pubkey.from_string(config["payerAuthorizer"]),
            "mint": Pubkey.from_string(config["token"]),
            "rentPayer": Pubkey.from_string(fee_payer),
            "openSlot": config["openSlot"],
        }
    )
    return bytes([1]) + bytes(body)


@dataclass
class FakeChain:
    """In-memory ``SolanaRpc`` stand-in."""

    accounts: dict[str, tuple[bytes, str]] = field(default_factory=lambda: {})
    statuses: dict[str, dict[str, Any]] = field(default_factory=lambda: {})
    sent: list[VersionedTransaction] = field(default_factory=lambda: [])
    simulated: list[bytes] = field(default_factory=lambda: [])
    simulation_error: object = None
    slot: int = SLOT + 10
    account_reads: int = 0
    # Channel reads that answer "absent" before the account becomes visible.
    lagging_reads: int = 0
    effects: list[Callable[[VersionedTransaction], None]] = field(default_factory=lambda: [])
    confirm_error: PaymentError | None = None
    send_error: PaymentError | None = None
    program_accounts: list[tuple[str, bytes]] = field(default_factory=lambda: [])
    # The getLatestBlockhash context slot, when it differs from ``slot`` (getSlot).
    blockhash_slot: int | None = None
    # What isBlockhashValid answers.
    blockhash_valid: bool = True

    def _read(self, address: str) -> tuple[bytes, str] | None:
        self.account_reads += 1
        account = self.accounts.get(address)
        if account is not None and account[1] == PAYMENT_CHANNELS_PROGRAM_ID and self.lagging_reads > 0:
            self.lagging_reads -= 1
            return None
        return account

    async def get_account_info(self, address: str, commitment: str = "confirmed") -> tuple[bytes, str] | None:
        return self._read(address)

    async def get_multiple_accounts(self, addresses: list[str], commitment: str = "confirmed") -> list[Any]:
        return [self._read(address) for address in addresses]

    async def get_signature_statuses(self, signatures: list[str]) -> list[Any]:
        return [self.statuses.get(signature) for signature in signatures]

    async def send_raw_transaction(self, raw: bytes) -> Any:
        if self.send_error is not None:
            raise self.send_error
        tx = VersionedTransaction.from_bytes(raw)
        self.sent.append(tx)
        self.statuses[str(tx.signatures[0])] = {"confirmationStatus": "confirmed", "err": None}
        if self.effects:
            self.effects.pop(0)(tx)
        return str(tx.signatures[0])

    async def await_confirmation(self, signature: str, *_: Any, **__: Any) -> None:
        if self.confirm_error is not None:
            raise self.confirm_error

    async def simulate_transaction(self, raw: bytes, commitment: str = "confirmed") -> dict[str, Any]:
        self.simulated.append(raw)
        return {"err": self.simulation_error, "logs": ["log"]}

    async def get_slot(self, commitment: str = "confirmed") -> int:
        return self.slot

    async def get_latest_blockhash(self, commitment: str = "confirmed") -> Any:
        slot = self.blockhash_slot if self.blockhash_slot is not None else self.slot

        class _Value:
            blockhash = BLOCKHASH

        class _Context:
            pass

        class _Response:
            value = _Value()
            context = _Context()

        _Response.context.slot = slot  # type: ignore[attr-defined]
        return _Response()

    async def is_blockhash_valid(self, blockhash: str, commitment: str = "confirmed") -> bool:
        return self.blockhash_valid

    async def get_program_accounts(self, program_id: str, **_: Any) -> list[tuple[str, bytes]]:
        return self.program_accounts

    async def aclose(self) -> None:
        return None


@dataclass
class World:
    """A configured server, its fake chain, and one paying client."""

    config: Config
    chain: FakeChain
    fee_payer: LocalSigner
    pay_to: str
    payer: LocalSigner
    gate: Gate

    def channel_config(self, **overrides: Any) -> BatchChannelConfig:
        config: dict[str, Any] = {
            "payer": self.payer.pubkey(),
            "payerAuthorizer": self.payer.pubkey(),
            "receiver": self.pay_to,
            "token": MINT,
            "withdrawDelay": 900,
            "salt": "0",
            "openSlot": SLOT,
        }
        config.update(overrides)
        return cast("BatchChannelConfig", config)

    def channel_id(self, config: BatchChannelConfig | None = None) -> str:
        config = config or self.channel_config()
        pda, _ = find_channel_pda(
            Pubkey.from_string(config["payer"]),
            Pubkey.from_string(self.fee_payer.pubkey()),
            Pubkey.from_string(config["token"]),
            Pubkey.from_string(config["payerAuthorizer"]),
            int(config["salt"]),
            config["openSlot"],
        )
        return str(pda)

    def put_channel(self, config: BatchChannelConfig | None = None, **fields: Any) -> str:
        config = config or self.channel_config()
        channel_id = self.channel_id(config)
        data = channel_account(config, self.fee_payer.pubkey(), self.pay_to, **fields)
        self.chain.accounts[channel_id] = (data, PAYMENT_CHANNELS_PROGRAM_ID)
        return channel_id

    def signed(self, instructions: list[Instruction]) -> str:
        """A v0 transaction paid by the server's fee payer and signed by the client payer."""
        message = MessageV0.try_compile(
            Pubkey.from_string(self.fee_payer.pubkey()), instructions, [], Hash.new_unique()
        )
        signers = list(message.account_keys)[: int(message.header.num_required_signatures)]
        signatures = [Signature.default()] * len(signers)
        payer_key = Pubkey.from_string(self.payer.pubkey())
        signatures[signers.index(payer_key)] = Signature.from_bytes(self.payer.sign(bytes(to_bytes_versioned(message))))
        return base64.b64encode(bytes(VersionedTransaction.populate(message, signatures))).decode()

    def open_tx(self, deposit: int, config: BatchChannelConfig | None = None) -> str:
        config = config or self.channel_config()
        ix = build_open_instruction(
            OpenChannelParams(
                payer=Pubkey.from_string(config["payer"]),
                rent_payer=Pubkey.from_string(self.fee_payer.pubkey()),
                payee=Pubkey.from_string(self.fee_payer.pubkey()),
                mint=Pubkey.from_string(config["token"]),
                authorized_signer=Pubkey.from_string(config["payerAuthorizer"]),
                salt=int(config["salt"]),
                deposit=deposit,
                grace_period=config["withdrawDelay"],
                open_slot=config["openSlot"],
                recipients=[Distribution(Pubkey.from_string(self.pay_to), 10_000)],
            )
        )
        return self.signed([ix, memo()])

    def top_up_tx(self, amount: int, config: BatchChannelConfig | None = None) -> str:
        channel = Pubkey.from_string(self.channel_id(config))
        ix = build_top_up_instruction(
            TopUpParams(
                payer=Pubkey.from_string(self.payer.pubkey()),
                channel=channel,
                mint=Pubkey.from_string(MINT),
                amount=amount,
            )
        )
        return self.signed([ix, memo()])

    def request_close_tx(self, config: BatchChannelConfig | None = None) -> str:
        channel = Pubkey.from_string(self.channel_id(config))
        return self.signed(
            [build_request_close_instruction(payer=Pubkey.from_string(self.payer.pubkey()), channel=channel), memo()]
        )

    def lands_as_channel(self, config: BatchChannelConfig | None = None, **fields: Any) -> None:
        """Script the next send to create/overwrite the channel account."""

        def land(_tx: VersionedTransaction) -> None:
            self.put_channel(config, **fields)

        self.chain.effects.append(land)

    def header(self, requirement: BatchRequirements, payload: dict[str, Any]) -> dict[str, Any]:
        envelope = {"x402Version": 2, "accepted": requirement, "payload": payload}
        encoded = base64.b64encode(json.dumps(envelope).encode()).decode()
        return {"headers": {"payment-signature": encoded}, "path": "/batch"}

    def deposit_payload(
        self, deposit: int, cumulative: int, *, transaction: str | None = None, config: BatchChannelConfig | None = None
    ) -> dict[str, Any]:
        config = config or self.channel_config()
        return {
            "type": "deposit",
            "channelConfig": config,
            "deposit": {"amount": str(deposit), "transaction": transaction or self.open_tx(deposit, config)},
            "voucher": sign_voucher(self.payer, self.channel_id(config), cumulative),
        }

    def voucher_payload(self, cumulative: int, config: BatchChannelConfig | None = None) -> dict[str, Any]:
        config = config or self.channel_config()
        return {
            "type": "voucher",
            "channelConfig": config,
            "voucher": sign_voucher(self.payer, self.channel_id(config), cumulative),
        }


def memo(text: str = NONCE) -> Instruction:
    return Instruction(Pubkey.from_string(MEMO_PROGRAM), text.encode(), [])


def make_world(monkeypatch: Any, **config_overrides: Any) -> World:
    """A localnet server with a funded-looking chain: mint and every settlement ATA exist."""
    monkeypatch.setenv("PAY_KIT_DISABLE_PREFLIGHT", "1")
    fee_payer = LocalSigner.from_keypair(Keypair.from_seed(bytes([2] * 32)))
    pay_to = str(Keypair.from_seed(bytes([3] * 32)).pubkey())
    payer = LocalSigner.from_keypair(Keypair.from_seed(bytes([1] * 32)))
    config = configure(
        network="solana_localnet",
        preflight=False,
        accept=(Protocol.X402,),
        operator=Operator(signer=fee_payer, recipient=pay_to),
        rpc_url="http://127.0.0.1:8899",
        **config_overrides,
    )
    chain = FakeChain()
    chain.accounts[MINT] = (b"\x00" * 82, TOKEN_PROGRAM)
    program = Pubkey.from_string(TOKEN_PROGRAM)
    for owner in (fee_payer.pubkey(), str(treasury_owner()), pay_to, payer.pubkey()):
        ata, _ = find_associated_token_address(Pubkey.from_string(owner), Pubkey.from_string(MINT), program)
        chain.accounts[str(ata)] = (token_account(MINT, owner), TOKEN_PROGRAM)
    gate = Gate.build(
        name="batch", amount=Price.usd("0.01", Stablecoin.USDC), default_pay_to=pay_to, accept=(Protocol.X402,)
    )
    return World(config, chain, fee_payer, pay_to, payer, gate)
