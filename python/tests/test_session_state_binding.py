from __future__ import annotations

import hashlib
import struct
from typing import Any

import pytest
from solders.keypair import Keypair  # type: ignore[import-untyped]
from solders.pubkey import Pubkey  # type: ignore[import-untyped]
from solders.signature import Signature  # type: ignore[import-untyped]

from solana_pay_kit._paycore.errors import PaymentError
from solana_pay_kit._paycore.paymentchannels import PAYMENT_CHANNELS_PROGRAM_ID
from solana_pay_kit._paycore.solana import resolve_mint
from solana_pay_kit.protocols.mpp._paymentchannels import find_channel_pda
from solana_pay_kit.protocols.mpp.intents.session import OpenPayload, TopUpPayload
from solana_pay_kit.protocols.mpp.server.session import DeliveryRequest, SessionConfig, SessionServer
from solana_pay_kit.protocols.mpp.server.session_method import SessionOptions, new_session
from solana_pay_kit.protocols.mpp.server.session_onchain import (
    confirm_transaction_signature,
    fetch_and_bind_channel_account,
    new_top_up_state_tx_verifier,
)
from solana_pay_kit.protocols.mpp.server.session_store import (
    ChannelState,
    MemoryChannelStore,
    SessionStoreDurability,
)
from solana_pay_kit.protocols.programs.paymentchannels.accounts.channel import Channel


def _wallet(seed: int) -> str:
    return str(Keypair.from_seed(bytes([seed] * 32)).pubkey())


def _signature(seed: int) -> str:
    return str(Signature.from_bytes(bytes([seed] * 64)))


def _channel_bytes(
    *,
    deposit: int,
    payer: str,
    payee: str,
    signer: str,
    mint: str,
    status: int = 0,
    settled: int = 0,
    payout_watermark: int = 0,
    grace_period: int = 900,
    distribution_hash: bytes | None = None,
) -> bytes:
    if distribution_hash is None:
        distribution_hash = hashlib.sha256(struct.pack("<I", 0)).digest()
    body = Channel.layout.build(
        {
            "version": 1,
            "bump": 255,
            "status": status,
            "salt": 7,
            "deposit": deposit,
            "settlement": {"settled": settled, "payoutWatermark": payout_watermark},
            "closureStartedAt": 0,
            "payerWithdrawnAt": 0,
            "gracePeriod": grace_period,
            "distributionHash": list(distribution_hash),
            "payer": Pubkey.from_string(payer),
            "payee": Pubkey.from_string(payee),
            "authorizedSigner": Pubkey.from_string(signer),
            "mint": Pubkey.from_string(mint),
            "rentPayer": Pubkey.from_string(payee),
            "openSlot": 42,
        }
    )
    return bytes([1]) + bytes(body)


class _Rpc:
    def __init__(self) -> None:
        self.accounts: dict[str, tuple[bytes, str] | None] = {}
        self.status: dict | None = {"err": None, "confirmationStatus": "confirmed", "slot": 42}
        self.transaction: dict | None = None
        self.min_context_slot: int | None = None

    async def get_account_info(
        self, address: str, commitment: str = "confirmed", min_context_slot: int | None = None
    ) -> tuple[bytes, str] | None:
        self.min_context_slot = min_context_slot
        return self.accounts.get(address)

    async def get_signature_statuses(self, signatures: list[str]) -> list[dict | None]:
        return [self.status for _ in signatures]

    async def get_transaction(self, signature: str, **kwargs):  # noqa: ANN003, ANN201
        return self.transaction

    async def get_latest_blockhash(self, commitment: str = "confirmed"):  # noqa: ANN201
        raise NotImplementedError

    async def send_raw_transaction(self, raw_tx: bytes):  # noqa: ANN201
        raise NotImplementedError


async def test_bare_push_open_persists_authoritative_channel_deposit_and_payer() -> None:
    rpc = _Rpc()
    recipient = _wallet(1)
    signer = _wallet(3)
    payer = _wallet(4)
    mint = resolve_mint("USDC", "mainnet")
    assert mint is not None
    channel_id = str(
        find_channel_pda(
            Pubkey.from_string(payer),
            Pubkey.from_string(recipient),
            Pubkey.from_string(mint),
            Pubkey.from_string(signer),
            7,
            42,
            Pubkey.from_string(PAYMENT_CHANNELS_PROGRAM_ID),
        )[0]
    )
    rpc.accounts[channel_id] = (
        _channel_bytes(deposit=4_000, payer=payer, payee=recipient, signer=signer, mint=mint),
        PAYMENT_CHANNELS_PROGRAM_ID,
    )
    store = MemoryChannelStore()
    store.session_store_durability = SessionStoreDurability.DURABLE_SHARED
    session = new_session(
        SessionOptions(
            operator=recipient,
            recipient=recipient,
            cap=10_000,
            currency="USDC",
            network="mainnet",
            secret_key="test-secret",
            realm="api.test",
            rpc=rpc,
            store=store,
        )
    )
    payload = OpenPayload.payment_channel(
        channel_id, "1000", _wallet(5), recipient, mint, 7, 900, 0, signer, _signature(6)
    )
    payload.transaction = None
    await session._handle_open(payload)
    state = await store.get_channel(channel_id)
    assert state is not None
    assert state.deposit == 4_000
    assert state.operator == payer
    assert state.open_slot == 42
    assert state.salt == 7


async def test_top_up_binds_resulting_deposit_and_open_status() -> None:
    rpc = _Rpc()
    recipient = _wallet(11)
    channel_id = _wallet(12)
    signer = _wallet(13)
    payer = _wallet(14)
    mint = resolve_mint("USDC", "localnet")
    assert mint is not None
    config = SessionConfig(
        recipient=recipient,
        max_cap=10_000,
        currency="USDC",
        network="localnet",
        operator=recipient,
    )
    verifier = new_top_up_state_tx_verifier(config, rpc)
    assert verifier is not None
    payload = TopUpPayload(channel_id=channel_id, new_deposit="3000", signature=_signature(15))
    current = ChannelState(channel_id=channel_id, authorized_signer=signer, deposit=1_000, operator=payer)

    rpc.accounts[channel_id] = (
        _channel_bytes(deposit=2_000, payer=payer, payee=recipient, signer=signer, mint=mint),
        PAYMENT_CHANNELS_PROGRAM_ID,
    )
    current.authorized_signer = _wallet(16)
    with pytest.raises(PaymentError, match="authorized signer does not match stored"):
        await verifier(payload, current)
    current.authorized_signer = signer
    with pytest.raises(PaymentError, match="!= asserted newDeposit 3000"):
        await verifier(payload, current)

    rpc.accounts[channel_id] = (
        _channel_bytes(deposit=3_000, payer=payer, payee=recipient, signer=signer, mint=mint, status=1),
        PAYMENT_CHANNELS_PROGRAM_ID,
    )
    with pytest.raises(PaymentError, match="not open on-chain"):
        await verifier(payload, current)


async def test_top_up_fails_closed_without_rpc_off_localnet() -> None:
    config = SessionConfig(recipient=_wallet(21), currency="USDC", network="mainnet")
    verifier = new_top_up_state_tx_verifier(config, None)
    assert verifier is not None
    with pytest.raises(PaymentError, match="requires an rpc client") as error:
        await verifier(
            TopUpPayload(channel_id=_wallet(22), new_deposit="2", signature=_signature(23)),
            ChannelState(channel_id=_wallet(22), authorized_signer=_wallet(24), operator=_wallet(25)),
        )
    assert error.value.code == "invalid-config"


async def test_core_direct_construction_rejects_nonlocalnet_bypasses() -> None:
    recipient = _wallet(31)
    payload = OpenPayload.push(_wallet(32), "1000", _wallet(33), _signature(34))
    memory = MemoryChannelStore()
    config = SessionConfig(recipient=recipient, max_cap=10_000, currency="USDC", network="mainnet")
    with pytest.raises(ValueError, match="ephemeral"):
        await SessionServer(config, memory).process_open(payload)

    memory.session_store_durability = SessionStoreDurability.DURABLE_SHARED
    with pytest.raises(ValueError, match="requires an on-chain verifier"):
        await SessionServer(config, memory).process_open(payload)
    await memory.update_channel(
        "topup",
        lambda _: ChannelState(channel_id="topup", authorized_signer=_wallet(34), deposit=1_000, operator=_wallet(35)),
    )

    async def legacy_top_up_only(_payload: TopUpPayload) -> None:
        return None

    config.verify_top_up_tx = legacy_top_up_only
    with pytest.raises(ValueError, match="state-aware on-chain verifier"):
        await SessionServer(config, memory).process_top_up(
            TopUpPayload(channel_id="topup", new_deposit="2000", signature=_signature(36))
        )

    class UnmarkedStore(MemoryChannelStore):
        session_store_durability = None

    with pytest.raises(ValueError, match="explicitly declare durable shared"):
        await SessionServer(config, UnmarkedStore()).process_open(payload)


async def test_preloaded_ephemeral_store_cannot_serve_state_operations_off_localnet() -> None:
    config = SessionConfig(recipient=_wallet(51), max_cap=10_000, currency="USDC", network="mainnet")
    server = SessionServer(config, MemoryChannelStore())
    with pytest.raises(ValueError, match="ephemeral session store"):
        await server.begin_delivery(DeliveryRequest(session_id="preloaded", amount=1))
    with pytest.raises(ValueError, match="ephemeral session store"):
        await server.mark_sealed("preloaded")


async def test_processed_signature_rejected_and_account_read_is_slot_pinned() -> None:
    rpc = _Rpc()
    rpc.status = {"err": None, "confirmationStatus": "processed", "slot": 88}
    with pytest.raises(PaymentError, match="not confirmed"):
        await confirm_transaction_signature(rpc, _signature(35), "open", timeout_seconds=0)

    for invalid_slot in (None, -1, True, "88"):
        rpc.status = {"err": None, "confirmationStatus": "confirmed", "slot": invalid_slot}
        with pytest.raises(PaymentError, match="confirmation response has an invalid slot"):
            await confirm_transaction_signature(rpc, _signature(35), "open", timeout_seconds=0)

    rpc.status = {"err": None, "confirmationStatus": "confirmed", "slot": 88}
    recipient = _wallet(36)
    signer = _wallet(38)
    payer = _wallet(39)
    mint = resolve_mint("USDC", "mainnet")
    assert mint is not None
    channel_id = str(
        find_channel_pda(
            Pubkey.from_string(payer),
            Pubkey.from_string(recipient),
            Pubkey.from_string(mint),
            Pubkey.from_string(signer),
            7,
            42,
            Pubkey.from_string(PAYMENT_CHANNELS_PROGRAM_ID),
        )[0]
    )
    rpc.accounts[channel_id] = (
        _channel_bytes(deposit=2_000, payer=payer, payee=recipient, signer=signer, mint=mint),
        PAYMENT_CHANNELS_PROGRAM_ID,
    )
    await fetch_and_bind_channel_account(
        rpc,
        channel_id,
        program_id=None,
        max_cap=10_000,
        expected_authorized_signer=signer,
        expected_payee=recipient,
        expected_mint=mint,
        expected_operator=recipient,
        min_context_slot=88,
    )
    assert rpc.min_context_slot == 88


async def test_channel_account_rejects_invalid_discriminator_version_and_length() -> None:
    rpc = _Rpc()
    recipient = _wallet(41)
    channel_id = _wallet(42)
    signer = _wallet(43)
    payer = _wallet(44)
    mint = resolve_mint("USDC", "mainnet")
    assert mint is not None
    valid = _channel_bytes(deposit=2_000, payer=payer, payee=recipient, signer=signer, mint=mint)
    malformed = [bytes([9]) + valid[1:], valid[:1] + bytes([9]) + valid[2:], valid[:-1]]
    for data in malformed:
        rpc.accounts[channel_id] = (data, PAYMENT_CHANNELS_PROGRAM_ID)
        with pytest.raises(PaymentError):
            await fetch_and_bind_channel_account(
                rpc,
                channel_id,
                program_id=None,
                max_cap=10_000,
                expected_authorized_signer=signer,
                expected_payee=recipient,
                expected_mint=mint,
                expected_operator=recipient,
                min_context_slot=1,
            )


@pytest.mark.parametrize(
    "overrides",
    [
        {"settled": 1},
        {"payout_watermark": 1},
        {"grace_period": 901},
        {"distribution_hash": bytes([0xAA] * 32)},
    ],
)
async def test_channel_account_rejects_spent_or_economically_mismatched_state(
    overrides: dict[str, Any],
) -> None:
    rpc = _Rpc()
    recipient = _wallet(61)
    channel_id = _wallet(62)
    signer = _wallet(63)
    payer = _wallet(64)
    mint = resolve_mint("USDC", "mainnet")
    assert mint is not None
    rpc.accounts[channel_id] = (
        _channel_bytes(deposit=2_000, payer=payer, payee=recipient, signer=signer, mint=mint, **overrides),
        PAYMENT_CHANNELS_PROGRAM_ID,
    )
    with pytest.raises(PaymentError):
        await fetch_and_bind_channel_account(
            rpc,
            channel_id,
            program_id=None,
            max_cap=10_000,
            expected_authorized_signer=signer,
            expected_payee=recipient,
            expected_mint=mint,
            expected_operator=recipient,
            min_context_slot=1,
        )
