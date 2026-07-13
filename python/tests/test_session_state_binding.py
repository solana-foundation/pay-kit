from __future__ import annotations

import base64
import hashlib
import struct
from typing import Any

import pytest
from solders.hash import Hash  # type: ignore[import-untyped]
from solders.keypair import Keypair  # type: ignore[import-untyped]
from solders.message import Message  # type: ignore[import-untyped]
from solders.pubkey import Pubkey  # type: ignore[import-untyped]
from solders.signature import Signature  # type: ignore[import-untyped]
from solders.transaction import Transaction  # type: ignore[import-untyped]

from solana_pay_kit._paycore.errors import PaymentError
from solana_pay_kit._paycore.paymentchannels import PAYMENT_CHANNELS_PROGRAM_ID
from solana_pay_kit._paycore.solana import TOKEN_PROGRAM, resolve_mint
from solana_pay_kit.protocols.mpp._paymentchannels import OpenChannelParams, build_open_instruction, find_channel_pda
from solana_pay_kit.protocols.mpp.intents.session import OpenPayload
from solana_pay_kit.protocols.mpp.server.session import SessionConfig, SessionServer
from solana_pay_kit.protocols.mpp.server.session_method import SessionOptions, new_session
from solana_pay_kit.protocols.mpp.server.session_onchain import (
    confirm_transaction_signature,
    fetch_and_bind_channel_account,
)
from solana_pay_kit.protocols.mpp.server.session_store import (
    ChannelMutator,
    ChannelState,
    ChannelStore,
    ListChannelsFilter,
    MemoryChannelStore,
    ProductionChannelStore,
)
from solana_pay_kit.protocols.programs.paymentchannels.accounts.channel import Channel


def _wallet(seed: int) -> str:
    return str(Keypair.from_seed(bytes([seed] * 32)).pubkey())


def _signature(seed: int) -> str:
    return str(Signature.from_bytes(bytes([seed] * 64)))


class _DelegatingChannelStore(ChannelStore):
    """Process-local stand-in that carries the production marker so it passes
    the off-localnet channel-store policy without being the bundled
    MemoryChannelStore instance the policy rejects."""

    def __init__(self) -> None:
        self._delegate = MemoryChannelStore()

    async def get_channel(self, channel_id: str) -> ChannelState | None:
        return await self._delegate.get_channel(channel_id)

    async def update_channel(self, channel_id: str, mutator: ChannelMutator) -> ChannelState:
        return await self._delegate.update_channel(channel_id, mutator)

    async def delete_channel(self, channel_id: str) -> None:
        await self._delegate.delete_channel(channel_id)

    async def list_channels(self, filter: ListChannelsFilter | None = None) -> list[ChannelState]:
        return await self._delegate.list_channels(filter)

    async def mark_sealed(self, channel_id: str) -> ChannelState:
        return await self._delegate.mark_sealed(channel_id)


class _ProductionChannelStore(_DelegatingChannelStore, ProductionChannelStore):
    """Application-asserted production backend accepted off localnet."""


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


def _open_transaction(*, deposit: int, payer: str, payee: str, signer: str, mint: str) -> tuple[str, str]:
    operator = Keypair.from_seed(bytes([1] * 32))
    payer_keypair = Keypair.from_seed(bytes([4] * 32))
    instruction = build_open_instruction(
        OpenChannelParams(
            payer=Pubkey.from_string(payer),
            rent_payer=operator.pubkey(),
            payee=Pubkey.from_string(payee),
            mint=Pubkey.from_string(mint),
            authorized_signer=Pubkey.from_string(signer),
            salt=7,
            deposit=deposit,
            grace_period=900,
            open_slot=42,
            token_program=Pubkey.from_string(TOKEN_PROGRAM),
        )
    )
    blockhash = Hash.from_string("EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N")
    message = Message.new_with_blockhash([instruction], operator.pubkey(), blockhash)
    transaction = Transaction([operator, payer_keypair], message, blockhash)
    encoded = base64.b64encode(bytes(transaction)).decode("ascii")
    return encoded, str(transaction.signatures[0])


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
    transaction, signature = _open_transaction(
        deposit=4_000, payer=payer, payee=recipient, signer=signer, mint=mint
    )
    rpc.transaction = {"meta": {"err": None}, "transaction": [transaction, "base64"]}
    store = _ProductionChannelStore()
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
        channel_id, "4000", _wallet(5), recipient, mint, 7, 900, 0, signer, signature
    )
    payload.transaction = None
    await session._handle_open(payload, challenge_recent_slot=42)
    state = await store.get_channel(channel_id)
    assert state is not None
    assert state.deposit == 4_000
    assert state.operator == payer
    assert state.open_slot == 42
    assert state.salt == 7


async def test_bare_push_open_rejects_asserted_deposit_mismatch() -> None:
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
    transaction, signature = _open_transaction(
        deposit=4_000, payer=payer, payee=recipient, signer=signer, mint=mint
    )
    rpc.transaction = {"meta": {"err": None}, "transaction": [transaction, "base64"]}
    store = _ProductionChannelStore()
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
        channel_id, "1000", _wallet(5), recipient, mint, 7, 900, 0, signer, signature
    )
    payload.transaction = None

    with pytest.raises(PaymentError, match="asserted deposit"):
        await session._handle_open(payload, challenge_recent_slot=42)
    assert await store.get_channel(channel_id) is None


async def test_bare_push_open_rejects_channel_from_wrong_challenge_incarnation() -> None:
    """A signature-only open must bind the confirmed channel openSlot to the
    challenge recentSlot, even when the payload omits or forges that echo."""
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
    transaction, signature = _open_transaction(
        deposit=4_000, payer=payer, payee=recipient, signer=signer, mint=mint
    )
    rpc.transaction = {"meta": {"err": None}, "transaction": [transaction, "base64"]}
    store = _ProductionChannelStore()
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
        channel_id, "4000", _wallet(10), recipient, mint, 99, 900, 0, signer, signature
    )
    payload.transaction = None
    payload.recent_slot = None

    with pytest.raises(PaymentError, match="recentSlot 43 .*openSlot 42"):
        await session._handle_open(payload, challenge_recent_slot=43)
    assert await store.get_channel(channel_id) is None


async def test_core_direct_construction_rejects_nonlocalnet_bypasses() -> None:
    recipient = _wallet(31)
    payload = OpenPayload.push(_wallet(32), "1000", _wallet(33), _signature(34))
    config = SessionConfig(recipient=recipient, max_cap=10_000, currency="USDC", network="mainnet")

    # The bundled process-local store is rejected at construction off localnet,
    # so a direct SessionServer cannot bypass the factory's store policy.
    with pytest.raises(PaymentError, match="ProductionChannelStore"):
        SessionServer(config, MemoryChannelStore())

    # A production-marked store constructs, but a payment-channel open off
    # localnet still fails closed without the authoritative state verifier: the
    # payload's claimed economics are never persisted as facts.
    store = _ProductionChannelStore()
    with pytest.raises(ValueError, match="requires an authoritative verifier"):
        await SessionServer(config, store).process_open(payload)

    async def signature_only_without_state(_payload: OpenPayload) -> None:
        return None

    # A legacy structural/payload-only verifier does not lift the requirement.
    config.verify_open_tx = signature_only_without_state
    with pytest.raises(ValueError, match="requires an authoritative verifier"):
        await SessionServer(config, store).process_open(payload)

    config.verify_open_state_tx = signature_only_without_state  # type: ignore[assignment]
    with pytest.raises(ValueError, match="authoritative channel facts"):
        await SessionServer(config, store).process_open(payload)


async def test_preloaded_ephemeral_store_cannot_serve_state_operations_off_localnet() -> None:
    config = SessionConfig(recipient=_wallet(51), max_cap=10_000, currency="USDC", network="mainnet")
    # An ephemeral store can never back money-path state operations off localnet
    # because the deployment policy rejects it at construction.
    with pytest.raises(PaymentError, match="ProductionChannelStore"):
        SessionServer(config, MemoryChannelStore())


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
