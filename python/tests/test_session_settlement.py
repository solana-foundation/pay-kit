"""Settlement tests for persisted final session state."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from solders.keypair import Keypair  # type: ignore[import-untyped]

from solana_pay_kit._paycore.errors import PaymentError
from solana_pay_kit.protocols.mpp.server import SessionOptions, new_session
from solana_pay_kit.protocols.mpp.server.session_store import ChannelState
from solana_pay_kit.signer import LocalSigner

BLOCKHASH = "EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N"
SETTLEMENT_SIGNATURE = str(Keypair.from_seed(bytes([99] * 32)).sign_message(b"settle"))


class _Response:
    def __init__(self, value: Any) -> None:
        self.value = value


class _Blockhash:
    def __init__(self) -> None:
        self.blockhash = BLOCKHASH


class _Rpc:
    def __init__(self, *, fail: bool = False, delay: bool = False) -> None:
        self.fail = fail
        self.delay = delay
        self.sent: list[bytes] = []
        self.broadcast = asyncio.Event()
        self.release = asyncio.Event()

    async def get_latest_blockhash(self, commitment: str = "confirmed") -> _Response:
        return _Response(_Blockhash())

    async def send_raw_transaction(self, raw_tx: bytes) -> _Response:
        self.sent.append(raw_tx)
        self.broadcast.set()
        if self.delay:
            await self.release.wait()
        return _Response(SETTLEMENT_SIGNATURE)

    async def get_signature_statuses(self, signatures: list[str]) -> list[dict | None]:
        if self.fail:
            return [{"err": {"InstructionError": [0, "Custom"]}}]
        return [{"err": None, "confirmationStatus": "confirmed"}]


def _session(rpc: _Rpc, merchant: Keypair):
    return new_session(
        SessionOptions(
            recipient=str(merchant.pubkey()),
            amount=25,
            currency="USDC",
            decimals=6,
            network="localnet",
            secret_key="a" * 64,
            signer=LocalSigner.from_keypair(merchant),
            rpc=rpc,  # type: ignore[arg-type]
        )
    )


def _state(*, payer: str, voucher: bool = True) -> ChannelState:
    signer = Keypair.from_seed(bytes([2] * 32))
    channel = str(Keypair.from_seed(bytes([3] * 32)).pubkey())
    return ChannelState(
        channel_id=channel,
        authorized_signer=str(signer.pubkey()),
        payer=payer,
        rent_payer=payer,
        deposit=1_000,
        cumulative=500 if voucher else 0,
        highest_voucher_signature=(str(signer.sign_message(b"voucher")) if voucher else None),
        highest_voucher_expires_at=(4_102_444_800 if voucher else None),
        close_requested_at=1,
    )


async def _seed(session: Any, state: ChannelState) -> None:
    await session.core().store().update_channel(state.channel_id, lambda _: state)


async def test_settlement_broadcasts_and_seals_with_final_voucher() -> None:
    merchant = Keypair.from_seed(bytes([1] * 32))
    rpc = _Rpc()
    session = _session(rpc, merchant)
    state = _state(payer=str(merchant.pubkey()))
    await _seed(session, state)

    signature = await session._settle_channel(state.channel_id)
    stored = await session.core().store().get_channel(state.channel_id)
    assert signature == SETTLEMENT_SIGNATURE
    assert len(rpc.sent) == 1
    assert stored is not None and stored.sealed and stored.settled_signature == signature
    session.shutdown()


async def test_settlement_without_voucher_is_supported_for_idle_close() -> None:
    merchant = Keypair.from_seed(bytes([4] * 32))
    rpc = _Rpc()
    session = _session(rpc, merchant)
    state = _state(payer=str(merchant.pubkey()), voucher=False)
    await _seed(session, state)
    assert await session._settle_channel(state.channel_id) == SETTLEMENT_SIGNATURE
    assert len(rpc.sent) == 1
    session.shutdown()


async def test_failed_settlement_does_not_seal_and_releases_guard() -> None:
    merchant = Keypair.from_seed(bytes([5] * 32))
    rpc = _Rpc(fail=True)
    session = _session(rpc, merchant)
    state = _state(payer=str(merchant.pubkey()))
    await _seed(session, state)
    with pytest.raises(PaymentError, match="failed on-chain"):
        await session._settle_channel(state.channel_id)
    stored = await session.core().store().get_channel(state.channel_id)
    assert stored is not None and not stored.sealed and not stored.settling
    session.shutdown()


async def test_settlement_requires_recorded_payer() -> None:
    merchant = Keypair.from_seed(bytes([6] * 32))
    rpc = _Rpc()
    session = _session(rpc, merchant)
    state = _state(payer="")
    await _seed(session, state)
    with pytest.raises(PaymentError, match="payer is unknown"):
        await session._settle_channel(state.channel_id)
    assert rpc.sent == []
    session.shutdown()


async def test_settlement_distribute_uses_the_recorded_rent_payer() -> None:
    """Non-gasless config: the channel rent was funded by an account that is
    neither the operator nor the payer. The distribute instruction must
    reference the recorded ``rent_payer`` — the on-chain check pins to it, so
    building with any other account makes the settle bundle revert forever."""
    from solders.transaction import Transaction

    merchant = Keypair.from_seed(bytes([8] * 32))
    rent_payer = Keypair.from_seed(bytes([9] * 32))
    rpc = _Rpc()
    session = _session(rpc, merchant)
    state = _state(payer=str(Keypair.from_seed(bytes([10] * 32)).pubkey()))
    state.rent_payer = str(rent_payer.pubkey())
    await _seed(session, state)

    assert await session._settle_channel(state.channel_id) == SETTLEMENT_SIGNATURE
    assert len(rpc.sent) == 1
    keys = [str(key) for key in Transaction.from_bytes(rpc.sent[0]).message.account_keys]
    assert str(rent_payer.pubkey()) in keys
    session.shutdown()


async def test_concurrent_settlement_broadcasts_once() -> None:
    merchant = Keypair.from_seed(bytes([7] * 32))
    rpc = _Rpc(delay=True)
    session = _session(rpc, merchant)
    state = _state(payer=str(merchant.pubkey()))
    await _seed(session, state)
    first = asyncio.create_task(session._settle_channel(state.channel_id))
    await rpc.broadcast.wait()
    second = await session._settle_channel(state.channel_id)
    assert second is None
    rpc.release.set()
    assert await first == SETTLEMENT_SIGNATURE
    assert len(rpc.sent) == 1
    session.shutdown()
