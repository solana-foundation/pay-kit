"""On-chain settle-at-close: a close with a signer + RPC broadcasts a
settle_and_finalize (+ Ed25519 precompile when a voucher was recorded) and a
distribute instruction, then records the settlement signature and finalizes.
Mirrors the Go/TS closeAndSettleChannel path.
"""

from __future__ import annotations

from typing import Any

import pytest
from solders.keypair import Keypair  # type: ignore[import-untyped]
from solders.transaction import Transaction  # type: ignore[import-untyped]

from pay_kit.protocols.mpp.server import SessionOptions, new_session
from pay_kit.protocols.mpp.server.session_store import ChannelState
from pay_kit.signer import LocalSigner

_BLOCKHASH = "EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N"
# A valid base58 signature the fake RPC returns; the open path confirms it.
_SENT_SIGNATURE = str(Keypair.from_seed(bytes([99] * 32)).sign_message(b"settle"))


class _Resp:
    def __init__(self, value: Any) -> None:
        self.value = value


class _Blockhash:
    def __init__(self, blockhash: str) -> None:
        self.blockhash = blockhash


class _SettleRpc:
    """Captures the broadcast settle transaction and returns a fixed signature."""

    def __init__(self) -> None:
        self.sent: list[bytes] = []

    async def get_signature_statuses(self, signatures: list[str]) -> list[dict | None]:
        return [{"err": None, "confirmationStatus": "confirmed"} for _ in signatures]

    async def get_latest_blockhash(self, commitment: str = "confirmed") -> _Resp:
        return _Resp(_Blockhash(_BLOCKHASH))

    async def send_raw_transaction(self, raw_tx: bytes) -> _Resp:
        self.sent.append(raw_tx)
        return _Resp(_SENT_SIGNATURE)


def _session(rpc: _SettleRpc, operator: Keypair):
    return new_session(
        SessionOptions(
            operator=str(operator.pubkey()),
            recipient=str(operator.pubkey()),
            cap=1_000_000,
            currency="USDC",
            decimals=6,
            network="localnet",
            secret_key="a" * 64,
            modes=["pull"],
            pull_voucher_strategy="clientVoucher",
            signer=LocalSigner.from_keypair(operator),
            rpc=rpc,
        )
    )


async def _seed(session, state: ChannelState) -> None:
    await session._core.store().update_channel(state.channel_id, lambda _current: state)


def _instruction_discriminators(raw_tx: bytes) -> list[int]:
    msg = Transaction.from_bytes(raw_tx).message
    return [bytes(ix.data)[0] for ix in msg.instructions]


@pytest.mark.asyncio
async def test_close_settles_with_voucher_and_records_signature() -> None:
    operator = Keypair.from_seed(bytes([1] * 32))
    auth = Keypair.from_seed(bytes([2] * 32))
    channel = str(Keypair.from_seed(bytes([3] * 32)).pubkey())
    voucher_sig = str(auth.sign_message(b"voucher"))

    rpc = _SettleRpc()
    session = _session(rpc, operator)
    await _seed(
        session,
        ChannelState(
            channel_id=channel,
            authorized_signer=str(auth.pubkey()),
            deposit=1_000_000,
            cumulative=500_000,
            highest_voucher_signature=voucher_sig,
            highest_voucher_expires_at=4_102_444_800,
            operator=str(operator.pubkey()),
        ),
    )

    settled = await session._settle_channel(channel)

    assert settled == _SENT_SIGNATURE
    final = await session._core.store().get_channel(channel)
    assert final is not None
    assert final.finalized is True
    assert final.settled_signature == settled
    # Exactly one tx, instructions [ed25519(1), settleAndFinalize(4), distribute(7)].
    assert len(rpc.sent) == 1
    assert _instruction_discriminators(rpc.sent[0]) == [1, 4, 7]


@pytest.mark.asyncio
async def test_close_without_voucher_omits_ed25519_precompile() -> None:
    operator = Keypair.from_seed(bytes([4] * 32))
    channel = str(Keypair.from_seed(bytes([5] * 32)).pubkey())

    rpc = _SettleRpc()
    session = _session(rpc, operator)
    await _seed(
        session,
        ChannelState(
            channel_id=channel,
            authorized_signer=str(operator.pubkey()),
            deposit=1_000_000,
            cumulative=0,
            operator=str(operator.pubkey()),
        ),
    )

    await session._settle_channel(channel)

    # No voucher recorded: just [settleAndFinalize(4), distribute(7)].
    assert _instruction_discriminators(rpc.sent[0]) == [4, 7]


@pytest.mark.asyncio
async def test_settle_is_noop_without_signer_or_rpc() -> None:
    operator = Keypair.from_seed(bytes([6] * 32))
    session = new_session(
        SessionOptions(
            operator=str(operator.pubkey()),
            recipient=str(operator.pubkey()),
            cap=1_000_000,
            currency="USDC",
            decimals=6,
            network="localnet",
            secret_key="a" * 64,
            modes=["pull"],
            pull_voucher_strategy="clientVoucher",
        )
    )
    channel = str(Keypair.from_seed(bytes([7] * 32)).pubkey())
    await _seed(
        session,
        ChannelState(
            channel_id=channel, authorized_signer=str(operator.pubkey()), deposit=1, operator=str(operator.pubkey())
        ),
    )
    assert await session._settle_channel(channel) is None


# --- A4: server-broadcast open --------------------------------------------------


def _server_open_payload(operator: Keypair):
    from pay_kit.protocols.mpp.client.payment_channels import (
        PENDING_SERVER_SIGNATURE,
        PaymentChannelOpenOptions,
        derive_payment_channel_open,
    )
    from pay_kit.protocols.mpp.intents.session import SessionRequest

    auth = Keypair.from_seed(bytes([9] * 32))
    request = SessionRequest(
        cap="1000000",
        currency="USDC",
        operator=str(operator.pubkey()),
        recipient=str(operator.pubkey()),
        decimals=6,
        network="localnet",
        modes=["pull"],
        pull_voucher_strategy="clientVoucher",
    )
    open_ = derive_payment_channel_open(request, operator.pubkey(), auth.pubkey(), PaymentChannelOpenOptions(salt=42))
    return open_, open_.open_payload("pull", PENDING_SERVER_SIGNATURE)


@pytest.mark.asyncio
async def test_server_broadcast_open_builds_signs_and_persists() -> None:
    operator = Keypair.from_seed(bytes([8] * 32))
    rpc = _SettleRpc()
    session = new_session(
        SessionOptions(
            operator=str(operator.pubkey()),
            recipient=str(operator.pubkey()),
            cap=1_000_000,
            currency="USDC",
            decimals=6,
            network="localnet",
            secret_key="a" * 64,
            modes=["pull"],
            pull_voucher_strategy="clientVoucher",
            open_tx_submitter="server",
            signer=LocalSigner.from_keypair(operator),
            rpc=rpc,
        )
    )
    open_, payload = _server_open_payload(operator)

    signature = await session._handle_open(payload)

    assert signature == _SENT_SIGNATURE
    # One open transaction broadcast, a single open instruction (discriminator 1).
    assert len(rpc.sent) == 1
    assert _instruction_discriminators(rpc.sent[0]) == [1]
    # The channel is persisted under its derived id.
    persisted = await session._core.store().get_channel(str(open_.channel_id))
    assert persisted is not None


@pytest.mark.asyncio
async def test_server_open_requires_signer_and_rpc() -> None:
    operator = Keypair.from_seed(bytes([10] * 32))
    session = new_session(
        SessionOptions(
            operator=str(operator.pubkey()),
            recipient=str(operator.pubkey()),
            cap=1_000_000,
            currency="USDC",
            decimals=6,
            network="localnet",
            secret_key="a" * 64,
            modes=["pull"],
            pull_voucher_strategy="clientVoucher",
            open_tx_submitter="server",
        )
    )
    _open, payload = _server_open_payload(operator)
    with pytest.raises(Exception, match="requires a signer"):
        await session._handle_open(payload)
