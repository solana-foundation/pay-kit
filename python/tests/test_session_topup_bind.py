"""Regression coverage for the in-core top-up deposit bind.

The exported core ``process_top_up`` must not trust a client-asserted
``new_deposit``: the shipped top-up seam fetches the on-chain ``Channel``
account and requires its deposit to have actually reached ``new_deposit``,
failing closed off localnet. These tests exercise the seam directly through
``process_top_up`` and through the production-wired ``Session`` dispatcher.

Mirrors ``go/protocols/mpp/server/session_topup_bind_test.go``.
"""

from __future__ import annotations

import pytest
from solders.keypair import Keypair  # type: ignore[import-untyped]
from solders.pubkey import Pubkey  # type: ignore[import-untyped]
from solders.signature import Signature  # type: ignore[import-untyped]

from solana_pay_kit._paycore.errors import PaymentError
from solana_pay_kit.protocols.mpp.intents.session import OpenPayload, SessionAction, TopUpPayload
from solana_pay_kit.protocols.mpp.server.session import SessionConfig, SessionServer
from solana_pay_kit.protocols.mpp.server.session_method import SessionOptions, new_session
from solana_pay_kit.protocols.mpp.server.session_onchain import (
    fetch_and_bind_channel_account,
    new_top_up_tx_verifier,
)
from solana_pay_kit.protocols.mpp.server.session_store import ChannelState, MemoryChannelStore

SESSION_METHOD_SECRET = "session-method-secret"
SESSION_TEST_RECIPIENT = str(Keypair.from_seed(bytes([7] * 32)).pubkey())
SESSION_TEST_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"


class _TestVoucherSigner:
    def __init__(self, seed: int) -> None:
        self._kp = Keypair.from_seed(bytes([seed] * 32))

    def address(self) -> str:
        return str(self._kp.pubkey())


def _new_wallet() -> str:
    import secrets

    return str(Keypair.from_seed(secrets.token_bytes(32)).pubkey())


def _confirmed_signature(fill: int) -> str:
    return str(Signature.from_bytes(bytes([fill] * 64)))


def _encode_channel_account(
    *,
    deposit: int,
    payer: str,
    payee: str,
    authorized_signer: str,
    mint: str,
    status: int = 0,
) -> tuple[bytes, str]:
    from solana_pay_kit._paycore.paymentchannels import PAYMENT_CHANNELS_PROGRAM_ID
    from solana_pay_kit.protocols.programs.paymentchannels.accounts.channel import Channel

    body = Channel.layout.build(
        {
            "version": 1,
            "bump": 255,
            "status": status,
            "salt": 0,
            "deposit": deposit,
            "settlement": {"settled": 0, "payoutWatermark": 0},
            "closureStartedAt": 0,
            "payerWithdrawnAt": 0,
            "gracePeriod": 900,
            "distributionHash": [0] * 32,
            "payer": Pubkey.from_string(payer),
            "payee": Pubkey.from_string(payee),
            "authorizedSigner": Pubkey.from_string(authorized_signer),
            "mint": Pubkey.from_string(mint),
            "rentPayer": Pubkey.from_string(payee),
        }
    )
    return bytes([7]) + bytes(body), PAYMENT_CHANNELS_PROGRAM_ID


class _FakeRpc:
    def __init__(self) -> None:
        self.statuses: dict[str, dict | None] = {}
        self.accounts: dict[str, tuple[bytes, str] | None] = {}

    def seed_channel(
        self,
        channel_id: str,
        *,
        deposit: int,
        payer: str,
        payee: str,
        authorized_signer: str,
        mint: str,
        status: int = 0,
    ) -> None:
        self.accounts[channel_id] = _encode_channel_account(
            deposit=deposit,
            payer=payer,
            payee=payee,
            authorized_signer=authorized_signer,
            mint=mint,
            status=status,
        )

    async def get_account_info(self, address: str, commitment: str = "confirmed") -> tuple[bytes, str] | None:
        return self.accounts.get(address)

    async def get_signature_statuses(self, signatures: list[str]) -> list[dict | None]:
        return [self.statuses.get(sig, {"err": None, "confirmationStatus": "confirmed"}) for sig in signatures]

    async def get_latest_blockhash(self, commitment: str = "confirmed"):  # noqa: ANN201
        raise NotImplementedError


def _core_config(*, network: str) -> SessionConfig:
    return SessionConfig(
        operator=SESSION_TEST_RECIPIENT,
        recipient=SESSION_TEST_RECIPIENT,
        max_cap=10_000_000,
        currency="USDC",
        decimals=6,
        network=network,
    )


async def _seed_open_channel(server: SessionServer, channel_id: str, deposit: int, authorized_signer: str) -> None:
    def seed(_current: ChannelState | None) -> ChannelState:
        return ChannelState(channel_id=channel_id, authorized_signer=authorized_signer, deposit=deposit)

    await server.store().update_channel(channel_id, seed)


async def test_process_top_up_binds_deposit_through_shipped_seam() -> None:
    """The exported core process_top_up rejects a fabricated new_deposit when
    wired with the shipped top-up seam: the on-chain Channel shows a smaller
    deposit, so the bind rejects before the range checks pass."""
    fake = _FakeRpc()
    signer = _TestVoucherSigner(1)
    channel_id = _new_wallet()

    config = _core_config(network="mainnet")
    # The shipped seam performs the deposit bind, not just signature liveness.
    config.verify_top_up_tx = new_top_up_tx_verifier(config, fake)
    server = SessionServer(config, MemoryChannelStore())
    await _seed_open_channel(server, channel_id, 1_000_000, signer.address())

    # The on-chain channel only reached 3_000_000; the client fabricates 5_000_000.
    fake.seed_channel(
        channel_id,
        deposit=3_000_000,
        payer=_new_wallet(),
        payee=SESSION_TEST_RECIPIENT,
        authorized_signer=signer.address(),
        mint=SESSION_TEST_MINT,
    )
    # process_top_up surfaces a seam rejection as a wrapped ValueError (the same
    # contract as the process_open seam); the on-chain-bind detail is preserved.
    with pytest.raises(ValueError, match="!= asserted newDeposit 5000000"):
        await server.process_top_up(
            TopUpPayload(channel_id=channel_id, new_deposit="5000000", signature=_confirmed_signature(0x88))
        )
    state = await server.store().get_channel(channel_id)
    assert state is not None and state.deposit == 1_000_000


async def test_process_top_up_bind_fails_closed_without_rpc_off_localnet() -> None:
    """Without an RPC client, off localnet the shipped seam must be an erroring
    bind (never None) so the raised deposit cannot be trusted."""
    config = _core_config(network="mainnet")
    config.verify_top_up_tx = new_top_up_tx_verifier(config, None)
    assert config.verify_top_up_tx is not None, "off localnet new_top_up_tx_verifier(config, None) must not be None"
    server = SessionServer(config, MemoryChannelStore())

    signer = _TestVoucherSigner(1)
    channel_id = _new_wallet()
    await _seed_open_channel(server, channel_id, 1_000_000, signer.address())

    with pytest.raises(ValueError, match="requires an rpc client"):
        await server.process_top_up(
            TopUpPayload(channel_id=channel_id, new_deposit="5000000", signature=_confirmed_signature(0x22))
        )


async def test_fetch_and_bind_empty_expected_signer_fails_closed() -> None:
    """An empty expected authorized signer no longer short-circuits the
    on-chain authorizedSigner compare, so a mismatch fails closed."""
    fake = _FakeRpc()
    channel_id = _new_wallet()
    mint = _new_wallet()
    payee = _new_wallet()
    on_chain_signer = _new_wallet()
    fake.seed_channel(
        channel_id,
        deposit=1_000,
        payer=_new_wallet(),
        payee=payee,
        authorized_signer=on_chain_signer,
        mint=mint,
    )
    with pytest.raises(PaymentError, match="authorized_signer|authorizedSigner"):
        await fetch_and_bind_channel_account(
            fake,
            channel_id,
            program_id=None,
            max_cap=10_000_000,
            expected_authorized_signer="",
            expected_payee=payee,
            expected_mint=mint,
        )


async def test_session_top_up_production_wires_the_bind_seam() -> None:
    """The bind is production wired: the real Session dispatcher rejects a
    fabricated new_deposit that the on-chain Channel does not back."""
    fake = _FakeRpc()
    signer = _TestVoucherSigner(1)
    channel_id = _new_wallet()

    options = SessionOptions(
        operator=SESSION_TEST_RECIPIENT,
        recipient=SESSION_TEST_RECIPIENT,
        cap=5_000_000,
        currency="USDC",
        decimals=6,
        network="mainnet",
        secret_key=SESSION_METHOD_SECRET,
        realm="api.test",
        rpc=fake,
        store=MemoryChannelStore(),
    )
    session = new_session(options)

    # Open at 1_000_000 (bind against a seeded on-chain account).
    fake.seed_channel(
        channel_id,
        deposit=1_000_000,
        payer=_new_wallet(),
        payee=SESSION_TEST_RECIPIENT,
        authorized_signer=signer.address(),
        mint=SESSION_TEST_MINT,
    )
    open_payload = OpenPayload.push(channel_id, "1000000", signer.address(), _confirmed_signature(0x33))
    challenge = await session.challenge()
    from solana_pay_kit.protocols.mpp.core.types import PaymentCredential

    open_cred = PaymentCredential(
        challenge=challenge.to_echo(), payload=SessionAction.open_action(open_payload).to_dict()
    )
    await session.verify_credential(open_cred)

    # On-chain the channel only reached 2_000_000; the client asserts 4_000_000.
    fake.seed_channel(
        channel_id,
        deposit=2_000_000,
        payer=_new_wallet(),
        payee=SESSION_TEST_RECIPIENT,
        authorized_signer=signer.address(),
        mint=SESSION_TEST_MINT,
    )
    challenge = await session.challenge()
    topup_cred = PaymentCredential(
        challenge=challenge.to_echo(),
        payload=SessionAction.top_up_action(
            TopUpPayload(channel_id=channel_id, new_deposit="4000000", signature=_confirmed_signature(0x44))
        ).to_dict(),
    )
    with pytest.raises(PaymentError, match="!= asserted newDeposit 4000000"):
        await session.verify_credential(topup_cred)
    state = await session.core().store().get_channel(channel_id)
    assert state is not None and state.deposit == 1_000_000
