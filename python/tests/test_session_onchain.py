"""Security tests for exact on-chain session transaction verification."""

from __future__ import annotations

import base64
from dataclasses import dataclass

import pytest
from solders.hash import Hash  # type: ignore[import-untyped]
from solders.keypair import Keypair  # type: ignore[import-untyped]
from solders.message import Message, MessageV0  # type: ignore[import-untyped]
from solders.pubkey import Pubkey  # type: ignore[import-untyped]
from solders.signature import Signature  # type: ignore[import-untyped]
from solders.transaction import Transaction, VersionedTransaction  # type: ignore[import-untyped]

from solana_pay_kit._paycore.errors import PaymentError
from solana_pay_kit._paycore.solana import TOKEN_PROGRAM
from solana_pay_kit.protocols.mpp._paymentchannels import (
    PROGRAM_ID,
    OpenChannelParams,
    build_open_instruction,
    find_channel_pda,
)
from solana_pay_kit.protocols.mpp.intents.session import OpenPayload, TopUpPayload
from solana_pay_kit.protocols.mpp.server.session import SessionConfig, SessionOpenContext
from solana_pay_kit.protocols.mpp.server.session_onchain import (
    TopUpTxVerifier,
    VerifyOpenTxExpected,
    confirm_transaction_signature,
    is_placeholder_signature,
    new_open_tx_verifier,
    new_top_up_tx_verifier,
    verify_open_tx,
)
from solana_pay_kit.protocols.mpp.server.session_store import ChannelState, MemoryChannelStore

USDC_MAINNET_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"


@dataclass
class _Fixture:
    payload: OpenPayload
    expected: VerifyOpenTxExpected
    payer: Keypair


def _fixture(*, v0: bool = False) -> _Fixture:
    payer = Keypair.from_seed(bytes([1] * 32))
    payee = Keypair.from_seed(bytes([2] * 32)).pubkey()
    authorized = Keypair.from_seed(bytes([3] * 32)).pubkey()
    mint = Pubkey.from_string(USDC_MAINNET_MINT)
    salt, deposit, grace, slot = 7, 1_000, 900, 42
    channel, _ = find_channel_pda(payer.pubkey(), payee, mint, authorized, salt, slot, PROGRAM_ID)
    instruction = build_open_instruction(
        OpenChannelParams(
            payer=payer.pubkey(),
            rent_payer=payer.pubkey(),
            payee=payee,
            mint=mint,
            authorized_signer=authorized,
            salt=salt,
            deposit=deposit,
            grace_period=grace,
            open_slot=slot,
            token_program=Pubkey.from_string(TOKEN_PROGRAM),
            program_id=PROGRAM_ID,
        )
    )
    if v0:
        message = MessageV0.try_compile(payer.pubkey(), [instruction], [], Hash.default())
        transaction = VersionedTransaction(message, [payer])
    else:
        transaction = Transaction(
            [payer], Message.new_with_blockhash([instruction], payer.pubkey(), Hash.default()), Hash.default()
        )
    payload = OpenPayload(
        channel_id=str(channel),
        payer=str(payer.pubkey()),
        payee=str(payee),
        mint=str(mint),
        authorized_signer=str(authorized),
        salt=salt,
        deposit_amount=str(deposit),
        grace_period_seconds=grace,
        open_slot=slot,
        transaction=base64.b64encode(bytes(transaction)).decode(),
    )
    expected = VerifyOpenTxExpected(
        authorized_signer=str(authorized),
        currency="USDC",
        recipient=str(payee),
        network="mainnet",
        minimum_deposit=100,
        mint=str(mint),
        fee_payer=str(payer.pubkey()),
        rent_payer=str(payer.pubkey()),
        token_program=TOKEN_PROGRAM,
        grace_period_seconds=grace,
        program_id=PROGRAM_ID,
        # The fixture transactions above compile against Hash.default(); the
        # challenge is taken to have advertised exactly that blockhash.
        recent_blockhash=str(Hash.default()),
    )
    return _Fixture(payload, expected, payer)


def _context(recent_blockhash: str | None = None, recent_slot: int = 42) -> SessionOpenContext:
    return SessionOpenContext(
        challenge_id="challenge-1",
        expires="2099-01-01T00:00:00Z",
        recent_blockhash=recent_blockhash if recent_blockhash is not None else str(Hash.default()),
        recent_slot=recent_slot,
    )


@pytest.mark.parametrize("v0", [False, True])
async def test_verify_open_tx_accepts_exact_legacy_and_v0(v0: bool) -> None:
    fixture = _fixture(v0=v0)
    result = await verify_open_tx(fixture.expected, fixture.payload, None)
    assert result.channel_id == fixture.payload.channel_id
    assert result.deposit == 1_000
    assert result.open_slot == 42


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("channel_id", str(Keypair().pubkey()), "channelId"),
        ("payer", str(Keypair().pubkey()), "payload payer"),
        ("deposit_amount", "999", "depositAmount"),
        ("salt", 8, "payload salt"),
        ("grace_period_seconds", 30, "gracePeriodSeconds"),
        ("open_slot", 43, "openSlot"),
    ],
)
async def test_verify_open_tx_rejects_payload_mismatch(field: str, value: object, message: str) -> None:
    fixture = _fixture()
    setattr(fixture.payload, field, value)
    with pytest.raises(PaymentError, match=message):
        await verify_open_tx(fixture.expected, fixture.payload, None)


async def test_verify_open_tx_rejects_challenge_policy_mismatch() -> None:
    fixture = _fixture()
    fixture.expected.recipient = str(Keypair().pubkey())
    with pytest.raises(PaymentError, match="expected recipient"):
        await verify_open_tx(fixture.expected, fixture.payload, None)


@pytest.mark.parametrize("v0", [False, True])
async def test_verify_open_tx_rejects_wrong_challenged_blockhash(v0: bool) -> None:
    # The fixture transaction compiles against Hash.default(); a challenge
    # that advertised a different recentBlockhash means the transaction was
    # not built for this challenge — rejected before broadcast.
    fixture = _fixture(v0=v0)
    fixture.expected.recent_blockhash = str(Hash.new_unique())
    with pytest.raises(PaymentError, match="challenged recentBlockhash"):
        await verify_open_tx(fixture.expected, fixture.payload, None)


async def test_verify_open_tx_requires_challenged_blockhash() -> None:
    # recentBlockhash is a challenge-binding boundary like feePayer/rentPayer:
    # a standalone verifier must not accept an open without proving it.
    fixture = _fixture()
    fixture.expected.recent_blockhash = ""
    with pytest.raises(ValueError, match="recentBlockhash is required"):
        await verify_open_tx(fixture.expected, fixture.payload, None)


async def test_open_verifier_threads_challenged_blockhash() -> None:
    # new_open_tx_verifier feeds the SessionOpenContext's recentBlockhash into
    # the structural check, so a mismatched context rejects pre-broadcast even
    # with a live RPC configured.
    fixture = _fixture()
    config = SessionConfig(
        recipient=fixture.expected.recipient,
        amount=25,
        currency="USDC",
        network="mainnet",
        channel_program=str(PROGRAM_ID),
        token_program=TOKEN_PROGRAM,
        grace_period_seconds=900,
        minimum_deposit=100,
    )
    broadcasts: list[bytes] = []

    class _Rpc(_StatusRpc):
        async def send_raw_transaction(self, raw_tx: bytes) -> object:
            broadcasts.append(raw_tx)
            raise AssertionError("must reject before broadcast")

    verifier = new_open_tx_verifier(config, _Rpc([]))
    with pytest.raises(PaymentError, match="challenged recentBlockhash"):
        await verifier(fixture.payload, _context(recent_blockhash=str(Hash.new_unique())))
    assert broadcasts == []


async def test_verify_open_tx_requires_transaction() -> None:
    fixture = _fixture()
    fixture.payload.transaction = ""
    with pytest.raises(PaymentError, match="transaction is required"):
        await verify_open_tx(fixture.expected, fixture.payload, None)


async def test_verify_open_tx_rejects_missing_payer_signature() -> None:
    fixture = _fixture()
    transaction = Transaction.from_bytes(base64.b64decode(fixture.payload.transaction))
    fixture.payload.transaction = base64.b64encode(
        bytes(Transaction.populate(transaction.message, [Signature.default()]))
    ).decode()
    with pytest.raises(PaymentError, match="payer signature is missing"):
        await verify_open_tx(fixture.expected, fixture.payload, None)


async def test_open_verifier_fails_closed_without_rpc() -> None:
    fixture = _fixture()
    config = SessionConfig(
        recipient=fixture.expected.recipient,
        amount=25,
        currency="USDC",
        network="mainnet",
        channel_program=str(PROGRAM_ID),
        token_program=TOKEN_PROGRAM,
        grace_period_seconds=900,
    )
    verifier = new_open_tx_verifier(config, None)
    with pytest.raises(PaymentError, match="requires an RPC client"):
        await verifier(fixture.payload, _context())


async def test_top_up_verifier_fails_closed_without_rpc() -> None:
    config = SessionConfig(currency="USDC", network="mainnet", channel_program=str(PROGRAM_ID))
    verifier = new_top_up_tx_verifier(config, MemoryChannelStore(), None)
    with pytest.raises(PaymentError, match="requires an RPC client"):
        await verifier(TopUpPayload(str(Keypair().pubkey()), "1", "transaction"))


class _StatusRpc:
    def __init__(self, statuses: list[dict | None]) -> None:
        self.statuses = statuses

    async def get_signature_statuses(self, signatures: list[str]) -> list[dict | None]:
        del signatures
        return [self.statuses.pop(0)]

    async def get_latest_blockhash(self, commitment: str = "confirmed") -> object:
        del commitment
        raise AssertionError("not used by confirmation tests")

    async def send_raw_transaction(self, raw_tx: bytes) -> object:
        del raw_tx
        raise AssertionError("not used by confirmation tests")


async def test_confirmation_polls_until_confirmed() -> None:
    signature = str(Keypair().sign_message(b"transaction"))
    rpc = _StatusRpc([None, {"err": None, "confirmationStatus": "confirmed"}])
    await confirm_transaction_signature(rpc, signature, "open", timeout_seconds=1, poll_interval_seconds=0)


async def test_confirmation_surfaces_chain_failure() -> None:
    signature = str(Keypair().sign_message(b"transaction"))
    rpc = _StatusRpc([{"err": {"InstructionError": [0, "Custom"]}, "confirmationStatus": "confirmed"}])
    with pytest.raises(PaymentError, match="failed on-chain"):
        await confirm_transaction_signature(rpc, signature, "open", timeout_seconds=1, poll_interval_seconds=0)


def test_placeholder_signature_detection() -> None:
    assert is_placeholder_signature("")
    assert is_placeholder_signature("1" * 40)
    assert not is_placeholder_signature("1" * 39)
    assert not is_placeholder_signature("1" * 39 + "2")


async def test_confirmation_rejects_invalid_signature() -> None:
    with pytest.raises(PaymentError, match="invalid open tx signature"):
        await confirm_transaction_signature(_StatusRpc([]), "not-base58", "open")


async def test_confirmation_reports_not_found_and_not_confirmed() -> None:
    signature = str(Keypair().sign_message(b"transaction"))
    with pytest.raises(PaymentError, match="not found"):
        await confirm_transaction_signature(_StatusRpc([None]), signature, "open", timeout_seconds=0)
    with pytest.raises(PaymentError, match="not confirmed"):
        await confirm_transaction_signature(
            _StatusRpc([{"err": None, "confirmationStatus": "processed"}]),
            signature,
            "open",
            timeout_seconds=0,
        )


class _FailingStatusRpc(_StatusRpc):
    async def get_signature_statuses(self, signatures: list[str]) -> list[dict | None]:
        del signatures
        raise RuntimeError("rpc unavailable")


async def test_confirmation_wraps_rpc_errors() -> None:
    signature = str(Keypair().sign_message(b"transaction"))
    with pytest.raises(PaymentError, match="RPC error verifying open tx"):
        await confirm_transaction_signature(_FailingStatusRpc([]), signature, "open", timeout_seconds=0)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("authorized_signer", str(Keypair().pubkey()), "authorizedSigner"),
        ("mint", str(Keypair().pubkey()), "expected mint"),
        ("rent_payer", str(Keypair().pubkey()), "rentPayer"),
        ("token_program", str(Keypair().pubkey()), "tokenProgram"),
        ("grace_period_seconds", 30, "challenge"),
        ("minimum_deposit", 2_000, "minimumDeposit"),
    ],
)
async def test_verify_open_tx_rejects_additional_challenge_mismatches(field: str, value: object, message: str) -> None:
    fixture = _fixture()
    setattr(fixture.expected, field, value)
    with pytest.raises(PaymentError, match=message):
        await verify_open_tx(fixture.expected, fixture.payload, None)


async def test_verify_open_tx_rejects_bad_encoding_and_fee_payer() -> None:
    fixture = _fixture()
    fixture.payload.transaction = "not base64"
    with pytest.raises(PaymentError, match="decode open transaction"):
        await verify_open_tx(fixture.expected, fixture.payload, None)

    fixture = _fixture()
    fixture.expected.fee_payer = str(Keypair().pubkey())
    with pytest.raises(PaymentError, match="fee payer"):
        await verify_open_tx(fixture.expected, fixture.payload, None)


# -- landed-signature rescues -------------------------------------------------
#
# A broadcast rejection is not authoritative: mainnet rejects a duplicate of an
# already-landed transaction at preflight, so a retry whose first submission
# landed (response lost, or the store write after it failed) must be resolved
# against the chain, not the broadcast error. Mirrors the Rust
# retried_open_survives_preflight_rejection_without_stored_state scenario and
# the TS submitTopUpTx rescue.


class _MainnetLikeRpc:
    """Mock RPC that, like mainnet, rejects a duplicate send at preflight."""

    def __init__(self, *, account: object | None, status: dict | None) -> None:
        self.sent: list[bytes] = []
        self.account = account
        self.status = status

    async def send_raw_transaction(self, raw_tx: bytes) -> object:
        if raw_tx in self.sent:
            raise RuntimeError("Transaction simulation failed: This transaction has already been processed")
        self.sent.append(raw_tx)
        signature = _first_signature(raw_tx)

        class _Resp:
            value = signature

        return _Resp()

    async def get_signature_statuses(self, signatures: list[str]) -> list[dict | None]:
        del signatures
        return [dict(self.status) if self.status is not None else None]

    async def get_account_info(self, _addr: object, commitment: str = "confirmed") -> object:
        del commitment
        from types import SimpleNamespace

        return SimpleNamespace(value=self.account)

    async def get_latest_blockhash(self, commitment: str = "confirmed") -> object:
        del commitment
        raise AssertionError("not used by rescue tests")


def _first_signature(raw_tx: bytes) -> str:
    return str(Transaction.from_bytes(raw_tx).signatures[0])


_LANDED_CLEAN = {"err": None, "confirmationStatus": "finalized"}


def _open_config(fixture: _Fixture) -> SessionConfig:
    return SessionConfig(
        recipient=fixture.expected.recipient,
        amount=25,
        currency="USDC",
        network="mainnet",
        channel_program=str(PROGRAM_ID),
        token_program=TOKEN_PROGRAM,
        grace_period_seconds=900,
        minimum_deposit=100,
    )


def _channel_account(fixture: _Fixture) -> object:
    """The confirmed on-chain channel account the fixture's open creates."""
    from types import SimpleNamespace

    from solana_pay_kit.protocols.programs.paymentchannels.accounts.channel import Channel

    body = Channel.layout.build(
        {
            "version": 1,
            "bump": 255,
            "status": 0,
            "salt": fixture.payload.salt,
            "deposit": int(fixture.payload.deposit_amount),
            "settlement": {"settled": 0, "payoutWatermark": 0},
            "closureStartedAt": 0,
            "payerWithdrawnAt": 0,
            "gracePeriod": fixture.payload.grace_period_seconds,
            "distributionHash": [0] * 32,
            "payer": Pubkey.from_string(fixture.payload.payer),
            "payee": Pubkey.from_string(fixture.payload.payee),
            "authorizedSigner": Pubkey.from_string(fixture.payload.authorized_signer),
            "mint": Pubkey.from_string(fixture.payload.mint),
            "rentPayer": Pubkey.from_string(fixture.payload.payer),
            "openSlot": fixture.payload.open_slot,
        }
    )
    return SimpleNamespace(owner=PROGRAM_ID, data=bytes([7]) + bytes(body))


async def test_open_verifier_rescues_landed_open_on_duplicate_preflight_rejection() -> None:
    # First submission lands but the response (or the store write after it) is
    # lost; the retry of the same signed transaction dies at preflight. The
    # confirmed channel account matches the verified open params only if this
    # exact open succeeded, so the retry must verify.
    fixture = _fixture()
    rpc = _MainnetLikeRpc(account=_channel_account(fixture), status=_LANDED_CLEAN)
    verifier = new_open_tx_verifier(_open_config(fixture), rpc)
    await verifier(fixture.payload, _context())
    await verifier(fixture.payload, _context())
    assert len(rpc.sent) == 1


async def test_open_verifier_keeps_broadcast_error_without_matching_account() -> None:
    # The rescue only applies on a full field match: if the confirmed account
    # is missing, the original broadcast failure stays authoritative.
    fixture = _fixture()
    rpc = _MainnetLikeRpc(account=None, status=_LANDED_CLEAN)
    rpc.sent.append(base64.b64decode(fixture.payload.transaction))
    verifier = new_open_tx_verifier(_open_config(fixture), rpc)
    with pytest.raises(RuntimeError, match="already been processed"):
        await verifier(fixture.payload, _context())


async def test_open_verifier_still_fails_on_account_mismatch_after_clean_broadcast() -> None:
    # A clean broadcast with a non-matching confirmed account is still a
    # verification failure — the rescue must not weaken the account check.
    fixture = _fixture()
    rpc = _MainnetLikeRpc(account=None, status=_LANDED_CLEAN)
    verifier = new_open_tx_verifier(_open_config(fixture), rpc)
    with pytest.raises(PaymentError, match="confirmed channel account was not found"):
        await verifier(fixture.payload, _context())


def _top_up_scenario(*, deposit_after: int) -> tuple[TopUpPayload, ChannelState, object]:
    from types import SimpleNamespace

    from solana_pay_kit._paycore.solana import resolve_mint
    from solana_pay_kit.protocols.mpp._paymentchannels import TopUpParams, build_top_up_instruction
    from solana_pay_kit.protocols.programs.paymentchannels.accounts.channel import Channel

    payer = Keypair.from_seed(bytes([11] * 32))
    channel = Keypair.from_seed(bytes([12] * 32)).pubkey()
    mint = Pubkey.from_string(resolve_mint("USDC", "mainnet"))
    state = ChannelState(
        channel_id=str(channel),
        authorized_signer=str(Keypair.from_seed(bytes([13] * 32)).pubkey()),
        payer=str(payer.pubkey()),
        rent_payer=str(payer.pubkey()),
        deposit=1_000,
    )
    instruction = build_top_up_instruction(
        TopUpParams(
            payer=payer.pubkey(),
            channel=channel,
            mint=mint,
            amount=250,
            token_program=Pubkey.from_string(TOKEN_PROGRAM),
            program_id=PROGRAM_ID,
        )
    )
    transaction = Transaction(
        [payer], Message.new_with_blockhash([instruction], payer.pubkey(), Hash.default()), Hash.default()
    )
    payload = TopUpPayload(str(channel), "250", base64.b64encode(bytes(transaction)).decode())
    body = Channel.layout.build(
        {
            "version": 1,
            "bump": 255,
            "status": 0,
            "salt": 0,
            "deposit": deposit_after,
            "settlement": {"settled": 0, "payoutWatermark": 0},
            "closureStartedAt": 0,
            "payerWithdrawnAt": 0,
            "gracePeriod": 900,
            "distributionHash": [0] * 32,
            "payer": payer.pubkey(),
            "payee": Keypair.from_seed(bytes([14] * 32)).pubkey(),
            "authorizedSigner": Pubkey.from_string(state.authorized_signer),
            "mint": mint,
            "rentPayer": payer.pubkey(),
            "openSlot": 0,
        }
    )
    account = SimpleNamespace(owner=PROGRAM_ID, data=bytes([7]) + bytes(body))
    return payload, state, account


async def _seeded_top_up_verifier(rpc: _MainnetLikeRpc, state: ChannelState) -> TopUpTxVerifier:
    store = MemoryChannelStore()
    await store.update_channel(state.channel_id, lambda _: state)
    config = SessionConfig(currency="USDC", network="mainnet", channel_program=str(PROGRAM_ID))
    return new_top_up_tx_verifier(config, store, rpc)


async def test_top_up_verifier_rescues_landed_top_up_on_duplicate_preflight_rejection() -> None:
    # First submission funds escrow but the credit is lost before it persists;
    # the retry dies at preflight. The transaction's own signature landed clean
    # and the confirmed deposit reflects the top-up, so the retry must verify.
    payload, state, account = _top_up_scenario(deposit_after=1_250)
    rpc = _MainnetLikeRpc(account=account, status=_LANDED_CLEAN)
    verifier = await _seeded_top_up_verifier(rpc, state)
    await verifier(payload)
    await verifier(payload)
    assert len(rpc.sent) == 1


async def test_top_up_verifier_keeps_broadcast_error_when_transaction_failed_on_chain() -> None:
    # A landed-but-FAILED transaction did not fund escrow: the original
    # broadcast failure stays authoritative.
    payload, state, account = _top_up_scenario(deposit_after=1_250)
    rpc = _MainnetLikeRpc(account=account, status={"err": {"InstructionError": [0, "Custom"]}})
    rpc.sent.append(base64.b64decode(payload.transaction))
    verifier = await _seeded_top_up_verifier(rpc, state)
    with pytest.raises(RuntimeError, match="already been processed"):
        await verifier(payload)


async def test_top_up_verifier_keeps_broadcast_error_when_signature_never_landed() -> None:
    # No landed status means the first submission did not fund escrow either.
    payload, state, account = _top_up_scenario(deposit_after=1_250)
    rpc = _MainnetLikeRpc(account=account, status=None)
    rpc.sent.append(base64.b64decode(payload.transaction))
    verifier = await _seeded_top_up_verifier(rpc, state)
    with pytest.raises(RuntimeError, match="already been processed"):
        await verifier(payload)
