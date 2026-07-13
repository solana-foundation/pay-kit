"""On-chain settle-at-close: a close with a signer + RPC broadcasts a
settle_and_seal (+ Ed25519 precompile when a voucher was recorded) and a
distribute instruction, then records the settlement signature and seals.
Mirrors the Go/TS closeAndSettleChannel path.
"""

from __future__ import annotations

import asyncio
import base64
import copy
from typing import Any

import pytest
from solders.keypair import Keypair  # type: ignore[import-untyped]
from solders.pubkey import Pubkey  # type: ignore[import-untyped]
from solders.transaction import Transaction  # type: ignore[import-untyped]

from solana_pay_kit._paycore.errors import PaymentError
from solana_pay_kit._paycore.solana import TOKEN_2022_PROGRAM, TOKEN_PROGRAM, resolve_mint
from solana_pay_kit.protocols.mpp._paymentchannels import find_associated_token_address
from solana_pay_kit.protocols.mpp.core.headers import PAYMENT_RECEIPT_HEADER, format_authorization
from solana_pay_kit.protocols.mpp.core.types import PaymentCredential
from solana_pay_kit.protocols.mpp.intents.session import ClosePayload, SessionAction
from solana_pay_kit.protocols.mpp.server import SessionChallengeOptions, SessionOptions, new_session
from solana_pay_kit.protocols.mpp.server.session_store import ChannelState, MemoryChannelStore
from solana_pay_kit.signer import LocalSigner

_BLOCKHASH = "EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N"


class _Resp:
    def __init__(self, value: Any) -> None:
        self.value = value


class _Blockhash:
    def __init__(self, blockhash: str) -> None:
        self.blockhash = blockhash


class _SettleRpc:
    """Captures the broadcast settle transaction and returns a fixed signature.

    ``status_queries`` records every call to ``get_signature_statuses`` so a test
    can assert no on-chain confirmation was attempted on a trust path.
    """

    def __init__(self) -> None:
        self.accounts: dict[str, tuple[bytes, str]] = {}
        self.account_info_requests: list[str] = []
        self.sent: list[bytes] = []
        self.sent_signatures: list[str] = []
        self.status_queries: list[list[str]] = []
        self.search_history_queries: list[bool] = []

    async def get_signature_statuses(
        self, signatures: list[str], *, search_transaction_history: bool = False
    ) -> list[dict | None]:
        self.status_queries.append(list(signatures))
        self.search_history_queries.append(search_transaction_history)
        return [{"err": None, "confirmationStatus": "confirmed"} for _ in signatures]

    async def get_latest_blockhash(self, commitment: str = "confirmed") -> _Resp:
        return _Resp(_Blockhash(_BLOCKHASH))

    async def send_raw_transaction(self, raw_tx: bytes) -> _Resp:
        self.sent.append(raw_tx)
        signature = str(Transaction.from_bytes(raw_tx).signatures[0])
        self.sent_signatures.append(signature)
        return _Resp(signature)

    async def get_account_info(
        self, address: str, commitment: str = "confirmed", min_context_slot: int | None = None
    ) -> tuple[bytes, str] | None:
        self.account_info_requests.append(address)
        return self.accounts.get(address)


def _seed_settlement_mint(rpc: _SettleRpc, currency: str, token_program: str) -> None:
    mint = resolve_mint(currency, "localnet")
    assert mint is not None
    rpc.accounts[mint] = (b"", token_program)


def _seed_settlement_recipient_ata(rpc: _SettleRpc, recipient: str, currency: str, token_program: str) -> None:
    mint = resolve_mint(currency, "localnet")
    assert mint is not None
    program = Pubkey.from_string(token_program)
    recipient_ata, _ = find_associated_token_address(Pubkey.from_string(recipient), Pubkey.from_string(mint), program)
    rpc.accounts[str(recipient_ata)] = (b"", token_program)


def _session(
    rpc: _SettleRpc,
    operator: Keypair,
    recipient: str | None = None,
    *,
    currency: str = "USDC",
    token_program: str = TOKEN_PROGRAM,
    recipient_ata_exists: bool = True,
    store: MemoryChannelStore | None = None,
    open_tx_submitter: str = "",
    cap: int = 1_000_000,
):
    if recipient is None:
        recipient = str(operator.pubkey())
    session = new_session(
        SessionOptions(
            operator=str(operator.pubkey()),
            recipient=recipient,
            cap=cap,
            currency=currency,
            decimals=6,
            network="localnet",
            secret_key="a" * 64,
            modes=["pull"],
            pull_voucher_strategy="clientVoucher",
            signer=LocalSigner.from_keypair(operator),
            rpc=rpc,
            store=store,
            open_tx_submitter=open_tx_submitter,
        )
    )
    _seed_settlement_mint(rpc, currency, token_program)
    if recipient_ata_exists:
        _seed_settlement_recipient_ata(rpc, recipient, currency, token_program)
    return session


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

    assert settled == rpc.sent_signatures[0]
    final = await session._core.store().get_channel(channel)
    assert final is not None
    assert final.sealed is True
    assert final.settled_signature == settled
    # Exactly one tx, instructions [ed25519(1), settleAndSeal(4), distribute(7)].
    assert len(rpc.sent) == 1
    assert _instruction_discriminators(rpc.sent[0]) == [1, 4, 7]


@pytest.mark.asyncio
async def test_settle_raises_and_does_not_seal_when_tx_unconfirmed() -> None:
    """A dropped/failed settle tx must raise (the broadcast is confirmed before
    return), so the channel is NOT marked sealed with an unconfirmed
    signature and the re-drivable-close guard still applies."""

    class _FailingSettleRpc(_SettleRpc):
        async def get_signature_statuses(
            self, signatures: list[str], *, search_transaction_history: bool = False
        ) -> list[dict | None]:
            return [{"err": {"InstructionError": [0, "Custom"]}} for _ in signatures]

    operator = Keypair.from_seed(bytes([8] * 32))
    auth = Keypair.from_seed(bytes([9] * 32))
    channel = str(Keypair.from_seed(bytes([10] * 32)).pubkey())
    rpc = _FailingSettleRpc()
    session = _session(rpc, operator)
    await _seed(
        session,
        ChannelState(
            channel_id=channel,
            authorized_signer=str(auth.pubkey()),
            deposit=1_000_000,
            cumulative=500_000,
            highest_voucher_signature=str(auth.sign_message(b"voucher")),
            highest_voucher_expires_at=4_102_444_800,
            operator=str(operator.pubkey()),
        ),
    )

    with pytest.raises(PaymentError, match="failed on-chain"):
        await session._settle_channel(channel)

    final = await session._core.store().get_channel(channel)
    assert final is not None
    assert final.sealed is False
    assert final.settled_signature is None


@pytest.mark.asyncio
async def test_close_rejects_missing_recipient_ata_without_broadcast_or_receipt_reference() -> None:
    operator = Keypair.from_seed(bytes([11] * 32))
    recipient = str(Keypair.from_seed(bytes([12] * 32)).pubkey())
    channel = str(Keypair.from_seed(bytes([13] * 32)).pubkey())
    rpc = _SettleRpc()
    session = _session(rpc, operator, recipient, recipient_ata_exists=False)
    await _seed(
        session,
        ChannelState(
            channel_id=channel,
            authorized_signer=str(operator.pubkey()),
            deposit=1_000_000,
            cumulative=500_000,
            operator=str(operator.pubkey()),
        ),
    )

    with pytest.raises(PaymentError, match="settlement recipient ATA .* does not exist"):
        await session._handle_close(ClosePayload(channel_id=channel))

    assert rpc.sent == []
    state = await session._core.store().get_channel(channel)
    assert state is not None
    assert state.sealed is False
    assert state.settled_signature is None
    assert state.settling is False

    challenge_options = SessionChallengeOptions()
    challenge = await session.challenge(challenge_options)
    credential = PaymentCredential(
        challenge=challenge.to_echo(),
        payload=SessionAction.close_action(ClosePayload(channel_id=channel)).to_dict(),
    )
    result = await session.handle(format_authorization(credential), challenge_options)

    assert result.ok is False
    assert result.status == 402
    assert PAYMENT_RECEIPT_HEADER not in result.headers
    assert result.body is not None
    assert result.body["code"] == "payment_invalid"
    assert "settlement recipient ATA" in result.body["message"]
    assert rpc.sent == []


@pytest.mark.asyncio
async def test_close_uses_raw_token_2022_mint_owner_for_recipient_ata_and_distribute() -> None:
    operator = Keypair.from_seed(bytes([14] * 32))
    recipient = str(Keypair.from_seed(bytes([15] * 32)).pubkey())
    mint = str(Keypair.from_seed(bytes([16] * 32)).pubkey())
    channel = str(Keypair.from_seed(bytes([17] * 32)).pubkey())
    rpc = _SettleRpc()
    session = _session(rpc, operator, recipient, currency=mint, token_program=TOKEN_2022_PROGRAM)
    await _seed(
        session,
        ChannelState(
            channel_id=channel,
            authorized_signer=str(operator.pubkey()),
            deposit=1_000_000,
            cumulative=500_000,
            operator=str(operator.pubkey()),
        ),
    )

    await session._settle_channel(channel)

    message = Transaction.from_bytes(rpc.sent[0]).message
    distribute = message.instructions[-1]
    recipient_ata, _ = find_associated_token_address(
        Pubkey.from_string(recipient), Pubkey.from_string(mint), Pubkey.from_string(TOKEN_2022_PROGRAM)
    )
    assert str(message.account_keys[distribute.accounts[5]]) == str(recipient_ata)
    assert str(message.account_keys[distribute.accounts[8]]) == TOKEN_2022_PROGRAM
    assert rpc.account_info_requests[:2] == [mint, str(recipient_ata)]


@pytest.mark.asyncio
async def test_close_rejects_mint_owned_by_unexpected_program_before_broadcast() -> None:
    operator = Keypair.from_seed(bytes([18] * 32))
    recipient = str(Keypair.from_seed(bytes([19] * 32)).pubkey())
    mint = str(Keypair.from_seed(bytes([20] * 32)).pubkey())
    channel = str(Keypair.from_seed(bytes([21] * 32)).pubkey())
    unexpected_owner = str(Keypair.from_seed(bytes([22] * 32)).pubkey())
    rpc = _SettleRpc()
    session = _session(rpc, operator, recipient, currency=mint, token_program=unexpected_owner)
    await _seed(
        session,
        ChannelState(
            channel_id=channel,
            authorized_signer=str(operator.pubkey()),
            deposit=1_000_000,
            cumulative=500_000,
            operator=str(operator.pubkey()),
        ),
    )

    with pytest.raises(PaymentError, match="owned by unsupported token program"):
        await session._settle_channel(channel)

    assert rpc.sent == []
    assert rpc.account_info_requests == [mint]
    state = await session._core.store().get_channel(channel)
    assert state is not None
    assert state.sealed is False
    assert state.settled_signature is None
    assert state.settling is False


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

    # No voucher recorded: settleAndSeal then distribute.
    assert _instruction_discriminators(rpc.sent[0]) == [4, 7]


@pytest.mark.asyncio
async def test_settle_requires_recorded_channel_payer() -> None:
    """Settlement must fail loudly when the channel payer (opener) was never
    recorded: falling back to another account (e.g. the recipient) would
    derive the wrong refund ATA. Mirrors Go's strict payer handling. Nothing
    is broadcast and the settle guard is released for a retry."""
    operator = Keypair.from_seed(bytes([31] * 32))
    channel = str(Keypair.from_seed(bytes([32] * 32)).pubkey())
    rpc = _SettleRpc()
    session = _session(rpc, operator)
    await _seed(
        session,
        ChannelState(
            channel_id=channel,
            authorized_signer=str(operator.pubkey()),
            deposit=1_000_000,
            cumulative=0,
            operator=None,
        ),
    )

    with pytest.raises(PaymentError, match="payer is unknown"):
        await session._settle_channel(channel)

    assert rpc.sent == []
    state = await session._core.store().get_channel(channel)
    assert state is not None
    assert state.sealed is False
    assert state.settling is False


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


def _server_open_payload(operator: Keypair, cap: str = "1000000", *, salt: int | None = None):
    """A client-built open whose fee-payer (operator) slot the server completes."""
    from solana_pay_kit.protocols.mpp.client.payment_channels import (
        PaymentChannelOpenOptions,
        PaymentChannelSessionOpenOptions,
        create_payment_channel_session_opener,
    )
    from solana_pay_kit.protocols.mpp.intents.session import SessionRequest

    payer = Keypair.from_seed(bytes([11] * 32))
    session_signer = Keypair.from_seed(bytes([9] * 32))
    request = SessionRequest(
        cap=cap,
        currency="USDC",
        operator=str(operator.pubkey()),
        recipient=str(operator.pubkey()),
        decimals=6,
        network="localnet",
        modes=["pull"],
        pull_voucher_strategy="clientVoucher",
        recent_slot=4242,
    )
    opener = create_payment_channel_session_opener(
        request,
        payer,
        session_signer,
        _BLOCKHASH,
        PaymentChannelSessionOpenOptions(open=PaymentChannelOpenOptions(salt=salt)),
    )
    payload = opener.action.open
    assert payload is not None
    return opener.open, payload


@pytest.mark.asyncio
async def test_server_broadcast_open_builds_signs_and_persists() -> None:
    operator = Keypair.from_seed(bytes([8] * 32))
    rpc = _SettleRpc()
    session = new_session(
        SessionOptions(
            operator=str(operator.pubkey()),
            recipient=str(operator.pubkey()),
            cap=2_000_000,
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
    payload.deposit = "1500000"

    signature = await session._handle_open(payload)

    assert signature == rpc.sent_signatures[0]
    # One open transaction broadcast, a single open instruction (discriminator 1).
    assert len(rpc.sent) == 1
    assert _instruction_discriminators(rpc.sent[0]) == [1]
    # The channel is persisted under its derived id.
    persisted = await session._core.store().get_channel(str(open_.channel_id))
    assert persisted is not None
    assert persisted.deposit == open_.deposit
    assert persisted.operator == str(open_.payer)


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


@pytest.mark.asyncio
async def test_server_broadcast_open_skipped_for_pull_without_transaction() -> None:
    """A pull open with no transaction must not enter the server-broadcast
    block even when ``openTxSubmitter=server`` is configured.

    The server-broadcast path is gated on a transaction being attached (it
    requires one to co-sign and broadcast). A pull open carrying only the
    channel id / token account and approved amount falls through to the
    trust-the-channel-id path. Without this gate every pull open against a
    server-broadcast server was hard-rejected by verify_open_tx's transaction
    requirement, so the playground's ``modes=["pull"]`` +
    ``openTxSubmitter="server"`` config could never establish a session for a
    no-transaction client. Mirrors the TS ``else`` open branch.
    """
    from solana_pay_kit.protocols.mpp.intents.session import OpenPayload

    operator = Keypair.from_seed(bytes([12] * 32))
    rpc = _SettleRpc()
    session = new_session(
        SessionOptions(
            operator=str(operator.pubkey()),
            recipient=str(operator.pubkey()),
            cap=2_000_000,
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
    token_account = str(Keypair.from_seed(bytes([13] * 32)).pubkey())
    payload = OpenPayload.pull(
        token_account=token_account,
        approved_amount="1000000",
        owner=str(operator.pubkey()),
        authorized_signer=str(operator.pubkey()),
        signature="",
    )
    assert payload.transaction is None

    reference = await session._handle_open(payload)

    # No on-chain open is broadcast for a no-transaction pull open.
    assert rpc.sent == []
    # No on-chain confirmation is attempted on the trust path either.
    assert rpc.status_queries == []
    # The channel is persisted under its session id (the token account).
    persisted = await session._core.store().get_channel(token_account)
    assert persisted is not None
    assert persisted.deposit == 1_000_000
    # The receipt reference is the channel id when no signature is recorded.
    assert reference == token_account


@pytest.mark.asyncio
async def test_open_tx_submitter_client_verifies_pull_transaction() -> None:
    """A pull open with a transaction and ``openTxSubmitter=client`` takes the
    client-broadcast verify branch (not the server-broadcast branch), recording
    the verified payer/deposit from the attached transaction. Guards against a
    regression that would misroute a transaction-carrying pull open."""
    operator = Keypair.from_seed(bytes([14] * 32))
    open_, payload = _server_open_payload(operator)
    rpc = _SettleRpc()
    session = new_session(
        SessionOptions(
            operator=str(operator.pubkey()),
            recipient=str(operator.pubkey()),
            cap=2_000_000,
            currency="USDC",
            decimals=6,
            network="localnet",
            secret_key="a" * 64,
            modes=["pull"],
            pull_voucher_strategy="clientVoucher",
            open_tx_submitter="client",
            signer=LocalSigner.from_keypair(operator),
            rpc=rpc,
        )
    )
    payload.deposit = "1500000"
    from solana_pay_kit.protocols.mpp.server.session_onchain import complete_open_transaction

    prepared = complete_open_transaction(payload, operator)
    payload.transaction = base64.b64encode(prepared.wire).decode("ascii")
    payload.signature = prepared.signature

    reference = await session._handle_open(payload)

    # Client-broadcast verify: no server broadcast of the open.
    assert rpc.sent == []
    # The verified payer from the attached open transaction is propagated.
    persisted = await session._core.store().get_channel(str(open_.channel_id))
    assert persisted is not None
    assert persisted.operator == str(open_.payer)
    assert persisted.deposit == open_.deposit
    # The receipt reference is the (pending) open signature the client supplied.
    assert reference == payload.signature


@pytest.mark.asyncio
async def test_push_open_without_transaction_trusts_channel_id_without_rpc() -> None:
    """A push open with a channel id and no RPC (and no signer) falls through to
    the trust path: no on-chain confirmation is attempted and the channel is
    persisted under the channel id. Mirrors the TS push-else branch when no RPC
    is configured (the open signature is trusted as previously broadcast)."""
    from solana_pay_kit.protocols.mpp.intents.session import OpenPayload

    recipient = str(Keypair.from_seed(bytes([15] * 32)).pubkey())
    session = new_session(
        SessionOptions(
            operator=recipient,
            recipient=recipient,
            cap=1_000_000,
            currency="USDC",
            decimals=6,
            network="localnet",
            secret_key="a" * 64,
            modes=["push"],
        )
    )
    channel_id = str(Keypair.from_seed(bytes([16] * 32)).pubkey())
    payload = OpenPayload.push(channel_id, "500000", recipient, "open-sig")

    reference = await session._handle_open(payload)

    persisted = await session._core.store().get_channel(channel_id)
    assert persisted is not None
    assert persisted.deposit == 500_000
    assert reference == "open-sig"


# --- B1: polling confirmation on just-broadcast settle -------------------------


class _PollingSettleRpc(_SettleRpc):
    """Returns ``None`` for the first ``n`` ``getSignatureStatuses`` calls on a
    given signature, then returns confirmed. Mirrors the common Solana behaviour
    where a freshly submitted signature is not yet visible to the RPC."""

    def __init__(self, none_rounds: int = 2) -> None:
        super().__init__()
        self._none_left = none_rounds
        self._bounced_sig: str | None = None

    async def get_signature_statuses(
        self, signatures: list[str], *, search_transaction_history: bool = False
    ) -> list[dict | None]:
        self.status_queries.append(list(signatures))
        if self._none_left > 0 and signatures:
            self._bounced_sig = signatures[0]
            self._none_left -= 1
            return [None for _ in signatures]
        return [{"err": None, "confirmationStatus": "confirmed"} for _ in signatures]


@pytest.mark.asyncio
async def test_settle_polls_until_confirmed_when_status_initially_none() -> None:
    """B1: a just-broadcast settle tx commonly returns ``None`` from
    ``getSignatureStatuses`` for a few rounds before landing. The single-shot
    predecessor raised spuriously; the polling confirm retries until
    confirmed, seals, and records the signature.
    """

    operator = Keypair.from_seed(bytes([20] * 32))
    auth = Keypair.from_seed(bytes([21] * 32))
    channel = str(Keypair.from_seed(bytes([22] * 32)).pubkey())

    rpc = _PollingSettleRpc(none_rounds=2)
    session = _session(rpc, operator)
    await _seed(
        session,
        ChannelState(
            channel_id=channel,
            authorized_signer=str(auth.pubkey()),
            deposit=1_000_000,
            cumulative=500_000,
            highest_voucher_signature=str(auth.sign_message(b"voucher")),
            highest_voucher_expires_at=4_102_444_800,
            operator=str(operator.pubkey()),
        ),
    )

    settled = await session._settle_channel(channel)

    assert settled == rpc.sent_signatures[0]
    # The poll loop was entered: more than one status query for the same sig.
    assert len(rpc.status_queries) >= 3
    final = await session._core.store().get_channel(channel)
    assert final is not None
    assert final.sealed is True
    assert final.settled_signature == rpc.sent_signatures[0]
    assert final.settling is False


@pytest.mark.asyncio
async def test_settle_not_confirmed_within_timeout_preserves_signature_for_reconciliation() -> None:
    """An ambiguous post-broadcast timeout keeps the signature and replays only
    confirmation, never a fresh settlement transaction."""

    class _StuckNoneRpc(_SettleRpc):
        confirmed = False

        async def get_signature_statuses(
            self, signatures: list[str], *, search_transaction_history: bool = False
        ) -> list[dict | None]:
            self.status_queries.append(list(signatures))
            if self.confirmed:
                return [{"err": None, "confirmationStatus": "confirmed"} for _ in signatures]
            return [None for _ in signatures]

    operator = Keypair.from_seed(bytes([23] * 32))
    channel = str(Keypair.from_seed(bytes([24] * 32)).pubkey())

    rpc = _StuckNoneRpc()
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

    import inspect

    import solana_pay_kit.protocols.mpp.server.session_onchain as onchain

    confirm = onchain.confirm_transaction_signature
    timeout_kw = "timeout_seconds"
    params = inspect.signature(confirm).parameters
    # The helper may accept timeout_seconds as a keyword-only arg; pass the
    # smallest nonzero timeout plus a tiny poll interval so the test is fast.
    kwargs: dict[str, float] = {}
    if timeout_kw in params:
        kwargs[timeout_kw] = 0.1
    if "poll_interval_seconds" in params:
        kwargs["poll_interval_seconds"] = 0.05
    # Monkey-patch the module-level helper reference used by settle_and_seal
    # via the session_onchain module so the timeout applies.
    original = onchain.confirm_transaction_signature

    async def fast_confirm(rpc_client, signature, label, **kw):  # noqa: ANN001, ANN002, ANN003
        kw.update(kwargs)
        return await original(rpc_client, signature, label, **kw)

    onchain.confirm_transaction_signature = fast_confirm  # type: ignore[assignment]
    try:
        with pytest.raises(PaymentError, match="not found"):
            await session._settle_channel(channel)
    finally:
        onchain.confirm_transaction_signature = original  # type: ignore[assignment]

    final = await session._core.store().get_channel(channel)
    assert final is not None
    assert final.sealed is False
    assert final.settled_signature == rpc.sent_signatures[0]
    assert final.settling is True
    assert len(rpc.sent) == 1

    rpc.confirmed = True
    reconciled = await session._settle_channel(channel)

    assert reconciled == rpc.sent_signatures[0]
    assert len(rpc.sent) == 1
    final = await session._core.store().get_channel(channel)
    assert final is not None
    assert final.sealed is True
    assert final.settled_signature == rpc.sent_signatures[0]
    assert final.settling is False


# --- S2: double-settle concurrency guard ---------------------------------------


@pytest.mark.asyncio
async def test_concurrent_settle_claimed_once_does_not_double_broadcast() -> None:
    """S2: a second ``_settle_channel`` call while the first is mid-flight (or
    after the first sealed) must not broadcast a second settle tx. The
    atomic ``settling`` claim serializes concurrent callers; a second caller
    after seal is short-circuited by the already-sealed check.
    """

    operator = Keypair.from_seed(bytes([25] * 32))
    channel = str(Keypair.from_seed(bytes([26] * 32)).pubkey())

    rpc = _SettleRpc()
    session = _session(rpc, operator)
    await _seed(
        session,
        ChannelState(
            channel_id=channel,
            authorized_signer=str(operator.pubkey()),
            deposit=1_000_000,
            cumulative=100_000,
            highest_voucher_signature=str(operator.sign_message(b"v")),
            highest_voucher_expires_at=4_102_444_800,
            operator=str(operator.pubkey()),
        ),
    )

    first = await session._settle_channel(channel)
    second = await session._settle_channel(channel)

    assert first == rpc.sent_signatures[0]
    assert second == rpc.sent_signatures[0]
    assert len(rpc.sent) == 1
    final = await session._core.store().get_channel(channel)
    assert final is not None
    assert final.sealed is True
    assert final.settling is False


@pytest.mark.asyncio
async def test_concurrent_settle_in_progress_guard_blocks_second_caller() -> None:
    """S2: a channel in ``settling=True`` state (claim taken mid-broadcast) is
    seen as busy by a second caller, which receives a retryable error instead
    of a receipt or a re-broadcast."""

    operator = Keypair.from_seed(bytes([28] * 32))
    channel = str(Keypair.from_seed(bytes([29] * 32)).pubkey())

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
            settling=True,
        ),
    )

    with pytest.raises(PaymentError, match="already in progress") as excinfo:
        await session._settle_channel(channel)
    assert excinfo.value.retryable is True
    assert len(rpc.sent) == 0
    state = await session._core.store().get_channel(channel)
    assert state is not None
    assert state.sealed is False
    assert state.settling is True


@pytest.mark.asyncio
async def test_public_concurrent_close_does_not_issue_receipt_while_claim_is_owned() -> None:
    """The public gate must not turn a busy settlement into a success receipt."""

    class _BlockedBroadcastRpc(_SettleRpc):
        def __init__(self) -> None:
            super().__init__()
            self.block_next_blockhash = False
            self.blockhash_requested = asyncio.Event()
            self.release = asyncio.Event()

        async def get_latest_blockhash(self, commitment: str = "confirmed") -> _Resp:
            if not self.block_next_blockhash:
                return await super().get_latest_blockhash(commitment)
            self.block_next_blockhash = False
            self.blockhash_requested.set()
            await self.release.wait()
            return await super().get_latest_blockhash(commitment)

        async def get_signature_statuses(
            self, signatures: list[str], *, search_transaction_history: bool = False
        ) -> list[dict | None]:
            self.status_queries.append(list(signatures))
            return [{"err": {"InstructionError": [0, "Custom"]}} for _ in signatures]

    operator = Keypair.from_seed(bytes([41] * 32))
    channel = str(Keypair.from_seed(bytes([42] * 32)).pubkey())
    rpc = _BlockedBroadcastRpc()
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

    options = SessionChallengeOptions()
    challenge = await session.challenge(options)
    credential = PaymentCredential(
        challenge=challenge.to_echo(),
        payload=SessionAction.close_action(ClosePayload(channel_id=channel)).to_dict(),
    )
    authorization = format_authorization(credential)

    rpc.block_next_blockhash = True
    owner = asyncio.create_task(session.handle(authorization, options))
    await rpc.blockhash_requested.wait()

    losing_result = await session.handle(authorization, options)

    assert losing_result.ok is False
    assert losing_result.status == 402
    assert PAYMENT_RECEIPT_HEADER not in losing_result.headers

    rpc.release.set()
    owner_result = await owner
    assert owner_result.ok is False
    assert PAYMENT_RECEIPT_HEADER not in owner_result.headers
    assert len(rpc.sent) == 1


@pytest.mark.asyncio
async def test_cancelled_settle_releases_pre_broadcast_claim() -> None:
    """Cancellation before broadcast must not leave the channel permanently busy."""

    class _BlockedBlockhashRpc(_SettleRpc):
        def __init__(self) -> None:
            super().__init__()
            self.blockhash_requested = asyncio.Event()
            self.release = asyncio.Event()

        async def get_latest_blockhash(self, commitment: str = "confirmed") -> _Resp:
            self.blockhash_requested.set()
            await self.release.wait()
            return await super().get_latest_blockhash(commitment)

    operator = Keypair.from_seed(bytes([43] * 32))
    channel = str(Keypair.from_seed(bytes([44] * 32)).pubkey())
    rpc = _BlockedBlockhashRpc()
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

    pending = asyncio.create_task(session._settle_channel(channel))
    await rpc.blockhash_requested.wait()
    pending.cancel()

    with pytest.raises(asyncio.CancelledError):
        await pending

    state = await session._core.store().get_channel(channel)
    assert state is not None
    assert state.sealed is False
    assert state.settled_signature is None
    assert state.settling is False
    assert rpc.sent == []


@pytest.mark.asyncio
async def test_cancelled_post_broadcast_settle_preserves_signature_for_reconciliation() -> None:
    """Cancellation after RPC acceptance records the signature before releasing."""

    class _BlockedConfirmationRpc(_SettleRpc):
        def __init__(self) -> None:
            super().__init__()
            self.confirmation_requested = asyncio.Event()
            self.release = asyncio.Event()
            self.confirmed = False

        async def get_signature_statuses(
            self, signatures: list[str], *, search_transaction_history: bool = False
        ) -> list[dict | None]:
            self.status_queries.append(list(signatures))
            self.search_history_queries.append(search_transaction_history)
            if self.confirmed:
                return [{"err": None, "confirmationStatus": "confirmed"} for _ in signatures]
            self.confirmation_requested.set()
            await self.release.wait()
            return [{"err": None, "confirmationStatus": "confirmed"} for _ in signatures]

    operator = Keypair.from_seed(bytes([45] * 32))
    channel = str(Keypair.from_seed(bytes([46] * 32)).pubkey())
    rpc = _BlockedConfirmationRpc()
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

    pending = asyncio.create_task(session._settle_channel(channel))
    await rpc.confirmation_requested.wait()
    pending.cancel()

    with pytest.raises(asyncio.CancelledError):
        await pending

    state = await session._core.store().get_channel(channel)
    assert state is not None
    assert state.sealed is False
    assert state.settled_signature == rpc.sent_signatures[0]
    assert state.settling is True
    assert len(rpc.sent) == 1

    rpc.confirmed = True
    assert await session._settle_channel(channel) == rpc.sent_signatures[0]
    assert len(rpc.sent) == 1
    assert rpc.search_history_queries[-1] is True
    state = await session._core.store().get_channel(channel)
    assert state is not None
    assert state.sealed is True
    assert state.settling is False


@pytest.mark.asyncio
async def test_settlement_intent_persistence_failure_prevents_send_and_recovers() -> None:
    """A failed durable intent write happens before send, so retry is safe."""

    class _RejectIntentStore(MemoryChannelStore):
        def __init__(self) -> None:
            super().__init__()
            self.reject_next_intent = False

        async def update_channel(self, channel_id, mutator):  # type: ignore[override]
            def guarded(current):
                next_state = mutator(current)
                if (
                    self.reject_next_intent
                    and current is not None
                    and current.settled_signature is None
                    and next_state.settled_signature is not None
                ):
                    self.reject_next_intent = False
                    raise OSError("durable store unavailable")
                return next_state

            return await super().update_channel(channel_id, guarded)

    operator = Keypair.from_seed(bytes([60] * 32))
    channel = str(Keypair.from_seed(bytes([61] * 32)).pubkey())
    rpc = _SettleRpc()
    store = _RejectIntentStore()
    session = _session(rpc, operator, store=store)
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
    store.reject_next_intent = True

    with pytest.raises(OSError, match="durable store unavailable"):
        await session._settle_channel(channel)

    state = await store.get_channel(channel)
    assert state is not None
    assert state.settled_signature is None
    assert state.settling is False
    assert rpc.sent == []

    signature = await session._settle_channel(channel)
    assert signature == rpc.sent_signatures[0]
    assert len(rpc.sent) == 1


@pytest.mark.asyncio
async def test_settlement_post_send_state_failure_reconciles_durable_intent() -> None:
    """A write failure after send retains the pre-persisted intent for recovery."""

    class _RejectSealStore(MemoryChannelStore):
        def __init__(self) -> None:
            super().__init__()
            self.reject_next_seal = False

        async def update_channel(self, channel_id, mutator):  # type: ignore[override]
            def guarded(current):
                next_state = mutator(current)
                if (
                    self.reject_next_seal
                    and current is not None
                    and not current.sealed
                    and current.settled_signature is not None
                    and next_state.sealed
                ):
                    self.reject_next_seal = False
                    raise OSError("durable store unavailable after broadcast")
                return next_state

            return await super().update_channel(channel_id, guarded)

    operator = Keypair.from_seed(bytes([62] * 32))
    channel = str(Keypair.from_seed(bytes([63] * 32)).pubkey())
    rpc = _SettleRpc()
    store = _RejectSealStore()
    session = _session(rpc, operator, store=store)
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
    store.reject_next_seal = True

    with pytest.raises(OSError, match="durable store unavailable after broadcast"):
        await session._settle_channel(channel)

    state = await store.get_channel(channel)
    assert state is not None
    assert state.sealed is False
    assert state.settling is True
    assert state.settled_signature == rpc.sent_signatures[0]
    assert len(rpc.sent) == 1

    assert await session._settle_channel(channel) == rpc.sent_signatures[0]
    assert len(rpc.sent) == 1
    assert rpc.search_history_queries[-1] is True
    state = await store.get_channel(channel)
    assert state is not None and state.sealed is True


@pytest.mark.asyncio
async def test_settlement_reconciliation_searches_transaction_history() -> None:
    """A durable intent outside the recent-status cache is still reconciled."""

    class _HistoryOnlyRpc(_SettleRpc):
        async def get_signature_statuses(
            self, signatures: list[str], *, search_transaction_history: bool = False
        ) -> list[dict | None]:
            self.status_queries.append(list(signatures))
            self.search_history_queries.append(search_transaction_history)
            if search_transaction_history:
                return [{"err": None, "confirmationStatus": "finalized"} for _ in signatures]
            return [None for _ in signatures]

    operator = Keypair.from_seed(bytes([62] * 32))
    channel = str(Keypair.from_seed(bytes([63] * 32)).pubkey())
    signature = str(operator.sign_message(b"historical-settlement"))
    rpc = _HistoryOnlyRpc()
    session = _session(rpc, operator)
    await _seed(
        session,
        ChannelState(
            channel_id=channel,
            authorized_signer=str(operator.pubkey()),
            deposit=1_000_000,
            cumulative=0,
            settled_signature=signature,
            settling=True,
            operator=str(operator.pubkey()),
        ),
    )

    assert await session._settle_channel(channel) == signature
    assert rpc.sent == []
    assert rpc.search_history_queries == [True]
    state = await session._core.store().get_channel(channel)
    assert state is not None and state.sealed is True


@pytest.mark.asyncio
async def test_cancelled_during_settlement_send_keeps_claim_for_reconciliation() -> None:
    """Cancellation while send is unresolved cannot reopen a possibly sent tx."""

    class _BlockedSendRpc(_SettleRpc):
        def __init__(self) -> None:
            super().__init__()
            self.send_started = asyncio.Event()
            self.release = asyncio.Event()

        async def send_raw_transaction(self, raw_tx: bytes) -> _Resp:
            self.sent.append(raw_tx)
            self.send_started.set()
            await self.release.wait()
            return await super().send_raw_transaction(raw_tx)

    operator = Keypair.from_seed(bytes([64] * 32))
    channel = str(Keypair.from_seed(bytes([65] * 32)).pubkey())
    rpc = _BlockedSendRpc()
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

    pending = asyncio.create_task(session._settle_channel(channel))
    await rpc.send_started.wait()
    pending.cancel()
    with pytest.raises(asyncio.CancelledError):
        await pending

    state = await session._core.store().get_channel(channel)
    assert state is not None
    assert state.sealed is False
    assert state.settling is True
    assert state.settled_signature == str(Transaction.from_bytes(rpc.sent[0]).signatures[0])

    assert await session._settle_channel(channel) == state.settled_signature
    assert len(rpc.sent) == 1
    assert rpc.search_history_queries[-1] is True


@pytest.mark.asyncio
async def test_server_broadcast_open_claim_serializes_workers() -> None:
    """Two workers share one signed open outbox instead of racing broadcasts."""

    class _BlockedOpenRpc(_SettleRpc):
        def __init__(self) -> None:
            super().__init__()
            self.send_started = asyncio.Event()
            self.release = asyncio.Event()

        async def send_raw_transaction(self, raw_tx: bytes) -> _Resp:
            self.sent.append(raw_tx)
            signature = str(Transaction.from_bytes(raw_tx).signatures[0])
            self.sent_signatures.append(signature)
            self.send_started.set()
            await self.release.wait()
            return _Resp(signature)

    operator = Keypair.from_seed(bytes([66] * 32))
    rpc = _BlockedOpenRpc()
    store = MemoryChannelStore()
    first_session = _session(rpc, operator, store=store, open_tx_submitter="server")
    second_session = _session(rpc, operator, store=store, open_tx_submitter="server")
    open_, payload = _server_open_payload(operator)
    payload.deposit = "1500000"
    competing_payload = copy.deepcopy(payload)

    first = asyncio.create_task(first_session._handle_open(payload))
    await rpc.send_started.wait()

    with pytest.raises(PaymentError, match="already in progress") as excinfo:
        await second_session._handle_open(competing_payload)
    assert excinfo.value.retryable is True
    assert len(rpc.sent) == 1

    rpc.release.set()
    assert await first == rpc.sent_signatures[0]
    assert len(rpc.sent) == 1
    persisted = await store.get_channel(str(open_.channel_id))
    assert persisted is not None and persisted.deposit == open_.deposit


@pytest.mark.asyncio
async def test_server_open_recovery_rejects_different_verified_facts_before_broadcast() -> None:
    """An expired outbox cannot bind its old signed wire to new open facts."""

    class _FailFirstOpenSendRpc(_SettleRpc):
        def __init__(self) -> None:
            super().__init__()
            self.fail_first_send = True

        async def send_raw_transaction(self, raw_tx: bytes) -> _Resp:
            self.sent.append(raw_tx)
            signature = str(Transaction.from_bytes(raw_tx).signatures[0])
            self.sent_signatures.append(signature)
            if self.fail_first_send:
                self.fail_first_send = False
                raise OSError("simulated open send failure")
            return _Resp(signature)

    from solana_pay_kit.protocols.mpp.server.session_method import _open_outbox_key

    operator = Keypair.from_seed(bytes([67] * 32))
    rpc = _FailFirstOpenSendRpc()
    store = MemoryChannelStore()
    session = _session(rpc, operator, store=store, open_tx_submitter="server", cap=2_000_000)
    old_open, old_payload = _server_open_payload(operator, salt=67)
    recovery_open, recovery_payload = _server_open_payload(operator, cap="1500000", salt=67)
    channel_id = str(old_open.channel_id)
    assert recovery_open.channel_id == old_open.channel_id
    assert recovery_open.deposit != old_open.deposit

    with pytest.raises(OSError, match="simulated open send failure"):
        await session._handle_open(old_payload)
    old_wire = rpc.sent[0]

    def expire_outbox(state: ChannelState | None) -> ChannelState:
        assert state is not None
        expired = state.clone()
        expired.close_requested_at = 0
        return expired

    outbox_key = _open_outbox_key(channel_id)
    expired_outbox = await store.update_channel(outbox_key, expire_outbox)
    assert expired_outbox.deposit == old_open.deposit
    assert expired_outbox.open_slot == old_payload.recent_slot

    with pytest.raises(PaymentError, match="different verified open facts"):
        await session._handle_open(recovery_payload)

    # The recovery request neither re-broadcasts the old wire nor persists its
    # new facts under the old transaction's receipt/signature.
    assert rpc.sent == [old_wire]
    assert await store.get_channel(channel_id) is None
    persisted_outbox = await store.get_channel(outbox_key)
    assert persisted_outbox is not None
    assert persisted_outbox.deposit == old_open.deposit
    assert persisted_outbox.open_slot == old_payload.recent_slot


@pytest.mark.asyncio
async def test_server_open_matching_recovery_claims_one_expired_outbox_lease() -> None:
    """Matching recoveries rebroadcast the durable wire through one lease owner."""

    class _FailThenBlockRecoveryRpc(_SettleRpc):
        def __init__(self) -> None:
            super().__init__()
            self.fail_first_send = True
            self.recovery_send_started = asyncio.Event()
            self.release_recovery = asyncio.Event()

        async def send_raw_transaction(self, raw_tx: bytes) -> _Resp:
            self.sent.append(raw_tx)
            signature = str(Transaction.from_bytes(raw_tx).signatures[0])
            self.sent_signatures.append(signature)
            if self.fail_first_send:
                self.fail_first_send = False
                raise OSError("simulated open send failure")
            self.recovery_send_started.set()
            await self.release_recovery.wait()
            return _Resp(signature)

    from solana_pay_kit.protocols.mpp.server.session_method import _open_outbox_key

    operator = Keypair.from_seed(bytes([68] * 32))
    rpc = _FailThenBlockRecoveryRpc()
    store = MemoryChannelStore()
    first_session = _session(rpc, operator, store=store, open_tx_submitter="server")
    second_session = _session(rpc, operator, store=store, open_tx_submitter="server")
    open_, original_payload = _server_open_payload(operator, salt=68)
    channel_id = str(open_.channel_id)

    with pytest.raises(OSError, match="simulated open send failure"):
        await first_session._handle_open(original_payload)
    persisted_wire = rpc.sent[0]
    persisted_signature = rpc.sent_signatures[0]

    def expire_outbox(state: ChannelState | None) -> ChannelState:
        assert state is not None
        expired = state.clone()
        expired.close_requested_at = 0
        return expired

    outbox_key = _open_outbox_key(channel_id)
    await store.update_channel(outbox_key, expire_outbox)

    recovery_open, recovery_payload = _server_open_payload(operator, salt=68)
    assert recovery_open.channel_id == open_.channel_id
    competing_payload = copy.deepcopy(recovery_payload)
    recovering = asyncio.create_task(first_session._handle_open(recovery_payload))
    await rpc.recovery_send_started.wait()

    with pytest.raises(PaymentError, match="already in progress") as excinfo:
        await second_session._handle_open(competing_payload)
    assert excinfo.value.retryable is True
    assert rpc.sent == [persisted_wire, persisted_wire]

    rpc.release_recovery.set()
    assert await recovering == persisted_signature
    assert len(rpc.sent) == 2
    persisted_channel = await store.get_channel(channel_id)
    assert persisted_channel is not None
    assert persisted_channel.authorized_signer == original_payload.authorized_signer
    assert persisted_channel.deposit == open_.deposit
    assert persisted_channel.operator == original_payload.payer
    assert persisted_channel.open_slot == original_payload.recent_slot
    assert await store.get_channel(outbox_key) is None


# --- S1: server-broadcast open replay does not re-broadcast -------------------


@pytest.mark.asyncio
async def test_server_broadcast_open_replay_does_not_re_broadcast() -> None:
    """S1: a replayed server-broadcast open (same payload, channel already
    persisted) must NOT call ``send_raw_transaction`` again. The store
    idempotency pre-check short-circuits the broadcast; ``process_open`` is
    still the final source of truth (the existing state is returned
    unchanged, the voucher watermark is preserved)."""

    operator = Keypair.from_seed(bytes([27] * 32))
    rpc = _SettleRpc()
    session = new_session(
        SessionOptions(
            operator=str(operator.pubkey()),
            recipient=str(operator.pubkey()),
            cap=2_000_000,
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
    payload.deposit = "1500000"

    first = await session._handle_open(payload)
    assert first == rpc.sent_signatures[0]
    assert len(rpc.sent) == 1

    replay = await session._handle_open(payload)

    # No second broadcast on replay.
    assert len(rpc.sent) == 1
    # The replay returns the original signature (already recorded).
    assert replay == rpc.sent_signatures[0]
    persisted = await session._core.store().get_channel(str(open_.channel_id))
    assert persisted is not None
    assert persisted.deposit == open_.deposit
