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

from pay_kit._paycore.errors import PaymentError
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
    """Captures the broadcast settle transaction and returns a fixed signature.

    ``status_queries`` records every call to ``get_signature_statuses`` so a test
    can assert no on-chain confirmation was attempted on a trust path.
    """

    def __init__(self) -> None:
        self.sent: list[bytes] = []
        self.status_queries: list[list[str]] = []

    async def get_signature_statuses(self, signatures: list[str]) -> list[dict | None]:
        self.status_queries.append(list(signatures))
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
async def test_settle_raises_and_does_not_finalize_when_tx_unconfirmed() -> None:
    """A dropped/failed settle tx must raise (the broadcast is confirmed before
    return), so the channel is NOT marked finalized with an unconfirmed
    signature and the re-drivable-close guard still applies."""

    class _FailingSettleRpc(_SettleRpc):
        async def get_signature_statuses(self, signatures: list[str]) -> list[dict | None]:
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
    assert final.finalized is False
    assert final.settled_signature is None


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
    """A client-built open whose fee-payer (operator) slot the server completes."""
    from pay_kit.protocols.mpp.client.payment_channels import (
        PaymentChannelSessionOpenOptions,
        create_payment_channel_session_opener,
    )
    from pay_kit.protocols.mpp.intents.session import SessionRequest

    payer = Keypair.from_seed(bytes([11] * 32))
    session_signer = Keypair.from_seed(bytes([9] * 32))
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
    opener = create_payment_channel_session_opener(
        request, payer, session_signer, _BLOCKHASH, PaymentChannelSessionOpenOptions()
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

    assert signature == _SENT_SIGNATURE
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
    from pay_kit.protocols.mpp.intents.session import OpenPayload

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
    from pay_kit.protocols.mpp.intents.session import OpenPayload

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

    async def get_signature_statuses(self, signatures: list[str]) -> list[dict | None]:
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
    confirmed, finalizes, and records the signature.
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

    assert settled == _SENT_SIGNATURE
    # The poll loop was entered: more than one status query for the same sig.
    assert len(rpc.status_queries) >= 3
    final = await session._core.store().get_channel(channel)
    assert final is not None
    assert final.finalized is True
    assert final.settled_signature == _SENT_SIGNATURE
    assert final.settling is False


@pytest.mark.asyncio
async def test_settle_not_confirmed_within_timeout_raises_and_releases_settling() -> None:
    """B1: when the poll times out before any status is seen the channel is NOT
    finalized and the settle-in-progress guard is released so a retry can claim
    again (S2)."""

    class _StuckNoneRpc(_SettleRpc):
        async def get_signature_statuses(self, signatures: list[str]) -> list[dict | None]:
            self.status_queries.append(list(signatures))
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

    import pay_kit.protocols.mpp.server.session_onchain as onchain

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
    # Monkey-patch the module-level helper reference used by settle_and_finalize
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
    assert final.finalized is False
    assert final.settled_signature is None
    assert final.settling is False


# --- S2: double-settle concurrency guard ---------------------------------------


@pytest.mark.asyncio
async def test_concurrent_settle_claimed_once_does_not_double_broadcast() -> None:
    """S2: a second ``_settle_channel`` call while the first is mid-flight (or
    after the first finalized) must not broadcast a second settle tx. The
    atomic ``settling`` claim serializes concurrent callers; a second caller
    after finalize is short-circuited by the already-finalized check.
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

    assert first == _SENT_SIGNATURE
    assert second == _SENT_SIGNATURE
    assert len(rpc.sent) == 1
    final = await session._core.store().get_channel(channel)
    assert final is not None
    assert final.finalized is True
    assert final.settling is False


@pytest.mark.asyncio
async def test_concurrent_settle_in_progress_guard_blocks_second_caller() -> None:
    """S2: a channel in ``settling=True`` state (claim taken mid-broadcast) is
    seen as busy by a second caller, which returns ``None`` instead of
    re-broadcasting."""

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

    result = await session._settle_channel(channel)
    assert result is None
    assert len(rpc.sent) == 0
    state = await session._core.store().get_channel(channel)
    assert state is not None
    assert state.finalized is False
    assert state.settling is True


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
    assert first == _SENT_SIGNATURE
    assert len(rpc.sent) == 1

    replay = await session._handle_open(payload)

    # No second broadcast on replay.
    assert len(rpc.sent) == 1
    # The replay returns the original signature (already recorded).
    assert replay == _SENT_SIGNATURE
    persisted = await session._core.store().get_channel(str(open_.channel_id))
    assert persisted is not None
    assert persisted.deposit == open_.deposit
