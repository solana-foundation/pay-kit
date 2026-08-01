"""HTTP session-method tests for expiry, authentication, and idempotency."""

from __future__ import annotations

import pytest
from solders.keypair import Keypair  # type: ignore[import-untyped]

from solana_pay_kit._paycore.errors import PaymentError
from solana_pay_kit.protocols.mpp._paymentchannels import PROGRAM_ID
from solana_pay_kit.protocols.mpp.core.headers import format_authorization
from solana_pay_kit.protocols.mpp.core.types import PaymentChallenge, PaymentCredential
from solana_pay_kit.protocols.mpp.intents.session import (
    ClosePayload,
    OpenPayload,
    SessionAction,
    SignedVoucher,
    TopUpPayload,
    UsePayload,
    VoucherData,
    VoucherPayload,
    sign_session_authentication,
)
from solana_pay_kit.protocols.mpp.server.session import SessionConfig, SessionServer, Split
from solana_pay_kit.protocols.mpp.server.session_method import (
    Session,
    SessionChallengeOptions,
    SessionOptions,
    new_session,
)
from solana_pay_kit.protocols.mpp.server.session_store import ChannelState, MemoryChannelStore
from solana_pay_kit.signer import LocalSigner

SECRET = "session-method-secret"
RECIPIENT = str(Keypair.from_seed(bytes([7] * 32)).pubkey())

# Pinned challenge open-transaction context (recentBlockhash, recentSlot):
# every challenge in this module advertises this pair via the blockhash cache
# or the RPC double, mirroring the Rust test_blockhash/CHALLENGED_SLOT pair.
CHALLENGED_BLOCKHASH = "4vJ9JU1bJJQpUgJ8V6hYz7xXKz4F2tN6aBrZEcD3xKhs"
CHALLENGED_SLOT = 42


class _Rpc:
    """RPC double: serves the pinned challenge blockhash context; funding
    tests inject the lower seam."""

    async def get_latest_blockhash(self, commitment: str = "confirmed") -> object:
        del commitment

        class _Ctx:
            slot = CHALLENGED_SLOT

        class _Value:
            blockhash = CHALLENGED_BLOCKHASH

        class _Resp:
            value = _Value()
            context = _Ctx()

        return _Resp()


def _core(config: SessionConfig, store: MemoryChannelStore | None = None) -> SessionServer:
    """A SessionServer whose challenges serve the pinned open-transaction
    context from a blockhash cache."""
    return SessionServer(config, store if store is not None else MemoryChannelStore()).with_blockhash_cache(
        lambda: (CHALLENGED_BLOCKHASH, CHALLENGED_SLOT)
    )


def _options(**overrides: object) -> SessionOptions:
    options = SessionOptions(
        recipient=RECIPIENT,
        amount=25,
        currency="USDC",
        decimals=6,
        network="localnet",
        secret_key=SECRET,
        realm="api.test",
        rpc=_Rpc(),  # type: ignore[arg-type]
    )
    for key, value in overrides.items():
        setattr(options, key, value)
    return options


async def _challenge(core: SessionServer, expires: str) -> PaymentChallenge:
    return PaymentChallenge.with_secret_key(
        secret_key=SECRET,
        realm="api.test",
        method="solana",
        intent="session",
        request=PaymentChallenge.encode_request((await core.build_challenge_request()).to_dict()),
        expires=expires,
    )


def _session(core: SessionServer) -> Session:
    return Session(
        core=core,
        secret_key=SECRET,
        realm="api.test",
        amount=25,
        currency="USDC",
        recipient=RECIPIENT,
        network="localnet",
        rpc=None,
        lifecycle=None,
    )


def _voucher_payload(voucher):
    return VoucherPayload(channel_id=voucher.data.channel_id, voucher=voucher)


def test_new_session_fails_closed_without_rpc() -> None:
    with pytest.raises(PaymentError, match="RPC client"):
        new_session(_options(rpc=None))


def test_new_session_validates_amount_recipient_and_fee_payer() -> None:
    with pytest.raises(PaymentError, match="amount must be positive"):
        new_session(_options(amount=0))
    with pytest.raises(PaymentError, match="recipient is required"):
        new_session(_options(recipient=""))
    with pytest.raises(PaymentError, match="fee payer mode requires signer"):
        new_session(_options(fee_payer=True))


def test_new_session_validates_remaining_configuration(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(PaymentError, match="invalid recipient"):
        new_session(_options(recipient="not-base58"))
    with pytest.raises(PaymentError, match="splits cannot exceed"):
        new_session(_options(splits=[Split(RECIPIENT, 1)] * 33))
    monkeypatch.delenv("MPP_SECRET_KEY", raising=False)
    with pytest.raises(PaymentError, match="missing secret key"):
        new_session(_options(secret_key=""))
    with pytest.raises(PaymentError, match="voucherSigner"):
        new_session(_options(voucher_signer="invalid"))
    with pytest.raises(PaymentError, match="requires signer"):
        new_session(_options(voucher_signer="operator"))


async def test_challenge_uses_exact_final_request_shape() -> None:
    session = new_session(_options(suggested_deposit=1_000, minimum_deposit=100))
    challenge = await session.challenge(SessionChallengeOptions(description="metered", external_id="order-1"))
    request = challenge.decode_request()
    assert request["amount"] == "25"
    assert request["suggestedDeposit"] == "1000"
    assert request["minimumDeposit"] == "100"
    assert request["methodDetails"]["channelProgram"] == str(PROGRAM_ID)
    assert request["methodDetails"]["network"] == "localnet"
    # The new-channel challenge carries the open-transaction context fetched
    # through the configured RPC (recentSlot as a decimal string).
    assert request["methodDetails"]["recentBlockhash"] == CHALLENGED_BLOCKHASH
    assert request["methodDetails"]["recentSlot"] == str(CHALLENGED_SLOT)
    for stale in ("cap", "programId", "recentSlot", "modes"):
        assert stale not in request
    session.shutdown()


async def test_open_challenge_expiry_is_enforced() -> None:
    config = SessionConfig(
        recipient=RECIPIENT,
        amount=25,
        currency="USDC",
        decimals=6,
        network="localnet",
        channel_program=str(PROGRAM_ID),
        grace_period_seconds=900,
    )

    async def accept_open(_: OpenPayload, __: object) -> None:
        return None

    config.verify_open_tx = accept_open
    core = _core(config)
    session = _session(core)
    challenge = await _challenge(core, "2020-01-01T00:00:00Z")
    payload = OpenPayload(
        channel_id=RECIPIENT,
        payer=RECIPIENT,
        payee=RECIPIENT,
        mint=RECIPIENT,
        authorized_signer=RECIPIENT,
        salt=1,
        deposit_amount="100",
        grace_period_seconds=900,
        open_slot=1,
        transaction="transaction",
    )
    with pytest.raises(PaymentError, match="expired"):
        await session.verify_credential(
            PaymentCredential(challenge=challenge.to_echo(), payload=SessionAction.open_action(payload).to_dict())
        )


async def test_operator_use_survives_challenge_expiry_and_is_idempotent() -> None:
    payer = Keypair.from_seed(bytes([8] * 32))
    operator = Keypair.from_seed(bytes([9] * 32))
    config = SessionConfig(
        operator=str(operator.pubkey()),
        recipient=RECIPIENT,
        amount=25,
        currency="USDC",
        decimals=6,
        network="localnet",
        channel_program=str(PROGRAM_ID),
        grace_period_seconds=900,
        voucher_signer="operator",
        operator_signer=operator,
    )
    store = MemoryChannelStore()
    core = _core(config, store)
    session = _session(core)
    challenge = await _challenge(core, "2020-01-01T00:00:00Z")
    authentication = sign_session_authentication(challenge.id, RECIPIENT, payer)
    await store.update_channel(
        RECIPIENT,
        lambda _: ChannelState(
            channel_id=RECIPIENT,
            authorized_signer=str(operator.pubkey()),
            payer=str(payer.pubkey()),
            deposit=1_000,
            opening_challenge_id=challenge.id,
            authentication=authentication.to_dict(),
            voucher_signer="operator",
        ),
    )
    action = SessionAction.use_action(UsePayload(RECIPIENT, authentication))
    credential = PaymentCredential(challenge=challenge.to_echo(), payload=action.to_dict())

    first = await session.verify_credential(credential, idempotency_key="request-1")
    refreshed = await session.challenge(SessionChallengeOptions(amount="999", expires="2030-01-01T00:00:00Z"))
    replay = await session.verify_credential(
        PaymentCredential(challenge=refreshed.to_echo(), payload=action.to_dict()),
        idempotency_key="request-1",
    )
    state = await store.get_channel(RECIPIENT)
    assert first.reference == replay.reference
    assert state is not None and state.cumulative == 25 and len(state.processed_uses) == 1


async def test_operator_close_requires_bound_authentication() -> None:
    payer = Keypair.from_seed(bytes([8] * 32))
    operator = Keypair.from_seed(bytes([9] * 32))
    challenge_id = "opening"
    authentication = sign_session_authentication(challenge_id, RECIPIENT, payer)
    store = MemoryChannelStore()
    core = SessionServer(
        SessionConfig(
            operator=str(operator.pubkey()),
            recipient=RECIPIENT,
            amount=25,
            currency="USDC",
            network="localnet",
            channel_program=str(PROGRAM_ID),
            voucher_signer="operator",
            operator_signer=operator,
        ),
        store,
    )
    await store.update_channel(
        RECIPIENT,
        lambda _: ChannelState(
            channel_id=RECIPIENT,
            authorized_signer=str(operator.pubkey()),
            payer=str(payer.pubkey()),
            deposit=1_000,
            opening_challenge_id=challenge_id,
            authentication=authentication.to_dict(),
            voucher_signer="operator",
        ),
    )
    with pytest.raises(ValueError, match="authentication"):
        await core.process_close(ClosePayload(RECIPIENT))
    await core.process_close(ClosePayload(RECIPIENT, authentication=authentication))
    state = await store.get_channel(RECIPIENT)
    assert state is not None and state.close_requested_at is not None


def test_operator_new_session_uses_signer_identity() -> None:
    signer = LocalSigner.from_keypair(Keypair.from_seed(bytes([11] * 32)))
    session = new_session(_options(voucher_signer="operator", signer=signer))
    assert session.core().config.operator == str(signer.pubkey())
    session.shutdown()


async def test_challenge_rejects_non_u64_amounts() -> None:
    session = new_session(_options())
    for amount in ("-1", "1.5", str(1 << 64)):
        with pytest.raises(PaymentError, match="invalid requested amount"):
            await session.challenge(SessionChallengeOptions(amount=amount))
    session.shutdown()


async def test_handle_returns_challenge_for_missing_and_malformed_credentials() -> None:
    session = new_session(_options())
    missing = await session.handle(None, SessionChallengeOptions(description="metered"))
    assert missing.status == 402 and "www-authenticate" in missing.headers
    malformed = await session.handle("Payment !!!", SessionChallengeOptions())
    assert malformed.status == 402
    assert malformed.body is not None and malformed.body["status"] == 402
    session.shutdown()


@pytest.mark.parametrize("mismatch", ["method", "intent", "realm", "currency", "recipient"])
async def test_pinned_route_fields_reject_cross_route_credentials(mismatch: str) -> None:
    core = _core(
        SessionConfig(
            recipient=RECIPIENT,
            amount=25,
            currency="USDC",
            network="localnet",
            channel_program=str(PROGRAM_ID),
        )
    )
    request = (await core.build_challenge_request()).to_dict()
    method, intent, realm = "solana", "session", "api.test"
    if mismatch == "method":
        method = "tempo"
    elif mismatch == "intent":
        intent = "charge"
    elif mismatch == "realm":
        realm = "other.test"
    elif mismatch == "currency":
        request["currency"] = "USDT"
    else:
        request["recipient"] = str(Keypair().pubkey())
    challenge = PaymentChallenge.with_secret_key(
        secret_key=SECRET,
        realm=realm,
        method=method,
        intent=intent,
        request=PaymentChallenge.encode_request(request),
        expires="2099-01-01T00:00:00Z",
    )
    credential = PaymentCredential(challenge=challenge.to_echo(), payload={"action": "close", "channelId": RECIPIENT})
    with pytest.raises(PaymentError, match="does not match|not a session|recipient"):
        await _session(core).verify_credential(credential)


async def test_verify_dispatches_client_voucher_top_up_and_close() -> None:
    signer = Keypair.from_seed(bytes([13] * 32))
    config = SessionConfig(
        recipient=RECIPIENT,
        amount=25,
        currency="USDC",
        network="localnet",
        channel_program=str(PROGRAM_ID),
        grace_period_seconds=900,
    )

    async def accept_open(_: OpenPayload, __: object) -> None:
        return None

    async def accept_top_up(_: TopUpPayload) -> None:
        return None

    config.verify_open_tx = accept_open
    config.verify_top_up_tx = accept_top_up
    core = _core(config)
    challenge = await _challenge(core, "2099-01-01T00:00:00Z")
    payload = OpenPayload(
        channel_id=RECIPIENT,
        payer=RECIPIENT,
        payee=RECIPIENT,
        mint=RECIPIENT,
        authorized_signer=str(signer.pubkey()),
        salt=1,
        deposit_amount="1000",
        grace_period_seconds=900,
        open_slot=1,
        transaction="transaction",
    )
    await core.process_open(payload, challenge)
    session = _session(core)

    def voucher(cumulative: int) -> SignedVoucher:
        data = VoucherData(RECIPIENT, str(cumulative))
        return SignedVoucher(
            data=data,
            signer=str(signer.pubkey()),
            signature=str(signer.sign_message(data.message_bytes())),
        )

    voucher_receipt = await session.verify_credential(
        PaymentCredential(
            challenge=challenge.to_echo(),
            payload=SessionAction.voucher_action(_voucher_payload(voucher(100))).to_dict(),
        )
    )
    assert voucher_receipt.reference == f"{RECIPIENT}:100"
    top_up_receipt = await session.verify_credential(
        PaymentCredential(
            challenge=challenge.to_echo(),
            payload=SessionAction.top_up_action(TopUpPayload(RECIPIENT, "250", "transaction")).to_dict(),
        )
    )
    assert top_up_receipt.reference == RECIPIENT
    close_receipt = await session.verify_credential(
        PaymentCredential(
            challenge=challenge.to_echo(),
            payload=SessionAction.close_action(ClosePayload(RECIPIENT, voucher=voucher(200))).to_dict(),
        )
    )
    assert close_receipt.reference == RECIPIENT


async def test_handle_accepts_valid_operator_use_header() -> None:
    payer = Keypair.from_seed(bytes([14] * 32))
    operator = Keypair.from_seed(bytes([15] * 32))
    config = SessionConfig(
        operator=str(operator.pubkey()),
        recipient=RECIPIENT,
        amount=25,
        currency="USDC",
        network="localnet",
        channel_program=str(PROGRAM_ID),
        voucher_signer="operator",
        operator_signer=operator,
    )
    store = MemoryChannelStore()
    core = _core(config, store)
    session = _session(core)
    challenge = await _challenge(core, "2000-01-01T00:00:00Z")
    authentication = sign_session_authentication(challenge.id, RECIPIENT, payer)
    await store.update_channel(
        RECIPIENT,
        lambda _: ChannelState(
            channel_id=RECIPIENT,
            authorized_signer=str(operator.pubkey()),
            payer=str(payer.pubkey()),
            deposit=1_000,
            opening_challenge_id=challenge.id,
            authentication=authentication.to_dict(),
            voucher_signer="operator",
        ),
    )
    credential = PaymentCredential(
        challenge=challenge.to_echo(),
        payload=SessionAction.use_action(UsePayload(RECIPIENT, authentication)).to_dict(),
    )
    result = await session.handle(
        format_authorization(credential),
        SessionChallengeOptions(),
        idempotency_key="request-1",
    )
    assert result.ok and result.status == 200 and "payment-receipt" in result.headers


class _LifecycleSpy:
    def __init__(self) -> None:
        self.touches: list[tuple[str, float | None]] = []
        self.removed: list[str] = []

    def touch(self, channel_id: str, timeout: float | None = None) -> None:
        self.touches.append((channel_id, timeout))

    def remove_channel(self, channel_id: str) -> None:
        self.removed.append(channel_id)

    def shutdown(self) -> None:
        return None


async def test_idle_close_rechecks_persisted_activity() -> None:
    store = MemoryChannelStore()
    core = SessionServer(
        SessionConfig(recipient=RECIPIENT, amount=25, currency="USDC", network="localnet"),
        store,
    )
    state = ChannelState(
        channel_id=RECIPIENT,
        authorized_signer=RECIPIENT,
        payer=RECIPIENT,
        deposit=1_000,
        idle_timeout_seconds=60,
        last_activity_at=0,
        voucher_signer="operator",
        authentication={"type": "proof"},
    )
    await store.update_channel(RECIPIENT, lambda _: state)
    session = _session(core)
    await session._close_on_idle(RECIPIENT)
    closed = await store.get_channel(RECIPIENT)
    assert closed is not None and closed.close_requested_at is not None


async def test_idle_close_reschedules_recent_activity_and_reconciles_store() -> None:
    import time

    store = MemoryChannelStore()
    core = SessionServer(
        SessionConfig(recipient=RECIPIENT, amount=25, currency="USDC", network="localnet"),
        store,
    )
    state = ChannelState(
        channel_id=RECIPIENT,
        authorized_signer=RECIPIENT,
        payer=RECIPIENT,
        deposit=1_000,
        idle_timeout_seconds=60,
        last_activity_at=int(time.time() * 1000),
    )
    await store.update_channel(RECIPIENT, lambda _: state)
    spy = _LifecycleSpy()
    session = _session(core)
    session._lifecycle = spy  # type: ignore[assignment]
    await session._touch(RECIPIENT)
    await session._close_on_idle(RECIPIENT)
    assert spy.touches and spy.touches[-1][1] is not None
    session._lifecycle_reconciled = False
    await session._reconcile_lifecycle()
    assert len(spy.touches) >= 2


async def test_failed_settle_keeps_the_watchdog_and_the_close_redrives() -> None:
    """A close whose settle fails must not release the idle watchdog
    (``remove_channel`` after the settle, not before) and must stay
    re-drivable: the retried close settles, and only then is the watchdog
    released."""
    signer = Keypair.from_seed(bytes([14] * 32))
    config = SessionConfig(
        recipient=RECIPIENT,
        amount=25,
        currency="USDC",
        network="localnet",
        channel_program=str(PROGRAM_ID),
        grace_period_seconds=900,
    )

    async def accept_open(_: OpenPayload, __: object) -> None:
        return None

    config.verify_open_tx = accept_open
    core = _core(config)
    challenge = await _challenge(core, "2099-01-01T00:00:00Z")
    await core.process_open(
        OpenPayload(
            channel_id=RECIPIENT,
            payer=RECIPIENT,
            payee=RECIPIENT,
            mint=RECIPIENT,
            authorized_signer=str(signer.pubkey()),
            salt=1,
            deposit_amount="1000",
            grace_period_seconds=900,
            open_slot=1,
            transaction="transaction",
        ),
        challenge,
    )
    session = _session(core)
    spy = _LifecycleSpy()
    session._lifecycle = spy  # type: ignore[assignment]

    data = VoucherData(RECIPIENT, "200")
    voucher = SignedVoucher(
        data=data,
        signer=str(signer.pubkey()),
        signature=str(signer.sign_message(data.message_bytes())),
    )

    async def failing_settle(channel_id: str) -> str | None:
        del channel_id
        raise RuntimeError("settle broadcast failed")

    session._settle_channel = failing_settle  # type: ignore[method-assign]
    with pytest.raises(RuntimeError, match="settle broadcast failed"):
        await session._handle_close(ClosePayload(RECIPIENT, voucher=voucher))
    assert spy.removed == []
    stranded = await core.store().get_channel(RECIPIENT)
    assert stranded is not None
    assert stranded.close_requested_at is not None and stranded.settled_signature is None

    async def working_settle(channel_id: str) -> str | None:
        del channel_id
        return "SETTLEDSIG"

    session._settle_channel = working_settle  # type: ignore[method-assign]
    reference = await session._handle_close(ClosePayload(RECIPIENT, voucher=voucher))
    assert reference == "SETTLEDSIG"
    assert spy.removed == [RECIPIENT]


async def test_idle_close_redrives_a_stranded_settle() -> None:
    """Close-pending with no settlement signature means a prior settle never
    landed: a watchdog fire must re-drive the settle, and lifecycle
    reconciliation must re-arm a timer for such channels (and skip settled
    ones)."""
    store = MemoryChannelStore()
    core = SessionServer(
        SessionConfig(recipient=RECIPIENT, amount=25, currency="USDC", network="localnet"),
        store,
    )
    state = ChannelState(
        channel_id=RECIPIENT,
        authorized_signer=RECIPIENT,
        payer=RECIPIENT,
        deposit=1_000,
        idle_timeout_seconds=60,
        last_activity_at=0,
        close_requested_at=1,
    )
    await store.update_channel(RECIPIENT, lambda _: state)
    session = _session(core)
    settled: list[str] = []

    async def spy_settle(channel_id: str) -> str | None:
        settled.append(channel_id)
        return None

    session._settle_channel = spy_settle  # type: ignore[method-assign]
    await session._close_on_idle(RECIPIENT)
    assert settled == [RECIPIENT]

    spy = _LifecycleSpy()
    session._lifecycle = spy  # type: ignore[assignment]
    session._lifecycle_reconciled = False
    await session._reconcile_lifecycle()
    assert (RECIPIENT, 0.001) in spy.touches

    def record_settled(current: ChannelState | None) -> ChannelState:
        assert current is not None
        nxt = current.clone()
        nxt.settled_signature = "SIG"
        return nxt

    await store.update_channel(RECIPIENT, record_settled)
    settled.clear()
    await session._close_on_idle(RECIPIENT)
    assert settled == []

    settled_spy = _LifecycleSpy()
    session._lifecycle = settled_spy  # type: ignore[assignment]
    session._lifecycle_reconciled = False
    await session._reconcile_lifecycle()
    assert settled_spy.touches == []
