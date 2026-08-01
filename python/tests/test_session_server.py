"""Core session server tests for final funding and authorization semantics."""

from __future__ import annotations

import asyncio
import time
from dataclasses import replace

import pytest
from solders.keypair import Keypair  # type: ignore[import-untyped]

from solana_pay_kit.protocols.mpp._paymentchannels import PROGRAM_ID
from solana_pay_kit.protocols.mpp.core.types import PaymentChallenge
from solana_pay_kit.protocols.mpp.intents.session import (
    DEFAULT_SESSION_EXPIRES_AT,
    ClosePayload,
    CommitPayload,
    OpenPayload,
    SessionAuthentication,
    SessionSplit,
    SignedVoucher,
    TopUpPayload,
    UsePayload,
    VoucherData,
    VoucherPayload,
    sign_session_authentication,
)
from solana_pay_kit.protocols.mpp.server.session import DeliveryRequest, SessionConfig, SessionServer, Split
from solana_pay_kit.protocols.mpp.server.session_store import ChannelState, MemoryChannelStore

PAYER = Keypair.from_seed(bytes([1] * 32))
PAYEE = str(Keypair.from_seed(bytes([2] * 32)).pubkey())
CLIENT_SIGNER = Keypair.from_seed(bytes([3] * 32))
OPERATOR = Keypair.from_seed(bytes([4] * 32))
CHANNEL = str(Keypair.from_seed(bytes([5] * 32)).pubkey())

# The recentBlockhash/recentSlot every test challenge advertises; matches the
# _open fixture's open_slot so opens bind to the challenge (mirrors the Rust
# CHALLENGED_SLOT / test_blockhash pair).
CHALLENGED_BLOCKHASH = "4vJ9JU1bJJQpUgJ8V6hYz7xXKz4F2tN6aBrZEcD3xKhs"
CHALLENGED_SLOT = 42


def _core(config: SessionConfig) -> SessionServer:
    """A SessionServer whose challenges serve the pinned open-transaction
    context from a blockhash cache (no RPC round-trip)."""
    return SessionServer(config, MemoryChannelStore()).with_blockhash_cache(
        lambda: (CHALLENGED_BLOCKHASH, CHALLENGED_SLOT)
    )


async def _challenge(config: SessionConfig, *, expires: str = "2099-01-01T00:00:00Z") -> PaymentChallenge:
    return PaymentChallenge.with_secret_key(
        secret_key="secret",
        realm="api.test",
        method="solana",
        intent="session",
        request=PaymentChallenge.encode_request((await _core(config).build_challenge_request()).to_dict()),
        expires=expires,
    )


def _config(*, operator: bool = False) -> SessionConfig:
    return SessionConfig(
        operator=str(OPERATOR.pubkey()) if operator else "",
        recipient=PAYEE,
        amount=25,
        currency="USDC",
        decimals=6,
        network="localnet",
        channel_program=str(PROGRAM_ID),
        suggested_deposit=1_000,
        minimum_deposit=100,
        grace_period_seconds=900,
        voucher_signer="operator" if operator else "client",
        operator_signer=OPERATOR if operator else None,
        idle_timeout_options_seconds=[30, 300],
        idle_timeout_seconds=300,
    )


def _authentication(challenge_id: str) -> SessionAuthentication:
    return sign_session_authentication(challenge_id, CHANNEL, PAYER)


def _open(config: SessionConfig, challenge: PaymentChallenge) -> OpenPayload:
    return OpenPayload(
        channel_id=CHANNEL,
        payer=str(PAYER.pubkey()),
        payee=PAYEE,
        mint=str(Keypair.from_seed(bytes([6] * 32)).pubkey()),
        authorized_signer=str(OPERATOR.pubkey())
        if config.voucher_signer == "operator"
        else str(CLIENT_SIGNER.pubkey()),
        salt=7,
        deposit_amount="1000",
        grace_period_seconds=900,
        idle_timeout_seconds=30,
        open_slot=42,
        transaction="transaction",
        authentication=_authentication(challenge.id) if config.voucher_signer == "operator" else None,
    )


def _voucher(cumulative: int) -> SignedVoucher:
    data = VoucherData(CHANNEL, str(cumulative))
    return SignedVoucher(
        data=data,
        signer=str(CLIENT_SIGNER.pubkey()),
        signature=str(CLIENT_SIGNER.sign_message(data.message_bytes())),
    )


async def _server(*, operator: bool = False) -> tuple[SessionServer, SessionConfig, PaymentChallenge]:
    config = _config(operator=operator)

    async def verify_open(_: OpenPayload, __: object) -> None:
        return None

    async def verify_top_up(_: TopUpPayload) -> None:
        return None

    config.verify_open_tx = verify_open
    config.verify_top_up_tx = verify_top_up
    server = SessionServer(config, MemoryChannelStore())
    challenge = await _challenge(config)
    await server.process_open(_open(config, challenge), challenge)
    return server, config, challenge


async def test_build_challenge_request_uses_exact_nested_schema() -> None:
    request = (await _core(_config()).build_challenge_request()).to_dict()
    assert request["amount"] == "25"
    assert request["suggestedDeposit"] == "1000"
    assert request["methodDetails"]["channelProgram"] == str(PROGRAM_ID)
    assert request["methodDetails"]["idleTimeoutOptionsSeconds"] == [30, 300]
    # Both open-transaction context fields come from the one cached
    # getLatestBlockhash entry — never from a per-challenge RPC call — and
    # recentSlot is a decimal string on the wire.
    assert request["methodDetails"]["recentBlockhash"] == CHALLENGED_BLOCKHASH
    assert request["methodDetails"]["recentSlot"] == str(CHALLENGED_SLOT)
    assert "channelId" not in request["methodDetails"]
    assert request["minimumDeposit"] == "100"
    assert "cap" not in request and "programId" not in request


async def test_challenge_fails_without_open_transaction_context() -> None:
    # A new-channel challenge REQUIRES recentBlockhash/recentSlot, so a server
    # with neither a blockhash cache nor an RPC client must fail the challenge
    # (retryable) instead of degrading to a hint-less 402 the client cannot
    # open against.
    server = SessionServer(_config(), MemoryChannelStore())
    with pytest.raises(ValueError, match="recentBlockhash"):
        await server.build_challenge_request()


async def test_challenge_falls_back_to_one_rpc_fetch() -> None:
    class _Rpc:
        calls = 0

        async def get_latest_blockhash(self, commitment: str = "confirmed") -> object:
            type(self).calls += 1

            class _Ctx:
                slot = CHALLENGED_SLOT

            class _Value:
                blockhash = CHALLENGED_BLOCKHASH

            class _Resp:
                value = _Value()
                context = _Ctx()

            return _Resp()

    server = SessionServer(_config(), MemoryChannelStore(), rpc=_Rpc())
    request = await server.build_challenge_request()
    assert _Rpc.calls == 1
    assert request.method_details.recent_blockhash == CHALLENGED_BLOCKHASH
    assert request.method_details.recent_slot == CHALLENGED_SLOT


async def test_challenge_surfaces_rpc_fetch_failure() -> None:
    class _Rpc:
        async def get_latest_blockhash(self, commitment: str = "confirmed") -> object:
            raise RuntimeError("rpc down")

    server = SessionServer(_config(), MemoryChannelStore(), rpc=_Rpc())
    # Fetch failure fails the challenge with a clear error; never a degraded
    # challenge without the fields.
    with pytest.raises(ValueError, match="failed to fetch recentBlockhash/recentSlot.*rpc down"):
        await server.build_challenge_request()


async def test_open_fails_closed_without_rpc_verifier() -> None:
    config = _config()
    challenge = await _challenge(config)
    server = SessionServer(config, MemoryChannelStore())
    with pytest.raises(ValueError, match="requires a configured RPC verifier"):
        await server.process_open(_open(config, challenge), challenge)
    assert await server.store().get_channel(CHANNEL) is None


async def test_open_binds_open_slot_to_challenged_recent_slot() -> None:
    config = _config()

    async def verify(_: OpenPayload, __: object) -> None:
        return None

    config.verify_open_tx = verify
    challenge = await _challenge(config)
    server = SessionServer(config, MemoryChannelStore())

    # An openSlot ahead of the challenged recentSlot was not built for this
    # challenge.
    ahead = _open(config, challenge)
    ahead.open_slot = CHALLENGED_SLOT + 1
    with pytest.raises(ValueError, match="ahead of the challenged recentSlot"):
        await server.process_open(ahead, challenge)

    # An openSlot staler than the 1500-slot freshness window is rejected.
    from solana_pay_kit._paycore.paymentchannels import OPEN_SLOT_WINDOW

    stale_challenge_config = _config()
    stale_challenge_config.verify_open_tx = verify
    stale = PaymentChallenge.with_secret_key(
        secret_key="secret",
        realm="api.test",
        method="solana",
        intent="session",
        request=PaymentChallenge.encode_request(
            (
                await SessionServer(stale_challenge_config, MemoryChannelStore())
                .with_blockhash_cache(lambda: (CHALLENGED_BLOCKHASH, CHALLENGED_SLOT + OPEN_SLOT_WINDOW + 1))
                .build_challenge_request()
            ).to_dict()
        ),
        expires="2099-01-01T00:00:00Z",
    )
    payload = _open(stale_challenge_config, stale)
    with pytest.raises(ValueError, match="outside the 1500-slot freshness window"):
        await SessionServer(stale_challenge_config, MemoryChannelStore()).process_open(payload, stale)

    # An earlier openSlot within the window is accepted.
    earlier = _open(config, challenge)
    earlier.open_slot = CHALLENGED_SLOT - 1
    state = await server.process_open(earlier, challenge)
    assert state.open_slot == CHALLENGED_SLOT - 1


async def test_open_rejects_challenge_without_open_transaction_context() -> None:
    config = _config()

    async def verify(_: OpenPayload, __: object) -> None:
        return None

    config.verify_open_tx = verify
    request = (await _core(config).build_challenge_request()).to_dict()
    del request["methodDetails"]["recentBlockhash"]
    del request["methodDetails"]["recentSlot"]
    challenge = PaymentChallenge.with_secret_key(
        secret_key="secret",
        realm="api.test",
        method="solana",
        intent="session",
        request=PaymentChallenge.encode_request(request),
        expires="2099-01-01T00:00:00Z",
    )
    with pytest.raises(ValueError, match="missing recentBlockhash/recentSlot"):
        await SessionServer(config, MemoryChannelStore()).process_open(_open(config, challenge), challenge)


async def test_open_verifier_receives_challenged_context() -> None:
    config = _config()
    seen: list[object] = []

    async def verify(_: OpenPayload, context: object) -> None:
        seen.append(context)

    config.verify_open_tx = verify
    challenge = await _challenge(config)
    await SessionServer(config, MemoryChannelStore()).process_open(_open(config, challenge), challenge)
    assert len(seen) == 1
    context = seen[0]
    assert context.challenge_id == challenge.id  # type: ignore[attr-defined]
    assert context.recent_blockhash == CHALLENGED_BLOCKHASH  # type: ignore[attr-defined]
    assert context.recent_slot == CHALLENGED_SLOT  # type: ignore[attr-defined]


async def test_open_binds_challenge_payer_and_policy() -> None:
    server, config, challenge = await _server(operator=True)
    state = await server.store().get_channel(CHANNEL)
    assert state is not None
    assert state.payer == str(PAYER.pubkey())
    assert state.opening_challenge_id == challenge.id
    assert state.authentication == _authentication(challenge.id).to_dict()
    assert state.voucher_signer == "operator"
    assert state.idle_timeout_seconds == 30

    wrong = _open(config, challenge)
    wrong.authentication = sign_session_authentication("different", CHANNEL, PAYER)
    with pytest.raises(ValueError, match="opening challenge"):
        await server.process_open(wrong, challenge)


async def test_concurrent_open_verifies_and_persists_once() -> None:
    config = _config()
    calls = 0

    async def verify(_: OpenPayload, __: object) -> None:
        nonlocal calls
        calls += 1
        await asyncio.sleep(0.01)

    config.verify_open_tx = verify
    challenge = await _challenge(config)
    server = SessionServer(config, MemoryChannelStore())
    payload = _open(config, challenge)
    first, replay = await asyncio.gather(
        server.process_open(payload, challenge),
        server.process_open(payload, challenge),
    )
    assert first == replay
    assert calls == 1
    # The replay neither rebroadcasts nor resets the stored watermark.
    assert (await server.store().get_channel(CHANNEL)).cumulative == 0  # type: ignore[union-attr]


async def test_client_voucher_advances_watermark_and_replays_idempotently() -> None:
    server, _, _ = await _server()
    voucher = _voucher(100)
    assert await server.verify_voucher(_voucher_payload(voucher)) == 100
    assert await server.verify_voucher(_voucher_payload(voucher)) == 100
    state = await server.store().get_channel(CHANNEL)
    assert state is not None and state.cumulative == 100


async def test_voucher_action_channel_id_must_match_the_signed_voucher() -> None:
    # The top-level channelId is the routing key; it must never diverge from
    # the signed voucher's inner channelId (spec: servers MUST reject).
    server, _, _ = await _server()
    voucher = _voucher(100)
    with pytest.raises(ValueError, match="does not match the signed voucher"):
        await server.verify_voucher(VoucherPayload("SomeOtherChannel1111111111111111", voucher))
    state = await server.store().get_channel(CHANNEL)
    assert state is not None and state.cumulative == 0


async def test_close_voucher_channel_id_must_match_the_close() -> None:
    # Same routing-key invariant on close: a final voucher bound to another
    # channel is rejected before any state transition.
    server, _, _ = await _server()
    await server.verify_voucher(_voucher_payload(_voucher(100)))
    foreign = _voucher(200)
    foreign.data.channel_id = "SomeOtherChannel1111111111111111"
    with pytest.raises(ValueError, match="does not match the close channelId"):
        await server.process_close(ClosePayload(CHANNEL, voucher=foreign))
    state = await server.store().get_channel(CHANNEL)
    assert state is not None and state.close_requested_at is None


async def test_operator_use_requires_idempotency_and_charges_once() -> None:
    server, _, challenge = await _server(operator=True)
    authentication = _authentication(challenge.id)
    payload = UsePayload(CHANNEL, authentication)
    with pytest.raises(ValueError, match="Idempotency-Key"):
        await server.process_use(payload, challenge.id, "")
    first = await server.process_use(payload, challenge.id, "request-1")
    replay = await server.process_use(payload, "refreshed-challenge", "request-1", 999)
    assert first == replay
    state = await server.store().get_channel(CHANNEL)
    assert state is not None and state.cumulative == 25 and len(state.processed_uses) == 1


async def test_top_up_fails_closed_and_applies_exact_additional_amount() -> None:
    server, config, _ = await _server()
    payload = TopUpPayload(CHANNEL, "250", "transaction")
    config.verify_top_up_tx = None
    with pytest.raises(ValueError, match="requires a configured RPC verifier"):
        await server.process_top_up(payload)

    async def verify(_: TopUpPayload) -> None:
        return None

    config.verify_top_up_tx = verify
    state = await server.process_top_up(payload)
    assert state.deposit == 1_250


async def test_close_enforces_channel_signing_mode() -> None:
    client, _, _ = await _server()
    with pytest.raises(ValueError, match="final voucher"):
        await client.process_close(ClosePayload(CHANNEL))
    await client.process_close(ClosePayload(CHANNEL, voucher=_voucher(100)))

    operator, _, challenge = await _server(operator=True)
    with pytest.raises(ValueError, match="requires authentication"):
        await operator.process_close(ClosePayload(CHANNEL))
    await operator.process_close(ClosePayload(CHANNEL, authentication=_authentication(challenge.id)))


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda payload: setattr(payload, "deposit_amount", "0"), "greater than zero"),
        (lambda payload: setattr(payload, "deposit_amount", "99"), "minimumDeposit"),
        (lambda payload: setattr(payload, "payee", str(Keypair().pubkey())), "payee"),
        (lambda payload: setattr(payload, "grace_period_seconds", 30), "gracePeriodSeconds"),
    ],
)
async def test_open_rejects_final_policy_mismatches(mutate: object, message: str) -> None:
    config = _config()
    challenge = await _challenge(config)
    payload = _open(config, challenge)
    mutate(payload)  # type: ignore[operator]

    async def verify(_: OpenPayload, __: object) -> None:
        return None

    config.verify_open_tx = verify
    with pytest.raises(ValueError, match=message):
        await SessionServer(config, MemoryChannelStore()).process_open(payload, challenge)


async def test_open_rejects_client_authentication_and_verifier_failure() -> None:
    config = _config()
    challenge = await _challenge(config)
    payload = _open(config, challenge)
    payload.authentication = _authentication(challenge.id)

    async def verify(_: OpenPayload, __: object) -> None:
        raise RuntimeError("rpc rejected")

    config.verify_open_tx = verify
    server = SessionServer(config, MemoryChannelStore())
    with pytest.raises(ValueError, match="only valid"):
        await server.process_open(payload, challenge)
    payload.authentication = None
    with pytest.raises(ValueError, match="open tx verification failed: rpc rejected"):
        await server.process_open(payload, challenge)
    assert await server.store().get_channel(CHANNEL) is None


async def test_open_replay_rejects_mismatch_and_sealed_channel() -> None:
    server, config, challenge = await _server()
    mismatch = _open(config, challenge)
    # 41 stays within the challenge's openSlot binding (<= recentSlot 42), so
    # the replay-mismatch check is what rejects it.
    mismatch.open_slot = 41
    with pytest.raises(ValueError, match="does not match"):
        await server.process_open(mismatch, challenge)
    await server.mark_sealed(CHANNEL)
    with pytest.raises(ValueError, match="sealed"):
        await server.process_open(_open(config, challenge), challenge)


async def test_operator_use_rejects_invalid_state_and_amounts() -> None:
    client, _, challenge = await _server()
    with pytest.raises(ValueError, match="operator-signed"):
        await client.process_use(UsePayload(CHANNEL, _authentication(challenge.id)), challenge.id, "key")

    operator, _, challenge = await _server(operator=True)
    bad = SessionAuthentication(challenge.id, str(PAYER.pubkey()), "bad")
    with pytest.raises(ValueError, match="invalid session authentication"):
        await operator.process_use(UsePayload(CHANNEL, bad), challenge.id, "bad-proof")
    with pytest.raises(ValueError, match="positive u64"):
        await operator.process_use(UsePayload(CHANNEL, _authentication(challenge.id)), challenge.id, "zero", 0)
    with pytest.raises(ValueError, match="availability"):
        await operator.process_use(UsePayload(CHANNEL, _authentication(challenge.id)), challenge.id, "too-large", 1_001)
    await operator.process_close(ClosePayload(CHANNEL, authentication=_authentication(challenge.id)))
    with pytest.raises(ValueError, match="closed"):
        await operator.process_use(UsePayload(CHANNEL, _authentication(challenge.id)), challenge.id, "closed")


async def test_use_and_close_name_pre_binding_records() -> None:
    """A record whose binding fields were stripped by a pre-binding writer
    (or that predates proof binding) must fail with its own error, not the
    generic proof-mismatch one."""
    operator, _, challenge = await _server(operator=True)

    def wipe(current: ChannelState | None) -> ChannelState:
        assert current is not None
        return replace(current, opening_challenge_id="", authentication=None, voucher_signer="")

    await operator.store().update_channel(CHANNEL, wipe)

    with pytest.raises(ValueError, match="predates proof binding"):
        await operator.process_use(UsePayload(CHANNEL, _authentication(challenge.id)), challenge.id, "key")
    with pytest.raises(ValueError, match="predates proof binding"):
        await operator.process_close(ClosePayload(CHANNEL, authentication=_authentication(challenge.id)))


async def test_voucher_rejections_cover_channel_mode_delta_and_deposit() -> None:
    server, config, _ = await _server()
    other_channel = str(Keypair.from_seed(bytes([12] * 32)).pubkey())
    other_data = VoucherData(other_channel, "1")
    other_voucher = SignedVoucher(
        data=other_data,
        signer=str(CLIENT_SIGNER.pubkey()),
        signature=str(CLIENT_SIGNER.sign_message(other_data.message_bytes())),
    )
    with pytest.raises(ValueError, match="not found"):
        await server.verify_voucher(_voucher_payload(other_voucher))

    config.min_voucher_delta = 100
    with pytest.raises(ValueError, match="below-min-delta"):
        await server.verify_voucher(_voucher_payload(_voucher(50)))
    await server.verify_voucher(_voucher_payload(_voucher(100)))
    with pytest.raises(ValueError, match="cumulative-not-monotonic"):
        await server.verify_voucher(_voucher_payload(_voucher(99)))
    with pytest.raises(ValueError, match="exceeds-deposit"):
        await server.verify_voucher(_voucher_payload(_voucher(1_001)))

    operator, _, _ = await _server(operator=True)
    with pytest.raises(ValueError, match="client-signed"):
        await operator.verify_voucher(_voucher_payload(_voucher(1)))


async def test_top_up_rejects_invalid_amount_state_and_verifier_errors() -> None:
    server, config, _ = await _server()
    with pytest.raises(ValueError, match="greater than zero"):
        await server.process_top_up(TopUpPayload(CHANNEL, "0", "transaction"))

    async def reject(_: TopUpPayload) -> None:
        raise RuntimeError("rpc rejected")

    config.verify_top_up_tx = reject
    with pytest.raises(ValueError, match="top-up tx verification failed: rpc rejected"):
        await server.process_top_up(TopUpPayload(CHANNEL, "1", "transaction"))

    async def accept(_: TopUpPayload) -> None:
        return None

    config.verify_top_up_tx = accept
    with pytest.raises(ValueError, match="not found"):
        await server.process_top_up(TopUpPayload("missing", "1", "transaction"))
    await server.mark_sealed(CHANNEL)
    with pytest.raises(ValueError, match="sealed"):
        await server.process_top_up(TopUpPayload(CHANNEL, "1", "transaction"))


async def test_delivery_commit_happy_path_and_replay() -> None:
    server, _, _ = await _server()
    first = await server.begin_delivery(DeliveryRequest(CHANNEL, 100))
    assert first.delivery_id == f"{CHANNEL}:1"
    assert first.expires_at == DEFAULT_SESSION_EXPIRES_AT
    custom = await server.begin_delivery(
        DeliveryRequest(CHANNEL, 50, delivery_id="custom", commit_url="https://example.test/commit", proof="p")
    )
    assert custom.commit_url == "https://example.test/commit" and custom.proof == "p"
    receipt = await server.process_commit(CommitPayload(first.delivery_id, _voucher(100)))
    assert receipt.status == "committed" and receipt.amount == "100"
    replay = await server.process_commit(CommitPayload(first.delivery_id, _voucher(100)))
    assert replay.status == "replayed"


async def test_commit_refreshes_activity_watermark_but_replay_does_not() -> None:
    # A channel paying only through the metered-delivery flow must not look
    # idle: the committed path refreshes last_activity_at (the field the
    # idle-close recheck and the post-restart reconcile read), the idempotent
    # replay does not.
    server, _, _ = await _server()
    directive = await server.begin_delivery(DeliveryRequest(CHANNEL, 100))

    def age(current):  # type: ignore[no-untyped-def]
        assert current is not None
        aged = current.clone()
        aged.last_activity_at = 1
        return aged

    await server.store().update_channel(CHANNEL, age)

    receipt = await server.process_commit(CommitPayload(directive.delivery_id, _voucher(100)))
    assert receipt.status == "committed"
    stored = await server.store().get_channel(CHANNEL)
    assert stored is not None and stored.last_activity_at > 1

    before_replay = stored.last_activity_at
    replay = await server.process_commit(CommitPayload(directive.delivery_id, _voucher(100)))
    assert replay.status == "replayed"
    after = await server.store().get_channel(CHANNEL)
    assert after is not None and after.last_activity_at == before_replay


async def test_delivery_and_commit_reject_invalid_reservations() -> None:
    server, _, _ = await _server()
    with pytest.raises(ValueError, match="greater than zero"):
        await server.begin_delivery(DeliveryRequest(CHANNEL, 0))
    with pytest.raises(ValueError, match="not found"):
        await server.begin_delivery(DeliveryRequest("missing", 1))
    await server.begin_delivery(DeliveryRequest(CHANNEL, 900, delivery_id="dup"))
    with pytest.raises(ValueError, match="already exists"):
        await server.begin_delivery(DeliveryRequest(CHANNEL, 1, delivery_id="dup"))
    with pytest.raises(ValueError, match="available deposit"):
        await server.begin_delivery(DeliveryRequest(CHANNEL, 101))
    with pytest.raises(ValueError, match="not found"):
        await server.process_commit(CommitPayload("missing", _voucher(1)))


async def test_commit_rejects_expired_and_over_reserved_vouchers() -> None:
    server, _, _ = await _server()
    expired = await server.begin_delivery(
        DeliveryRequest(CHANNEL, 100, delivery_id="expired", expires_at=int(time.time()) - 1)
    )
    with pytest.raises(ValueError, match="expired"):
        await server.process_commit(CommitPayload(expired.delivery_id, _voucher(100)))

    valid = await server.begin_delivery(DeliveryRequest(CHANNEL, 100, delivery_id="valid"))
    with pytest.raises(ValueError, match="exceeds reserved amount"):
        await server.process_commit(CommitPayload(valid.delivery_id, _voucher(150)))


async def test_open_rejects_unsupported_idle_timeout_before_broadcast() -> None:
    """An unsupported idle-timeout selection must fail before the verifier
    broadcasts the funding transaction: afterwards the deposit is locked in
    escrow and every retry fails the same way (mirrors the Rust/TS ordering)."""
    config = _config()
    broadcasts: list[str] = []

    async def verify_open(payload: OpenPayload, _: object) -> None:
        broadcasts.append(payload.channel_id)

    config.verify_open_tx = verify_open
    challenge = await _challenge(config)
    payload = _open(config, challenge)
    payload.idle_timeout_seconds = 999
    server = SessionServer(config, MemoryChannelStore())
    with pytest.raises(ValueError, match="idleTimeoutSeconds"):
        await server.process_open(payload, challenge)
    assert broadcasts == []


async def test_top_up_credits_exactly_once_per_transaction_signature() -> None:
    """The same signed top-up transaction submitted twice (a retry after a
    lost response, or two in-flight duplicates) must credit the deposit
    exactly once; a distinct transaction still credits."""
    import base64

    from solders.hash import Hash
    from solders.message import Message
    from solders.system_program import TransferParams, transfer
    from solders.transaction import Transaction

    server, _, _ = await _server()
    payer = Keypair.from_seed(bytes([31] * 32))

    def wire(blockhash: Hash) -> tuple[str, str]:
        # Any decodable signed wire transaction works here: the on-chain
        # verifier seam is stubbed by _server(); the real transaction
        # verification is covered by the on-chain tests.
        ix = transfer(TransferParams(from_pubkey=payer.pubkey(), to_pubkey=payer.pubkey(), lamports=1))
        tx = Transaction([payer], Message.new_with_blockhash([ix], payer.pubkey(), blockhash), blockhash)
        return base64.b64encode(bytes(tx)).decode(), str(tx.signatures[0])

    first_wire, first_signature = wire(Hash.default())
    payload = TopUpPayload(CHANNEL, "250", first_wire)
    first = await server.process_top_up(payload)
    assert first.deposit == 1_250
    replayed = await server.process_top_up(payload)
    assert replayed.deposit == 1_250
    state = await server.store().get_channel(CHANNEL)
    assert state is not None and state.deposit == 1_250
    assert state.processed_topup_signatures == [first_signature]

    second_wire, second_signature = wire(Hash.new_unique())
    second = await server.process_top_up(TopUpPayload(CHANNEL, "250", second_wire))
    assert second.deposit == 1_500
    state = await server.store().get_channel(CHANNEL)
    assert state is not None
    assert state.processed_topup_signatures == [first_signature, second_signature]


async def test_client_close_final_voucher_rules_and_double_close() -> None:
    server, _, _ = await _server()
    await server.verify_voucher(_voucher_payload(_voucher(100)))
    with pytest.raises(ValueError, match="must exceed watermark"):
        await server.process_close(ClosePayload(CHANNEL, voucher=_voucher(99)))
    with pytest.raises(ValueError, match="exceeds deposit"):
        await server.process_close(ClosePayload(CHANNEL, voucher=_voucher(1_001)))
    state = await server.process_close(ClosePayload(CHANNEL, voucher=_voucher(200)))
    assert state.cumulative == 200 and state.close_requested_at is not None
    first_close_at = state.close_requested_at

    # No settlement signature recorded yet: a matching close re-drives so a
    # transient settle failure cannot strand the channel close-pending with
    # the merchant's accepted vouchers unsettled.
    redriven = await server.process_close(ClosePayload(CHANNEL, voucher=_voucher(200)))
    assert redriven.close_requested_at == first_close_at
    assert redriven.cumulative == 200 and not redriven.sealed
    # The re-drive must replay the recorded final voucher, not present a new one.
    with pytest.raises(ValueError, match="must replay the recorded final voucher"):
        await server.process_close(ClosePayload(CHANNEL, voucher=_voucher(300)))

    # Once a settlement signature is recorded, a second close hard-rejects.
    def record_settled(current: ChannelState | None) -> ChannelState:
        assert current is not None
        nxt = current.clone()
        nxt.settled_signature = "SIG"
        return nxt

    await server.store().update_channel(CHANNEL, record_settled)
    with pytest.raises(ValueError, match="already requested"):
        await server.process_close(ClosePayload(CHANNEL, voucher=_voucher(200)))


async def test_process_open_binds_distribution_splits_to_the_challenge() -> None:
    # The open must encode exactly the server-configured (challenged) splits:
    # a client-substituted list would commit a different on-chain
    # distributionHash than the distribute the server later builds from its
    # config, stranding every voucher behind a reverting settle bundle.
    platform = str(Keypair.from_seed(bytes([7] * 32)).pubkey())
    attacker = str(Keypair.from_seed(bytes([8] * 32)).pubkey())
    config = _config()
    config.splits = [Split(recipient=platform, bps=500)]

    async def verify_open(_: OpenPayload, __: object) -> None:
        return None

    config.verify_open_tx = verify_open
    challenge = await _challenge(config)

    def open_with(splits: list[SessionSplit]) -> OpenPayload:
        payload = _open(config, challenge)
        payload.distribution_splits = splits
        return payload

    server = SessionServer(config, MemoryChannelStore())
    # Dropping the challenged splits entirely is rejected.
    with pytest.raises(ValueError, match="distributionSplits do not match the challenge"):
        await server.process_open(open_with([]), challenge)
    # Redirecting the challenged share is rejected.
    with pytest.raises(ValueError, match="distributionSplits do not match the challenge"):
        await server.process_open(open_with([SessionSplit(recipient=attacker, share_bps=500)]), challenge)
    # Inflating the challenged share is rejected.
    with pytest.raises(ValueError, match="distributionSplits do not match the challenge"):
        await server.process_open(open_with([SessionSplit(recipient=platform, share_bps=1)]), challenge)
    # The exact challenged splits are accepted.
    state = await server.process_open(open_with([SessionSplit(recipient=platform, share_bps=500)]), challenge)
    assert state.channel_id == CHANNEL


async def test_process_open_rejects_unsolicited_splits() -> None:
    # A challenge with no configured splits must refuse an open that smuggles
    # some in.
    config = _config()

    async def verify_open(_: OpenPayload, __: object) -> None:
        return None

    config.verify_open_tx = verify_open
    challenge = await _challenge(config)
    payload = _open(config, challenge)
    payload.distribution_splits = [SessionSplit(recipient=str(PAYER.pubkey()), share_bps=100)]
    server = SessionServer(config, MemoryChannelStore())
    with pytest.raises(ValueError, match="distributionSplits do not match the challenge"):
        await server.process_open(payload, challenge)


def _voucher_payload(voucher: SignedVoucher) -> VoucherPayload:
    return VoucherPayload(channel_id=voucher.data.channel_id, voucher=voucher)
