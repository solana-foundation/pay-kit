"""The session server's pre-broadcast checks, the authenticate-then-charge
use path and the client's challenge checks (draft-solana-session-00).

Every open here is the SDK client's own open for the challenge the SDK server
issues, so each test exercises the client and server sides together, the way
the conformance vectors in harness/vectors/session-*.json do.
"""

from __future__ import annotations

import base64
from dataclasses import replace

import pytest
from solana_keychain import MemorySigner
from solders.hash import Hash  # type: ignore[import-untyped]
from solders.instruction import AccountMeta, Instruction  # type: ignore[import-untyped]
from solders.keypair import Keypair  # type: ignore[import-untyped]
from solders.message import MessageV0  # type: ignore[import-untyped]
from solders.pubkey import Pubkey  # type: ignore[import-untyped]
from solders.signature import Signature  # type: ignore[import-untyped]
from solders.transaction import VersionedTransaction  # type: ignore[import-untyped]

from solana_pay_kit._paycore.errors import PaymentError
from solana_pay_kit._paycore.paymentchannels import TopUpParams, build_top_up_instruction
from solana_pay_kit._paycore.rpc import SolanaRpc
from solana_pay_kit._paycore.solana import resolve_mint
from solana_pay_kit._paycore.transaction import build_partially_signed_v0_transaction, verify_required_signatures
from solana_pay_kit._paycore.txv1 import (
    TransactionVersionError,
    check_v0_budget_caps,
    require_budget_prefix,
)
from solana_pay_kit.protocols.mpp._paymentchannels import PROGRAM_ID
from solana_pay_kit.protocols.mpp.client.payment_channels import (
    PaymentChannelOpenOptions,
    PaymentChannelSessionOpenOptions,
    create_payment_channel_session_opener,
    validate_session_challenge,
    verify_open_blockhash,
)
from solana_pay_kit.protocols.mpp.intents.session import (
    OpenPayload,
    SessionAuthentication,
    SessionRequest,
    TopUpPayload,
    UsePayload,
    sign_session_authentication,
)
from solana_pay_kit.protocols.mpp.server import session_testkit
from solana_pay_kit.protocols.mpp.server.session import (
    AuthenticatedUse,
    SessionConfig,
    SessionOpenContext,
    SessionServer,
)
from solana_pay_kit.protocols.mpp.server.session_method import SessionOptions, new_session
from solana_pay_kit.protocols.mpp.server.session_onchain import cosign_session_transaction
from solana_pay_kit.protocols.mpp.server.session_store import ChannelState, MemoryChannelStore, ProcessedUse

PAYER = Keypair.from_seed(bytes([21] * 32))
SESSION_KEY = Keypair.from_seed(bytes([22] * 32))
OPERATOR = Keypair.from_seed(bytes([23] * 32))
SPONSOR = Keypair.from_seed(bytes([24] * 32))
STRANGER = Keypair.from_seed(bytes([25] * 32))
RECIPIENT = str(Keypair.from_seed(bytes([26] * 32)).pubkey())
BLOCKHASH = str(Hash.new_unique())
SLOT = 250_000_000
CHALLENGE_ID = "c_session_0001"


def _config(**overrides: object) -> SessionConfig:
    config = SessionConfig(
        operator=str(OPERATOR.pubkey()),
        recipient=RECIPIENT,
        amount=25,
        currency="USDC",
        decimals=6,
        network="devnet",
        minimum_deposit=100,
        suggested_deposit=1_000,
    )
    for key, value in overrides.items():
        setattr(config, key, value)
    return config


def _sponsored() -> SessionConfig:
    return _config(fee_payer=True, fee_payer_key=str(SPONSOR.pubkey()), fee_payer_signer=MemorySigner(SPONSOR))


def _server(config: SessionConfig, store: MemoryChannelStore | None = None) -> SessionServer:
    return SessionServer(config, store or MemoryChannelStore()).with_blockhash_cache(lambda: (BLOCKHASH, SLOT))


def _context(**overrides: object) -> SessionOpenContext:
    context = SessionOpenContext(challenge_id=CHALLENGE_ID, expires="", recent_blockhash=BLOCKHASH, recent_slot=SLOT)
    return replace(context, **overrides)  # type: ignore[arg-type]


async def _open(server: SessionServer, **options: object) -> OpenPayload:
    """The SDK client's open for the challenge ``server`` issues."""
    request = await server.build_challenge_request()
    opened = await create_payment_channel_session_opener(
        request,
        MemorySigner(PAYER),
        MemorySigner(SESSION_KEY),
        options=PaymentChannelSessionOpenOptions(open=PaymentChannelOpenOptions(salt=7), **options),  # type: ignore[arg-type]
    )
    assert opened.action.open is not None
    return opened.action.open


def _resign(payload: OpenPayload, message: MessageV0) -> OpenPayload:
    """``payload`` carrying ``message``, signed by the payer (and only it)."""
    signatures = [
        PAYER.sign_message(bytes(message_bytes(message))) if key == PAYER.pubkey() else Signature.default()
        for key in message.account_keys[: message.header.num_required_signatures]
    ]
    tx = VersionedTransaction.populate(message, signatures)
    return replace(payload, transaction=base64.b64encode(bytes(tx)).decode())


def message_bytes(message: MessageV0) -> bytes:
    from solders.message import to_bytes_versioned  # type: ignore[import-untyped]

    return bytes(to_bytes_versioned(message))


def _decoded(payload: OpenPayload) -> VersionedTransaction:
    return VersionedTransaction.from_bytes(base64.b64decode(payload.transaction))


# ── open ───────────────────────────────────────────────────────────────────


async def test_client_paid_open_passes_every_pre_broadcast_check() -> None:
    server = _server(_config())
    payload = await _open(server)
    await session_testkit.verify_open_pre_broadcast(server, payload, _context())
    await session_testkit.verify_open_transaction_pre_broadcast(server, payload, BLOCKHASH)


async def test_sponsored_open_is_cosigned_in_memory() -> None:
    server = _server(_sponsored())
    payload = await _open(server)
    assert _decoded(payload).signatures[0] == Signature.default()
    await session_testkit.verify_open_pre_broadcast(server, payload, _context())
    cosigned = await cosign_session_transaction(base64.b64decode(payload.transaction), MemorySigner(SPONSOR))
    verify_required_signatures(VersionedTransaction.from_bytes(cosigned))


async def test_sponsored_open_without_signer_is_refused() -> None:
    config = _sponsored()
    server = _server(config)
    payload = await _open(server)
    config.fee_payer_signer = None
    with pytest.raises(PaymentError, match="configured signer"):
        await session_testkit.verify_open_pre_broadcast(server, payload, _context())


async def test_cosign_refuses_a_transaction_another_key_pays_for() -> None:
    server = _server(_config())
    payload = await _open(server)
    with pytest.raises(PaymentError, match="not the transaction fee payer"):
        await cosign_session_transaction(base64.b64decode(payload.transaction), MemorySigner(SPONSOR))


@pytest.mark.parametrize(
    ("edit", "message"),
    [
        ({"mint": str(Keypair().pubkey())}, "mint does not match challenge currency"),
        ({"payee": str(Keypair().pubkey())}, "payee does not match challenge recipient"),
        ({"grace_period_seconds": 60}, "gracePeriodSeconds does not match challenge"),
        ({"salt": 8}, "channelId does not match derived channel PDA"),
        ({"authorized_signer": str(STRANGER.pubkey())}, "channelId does not match derived channel PDA"),
        ({"deposit_amount": "99"}, "below minimumDeposit"),
        ({"deposit_amount": "0"}, "deposit must be greater than zero"),
        ({"payer": "not-a-key"}, "invalid payment-channel payer"),
    ],
)
async def test_open_parameters_bind_to_the_challenge(edit: dict[str, object], message: str) -> None:
    server = _server(_config())
    payload = replace(await _open(server), **edit)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match=message):
        await session_testkit.verify_open_pre_broadcast(server, payload, _context())


async def test_open_refuses_an_off_curve_authorized_signer() -> None:
    server = _server(_config())
    pda = Pubkey.find_program_address([b"x"], PROGRAM_ID)[0]
    payload = replace(await _open(server), authorized_signer=str(pda))
    with pytest.raises(ValueError, match="on-curve"):
        server.payment_channel_open_params(payload)


async def test_sponsored_open_refuses_the_sponsor_as_payer() -> None:
    config = _sponsored()
    config.fee_payer_key = str(PAYER.pubkey())
    server = _server(config)
    with pytest.raises(ValueError, match="must differ from the sponsored fee payer"):
        server.payment_channel_open_params(await _open(_server(_config())))
    config.fee_payer_key = None
    with pytest.raises(ValueError, match="feePayerKey is required"):
        server.payment_channel_open_params(await _open(_server(_config())))


async def test_operator_open_requires_the_operator_and_its_proof() -> None:
    config = _config(voucher_signer="operator", operator_signer=MemorySigner(OPERATOR))
    server = _server(config)
    client_payload = await _open(_server(_config()))
    with pytest.raises(ValueError, match="authorizedSigner to match the operator"):
        server.payment_channel_open_params(client_payload)
    config.operator = " "
    with pytest.raises(ValueError, match="requires a configured operator signer"):
        server.payment_channel_open_params(client_payload)
    config.operator = str(OPERATOR.pubkey())

    request = await server.build_challenge_request()
    channel = (
        await create_payment_channel_session_opener(
            request,
            MemorySigner(PAYER),
            MemorySigner(SESSION_KEY),
            options=PaymentChannelSessionOpenOptions(
                open=PaymentChannelOpenOptions(salt=7),
                authentication=SessionAuthentication(CHALLENGE_ID, str(PAYER.pubkey()), "x"),
            ),
        )
    ).open.channel_id
    proof = await sign_session_authentication(CHALLENGE_ID, str(channel), MemorySigner(PAYER))
    opened = await create_payment_channel_session_opener(
        request,
        MemorySigner(PAYER),
        MemorySigner(SESSION_KEY),
        options=PaymentChannelSessionOpenOptions(open=PaymentChannelOpenOptions(salt=7), authentication=proof),
    )
    assert opened.action.open is not None
    await session_testkit.verify_open_pre_broadcast(server, opened.action.open, _context())
    with pytest.raises(ValueError, match="challengeId does not match"):
        await session_testkit.verify_open_pre_broadcast(server, opened.action.open, _context(challenge_id="other"))
    with pytest.raises(ValueError, match="requires authentication"):
        await session_testkit.verify_open_pre_broadcast(
            server, replace(opened.action.open, authentication=None), _context()
        )
    stranger = await sign_session_authentication(CHALLENGE_ID, str(channel), MemorySigner(STRANGER))
    with pytest.raises(ValueError, match="payer does not match"):
        await session_testkit.verify_open_pre_broadcast(
            server, replace(opened.action.open, authentication=stranger), _context()
        )
    forged = SessionAuthentication(CHALLENGE_ID, str(PAYER.pubkey()), stranger.signature)
    with pytest.raises(ValueError, match="invalid session authentication signature"):
        await session_testkit.verify_open_pre_broadcast(
            server, replace(opened.action.open, authentication=forged), _context()
        )


async def test_client_open_refuses_authentication() -> None:
    server = _server(_config())
    payload = replace(await _open(server), authentication=SessionAuthentication(CHALLENGE_ID, "p", "s"))
    with pytest.raises(ValueError, match="only valid when voucherSigner is operator"):
        await session_testkit.verify_open_pre_broadcast(server, payload, _context())


async def test_open_refuses_an_expired_challenge_and_a_stale_open_slot() -> None:
    server = _server(_config())
    payload = await _open(server)
    with pytest.raises(ValueError, match="challenge expired"):
        await session_testkit.verify_open_pre_broadcast(server, payload, _context(expires="2020-01-01T00:00:00Z"))
    with pytest.raises(ValueError, match="ahead of the challenged recentSlot"):
        await session_testkit.verify_open_pre_broadcast(server, payload, _context(recent_slot=SLOT - 1))
    with pytest.raises(ValueError, match="freshness"):
        await session_testkit.verify_open_pre_broadcast(server, payload, _context(recent_slot=SLOT + 10_000))


async def test_open_transaction_refuses_a_wrong_blockhash_and_fee_payer() -> None:
    server = _server(_config())
    payload = await _open(server)
    with pytest.raises(PaymentError, match="challenged recentBlockhash"):
        await session_testkit.verify_open_transaction_pre_broadcast(server, payload, str(Hash.new_unique()))
    sponsored = _server(_sponsored())
    with pytest.raises(PaymentError, match="fee payer does not match"):
        await session_testkit.verify_open_transaction_pre_broadcast(sponsored, payload, BLOCKHASH)


async def test_open_transaction_refuses_a_foreign_instruction_and_extra_privileges() -> None:
    server = _server(_config())
    payload = await _open(server)
    message = _decoded(payload).message
    ix = message.instructions[-1]
    keys = list(message.account_keys)
    open_ix = Instruction(
        keys[ix.program_id_index],
        bytes(ix.data),
        [AccountMeta(keys[i], message.is_signer(i), message.is_maybe_writable(i)) for i in ix.accounts],
    )
    memo = Instruction(Pubkey.from_string("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"), b"x", [])
    foreign = MessageV0.try_compile(PAYER.pubkey(), [open_ix, memo], [], Hash.from_string(BLOCKHASH))
    with pytest.raises(PaymentError, match="unexpected instruction"):
        await session_testkit.verify_open_transaction_pre_broadcast(server, _resign(payload, foreign), BLOCKHASH)

    # The mint (open account 3) is read-only in the program's open; a message
    # that marks it writable grants a privilege the open does not use.
    mint = Pubkey.from_string(payload.mint)
    writable = Instruction(
        open_ix.program_id,
        open_ix.data,
        [AccountMeta(m.pubkey, m.is_signer, True if m.pubkey == mint else m.is_writable) for m in open_ix.accounts],
    )
    widened = MessageV0.try_compile(PAYER.pubkey(), [writable], [], Hash.from_string(BLOCKHASH))
    with pytest.raises(PaymentError, match="privileges"):
        await session_testkit.verify_open_transaction_pre_broadcast(server, _resign(payload, widened), BLOCKHASH)


async def test_open_transaction_version_policy() -> None:
    server = _server(_config())
    payload = await _open(server)
    server.config.transaction_versions = [1]
    with pytest.raises(PaymentError, match="transaction version 0 is not accepted"):
        await session_testkit.verify_open_transaction_pre_broadcast(server, payload, BLOCKHASH)
    server.config.transaction_versions = [0, 1]
    await session_testkit.verify_open_transaction_pre_broadcast(server, payload, BLOCKHASH)
    assert (await server.build_challenge_request()).method_details.transaction_versions == [0, 1]
    server.config.transaction_versions = None
    assert (await server.build_challenge_request()).method_details.transaction_versions is None


def test_new_session_validates_transaction_versions() -> None:
    class _Rpc:
        async def get_slot(self) -> int:
            return SLOT

    options = SessionOptions(recipient=RECIPIENT, amount=1, secret_key="s" * 32, rpc=_Rpc())  # type: ignore[arg-type]
    session = new_session(replace(options, transaction_versions=[0, 1]))
    assert session.core().config.transaction_versions == [0, 1]
    with pytest.raises(PaymentError, match="unsupported transaction version"):
        new_session(replace(options, transaction_versions=[2]))
    with pytest.raises(PaymentError, match="at least one version"):
        new_session(replace(options, transaction_versions=[]))


# ── version-0 compute budget ───────────────────────────────────────────────


def _budget(*data: bytes, accounts: list[AccountMeta] | None = None) -> MessageV0:
    program = Pubkey.from_string("ComputeBudget111111111111111111111111111111")
    budget = [Instruction(program, d, accounts or []) for d in data]
    transfer = Instruction(Pubkey.default(), b"\x02\x00\x00\x00" + bytes(8), [AccountMeta(PAYER.pubkey(), True, True)])
    return MessageV0.try_compile(PAYER.pubkey(), [*budget, transfer], [], Hash.default())


def _limit(units: int) -> bytes:
    return b"\x02" + units.to_bytes(4, "little")


def _price(micro: int) -> bytes:
    return b"\x03" + micro.to_bytes(8, "little")


def test_v0_budget_caps_and_prefix() -> None:
    declared = check_v0_budget_caps(_budget(_limit(100), _price(5)), 200_000, 10)
    assert declared is not None and declared.unit_limit == 100
    require_budget_prefix(_budget(_limit(100), _price(5)), declared)
    with pytest.raises(TransactionVersionError, match="must precede"):
        message = _budget(_price(5), _limit(100))
        require_budget_prefix(message, check_v0_budget_caps(message, 200_000, 10))  # type: ignore[arg-type]
    with pytest.raises(TransactionVersionError, match="exceeds maximum"):
        check_v0_budget_caps(_budget(_limit(300_000)), 200_000, 10)
    with pytest.raises(TransactionVersionError, match="must be positive"):
        check_v0_budget_caps(_budget(_limit(0)), 200_000, 10)
    with pytest.raises(TransactionVersionError, match="compute unit price 11 exceeds"):
        check_v0_budget_caps(_budget(_limit(100), _price(11)), 200_000, 10)
    with pytest.raises(TransactionVersionError, match="implicit compute unit limit"):
        check_v0_budget_caps(_budget(_price(1)), 100_000, 10)
    with pytest.raises(TransactionVersionError, match="not supported"):
        check_v0_budget_caps(_budget(b"\x04" + (1).to_bytes(4, "little")), 200_000, 10)
    with pytest.raises(TransactionVersionError, match="must not have accounts"):
        check_v0_budget_caps(_budget(_limit(1), accounts=[AccountMeta(STRANGER.pubkey(), False, False)]), 200_000, 10)


def test_v0_budget_prefix_must_lead() -> None:
    program = Pubkey.from_string("ComputeBudget111111111111111111111111111111")
    transfer = Instruction(Pubkey.default(), b"\x02\x00\x00\x00" + bytes(8), [AccountMeta(PAYER.pubkey(), True, True)])
    message = MessageV0.try_compile(PAYER.pubkey(), [transfer, Instruction(program, _limit(1), [])], [], Hash.default())
    declared = check_v0_budget_caps(message, 200_000, 10)
    assert declared is not None
    with pytest.raises(TransactionVersionError, match="must lead"):
        require_budget_prefix(message, declared)


# ── top-up ─────────────────────────────────────────────────────────────────


def _channel(*, rent_payer: Keypair = PAYER, **overrides: object) -> ChannelState:
    state = ChannelState(
        channel_id=str(Keypair.from_seed(bytes([27] * 32)).pubkey()),
        authorized_signer=str(SESSION_KEY.pubkey()),
        deposit=1_000,
        payer=str(PAYER.pubkey()),
        rent_payer=str(rent_payer.pubkey()),
        opening_challenge_id=CHALLENGE_ID,
    )
    return replace(state, **overrides)  # type: ignore[arg-type]


async def _top_up(
    state: ChannelState, amount: int = 250, *, fee_payer: Pubkey | None = None, extra: bool = False
) -> TopUpPayload:
    ix = build_top_up_instruction(
        TopUpParams(
            payer=PAYER.pubkey(),
            channel=Pubkey.from_string(state.channel_id),
            mint=Pubkey.from_string(resolve_mint("USDC", "devnet")),
            amount=amount,
            program_id=PROGRAM_ID,
        )
    )
    instructions = [ix]
    if extra:
        instructions.append(Instruction(Pubkey.from_string("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"), b"x", []))
    wire = await build_partially_signed_v0_transaction(
        instructions, fee_payer or PAYER.pubkey(), Hash.from_string(BLOCKHASH), MemorySigner(PAYER)
    )
    return TopUpPayload(state.channel_id, str(amount), base64.b64encode(wire).decode())


async def _seeded(config: SessionConfig, state: ChannelState) -> SessionServer:
    store = MemoryChannelStore()
    await store.update_channel(state.channel_id, lambda _: state)
    return _server(config, store)


async def test_client_paid_top_up_passes_every_pre_broadcast_check() -> None:
    state = _channel()
    server = await _seeded(_config(), state)
    await session_testkit.verify_topup_pre_broadcast(server, await _top_up(state))


async def test_sponsored_top_up_needs_the_channels_rent_payer_signer() -> None:
    state = _channel(rent_payer=SPONSOR)
    payload = await _top_up(state, fee_payer=SPONSOR.pubkey())
    await session_testkit.verify_topup_pre_broadcast(await _seeded(_sponsored(), state), payload)
    with pytest.raises(PaymentError, match="requires the channel fee-payer signer"):
        await session_testkit.verify_topup_pre_broadcast(await _seeded(_config(), state), payload)
    other = _config(fee_payer=True, fee_payer_key=str(STRANGER.pubkey()), fee_payer_signer=MemorySigner(STRANGER))
    with pytest.raises(PaymentError, match="does not match the channel rentPayer"):
        await session_testkit.verify_topup_pre_broadcast(await _seeded(other, state), payload)


async def test_top_up_refuses_what_the_stored_channel_does_not_allow() -> None:
    state = _channel()
    server = await _seeded(_config(), state)
    with pytest.raises(PaymentError, match="amount does not match additionalAmount"):
        await session_testkit.verify_topup_pre_broadcast(server, replace(await _top_up(state), additional_amount="300"))
    with pytest.raises(PaymentError, match="unexpected instruction"):
        await session_testkit.verify_topup_pre_broadcast(server, await _top_up(state, extra=True))
    with pytest.raises(PaymentError, match="fee payer does not match"):
        await session_testkit.verify_topup_pre_broadcast(server, await _top_up(state, fee_payer=STRANGER.pubkey()))
    with pytest.raises(ValueError, match="greater than zero"):
        await session_testkit.verify_topup_pre_broadcast(server, replace(await _top_up(state), additional_amount="0"))
    with pytest.raises(ValueError, match="invalid additionalAmount"):
        await session_testkit.verify_topup_pre_broadcast(server, replace(await _top_up(state), additional_amount="1e3"))
    with pytest.raises(ValueError, match="not found"):
        await session_testkit.verify_topup_pre_broadcast(
            server, replace(await _top_up(state), channel_id=str(Keypair().pubkey()))
        )
    closing = await _seeded(_config(), replace(state, close_requested_at=1))
    with pytest.raises(ValueError, match="closed or close is pending"):
        await session_testkit.verify_topup_pre_broadcast(closing, await _top_up(state))
    unsigned = replace(
        await _top_up(state),
        transaction=base64.b64encode(
            bytes(
                VersionedTransaction.populate(
                    _decoded(replace(await _top_up(state))).message,  # type: ignore[arg-type]
                    [Signature.default()],
                )
            )
        ).decode(),
    )
    with pytest.raises(PaymentError, match="signature verification failed"):
        await session_testkit.verify_topup_pre_broadcast(server, unsigned)
    with pytest.raises(PaymentError, match="decode top-up transaction"):
        await session_testkit.verify_topup_pre_broadcast(server, replace(await _top_up(state), transaction="%%"))


async def test_process_top_up_refuses_a_closing_channel_before_broadcast() -> None:
    state = _channel(close_requested_at=1)
    calls: list[TopUpPayload] = []

    async def verify(payload: TopUpPayload) -> None:
        calls.append(payload)

    server = await _seeded(_config(verify_top_up_tx=verify), state)
    with pytest.raises(ValueError, match="closed or close is pending"):
        await server.process_top_up(await _top_up(state))
    assert calls == []


# ── operator-signed use ────────────────────────────────────────────────────


async def _operator_channel(**overrides: object) -> tuple[SessionServer, UsePayload]:
    state = _channel(
        authorized_signer=str(OPERATOR.pubkey()),
        cumulative=100,
        spent_amount=100,
        voucher_signer="operator",
    )
    proof = await sign_session_authentication(CHALLENGE_ID, state.channel_id, MemorySigner(PAYER))
    state = replace(state, authentication=proof.to_dict(), **overrides)  # type: ignore[arg-type]
    config = _config(voucher_signer="operator", operator_signer=MemorySigner(OPERATOR))
    return await _seeded(config, state), UsePayload(state.channel_id, proof)


async def _metered(server: SessionServer, payload: UsePayload, total: int, *, key: str = "request-1"):
    authenticated = await server.authenticate_use(payload, CHALLENGE_ID, key)
    return await server.charge_operator_request(authenticated, MemorySigner(OPERATOR), total)


async def test_metered_use_charges_the_request_total_once() -> None:
    server, payload = await _operator_channel()
    first = await _metered(server, payload, 7)
    assert (first.cumulative, first.charged, first.replay) == (107, 7, False)
    state = await server.store().get_channel(payload.channel_id)
    assert state is not None
    assert (state.cumulative, state.spent_amount) == (107, 107)
    assert state.highest_voucher_signature == first.voucher.signature
    assert state.processed_uses[-1].amount == 7

    replay = await _metered(server, payload, 7)
    assert (replay.cumulative, replay.charged, replay.replay) == (107, 0, True)
    assert replay.voucher.signature == first.voucher.signature
    lower = await _metered(server, payload, 5)
    assert lower.replay and lower.cumulative == 107

    advanced = await _metered(server, payload, 8)
    assert (advanced.cumulative, advanced.charged, advanced.request_total) == (108, 1, 8)
    state = await server.store().get_channel(payload.channel_id)
    assert state is not None and len(state.processed_uses) == 1


async def test_metered_use_refusals() -> None:
    server, payload = await _operator_channel()
    with pytest.raises(ValueError, match="must be positive"):
        await _metered(server, payload, 0)
    with pytest.raises(ValueError, match="insufficient channel availability"):
        await _metered(server, payload, 901)
    assert (await _metered(server, payload, 900)).cumulative == 1_000
    with pytest.raises(ValueError, match="Idempotency-Key"):
        await server.authenticate_use(payload, CHALLENGE_ID, "")
    with pytest.raises(ValueError, match="exceeds 255 bytes"):
        await server.authenticate_use(payload, CHALLENGE_ID, "k" * 256)
    authenticated = await server.authenticate_use(payload, CHALLENGE_ID, "request-2")
    with pytest.raises(ValueError, match="does not match configured operator"):
        await server.charge_operator_request(authenticated, MemorySigner(STRANGER), 1)
    with pytest.raises(ValueError, match="must be a u64"):
        await server.charge_operator_request(authenticated, MemorySigner(OPERATOR), 1 << 64)


async def test_metered_use_refuses_a_stranger_and_a_forged_proof() -> None:
    server, payload = await _operator_channel()
    stranger = await sign_session_authentication(CHALLENGE_ID, payload.channel_id, MemorySigner(STRANGER))
    with pytest.raises(ValueError, match="does not match the proof bound at open"):
        await server.authenticate_use(UsePayload(payload.channel_id, stranger), CHALLENGE_ID, "k")
    forged = SessionAuthentication(CHALLENGE_ID, str(PAYER.pubkey()), stranger.signature)
    with pytest.raises(ValueError, match="does not match the proof bound at open"):
        await server.authenticate_use(UsePayload(payload.channel_id, forged), CHALLENGE_ID, "k")
    with pytest.raises(ValueError, match="does not match the proof bound at open"):
        await server.charge_operator_request(
            AuthenticatedUse(payload.channel_id, stranger.to_dict(), CHALLENGE_ID, "k"), MemorySigner(OPERATOR), 1
        )


@pytest.mark.parametrize("overrides", [{"close_requested_at": 1}, {"sealed": True}])
async def test_metered_use_refuses_a_closing_channel(overrides: dict[str, object]) -> None:
    server, payload = await _operator_channel(**overrides)
    with pytest.raises(ValueError, match="closed or close is pending"):
        await server.authenticate_use(payload, CHALLENGE_ID, "k")
    open_server, open_payload = await _operator_channel()
    authenticated = await open_server.authenticate_use(open_payload, CHALLENGE_ID, "k")
    await open_server.store().update_channel(
        open_payload.channel_id,
        lambda state: replace(state, **overrides),  # type: ignore[arg-type, misc]
    )
    with pytest.raises(ValueError, match="closed or close is pending"):
        await open_server.charge_operator_request(authenticated, MemorySigner(OPERATOR), 1)


async def test_metered_use_refuses_a_key_recorded_for_another_request() -> None:
    record = ProcessedUse("c_other", "request-1", 107, "sig", amount=7)
    server, payload = await _operator_channel(processed_uses=[record])
    with pytest.raises(ValueError, match="used for a different request"):
        await _metered(server, payload, 7)
    untotaled = ProcessedUse(CHALLENGE_ID, "request-1", 107, "sig")
    server, payload = await _operator_channel(processed_uses=[untotaled])
    with pytest.raises(ValueError, match="used for a different request"):
        await _metered(server, payload, 7)


async def test_metered_use_on_a_client_signed_server_is_refused() -> None:
    server, payload = await _operator_channel()
    server.config.voucher_signer = "client"
    with pytest.raises(ValueError, match="only valid for an operator-signed channel"):
        await server.authenticate_use(payload, CHALLENGE_ID, "k")
    with pytest.raises(ValueError, match="only valid for an operator-signed channel"):
        await server.charge_operator_request(
            AuthenticatedUse(payload.channel_id, payload.authentication.to_dict(), CHALLENGE_ID, "k"),
            MemorySigner(OPERATOR),
            1,
        )


async def test_metered_charge_retries_when_the_watermark_moves() -> None:
    server, payload = await _operator_channel()
    authenticated = await server.authenticate_use(payload, CHALLENGE_ID, "request-1")
    store = server.store()
    original = store.update_channel
    moved: list[bool] = []

    async def racing_update(channel_id, mutator):  # type: ignore[no-untyped-def]
        if not moved:
            moved.append(True)
            await original(channel_id, lambda state: replace(state, cumulative=state.cumulative + 1))  # type: ignore[arg-type]
        return await original(channel_id, mutator)

    store.update_channel = racing_update  # type: ignore[method-assign]
    charge = await server.charge_operator_request(authenticated, MemorySigner(OPERATOR), 7)
    assert charge.previous_cumulative == 101 and charge.cumulative == 108


async def test_fixed_price_use_records_its_amount() -> None:
    server, payload = await _operator_channel()
    voucher = await server.process_use(payload, CHALLENGE_ID, "request-1")
    assert voucher.data.cumulative_amount == "125"
    state = await server.store().get_channel(payload.channel_id)
    assert state is not None and state.processed_uses[-1].amount == 25


def test_processed_use_amount_round_trips() -> None:
    use = ProcessedUse("c", "k", 7, "sig", amount=7)
    assert ProcessedUse.from_dict(use.to_dict()) == use
    legacy = ProcessedUse("c", "k", 7, "sig")
    assert "amount" not in legacy.to_dict()
    assert ProcessedUse.from_dict(legacy.to_dict()).amount is None


# ── client ─────────────────────────────────────────────────────────────────


async def _request() -> SessionRequest:
    return await _server(_config()).build_challenge_request()


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("network", "testnet", "network"),
        ("decimals", None, "missing decimals"),
        ("decimals", 10, "outside 0 through 9"),
        ("token_program", "11111111111111111111111111111111", "neither SPL Token nor Token-2022"),
        ("grace_period_seconds", 0, "greater than zero"),
        ("channel_program", "Stake11111111111111111111111111111111111111", "unknown channel program"),
    ],
)
async def test_client_refuses_an_out_of_spec_challenge(field: str, value: object, message: str) -> None:
    request = await _request()
    setattr(request.method_details, field, value)
    with pytest.raises(ValueError, match=message):
        validate_session_challenge(request)


async def test_client_refuses_a_deposit_below_minimum_and_operator_without_key() -> None:
    request = await _request()
    with pytest.raises(ValueError, match="below minimumDeposit"):
        await create_payment_channel_session_opener(
            request,
            MemorySigner(PAYER),
            MemorySigner(SESSION_KEY),
            options=PaymentChannelSessionOpenOptions(open=PaymentChannelOpenOptions(salt=7, deposit=99)),
        )
    request.method_details.voucher_signer = "operator"
    request.method_details.operator = None
    with pytest.raises(ValueError, match="operator is required"):
        await create_payment_channel_session_opener(request, MemorySigner(PAYER), MemorySigner(SESSION_KEY))


class _BlockhashRpc:
    def __init__(self, live: bool | Exception) -> None:
        self.live = live
        self.asked: list[str] = []

    async def is_blockhash_valid(self, blockhash: str, commitment: str = "confirmed") -> bool:
        self.asked.append(blockhash)
        if isinstance(self.live, Exception):
            raise self.live
        return self.live


async def test_open_blockhash_must_be_live_on_the_clients_cluster() -> None:
    request = await _request()
    rpc = _BlockhashRpc(True)
    assert str(await verify_open_blockhash(rpc, request)) == BLOCKHASH
    assert rpc.asked == [BLOCKHASH]
    with pytest.raises(ValueError, match="not a live blockhash"):
        await verify_open_blockhash(_BlockhashRpc(False), request)
    with pytest.raises(ValueError, match="could not check"):
        await verify_open_blockhash(_BlockhashRpc(RuntimeError("down")), request)
    request.method_details.recent_blockhash = "not-a-hash"
    with pytest.raises(ValueError, match="invalid challenged recentBlockhash"):
        await verify_open_blockhash(rpc, request)
    request.method_details.recent_blockhash = None
    with pytest.raises(ValueError, match="missing recentBlockhash"):
        await verify_open_blockhash(rpc, request)


async def test_rpc_is_blockhash_valid() -> None:
    class _Client:
        def __init__(self, result: object) -> None:
            self.result = result
            self.body: dict | None = None

        async def post(self, _url: str, json: dict) -> object:
            self.body = json
            result = self.result

            class _Response:
                def raise_for_status(self) -> None:
                    return None

                def json(self) -> dict:
                    return {"jsonrpc": "2.0", "id": json["id"], "result": result}

            return _Response()

    rpc = SolanaRpc("http://localhost:9999")
    client = _Client({"context": {"slot": 1}, "value": True})
    rpc._client = client  # type: ignore[assignment]
    assert await rpc.is_blockhash_valid(BLOCKHASH) is True
    assert client.body is not None and client.body["method"] == "isBlockhashValid"
    rpc._client = _Client({"value": None})  # type: ignore[assignment]
    with pytest.raises(Exception, match="no boolean"):
        await rpc.is_blockhash_valid(BLOCKHASH)
