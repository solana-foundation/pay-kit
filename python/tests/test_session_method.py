"""Tests for the HTTP-facing MPP session method handler.

Mirrors the offline-core behaviors in
``go/protocols/mpp/server/session_method_test.go``: ``NewSession`` validation
and defaults, challenge issuance (canonical shape, cap clamping, pull
advertisement, blockhash prefetch), the Tier-1 + Tier-2 credential checks, and
the five ``verify_credential`` actions (open / voucher / commit / topUp / close)
with their replay and hardening semantics, including the optional RPC liveness
confirm seam.

This file covers the offline-core handler. The on-chain settlement path at
close, the server-broadcast open (``OpenTxSubmitterServer``), the
attached-transaction open verification, and the metering side-channel HTTP
routes are exercised in their own suites (``test_session_settlement.py``,
``test_session_onchain.py``, ``test_session_routes.py``, and the surfnet
``test_session_e2e_surfnet.py``), not here. Each test name below maps to the Go
test it mirrors in the docstring.
"""

from __future__ import annotations

import pytest
from solders.keypair import Keypair  # type: ignore[import-untyped]
from solders.signature import Signature  # type: ignore[import-untyped]

from pay_kit._paycore.errors import PaymentError
from pay_kit.protocols.mpp.core.types import PaymentChallenge, PaymentCredential
from pay_kit.protocols.mpp.intents.session import (
    ClosePayload,
    CommitPayload,
    OpenPayload,
    SessionAction,
    SignedVoucher,
    TopUpPayload,
    VoucherData,
    VoucherPayload,
)
from pay_kit.protocols.mpp.server.session import Split
from pay_kit.protocols.mpp.server.session_method import (
    Session,
    SessionChallengeOptions,
    SessionOptions,
    new_session,
)
from pay_kit.signer import LocalSigner

SESSION_METHOD_SECRET = "session-method-secret"
SESSION_TEST_RECIPIENT = str(Keypair.from_seed(bytes([7] * 32)).pubkey())


class _TestVoucherSigner:
    """An Ed25519 keypair signing canonical 48-byte vouchers. Mirrors
    ``testVoucherSigner`` in the Go suite."""

    def __init__(self, seed: int) -> None:
        self._kp = Keypair.from_seed(bytes([seed] * 32))

    def address(self) -> str:
        return str(self._kp.pubkey())

    def sign_voucher(self, channel_id: str, cumulative: int, expires_at: int) -> SignedVoucher:
        data = VoucherData(channel_id=channel_id, cumulative=str(cumulative), expires_at=expires_at)
        signature = self._kp.sign_message(data.message_bytes())
        return SignedVoucher(data=data, signature=str(signature))


def _far_future() -> int:
    return 4_102_444_800


def _new_wallet() -> str:
    import secrets

    return str(Keypair.from_seed(secrets.token_bytes(32)).pubkey())


def _confirmed_signature(fill: int) -> str:
    return str(Signature.from_bytes(bytes([fill] * 64)))


class _FakeRpc:
    """Minimal RPC double: ``get_signature_statuses`` (any signature not seeded
    is confirmed) and ``get_latest_blockhash``. Mirrors ``testutil.FakeRPC``."""

    def __init__(self, blockhash: str = "FakeBlockhash1111111111111111111111111111111") -> None:
        self.statuses: dict[str, dict | None] = {}
        self.blockhash = blockhash

    async def get_signature_statuses(self, signatures: list[str]) -> list[dict | None]:
        out: list[dict | None] = []
        for signature in signatures:
            if signature in self.statuses:
                out.append(self.statuses[signature])
            else:
                out.append({"err": None, "confirmationStatus": "confirmed"})
        return out

    async def get_latest_blockhash(self, commitment: str = "confirmed"):
        class _Value:
            def __init__(self, blockhash: str) -> None:
                self.blockhash = blockhash

        class _Resp:
            def __init__(self, blockhash: str) -> None:
                self.value = _Value(blockhash)

        return _Resp(self.blockhash)


def _new_test_session(**overrides) -> Session:
    options = SessionOptions(
        operator=SESSION_TEST_RECIPIENT,
        recipient=SESSION_TEST_RECIPIENT,
        cap=5_000_000,
        currency="USDC",
        decimals=6,
        network="localnet",
        secret_key=SESSION_METHOD_SECRET,
        realm="api.test",
    )
    for key, value in overrides.items():
        setattr(options, key, value)
    return new_session(options)


async def _session_action_credential(session: Session, action: SessionAction | dict) -> PaymentCredential:
    challenge = await session.challenge(SessionChallengeOptions())
    payload = action.to_dict() if isinstance(action, SessionAction) else action
    return PaymentCredential(challenge=challenge.to_echo(), payload=payload)


async def _verify_session_action(session: Session, action: SessionAction | dict):
    credential = await _session_action_credential(session, action)
    return await session.verify_credential(credential)


async def _open_session_channel(
    session: Session, channel_id: str, deposit: int, authorized_signer: str, signature: str
):
    payload = OpenPayload.push(channel_id, str(deposit), authorized_signer, signature)
    return await _verify_session_action(session, SessionAction.open_action(payload))


async def _open_trusted_channel(session: Session, deposit: int) -> tuple[_TestVoucherSigner, str]:
    signer = _TestVoucherSigner(0x21)
    channel_id = _new_wallet()
    await _open_session_channel(session, channel_id, deposit, signer.address(), _confirmed_signature(0x99))
    return signer, channel_id


async def _submit_voucher(session: Session, signer: _TestVoucherSigner, channel_id: str, cumulative: int):
    voucher = signer.sign_voucher(channel_id, cumulative, _far_future())
    return await _verify_session_action(session, SessionAction.voucher_action(VoucherPayload(voucher=voucher)))


async def _get_channel(session: Session, channel_id: str):
    return await session.core().store().get_channel(channel_id)


# ── new_session validation (TestNewSessionValidation) ──


def test_new_session_validation_zero_cap() -> None:
    with pytest.raises(PaymentError, match="cap must be positive"):
        new_session(SessionOptions(recipient=SESSION_TEST_RECIPIENT, cap=0, secret_key=SESSION_METHOD_SECRET))


def test_new_session_validation_missing_recipient() -> None:
    with pytest.raises(PaymentError, match="recipient is required"):
        new_session(SessionOptions(recipient="", cap=1_000, secret_key=SESSION_METHOD_SECRET))


def test_new_session_validation_invalid_recipient() -> None:
    with pytest.raises(PaymentError, match="invalid recipient"):
        new_session(SessionOptions(recipient="not-base58!", cap=1_000, secret_key=SESSION_METHOD_SECRET))


def test_new_session_validation_too_many_splits() -> None:
    splits = [Split(recipient=_new_wallet(), bps=1) for _ in range(9)]
    with pytest.raises(PaymentError, match="splits cannot exceed"):
        new_session(
            SessionOptions(recipient=SESSION_TEST_RECIPIENT, cap=1_000, secret_key=SESSION_METHOD_SECRET, splits=splits)
        )


def test_new_session_validation_pull_requires_strategy() -> None:
    with pytest.raises(PaymentError, match="pullVoucherStrategy is required"):
        new_session(
            SessionOptions(
                recipient=SESSION_TEST_RECIPIENT,
                cap=1_000,
                secret_key=SESSION_METHOD_SECRET,
                modes=["pull"],
            )
        )


def test_new_session_validation_bad_submitter() -> None:
    with pytest.raises(PaymentError, match="openTxSubmitter"):
        new_session(
            SessionOptions(
                recipient=SESSION_TEST_RECIPIENT,
                cap=1_000,
                secret_key=SESSION_METHOD_SECRET,
                open_tx_submitter="relay",
            )
        )


def test_new_session_validation_missing_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MPP_SECRET_KEY", raising=False)
    with pytest.raises(PaymentError, match="missing secret key"):
        new_session(SessionOptions(recipient=SESSION_TEST_RECIPIENT, cap=1_000, secret_key=""))


# ── new_session defaults (TestNewSessionDefaults) ──


def test_new_session_defaults() -> None:
    session = _new_test_session(currency="", decimals=0, network="", open_tx_submitter="")
    assert session._currency == "USDC"
    assert session._network == "mainnet"
    assert session._open_tx_submitter == "client"
    assert session.core().config.decimals == 6


# ── challenge ──


async def test_session_challenge_canonical_shape() -> None:
    """Mirrors TestSessionChallengeCanonicalShape."""
    session = _new_test_session()
    challenge = await session.challenge(SessionChallengeOptions(cap="1000000", description="Metered token stream"))
    assert challenge.verify(SESSION_METHOD_SECRET)
    assert challenge.intent.lower() == "session"
    assert challenge.method == "solana"
    assert challenge.realm == "api.test"

    from pay_kit.protocols.mpp.intents.session import SessionRequest

    request = SessionRequest.from_dict(challenge.decode_request())
    assert request.cap == "1000000"
    assert request.currency == "USDC"
    assert request.operator == SESSION_TEST_RECIPIENT
    assert request.recipient == SESSION_TEST_RECIPIENT
    assert request.network == "localnet"
    assert request.decimals == 6
    assert request.description == "Metered token stream"
    assert request.modes == []  # omitted when push-only
    assert request.recent_blockhash is None  # absent without an RPC client


async def test_session_challenge_clamps_requested_cap() -> None:
    """Mirrors TestSessionChallengeClampsRequestedCap."""
    session = _new_test_session(cap=1_000_000)
    challenge = await session.challenge(SessionChallengeOptions(cap="50000000"))
    from pay_kit.protocols.mpp.intents.session import SessionRequest

    request = SessionRequest.from_dict(challenge.decode_request())
    assert request.cap == "1000000"


async def test_session_challenge_invalid_cap_rejected() -> None:
    """Mirrors TestSessionChallengeInvalidCapRejected."""
    session = _new_test_session()
    with pytest.raises(PaymentError):
        await session.challenge(SessionChallengeOptions(cap="1.5"))


async def test_session_challenge_includes_blockhash_with_rpc() -> None:
    """Mirrors TestSessionChallengeIncludesBlockhashWithRPC."""
    fake = _FakeRpc()
    session = _new_test_session(rpc=fake)
    challenge = await session.challenge(SessionChallengeOptions())
    from pay_kit.protocols.mpp.intents.session import SessionRequest

    request = SessionRequest.from_dict(challenge.decode_request())
    assert request.recent_blockhash == fake.blockhash


async def test_session_challenge_advertises_pull_strategy() -> None:
    """Mirrors TestSessionChallengeAdvertisesPullStrategy."""
    session = _new_test_session(modes=["pull", "push"], pull_voucher_strategy="clientVoucher")
    challenge = await session.challenge(SessionChallengeOptions(external_id="ref-7"))
    from pay_kit.protocols.mpp.intents.session import SessionRequest

    request = SessionRequest.from_dict(challenge.decode_request())
    assert len(request.modes) == 2
    assert request.pull_voucher_strategy == "clientVoucher"
    assert request.external_id == "ref-7"


# ── VerifyCredential: tier-1 + tier-2 ──


async def test_verify_credential_rejects_tampered_and_expired_challenges() -> None:
    """Mirrors TestVerifyCredentialRejectsTamperedAndExpiredChallenges."""
    session = _new_test_session()
    signer = _TestVoucherSigner(1)
    channel_id = _new_wallet()
    action = SessionAction.open_action(OpenPayload.push(channel_id, "1000", signer.address(), "sig"))

    credential = await _session_action_credential(session, action)
    credential.challenge.realm = "tampered.example"
    with pytest.raises(PaymentError, match="challenge ID mismatch"):
        await session.verify_credential(credential)

    request = session.core().build_challenge_request(1_000)
    expired = PaymentChallenge.with_secret_key(
        secret_key=SESSION_METHOD_SECRET,
        realm="api.test",
        method="solana",
        intent="session",
        request=PaymentChallenge.encode_request(request.to_dict()),
        expires="2020-01-01T00:00:00Z",
    )
    expired_credential = PaymentCredential(challenge=expired.to_echo(), payload=action.to_dict())
    with pytest.raises(PaymentError, match="expired"):
        await session.verify_credential(expired_credential)


async def test_verify_credential_pinned_field_backstop() -> None:
    """Mirrors TestVerifyCredentialPinnedFieldBackstop."""
    session = _new_test_session()
    signer = _TestVoucherSigner(1)
    action = SessionAction.open_action(OpenPayload.push(_new_wallet(), "1000", signer.address(), "sig"))

    def issue(intent: str, request) -> PaymentCredential:
        challenge = PaymentChallenge.with_secret_key(
            secret_key=SESSION_METHOD_SECRET,
            realm="api.test",
            method="solana",
            intent=intent,
            request=PaymentChallenge.encode_request(request.to_dict()),
            expires="2999-01-01T00:00:00Z",
        )
        return PaymentCredential(challenge=challenge.to_echo(), payload=action.to_dict())

    charge_intent = issue("charge", session.core().build_challenge_request(1_000))
    with pytest.raises(PaymentError, match="not a session"):
        await session.verify_credential(charge_intent)

    wrong_currency = session.core().build_challenge_request(1_000)
    wrong_currency.currency = "USDT"
    with pytest.raises(PaymentError, match="currency"):
        await session.verify_credential(issue("session", wrong_currency))

    wrong_recipient = session.core().build_challenge_request(1_000)
    wrong_recipient.recipient = _new_wallet()
    with pytest.raises(PaymentError, match="recipient"):
        await session.verify_credential(issue("session", wrong_recipient))

    unknown_action = await _session_action_credential(session, {"action": "refund"})
    with pytest.raises(PaymentError, match="decode session action"):
        await session.verify_credential(unknown_action)


# ── open ──


async def test_session_open_trusts_channel_id_and_deposit() -> None:
    """Mirrors TestSessionOpenTrustsChannelIDAndDeposit."""
    session = _new_test_session()
    signer = _TestVoucherSigner(1)
    channel_id = _new_wallet()
    receipt = await _open_session_channel(session, channel_id, 1_000_000, signer.address(), "sig-1")
    assert receipt.status == "success"
    assert receipt.reference == "sig-1"
    state = await _get_channel(session, channel_id)
    assert state is not None
    assert state.deposit == 1_000_000
    assert state.cumulative == 0
    assert state.authorized_signer == signer.address()


async def test_session_open_rejects_unadvertised_mode() -> None:
    """Mirrors TestSessionOpenRejectsUnadvertisedMode."""
    session = _new_test_session()
    signer = _TestVoucherSigner(1)
    payload = OpenPayload.pull(_new_wallet(), "1000", _new_wallet(), signer.address(), "sig")
    with pytest.raises(PaymentError, match="not supported"):
        await _verify_session_action(session, SessionAction.open_action(payload))


async def test_session_open_rejects_bad_deposits() -> None:
    """Mirrors TestSessionOpenRejectsBadDeposits."""
    session = _new_test_session(cap=1_000)
    signer = _TestVoucherSigner(1)
    channel_id = _new_wallet()

    over = OpenPayload.push(channel_id, "10000", signer.address(), "sig")
    with pytest.raises(PaymentError, match="exceeds max cap"):
        await _verify_session_action(session, SessionAction.open_action(over))

    zero = OpenPayload.push(channel_id, "0", signer.address(), "sig")
    with pytest.raises(PaymentError, match="greater than zero"):
        await _verify_session_action(session, SessionAction.open_action(zero))

    missing = OpenPayload(mode="push", authorized_signer=signer.address(), signature="sig")
    with pytest.raises(PaymentError, match="missing transaction or channelId"):
        await _verify_session_action(session, SessionAction.open_action(missing))


async def test_session_open_rejects_empty_string_fields() -> None:
    """Mirrors TestSessionOpenRejectsEmptyStringFields."""
    session = _new_test_session()
    signer = _TestVoucherSigner(1)

    empty_tx = OpenPayload(mode="push", transaction="", authorized_signer=signer.address(), signature="sig")
    with pytest.raises(PaymentError, match="missing transaction or channelId"):
        await _verify_session_action(session, SessionAction.open_action(empty_tx))

    empty_both = OpenPayload(
        mode="push", transaction="", channel_id="", authorized_signer=signer.address(), signature="sig"
    )
    with pytest.raises(PaymentError, match="missing transaction or channelId"):
        await _verify_session_action(session, SessionAction.open_action(empty_both))


async def test_session_open_replay_semantics() -> None:
    """Mirrors TestSessionOpenReplaySemantics."""
    session = _new_test_session()
    signer, channel_id = await _open_trusted_channel(session, 1_000)
    await _submit_voucher(session, signer, channel_id, 250)

    # Idempotent replay preserves the watermark.
    await _open_session_channel(session, channel_id, 1_000, signer.address(), "open-sig")
    state = await _get_channel(session, channel_id)
    assert state is not None and state.cumulative == 250 and state.highest_voucher_signature is not None

    # Different authorizedSigner rejects without overwriting.
    intruder = _TestVoucherSigner(2)
    payload = OpenPayload.push(channel_id, "1000", intruder.address(), "open-sig")
    with pytest.raises(PaymentError, match="authorized signer"):
        await _verify_session_action(session, SessionAction.open_action(payload))
    state = await _get_channel(session, channel_id)
    assert state is not None and state.authorized_signer == signer.address()

    # Finalized channel rejects replays.
    await session.core().store().mark_finalized(channel_id)
    replay = OpenPayload.push(channel_id, "1000", signer.address(), "open-sig")
    with pytest.raises(PaymentError, match="finalized"):
        await _verify_session_action(session, SessionAction.open_action(replay))


async def test_session_open_verifies_signature_on_chain() -> None:
    """Mirrors TestSessionOpenVerifiesSignatureOnChain."""
    fake = _FakeRpc()
    ok_sig = _confirmed_signature(0x11)
    ghost_sig = _confirmed_signature(0x22)
    failed_sig = _confirmed_signature(0x33)
    fake.statuses[ghost_sig] = None
    fake.statuses[failed_sig] = {"err": {"InstructionError": [0, "Custom"]}}

    session = _new_test_session(rpc=fake)
    signer = _TestVoucherSigner(1)

    channel_id = _new_wallet()
    receipt = await _open_session_channel(session, channel_id, 1_000, signer.address(), ok_sig)
    assert receipt.reference == ok_sig

    ghost_channel = _new_wallet()
    ghost = OpenPayload.push(ghost_channel, "1000", signer.address(), ghost_sig)
    with pytest.raises(PaymentError, match="not found"):
        await _verify_session_action(session, SessionAction.open_action(ghost))
    assert await _get_channel(session, ghost_channel) is None

    failed = OpenPayload.push(_new_wallet(), "1000", signer.address(), failed_sig)
    with pytest.raises(PaymentError, match="failed on-chain"):
        await _verify_session_action(session, SessionAction.open_action(failed))


async def test_session_pull_open_prefers_channel_id_over_token_account() -> None:
    """Mirrors TestSessionPullOpenPrefersChannelIDOverTokenAccount."""
    session = _new_test_session(modes=["pull"], pull_voucher_strategy="clientVoucher")
    signer = _TestVoucherSigner(1)
    channel_id = _new_wallet()
    token_account = _new_wallet()

    payload = OpenPayload.pull(token_account, "1000", _new_wallet(), signer.address(), "sig-1")
    payload.channel_id = channel_id
    await _verify_session_action(session, SessionAction.open_action(payload))
    assert await _get_channel(session, channel_id) is not None
    assert await _get_channel(session, token_account) is None
    state = await _get_channel(session, channel_id)
    assert state is not None and state.operator is not None


# ── voucher ──


async def test_session_voucher_advances_watermark() -> None:
    """Mirrors TestSessionVoucherAdvancesWatermark."""
    session = _new_test_session()
    signer, channel_id = await _open_trusted_channel(session, 1_000)

    voucher = signer.sign_voucher(channel_id, 250, _far_future())
    receipt = await _verify_session_action(session, SessionAction.voucher_action(VoucherPayload(voucher=voucher)))
    assert receipt.reference == f"{channel_id}:250"
    state = await _get_channel(session, channel_id)
    assert state is not None
    assert state.cumulative == 250
    assert state.highest_voucher_signature == voucher.signature


async def test_session_voucher_unknown_channel_rejected() -> None:
    """Mirrors TestSessionVoucherUnknownChannelRejected."""
    session = _new_test_session()
    signer = _TestVoucherSigner(1)
    with pytest.raises(PaymentError, match="not found"):
        await _submit_voucher(session, signer, _new_wallet(), 100)


async def test_session_voucher_non_monotonic_tagged_rejection() -> None:
    """Mirrors TestSessionVoucherNonMonotonicTaggedRejection."""
    session = _new_test_session()
    signer, channel_id = await _open_trusted_channel(session, 1_000)
    await _submit_voucher(session, signer, channel_id, 100)
    with pytest.raises(PaymentError, match="cumulative-not-monotonic"):
        await _submit_voucher(session, signer, channel_id, 50)


async def test_session_voucher_accepts_cumulative_alias_on_the_wire() -> None:
    """Mirrors TestSessionVoucherAcceptsCumulativeAliasOnTheWire."""
    session = _new_test_session()
    signer, channel_id = await _open_trusted_channel(session, 1_000)
    canonical = signer.sign_voucher(channel_id, 250, _far_future())

    aliased = {
        "action": "voucher",
        "voucher": {
            "data": {"channelId": channel_id, "cumulative": "250", "expiresAt": canonical.data.expires_at},
            "signature": canonical.signature,
        },
    }
    receipt = await _verify_session_action(session, aliased)
    assert receipt.reference == f"{channel_id}:250"
    state = await _get_channel(session, channel_id)
    assert state is not None and state.cumulative == 250

    neither = {
        "action": "voucher",
        "voucher": {
            "data": {"channelId": channel_id, "expiresAt": canonical.data.expires_at},
            "signature": canonical.signature,
        },
    }
    # An absent cumulative decodes to "" and fails the strict u64 parse.
    with pytest.raises(PaymentError):
        await _verify_session_action(session, neither)


# ── topUp ──


async def test_session_top_up_updates_deposit() -> None:
    """Mirrors TestSessionTopUpUpdatesDeposit."""
    session = _new_test_session()
    _, channel_id = await _open_trusted_channel(session, 1_000)

    receipt = await _verify_session_action(
        session,
        SessionAction.top_up_action(TopUpPayload(channel_id=channel_id, new_deposit="5000", signature="topup-sig")),
    )
    assert receipt.reference == "topup-sig"
    state = await _get_channel(session, channel_id)
    assert state is not None and state.deposit == 5_000


async def test_session_top_up_hardening() -> None:
    """Mirrors TestSessionTopUpHardening."""
    session = _new_test_session()
    _, channel_id = await _open_trusted_channel(session, 5_000)

    with pytest.raises(PaymentError, match="must exceed current deposit"):
        await _verify_session_action(
            session,
            SessionAction.top_up_action(TopUpPayload(channel_id=channel_id, new_deposit="1000", signature="sig")),
        )

    with pytest.raises(PaymentError, match="exceeds cap"):
        await _verify_session_action(
            session,
            SessionAction.top_up_action(TopUpPayload(channel_id=channel_id, new_deposit="99000000", signature="sig")),
        )

    with pytest.raises(PaymentError, match="not found"):
        await _verify_session_action(
            session,
            SessionAction.top_up_action(TopUpPayload(channel_id=_new_wallet(), new_deposit="9000", signature="sig")),
        )

    # Close-pending blocks top-ups.
    await _verify_session_action(session, SessionAction.close_action(ClosePayload(channel_id=channel_id)))
    with pytest.raises(PaymentError, match="close is pending"):
        await _verify_session_action(
            session,
            SessionAction.top_up_action(TopUpPayload(channel_id=channel_id, new_deposit="9000", signature="sig")),
        )

    # Finalized blocks top-ups.
    _, finalized_channel = await _open_trusted_channel(session, 5_000)
    await session.core().store().mark_finalized(finalized_channel)
    with pytest.raises(PaymentError, match="finalized"):
        await _verify_session_action(
            session,
            SessionAction.top_up_action(
                TopUpPayload(channel_id=finalized_channel, new_deposit="9000", signature="sig")
            ),
        )


async def test_session_top_up_non_string_new_deposit_rejected() -> None:
    """A JSON-number newDeposit must surface as PaymentError, not an uncaught
    AttributeError (int has no .isascii). The method-layer u64 parser now guards
    isinstance(str) like the routes-layer one."""
    session = _new_test_session()
    _, channel_id = await _open_trusted_channel(session, 1_000)
    with pytest.raises(PaymentError, match="unsigned integer string"):
        await _verify_session_action(
            session,
            SessionAction.top_up_action(TopUpPayload(channel_id=channel_id, new_deposit=500_000, signature="sig")),  # type: ignore[arg-type]
        )


async def test_session_top_up_verifies_signature_on_chain() -> None:
    """Mirrors TestSessionTopUpVerifiesSignatureOnChain."""
    fake = _FakeRpc()
    open_sig = _confirmed_signature(0x44)
    topup_sig = _confirmed_signature(0x55)
    ghost_sig = _confirmed_signature(0x66)
    fake.statuses[ghost_sig] = None

    session = _new_test_session(rpc=fake)
    signer = _TestVoucherSigner(1)
    channel_id = _new_wallet()
    await _open_session_channel(session, channel_id, 1_000, signer.address(), open_sig)

    receipt = await _verify_session_action(
        session,
        SessionAction.top_up_action(TopUpPayload(channel_id=channel_id, new_deposit="5000", signature=topup_sig)),
    )
    assert receipt.reference == topup_sig
    state = await _get_channel(session, channel_id)
    assert state is not None and state.deposit == 5_000

    with pytest.raises(PaymentError, match="not found"):
        await _verify_session_action(
            session,
            SessionAction.top_up_action(TopUpPayload(channel_id=channel_id, new_deposit="9000", signature=ghost_sig)),
        )
    state = await _get_channel(session, channel_id)
    assert state is not None and state.deposit == 5_000


# ── close ──


async def test_session_close_flips_close_pending() -> None:
    """Mirrors TestSessionCloseFlipsClosePending."""
    session = _new_test_session()
    _, channel_id = await _open_trusted_channel(session, 1_000)

    receipt = await _verify_session_action(session, SessionAction.close_action(ClosePayload(channel_id=channel_id)))
    assert receipt.reference == channel_id
    state = await _get_channel(session, channel_id)
    assert state is not None and state.close_requested_at is not None and not state.finalized


async def test_session_close_with_final_voucher_advances_watermark() -> None:
    """Mirrors TestSessionCloseWithFinalVoucherAdvancesWatermark."""
    session = _new_test_session()
    signer, channel_id = await _open_trusted_channel(session, 1_000)

    final = signer.sign_voucher(channel_id, 750, _far_future())
    await _verify_session_action(
        session, SessionAction.close_action(ClosePayload(channel_id=channel_id, voucher=final))
    )
    state = await _get_channel(session, channel_id)
    assert state is not None and state.cumulative == 750 and state.close_requested_at is not None


async def test_session_close_non_monotonic_final_voucher_hard_error() -> None:
    """Mirrors TestSessionCloseNonMonotonicFinalVoucherHardError."""
    session = _new_test_session()
    signer, channel_id = await _open_trusted_channel(session, 1_000)
    await _submit_voucher(session, signer, channel_id, 250)

    stale = signer.sign_voucher(channel_id, 100, _far_future())
    with pytest.raises(PaymentError, match="must exceed watermark"):
        await _verify_session_action(
            session, SessionAction.close_action(ClosePayload(channel_id=channel_id, voucher=stale))
        )
    state = await _get_channel(session, channel_id)
    assert state is not None and state.close_requested_at is None and state.cumulative == 250


async def test_session_close_accepts_replay_of_highest_voucher() -> None:
    """Mirrors TestSessionCloseAcceptsReplayOfHighestVoucher."""
    session = _new_test_session()
    signer, channel_id = await _open_trusted_channel(session, 1_000)
    voucher = signer.sign_voucher(channel_id, 250, _far_future())
    await _verify_session_action(session, SessionAction.voucher_action(VoucherPayload(voucher=voucher)))

    await _verify_session_action(
        session, SessionAction.close_action(ClosePayload(channel_id=channel_id, voucher=voucher))
    )
    state = await _get_channel(session, channel_id)
    assert state is not None and state.close_requested_at is not None and state.cumulative == 250


async def test_session_close_second_close_on_closing_channel_redrives() -> None:
    """A second close on an already-closing channel that has no settled
    signature re-drives (matches Go ``handleClose``) rather than hard-rejecting
    with "close already requested".

    Mirrors the re-drivable branch of Go ``handleClose`` (session_method.go
    ~681-688): ``CloseRequestedAt != nil && SettledSignature == nil`` leaves the
    state untouched and lets the settlement retry proceed. Python's close path
    never records a settled signature (the on-chain settlement is not ported),
    so the channel stays re-drivable.
    """
    session = _new_test_session()
    _, channel_id = await _open_trusted_channel(session, 1_000)

    first = await _verify_session_action(session, SessionAction.close_action(ClosePayload(channel_id=channel_id)))
    assert first.reference == channel_id
    after_first = await _get_channel(session, channel_id)
    assert after_first is not None and after_first.close_requested_at is not None
    first_close_at = after_first.close_requested_at

    # Second close on the closing channel re-drives instead of raising.
    second = await _verify_session_action(session, SessionAction.close_action(ClosePayload(channel_id=channel_id)))
    assert second.reference == channel_id
    after_second = await _get_channel(session, channel_id)
    assert after_second is not None
    assert after_second.close_requested_at == first_close_at
    assert not after_second.finalized


async def test_session_close_settled_double_close_rejected() -> None:
    """A close-pending channel that already recorded a settlement signature is
    NOT re-drivable: a second close hard-rejects with "close already requested".

    Mirrors Go ``handleClose`` (session_method.go ~681-688) and
    TestSessionCloseUnknownChannelAndSettledDoubleClose: the re-drive guard only
    fires while ``SettledSignature == nil``.
    """
    from pay_kit.protocols.mpp.server.session_store import ChannelState

    session = _new_test_session()
    signer = _TestVoucherSigner(0x21)
    channel_id = _new_wallet()

    def seed(_current: ChannelState | None) -> ChannelState:
        return ChannelState(
            channel_id=channel_id,
            authorized_signer=signer.address(),
            deposit=1_000,
            close_requested_at=1,
            settled_signature=_confirmed_signature(0xAB),
        )

    await session.core().store().update_channel(channel_id, seed)

    with pytest.raises(PaymentError, match="close already requested"):
        await _verify_session_action(session, SessionAction.close_action(ClosePayload(channel_id=channel_id)))


async def test_session_idle_close_flips_state_without_signer_or_rpc() -> None:
    """The idle-close watchdog must flip close_requested_at even when no signer/
    RPC is configured (e.g. the playground); only the on-chain settle is gated.
    Previously it early-returned and the idle timeout never took effect."""
    session = _new_test_session()  # no signer, rpc=None
    _, channel_id = await _open_trusted_channel(session, 1_000)

    await session._close_on_idle(channel_id)  # pyright: ignore[reportPrivateUsage]

    state = await _get_channel(session, channel_id)
    assert state is not None
    assert state.close_requested_at is not None
    assert not state.finalized
    assert state.settled_signature is None


# ── method-layer open guards ──


async def test_session_push_open_requires_payer_or_transaction_for_settlement() -> None:
    operator = Keypair.from_seed(bytes([44] * 32))
    session = _new_test_session(
        operator=str(operator.pubkey()),
        recipient=SESSION_TEST_RECIPIENT,
        signer=LocalSigner.from_keypair(operator),
        rpc=_FakeRpc(),
    )
    channel_id = _new_wallet()
    signer = _TestVoucherSigner(0x30)

    with pytest.raises(PaymentError, match="requires payer or transaction"):
        await _verify_session_action(
            session,
            SessionAction.open_action(
                OpenPayload.push(channel_id, "1000", signer.address(), _confirmed_signature(0x31))
            ),
        )

    payer = _new_wallet()
    await _verify_session_action(
        session,
        SessionAction.open_action(
            OpenPayload.payment_channel(
                channel_id,
                "1000",
                payer,
                SESSION_TEST_RECIPIENT,
                "USDC",
                1,
                900,
                signer.address(),
                _confirmed_signature(0x32),
            )
        ),
    )
    state = await _get_channel(session, channel_id)
    assert state is not None
    assert state.operator == payer


async def test_session_open_pull_without_strategy_rejected_at_method_layer() -> None:
    """Pull-mode open requires a pull voucher strategy on the server config.

    Mirrors the Go ``handleOpen`` method-layer guard (session_method.go
    ~458-460). ``new_session`` rejects pull-without-strategy at construction, so
    this builds the core ``SessionServer`` directly with a pull-mode config that
    omits the strategy to exercise the method-layer guard in isolation.
    """
    from pay_kit.protocols.mpp.server.session import SessionConfig, SessionServer
    from pay_kit.protocols.mpp.server.session_store import MemoryChannelStore

    config = SessionConfig(
        operator=SESSION_TEST_RECIPIENT,
        recipient=SESSION_TEST_RECIPIENT,
        max_cap=5_000_000,
        currency="USDC",
        decimals=6,
        network="localnet",
        modes=["pull"],
        pull_voucher_strategy=None,
    )
    core = SessionServer(config, MemoryChannelStore())
    session = Session(
        core=core,
        secret_key=SESSION_METHOD_SECRET,
        realm="api.test",
        cap=5_000_000,
        currency="USDC",
        recipient=SESSION_TEST_RECIPIENT,
        network="localnet",
        open_tx_submitter="client",
        rpc=None,
        lifecycle=None,
    )

    signer = _TestVoucherSigner(0x21)
    payload = OpenPayload.pull(_new_wallet(), "1000", _new_wallet(), signer.address(), "sig")
    with pytest.raises(PaymentError, match="pull-mode open requires a pullVoucherStrategy"):
        await _verify_session_action(session, SessionAction.open_action(payload))


# ── commit ──


async def test_session_commit_for_reserved_delivery() -> None:
    """Mirrors the credential-layer half of TestSessionCommitForReservedDelivery
    (the metering reservation runs through the core ``begin_delivery``; the
    HTTP ``Routes`` wrapper is not ported)."""
    session = _new_test_session()
    signer, channel_id = await _open_trusted_channel(session, 1_000)

    from pay_kit.protocols.mpp.server.session import DeliveryRequest

    directive = await session.core().begin_delivery(DeliveryRequest(session_id=channel_id, amount=200))
    assert directive.delivery_id == f"{channel_id}:1"
    assert directive.sequence == 1
    assert directive.currency == "USDC"
    assert directive.amount == "200"

    voucher = signer.sign_voucher(channel_id, 150, _far_future())
    receipt = await _verify_session_action(
        session, SessionAction.commit_action(CommitPayload(delivery_id=directive.delivery_id, voucher=voucher))
    )
    assert receipt.reference == f"{channel_id}:{directive.delivery_id}:150"
    state = await _get_channel(session, channel_id)
    assert state is not None
    assert state.cumulative == 150
    assert len(state.committed_deliveries) == 1
    assert len(state.pending_deliveries) == 0


async def test_session_commit_replay_re_verifies_signature() -> None:
    """Mirrors TestSessionCommitReplayReVerifiesSignature."""
    from pay_kit.protocols.mpp.server.session_store import ChannelState, CommittedDelivery

    session = _new_test_session()
    signer = _TestVoucherSigner(1)
    channel_id = _new_wallet()
    forged = _confirmed_signature(0xAA)

    def seed(_current: ChannelState | None) -> ChannelState:
        return ChannelState(
            channel_id=channel_id,
            authorized_signer=signer.address(),
            deposit=1_000,
            cumulative=50,
            next_delivery_sequence=1,
            committed_deliveries=[
                CommittedDelivery(delivery_id="d-1", amount=50, cumulative=50, voucher_signature=forged)
            ],
        )

    await session.core().store().update_channel(channel_id, seed)

    forged_voucher = SignedVoucher(
        data=VoucherData(channel_id=channel_id, cumulative="50", expires_at=_far_future()),
        signature=forged,
    )
    with pytest.raises(PaymentError, match="signature"):
        await _verify_session_action(
            session, SessionAction.commit_action(CommitPayload(delivery_id="d-1", voucher=forged_voucher))
        )
