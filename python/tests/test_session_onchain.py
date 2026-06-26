"""Tests for the session on-chain open-tx verifier and helpers.

Mirrors the behaviors in
``go/protocols/mpp/server/session_onchain_test.go`` for the standalone
``verify_open_tx`` slice and the top-up / open verifier seam factories. The
``SessionServer``-bound ``SettlementInstructions`` method and the
``ProcessOpen`` integration tests are not ported here: the base session server
is not yet ported to Python, so the settlement method and the
verifier-through-``ProcessOpen`` paths land with that follow-up.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, replace

import pytest
from solders.hash import Hash  # type: ignore[import-untyped]
from solders.instruction import Instruction  # type: ignore[import-untyped]
from solders.keypair import Keypair  # type: ignore[import-untyped]
from solders.message import Message, MessageV0  # type: ignore[import-untyped]
from solders.pubkey import Pubkey  # type: ignore[import-untyped]
from solders.signature import Signature  # type: ignore[import-untyped]
from solders.transaction import (  # type: ignore[import-untyped]
    Transaction,
    VersionedTransaction,
)

from pay_kit._paycore.errors import PaymentError
from pay_kit._paycore.solana import TOKEN_PROGRAM
from pay_kit.protocols.mpp._paymentchannels import (
    PROGRAM_ID,
    OpenChannelParams,
    build_open_instruction,
    find_channel_pda,
)
from pay_kit.protocols.mpp.intents.session import OpenPayload, TopUpPayload
from pay_kit.protocols.mpp.server.session_onchain import (
    VerifyOpenTxExpected,
    is_placeholder_signature,
    new_open_tx_verifier,
    new_top_up_tx_verifier,
    verify_open_tx,
)

USDC_MAINNET_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"

OPEN_FIXTURE_SALT = 7
OPEN_FIXTURE_DEPOSIT = 1_000_000
OPEN_FIXTURE_GRACE = 900


@dataclass
class OpenTxFixture:
    """A freshly built and signed payment-channel open tx plus the challenge
    expectations that accept it. Mirrors ``openTxFixture`` in the Go test."""

    payer: Keypair
    payee: Pubkey
    authorized: Pubkey
    mint: Pubkey
    channel: Pubkey
    signature: str
    payload: OpenPayload
    expected: VerifyOpenTxExpected


class _FakeRpc:
    """Minimal RPC double exposing ``get_signature_statuses`` like the
    production ``SolanaRpc``. Mirrors ``testutil.FakeRPC``: any signature not in
    ``statuses`` is reported confirmed with no error."""

    def __init__(self) -> None:
        self.statuses: dict[str, dict | None] = {}

    async def get_signature_statuses(self, signatures: list[str]) -> list[dict | None]:
        out: list[dict | None] = []
        for signature in signatures:
            if signature in self.statuses:
                out.append(self.statuses[signature])
            else:
                out.append({"err": None, "confirmationStatus": "confirmed"})
        return out

    async def get_latest_blockhash(self, commitment: str = "confirmed"):  # noqa: ANN201 (RPC seam stub)
        raise NotImplementedError  # not exercised by the open/top-up verifier tests

    async def send_raw_transaction(self, raw_tx: bytes):  # noqa: ANN201 (RPC seam stub)
        raise NotImplementedError  # not exercised by the open/top-up verifier tests


def _kp(seed: int) -> Keypair:
    return Keypair.from_seed(bytes([seed] * 32))


def _sign_and_attach(fixture: OpenTxFixture, ix: Instruction, v0: bool) -> tuple[str, OpenPayload]:
    blockhash = Hash.from_string("EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N")
    payer_pubkey = fixture.payer.pubkey()
    if v0:
        message_v0 = MessageV0.try_compile(payer_pubkey, [ix], [], blockhash)
        vtx = VersionedTransaction(message_v0, [fixture.payer])
        encoded = base64.b64encode(bytes(vtx)).decode("ascii")
        signature = str(vtx.signatures[0])
    else:
        message = Message.new_with_blockhash([ix], payer_pubkey, blockhash)
        tx = Transaction([fixture.payer], message, blockhash)
        encoded = base64.b64encode(bytes(tx)).decode("ascii")
        signature = str(tx.signatures[0])
    payload = OpenPayload.payment_channel(
        str(fixture.channel),
        str(OPEN_FIXTURE_DEPOSIT),
        str(payer_pubkey),
        str(fixture.payee),
        str(fixture.mint),
        OPEN_FIXTURE_SALT,
        OPEN_FIXTURE_GRACE,
        str(fixture.authorized),
        signature,
    ).with_transaction(encoded)
    return signature, payload


def build_open_tx_fixture(v0: bool) -> OpenTxFixture:
    payer = _kp(1)
    payee = _kp(2).pubkey()
    authorized = _kp(3).pubkey()
    mint = Pubkey.from_string(USDC_MAINNET_MINT)
    channel, _ = find_channel_pda(payer.pubkey(), payee, mint, authorized, OPEN_FIXTURE_SALT, PROGRAM_ID)
    ix = build_open_instruction(
        OpenChannelParams(
            payer=payer.pubkey(),
            payee=payee,
            mint=mint,
            authorized_signer=authorized,
            salt=OPEN_FIXTURE_SALT,
            deposit=OPEN_FIXTURE_DEPOSIT,
            grace_period=OPEN_FIXTURE_GRACE,
            token_program=Pubkey.from_string(TOKEN_PROGRAM),
            rent_payer=payer.pubkey(),
        )
    )
    fixture = OpenTxFixture(
        payer=payer,
        payee=payee,
        authorized=authorized,
        mint=mint,
        channel=channel,
        signature="",
        payload=OpenPayload.payment_channel("", "", "", "", "", 0, 0, "", ""),
        expected=VerifyOpenTxExpected(authorized_signer="", recipient="", currency="", network=""),
    )
    fixture.signature, fixture.payload = _sign_and_attach(fixture, ix, v0)
    fixture.expected = VerifyOpenTxExpected(
        authorized_signer=str(authorized),
        currency="USDC",
        max_cap=5_000_000,
        network="localnet",
        recipient=str(payee),
        # operator is the expected rentPayer (required); the fixture pins
        # rentPayer to its own payer.
        operator=str(payer.pubkey()),
    )
    return fixture


# -- verify_open_tx: accepted encodings ---------------------------------------


async def test_verify_open_tx_accepts_legacy_encoding() -> None:
    """Mirrors TestVerifyOpenTxAcceptsLegacyEncoding."""
    fixture = build_open_tx_fixture(v0=False)
    result = await verify_open_tx(fixture.expected, fixture.payload, None)
    assert result.channel_id == str(fixture.channel)
    assert result.deposit == OPEN_FIXTURE_DEPOSIT
    assert result.grace_period == OPEN_FIXTURE_GRACE
    assert result.salt == OPEN_FIXTURE_SALT
    # payer (open slot 0) is surfaced so the method layer can record
    # state.operator and refund the opener's ATA at settle-at-close.
    assert result.payer == str(fixture.payer.pubkey())


async def test_verify_open_tx_accepts_v0_encoding() -> None:
    """Mirrors TestVerifyOpenTxAcceptsV0Encoding."""
    fixture = build_open_tx_fixture(v0=True)
    # Confirm the fixture really emits the v0 wire prefix before asserting it
    # verifies: the message must round-trip through the versioned decoder.
    assert fixture.payload.transaction is not None
    raw = base64.b64decode(fixture.payload.transaction, validate=True)
    vtx = VersionedTransaction.from_bytes(raw)
    assert isinstance(vtx.message, MessageV0)
    result = await verify_open_tx(fixture.expected, fixture.payload, None)
    assert result.channel_id == str(fixture.channel)


async def test_verify_open_tx_honors_explicit_mint_and_program_overrides() -> None:
    """Mirrors TestVerifyOpenTxHonorsExplicitMintAndProgramOverrides."""
    fixture = build_open_tx_fixture(v0=False)
    expected = replace(
        fixture.expected,
        currency="not-a-currency",
        mint=str(fixture.mint),
        program_id=PROGRAM_ID,
    )
    result = await verify_open_tx(expected, fixture.payload, None)
    assert result.channel_id == str(fixture.channel)


# -- verify_open_tx: failure modes --------------------------------------------


async def test_verify_open_tx_rejects_undecodable_transaction() -> None:
    """Mirrors TestVerifyOpenTxRejectsUndecodableTransaction."""
    fixture = build_open_tx_fixture(v0=False)
    fixture.payload.transaction = "not-base64!"
    with pytest.raises(PaymentError, match="decode open transaction"):
        await verify_open_tx(fixture.expected, fixture.payload, None)


async def test_verify_open_tx_requires_transaction() -> None:
    """Mirrors TestVerifyOpenTxRequiresTransaction."""
    fixture = build_open_tx_fixture(v0=False)
    fixture.payload.transaction = None
    with pytest.raises(PaymentError, match="transaction is required"):
        await verify_open_tx(fixture.expected, fixture.payload, None)


async def test_verify_open_tx_rejects_wrong_payee() -> None:
    """Mirrors TestVerifyOpenTxRejectsWrongPayee."""
    fixture = build_open_tx_fixture(v0=False)
    expected = replace(fixture.expected, recipient=str(fixture.payer.pubkey()))
    with pytest.raises(PaymentError, match="payee"):
        await verify_open_tx(expected, fixture.payload, None)


async def test_verify_open_tx_rejects_wrong_mint() -> None:
    """Mirrors TestVerifyOpenTxRejectsWrongMint."""
    fixture = build_open_tx_fixture(v0=False)
    expected = replace(fixture.expected, currency="USDT")
    with pytest.raises(PaymentError, match="mint"):
        await verify_open_tx(expected, fixture.payload, None)


async def test_verify_open_tx_rejects_wrong_authorized_signer() -> None:
    """Mirrors TestVerifyOpenTxRejectsWrongAuthorizedSigner."""
    fixture = build_open_tx_fixture(v0=False)
    expected = replace(fixture.expected, authorized_signer=str(_kp(99).pubkey()))
    with pytest.raises(PaymentError, match="authorizedSigner"):
        await verify_open_tx(expected, fixture.payload, None)


async def test_verify_open_tx_requires_operator() -> None:
    """rentPayer is a security boundary: an empty/None expected operator must
    raise ValueError rather than skipping the slot-1 rentPayer check."""
    fixture = build_open_tx_fixture(v0=False)
    expected = replace(fixture.expected, operator="")
    with pytest.raises(ValueError, match="operator .*is required"):
        await verify_open_tx(expected, fixture.payload, None)


async def test_verify_open_tx_rejects_wrong_operator() -> None:
    """The open's slot-1 rentPayer must equal the expected operator."""
    fixture = build_open_tx_fixture(v0=False)
    expected = replace(fixture.expected, operator=str(_kp(99).pubkey()))
    with pytest.raises(PaymentError, match="rentPayer"):
        await verify_open_tx(expected, fixture.payload, None)


async def test_verify_open_tx_rejects_over_cap_deposit() -> None:
    """Mirrors TestVerifyOpenTxRejectsOverCapDeposit."""
    fixture = build_open_tx_fixture(v0=False)
    expected = replace(fixture.expected, max_cap=OPEN_FIXTURE_DEPOSIT - 1)
    with pytest.raises(PaymentError, match="exceeds max cap"):
        await verify_open_tx(expected, fixture.payload, None)


async def test_verify_open_tx_rejects_zero_deposit() -> None:
    """Mirrors TestVerifyOpenTxRejectsZeroDeposit."""
    fixture = build_open_tx_fixture(v0=False)
    # Rebuild the open instruction with a zero deposit; the channel PDA does not
    # embed the deposit, so only the deposit check can reject it.
    ix = build_open_instruction(
        OpenChannelParams(
            payer=fixture.payer.pubkey(),
            payee=fixture.payee,
            mint=fixture.mint,
            authorized_signer=fixture.authorized,
            salt=OPEN_FIXTURE_SALT,
            deposit=0,
            grace_period=OPEN_FIXTURE_GRACE,
            token_program=Pubkey.from_string(TOKEN_PROGRAM),
            rent_payer=fixture.payer.pubkey(),
        )
    )
    _, fixture.payload = _sign_and_attach(fixture, ix, v0=False)
    with pytest.raises(PaymentError, match="greater than zero"):
        await verify_open_tx(fixture.expected, fixture.payload, None)


async def test_verify_open_tx_rejects_unbound_signature() -> None:
    """Mirrors TestVerifyOpenTxRejectsUnboundSignature."""
    fixture = build_open_tx_fixture(v0=False)
    unrelated = _kp(50).sign_message(b"unrelated transaction")
    fixture.payload.signature = str(unrelated)
    with pytest.raises(PaymentError, match="transaction signature"):
        await verify_open_tx(fixture.expected, fixture.payload, None)


async def test_verify_open_tx_rejects_signature_without_fee_payer_signature() -> None:
    """Mirrors TestVerifyOpenTxRejectsSignatureWithoutFeePayerSignature."""
    fixture = build_open_tx_fixture(v0=False)
    assert fixture.payload.transaction is not None
    raw = base64.b64decode(fixture.payload.transaction, validate=True)
    tx = Transaction.from_bytes(raw)
    stripped = Transaction.populate(tx.message, [Signature.default()])
    fixture.payload.transaction = base64.b64encode(bytes(stripped)).decode("ascii")
    with pytest.raises(PaymentError, match="no fee-payer signature"):
        await verify_open_tx(fixture.expected, fixture.payload, None)


async def test_verify_open_tx_accepts_placeholder_signature_without_binding() -> None:
    """Mirrors TestVerifyOpenTxAcceptsPlaceholderSignatureWithoutBinding."""
    fixture = build_open_tx_fixture(v0=False)
    fixture.payload.signature = "1" * 64
    result = await verify_open_tx(fixture.expected, fixture.payload, None)
    assert result.channel_id == str(fixture.channel)


async def test_verify_open_tx_rejects_missing_open_instruction() -> None:
    """Mirrors TestVerifyOpenTxRejectsMissingOpenInstruction."""
    fixture = build_open_tx_fixture(v0=False)
    memo = Instruction(
        Pubkey.from_string("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"),
        b"not an open",
        [],
    )
    _, fixture.payload = _sign_and_attach(fixture, memo, v0=False)
    with pytest.raises(PaymentError, match="no payment-channels open instruction"):
        await verify_open_tx(fixture.expected, fixture.payload, None)


async def test_verify_open_tx_rejects_channel_pda_mismatch() -> None:
    """Mirrors TestVerifyOpenTxRejectsChannelPDAMismatch."""
    fixture = build_open_tx_fixture(v0=False)
    ix = build_open_instruction(
        OpenChannelParams(
            payer=fixture.payer.pubkey(),
            payee=fixture.payee,
            mint=fixture.mint,
            authorized_signer=fixture.authorized,
            salt=OPEN_FIXTURE_SALT,
            deposit=OPEN_FIXTURE_DEPOSIT,
            grace_period=OPEN_FIXTURE_GRACE,
            token_program=Pubkey.from_string(TOKEN_PROGRAM),
            rent_payer=fixture.payer.pubkey(),
        )
    )
    # Swap the channel account (slot 5, after the rentPayer +1 shift) for an
    # unrelated key while keeping the instruction data intact: the re-derived
    # PDA must catch it.
    accounts = list(ix.accounts)
    tampered = accounts[5]
    accounts[5] = type(tampered)(_kp(77).pubkey(), tampered.is_signer, tampered.is_writable)
    forged = Instruction(ix.program_id, ix.data, accounts)
    _, fixture.payload = _sign_and_attach(fixture, forged, v0=False)
    with pytest.raises(PaymentError, match="PDA"):
        await verify_open_tx(fixture.expected, fixture.payload, None)


async def test_verify_open_tx_rejects_payload_channel_id_mismatch() -> None:
    """Mirrors TestVerifyOpenTxRejectsPayloadChannelIDMismatch."""
    fixture = build_open_tx_fixture(v0=False)
    fixture.payload.channel_id = str(_kp(88).pubkey())
    with pytest.raises(PaymentError, match="channelId"):
        await verify_open_tx(fixture.expected, fixture.payload, None)


# -- verify_open_tx: RPC liveness ---------------------------------------------


async def test_verify_open_tx_confirms_bound_signature_via_rpc() -> None:
    """Mirrors TestVerifyOpenTxConfirmsBoundSignatureViaRPC."""
    fixture = build_open_tx_fixture(v0=False)
    fake_rpc = _FakeRpc()
    result = await verify_open_tx(fixture.expected, fixture.payload, fake_rpc)
    assert result.channel_id == str(fixture.channel)


async def test_verify_open_tx_surfaces_rpc_failure() -> None:
    """Mirrors TestVerifyOpenTxSurfacesRPCFailure."""
    fixture = build_open_tx_fixture(v0=False)
    fake_rpc = _FakeRpc()
    fake_rpc.statuses[fixture.signature] = {"err": "InstructionError"}
    with pytest.raises(PaymentError, match="failed on-chain"):
        await verify_open_tx(fixture.expected, fixture.payload, fake_rpc)


async def test_verify_open_tx_surfaces_rpc_not_found() -> None:
    """Mirrors TestVerifyOpenTxSurfacesRPCNotFound."""
    fixture = build_open_tx_fixture(v0=False)
    fake_rpc = _FakeRpc()
    fake_rpc.statuses[fixture.signature] = None
    with pytest.raises(PaymentError, match="not found"):
        await verify_open_tx(fixture.expected, fixture.payload, fake_rpc)


def test_is_placeholder_signature() -> None:
    """Mirrors TestIsPlaceholderSignature."""
    cases = [
        ("", True),
        ("1" * 64, True),
        ("1" * 40, True),
        ("1" * 39, False),
        ("1" * 63 + "2", False),
        ("5VERYrealLookingBase58SignatureValue11111111111111111111111111111", False),
    ]
    for signature, want in cases:
        assert is_placeholder_signature(signature) is want


# -- new_open_tx_verifier wiring ----------------------------------------------


@dataclass
class _OpenConfig:
    """Lightweight stand-in for the not-yet-ported SessionConfig, exposing only
    the fields new_open_tx_verifier reads."""

    currency: str
    network: str
    recipient: str
    max_cap: int
    operator: str = ""
    program_id: Pubkey | None = None


def _open_session_config(fixture: OpenTxFixture) -> _OpenConfig:
    return _OpenConfig(
        currency="USDC",
        network="localnet",
        recipient=str(fixture.payee),
        max_cap=5_000_000,
        # The fixture pins rentPayer (the operator/fee payer) to its own payer.
        operator=str(fixture.payer.pubkey()),
    )


async def test_new_open_tx_verifier_accepts_valid_open() -> None:
    """Mirrors the verifier-seam half of
    TestNewOpenTxVerifierAcceptsValidOpenThroughProcessOpen (the ProcessOpen
    integration lands with the base session server port)."""
    fixture = build_open_tx_fixture(v0=False)
    verifier = new_open_tx_verifier(_open_session_config(fixture), None)
    await verifier(fixture.payload)


async def test_new_open_tx_verifier_rejects_foreign_recipient() -> None:
    """Mirrors the verifier-seam half of
    TestNewOpenTxVerifierRejectsForeignRecipientThroughProcessOpen."""
    fixture = build_open_tx_fixture(v0=False)
    config = _open_session_config(fixture)
    config.recipient = str(fixture.payer.pubkey())  # not the tx payee
    verifier = new_open_tx_verifier(config, None)
    with pytest.raises(PaymentError, match="payee"):
        await verifier(fixture.payload)


async def test_new_open_tx_verifier_without_transaction_requires_rpc() -> None:
    """Mirrors TestNewOpenTxVerifierWithoutTransactionRequiresRPC."""
    fixture = build_open_tx_fixture(v0=False)
    verifier = new_open_tx_verifier(_open_session_config(fixture), None)
    fixture.payload.transaction = None
    with pytest.raises(PaymentError, match="RPC client"):
        await verifier(fixture.payload)


async def test_new_open_tx_verifier_without_transaction_confirms_signature() -> None:
    """Mirrors TestNewOpenTxVerifierWithoutTransactionConfirmsSignature."""
    fixture = build_open_tx_fixture(v0=False)
    verifier = new_open_tx_verifier(_open_session_config(fixture), _FakeRpc())
    fixture.payload.transaction = None
    await verifier(fixture.payload)


# -- new_top_up_tx_verifier ---------------------------------------------------


def test_new_top_up_tx_verifier_none_rpc_disables_the_seam() -> None:
    """Mirrors TestNewTopUpTxVerifierNilRPCDisablesTheSeam."""
    assert new_top_up_tx_verifier(None) is None


async def test_new_top_up_tx_verifier_confirms_signature() -> None:
    """Mirrors TestNewTopUpTxVerifierConfirmsSignature."""
    signature = _kp(20).sign_message(b"top-up")
    verifier = new_top_up_tx_verifier(_FakeRpc())
    assert verifier is not None
    payload = TopUpPayload(channel_id="chan", new_deposit="2000000", signature=str(signature))
    await verifier(payload)


async def test_new_top_up_tx_verifier_surfaces_failure_and_not_found() -> None:
    """Mirrors TestNewTopUpTxVerifierSurfacesFailureAndNotFound."""
    signature = str(_kp(21).sign_message(b"top-up"))
    fake_rpc = _FakeRpc()
    fake_rpc.statuses[signature] = {"err": "InstructionError"}
    verifier = new_top_up_tx_verifier(fake_rpc)
    assert verifier is not None
    payload = TopUpPayload(channel_id="chan", new_deposit="2000000", signature=signature)
    with pytest.raises(PaymentError, match="top-up"):
        await verifier(payload)

    fake_rpc.statuses[signature] = None
    with pytest.raises(PaymentError, match="not found"):
        await verifier(payload)

    with pytest.raises(PaymentError, match="invalid top-up tx signature"):
        await verifier(TopUpPayload(channel_id="", new_deposit="", signature="not-base58!"))
