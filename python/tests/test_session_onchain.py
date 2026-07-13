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
from dataclasses import dataclass, field, replace

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

from solana_pay_kit._paycore.errors import PaymentError
from solana_pay_kit._paycore.solana import TOKEN_PROGRAM
from solana_pay_kit.protocols.mpp._paymentchannels import (
    PROGRAM_ID,
    Distribution,
    OpenChannelParams,
    TopUpParams,
    build_open_instruction,
    build_top_up_instruction,
    find_channel_pda,
)
from solana_pay_kit.protocols.mpp.intents.session import OpenPayload, TopUpPayload
from solana_pay_kit.protocols.mpp.server.session import Split
from solana_pay_kit.protocols.mpp.server.session_onchain import (
    VerifyOpenTxExpected,
    is_placeholder_signature,
    new_open_tx_verifier,
    new_top_up_state_tx_verifier,
    new_top_up_tx_verifier,
    verify_open_tx,
)
from solana_pay_kit.protocols.mpp.server.session_store import ChannelState

USDC_MAINNET_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"

OPEN_FIXTURE_SALT = 7
OPEN_FIXTURE_DEPOSIT = 1_000_000
OPEN_FIXTURE_GRACE = 900
OPEN_FIXTURE_SLOT = 4242


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
        self.transactions: dict[str, dict] = {}
        self.get_transaction_kwargs: list[dict[str, object]] = []

    async def get_signature_statuses(
        self, signatures: list[str], *, search_transaction_history: bool = False
    ) -> list[dict | None]:
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

    async def get_transaction(self, signature: str, **kwargs):  # noqa: ANN201 (RPC seam stub)
        self.get_transaction_kwargs.append(kwargs)
        return self.transactions.get(str(signature))


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
        OPEN_FIXTURE_SLOT,
        str(fixture.authorized),
        signature,
    ).with_transaction(encoded)
    return signature, payload


def build_open_tx_fixture(v0: bool, recipients: list[Distribution] | None = None) -> OpenTxFixture:
    if recipients is None:
        recipients = []
    payer = _kp(1)
    payee = _kp(2).pubkey()
    authorized = _kp(3).pubkey()
    mint = Pubkey.from_string(USDC_MAINNET_MINT)
    channel, _ = find_channel_pda(
        payer.pubkey(), payee, mint, authorized, OPEN_FIXTURE_SALT, OPEN_FIXTURE_SLOT, PROGRAM_ID
    )
    ix = build_open_instruction(
        OpenChannelParams(
            payer=payer.pubkey(),
            payee=payee,
            mint=mint,
            authorized_signer=authorized,
            salt=OPEN_FIXTURE_SALT,
            deposit=OPEN_FIXTURE_DEPOSIT,
            grace_period=OPEN_FIXTURE_GRACE,
            open_slot=OPEN_FIXTURE_SLOT,
            recipients=recipients,
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
        payload=OpenPayload.payment_channel("", "", "", "", "", 0, 0, 0, "", ""),
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
        recipients=[(str(entry.recipient), entry.bps) for entry in recipients],
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
    # openSlot is decoded from the instruction data and surfaced so the method
    # layer persists it (the channel PDA seed / reclaim input).
    assert result.open_slot == OPEN_FIXTURE_SLOT
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


async def test_verify_open_tx_binds_all_ordered_distribution_recipients() -> None:
    """Every Borsh recipient entry is part of the open commitment: swapping
    entries or changing a share must reject before the server persists a channel
    that would distribute to a different destination at close."""
    recipients = [
        Distribution(recipient=_kp(4).pubkey(), bps=2_500),
        Distribution(recipient=_kp(5).pubkey(), bps=7_500),
    ]
    fixture = build_open_tx_fixture(v0=False, recipients=recipients)

    accepted = await verify_open_tx(fixture.expected, fixture.payload, None)
    assert accepted.channel_id == str(fixture.channel)

    reordered = replace(fixture.expected, recipients=list(reversed(fixture.expected.recipients)))
    with pytest.raises(PaymentError, match="open recipients"):
        await verify_open_tx(reordered, fixture.payload, None)

    changed_bps = replace(
        fixture.expected,
        recipients=[(fixture.expected.recipients[0][0], 2_499), fixture.expected.recipients[1]],
    )
    with pytest.raises(PaymentError, match="open recipients"):
        await verify_open_tx(changed_bps, fixture.payload, None)


async def test_verify_open_tx_rejects_address_lookup_tables() -> None:
    """A v0 open tx that resolves accounts through an address lookup table is
    rejected: ``verify_open_tx`` validates the open instruction's accounts
    against the static account keys and re-derives the channel PDA from them, so
    an ALT could hide the real rentPayer / payee / mint behind indices the
    verifier cannot see. The operator must never co-sign such a transaction.
    """
    from solders.address_lookup_table_account import (  # type: ignore[import-untyped]
        AddressLookupTableAccount,
    )

    payer = _kp(1)
    payee = _kp(2).pubkey()
    authorized = _kp(3).pubkey()
    mint = Pubkey.from_string(USDC_MAINNET_MINT)
    channel, _ = find_channel_pda(
        payer.pubkey(), payee, mint, authorized, OPEN_FIXTURE_SALT, OPEN_FIXTURE_SLOT, PROGRAM_ID
    )
    ix = build_open_instruction(
        OpenChannelParams(
            payer=payer.pubkey(),
            payee=payee,
            mint=mint,
            authorized_signer=authorized,
            salt=OPEN_FIXTURE_SALT,
            deposit=OPEN_FIXTURE_DEPOSIT,
            grace_period=OPEN_FIXTURE_GRACE,
            open_slot=OPEN_FIXTURE_SLOT,
            token_program=Pubkey.from_string(TOKEN_PROGRAM),
            rent_payer=payer.pubkey(),
        )
    )
    # Stuff some of the instruction's read-only accounts into a lookup table so
    # ``MessageV0.try_compile`` emits a non-empty ``address_table_lookups`` list.
    lookup_addresses = [meta.pubkey for meta in ix.accounts if not meta.is_signer]
    alt = AddressLookupTableAccount(key=_kp(9).pubkey(), addresses=lookup_addresses)
    blockhash = Hash.from_string("EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N")
    message_v0 = MessageV0.try_compile(payer.pubkey(), [ix], [alt], blockhash)
    vtx = VersionedTransaction(message_v0, [payer])
    # Confirm the fixture actually exercises an ALT before asserting rejection.
    assert message_v0.address_table_lookups

    encoded = base64.b64encode(bytes(vtx)).decode("ascii")
    payload = OpenPayload.payment_channel(
        str(channel),
        str(OPEN_FIXTURE_DEPOSIT),
        str(payer.pubkey()),
        str(payee),
        str(mint),
        OPEN_FIXTURE_SALT,
        OPEN_FIXTURE_GRACE,
        OPEN_FIXTURE_SLOT,
        str(authorized),
        str(vtx.signatures[0]),
    ).with_transaction(encoded)
    expected = VerifyOpenTxExpected(
        authorized_signer=str(authorized),
        currency="USDC",
        max_cap=5_000_000,
        network="localnet",
        recipient=str(payee),
        operator=str(payer.pubkey()),
    )

    with pytest.raises(PaymentError, match="address lookup tables"):
        await verify_open_tx(expected, payload, None)


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
            open_slot=OPEN_FIXTURE_SLOT,
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


@pytest.mark.parametrize("signature", ["", "1" * 64])
async def test_verify_open_tx_rejects_client_placeholder_signature(signature: str) -> None:
    """A client-submitted open cannot omit or defer its fee-payer signature."""
    fixture = build_open_tx_fixture(v0=False)
    fixture.payload.signature = signature
    with pytest.raises(PaymentError, match="non-placeholder fee-payer signature"):
        await verify_open_tx(fixture.expected, fixture.payload, None)


async def test_verify_open_tx_allows_placeholder_only_for_server_cosign() -> None:
    """The explicit server co-sign path may receive the incomplete wire."""
    fixture = build_open_tx_fixture(v0=False)
    assert fixture.payload.transaction is not None
    raw = base64.b64decode(fixture.payload.transaction, validate=True)
    tx = Transaction.from_bytes(raw)
    stripped = Transaction.populate(tx.message, [Signature.default()])
    fixture.payload.transaction = base64.b64encode(bytes(stripped)).decode("ascii")
    fixture.payload.signature = ""

    result = await verify_open_tx(
        fixture.expected,
        fixture.payload,
        None,
        allow_fee_payer_placeholder=True,
    )
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
            open_slot=OPEN_FIXTURE_SLOT,
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


async def test_verify_open_tx_rejects_payload_recent_slot_mismatch() -> None:
    """A payload recentSlot that disagrees with the transaction's openSlot is
    rejected (the instruction data is authoritative)."""
    fixture = build_open_tx_fixture(v0=False)
    fixture.payload.recent_slot = OPEN_FIXTURE_SLOT + 1
    with pytest.raises(PaymentError, match="recentSlot"):
        await verify_open_tx(fixture.expected, fixture.payload, None)


async def test_verify_open_tx_binds_challenge_recent_slot() -> None:
    """When the caller supplies the challenge-issued recentSlot, the
    transaction's own openSlot must equal it — even when the payload omits
    recentSlot (otherwise a transaction built against a different slot would
    slip through and the decoded slot would overwrite the payload)."""
    fixture = build_open_tx_fixture(v0=False)
    fixture.payload.recent_slot = None
    expected = replace(fixture.expected, recent_slot=OPEN_FIXTURE_SLOT + 1)
    with pytest.raises(PaymentError, match="challenge recentSlot"):
        await verify_open_tx(expected, fixture.payload, None)

    accepted = replace(fixture.expected, recent_slot=OPEN_FIXTURE_SLOT)
    result = await verify_open_tx(accepted, fixture.payload, None)
    assert result.open_slot == OPEN_FIXTURE_SLOT


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
    splits: list[Split] = field(default_factory=list)


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


@dataclass
class _TopUpConfig:
    program_id: Pubkey | None = None


def _base58_encode(data: bytes) -> str:
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    number = int.from_bytes(data, "big")
    encoded = ""
    while number:
        number, remainder = divmod(number, 58)
        encoded = alphabet[remainder] + encoded
    leading_zeros = len(data) - len(data.lstrip(b"\0"))
    return "1" * leading_zeros + (encoded or "1")


def _top_up_instruction(channel: Pubkey, amount: int) -> dict[str, object]:
    instruction = build_top_up_instruction(
        TopUpParams(
            payer=_kp(20).pubkey(),
            channel=channel,
            mint=Pubkey.from_string(USDC_MAINNET_MINT),
            amount=amount,
            token_program=Pubkey.from_string(TOKEN_PROGRAM),
        )
    )
    return {
        "programId": str(instruction.program_id),
        "accounts": [str(account.pubkey) for account in instruction.accounts],
        "data": _base58_encode(bytes(instruction.data)),
    }


def _confirmed_top_up_transaction(channel: Pubkey, *amounts: int) -> dict:
    return {
        "meta": {"err": None},
        "transaction": {"message": {"instructions": [_top_up_instruction(channel, amount) for amount in amounts]}},
    }


def _top_up_state(channel: Pubkey, deposit: int = 1_000_000) -> ChannelState:
    return ChannelState(channel_id=str(channel), authorized_signer=str(_kp(21).pubkey()), deposit=deposit)


def test_new_top_up_tx_verifier_none_rpc_disables_the_seam() -> None:
    """Mirrors TestNewTopUpTxVerifierNilRPCDisablesTheSeam."""
    assert new_top_up_tx_verifier(None) is None
    assert new_top_up_tx_verifier(_TopUpConfig(), None) is None


async def test_new_top_up_tx_verifier_preserves_payload_only_callback() -> None:
    signature = _kp(19).sign_message(b"legacy-top-up")
    fake_rpc = _FakeRpc()
    verifier = new_top_up_tx_verifier(rpc_client=fake_rpc)
    assert verifier is not None

    await verifier(TopUpPayload(channel_id="ignored", new_deposit="1", signature=str(signature)))

    assert fake_rpc.get_transaction_kwargs == []


async def test_new_top_up_state_tx_verifier_confirms_signature() -> None:
    """A confirmed transaction must prove the configured program, exact channel,
    and amount delta rather than merely carrying a successful signature."""
    signature = _kp(20).sign_message(b"top-up")
    channel = _kp(22).pubkey()
    fake_rpc = _FakeRpc()
    fake_rpc.transactions[str(signature)] = _confirmed_top_up_transaction(channel, 1_000_000)
    verifier = new_top_up_state_tx_verifier(_TopUpConfig(), fake_rpc)
    assert verifier is not None
    payload = TopUpPayload(channel_id=str(channel), new_deposit="2000000", signature=str(signature))
    await verifier(payload, _top_up_state(channel))
    assert fake_rpc.get_transaction_kwargs == [
        {"commitment": "confirmed", "encoding": "jsonParsed", "max_supported_transaction_version": 0}
    ]


async def test_new_top_up_state_tx_verifier_sums_matching_top_ups() -> None:
    """Two +500_000 top-ups fund the claimed +1_000_000 deposit delta."""
    signature = str(_kp(32).sign_message(b"split-top-up"))
    channel = _kp(33).pubkey()
    fake_rpc = _FakeRpc()
    fake_rpc.transactions[signature] = _confirmed_top_up_transaction(channel, 500_000, 500_000)
    verifier = new_top_up_state_tx_verifier(_TopUpConfig(), fake_rpc)
    assert verifier is not None

    await verifier(
        TopUpPayload(channel_id=str(channel), new_deposit="2000000", signature=signature),
        _top_up_state(channel),
    )


async def test_new_top_up_tx_verifier_accepts_newer_state_aware_constructor() -> None:
    signature = _kp(28).sign_message(b"top-up")
    channel = _kp(29).pubkey()
    fake_rpc = _FakeRpc()
    fake_rpc.transactions[str(signature)] = _confirmed_top_up_transaction(channel, 1_000_000)
    verifier = new_top_up_tx_verifier(config=_TopUpConfig(), rpc_client=fake_rpc)
    assert verifier is not None

    await verifier(
        TopUpPayload(channel_id=str(channel), new_deposit="2000000", signature=str(signature)),
        _top_up_state(channel),
    )


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("program", "topUp instruction"),
        ("channel", "channel"),
    ],
)
async def test_new_top_up_state_tx_verifier_rejects_foreign_program_or_channel(mutation: str, message: str) -> None:
    signature = str(_kp(23).sign_message(b"top-up"))
    channel = _kp(24).pubkey()
    fake_rpc = _FakeRpc()
    transaction = _confirmed_top_up_transaction(channel, 1_000_000)
    instruction = transaction["transaction"]["message"]["instructions"][0]
    if mutation == "program":
        instruction["programId"] = str(_kp(30).pubkey())
    else:
        instruction["accounts"][1] = str(_kp(31).pubkey())
    fake_rpc.transactions[signature] = transaction
    verifier = new_top_up_state_tx_verifier(_TopUpConfig(), fake_rpc)
    assert verifier is not None
    payload = TopUpPayload(channel_id=str(channel), new_deposit="2000000", signature=signature)
    with pytest.raises(PaymentError, match=message):
        await verifier(payload, _top_up_state(channel))


async def test_new_top_up_state_tx_verifier_rejects_delta_mismatch() -> None:
    signature = str(_kp(25).sign_message(b"top-up"))
    channel = _kp(26).pubkey()
    fake_rpc = _FakeRpc()
    fake_rpc.transactions[signature] = _confirmed_top_up_transaction(channel, 999_999)
    verifier = new_top_up_state_tx_verifier(_TopUpConfig(), fake_rpc)
    assert verifier is not None
    payload = TopUpPayload(channel_id=str(channel), new_deposit="2000000", signature=signature)
    with pytest.raises(PaymentError, match="amount"):
        await verifier(payload, _top_up_state(channel))


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("malformed", "invalid length"),
        ("overflow", "overflows total"),
    ],
)
async def test_new_top_up_state_tx_verifier_rejects_malformed_or_overflowing_top_ups(
    mutation: str, message: str
) -> None:
    signature = str(_kp(34).sign_message(b"adversarial-top-up"))
    channel = _kp(35).pubkey()
    fake_rpc = _FakeRpc()
    if mutation == "malformed":
        transaction = _confirmed_top_up_transaction(channel, 1_000_000)
        transaction["transaction"]["message"]["instructions"][0]["data"] = _base58_encode(b"\x03")
        new_deposit = "2000000"
        state = _top_up_state(channel)
    else:
        transaction = _confirmed_top_up_transaction(channel, (1 << 64) - 1, 1)
        new_deposit = "1"
        state = _top_up_state(channel, deposit=0)
    fake_rpc.transactions[signature] = transaction
    verifier = new_top_up_state_tx_verifier(_TopUpConfig(), fake_rpc)
    assert verifier is not None

    with pytest.raises(PaymentError, match=message):
        await verifier(TopUpPayload(channel_id=str(channel), new_deposit=new_deposit, signature=signature), state)


async def test_new_top_up_state_tx_verifier_surfaces_failure_and_not_found() -> None:
    """Mirrors TestNewTopUpTxVerifierSurfacesFailureAndNotFound."""
    signature = str(_kp(21).sign_message(b"top-up"))
    fake_rpc = _FakeRpc()
    fake_rpc.statuses[signature] = {"err": "InstructionError"}
    verifier = new_top_up_state_tx_verifier(_TopUpConfig(), fake_rpc)
    assert verifier is not None
    channel = _kp(27).pubkey()
    payload = TopUpPayload(channel_id=str(channel), new_deposit="2000000", signature=signature)
    with pytest.raises(PaymentError, match="top-up"):
        await verifier(payload, _top_up_state(channel))

    fake_rpc.statuses[signature] = None
    with pytest.raises(PaymentError, match="not found"):
        await verifier(payload, _top_up_state(channel))

    with pytest.raises(PaymentError, match="invalid top-up tx signature"):
        await verifier(TopUpPayload(channel_id="", new_deposit="", signature="not-base58!"), _top_up_state(channel))
