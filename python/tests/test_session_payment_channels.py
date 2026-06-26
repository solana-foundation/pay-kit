"""Tests for the challenge-driven payment-channel open layer.

Mirrors the ``#[cfg(test)] mod tests`` in
``rust/crates/mpp/src/client/payment_channels.rs``: challenge-derived defaults
(deposit from cap, grace 900, mint and token program from the currency,
splits), explicit option overrides, invalid challenge values, the partially
signed open transaction (fee payer = operator with an empty signature slot),
and the pull/clientVoucher session openers with the pending-server-signature
placeholder.
"""

from __future__ import annotations

import base64

import pytest
from solders.hash import Hash  # type: ignore[import-untyped]
from solders.keypair import Keypair  # type: ignore[import-untyped]
from solders.pubkey import Pubkey  # type: ignore[import-untyped]
from solders.signature import Signature  # type: ignore[import-untyped]
from solders.transaction import Transaction  # type: ignore[import-untyped]

from pay_kit._paycore.solana import TOKEN_2022_PROGRAM, TOKEN_PROGRAM
from pay_kit.protocols.mpp._paymentchannels import (
    ED25519_PROGRAM_ID,
    PROGRAM_ID,
    Distribution,
    build_ed25519_verify_instruction,
    find_channel_pda,
)
from pay_kit.protocols.mpp.client.payment_channels import (
    DEFAULT_GRACE_PERIOD_SECONDS,
    PENDING_SERVER_SIGNATURE,
    PaymentChannelOpenOptions,
    PaymentChannelSessionOpenOptions,
    ServerOpenedPaymentChannelSessionOpenOptions,
    build_open_payment_channel_transaction,
    create_payment_channel_session_opener,
    create_server_opened_payment_channel_session_opener,
    derive_payment_channel_open,
    generate_authorized_signer,
    unique_salt,
)
from pay_kit.protocols.mpp.intents.session import SessionRequest, SessionSplit

_USDC_MAINNET = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
_PYUSD_MAINNET = "2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo"
_U64_MAX = 2**64 - 1


def _kp(seed: int) -> Keypair:
    return Keypair.from_seed(bytes([seed] * 32))


def _pk(seed: int) -> Pubkey:
    return _kp(seed).pubkey()


def _request(operator: Pubkey, recipient: Pubkey, currency: str = "USDC") -> SessionRequest:
    return SessionRequest(
        cap="1000",
        currency=currency,
        operator=str(operator),
        recipient=str(recipient),
        decimals=6,
        network="localnet",
        modes=["pull"],
        pull_voucher_strategy="clientVoucher",
    )


def _decode_tx(encoded: str) -> Transaction:
    return Transaction.from_bytes(base64.b64decode(encoded, validate=True))


# -- derive_payment_channel_open ---------------------------------------------


def test_derive_uses_challenge_defaults_and_splits() -> None:
    split_recipient = _pk(3)
    request = _request(_pk(1), _pk(2))
    request.splits.append(SessionSplit(recipient=str(split_recipient), bps=10))

    payer = _pk(4)
    authorized_signer = _pk(5)
    open_ = derive_payment_channel_open(
        request,
        payer,
        authorized_signer,
        PaymentChannelOpenOptions(salt=42),
    )

    assert open_.payer == payer
    assert open_.payee == _pk(2)
    assert open_.authorized_signer == authorized_signer
    assert open_.deposit == 1000  # deposit defaults to the cap
    assert open_.grace_period == DEFAULT_GRACE_PERIOD_SECONDS
    assert open_.salt == 42
    assert open_.recipients == [Distribution(recipient=split_recipient, bps=10)]
    # localnet resolves to the mainnet mint (Surfpool clones mainnet state).
    assert str(open_.mint) == _USDC_MAINNET
    assert str(open_.token_program) == TOKEN_PROGRAM
    assert open_.program_id == PROGRAM_ID
    expected_channel, _ = find_channel_pda(payer, _pk(2), open_.mint, authorized_signer, 42, PROGRAM_ID)
    assert open_.channel_id == expected_channel


def test_derive_resolves_token_2022_from_currency() -> None:
    open_ = derive_payment_channel_open(
        _request(_pk(1), _pk(2), currency="PYUSD"),
        _pk(4),
        _pk(5),
        PaymentChannelOpenOptions(salt=7),
    )
    assert str(open_.mint) == _PYUSD_MAINNET
    assert str(open_.token_program) == TOKEN_2022_PROGRAM


def test_derive_honors_explicit_options() -> None:
    program_id = _pk(9)
    split_recipient = _pk(3)
    token_program = Pubkey.from_string(TOKEN_2022_PROGRAM)
    request = _request(_pk(1), _pk(2))
    request.cap = "not-a-number"
    request.splits.append(SessionSplit(recipient="not-a-pubkey", bps=999))

    open_ = derive_payment_channel_open(
        request,
        _pk(4),
        _pk(5),
        PaymentChannelOpenOptions(
            deposit=55,
            grace_period=12,
            program_id=program_id,
            recipients=[Distribution(recipient=split_recipient, bps=25)],
            salt=7,
            token_program=token_program,
        ),
    )

    assert open_.deposit == 55
    assert open_.grace_period == 12
    assert open_.program_id == program_id
    assert open_.token_program == token_program
    assert open_.recipients == [Distribution(recipient=split_recipient, bps=25)]
    assert open_.open_channel_params().program_id == program_id


def test_derive_rejects_invalid_challenge_values() -> None:
    payer, signer = _pk(4), _pk(5)

    request = _request(_pk(1), _pk(2))
    request.currency = "SOL"
    with pytest.raises(ValueError, match="SPL token"):
        derive_payment_channel_open(request, payer, signer)

    request = _request(_pk(1), _pk(2))
    request.cap = "not-a-number"
    with pytest.raises(ValueError, match="session cap"):
        derive_payment_channel_open(request, payer, signer)

    request = _request(_pk(1), _pk(2))
    request.recipient = "not-a-pubkey"
    with pytest.raises(ValueError, match="recipient"):
        derive_payment_channel_open(request, payer, signer)

    request = _request(_pk(1), _pk(2))
    request.program_id = "not-a-program"
    with pytest.raises(ValueError, match="programId"):
        derive_payment_channel_open(request, payer, signer)

    request = _request(_pk(1), _pk(2))
    request.splits.append(SessionSplit(recipient="not-a-pubkey", bps=10))
    with pytest.raises(ValueError, match="split recipient"):
        derive_payment_channel_open(request, payer, signer)


# -- build_open_payment_channel_transaction -----------------------------------


def test_build_open_transaction_partially_signs_for_operator_broadcast() -> None:
    operator = _pk(1)
    request = _request(operator, _pk(2))
    payer_signer = _kp(7)
    authorized_signer = _pk(8)

    built = build_open_payment_channel_transaction(
        request,
        payer_signer,
        authorized_signer,
        Hash.default(),
        options=PaymentChannelOpenOptions(salt=99),
    )
    expected = derive_payment_channel_open(
        request,
        payer_signer.pubkey(),
        authorized_signer,
        PaymentChannelOpenOptions(salt=99),
    )
    assert built.channel_id == expected.channel_id

    tx = _decode_tx(built.transaction)
    account_keys = list(tx.message.account_keys)
    assert account_keys[0] == operator  # fee payer = challenge operator
    assert len(tx.message.instructions) == 1
    # The operator slot is left unsigned; the payer slot carries a real
    # signature over the message bytes.
    payer_index = account_keys.index(payer_signer.pubkey())
    assert tx.signatures[0] == Signature.default()
    assert tx.signatures[payer_index] != Signature.default()
    assert tx.signatures[payer_index].verify(payer_signer.pubkey(), bytes(tx.message))


def test_build_open_transaction_accepts_duck_typed_signer() -> None:
    class _BytesSigner:
        def __init__(self, kp: Keypair) -> None:
            self._kp = kp

        def pubkey(self) -> str:
            return str(self._kp.pubkey())

        def sign(self, message: bytes) -> bytes:
            return bytes(self._kp.sign_message(message))

    kp = _kp(11)
    built = build_open_payment_channel_transaction(
        _request(_pk(1), _pk(2)),
        _BytesSigner(kp),
        _pk(8),
        Hash.default(),
        options=PaymentChannelOpenOptions(salt=99),
    )
    tx = _decode_tx(built.transaction)
    payer_index = list(tx.message.account_keys).index(kp.pubkey())
    assert tx.signatures[payer_index].verify(kp.pubkey(), bytes(tx.message))


def test_build_open_transaction_accepts_explicit_operator_fee_payer() -> None:
    operator = _pk(1)
    built = build_open_payment_channel_transaction(
        _request(operator, _pk(2)),
        _kp(15),
        _pk(16),
        Hash.default(),
        fee_payer=operator,
        options=PaymentChannelOpenOptions(salt=123),
    )
    tx = _decode_tx(built.transaction)
    assert list(tx.message.account_keys)[0] == operator


def test_build_open_transaction_rejects_non_operator_fee_payer() -> None:
    operator = _pk(1)
    non_operator_fee_payer = _pk(6)
    with pytest.raises(ValueError, match="fee_payer must equal the challenge operator"):
        build_open_payment_channel_transaction(
            _request(operator, _pk(2)),
            _kp(15),
            _pk(16),
            Hash.default(),
            fee_payer=non_operator_fee_payer,
            options=PaymentChannelOpenOptions(salt=123),
        )


# -- session openers -----------------------------------------------------------


def test_opener_builds_pull_client_voucher_action() -> None:
    request = _request(_pk(1), _pk(2))
    payer_signer = _kp(9)
    session_signer = _kp(10)

    opened = create_payment_channel_session_opener(
        request,
        payer_signer,
        session_signer,
        Hash.default(),
        PaymentChannelSessionOpenOptions(open=PaymentChannelOpenOptions(salt=11)),
    )

    assert opened.session.channel_id == opened.open.channel_id
    payload = opened.action.open
    assert payload is not None
    assert payload.mode == "pull"
    assert payload.channel_id == str(opened.open.channel_id)
    assert payload.payer == str(payer_signer.pubkey())
    assert payload.authorized_signer == str(session_signer.pubkey())
    assert payload.signature == PENDING_SERVER_SIGNATURE
    assert payload.transaction is not None
    assert payload.token_account is None
    assert payload.approved_amount is None
    assert payload.init_multi_delegate_tx is None
    assert payload.update_delegation_tx is None


def test_opener_applies_session_options() -> None:
    opened = create_payment_channel_session_opener(
        _request(_pk(1), _pk(2)),
        _kp(17),
        _kp(18),
        Hash.default(),
        PaymentChannelSessionOpenOptions(
            open=PaymentChannelOpenOptions(salt=19),
            signature="operator-will-fill",
            cumulative=20,
            expires_at=1234,
        ),
    )
    payload = opened.action.open
    assert payload is not None
    assert payload.signature == "operator-will-fill"
    voucher = opened.session.prepare_increment(5)
    assert voucher.data.cumulative == "25"
    assert voucher.data.expires_at == 1234


def test_server_opened_opener_uses_operator_payer_without_transaction() -> None:
    operator = _pk(1)
    request = _request(operator, _pk(2))
    session_signer = _kp(12)

    opened = create_server_opened_payment_channel_session_opener(
        request,
        session_signer,
        ServerOpenedPaymentChannelSessionOpenOptions(open=PaymentChannelOpenOptions(salt=13)),
    )

    assert opened.open.payer == operator
    payload = opened.action.open
    assert payload is not None
    assert payload.mode == "pull"
    assert payload.payer == str(operator)
    assert payload.authorized_signer == str(session_signer.pubkey())
    assert payload.signature == PENDING_SERVER_SIGNATURE
    assert payload.transaction is None
    assert payload.token_account is None
    assert payload.approved_amount is None


def test_opener_rejects_non_pull_challenge() -> None:
    request = _request(_pk(1), _pk(2))
    request.modes = ["push"]
    request.pull_voucher_strategy = None
    with pytest.raises(ValueError, match="pull mode"):
        create_server_opened_payment_channel_session_opener(request, _kp(20))


def test_opener_rejects_operated_voucher_pull_challenge() -> None:
    request = _request(_pk(1), _pk(2))
    request.pull_voucher_strategy = "operatedVoucher"
    with pytest.raises(ValueError, match="pull \\+ clientVoucher"):
        create_server_opened_payment_channel_session_opener(request, _kp(14))


# -- helpers -------------------------------------------------------------------


def test_unique_salt_is_a_u64() -> None:
    salts = {unique_salt() for _ in range(8)}
    assert all(0 <= salt <= _U64_MAX for salt in salts)
    assert len(salts) > 1  # eight CSPRNG draws collide with negligible odds


def test_generate_authorized_signer_returns_usable_session_keypair() -> None:
    signer = generate_authorized_signer()
    assert isinstance(signer, Keypair)
    opened = create_server_opened_payment_channel_session_opener(
        _request(_pk(1), _pk(2)),
        signer,
        ServerOpenedPaymentChannelSessionOpenOptions(open=PaymentChannelOpenOptions(salt=21)),
    )
    assert opened.session.authorized_signer == str(signer.pubkey())
    voucher = opened.session.sign_increment(5)
    sig = Signature.from_string(voucher.signature)
    assert sig.verify(signer.pubkey(), voucher.data.message_bytes())


# -- build_ed25519_verify_instruction (settle precompile) ---------------------


def test_ed25519_verify_instruction_golden_layout() -> None:
    """The Ed25519 precompile data layout must match the Rust/Go builders:
    one signature, all three offsets pointing into this instruction's own data
    (pubkey@16, signature@48, message@112), 0xffff = current-instruction."""
    import struct

    signer = _pk(7)
    signature = bytes(range(64))
    message = bytes([0xAB] * 48)  # voucher preimage is 48 bytes

    ix = build_ed25519_verify_instruction(signer, signature, message)

    assert str(ix.program_id) == ED25519_PROGRAM_ID
    assert ix.accounts == []
    data = bytes(ix.data)
    assert len(data) == 112 + len(message)
    assert data[0] == 1  # num_signatures
    assert data[1] == 0  # padding
    # offset header: sig=48, 0xffff, pubkey=16, 0xffff, msg=112, msg_len, 0xffff
    assert struct.unpack_from("<7H", data, 2) == (48, 0xFFFF, 16, 0xFFFF, 112, len(message), 0xFFFF)
    assert data[16:48] == bytes(signer)
    assert data[48:112] == signature
    assert data[112:] == message


def test_ed25519_verify_instruction_rejects_bad_signature_length() -> None:
    with pytest.raises(ValueError, match="64 bytes"):
        build_ed25519_verify_instruction(_pk(1), b"\x00" * 63, b"msg")
