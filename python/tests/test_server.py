"""Tests for server/mpp module."""

from __future__ import annotations

import pytest
from solders.hash import Hash
from solders.instruction import AccountMeta, Instruction
from solders.keypair import Keypair
from solders.message import Message, MessageV0, to_bytes_versioned
from solders.pubkey import Pubkey
from solders.signature import Signature
from solders.system_program import TransferParams, transfer
from solders.transaction import Transaction

from solana_mpp._errors import ChallengeExpiredError, ChallengeMismatchError, PaymentError, ReplayError
from solana_mpp._types import ChallengeEcho, PaymentCredential
from solana_mpp.protocol.intents import ChargeRequest
from solana_mpp.protocol.solana import ASSOCIATED_TOKEN_PROGRAM, MEMO_PROGRAM, TOKEN_2022_PROGRAM, MethodDetails, Split
from solana_mpp.server.mpp import (
    ChargeOptions,
    Config,
    Mpp,
    _build_expected_transfers,
    _json_like,
    _parsed_ata_creation_matches,
    _parsed_info_string,
    _parsed_program_id,
    _rpc_value,
    _status_ok,
    _transaction_dict,
    _verify_ata_owner,
    _verify_local_transaction_intent,
    _verify_parsed_memo_instructions,
    _verify_parsed_sol_transfers,
    _verify_parsed_spl_transfers,
)

TEST_SECRET = "test-secret-key-that-is-long-enough-for-hmac-sha256"
TEST_RECIPIENT = "11111111111111111111111111111112"
VALID_SIGNATURE = "1111111111111111111111111111111111111111111111111111111111111111"
TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
USDC_DEVNET = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"
ATA_PROGRAM = Pubkey.from_string("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")
TEST_BLOCKHASH = "4vJ9JU1bJJQpUgJ8V6hYz7xXKz4F2tN6aBrZEcD3xKhs"
SYSTEM_PROGRAM = "11111111111111111111111111111111"


def _derive_ata(owner: str, mint: str, token_program: str = TOKEN_PROGRAM) -> str:
    """Derive ATA address for test helpers."""
    owner_pk = Pubkey.from_string(owner)
    mint_pk = Pubkey.from_string(mint)
    tp_pk = Pubkey.from_string(token_program)
    ata, _ = Pubkey.find_program_address([bytes(owner_pk), bytes(tp_pk), bytes(mint_pk)], ATA_PROGRAM)
    return str(ata)


def _build_sol_transaction(recipient: str, lamports: int, memo: str = "") -> str:
    signer = Keypair()
    instructions = [
        transfer(
            TransferParams(
                from_pubkey=signer.pubkey(),
                to_pubkey=Pubkey.from_string(recipient),
                lamports=lamports,
            )
        )
    ]
    if memo:
        instructions.append(Instruction(Pubkey.from_string(MEMO_PROGRAM), memo.encode("utf-8"), []))

    blockhash = Hash.from_string(TEST_BLOCKHASH)
    message = Message.new_with_blockhash(instructions, signer.pubkey(), blockhash)
    transaction = Transaction.new_unsigned(message)
    transaction.sign([signer], blockhash)

    import base64

    return base64.b64encode(bytes(transaction)).decode("ascii")


def _build_versioned_sol_transaction(recipient: str, lamports: int, memo: str = "") -> str:
    signer = Keypair()
    instructions = [
        transfer(
            TransferParams(
                from_pubkey=signer.pubkey(),
                to_pubkey=Pubkey.from_string(recipient),
                lamports=lamports,
            )
        )
    ]
    if memo:
        instructions.append(Instruction(Pubkey.from_string(MEMO_PROGRAM), memo.encode("utf-8"), []))

    blockhash = Hash.from_string(TEST_BLOCKHASH)
    message = MessageV0.try_compile(signer.pubkey(), instructions, [], blockhash)
    signature = signer.sign_message(to_bytes_versioned(message))

    from solders.transaction import VersionedTransaction

    transaction = VersionedTransaction.populate(message, [Signature.from_bytes(bytes(signature))])

    import base64

    return base64.b64encode(bytes(transaction)).decode("ascii")


def _build_spl_transfer_checked_transaction(
    recipient: str,
    mint: str,
    amount: int,
    memo: str = "",
    token_program: str = TOKEN_PROGRAM,
    decimals: int = 6,
) -> str:
    signer = Keypair()
    source = Pubkey.new_unique()
    destination = Pubkey.from_string(_derive_ata(recipient, mint, token_program))
    mint_key = Pubkey.from_string(mint)
    data = bytes([12]) + amount.to_bytes(8, "little") + bytes([decimals])
    instructions = [
        Instruction(
            Pubkey.from_string(token_program),
            data,
            [
                AccountMeta(source, False, True),
                AccountMeta(mint_key, False, False),
                AccountMeta(destination, False, True),
                AccountMeta(signer.pubkey(), True, False),
            ],
        )
    ]
    if memo:
        instructions.append(Instruction(Pubkey.from_string(MEMO_PROGRAM), memo.encode("utf-8"), []))

    blockhash = Hash.from_string(TEST_BLOCKHASH)
    message = Message.new_with_blockhash(instructions, signer.pubkey(), blockhash)
    transaction = Transaction.new_unsigned(message)
    transaction.sign([signer], blockhash)

    import base64

    return base64.b64encode(bytes(transaction)).decode("ascii")


def _build_spl_split_transaction(
    recipient: str,
    split_recipient: str,
    mint: str,
    primary_amount: int,
    split_amount: int,
    create_split_ata: bool,
    token_program: str = TOKEN_PROGRAM,
    decimals: int = 6,
) -> str:
    signer = Keypair()
    mint_key = Pubkey.from_string(mint)
    recipient_ata = Pubkey.from_string(_derive_ata(recipient, mint, token_program))
    split_ata = Pubkey.from_string(_derive_ata(split_recipient, mint, token_program))
    instructions = []
    if create_split_ata:
        instructions.append(
            Instruction(
                Pubkey.from_string(ASSOCIATED_TOKEN_PROGRAM),
                bytes([1]),
                [
                    AccountMeta(signer.pubkey(), True, True),
                    AccountMeta(split_ata, False, True),
                    AccountMeta(Pubkey.from_string(split_recipient), False, False),
                    AccountMeta(mint_key, False, False),
                    AccountMeta(Pubkey.from_string(SYSTEM_PROGRAM), False, False),
                    AccountMeta(Pubkey.from_string(token_program), False, False),
                ],
            )
        )
    for destination, amount in ((recipient_ata, primary_amount), (split_ata, split_amount)):
        instructions.append(
            Instruction(
                Pubkey.from_string(token_program),
                bytes([12]) + amount.to_bytes(8, "little") + bytes([decimals]),
                [
                    AccountMeta(Pubkey.new_unique(), False, True),
                    AccountMeta(mint_key, False, False),
                    AccountMeta(destination, False, True),
                    AccountMeta(signer.pubkey(), True, False),
                ],
            )
        )

    blockhash = Hash.from_string(TEST_BLOCKHASH)
    message = Message.new_with_blockhash(instructions, signer.pubkey(), blockhash)
    transaction = Transaction.new_unsigned(message)
    transaction.sign([signer], blockhash)

    import base64

    return base64.b64encode(bytes(transaction)).decode("ascii")


class FakeResponse:
    def __init__(self, value):
        self.value = value


class FakeRPC:
    def __init__(self, tx=None, send_value="sig-123", statuses=None, token_accounts=None):
        self.tx = tx
        self.send_value = send_value
        self.statuses = statuses if statuses is not None else [{"err": None}]
        self.token_accounts = token_accounts or {}
        self.sent = []

    async def get_transaction(self, *_args, **_kwargs):
        return FakeResponse(self.tx)

    async def send_raw_transaction(self, raw: bytes):
        self.sent.append(raw)
        return FakeResponse(self.send_value)

    async def confirm_transaction(self, *_args, **_kwargs):
        return FakeResponse(self.statuses)


@pytest.fixture
def mpp() -> Mpp:
    rpc = FakeRPC(
        tx={
            "meta": {"err": None},
            "transaction": {
                "message": {
                    "instructions": [
                        {
                            "programId": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
                            "parsed": {
                                "type": "transferChecked",
                                "info": {
                                    "destination": _derive_ata(TEST_RECIPIENT, USDC_DEVNET),
                                    "mint": USDC_DEVNET,
                                    "tokenAmount": {"amount": "1000000"},
                                },
                            },
                        }
                    ]
                }
            },
        },
        token_accounts={_derive_ata(TEST_RECIPIENT, USDC_DEVNET): {"owner": TEST_RECIPIENT, "mint": USDC_DEVNET}},
    )
    config = Config(
        recipient=TEST_RECIPIENT,
        currency="USDC",
        decimals=6,
        network="devnet",
        secret_key=TEST_SECRET,
        rpc=rpc,
    )
    return Mpp(config)


class TestConfig:
    def test_missing_recipient_raises(self):
        with pytest.raises(PaymentError, match="recipient"):
            Mpp(Config(recipient="", secret_key=TEST_SECRET))

    def test_missing_secret_key_raises(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.delenv("MPP_SECRET_KEY", raising=False)
        with pytest.raises(PaymentError, match="secret key"):
            Mpp(Config(recipient=TEST_RECIPIENT, secret_key=""))

    def test_defaults(self, mpp: Mpp):
        assert mpp.realm == "MPP Payment"
        assert "devnet" in mpp.rpc_url


class TestCharge:
    def test_charge_creates_challenge(self, mpp: Mpp):
        challenge = mpp.charge("1.00")
        assert challenge.id != ""
        assert challenge.method == "solana"
        assert challenge.intent == "charge"
        assert challenge.verify(TEST_SECRET)

    def test_charge_with_options(self, mpp: Mpp):
        options = ChargeOptions(
            description="Test payment",
            external_id="ext-1",
            expires="2099-01-01T00:00:00Z",
        )
        challenge = mpp.charge_with_options("0.50", options)
        assert challenge.description == "Test payment"
        assert challenge.expires == "2099-01-01T00:00:00Z"

    def test_charge_converts_units(self, mpp: Mpp):
        challenge = mpp.charge("1.50")
        request = challenge.decode_request()
        assert request["amount"] == "1500000"

    def test_charge_includes_recipient(self, mpp: Mpp):
        challenge = mpp.charge("1.00")
        request = challenge.decode_request()
        assert request["recipient"] == TEST_RECIPIENT
        assert request["currency"] == "USDC"

    def test_charge_with_splits(self, mpp: Mpp):
        options = ChargeOptions(
            splits=[
                {
                    "recipient": "VendorPayoutsWaLLetxxxxxxxxxxxxxxxxxxxxxx1111",
                    "amount": "500000",
                    "memo": "Vendor payout",
                },
                {"recipient": "ProcessorFeeWaLLetxxxxxxxxxxxxxxxxxxxxxxx1111", "amount": "29000"},
            ],
        )
        challenge = mpp.charge_with_options("1.00", options)
        request = challenge.decode_request()
        md = request["methodDetails"]
        assert "splits" in md
        assert len(md["splits"]) == 2
        assert md["splits"][0]["amount"] == "500000"
        assert md["splits"][0]["memo"] == "Vendor payout"

    def test_charge_without_splits_omitted(self, mpp: Mpp):
        challenge = mpp.charge("1.00")
        request = challenge.decode_request()
        md = request["methodDetails"]
        assert "splits" not in md

    @pytest.mark.parametrize(
        ("currency", "expected_program"),
        [
            ("USDC", TOKEN_PROGRAM),
            ("USDT", TOKEN_PROGRAM),
            ("PYUSD", TOKEN_2022_PROGRAM),
            ("USDG", TOKEN_2022_PROGRAM),
            ("CASH", TOKEN_2022_PROGRAM),
        ],
    )
    def test_charge_includes_known_stablecoin_token_program(self, currency: str, expected_program: str):
        handler = Mpp(
            Config(
                recipient=TEST_RECIPIENT,
                currency=currency,
                decimals=6,
                network="mainnet-beta",
                secret_key=TEST_SECRET,
                rpc=FakeRPC(),
            )
        )
        challenge = handler.charge("1.00")
        request = challenge.decode_request()
        assert request["methodDetails"]["tokenProgram"] == expected_program

    def test_charge_rejects_split_ata_creation_for_native_sol(self):
        handler = Mpp(Config(recipient=TEST_RECIPIENT, currency="SOL", decimals=9, secret_key=TEST_SECRET))

        with pytest.raises(PaymentError, match="SPL token currency"):
            handler.charge_with_options(
                "1.00",
                ChargeOptions(
                    splits=[
                        {
                            "recipient": str(Pubkey.new_unique()),
                            "amount": "50000",
                            "ataCreationRequired": True,
                        }
                    ]
                ),
            )

    def test_charge_rejects_split_ata_creation_for_stablecoin_symbol(self, mpp: Mpp):
        with pytest.raises(PaymentError, match="mint address"):
            mpp.charge_with_options(
                "1.00",
                ChargeOptions(
                    splits=[
                        {
                            "recipient": str(Pubkey.new_unique()),
                            "amount": "50000",
                            "ataCreationRequired": True,
                        }
                    ]
                ),
            )

    def test_charge_accepts_split_ata_creation_for_raw_mint(self):
        handler = Mpp(
            Config(
                recipient=TEST_RECIPIENT,
                currency=USDC_DEVNET,
                decimals=6,
                network="devnet",
                secret_key=TEST_SECRET,
                rpc=FakeRPC(),
            )
        )
        split = {"recipient": str(Pubkey.new_unique()), "amount": "50000", "ataCreationRequired": True}

        challenge = handler.charge_with_options("1.00", ChargeOptions(splits=[split]))
        request = challenge.decode_request()

        assert request["currency"] == USDC_DEVNET
        assert request["methodDetails"]["splits"] == [split]


class TestLocalTransactionIntent:
    def test_accepts_versioned_sol_transfer(self):
        request = ChargeRequest(amount="1000", currency="SOL", recipient=TEST_RECIPIENT)
        details = MethodDetails(network="mainnet-beta")
        transaction = _build_versioned_sol_transaction(TEST_RECIPIENT, 1000)

        _verify_local_transaction_intent(transaction, request, details)

    def test_rejects_missing_required_split_ata_creation(self):
        split_recipient = str(Pubkey.new_unique())
        request = ChargeRequest(amount="1000000", currency=USDC_DEVNET, recipient=TEST_RECIPIENT)
        details = MethodDetails(
            network="devnet",
            token_program=TOKEN_PROGRAM,
            splits=[Split(recipient=split_recipient, amount="50000", ata_creation_required=True)],
        )
        transaction = _build_spl_split_transaction(
            TEST_RECIPIENT,
            split_recipient,
            USDC_DEVNET,
            950000,
            50000,
            create_split_ata=False,
        )

        with pytest.raises(PaymentError, match="Missing required ATA creation"):
            _verify_local_transaction_intent(transaction, request, details)

    def test_accepts_required_split_ata_creation(self):
        split_recipient = str(Pubkey.new_unique())
        request = ChargeRequest(amount="1000000", currency=USDC_DEVNET, recipient=TEST_RECIPIENT)
        details = MethodDetails(
            network="devnet",
            token_program=TOKEN_PROGRAM,
            splits=[Split(recipient=split_recipient, amount="50000", ata_creation_required=True)],
        )
        transaction = _build_spl_split_transaction(
            TEST_RECIPIENT,
            split_recipient,
            USDC_DEVNET,
            950000,
            50000,
            create_split_ata=True,
        )

        _verify_local_transaction_intent(transaction, request, details)


class TestVerifyCredential:
    async def test_challenge_mismatch(self, mpp: Mpp):
        echo = ChallengeEcho(id="bad-id", realm="r", method="solana", intent="charge", request="e30")
        credential = PaymentCredential(
            challenge=echo,
            payload={"type": "transaction", "transaction": "abc"},
        )
        with pytest.raises(ChallengeMismatchError):
            await mpp.verify_credential(credential)

    async def test_challenge_expired(self, mpp: Mpp):
        challenge = mpp.charge_with_options("1.00", ChargeOptions(expires="2020-01-01T00:00:00Z"))
        echo = challenge.to_echo()
        credential = PaymentCredential(
            challenge=echo,
            payload={"type": "transaction", "transaction": "abc"},
        )
        with pytest.raises(ChallengeExpiredError):
            await mpp.verify_credential(credential)

    async def test_invalid_payload_type(self, mpp: Mpp):
        challenge = mpp.charge("1.00")
        echo = challenge.to_echo()
        credential = PaymentCredential(
            challenge=echo,
            payload={"type": "unknown"},
        )
        with pytest.raises(PaymentError, match="invalid payload type"):
            await mpp.verify_credential(credential)

    async def test_replay_protection(self, mpp: Mpp):
        challenge = mpp.charge("1.00")
        echo = challenge.to_echo()
        credential = PaymentCredential(
            challenge=echo,
            payload={"type": "signature", "signature": VALID_SIGNATURE},
        )
        # First call succeeds
        receipt = await mpp.verify_credential(credential)
        assert receipt.is_success()

        # Second call with same signature fails
        with pytest.raises(ReplayError):
            await mpp.verify_credential(credential)

    async def test_missing_transaction(self, mpp: Mpp):
        challenge = mpp.charge("1.00")
        echo = challenge.to_echo()
        credential = PaymentCredential(
            challenge=echo,
            payload={"type": "transaction", "transaction": ""},
        )
        with pytest.raises(PaymentError, match="missing transaction"):
            await mpp.verify_credential(credential)

    async def test_missing_signature(self, mpp: Mpp):
        challenge = mpp.charge("1.00")
        echo = challenge.to_echo()
        credential = PaymentCredential(
            challenge=echo,
            payload={"type": "signature", "signature": ""},
        )
        with pytest.raises(PaymentError, match="missing signature"):
            await mpp.verify_credential(credential)

    async def test_signature_fee_payer_rejected(self, mpp: Mpp):
        options = ChargeOptions(fee_payer=True)
        challenge = mpp.charge_with_options("1.00", options)
        echo = challenge.to_echo()
        credential = PaymentCredential(
            challenge=echo,
            payload={"type": "signature", "signature": "sig456"},
        )
        with pytest.raises(PaymentError, match="fee sponsorship"):
            await mpp.verify_credential(credential)

    async def test_signature_verification_fetches_and_checks_transaction(self):
        recipient_ata = _derive_ata(TEST_RECIPIENT, USDC_DEVNET)
        tx = {
            "meta": {"err": None},
            "transaction": {
                "message": {
                    "instructions": [
                        {
                            "programId": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
                            "parsed": {
                                "type": "transferChecked",
                                "info": {
                                    "destination": recipient_ata,
                                    "mint": USDC_DEVNET,
                                    "tokenAmount": {"amount": "1000000"},
                                },
                            },
                        }
                    ]
                }
            },
        }
        rpc = FakeRPC(tx=tx, token_accounts={recipient_ata: {"owner": TEST_RECIPIENT, "mint": USDC_DEVNET}})
        mpp = Mpp(
            Config(
                recipient=TEST_RECIPIENT,
                currency="USDC",
                decimals=6,
                network="devnet",
                secret_key=TEST_SECRET,
                rpc=rpc,
            )
        )
        challenge = mpp.charge("1.00")
        credential = PaymentCredential(
            challenge=challenge.to_echo(),
            payload={"type": "signature", "signature": VALID_SIGNATURE},
        )

        receipt = await mpp.verify_credential(credential)
        assert receipt.is_success()
        assert receipt.reference == credential.payload["signature"]

    async def test_signature_verification_checks_external_id_memo(self):
        tx = {
            "meta": {"err": None},
            "transaction": {
                "message": {
                    "instructions": [
                        {
                            "program": "system",
                            "parsed": {"type": "transfer", "info": {"destination": TEST_RECIPIENT, "lamports": "1000"}},
                        },
                        {"program": "spl-memo", "parsed": "order-123"},
                    ]
                }
            },
        }
        rpc = FakeRPC(tx=tx)
        mpp = Mpp(
            Config(
                recipient=TEST_RECIPIENT,
                currency="SOL",
                decimals=9,
                network="devnet",
                secret_key=TEST_SECRET,
                rpc=rpc,
            )
        )
        challenge = mpp.charge_with_options("0.000001", ChargeOptions(external_id="order-123"))
        credential = PaymentCredential(
            challenge=challenge.to_echo(),
            payload={"type": "signature", "signature": VALID_SIGNATURE},
        )

        receipt = await mpp.verify_credential(credential)
        assert receipt.is_success()
        assert receipt.external_id == "order-123"

    async def test_transaction_verification_broadcasts_and_checks_transaction(self):
        tx = {
            "meta": {"err": None},
            "transaction": {
                "message": {
                    "instructions": [
                        {
                            "program": "system",
                            "parsed": {"type": "transfer", "info": {"destination": TEST_RECIPIENT, "lamports": "1000"}},
                        }
                    ]
                }
            },
        }
        rpc = FakeRPC(tx=tx, send_value="1111111111111111111111111111111111111111111111111111111111111111")
        mpp = Mpp(
            Config(
                recipient=TEST_RECIPIENT,
                currency="SOL",
                decimals=9,
                network="mainnet-beta",
                secret_key=TEST_SECRET,
                rpc=rpc,
            )
        )
        challenge = mpp.charge_with_options("0.000001", ChargeOptions())
        credential = PaymentCredential(
            challenge=challenge.to_echo(),
            payload={
                "type": "transaction",
                "transaction": _build_sol_transaction(TEST_RECIPIENT, 1000),
            },
        )

        receipt = await mpp.verify_credential(credential)
        assert receipt.is_success()
        assert receipt.reference == "1111111111111111111111111111111111111111111111111111111111111111"
        assert rpc.sent

    async def test_transaction_verification_rejects_wrong_recipient_before_broadcast(self):
        tx = {"meta": {"err": None}, "transaction": {"message": {"instructions": []}}}
        rpc = FakeRPC(tx=tx, send_value="1111111111111111111111111111111111111111111111111111111111111111")
        mpp = Mpp(
            Config(
                recipient=TEST_RECIPIENT,
                currency="SOL",
                decimals=9,
                network="mainnet-beta",
                secret_key=TEST_SECRET,
                rpc=rpc,
            )
        )
        challenge = mpp.charge_with_options("0.000001", ChargeOptions())
        credential = PaymentCredential(
            challenge=challenge.to_echo(),
            payload={
                "type": "transaction",
                "transaction": _build_sol_transaction(str(Pubkey.new_unique()), 1000),
            },
        )

        with pytest.raises(PaymentError, match="no matching SOL transfer"):
            await mpp.verify_credential(credential)
        assert rpc.sent == []

    async def test_transaction_verification_rejects_wrong_amount_before_broadcast(self):
        tx = {"meta": {"err": None}, "transaction": {"message": {"instructions": []}}}
        rpc = FakeRPC(tx=tx, send_value="1111111111111111111111111111111111111111111111111111111111111111")
        mpp = Mpp(
            Config(
                recipient=TEST_RECIPIENT,
                currency="SOL",
                decimals=9,
                network="mainnet-beta",
                secret_key=TEST_SECRET,
                rpc=rpc,
            )
        )
        challenge = mpp.charge_with_options("0.000001", ChargeOptions())
        credential = PaymentCredential(
            challenge=challenge.to_echo(),
            payload={
                "type": "transaction",
                "transaction": _build_sol_transaction(TEST_RECIPIENT, 999),
            },
        )

        with pytest.raises(PaymentError, match="no matching SOL transfer"):
            await mpp.verify_credential(credential)
        assert rpc.sent == []

    async def test_transaction_verification_rejects_missing_memo_before_broadcast(self):
        tx = {"meta": {"err": None}, "transaction": {"message": {"instructions": []}}}
        rpc = FakeRPC(tx=tx, send_value="1111111111111111111111111111111111111111111111111111111111111111")
        mpp = Mpp(
            Config(
                recipient=TEST_RECIPIENT,
                currency="SOL",
                decimals=9,
                network="mainnet-beta",
                secret_key=TEST_SECRET,
                rpc=rpc,
            )
        )
        challenge = mpp.charge_with_options("0.000001", ChargeOptions(external_id="order-123"))
        credential = PaymentCredential(
            challenge=challenge.to_echo(),
            payload={
                "type": "transaction",
                "transaction": _build_sol_transaction(TEST_RECIPIENT, 1000),
            },
        )

        with pytest.raises(PaymentError, match="No memo instruction found"):
            await mpp.verify_credential(credential)
        assert rpc.sent == []

    async def test_token_transaction_verification_broadcasts_matching_transaction(self):
        recipient_ata = _derive_ata(TEST_RECIPIENT, USDC_DEVNET)
        tx = {
            "meta": {"err": None},
            "transaction": {
                "message": {
                    "instructions": [
                        {
                            "programId": TOKEN_PROGRAM,
                            "parsed": {
                                "type": "transferChecked",
                                "info": {
                                    "destination": recipient_ata,
                                    "mint": USDC_DEVNET,
                                    "tokenAmount": {"amount": "1000000"},
                                },
                            },
                        }
                    ]
                }
            },
        }
        rpc = FakeRPC(tx=tx, send_value="1111111111111111111111111111111111111111111111111111111111111111")
        mpp = Mpp(
            Config(
                recipient=TEST_RECIPIENT,
                currency="USDC",
                decimals=6,
                network="devnet",
                secret_key=TEST_SECRET,
                rpc=rpc,
            )
        )
        challenge = mpp.charge_with_options("1.00", ChargeOptions())
        credential = PaymentCredential(
            challenge=challenge.to_echo(),
            payload={
                "type": "transaction",
                "transaction": _build_spl_transfer_checked_transaction(TEST_RECIPIENT, USDC_DEVNET, 1000000),
            },
        )

        receipt = await mpp.verify_credential(credential)
        assert receipt.is_success()
        assert rpc.sent

    async def test_token_transaction_verification_rejects_wrong_recipient_before_broadcast(self):
        tx = {"meta": {"err": None}, "transaction": {"message": {"instructions": []}}}
        rpc = FakeRPC(tx=tx, send_value="1111111111111111111111111111111111111111111111111111111111111111")
        mpp = Mpp(
            Config(
                recipient=TEST_RECIPIENT,
                currency="USDC",
                decimals=6,
                network="devnet",
                secret_key=TEST_SECRET,
                rpc=rpc,
            )
        )
        challenge = mpp.charge_with_options("1.00", ChargeOptions())
        credential = PaymentCredential(
            challenge=challenge.to_echo(),
            payload={
                "type": "transaction",
                "transaction": _build_spl_transfer_checked_transaction(str(Pubkey.new_unique()), USDC_DEVNET, 1000000),
            },
        )

        with pytest.raises(PaymentError, match="no matching token transfer"):
            await mpp.verify_credential(credential)
        assert rpc.sent == []

    async def test_token_transaction_verification_rejects_wrong_amount_before_broadcast(self):
        tx = {"meta": {"err": None}, "transaction": {"message": {"instructions": []}}}
        rpc = FakeRPC(tx=tx, send_value="1111111111111111111111111111111111111111111111111111111111111111")
        mpp = Mpp(
            Config(
                recipient=TEST_RECIPIENT,
                currency="USDC",
                decimals=6,
                network="devnet",
                secret_key=TEST_SECRET,
                rpc=rpc,
            )
        )
        challenge = mpp.charge_with_options("1.00", ChargeOptions())
        credential = PaymentCredential(
            challenge=challenge.to_echo(),
            payload={
                "type": "transaction",
                "transaction": _build_spl_transfer_checked_transaction(TEST_RECIPIENT, USDC_DEVNET, 999999),
            },
        )

        with pytest.raises(PaymentError, match="no matching token transfer"):
            await mpp.verify_credential(credential)
        assert rpc.sent == []

    async def test_token_transaction_verification_rejects_missing_memo_before_broadcast(self):
        tx = {"meta": {"err": None}, "transaction": {"message": {"instructions": []}}}
        rpc = FakeRPC(tx=tx, send_value="1111111111111111111111111111111111111111111111111111111111111111")
        mpp = Mpp(
            Config(
                recipient=TEST_RECIPIENT,
                currency="USDC",
                decimals=6,
                network="devnet",
                secret_key=TEST_SECRET,
                rpc=rpc,
            )
        )
        challenge = mpp.charge_with_options("1.00", ChargeOptions(external_id="order-123"))
        credential = PaymentCredential(
            challenge=challenge.to_echo(),
            payload={
                "type": "transaction",
                "transaction": _build_spl_transfer_checked_transaction(TEST_RECIPIENT, USDC_DEVNET, 1000000),
            },
        )

        with pytest.raises(PaymentError, match="No memo instruction found"):
            await mpp.verify_credential(credential)
        assert rpc.sent == []

    async def test_signature_verification_rejects_missing_required_split_ata_creation(self):
        split_recipient = str(Pubkey.new_unique())
        tx = {
            "meta": {"err": None},
            "transaction": {
                "message": {
                    "instructions": [
                        {
                            "programId": TOKEN_PROGRAM,
                            "parsed": {
                                "type": "transferChecked",
                                "info": {
                                    "destination": _derive_ata(TEST_RECIPIENT, USDC_DEVNET),
                                    "mint": USDC_DEVNET,
                                    "tokenAmount": {"amount": "950000"},
                                },
                            },
                        },
                        {
                            "programId": TOKEN_PROGRAM,
                            "parsed": {
                                "type": "transferChecked",
                                "info": {
                                    "destination": _derive_ata(split_recipient, USDC_DEVNET),
                                    "mint": USDC_DEVNET,
                                    "tokenAmount": {"amount": "50000"},
                                },
                            },
                        },
                    ]
                }
            },
        }
        rpc = FakeRPC(tx=tx)
        handler = Mpp(
            Config(
                recipient=TEST_RECIPIENT,
                currency=USDC_DEVNET,
                decimals=6,
                network="devnet",
                secret_key=TEST_SECRET,
                rpc=rpc,
            )
        )
        challenge = handler.charge_with_options(
            "1.00",
            ChargeOptions(
                splits=[
                    {
                        "recipient": split_recipient,
                        "amount": "50000",
                        "ataCreationRequired": True,
                    }
                ]
            ),
        )
        credential = PaymentCredential(
            challenge=challenge.to_echo(),
            payload={"type": "signature", "signature": VALID_SIGNATURE},
        )

        with pytest.raises(PaymentError, match="Missing required ATA creation"):
            await handler.verify_credential(credential)


class TestParsedTransferVerification:
    def test_build_expected_transfers_rejects_splits_that_consume_amount(self):
        request = ChargeRequest(amount="1000", currency="sol", recipient="recipient-1")
        details = MethodDetails(splits=[Split(recipient="recipient-2", amount="1000")])

        with pytest.raises(PaymentError, match="primary recipient"):
            _build_expected_transfers(request, details)

    def test_sol_verifier_rejects_duplicate_split_reuse(self):
        request = ChargeRequest(amount="1000", currency="sol", recipient="recipient-1")
        details = MethodDetails(
            splits=[
                Split(recipient="recipient-2", amount="100"),
                Split(recipient="recipient-2", amount="100"),
            ]
        )
        instructions = [
            {
                "program": "system",
                "parsed": {"type": "transfer", "info": {"destination": "recipient-1", "lamports": "800"}},
            },
            {
                "program": "system",
                "parsed": {"type": "transfer", "info": {"destination": "recipient-2", "lamports": "100"}},
            },
        ]

        with pytest.raises(PaymentError, match="no matching SOL transfer"):
            _verify_parsed_sol_transfers(instructions, request, details)

    def test_sol_verifier_matches_same_recipient_by_amount(self):
        request = ChargeRequest(amount="1000", currency="sol", recipient="recipient-1")
        details = MethodDetails(splits=[Split(recipient="recipient-1", amount="200")])
        instructions = [
            {
                "program": "system",
                "parsed": {"type": "transfer", "info": {"destination": "recipient-1", "lamports": "800"}},
            },
            {
                "program": "system",
                "parsed": {"type": "transfer", "info": {"destination": "recipient-1", "lamports": "200"}},
            },
        ]

        _verify_parsed_sol_transfers(instructions, request, details)

    def test_spl_verifier_rejects_wrong_mint(self):
        # Use real pubkeys for mint addresses
        expected_mint = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
        wrong_mint = "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB"
        recipient = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY"
        request = ChargeRequest(amount="1000", currency=expected_mint, recipient=recipient)
        details = MethodDetails(token_program=TOKEN_PROGRAM)
        instructions = [
            {
                "programId": TOKEN_PROGRAM,
                "parsed": {
                    "type": "transferChecked",
                    "info": {
                        "destination": _derive_ata(recipient, wrong_mint),
                        "mint": wrong_mint,
                        "tokenAmount": {"amount": "1000"},
                    },
                },
            }
        ]

        with pytest.raises(PaymentError, match="no matching token transfer"):
            _verify_parsed_spl_transfers(instructions, request, details)

    def test_spl_verifier_matches_same_recipient_by_amount(self):
        recipient = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY"
        mint = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
        primary_ata = _derive_ata(recipient, mint)
        # Same recipient for split — same ATA
        request = ChargeRequest(amount="1000", currency=mint, recipient=recipient)
        details = MethodDetails(
            token_program=TOKEN_PROGRAM,
            splits=[Split(recipient=recipient, amount="200")],
        )
        instructions = [
            {
                "programId": TOKEN_PROGRAM,
                "parsed": {
                    "type": "transferChecked",
                    "info": {
                        "destination": primary_ata,
                        "mint": mint,
                        "tokenAmount": {"amount": "800"},
                    },
                },
            },
            {
                "programId": TOKEN_PROGRAM,
                "parsed": {
                    "type": "transferChecked",
                    "info": {
                        "destination": primary_ata,
                        "mint": mint,
                        "tokenAmount": {"amount": "200"},
                    },
                },
            },
        ]

        _verify_parsed_spl_transfers(instructions, request, details)

    @pytest.mark.parametrize(
        "memo_instruction",
        [
            {"program": "spl-memo", "parsed": "order-123"},
            {"programId": MEMO_PROGRAM, "parsed": {"info": {"memo": "order-123"}}},
            {"programId": MEMO_PROGRAM, "parsed": {"info": {"data": "order-123"}}},
        ],
    )
    def test_memo_verifier_accepts_external_id_shapes(self, memo_instruction: dict):
        request = ChargeRequest(amount="1000", currency="sol", recipient="recipient-1", external_id="order-123")
        details = MethodDetails()

        _verify_parsed_memo_instructions([memo_instruction], request, details)

    def test_memo_verifier_accepts_split_memo(self):
        request = ChargeRequest(amount="1000", currency="sol", recipient="recipient-1")
        details = MethodDetails(splits=[Split(recipient="recipient-2", amount="200", memo="platform fee")])
        instructions = [{"programId": MEMO_PROGRAM, "parsed": "platform fee"}]

        _verify_parsed_memo_instructions(instructions, request, details)

    def test_memo_verifier_rejects_missing_external_id_memo(self):
        request = ChargeRequest(amount="1000", currency="sol", recipient="recipient-1", external_id="order-123")
        details = MethodDetails()

        with pytest.raises(PaymentError, match="No memo instruction found for externalId memo"):
            _verify_parsed_memo_instructions([], request, details)

    def test_memo_verifier_rejects_unexpected_memo(self):
        request = ChargeRequest(amount="1000", currency="sol", recipient="recipient-1")
        details = MethodDetails()
        instructions = [{"programId": MEMO_PROGRAM, "parsed": "unexpected"}]

        with pytest.raises(PaymentError, match="unexpected Memo Program instruction"):
            _verify_parsed_memo_instructions(instructions, request, details)

    def test_memo_verifier_requires_distinct_duplicate_memos(self):
        request = ChargeRequest(amount="1000", currency="sol", recipient="recipient-1", external_id="same")
        details = MethodDetails(splits=[Split(recipient="recipient-2", amount="200", memo="same")])
        instructions = [{"programId": MEMO_PROGRAM, "parsed": "same"}]

        with pytest.raises(PaymentError, match="No memo instruction found for split memo"):
            _verify_parsed_memo_instructions(instructions, request, details)


class TestVerifierHelpers:
    def test_verify_ata_owner_returns_false_for_invalid_address(self):
        assert not _verify_ata_owner("not-an-ata", "not-an-owner", "not-a-mint", TOKEN_PROGRAM)

    def test_parsed_program_id_accepts_named_associated_token_program(self):
        instruction = {"program": "spl-associated-token-account"}

        assert _parsed_program_id(instruction) == ASSOCIATED_TOKEN_PROGRAM

    def test_parsed_info_string_returns_empty_for_missing_keys(self):
        assert _parsed_info_string({"owner": None}, ("wallet", "owner")) == ""

    def test_parsed_ata_creation_matches_rejects_non_dict_shapes(self):
        assert not _parsed_ata_creation_matches({}, "owner", "ata", "mint", TOKEN_PROGRAM)
        assert not _parsed_ata_creation_matches({"parsed": {"info": "not-a-dict"}}, "owner", "ata", "mint", TOKEN_PROGRAM)

    def test_parsed_ata_creation_matches_rejects_unsupported_token_program(self):
        instruction = {
            "parsed": {
                "info": {
                    "wallet": "owner",
                    "account": "ata",
                    "mint": "mint",
                    "tokenProgram": "unsupported-token-program",
                }
            }
        }

        with pytest.raises(PaymentError, match="unsupported token program"):
            _parsed_ata_creation_matches(instruction, "owner", "ata", "mint", TOKEN_PROGRAM)

    def test_rpc_value_handles_none_and_dict_values(self):
        assert _rpc_value(None) is None
        assert _rpc_value({"value": "ok"}) == "ok"
        assert _rpc_value({"other": "ok"}) == {"other": "ok"}

    def test_json_like_handles_objects_with_to_json_and_dict(self):
        class JsonObject:
            def to_json(self):
                return '{"value": {"nested": true}}'

        class PlainObject:
            def __init__(self):
                self.value = JsonObject()

        assert _json_like(JsonObject()) == {"value": {"nested": True}}
        assert _json_like(PlainObject()) == {"value": {"value": {"nested": True}}}

    def test_transaction_dict_rejects_missing_transaction_key(self):
        assert _transaction_dict(None) is None
        assert _transaction_dict({"value": {"meta": {}}}) is None

    def test_status_ok_handles_empty_and_error_entries(self):
        assert not _status_ok({"value": []})
        assert not _status_ok({"value": [{"err": "failed"}]})
        assert _status_ok({"value": [{"err": None}]})

    def test_confirmed_transaction_rejects_on_chain_error(self):
        handler = Mpp(Config(recipient=TEST_RECIPIENT, currency="SOL", decimals=9, secret_key=TEST_SECRET))
        request = ChargeRequest(amount="1000", currency="SOL", recipient=TEST_RECIPIENT)

        with pytest.raises(PaymentError, match="transaction failed"):
            handler._verify_confirmed_transaction({"meta": {"err": {"InstructionError": [0, "Custom"]}}}, request, MethodDetails())
