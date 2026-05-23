"""Tests for server/mpp module."""

from __future__ import annotations

import pytest
from solders.hash import Hash
from solders.instruction import AccountMeta, Instruction
from solders.keypair import Keypair
from solders.message import Message
from solders.pubkey import Pubkey
from solders.system_program import TransferParams, transfer
from solders.transaction import Transaction

from solana_mpp._errors import ChallengeExpiredError, ChallengeMismatchError, PaymentError, ReplayError
from solana_mpp._types import ChallengeEcho, PaymentCredential
from solana_mpp.protocol.intents import ChargeRequest
from solana_mpp.protocol.solana import MEMO_PROGRAM, TOKEN_2022_PROGRAM, MethodDetails, Split
from solana_mpp.server.mpp import (
    ChargeOptions,
    Config,
    Mpp,
    _verify_parsed_memo_instructions,
    _verify_parsed_sol_transfers,
    _verify_parsed_spl_transfers,
)
from solana_mpp.store import MemoryStore

TEST_SECRET = "test-secret-key-that-is-long-enough-for-hmac-sha256"
TEST_RECIPIENT = "11111111111111111111111111111112"
VALID_SIGNATURE = "1111111111111111111111111111111111111111111111111111111111111111"
TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
USDC_DEVNET = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"
ATA_PROGRAM = Pubkey.from_string("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")
TEST_BLOCKHASH = "4vJ9JU1bJJQpUgJ8V6hYz7xXKz4F2tN6aBrZEcD3xKhs"


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

    async def await_confirmation(self, *_args, **_kwargs):
        """Mirror the discriminated-error behaviour of the real RPC client
        so tests that drive the post-L8 settlement path see the same
        success / failure / timeout signals as production."""
        status = (self.statuses or [{}])[0]
        err = status.get("err") if isinstance(status, dict) else None
        if err is not None:
            from solana_mpp._errors import PaymentError
            raise PaymentError(
                f"transaction failed on-chain: {err}",
                code="transaction-failed",
            )


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
        store=MemoryStore(),
    )
    return Mpp(config)


class TestConfig:
    def test_missing_recipient_raises(self):
        with pytest.raises(PaymentError, match="recipient"):
            Mpp(Config(recipient="", secret_key=TEST_SECRET, store=MemoryStore()))

    def test_missing_secret_key_raises(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.delenv("MPP_SECRET_KEY", raising=False)
        with pytest.raises(PaymentError, match="secret key"):
            Mpp(Config(recipient=TEST_RECIPIENT, secret_key="", store=MemoryStore()))

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
                store=MemoryStore(),
            )
        )
        challenge = handler.charge("1.00")
        request = challenge.decode_request()
        assert request["methodDetails"]["tokenProgram"] == expected_program


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
                store=MemoryStore(),
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
                store=MemoryStore(),
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
                store=MemoryStore(),
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
                store=MemoryStore(),
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
                store=MemoryStore(),
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
                store=MemoryStore(),
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
                store=MemoryStore(),
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
                store=MemoryStore(),
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
                store=MemoryStore(),
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
                store=MemoryStore(),
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


class TestParsedTransferVerification:
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


class TestMemoV1Rejected:
    """L2 lock: charge verifier MUST reject Solana memo v1 (Memo1Uhk...).

    Memo v1 has a different instruction shape from memo v2 (no signer check)
    and would let a tampered transaction slip past the v2-only matcher used in
    _verify_parsed_memo_instructions. Mirrors PHP fde0efb + Ruby + Rust + Lua.
    """

    _MEMO_V1 = "Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo"

    def _build_tx_with_memo_v1(self) -> str:
        signer = Keypair()
        instructions = [
            transfer(
                TransferParams(
                    from_pubkey=signer.pubkey(),
                    to_pubkey=Pubkey.from_string(TEST_RECIPIENT),
                    lamports=1000,
                )
            ),
            Instruction(
                Pubkey.from_string(self._MEMO_V1),
                b"hello from memo v1",
                [],
            ),
        ]
        blockhash = Hash.from_string(TEST_BLOCKHASH)
        message = Message.new_with_blockhash(instructions, signer.pubkey(), blockhash)
        transaction = Transaction.new_unsigned(message)
        transaction.sign([signer], blockhash)
        import base64

        return base64.b64encode(bytes(transaction)).decode("ascii")

    def test_decode_rejects_memo_v1(self):
        from solana_mpp.server.mpp import _decode_legacy_payment_instructions

        tx_b64 = self._build_tx_with_memo_v1()
        with pytest.raises(PaymentError, match="memo v1"):
            _decode_legacy_payment_instructions(tx_b64)

    def test_parsed_memo_verifier_rejects_memo_v1(self):
        """Push-mode (signature credential) reaches
        ``_verify_parsed_memo_instructions`` without going through the
        pre-broadcast decoder. The matcher must reject a Memo v1
        program ID directly so push-mode matches pull-mode behaviour.
        """
        request = ChargeRequest(amount="1000", currency="sol", recipient="recipient-1")
        details = MethodDetails()
        v1_instruction = {
            "programId": self._MEMO_V1,
            "parsed": {"type": "memo", "info": "tampered"},
        }
        with pytest.raises(PaymentError, match="memo v1"):
            _verify_parsed_memo_instructions([v1_instruction], request, details)


class TestL8SettlementOrdering:
    """L8 lock: broadcast → consume_signature → await_confirmation.

    The previous order (consume → broadcast → await with a rollback on
    failure) had a fatal flaw: a confirmation timeout after a successful
    broadcast triggered the rollback, which deleted the consume marker,
    so a retry could re-broadcast the same transaction and double-pay.
    Mirrors lua/mpp/server/charge_handler.lua docstring and the cross-SDK
    L8 lock that landed on Rust + Ruby + PHP in PR #96 / #102.
    """

    class _OrderingRPC:
        """Stub RPC that records the order of calls so the test can assert
        broadcast happened before the store insert."""

        def __init__(self, ordering: list[str], confirm_value):
            self._ordering = ordering
            self._confirm_value = confirm_value
            self.tx = {
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
                                        "tokenAmount": {"amount": "1000000"},
                                    },
                                },
                            }
                        ]
                    }
                },
            }

        async def send_raw_transaction(self, _raw: bytes):
            self._ordering.append("send_raw_transaction")
            return FakeResponse(VALID_SIGNATURE)

        async def confirm_transaction(self, *_args, **_kwargs):
            self._ordering.append("confirm_transaction")
            return FakeResponse(self._confirm_value)

        async def await_confirmation(self, *_args, **_kwargs):
            self._ordering.append("await_confirmation")
            status = (self._confirm_value or [{}])[0]
            err = status.get("err") if isinstance(status, dict) else None
            if err is not None:
                from solana_mpp._errors import PaymentError
                raise PaymentError(
                    f"transaction failed on-chain: {err}",
                    code="transaction-failed",
                )

        async def get_transaction(self, *_args, **_kwargs):
            self._ordering.append("get_transaction")
            return FakeResponse(self.tx)

    class _RecordingStore:
        def __init__(self, ordering: list[str]):
            self._ordering = ordering
            self._data: dict = {}

        async def get(self, key):
            return self._data.get(key)

        async def put(self, key, value):
            self._data[key] = value

        async def delete(self, key):
            self._ordering.append("store.delete")
            self._data.pop(key, None)

        async def put_if_absent(self, key, value):
            self._ordering.append("store.put_if_absent")
            if key in self._data:
                return False
            self._data[key] = value
            return True

    def _build_credential(self, mpp_handler: Mpp) -> tuple[PaymentCredential, str]:
        transaction = _build_spl_transfer_checked_transaction(TEST_RECIPIENT, USDC_DEVNET, 1_000_000)
        challenge = mpp_handler.charge("1.00")
        echo = challenge.to_echo()
        credential = PaymentCredential(
            challenge=echo,
            payload={"type": "transaction", "transaction": transaction},
        )
        return credential, transaction

    async def test_broadcast_before_consume(self):
        ordering: list[str] = []
        rpc = self._OrderingRPC(ordering, [{"err": None}])
        store = self._RecordingStore(ordering)
        from solana_mpp.store import Store  # noqa: F401  ensure protocol import

        handler = Mpp(
            Config(
                recipient=TEST_RECIPIENT,
                currency="USDC",
                decimals=6,
                network="devnet",
                secret_key=TEST_SECRET,
                rpc=rpc,
                store=store,
            )
        )
        credential, _tx = self._build_credential(handler)

        receipt = await handler.verify_credential(credential)
        assert receipt.is_success()

        # The canonical L8 order is broadcast → consume → await. assertions
        # are positional, not equality, so adding extra steps later (e.g.
        # simulate before broadcast) does not break this test as long as
        # the relative order holds.
        broadcast_idx = ordering.index("send_raw_transaction")
        consume_idx = ordering.index("store.put_if_absent")
        # The handler now uses ``await_confirmation`` (discriminated
        # error codes) instead of ``confirm_transaction``; assert against
        # the new step name.
        confirm_idx = ordering.index("await_confirmation")
        assert broadcast_idx < consume_idx, f"L8 violation: broadcast must precede consume; saw {ordering}"
        assert consume_idx < confirm_idx, f"L8 violation: consume must precede await; saw {ordering}"

    async def test_confirm_timeout_after_broadcast_does_not_rollback_consume(self):
        """The headline L8 bug: a confirm-timeout post-broadcast used to
        delete the consume marker on the way out. After L8, the marker
        MUST survive so a retry of the same credential hits the consumed
        check first and cannot re-broadcast."""
        ordering: list[str] = []
        # confirm returns no-ok statuses -> handler raises transaction-not-found
        rpc = self._OrderingRPC(ordering, [{"err": "Timeout"}])
        store = self._RecordingStore(ordering)

        handler = Mpp(
            Config(
                recipient=TEST_RECIPIENT,
                currency="USDC",
                decimals=6,
                network="devnet",
                secret_key=TEST_SECRET,
                rpc=rpc,
                store=store,
            )
        )
        credential, _tx = self._build_credential(handler)

        with pytest.raises(PaymentError):
            await handler.verify_credential(credential)

        # The consume marker must still be present after the timeout: the
        # signature is on the wire and may finalize asynchronously.
        assert "store.put_if_absent" in ordering
        assert "store.delete" not in ordering, (
            "L8 regression: consume marker must not be rolled back after a "
            "successful broadcast even if confirmation times out"
        )

    async def test_b34_signature_credential_with_fee_payer_rejected_before_rpc(self):
        """B34 lock: signature-mode credential against a challenge that
        carries feePayer=true MUST be rejected by the server before any
        RPC call. The push-mode contract is that the client already
        broadcast the transaction; if the challenge says the server is
        the fee payer, the client could not have signed it as fee payer
        without the server's key, so the credential is structurally
        impossible. Mirrors the audit v2 row 34 spec gap fix.
        """
        ordering: list[str] = []

        class _NoRPC:
            async def get_transaction(self, *_a, **_kw):
                ordering.append("get_transaction")
                return FakeResponse(None)

            async def send_raw_transaction(self, *_a, **_kw):
                ordering.append("send_raw_transaction")
                return FakeResponse(None)

            async def confirm_transaction(self, *_a, **_kw):
                ordering.append("confirm_transaction")
                return FakeResponse(None)

            async def await_confirmation(self, *_a, **_kw):
                ordering.append("await_confirmation")

        rpc = _NoRPC()
        from solana_mpp.store import MemoryStore

        handler = Mpp(
            Config(
                recipient=TEST_RECIPIENT,
                currency="USDC",
                decimals=6,
                network="devnet",
                secret_key=TEST_SECRET,
                rpc=rpc,
                store=MemoryStore(),
            )
        )
        # Build a challenge with feePayer=true via ChargeOptions.
        challenge = handler.charge_with_options("1.00", ChargeOptions(fee_payer=True))
        echo = challenge.to_echo()
        credential = PaymentCredential(
            challenge=echo,
            payload={"type": "signature", "signature": VALID_SIGNATURE},
        )

        with pytest.raises(PaymentError, match="fee sponsorship"):
            await handler.verify_credential(credential)

        # Critical: the rejection happened BEFORE any RPC call. A signature
        # credential under feePayer is a structural error; we never look up
        # the transaction on chain.
        assert ordering == [], f"B34 violation: rejection must happen before RPC; saw {ordering}"

    async def test_signature_keyed_consume_not_credential_keyed(self):
        """A retry of the same credential MUST collide on the on-chain
        signature, not on the credential-payload bytes. Keying by credential
        bytes used to let a retry with the same payload look like a fresh
        request whenever the signature differed."""
        ordering: list[str] = []
        rpc = self._OrderingRPC(ordering, [{"err": None}])
        store = self._RecordingStore(ordering)

        handler = Mpp(
            Config(
                recipient=TEST_RECIPIENT,
                currency="USDC",
                decimals=6,
                network="devnet",
                secret_key=TEST_SECRET,
                rpc=rpc,
                store=store,
            )
        )
        credential, _tx = self._build_credential(handler)
        await handler.verify_credential(credential)

        # Inspect the store: the consume key must include the on-chain
        # signature returned by send_raw_transaction, not the credential
        # transaction prefix.
        keys = list(store._data.keys())
        assert any(VALID_SIGNATURE in key for key in keys), (
            f"consume key must be keyed by on-chain signature; saw {keys}"
        )


class TestCoSignSplitBounds:
    """Greptile follow-up: ``_co_sign_with_fee_payer`` MUST validate that
    the fee-payer account index falls inside the required-signers block
    before splicing the signature into the wire transaction. Splicing at
    ``1 + idx * 64`` for an out-of-range index would overwrite message
    bytes and produce a corrupted transaction the cluster rejects
    opaquely.
    """

    def test_fee_payer_in_readonly_unsigned_block_is_rejected(self):
        from solders.hash import Hash
        from solders.instruction import AccountMeta, Instruction
        from solders.keypair import Keypair
        from solders.message import Message
        from solders.pubkey import Pubkey
        from solders.system_program import TransferParams, transfer
        from solders.transaction import Transaction

        from solana_mpp.server.mpp import _co_sign_with_fee_payer

        # Build a transaction whose only signer is ``real_signer``. Then
        # reference ``rogue_fee_payer.pubkey()`` in a readonly-unsigned
        # account meta. The fee-payer key exists in account_keys but its
        # index lands in the readonly-unsigned region, outside the
        # required-signers block.
        real_signer = Keypair()
        rogue_fee_payer = Keypair()
        recipient = Pubkey.from_string(TEST_RECIPIENT)

        transfer_ix = transfer(
            TransferParams(
                from_pubkey=real_signer.pubkey(),
                to_pubkey=recipient,
                lamports=1000,
            )
        )
        # A second instruction that touches the rogue pubkey as a readonly
        # non-signer account; this places it in the readonly-unsigned
        # block of the compiled message.
        touch_rogue = Instruction(
            Pubkey.from_string(MEMO_PROGRAM),
            b"touch",
            [AccountMeta(rogue_fee_payer.pubkey(), False, False)],
        )

        blockhash = Hash.from_string(TEST_BLOCKHASH)
        message = Message.new_with_blockhash([transfer_ix, touch_rogue], real_signer.pubkey(), blockhash)
        transaction = Transaction.new_unsigned(message)
        transaction.sign([real_signer], blockhash)
        import base64

        tx_b64 = base64.b64encode(bytes(transaction)).decode("ascii")

        # The rogue pubkey is present in account_keys but its index is >=
        # num_required_signatures (== 1 here). Splicing at that slot would
        # overwrite message bytes.
        with pytest.raises(PaymentError, match="outside the required-signers block"):
            _co_sign_with_fee_payer(tx_b64, rogue_fee_payer)

    def test_fee_payer_at_required_slot_co_signs(self):
        # Positive control: when the fee-payer pubkey IS the first
        # required signer, the splice succeeds. Verifies the new bounds
        # check did not regress the happy path.
        from solders.hash import Hash
        from solders.keypair import Keypair
        from solders.message import Message
        from solders.pubkey import Pubkey
        from solders.system_program import TransferParams, transfer
        from solders.transaction import Transaction

        from solana_mpp.server.mpp import _co_sign_with_fee_payer

        fee_payer = Keypair()
        recipient = Pubkey.from_string(TEST_RECIPIENT)

        ix = transfer(
            TransferParams(
                from_pubkey=fee_payer.pubkey(),
                to_pubkey=recipient,
                lamports=1000,
            )
        )
        blockhash = Hash.from_string(TEST_BLOCKHASH)
        message = Message.new_with_blockhash([ix], fee_payer.pubkey(), blockhash)
        transaction = Transaction.new_unsigned(message)
        # Leave the signature slot zeroed so cosign can fill it.
        import base64

        tx_b64 = base64.b64encode(bytes(transaction)).decode("ascii")

        signed_b64 = _co_sign_with_fee_payer(tx_b64, fee_payer)
        # Splice succeeded if the result is decodable and the signature
        # slot is no longer all zeros.
        signed_bytes = base64.b64decode(signed_b64)
        # Skip the 1-byte num_sigs prefix; first 64 bytes after are the
        # fee-payer signature slot.
        assert signed_bytes[1:65] != b"\x00" * 64

    def test_fee_payer_at_non_zero_signer_slot_is_rejected(self):
        """Greptile follow-up: the fee payer must occupy ``account_keys[0]``.

        A client that places the server's fee-payer pubkey at any other
        required-signer slot (e.g. slot 1) could trick the server into
        producing a signature usable for an unrelated instruction that
        also requires that key. Mirrors the Rust spine's
        ``expected_fee_payer`` invariant.
        """
        from solders.hash import Hash
        from solders.keypair import Keypair
        from solders.message import Message
        from solders.pubkey import Pubkey
        from solders.system_program import TransferParams, transfer
        from solders.transaction import Transaction

        from solana_mpp.server.mpp import _co_sign_with_fee_payer

        # Put a different real signer at slot 0 (the actual fee payer),
        # and reference the server's would-be fee-payer pubkey as the
        # transfer source so it lands in the required-signers block at
        # slot 1.
        real_signer = Keypair()
        rogue_fee_payer = Keypair()
        recipient = Pubkey.from_string(TEST_RECIPIENT)

        ix = transfer(
            TransferParams(
                from_pubkey=rogue_fee_payer.pubkey(),
                to_pubkey=recipient,
                lamports=1000,
            )
        )
        blockhash = Hash.from_string(TEST_BLOCKHASH)
        # payer=real_signer keeps account_keys[0] = real_signer; the
        # transfer source becomes a second required signer at slot 1.
        message = Message.new_with_blockhash([ix], real_signer.pubkey(), blockhash)
        transaction = Transaction.new_unsigned(message)
        transaction.sign([real_signer, rogue_fee_payer], blockhash)

        import base64

        tx_b64 = base64.b64encode(bytes(transaction)).decode("ascii")

        with pytest.raises(PaymentError, match="must occupy account index 0"):
            _co_sign_with_fee_payer(tx_b64, rogue_fee_payer)


class TestComputeBudgetGuard:
    """Compute-budget allowlist parity with Rust / PHP / Ruby.

    SetComputeUnitLimit and SetComputeUnitPrice are the only accepted
    instruction shapes; values must stay at or under the per-instruction
    caps. Mirrors ``validate_compute_budget_instruction`` in
    ``rust/src/server/charge.rs`` and the matching PHP / Ruby validators.
    """

    _COMPUTE_BUDGET = "ComputeBudget111111111111111111111111111111"

    @staticmethod
    def _build_tx_with_compute_budget_data(data: bytes) -> str:
        signer = Keypair()
        instructions = [
            Instruction(Pubkey.from_string(TestComputeBudgetGuard._COMPUTE_BUDGET), data, []),
            transfer(
                TransferParams(
                    from_pubkey=signer.pubkey(),
                    to_pubkey=Pubkey.from_string(TEST_RECIPIENT),
                    lamports=1000,
                )
            ),
        ]
        blockhash = Hash.from_string(TEST_BLOCKHASH)
        message = Message.new_with_blockhash(instructions, signer.pubkey(), blockhash)
        transaction = Transaction.new_unsigned(message)
        transaction.sign([signer], blockhash)
        import base64

        return base64.b64encode(bytes(transaction)).decode("ascii")

    def test_set_compute_unit_limit_at_cap_is_accepted(self):
        from solana_mpp.server.mpp import MAX_COMPUTE_UNIT_LIMIT, _decode_legacy_payment_instructions

        data = bytes([2]) + MAX_COMPUTE_UNIT_LIMIT.to_bytes(4, "little")
        tx_b64 = self._build_tx_with_compute_budget_data(data)
        # No exception: the transfer is decoded and the compute-budget
        # instruction is silently accepted (not surfaced in the parsed list).
        out = _decode_legacy_payment_instructions(tx_b64)
        assert any(item.get("program") == "system" for item in out)
        assert not any(item.get("programId") == self._COMPUTE_BUDGET for item in out)

    def test_set_compute_unit_limit_over_cap_is_rejected(self):
        from solana_mpp.server.mpp import MAX_COMPUTE_UNIT_LIMIT, _decode_legacy_payment_instructions

        over = MAX_COMPUTE_UNIT_LIMIT + 1
        data = bytes([2]) + over.to_bytes(4, "little")
        tx_b64 = self._build_tx_with_compute_budget_data(data)
        with pytest.raises(PaymentError) as exc:
            _decode_legacy_payment_instructions(tx_b64)
        assert exc.value.code == "compute-budget-cap-exceeded"
        assert str(MAX_COMPUTE_UNIT_LIMIT) in str(exc.value)
        assert str(over) in str(exc.value)

    def test_set_compute_unit_price_over_cap_is_rejected(self):
        from solana_mpp.server.mpp import (
            MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS,
            _decode_legacy_payment_instructions,
        )

        over = MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS + 1
        data = bytes([3]) + over.to_bytes(8, "little")
        tx_b64 = self._build_tx_with_compute_budget_data(data)
        with pytest.raises(PaymentError) as exc:
            _decode_legacy_payment_instructions(tx_b64)
        assert exc.value.code == "compute-budget-cap-exceeded"
        assert str(MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS) in str(exc.value)
        assert str(over) in str(exc.value)

    def test_unknown_compute_budget_discriminator_is_rejected(self):
        from solana_mpp.server.mpp import _decode_legacy_payment_instructions

        # Discriminator 0 (RequestUnits) is no longer a permitted shape
        # in the MPP allowlist; reject as invalid payload.
        data = bytes([0, 0, 0, 0, 0])
        tx_b64 = self._build_tx_with_compute_budget_data(data)
        with pytest.raises(PaymentError) as exc:
            _decode_legacy_payment_instructions(tx_b64)
        assert exc.value.code == "compute-budget-invalid"

    def test_canonical_code_maps_to_payment_invalid(self):
        from solana_mpp._errors import CODE_PAYMENT_INVALID, canonical_code

        assert canonical_code("compute-budget-cap-exceeded") == CODE_PAYMENT_INVALID
        assert canonical_code("compute-budget-invalid") == CODE_PAYMENT_INVALID


class TestSplitsCountGuard:
    """Splits-count cap parity with Rust / PHP / Ruby.

    A challenge advertising more than ``MAX_SPLITS`` (8) split recipients
    is rejected before transaction verification so the verifier never
    walks an unbounded ATA list or transfer list. Mirrors the Rust guard
    in ``verify_versioned_transaction_pre_broadcast`` and the matching
    PHP / Ruby counts.
    """

    @staticmethod
    def _make_request_with_n_splits(n: int) -> tuple[ChargeRequest, MethodDetails]:
        request = ChargeRequest(amount="10000", currency="USDC", recipient=TEST_RECIPIENT)
        splits = [
            Split(recipient=TEST_RECIPIENT, amount="1")
            for _ in range(n)
        ]
        details = MethodDetails(splits=splits)
        return request, details

    def test_splits_at_cap_is_accepted(self):
        from solana_mpp.server.mpp import MAX_SPLITS, _build_expected_transfers

        request, details = self._make_request_with_n_splits(MAX_SPLITS)
        out = _build_expected_transfers(request, details)
        # primary + 8 splits = 9 entries
        assert len(out) == MAX_SPLITS + 1

    def test_splits_over_cap_is_rejected(self):
        from solana_mpp.server.mpp import MAX_SPLITS, _build_expected_transfers

        observed = MAX_SPLITS + 1
        request, details = self._make_request_with_n_splits(observed)
        with pytest.raises(PaymentError) as exc:
            _build_expected_transfers(request, details)
        assert exc.value.code == "too-many-splits"
        assert str(observed) in str(exc.value)
        assert str(MAX_SPLITS) in str(exc.value)

    def test_canonical_code_maps_to_payment_invalid(self):
        from solana_mpp._errors import CODE_PAYMENT_INVALID, canonical_code

        assert canonical_code("too-many-splits") == CODE_PAYMENT_INVALID


class TestInstructionAllowlist:
    """SECURITY: strict no-leftovers allowlist for the fee-payer co-sign path.

    The verifier MUST reject any instruction that is not on the canonical
    allowlist (ComputeBudget, Memo v2 matching an expected memo, System
    Program transfer matching an expected payment transfer, SPL
    transferChecked matching an expected payment transfer, ATA idempotent
    create for a charge-recipient owner). Without this guard a malicious
    client could include the valid payment plus an extra System Program
    transfer FROM the fee payer account TO an attacker, and the server
    would co-sign the entire transaction and DRAIN fee-payer SOL.
    Mirrors ``validate_instruction_allowlist`` in
    ``rust/src/server/charge.rs``.
    """

    AMOUNT_LAMPORTS = 1000
    ATTACKER = "11111111111111111111111111111113"

    def _request_and_details(self) -> tuple[ChargeRequest, MethodDetails]:
        request = ChargeRequest(
            amount=str(self.AMOUNT_LAMPORTS),
            currency="SOL",
            recipient=TEST_RECIPIENT,
        )
        details = MethodDetails(network="devnet")
        return request, details

    def _build_tx(self, instructions: list[Instruction], fee_payer: Keypair) -> str:
        blockhash = Hash.from_string(TEST_BLOCKHASH)
        message = Message.new_with_blockhash(instructions, fee_payer.pubkey(), blockhash)
        transaction = Transaction.new_unsigned(message)
        transaction.sign([fee_payer], blockhash)
        import base64

        return base64.b64encode(bytes(transaction)).decode("ascii")

    def test_valid_payment_with_compute_budget_is_accepted(self):
        """Positive control: a charge transaction with a permitted
        ComputeBudget SetComputeUnitLimit alongside the required transfer
        must pass the allowlist."""
        from solana_mpp.server.mpp import _verify_local_transaction_intent

        fee_payer = Keypair()
        request, details = self._request_and_details()
        compute_budget = Instruction(
            Pubkey.from_string("ComputeBudget111111111111111111111111111111"),
            bytes([2]) + (50_000).to_bytes(4, "little"),
            [],
        )
        payment = transfer(
            TransferParams(
                from_pubkey=fee_payer.pubkey(),
                to_pubkey=Pubkey.from_string(TEST_RECIPIENT),
                lamports=self.AMOUNT_LAMPORTS,
            )
        )
        tx_b64 = self._build_tx([compute_budget, payment], fee_payer)
        # Must not raise.
        _verify_local_transaction_intent(tx_b64, request, details)

    def test_valid_payment_with_extra_system_transfer_to_attacker_is_rejected(self):
        """SECURITY: an attacker tacks an extra System Program transfer
        onto the valid payment. The transfer pulls fee-payer SOL to an
        attacker address. Without the allowlist this would be co-signed
        and broadcast, draining the fee payer. MUST be rejected with
        the canonical ``payment_invalid`` code before co-sign."""
        from solana_mpp._errors import CODE_PAYMENT_INVALID, canonical_code
        from solana_mpp.server.mpp import _verify_local_transaction_intent

        fee_payer = Keypair()
        request, details = self._request_and_details()
        payment = transfer(
            TransferParams(
                from_pubkey=fee_payer.pubkey(),
                to_pubkey=Pubkey.from_string(TEST_RECIPIENT),
                lamports=self.AMOUNT_LAMPORTS,
            )
        )
        drain = transfer(
            TransferParams(
                from_pubkey=fee_payer.pubkey(),
                to_pubkey=Pubkey.from_string(self.ATTACKER),
                lamports=999_999_999,
            )
        )
        tx_b64 = self._build_tx([payment, drain], fee_payer)
        with pytest.raises(PaymentError) as exc:
            _verify_local_transaction_intent(tx_b64, request, details)
        assert canonical_code(exc.value.code) == CODE_PAYMENT_INVALID
        assert "unexpected" in str(exc.value).lower()

    def test_valid_payment_with_extra_spl_transfer_is_rejected(self):
        """SECURITY: an attacker includes the valid SOL payment plus an
        SPL Token transfer instruction. The native-SOL allowlist must
        reject any Token Program instruction since a native-SOL charge
        never legitimately carries one."""
        from solana_mpp._errors import CODE_PAYMENT_INVALID, canonical_code
        from solana_mpp.server.mpp import _verify_local_transaction_intent

        fee_payer = Keypair()
        request, details = self._request_and_details()
        payment = transfer(
            TransferParams(
                from_pubkey=fee_payer.pubkey(),
                to_pubkey=Pubkey.from_string(TEST_RECIPIENT),
                lamports=self.AMOUNT_LAMPORTS,
            )
        )
        # Crafted SPL transferChecked targeting an attacker mint.
        attacker_mint = Pubkey.new_unique()
        attacker_dest = Pubkey.new_unique()
        spl_drain = Instruction(
            Pubkey.from_string(TOKEN_PROGRAM),
            bytes([12]) + (1).to_bytes(8, "little") + bytes([6]),
            [
                AccountMeta(Pubkey.new_unique(), False, True),
                AccountMeta(attacker_mint, False, False),
                AccountMeta(attacker_dest, False, True),
                AccountMeta(fee_payer.pubkey(), True, False),
            ],
        )
        tx_b64 = self._build_tx([payment, spl_drain], fee_payer)
        with pytest.raises(PaymentError) as exc:
            _verify_local_transaction_intent(tx_b64, request, details)
        assert canonical_code(exc.value.code) == CODE_PAYMENT_INVALID

    def test_valid_payment_with_unknown_program_is_rejected(self):
        """SECURITY: an arbitrary BPF program invocation alongside the
        valid payment is not on the allowlist and must be rejected."""
        from solana_mpp._errors import CODE_PAYMENT_INVALID, canonical_code
        from solana_mpp.server.mpp import _verify_local_transaction_intent

        fee_payer = Keypair()
        request, details = self._request_and_details()
        payment = transfer(
            TransferParams(
                from_pubkey=fee_payer.pubkey(),
                to_pubkey=Pubkey.from_string(TEST_RECIPIENT),
                lamports=self.AMOUNT_LAMPORTS,
            )
        )
        unknown = Instruction(Pubkey.new_unique(), b"\x00", [])
        tx_b64 = self._build_tx([payment, unknown], fee_payer)
        with pytest.raises(PaymentError) as exc:
            _verify_local_transaction_intent(tx_b64, request, details)
        assert canonical_code(exc.value.code) == CODE_PAYMENT_INVALID
        assert "unexpected" in str(exc.value).lower()

    def test_valid_payment_with_memo_v1_is_rejected(self):
        """L2 lock parity: memo v1 is rejected even when the v2 verifier
        would otherwise let extra memos slip past as unmatched."""
        from solana_mpp.server.mpp import _verify_local_transaction_intent

        fee_payer = Keypair()
        request, details = self._request_and_details()
        payment = transfer(
            TransferParams(
                from_pubkey=fee_payer.pubkey(),
                to_pubkey=Pubkey.from_string(TEST_RECIPIENT),
                lamports=self.AMOUNT_LAMPORTS,
            )
        )
        memo_v1 = Instruction(
            Pubkey.from_string("Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo"),
            b"hi",
            [],
        )
        tx_b64 = self._build_tx([payment, memo_v1], fee_payer)
        with pytest.raises(PaymentError, match="memo v1"):
            _verify_local_transaction_intent(tx_b64, request, details)

    def test_valid_spl_payment_with_ata_create_for_recipient_is_accepted(self):
        """Positive control: SPL payment can legitimately include an
        idempotent ATA create for the recipient ahead of the transfer."""
        from solana_mpp.protocol.solana import ASSOCIATED_TOKEN_PROGRAM
        from solana_mpp.server.mpp import _verify_local_transaction_intent

        fee_payer = Keypair()
        request = ChargeRequest(
            amount="1000000",
            currency="USDC",
            recipient=TEST_RECIPIENT,
        )
        details = MethodDetails(network="devnet", token_program=TOKEN_PROGRAM, decimals=6)
        mint = USDC_DEVNET
        recipient_ata = _derive_ata(TEST_RECIPIENT, mint, TOKEN_PROGRAM)
        # Idempotent ATA create: data == [1], 6 accounts in canonical order
        # (payer, ata, owner, mint, system, token_program).
        ata_create = Instruction(
            Pubkey.from_string(ASSOCIATED_TOKEN_PROGRAM),
            b"\x01",
            [
                AccountMeta(fee_payer.pubkey(), True, True),
                AccountMeta(Pubkey.from_string(recipient_ata), False, True),
                AccountMeta(Pubkey.from_string(TEST_RECIPIENT), False, False),
                AccountMeta(Pubkey.from_string(mint), False, False),
                AccountMeta(Pubkey.from_string("11111111111111111111111111111111"), False, False),
                AccountMeta(Pubkey.from_string(TOKEN_PROGRAM), False, False),
            ],
        )
        # Build SPL transfer matching the recipient ATA.
        source = Pubkey.new_unique()
        spl_data = bytes([12]) + (1_000_000).to_bytes(8, "little") + bytes([6])
        spl_transfer = Instruction(
            Pubkey.from_string(TOKEN_PROGRAM),
            spl_data,
            [
                AccountMeta(source, False, True),
                AccountMeta(Pubkey.from_string(mint), False, False),
                AccountMeta(Pubkey.from_string(recipient_ata), False, True),
                AccountMeta(fee_payer.pubkey(), True, False),
            ],
        )
        tx_b64 = self._build_tx([ata_create, spl_transfer], fee_payer)
        # Must not raise.
        _verify_local_transaction_intent(tx_b64, request, details)

    def test_ata_create_for_attacker_owner_is_rejected(self):
        """SECURITY: an ATA create for an owner that is NOT a charge
        recipient must be rejected so the attacker cannot get the fee
        payer to fund an arbitrary ATA rent."""
        from solana_mpp.protocol.solana import ASSOCIATED_TOKEN_PROGRAM
        from solana_mpp._errors import CODE_PAYMENT_INVALID, canonical_code
        from solana_mpp.server.mpp import _verify_local_transaction_intent

        fee_payer = Keypair()
        request = ChargeRequest(
            amount="1000000",
            currency="USDC",
            recipient=TEST_RECIPIENT,
        )
        details = MethodDetails(network="devnet", token_program=TOKEN_PROGRAM, decimals=6)
        mint = USDC_DEVNET
        # ATA create for attacker owner.
        attacker_ata = _derive_ata(self.ATTACKER, mint, TOKEN_PROGRAM)
        ata_create = Instruction(
            Pubkey.from_string(ASSOCIATED_TOKEN_PROGRAM),
            b"\x01",
            [
                AccountMeta(fee_payer.pubkey(), True, True),
                AccountMeta(Pubkey.from_string(attacker_ata), False, True),
                AccountMeta(Pubkey.from_string(self.ATTACKER), False, False),
                AccountMeta(Pubkey.from_string(mint), False, False),
                AccountMeta(Pubkey.from_string("11111111111111111111111111111111"), False, False),
                AccountMeta(Pubkey.from_string(TOKEN_PROGRAM), False, False),
            ],
        )
        # Required transfer to actual recipient.
        recipient_ata = _derive_ata(TEST_RECIPIENT, mint, TOKEN_PROGRAM)
        source = Pubkey.new_unique()
        spl_data = bytes([12]) + (1_000_000).to_bytes(8, "little") + bytes([6])
        spl_transfer = Instruction(
            Pubkey.from_string(TOKEN_PROGRAM),
            spl_data,
            [
                AccountMeta(source, False, True),
                AccountMeta(Pubkey.from_string(mint), False, False),
                AccountMeta(Pubkey.from_string(recipient_ata), False, True),
                AccountMeta(fee_payer.pubkey(), True, False),
            ],
        )
        tx_b64 = self._build_tx([ata_create, spl_transfer], fee_payer)
        with pytest.raises(PaymentError) as exc:
            _verify_local_transaction_intent(tx_b64, request, details)
        assert canonical_code(exc.value.code) == CODE_PAYMENT_INVALID
