"""x402 ``exact`` transaction versions (scheme_exact_svm.md §1.5, SIMD-0385).

The client negotiates the message version from ``extra.transactionVersions``
and builds version 1 with its compute budget in the header; the sponsor admits
only the versions its offer advertises, applies the version-1 header rules,
bounds the compute unit limit and the priority fee it pays, allows only the
fee payer and the transfer authority to sign, and co-signs version 1 over its
message bytes.
"""

from __future__ import annotations

import base64
import json
import struct
from typing import Any, cast

import pytest
from solana_keychain import MemorySigner
from solders.hash import Hash
from solders.instruction import AccountMeta, Instruction
from solders.keypair import Keypair
from solders.message import MessageV0
from solders.pubkey import Pubkey
from solders.signature import Signature
from solders.transaction import VersionedTransaction

from solana_pay_kit import Gate, Price, Protocol, Stablecoin, configure
from solana_pay_kit._paycore import txv1
from solana_pay_kit._paycore.errors import InvalidChallengeError
from solana_pay_kit._paycore.mints import derive_ata
from solana_pay_kit._paycore.solana import TOKEN_PROGRAM
from solana_pay_kit._paycore.transaction import verify_required_signatures
from solana_pay_kit.config import X402Config, reset
from solana_pay_kit.errors import InvalidProofError
from solana_pay_kit.protocols.x402 import ExactVerifier, X402Adapter, verify_exact_credential
from solana_pay_kit.protocols.x402.client.exact import build_payment, build_payment_header
from solana_pay_kit.protocols.x402.exact.types import X402AcceptsEntry
from solana_pay_kit.protocols.x402.exact.verify import (
    COMPUTE_BUDGET_PROGRAM,
    MAX_COMPUTE_UNIT_LIMIT,
    MEMO_PROGRAM,
    accepted_transaction_versions,
)

DEVNET = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"
MINT = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"
BH = "11111111111111111111111111111111"
AMOUNT = 1000
BOTH = [0, 1]


class _MintAccount:
    def __init__(self) -> None:
        data = bytearray(82)
        data[44] = 6
        data[45] = 1
        self.owner = TOKEN_PROGRAM
        self.data = bytes(data)


class _MintResp:
    value = _MintAccount()


class _Rpc:
    async def get_account_info(self, _pubkey: Any) -> _MintResp:
        return _MintResp()


def _offer(fee_payer: str, pay_to: str, versions: object = None) -> X402AcceptsEntry:
    extra: dict[str, object] = {"feePayer": fee_payer, "recentBlockhash": BH}
    if versions is not None:
        extra["transactionVersions"] = versions
    return cast(
        "X402AcceptsEntry",
        {
            "scheme": "exact",
            "network": DEVNET,
            "amount": str(AMOUNT),
            "asset": MINT,
            "payTo": pay_to,
            "maxTimeoutSeconds": 300,
            "extra": extra,
        },
    )


def _tx_of(envelope: object) -> Any:
    payload = cast("dict[str, Any]", cast("dict[str, Any]", envelope)["payload"])
    return txv1.decode_transaction(base64.b64decode(payload["transaction"]))


# -- hand-built transactions -------------------------------------------------


def _transfer(authority: Pubkey, pay_to: str, *, amount: int = AMOUNT) -> Instruction:
    return Instruction(
        Pubkey.from_string(TOKEN_PROGRAM),
        bytes([12]) + struct.pack("<Q", amount) + bytes([6]),
        [
            AccountMeta(Pubkey.from_string(derive_ata(str(authority), MINT, TOKEN_PROGRAM)), False, True),
            AccountMeta(Pubkey.from_string(MINT), False, False),
            AccountMeta(Pubkey.from_string(derive_ata(pay_to, MINT, TOKEN_PROGRAM)), False, True),
            AccountMeta(authority, True, False),
        ],
    )


def _memo(text: str = "nonce-0123456789") -> Instruction:
    return Instruction(Pubkey.from_string(MEMO_PROGRAM), text.encode(), [])


def _budget_ix(tag: int, value: int, width: int) -> Instruction:
    return Instruction(Pubkey.from_string(COMPUTE_BUDGET_PROGRAM), bytes([tag]) + value.to_bytes(width, "little"), [])


def _default_config(**overrides: int | None) -> txv1.TransactionConfig:
    values: dict[str, int | None] = {
        "priority_fee": 1,
        "compute_unit_limit": 20_000,
        "loaded_accounts_data_size_limit": 4 * 1024 * 1024,
        "heap_size": None,
    }
    values.update(overrides)
    return txv1.TransactionConfig(**values)


def _v1_b64(
    fee_payer: Keypair,
    instructions: list[Instruction],
    signers: list[Keypair],
    config: txv1.TransactionConfig | None = None,
) -> str:
    message = txv1.MessageV1.try_compile(
        fee_payer.pubkey(), instructions, Hash.from_string(BH), config or _default_config()
    )
    by_key = {signer.pubkey(): signer for signer in signers}
    required = message.account_keys[: message.header.num_required_signatures]
    signatures = [
        by_key[key].sign_message(bytes(message)) if key in by_key else Signature.default() for key in required
    ]
    return base64.b64encode(bytes(txv1.TransactionV1.populate(message, signatures))).decode()


def _v0_b64(fee_payer: Keypair, instructions: list[Instruction], signers: list[Keypair]) -> str:
    message = MessageV0.try_compile(fee_payer.pubkey(), instructions, [], Hash.from_string(BH))
    return base64.b64encode(bytes(VersionedTransaction(message, signers))).decode()


def _parties() -> tuple[Keypair, Keypair, str]:
    return Keypair(), Keypair(), str(Keypair().pubkey())


def _requirement(fee_payer: Keypair, pay_to: str, versions: object = BOTH) -> dict[str, Any]:
    return cast("dict[str, Any]", _offer(str(fee_payer.pubkey()), pay_to, versions))


def _verify(tx: str, fee_payer: Keypair, pay_to: str, versions: object = BOTH) -> dict[str, Any]:
    return ExactVerifier.verify(tx, _requirement(fee_payer, pay_to, versions), [str(fee_payer.pubkey())])


def _reject(tx: str, fee_payer: Keypair, pay_to: str, code: str, versions: object = BOTH) -> None:
    with pytest.raises(InvalidProofError) as err:
        _verify(tx, fee_payer, pay_to, versions)
    assert err.value.code == code


# -- client negotiation ------------------------------------------------------


async def test_client_builds_version_1_with_a_header_budget_when_advertised():
    fee_payer, pay_to = str(Keypair().pubkey()), str(Keypair().pubkey())
    env = await build_payment(MemorySigner(Keypair()), _Rpc(), _offer(fee_payer, pay_to, BOTH))
    tx = _tx_of(env)
    assert isinstance(tx, txv1.TransactionV1)
    assert tx.message.config == _default_config()
    programs = {str(tx.message.account_keys[ix.program_id_index]) for ix in tx.message.instructions}
    assert COMPUTE_BUDGET_PROGRAM not in programs
    # The client slot verifies; the sponsor's slot is still empty.
    verify_required_signatures(tx, unsigned=Pubkey.from_string(fee_payer))


@pytest.mark.parametrize(
    ("versions", "max_version", "expected"),
    [
        (None, None, 0),
        ([0], None, 0),
        ([1, 0, 1], None, 1),
        (BOTH, 0, 0),
    ],
)
async def test_client_picks_the_highest_version_it_can_sign(versions, max_version, expected):
    offer = _offer(str(Keypair().pubkey()), str(Keypair().pubkey()), versions)
    env = await build_payment(MemorySigner(Keypair()), _Rpc(), offer, max_transaction_version=max_version)
    assert txv1.policy_version(_tx_of(env).message) == expected


@pytest.mark.parametrize(
    ("versions", "max_version"),
    [([], None), ([1], 0), ([2, 1, 0], None), (["1", 0], None), (["legacy"], None), ("0,1", None)],
)
async def test_client_refuses_an_unusable_advertisement(versions, max_version):
    offer = _offer(str(Keypair().pubkey()), str(Keypair().pubkey()), versions)
    with pytest.raises(InvalidChallengeError, match="unsupported_transaction_version"):
        await build_payment(MemorySigner(Keypair()), _Rpc(), offer, max_transaction_version=max_version)


# -- sponsor admission -------------------------------------------------------


def test_accepted_set_comes_from_the_offer():
    assert accepted_transaction_versions({"extra": {}}) == (0,)
    assert accepted_transaction_versions({"extra": {"transactionVersions": BOTH}}) == (0, 1)
    with pytest.raises(ValueError, match="transactionVersions"):
        accepted_transaction_versions({"extra": {"transactionVersions": ["legacy"]}})


def test_version_1_is_accepted_only_when_advertised():
    fee_payer, authority, pay_to = _parties()
    tx = _v1_b64(fee_payer, [_transfer(authority.pubkey(), pay_to), _memo()], [authority])
    assert _verify(tx, fee_payer, pay_to)["transactionVersion"] == 1
    _reject(tx, fee_payer, pay_to, "unsupported_transaction_version", versions=None)
    _reject(tx, fee_payer, pay_to, "unsupported_transaction_version", versions=[0])


def test_version_0_over_the_packet_limit_is_refused():
    fee_payer, authority, pay_to = _parties()
    big = [_memo("x" * 400), _memo("y" * 400), _memo("z" * 400)]
    tx = _v0_b64(
        fee_payer,
        [_budget_ix(2, 20_000, 4), _budget_ix(3, 1, 8), _transfer(authority.pubkey(), pay_to), *big],
        [fee_payer, authority],
    )
    _reject(tx, fee_payer, pay_to, "invalid_exact_svm_payload_transaction")
    # The same payload fits a version-1 transaction (4096 bytes).
    v1 = _v1_b64(fee_payer, [_transfer(authority.pubkey(), pay_to), *big], [authority])
    assert _verify(v1, fee_payer, pay_to)["amount"] == AMOUNT


@pytest.mark.parametrize(
    ("config", "extra_ixs", "code"),
    [
        ({}, [_budget_ix(2, 20_000, 4)], "invalid_exact_svm_payload_transaction_v1_compute_budget_instruction"),
        ({"heap_size": 64 * 1024}, [], "invalid_exact_svm_payload_transaction_v1_heap_size"),
        (
            {"compute_unit_limit": None},
            [],
            "invalid_exact_svm_payload_transaction_instructions_compute_limit_instruction",
        ),
        (
            {"loaded_accounts_data_size_limit": None},
            [],
            "invalid_exact_svm_payload_transaction_loaded_accounts_data_size_limit_missing",
        ),
        (
            {"compute_unit_limit": MAX_COMPUTE_UNIT_LIMIT + 1},
            [],
            "invalid_exact_svm_payload_transaction_instructions_compute_limit_instruction_too_high",
        ),
        (
            {"priority_fee": 2_001},
            [],
            "invalid_exact_svm_payload_transaction_instructions_compute_price_instruction_too_high",
        ),
        ({"loaded_accounts_data_size_limit": 0}, [], "invalid_exact_svm_payload_transaction"),
    ],
)
def test_version_1_header_rules(config, extra_ixs, code):
    fee_payer, authority, pay_to = _parties()
    tx = _v1_b64(
        fee_payer, [*extra_ixs, _transfer(authority.pubkey(), pay_to), _memo()], [authority], _default_config(**config)
    )
    _reject(tx, fee_payer, pay_to, code)


def test_version_1_caps_are_inclusive():
    fee_payer, authority, pay_to = _parties()
    config = _default_config(compute_unit_limit=MAX_COMPUTE_UNIT_LIMIT, priority_fee=2_000)
    tx = _v1_b64(fee_payer, [_transfer(authority.pubkey(), pay_to), _memo()], [authority], config)
    assert _verify(tx, fee_payer, pay_to)["amount"] == AMOUNT


def test_version_0_compute_unit_limit_is_capped():
    fee_payer, authority, pay_to = _parties()
    tx = _v0_b64(
        fee_payer,
        [_budget_ix(2, MAX_COMPUTE_UNIT_LIMIT + 1, 4), _budget_ix(3, 1, 8), _transfer(authority.pubkey(), pay_to)],
        [fee_payer, authority],
    )
    _reject(
        tx, fee_payer, pay_to, "invalid_exact_svm_payload_transaction_instructions_compute_limit_instruction_too_high"
    )


def test_version_0_priority_fee_is_bounded_as_limit_times_price():
    # Each factor is under its own cap, the product is not (RULINGS S6).
    fee_payer, authority, pay_to = _parties()
    tx = _v0_b64(
        fee_payer,
        # 400_000 units x 10_000 microlamports = 4_000 lamports > 2_000.
        [_budget_ix(2, 400_000, 4), _budget_ix(3, 10_000, 8), _transfer(authority.pubkey(), pay_to)],
        [fee_payer, authority],
    )
    _reject(
        tx, fee_payer, pay_to, "invalid_exact_svm_payload_transaction_instructions_compute_price_instruction_too_high"
    )


def test_only_the_fee_payer_and_the_authority_may_sign():
    fee_payer, authority, pay_to = _parties()
    third = Keypair()
    memo = Instruction(
        Pubkey.from_string(MEMO_PROGRAM), b"nonce-0123456789", [AccountMeta(third.pubkey(), True, False)]
    )
    tx = _v1_b64(fee_payer, [_transfer(authority.pubkey(), pay_to), memo], [authority, third])
    _reject(tx, fee_payer, pay_to, "invalid_exact_svm_payload_transaction_unexpected_signer")


def test_the_fee_payer_may_not_be_invoked_as_a_program():
    fee_payer, authority, pay_to = _parties()
    drain = Instruction(fee_payer.pubkey(), b"\x00", [])
    tx = _v1_b64(fee_payer, [_transfer(authority.pubkey(), pay_to), drain], [authority])
    _reject(tx, fee_payer, pay_to, "invalid_exact_svm_payload_transaction_fee_payer_in_instruction_accounts")


# -- sponsor co-signing ------------------------------------------------------


async def test_sponsor_cosigns_a_version_1_credential():
    fee_payer = MemorySigner(Keypair())
    offer = _offer(str(fee_payer.pubkey), str(Keypair().pubkey()), BOTH)
    header = await build_payment_header(MemorySigner(Keypair()), _Rpc(), offer)
    verified = await verify_exact_credential(header, offer, fee_payer, require_payment_identifier=False)
    tx = txv1.decode_transaction(verified.cosigned_wire)
    assert isinstance(tx, txv1.TransactionV1)
    assert tx.message.account_keys[0] == fee_payer.pubkey
    verify_required_signatures(tx)


async def test_sponsor_refuses_a_version_1_credential_it_did_not_advertise():
    fee_payer = MemorySigner(Keypair())
    pay_to = str(Keypair().pubkey())
    header = await build_payment_header(MemorySigner(Keypair()), _Rpc(), _offer(str(fee_payer.pubkey), pay_to, BOTH))
    env = json.loads(base64.b64decode(header))
    env["accepted"]["extra"].pop("transactionVersions")
    header = base64.b64encode(json.dumps(env).encode()).decode()
    with pytest.raises(InvalidProofError, match="unsupported_transaction_version"):
        await verify_exact_credential(
            header, _offer(str(fee_payer.pubkey), pay_to), fee_payer, require_payment_identifier=False
        )


# -- configuration -----------------------------------------------------------


def test_config_validates_transaction_versions():
    assert X402Config.model_validate({"transaction_versions": [0, 1]}).transaction_versions == (0, 1)
    assert X402Config(transaction_versions=(1,)).transaction_versions == (1,)
    assert X402Config().transaction_versions is None
    for bad in ([], ["legacy"], [2], "0"):
        with pytest.raises(ValueError):
            X402Config.model_validate({"transaction_versions": bad})


@pytest.fixture
def _clean(monkeypatch):
    reset()
    monkeypatch.setenv("PAY_KIT_DISABLE_PREFLIGHT", "1")
    yield
    reset()


@pytest.mark.usefixtures("_clean")
@pytest.mark.parametrize(("versions", "advertised"), [(None, None), ((0,), None), ((0, 1), [0, 1])])
def test_adapter_advertises_non_default_versions(versions, advertised):
    cfg = configure(network="solana_localnet", preflight=False)
    cfg = cfg.model_copy(update={"x402": X402Config(transaction_versions=versions)})
    gate = Gate.build(
        name="report",
        amount=Price.usd("0.10", Stablecoin.USDC),
        default_pay_to=cfg.effective_recipient(),
        accept=(Protocol.X402,),
    )
    entry = X402Adapter(cfg).accepts_entry(gate, {"path": "/report"})
    assert entry["extra"].get("transactionVersions") == advertised
