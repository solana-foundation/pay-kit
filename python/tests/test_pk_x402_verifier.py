"""x402 ``exact`` 11-rule structural verifier coverage.

Builds real ``VersionedTransaction`` payloads with solders and exercises each
of the verifier's reject branches by name, plus the happy path with an optional
memo, a Lighthouse optional instruction, and the Token-2022 program. ATA-create
is explicitly rejected (149-3). Also covers the adapter's ``accepts_entry`` /
``challenge_headers`` and the caveat #5 ``recentBlockhash`` injection via the
offline ``recent_blockhash_provider``.
"""

from __future__ import annotations

import base64
import struct

import pytest
from solders.hash import Hash
from solders.instruction import AccountMeta, Instruction
from solders.keypair import Keypair
from solders.message import MessageV0
from solders.pubkey import Pubkey
from solders.transaction import VersionedTransaction

from pay_kit import Gate, Price, Protocol, Stablecoin, configure
from pay_kit._paycore.mints import derive_ata, resolve, token_program_for
from pay_kit._paycore.solana import ASSOCIATED_TOKEN_PROGRAM
from pay_kit.config import reset
from pay_kit.errors import InvalidProofError
from pay_kit.protocols.x402 import ExactVerifier, X402Adapter
from pay_kit.protocols.x402.exact.verify import (
    COMPUTE_BUDGET_PROGRAM,
    MEMO_PROGRAM,
    TOKEN_2022_PROGRAM,
)

BH = "4vJ9JU1bJJQpUgJ8V6hYz7xXKz4F2tN6aBrZEcD3xKhs"
_MINT = resolve("USDC", "mainnet")
assert _MINT is not None
MINT: str = _MINT
TOKEN_PROGRAM = token_program_for("USDC", "mainnet")
AMOUNT = 100_000


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    reset()
    monkeypatch.setenv("PAY_KIT_DISABLE_PREFLIGHT", "1")
    yield
    reset()


# -- transaction builders ----------------------------------------------------


def _compute_limit_ix(disc: int = 2, length: int = 5, program: str = COMPUTE_BUDGET_PROGRAM) -> Instruction:
    data = bytes([disc]) + struct.pack("<I", 200_000)
    if length != 5:
        data = data[:length].ljust(length, b"\x00")
    return Instruction(Pubkey.from_string(program), data, [])


def _compute_price_ix(micro: int = 1_000, disc: int = 3, program: str = COMPUTE_BUDGET_PROGRAM) -> Instruction:
    data = bytes([disc]) + struct.pack("<Q", micro)
    return Instruction(Pubkey.from_string(program), data, [])


def _transfer_checked_ix(
    *,
    source: str,
    mint: str,
    destination: str,
    authority: Pubkey,
    amount: int = AMOUNT,
    program: str = TOKEN_PROGRAM,
    disc: int = 12,
    n_accounts: int = 4,
) -> Instruction:
    data = bytes([disc]) + struct.pack("<Q", amount) + bytes([6])
    metas = [
        AccountMeta(Pubkey.from_string(source), False, True),
        AccountMeta(Pubkey.from_string(mint), False, False),
        AccountMeta(Pubkey.from_string(destination), False, True),
        AccountMeta(authority, True, False),
    ]
    return Instruction(Pubkey.from_string(program), data, metas[:n_accounts])


def _memo_ix(text: str) -> Instruction:
    return Instruction(Pubkey.from_string(MEMO_PROGRAM), text.encode(), [])


def _ata_create_ix(*, payer: Pubkey, ata: str, owner: str, mint: str, program: str) -> Instruction:
    metas = [
        AccountMeta(payer, True, True),
        AccountMeta(Pubkey.from_string(ata), False, True),
        AccountMeta(Pubkey.from_string(owner), False, False),
        AccountMeta(Pubkey.from_string(mint), False, False),
        AccountMeta(Pubkey.from_string("11111111111111111111111111111111"), False, False),
        AccountMeta(Pubkey.from_string(program), False, False),
    ]
    return Instruction(Pubkey.from_string(ASSOCIATED_TOKEN_PROGRAM), bytes([1]), metas)


def _tx_b64(fee_payer: Keypair, instructions, signers) -> str:
    msg = MessageV0.try_compile(fee_payer.pubkey(), instructions, [], Hash.from_string(BH))
    vtx = VersionedTransaction(msg, signers)
    return base64.b64encode(bytes(vtx)).decode("ascii")


def _scenario(*, program: str = TOKEN_PROGRAM, mint: str = MINT):
    """Return (fee_payer, authority, pay_to, src, dest) for a transfer."""
    fee_payer = Keypair()
    authority = Keypair()
    pay_to = str(Keypair().pubkey())
    dest = derive_ata(pay_to, mint, program)
    src = derive_ata(str(authority.pubkey()), mint, program)
    return fee_payer, authority, pay_to, src, dest


def _requirement(pay_to: str, *, mint: str = MINT, program: str = TOKEN_PROGRAM, memo: str | None = None):
    extra = {"tokenProgram": program, "decimals": 6}
    if memo is not None:
        extra["memo"] = memo
    return {
        "asset": mint,
        "amount": str(AMOUNT),
        "maxAmountRequired": str(AMOUNT),
        "payTo": pay_to,
        "extra": extra,
    }


def _happy(*, program: str = TOKEN_PROGRAM, mint: str = MINT, memo: str | None = None, extra_ixs=()):
    fee_payer, authority, pay_to, src, dest = _scenario(program=program, mint=mint)
    ixs = [
        _compute_limit_ix(),
        _compute_price_ix(),
        _transfer_checked_ix(source=src, mint=mint, destination=dest, authority=authority.pubkey(), program=program),
        *extra_ixs,
    ]
    if memo is not None:
        ixs.append(_memo_ix(memo))
    tx = _tx_b64(fee_payer, ixs, [fee_payer, authority])
    return tx, _requirement(pay_to, mint=mint, program=program, memo=memo), [str(fee_payer.pubkey())]


# -- happy paths -------------------------------------------------------------


def test_verify_happy_path():
    tx, req, managed = _happy()
    out = ExactVerifier.verify(tx, req, managed)
    assert out["amount"] == AMOUNT
    assert out["mint"] == MINT
    assert out["destinationCreateAta"] is False


def test_verify_happy_with_memo_binding():
    tx, req, managed = _happy(memo="/report")
    out = ExactVerifier.verify(tx, req, managed)
    assert out["amount"] == AMOUNT


def test_verify_happy_with_token_2022_program():
    tx, req, managed = _happy(program=TOKEN_2022_PROGRAM)
    out = ExactVerifier.verify(tx, req, managed)
    assert out["program"] == TOKEN_2022_PROGRAM


def test_verify_rejects_ata_create_instruction():
    """149-3: ATA-create is NOT an allowed optional instruction.

    Per the official x402 SVM exact contract the destination ATA MUST
    pre-exist; only Lighthouse and Memo are permitted optional slots. A
    transaction carrying an Associated-Token-Program create instruction must
    be rejected, matching the Rust/Go verifiers.
    """
    fee_payer, authority, pay_to, src, dest = _scenario()
    ixs = [
        _compute_limit_ix(),
        _compute_price_ix(),
        _transfer_checked_ix(source=src, mint=MINT, destination=dest, authority=authority.pubkey()),
        _ata_create_ix(payer=fee_payer.pubkey(), ata=dest, owner=pay_to, mint=MINT, program=TOKEN_PROGRAM),
    ]
    tx = _tx_b64(fee_payer, ixs, [fee_payer, authority])
    with pytest.raises(InvalidProofError) as e:
        ExactVerifier.verify(tx, _requirement(pay_to), [str(fee_payer.pubkey())])
    assert e.value.code == "invalid_exact_svm_payload_unknown_fourth_instruction"


def test_verify_allows_lighthouse_optional_instruction():
    """Lighthouse asserts are wallet-injected and MUST be allowed."""
    from pay_kit.protocols.x402.exact.verify import LIGHTHOUSE_PROGRAM

    fee_payer, authority, pay_to, src, dest = _scenario()
    lighthouse = Instruction(Pubkey.from_string(LIGHTHOUSE_PROGRAM), b"\x00", [])
    ixs = [
        _compute_limit_ix(),
        _compute_price_ix(),
        _transfer_checked_ix(source=src, mint=MINT, destination=dest, authority=authority.pubkey()),
        lighthouse,
    ]
    tx = _tx_b64(fee_payer, ixs, [fee_payer, authority])
    out = ExactVerifier.verify(tx, _requirement(pay_to), [str(fee_payer.pubkey())])
    assert out["destinationCreateAta"] is False


def test_verify_allows_lighthouse_in_last_optional_slot():
    """Regression: Lighthouse MUST be accepted in ANY optional slot, not just the first.

    Exercises the maximum-slot layout [ComputeUnitLimit, ComputeUnitPrice,
    transferChecked, Memo, Lighthouse, Lighthouse] so that Lighthouse sits at
    instruction index 4 (slot_index 1) and instruction index 5 (slot_index 2).
    The old ``slot_index < 2`` guard wrongly rejected Lighthouse at slot_index 2.
    """
    from pay_kit.protocols.x402.exact.verify import LIGHTHOUSE_PROGRAM

    fee_payer, authority, pay_to, src, dest = _scenario()
    lighthouse = Instruction(Pubkey.from_string(LIGHTHOUSE_PROGRAM), b"\x00", [])

    # Lighthouse at i=4 (slot_index 1)
    ixs_slot1 = [
        _compute_limit_ix(),
        _compute_price_ix(),
        _transfer_checked_ix(source=src, mint=MINT, destination=dest, authority=authority.pubkey()),
        _memo_ix("/pay"),
        lighthouse,
    ]
    tx_slot1 = _tx_b64(fee_payer, ixs_slot1, [fee_payer, authority])
    out1 = ExactVerifier.verify(tx_slot1, _requirement(pay_to, memo="/pay"), [str(fee_payer.pubkey())])
    assert out1["destinationCreateAta"] is False

    # Lighthouse at i=5 (slot_index 2) — the last permitted optional slot.
    ixs_slot2 = [
        _compute_limit_ix(),
        _compute_price_ix(),
        _transfer_checked_ix(source=src, mint=MINT, destination=dest, authority=authority.pubkey()),
        _memo_ix("/pay"),
        lighthouse,
        lighthouse,
    ]
    tx_slot2 = _tx_b64(fee_payer, ixs_slot2, [fee_payer, authority])
    out2 = ExactVerifier.verify(tx_slot2, _requirement(pay_to, memo="/pay"), [str(fee_payer.pubkey())])
    assert out2["destinationCreateAta"] is False


# -- rule 0: payload decode --------------------------------------------------


def test_reject_non_base64():
    with pytest.raises(InvalidProofError) as e:
        ExactVerifier.verify("!!!notbase64!!!", _requirement("x"), [])
    assert e.value.code == "invalid_exact_svm_payload_base64"


def test_reject_empty_payload():
    with pytest.raises(InvalidProofError) as e:
        ExactVerifier.verify(base64.b64encode(b"").decode(), _requirement("x"), [])
    assert e.value.code == "invalid_exact_svm_payload_base64"


def test_reject_unparseable_transaction():
    with pytest.raises(InvalidProofError) as e:
        ExactVerifier.verify(base64.b64encode(b"\x01\x02\x03\x04").decode(), _requirement("x"), [])
    assert e.value.code == "invalid_exact_svm_payload_transaction_parse"


# -- rule 1: instruction count ----------------------------------------------


def test_reject_too_few_instructions():
    fee_payer, authority, pay_to, src, dest = _scenario()
    tx = _tx_b64(fee_payer, [_compute_limit_ix(), _compute_price_ix()], [fee_payer])
    with pytest.raises(InvalidProofError) as e:
        ExactVerifier.verify(tx, _requirement(pay_to), [str(fee_payer.pubkey())])
    assert e.value.code == "invalid_exact_svm_payload_transaction_instructions_length"


def test_reject_too_many_instructions():
    fee_payer, authority, pay_to, src, dest = _scenario()
    ixs = [
        _compute_limit_ix(),
        _compute_price_ix(),
        _transfer_checked_ix(source=src, mint=MINT, destination=dest, authority=authority.pubkey()),
    ] + [_memo_ix(f"m{i}") for i in range(4)]
    tx = _tx_b64(fee_payer, ixs, [fee_payer, authority])
    with pytest.raises(InvalidProofError) as e:
        ExactVerifier.verify(tx, _requirement(pay_to), [str(fee_payer.pubkey())])
    assert e.value.code == "invalid_exact_svm_payload_transaction_instructions_length"


# -- rule 2: compute limit ---------------------------------------------------


def test_reject_bad_compute_limit():
    fee_payer, authority, pay_to, src, dest = _scenario()
    ixs = [
        _compute_limit_ix(disc=9),  # wrong discriminator
        _compute_price_ix(),
        _transfer_checked_ix(source=src, mint=MINT, destination=dest, authority=authority.pubkey()),
    ]
    tx = _tx_b64(fee_payer, ixs, [fee_payer, authority])
    with pytest.raises(InvalidProofError) as e:
        ExactVerifier.verify(tx, _requirement(pay_to), [str(fee_payer.pubkey())])
    assert e.value.code == "invalid_exact_svm_payload_transaction_instructions_compute_limit_instruction"


# -- rule 3: compute price ---------------------------------------------------


def test_reject_bad_compute_price_disc():
    fee_payer, authority, pay_to, src, dest = _scenario()
    ixs = [
        _compute_limit_ix(),
        _compute_price_ix(disc=7),
        _transfer_checked_ix(source=src, mint=MINT, destination=dest, authority=authority.pubkey()),
    ]
    tx = _tx_b64(fee_payer, ixs, [fee_payer, authority])
    with pytest.raises(InvalidProofError) as e:
        ExactVerifier.verify(tx, _requirement(pay_to), [str(fee_payer.pubkey())])
    assert e.value.code == "invalid_exact_svm_payload_transaction_instructions_compute_price_instruction"


def test_reject_compute_price_too_high():
    fee_payer, authority, pay_to, src, dest = _scenario()
    ixs = [
        _compute_limit_ix(),
        _compute_price_ix(micro=5_000_001),  # MAX is 5_000_000
        _transfer_checked_ix(source=src, mint=MINT, destination=dest, authority=authority.pubkey()),
    ]
    tx = _tx_b64(fee_payer, ixs, [fee_payer, authority])
    with pytest.raises(InvalidProofError) as e:
        ExactVerifier.verify(tx, _requirement(pay_to), [str(fee_payer.pubkey())])
    assert e.value.code == "invalid_exact_svm_payload_transaction_instructions_compute_price_instruction_too_high"


# -- rule 4 + 11: transfer shape + token program ----------------------------


def test_reject_wrong_token_program():
    fee_payer, authority, pay_to, src, dest = _scenario()
    bogus = str(Keypair().pubkey())
    ixs = [
        _compute_limit_ix(),
        _compute_price_ix(),
        _transfer_checked_ix(source=src, mint=MINT, destination=dest, authority=authority.pubkey(), program=bogus),
    ]
    tx = _tx_b64(fee_payer, ixs, [fee_payer, authority])
    with pytest.raises(InvalidProofError) as e:
        ExactVerifier.verify(tx, _requirement(pay_to), [str(fee_payer.pubkey())])
    assert e.value.code == "invalid_exact_svm_payload_no_transfer_instruction"


def test_reject_bad_transfer_discriminator():
    fee_payer, authority, pay_to, src, dest = _scenario()
    ixs = [
        _compute_limit_ix(),
        _compute_price_ix(),
        _transfer_checked_ix(source=src, mint=MINT, destination=dest, authority=authority.pubkey(), disc=3),
    ]
    tx = _tx_b64(fee_payer, ixs, [fee_payer, authority])
    with pytest.raises(InvalidProofError) as e:
        ExactVerifier.verify(tx, _requirement(pay_to), [str(fee_payer.pubkey())])
    assert e.value.code == "invalid_exact_svm_payload_no_transfer_instruction"


def test_reject_missing_token_program_extra():
    tx, req, managed = _happy()
    del req["extra"]["tokenProgram"]
    with pytest.raises(InvalidProofError) as e:
        ExactVerifier.verify(tx, req, managed)
    assert e.value.code == "invalid_exact_svm_payload_missing_extra_tokenProgram"


# -- rule 5: managed-signer guard --------------------------------------------


def test_reject_fee_payer_as_authority():
    fee_payer, _authority, pay_to, src, dest = _scenario()
    # fee_payer signs as the transfer authority -> managed signer transferring.
    src_fp = derive_ata(str(fee_payer.pubkey()), MINT, TOKEN_PROGRAM)
    ixs = [
        _compute_limit_ix(),
        _compute_price_ix(),
        _transfer_checked_ix(source=src_fp, mint=MINT, destination=dest, authority=fee_payer.pubkey()),
    ]
    tx = _tx_b64(fee_payer, ixs, [fee_payer])
    with pytest.raises(InvalidProofError) as e:
        ExactVerifier.verify(tx, _requirement(pay_to), [str(fee_payer.pubkey())])
    assert e.value.code == "invalid_exact_svm_payload_transaction_fee_payer_transferring_funds"


# -- rule 6: mint mismatch ---------------------------------------------------


def test_reject_mint_mismatch():
    tx, req, managed = _happy()
    req["asset"] = str(Keypair().pubkey())  # different mint than the tx uses
    with pytest.raises(InvalidProofError) as e:
        ExactVerifier.verify(tx, req, managed)
    assert e.value.code == "invalid_exact_svm_payload_mint_mismatch"


# -- rule 7: destination ATA mismatch ----------------------------------------


def test_reject_destination_mismatch():
    fee_payer, authority, pay_to, src, _dest = _scenario()
    wrong_dest = derive_ata(str(Keypair().pubkey()), MINT, TOKEN_PROGRAM)
    ixs = [
        _compute_limit_ix(),
        _compute_price_ix(),
        _transfer_checked_ix(source=src, mint=MINT, destination=wrong_dest, authority=authority.pubkey()),
    ]
    tx = _tx_b64(fee_payer, ixs, [fee_payer, authority])
    with pytest.raises(InvalidProofError) as e:
        ExactVerifier.verify(tx, _requirement(pay_to), [str(fee_payer.pubkey())])
    assert e.value.code == "invalid_exact_svm_payload_recipient_mismatch"


# -- rule 8: amount mismatch -------------------------------------------------


def test_reject_amount_mismatch():
    fee_payer, authority, pay_to, src, dest = _scenario()
    ixs = [
        _compute_limit_ix(),
        _compute_price_ix(),
        _transfer_checked_ix(source=src, mint=MINT, destination=dest, authority=authority.pubkey(), amount=999),
    ]
    tx = _tx_b64(fee_payer, ixs, [fee_payer, authority])
    with pytest.raises(InvalidProofError) as e:
        ExactVerifier.verify(tx, _requirement(pay_to), [str(fee_payer.pubkey())])
    assert e.value.code == "invalid_exact_svm_payload_amount_mismatch"


def test_amount_from_max_amount_required_field():
    tx, req, managed = _happy()
    del req["amount"]  # only maxAmountRequired remains
    out = ExactVerifier.verify(tx, req, managed)
    assert out["amount"] == AMOUNT


def test_reject_missing_amount_field():
    tx, req, managed = _happy()
    del req["amount"]
    del req["maxAmountRequired"]
    with pytest.raises(InvalidProofError) as e:
        ExactVerifier.verify(tx, req, managed)
    assert e.value.code == "invalid_exact_svm_payload_missing_field_amount"


def test_reject_missing_pay_to_field():
    tx, req, managed = _happy()
    del req["payTo"]
    with pytest.raises(InvalidProofError) as e:
        ExactVerifier.verify(tx, req, managed)
    assert e.value.code == "invalid_exact_svm_payload_missing_field_payTo"


# -- rule 9: optional-instruction allowlist ----------------------------------


def test_reject_unknown_fourth_instruction():
    fee_payer, authority, pay_to, src, dest = _scenario()
    junk = Instruction(Pubkey.from_string(str(Keypair().pubkey())), b"\x00", [])
    ixs = [
        _compute_limit_ix(),
        _compute_price_ix(),
        _transfer_checked_ix(source=src, mint=MINT, destination=dest, authority=authority.pubkey()),
        junk,
    ]
    tx = _tx_b64(fee_payer, ixs, [fee_payer, authority])
    with pytest.raises(InvalidProofError) as e:
        ExactVerifier.verify(tx, _requirement(pay_to), [str(fee_payer.pubkey())])
    assert e.value.code == "invalid_exact_svm_payload_unknown_fourth_instruction"


# -- rule 10: memo binding ---------------------------------------------------


def test_reject_memo_mismatch():
    tx, _req, managed = _happy(memo="/expected")
    # Build a tx with a different memo than the requirement asks for.
    fee_payer, authority, pay_to, src, dest = _scenario()
    ixs = [
        _compute_limit_ix(),
        _compute_price_ix(),
        _transfer_checked_ix(source=src, mint=MINT, destination=dest, authority=authority.pubkey()),
        _memo_ix("/actual-different"),
    ]
    tx2 = _tx_b64(fee_payer, ixs, [fee_payer, authority])
    with pytest.raises(InvalidProofError) as e:
        ExactVerifier.verify(tx2, _requirement(pay_to, memo="/expected"), [str(fee_payer.pubkey())])
    assert e.value.code == "invalid_exact_svm_payload_memo_mismatch"


def test_reject_memo_count_zero_when_expected():
    # requirement expects a memo but the tx has none.
    tx, _req, managed = _happy()  # no memo in tx
    fee_payer, authority, pay_to, src, dest = _scenario()
    ixs = [
        _compute_limit_ix(),
        _compute_price_ix(),
        _transfer_checked_ix(source=src, mint=MINT, destination=dest, authority=authority.pubkey()),
    ]
    tx2 = _tx_b64(fee_payer, ixs, [fee_payer, authority])
    with pytest.raises(InvalidProofError) as e:
        ExactVerifier.verify(tx2, _requirement(pay_to, memo="/required"), [str(fee_payer.pubkey())])
    assert e.value.code == "invalid_exact_svm_payload_memo_count"


# -- adapter: accepts_entry / challenge / recentBlockhash (caveat #5) --------


def _gate(cfg, *, accept=(Protocol.X402, Protocol.MPP)):
    return Gate.build(
        name="report",
        amount=Price.usd("0.10", Stablecoin.USDC),
        default_pay_to=cfg.effective_recipient(),
        accept=accept,
    )


def test_adapter_accepts_entry_shape():
    cfg = configure(network="solana_localnet", preflight=False)
    adapter = X402Adapter(cfg)
    entry = adapter.accepts_entry(_gate(cfg), {"path": "/report"})
    assert entry["protocol"] == "x402"
    assert entry["scheme"] == "exact"
    assert entry["amount"] == str(AMOUNT)
    assert entry["asset"] == MINT  # localnet falls back to mainnet mint (caveat #1)
    assert entry["extra"]["memo"] == "/report"
    assert "recentBlockhash" not in entry["extra"]  # no provider wired


def test_adapter_embeds_recent_blockhash_when_provider_set():
    cfg = configure(network="solana_localnet", preflight=False)
    adapter = X402Adapter(cfg, recent_blockhash_provider=lambda: BH)
    entry = adapter.accepts_entry(_gate(cfg), {"path": "/report"})
    assert entry["extra"].get("recentBlockhash") == BH


def test_adapter_blockhash_provider_failure_is_swallowed():
    cfg = configure(network="solana_localnet", preflight=False)

    def boom():
        raise RuntimeError("rpc down")

    adapter = X402Adapter(cfg, recent_blockhash_provider=boom)
    entry = adapter.accepts_entry(_gate(cfg), {"path": "/report"})
    assert "recentBlockhash" not in entry["extra"]


def test_adapter_challenge_headers_base64():
    cfg = configure(network="solana_localnet", preflight=False)
    adapter = X402Adapter(cfg)
    headers = adapter.challenge_headers(_gate(cfg), {"path": "/report"})
    assert "payment-required" in headers
    decoded = base64.b64decode(headers["payment-required"])
    assert b"accepts" in decoded


def test_adapter_delegated_mode_not_implemented():
    from pay_kit import X402Config

    cfg = configure(network="solana_localnet", preflight=False, x402=X402Config(facilitator_url="https://fac"))
    with pytest.raises(NotImplementedError, match="delegated mode"):
        X402Adapter(cfg)
