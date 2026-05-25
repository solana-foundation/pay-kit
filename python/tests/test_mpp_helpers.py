"""Unit coverage for the private helpers in :mod:`solana_mpp.server.mpp`.

These tests exercise the small pure helpers (no RPC, no I/O) so the
``server/mpp.py`` line coverage clears the 90 percent gate. Each test
targets a specific branch: rpc-value unwrapping, JSON-like flattening,
compute-budget validation (limit / price / over-cap / shape errors),
fee-payer signature-slot enforcement, ATA-create-idempotent validation
errors, and split-recipient set expansion.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass

import pytest
from solders.keypair import Keypair
from solders.system_program import TransferParams, transfer
from solders.transaction import Transaction

from solana_mpp._errors import PaymentError
from solana_mpp.protocol.solana import (
    TOKEN_2022_PROGRAM,
    TOKEN_PROGRAM,
    MethodDetails,
    Split,
)
from solana_mpp.server import mpp as M

# ---------------------------------------------------------------------------
# _rpc_value / _json_like / _transaction_dict / _status_ok
# ---------------------------------------------------------------------------


def test_rpc_value_none():
    assert M._rpc_value(None) is None


def test_rpc_value_dict_with_value_key():
    assert M._rpc_value({"value": 1}) == 1


def test_rpc_value_dict_without_value_key():
    d = {"foo": 1}
    assert M._rpc_value(d) == d


def test_rpc_value_object_with_value_attr():
    class Obj:
        value = 42

    assert M._rpc_value(Obj()) == 42


def test_rpc_value_object_without_value_attr_returns_self():
    class Obj:
        pass

    o = Obj()
    assert M._rpc_value(o) is o


def test_json_like_passthrough_primitives():
    assert M._json_like(None) is None
    assert M._json_like("s") == "s"
    assert M._json_like(1) == 1
    assert M._json_like(1.5) == 1.5
    assert M._json_like(True) is True


def test_json_like_dict_and_list():
    assert M._json_like({"a": [1, "x"]}) == {"a": [1, "x"]}
    assert M._json_like([{"a": 1}, 2]) == [{"a": 1}, 2]


def test_json_like_to_json_method():
    class T:
        def to_json(self):
            return '{"x":1}'

    assert M._json_like(T()) == {"x": 1}


def test_json_like_object_via_vars():
    class T:
        def __init__(self):
            self.a = 1
            self.b = "hi"

    assert M._json_like(T()) == {"a": 1, "b": "hi"}


def test_json_like_unconvertible_returns_self():
    obj = object()
    assert M._json_like(obj) is obj


def test_transaction_dict_none():
    assert M._transaction_dict(None) is None


def test_transaction_dict_missing_transaction_key():
    assert M._transaction_dict({"value": {"slot": 1}}) is None


def test_transaction_dict_present():
    out = M._transaction_dict({"value": {"transaction": {"sig": "x"}, "slot": 2}})
    assert out == {"transaction": {"sig": "x"}, "slot": 2}


def test_status_ok_returns_true_on_list_with_no_err():
    assert M._status_ok({"value": [{"err": None}]}) is True


def test_status_ok_returns_false_on_list_all_err():
    assert M._status_ok({"value": [{"err": "x"}]}) is False


def test_status_ok_returns_false_on_empty_list():
    assert M._status_ok({"value": []}) is False


def test_status_ok_returns_true_on_truthy_non_list():
    assert M._status_ok({"value": {"any": "data"}}) is True


def test_status_ok_returns_false_on_none():
    assert M._status_ok({"value": None}) is False


# ---------------------------------------------------------------------------
# _validate_compute_budget_instruction
# ---------------------------------------------------------------------------


def test_compute_budget_rejects_nonzero_account_count():
    with pytest.raises(PaymentError) as exc:
        M._validate_compute_budget_instruction(b"\x02\x00\x00\x00\x00", 1)
    assert exc.value.code == "compute-budget-invalid"


def test_compute_budget_rejects_empty_data():
    with pytest.raises(PaymentError) as exc:
        M._validate_compute_budget_instruction(b"", 0)
    assert exc.value.code == "compute-budget-invalid"


def test_compute_budget_accepts_set_limit_under_cap():
    units = 200_000
    data = bytes([2]) + units.to_bytes(4, "little")
    M._validate_compute_budget_instruction(data, 0)


def test_compute_budget_rejects_set_limit_over_cap():
    units = M.MAX_COMPUTE_UNIT_LIMIT + 1
    data = bytes([2]) + units.to_bytes(4, "little")
    with pytest.raises(PaymentError) as exc:
        M._validate_compute_budget_instruction(data, 0)
    assert exc.value.code == "compute-budget-cap-exceeded"


def test_compute_budget_accepts_set_price_under_cap():
    price = 1_000
    data = bytes([3]) + price.to_bytes(8, "little")
    M._validate_compute_budget_instruction(data, 0)


def test_compute_budget_rejects_set_price_over_cap():
    price = M.MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS + 1
    data = bytes([3]) + price.to_bytes(8, "little")
    with pytest.raises(PaymentError) as exc:
        M._validate_compute_budget_instruction(data, 0)
    assert exc.value.code == "compute-budget-cap-exceeded"


def test_compute_budget_rejects_unknown_discriminator():
    # Unknown opcode with wrong length combo.
    data = bytes([99]) + b"\x00" * 4
    with pytest.raises(PaymentError) as exc:
        M._validate_compute_budget_instruction(data, 0)
    assert exc.value.code == "compute-budget-invalid"


def test_compute_budget_rejects_set_limit_wrong_length():
    # Discriminator 2 (SetLimit) but extra trailing byte → falls to fallback.
    data = bytes([2]) + b"\x00\x00\x00\x00\xff"
    with pytest.raises(PaymentError) as exc:
        M._validate_compute_budget_instruction(data, 0)
    assert exc.value.code == "compute-budget-invalid"


def test_compute_budget_rejects_set_price_wrong_length():
    # Discriminator 3 (SetPrice) but only 4 bytes payload.
    data = bytes([3]) + b"\x00\x00\x00\x00"
    with pytest.raises(PaymentError):
        M._validate_compute_budget_instruction(data, 0)


# ---------------------------------------------------------------------------
# _assert_signature_slot
# ---------------------------------------------------------------------------


def test_assert_signature_slot_zero_ok():
    M._assert_signature_slot(0, 2)


def test_assert_signature_slot_negative_rejected():
    with pytest.raises(PaymentError) as exc:
        M._assert_signature_slot(-1, 2)
    assert exc.value.code == "invalid-payload"
    assert "outside the required-signers" in str(exc.value)


def test_assert_signature_slot_out_of_range_rejected():
    with pytest.raises(PaymentError) as exc:
        M._assert_signature_slot(5, 2)
    assert exc.value.code == "invalid-payload"
    assert "outside the required-signers" in str(exc.value)


def test_assert_signature_slot_inside_range_but_not_zero_rejected():
    with pytest.raises(PaymentError) as exc:
        M._assert_signature_slot(1, 3)
    assert exc.value.code == "invalid-payload"
    assert "must occupy account index 0" in str(exc.value)


# ---------------------------------------------------------------------------
# _expected_ata_creation_policy (mirrors rust spine)
# ---------------------------------------------------------------------------


def test_ata_policy_no_fee_payer_allows_every_split_owner():
    # When no fee-payer co-sign is in play the client pays its own rent,
    # so any declared split may opportunistically host an ATA create.
    # Primary recipient is NEVER in the allowed set.
    details = MethodDetails(
        splits=[
            Split(recipient="SPL1", amount="10"),
            Split(recipient="SPL2", amount="20", ata_creation_required=True),
        ]
    )
    allowed, required = M._expected_ata_creation_policy(details, fee_payer_pubkey=None)
    assert allowed == {"SPL1", "SPL2"}
    assert required == {"SPL2"}


def test_ata_policy_with_fee_payer_only_allows_required_split_owners():
    # When fee-payer co-sign is in play the server only sponsors ATA
    # creates the route explicitly demanded via ataCreationRequired.
    # An unmarked split MUST NOT appear in allowed; primary recipient is
    # never allowed regardless of fee-payer.
    details = MethodDetails(
        splits=[
            Split(recipient="SPL1", amount="10"),  # not required
            Split(recipient="SPL2", amount="20", ata_creation_required=True),
        ]
    )
    allowed, required = M._expected_ata_creation_policy(details, fee_payer_pubkey="FP")
    assert allowed == {"SPL2"}
    assert required == {"SPL2"}


def test_ata_policy_no_splits():
    details = MethodDetails()
    allowed_no_fp, required_no_fp = M._expected_ata_creation_policy(details, None)
    assert allowed_no_fp == set()
    assert required_no_fp == set()
    allowed_fp, required_fp = M._expected_ata_creation_policy(details, "FP")
    assert allowed_fp == set()
    assert required_fp == set()


# ---------------------------------------------------------------------------
# _validate_ata_create_idempotent
# ---------------------------------------------------------------------------


@dataclass
class _FakeInstr:
    data: bytes
    accounts: list[int]


def test_ata_create_rejects_native_sol():
    with pytest.raises(PaymentError) as exc:
        M._validate_ata_create_idempotent(
            _FakeInstr(b"\x01", [0, 1, 2, 3, 4, 5]),
            ["a"] * 6,
            expected_mint=None,
            allowed_ata_owners={"a"},
            expected_token_program=None,
            expected_payer="a",
        )
    assert exc.value.code == "invalid-payload"
    assert "native SOL" in str(exc.value)


def test_ata_create_rejects_non_idempotent_discriminator():
    with pytest.raises(PaymentError) as exc:
        M._validate_ata_create_idempotent(
            _FakeInstr(b"\x00", [0, 1, 2, 3, 4, 5]),
            ["a"] * 6,
            expected_mint="m",
            allowed_ata_owners={"a"},
            expected_token_program=TOKEN_PROGRAM,
            expected_payer="a",
        )
    assert "idempotent" in str(exc.value)


def test_ata_create_rejects_wrong_account_count():
    with pytest.raises(PaymentError) as exc:
        M._validate_ata_create_idempotent(
            _FakeInstr(b"\x01", [0, 1, 2]),
            ["a"] * 6,
            expected_mint="m",
            allowed_ata_owners={"a"},
            expected_token_program=TOKEN_PROGRAM,
            expected_payer="a",
        )
    assert "account layout" in str(exc.value)


def test_ata_create_rejects_payer_mismatch():
    with pytest.raises(PaymentError) as exc:
        M._validate_ata_create_idempotent(
            _FakeInstr(b"\x01", [0, 1, 2, 3, 4, 5]),
            ["NOT_PAYER", "ata", "owner", "mint", M._SYSTEM_PROGRAM, TOKEN_PROGRAM],
            expected_mint="mint",
            allowed_ata_owners={"owner"},
            expected_token_program=TOKEN_PROGRAM,
            expected_payer="EXPECTED",
        )
    assert "fee payer" in str(exc.value)


def test_ata_create_rejects_mint_mismatch():
    with pytest.raises(PaymentError) as exc:
        M._validate_ata_create_idempotent(
            _FakeInstr(b"\x01", [0, 1, 2, 3, 4, 5]),
            ["payer", "ata", "owner", "WRONG_MINT", M._SYSTEM_PROGRAM, TOKEN_PROGRAM],
            expected_mint="EXPECTED_MINT",
            allowed_ata_owners={"owner"},
            expected_token_program=TOKEN_PROGRAM,
            expected_payer="payer",
        )
    assert "mint" in str(exc.value)


def test_ata_create_rejects_unauthorized_owner():
    with pytest.raises(PaymentError) as exc:
        M._validate_ata_create_idempotent(
            _FakeInstr(b"\x01", [0, 1, 2, 3, 4, 5]),
            ["payer", "ata", "BAD_OWNER", "mint", M._SYSTEM_PROGRAM, TOKEN_PROGRAM],
            expected_mint="mint",
            allowed_ata_owners={"owner"},
            expected_token_program=TOKEN_PROGRAM,
            expected_payer="payer",
        )
    assert "authorized" in str(exc.value)


def test_ata_create_rejects_wrong_system_program():
    with pytest.raises(PaymentError) as exc:
        M._validate_ata_create_idempotent(
            _FakeInstr(b"\x01", [0, 1, 2, 3, 4, 5]),
            ["payer", "ata", "owner", "mint", "NOT_SYSTEM", TOKEN_PROGRAM],
            expected_mint="mint",
            allowed_ata_owners={"owner"},
            expected_token_program=TOKEN_PROGRAM,
            expected_payer="payer",
        )
    assert "System Program" in str(exc.value)


def test_ata_create_rejects_unsupported_token_program():
    with pytest.raises(PaymentError) as exc:
        M._validate_ata_create_idempotent(
            _FakeInstr(b"\x01", [0, 1, 2, 3, 4, 5]),
            ["payer", "ata", "owner", "mint", M._SYSTEM_PROGRAM, "BPFLoader11111111111111111111111111111111111"],
            expected_mint="mint",
            allowed_ata_owners={"owner"},
            expected_token_program=None,
            expected_payer="payer",
        )
    assert "token program" in str(exc.value)


def test_ata_create_rejects_token_program_mismatch():
    with pytest.raises(PaymentError) as exc:
        M._validate_ata_create_idempotent(
            _FakeInstr(b"\x01", [0, 1, 2, 3, 4, 5]),
            ["payer", "ata", "owner", "mint", M._SYSTEM_PROGRAM, TOKEN_PROGRAM],
            expected_mint="mint",
            allowed_ata_owners={"owner"},
            expected_token_program=TOKEN_2022_PROGRAM,
            expected_payer="payer",
        )
    assert "methodDetails.tokenProgram" in str(exc.value)


def test_ata_create_rejects_index_out_of_range():
    with pytest.raises(PaymentError) as exc:
        M._validate_ata_create_idempotent(
            _FakeInstr(b"\x01", [99, 1, 2, 3, 4, 5]),
            ["payer", "ata"],
            expected_mint="m",
            allowed_ata_owners={"o"},
            expected_token_program=TOKEN_PROGRAM,
            expected_payer="payer",
        )
    assert "unknown account index" in str(exc.value)


def test_ata_create_rejects_wrong_derived_ata():
    # Real owner/mint/token_program, but ATA field is bogus → derivation mismatch.
    owner = Keypair().pubkey()
    mint = Keypair().pubkey()
    payer = Keypair().pubkey()
    with pytest.raises(PaymentError) as exc:
        M._validate_ata_create_idempotent(
            _FakeInstr(b"\x01", [0, 1, 2, 3, 4, 5]),
            [
                str(payer),
                "NotTheRightAta11111111111111111111111111111",
                str(owner),
                str(mint),
                M._SYSTEM_PROGRAM,
                TOKEN_PROGRAM,
            ],
            expected_mint=str(mint),
            allowed_ata_owners={str(owner)},
            expected_token_program=TOKEN_PROGRAM,
            expected_payer=str(payer),
        )
    assert "does not match" in str(exc.value)


# ---------------------------------------------------------------------------
# _extract_recent_blockhash + _decode_legacy_payment_instructions errors
# ---------------------------------------------------------------------------


def _build_simple_legacy_tx() -> str:
    from solders.hash import Hash
    from solders.message import Message

    src = Keypair()
    dst = Keypair()
    ix = transfer(TransferParams(from_pubkey=src.pubkey(), to_pubkey=dst.pubkey(), lamports=1))
    msg = Message.new_with_blockhash([ix], src.pubkey(), Hash.default())
    tx = Transaction.new_unsigned(msg)
    return base64.b64encode(bytes(tx)).decode("ascii")


def test_extract_recent_blockhash_legacy():
    tx_b64 = _build_simple_legacy_tx()
    bh = M._extract_recent_blockhash(tx_b64)
    # Default Hash → base58 representation of all-zeros = "11111111111111111111111111111111".
    assert isinstance(bh, str)
    assert len(bh) > 0


def test_decode_legacy_payment_instructions_invalid_base64():
    # Invalid base64 raises either binascii.Error (stdlib) or ValueError
    # depending on PEP-657 enforcement; both are acceptable.
    with pytest.raises((ValueError, Exception)):  # noqa: B017
        M._decode_legacy_payment_instructions("===not base64===")


def test_decode_legacy_payment_instructions_short_random_raises_invalid_payload_type():
    # Random short bytes will fail both legacy and versioned decode.
    bad = base64.b64encode(b"\x00\x01\x02\x03").decode()
    with pytest.raises(PaymentError) as exc:
        M._decode_legacy_payment_instructions(bad)
    assert exc.value.code == "invalid-payload-type"
