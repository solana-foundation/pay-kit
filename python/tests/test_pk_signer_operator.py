"""Signer factory family and Operator default-resolution coverage.

Signer: every factory (demo/bytes/json/base58/hex/file/generate/env) including
``from_env`` None/malformed handling and the demo warn-once behaviour. Operator:
``None``-as-default resolution, ``effective_recipient`` fallback, equality/hash
over the resolved identity, and field validators.
"""

from __future__ import annotations

import json
import warnings

import pytest
from solders.keypair import Keypair

import solana_pay_kit.signer as signer_mod
from solana_pay_kit import LocalSigner, Operator, Signer
from solana_pay_kit.errors import ConfigurationError, InvalidKeyError
from solana_pay_kit.signer import DEMO_PUBKEY


@pytest.fixture(autouse=True)
def _reset_demo_warn():
    """Reset the demo warn-once guard so each test sees a clean process state."""
    signer_mod._reset_demo_for_tests()
    yield
    signer_mod._reset_demo_for_tests()


# -- Signer factories --------------------------------------------------------


def test_signer_demo_pubkey_is_fixed_and_flagged():
    s = Signer.demo()
    assert s.pubkey() == DEMO_PUBKEY
    assert s.is_demo() is True
    assert s.is_fee_payer() is True


def test_signer_demo_warns_once_and_caches():
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        first = Signer.demo()
        second = Signer.demo()
    assert first is second  # cached singleton
    demo_warnings = [w for w in caught if "demo signer" in str(w.message)]
    assert len(demo_warnings) == 1  # warn-once


def test_signer_generate_is_ephemeral_and_not_demo():
    a = Signer.generate()
    b = Signer.generate()
    assert a.pubkey() != b.pubkey()
    assert a.is_demo() is False


def test_signer_bytes_roundtrip():
    kp = Keypair()
    s = Signer.bytes(bytes(kp))
    assert s.pubkey() == str(kp.pubkey())


def test_signer_bytes_sequence_of_ints():
    kp = Keypair()
    s = Signer.bytes(list(bytes(kp)))
    assert s.pubkey() == str(kp.pubkey())


def test_signer_bytes_wrong_length_raises():
    with pytest.raises(InvalidKeyError, match="64-byte"):
        Signer.bytes(b"\x00" * 10)


def test_signer_bytes_wrong_int_count_raises():
    with pytest.raises(InvalidKeyError, match="64 integers"):
        Signer.bytes([0] * 10)


def test_signer_bytes_out_of_range_int_raises():
    bad = [0] * 63 + [999]
    with pytest.raises(InvalidKeyError, match=r"\[0,255\]"):
        Signer.bytes(bad)


def test_signer_bytes_str_rejected():
    with pytest.raises(InvalidKeyError, match="not str"):
        Signer.bytes("not-bytes")  # type: ignore[arg-type]


def test_signer_bytes_non_sequence_rejected():
    with pytest.raises(InvalidKeyError, match="sequence of ints"):
        Signer.bytes(123)  # type: ignore[arg-type]


def test_signer_json_roundtrip():
    kp = Keypair()
    arr = json.dumps(list(bytes(kp)))
    s = Signer.json(arr)
    assert s.pubkey() == str(kp.pubkey())


def test_signer_json_empty_raises():
    with pytest.raises(InvalidKeyError, match="empty"):
        Signer.json("   ")


def test_signer_json_not_string_raises():
    with pytest.raises(InvalidKeyError, match="expects a string"):
        Signer.json(123)  # type: ignore[arg-type]


def test_signer_json_malformed_raises():
    with pytest.raises(InvalidKeyError, match="malformed"):
        Signer.json("[1,2,")


def test_signer_json_not_array_raises():
    with pytest.raises(InvalidKeyError, match="expected a JSON array"):
        Signer.json('{"a":1}')


def test_signer_base58_roundtrip():
    kp = Keypair()
    s = Signer.base58(str(kp))  # solders Keypair str() is base58 secret
    assert s.pubkey() == str(kp.pubkey())


def test_signer_base58_empty_raises():
    with pytest.raises(InvalidKeyError, match="non-empty string"):
        Signer.base58("")


def test_signer_base58_malformed_raises():
    with pytest.raises(InvalidKeyError, match="invalid base58"):
        Signer.base58("not-valid-base58-!!!")


def test_signer_hex_roundtrip():
    kp = Keypair()
    s = Signer.hex(bytes(kp).hex())
    assert s.pubkey() == str(kp.pubkey())


def test_signer_hex_wrong_length_raises():
    with pytest.raises(InvalidKeyError, match="128 chars"):
        Signer.hex("abcd")


def test_signer_hex_non_hex_chars_raises():
    with pytest.raises(InvalidKeyError, match="non-hex"):
        Signer.hex("z" * 128)


def test_signer_file_roundtrip(tmp_path):
    kp = Keypair()
    p = tmp_path / "id.json"
    p.write_text(json.dumps(list(bytes(kp))))
    s = Signer.file(str(p))
    assert s.pubkey() == str(kp.pubkey())


def test_signer_file_empty_path_raises():
    with pytest.raises(InvalidKeyError, match="non-empty path"):
        Signer.file("")


def test_signer_file_missing_raises():
    with pytest.raises(InvalidKeyError, match="cannot read"):
        Signer.file("/nonexistent/keypair.json")


def test_signer_sign_produces_64_bytes():
    s = Signer.generate()
    sig = s.sign(b"hello")
    assert isinstance(sig, bytes) and len(sig) == 64


def test_local_signer_from_keypair_and_secret_key():
    kp = Keypair()
    s = LocalSigner.from_keypair(kp)
    assert s.keypair == kp
    assert len(s.secret_key()) == 64


def test_local_signer_from_bytes_invalid_raises():
    with pytest.raises(InvalidKeyError):
        LocalSigner.from_bytes(bytes([0]) * 64)  # all-zero is an invalid keypair


def test_signer_namespace_not_instantiable():
    with pytest.raises(TypeError, match="factory namespace"):
        Signer()


# -- Signer.env --------------------------------------------------------------


def test_signer_env_unset_returns_none(monkeypatch):
    monkeypatch.delenv("PK_TEST_KEY", raising=False)
    assert Signer.env("PK_TEST_KEY") is None


def test_signer_env_empty_returns_none(monkeypatch):
    monkeypatch.setenv("PK_TEST_KEY", "   ")
    assert Signer.env("PK_TEST_KEY") is None


def test_signer_env_empty_name_raises():
    with pytest.raises(InvalidKeyError, match="non-empty name"):
        Signer.env("")


def test_signer_env_json_array(monkeypatch):
    kp = Keypair()
    monkeypatch.setenv("PK_TEST_KEY", json.dumps(list(bytes(kp))))
    s = Signer.env("PK_TEST_KEY")
    assert s is not None and s.pubkey() == str(kp.pubkey())


def test_signer_env_hex(monkeypatch):
    kp = Keypair()
    monkeypatch.setenv("PK_TEST_KEY", bytes(kp).hex())
    s = Signer.env("PK_TEST_KEY")
    assert s is not None and s.pubkey() == str(kp.pubkey())


def test_signer_env_base58(monkeypatch):
    kp = Keypair()
    monkeypatch.setenv("PK_TEST_KEY", str(kp))
    s = Signer.env("PK_TEST_KEY")
    assert s is not None and s.pubkey() == str(kp.pubkey())


def test_signer_env_malformed_raises(monkeypatch):
    monkeypatch.setenv("PK_TEST_KEY", "[1,2,3]")  # too short -> InvalidKeyError
    with pytest.raises(InvalidKeyError):
        Signer.env("PK_TEST_KEY")


# -- Operator ----------------------------------------------------------------


def test_operator_defaults_resolve_to_demo():
    op = Operator().with_defaults()
    assert op.signer is not None and op.signer.is_demo()
    assert op.recipient == DEMO_PUBKEY  # falls back to signer pubkey


def test_operator_effective_recipient_explicit():
    op = Operator(recipient="ExplicitRecipient111111111111111111111111")
    assert op.effective_recipient() == "ExplicitRecipient111111111111111111111111"


def test_operator_effective_recipient_falls_back_to_signer():
    op = Operator()  # no recipient, no signer
    assert op.effective_recipient() == DEMO_PUBKEY


def test_operator_with_explicit_signer_keeps_it():
    kp = Keypair()
    op = Operator(signer=LocalSigner.from_keypair(kp)).with_defaults()
    assert op.signer is not None and op.signer.pubkey() == str(kp.pubkey())
    assert op.recipient == str(kp.pubkey())


def test_operator_recipient_non_string_raises():
    with pytest.raises(ConfigurationError, match="recipient must be a str"):
        Operator(recipient=123)  # type: ignore[arg-type]


def test_operator_fee_payer_must_be_bool():
    with pytest.raises(ConfigurationError, match="fee_payer must be"):
        Operator(fee_payer="yes")  # type: ignore[arg-type]


def test_operator_equality_and_hash_over_resolved_identity():
    a = Operator(recipient="R1111111111111111111111111111111111111111")
    b = Operator(recipient="R1111111111111111111111111111111111111111")
    assert a == b
    assert hash(a) == hash(b)


def test_operator_inequality_on_different_recipient():
    a = Operator(recipient="R1111111111111111111111111111111111111111")
    b = Operator(recipient="R2222222222222222222222222222222222222222")
    assert a != b


def test_operator_eq_with_non_operator_is_not_implemented():
    assert Operator().__eq__("nope") is NotImplemented
