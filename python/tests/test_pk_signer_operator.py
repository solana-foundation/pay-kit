"""PayKit metadata/factory adapters preserve native keychain capabilities."""

from __future__ import annotations

import json
import warnings

import pytest
from pydantic import ValidationError
from solana_keychain import MemorySigner, TransactionSigner
from solders.hash import Hash
from solders.keypair import Keypair
from solders.message import Message
from solders.signature import Signature
from solders.transaction import VersionedTransaction

import solana_pay_kit.signer as signer_mod
from solana_pay_kit import Operator, Signer
from solana_pay_kit.errors import ConfigurationError, InvalidKeyError
from solana_pay_kit.signer import DEMO_PUBKEY, is_demo_signer


@pytest.fixture(autouse=True)
def reset_demo_warn():
    signer_mod._reset_demo_for_tests()
    yield
    signer_mod._reset_demo_for_tests()


def test_demo_is_native_cached_and_warns_once():
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        first = Signer.demo()
        second = Signer.demo()
    assert first is second
    assert type(first) is MemorySigner
    assert str(first.pubkey) == DEMO_PUBKEY
    assert is_demo_signer(first)
    assert len([w for w in caught if "demo signer" in str(w.message)]) == 1


def test_explicitly_loaded_demo_identity_is_recognized():
    assert is_demo_signer(Signer.bytes(signer_mod._DEMO_SECRET_BYTES))


def test_generated_signers_are_distinct_and_not_demo():
    a, b = Signer.generate(), Signer.generate()
    assert a.pubkey != b.pubkey
    assert not is_demo_signer(a)


@pytest.mark.parametrize("encoding", ["bytes", "sequence", "json", "base58", "hex", "file"])
def test_factory_returns_native_signer(encoding, tmp_path):
    kp = Keypair()
    path = tmp_path / "id.json"
    path.write_text(json.dumps(list(bytes(kp))))
    factories = {
        "bytes": lambda: Signer.bytes(bytes(kp)),
        "sequence": lambda: Signer.bytes(list(bytes(kp))),
        "json": lambda: Signer.json(json.dumps(list(bytes(kp)))),
        "base58": lambda: Signer.base58(str(kp)),
        "hex": lambda: Signer.hex(bytes(kp).hex()),
        "file": lambda: Signer.file(str(path)),
    }
    signer = factories[encoding]()
    assert type(signer) is MemorySigner
    assert signer.pubkey == kp.pubkey()


def test_native_seed_loading_supported():
    seed = bytes(range(32))
    assert Signer.bytes(seed).pubkey == Keypair.from_seed(seed).pubkey()


@pytest.mark.parametrize(
    ("factory", "value"),
    [
        (Signer.bytes, b"\x00" * 10),
        (Signer.bytes, bytes(64)),
        (Signer.bytes, [999] * 64),
        (Signer.bytes, "not-bytes"),
        (Signer.bytes, 32),
        (Signer.bytes, [True] * 32),
        (Signer.json, ""),
        (Signer.json, 123),
        (Signer.json, "[1,2,"),
        (Signer.json, '{"a":1}'),
        (Signer.json, json.dumps([True] * 64)),
        (Signer.base58, ""),
        (Signer.base58, "not-base58-!!!"),
        (Signer.hex, "abcd"),
        (Signer.hex, "z" * 128),
        (Signer.file, ""),
        (Signer.file, "/nonexistent/keypair.json"),
    ],
)
def test_invalid_key_inputs_fail_without_echoing_secrets(factory, value):
    with pytest.raises(InvalidKeyError, match="invalid or unreadable private key"):
        factory(value)


async def test_native_message_and_transaction_signing():
    signer = Signer.generate()
    signature = await signer.sign_message(b"hello")
    assert isinstance(signature, Signature)
    assert signature.verify(signer.pubkey, b"hello")
    assert await signer.is_available()
    message = Message.new_with_blockhash([], signer.pubkey, Hash.default())
    unsigned = VersionedTransaction.populate(message, [Signature.default()])
    result = await signer.sign_transaction(unsigned)
    assert result.transaction.verify_with_results() == [True]
    assert result.is_complete
    assert not hasattr(signer, "secret_key")
    assert not hasattr(signer, "keypair")


def test_namespace_not_instantiable():
    with pytest.raises(TypeError, match="factory namespace"):
        Signer()


@pytest.mark.parametrize("value", [None, "", "   "])
def test_env_absent_or_blank_returns_none(monkeypatch, value):
    if value is None:
        monkeypatch.delenv("PK_TEST_KEY", raising=False)
    else:
        monkeypatch.setenv("PK_TEST_KEY", value)
    assert Signer.env("PK_TEST_KEY") is None


@pytest.mark.parametrize("encoding", ["json", "hex", "base58"])
def test_env_loads_key(monkeypatch, encoding):
    kp = Keypair()
    raw = {"json": json.dumps(list(bytes(kp))), "hex": bytes(kp).hex(), "base58": str(kp)}[encoding]
    monkeypatch.setenv("PK_TEST_KEY", raw)
    signer = Signer.env("PK_TEST_KEY")
    assert signer is not None and signer.pubkey == kp.pubkey()


def test_env_bad_key_does_not_fall_back(monkeypatch):
    monkeypatch.setenv("PK_TEST_KEY", "[1,2,3]")
    with pytest.raises(InvalidKeyError):
        Signer.env("PK_TEST_KEY")
    with pytest.raises(InvalidKeyError):
        Signer.env("")


def test_operator_defaults_and_explicit_recipient():
    op = Operator().with_defaults()
    assert op.signer is not None and is_demo_signer(op.signer)
    assert op.recipient == DEMO_PUBKEY
    assert Operator().effective_recipient() == DEMO_PUBKEY
    assert Operator(recipient="explicit").effective_recipient() == "explicit"


def test_operator_accepts_native_non_memory_signer():
    class RemoteSigner(TransactionSigner):
        @property
        def pubkey(self):
            return kp.pubkey()

        async def sign_message(self, message):
            raise AssertionError("configuration must not sign")

        async def sign_transaction(self, transaction):
            raise AssertionError("configuration must not sign")

        async def is_available(self):
            raise AssertionError("configuration must not probe the provider")

    kp = Keypair()
    signer = RemoteSigner()
    op = Operator(signer=signer).with_defaults()
    assert op.signer is signer
    assert op.recipient == str(kp.pubkey())


def test_operator_rejects_non_signer():
    with pytest.raises(ValidationError):
        Operator(signer=object())  # type: ignore[arg-type]


def test_operator_validates_fields():
    with pytest.raises(ConfigurationError, match="recipient must be a str"):
        Operator(recipient=123)  # type: ignore[arg-type]
    with pytest.raises(ConfigurationError, match="fee_payer must be"):
        Operator(fee_payer="yes")  # type: ignore[arg-type]


def test_operator_equality_and_hash_use_resolved_identity():
    a, b = Operator(recipient="A"), Operator(recipient="A")
    assert a == b
    assert hash(a) == hash(b)
    assert a != Operator(recipient="B")
    assert a.__eq__("nope") is NotImplemented
