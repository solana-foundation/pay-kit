"""Tests for _base64url module."""

from __future__ import annotations

from solana_pay_kit.protocols.mpp.core.base64url import decode, decode_json, encode, encode_json


def test_encode_decode_roundtrip():
    data = b"hello world"
    encoded = encode(data)
    assert "=" not in encoded
    assert decode(encoded) == data


def test_encode_empty():
    assert encode(b"") == ""
    assert decode("") == b""


def test_encode_json_roundtrip():
    obj = {"amount": "1000", "currency": "USDC"}
    encoded = encode_json(obj)
    decoded = decode_json(encoded)
    assert decoded == obj


def test_encode_json_sorts_keys():
    obj = {"z": 1, "a": 2}
    encoded = encode_json(obj)
    decoded = decode_json(encoded)
    assert decoded == obj


def test_decode_handles_padding():
    """Decode should handle input with or without padding."""
    data = b"test"
    encoded_no_pad = encode(data)
    encoded_with_pad = encoded_no_pad + "=" * (-len(encoded_no_pad) % 4)
    assert decode(encoded_no_pad) == data
    assert decode(encoded_with_pad) == data


def test_decode_handles_standard_base64():
    """Decode should handle standard base64 characters (+, /)."""
    import base64

    data = b"\xff\xfe\xfd"
    standard = base64.b64encode(data).decode("ascii")
    assert decode(standard) == data


def test_encode_url_safe():
    """Encode should produce URL-safe characters (- instead of +, _ instead of /)."""
    data = b"\xff\xfe\xfd"
    encoded = encode(data)
    assert "+" not in encoded
    assert "/" not in encoded
