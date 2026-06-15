"""x402 v2 ``extensions`` echo-and-append coverage.

Mirrors the rust spine unit tests in
``rust/crates/x402/src/protocol/schemes/exact/types.rs`` (echoing returns None
when inbound absent; unknown keys preserved verbatim; with_payment_identifier_id
appends without overwriting; id generation shape) and the client/server wiring
that drives the conformance extension vectors.
"""

from __future__ import annotations

import base64
import json
from typing import Any, cast

import pytest
from solders.keypair import Keypair

from pay_kit._paycore.mints import resolve, token_program_for
from pay_kit.protocols.x402.client.exact import build_payment, build_payment_header
from pay_kit.protocols.x402.exact.extensions import (
    PAYMENT_IDENTIFIER_ID_PATTERN,
    PAYMENT_IDENTIFIER_KEY,
    PaymentIdentifierError,
    echo_extensions,
    extensions_is_empty,
    extract_payment_identifier_id,
    generate_payment_identifier_id,
    requires_payment_identifier,
    verify_payment_identifier,
    with_payment_identifier_id,
)
from pay_kit.protocols.x402.exact.types import X402AcceptsEntry
from pay_kit.signer import Signer

BH = "4vJ9JU1bJJQpUgJ8V6hYz7xXKz4F2tN6aBrZEcD3xKhs"
_USDC_DEVNET = resolve("USDC", "devnet")
assert _USDC_DEVNET is not None
USDC_DEVNET: str = _USDC_DEVNET
TP_USDC = token_program_for("USDC", "devnet")
DEVNET = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"


def _offer() -> dict[str, Any]:
    extra = {
        "feePayer": str(Keypair().pubkey()),
        "decimals": 6,
        "tokenProgram": TP_USDC,
        "memo": "/protected",
        "recentBlockhash": BH,
    }
    return {
        "protocol": "x402",
        "scheme": "exact",
        "network": DEVNET,
        "asset": USDC_DEVNET,
        "amount": "1000",
        "maxAmountRequired": "1000",
        "payTo": str(Keypair().pubkey()),
        "maxTimeoutSeconds": 60,
        "extra": extra,
    }


def _entry(offer: dict[str, Any]) -> X402AcceptsEntry:
    return cast("X402AcceptsEntry", offer)


def _ext_of(env: object) -> dict[str, Any] | None:
    return cast("dict[str, Any]", env).get("extensions")


# -- generate_payment_identifier_id ------------------------------------------


def test_generate_payment_identifier_id_shape():
    pid = generate_payment_identifier_id()
    assert pid.startswith("pay_")
    assert len(pid) == 36  # pay_ + 32 hex
    assert PAYMENT_IDENTIFIER_ID_PATTERN.match(pid)
    # 32 hex after the prefix.
    bytes.fromhex(pid[4:])


def test_generate_payment_identifier_id_is_unique():
    assert generate_payment_identifier_id() != generate_payment_identifier_id()


# -- echo_extensions ---------------------------------------------------------


def test_echoing_returns_none_when_inbound_absent():
    """rust payment_extensions_echoing_returns_none_when_inbound_absent."""
    assert echo_extensions(None) is None


def test_echoing_deep_copies_so_inbound_is_not_mutated():
    inbound = {PAYMENT_IDENTIFIER_KEY: {"info": {"required": True}}}
    echoed = echo_extensions(inbound)
    assert echoed == inbound
    assert echoed is not inbound
    echoed = with_payment_identifier_id(echoed, "pay_abcdef1234567890")
    # The original challenge object is untouched.
    assert "id" not in inbound[PAYMENT_IDENTIFIER_KEY]["info"]


def test_echoes_unknown_keys_verbatim():
    """rust payment_extensions_echoes_unknown_keys_verbatim."""
    inbound = {
        PAYMENT_IDENTIFIER_KEY: {"info": {"required": True}},
        "future-extension": {"info": {"foo": "bar"}, "nested": [1, 2, 3]},
    }
    echoed = echo_extensions(inbound)
    assert echoed == inbound


# -- requires_payment_identifier ---------------------------------------------


def test_requires_true_only_when_required_flag_set():
    assert requires_payment_identifier({PAYMENT_IDENTIFIER_KEY: {"info": {"required": True}}}) is True
    assert requires_payment_identifier({PAYMENT_IDENTIFIER_KEY: {"info": {"required": False}}}) is False
    assert requires_payment_identifier({PAYMENT_IDENTIFIER_KEY: {"info": {}}}) is False
    assert requires_payment_identifier({PAYMENT_IDENTIFIER_KEY: {}}) is False
    assert requires_payment_identifier({}) is False
    assert requires_payment_identifier(None) is False
    # Non-bool truthy values do not count (rust required == Some(true)).
    assert requires_payment_identifier({PAYMENT_IDENTIFIER_KEY: {"info": {"required": "yes"}}}) is False


# -- with_payment_identifier_id ----------------------------------------------


def test_appends_id_without_overwriting_server_fields():
    """rust with_payment_identifier_id_appends_without_overwriting_server_fields."""
    inbound = {
        PAYMENT_IDENTIFIER_KEY: {
            "info": {"required": True},
            "schema": {"type": "object", "required": ["id"]},
        }
    }
    out = with_payment_identifier_id(inbound, "pay_abcdef1234567890abcdef1234567890")
    pid = out[PAYMENT_IDENTIFIER_KEY]
    assert pid["info"]["required"] is True  # server field preserved
    assert pid["info"]["id"] == "pay_abcdef1234567890abcdef1234567890"
    assert pid["schema"] == {"type": "object", "required": ["id"]}  # schema echoed verbatim


def test_creates_entry_when_server_did_not_advertise():
    out = with_payment_identifier_id(None, "pay_abcdef1234567890")
    assert out[PAYMENT_IDENTIFIER_KEY]["info"]["id"] == "pay_abcdef1234567890"


# -- extensions_is_empty -----------------------------------------------------


def test_extensions_is_empty():
    assert extensions_is_empty(None) is True
    assert extensions_is_empty({}) is True
    assert extensions_is_empty({PAYMENT_IDENTIFIER_KEY: {}}) is False


# -- extract_payment_identifier_id -------------------------------------------


def test_extract_payment_identifier_id():
    assert extract_payment_identifier_id(None) is None
    assert extract_payment_identifier_id({}) is None
    assert extract_payment_identifier_id({PAYMENT_IDENTIFIER_KEY: {}}) is None
    assert extract_payment_identifier_id({PAYMENT_IDENTIFIER_KEY: {"info": {}}}) is None
    assert (
        extract_payment_identifier_id({PAYMENT_IDENTIFIER_KEY: {"info": {"id": "pay_x16charssssss!"}}})
        == "pay_x16charssssss!"
    )


# -- verify_payment_identifier (server reject gate) --------------------------


def test_verify_noop_when_not_required():
    verify_payment_identifier(None, required=False)  # no raise


def test_verify_rejects_missing_id():
    with pytest.raises(PaymentIdentifierError, match="payment-identifier required"):
        verify_payment_identifier({PAYMENT_IDENTIFIER_KEY: {"info": {"required": True}}}, required=True)


def test_verify_rejects_empty_id():
    with pytest.raises(PaymentIdentifierError, match="payment-identifier required"):
        verify_payment_identifier({PAYMENT_IDENTIFIER_KEY: {"info": {"id": ""}}}, required=True)


def test_verify_rejects_pattern_violating_id():
    with pytest.raises(PaymentIdentifierError, match="does not match"):
        verify_payment_identifier({PAYMENT_IDENTIFIER_KEY: {"info": {"id": "short"}}}, required=True)


def test_verify_accepts_valid_id():
    verify_payment_identifier(
        {PAYMENT_IDENTIFIER_KEY: {"info": {"id": "pay_abcdef1234567890abcdef1234567890"}}},
        required=True,
    )  # no raise


# -- client build wiring -----------------------------------------------------


@pytest.mark.asyncio
async def test_build_omits_extensions_when_none_advertised():
    signer = Signer.generate()
    env = await build_payment(signer, None, _entry(_offer()))
    assert "extensions" not in cast("dict[str, Any]", env)


@pytest.mark.asyncio
async def test_build_echoes_and_generates_id_when_required():
    signer = Signer.generate()
    advertised = {
        PAYMENT_IDENTIFIER_KEY: {"info": {"required": True}, "schema": {"type": "object"}},
    }
    env = await build_payment(signer, None, _entry(_offer()), advertised_extensions=advertised)
    ext = _ext_of(env)
    assert ext is not None
    pid = ext[PAYMENT_IDENTIFIER_KEY]
    assert pid["info"]["required"] is True
    assert PAYMENT_IDENTIFIER_ID_PATTERN.match(pid["info"]["id"])
    assert pid["schema"] == {"type": "object"}  # echoed verbatim


@pytest.mark.asyncio
async def test_build_pins_id_and_preserves_unknown_verbatim():
    signer = Signer.generate()
    advertised = {
        PAYMENT_IDENTIFIER_KEY: {"info": {"required": True}},
        "future-extension": {"info": {"foo": "bar"}},
    }
    env = await build_payment(
        signer,
        None,
        _entry(_offer()),
        advertised_extensions=advertised,
        payment_identifier_id="pay_abcdef1234567890abcdef1234567890",
    )
    ext = _ext_of(env)
    assert ext is not None
    assert ext[PAYMENT_IDENTIFIER_KEY]["info"]["id"] == "pay_abcdef1234567890abcdef1234567890"
    assert ext["future-extension"] == {"info": {"foo": "bar"}}  # unknown preserved


@pytest.mark.asyncio
async def test_build_does_not_generate_id_when_advertised_but_not_required():
    """Advertised payment-identifier without info.required=true gets echoed but no id."""
    signer = Signer.generate()
    advertised = {PAYMENT_IDENTIFIER_KEY: {"info": {"required": False}}}
    env = await build_payment(signer, None, _entry(_offer()), advertised_extensions=advertised)
    ext = _ext_of(env)
    assert ext is not None
    assert "id" not in ext[PAYMENT_IDENTIFIER_KEY]["info"]


@pytest.mark.asyncio
async def test_build_header_emits_extensions_on_wire():
    signer = Signer.generate()
    advertised = {PAYMENT_IDENTIFIER_KEY: {"info": {"required": True}}}
    header = await build_payment_header(
        signer,
        None,
        _entry(_offer()),
        advertised_extensions=advertised,
        payment_identifier_id="pay_abcdef1234567890abcdef1234567890",
    )
    decoded = json.loads(base64.b64decode(header))
    assert decoded["extensions"][PAYMENT_IDENTIFIER_KEY]["info"]["id"] == "pay_abcdef1234567890abcdef1234567890"
