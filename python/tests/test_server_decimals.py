"""Charge server decimals and tokenProgram on the wire (RULINGS C2/C3).

draft-solana-charge-00: ``decimals`` "MUST be present when `currency` is a mint
address; MUST be absent when `currency` is "sol"", and ``tokenProgram`` "MUST
NOT be present when `currency` is "sol"".
"""

from __future__ import annotations

import base64
from typing import Any

import httpx
import pytest
from solders.pubkey import Pubkey

from solana_pay_kit._paycore.errors import PaymentError
from solana_pay_kit._paycore.solana import TOKEN_2022_PROGRAM, TOKEN_PROGRAM
from solana_pay_kit._paycore.store import MemoryStore
from solana_pay_kit.protocols.mpp.server.charge import Config, Mpp

SECRET = "test-secret-key-that-is-long-enough-for-hmac-sha256"
RECIPIENT = "11111111111111111111111111111112"
RPC_URL = "http://fixture.invalid"


def _serve_mint(monkeypatch: pytest.MonkeyPatch, mint: str, owner: str, decimals: int) -> list[str]:
    """Answer the server's boot-time getAccountInfo with an SPL mint account."""
    data = bytearray(82)
    data[44] = decimals
    data[45] = 1
    calls: list[str] = []

    def post(url: str, json: dict[str, Any], timeout: float) -> httpx.Response:
        calls.append(json["params"][0])
        value = (
            {"owner": owner, "data": [base64.b64encode(bytes(data)).decode(), "base64"]}
            if json["params"][0] == mint
            else None
        )
        return httpx.Response(200, json={"result": {"value": value}}, request=httpx.Request("POST", url))

    monkeypatch.setattr(httpx, "post", post)
    return calls


def _mpp(currency: str, decimals: int | None) -> Mpp:
    return Mpp(
        Config(
            recipient=RECIPIENT,
            currency=currency,
            decimals=decimals,
            network="mainnet",
            rpc_url=RPC_URL,
            secret_key=SECRET,
            store=MemoryStore(),
        )
    )


def _request(mpp: Mpp, amount: str) -> dict[str, Any]:
    return mpp.charge(amount).decode_request()


def test_explicit_zero_decimals_is_kept(monkeypatch: pytest.MonkeyPatch):
    # Before: ``config.decimals or 6`` turned 0 into 6, so "5" became 5_000_000.
    mint = str(Pubkey.new_unique())
    _serve_mint(monkeypatch, mint, TOKEN_PROGRAM, 0)
    request = _request(_mpp(mint, 0), "5")
    assert request["amount"] == "5"
    assert request["methodDetails"]["decimals"] == 0
    assert request["methodDetails"]["tokenProgram"] == TOKEN_PROGRAM


def test_arbitrary_mint_decimals_come_from_the_mint(monkeypatch: pytest.MonkeyPatch):
    # Before: an unset value silently became 6 for any mint.
    mint = str(Pubkey.new_unique())
    calls = _serve_mint(monkeypatch, mint, TOKEN_2022_PROGRAM, 9)
    request = _request(_mpp(mint, None), "1.5")
    assert calls == [mint]
    assert request["amount"] == "1500000000"
    assert request["methodDetails"]["decimals"] == 9
    assert request["methodDetails"]["tokenProgram"] == TOKEN_2022_PROGRAM


def test_configured_decimals_must_match_the_mint(monkeypatch: pytest.MonkeyPatch):
    mint = str(Pubkey.new_unique())
    _serve_mint(monkeypatch, mint, TOKEN_PROGRAM, 9)
    with pytest.raises(PaymentError, match="do not match") as exc:
        _mpp(mint, 6)
    assert exc.value.code == "invalid-config"


def test_arbitrary_mint_that_cannot_be_read_fails_at_boot(monkeypatch: pytest.MonkeyPatch):
    _serve_mint(monkeypatch, str(Pubkey.new_unique()), TOKEN_PROGRAM, 6)
    with pytest.raises(PaymentError, match="not found") as exc:
        _mpp(str(Pubkey.new_unique()), 6)
    assert exc.value.code == "invalid-config"


def test_known_stablecoin_decimals_from_the_table():
    request = _request(_mpp("USDC", None), "1.25")
    assert request["amount"] == "1250000"
    assert request["methodDetails"]["decimals"] == 6
    assert request["methodDetails"]["tokenProgram"] == TOKEN_PROGRAM


def test_known_stablecoin_rejects_wrong_configured_decimals():
    with pytest.raises(PaymentError, match="do not match"):
        _mpp("USDC", 9)


@pytest.mark.parametrize("decimals", [None, 9])
def test_sol_challenge_has_no_decimals_or_token_program(decimals: int | None):
    request = _request(_mpp("SOL", decimals), "0.5")
    assert request["amount"] == "500000000"
    assert "decimals" not in request["methodDetails"]
    assert "tokenProgram" not in request["methodDetails"]


def test_wire_currency_is_sol_or_a_mint():
    # RULINGS C1: a configured symbol never reaches the wire.
    assert _request(_mpp("SOL", None), "1")["currency"] == "sol"
    assert _request(_mpp("USDC", None), "1")["currency"] == "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"


def test_sol_rejects_non_native_precision():
    with pytest.raises(PaymentError, match="do not match"):
        _mpp("SOL", 6)
