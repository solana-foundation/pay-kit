"""draft-solana-charge-00 tokenProgram resolution on the client (RULINGS C3).

"If omitted, clients MUST determine the correct token program by fetching the
mint account ... If that lookup fails, returns an unexpected owner, or cannot
be verified, clients MUST reject the challenge rather than falling back to the
Token Program."
"""

from __future__ import annotations

import base64
import json
from typing import Any

import httpx
import pytest
from solana_keychain import MemorySigner
from solders.keypair import Keypair
from solders.transaction import VersionedTransaction

from solana_pay_kit._paycore.errors import InvalidChallengeError
from solana_pay_kit._paycore.mint_account import MintLookupError, fetch_mint_account, parse_mint_account
from solana_pay_kit._paycore.rpc import SolanaRpc
from solana_pay_kit._paycore.solana import SYSTEM_PROGRAM, TOKEN_2022_PROGRAM, TOKEN_PROGRAM, MethodDetails
from solana_pay_kit.protocols.mpp.client.charge import build_charge_transaction

BLOCKHASH = "11111111111111111111111111111111"
USDC_DEVNET = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"
PYUSD_MAINNET = "2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo"


def _mint_data(decimals: int = 6, initialized: bool = True) -> bytes:
    data = bytearray(82)
    data[44] = decimals
    data[45] = 1 if initialized else 0
    return bytes(data)


class _Account:
    def __init__(self, owner: str, data: bytes) -> None:
        self.owner = owner
        self.data = data


class _Resp:
    def __init__(self, value: Any) -> None:
        self.value = value


class _AsyncClientRpc:
    """solana-py ``AsyncClient`` shape: ``get_account_info(Pubkey).value``."""

    def __init__(self, accounts: dict[str, _Account], *, fail: bool = False) -> None:
        self.accounts = accounts
        self.fail = fail
        self.calls: list[str] = []

    async def get_account_info(self, pubkey: Any) -> _Resp:
        self.calls.append(str(pubkey))
        if self.fail:
            raise ConnectionError("rpc unreachable")
        return _Resp(self.accounts.get(str(pubkey)))


def _fixture_solana_rpc(accounts: dict[str, tuple[str, bytes]]) -> SolanaRpc:
    """A real ``SolanaRpc`` wired to an in-process JSON-RPC fixture."""

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        assert body["method"] == "getAccountInfo"
        entry = accounts.get(body["params"][0])
        value = (
            None
            if entry is None
            else {
                "owner": entry[0],
                "data": [base64.b64encode(entry[1]).decode(), "base64"],
                "lamports": 1,
                "executable": False,
                "rentEpoch": 0,
            }
        )
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": {"value": value}})

    rpc = SolanaRpc("http://fixture.invalid")
    rpc._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))  # pyright: ignore[reportPrivateUsage]
    return rpc


async def _build(currency: str, rpc: Any, *, token_program: str | None = None, network: str = "localnet") -> str:
    payload = await build_charge_transaction(
        signer=MemorySigner(Keypair()),
        rpc_client=rpc,
        amount="1000",
        currency=currency,
        recipient=str(Keypair().pubkey()),
        method_details=MethodDetails(
            network=network, decimals=6, token_program=token_program, recent_blockhash=BLOCKHASH
        ),
    )
    assert payload.transaction is not None
    return payload.transaction


def _transfer_program(transaction_b64: str) -> str:
    tx = VersionedTransaction.from_bytes(base64.b64decode(transaction_b64))
    keys = [str(k) for k in tx.message.account_keys]
    transfer = next(ix for ix in tx.message.instructions if bytes(ix.data)[:1] == bytes([12]))
    return keys[transfer.program_id_index]


# -- rejections (each fell back to the currency table before) ---------------


async def test_rejects_when_no_rpc_client_even_for_known_stablecoin():
    # Before: USDC devnet resolved from the stablecoin table without a lookup.
    with pytest.raises(InvalidChallengeError, match="no RPC client"):
        await _build(USDC_DEVNET, None)


async def test_rejects_when_mint_account_missing():
    rpc = _AsyncClientRpc({})
    with pytest.raises(InvalidChallengeError, match="not found"):
        await _build(USDC_DEVNET, rpc)
    assert rpc.calls == [USDC_DEVNET]


async def test_rejects_when_mint_owner_is_unexpected():
    rpc = _AsyncClientRpc({USDC_DEVNET: _Account(SYSTEM_PROGRAM, _mint_data())})
    with pytest.raises(InvalidChallengeError, match="unexpected program"):
        await _build(USDC_DEVNET, rpc)


async def test_rejects_when_lookup_fails():
    rpc = _AsyncClientRpc({}, fail=True)
    with pytest.raises(InvalidChallengeError, match="lookup .* failed"):
        await _build(USDC_DEVNET, rpc)


async def test_rejects_unsupported_explicit_token_program():
    with pytest.raises(InvalidChallengeError, match="Unsupported token program"):
        await _build(USDC_DEVNET, None, token_program=SYSTEM_PROGRAM)


async def test_solana_rpc_missing_mint_rejects():
    rpc = _fixture_solana_rpc({})
    try:
        with pytest.raises(MintLookupError, match="not found"):
            await _build(USDC_DEVNET, rpc)
    finally:
        await rpc.aclose()


# -- positive controls ------------------------------------------------------


async def test_resolves_token_program_from_mint_owner():
    rpc = _AsyncClientRpc({USDC_DEVNET: _Account(TOKEN_PROGRAM, _mint_data())})
    assert _transfer_program(await _build(USDC_DEVNET, rpc)) == TOKEN_PROGRAM


async def test_resolves_token_2022_from_mint_owner_via_solana_rpc():
    rpc = _fixture_solana_rpc({PYUSD_MAINNET: (TOKEN_2022_PROGRAM, _mint_data())})
    try:
        assert _transfer_program(await _build(PYUSD_MAINNET, rpc, network="mainnet")) == TOKEN_2022_PROGRAM
    finally:
        await rpc.aclose()


async def test_explicit_token_program_skips_lookup():
    rpc = _AsyncClientRpc({})
    assert _transfer_program(await _build(USDC_DEVNET, rpc, token_program=TOKEN_PROGRAM)) == TOKEN_PROGRAM
    assert rpc.calls == []


# -- mint account parsing ---------------------------------------------------


def test_parse_mint_account_reads_decimals_and_owner():
    mint = parse_mint_account(USDC_DEVNET, TOKEN_2022_PROGRAM, _mint_data(decimals=0) + b"\x00" * 10)
    assert (mint.token_program, mint.decimals) == (TOKEN_2022_PROGRAM, 0)


@pytest.mark.parametrize(
    ("owner", "data", "match"),
    [
        (SYSTEM_PROGRAM, _mint_data(), "unexpected program"),
        (TOKEN_PROGRAM, b"\x00" * 81, "not an SPL mint"),
        (TOKEN_PROGRAM, _mint_data(initialized=False), "not initialized"),
    ],
)
def test_parse_mint_account_rejects_non_mints(owner: str, data: bytes, match: str):
    with pytest.raises(MintLookupError, match=match):
        parse_mint_account(USDC_DEVNET, owner, data)


async def test_fetch_mint_account_reads_decimals():
    rpc = _AsyncClientRpc({USDC_DEVNET: _Account(TOKEN_PROGRAM, _mint_data(decimals=9))})
    assert (await fetch_mint_account(rpc, USDC_DEVNET)).decimals == 9
