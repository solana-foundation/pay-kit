"""x402 ``exact`` client coverage: challenge parsing, payment building, transport.

Exercises the client surface against the same ``ExactVerifier`` the server runs,
so every built transaction is asserted to round-trip through verification. The
transport test wires a stub ASGI app backed by a real ``X402Adapter`` (RPC
stubbed) to a single x402-gated route and asserts the 402 -> pay -> 200 flow,
including that the retried request carries ``PAYMENT-SIGNATURE``.
"""

from __future__ import annotations

import base64
import json
from typing import Any, cast

import httpx
import pytest
from solders.keypair import Keypair
from solders.transaction import VersionedTransaction

from pay_kit import (
    LocalSigner,
    MemoryStore,
    Operator,
    Price,
    Protocol,
    Stablecoin,
    configure,
)
from pay_kit._paycore.mints import derive_ata, resolve, token_program_for
from pay_kit.config import reset
from pay_kit.gate import Gate
from pay_kit.protocols.x402 import X402Adapter
from pay_kit.protocols.x402.client.exact import (
    ChallengeSelection,
    PaymentTransport,
    X402Client,
    build_payment,
    build_payment_header,
    parse_x402_challenge,
)
from pay_kit.protocols.x402.exact.types import X402AcceptsEntry
from pay_kit.protocols.x402.exact.verify import ExactVerifier
from pay_kit.signer import Signer

# A Surfpool-style blockhash: any valid base58 hash works for offline tests.
BH = "4vJ9JU1bJJQpUgJ8V6hYz7xXKz4F2tN6aBrZEcD3xKhs"
_USDC_DEVNET = resolve("USDC", "devnet")
assert _USDC_DEVNET is not None
USDC_DEVNET: str = _USDC_DEVNET
TP_USDC = token_program_for("USDC", "devnet")
DEVNET = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"
MAINNET = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    reset()
    monkeypatch.setenv("PAY_KIT_DISABLE_PREFLIGHT", "1")
    yield
    reset()


async def _fixed_blockhash() -> str:
    return BH


def _offer(
    *,
    asset: str = USDC_DEVNET,
    amount: str = "1000",
    network: str = DEVNET,
    token_program: str = TP_USDC,
    pay_to: str | None = None,
    memo: str = "/protected",
    decimals: int = 6,
    blockhash: str | None = BH,
    fee_payer: str | None = None,
) -> dict[str, Any]:
    pay_to = pay_to or str(Keypair().pubkey())
    fee_payer = fee_payer or str(Keypair().pubkey())
    extra: dict[str, Any] = {"feePayer": fee_payer, "decimals": decimals, "tokenProgram": token_program, "memo": memo}
    if blockhash is not None:
        extra["recentBlockhash"] = blockhash
    return {
        "protocol": "x402",
        "scheme": "exact",
        "network": network,
        "asset": asset,
        "amount": amount,
        "maxAmountRequired": amount,
        "payTo": pay_to,
        "maxTimeoutSeconds": 60,
        "extra": extra,
    }


def _entry(offer: dict[str, Any]) -> X402AcceptsEntry:
    """Narrow a test-built offer dict to the wire TypedDict for the client API."""
    return cast("X402AcceptsEntry", offer)


def _tx(env: object) -> str:
    """Pull the base64 transaction out of a built X402Envelope."""
    payload = cast("dict[str, Any]", cast("dict[str, Any]", env)["payload"])
    return cast("str", payload["transaction"])


def _challenge_header(*offers: dict[str, Any]) -> str:
    body = {"x402Version": 2, "resource": {"type": "http", "url": "/protected"}, "accepts": list(offers)}
    return base64.b64encode(json.dumps(body).encode()).decode()


def _challenge_body(*offers: dict[str, Any]) -> str:
    return json.dumps({"x402Version": 2, "accepts": list(offers)})


# -- parse_x402_challenge ----------------------------------------------------


def test_parse_from_header():
    offer = _offer()
    picked = parse_x402_challenge(
        {"payment-required": _challenge_header(offer)}, None, ChallengeSelection(network="devnet")
    )
    assert picked is not None
    assert picked["asset"] == USDC_DEVNET


def test_parse_header_case_insensitive_lookup():
    offer = _offer()
    picked = parse_x402_challenge(
        {"Payment-Required": _challenge_header(offer)}, None, ChallengeSelection(network="devnet")
    )
    assert picked is not None


def test_parse_from_body_when_header_absent():
    offer = _offer()
    picked = parse_x402_challenge({}, _challenge_body(offer), ChallengeSelection(network="devnet"))
    assert picked is not None
    assert picked["asset"] == USDC_DEVNET


def test_parse_header_preferred_over_body():
    header_offer = _offer(amount="100")
    body_offer = _offer(amount="999")
    picked = parse_x402_challenge(
        {"payment-required": _challenge_header(header_offer)},
        _challenge_body(body_offer),
        ChallengeSelection(network="devnet"),
    )
    assert picked is not None
    assert picked["amount"] == "100"


def test_parse_network_filter_prefers_matching_network():
    # Two solana offers: one on the preferred devnet, one on mainnet. With no
    # currency preference the preferred-network offer wins even though it is
    # not the cheapest (mirror rust: filter to preferred, then cheapest).
    devnet_offer = _offer(network=DEVNET, amount="9000")
    mainnet_offer = _offer(network=MAINNET, amount="1")
    picked = parse_x402_challenge(
        {"payment-required": _challenge_header(mainnet_offer, devnet_offer)},
        None,
        ChallengeSelection(network="devnet"),
    )
    assert picked is not None
    assert picked["network"] == DEVNET


def test_parse_currency_preference_restricts_to_network():
    # Currency preference path: the wanted currency exists only on mainnet, but
    # the client wants devnet -> no match on the preferred network -> None.
    mainnet_offer = _offer(network=MAINNET, asset=USDC_DEVNET, amount="1000")
    picked = parse_x402_challenge(
        {"payment-required": _challenge_header(mainnet_offer)},
        None,
        ChallengeSelection(network="devnet", currencies=["USDC"]),
    )
    assert picked is None


def test_parse_rejects_non_solana_and_non_exact():
    bad_scheme = {**_offer(), "scheme": "upto"}
    foreign = {**_offer(), "network": "ethereum:1"}
    picked = parse_x402_challenge(
        {"payment-required": _challenge_header(bad_scheme, foreign)},
        None,
        ChallengeSelection(network="devnet"),
    )
    assert picked is None


def test_parse_currency_preference_order():
    usdc = _offer(asset=USDC_DEVNET, amount="1000000")
    pyusd_mint = resolve("PYUSD", "devnet")
    assert pyusd_mint is not None
    pyusd = _offer(asset=pyusd_mint, amount="1000000", token_program=token_program_for("PYUSD", "devnet"))
    # Client prefers PYUSD first even though USDC is listed first.
    picked = parse_x402_challenge(
        {"payment-required": _challenge_header(usdc, pyusd)},
        None,
        ChallengeSelection(network="devnet", currencies=["PYUSD", "USDC"]),
    )
    assert picked is not None
    assert picked["asset"] == pyusd_mint


def test_parse_currency_falls_back_to_second_choice():
    usdc = _offer(asset=USDC_DEVNET, amount="1000000")
    picked = parse_x402_challenge(
        {"payment-required": _challenge_header(usdc)},
        None,
        ChallengeSelection(network="devnet", currencies=["USDT", "USDC"]),
    )
    assert picked is not None
    assert picked["asset"] == USDC_DEVNET


def test_parse_currency_none_match_returns_none():
    usdc = _offer(asset=USDC_DEVNET, amount="1000000")
    picked = parse_x402_challenge(
        {"payment-required": _challenge_header(usdc)},
        None,
        ChallengeSelection(network="devnet", currencies=["USDT"]),
    )
    assert picked is None


def test_parse_currency_accepts_mint_address_as_key():
    usdc = _offer(asset=USDC_DEVNET, amount="1000000")
    picked = parse_x402_challenge(
        {"payment-required": _challenge_header(usdc)},
        None,
        ChallengeSelection(network="devnet", currencies=[USDC_DEVNET]),
    )
    assert picked is not None
    assert picked["asset"] == USDC_DEVNET


def test_parse_no_preference_picks_cheapest():
    expensive = _offer(asset=USDC_DEVNET, amount="1000000")
    pyusd_mint = resolve("PYUSD", "devnet")
    assert pyusd_mint is not None
    cheap = _offer(asset=pyusd_mint, amount="5000", token_program=token_program_for("PYUSD", "devnet"))
    picked = parse_x402_challenge(
        {"payment-required": _challenge_header(expensive, cheap)},
        None,
        ChallengeSelection(network="devnet"),
    )
    assert picked is not None
    assert picked["amount"] == "5000"


def test_parse_garbage_returns_none():
    assert parse_x402_challenge({}, None, ChallengeSelection()) is None
    assert parse_x402_challenge({"payment-required": "not-base64-json!!"}, None, ChallengeSelection()) is None
    assert parse_x402_challenge({}, "garbage", ChallengeSelection()) is None


def test_parse_default_network_is_mainnet():
    # No selection.network -> default mainnet: the mainnet offer wins over a
    # devnet one even though devnet is cheaper.
    mainnet_offer = _offer(network=MAINNET, amount="9000")
    devnet_offer = _offer(network=DEVNET, amount="1")
    picked = parse_x402_challenge(
        {"payment-required": _challenge_header(devnet_offer, mainnet_offer)},
        None,
        ChallengeSelection(),
    )
    assert picked is not None
    assert picked["network"] == MAINNET


def test_parse_falls_back_to_any_solana_when_no_offer_on_preferred_network():
    # No currency preference and no offer on the preferred network -> fall back
    # to the overall cheapest solana offer (mirror rust ``.or_else``).
    devnet_offer = _offer(network=DEVNET, amount="1234")
    picked = parse_x402_challenge(
        {"payment-required": _challenge_header(devnet_offer)},
        None,
        ChallengeSelection(network="mainnet"),
    )
    assert picked is not None
    assert picked["network"] == DEVNET


# -- build_payment -----------------------------------------------------------


@pytest.mark.asyncio
async def test_build_payment_spl_round_trips_through_verifier():
    signer = Signer.generate()
    offer = _offer()
    env = await build_payment(signer, None, _entry(offer))
    assert cast("dict[str, Any]", env)["x402Version"] == 2
    assert cast("dict[str, Any]", env)["accepted"] == offer
    tx_b64 = _tx(env)
    # The built transaction must satisfy the structural verifier the server runs.
    result = ExactVerifier.verify(tx_b64, offer, [offer["extra"]["feePayer"]])
    assert result["amount"] == 1000
    assert result["mint"] == USDC_DEVNET
    assert result["destination"] == derive_ata(offer["payTo"], USDC_DEVNET, TP_USDC)


@pytest.mark.asyncio
async def test_build_payment_instruction_layout():
    signer = Signer.generate()
    offer = _offer()
    env = await build_payment(signer, None, _entry(offer))
    raw = base64.b64decode(_tx(env))
    tx = VersionedTransaction.from_bytes(raw)
    instructions = list(tx.message.instructions)
    keys = [str(k) for k in tx.message.account_keys]
    # ComputeBudget limit (disc 2) + price (disc 3) + transferChecked + memo.
    assert len(instructions) == 4
    assert bytes(instructions[0].data)[0] == 2
    # Canonical SetComputeUnitLimit value: 20_000, matching the rust/go clients.
    assert int.from_bytes(bytes(instructions[0].data)[1:5], "little") == 20_000
    assert bytes(instructions[1].data)[0] == 3
    # transferChecked: disc 12, amount u64 LE, decimals byte.
    transfer_data = bytes(instructions[2].data)
    assert transfer_data[0] == 12
    assert int.from_bytes(transfer_data[1:9], "little") == 1000
    assert transfer_data[9] == 6
    # fee payer (extra.feePayer) is account[0] and a required signer.
    assert keys[0] == offer["extra"]["feePayer"]
    assert int(tx.message.header.num_required_signatures) == 2


@pytest.mark.asyncio
async def test_build_payment_appends_random_memo_when_offer_has_none():
    """Decision 2: the client ALWAYS appends a memo.

    When the offer carries no ``extra.memo`` the client must still emit exactly
    one Memo instruction holding a >=16-byte hex nonce, so two otherwise
    identical payments are distinct on-chain.
    """
    from pay_kit.protocols.x402.exact.verify import MEMO_PROGRAM

    signer = Signer.generate()
    offer = _offer()
    del offer["extra"]["memo"]
    env = await build_payment(signer, None, _entry(offer))
    tx = VersionedTransaction.from_bytes(base64.b64decode(_tx(env)))
    instructions = list(tx.message.instructions)
    keys = [str(k) for k in tx.message.account_keys]
    assert len(instructions) == 4  # compute x2 + transfer + memo
    memo_ix = instructions[3]
    assert keys[int(memo_ix.program_id_index)] == MEMO_PROGRAM
    memo_text = bytes(memo_ix.data).decode("utf-8")
    # 16 bytes hex-encoded == 32 hex chars; bytes.fromhex validates it is hex.
    assert len(memo_text) >= 32
    bytes.fromhex(memo_text)


@pytest.mark.asyncio
async def test_build_payment_memo_nonce_is_injectable():
    """The nonce source is injectable so golden-vector tests stay deterministic."""
    from pay_kit.protocols.x402.exact.verify import MEMO_PROGRAM

    signer = Signer.generate()
    offer = _offer()
    del offer["extra"]["memo"]
    fixed = "00112233445566778899aabbccddeeff"
    env = await build_payment(signer, None, _entry(offer), memo_nonce=lambda: fixed)
    tx = VersionedTransaction.from_bytes(base64.b64decode(_tx(env)))
    instructions = list(tx.message.instructions)
    keys = [str(k) for k in tx.message.account_keys]
    memo_ix = instructions[3]
    assert keys[int(memo_ix.program_id_index)] == MEMO_PROGRAM
    assert bytes(memo_ix.data).decode("utf-8") == fixed


@pytest.mark.asyncio
async def test_build_payment_two_no_memo_payments_differ():
    """Two payments for the same offer must produce distinct transactions."""
    signer = Signer.generate()
    offer = _offer()
    del offer["extra"]["memo"]
    env1 = await build_payment(signer, None, _entry(offer))
    env2 = await build_payment(signer, None, _entry(offer))
    assert _tx(env1) != _tx(env2)


@pytest.mark.asyncio
async def test_build_payment_uses_extra_blockhash():
    signer = Signer.generate()
    offer = _offer(blockhash=BH)
    env = await build_payment(signer, None, _entry(offer))
    tx = VersionedTransaction.from_bytes(base64.b64decode(_tx(env)))
    assert str(tx.message.recent_blockhash) == BH


@pytest.mark.asyncio
async def test_build_payment_offline_via_injected_provider():
    signer = Signer.generate()
    offer = _offer(blockhash=None)  # no extra.recentBlockhash -> use provider
    env = await build_payment(signer, None, _entry(offer), recent_blockhash_provider=_fixed_blockhash)
    tx = VersionedTransaction.from_bytes(base64.b64decode(_tx(env)))
    assert str(tx.message.recent_blockhash) == BH


@pytest.mark.asyncio
async def test_build_payment_sync_provider():
    signer = Signer.generate()
    offer = _offer(blockhash=None)
    env = await build_payment(signer, None, _entry(offer), recent_blockhash_provider=lambda: BH)
    tx = VersionedTransaction.from_bytes(base64.b64decode(_tx(env)))
    assert str(tx.message.recent_blockhash) == BH


@pytest.mark.asyncio
async def test_build_payment_falls_back_to_rpc_blockhash():
    class _Rpc:
        async def get_latest_blockhash(self):
            from solders.hash import Hash

            class _Val:
                blockhash = Hash.from_string(BH)

            class _Resp:
                value = _Val()

            return _Resp()

    signer = Signer.generate()
    offer = _offer(blockhash=None)
    env = await build_payment(signer, _Rpc(), _entry(offer))
    tx = VersionedTransaction.from_bytes(base64.b64decode(_tx(env)))
    assert str(tx.message.recent_blockhash) == BH


@pytest.mark.asyncio
async def test_build_payment_native_sol():
    signer = Signer.generate()
    offer = _offer(asset="SOL", amount="5000")
    # SOL offers carry no tokenProgram; the System transfer path is taken.
    offer["extra"].pop("tokenProgram", None)
    env = await build_payment(signer, None, _entry(offer))
    tx = VersionedTransaction.from_bytes(base64.b64decode(_tx(env)))
    instructions = list(tx.message.instructions)
    # ComputeBudget x2 + System transfer + memo.
    assert len(instructions) == 4
    # System transfer instruction data: discriminator 2 (u32 LE) + lamports.
    transfer_data = bytes(instructions[2].data)
    assert int.from_bytes(transfer_data[0:4], "little") == 2
    assert int.from_bytes(transfer_data[4:12], "little") == 5000


@pytest.mark.asyncio
async def test_build_payment_rejects_invalid_amount():
    signer = Signer.generate()
    offer = _offer(amount="not-a-number")
    with pytest.raises(ValueError, match="invalid amount"):
        await build_payment(signer, None, _entry(offer))


@pytest.mark.asyncio
async def test_build_payment_defaults_token_program_when_offer_omits_it():
    # Rust ``build_spl_instructions`` defaults the token program via
    # ``default_token_program_for_currency`` when the offer omits it
    # (client/exact/payment.rs:445-452); the client must not error. USDC ->
    # classic Token program, so the built transferChecked uses TP_USDC.
    signer = Signer.generate()
    offer = _offer()
    del offer["extra"]["tokenProgram"]
    env = await build_payment(signer, None, _entry(offer))
    tx = VersionedTransaction.from_bytes(base64.b64decode(_tx(env)))
    instructions = list(tx.message.instructions)
    keys = [str(k) for k in tx.message.account_keys]
    transfer_ix = instructions[2]
    assert keys[int(transfer_ix.program_id_index)] == TP_USDC
    # The transfer's source/dest ATAs are derived off the same defaulted
    # program, matching what a server that pins extra.tokenProgram=TP_USDC
    # would re-derive.
    assert keys[int(transfer_ix.accounts[2])] == derive_ata(offer["payTo"], USDC_DEVNET, TP_USDC)


@pytest.mark.asyncio
async def test_build_payment_rejects_missing_asset():
    signer = Signer.generate()
    offer = _offer()
    del offer["asset"]
    with pytest.raises(ValueError, match="asset"):
        await build_payment(signer, None, _entry(offer))


@pytest.mark.asyncio
async def test_build_payment_rejects_missing_pay_to():
    signer = Signer.generate()
    offer = _offer()
    del offer["payTo"]
    with pytest.raises(ValueError, match="payTo"):
        await build_payment(signer, None, _entry(offer))


# -- rust-parity regressions -------------------------------------------------


@pytest.mark.asyncio
async def test_build_payment_fee_payer_explicit_false_opts_out():
    # Rust ``use_fee_payer = feePayer.unwrap_or(false) && fee_payer_key.is_some()``
    # (payment.rs:43-44): an explicit ``feePayer: false`` opts out even when a
    # key is present, so the client signer becomes the message fee payer
    # (account[0]) and the only required signer.
    signer = Signer.generate()
    offer = _offer()
    offer["feePayer"] = False
    env = await build_payment(signer, None, _entry(offer))
    tx = VersionedTransaction.from_bytes(base64.b64decode(_tx(env)))
    keys = [str(k) for k in tx.message.account_keys]
    assert keys[0] == str(signer.keypair.pubkey())
    assert int(tx.message.header.num_required_signatures) == 1


@pytest.mark.asyncio
async def test_build_payment_fee_payer_key_from_top_level():
    # Rust sources the fee-payer key from top-level ``feePayerKey`` first
    # (types.rs:350-351). A top-level key with no extra.feePayer must still be
    # used as account[0].
    signer = Signer.generate()
    fee_payer = str(Keypair().pubkey())
    offer = _offer()
    del offer["extra"]["feePayer"]
    offer["feePayerKey"] = fee_payer
    env = await build_payment(signer, None, _entry(offer))
    tx = VersionedTransaction.from_bytes(base64.b64decode(_tx(env)))
    keys = [str(k) for k in tx.message.account_keys]
    assert keys[0] == fee_payer
    assert int(tx.message.header.num_required_signatures) == 2


@pytest.mark.asyncio
async def test_build_payment_reads_token_program_and_decimals_top_level_first():
    # Rust reads tokenProgram/decimals/recentBlockhash top-level before extra
    # (types.rs:344-349). A top-level tokenProgram/decimals must win over extra.
    signer = Signer.generate()
    pyusd_mint = resolve("PYUSD", "devnet")
    assert pyusd_mint is not None
    tp_pyusd = token_program_for("PYUSD", "devnet")
    offer = _offer(asset=pyusd_mint, token_program=tp_pyusd)
    # Wrong values in extra; correct values at top level must override.
    offer["extra"]["tokenProgram"] = TP_USDC
    offer["extra"]["decimals"] = 9
    offer["tokenProgram"] = tp_pyusd
    offer["decimals"] = 6
    env = await build_payment(signer, None, _entry(offer))
    tx = VersionedTransaction.from_bytes(base64.b64decode(_tx(env)))
    instructions = list(tx.message.instructions)
    keys = [str(k) for k in tx.message.account_keys]
    transfer_ix = instructions[2]
    assert keys[int(transfer_ix.program_id_index)] == tp_pyusd
    assert bytes(transfer_ix.data)[9] == 6


@pytest.mark.asyncio
async def test_build_payment_reads_recent_blockhash_top_level_first():
    signer = Signer.generate()
    offer = _offer(blockhash=None)
    offer["recentBlockhash"] = BH
    env = await build_payment(signer, None, _entry(offer))
    tx = VersionedTransaction.from_bytes(base64.b64decode(_tx(env)))
    assert str(tx.message.recent_blockhash) == BH


@pytest.mark.asyncio
async def test_build_payment_currency_and_recipient_aliases_win():
    # Rust resolves currency/recipient top-level first, then asset/payTo
    # (types.rs:334-342). A top-level currency/recipient must override the
    # canonical asset/payTo aliases.
    signer = Signer.generate()
    real_pay_to = str(Keypair().pubkey())
    offer = _offer(asset="SOL", amount="5000")
    offer["extra"].pop("tokenProgram", None)
    offer["payTo"] = str(Keypair().pubkey())
    offer["recipient"] = real_pay_to
    env = await build_payment(signer, None, _entry(offer))
    tx = VersionedTransaction.from_bytes(base64.b64decode(_tx(env)))
    instructions = list(tx.message.instructions)
    keys = [str(k) for k in tx.message.account_keys]
    # System transfer destination is account index 1 of the transfer ix.
    transfer_ix = instructions[2]
    assert keys[int(transfer_ix.accounts[1])] == real_pay_to


@pytest.mark.asyncio
async def test_build_payment_rejects_negative_amount():
    # Rust ``amount.parse::<u64>()`` rejects a negative amount up front
    # (payment.rs:33-36); python must reject at parse, not at to_bytes.
    signer = Signer.generate()
    offer = _offer(amount="-1")
    with pytest.raises(ValueError, match="invalid amount"):
        await build_payment(signer, None, _entry(offer))


@pytest.mark.asyncio
async def test_build_payment_rejects_amount_above_u64():
    signer = Signer.generate()
    offer = _offer(amount=str(1 << 64))
    with pytest.raises(ValueError, match="invalid amount"):
        await build_payment(signer, None, _entry(offer))


@pytest.mark.asyncio
async def test_build_payment_echoes_resource_in_envelope():
    # Rust ``build_payment_header`` sets ``resource = requirements.resource_info()``
    # (payment.rs:131-138). When the offer carries resource info the client must
    # echo it at the envelope top level.
    signer = Signer.generate()
    offer = _offer()
    offer["resource"] = "https://api.example.test/data"
    offer["description"] = "Test data"
    env = await build_payment(signer, None, _entry(offer))
    resource = cast("dict[str, Any]", env)["resource"]
    assert resource == {"url": "https://api.example.test/data", "description": "Test data"}


@pytest.mark.asyncio
async def test_build_payment_omits_resource_when_offer_has_none():
    signer = Signer.generate()
    offer = _offer()
    env = await build_payment(signer, None, _entry(offer))
    assert "resource" not in cast("dict[str, Any]", env)


@pytest.mark.asyncio
async def test_parse_stashes_envelope_resource_without_polluting_accepted():
    # Rust ``with_resource_on_accepts`` (types.rs:463-476) attaches the
    # envelope's v2 resource to each parsed requirement so the client can echo
    # it at the *envelope* top level. The echoed ``accepted`` body must NOT gain
    # ``resource``/``description`` wire fields: the rust server's structural
    # compare (server/exact.rs verify_envelope_payload) rejects any top-level
    # field its own freshly built requirements do not carry, returning HTTP 402
    # ``payment_invalid``. Mirror rust ``to_accepted_value`` echoing the offer
    # verbatim while ``resource_info`` rides only the envelope.
    offer = _offer()
    body = {
        "x402Version": 2,
        "resource": {"url": "https://api.example.test/joke", "description": "A joke"},
        "accepts": [offer],
    }
    header = base64.b64encode(json.dumps(body).encode()).decode()
    picked = parse_x402_challenge(
        {"payment-required": header}, None, ChallengeSelection(network="devnet")
    )
    assert picked is not None
    # The wire-visible offer is untouched: no top-level resource/description.
    assert "resource" not in cast("dict[str, Any]", picked)
    assert "description" not in cast("dict[str, Any]", picked)

    signer = Signer.generate()
    env = await build_payment(signer, None, picked)
    decoded = cast("dict[str, Any]", env)
    # Envelope echoes the resource; the accepted body stays clean.
    assert decoded["resource"] == {
        "url": "https://api.example.test/joke",
        "description": "A joke",
    }
    assert "resource" not in decoded["accepted"]
    assert "description" not in decoded["accepted"]
    assert decoded["accepted"] == offer


# -- build_payment_header ----------------------------------------------------


@pytest.mark.asyncio
async def test_build_payment_header_envelope_shape():
    signer = Signer.generate()
    offer = _offer()
    header = await build_payment_header(signer, None, _entry(offer))
    decoded = json.loads(base64.b64decode(header))
    assert decoded["x402Version"] == 2
    assert decoded["accepted"] == offer
    assert "transaction" in decoded["payload"]
    # payload.transaction is itself valid base64.
    assert base64.b64decode(decoded["payload"]["transaction"])


# -- transport (402 -> pay -> 200) -------------------------------------------


class _FakeRpc:
    """Stub for the server-side SolanaRpc broadcast surface."""

    def __init__(self, *_a, signature: str = "SIG-client-harness", **_k):
        self._signature = signature

    async def send_raw_transaction(self, _raw):
        class _Resp:
            value = self._signature

        return _Resp()

    async def await_confirmation(self, _signature, *_a, **_k):
        return None

    async def aclose(self):
        return None


def _server_adapter_and_gate(monkeypatch):
    import pay_kit.protocols.x402 as xmod

    op = Operator(signer=LocalSigner.from_keypair(Keypair()), recipient=str(Keypair().pubkey()))
    cfg = configure(
        network="solana_localnet",
        preflight=False,
        accept=(Protocol.X402,),
        operator=op,
        rpc_url="http://127.0.0.1:8899",  # loopback skips the blockhash net check
    )
    gate = Gate.build(
        name="protected",
        amount=Price.usd("0.001", Stablecoin.USDC),
        default_pay_to=cfg.effective_recipient(),
        accept=(Protocol.X402,),
    )
    # Stamp a fixed blockhash into the offer so the client signs offline against it.
    adapter = X402Adapter(cfg, replay_store=MemoryStore(), recent_blockhash_provider=lambda: BH)
    monkeypatch.setattr(xmod, "SolanaRpc", lambda *_a, **_k: _FakeRpc())
    return adapter, gate


def _asgi_app(adapter: X402Adapter, gate: Gate):
    async def app(scope, receive, send):
        assert scope["type"] == "http"
        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
        request = {"headers": headers, "path": scope["path"]}

        async def respond(status: int, body: dict, extra_headers: dict):
            payload = json.dumps(body).encode()
            raw_headers = [(b"content-type", b"application/json")]
            for name, value in extra_headers.items():
                raw_headers.append((name.lower().encode(), value.encode()))
            await send({"type": "http.response.start", "status": status, "headers": raw_headers})
            await send({"type": "http.response.body", "body": payload})

        if not headers.get("payment-signature"):
            await respond(
                402,
                {"error": "payment_required"},
                adapter.challenge_headers(gate, request),
            )
            return
        payment = await adapter.verify_and_settle(gate, request)
        settle = dict(payment.settlement_headers)
        settle["x-fixture-settlement"] = payment.transaction
        await respond(200, {"ok": True, "transaction": payment.transaction}, settle)

    return app


@pytest.mark.asyncio
async def test_transport_402_then_pay_then_200(monkeypatch):
    adapter, gate = _server_adapter_and_gate(monkeypatch)
    app = _asgi_app(adapter, gate)
    signer = Signer.generate()

    inner = httpx.ASGITransport(app=app)
    transport = PaymentTransport(signer, None, network="localnet", base_transport=inner)
    async with httpx.AsyncClient(transport=transport, base_url="http://server") as client:
        resp = await client.get("/protected")

    assert resp.status_code == 200
    assert resp.json()["ok"] is True
    assert resp.headers["x-fixture-settlement"] == "SIG-client-harness"


@pytest.mark.asyncio
async def test_transport_sends_payment_signature_header(monkeypatch):
    adapter, gate = _server_adapter_and_gate(monkeypatch)
    seen_headers: list[dict[str, str]] = []
    base_app = _asgi_app(adapter, gate)

    async def recording_app(scope, receive, send):
        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
        seen_headers.append(headers)
        await base_app(scope, receive, send)

    inner = httpx.ASGITransport(app=recording_app)
    signer = Signer.generate()
    transport = PaymentTransport(signer, None, network="localnet", base_transport=inner)
    async with httpx.AsyncClient(transport=transport, base_url="http://server") as client:
        resp = await client.get("/protected")

    assert resp.status_code == 200
    # Two requests reached the app: the unpaid GET and the retried paid GET.
    assert len(seen_headers) == 2
    assert "payment-signature" not in seen_headers[0]
    assert "payment-signature" in seen_headers[1]


@pytest.mark.asyncio
async def test_transport_sends_x_payment_header_for_v1_challenge(monkeypatch):
    # A v1 challenge (x402Version:1 body) must make the transport emit the legacy
    # X-PAYMENT credential, not v2 PAYMENT-SIGNATURE. Regression for the gap where
    # the transport always built the v2 producer regardless of declared version.
    import pay_kit.protocols.x402.client.exact.transport as tmod

    async def fake_v1(*_a, **_k):
        return "V1-CRED"

    async def fake_v2(*_a, **_k):
        return "V2-CRED"

    monkeypatch.setattr(tmod, "build_payment_header_legacy", fake_v1)
    monkeypatch.setattr(tmod, "build_payment_header", fake_v2)

    v1_body = json.dumps({"x402Version": 1, "accepts": [_offer(network="solana-devnet")]})
    seen_headers: list[dict[str, str]] = []

    async def app(scope, receive, send):
        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
        seen_headers.append(headers)
        if "x-payment" in headers or "payment-signature" in headers:
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"{}"})
            return
        await send(
            {"type": "http.response.start", "status": 402, "headers": [(b"content-type", b"application/json")]}
        )
        await send({"type": "http.response.body", "body": v1_body.encode()})

    signer = Signer.generate()
    inner = httpx.ASGITransport(app=app)
    transport = PaymentTransport(signer, None, network="devnet", base_transport=inner)
    async with httpx.AsyncClient(transport=transport, base_url="http://server") as client:
        resp = await client.get("/protected")

    assert resp.status_code == 200
    assert len(seen_headers) == 2
    # The retry carries the legacy X-PAYMENT credential, NOT v2 Payment-Signature.
    assert seen_headers[1].get("x-payment") == "V1-CRED"
    assert "payment-signature" not in seen_headers[1]


@pytest.mark.asyncio
async def test_transport_passes_through_non_402(monkeypatch):
    async def ok_app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"text/plain")]})
        await send({"type": "http.response.body", "body": b"hi"})

    signer = Signer.generate()
    inner = httpx.ASGITransport(app=ok_app)
    transport = PaymentTransport(signer, None, network="localnet", base_transport=inner)
    async with httpx.AsyncClient(transport=transport, base_url="http://server") as client:
        resp = await client.get("/free")
    assert resp.status_code == 200
    assert resp.text == "hi"


@pytest.mark.asyncio
async def test_transport_returns_402_when_no_supported_challenge(monkeypatch):
    async def bare_402(scope, receive, send):
        await send({"type": "http.response.start", "status": 402, "headers": [(b"content-type", b"text/plain")]})
        await send({"type": "http.response.body", "body": b"nope"})

    signer = Signer.generate()
    inner = httpx.ASGITransport(app=bare_402)
    transport = PaymentTransport(signer, None, network="localnet", base_transport=inner)
    async with httpx.AsyncClient(transport=transport, base_url="http://server") as client:
        resp = await client.get("/protected")
    assert resp.status_code == 402


@pytest.mark.asyncio
async def test_transport_returns_original_402_on_build_failure(monkeypatch):
    # A challenge whose offer is missing tokenProgram: build_payment raises, the
    # transport logs and surfaces the original 402 rather than crashing.
    offer = _offer(network=DEVNET)
    del offer["extra"]["tokenProgram"]
    header = _challenge_header(offer)

    async def broken_app(scope, receive, send):
        await send(
            {
                "type": "http.response.start",
                "status": 402,
                "headers": [(b"content-type", b"application/json"), (b"payment-required", header.encode())],
            }
        )
        await send({"type": "http.response.body", "body": b"{}"})

    signer = Signer.generate()
    inner = httpx.ASGITransport(app=broken_app)
    transport = PaymentTransport(signer, None, network="devnet", base_transport=inner)
    async with httpx.AsyncClient(transport=transport, base_url="http://server") as client:
        resp = await client.get("/protected")
    assert resp.status_code == 402


@pytest.mark.asyncio
async def test_x402_client_factory(monkeypatch):
    adapter, gate = _server_adapter_and_gate(monkeypatch)
    app = _asgi_app(adapter, gate)
    signer = Signer.generate()
    inner = httpx.ASGITransport(app=app)
    client = X402Client(signer, None, network="localnet", base_transport=inner, base_url="http://server")
    try:
        resp = await client.get("/protected")
    finally:
        await client.aclose()
    assert resp.status_code == 200
