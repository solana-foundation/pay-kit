"""Legacy x402 ``exact`` wire coverage (x402Version=1).

Covers the three new surfaces that ship the legacy wire alongside the canonical
(v2) one, mirroring the rust spine v1 arms:

* :mod:`pay_kit.protocols.x402.exact.legacy` plain-SVM-name mappings.
* the client legacy producer ``build_payment_header_legacy`` (top-level
  scheme/network, no ``accepted``) and the legacy challenge-parse fallbacks
  (``X-PAYMENT-REQUIRED`` header + 402 ``accepts[]`` body with plain slugs).
* the server dual-accept path in ``X402Adapter.verify_and_settle``: it reads
  the canonical header first then falls back to ``X-PAYMENT``; it MUST accept a
  legacy credential, still reject a genuinely-unknown version, and still emit a
  v2 challenge by default.
"""

from __future__ import annotations

import base64
import json
import struct

import pytest
from solders.hash import Hash
from solders.instruction import AccountMeta, Instruction
from solders.keypair import Keypair
from solders.message import MessageV0
from solders.pubkey import Pubkey

import pay_kit.protocols.x402 as xmod
from pay_kit import Gate as GateCls
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
from pay_kit._paycore.network import SOLANA_DEVNET_CAIP2, SOLANA_MAINNET_CAIP2
from pay_kit.config import reset
from pay_kit.errors import InvalidProofError
from pay_kit.protocols.x402 import X402Adapter
from pay_kit.protocols.x402.client.exact import (
    ChallengeSelection,
    build_payment_header_legacy,
    parse_x402_challenge,
)
from pay_kit.protocols.x402.exact.legacy import (
    SOLANA_DEVNET_NAME,
    SOLANA_NETWORK_NAME,
    X402_LEGACY_PAYMENT_HEADER,
    X402_LEGACY_PAYMENT_REQUIRED_HEADER,
    caip2_for_network,
    legacy_network_for_caip2,
)
from pay_kit.protocols.x402.exact.verify import (
    COMPUTE_BUDGET_PROGRAM,
    EXACT_SCHEME,
    MEMO_PROGRAM,
    X402_VERSION_V1,
    X402_VERSION_V2,
)

BH = "4vJ9JU1bJJQpUgJ8V6hYz7xXKz4F2tN6aBrZEcD3xKhs"
_MINT_DEVNET = resolve("USDC", "devnet")
assert _MINT_DEVNET is not None
MINT_DEVNET: str = _MINT_DEVNET
TP_DEVNET = token_program_for("USDC", "devnet")


# ── legacy.py network mappings ──────────────────────────────────────────────


def test_legacy_network_for_caip2_devnet_family():
    assert legacy_network_for_caip2(SOLANA_DEVNET_CAIP2) == SOLANA_DEVNET_NAME
    assert legacy_network_for_caip2("devnet") == SOLANA_DEVNET_NAME
    assert legacy_network_for_caip2("solana-devnet") == SOLANA_DEVNET_NAME
    assert legacy_network_for_caip2("localnet") == SOLANA_DEVNET_NAME


def test_legacy_network_for_caip2_defaults_to_solana():
    assert legacy_network_for_caip2(SOLANA_MAINNET_CAIP2) == SOLANA_NETWORK_NAME
    assert legacy_network_for_caip2("mainnet") == SOLANA_NETWORK_NAME
    assert legacy_network_for_caip2(None) == SOLANA_NETWORK_NAME


def test_caip2_for_network_normalizes_plain_slugs():
    assert caip2_for_network("solana") == SOLANA_MAINNET_CAIP2
    assert caip2_for_network("mainnet-beta") == SOLANA_MAINNET_CAIP2
    assert caip2_for_network("solana-devnet") == SOLANA_DEVNET_CAIP2
    assert caip2_for_network("devnet") == SOLANA_DEVNET_CAIP2
    assert caip2_for_network("localnet") == SOLANA_DEVNET_CAIP2
    assert caip2_for_network(None) == SOLANA_MAINNET_CAIP2
    # testnet round-trips through its own CAIP-2 id, not mainnet.
    assert caip2_for_network("solana-testnet").startswith("solana:")
    assert caip2_for_network("solana-testnet") != SOLANA_MAINNET_CAIP2


def test_caip2_for_network_passthrough_caip2():
    assert caip2_for_network(SOLANA_DEVNET_CAIP2) == SOLANA_DEVNET_CAIP2
    assert caip2_for_network(SOLANA_MAINNET_CAIP2) == SOLANA_MAINNET_CAIP2


# ── client legacy producer ──────────────────────────────────────────────────


def _devnet_offer(amount: str = "1000") -> dict:
    feepayer = str(Keypair().pubkey())
    return {
        "protocol": "x402",
        "scheme": "exact",
        "network": SOLANA_DEVNET_CAIP2,
        "asset": MINT_DEVNET,
        "amount": amount,
        "maxAmountRequired": amount,
        "payTo": str(Keypair().pubkey()),
        "maxTimeoutSeconds": 60,
        "extra": {"feePayer": feepayer, "decimals": 6, "tokenProgram": TP_DEVNET, "memo": "/r"},
    }


@pytest.mark.asyncio
async def test_legacy_producer_emits_top_level_scheme_and_plain_network():
    signer = LocalSigner.generate()
    offer = _devnet_offer()
    header = await build_payment_header_legacy(
        signer,
        rpc=None,
        requirement=offer,  # type: ignore[arg-type]
        recent_blockhash_provider=lambda: BH,
        memo_nonce=lambda: "00112233445566778899aabbccddeeff",
    )
    env = json.loads(base64.b64decode(header, validate=True))
    assert env["x402Version"] == X402_VERSION_V1
    # scheme + network are TOP-LEVEL siblings of payload; NO accepted object.
    assert env["scheme"] == EXACT_SCHEME
    assert env["network"] == SOLANA_DEVNET_NAME
    assert "accepted" not in env
    assert isinstance(env["payload"]["transaction"], str) and env["payload"]["transaction"]


@pytest.mark.asyncio
async def test_legacy_producer_maps_mainnet_to_plain_solana():
    signer = LocalSigner.generate()
    mint_mainnet = resolve("USDC", "mainnet")
    offer = {
        "protocol": "x402",
        "scheme": "exact",
        "network": SOLANA_MAINNET_CAIP2,
        "asset": mint_mainnet,
        "amount": "10000",
        "maxAmountRequired": "10000",
        "payTo": str(Keypair().pubkey()),
        "maxTimeoutSeconds": 60,
        "extra": {
            "feePayer": str(Keypair().pubkey()),
            "decimals": 6,
            "tokenProgram": token_program_for("USDC", "mainnet"),
            "memo": "/r",
        },
    }
    header = await build_payment_header_legacy(
        signer,
        rpc=None,
        requirement=offer,  # type: ignore[arg-type]
        recent_blockhash_provider=lambda: BH,
        memo_nonce=lambda: "00112233445566778899aabbccddeeff",
    )
    env = json.loads(base64.b64decode(header, validate=True))
    assert env["network"] == SOLANA_NETWORK_NAME


# ── client legacy challenge parsing ─────────────────────────────────────────


def test_parse_challenge_from_legacy_payment_required_header():
    offer = _devnet_offer()
    # Legacy challenge body shape with a plain network slug + maxAmountRequired.
    legacy_offer = dict(offer)
    legacy_offer["network"] = SOLANA_DEVNET_NAME
    body = json.dumps({"accepts": [legacy_offer]})
    headers = {X402_LEGACY_PAYMENT_REQUIRED_HEADER: body}
    parsed = parse_x402_challenge(headers, None, ChallengeSelection(network="devnet"))
    assert parsed is not None
    assert parsed["network"] == SOLANA_DEVNET_NAME
    assert parsed["asset"] == MINT_DEVNET


def test_parse_challenge_from_legacy_402_body_plain_network():
    offer = _devnet_offer()
    legacy_offer = dict(offer)
    legacy_offer["network"] = SOLANA_DEVNET_NAME
    body = json.dumps({"accepts": [legacy_offer]})
    parsed = parse_x402_challenge({}, body, ChallengeSelection(network="devnet"))
    assert parsed is not None
    assert parsed["network"] == SOLANA_DEVNET_NAME


def test_parse_challenge_canonical_header_wins_over_body():
    # When both a canonical (v2) header and a legacy body are present, the v2
    # header takes precedence (rust precedence order).
    v2_offer = _devnet_offer()
    v2_body = {"x402Version": X402_VERSION_V2, "accepts": [v2_offer]}
    v2_header = base64.b64encode(json.dumps(v2_body).encode()).decode()
    legacy_offer = dict(_devnet_offer(amount="9999"))
    legacy_offer["network"] = SOLANA_DEVNET_NAME
    legacy_body = json.dumps({"accepts": [legacy_offer]})
    parsed = parse_x402_challenge(
        {"payment-required": v2_header},
        legacy_body,
        ChallengeSelection(network="devnet"),
    )
    assert parsed is not None
    # The v2 header offer (amount 1000) wins, not the legacy body (9999).
    assert parsed["amount"] == "1000"


# ── server dual-accept ──────────────────────────────────────────────────────


class _FakeRpc:
    def __init__(self, *_a, signature="SIG-legacy", **_k):
        self._signature = signature
        self.confirm_calls = 0
        self.aclose_calls = 0

    async def send_raw_transaction(self, _raw):
        class _Resp:
            value = self._signature

        return _Resp()

    async def await_confirmation(self, _sig, *_a, **_k):
        self.confirm_calls += 1
        return None

    async def aclose(self):
        self.aclose_calls += 1
        return None


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    reset()
    monkeypatch.setenv("PAY_KIT_DISABLE_PREFLIGHT", "1")
    yield
    reset()


def _devnet_adapter(monkeypatch, signature="SIG-legacy"):
    op_kp = Keypair()
    op = Operator(signer=LocalSigner.from_keypair(op_kp), recipient=str(Keypair().pubkey()))
    cfg = configure(
        network="solana_devnet",
        preflight=False,
        accept=(Protocol.X402,),
        operator=op,
        stablecoins=(Stablecoin.USDC,),
        rpc_url="http://127.0.0.1:8899",
    )
    gate = GateCls.build(
        name="report",
        amount=Price.usd("0.001", Stablecoin.USDC),
        default_pay_to=cfg.effective_recipient(),
        accept=(Protocol.X402,),
    )
    adapter = X402Adapter(cfg, replay_store=MemoryStore())

    def _factory(*_a, **_k):
        return _FakeRpc(signature=signature)

    monkeypatch.setattr(xmod, "SolanaRpc", _factory)
    return adapter, gate, op_kp


def _legacy_envelope(adapter, gate, op_kp, *, network=SOLANA_DEVNET_NAME, version=X402_VERSION_V1, scheme=EXACT_SCHEME):
    offer = adapter.accepts_entry(gate, {"path": "/report"})
    amt = int(offer["amount"])
    authority = Keypair()
    dest = derive_ata(offer["payTo"], MINT_DEVNET, TP_DEVNET)
    src = derive_ata(str(authority.pubkey()), MINT_DEVNET, TP_DEVNET)
    cl = Instruction(Pubkey.from_string(COMPUTE_BUDGET_PROGRAM), bytes([2]) + struct.pack("<I", 200_000), [])
    cp = Instruction(Pubkey.from_string(COMPUTE_BUDGET_PROGRAM), bytes([3]) + struct.pack("<Q", 1_000), [])
    data = bytes([12]) + struct.pack("<Q", amt) + bytes([6])
    metas = [
        AccountMeta(Pubkey.from_string(src), False, True),
        AccountMeta(Pubkey.from_string(MINT_DEVNET), False, False),
        AccountMeta(Pubkey.from_string(dest), False, True),
        AccountMeta(authority.pubkey(), True, False),
    ]
    transfer = Instruction(Pubkey.from_string(TP_DEVNET), data, metas)
    memo = Instruction(Pubkey.from_string(MEMO_PROGRAM), offer["extra"]["memo"].encode(), [])
    msg = MessageV0.try_compile(op_kp.pubkey(), [cl, cp, transfer, memo], [], Hash.from_string(BH))
    num = int(msg.header.num_required_signatures)
    wire = bytearray()
    wire.append(num)
    wire.extend(bytes(64) * num)
    wire.extend(bytes(msg))
    tx_b64 = base64.b64encode(bytes(wire)).decode()
    # Legacy envelope: top-level scheme + plain network, NO accepted object.
    envelope: dict = {
        "x402Version": version,
        "scheme": scheme,
        "network": network,
        "payload": {"transaction": tx_b64},
    }
    return base64.b64encode(json.dumps(envelope).encode()).decode()


class _LegacyReq:
    """Carries the credential ONLY in the legacy ``X-PAYMENT`` header."""

    def __init__(self, header, path="/report"):
        self.headers = {X402_LEGACY_PAYMENT_HEADER.lower(): header}
        self.path = path


@pytest.mark.asyncio
async def test_server_accepts_legacy_x_payment_header(monkeypatch):
    adapter, gate, op_kp = _devnet_adapter(monkeypatch, signature="SIG-legacy-ok")
    header = _legacy_envelope(adapter, gate, op_kp)
    payment = await adapter.verify_and_settle(gate, _LegacyReq(header))
    assert payment.protocol is Protocol.X402
    assert payment.transaction == "SIG-legacy-ok"
    # A v1 credential gets the legacy X-PAYMENT-RESPONSE receipt header, NOT the
    # v2 payment-response (rust X402_V1_PAYMENT_RESPONSE_HEADER, constants.rs:22).
    assert "payment-response" not in payment.settlement_headers
    resp = json.loads(base64.b64decode(payment.settlement_headers["x-payment-response"]))
    assert resp["network"] == SOLANA_DEVNET_CAIP2


@pytest.mark.asyncio
async def test_server_accepts_legacy_header_from_dict_request(monkeypatch):
    # The legacy reader's dict-request fallback (case-insensitive header key).
    adapter, gate, op_kp = _devnet_adapter(monkeypatch, signature="SIG-dict")
    header = _legacy_envelope(adapter, gate, op_kp)
    req = {"path": "/report", "headers": {"X-Payment": header}}
    payment = await adapter.verify_and_settle(gate, req)
    assert payment.transaction == "SIG-dict"


@pytest.mark.asyncio
async def test_server_rejects_unknown_version_on_dual_accept(monkeypatch):
    adapter, gate, op_kp = _devnet_adapter(monkeypatch)
    header = _legacy_envelope(adapter, gate, op_kp, version=9)
    with pytest.raises(InvalidProofError) as exc:
        await adapter.verify_and_settle(gate, _LegacyReq(header))
    assert exc.value.code == "unsupported_x402_version"


@pytest.mark.asyncio
async def test_server_rejects_legacy_wrong_network(monkeypatch):
    adapter, gate, op_kp = _devnet_adapter(monkeypatch)
    # Plain "solana" normalizes to mainnet, route is devnet -> mismatch.
    header = _legacy_envelope(adapter, gate, op_kp, network=SOLANA_NETWORK_NAME)
    with pytest.raises(InvalidProofError) as exc:
        await adapter.verify_and_settle(gate, _LegacyReq(header))
    assert exc.value.code == "charge_request_mismatch"
    assert "Network mismatch" in str(exc.value)


@pytest.mark.asyncio
async def test_server_rejects_legacy_non_exact_scheme(monkeypatch):
    adapter, gate, op_kp = _devnet_adapter(monkeypatch)
    header = _legacy_envelope(adapter, gate, op_kp, scheme="upto")
    with pytest.raises(InvalidProofError) as exc:
        await adapter.verify_and_settle(gate, _LegacyReq(header))
    assert exc.value.code == "invalid_exact_svm_payload_scheme"


@pytest.mark.asyncio
async def test_server_rejects_legacy_missing_payload(monkeypatch):
    adapter, gate, op_kp = _devnet_adapter(monkeypatch)
    envelope = {"x402Version": X402_VERSION_V1, "scheme": EXACT_SCHEME, "network": SOLANA_DEVNET_NAME}
    header = base64.b64encode(json.dumps(envelope).encode()).decode()
    with pytest.raises(InvalidProofError) as exc:
        await adapter.verify_and_settle(gate, _LegacyReq(header))
    assert exc.value.code == "invalid_exact_svm_payload_envelope"


@pytest.mark.asyncio
async def test_server_still_emits_v2_challenge_by_default(monkeypatch):
    # Adding the legacy path must NOT flip the default challenge producer.
    adapter, gate, _ = _devnet_adapter(monkeypatch)
    headers = adapter.challenge_headers(gate, {"path": "/report"})
    assert "payment-required" in headers
    challenge = json.loads(base64.b64decode(headers["payment-required"]))
    assert challenge["x402Version"] == X402_VERSION_V2
    assert challenge["accepts"][0]["network"] == SOLANA_DEVNET_CAIP2


@pytest.mark.asyncio
async def test_server_prefers_canonical_header_over_legacy(monkeypatch):
    # When BOTH headers are present, the canonical (v2) one is read first.
    from pay_kit.protocols.x402 import _legacy_payment_header, _payment_signature_header

    class _BothReq:
        def __init__(self, v2_header, legacy_header):
            self.headers = {
                "payment-signature": v2_header,
                X402_LEGACY_PAYMENT_HEADER.lower(): legacy_header,
            }
            self.path = "/report"

    req = _BothReq("V2VALUE", "LEGACYVALUE")
    assert _payment_signature_header(req) == "V2VALUE"
    assert _legacy_payment_header(req) == "LEGACYVALUE"
