"""x402 ``upto`` engine flow coverage with a stubbed RPC (never live).

Exercises ``accepts_entry`` / ``challenge_headers`` / ``detect_usage`` /
``settlement_headers``; the full ``verify_open`` path (decode → cosign →
broadcast → confirm → fetch + validate on-chain channel state) with a fake
Borsh-encoded channel account; and ``settle_actual`` for the nonzero (voucher),
zero (no-voucher refund), and ceiling-exceeded cases.
"""

from __future__ import annotations

import base64
import json
import time

import pytest
from solders.keypair import Keypair  # type: ignore[import-untyped]
from solders.pubkey import Pubkey  # type: ignore[import-untyped]

import solana_pay_kit.protocols.x402.upto as upto_mod
from solana_pay_kit import (
    Config,
    Gate,
    LocalSigner,
    Operator,
    Price,
    Protocol,
    Stablecoin,
    configure,
)
from solana_pay_kit._paycore.mints import resolve, token_program_for
from solana_pay_kit.config import reset
from solana_pay_kit.errors import InvalidProofError
from solana_pay_kit.protocols.programs.paymentchannels.accounts.channel import Channel
from solana_pay_kit.protocols.x402.client.upto import build_upto_payload, encode_upto_header
from solana_pay_kit.protocols.x402.upto import _EMPTY_DISTRIBUTION_HASH as EMPTY_HASH
from solana_pay_kit.protocols.x402.upto import VerifiedUptoOpen, X402Upto
from solana_pay_kit.protocols.x402.upto.types import UPTO_ERROR_SETTLEMENT_EXCEEDS_AMOUNT, UptoRequirements

BH = "4vJ9JU1bJJQpUgJ8V6hYz7xXKz4F2tN6aBrZEcD3xKhs"


@pytest.fixture(autouse=True)
def _clean(monkeypatch: pytest.MonkeyPatch):
    reset()
    monkeypatch.setenv("PAY_KIT_DISABLE_PREFLIGHT", "1")
    yield
    reset()


class _FakeRpc:
    """Async RPC stub matching the SolanaRpc surface the engine uses."""

    def __init__(self, holder: dict[str, tuple[bytes, str] | None]) -> None:
        self._holder = holder
        self.sent: list[bytes] = []

    async def send_raw_transaction(self, raw: bytes):
        self.sent.append(raw)

        class _Resp:
            value = "SIG-upto"

        return _Resp()

    async def await_confirmation(self, _sig, *_a, **_k) -> None:
        return None

    async def get_account_info(self, _addr: str, commitment: str = "confirmed"):
        return self._holder["account"]

    async def get_latest_blockhash(self, commitment: str = "confirmed"):
        class _V:
            blockhash = BH

        class _Resp:
            value = _V()

        return _Resp()

    async def aclose(self) -> None:
        return None


def _engine(monkeypatch) -> tuple[X402Upto, Config, dict[str, tuple[bytes, str] | None]]:
    op = Operator(signer=LocalSigner.from_keypair(Keypair()), recipient=str(Keypair().pubkey()))
    cfg = configure(
        network="solana_localnet",
        preflight=False,
        accept=(Protocol.X402,),
        operator=op,
        rpc_url="http://127.0.0.1:8899",
    )
    eng = X402Upto(cfg, recent_blockhash_provider=lambda: BH)
    holder: dict[str, tuple[bytes, str] | None] = {"account": None}
    monkeypatch.setattr(upto_mod, "SolanaRpc", lambda *_a, **_k: _FakeRpc(holder))
    return eng, cfg, holder


def _gate(cfg) -> Gate:
    return Gate.build(
        name="usage",
        amount=Price.usd("0.10", Stablecoin.USDC),
        default_pay_to=cfg.effective_recipient(),
        accept=(Protocol.X402,),
    )


def _op_pubkey(cfg: Config) -> str:
    signer = cfg.effective_x402_signer()
    assert signer is not None
    return signer.pubkey()


class _Req:
    def __init__(self, header: str, path: str = "/usage") -> None:
        self.headers = {"payment-signature": header}
        self.path = path


def _fake_channel(
    *,
    payer: str,
    payee: str,
    mint: str,
    operator: str,
    deposit: int,
    status: int = 0,
    distribution_hash: list[int] | None = None,
) -> tuple[bytes, str]:
    """Build a Borsh-encoded channel account (1-byte discriminator + struct)."""
    body = Channel.layout.build(
        {
            "version": 1,
            "bump": 255,
            "status": status,
            "salt": 0,
            "deposit": deposit,
            "settlement": {"settled": 0, "payoutWatermark": 0},
            "closureStartedAt": 0,
            "payerWithdrawnAt": 0,
            "gracePeriod": 900,
            "distributionHash": distribution_hash if distribution_hash is not None else EMPTY_HASH,
            "payer": Pubkey.from_string(payer),
            "payee": Pubkey.from_string(payee),
            "authorizedSigner": Pubkey.from_string(operator),
            "mint": Pubkey.from_string(mint),
            "rentPayer": Pubkey.from_string(operator),
        }
    )
    return bytes([7]) + bytes(body), upto_mod.PAYMENT_CHANNELS_PROGRAM_ID


def _client_header(eng: X402Upto, cfg: Config) -> tuple[str, str, UptoRequirements]:
    """Build a client PAYMENT-SIGNATURE for the gate; return (header, client_pk, requirements)."""
    req = eng.accepts_entry(_gate(cfg), {"path": "/usage"})
    client = LocalSigner.from_keypair(Keypair())
    payload = build_upto_payload(client, req, int(time.time()) + 300, nonce="n")
    return encode_upto_header(req, payload), client.pubkey(), req


# -- offline accessors ------------------------------------------------------


def test_accepts_entry_shape(monkeypatch) -> None:
    eng, cfg, _ = _engine(monkeypatch)
    req = eng.accepts_entry(_gate(cfg), {"path": "/usage"})
    assert req["scheme"] == "upto"
    assert req["amount"] == "100000"
    assert req["extra"]["profiles"] == ["payment-channel"]
    assert req["extra"]["feePayer"] == _op_pubkey(cfg)
    # The spec field `facilitator` is sent too, so the TS client interops.
    assert req["extra"].get("facilitator") == _op_pubkey(cfg)
    assert req["extra"].get("recentBlockhash") == BH


def test_challenge_and_detect(monkeypatch) -> None:
    eng, cfg, _ = _engine(monkeypatch)
    headers = eng.challenge_headers(_gate(cfg), {"path": "/usage"})
    assert "payment-required" in headers
    assert eng.detect_usage(_Req("hdr")) is True
    assert eng.detect_usage({"headers": {}}) is False


def test_settlement_headers(monkeypatch) -> None:
    eng, _cfg, _ = _engine(monkeypatch)
    headers = eng.settlement_headers({"success": True, "transaction": "SIG", "network": "n", "amount": "5"})
    assert headers["x-payment-settlement-signature"] == "SIG"
    assert "payment-response" in headers


# -- verify_open full flow --------------------------------------------------


@pytest.mark.asyncio
async def test_verify_open_happy(monkeypatch) -> None:
    eng, cfg, holder = _engine(monkeypatch)
    header, client_pk, req = _client_header(eng, cfg)
    operator = _op_pubkey(cfg)
    holder["account"] = _fake_channel(
        payer=client_pk, payee=cfg.effective_recipient(), mint=req["asset"], operator=operator, deposit=100000
    )
    verified = await eng.verify_open(_gate(cfg), _Req(header))
    assert verified.max_amount == 100000
    assert verified.deposit == 100000
    assert str(verified.payer) == client_pk
    # The channel stays reserved from verify_open until settlement releases it.
    assert str(verified.channel_id) in eng._in_flight  # noqa: SLF001
    verified.release()
    assert str(verified.channel_id) not in eng._in_flight  # noqa: SLF001


@pytest.mark.asyncio
async def test_verify_open_binds_custom_gate_payee(monkeypatch) -> None:
    """A usage gate with its own pay_to is honored end to end: the channel binds
    to that payee and settlement targets it, not the global recipient (P1
    security regression - settle_actual must use verified.payee)."""
    eng, cfg, holder = _engine(monkeypatch)
    custom_payee = str(Keypair().pubkey())
    gate = Gate.build(
        name="usage", amount=Price.usd("0.10", Stablecoin.USDC), pay_to=custom_payee, accept=(Protocol.X402,)
    )
    req = eng.accepts_entry(gate, {"path": "/usage"})
    assert req["payTo"] == custom_payee and custom_payee != cfg.effective_recipient()
    client = LocalSigner.from_keypair(Keypair())
    payload = build_upto_payload(client, req, int(time.time()) + 300, nonce="n")
    header = encode_upto_header(req, payload)
    holder["account"] = _fake_channel(
        payer=client.pubkey(), payee=custom_payee, mint=req["asset"], operator=_op_pubkey(cfg), deposit=100000
    )
    verified = await eng.verify_open(gate, _Req(header))
    assert str(verified.payee) == custom_payee
    verified.release()


@pytest.mark.asyncio
async def test_verify_open_rejects_deposit_mismatch(monkeypatch) -> None:
    eng, cfg, holder = _engine(monkeypatch)
    header, client_pk, req = _client_header(eng, cfg)
    operator = _op_pubkey(cfg)
    holder["account"] = _fake_channel(
        payer=client_pk, payee=cfg.effective_recipient(), mint=req["asset"], operator=operator, deposit=50000
    )
    with pytest.raises(InvalidProofError, match="deposit"):
        await eng.verify_open(_gate(cfg), _Req(header))


@pytest.mark.asyncio
async def test_verify_open_rejects_non_empty_distribution_hash(monkeypatch) -> None:
    eng, cfg, holder = _engine(monkeypatch)
    header, client_pk, req = _client_header(eng, cfg)
    operator = _op_pubkey(cfg)
    holder["account"] = _fake_channel(
        payer=client_pk,
        payee=cfg.effective_recipient(),
        mint=req["asset"],
        operator=operator,
        deposit=100000,
        distribution_hash=[1] * 32,
    )
    with pytest.raises(InvalidProofError, match="empty-recipient"):
        await eng.verify_open(_gate(cfg), _Req(header))


@pytest.mark.asyncio
async def test_verify_open_missing_credential(monkeypatch) -> None:
    eng, cfg, _ = _engine(monkeypatch)
    with pytest.raises(InvalidProofError, match="payment required"):
        await eng.verify_open(_gate(cfg), {"headers": {}})


# -- settle_actual ----------------------------------------------------------


def _verified(cfg, *, max_amount: int = 100000) -> VerifiedUptoOpen:
    operator = _op_pubkey(cfg)
    label = cfg.network.mints_label()
    mint = resolve("USDC", label)
    assert mint is not None
    return VerifiedUptoOpen(
        channel_id=Pubkey.from_string("11111111111111111111111111111112"),
        payer=Pubkey.from_string(str(Keypair().pubkey())),
        payee=Pubkey.from_string(cfg.effective_recipient()),
        rent_payer=Pubkey.from_string(operator),
        mint=Pubkey.from_string(mint),
        token_program=Pubkey.from_string(token_program_for("USDC", label)),
        program_id=Pubkey.from_string(upto_mod.PAYMENT_CHANNELS_PROGRAM_ID),
        deposit=max_amount,
        max_amount=max_amount,
        expires_at=int(time.time()) + 300,
        network=cfg.network.caip2(),
    )


@pytest.mark.asyncio
async def test_settle_actual_nonzero(monkeypatch) -> None:
    eng, cfg, _ = _engine(monkeypatch)
    result = await eng.settle_actual(_verified(cfg), 50000)
    assert result["success"] is True
    assert result["amount"] == "50000"
    assert result["transaction"] == "SIG-upto"


@pytest.mark.asyncio
async def test_settle_actual_zero_is_honored(monkeypatch) -> None:
    eng, cfg, _ = _engine(monkeypatch)
    result = await eng.settle_actual(_verified(cfg), 0)
    assert result["success"] is True
    assert result["amount"] == "0"  # spec: settled amount MAY be 0 (no-voucher finalize + refund)


@pytest.mark.asyncio
async def test_settle_actual_exceeds_ceiling(monkeypatch) -> None:
    eng, cfg, _ = _engine(monkeypatch)
    with pytest.raises(InvalidProofError) as exc:
        await eng.settle_actual(_verified(cfg, max_amount=100000), 100001)
    assert exc.value.code == UPTO_ERROR_SETTLEMENT_EXCEEDS_AMOUNT


def test_verified_release_idempotent() -> None:
    calls = {"n": 0}

    def _rel() -> None:
        calls["n"] += 1

    v = VerifiedUptoOpen(
        channel_id=Pubkey.default(),
        payer=Pubkey.default(),
        payee=Pubkey.default(),
        rent_payer=Pubkey.default(),
        mint=Pubkey.default(),
        token_program=Pubkey.default(),
        program_id=Pubkey.default(),
        deposit=1,
        max_amount=1,
        expires_at=0,
        network="n",
        _release_fn=_rel,
    )
    v.release()
    v.release()
    assert calls["n"] == 1


# -- verify_open negative branches ------------------------------------------


def _remux(header: str, mutate) -> str:
    """Decode a base64 envelope, apply ``mutate`` to the dict, re-encode."""
    envelope = json.loads(base64.b64decode(header))
    mutate(envelope)
    return base64.b64encode(json.dumps(envelope).encode()).decode()


@pytest.mark.asyncio
async def test_verify_open_rejects_wrong_scheme(monkeypatch) -> None:
    eng, cfg, _ = _engine(monkeypatch)
    header, _pk, _req = _client_header(eng, cfg)
    # x402 v2 carries scheme inside `accepted` (the chosen PaymentRequirements).
    bad = _remux(header, lambda e: e["accepted"].update(scheme="exact"))
    with pytest.raises(InvalidProofError, match="invalid payload type"):
        await eng.verify_open(_gate(cfg), _Req(bad))


@pytest.mark.asyncio
async def test_verify_open_rejects_network_mismatch(monkeypatch) -> None:
    eng, cfg, _ = _engine(monkeypatch)
    header, _pk, _req = _client_header(eng, cfg)
    # x402 v2 carries network inside `accepted` (the chosen PaymentRequirements).
    bad = _remux(header, lambda e: e["accepted"].update(network="solana:wrongwrongwrongwrongwrongwrong"))
    with pytest.raises(InvalidProofError, match="network mismatch"):
        await eng.verify_open(_gate(cfg), _Req(bad))


@pytest.mark.asyncio
async def test_verify_open_requires_open_transaction(monkeypatch) -> None:
    eng, cfg, _ = _engine(monkeypatch)
    header, _pk, _req = _client_header(eng, cfg)

    def _drop(e: dict) -> None:
        e["payload"].pop("openTransaction", None)

    bad = _remux(header, _drop)
    with pytest.raises(InvalidProofError, match="requires openTransaction"):
        await eng.verify_open(_gate(cfg), _Req(bad))


@pytest.mark.asyncio
async def test_verify_open_channel_not_open(monkeypatch) -> None:
    eng, cfg, holder = _engine(monkeypatch)
    header, client_pk, req = _client_header(eng, cfg)
    op = _op_pubkey(cfg)
    holder["account"] = _fake_channel(
        payer=client_pk, payee=cfg.effective_recipient(), mint=req["asset"], operator=op, deposit=100000, status=2
    )
    with pytest.raises(InvalidProofError, match="not open"):
        await eng.verify_open(_gate(cfg), _Req(header))


@pytest.mark.asyncio
async def test_verify_open_mint_mismatch(monkeypatch) -> None:
    eng, cfg, holder = _engine(monkeypatch)
    header, client_pk, _req = _client_header(eng, cfg)
    op = _op_pubkey(cfg)
    holder["account"] = _fake_channel(
        payer=client_pk,
        payee=cfg.effective_recipient(),
        mint=str(Keypair().pubkey()),  # wrong mint
        operator=op,
        deposit=100000,
    )
    with pytest.raises(InvalidProofError, match="mint mismatch"):
        await eng.verify_open(_gate(cfg), _Req(header))


@pytest.mark.asyncio
async def test_verify_open_payer_mismatch(monkeypatch) -> None:
    eng, cfg, holder = _engine(monkeypatch)
    header, _client_pk, req = _client_header(eng, cfg)
    op = _op_pubkey(cfg)
    holder["account"] = _fake_channel(
        payer=str(Keypair().pubkey()),  # not the credential payer
        payee=cfg.effective_recipient(),
        mint=req["asset"],
        operator=op,
        deposit=100000,
    )
    with pytest.raises(InvalidProofError, match="does not match"):
        await eng.verify_open(_gate(cfg), _Req(header))


@pytest.mark.asyncio
async def test_verify_open_authorized_signer_mismatch(monkeypatch) -> None:
    eng, cfg, holder = _engine(monkeypatch)
    header, client_pk, req = _client_header(eng, cfg)
    holder["account"] = _fake_channel(
        payer=client_pk,
        payee=cfg.effective_recipient(),
        mint=req["asset"],
        operator=str(Keypair().pubkey()),  # channel opened with a different authorized signer
        deposit=100000,
    )
    with pytest.raises(InvalidProofError, match="authorized_signer is not the operator"):
        await eng.verify_open(_gate(cfg), _Req(header))


@pytest.mark.asyncio
async def test_verify_open_channel_missing(monkeypatch) -> None:
    eng, cfg, holder = _engine(monkeypatch)
    header, _pk, _req = _client_header(eng, cfg)
    holder["account"] = None
    with pytest.raises(InvalidProofError, match="missing account data"):
        await eng.verify_open(_gate(cfg), _Req(header))


@pytest.mark.asyncio
async def test_verify_open_owner_mismatch(monkeypatch) -> None:
    eng, cfg, holder = _engine(monkeypatch)
    header, client_pk, req = _client_header(eng, cfg)
    op = _op_pubkey(cfg)
    data, _owner = _fake_channel(
        payer=client_pk, payee=cfg.effective_recipient(), mint=req["asset"], operator=op, deposit=100000
    )
    holder["account"] = (data, str(Keypair().pubkey()))  # wrong owner
    with pytest.raises(InvalidProofError, match="not owned by"):
        await eng.verify_open(_gate(cfg), _Req(header))


def test_reserve_channel_concurrent(monkeypatch) -> None:
    eng, _cfg, _ = _engine(monkeypatch)
    eng._reserve_channel("CHAN")  # noqa: SLF001
    with pytest.raises(InvalidProofError, match="already being processed"):
        eng._reserve_channel("CHAN")  # noqa: SLF001


def test_parse_payload_missing_field() -> None:
    with pytest.raises(InvalidProofError, match="missing"):
        upto_mod._parse_payload({"profile": "payment-channel"})  # noqa: SLF001


def test_parse_payload_not_a_dict() -> None:
    with pytest.raises(InvalidProofError, match="malformed"):
        upto_mod._parse_payload("nope")  # noqa: SLF001
