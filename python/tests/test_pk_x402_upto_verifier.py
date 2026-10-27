"""x402 ``upto`` pure-verifier + client-builder coverage (fully offline).

Covers the payload parse and ordered payload checks, the settlement-ceiling
assertion, the open-transaction acceptance policy (layout, accounts,
privileges, decoded args, versions), the pre-broadcast preparation and
co-signature, and the client builder - including a client↔engine wire
cross-check: the open the client builds must pass the engine's validator.
"""

from __future__ import annotations

import base64
import json
import time
from typing import Any

import pytest
from solana_keychain import MemorySigner
from solders.hash import Hash  # type: ignore[import-untyped]
from solders.instruction import AccountMeta, Instruction  # type: ignore[import-untyped]
from solders.keypair import Keypair  # type: ignore[import-untyped]
from solders.message import Message, MessageV0  # type: ignore[import-untyped]
from solders.pubkey import Pubkey  # type: ignore[import-untyped]
from solders.signature import Signature  # type: ignore[import-untyped]
from solders.transaction import VersionedTransaction  # type: ignore[import-untyped]

from solana_pay_kit._paycore import txv1
from solana_pay_kit._paycore.paymentchannels import (
    COMPUTE_BUDGET_SET_UNIT_LIMIT,
    COMPUTE_BUDGET_SET_UNIT_PRICE,
    LIGHTHOUSE_PROGRAM,
    PROGRAM_ID,
    Distribution,
    OpenChannelParams,
    build_open_instruction,
    distribution_hash,
    find_channel_pda,
)
from solana_pay_kit._paycore.solana import COMPUTE_BUDGET_PROGRAM, MEMO_PROGRAM, TOKEN_PROGRAM
from solana_pay_kit.errors import InvalidProofError
from solana_pay_kit.protocols.x402.client.upto import (
    build_upto_header,
    build_upto_payload,
    encode_upto_header,
    parse_upto_challenge,
)
from solana_pay_kit.protocols.x402.upto import (
    UptoRoute,
    cosign_upto_open,
    prepare_upto_open,
    route_memo,
    upto_requirements,
    verify_upto_open_preflight,
)
from solana_pay_kit.protocols.x402.upto.open import advertised_versions, match_offered_requirement
from solana_pay_kit.protocols.x402.upto.types import (
    UPTO_ERROR_SETTLEMENT_EXCEEDS_AMOUNT,
    UPTO_SCHEME,
    UptoRequirements,
)
from solana_pay_kit.protocols.x402.upto.verify import (
    ParsedUptoPayload,
    assert_settlement_within_ceiling,
    parse_base_units,
    parse_upto_payload,
    validate_upto_open_instruction,
    verify_payer_signature,
    verify_upto_payload,
)

BH = "4vJ9JU1bJJQpUgJ8V6hYz7xXKz4F2tN6aBrZEcD3xKhs"
MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"  # USDC mainnet
NETWORK = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"
MAX = 100000
SLOT = 4242
NOW = 1_800_000_000


def _operator() -> tuple[MemorySigner, str]:
    signer = MemorySigner(Keypair())
    return signer, str(signer.pubkey)


def _requirements(operator: str, pay_to: str, *, amount: int = MAX) -> UptoRequirements:
    return {
        "scheme": UPTO_SCHEME,
        "network": NETWORK,
        "amount": str(amount),
        "asset": MINT,
        "payTo": pay_to,
        "maxTimeoutSeconds": 300,
        "extra": {
            "decimals": 6,
            "tokenProgram": TOKEN_PROGRAM,
            "feePayer": operator,
            "receiverAuthorizer": operator,
            "withdrawDelay": 900,
            "recentBlockhash": BH,
            "recentSlot": str(SLOT),
        },
    }


def _payload(operator: str, *, now: int | None = None) -> dict[str, Any]:
    now = int(time.time()) if now is None else now
    return {
        "from": str(Keypair().pubkey()),
        "maxAmount": str(MAX),
        "expiresAt": now + 300,
        "validAfter": now - 10,
        "nonce": "7",
        "channelId": "11111111111111111111111111111112",
        "deposit": str(MAX),
        "authorizedSigner": operator,
        "openSlot": str(SLOT),
    }


# -- scalars and payload parse ---------------------------------------------------


def test_parse_base_units_ok() -> None:
    assert parse_base_units("100000", "amount") == 100000


@pytest.mark.parametrize("bad", ["", "abc", "-1", "+1", " 1", "1.5", str(2**64), 5])
def test_parse_base_units_rejects(bad: Any) -> None:
    with pytest.raises(InvalidProofError, match="invalid upto amount"):
        parse_base_units(bad, "amount")


def test_parse_payload_reads_both_slot_forms() -> None:
    _, op = _operator()
    parsed = parse_upto_payload(_payload(op))
    assert isinstance(parsed, ParsedUptoPayload)
    assert (parsed.nonce, parsed.open_slot, parsed.open_transaction) == (7, SLOT, None)
    number = {**_payload(op), "openSlot": SLOT}
    assert parse_upto_payload(number).open_slot == SLOT


@pytest.mark.parametrize(
    ("mutate", "needle"),
    [
        (lambda p: p.update(voucherSignature="sig"), "invalid_upto_svm_payload_unexpected_voucher"),
        (lambda p: p.update(voucherSignature=None), "invalid_upto_svm_payload_unexpected_voucher"),
        (lambda p: p.update(type="deposit"), "invalid_upto_svm_payload_type"),
        (lambda p: p.update(nonce="0x7"), "nonce .* is not a decimal u64"),
        (lambda p: p.update(nonce=7), "nonce .* is not a decimal u64"),
        (lambda p: p.pop("nonce"), "missing field `nonce`"),
        (lambda p: p.update(openSlot="-1"), "openSlot .* is not a u64"),
        (lambda p: p.update(openSlot=1.5), "openSlot .* is not a u64"),
        (lambda p: p.pop("openSlot"), "missing field `openSlot`"),
        (lambda p: p.update(expiresAt=1.5), "expiresAt .* is not an integer"),
        (lambda p: p.update(validAfter=True), "validAfter .* is not an integer"),
        (lambda p: p.pop("validAfter"), "missing field `validAfter`"),
        (lambda p: p.update(maxAmount=5), "maxAmount must be a string"),
        (lambda p: p.pop("from"), "missing field `from`"),
        (lambda p: p.update(openTransaction=5), "openTransaction must be a string"),
    ],
)
def test_parse_payload_rejects(mutate, needle: str) -> None:
    _, op = _operator()
    payload = _payload(op)
    mutate(payload)
    with pytest.raises(InvalidProofError, match=needle):
        parse_upto_payload(payload)


def test_parse_payload_rejects_a_non_object() -> None:
    with pytest.raises(InvalidProofError, match="must be an object"):
        parse_upto_payload("nope")


# -- verify_upto_payload ----------------------------------------------------


def _verify(payload: dict[str, Any], op: str, now: int, **kwargs: Any) -> None:
    verify_upto_payload(payload, _requirements(op, str(Keypair().pubkey())), op, now, **kwargs)


def test_verify_payload_happy() -> None:
    _, op = _operator()
    _verify(_payload(op, now=NOW), op, NOW)
    verify_upto_payload(parse_upto_payload(_payload(op, now=NOW)), _requirements(op, op), op, NOW)


@pytest.mark.parametrize(
    ("mutate", "needle"),
    [
        (lambda p: p.update(maxAmount="999", deposit="999"), "Amount mismatch"),
        (lambda p: p.update(maxAmount="1.5"), "invalid upto maxAmount"),
        (lambda p: p.update(deposit="50000"), "channel deposit 50000 != authorized maximum"),
        (lambda p: p.update(validAfter=NOW + 100), "not yet active"),
        (lambda p: p.update(expiresAt=NOW - 1), "authorization expired"),
        (lambda p: p.update(expiresAt=0), "authorization expired"),
        (lambda p: p.update(expiresAt=NOW), "authorization expired"),
        (lambda p: p.update(expiresAt=NOW + 361), "invalid_upto_svm_payload_expires_at_mismatch"),
        (lambda p: p.update(authorizedSigner=str(Keypair().pubkey())), "advertised receiver authorizer"),
    ],
)
def test_verify_payload_rejects(mutate, needle: str) -> None:
    _, op = _operator()
    payload = _payload(op, now=NOW)
    mutate(payload)
    with pytest.raises(InvalidProofError, match=needle):
        _verify(payload, op, NOW)


def test_verify_payload_bounds_the_channel_lifetime() -> None:
    _, op = _operator()
    # expiresAt within the completion window plus the 60 s skew verifies.
    _verify({**_payload(op, now=NOW), "expiresAt": NOW + 360}, op, NOW)
    with pytest.raises(InvalidProofError, match="channel_lifetime_exceeded: maxTimeoutSeconds 300"):
        _verify(_payload(op, now=NOW), op, NOW, max_channel_lifetime_seconds=299)
    with pytest.raises(InvalidProofError, match="channel_lifetime_exceeded: expiresAt is 361s away"):
        _verify({**_payload(op, now=NOW), "expiresAt": NOW + 361}, op, NOW, max_channel_lifetime_seconds=300)
    with pytest.raises(InvalidProofError, match="must be positive"):
        _verify(_payload(op, now=NOW), op, NOW, max_channel_lifetime_seconds=0)


# -- assert_settlement_within_ceiling ---------------------------------------


def test_ceiling_ok() -> None:
    assert_settlement_within_ceiling(50000, 100000)
    assert_settlement_within_ceiling(100000, 100000)
    assert_settlement_within_ceiling(0, 100000)


def test_ceiling_exceeded() -> None:
    with pytest.raises(InvalidProofError) as exc:
        assert_settlement_within_ceiling(100001, 100000)
    assert exc.value.code == UPTO_ERROR_SETTLEMENT_EXCEEDS_AMOUNT


# -- requirements and accepted matching -------------------------------------


def _route(op: str, pay_to: str, **kwargs: Any) -> UptoRoute:
    return UptoRoute(
        network=NETWORK,
        amount=MAX,
        asset=MINT,
        token_program=TOKEN_PROGRAM,
        pay_to=pay_to,
        fee_payer=op,
        receiver_authorizer=op,
        **kwargs,
    )


def test_distribution_hash_matches_the_program() -> None:
    recipient = Pubkey.from_string("CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY")
    digest = distribution_hash([Distribution(recipient=recipient, bps=10_000)])
    assert list(digest[:8]) == [74, 31, 25, 77, 17, 35, 50, 9]
    with pytest.raises(ValueError, match="bps"):
        distribution_hash([Distribution(recipient=recipient, bps=1 << 16)])


def test_route_memo_matches_the_rust_kit() -> None:
    assert route_memo("GET /reports?id=7") == "x402-upto:6cfdd3406cd373ee0107ec9cacd5c191"


def test_upto_requirements_shape() -> None:
    _, op = _operator()
    req = upto_requirements(_route(op, op))
    assert req["extra"] == {
        "tokenProgram": TOKEN_PROGRAM,
        "feePayer": op,
        "receiverAuthorizer": op,
        "withdrawDelay": 900,
    }
    assert req["maxTimeoutSeconds"] == 300
    bound = upto_requirements(_route(op, op, memo="m", transaction_versions=[0, 1], decimals=6))
    assert bound["extra"].get("memo") == "m"
    assert bound["extra"].get("transactionVersions") == [0, 1]
    assert bound["extra"].get("decimals") == 6
    assert advertised_versions((0,)) is None
    assert advertised_versions((0, 1)) == [0, 1]
    with pytest.raises(ValueError, match="withdrawDelay"):
        upto_requirements(_route(op, op, withdraw_delay=0))


def test_match_ignores_hints_and_informational_fields() -> None:
    _, op = _operator()
    offered = upto_requirements(_route(op, op))
    echoed = json.loads(json.dumps(_requirements(op, op)))
    echoed["extra"]["recentSlot"] = SLOT  # the number form
    echoed["extra"]["paymentFlow"] = "escrow"
    assert match_offered_requirement([offered], echoed) is offered


@pytest.mark.parametrize(
    ("mutate", "needle"),
    [
        (lambda a: a.update(amount="1"), "does not match any offered"),
        (lambda a: a["extra"].update(memo="other"), "does not match any offered"),
        (lambda a: a["extra"].update(transactionVersions=[0, 1]), "does not match any offered"),
        (lambda a: a["extra"].update(transactionVersions=["0"]), "invalid accepted requirement"),
        (lambda a: a["extra"].update(withdrawDelay=900.5), "invalid accepted requirement"),
        (lambda a: a["extra"].pop("feePayer"), "missing field `feePayer`"),
        (lambda a: a["extra"].update(recentSlot="x"), "recentSlot"),
        (lambda a: a["extra"].update(recentBlockhash=5), "recentBlockhash must be a string"),
        (lambda a: a["extra"].update(validAfter=1.5), "validAfter"),
        (lambda a: a["extra"].update(memo=5), "memo must be a string"),
        (lambda a: a.pop("extra"), "missing field `extra`"),
        (lambda a: a.update(scheme=5), "scheme must be a string"),
    ],
)
def test_match_rejects(mutate, needle: str) -> None:
    _, op = _operator()
    accepted = json.loads(json.dumps(_requirements(op, op)))
    mutate(accepted)
    with pytest.raises(InvalidProofError, match=needle):
        match_offered_requirement([upto_requirements(_route(op, op))], accepted)
    with pytest.raises(InvalidProofError, match="must be an object"):
        match_offered_requirement([], "nope")


# -- client builder ----------------------------------------------------------


def test_parse_upto_challenge() -> None:
    _, op = _operator()
    req = _requirements(op, str(Keypair().pubkey()))
    header = base64.b64encode(json.dumps({"x402Version": 2, "accepts": [req]}).encode()).decode()
    parsed = parse_upto_challenge({"payment-required": header})
    assert parsed is not None and parsed["scheme"] == UPTO_SCHEME
    body = json.dumps({"accepts": [req]})
    parsed = parse_upto_challenge({}, body)
    assert parsed is not None and parsed["payTo"] == req["payTo"]
    assert parse_upto_challenge({}) is None
    assert parse_upto_challenge({}, "{}") is None


class _SlotRpc:
    """``getLatestBlockhash`` with its response-context slot."""

    def __init__(self, slot: int | None = 5000, live: bool = True) -> None:
        self.slot = slot
        self.live = live
        self.calls = 0
        self.checked: list[str] = []

    async def is_blockhash_valid(self, blockhash: str, commitment: str = "confirmed") -> bool:
        assert commitment == "confirmed"
        self.checked.append(blockhash)
        return self.live

    async def get_latest_blockhash(self, commitment: str = "confirmed"):
        self.calls += 1
        slot = self.slot

        class _V:
            blockhash = BH

        class _C:
            pass

        context = _C()
        context.slot = slot  # type: ignore[attr-defined]

        class _Resp:
            value = _V()

        resp = _Resp()
        resp.context = context  # type: ignore[attr-defined]
        return resp

    async def get_account_info(self, _address: str, commitment: str = "confirmed"):
        return None


async def test_build_without_hints_reads_one_blockhash() -> None:
    _, op = _operator()
    client = MemorySigner(Keypair())
    req = _requirements(op, op)
    del req["extra"]["recentSlot"]
    with pytest.raises(ValueError, match="no rpc"):
        await build_upto_payload(client, req, NOW + 300)
    rpc = _SlotRpc()
    payload = await build_upto_payload(client, req, NOW + 300, rpc=rpc)
    assert payload["openSlot"] == "5000" and rpc.calls == 1
    del req["extra"]["recentBlockhash"]
    req["extra"]["recentSlot"] = SLOT  # type: ignore[typeddict-item]
    payload = await build_upto_payload(client, req, NOW + 300, rpc=rpc)
    assert payload["openSlot"] == str(SLOT)
    del req["extra"]["recentSlot"]
    with pytest.raises(ValueError, match="no slot"):
        await build_upto_payload(client, req, NOW + 300, rpc=_SlotRpc(None))


async def test_build_refuses_a_hint_blockhash_the_client_cluster_does_not_know() -> None:
    _, op = _operator()
    client = MemorySigner(Keypair())
    req = _requirements(op, op)
    live = _SlotRpc()
    await build_upto_payload(client, req, NOW + 300, rpc=live)
    assert live.checked == [BH] and live.calls == 0
    dead = _SlotRpc(live=False)
    with pytest.raises(ValueError, match="is not a live blockhash on the client's cluster"):
        await build_upto_payload(client, req, NOW + 300, rpc=dead)
    assert dead.checked == [BH]


async def test_build_salt_follows_the_request_nonce() -> None:
    _, op = _operator()
    client = MemorySigner(Keypair())
    req = _requirements(op, op)
    a = await build_upto_payload(client, req, NOW + 300, nonce="request-7")
    b = await build_upto_payload(client, req, NOW + 300, nonce="request-7")
    c = await build_upto_payload(client, req, NOW + 300)
    assert a["nonce"] == b["nonce"] and a["channelId"] == b["channelId"]
    assert c["nonce"] != a["nonce"]


@pytest.mark.parametrize(
    ("mutate", "needle"),
    [
        (lambda r: r["extra"].update(withdrawDelay=0), "withdrawDelay"),
        (lambda r: r["extra"].update(withdrawDelay=900.5), "withdrawDelay"),
        (lambda r: r["extra"].pop("feePayer"), "extra.feePayer"),
        (lambda r: r["extra"].pop("receiverAuthorizer"), "extra.receiverAuthorizer"),
        (lambda r: r["extra"].update(memo="m" * 257), "memo is 257 bytes"),
        (lambda r: r["extra"].update(memo=5), "memo must be a string"),
        (lambda r: r["extra"].update(recentSlot="x"), "recentSlot"),
        (lambda r: r["extra"].update(recentBlockhash=5), "recentBlockhash must be a string"),
        (lambda r: r["extra"].update(recentBlockhash="not-a-hash"), "invalid extra.recentBlockhash"),
        (lambda r: r["extra"].update(validAfter=1.5), "validAfter"),
        (lambda r: r["extra"].update(transactionVersions=["legacy"]), "transactionVersions"),
        (lambda r: r.update(amount="1.5"), "invalid upto amount"),
        (lambda r: r.update(asset="nope"), "invalid asset mint"),
        (lambda r: r.pop("extra"), "missing extra"),
    ],
)
async def test_build_refuses_a_bad_challenge(mutate, needle: str) -> None:
    _, op = _operator()
    req: Any = json.loads(json.dumps(_requirements(op, op)))
    mutate(req)
    with pytest.raises(ValueError, match=needle):
        await build_upto_payload(MemorySigner(Keypair()), req, NOW + 300)


async def test_build_negotiates_the_transaction_version() -> None:
    _, op = _operator()
    client = MemorySigner(Keypair())
    req = _requirements(op, op)
    req["extra"]["transactionVersions"] = [0, 1]
    v1 = _decode((await build_upto_payload(client, req, NOW + 300)).get("openTransaction", ""))
    assert txv1.is_v1(v1)
    # The header carries the budget: the runtime default for open + memo.
    assert v1.message.config.compute_unit_limit == 400_000
    assert v1.message.config.loaded_accounts_data_size_limit == txv1.MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES
    v0 = _decode(
        (await build_upto_payload(client, req, NOW + 300, max_transaction_version=0)).get("openTransaction", "")
    )
    assert txv1.message_version(v0.message) == 0
    req["extra"]["transactionVersions"] = [1]
    with pytest.raises(txv1.TransactionVersionError, match="signer signs up to version 0"):
        await build_upto_payload(client, req, NOW + 300, max_transaction_version=0)


def _decode(open_tx: str) -> Any:
    return txv1.decode_transaction(base64.b64decode(open_tx))


def _validate(tx: Any, **overrides: Any) -> None:
    kwargs: dict[str, Any] = {
        "accepted_versions": (0,),
        "program_id": PROGRAM_ID,
        "rent_payer": None,
        "authorized_signer": None,
        "payer": None,
        "payee": None,
        "mint": Pubkey.from_string(MINT),
        "token_program": Pubkey.from_string(TOKEN_PROGRAM),
        "channel_id": None,
        "max_amount": MAX,
        "withdraw_delay": 900,
        "payload_nonce": None,
        "payload_open_slot": SLOT,
        "recent_slot": SLOT,
        "expected_memo": None,
        "expected_recipients": None,
    }
    kwargs.update(overrides)
    validate_upto_open_instruction(tx, **kwargs)


async def _client_open(op: str, pay_to: str, *, receiver: str | None = None, memo: str | None = None):
    client = MemorySigner(Keypair())
    req = _requirements(op, pay_to)
    if receiver is not None:
        req["extra"]["receiverAuthorizer"] = receiver
    if memo is not None:
        req["extra"]["memo"] = memo
    payload = await build_upto_payload(client, req, NOW + 300, nonce="n")
    tx = _decode(payload.get("openTransaction", ""))
    receiver_key = Pubkey.from_string(receiver or op)
    expected = {
        "rent_payer": Pubkey.from_string(op),
        "authorized_signer": receiver_key,
        "payer": client.pubkey,
        "payee": Pubkey.from_string(op),
        "channel_id": Pubkey.from_string(payload["channelId"]),
        "payload_nonce": int(payload["nonce"]),
        "expected_recipients": [Distribution(recipient=Pubkey.from_string(pay_to), bps=10_000)],
    }
    return client, req, payload, tx, expected


async def test_client_open_passes_the_engine_validator() -> None:
    _, op = _operator()
    pay_to = str(Keypair().pubkey())
    client, req, payload, tx, expected = await _client_open(op, pay_to)
    raw = base64.b64decode(payload.get("openTransaction", ""))
    assert raw[1 + 64 * raw[0]] == 0x80  # a v0 message
    keys = list(tx.message.account_keys)
    assert keys[0] == Pubkey.from_string(op)
    # The open carries one random hex memo nonce of 16 bytes.
    memo_ix = tx.message.instructions[1]
    assert keys[memo_ix.program_id_index] == Pubkey.from_string(MEMO_PROGRAM)
    assert len(bytes(memo_ix.data)) == 32 and bytes(memo_ix.data).decode().isalnum()
    assert payload["openSlot"] == str(SLOT)
    _validate(tx, **expected)
    verify_payer_signature(tx, client.pubkey)

    header = encode_upto_header(req, payload)
    decoded = json.loads(base64.b64decode(header))
    assert decoded["accepted"]["scheme"] == UPTO_SCHEME
    assert decoded["payload"]["deposit"] == str(MAX)
    assert await build_upto_header(client, req, NOW + 300, nonce="n")


async def test_client_open_binds_distinct_fee_payer_and_receiver() -> None:
    _, fee_payer = _operator()
    _, authorizer = _operator()
    _client, _req, payload, tx, expected = await _client_open(fee_payer, fee_payer, receiver=authorizer)
    assert payload["authorizedSigner"] == authorizer
    _validate(tx, **expected)
    with pytest.raises(InvalidProofError, match="open transaction payee mismatch"):
        _validate(tx, **{**expected, "payee": Pubkey.from_string(authorizer)})


async def test_client_open_args_are_bound() -> None:
    _, op = _operator()
    _client, _req, _payload, tx, expected = await _client_open(op, op)
    cases = [
        ({"payload_nonce": expected["payload_nonce"] + 1}, "does not match payload nonce"),
        ({"payload_open_slot": SLOT + 1}, "does not match payload openSlot"),
        ({"withdraw_delay": 901}, "open withdraw delay"),
        ({"max_amount": MAX + 1}, "open deposit"),
        ({"channel_id": Pubkey.from_string(str(Keypair().pubkey()))}, "open transaction channel mismatch"),
        ({"recent_slot": SLOT - 1}, "ahead of the challenged"),
        ({"recent_slot": SLOT + 1501}, "freshness"),
        ({"expected_recipients": [Distribution(recipient=PROGRAM_ID, bps=10_000)]}, "open distribution"),
        ({"accepted_versions": (1,)}, "transaction version 0 is not accepted"),
        ({"expected_memo": "declared"}, "memo does not match the declared extra.memo"),
    ]
    for overrides, needle in cases:
        with pytest.raises(InvalidProofError, match=needle):
            _validate(tx, **{**expected, **overrides})
    _validate(tx, **{**expected, "recent_slot": SLOT + 1500})
    _validate(tx, **{**expected, "recent_slot": None})


async def test_client_emits_the_declared_memo_after_open() -> None:
    _, op = _operator()
    _client, _req, _payload, tx, expected = await _client_open(op, op, memo="order-4711")
    memo_ix = tx.message.instructions[1]
    assert bytes(memo_ix.data).decode("utf-8") == "order-4711"
    _validate(tx, **{**expected, "expected_memo": "order-4711"})


# -- open layout and accounts ------------------------------------------------


def _cu_limit_ix(units: int) -> Instruction:
    data = bytes([COMPUTE_BUDGET_SET_UNIT_LIMIT]) + units.to_bytes(4, "little")
    return Instruction(Pubkey.from_string(COMPUTE_BUDGET_PROGRAM), data, [])


def _cu_price_ix(micro_lamports: int) -> Instruction:
    data = bytes([COMPUTE_BUDGET_SET_UNIT_PRICE]) + micro_lamports.to_bytes(8, "little")
    return Instruction(Pubkey.from_string(COMPUTE_BUDGET_PROGRAM), data, [])


def _memo_ix(text: str | bytes, accounts: list[AccountMeta] | None = None) -> Instruction:
    data = text.encode("utf-8") if isinstance(text, str) else text
    return Instruction(Pubkey.from_string(MEMO_PROGRAM), data, accounts or [])


def _lighthouse_ix(accounts: list[AccountMeta] | None = None) -> Instruction:
    return Instruction(Pubkey.from_string(LIGHTHOUSE_PROGRAM), bytes([0]), accounts or [])


class _Open:
    """A canonical open with every expectation of the validator satisfied."""

    def __init__(self) -> None:
        self.operator_signer = MemorySigner(Keypair())
        self.operator = self.operator_signer.pubkey
        self.payer_kp = Keypair()
        self.payer = self.payer_kp.pubkey()
        self.mint = Pubkey.from_string(MINT)
        self.token_program = Pubkey.from_string(TOKEN_PROGRAM)
        self.recipients = [Distribution(recipient=Pubkey.from_string(str(Keypair().pubkey())), bps=10_000)]
        self.channel, _ = find_channel_pda(self.payer, self.operator, self.mint, self.operator, 7, SLOT, PROGRAM_ID)
        self.ix = build_open_instruction(
            OpenChannelParams(
                payer=self.payer,
                rent_payer=self.operator,
                payee=self.operator,
                mint=self.mint,
                authorized_signer=self.operator,
                salt=7,
                deposit=MAX,
                grace_period=900,
                open_slot=SLOT,
                recipients=self.recipients,
                token_program=self.token_program,
                program_id=PROGRAM_ID,
            )
        )

    def expected(self) -> dict[str, Any]:
        return {
            "rent_payer": self.operator,
            "authorized_signer": self.operator,
            "payer": self.payer,
            "payee": self.operator,
            "channel_id": self.channel,
            "payload_nonce": 7,
            "expected_recipients": self.recipients,
        }

    def tx(self, prefix: list[Instruction], suffix: list[Instruction], open_ix: Instruction | None = None) -> Any:
        message = MessageV0.try_compile(self.operator, [*prefix, open_ix or self.ix, *suffix], [], Hash.from_string(BH))
        return self.signed(message)

    def signed(self, message: Any) -> Any:
        required = message.header.num_required_signatures
        signatures = [Signature.default()] * required
        keys = list(message.account_keys)
        if self.payer in keys[:required]:
            signatures[keys.index(self.payer)] = self.payer_kp.sign_message(txv1.signed_message_bytes(message))
        return txv1.populate(message, signatures)

    def check(self, prefix: list[Instruction], suffix: list[Instruction], **overrides: Any) -> None:
        _validate(self.tx(prefix, suffix), **{**self.expected(), **overrides})


def test_open_layout_accepts_the_wrappers_clients_add() -> None:
    o = _Open()
    o.check([], [])
    o.check([_cu_limit_ix(90_000), _cu_price_ix(1)], [_memo_ix("order-4711")])
    o.check([], [_lighthouse_ix(), _lighthouse_ix(), _lighthouse_ix(), _memo_ix("x")])
    # An unbound route admits several memos; a declared one exactly one.
    o.check([], [_memo_ix("a"), _memo_ix("b")])
    o.check([], [_memo_ix("m")], expected_memo="m")


@pytest.mark.parametrize(
    ("prefix", "suffix", "overrides", "needle"),
    [
        ([_cu_price_ix(1), _cu_limit_ix(90_000)], [], {}, "must precede"),
        ([_cu_limit_ix(90_000), _cu_limit_ix(90_000)], [], {}, "duplicate SetComputeUnitLimit"),
        ([_cu_price_ix(1), _cu_price_ix(1)], [], {}, "duplicate SetComputeUnitPrice"),
        ([Instruction(Pubkey.from_string(COMPUTE_BUDGET_PROGRAM), bytes([1, 0, 0, 0, 0]), [])], [], {}, "unsupported"),
        ([_cu_limit_ix(400_001)], [], {}, "compute unit limit 400001 exceeds maximum"),
        ([_cu_price_ix(5_000_001)], [], {}, "compute unit price 5000001 exceeds maximum"),
        ([_cu_limit_ix(400_000), _cu_price_ix(5_001)], [], {}, "sponsored fee maximum"),
        ([_cu_price_ix(10_001)], [], {}, "sponsored fee maximum"),
        ([], [_lighthouse_ix()] * 4, {}, "Lighthouse instructions"),
        ([], [_lighthouse_ix()] * 3 + [_memo_ix("a"), _memo_ix("b")], {}, "instructions after open"),
        ([], [_cu_limit_ix(90_000)], {}, "must be Lighthouse or Memo"),
        ([_memo_ix("m")], [], {}, "targets an unexpected program"),
        ([], [], {"expected_memo": "m"}, "exactly one Memo"),
        ([], [_memo_ix("m"), _memo_ix("m")], {"expected_memo": "m"}, "at most one Memo"),
        ([], [_memo_ix("x" * 257)], {"expected_memo": "m"}, "over the 256-byte maximum"),
        ([], [_memo_ix(b"\xff")], {"expected_memo": "m"}, "not valid UTF-8"),
    ],
)
def test_open_layout_rejects(prefix, suffix, overrides, needle: str) -> None:
    o = _Open()
    with pytest.raises(InvalidProofError, match=needle):
        o.check(prefix, suffix, **overrides)


def test_open_wrappers_must_not_name_the_fee_payer() -> None:
    o = _Open()
    naming = [AccountMeta(o.operator, True, False)]
    with pytest.raises(InvalidProofError, match="Memo instruction must not reference the fee payer"):
        o.check([], [_memo_ix("m", naming)])
    with pytest.raises(InvalidProofError, match="Lighthouse instruction must not reference the fee payer"):
        o.check([], [_lighthouse_ix(naming)])


def test_open_accounts_privileges_and_args() -> None:
    o = _Open()
    accounts = list(o.ix.accounts)

    def with_accounts(metas: list[AccountMeta], data: bytes | None = None) -> Any:
        return o.tx([], [], Instruction(PROGRAM_ID, data if data is not None else bytes(o.ix.data), metas))

    extra = [*accounts, AccountMeta(Pubkey.from_string(str(Keypair().pubkey())), False, False)]
    with pytest.raises(InvalidProofError, match="exactly 14"):
        _validate(with_accounts(extra), **o.expected())
    writable_mint = [*accounts]
    writable_mint[3] = AccountMeta(o.mint, False, True)
    with pytest.raises(InvalidProofError, match="writable outside the open's writable roles"):
        _validate(with_accounts(writable_mint), **o.expected())
    readonly_channel = [*accounts]
    readonly_channel[5] = AccountMeta(o.channel, False, False)
    with pytest.raises(InvalidProofError, match="account #5 must be writable"):
        _validate(with_accounts(readonly_channel), **o.expected())
    stranger = Keypair().pubkey()
    signer_mint = [*accounts]
    signer_mint[3] = AccountMeta(stranger, True, False)
    with pytest.raises(InvalidProofError, match="open transaction mint mismatch"):
        _validate(with_accounts(signer_mint), **o.expected())
    with pytest.raises(InvalidProofError, match="unexpected signer"):
        _validate(o.tx([], [_lighthouse_ix([AccountMeta(stranger, True, False)])]), **o.expected())
    with pytest.raises(InvalidProofError, match="trailing bytes"):
        _validate(with_accounts(accounts, bytes(o.ix.data) + b"\x00"), **o.expected())
    with pytest.raises(InvalidProofError, match="args are malformed"):
        _validate(with_accounts(accounts, bytes(o.ix.data)[:-1]), **o.expected())
    with pytest.raises(InvalidProofError, match="channel-open|payment-channels open"):
        _validate(with_accounts(accounts, b"\x02"), **o.expected())
    # The channel account is not the PDA of the args' own salt.
    resalted = bytes(o.ix.data[:1]) + (8).to_bytes(8, "little") + bytes(o.ix.data[9:])
    with pytest.raises(InvalidProofError, match="open channel PDA"):
        _validate(with_accounts(accounts, resalted), **{**o.expected(), "payload_nonce": 8})
    # A header whose signer counts exceed the keys is refused.
    tx = o.tx([], [])
    from solders.message import MessageHeader  # type: ignore[import-untyped]

    bad = txv1.MessageV1(
        header=MessageHeader(2, 3, 0),
        config=txv1.v1_config(200_000, 0),
        recent_blockhash=Hash.from_string(BH),
        account_keys=list(tx.message.account_keys),
        instructions=list(tx.message.instructions),
    )
    with pytest.raises(InvalidProofError, match="signer counts exceed"):
        _validate(
            txv1.TransactionV1.populate(bad, [Signature.default()] * 2), **{**o.expected(), "accepted_versions": (0, 1)}
        )


def test_open_envelope_versions_and_budget() -> None:
    o = _Open()
    v0 = o.tx([], [_memo_ix("m")])
    v1_message = txv1.MessageV1.try_compile(
        o.operator, [o.ix, _memo_ix("m")], Hash.from_string(BH), txv1.v1_config(400_000, 0)
    )
    v1 = o.signed(v1_message)
    _validate(v1, **{**o.expected(), "accepted_versions": (0, 1)})
    with pytest.raises(InvalidProofError, match="transaction version 1 is not accepted"):
        _validate(v1, **o.expected())
    no_loaded = txv1.MessageV1.try_compile(
        o.operator, [o.ix], Hash.from_string(BH), txv1.TransactionConfig(priority_fee=0, compute_unit_limit=200_000)
    )
    with pytest.raises(InvalidProofError, match="loaded accounts data size"):
        _validate(o.signed(no_loaded), **{**o.expected(), "accepted_versions": (0, 1)})
    heap = txv1.MessageV1.try_compile(
        o.operator,
        [o.ix],
        Hash.from_string(BH),
        txv1.TransactionConfig(
            priority_fee=0,
            compute_unit_limit=200_000,
            loaded_accounts_data_size_limit=1024,
            heap_size=64 * 1024,
        ),
    )
    with pytest.raises(InvalidProofError, match="heap size"):
        _validate(o.signed(heap), **{**o.expected(), "accepted_versions": (0, 1)})
    # A legacy message is policed as version 0.
    legacy = o.signed(Message.new_with_blockhash([o.ix], o.operator, Hash.from_string(BH)))
    _validate(legacy, **o.expected())
    verify_payer_signature(v0, o.payer)


def test_payer_signature_must_verify() -> None:
    o = _Open()
    tx = o.tx([], [])
    verify_payer_signature(tx, o.payer)
    with pytest.raises(InvalidProofError, match="does not sign the open"):
        verify_payer_signature(tx, Keypair().pubkey())
    unsigned = VersionedTransaction.populate(tx.message, [Signature.default()] * 2)
    with pytest.raises(InvalidProofError, match="missing or invalid"):
        verify_payer_signature(unsigned, o.payer)


# -- prepare, cosign and the preflight ---------------------------------------


class _ChainRpc(_SlotRpc):
    def __init__(self, *, account: Any = None, slot: int | None = SLOT, fail: bool = False) -> None:
        super().__init__(slot)
        self.account = account
        self.fail = fail

    async def get_account_info(self, _address: str, commitment: str = "confirmed"):
        if self.fail:
            raise RuntimeError("rpc down")
        return self.account


async def _header(op: str, pay_to: str, *, now: int = NOW, versions: list[int] | None = None) -> tuple[str, Any]:
    client = MemorySigner(Keypair())
    req = upto_requirements(_route(op, pay_to, transaction_versions=versions))
    req["extra"]["recentBlockhash"] = BH
    req["extra"]["recentSlot"] = str(SLOT)
    payload = await build_upto_payload(client, req, now + 300, nonce="n")
    return encode_upto_header(req, payload), client


def _remux(header: str, mutate) -> str:
    envelope = json.loads(base64.b64decode(header))
    mutate(envelope)
    return base64.b64encode(json.dumps(envelope).encode()).decode()


async def test_preflight_accepts_and_cosigns() -> None:
    signer, op = _operator()
    header, client = await _header(op, op)
    offered = [upto_requirements(_route(op, op))]
    prepared = await verify_upto_open_preflight(
        header, offered, fee_payer_signer=signer, receiver_authorizer=op, rpc=_ChainRpc(), now=NOW
    )
    assert prepared.payer == client.pubkey
    assert prepared.expires_at == NOW + 300
    assert prepared.distribution == [Distribution(recipient=Pubkey.from_string(op), bps=10_000)]
    wire = await cosign_upto_open(prepared.transaction, signer)
    txv1.decode_transaction(wire)
    # The challenged slot falls back to the RPC; unknown skips the window.
    await prepare_upto_open(header, offered, fee_payer=op, receiver_authorizer=op, rpc=_ChainRpc(slot=None), now=NOW)


async def test_preflight_cosigns_a_v1_open() -> None:
    signer, op = _operator()
    header, _client = await _header(op, op, versions=[0, 1])
    prepared = await verify_upto_open_preflight(
        header,
        [upto_requirements(_route(op, op, transaction_versions=[0, 1]))],
        fee_payer_signer=signer,
        receiver_authorizer=op,
        rpc=_ChainRpc(),
        now=NOW,
        accepted_versions=(0, 1),
    )
    assert txv1.is_v1(prepared.transaction)


@pytest.mark.parametrize(
    ("mutate", "needle"),
    [
        (lambda e: e["accepted"].update(scheme="exact"), "Invalid payload type: exact"),
        (lambda e: e.update(accepted="x"), "Invalid payload type"),
        (lambda e: e["accepted"].update(network="solana:other"), "does not match any offered"),
        (lambda e: e["payload"].pop("openTransaction"), "requires openTransaction"),
        (lambda e: e["payload"].update(openTransaction="AAAA"), "invalid transaction"),
        (lambda e: e["payload"].update(voucherSignature="s"), "unexpected_voucher"),
        (lambda e: e.pop("accepted"), "missing field `accepted`"),
        (lambda e: e.pop("payload"), "missing field `payload`"),
        (lambda e: e.update(x402Version="2"), "x402Version"),
        (lambda e: e["payload"].update(channelId="nope"), "invalid channelId"),
    ],
)
async def test_prepare_rejects(mutate, needle: str) -> None:
    _, op = _operator()
    header, _client = await _header(op, op)
    with pytest.raises(InvalidProofError, match=needle):
        await prepare_upto_open(
            _remux(header, mutate),
            [upto_requirements(_route(op, op))],
            fee_payer=op,
            receiver_authorizer=op,
            rpc=_ChainRpc(),
            now=NOW,
        )


async def test_prepare_refuses_an_existing_channel_or_a_failed_read() -> None:
    _, op = _operator()
    header, _client = await _header(op, op)
    offered = [upto_requirements(_route(op, op))]
    with pytest.raises(InvalidProofError, match="invalid_upto_svm_channel_already_open"):
        await prepare_upto_open(
            header, offered, fee_payer=op, receiver_authorizer=op, rpc=_ChainRpc(account=(b"", "x")), now=NOW
        )
    with pytest.raises(InvalidProofError, match="channel account read failed"):
        await prepare_upto_open(
            header, offered, fee_payer=op, receiver_authorizer=op, rpc=_ChainRpc(fail=True), now=NOW
        )


@pytest.mark.parametrize("bad", ["%%%", base64.b64encode(b"not json").decode(), base64.b64encode(b"[]").decode()])
async def test_prepare_rejects_a_malformed_header(bad: str) -> None:
    _, op = _operator()
    with pytest.raises(InvalidProofError, match="invalid upto payment signature"):
        await prepare_upto_open(bad, [], fee_payer=op, receiver_authorizer=op, rpc=_ChainRpc(), now=NOW)


async def test_cosign_requires_the_advertised_fee_payer() -> None:
    o = _Open()
    with pytest.raises(InvalidProofError, match="fee payer must be the advertised fee payer"):
        await cosign_upto_open(o.tx([], []), MemorySigner(Keypair()))
    unsigned = VersionedTransaction.populate(o.tx([], []).message, [Signature.default()] * 2)
    with pytest.raises(InvalidProofError, match="signature verification failed"):
        await cosign_upto_open(unsigned, o.operator_signer)
    legacy = o.signed(Message.new_with_blockhash([o.ix], o.operator, Hash.from_string(BH)))
    signed = txv1.decode_transaction(await cosign_upto_open(legacy, o.operator_signer))
    assert signed.message == legacy.message
