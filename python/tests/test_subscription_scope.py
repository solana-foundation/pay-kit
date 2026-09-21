"""Tests for the pure activation-transaction validator and the server cosign.

Mirrors the Rust ``validate_activation_scope`` / ``co_sign_as_fee_payer`` tests
and the TS scope tests, plus the spec-strict rules the references relax (no
ATA instruction, pinned init and subscribe accounts and data). Each rejected
case asserts the reason, so a case cannot pass by tripping an unrelated rule.
"""

from __future__ import annotations

import base64
from collections.abc import Callable
from dataclasses import replace
from types import SimpleNamespace
from typing import Any

import pytest
from solders.address_lookup_table_account import AddressLookupTableAccount
from solders.hash import Hash
from solders.instruction import AccountMeta, Instruction
from solders.keypair import Keypair
from solders.message import Message, MessageV0, to_bytes_versioned
from solders.pubkey import Pubkey
from solders.signature import Signature
from solders.transaction import VersionedTransaction

from solana_pay_kit._paycore.errors import PaymentError
from solana_pay_kit._paycore.solana import (
    ASSOCIATED_TOKEN_PROGRAM,
    COMPUTE_BUDGET_PROGRAM,
    MEMO_PROGRAM,
    SYSTEM_PROGRAM,
    TOKEN_2022_PROGRAM,
)
from solana_pay_kit.protocols.mpp._subscriptions import (
    UNKNOWN_INIT_ID,
    PlanView,
    build_init_subscription_authority_ix,
    build_subscribe_ix,
    build_transfer_subscription_ix,
    decode_plan,
)
from solana_pay_kit.protocols.mpp.client.subscription import build_subscription_activation
from solana_pay_kit.protocols.mpp.server._subscription_scope import (
    ActivationExpectation,
    cosign,
    validate_activation,
)
from solana_pay_kit.signer import LocalSigner
from tests._subscription_fixtures import (
    AMOUNT,
    MINT,
    PLAN,
    PLAN_BUMP,
    PLAN_ID,
    PROGRAM,
    PROGRAM_ID,
    RECIPIENT,
    SERVER,
    SUBSCRIBER,
    TOKEN,
    FakeRpc,
    challenge_for,
    install_plan,
    pk,
    plan_bytes,
    request_dict,
)

PULLER = SERVER.pubkey()
SUB = SUBSCRIBER.pubkey()
SPONSOR = Keypair.from_seed(bytes([3] * 32))
PLAN_VIEW: PlanView = decode_plan(
    plan_bytes(owner=PULLER, mint=MINT, destinations=[RECIPIENT], plan_id=PLAN_ID, bump=PLAN_BUMP),
    PROGRAM_ID,
    PROGRAM_ID,
    PLAN,
)


def expect(**changes: Any) -> ActivationExpectation:
    base = ActivationExpectation(
        program=PROGRAM,
        plan=PLAN_VIEW,
        token_program=TOKEN,
        puller=PULLER,
        recipient=RECIPIENT,
        amount=AMOUNT,
        fee_payer=None,
    )
    return replace(base, **changes)


def compute(kind: int, value: int) -> Instruction:
    width = 4 if kind == 2 else 8
    return Instruction(Pubkey.from_string(COMPUTE_BUDGET_PROGRAM), bytes([kind]) + value.to_bytes(width, "little"), [])


def memo(text: str) -> Instruction:
    return Instruction(Pubkey.from_string(MEMO_PROGRAM), text.encode(), [])


def init_ix(subscriber: Pubkey = SUB, token_program: Pubkey = TOKEN) -> Instruction:
    return build_init_subscription_authority_ix(
        program=PROGRAM, subscriber=subscriber, mint=MINT, token_program=token_program
    )


def subscribe_ix(
    *, subscriber: Pubkey = SUB, plan: PlanView = PLAN_VIEW, init_id: int = UNKNOWN_INIT_ID, payer: Pubkey | None = None
) -> Instruction:
    return build_subscribe_ix(program=PROGRAM, subscriber=subscriber, plan=plan, init_id=init_id, payer=payer)


def transfer_ix(*, subscriber: Pubkey = SUB, recipient: Pubkey = RECIPIENT, amount: int = AMOUNT) -> Instruction:
    return build_transfer_subscription_ix(
        program=PROGRAM,
        subscriber=subscriber,
        plan=PLAN_VIEW,
        recipient=recipient,
        puller=PULLER,
        token_program=TOKEN,
        amount=amount,
    )


def good(*, payer: Pubkey | None = None) -> list[Instruction]:
    return [compute(2, 400_000), compute(3, 1), init_ix(), subscribe_ix(payer=payer), transfer_ix()]


def compile_b64(
    ixs: list[Instruction],
    fee_payer: Pubkey = SUB,
    *,
    legacy: bool = False,
    lookups: list[AddressLookupTableAccount] | None = None,
) -> str:
    blockhash = Hash(bytes([9] * 32))
    if legacy:
        message: Any = Message.new_with_blockhash(ixs, fee_payer, blockhash)
    else:
        message = MessageV0.try_compile(fee_payer, ixs, lookups or [], blockhash)
    # Sign the subscriber slot for real; server slots stay empty for cosign.
    signatures = [Signature.default()] * int(message.header.num_required_signatures)
    signer_keys = list(message.account_keys)[: len(signatures)]
    if SUB in signer_keys:
        signatures[signer_keys.index(SUB)] = SUBSCRIBER.sign_message(bytes(to_bytes_versioned(message)))
    return base64.b64encode(bytes(VersionedTransaction.populate(message, signatures))).decode()


def test_client_output_passes() -> None:
    parsed = validate_activation(compile_b64(good()), expect())
    assert (parsed.subscriber, parsed.has_init) == (SUB, True)
    without_init = [compute(2, 400_000), subscribe_ix(init_id=5), transfer_ix()]
    assert not validate_activation(compile_b64(without_init), expect()).has_init


async def test_real_client_output_passes() -> None:
    rpc = FakeRpc()
    install_plan(rpc)
    request = request_dict(externalId="order-7", methodDetails={"feePayer": True, "feePayerKey": str(PULLER)})
    activation = await build_subscription_activation(SUBSCRIBER, rpc, challenge_for(request))
    parsed = validate_activation(
        activation.credential.payload["transaction"], expect(fee_payer=PULLER, external_id="order-7")
    )
    assert parsed.subscriber == SUB


def test_legacy_message_passes() -> None:
    assert validate_activation(compile_b64(good(), legacy=True), expect()).subscriber == SUB


def _swap(index: int, ix: Instruction) -> Callable[[], list[Instruction]]:
    def build() -> list[Instruction]:
        ixs = good()
        ixs[index] = ix
        return ixs

    return build


_ATA_CREATE = Instruction(
    Pubkey.from_string(ASSOCIATED_TOKEN_PROGRAM),
    bytes([1]),
    [
        AccountMeta(SUB, True, True),
        AccountMeta(pk(60), False, True),
        AccountMeta(SUB, False, False),
        AccountMeta(MINT, False, False),
        AccountMeta(Pubkey.from_string(SYSTEM_PROGRAM), False, False),
        AccountMeta(TOKEN, False, False),
    ],
)
_SYSTEM_TRANSFER = Instruction(
    Pubkey.from_string(SYSTEM_PROGRAM),
    (2).to_bytes(4, "little") + (1).to_bytes(8, "little"),
    [AccountMeta(SUB, True, True), AccountMeta(pk(61), False, True)],
)
_NON_SIGNER_SUBSCRIBE = Instruction(
    PROGRAM,
    bytes(subscribe_ix(init_id=5, payer=SPONSOR.pubkey()).data),
    [
        AccountMeta(meta.pubkey, False, meta.is_writable) if meta.pubkey == SUB else meta
        for meta in subscribe_ix(init_id=5, payer=SPONSOR.pubkey()).accounts
    ],
)

REJECTED: dict[str, tuple[Callable[[], list[Instruction]], Pubkey, dict[str, Any], str]] = {
    "extra-program": (lambda: [*good(), _SYSTEM_TRANSFER], SUB, {}, "not allowed"),
    "ata-create": (lambda: [_ATA_CREATE, *good()], SUB, {}, "not allowed"),
    "wrong-recipient-ata": (_swap(4, transfer_ix(recipient=pk(50))), SUB, {}, "transfer_subscription does not match"),
    "transfer-amount": (_swap(4, transfer_ix(amount=AMOUNT + 1)), SUB, {}, "transfer_subscription does not match"),
    "missing-subscribe": (lambda: [init_ix(), transfer_ix()], SUB, {}, "one subscribe"),
    "duplicate-subscribe": (lambda: [*good()[:4], subscribe_ix(), transfer_ix()], SUB, {}, "repeats"),
    "missing-transfer": (lambda: good()[:4], SUB, {}, "one subscribe"),
    "duplicate-transfer": (lambda: [*good(), transfer_ix()], SUB, {}, "repeats"),
    "transfer-before-subscribe": (lambda: [init_ix(), transfer_ix(), subscribe_ix()], SUB, {}, "order"),
    "init-after-subscribe": (lambda: [subscribe_ix(), init_ix(), transfer_ix()], SUB, {}, "order"),
    "subscribe-wrong-merchant": (
        _swap(3, subscribe_ix(plan=replace(PLAN_VIEW, owner=pk(51)))),
        SUB,
        {},
        "subscribe does not match",
    ),
    "subscribe-wrong-terms": (
        _swap(3, subscribe_ix(plan=replace(PLAN_VIEW, amount=AMOUNT + 1))),
        SUB,
        {},
        "subscribe does not match",
    ),
    "sentinel-without-init": (lambda: [subscribe_ix(), transfer_ix()], SUB, {}, "sentinel"),
    "init-without-sentinel": (_swap(3, subscribe_ix(init_id=5)), SUB, {}, "sentinel"),
    "payer-meta-unsponsored": (_swap(3, subscribe_ix(payer=SUB)), SUB, {}, "subscribe does not match"),
    "payer-meta-missing-sponsored": (
        good,
        SPONSOR.pubkey(),
        {"fee_payer": SPONSOR.pubkey()},
        "subscribe does not match",
    ),
    "init-wrong-token-program": (
        _swap(2, init_ix(token_program=Pubkey.from_string(TOKEN_2022_PROGRAM))),
        SUB,
        {},
        "init authority does not match",
    ),
    "puller-pays-unsponsored": (good, PULLER, {}, "fee payer"),
    "sponsor-not-fee-payer": (lambda: good(payer=SPONSOR.pubkey()), SUB, {"fee_payer": SPONSOR.pubkey()}, "fee payer"),
    "sponsored-subscriber-not-signer": (
        lambda: [_NON_SIGNER_SUBSCRIBE, transfer_ix()],
        SPONSOR.pubkey(),
        {"fee_payer": SPONSOR.pubkey()},
        "required signers",
    ),
    "subscriber-is-puller": (
        lambda: [init_ix(PULLER), subscribe_ix(subscriber=PULLER), transfer_ix(subscriber=PULLER)],
        PULLER,
        {},
        "server key",
    ),
    "memo-signed-by-puller": (
        lambda: [*good(), Instruction(Pubkey.from_string(MEMO_PROGRAM), b"x", [AccountMeta(PULLER, True, False)])],
        SUB,
        {"external_id": "x"},
        "memo",
    ),
    "memo-missing": (good, SUB, {"external_id": "order-1"}, "memo"),
    "memo-unexpected": (lambda: [*good(), memo("order-1")], SUB, {}, "memo"),
    "memo-mismatch": (lambda: [*good(), memo("order-2")], SUB, {"external_id": "order-1"}, "memo"),
    "memo-twice": (lambda: [*good(), memo("order-1"), memo("order-1")], SUB, {"external_id": "order-1"}, "memo"),
    "compute-limit-over-cap": (_swap(0, compute(2, 400_001)), SUB, {}, "limit 400001"),
    "compute-price-over-sponsored-cap": (
        lambda: [compute(3, 10_001), *good(payer=SPONSOR.pubkey())[2:]],
        SPONSOR.pubkey(),
        {"fee_payer": SPONSOR.pubkey()},
        "price 10001",
    ),
    "compute-limit-twice": (lambda: [compute(2, 1), *good()], SUB, {}, "repeats a compute"),
}


@pytest.mark.parametrize("name", list(REJECTED))
def test_rejects(name: str) -> None:
    build, fee_payer, changes, reason = REJECTED[name]
    with pytest.raises(PaymentError, match=reason):
        validate_activation(compile_b64(build(), fee_payer), expect(**changes))


def test_sponsored_activation_passes() -> None:
    sponsored = compile_b64(good(payer=SPONSOR.pubkey()), SPONSOR.pubkey())
    assert validate_activation(sponsored, expect(fee_payer=SPONSOR.pubkey())).subscriber == SUB


@pytest.mark.parametrize("forgery", ["foreign-signature", "unsigned"])
def test_rejects_an_unverified_subscriber_signature(forgery: str) -> None:
    # Unsponsored, slot 0 is the transaction id: a client must not be able to
    # name another confirmed transaction (or nothing) as its activation.
    raw = bytearray(base64.b64decode(compile_b64(good())))
    raw[1:65] = bytes(Keypair().sign_message(b"another transaction")) if forgery == "foreign-signature" else bytes(64)
    with pytest.raises(PaymentError, match="does not verify"):
        validate_activation(base64.b64encode(bytes(raw)).decode(), expect())


def test_rejects_alt() -> None:
    table = AddressLookupTableAccount(pk(63), [RECIPIENT, pk(64)])
    ixs = [*good(), Instruction(PROGRAM, bytes([10]), [AccountMeta(pk(64), False, False)])]
    with pytest.raises(PaymentError, match="lookup"):
        validate_activation(compile_b64(ixs, lookups=[table]), expect())


def test_rejects_undecodable() -> None:
    with pytest.raises(PaymentError):
        validate_activation("not base64!", expect())
    with pytest.raises(PaymentError):
        validate_activation(base64.b64encode(b"\x01garbage").decode(), expect())


async def _client_activation(request: dict[str, Any]) -> bytes:
    rpc = FakeRpc()
    install_plan(rpc)
    activation = await build_subscription_activation(SUBSCRIBER, rpc, challenge_for(request))
    return base64.b64decode(activation.credential.payload["transaction"])


def _all_signed(wire: bytes) -> bool:
    return all(VersionedTransaction.from_bytes(wire).verify_with_results())


@pytest.mark.parametrize(
    ("sponsor", "signers"),
    [(None, [SERVER]), (SERVER, [SERVER, SERVER]), (SPONSOR, [SERVER, LocalSigner(SPONSOR)])],
    ids=["unsponsored", "sponsor-is-puller", "distinct-sponsor"],
)
async def test_cosign_splices_puller_and_fee_payer(sponsor: Keypair | None, signers: list[Any]) -> None:
    details = {"feePayer": True, "feePayerKey": str(sponsor.pubkey())} if sponsor else {}
    raw = await _client_activation(request_dict(methodDetails=details))
    assert not _all_signed(raw)
    wire, signature = cosign(raw, signers, fee_payer=sponsor.pubkey() if sponsor else None)
    assert _all_signed(wire)
    assert signature == str(VersionedTransaction.from_bytes(wire).signatures[0])


async def test_cosign_rejects_a_sponsor_that_is_not_the_fee_payer() -> None:
    raw = await _client_activation(request_dict())
    with pytest.raises(PaymentError, match="fee payer"):
        cosign(raw, [SERVER, SPONSOR], fee_payer=SPONSOR.pubkey())
    with pytest.raises(PaymentError, match="required signer"):
        cosign(raw, [SERVER, SPONSOR], fee_payer=None)
    # A key that is in the message but not a signer must not be spliced into the signature area.
    mint_holder = SimpleNamespace(pubkey=lambda: str(MINT), sign=lambda message: bytes(64))
    with pytest.raises(PaymentError, match="required signer"):
        cosign(raw, [SERVER, mint_holder], fee_payer=None)
