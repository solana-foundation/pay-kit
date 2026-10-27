"""x402 ``batch-settlement`` client builders and the sponsor's transaction policy."""

# pyright: reportOptionalMemberAccess=false

from __future__ import annotations

import base64
import dataclasses
import json
import struct
from typing import Any

import pytest
from solders.instruction import AccountMeta, Instruction
from solders.pubkey import Pubkey

from solana_pay_kit._paycore import txv1
from solana_pay_kit._paycore.paymentchannels import (
    LIGHTHOUSE_PROGRAM,
    PROGRAM_ID,
    TopUpParams,
    build_top_up_instruction,
    voucher_message_bytes,
)
from solana_pay_kit._paycore.solana import COMPUTE_BUDGET_PROGRAM, MEMO_PROGRAM, TOKEN_2022_PROGRAM
from solana_pay_kit._paycore.transaction import build_partially_signed_transaction
from solana_pay_kit.protocols.x402.batch_settlement import errors as codes
from solana_pay_kit.protocols.x402.batch_settlement.errors import BatchSettlementError
from solana_pay_kit.protocols.x402.batch_settlement.tx_policy import (
    MemoPolicy,
    SetupForm,
    TransactionExpectations,
    decode_transaction,
    payer_signature,
    scan_channel_tx_layout,
    setup_form_from_transaction,
    validate_request_close_transaction,
    validate_setup_transaction,
)
from solana_pay_kit.protocols.x402.batch_settlement.types import (
    BatchAuthorization,
    BatchChannelConfig,
    BatchRequirements,
    BatchSettlementExtra,
    BatchSettlementResponse,
    BatchVoucher,
    ChannelStateSnapshot,
    VoucherState,
)
from solana_pay_kit.protocols.x402.batch_settlement.verify import receiver_binding_memo
from solana_pay_kit.protocols.x402.client.batch_settlement import (
    BatchChannel,
    ServerSignedChannelsPolicy,
    build_deposit,
    build_refund,
    build_refund_request_close,
    build_top_up,
    channel_id_for,
    corrective_channel_id,
    encode_payment_header,
    parse_challenge,
    resolve_terms,
    resolve_terms_with_token_program,
    sign_authorization,
)
from tests._batch_fixture import (
    BLOCKHASH,
    FEE_PAYER,
    MINT,
    NETWORK,
    OPEN_SLOT,
    PAY_TO,
    PAYER,
    RECEIVER_AUTHORIZER,
    SLOT,
    STRANGER,
    TOKEN,
    FakeRpc,
    mint_account,
    requirements,
    signer,
)

MEMO = Pubkey.from_string(MEMO_PROGRAM)


def _code(exc: pytest.ExceptionInfo[BaseException]) -> str:
    assert isinstance(exc.value, BatchSettlementError), exc.value
    return exc.value.code


def _terms(req: BatchRequirements | None = None, **kwargs: Any) -> Any:
    return resolve_terms_with_token_program(req or requirements(), TOKEN, **kwargs)


async def _opened(req: BatchRequirements | None = None, version: int | None = None) -> tuple[BatchChannel, Any]:
    req = req or requirements()
    terms = _terms(req, max_tx_version=version)
    return await build_deposit(signer(), req, terms, 10_000, BLOCKHASH, OPEN_SLOT, salt=42)


def _expectations(
    channel: BatchChannel, versions: tuple[int, ...] = (0,), memo: str | None = "invoice-42"
) -> TransactionExpectations:
    return TransactionExpectations(
        program_id=PROGRAM_ID,
        fee_payer=FEE_PAYER.pubkey(),
        config=channel.config,
        channel_id=channel.channel_id,
        token_program=TOKEN,
        receiver=PAY_TO,
        receiver_authorizer=RECEIVER_AUTHORIZER.pubkey(),
        accepted_versions=versions,
        memo=memo,
    )


async def _sponsored(instructions: list[Instruction], version: int = 0, fee_payer: Pubkey | None = None) -> str:
    config = txv1.v1_config(200_000, 0) if version == 1 else None
    wire = await build_partially_signed_transaction(
        instructions, fee_payer or FEE_PAYER.pubkey(), BLOCKHASH, signer(), version=version, config=config
    )
    return base64.b64encode(wire).decode()


def _top_up_ix(channel: BatchChannel, amount: int = 6000) -> Instruction:
    return build_top_up_instruction(TopUpParams(PAYER.pubkey(), channel.channel_id, MINT, amount, TOKEN, PROGRAM_ID))


def _memo(text: str) -> Instruction:
    return Instruction(MEMO, text.encode(), [])


def _limit(units: int) -> Instruction:
    return Instruction(Pubkey.from_string(COMPUTE_BUDGET_PROGRAM), bytes([2]) + struct.pack("<I", units), [])


def _price(micro: int) -> Instruction:
    return Instruction(Pubkey.from_string(COMPUTE_BUDGET_PROGRAM), bytes([3]) + struct.pack("<Q", micro), [])


# ── terms ──


def test_terms_resolve_the_challenge() -> None:
    terms = _terms()
    assert terms.amount == 1000 and terms.tx_version == 0
    assert terms.memo == terms.continuation_memo == "invoice-42"
    assert terms.binding_memo == receiver_binding_memo(RECEIVER_AUTHORIZER.pubkey())
    nonce = _terms(requirements(memo=None)).memo
    assert len(nonce) == 32 and int(nonce, 16) >= 0
    assert _terms(requirements(transaction_versions=[0, 1])).tx_version == 1


@pytest.mark.parametrize(
    ("extra", "message"),
    [
        ({"operator": str(STRANGER.pubkey())}, "only valid"),
        ({"voucher_signer": "server"}, "is required"),
        ({"voucher_signer": "server", "operator": str(STRANGER.pubkey())}, "not trusted"),
        ({"voucher_signer": "bogus"}, "must be"),
        ({"receiver_authorizer": None}, "receiverAuthorizer"),
        ({"payment_flow": "upfront"}, codes.INVALID_PAYMENT_FLOW),
        ({"withdraw_delay": 899}, codes.INVALID_WITHDRAW_DELAY_OUT_OF_RANGE),
        ({"token_program": TOKEN_2022_PROGRAM}, codes.INVALID_TOKEN_PROGRAM),
        ({"transaction_versions": [1]}, "the server accepts transaction versions"),
    ],
)
def test_terms_refusals(extra: dict[str, Any], message: str) -> None:
    with (
        pytest.raises(ValueError, match=message)
        if not message.startswith("invalid_")
        else pytest.raises(BatchSettlementError, match=message)
    ):
        _terms(requirements(**extra), max_tx_version=0)


def test_server_signed_terms_need_an_explicit_grant() -> None:
    operator = STRANGER.pubkey()
    policy = ServerSignedChannelsPolicy().allow_operator(operator, 50_000)
    terms = _terms(requirements(voucher_signer="server", operator=str(operator)), policy=policy)
    assert terms.operator == operator and terms.server_signed_max_deposit == 50_000
    with pytest.raises(ValueError):
        ServerSignedChannelsPolicy().allow_operator(operator, 0)


async def test_resolve_terms_reads_the_mint_owner() -> None:
    rpc = FakeRpc()
    with pytest.raises(ValueError, match="not found"):
        await resolve_terms(rpc, requirements())  # type: ignore[arg-type]
    rpc.put(MINT, mint_account(), TOKEN_2022_PROGRAM)
    with pytest.raises(BatchSettlementError) as exc:
        await resolve_terms(rpc, requirements())  # type: ignore[arg-type]
    assert _code(exc) == codes.INVALID_TOKEN_PROGRAM
    rpc.put(MINT, mint_account(), TOKEN)
    assert (await resolve_terms(rpc, requirements())).token_program == TOKEN  # type: ignore[arg-type]


# ── builds ──


async def test_deposit_builds_a_canonical_open() -> None:
    channel, payload = await _opened()
    assert payload.type == "deposit" and payload.deposit.amount == "10000"
    assert payload.voucher.max_claimable_amount == "1000"
    assert channel.channel_id == channel_id_for(channel.config, requirements())
    validated = validate_setup_transaction(
        payload.deposit.transaction, SetupForm.OPEN, _expectations(channel), 10_000, SLOT
    )
    assert validated.payer == PAYER.pubkey()
    assert setup_form_from_transaction(payload.deposit.transaction, PROGRAM_ID) is SetupForm.OPEN
    assert payer_signature(validated.transaction) is not None
    header = json.loads(base64.b64decode(encode_payment_header(requirements(), payload)))
    assert header["x402Version"] == 2 and header["accepted"] == requirements().to_dict()


async def test_deposit_version_1() -> None:
    req = requirements(transaction_versions=[0, 1])
    channel, payload = await _opened(req)
    tx = decode_transaction(payload.deposit.transaction)
    assert txv1.is_v1(tx) and tx.message.config.compute_unit_limit == 400_000
    validate_setup_transaction(
        payload.deposit.transaction, SetupForm.OPEN, _expectations(channel, (0, 1)), 10_000, SLOT
    )
    with pytest.raises(BatchSettlementError) as exc:
        validate_setup_transaction(payload.deposit.transaction, SetupForm.OPEN, _expectations(channel), 10_000, SLOT)
    assert _code(exc) == codes.UNSUPPORTED_TRANSACTION_VERSION


async def test_deposit_refusals() -> None:
    terms = _terms()
    with pytest.raises(ValueError, match="at least one request"):
        await build_deposit(signer(), requirements(), terms, 999, BLOCKHASH, OPEN_SLOT)
    with pytest.raises(BatchSettlementError) as exc:
        await build_deposit(signer(FEE_PAYER), requirements(), terms, 10_000, BLOCKHASH, OPEN_SLOT)
    assert _code(exc) == codes.INVALID_FEE_PAYER_MISMATCH
    sponsor_operator = dataclasses.replace(terms, operator=FEE_PAYER.pubkey())
    with pytest.raises(BatchSettlementError):
        await build_deposit(signer(), requirements(), sponsor_operator, 10_000, BLOCKHASH, OPEN_SLOT)
    capped = dataclasses.replace(terms, server_signed_max_deposit=5000)
    with pytest.raises(ValueError, match="operator grant"):
        await build_deposit(signer(), requirements(), capped, 10_000, BLOCKHASH, OPEN_SLOT)
    with pytest.raises(ValueError, match="256-byte"):
        await build_deposit(
            signer(), requirements(), dataclasses.replace(terms, memo="m" * 257), 10_000, BLOCKHASH, OPEN_SLOT
        )


async def test_server_mode_builds_carry_payer_proofs() -> None:
    operator = STRANGER.pubkey()
    req = requirements(voucher_signer="server", operator=str(operator))
    terms = _terms(req, policy=ServerSignedChannelsPolicy().allow_operator(operator, 50_000))
    channel, deposit = await build_deposit(signer(), req, terms, 10_000, BLOCKHASH, OPEN_SLOT)
    assert deposit.voucher is None and deposit.authorization.authorized_amount == "1000"
    assert channel.config.voucher_signer == "server" and channel.config.payer_authorizer == str(operator)
    top_up = await build_top_up(signer(), channel, terms, 1000, BLOCKHASH)
    assert top_up.authorization is not None
    refund = await build_refund(signer(), channel, terms)
    assert refund.authorization.authorized_amount == "0"
    proof = await channel.authorization_payload(signer(), 1000, 10**10)
    assert proof.type == "authorization"
    with pytest.raises(ValueError, match="operator grant"):
        await build_top_up(
            signer(), channel, dataclasses.replace(terms, server_signed_max_deposit=10_500), 1000, BLOCKHASH
        )


async def test_top_up_refund_and_request_close() -> None:
    channel, _ = await _opened()
    channel.charged_cumulative_amount = 3000
    assert channel.can_cover(1000) and not BatchChannel(channel.channel_id, channel.config, 9500, 10_000).can_cover(
        1000
    )
    with pytest.raises(ValueError, match="client-signed"):
        await channel.authorization_payload(signer(), 1, 1)
    terms = _terms()
    top_up = await build_top_up(signer(), channel, terms, 6000, BLOCKHASH)
    assert top_up.voucher.max_claimable_amount == "4000"
    validate_setup_transaction(top_up.deposit.transaction, SetupForm.TOP_UP, _expectations(channel), 6000, None)
    refund = await build_refund(signer(), channel, terms)
    assert refund.voucher.max_claimable_amount == "3000" and refund.transaction is None
    retry = await build_refund_request_close(signer(), channel, terms, BLOCKHASH)
    assert retry.transaction is not None
    validate_request_close_transaction(retry.transaction, _expectations(channel))
    v1_terms = _terms(requirements(transaction_versions=[1]))
    v1 = await build_top_up(signer(), channel, v1_terms, 6000, BLOCKHASH)
    assert txv1.is_v1(decode_transaction(v1.deposit.transaction))


# ── tracker ──


def _response(charged: str = "4000", amount: str = "1000", **extra: Any) -> BatchSettlementResponse:
    state = ChannelStateSnapshot("c", "10000", "0", 0, charged)
    defaults: dict[str, Any] = {"commitment_id": "c:4000", "charged_amount": amount, "channel_state": state}
    defaults.update(extra)
    return BatchSettlementResponse(
        success=True, transaction="", network=NETWORK, extra=BatchSettlementExtra(**defaults)
    )


async def test_apply_payment_response() -> None:
    channel, _ = await _opened()
    channel.charged_cumulative_amount = 3000
    submitted = await channel.sign_next_voucher(signer(), 1000)
    req = requirements()
    bad = [
        BatchSettlementResponse.failure(NETWORK, "x"),
        BatchSettlementResponse(success=True, transaction="", network=NETWORK),
        _response(commitment_id=""),
        _response(amount="999"),
        _response(channel_state=None),
        _response(charged=None),  # type: ignore[arg-type]
        _response(charged="4x"),
        _response(charged="5000"),
    ]
    for response in bad:
        with pytest.raises(BatchSettlementError):
            channel.apply_payment_response(response, req, submitted)
    channel.apply_payment_response(_response(), req, submitted)
    assert (channel.charged_cumulative_amount, channel.deposit) == (4000, 10_000)


async def test_apply_authorization_response() -> None:
    operator = STRANGER
    config = BatchChannelConfig(
        payer=str(PAYER.pubkey()),
        payer_authorizer=str(operator.pubkey()),
        receiver=str(PAY_TO),
        token=str(MINT),
        withdraw_delay=3600,
        salt="42",
        open_slot=OPEN_SLOT,
        receiver_authorizer=str(RECEIVER_AUTHORIZER.pubkey()),
        voucher_signer="server",
    )
    channel_id = channel_id_for(config, requirements())
    channel = BatchChannel(channel_id, config, 1000, 10_000)
    proof = await sign_authorization(signer(), channel_id, operator.pubkey(), "r1", 1000, 10**10)

    def server_voucher(amount: int) -> BatchVoucher:
        signature = operator.sign_message(voucher_message_bytes(channel_id, amount, 0))
        return BatchVoucher(str(channel_id), str(amount), 0, str(signature))

    def response(amount: int = 1800, charged: str | None = "800", **extra: Any) -> BatchSettlementResponse:
        defaults: dict[str, Any] = {"commitment_id": "c", "charged_amount": charged, "voucher": server_voucher(amount)}
        defaults.update(extra)
        return BatchSettlementResponse(
            success=True, transaction="", network=NETWORK, extra=BatchSettlementExtra(**defaults)
        )

    foreign = dataclasses.replace(proof, payer=str(STRANGER.pubkey()))
    cases: list[tuple[Any, BatchAuthorization, int | None]] = [
        (BatchSettlementResponse.failure(NETWORK, "x"), proof, None),
        (response(), foreign, None),
        (BatchSettlementResponse(success=True, transaction="", network=NETWORK), proof, None),
        (response(commitment_id=None), proof, None),
        (response(voucher=None), proof, None),
        (response(amount=500), proof, None),
        (response(charged=None), proof, None),
        (response(charged="700"), proof, None),
        (response(amount=2100, charged="1100"), proof, None),
        (response(channel_state=ChannelStateSnapshot("c", "1", "0", 0, "1700")), proof, None),
        (response(amount=10_001, charged="9001"), dataclasses.replace(proof, authorized_amount="99999"), None),
        (response(), proof, 5000),
    ]
    for resp, authorization, confirmed in cases:
        with pytest.raises(BatchSettlementError):
            channel.apply_authorization_response(resp, authorization, confirmed)
    channel.apply_authorization_response(
        response(channel_state=ChannelStateSnapshot("c", "1", "0", 0, "1800")), proof, 20_000
    )
    assert (channel.charged_cumulative_amount, channel.deposit) == (1800, 20_000)


async def test_adopt_corrective_state() -> None:
    channel, _ = await _opened()
    proof = await channel.sign_next_voucher(signer(), 3000)

    def corrective(**state: Any) -> BatchRequirements:
        snapshot = {
            "channel_id": str(channel.channel_id),
            "balance": "10000",
            "total_claimed": "0",
            "withdraw_requested_at": 0,
        }
        snapshot.update(state)
        return requirements(
            channel_state=ChannelStateSnapshot(**snapshot),
            voucher_state=VoucherState(proof.max_claimable_amount, 0, proof.signature),
        )

    assert corrective_channel_id(corrective()) == channel.channel_id
    assert corrective_channel_id(requirements()) is None
    assert corrective_channel_id(corrective(channel_id="bad")) is None
    for req, code in (
        (requirements(), codes.INVALID_CUMULATIVE_AMOUNT_MISMATCH),
        (corrective(channel_id=str(STRANGER.pubkey())), codes.INVALID_CHANNEL_ID_MISMATCH),
        (corrective(charged_cumulative_amount="x"), codes.INVALID_CUMULATIVE_AMOUNT_MISMATCH),
        (
            dataclasses.replace(corrective(), extra=dataclasses.replace(corrective().extra, voucher_state=None)),
            codes.INVALID_CUMULATIVE_AMOUNT_MISMATCH,
        ),
    ):
        with pytest.raises(BatchSettlementError) as exc:
            channel.adopt_corrective_state(req)
        assert _code(exc) == code
    assert channel.adopt_corrective_state(corrective()) == 0
    assert channel.adopt_corrective_state(corrective(charged_cumulative_amount="3000")) == 3000
    small = BatchChannel(channel.channel_id, channel.config, 0, 1000)
    with pytest.raises(BatchSettlementError) as exc:
        small.adopt_corrective_state(corrective(charged_cumulative_amount="3000"))
    assert _code(exc) == codes.INVALID_CHANNEL_STATE


def test_parse_challenge() -> None:
    client = requirements().to_dict()
    operator = str(STRANGER.pubkey())
    server = requirements(voucher_signer="server", operator=operator).to_dict()
    envelope = {"x402Version": 2, "accepts": [server, {**client, "scheme": "exact"}, client], "error": "e"}
    header = base64.b64encode(json.dumps(envelope).encode()).decode()
    chosen = parse_challenge({"Payment-Required": header})
    assert chosen is not None and chosen[0].extra.operator is None and chosen[1] == "e"
    policy = ServerSignedChannelsPolicy().allow_operator(STRANGER.pubkey(), 1)
    trusted = parse_challenge({"payment-required": header}, policy=policy)
    assert trusted is not None and trusted[0].extra.operator == operator
    assert parse_challenge({}, json.dumps(envelope)) is not None
    assert parse_challenge({}, "not json") is None
    assert parse_challenge({}) is None
    assert parse_challenge({"payment-required": "!!"}) is None
    only_server = {"x402Version": 2, "accepts": [requirements(voucher_signer="server", operator="bad").to_dict()]}
    assert parse_challenge({}, json.dumps(only_server), policy=policy) is None


# ── sponsor policy ──


async def _policy_refusal(tx_b64: str, channel: BatchChannel, form: SetupForm = SetupForm.TOP_UP, **kwargs: Any) -> str:
    expected = _expectations(channel, **kwargs)
    with pytest.raises(BatchSettlementError) as exc:
        validate_setup_transaction(tx_b64, form, expected, 6000, None)
    return f"{exc.value.code}: {exc.value.detail}"


async def test_top_up_policy_refusals() -> None:
    channel, _ = await _opened()
    ix = _top_up_ix(channel)
    memo = _memo("invoice-42")
    third = Instruction(MEMO, b"invoice-42", [AccountMeta(STRANGER.pubkey(), True, False)])
    lighthouse = Instruction(Pubkey.from_string(LIGHTHOUSE_PROGRAM), b"\x00", [])
    fee_payer_lighthouse = Instruction(
        Pubkey.from_string(LIGHTHOUSE_PROGRAM), b"\x00", [AccountMeta(FEE_PAYER.pubkey(), False, False)]
    )
    cases: list[tuple[list[Instruction], str]] = [
        ([ix], "exactly one Memo"),
        ([ix, _memo("other")], "does not match the declared"),
        ([ix, memo, memo], "at most one Memo"),
        ([ix, memo, _memo("x" * 300)], "at most one Memo"),
        ([_price(1), _limit(1), ix, memo], "must precede"),
        ([_limit(1), _limit(1), ix, memo], "duplicate SetComputeUnitLimit"),
        ([_price(1), _price(1), ix, memo], "duplicate SetComputeUnitPrice"),
        ([_limit(500_000), ix, memo], "exceeds maximum"),
        ([_price(6_000_000), ix, memo], "exceeds maximum"),
        ([_limit(400_000), _price(10_000), ix, memo], "sponsored fee maximum"),
        (
            [Instruction(Pubkey.from_string(COMPUTE_BUDGET_PROGRAM), b"\x04\x00\x00\x00\x01", []), ix, memo],
            "unsupported ComputeBudget",
        ),
        (
            [
                Instruction(
                    Pubkey.from_string(COMPUTE_BUDGET_PROGRAM),
                    bytes(_limit(1).data),
                    [AccountMeta(PAYER.pubkey(), True, False)],
                )
            ],
            "no payment-channels instruction",
        ),
        ([memo, ix], "unexpected program"),
        ([ix, lighthouse, lighthouse, lighthouse, lighthouse, memo], "at most 3 Lighthouse"),
        ([ix, lighthouse, lighthouse, lighthouse, memo, memo], "at most 4 instructions"),
        ([ix, fee_payer_lighthouse, memo], "must not reference the fee payer"),
        ([ix, memo, Instruction(Pubkey.from_string(TOKEN_2022_PROGRAM), b"", [])], "must be Lighthouse or Memo"),
        ([ix, third], "exactly 2 signatures"),
        ([_top_up_ix(channel, 5000), memo], "does not match deposit.amount"),
    ]
    for instructions, message in cases:
        detail = await _policy_refusal(await _sponsored(instructions), channel)
        assert message in detail, (message, detail)
    assert "fee payer must be" in await _policy_refusal(await _sponsored([ix, memo], fee_payer=PAYER.pubkey()), channel)
    other = BatchChannel(Pubkey.from_string(str(STRANGER.pubkey())), channel.config, 0, 0)
    assert "channel mismatch" in await _policy_refusal(await _sponsored([ix, memo]), other)
    assert codes.INVALID_FEE_PAYER_MISMATCH in await _policy_refusal(
        await _sponsored([ix, memo]),
        BatchChannel(channel.channel_id, dataclasses.replace(channel.config, payer=str(FEE_PAYER.pubkey())), 0, 0),
    )
    # The sponsor must not be an instruction account of a top-up.
    sponsor_account = Instruction(
        ix.program_id, bytes(ix.data), [*ix.accounts, AccountMeta(FEE_PAYER.pubkey(), False, False)]
    )
    assert "exactly 6 accounts" in await _policy_refusal(await _sponsored([sponsor_account, memo]), channel)
    v1 = await _sponsored([ix, memo], version=1)
    validate_setup_transaction(v1, SetupForm.TOP_UP, _expectations(channel, (0, 1)), 6000, None)
    no_loaded_limit = await build_partially_signed_transaction(
        [ix, memo],
        FEE_PAYER.pubkey(),
        BLOCKHASH,
        signer(),
        version=1,
        config=txv1.TransactionConfig(compute_unit_limit=1),
    )
    detail = await _policy_refusal(base64.b64encode(no_loaded_limit).decode(), channel, versions=(0, 1))
    assert "loaded accounts data size" in detail
    # A hex nonce stands in for an undeclared memo.
    nonce = await _sponsored([ix, _memo("ab" * 16)])
    validate_setup_transaction(nonce, SetupForm.TOP_UP, _expectations(channel, memo=None), 6000, None)
    assert "hex nonce" in await _policy_refusal(await _sponsored([ix, _memo("zz")]), channel, memo=None)


async def test_open_policy_refusals() -> None:
    channel, payload = await _opened()
    tx = payload.deposit.transaction
    expected = _expectations(channel)
    for deposit, slot, message in (
        (9999, SLOT, "does not match deposit.amount"),
        (10_000, OPEN_SLOT - 1, "ahead of the current slot"),
        (10_000, OPEN_SLOT + 1501, "outside the 1500-slot window"),
    ):
        with pytest.raises(BatchSettlementError, match=message):
            validate_setup_transaction(tx, SetupForm.OPEN, expected, deposit, slot)
    with pytest.raises(BatchSettlementError) as exc:
        validate_setup_transaction(
            tx, SetupForm.OPEN, dataclasses.replace(expected, receiver_authorizer=STRANGER.pubkey()), 10_000, SLOT
        )
    assert _code(exc) == codes.INVALID_RECEIVER_AUTHORIZER_MISMATCH
    for config, message in (
        (dataclasses.replace(channel.config, withdraw_delay=7200), codes.INVALID_WITHDRAW_DELAY_MISMATCH),
        (dataclasses.replace(channel.config, salt="43"), "does not match channelConfig.salt"),
        (dataclasses.replace(channel.config, open_slot=OPEN_SLOT + 1), "does not match channelConfig.openSlot"),
    ):
        with pytest.raises(BatchSettlementError, match=message):
            validate_setup_transaction(tx, SetupForm.OPEN, dataclasses.replace(expected, config=config), 10_000, SLOT)
    with pytest.raises(BatchSettlementError, match="must pay 100%"):
        validate_setup_transaction(
            tx, SetupForm.OPEN, dataclasses.replace(expected, receiver=STRANGER.pubkey()), 10_000, SLOT
        )
    with pytest.raises(BatchSettlementError, match="mismatch"):
        validate_setup_transaction(
            tx,
            SetupForm.OPEN,
            dataclasses.replace(expected, token_program=Pubkey.from_string(TOKEN_2022_PROGRAM)),
            10_000,
            SLOT,
        )
    # A bare open (no binding memo) fails the layout scan.
    decoded = decode_transaction(tx)
    open_ix = decoded.message.instructions[0]
    keys = decoded.message.account_keys
    bare = Instruction(
        PROGRAM_ID, bytes(open_ix.data), [AccountMeta(keys[i], i < 2, True) for i in bytes(open_ix.accounts)]
    )
    with pytest.raises(BatchSettlementError, match="binding Memo"):
        validate_setup_transaction(
            await _sponsored([bare, _memo("invoice-42")]), SetupForm.OPEN, expected, 10_000, SLOT
        )
    binding = _memo(receiver_binding_memo(RECEIVER_AUTHORIZER.pubkey()))
    with pytest.raises(BatchSettlementError, match="exactly one binding Memo"):
        validate_setup_transaction(
            await _sponsored([bare, _memo("invoice-42"), binding, binding]), SetupForm.OPEN, expected, 10_000, SLOT
        )


async def test_decode_and_form_detection() -> None:
    channel, payload = await _opened()
    for bad in ("!!", base64.b64encode(b"\x01\x02").decode()):
        with pytest.raises(ValueError):
            decode_transaction(bad)
    raw = base64.b64decode(payload.deposit.transaction) + b"\x00"
    with pytest.raises(ValueError, match="non-canonical"):
        decode_transaction(base64.b64encode(raw).decode())
    with pytest.raises(BatchSettlementError, match="could not be decoded"):
        setup_form_from_transaction("!!", PROGRAM_ID)
    with pytest.raises(BatchSettlementError, match="exactly one open or top_up"):
        signed_memo = Instruction(MEMO, b"x", [AccountMeta(PAYER.pubkey(), True, False)])
        setup_form_from_transaction(await _sponsored([signed_memo]), PROGRAM_ID)
    unsigned = decode_transaction(payload.deposit.transaction)
    assert payer_signature(unsigned) is not None
    tx = await _sponsored([_top_up_ix(channel), _memo("a"), _memo("b")])
    primary = scan_channel_tx_layout(decode_transaction(tx), PROGRAM_ID, 3, "top_up", MemoPolicy("optional"))
    assert bytes(primary.data)[0] == 3
    with pytest.raises(ValueError, match="not a payment-channels top_up"):
        scan_channel_tx_layout(decode_transaction(tx), PROGRAM_ID, 1, "top_up", MemoPolicy("optional"))


async def test_request_close_policy() -> None:
    channel, _ = await _opened()
    terms = _terms()
    retry = await build_refund_request_close(signer(), channel, terms, BLOCKHASH)
    expected = _expectations(channel)
    with pytest.raises(BatchSettlementError) as exc:
        validate_request_close_transaction(
            retry.transaction or "", dataclasses.replace(expected, accepted_versions=(1,))
        )
    assert _code(exc) == codes.UNSUPPORTED_TRANSACTION_VERSION
    with pytest.raises(BatchSettlementError) as exc:
        validate_request_close_transaction("!!", expected)
    assert _code(exc) == codes.INVALID_REFUND_TRANSACTION
    request_close = Instruction(
        PROGRAM_ID, b"\x05", [AccountMeta(PAYER.pubkey(), True, False), AccountMeta(channel.channel_id, False, True)]
    )
    memo = _memo("invoice-42")
    for instructions, message in (
        ([request_close], "exactly one Memo"),
        ([Instruction(PROGRAM_ID, b"\x05\x00", list(request_close.accounts)), memo], "takes no arguments"),
        (
            [Instruction(PROGRAM_ID, b"\x05", [*request_close.accounts, AccountMeta(MINT, False, False)]), memo],
            "exactly 2 accounts",
        ),
        (
            [
                Instruction(
                    PROGRAM_ID, b"\x05", [request_close.accounts[0], AccountMeta(STRANGER.pubkey(), False, True)]
                ),
                memo,
            ],
            "channel mismatch",
        ),
        (
            [
                Instruction(
                    PROGRAM_ID, b"\x05", [request_close.accounts[0], AccountMeta(channel.channel_id, False, False)]
                ),
                memo,
            ],
            "must be writable",
        ),
    ):
        with pytest.raises(BatchSettlementError) as exc:
            validate_request_close_transaction(await _sponsored(instructions), expected)
        assert _code(exc) == codes.INVALID_REFUND_TRANSACTION and message in exc.value.detail, exc.value.detail
    with pytest.raises(BatchSettlementError) as exc:
        validate_request_close_transaction(await _sponsored([request_close, memo], fee_payer=PAYER.pubkey()), expected)
    assert _code(exc) == codes.INVALID_REFUND_TRANSACTION
