"""x402 ``upto`` pure-verifier + client-builder coverage (fully offline).

Covers the ordered payload checks, the settlement-ceiling assertion, the
14-account open-instruction validator, and the client builder - including a
client↔engine wire cross-check: the open transaction the client builds must pass
the engine's open-instruction validator with the matching expected pubkeys.
"""

from __future__ import annotations

import time

import pytest
from solders.keypair import Keypair  # type: ignore[import-untyped]
from solders.pubkey import Pubkey  # type: ignore[import-untyped]

from solana_pay_kit import LocalSigner
from solana_pay_kit._paycore.solana import TOKEN_PROGRAM
from solana_pay_kit.errors import InvalidProofError
from solana_pay_kit.protocols.x402.client.upto import (
    build_upto_header,
    build_upto_payload,
    encode_upto_header,
    parse_upto_challenge,
)
from solana_pay_kit.protocols.x402.upto import _decode_transaction
from solana_pay_kit.protocols.x402.upto.types import (
    UPTO_ERROR_SETTLEMENT_EXCEEDS_AMOUNT,
    UPTO_SCHEME,
    UptoPayload,
    UptoRequirements,
)
from solana_pay_kit.protocols.x402.upto.verify import (
    assert_settlement_within_ceiling,
    parse_base_units,
    validate_upto_open_instruction,
    verify_upto_payload,
)

BH = "4vJ9JU1bJJQpUgJ8V6hYz7xXKz4F2tN6aBrZEcD3xKhs"
MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"  # USDC mainnet
MAX = 100000


def _operator() -> tuple[LocalSigner, str]:
    signer = LocalSigner.from_keypair(Keypair())
    return signer, signer.pubkey()


def _requirements(operator: str, payee: str, *, amount: int = MAX) -> UptoRequirements:
    return {
        "scheme": UPTO_SCHEME,
        "network": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
        "amount": str(amount),
        "asset": MINT,
        "payTo": payee,
        "maxTimeoutSeconds": 300,
        "extra": {
            "decimals": 6,
            "tokenProgram": TOKEN_PROGRAM,
            "feePayer": operator,
            "receiverAuthorizer": operator,
            "withdrawDelay": 900,
            "recentBlockhash": BH,
            "recentSlot": "4242",
        },
    }


def _payload(operator: str, *, channel_id: str = "11111111111111111111111111111112") -> UptoPayload:
    now = int(time.time())
    return {
        "from": str(Keypair().pubkey()),
        "maxAmount": str(MAX),
        "expiresAt": now + 300,
        "validAfter": now - 10,
        "nonce": "7",
        "channelId": channel_id,
        "deposit": str(MAX),
        "authorizedSigner": operator,
        "openSlot": "4242",
    }


# -- parse_base_units -------------------------------------------------------


def test_parse_base_units_ok() -> None:
    assert parse_base_units("100000", "amount") == 100000


@pytest.mark.parametrize("bad", ["", "abc", "-1", "1.5", str(2**64)])
def test_parse_base_units_rejects(bad: str) -> None:
    with pytest.raises(InvalidProofError):
        parse_base_units(bad, "amount")


# -- verify_upto_payload ----------------------------------------------------


def test_verify_payload_happy() -> None:
    _, op = _operator()
    verify_upto_payload(_payload(op), _requirements(op, str(Keypair().pubkey())), op, int(time.time()))


def test_verify_payload_amount_mismatch() -> None:
    _, op = _operator()
    p = _payload(op)
    p["maxAmount"] = "999"
    p["deposit"] = "999"
    with pytest.raises(InvalidProofError, match="amount mismatch"):
        verify_upto_payload(p, _requirements(op, str(Keypair().pubkey())), op, int(time.time()))


def test_verify_payload_deposit_not_equal_max() -> None:
    _, op = _operator()
    p = _payload(op)
    p["deposit"] = "50000"
    with pytest.raises(InvalidProofError, match="deposit"):
        verify_upto_payload(p, _requirements(op, str(Keypair().pubkey())), op, int(time.time()))


def test_verify_payload_not_yet_active() -> None:
    _, op = _operator()
    p = _payload(op)
    now = int(time.time())
    p["validAfter"] = now + 100
    with pytest.raises(InvalidProofError, match="not yet active"):
        verify_upto_payload(p, _requirements(op, str(Keypair().pubkey())), op, now)


def test_verify_payload_expired() -> None:
    _, op = _operator()
    p = _payload(op)
    now = int(time.time())
    p["expiresAt"] = now - 1
    with pytest.raises(InvalidProofError, match="expired"):
        verify_upto_payload(p, _requirements(op, str(Keypair().pubkey())), op, now)


def test_verify_payload_rejects_zero_or_boundary_expiry() -> None:
    _, op = _operator()
    p = _payload(op)
    now = int(time.time())
    p["expiresAt"] = 0
    with pytest.raises(InvalidProofError, match="expired"):
        verify_upto_payload(p, _requirements(op, str(Keypair().pubkey())), op, now)
    p["expiresAt"] = now
    with pytest.raises(InvalidProofError, match="expired"):
        verify_upto_payload(p, _requirements(op, str(Keypair().pubkey())), op, now)


def test_verify_payload_authorized_signer_not_receiver_authorizer() -> None:
    _, op = _operator()
    p = _payload(op)
    p["authorizedSigner"] = str(Keypair().pubkey())
    with pytest.raises(InvalidProofError, match="receiver authorizer"):
        verify_upto_payload(p, _requirements(op, str(Keypair().pubkey())), op, int(time.time()))


# -- assert_settlement_within_ceiling ---------------------------------------


def test_ceiling_ok() -> None:
    assert_settlement_within_ceiling(50000, 100000)
    assert_settlement_within_ceiling(100000, 100000)
    assert_settlement_within_ceiling(0, 100000)


def test_ceiling_exceeded() -> None:
    with pytest.raises(InvalidProofError) as exc:
        assert_settlement_within_ceiling(100001, 100000)
    assert exc.value.code == UPTO_ERROR_SETTLEMENT_EXCEEDS_AMOUNT


# -- client builder + wire cross-check --------------------------------------


def test_parse_upto_challenge_from_header() -> None:
    _, op = _operator()
    from solana_pay_kit.protocols.x402.upto import X402Upto  # noqa: PLC0415

    req = _requirements(op, str(Keypair().pubkey()))
    import base64
    import json

    envelope = {"x402Version": 2, "accepts": [req]}
    header = base64.b64encode(json.dumps(envelope).encode()).decode()
    parsed = parse_upto_challenge({"payment-required": header})
    assert parsed is not None and parsed["scheme"] == UPTO_SCHEME
    assert X402Upto  # imported for symmetry


def test_parse_upto_challenge_from_body() -> None:
    _, op = _operator()
    import json

    req = _requirements(op, str(Keypair().pubkey()))
    body = json.dumps({"accepts": [req]})
    parsed = parse_upto_challenge({}, body)
    assert parsed is not None and parsed["payTo"] == req["payTo"]


def test_parse_upto_challenge_none_when_absent() -> None:
    assert parse_upto_challenge({}) is None
    assert parse_upto_challenge({}, "{}") is None


def test_build_payload_requires_blockhash() -> None:
    _, op = _operator()
    client = LocalSigner.from_keypair(Keypair())
    req = _requirements(op, str(Keypair().pubkey()))
    del req["extra"]["recentBlockhash"]
    with pytest.raises(ValueError, match="recentBlockhash"):
        build_upto_payload(client, req, int(time.time()) + 300)


def test_client_open_tx_passes_engine_validator() -> None:
    """The open transaction the client builds must satisfy the engine's
    14-account open-instruction validator with the matching expected pubkeys -
    proving the client and server agree on the wire."""
    _, op = _operator()
    payee = str(Keypair().pubkey())
    client = LocalSigner.from_keypair(Keypair())
    req = _requirements(op, payee)
    payload = build_upto_payload(client, req, int(time.time()) + 300, nonce="n")

    open_tx = payload.get("openTransaction", "")
    account_keys, instructions = _decode_transaction(open_tx)
    # Fee payer slot 0 is the advertised fee payer; the client signed only its own slot.
    assert account_keys[0] == op
    assert payload["nonce"] != "n"
    assert payload["nonce"].isdigit()
    assert payload["openSlot"] == "4242"
    validate_upto_open_instruction(
        account_keys,
        instructions,
        program_id=_default_program(),
        fee_payer=Pubkey.from_string(op),
        receiver_authorizer=Pubkey.from_string(op),
        payer=Pubkey.from_string(client.pubkey()),
        payee=Pubkey.from_string(op),
        mint=Pubkey.from_string(MINT),
        token_program=Pubkey.from_string(TOKEN_PROGRAM),
        channel_id=Pubkey.from_string(payload["channelId"]),
        max_amount=MAX,
        withdraw_delay=900,
        payload_nonce=payload["nonce"],
        payload_open_slot=payload["openSlot"],
        recent_slot=4242,  # the challenged extra.recentSlot the client built against
    )

    # Encode/decode the header round-trips and carries the payment-channel payload.
    import base64
    import json

    header = encode_upto_header(req, payload)
    decoded = json.loads(base64.b64decode(header))
    assert decoded["accepted"]["scheme"] == UPTO_SCHEME
    assert "profile" not in decoded["payload"]
    assert decoded["payload"]["deposit"] == str(MAX)
    # build_upto_header is the one-shot equivalent of build + encode.
    assert build_upto_header(client, req, int(time.time()) + 300, nonce="n")


def test_client_open_tx_payee_is_fee_payer() -> None:
    """With distinct feePayer/receiverAuthorizer keys, the client puts the fee
    payer in the payee seat (slot 2 + PDA seed) and keeps the receiver
    authorizer as the authorized signer only (slot 4 + voucher)."""
    _, fee_payer = _operator()
    _, authorizer = _operator()
    client = LocalSigner.from_keypair(Keypair())
    req = _requirements(fee_payer, str(Keypair().pubkey()))
    req["extra"]["receiverAuthorizer"] = authorizer
    payload = build_upto_payload(client, req, int(time.time()) + 300)
    assert payload["authorizedSigner"] == authorizer
    account_keys, instructions = _decode_transaction(payload.get("openTransaction", ""))
    assert account_keys[0] == fee_payer
    validate_upto_open_instruction(
        account_keys,
        instructions,
        program_id=_default_program(),
        fee_payer=Pubkey.from_string(fee_payer),
        receiver_authorizer=Pubkey.from_string(authorizer),
        payer=Pubkey.from_string(client.pubkey()),
        payee=Pubkey.from_string(fee_payer),  # the zero-share payee seat
        mint=Pubkey.from_string(MINT),
        token_program=Pubkey.from_string(TOKEN_PROGRAM),
        channel_id=Pubkey.from_string(payload["channelId"]),
        max_amount=MAX,
        withdraw_delay=900,
        payload_nonce=payload["nonce"],
        payload_open_slot=payload["openSlot"],
        recent_slot=4242,
    )
    # A validator that expects the receiver authorizer in the payee seat rejects.
    with pytest.raises(InvalidProofError, match="payee mismatch"):
        validate_upto_open_instruction(
            account_keys,
            instructions,
            program_id=_default_program(),
            fee_payer=Pubkey.from_string(fee_payer),
            receiver_authorizer=Pubkey.from_string(authorizer),
            payer=Pubkey.from_string(client.pubkey()),
            payee=Pubkey.from_string(authorizer),  # the old payee assignment
            mint=Pubkey.from_string(MINT),
            token_program=Pubkey.from_string(TOKEN_PROGRAM),
            channel_id=Pubkey.from_string(payload["channelId"]),
            max_amount=MAX,
            withdraw_delay=900,
            payload_nonce=payload["nonce"],
            payload_open_slot=payload["openSlot"],
            recent_slot=4242,
        )


def test_client_open_tx_validator_rejects_wrong_payee() -> None:
    _, op = _operator()
    payee = str(Keypair().pubkey())
    client = LocalSigner.from_keypair(Keypair())
    req = _requirements(op, payee)
    payload = build_upto_payload(client, req, int(time.time()) + 300, nonce="n")
    account_keys, instructions = _decode_transaction(payload.get("openTransaction", ""))
    with pytest.raises(InvalidProofError, match="payee mismatch"):
        validate_upto_open_instruction(
            account_keys,
            instructions,
            program_id=_default_program(),
            fee_payer=Pubkey.from_string(op),
            receiver_authorizer=Pubkey.from_string(op),
            payer=Pubkey.from_string(client.pubkey()),
            payee=Pubkey.from_string(str(Keypair().pubkey())),  # wrong payee
            mint=Pubkey.from_string(MINT),
            token_program=Pubkey.from_string(TOKEN_PROGRAM),
            channel_id=Pubkey.from_string(payload["channelId"]),
            max_amount=MAX,
            withdraw_delay=900,
            payload_nonce=payload["nonce"],
            payload_open_slot=payload["openSlot"],
            recent_slot=4242,
        )


def test_client_open_tx_validator_binds_open_args() -> None:
    """The validator decodes openArgs and enforces the slot-addressed channel
    invariant: a wrong deposit, a channel that is not the PDA derived from the
    args' salt/openSlot, an openSlot ahead of the challenged recentSlot, and a
    stale openSlot outside the freshness window all reject."""
    _, op = _operator()
    payee = str(Keypair().pubkey())
    client = LocalSigner.from_keypair(Keypair())
    req = _requirements(op, payee)
    payload = build_upto_payload(client, req, int(time.time()) + 300, nonce="n")
    account_keys, instructions = _decode_transaction(payload.get("openTransaction", ""))

    def check(**overrides):
        kwargs = {
            "program_id": _default_program(),
            "fee_payer": Pubkey.from_string(op),
            "receiver_authorizer": Pubkey.from_string(op),
            "payer": Pubkey.from_string(client.pubkey()),
            "payee": Pubkey.from_string(op),
            "mint": Pubkey.from_string(MINT),
            "token_program": Pubkey.from_string(TOKEN_PROGRAM),
            "channel_id": Pubkey.from_string(payload["channelId"]),
            "max_amount": MAX,
            "withdraw_delay": 900,
            "payload_nonce": payload["nonce"],
            "payload_open_slot": payload["openSlot"],
            "recent_slot": 4242,
        }
        kwargs.update(overrides)
        validate_upto_open_instruction(account_keys, instructions, **kwargs)

    # Deposit must equal the authorized maximum.
    with pytest.raises(InvalidProofError, match="payload nonce"):
        check(payload_nonce="8")
    with pytest.raises(InvalidProofError, match="payload openSlot"):
        check(payload_open_slot="4243")
    with pytest.raises(InvalidProofError, match="withdraw delay"):
        check(withdraw_delay=901)
    with pytest.raises(InvalidProofError, match="authorized maximum"):
        check(max_amount=MAX + 1)
    # A channel id that is not the PDA derived from the args fails the bind
    # (channel account check fires first on the mismatched slot-5 account).
    with pytest.raises(InvalidProofError, match="channel"):
        check(channel_id=Pubkey.from_string(str(Keypair().pubkey())))
    # openSlot (4242, from the challenge) ahead of the challenged slot rejects.
    with pytest.raises(InvalidProofError, match="ahead of the challenged"):
        check(recent_slot=4241)
    # openSlot outside the 1500-slot freshness window rejects.
    with pytest.raises(InvalidProofError, match="freshness"):
        check(recent_slot=4242 + 1501)
    # At the window edge it verifies.
    check(recent_slot=4242 + 1500)
    # Unknown challenged slot skips the window check but keeps the PDA bind.
    check(recent_slot=None)


def _default_program() -> Pubkey:
    from solana_pay_kit._paycore.paymentchannels import PROGRAM_ID

    return PROGRAM_ID


# -- open transaction layout ------------------------------------------------


def _cu_limit_ix(units: int):
    from solders.instruction import Instruction  # type: ignore[import-untyped]

    from solana_pay_kit._paycore.paymentchannels import COMPUTE_BUDGET_SET_UNIT_LIMIT
    from solana_pay_kit._paycore.solana import COMPUTE_BUDGET_PROGRAM

    data = bytes([COMPUTE_BUDGET_SET_UNIT_LIMIT]) + units.to_bytes(4, "little")
    return Instruction(Pubkey.from_string(COMPUTE_BUDGET_PROGRAM), data, [])


def _cu_price_ix(micro_lamports: int):
    from solders.instruction import Instruction  # type: ignore[import-untyped]

    from solana_pay_kit._paycore.paymentchannels import COMPUTE_BUDGET_SET_UNIT_PRICE
    from solana_pay_kit._paycore.solana import COMPUTE_BUDGET_PROGRAM

    data = bytes([COMPUTE_BUDGET_SET_UNIT_PRICE]) + micro_lamports.to_bytes(8, "little")
    return Instruction(Pubkey.from_string(COMPUTE_BUDGET_PROGRAM), data, [])


def _heap_frame_ix():
    """A ComputeBudget instruction outside the two the layout permits."""
    from solders.instruction import Instruction  # type: ignore[import-untyped]

    from solana_pay_kit._paycore.solana import COMPUTE_BUDGET_PROGRAM

    return Instruction(Pubkey.from_string(COMPUTE_BUDGET_PROGRAM), bytes([1, 0, 0, 0, 0]), [])


def _memo_ix(text: str):
    from solders.instruction import Instruction  # type: ignore[import-untyped]

    from solana_pay_kit._paycore.solana import MEMO_PROGRAM

    return Instruction(Pubkey.from_string(MEMO_PROGRAM), text.encode("utf-8"), [])


def _lighthouse_ix():
    from solders.instruction import Instruction  # type: ignore[import-untyped]

    from solana_pay_kit._paycore.paymentchannels import LIGHTHOUSE_PROGRAM

    return Instruction(Pubkey.from_string(LIGHTHOUSE_PROGRAM), bytes([0]), [])


def test_open_tx_layout_accepts_compute_budget_and_memo_wrapping() -> None:
    """The canonical TypeScript client sizes the compute budget before the open
    and appends a memo after it; Phantom/Solflare inject Lighthouse assertions.
    Every wrapper is optional, and the bare open the pay-kit clients build stays
    valid."""
    from solders.hash import Hash  # type: ignore[import-untyped]
    from solders.message import Message  # type: ignore[import-untyped]

    from solana_pay_kit._paycore.paymentchannels import (
        Distribution,
        OpenChannelParams,
        build_open_instruction,
        find_channel_pda,
    )

    _, op = _operator()
    operator = Pubkey.from_string(op)
    payer = Pubkey.from_string(LocalSigner.from_keypair(Keypair()).pubkey())
    mint = Pubkey.from_string(MINT)
    token_program = Pubkey.from_string(TOKEN_PROGRAM)
    program_id = _default_program()
    salt = 7
    open_slot = 4242
    channel, _ = find_channel_pda(payer, operator, mint, operator, salt, open_slot, program_id)
    open_ix = build_open_instruction(
        OpenChannelParams(
            payer=payer,
            rent_payer=operator,
            payee=operator,
            mint=mint,
            authorized_signer=operator,
            salt=salt,
            deposit=MAX,
            grace_period=900,
            open_slot=open_slot,
            recipients=[Distribution(recipient=Pubkey.from_string(str(Keypair().pubkey())), bps=10_000)],
            token_program=token_program,
            program_id=program_id,
        )
    )

    def check(prefix: list, suffix: list) -> None:
        """Validate `prefix` + open + `suffix` with every account expectation
        satisfied, so the outcome turns only on the layout."""
        message = Message.new_with_blockhash([*prefix, open_ix, *suffix], operator, Hash.from_string(BH))
        validate_upto_open_instruction(
            [str(k) for k in message.account_keys],
            list(message.instructions),
            program_id=program_id,
            fee_payer=operator,
            receiver_authorizer=operator,
            payer=payer,
            payee=operator,
            mint=mint,
            token_program=token_program,
            channel_id=channel,
            max_amount=MAX,
            withdraw_delay=900,
            payload_nonce=str(salt),
            payload_open_slot=str(open_slot),
            recent_slot=open_slot,
        )

    check([], [])
    check([_cu_limit_ix(90_000), _cu_price_ix(1)], [_memo_ix("order-4711")])
    check([], [_lighthouse_ix(), _lighthouse_ix(), _lighthouse_ix(), _memo_ix("x")])

    # ComputeBudget ordering, duplicates, and unsupported opcodes.
    with pytest.raises(InvalidProofError, match="must precede"):
        check([_cu_price_ix(1), _cu_limit_ix(90_000)], [])
    with pytest.raises(InvalidProofError, match="duplicate SetComputeUnitLimit"):
        check([_cu_limit_ix(90_000), _cu_limit_ix(90_000)], [])
    with pytest.raises(InvalidProofError, match="duplicate SetComputeUnitPrice"):
        check([_cu_price_ix(1), _cu_price_ix(1)], [])
    with pytest.raises(InvalidProofError, match="unsupported ComputeBudget"):
        check([_heap_frame_ix()], [])

    # The operator pays the priority fee on the requested limit, so both knobs
    # are capped.
    with pytest.raises(InvalidProofError, match="compute unit limit"):
        check([_cu_limit_ix(400_001)], [])
    with pytest.raises(InvalidProofError, match="compute unit price"):
        check([_cu_price_ix(5_000_001)], [])

    # Suffix budget: at most 3 Lighthouse assertions, 4 optional instructions,
    # and nothing but Lighthouse/Memo.
    with pytest.raises(InvalidProofError, match="Lighthouse instructions"):
        check([], [_lighthouse_ix()] * 4)
    with pytest.raises(InvalidProofError, match="instructions after open"):
        check([], [_lighthouse_ix(), _lighthouse_ix(), _lighthouse_ix(), _memo_ix("a"), _memo_ix("b")])
    with pytest.raises(InvalidProofError, match="must be Lighthouse or Memo"):
        check([], [_cu_limit_ix(90_000)])

    # The operator co-signs this transaction, so only `open` may reference it: a
    # wrapper instruction naming the fee payer could borrow its authority.
    from solders.instruction import AccountMeta, Instruction  # type: ignore[import-untyped]

    from solana_pay_kit._paycore.solana import MEMO_PROGRAM

    memo_naming_operator = Instruction(
        Pubkey.from_string(MEMO_PROGRAM),
        b"signed-memo",
        [AccountMeta(operator, True, False)],
    )
    with pytest.raises(InvalidProofError, match="Memo instruction must not reference the fee payer"):
        check([], [memo_naming_operator])


def test_client_emits_the_declared_memo_after_open() -> None:
    """A seller that declares extra.memo requires exactly one matching Memo
    after open, so the client emits it; without the declaration the transaction
    stays a bare open."""
    from solana_pay_kit._paycore.solana import MEMO_PROGRAM

    _, op = _operator()
    client = LocalSigner.from_keypair(Keypair())
    req = _requirements(op, str(Keypair().pubkey()))
    req["extra"]["memo"] = "order-4711"
    payload = build_upto_payload(client, req, int(time.time()) + 300)
    account_keys, instructions = _decode_transaction(payload.get("openTransaction", ""))
    assert len(instructions) == 2
    memo_ix = instructions[1]
    assert account_keys[int(memo_ix.program_id_index)] == MEMO_PROGRAM
    assert bytes(memo_ix.data).decode("utf-8") == "order-4711"
    # The wrapped open still satisfies the validator.
    validate_upto_open_instruction(
        account_keys,
        instructions,
        program_id=_default_program(),
        fee_payer=Pubkey.from_string(op),
        receiver_authorizer=Pubkey.from_string(op),
        payer=Pubkey.from_string(client.pubkey()),
        payee=Pubkey.from_string(op),
        mint=Pubkey.from_string(MINT),
        token_program=Pubkey.from_string(TOKEN_PROGRAM),
        channel_id=Pubkey.from_string(payload["channelId"]),
        max_amount=MAX,
        withdraw_delay=900,
        payload_nonce=payload["nonce"],
        payload_open_slot=payload["openSlot"],
        recent_slot=4242,
    )

    # An over-long memo is rejected at build time rather than by the facilitator.
    req["extra"]["memo"] = "x" * 257
    with pytest.raises(ValueError, match="memo"):
        build_upto_payload(client, req, int(time.time()) + 300)
