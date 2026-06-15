"""Fee-payer cosign and the strict pre-broadcast instruction allowlist.

The security-critical half of the server charge flow: splicing the fee-payer
signature into the canonical slot, the ATA-creation policy, and the
no-leftovers allowlist that protects the fee-payer keypair from being
co-opted into signing attacker-supplied transfers. Builds on the pure
decoders in :mod:`pay_kit.protocols.mpp.server._tx_decode`; the ``Mpp``
orchestration that drives broadcast / confirmation lives in
:mod:`pay_kit.protocols.mpp.server.charge`.
"""

from __future__ import annotations

import base64
from typing import Any

from pay_kit._paycore.errors import PaymentError
from pay_kit._paycore.solana import (
    ASSOCIATED_TOKEN_PROGRAM,
    MEMO_PROGRAM,
    TOKEN_2022_PROGRAM,
    TOKEN_PROGRAM,
    MethodDetails,
    default_token_program_for_currency,
    is_native_sol,
    resolve_mint,
)
from pay_kit._paycore.transaction import is_v0_wire_bytes
from pay_kit.protocols.mpp.intents.charge import ChargeRequest
from pay_kit.protocols.mpp.server._tx_decode import (
    _COMPUTE_BUDGET_PROGRAM,
    _MEMO_V1_PROGRAM,
    _SYSTEM_PROGRAM,
    _SYSTEM_TRANSFER_INSTRUCTION,
    _TOKEN_TRANSFER_CHECKED_INSTRUCTION,
    _build_expected_transfers,
    _decode_legacy_payment_instructions,
    _expected_memos,
    _validate_compute_budget_instruction,
    _verify_ata_owner,
    _verify_parsed_memo_instructions,
    _verify_parsed_sol_transfers,
    _verify_parsed_spl_transfers,
)


def _co_sign_with_fee_payer(transaction_b64: str, fee_payer: Any) -> str:
    """Co-sign a client transaction with the server's fee payer keypair.

    The fee payer occupies the first signer slot in Solana transactions. We
    serialize the message in the correct shape for its version (legacy uses
    ``bytes(msg)``; v0 uses ``to_bytes_versioned(msg)`` which prepends the
    ``0x80`` version tag), sign with the fee-payer private key, and splice
    the resulting signature into the signature array at the slot matching
    the fee-payer pubkey.

    Mirrors the cosign step in rust/src/server/charge.rs verify_pull.
    """
    from solders.message import to_bytes_versioned
    from solders.transaction import Transaction, VersionedTransaction

    raw = base64.b64decode(transaction_b64)
    fee_payer_pubkey = fee_payer.pubkey()

    # Try legacy transaction first (the common path); fall back to versioned.
    try:
        tx = Transaction.from_bytes(raw)
    except Exception:
        try:
            vtx = VersionedTransaction.from_bytes(raw)
        except Exception as exc:
            raise PaymentError(
                f"could not decode transaction for fee payer co-sign: {exc}",
                code="invalid-payload-type",
            ) from exc
        account_keys = list(vtx.message.account_keys)
        try:
            idx = account_keys.index(fee_payer_pubkey)
        except ValueError as exc:
            raise PaymentError(
                "fee payer pubkey not present in transaction accounts",
                code="invalid-payload",
            ) from exc
        num_required = int(vtx.message.header.num_required_signatures)
        _assert_signature_slot(idx, num_required)
        # v0 messages are signed over ``to_bytes_versioned(msg)`` which
        # prepends the 0x80 version byte.
        message_bytes = bytes(to_bytes_versioned(vtx.message))
        sig_bytes = bytes(fee_payer.sign_message(message_bytes))
        # Manual splice in the on-wire bytes preserves the rest of the
        # transaction exactly. Wire format: [num_sigs (compact-u16)] [sigs]
        # [message...]. num_sigs < 128 so it is a 1-byte prefix.
        serialized = bytearray(raw)
        sig_start = 1 + idx * 64
        serialized[sig_start : sig_start + 64] = sig_bytes
        return base64.b64encode(bytes(serialized)).decode("ascii")

    account_keys = list(tx.message.account_keys)
    try:
        idx = account_keys.index(fee_payer_pubkey)
    except ValueError as exc:
        raise PaymentError(
            "fee payer pubkey not present in transaction accounts",
            code="invalid-payload",
        ) from exc
    num_required = int(tx.message.header.num_required_signatures)
    _assert_signature_slot(idx, num_required)

    # Legacy Transaction: sign ``bytes(msg)`` directly.
    message_bytes = bytes(tx.message)
    sig_bytes = bytes(fee_payer.sign_message(message_bytes))
    serialized = bytearray(raw)
    sig_start = 1 + idx * 64
    serialized[sig_start : sig_start + 64] = sig_bytes
    return base64.b64encode(bytes(serialized)).decode("ascii")


def _assert_signature_slot(idx: int, num_required: int) -> None:
    """Validate that the fee payer occupies the canonical slot 0.

    The Solana protocol requires the fee payer to be ``account_keys[0]``:
    the runtime debits the first required signer for transaction fees. If
    we accepted a fee-payer pubkey at any slot inside the required-signers
    block, a client could craft a transaction that includes a benign
    payment transfer plus an extra instruction that *also* needs the
    server's key as a required signer (for example, at slot 1). The
    pre-broadcast decoder would still accept the transfer half, and the
    server would happily produce its signature, letting the client
    co-opt the server's private key to authorize arbitrary on-chain
    intents. Enforcing ``idx == 0`` matches the Rust spine's
    ``expected_fee_payer`` invariant (``account_keys.first() == fee_payer``)
    and closes that escalation path before any sign call is made.
    """
    if idx < 0 or idx >= num_required:
        raise PaymentError(
            f"fee payer pubkey at account index {idx} is outside the "
            f"required-signers block (num_required_signatures={num_required}); "
            "a client must place the fee payer inside the signer header",
            code="invalid-payload",
        )
    if idx != 0:
        raise PaymentError(
            "fee payer pubkey must occupy account index 0 (the transaction "
            f"fee-payer slot); found at index {idx}. The Solana runtime "
            "always debits the first required signer for fees, so any other "
            "placement would cause the server's key to sign for an "
            "instruction outside the fee-payment role.",
            code="invalid-payload",
        )


def _expected_ata_creation_policy(
    details: MethodDetails,
    fee_payer_pubkey: str | None,
) -> tuple[set[str], set[str]]:
    """Return ``(allowed_ata_owners, required_ata_owners)`` per Rust spine.

    Mirrors ``expected_ata_creation_policy`` in
    ``rust/src/server/charge.rs``:

    - ``required_ata_owners`` is the set of split recipients with
      ``ataCreationRequired=true``.
    - ``allowed_ata_owners`` is ``required_ata_owners`` when the route
      advertises ``feePayer=true`` (the server only sponsors ATA creates
      that the route explicitly demanded), and the set of every split
      recipient when no fee-payer co-sign is in play (client pays its
      own ATA rent so it may opportunistically create ATAs for any
      declared split).

    The primary recipient is NEVER in ``allowed_ata_owners``. Including
    it would let a sponsored route co-sign an ATA create for the top-level
    recipient even though no split asked for it, spending fee-payer SOL
    on rent the route did not authorize.
    """
    required_owners: set[str] = set()
    split_owners: set[str] = set()
    for split in details.splits:
        split_owners.add(split.recipient)
        if split.ata_creation_required:
            required_owners.add(split.recipient)

    allowed_owners = set(required_owners) if fee_payer_pubkey is not None else split_owners
    return allowed_owners, required_owners


def _validate_ata_create_idempotent(
    instruction: Any,
    account_keys: list[str],
    expected_mint: str | None,
    allowed_ata_owners: set[str],
    expected_token_program: str | None,
    expected_payer: str,
) -> str:
    """Validate an AssociatedTokenAccount create-idempotent instruction.

    Returns the validated ATA ``owner`` so the caller can confirm every
    ``ataCreationRequired`` split recipient actually had its ATA created,
    mirroring rust ``validate_create_ata_idempotent_instruction``.

    Mirrors ``validate_create_ata_idempotent_instruction`` in
    ``rust/src/server/charge.rs``. The only ATA program instruction the
    fee-payer co-sign path may include is the idempotent create variant
    (discriminator byte ``0x01``) and only for an ATA whose payer is the
    transaction fee payer, whose owner is a recipient declared by the
    charge, whose mint matches the challenge currency, and whose token
    program is the one the challenge selected. Any deviation is rejected
    so an attacker cannot trick the server into co-signing an ATA create
    that funds an attacker-controlled mint or owner with fee-payer SOL.
    """
    if expected_mint is None:
        raise PaymentError(
            "ATA creation is not allowed for native SOL payments",
            code="invalid-payload",
        )
    data = bytes(instruction.data)
    if data != b"\x01":
        raise PaymentError(
            "only idempotent ATA creation is allowed",
            code="invalid-payload",
        )
    accounts = list(instruction.accounts)
    if len(accounts) != 6:
        raise PaymentError(
            "unexpected ATA creation account layout",
            code="invalid-payload",
        )
    try:
        payer = account_keys[int(accounts[0])]
        ata = account_keys[int(accounts[1])]
        owner = account_keys[int(accounts[2])]
        mint = account_keys[int(accounts[3])]
        sys_program = account_keys[int(accounts[4])]
        token_program = account_keys[int(accounts[5])]
    except IndexError as exc:
        raise PaymentError(
            "ATA creation references an unknown account index",
            code="invalid-payload",
        ) from exc

    if payer != expected_payer:
        raise PaymentError(
            "ATA payer must match the transaction fee payer",
            code="invalid-payload",
        )
    if mint != expected_mint:
        raise PaymentError(
            "ATA creation mint does not match the charge currency",
            code="invalid-payload",
        )
    if owner not in allowed_ata_owners:
        raise PaymentError(
            "ATA creation owner is not authorized by the challenge",
            code="invalid-payload",
        )
    if sys_program != _SYSTEM_PROGRAM:
        raise PaymentError(
            "ATA creation must reference the System Program",
            code="invalid-payload",
        )
    if token_program not in {TOKEN_PROGRAM, TOKEN_2022_PROGRAM}:
        raise PaymentError(
            "ATA creation uses an unsupported token program",
            code="invalid-payload",
        )
    if expected_token_program is not None and token_program != expected_token_program:
        raise PaymentError(
            "ATA creation token program does not match methodDetails.tokenProgram",
            code="invalid-payload",
        )
    # Verify the derived ATA matches owner/mint/token_program so a caller
    # cannot funnel the create to an attacker-controlled address.
    try:
        from solders.pubkey import Pubkey

        owner_pk = Pubkey.from_string(owner)
        mint_pk = Pubkey.from_string(mint)
        tp_pk = Pubkey.from_string(token_program)
        ata_program = Pubkey.from_string(ASSOCIATED_TOKEN_PROGRAM)
        derived, _ = Pubkey.find_program_address(
            [bytes(owner_pk), bytes(tp_pk), bytes(mint_pk)],
            ata_program,
        )
        if str(derived) != ata:
            raise PaymentError(
                "ATA creation address does not match owner/mint/token program",
                code="invalid-payload",
            )
    except PaymentError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise PaymentError(
            f"could not validate ATA creation address: {exc}",
            code="invalid-payload",
        ) from exc

    return owner


def _validate_instruction_allowlist(
    transaction_b64: str,
    request: ChargeRequest,
    details: MethodDetails,
    expected_fee_payer_pubkey: str | None = None,
) -> None:
    """Reject any instruction not on the strict fee-payer co-sign allowlist.

    SECURITY: this is the no-leftovers check that protects the server's
    fee-payer keypair from being co-opted into signing attacker-supplied
    transfers. The lossy parsed-instruction verifier
    (``_verify_parsed_sol_transfers`` /
    ``_verify_parsed_spl_transfers`` / ``_verify_parsed_memo_instructions``)
    only checks that the required transfers / memos are present; it does
    not reject extra instructions. Without this allowlist a malicious
    client could include the expected payment plus a System Program
    transfer from the fee payer to the attacker, and the server would
    co-sign the entire transaction.

    The allowlist mirrors ``validate_instruction_allowlist`` in
    ``rust/src/server/charge.rs``: only ComputeBudget (validated),
    Memo v2 (must match an expected memo), System Program transfer (must
    match an expected payment transfer), SPL Token / Token-2022
    transferChecked (must match an expected payment transfer), and
    AssociatedTokenAccount create-idempotent (validated) are accepted.
    Anything else (including SOL transfers that do not match a required
    transfer, SPL transfers to unrelated mints, raw token approve /
    burn, BPF program calls, sysvar reads, etc.) is rejected before
    broadcast with a ``payment-invalid`` canonical code.
    """
    from solders.transaction import Transaction, VersionedTransaction

    raw = base64.b64decode(transaction_b64)
    message: Any = None
    message_instructions: list[Any] = []
    # Route v0 wire bytes straight to VersionedTransaction; the legacy
    # parser in solders is lenient and can mis-parse a signed v0 tx as a
    # degenerate legacy tx whose instructions point at random account
    # keys. The allowlist would then reject the legitimate v0 payment
    # with a misleading "unexpected program instruction" error sourced
    # from junk bytes. See is_v0_wire_bytes.
    parsed = False
    if is_v0_wire_bytes(raw):
        try:
            vtx = VersionedTransaction.from_bytes(raw)
        except Exception:
            vtx = None
        if vtx is not None:
            if getattr(vtx.message, "address_table_lookups", None):
                raise PaymentError(
                    "v0 transactions with address lookup tables are not supported",
                    code="invalid-payload",
                ) from None
            message = vtx.message
            message_instructions = list(vtx.message.instructions)
            parsed = True
    if not parsed:
        try:
            tx = Transaction.from_bytes(raw)
            message = tx.message
            message_instructions = list(tx.message.instructions)
        except Exception:
            try:
                vtx = VersionedTransaction.from_bytes(raw)
            except Exception as exc:
                raise PaymentError(
                    "unsupported transaction shape for instruction allowlist",
                    code="invalid-payload-type",
                ) from exc
            if getattr(vtx.message, "address_table_lookups", None):
                raise PaymentError(
                    "v0 transactions with address lookup tables are not supported",
                    code="invalid-payload",
                ) from None
            message = vtx.message
            message_instructions = list(vtx.message.instructions)

    account_keys = [str(key) for key in message.account_keys]
    if not account_keys:
        raise PaymentError("transaction has no accounts", code="invalid-payload")
    fee_payer_account = account_keys[0]
    # SECURITY: when the charge advertises feePayer=true the protective
    # pubkey used for drain detection MUST come from the server-side
    # signing context (``Mpp._fee_payer_signer.pubkey()``), NOT from
    # client-echoed ``methodDetails.feePayerKey``. A malicious client can
    # tamper the echoed key to a pubkey it controls, pass the source-account
    # checks below (because they compare against the tampered value), and
    # still get the real server keypair to co-sign and broadcast a transfer
    # sourced from the actual server fee-payer.
    #
    # The client-echoed ``details.fee_payer_key`` is cross-checked against
    # the server pubkey above this allowlist (in ``_verify_local_transaction_intent``)
    # so a mismatch is rejected up-front with ``payment_invalid``. Here we
    # only consume the server-supplied pubkey. If no server pubkey was
    # threaded (e.g. unit tests that call the helper directly), we fall
    # back to the echoed value for backward compatibility; production
    # callers always thread the server pubkey.
    fee_payer_pubkey: str | None
    if expected_fee_payer_pubkey is not None:
        fee_payer_pubkey = expected_fee_payer_pubkey
    elif details.fee_payer and details.fee_payer_key:
        fee_payer_pubkey = details.fee_payer_key
    else:
        fee_payer_pubkey = None

    expected_transfers = _build_expected_transfers(request, details)
    native = is_native_sol(request.currency)
    expected_mint = None if native else resolve_mint(request.currency, details.network)
    expected_token_program: str | None = None
    if not native:
        expected_token_program = details.token_program or default_token_program_for_currency(
            request.currency, details.network
        )
    allowed_ata_owners, required_ata_owners = _expected_ata_creation_policy(details, fee_payer_pubkey)
    created_ata_owners: set[str] = set()
    expected_memos = {memo for _label, memo in _expected_memos(request, details)}

    # Track which required transfers / memos have been satisfied so each
    # required entry can only be matched once; an attacker cannot replay
    # a single transfer to cover two required legs.
    remaining_transfers: list[tuple[str, int]] = list(expected_transfers)
    remaining_memos: set[str] = set(expected_memos)

    for instruction in message_instructions:
        try:
            program_id = account_keys[int(instruction.program_id_index)]
        except IndexError as exc:
            raise PaymentError(
                "instruction references an unknown program index",
                code="invalid-payload",
            ) from exc
        data = bytes(instruction.data)
        accounts = list(instruction.accounts)

        if program_id == _COMPUTE_BUDGET_PROGRAM:
            # Audit #25: apply the tight fee-sponsored price cap when the server
            # is the fee payer (it co-signs and pays the priority fee before
            # broadcast). Client-paid charges keep the general cap.
            _validate_compute_budget_instruction(
                data, len(accounts), fee_sponsored=details.fee_payer
            )
            continue

        if program_id == MEMO_PROGRAM:
            try:
                memo_text = data.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise PaymentError(
                    "memo instruction is not valid UTF-8",
                    code="invalid-payload",
                ) from exc
            if memo_text not in remaining_memos:
                raise PaymentError(
                    "unexpected Memo Program instruction in payment transaction",
                    code="invalid-payload",
                )
            remaining_memos.discard(memo_text)
            continue

        if program_id == _MEMO_V1_PROGRAM:
            raise PaymentError(
                "memo v1 program is not supported (use Memo v2)",
                code="invalid-payload",
            )

        if program_id == _SYSTEM_PROGRAM:
            if not native:
                raise PaymentError(
                    "unexpected System Program instruction in token payment transaction",
                    code="invalid-payload",
                )
            if len(data) < 12 or len(accounts) < 2:
                raise PaymentError(
                    "unexpected System Program instruction in payment transaction",
                    code="invalid-payload",
                )
            kind = int.from_bytes(data[:4], "little")
            if kind != _SYSTEM_TRANSFER_INSTRUCTION:
                raise PaymentError(
                    "unexpected System Program instruction in payment transaction",
                    code="invalid-payload",
                )
            try:
                source = account_keys[int(accounts[0])]
                destination = account_keys[int(accounts[1])]
            except IndexError as exc:
                raise PaymentError(
                    "transfer references an unknown account",
                    code="invalid-payload",
                ) from exc
            # SECURITY: reject any System transfer that sources lamports from
            # the configured fee-payer (mirrors rust spine ``verify_sol_transfer_instructions``).
            # Without this guard a malicious client can satisfy the required
            # payment with a transfer FROM the fee-payer, draining server SOL
            # on top of the network fee already debited from account_keys[0].
            if fee_payer_pubkey is not None and source == fee_payer_pubkey:
                raise PaymentError(
                    "fee payer cannot fund the SOL payment transfer",
                    code="invalid-payload",
                )
            lamports = int.from_bytes(data[4:12], "little")
            match_idx = next(
                (i for i, (rcpt, amt) in enumerate(remaining_transfers) if rcpt == destination and amt == lamports),
                -1,
            )
            if match_idx == -1:
                raise PaymentError(
                    "unexpected System Program transfer in payment transaction",
                    code="invalid-payload",
                )
            remaining_transfers.pop(match_idx)
            continue

        if program_id in {TOKEN_PROGRAM, TOKEN_2022_PROGRAM}:
            if native:
                raise PaymentError(
                    "unexpected Token Program instruction in native SOL payment",
                    code="invalid-payload",
                )
            if expected_token_program is not None and program_id != expected_token_program:
                raise PaymentError(
                    "token program does not match methodDetails.tokenProgram",
                    code="invalid-payload",
                )
            if len(data) < 10 or len(accounts) < 4:
                raise PaymentError(
                    "unexpected Token Program instruction in payment transaction",
                    code="invalid-payload",
                )
            if data[0] != _TOKEN_TRANSFER_CHECKED_INSTRUCTION:
                raise PaymentError(
                    "unexpected Token Program instruction in payment transaction",
                    code="invalid-payload",
                )
            try:
                source_ata = account_keys[int(accounts[0])]
                mint = account_keys[int(accounts[1])]
                destination = account_keys[int(accounts[2])]
                authority = account_keys[int(accounts[3])]
            except IndexError as exc:
                raise PaymentError(
                    "token transfer references an unknown account",
                    code="invalid-payload",
                ) from exc
            if expected_mint is not None and mint != expected_mint:
                raise PaymentError(
                    "token transfer mint does not match the charge currency",
                    code="invalid-payload",
                )
            # SECURITY: reject any SPL transferChecked authorized by the
            # configured fee-payer or sourced from the fee-payer's ATA for
            # this mint / token program. Mirrors rust spine
            # ``verify_spl_transfer_instructions``. Without these checks a
            # malicious client can present a transferChecked FROM the
            # fee-payer ATA TO the recipient ATA matching the required
            # amount; the allowlist would pass and the server would
            # co-sign, draining fee-payer tokens.
            if fee_payer_pubkey is not None:
                if authority == fee_payer_pubkey:
                    raise PaymentError(
                        "fee payer cannot authorize the SPL payment transfer",
                        code="invalid-payload",
                    )
                if _verify_ata_owner(source_ata, fee_payer_pubkey, mint, program_id):
                    raise PaymentError(
                        "fee payer token account cannot fund the SPL payment transfer",
                        code="invalid-payload",
                    )
            amount = int.from_bytes(data[1:9], "little")
            # transferChecked encodes the token decimals as the trailing byte
            # (data[9]); reject a mismatch against the challenge decimals so a
            # transfer targeting a different mint precision cannot satisfy a
            # required leg. Mirrors the parsed-transfer matcher and the TS
            # reference verifier (server/Charge.ts verifySplTransferPreBroadcast).
            decimals = data[9]
            match_idx = next(
                (
                    i
                    for i, (rcpt, amt) in enumerate(remaining_transfers)
                    if amt == amount
                    and (details.decimals is None or decimals == details.decimals)
                    and _verify_ata_owner(destination, rcpt, mint, program_id)
                ),
                -1,
            )
            if match_idx == -1:
                raise PaymentError(
                    "unexpected Token Program transfer in payment transaction",
                    code="invalid-payload",
                )
            remaining_transfers.pop(match_idx)
            continue

        if program_id == ASSOCIATED_TOKEN_PROGRAM:
            created_owner = _validate_ata_create_idempotent(
                instruction,
                account_keys,
                expected_mint,
                allowed_ata_owners,
                expected_token_program,
                fee_payer_account,
            )
            created_ata_owners.add(created_owner)
            continue

        raise PaymentError(
            f"unexpected program instruction in payment transaction: {program_id}",
            code="invalid-payload",
        )

    # SECURITY: every split recipient flagged ``ataCreationRequired`` must have
    # a matching create-ATA-idempotent instruction, mirroring rust
    # ``validate_instruction_allowlist`` (server/charge.rs:1362-1368). Without
    # this a sponsored credential that omits a demanded create is accepted and
    # the server cosigns/broadcasts, so settlement under-creates the recipient ATA.
    for owner in required_ata_owners:
        if owner not in created_ata_owners:
            raise PaymentError(
                f"missing required ATA creation instruction for split recipient {owner}",
                code="invalid-payload",
            )


def _verify_local_transaction_intent(
    transaction_b64: str,
    request: ChargeRequest,
    details: MethodDetails,
    expected_fee_payer_pubkey: str | None = None,
) -> None:
    """Verify locally-decodable payment intent before broadcasting.

    ``expected_fee_payer_pubkey`` is the AUTHORITATIVE server-side fee-payer
    pubkey (``Mpp._fee_payer_signer.pubkey()``). It is threaded by
    ``_verify_transaction`` so the no-leftovers allowlist can detect drain
    attempts against the real server key, not against a client-echoed
    ``methodDetails.feePayerKey`` value (which an attacker controls). When
    both are present and ``details.fee_payer`` is true we also reject any
    mismatch up-front with the canonical ``payment_invalid`` code so a
    tampered echoed key cannot silently slip through.
    """
    if (
        expected_fee_payer_pubkey is not None
        and details.fee_payer
        and details.fee_payer_key
        and details.fee_payer_key != expected_fee_payer_pubkey
    ):
        raise PaymentError(
            "methodDetails.feePayerKey does not match the server fee-payer signer",
            code="invalid-payload",
        )
    instructions = _decode_legacy_payment_instructions(transaction_b64)
    if is_native_sol(request.currency):
        _verify_parsed_sol_transfers(instructions, request, details)
    else:
        _verify_parsed_spl_transfers(instructions, request, details)
    _verify_parsed_memo_instructions(instructions, request, details)
    # SECURITY: strict no-leftovers allowlist. Runs after the parsed
    # verifiers so a missing-required-transfer fails with the canonical
    # ``no-transfer`` code; this final pass rejects ANY extra instruction
    # (especially System Program transfers from the fee payer) so the
    # fee-payer co-sign path cannot be tricked into draining the
    # server's SOL.
    _validate_instruction_allowlist(
        transaction_b64,
        request,
        details,
        expected_fee_payer_pubkey=expected_fee_payer_pubkey,
    )
