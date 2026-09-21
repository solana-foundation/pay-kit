"""Pure validation of a subscriber-signed subscription activation transaction.

The server co-signs the activation as the plan puller (and as fee payer when
sponsored), so every instruction the transaction carries runs under a server
signature. :func:`validate_activation` therefore allows only compute-budget,
one memo, and the subscriptions program's ``init authority``, ``subscribe``
and ``transfer_subscription``, each pinned to the exact accounts and data the
challenge implies. Any associated-token-account instruction is rejected, as
the spec requires. No RPC and no signing happens here; :func:`cosign` signs
only after validation passed.

Legacy and v0 messages are accepted, like the other Python servers; address
lookup tables are not, so every account the transaction touches is visible.
"""

from __future__ import annotations

import base64
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from solders.instruction import Instruction  # type: ignore[import-untyped]
from solders.message import to_bytes_versioned  # type: ignore[import-untyped]
from solders.pubkey import Pubkey  # type: ignore[import-untyped]
from solders.signature import Signature  # type: ignore[import-untyped]
from solders.transaction import VersionedTransaction  # type: ignore[import-untyped]

from solana_pay_kit._paycore.errors import PaymentError
from solana_pay_kit._paycore.solana import COMPUTE_BUDGET_PROGRAM, MEMO_PROGRAM
from solana_pay_kit.protocols.mpp._subscriptions import (
    IX_INIT_SA,
    IX_SUBSCRIBE,
    IX_TRANSFER_SUBSCRIPTION,
    UNKNOWN_INIT_ID,
    PlanView,
    build_init_subscription_authority_ix,
    build_subscribe_ix,
    build_transfer_subscription_ix,
    sign_message,
    signer_pubkey,
)
from solana_pay_kit.protocols.mpp.server._tx_decode import (
    _validate_compute_budget_instruction,  # pyright: ignore[reportPrivateUsage]
)

__all__ = [
    "ACTIVATION_MAX_COMPUTE_UNIT_LIMIT",
    "ActivationExpectation",
    "ParsedActivation",
    "cosign",
    "validate_activation",
]

#: Compute-unit ceiling for an activation (init + subscribe + transfer), as in Rust and TS.
ACTIVATION_MAX_COMPUTE_UNIT_LIMIT = 400_000

_COMPUTE_BUDGET = Pubkey.from_string(COMPUTE_BUDGET_PROGRAM)
_MEMO = Pubkey.from_string(MEMO_PROGRAM)
_ALLOWED_SUBSCRIPTION_IXS = (bytes([IX_INIT_SA]), bytes([IX_SUBSCRIBE]), bytes([IX_TRANSFER_SUBSCRIPTION]))
_SUBSCRIBE_DATA_LEN = 74
_INIT_ID_OFFSET = 66
_MAX_SIGNATURES = 127  # the signature count must fit the 1-byte compact-u16 prefix cosign splices after


@dataclass(frozen=True)
class ActivationExpectation:
    """What the challenge and the on-chain plan pin; ``fee_payer`` is the sponsor, or ``None`` when unsponsored."""

    program: Pubkey
    plan: PlanView
    token_program: Pubkey
    puller: Pubkey
    recipient: Pubkey
    amount: int
    fee_payer: Pubkey | None
    external_id: str = ""


@dataclass(frozen=True)
class ParsedActivation:
    """A validated activation: its subscriber, whether it inits the authority, and the wire bytes."""

    subscriber: Pubkey
    has_init: bool
    raw: bytes


def _reject(message: str) -> PaymentError:
    return PaymentError(message, code="invalid-payload")


def _decode(raw: bytes) -> VersionedTransaction:
    try:
        return VersionedTransaction.from_bytes(raw)
    except Exception as exc:  # noqa: BLE001 - solders raises its own error types
        raise PaymentError(f"activation transaction does not decode: {exc}", code="invalid-payload-type") from exc


def _same(ix: Instruction, accounts: list[Pubkey], data: bytes) -> bool:
    return [meta.pubkey for meta in ix.accounts] == accounts and bytes(ix.data) == data


def validate_activation(tx_b64: str, expect: ActivationExpectation) -> ParsedActivation:
    """Check the activation's instructions, accounts, data and signers against ``expect``; raise on any deviation."""
    try:
        raw = base64.b64decode(tx_b64, validate=True)
    except ValueError as exc:
        raise PaymentError("activation transaction is not base64", code="invalid-payload-type") from exc
    tx = _decode(raw)
    message = tx.message
    if getattr(message, "address_table_lookups", None):
        raise _reject("activation transactions with address lookup tables are not supported")
    keys: list[Pubkey] = list(message.account_keys)
    num_signers = int(message.header.num_required_signatures)
    if len(tx.signatures) != num_signers or num_signers > _MAX_SIGNATURES:
        raise _reject("activation signature count does not match the message header")

    found: dict[int, tuple[int, list[Pubkey], bytes]] = {}
    compute_kinds: set[int] = set()
    memo_seen = False
    for position, ix in enumerate(message.instructions):
        try:
            program = keys[ix.program_id_index]
            accounts = [keys[index] for index in ix.accounts]
        except IndexError as exc:
            raise _reject("activation instruction references an unknown account") from exc
        data = bytes(ix.data)
        if program == _COMPUTE_BUDGET:
            _validate_compute_budget_instruction(
                data,
                len(accounts),
                fee_sponsored=expect.fee_payer is not None,
                max_unit_limit=ACTIVATION_MAX_COMPUTE_UNIT_LIMIT,
            )
            if data[0] in compute_kinds:
                raise _reject("activation repeats a compute-budget instruction")
            compute_kinds.add(data[0])
        elif program == _MEMO:
            if memo_seen or accounts or not expect.external_id or data != expect.external_id.encode("utf-8"):
                raise _reject("activation memo does not match the challenge externalId")
            memo_seen = True
        elif program == expect.program and data[:1] in _ALLOWED_SUBSCRIPTION_IXS:
            if data[0] in found:
                raise _reject("activation repeats a subscriptions instruction")
            found[data[0]] = (position, accounts, data)
        else:
            raise _reject(f"activation instruction for program {program} is not allowed")
    if bool(expect.external_id) != memo_seen:
        raise _reject("activation memo does not match the challenge externalId")
    if IX_SUBSCRIBE not in found or IX_TRANSFER_SUBSCRIPTION not in found:
        raise _reject("activation must contain one subscribe and one transfer_subscription")
    subscribe_at, subscribe_accounts, subscribe_data = found[IX_SUBSCRIBE]
    init = found.get(IX_INIT_SA)
    if found[IX_TRANSFER_SUBSCRIPTION][0] < subscribe_at or (init is not None and init[0] > subscribe_at):
        raise _reject("activation order must be init authority, subscribe, transfer_subscription")
    if not subscribe_accounts or len(subscribe_data) != _SUBSCRIBE_DATA_LEN:
        raise _reject("subscribe does not match the challenged activation")

    subscriber = subscribe_accounts[0]
    plan = expect.plan
    init_id = int.from_bytes(subscribe_data[_INIT_ID_OFFSET:], "little", signed=True)
    if (init_id == UNKNOWN_INIT_ID) != (init is not None):
        raise _reject("subscribe must use the UNKNOWN_INIT_ID sentinel exactly when it inits the authority")
    expected = build_subscribe_ix(
        program=expect.program, subscriber=subscriber, plan=plan, init_id=init_id, payer=expect.fee_payer
    )
    if not _same(expected, subscribe_accounts, subscribe_data):
        raise _reject("subscribe does not match the challenged activation")
    expected = build_transfer_subscription_ix(
        program=expect.program,
        subscriber=subscriber,
        plan=plan,
        recipient=expect.recipient,
        puller=expect.puller,
        token_program=expect.token_program,
        amount=expect.amount,
    )
    if not _same(expected, *found[IX_TRANSFER_SUBSCRIPTION][1:]):
        raise _reject("transfer_subscription does not match the challenged activation")
    if init is not None:
        expected = build_init_subscription_authority_ix(
            program=expect.program, subscriber=subscriber, mint=plan.mint, token_program=expect.token_program
        )
        if not _same(expected, *init[1:]):
            raise _reject("init authority does not match the challenged activation")

    signers = keys[:num_signers]
    if subscriber in (expect.puller, expect.fee_payer):
        raise _reject("the subscriber must not be a server key")
    if subscriber not in signers or expect.puller not in signers:
        raise _reject("the subscriber and the puller must both be required signers")
    if keys[0] != (expect.fee_payer if expect.fee_payer is not None else subscriber):
        raise _reject("activation fee payer must be the sponsor when sponsored, else the subscriber")
    # Every slot the server does not fill must already carry a valid signature.
    # Unsponsored, slot 0 is the transaction id the replay keys and the status
    # check trust, so an unverified slot would let a client name any confirmed
    # transaction as its own.
    message_bytes = bytes(to_bytes_versioned(message))
    for index, key in enumerate(signers):
        if key not in (expect.puller, expect.fee_payer) and not tx.signatures[index].verify(key, message_bytes):
            raise _reject(f"activation signature for {key} does not verify")
    return ParsedActivation(subscriber=subscriber, has_init=init is not None, raw=raw)


def cosign(raw: bytes, signers: Sequence[Any], *, fee_payer: Pubkey | None) -> tuple[bytes, str]:
    """Splice each server signer's signature into its slot; return the wire and the transaction signature.

    ``fee_payer`` (the sponsor) must sit at account index 0. A signer whose key
    is not a required signer of the message is refused before anything is signed.
    """
    tx = _decode(raw)
    keys: list[Pubkey] = list(tx.message.account_keys)
    num_signers = int(tx.message.header.num_required_signatures)
    if num_signers > _MAX_SIGNATURES or raw[0] != num_signers:
        raise _reject("activation signature count does not match the message header")
    if fee_payer is not None and keys[0] != fee_payer:
        raise _reject("the sponsor is not the activation fee payer")
    slots: dict[int, Any] = {}
    for signer in signers:
        key = signer_pubkey(signer)
        if key not in keys[:num_signers]:
            raise _reject(f"server key {key} is not a required signer of the activation")
        slots[keys.index(key)] = signer
    message = bytes(to_bytes_versioned(tx.message))
    wire = bytearray(raw)
    for index, signer in slots.items():
        wire[1 + 64 * index : 65 + 64 * index] = sign_message(signer, message)
    return bytes(wire), str(Signature.from_bytes(bytes(wire[1:65])))
