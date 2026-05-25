from __future__ import annotations

import base64
import json
import secrets
from dataclasses import dataclass
from typing import Any

from solana.rpc.api import Client
from solders.compute_budget import set_compute_unit_limit, set_compute_unit_price
from solders.hash import Hash
from solders.instruction import Instruction
from solders.keypair import Keypair
from solders.message import MessageV0, to_bytes_versioned
from solders.pubkey import Pubkey
from solders.signature import Signature
from solders.transaction import VersionedTransaction
from spl.token.constants import TOKEN_2022_PROGRAM_ID, TOKEN_PROGRAM_ID
from spl.token.instructions import (
    TransferCheckedParams,
    get_associated_token_address,
    transfer_checked,
)

MEMO_PROGRAM_ID = Pubkey.from_string("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr")
DEFAULT_COMPUTE_UNIT_LIMIT = 20_000
DEFAULT_COMPUTE_UNIT_PRICE_MICROLAMPORTS = 1
MAX_MEMO_BYTES = 256
TOKEN_MINT_DECIMALS_OFFSET = 44


@dataclass(frozen=True)
class MintMetadata:
    decimals: int
    token_program: Pubkey


def keypair_from_json_secret(raw: str) -> Keypair:
    decoded = json.loads(raw)
    if not isinstance(decoded, list) or len(decoded) != 64:
        raise ValueError("expected a 64-byte Solana secret key JSON array")
    return Keypair.from_bytes(bytes(int(value) for value in decoded))


def fetch_mint_metadata(rpc_url: str, mint: str) -> MintMetadata:
    client = Client(rpc_url)
    response = client.get_account_info(Pubkey.from_string(mint), encoding="base64")
    account = response.value
    if account is None:
        raise RuntimeError(f"mint account not found: {mint}")

    data = bytes(account.data)
    if len(data) <= TOKEN_MINT_DECIMALS_OFFSET:
        raise RuntimeError(f"mint account data is too short: {mint}")

    owner = account.owner
    if owner not in (TOKEN_PROGRAM_ID, TOKEN_2022_PROGRAM_ID):
        raise RuntimeError(f"mint owner is not a known token program: {owner}")

    return MintMetadata(decimals=data[TOKEN_MINT_DECIMALS_OFFSET], token_program=owner)


def latest_blockhash(rpc_url: str) -> str:
    return str(Client(rpc_url).get_latest_blockhash().value.blockhash)


def _requirement_extra(requirement: dict[str, Any]) -> dict[str, Any]:
    extra = requirement.get("extra")
    return extra if isinstance(extra, dict) else {}


def _require_string(requirement: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = requirement.get(key)
        if isinstance(value, str) and value:
            return value
    raise ValueError(f"payment requirement is missing {keys[0]}")


def _require_int(requirement: dict[str, Any], key: str) -> int:
    value = requirement.get(key)
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    extra = _requirement_extra(requirement)
    extra_value = extra.get(key)
    if isinstance(extra_value, int):
        return extra_value
    if isinstance(extra_value, str) and extra_value.isdigit():
        return int(extra_value)
    raise ValueError(f"payment requirement is missing integer {key}")


def _optional_extra_string(requirement: dict[str, Any], key: str) -> str | None:
    value = requirement.get(key)
    if isinstance(value, str) and value:
        return value
    extra_value = _requirement_extra(requirement).get(key)
    return extra_value if isinstance(extra_value, str) and extra_value else None


def _memo_instruction(requirement: dict[str, Any]) -> Instruction:
    memo = _optional_extra_string(requirement, "memo")
    memo_text = memo if memo is not None else secrets.token_hex(16)
    memo_data = memo_text.encode("utf-8")
    if len(memo_data) > MAX_MEMO_BYTES:
        raise ValueError(f"extra.memo exceeds maximum {MAX_MEMO_BYTES} bytes")
    return Instruction(MEMO_PROGRAM_ID, memo_data, [])


def build_exact_payment_signature(
    *,
    requirement: dict[str, Any],
    client_keypair: Keypair,
    blockhash: str,
    decimals: int,
    token_program: Pubkey,
    resource: dict[str, Any] | None = None,
) -> str:
    if requirement.get("scheme") != "exact":
        raise ValueError("only exact payment requirements can be signed")

    amount = _require_int(requirement, "amount")
    mint = Pubkey.from_string(_require_string(requirement, "asset", "currency"))
    pay_to = Pubkey.from_string(_require_string(requirement, "payTo", "recipient"))
    fee_payer = Pubkey.from_string(_require_string(_requirement_extra(requirement), "feePayer"))
    source_ata = get_associated_token_address(client_keypair.pubkey(), mint, token_program)
    destination_ata = get_associated_token_address(pay_to, mint, token_program)

    instructions = [
        set_compute_unit_limit(DEFAULT_COMPUTE_UNIT_LIMIT),
        set_compute_unit_price(DEFAULT_COMPUTE_UNIT_PRICE_MICROLAMPORTS),
        transfer_checked(
            TransferCheckedParams(
                program_id=token_program,
                source=source_ata,
                mint=mint,
                dest=destination_ata,
                owner=client_keypair.pubkey(),
                amount=amount,
                decimals=decimals,
            )
        ),
        _memo_instruction(requirement),
    ]

    message = MessageV0.try_compile(fee_payer, instructions, [], Hash.from_string(blockhash))
    signatures = [Signature.default()] * message.header.num_required_signatures
    signer_index = list(message.account_keys).index(client_keypair.pubkey())
    signatures[signer_index] = client_keypair.sign_message(to_bytes_versioned(message))
    transaction = VersionedTransaction.populate(message, signatures)
    payload = {
        "x402Version": 2,
        "accepted": requirement,
        "payload": {
            "transaction": base64.b64encode(bytes(transaction)).decode("ascii"),
        },
    }
    if resource is not None:
        payload["resource"] = resource

    return base64.b64encode(
        json.dumps(payload, separators=(",", ":")).encode("utf-8")
    ).decode("ascii")


def build_exact_payment_signature_from_rpc(
    *,
    requirement: dict[str, Any],
    client_secret_key: str,
    rpc_url: str,
    resource: dict[str, Any] | None = None,
) -> str:
    extra = _requirement_extra(requirement)
    decimals_value = requirement.get("decimals", extra.get("decimals"))
    token_program_value = requirement.get("tokenProgram", extra.get("tokenProgram"))
    blockhash = _optional_extra_string(requirement, "recentBlockhash") or latest_blockhash(rpc_url)

    if isinstance(decimals_value, int) and isinstance(token_program_value, str):
        metadata = MintMetadata(
            decimals=decimals_value,
            token_program=Pubkey.from_string(token_program_value),
        )
    else:
        metadata = fetch_mint_metadata(rpc_url, _require_string(requirement, "asset", "currency"))

    return build_exact_payment_signature(
        requirement=requirement,
        client_keypair=keypair_from_json_secret(client_secret_key),
        blockhash=blockhash,
        decimals=metadata.decimals,
        token_program=metadata.token_program,
        resource=resource,
    )
