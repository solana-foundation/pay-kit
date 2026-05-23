"""Client-side transaction building for charge intent."""

from __future__ import annotations

import logging
from typing import Any

from solana_mpp._base64url import decode_json
from solana_mpp._headers import format_authorization
from solana_mpp._types import PaymentChallenge, PaymentCredential
from solana_mpp.protocol.intents import ChargeRequest
from solana_mpp.protocol.solana import (
    MEMO_PROGRAM,
    CredentialPayload,
    MethodDetails,
    is_native_sol,
)

logger = logging.getLogger(__name__)


async def build_credential_header(
    signer: Any,
    rpc_client: Any,
    challenge: PaymentChallenge,
) -> str:
    """Create an Authorization header value from a challenge.

    Args:
        signer: A Solana keypair (solders.Keypair) for signing transactions.
        rpc_client: A solana.rpc.async_api.AsyncClient for RPC calls.
        challenge: The payment challenge to satisfy.

    Returns:
        The formatted Authorization header value.
    """
    request_data = decode_json(challenge.request)
    request = ChargeRequest.from_dict(request_data)

    details = MethodDetails()
    if request.method_details:
        details = MethodDetails.from_dict(request.method_details)

    payload = await build_charge_transaction(
        signer=signer,
        rpc_client=rpc_client,
        amount=request.amount,
        currency=request.currency,
        recipient=request.recipient,
        external_id=request.external_id,
        method_details=details,
    )

    credential = PaymentCredential(
        challenge=challenge.to_echo(),
        payload=payload.to_dict(),
    )

    return format_authorization(credential)


async def build_charge_transaction(
    signer: Any,
    rpc_client: Any,
    amount: str,
    currency: str,
    recipient: str,
    method_details: MethodDetails | None = None,
    external_id: str = "",
) -> CredentialPayload:
    """Build a Solana transaction for a charge intent.

    This creates the appropriate transfer instructions (SOL or SPL token),
    signs the transaction, and returns a credential payload.

    Args:
        signer: A Solana keypair for signing.
        rpc_client: An async Solana RPC client.
        amount: Amount in base units.
        currency: Currency symbol or mint address.
        recipient: Recipient public key (base58).
        external_id: Optional root payment memo requested by the server.
        method_details: Optional Solana-specific method details.

    Returns:
        A CredentialPayload with the signed transaction.
    """
    # Lazy imports so the module can be imported without solana/solders installed
    from solders.hash import Hash  # type: ignore[import-untyped]
    from solders.instruction import Instruction  # type: ignore[import-untyped]
    from solders.message import Message  # type: ignore[import-untyped]
    from solders.pubkey import Pubkey  # type: ignore[import-untyped]
    from solders.system_program import TransferParams, transfer  # type: ignore[import-untyped]
    from solders.transaction import Transaction  # type: ignore[import-untyped]

    details = method_details or MethodDetails()
    amount_int = int(amount)
    split_total = sum(int(split.amount) for split in details.splits)
    primary_amount = amount_int - split_total
    if primary_amount <= 0:
        raise ValueError("splits consume the entire amount")
    recipient_key = Pubkey.from_string(recipient)

    instructions = []
    memo_program = Pubkey.from_string(MEMO_PROGRAM)

    def append_memo(memo: str) -> None:
        if not memo:
            return
        data = memo.encode("utf-8")
        if len(data) > 566:
            raise ValueError("memo cannot exceed 566 bytes")
        instructions.append(Instruction(memo_program, data, []))

    if is_native_sol(currency):
        # SOL transfer
        ix = transfer(
            TransferParams(
                from_pubkey=signer.pubkey(),
                to_pubkey=recipient_key,
                lamports=primary_amount,
            )
        )
        instructions.append(ix)
        append_memo(external_id)

        # Add split transfers
        for split in details.splits:
            split_key = Pubkey.from_string(split.recipient)
            split_amount = int(split.amount)
            split_ix = transfer(
                TransferParams(
                    from_pubkey=signer.pubkey(),
                    to_pubkey=split_key,
                    lamports=split_amount,
                )
            )
            instructions.append(split_ix)
            append_memo(split.memo)
    else:
        # SPL token transfer -- requires more complex instruction building
        # This is a simplified version; full implementation would handle
        # ATA creation, TransferChecked, etc.
        logger.warning("SPL token transfers require full solana-py integration")
        raise NotImplementedError("SPL token client transfers not yet implemented")

    # Get recent blockhash
    if details.recent_blockhash:
        blockhash = Hash.from_string(details.recent_blockhash)
    else:
        resp = await rpc_client.get_latest_blockhash()
        blockhash = resp.value.blockhash

    # Build and sign transaction
    msg = Message.new_with_blockhash(instructions, signer.pubkey(), blockhash)
    tx = Transaction.new_unsigned(msg)
    tx.sign([signer], blockhash)

    # Encode transaction
    import base64 as b64

    tx_bytes = bytes(tx)
    tx_b64 = b64.b64encode(tx_bytes).decode("ascii")

    return CredentialPayload(type="transaction", transaction=tx_b64)
