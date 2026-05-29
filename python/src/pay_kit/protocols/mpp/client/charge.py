"""Client-side transaction building for charge intent."""

from __future__ import annotations

from typing import Any

from pay_kit._paycore.mints import derive_ata
from pay_kit._paycore.solana import (
    ASSOCIATED_TOKEN_PROGRAM,
    MEMO_PROGRAM,
    SYSTEM_PROGRAM,
    CredentialPayload,
    MethodDetails,
    default_token_program_for_currency,
    is_native_sol,
    resolve_mint,
)
from pay_kit.protocols.mpp.core.base64url import decode_json
from pay_kit.protocols.mpp.core.headers import format_authorization
from pay_kit.protocols.mpp.core.types import PaymentChallenge, PaymentCredential
from pay_kit.protocols.mpp.intents.charge import ChargeRequest


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
        # SPL token transfer: one TransferChecked per recipient to their ATA,
        # mirroring the Go client and what the server verifier expects. Decimals
        # come from the challenge methodDetails (stablecoins are 6). An
        # idempotent create-ATA is prepended only for splits that flag it.
        from solders.instruction import AccountMeta

        mint = resolve_mint(currency, details.network)
        token_program = details.token_program or default_token_program_for_currency(currency, details.network)
        decimals = details.decimals if details.decimals is not None else 6
        token_program_key = Pubkey.from_string(token_program)
        mint_key = Pubkey.from_string(mint)
        system_program_key = Pubkey.from_string(SYSTEM_PROGRAM)
        ata_program_key = Pubkey.from_string(ASSOCIATED_TOKEN_PROGRAM)
        source_ata = Pubkey.from_string(derive_ata(str(signer.pubkey()), mint, token_program))

        def append_transfer_checked(owner: Any, transfer_amount: int, create_ata: bool, memo: str) -> None:
            dest_ata = Pubkey.from_string(derive_ata(str(owner), mint, token_program))
            if create_ata:
                # Associated Token Account program CreateIdempotent (discriminator 1):
                # the payer funds the recipient's ATA when it does not yet exist.
                instructions.append(
                    Instruction(
                        ata_program_key,
                        bytes([1]),
                        [
                            AccountMeta(signer.pubkey(), True, True),
                            AccountMeta(dest_ata, False, True),
                            AccountMeta(owner, False, False),
                            AccountMeta(mint_key, False, False),
                            AccountMeta(system_program_key, False, False),
                            AccountMeta(token_program_key, False, False),
                        ],
                    )
                )
            # SPL Token TransferChecked (discriminator 12): amount u64 LE + decimals u8.
            data = bytes([12]) + transfer_amount.to_bytes(8, "little") + bytes([decimals])
            instructions.append(
                Instruction(
                    token_program_key,
                    data,
                    [
                        AccountMeta(source_ata, False, True),
                        AccountMeta(mint_key, False, False),
                        AccountMeta(dest_ata, False, True),
                        AccountMeta(signer.pubkey(), True, False),
                    ],
                )
            )
            append_memo(memo)

        append_transfer_checked(recipient_key, primary_amount, False, external_id)
        for split in details.splits:
            append_transfer_checked(
                Pubkey.from_string(split.recipient),
                int(split.amount),
                split.ata_creation_required,
                split.memo,
            )

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
