"""Client-side transaction building for charge intent."""

from __future__ import annotations

from typing import Any

from pay_kit._paycore.mints import derive_ata
from pay_kit._paycore.solana import (
    ASSOCIATED_TOKEN_PROGRAM,
    COMPUTE_BUDGET_PROGRAM,
    MEMO_PROGRAM,
    SYSTEM_PROGRAM,
    TOKEN_2022_PROGRAM,
    TOKEN_PROGRAM,
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
    compute_unit_limit: int | None = None,
    compute_unit_price: int | None = None,
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
        compute_unit_limit: Optional override for the SetComputeUnitLimit
            prelude (defaults to 200_000), mirroring the Go ``BuildOptions``
            and the TS ``buildChargeTransaction`` compute overrides.
        compute_unit_price: Optional override for the SetComputeUnitPrice
            prelude (defaults to 1 micro-lamport).

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
    # Cap split count, matching rust ``if splits.len() > 8`` (charge.rs:76-78);
    # the server enforces MAX_SPLITS=8 too, but the client must fail fast.
    if len(details.splits) > 8:
        raise ValueError("too many splits: maximum is 8")
    split_total = sum(int(split.amount) for split in details.splits)
    primary_amount = amount_int - split_total
    if primary_amount <= 0:
        raise ValueError("splits consume the entire amount")
    recipient_key = Pubkey.from_string(recipient)

    # Fee-payer toggle mirrors rust (charge.rs:96-104): a sponsored route uses
    # the server fee payer as the message fee payer (account[0]); the client
    # signs only its own signature slot and the server cosigns slot 0.
    use_fee_payer = details.fee_payer and bool(details.fee_payer_key)
    fee_payer_key = Pubkey.from_string(details.fee_payer_key) if use_fee_payer else None

    instructions = []
    memo_program = Pubkey.from_string(MEMO_PROGRAM)

    # ComputeBudget prelude, matching rust charge.rs:108-110: SetComputeUnitPrice(1)
    # (program ComputeBudget111..., disc 3, u64 LE) THEN SetComputeUnitLimit(200_000)
    # (disc 2, u32 LE), both with zero accounts. Restores byte-level instruction
    # order parity with the rust/cross-impl clients for an identical challenge.
    # The price / limit are overridable so a caller can build a transaction
    # carrying values the server cap rejects (parity with the Go BuildOptions
    # and the TS compute overrides).
    price = compute_unit_price if compute_unit_price is not None else 1
    limit = compute_unit_limit if compute_unit_limit is not None else 200_000
    compute_budget_program = Pubkey.from_string(COMPUTE_BUDGET_PROGRAM)
    instructions.append(
        Instruction(compute_budget_program, bytes([3]) + price.to_bytes(8, "little"), [])
    )
    instructions.append(
        Instruction(compute_budget_program, bytes([2]) + limit.to_bytes(4, "little"), [])
    )

    def append_memo(memo: str) -> None:
        if not memo:
            return
        data = memo.encode("utf-8")
        if len(data) > 566:
            raise ValueError("memo cannot exceed 566 bytes")
        instructions.append(Instruction(memo_program, data, []))

    # ataCreationRequired gate, matching rust charge.rs:113-128: any split that
    # flags ata_creation_required requires the charge currency to be an SPL token
    # mint address (not native SOL and not a symbol). resolve_mint returns "" for
    # SOL and the raw mint for an SPL mint address; for a known symbol it returns
    # a mint that differs from the symbol input, which we reject here.
    if any(split.ata_creation_required for split in details.splits):
        resolved = resolve_mint(currency, details.network)
        if is_native_sol(currency) or not resolved:
            raise ValueError("ataCreationRequired requires an SPL token charge")
        if resolved != currency:
            raise ValueError(
                "ataCreationRequired requires currency to be an SPL token mint address"
            )

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
        token_program = await _resolve_token_program(rpc_client, mint, details)
        decimals = details.decimals if details.decimals is not None else 6
        token_program_key = Pubkey.from_string(token_program)
        mint_key = Pubkey.from_string(mint)
        system_program_key = Pubkey.from_string(SYSTEM_PROGRAM)
        ata_program_key = Pubkey.from_string(ASSOCIATED_TOKEN_PROGRAM)
        source_ata = Pubkey.from_string(derive_ata(str(signer.pubkey()), mint, token_program))
        # The create-ATA payer is the fee payer when sponsored, else the signer,
        # matching rust ``let payer = fee_payer.copied().unwrap_or(*signer)``
        # (charge.rs:368).
        ata_payer = fee_payer_key if fee_payer_key is not None else signer.pubkey()

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
                            AccountMeta(ata_payer, True, True),
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

    # Build and sign transaction. The message fee payer (account[0]) is the
    # server fee payer when sponsored, else the signer, matching rust
    # ``actual_fee_payer = fee_payer_pubkey.unwrap_or(signer_pubkey)``
    # (charge.rs:162-163). The client signs ONLY its own slot via partial_sign;
    # when sponsored the server cosigns the fee-payer slot at account[0].
    actual_fee_payer = fee_payer_key if fee_payer_key is not None else signer.pubkey()
    msg = Message.new_with_blockhash(instructions, actual_fee_payer, blockhash)
    tx = Transaction.new_unsigned(msg)
    tx.partial_sign([signer], blockhash)

    # Encode transaction
    import base64 as b64

    tx_bytes = bytes(tx)
    tx_b64 = b64.b64encode(tx_bytes).decode("ascii")

    return CredentialPayload(type="transaction", transaction=tx_b64)


async def _resolve_token_program(rpc_client: Any, mint: str, details: MethodDetails) -> str:
    """Resolve the SPL token program for ``mint``, matching rust resolve_token_program.

    Mirrors rust ``resolve_token_program`` (charge.rs:442-466): use
    ``methodDetails.tokenProgram`` when present; otherwise fetch the mint
    account owner via RPC; then reject any program that is not the classic SPL
    Token program or Token-2022. Without this, an unknown mint that omits
    ``tokenProgram`` silently defaults to the classic program where rust
    consults the chain, building the wrong program id / ATA derivation.
    """
    if details.token_program:
        token_program = details.token_program
    else:
        owner = await _fetch_mint_owner(rpc_client, mint)
        token_program = owner if owner is not None else default_token_program_for_currency(
            mint, details.network
        )
    if token_program not in (TOKEN_PROGRAM, TOKEN_2022_PROGRAM):
        raise ValueError(f"Unsupported token program: {token_program}")
    return token_program


async def _fetch_mint_owner(rpc_client: Any, mint: str) -> str | None:
    """Return the on-chain owner program of ``mint`` via RPC, or None when unavailable.

    Mirrors the rust ``rpc.get_account(mint).owner`` lookup. Tolerates an absent
    or stubbed RPC client (offline tests pass ``None``) by returning None so the
    caller falls back to the symbol-derived default.
    """
    if rpc_client is None:
        return None
    from solders.pubkey import Pubkey

    resp = await rpc_client.get_account(Pubkey.from_string(mint))
    value = getattr(resp, "value", resp)
    if value is None:
        return None
    owner = getattr(value, "owner", None)
    return str(owner) if owner is not None else None
