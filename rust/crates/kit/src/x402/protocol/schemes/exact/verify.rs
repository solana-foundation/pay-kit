use std::str::FromStr;

use solana_message::compiled_instruction::CompiledInstruction;
use solana_pubkey::Pubkey;
use solana_rpc_client::rpc_client::RpcClient;
use solana_signature::Signature;
use solana_transaction::versioned::VersionedTransaction;
use solana_transaction_status_client_types::{
    EncodedConfirmedTransactionWithStatusMeta, EncodedTransaction, UiInstruction, UiMessage,
    UiParsedInstruction,
};

use super::{programs, resolve_stablecoin_mint, PaymentRequirements};
use crate::x402::error::Error;

const MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS: u64 = 5_000_000;

/// Highest compute-unit limit a sponsored fee payer co-signs.
const MAX_COMPUTE_UNIT_LIMIT: u32 = 200_000;

/// Verify a confirmed transaction matches the expected payment requirements.
///
/// Looks at the on-chain transaction returned for a signature-mode credential
/// and confirms it actually contains a `transferChecked` of the expected
/// amount, mint, and destination ATA. Earlier versions of this function were
/// a stub and accepted any successful Solana signature — that meant any
/// confirmed transaction satisfied any route.
pub fn verify_transaction_details(
    tx: &EncodedConfirmedTransactionWithStatusMeta,
    requirements: &PaymentRequirements,
) -> Result<(), Error> {
    // Check for on-chain error.
    if let Some(meta) = &tx.transaction.meta {
        if meta.err.is_some() {
            return Err(Error::TransactionFailed(format!("{:?}", meta.err)));
        }
    }

    let expected_amount: u64 = requirements
        .amount
        .parse()
        .map_err(|_| Error::Other(format!("Invalid amount: {}", requirements.amount)))?;

    verify_on_chain_transfer(tx, requirements, expected_amount)?;

    if let Some(expected_memo) = expected_memo(requirements) {
        let memo_instructions = transaction_memos(tx)?;
        if memo_instructions.len() != 1 {
            return invalid("invalid_exact_svm_payload_memo_count");
        }
        if memo_instructions[0] != expected_memo {
            return invalid("invalid_exact_svm_payload_memo_mismatch");
        }
    }

    Ok(())
}

/// Reject a confirmed payment older than the requirement's advertised
/// validity window (`maxTimeoutSeconds`). A transaction without a block time
/// cannot be shown to be fresh.
pub(crate) fn verify_transaction_age(
    tx: &EncodedConfirmedTransactionWithStatusMeta,
    requirements: &PaymentRequirements,
    now_unix: i64,
) -> Result<(), Error> {
    let max_age = requirements
        .max_age
        .unwrap_or(super::DEFAULT_MAX_TIMEOUT_SECONDS);
    let block_time = tx
        .block_time
        .ok_or_else(|| Error::Other("invalid_exact_svm_payload_missing_block_time".into()))?;
    let age = now_unix.saturating_sub(block_time);
    if age > i64::try_from(max_age).unwrap_or(i64::MAX) {
        return Err(Error::Other(format!(
            "invalid_exact_svm_payload_expired: confirmed {age}s ago, accepted for {max_age}s"
        )));
    }
    Ok(())
}

/// Find a `transferChecked` instruction matching the route's requirements in
/// the encoded transaction's instruction list.
///
/// Handles both `JsonParsed` (returned by RPC under
/// `UiTransactionEncoding::JsonParsed` for the SPL-token program) and `Raw`
/// (compiled bytes). Returns `Ok(())` on first match, error if none.
fn verify_on_chain_transfer(
    tx: &EncodedConfirmedTransactionWithStatusMeta,
    requirements: &PaymentRequirements,
    expected_amount: u64,
) -> Result<(), Error> {
    let expected_mint = resolve_expected_mint(requirements);
    let expected_recipient = Pubkey::from_str(&requirements.recipient)
        .map_err(|e| Error::Other(format!("Invalid recipient: {e}")))?;
    let expected_mint_pubkey =
        Pubkey::from_str(&expected_mint).map_err(|e| Error::Other(format!("Invalid mint: {e}")))?;
    let token_program_str = requirements
        .token_program
        .clone()
        .unwrap_or_else(|| programs::TOKEN_PROGRAM.to_string());
    let token_program = Pubkey::from_str(&token_program_str)
        .map_err(|e| Error::Other(format!("Invalid token program: {e}")))?;
    let expected_destination =
        get_associated_token_address(&expected_recipient, &expected_mint_pubkey, &token_program)
            .to_string();
    let expected_decimals = expected_decimals(requirements)?;

    let ui_tx = match &tx.transaction.transaction {
        EncodedTransaction::Json(ui_tx) => ui_tx,
        _ => return invalid("invalid_exact_svm_payload_no_transfer_instruction"),
    };

    // Scheme §1.4: across top-level instructions and the CPI trace, exactly
    // one transferChecked matches (mint, destination ATA, amount >= required).
    let raw_keys: Option<&[String]> = match &ui_tx.message {
        UiMessage::Raw(message) => Some(&message.account_keys),
        UiMessage::Parsed(_) => None,
    };
    let matches = |instruction: &UiInstruction| match instruction {
        UiInstruction::Compiled(compiled) => raw_keys.is_some_and(|keys| {
            matches_raw_transfer(
                compiled,
                keys,
                &expected_destination,
                &expected_mint,
                expected_amount,
                expected_decimals,
            )
        }),
        parsed => matches_parsed_transfer(
            parsed,
            &expected_destination,
            &expected_mint,
            expected_amount,
            expected_decimals,
        ),
    };
    let top_level: Vec<UiInstruction> = match &ui_tx.message {
        UiMessage::Parsed(message) => message.instructions.clone(),
        UiMessage::Raw(message) => message
            .instructions
            .iter()
            .cloned()
            .map(UiInstruction::Compiled)
            .collect(),
    };
    let inner: Vec<UiInstruction> = tx
        .transaction
        .meta
        .as_ref()
        .and_then(|meta| Option::<&Vec<_>>::from(meta.inner_instructions.as_ref()))
        .map(|sets| {
            sets.iter()
                .flat_map(|set| set.instructions.iter().cloned())
                .collect()
        })
        .unwrap_or_default();
    let count = top_level
        .iter()
        .chain(inner.iter())
        .filter(|ix| matches(ix))
        .count();

    match count {
        1 => Ok(()),
        0 => invalid("invalid_exact_svm_payload_no_transfer_instruction"),
        _ => invalid("invalid_exact_svm_payload_multiple_matching_transfers"),
    }
}

fn matches_parsed_transfer(
    instruction: &UiInstruction,
    expected_destination: &str,
    expected_mint: &str,
    expected_amount: u64,
    expected_decimals: u8,
) -> bool {
    let parsed = match instruction {
        UiInstruction::Parsed(UiParsedInstruction::Parsed(parsed)) => parsed,
        _ => return false,
    };
    if parsed.program_id != programs::TOKEN_PROGRAM
        && parsed.program_id != programs::TOKEN_2022_PROGRAM
    {
        return false;
    }
    let parsed_obj = match parsed.parsed.as_object() {
        Some(obj) => obj,
        None => return false,
    };
    if parsed_obj.get("type").and_then(|v| v.as_str()) != Some("transferChecked") {
        return false;
    }
    let info = match parsed_obj.get("info").and_then(|v| v.as_object()) {
        Some(info) => info,
        None => return false,
    };
    let destination = info
        .get("destination")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let mint = info.get("mint").and_then(|v| v.as_str()).unwrap_or("");
    let token_amount = info.get("tokenAmount").and_then(|v| v.as_object());
    let amount = token_amount
        .and_then(|o| o.get("amount"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let decimals = token_amount
        .and_then(|o| o.get("decimals"))
        .and_then(|v| v.as_u64());
    destination == expected_destination
        && mint == expected_mint
        && amount
            .parse::<u64>()
            .is_ok_and(|amount| amount >= expected_amount)
        && decimals == Some(u64::from(expected_decimals))
}

fn matches_raw_transfer(
    instruction: &solana_transaction_status_client_types::UiCompiledInstruction,
    account_keys: &[String],
    expected_destination: &str,
    expected_mint: &str,
    expected_amount: u64,
    expected_decimals: u8,
) -> bool {
    let program = match account_keys.get(instruction.program_id_index as usize) {
        Some(s) => s.as_str(),
        None => return false,
    };
    if program != programs::TOKEN_PROGRAM && program != programs::TOKEN_2022_PROGRAM {
        return false;
    }
    let bytes = match bs58::decode(&instruction.data).into_vec() {
        Ok(b) => b,
        Err(_) => return false,
    };
    // transferChecked: discriminator 12, then 8-byte u64 amount, then 1-byte decimals.
    if bytes.len() != 10 || bytes[0] != 12 {
        return false;
    }
    let amount_bytes: [u8; 8] = match bytes[1..9].try_into() {
        Ok(b) => b,
        Err(_) => return false,
    };
    if u64::from_le_bytes(amount_bytes) < expected_amount || bytes[9] != expected_decimals {
        return false;
    }
    if instruction.accounts.len() < 4 {
        return false;
    }
    let mint = match account_keys.get(instruction.accounts[1] as usize) {
        Some(s) => s.as_str(),
        None => return false,
    };
    let destination = match account_keys.get(instruction.accounts[2] as usize) {
        Some(s) => s.as_str(),
        None => return false,
    };
    mint == expected_mint && destination == expected_destination
}

/// Verify a signed `exact` transaction against Rust payment requirements.
///
/// This mirrors the canonical TypeScript facilitator's transaction-shape checks.
pub fn verify_exact_transaction(
    tx: &VersionedTransaction,
    requirements: &PaymentRequirements,
    managed_signers: &[Pubkey],
) -> Result<(), Error> {
    verify_exact_versioned_transaction(tx, requirements, managed_signers)
}

/// Verify a signed versioned `exact` transaction against payment requirements.
pub fn verify_exact_versioned_transaction(
    tx: &VersionedTransaction,
    requirements: &PaymentRequirements,
    managed_signers: &[Pubkey],
) -> Result<(), Error> {
    let version = crate::core::tx::TxVersion::of(&tx.message)
        .map_err(|e| Error::Other(format!("invalid_exact_svm_payload_transaction: {e}")))?;
    // Version 1 carries its compute budget in the header, so the static layout
    // has no ComputeBudget prefix; the price cap is applied to the header.
    let budgeted = version == crate::core::tx::TxVersion::V1;
    if budgeted {
        let declared = crate::core::tx::DeclaredBudget::of(&tx.message)
            .map_err(|e| Error::Other(format!("invalid_exact_svm_payload_transaction: {e}")))?;
        if declared
            .unit_limit
            .is_some_and(|limit| limit > MAX_COMPUTE_UNIT_LIMIT)
        {
            return invalid(
                "invalid_exact_svm_payload_transaction_instructions_compute_limit_instruction_too_high",
            );
        }
        if declared
            .unit_price_micro_lamports
            .is_some_and(|price| price > MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS)
        {
            return invalid(
                "invalid_exact_svm_payload_transaction_instructions_compute_price_instruction_too_high",
            );
        }
        // The limit and price caps are checked above with their own reasons;
        // what is left (a zero unit limit, a missing or short
        // loadedAccountsDataSizeLimit) is a malformed version-1 header.
        crate::core::tx::check_v1_budget_caps(
            &tx.message,
            MAX_COMPUTE_UNIT_LIMIT,
            MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS,
        )
        .map_err(|e| Error::Other(format!("invalid_exact_svm_payload_transaction: {e}")))?;
    }
    verify_exact_instructions(
        tx.message.static_account_keys(),
        tx.message.instructions(),
        requirements,
        managed_signers,
        budgeted,
    )?;
    // The facilitator is the fee payer, so it pays whatever priority fee the
    // client's limit and price add up to: bound the product, not each factor.
    crate::core::tx::check_priority_fee(
        &tx.message,
        crate::core::tx::MAX_SPONSORED_PRIORITY_FEE_LAMPORTS,
    )
    .map_err(|_| {
        Error::Other(
            "invalid_exact_svm_payload_transaction_instructions_compute_price_instruction_too_high"
                .into(),
        )
    })?;
    verify_required_signers(&tx.message, budgeted)
}

/// Only the fee payer and the transfer authority may sign: every extra
/// required signature is a base fee the sponsor pays.
fn verify_required_signers(
    message: &solana_message::VersionedMessage,
    header_budget: bool,
) -> Result<(), Error> {
    let keys = message.static_account_keys();
    let prefix = if header_budget { 0 } else { 2 };
    let authority = message
        .instructions()
        .get(prefix)
        .and_then(|transfer| transfer.accounts.get(3))
        .and_then(|index| keys.get(*index as usize))
        .ok_or_else(|| Error::Other("invalid_exact_svm_payload_no_transfer_instruction".into()))?;
    let fee_payer = keys
        .first()
        .ok_or_else(|| Error::Other("invalid_exact_svm_payload_transaction".into()))?;
    let required = message.header().num_required_signatures as usize;
    let signers = keys
        .get(..required)
        .ok_or_else(|| Error::Other("invalid_exact_svm_payload_transaction".into()))?;
    if signers
        .iter()
        .any(|signer| signer != fee_payer && signer != authority)
    {
        return invalid("invalid_exact_svm_payload_transaction_unexpected_signer");
    }
    Ok(())
}

fn verify_exact_instructions(
    account_keys: &[Pubkey],
    instructions: &[CompiledInstruction],
    requirements: &PaymentRequirements,
    managed_signers: &[Pubkey],
    header_budget: bool,
) -> Result<(), Error> {
    // Version 0: [limit, price, transfer, ≤4 optional] (scheme §3.1: 3 to 7
    // instructions). Version 1: the budget is in the header, so [transfer,
    // ≤4 optional].
    let prefix = if header_budget { 0 } else { 2 };
    if !(prefix + 1..=prefix + 5).contains(&instructions.len()) {
        return invalid("invalid_exact_svm_payload_transaction_instructions_length");
    }

    if !header_budget {
        verify_compute_limit_instruction(
            instructions.first().ok_or_else(|| {
                Error::Other("invalid_exact_svm_payload_transaction_instructions_length".into())
            })?,
            account_keys,
        )?;
        verify_compute_price_instruction(
            instructions.get(1).ok_or_else(|| {
                Error::Other("invalid_exact_svm_payload_transaction_instructions_length".into())
            })?,
            account_keys,
        )?;
    }

    let transfer_ix = instructions.get(prefix).ok_or_else(|| {
        Error::Other("invalid_exact_svm_payload_transaction_instructions_length".into())
    })?;
    verify_transfer_instruction(transfer_ix, account_keys, requirements, managed_signers)?;
    verify_fee_payer_isolation(instructions, account_keys, managed_signers)?;

    let invalid_reason_by_index = [
        "invalid_exact_svm_payload_unknown_fourth_instruction",
        "invalid_exact_svm_payload_unknown_fifth_instruction",
        "invalid_exact_svm_payload_unknown_sixth_instruction",
        "invalid_exact_svm_payload_unknown_seventh_instruction",
    ];

    for (index, instruction) in instructions.iter().skip(prefix + 1).enumerate() {
        let program = program_id_for_instruction(instruction, account_keys)?;
        let program = program.to_string();
        // Optional slots 4-6 take Lighthouse or Memo; slot 7 takes Memo only.
        if program == programs::MEMO_PROGRAM
            || (index < 3 && program == programs::LIGHTHOUSE_PROGRAM)
        {
            continue;
        }
        return invalid(
            invalid_reason_by_index
                .get(index)
                .copied()
                .unwrap_or("invalid_exact_svm_payload_unknown_optional_instruction"),
        );
    }

    if let Some(expected_memo) = expected_memo(requirements) {
        let memo_instructions: Vec<_> = instructions
            .iter()
            .skip(prefix + 1)
            .filter(|instruction| {
                program_id_for_instruction(instruction, account_keys)
                    .map(|program| program.to_string() == programs::MEMO_PROGRAM)
                    .unwrap_or(false)
            })
            .collect();

        if memo_instructions.len() != 1 {
            return invalid("invalid_exact_svm_payload_memo_count");
        }

        let actual_memo = std::str::from_utf8(&memo_instructions[0].data)
            .map_err(|_| Error::Other("invalid_exact_svm_payload_memo_mismatch".to_string()))?;
        if actual_memo != expected_memo {
            return invalid("invalid_exact_svm_payload_memo_mismatch");
        }
    }

    Ok(())
}

/// Scheme §2.1.1: the sponsor's key MUST NOT appear in any instruction's
/// accounts and MUST NOT be invoked as a program. Receiving as `payTo` is
/// unaffected: the transfer names the payee's ATA, never the payee.
fn verify_fee_payer_isolation(
    instructions: &[CompiledInstruction],
    account_keys: &[Pubkey],
    managed_signers: &[Pubkey],
) -> Result<(), Error> {
    if managed_signers.is_empty() {
        return Ok(());
    }
    let is_managed = |index: u8| {
        account_keys
            .get(index as usize)
            .is_some_and(|key| managed_signers.contains(key))
    };
    for instruction in instructions {
        if is_managed(instruction.program_id_index)
            || instruction.accounts.iter().any(|a| is_managed(*a))
        {
            return invalid(
                "invalid_exact_svm_payload_transaction_fee_payer_included_in_instruction_accounts",
            );
        }
    }
    Ok(())
}

/// Fetch a confirmed transaction from an RPC endpoint.
pub fn fetch_transaction(
    rpc: &RpcClient,
    signature_str: &str,
) -> Result<EncodedConfirmedTransactionWithStatusMeta, Error> {
    let signature = Signature::from_str(signature_str)
        .map_err(|e| Error::Other(format!("Invalid signature: {e}")))?;

    rpc.get_transaction_with_config(&signature, crate::core::rpc::parsed_transaction_config())
        .map_err(|e| {
            if e.to_string().contains("not found") {
                Error::TransactionNotFound
            } else {
                Error::Rpc(e.to_string())
            }
        })
}

fn verify_compute_limit_instruction(
    instruction: &CompiledInstruction,
    account_keys: &[Pubkey],
) -> Result<(), Error> {
    let program = program_id_for_instruction(instruction, account_keys)?;
    if program.to_string() != programs::COMPUTE_BUDGET_PROGRAM
        || instruction.data.len() != 5
        || instruction.data.first().copied() != Some(2)
    {
        return invalid(
            "invalid_exact_svm_payload_transaction_instructions_compute_limit_instruction",
        );
    }
    let units = u32::from_le_bytes(instruction.data[1..5].try_into().map_err(|_| {
        Error::Other(
            "invalid_exact_svm_payload_transaction_instructions_compute_limit_instruction".into(),
        )
    })?);
    if units > MAX_COMPUTE_UNIT_LIMIT {
        return invalid(
            "invalid_exact_svm_payload_transaction_instructions_compute_limit_instruction_too_high",
        );
    }
    Ok(())
}

fn verify_compute_price_instruction(
    instruction: &CompiledInstruction,
    account_keys: &[Pubkey],
) -> Result<(), Error> {
    let program = program_id_for_instruction(instruction, account_keys)?;
    if program.to_string() != programs::COMPUTE_BUDGET_PROGRAM
        || instruction.data.len() != 9
        || instruction.data.first().copied() != Some(3)
    {
        return invalid(
            "invalid_exact_svm_payload_transaction_instructions_compute_price_instruction",
        );
    }

    let micro_lamports = u64::from_le_bytes(instruction.data[1..9].try_into().map_err(|_| {
        Error::Other(
            "invalid_exact_svm_payload_transaction_instructions_compute_price_instruction".into(),
        )
    })?);

    if micro_lamports > MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS {
        return invalid(
            "invalid_exact_svm_payload_transaction_instructions_compute_price_instruction_too_high",
        );
    }

    Ok(())
}

fn verify_transfer_instruction(
    instruction: &CompiledInstruction,
    account_keys: &[Pubkey],
    requirements: &PaymentRequirements,
    managed_signers: &[Pubkey],
) -> Result<(), Error> {
    let program = program_id_for_instruction(instruction, account_keys)?;
    let program_str = program.to_string();
    if program_str != programs::TOKEN_PROGRAM && program_str != programs::TOKEN_2022_PROGRAM {
        return invalid("invalid_exact_svm_payload_no_transfer_instruction");
    }

    if instruction.accounts.len() < 4 || instruction.data.len() != 10 || instruction.data[0] != 12 {
        return invalid("invalid_exact_svm_payload_no_transfer_instruction");
    }

    let mint = key_for_account_index(instruction.accounts[1], account_keys)?;
    let destination = key_for_account_index(instruction.accounts[2], account_keys)?;
    let authority = key_for_account_index(instruction.accounts[3], account_keys)?;

    if managed_signers.iter().any(|managed| managed == authority) {
        return invalid("invalid_exact_svm_payload_transaction_fee_payer_transferring_funds");
    }

    let expected_mint = resolve_expected_mint(requirements);
    if mint.to_string() != expected_mint {
        return invalid("invalid_exact_svm_payload_mint_mismatch");
    }

    let expected_destination = get_associated_token_address(
        &Pubkey::from_str(&requirements.pay_to_recipient()?)
            .map_err(|e| Error::Other(format!("Invalid recipient: {e}")))?,
        &Pubkey::from_str(&expected_mint)
            .map_err(|e| Error::Other(format!("Invalid mint: {e}")))?,
        program,
    );
    if destination != &expected_destination {
        return invalid("invalid_exact_svm_payload_recipient_mismatch");
    }

    let amount = u64::from_le_bytes(
        instruction.data[1..9]
            .try_into()
            .map_err(|_| Error::Other("invalid_exact_svm_payload_amount_mismatch".into()))?,
    );
    let expected_amount: u64 = requirements
        .amount
        .parse()
        .map_err(|_| Error::Other(format!("Invalid amount: {}", requirements.amount)))?;
    // Scheme §1.4: a matching transfer MAY exceed the amount; it MUST NOT be less.
    if amount < expected_amount {
        return invalid("invalid_exact_svm_payload_amount_mismatch");
    }
    // `transferChecked` fails unless this equals the mint's decimals, so it
    // proves the advertised precision.
    if instruction.data[9] != expected_decimals(requirements)? {
        return invalid("invalid_exact_svm_payload_decimals_mismatch");
    }

    Ok(())
}

/// The precision the route priced the transfer at; SPL payments require it.
fn expected_decimals(requirements: &PaymentRequirements) -> Result<u8, Error> {
    requirements
        .decimals
        .ok_or_else(|| Error::Other("invalid_exact_svm_payload_decimals_missing".into()))
}

fn key_for_account_index(index: u8, account_keys: &[Pubkey]) -> Result<&Pubkey, Error> {
    account_keys
        .get(index as usize)
        .ok_or_else(|| Error::Other("invalid_exact_svm_payload_no_transfer_instruction".into()))
}

fn program_id_for_instruction<'a>(
    instruction: &CompiledInstruction,
    account_keys: &'a [Pubkey],
) -> Result<&'a Pubkey, Error> {
    account_keys
        .get(instruction.program_id_index as usize)
        .ok_or_else(|| Error::Other("invalid_exact_svm_payload_no_transfer_instruction".into()))
}

fn get_associated_token_address(owner: &Pubkey, mint: &Pubkey, token_program: &Pubkey) -> Pubkey {
    let ata_program = Pubkey::from_str(programs::ASSOCIATED_TOKEN_PROGRAM).unwrap();
    let seeds = &[owner.as_ref(), token_program.as_ref(), mint.as_ref()];
    Pubkey::find_program_address(seeds, &ata_program).0
}

fn resolve_expected_mint(requirements: &PaymentRequirements) -> String {
    resolve_stablecoin_mint(&requirements.currency, requirements.cluster.as_deref())
        .unwrap_or(&requirements.currency)
        .to_string()
}

fn transaction_memos(tx: &EncodedConfirmedTransactionWithStatusMeta) -> Result<Vec<String>, Error> {
    let EncodedTransaction::Json(ui_tx) = &tx.transaction.transaction else {
        return Ok(Vec::new());
    };

    match &ui_tx.message {
        UiMessage::Parsed(message) => {
            let account_keys = message
                .account_keys
                .iter()
                .map(|account| account.pubkey.clone())
                .collect::<Vec<_>>();
            message
                .instructions
                .iter()
                .filter_map(|instruction| {
                    memo_text_from_ui_instruction(instruction, Some(&account_keys))
                })
                .collect()
        }
        UiMessage::Raw(message) => message
            .instructions
            .iter()
            .filter_map(|instruction| {
                let program = message
                    .account_keys
                    .get(instruction.program_id_index as usize)
                    .map(String::as_str)?;
                if program != programs::MEMO_PROGRAM {
                    return None;
                }
                Some(decode_memo_data(&instruction.data))
            })
            .collect(),
    }
}

fn memo_text_from_ui_instruction(
    instruction: &UiInstruction,
    raw_account_keys: Option<&[String]>,
) -> Option<Result<String, Error>> {
    match instruction {
        UiInstruction::Parsed(UiParsedInstruction::Parsed(parsed)) => {
            if parsed.program_id != programs::MEMO_PROGRAM && parsed.program != "spl-memo" {
                return None;
            }
            Some(
                parsed_memo_text(&parsed.parsed).ok_or_else(|| {
                    Error::Other("invalid_exact_svm_payload_memo_mismatch".to_string())
                }),
            )
        }
        UiInstruction::Parsed(UiParsedInstruction::PartiallyDecoded(decoded)) => {
            if decoded.program_id != programs::MEMO_PROGRAM {
                return None;
            }
            Some(decode_memo_data(&decoded.data))
        }
        UiInstruction::Compiled(compiled) => {
            let account_keys = raw_account_keys?;
            let program = account_keys
                .get(compiled.program_id_index as usize)
                .map(String::as_str)?;
            if program != programs::MEMO_PROGRAM {
                return None;
            }
            Some(decode_memo_data(&compiled.data))
        }
    }
}

fn parsed_memo_text(parsed: &serde_json::Value) -> Option<String> {
    match parsed {
        serde_json::Value::String(memo) => Some(memo.clone()),
        serde_json::Value::Object(parsed) => parsed
            .get("info")
            .and_then(|info| info.as_object())
            .and_then(|info| {
                info.get("memo")
                    .or_else(|| info.get("data"))
                    .and_then(|value| value.as_str())
            })
            .map(str::to_string),
        _ => None,
    }
}

fn decode_memo_data(encoded: &str) -> Result<String, Error> {
    let bytes = bs58::decode(encoded)
        .into_vec()
        .map_err(|_| Error::Other("invalid_exact_svm_payload_memo_mismatch".to_string()))?;
    String::from_utf8(bytes)
        .map_err(|_| Error::Other("invalid_exact_svm_payload_memo_mismatch".to_string()))
}

fn expected_memo(requirements: &PaymentRequirements) -> Option<&str> {
    requirements
        .extra
        .as_ref()
        .and_then(|extra| extra.get("memo"))
        .and_then(|memo| memo.as_str())
}

fn invalid<T>(reason: &str) -> Result<T, Error> {
    Err(Error::Other(reason.to_string()))
}

trait RequirementsRecipientExt {
    fn pay_to_recipient(&self) -> Result<String, Error>;
}

impl RequirementsRecipientExt for PaymentRequirements {
    fn pay_to_recipient(&self) -> Result<String, Error> {
        Ok(self.recipient.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mutable access to a compiled instruction of a version-0 test fixture.
    fn ix_mut(
        tx: &mut VersionedTransaction,
        index: usize,
    ) -> &mut solana_message::compiled_instruction::CompiledInstruction {
        match &mut tx.message {
            solana_message::VersionedMessage::V0(message) => &mut message.instructions[index],
            _ => panic!("fixture is version 0"),
        }
    }
    use crate::x402::protocol::schemes::exact::{mints, SOLANA_DEVNET};
    use solana_hash::Hash;
    use solana_instruction::{AccountMeta, Instruction};
    use solana_message::{v0, MessageHeader, VersionedMessage};
    use solana_signature::Signature;
    use solana_transaction::versioned::VersionedTransaction;
    use solana_transaction::TransactionError;
    use solana_transaction_status_client_types::{
        option_serializer::OptionSerializer, EncodedTransaction, EncodedTransactionWithStatusMeta,
        UiMessage, UiRawMessage, UiTransaction, UiTransactionStatusMeta,
    };

    fn requirements(amount: &str) -> PaymentRequirements {
        PaymentRequirements {
            network: SOLANA_DEVNET.to_string(),
            cluster: Some("devnet".to_string()),
            recipient: Pubkey::new_unique().to_string(),
            amount: amount.to_string(),
            currency: "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU".to_string(),
            decimals: Some(6),
            token_program: Some(programs::TOKEN_PROGRAM.to_string()),
            resource: "/resource".to_string(),
            description: None,
            max_age: None,
            recent_blockhash: None,
            fee_payer: None,
            fee_payer_key: None,
            extra: None,
            accepted: None,
            resource_info: None,
            transaction_versions: None,
        }
    }

    fn tx_with_meta(err: Option<TransactionError>) -> EncodedConfirmedTransactionWithStatusMeta {
        EncodedConfirmedTransactionWithStatusMeta {
            slot: 1,
            transaction_index: None,
            transaction: EncodedTransactionWithStatusMeta {
                transaction: EncodedTransaction::Json(UiTransaction {
                    signatures: vec!["sig".to_string()],
                    message: UiMessage::Raw(UiRawMessage {
                        header: MessageHeader {
                            num_required_signatures: 1,
                            num_readonly_signed_accounts: 0,
                            num_readonly_unsigned_accounts: 1,
                        },
                        account_keys: vec![
                            "payer".to_string(),
                            "recipient".to_string(),
                            "11111111111111111111111111111111".to_string(),
                        ],
                        recent_blockhash: "blockhash".to_string(),
                        instructions: vec![],
                        address_table_lookups: None,
                        transaction_config: None,
                    }),
                }),
                meta: Some(UiTransactionStatusMeta {
                    err: err.clone().map(Into::into),
                    status: err.map_or(Ok(()), |e| Err(e.into())),
                    fee: 5000,
                    pre_balances: vec![10_000, 0, 0],
                    post_balances: vec![5_000, 5_000, 0],
                    inner_instructions: OptionSerializer::None,
                    log_messages: OptionSerializer::None,
                    pre_token_balances: OptionSerializer::None,
                    post_token_balances: OptionSerializer::None,
                    rewards: OptionSerializer::None,
                    loaded_addresses: OptionSerializer::Skip,
                    return_data: OptionSerializer::Skip,
                    compute_units_consumed: OptionSerializer::Skip,
                    cost_units: OptionSerializer::Skip,
                }),
                version: None,
            },
            block_time: None,
        }
    }

    /// Build an encoded transaction whose parsed instructions include a
    /// `transferChecked` matching the requirements plus optional memos.
    /// Mirrors the JsonParsed shape RPC returns when fetching a confirmed
    /// SPL-token transfer.
    fn tx_with_parsed_transfer_and_memos(
        requirements: &PaymentRequirements,
        memos: &[&str],
    ) -> EncodedConfirmedTransactionWithStatusMeta {
        let mut tx = tx_with_meta(None);
        let mint = Pubkey::from_str(&requirements.currency).unwrap();
        let recipient = Pubkey::from_str(&requirements.recipient).unwrap();
        let token_program =
            Pubkey::from_str(requirements.token_program.as_deref().unwrap()).unwrap();
        let destination = get_associated_token_address(&recipient, &mint, &token_program);

        let mut instructions = vec![serde_json::json!({
            "program": "spl-token",
            "programId": programs::TOKEN_PROGRAM,
            "parsed": {
                "type": "transferChecked",
                "info": {
                    "destination": destination.to_string(),
                    "mint": requirements.currency,
                    "tokenAmount": {
                        "amount": requirements.amount,
                        "decimals": requirements.decimals.unwrap_or(6),
                    },
                },
            },
            "stackHeight": null
        })];
        for memo in memos {
            instructions.push(serde_json::json!({
                "program": "spl-memo",
                "programId": programs::MEMO_PROGRAM,
                "parsed": memo,
                "stackHeight": null
            }));
        }
        tx.transaction.transaction = EncodedTransaction::Json(
            serde_json::from_value(serde_json::json!({
                "signatures": ["sig"],
                "message": {
                    "accountKeys": [
                        { "pubkey": programs::TOKEN_PROGRAM, "writable": false, "signer": false, "source": null },
                        { "pubkey": programs::MEMO_PROGRAM, "writable": false, "signer": false, "source": null }
                    ],
                    "recentBlockhash": "blockhash",
                    "instructions": instructions,
                    "addressTableLookups": null
                }
            }))
            .unwrap(),
        );
        tx
    }

    fn compute_limit_ix() -> Instruction {
        Instruction {
            program_id: Pubkey::from_str(programs::COMPUTE_BUDGET_PROGRAM).unwrap(),
            accounts: vec![],
            data: [vec![2], 20_000u32.to_le_bytes().to_vec()].concat(),
        }
    }

    fn compute_price_ix(microlamports: u64) -> Instruction {
        Instruction {
            program_id: Pubkey::from_str(programs::COMPUTE_BUDGET_PROGRAM).unwrap(),
            accounts: vec![],
            data: [vec![3], microlamports.to_le_bytes().to_vec()].concat(),
        }
    }

    fn memo_ix() -> Instruction {
        Instruction {
            program_id: Pubkey::from_str(programs::MEMO_PROGRAM).unwrap(),
            accounts: vec![],
            data: b"deadbeef".to_vec(),
        }
    }

    fn unknown_ix() -> Instruction {
        Instruction {
            program_id: Pubkey::new_unique(),
            accounts: vec![],
            data: vec![1],
        }
    }

    fn transfer_checked_ix(
        owner: &Pubkey,
        requirements: &PaymentRequirements,
        amount: u64,
        destination_override: Option<Pubkey>,
        mint_override: Option<Pubkey>,
    ) -> Instruction {
        let mint =
            mint_override.unwrap_or_else(|| Pubkey::from_str(&requirements.currency).unwrap());
        let token_program =
            Pubkey::from_str(requirements.token_program.as_deref().unwrap()).unwrap();
        let destination = destination_override.unwrap_or_else(|| {
            get_associated_token_address(
                &Pubkey::from_str(&requirements.recipient).unwrap(),
                &mint,
                &token_program,
            )
        });
        let source = get_associated_token_address(owner, &mint, &token_program);

        let mut data = vec![12u8];
        data.extend_from_slice(&amount.to_le_bytes());
        data.push(requirements.decimals.unwrap_or(6));

        Instruction {
            program_id: token_program,
            accounts: vec![
                AccountMeta::new(source, false),
                AccountMeta::new_readonly(mint, false),
                AccountMeta::new(destination, false),
                AccountMeta::new_readonly(*owner, true),
            ],
            data,
        }
    }

    fn build_exact_transaction(
        requirements: &PaymentRequirements,
        owner: &Pubkey,
        transfer_owner: &Pubkey,
        optional_ixs: Vec<Instruction>,
        amount: u64,
        destination_override: Option<Pubkey>,
        mint_override: Option<Pubkey>,
    ) -> VersionedTransaction {
        let mut instructions = vec![
            compute_limit_ix(),
            compute_price_ix(1),
            transfer_checked_ix(
                transfer_owner,
                requirements,
                amount,
                destination_override,
                mint_override,
            ),
        ];
        instructions.extend(optional_ixs);

        crate::core::tx::build_unsigned_unchecked(
            crate::core::tx::TxVersion::V0,
            owner,
            &instructions,
            Hash::new_from_array([9u8; 32]),
            None,
        )
        .unwrap()
    }

    /// Version 1: the compute budget lives in the header, so the transaction
    /// carries the transfer at index 0 and no ComputeBudget instructions.
    fn build_exact_v1_transaction(
        requirements: &PaymentRequirements,
        fee_payer: &Pubkey,
        transfer_owner: &Pubkey,
        optional_ixs: Vec<Instruction>,
        budget: crate::core::tx::ComputeBudget,
    ) -> VersionedTransaction {
        let mut instructions = vec![transfer_checked_ix(
            transfer_owner,
            requirements,
            1000,
            None,
            None,
        )];
        instructions.extend(optional_ixs);
        crate::core::tx::build_unsigned(
            crate::core::tx::TxVersion::V1,
            fee_payer,
            &instructions,
            Hash::new_from_array([9u8; 32]),
            Some(&budget),
        )
        .unwrap()
    }

    #[test]
    fn verify_exact_versioned_transaction_accepts_v1_header_budget() {
        let requirements = requirements("1000");
        let fee_payer = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let tx = build_exact_v1_transaction(
            &requirements,
            &fee_payer,
            &owner,
            vec![memo_ix()],
            crate::core::tx::ComputeBudget::new(20_000, 1),
        );
        assert!(verify_exact_versioned_transaction(&tx, &requirements, &[fee_payer]).is_ok());

        // The per-unit price cap applies to the header fee: 20_000 CU at
        // 6 lamports/CU is over the 5 lamports/CU maximum.
        let tx = build_exact_v1_transaction(
            &requirements,
            &fee_payer,
            &owner,
            vec![memo_ix()],
            crate::core::tx::ComputeBudget::new(20_000, 6_000_000),
        );
        let err = verify_exact_versioned_transaction(&tx, &requirements, &[fee_payer]).unwrap_err();
        assert!(err.to_string().contains("compute_price"), "{err}");

        // ComputeBudget instructions inside a version-1 message are rejected:
        // the runtime ignores them, so nothing they say could be bounded.
        let mut instructions = vec![
            compute_limit_ix(),
            compute_price_ix(1),
            transfer_checked_ix(&owner, &requirements, 1000, None, None),
        ];
        instructions.push(memo_ix());
        let tx = crate::core::tx::build_unsigned(
            crate::core::tx::TxVersion::V1,
            &fee_payer,
            &instructions,
            Hash::new_from_array([9u8; 32]),
            Some(&crate::core::tx::ComputeBudget::new(20_000, 1)),
        )
        .unwrap();
        assert!(verify_exact_versioned_transaction(&tx, &requirements, &[fee_payer]).is_err());
    }

    fn build_exact_versioned_transaction(
        requirements: &PaymentRequirements,
        fee_payer: &Pubkey,
        transfer_owner: &Pubkey,
        optional_ixs: Vec<Instruction>,
    ) -> VersionedTransaction {
        let mut instructions = vec![
            compute_limit_ix(),
            compute_price_ix(1),
            transfer_checked_ix(transfer_owner, requirements, 1000, None, None),
        ];
        instructions.extend(optional_ixs);

        let message = v0::Message::try_compile(
            fee_payer,
            &instructions,
            &[],
            Hash::new_from_array([9u8; 32]),
        )
        .unwrap();
        VersionedTransaction {
            signatures: vec![Signature::default(); message.header.num_required_signatures as usize],
            message: VersionedMessage::V0(message),
        }
    }

    #[test]
    fn verify_transaction_details_accepts_nominal_meta() {
        let requirements = requirements("1000");
        let tx = tx_with_parsed_transfer_and_memos(&requirements, &[]);
        assert!(verify_transaction_details(&tx, &requirements).is_ok());
    }

    #[test]
    fn verify_transaction_details_accepts_missing_meta() {
        let requirements = requirements("1000");
        let mut tx = tx_with_parsed_transfer_and_memos(&requirements, &[]);
        tx.transaction.meta = None;
        assert!(verify_transaction_details(&tx, &requirements).is_ok());
    }

    #[test]
    fn verify_transaction_details_rejects_onchain_error() {
        let requirements = requirements("1000");
        let mut tx = tx_with_parsed_transfer_and_memos(&requirements, &[]);
        if let Some(meta) = tx.transaction.meta.as_mut() {
            meta.err = Some(TransactionError::AccountInUse.into());
            meta.status = Err(TransactionError::AccountInUse.into());
        }
        let err = verify_transaction_details(&tx, &requirements).unwrap_err();
        assert!(matches!(err, Error::TransactionFailed(_)));
    }

    #[test]
    fn verify_transaction_details_rejects_invalid_amount() {
        let requirements = requirements("abc");
        let tx = tx_with_meta(None);
        let err = verify_transaction_details(&tx, &requirements).unwrap_err();
        assert!(matches!(err, Error::Other(_)));
    }

    #[test]
    fn verify_transaction_details_rejects_missing_transfer() {
        // No transfer instruction in the tx — must reject. This is the
        // direct regression test for the previous stub behavior.
        let requirements = requirements("1000");
        let tx = tx_with_meta(None);
        let err = verify_transaction_details(&tx, &requirements).unwrap_err();
        assert!(
            matches!(err, Error::Other(ref reason) if reason == "invalid_exact_svm_payload_no_transfer_instruction"),
            "got: {err:?}"
        );
    }

    #[test]
    fn verify_transaction_details_rejects_wrong_amount_transfer() {
        // The on-chain tx pays 999 but the requirements ask for 1000.
        let requirements_route = requirements("1000");
        let mut requirements_credential = requirements_route.clone();
        requirements_credential.amount = "999".into();
        let tx = tx_with_parsed_transfer_and_memos(&requirements_credential, &[]);
        let err = verify_transaction_details(&tx, &requirements_route).unwrap_err();
        assert!(
            matches!(err, Error::Other(ref reason) if reason == "invalid_exact_svm_payload_no_transfer_instruction"),
            "got: {err:?}"
        );
    }

    #[test]
    fn verify_transaction_details_rejects_wrong_recipient_transfer() {
        // The on-chain tx pays a different recipient.
        let requirements_route = requirements("1000");
        let mut requirements_credential = requirements_route.clone();
        requirements_credential.recipient = Pubkey::new_unique().to_string();
        let tx = tx_with_parsed_transfer_and_memos(&requirements_credential, &[]);
        let err = verify_transaction_details(&tx, &requirements_route).unwrap_err();
        assert!(
            matches!(err, Error::Other(ref reason) if reason == "invalid_exact_svm_payload_no_transfer_instruction"),
            "got: {err:?}"
        );
    }

    #[test]
    fn verify_transaction_details_enforces_expected_memo() {
        let mut requirements = requirements("1000");
        requirements.extra = Some(serde_json::json!({ "memo": "deadbeef" }));
        let tx = tx_with_parsed_transfer_and_memos(&requirements, &["deadbeef"]);

        assert!(verify_transaction_details(&tx, &requirements).is_ok());

        requirements.extra = Some(serde_json::json!({ "memo": "expected" }));
        let err = verify_transaction_details(&tx, &requirements).unwrap_err();
        assert!(
            matches!(err, Error::Other(reason) if reason == "invalid_exact_svm_payload_memo_mismatch")
        );
    }

    #[test]
    fn verify_transaction_details_rejects_missing_expected_memo() {
        let mut requirements = requirements("1000");
        requirements.extra = Some(serde_json::json!({ "memo": "required" }));
        let tx = tx_with_parsed_transfer_and_memos(&requirements, &[]);

        let err = verify_transaction_details(&tx, &requirements).unwrap_err();
        assert!(
            matches!(err, Error::Other(reason) if reason == "invalid_exact_svm_payload_memo_count")
        );
    }

    #[test]
    fn verify_transaction_details_rejects_multiple_expected_memos() {
        let mut requirements = requirements("1000");
        requirements.extra = Some(serde_json::json!({ "memo": "deadbeef" }));
        let tx = tx_with_parsed_transfer_and_memos(&requirements, &["deadbeef", "deadbeef"]);

        let err = verify_transaction_details(&tx, &requirements).unwrap_err();
        assert!(
            matches!(err, Error::Other(reason) if reason == "invalid_exact_svm_payload_memo_count")
        );
    }

    #[test]
    fn fetch_transaction_rejects_invalid_signature_before_rpc() {
        let rpc = RpcClient::new("http://localhost:8899".to_string());
        let err = fetch_transaction(&rpc, "not-a-signature").unwrap_err();
        assert!(matches!(err, Error::Other(_)));
    }

    #[test]
    fn verify_exact_transaction_accepts_nominal_shape() {
        let requirements = requirements("1000");
        let fee_payer = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let tx = build_exact_transaction(
            &requirements,
            &fee_payer,
            &owner,
            vec![memo_ix()],
            1000,
            None,
            None,
        );
        assert!(verify_exact_transaction(&tx, &requirements, &[fee_payer]).is_ok());
    }

    #[test]
    fn verify_exact_versioned_transaction_accepts_v0_shape() {
        let requirements = requirements("1000");
        let fee_payer = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let tx =
            build_exact_versioned_transaction(&requirements, &fee_payer, &owner, vec![memo_ix()]);

        assert!(verify_exact_versioned_transaction(&tx, &requirements, &[fee_payer]).is_ok());
    }

    #[test]
    fn verify_exact_transaction_accepts_usdt_symbol() {
        let mut requirements = requirements("1000");
        requirements.currency = "USDT".to_string();
        requirements.cluster = Some("mainnet-beta".to_string());

        let fee_payer = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let tx = build_exact_transaction(
            &requirements,
            &fee_payer,
            &owner,
            vec![memo_ix()],
            1000,
            None,
            Some(Pubkey::from_str(mints::USDT_MAINNET).unwrap()),
        );

        assert!(verify_exact_transaction(&tx, &requirements, &[fee_payer]).is_ok());
    }

    #[test]
    fn verify_exact_transaction_accepts_pyusd_and_cash_symbols() {
        let mut pyusd = requirements("1000");
        pyusd.currency = "PYUSD".to_string();
        pyusd.cluster = Some(SOLANA_DEVNET.to_string());
        assert_eq!(resolve_expected_mint(&pyusd), mints::PYUSD_DEVNET);

        let mut usdg = requirements("1000");
        usdg.currency = "USDG".to_string();
        usdg.cluster = Some(SOLANA_DEVNET.to_string());
        assert_eq!(resolve_expected_mint(&usdg), mints::USDG_DEVNET);

        let mut cash = requirements("1000");
        cash.currency = "CASH".to_string();
        assert_eq!(resolve_expected_mint(&cash), mints::CASH_MAINNET);
    }

    #[test]
    fn verify_exact_transaction_enforces_expected_memo() {
        let mut requirements = requirements("1000");
        requirements.extra = Some(serde_json::json!({ "memo": "deadbeef" }));
        let fee_payer = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let tx = build_exact_transaction(
            &requirements,
            &fee_payer,
            &owner,
            vec![memo_ix()],
            1000,
            None,
            None,
        );

        assert!(verify_exact_transaction(&tx, &requirements, &[fee_payer]).is_ok());

        requirements.extra = Some(serde_json::json!({ "memo": "expected" }));
        let err = verify_exact_transaction(&tx, &requirements, &[fee_payer]).unwrap_err();
        assert!(
            matches!(err, Error::Other(reason) if reason == "invalid_exact_svm_payload_memo_mismatch")
        );
    }

    #[test]
    fn verify_exact_transaction_rejects_missing_expected_memo() {
        let mut requirements = requirements("1000");
        requirements.extra = Some(serde_json::json!({ "memo": "required" }));
        let fee_payer = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let tx =
            build_exact_transaction(&requirements, &fee_payer, &owner, vec![], 1000, None, None);

        let err = verify_exact_transaction(&tx, &requirements, &[fee_payer]).unwrap_err();
        assert!(
            matches!(err, Error::Other(reason) if reason == "invalid_exact_svm_payload_memo_count")
        );
    }

    #[test]
    fn verify_exact_transaction_rejects_instruction_length() {
        let requirements = requirements("1000");
        let fee_payer = Pubkey::new_unique();
        let tx = crate::core::tx::build_unsigned_unchecked(
            crate::core::tx::TxVersion::V0,
            &fee_payer,
            &[compute_limit_ix(), compute_price_ix(1)],
            Hash::new_from_array([9u8; 32]),
            None,
        )
        .unwrap();
        let err = verify_exact_transaction(&tx, &requirements, &[fee_payer]).unwrap_err();
        assert!(
            matches!(err, Error::Other(reason) if reason == "invalid_exact_svm_payload_transaction_instructions_length")
        );
    }

    #[test]
    fn verify_exact_transaction_rejects_bad_compute_limit() {
        let requirements = requirements("1000");
        let fee_payer = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let mut tx =
            build_exact_transaction(&requirements, &fee_payer, &owner, vec![], 1000, None, None);
        ix_mut(&mut tx, 0).data = vec![9];
        let err = verify_exact_transaction(&tx, &requirements, &[fee_payer]).unwrap_err();
        assert!(
            matches!(err, Error::Other(reason) if reason == "invalid_exact_svm_payload_transaction_instructions_compute_limit_instruction")
        );
    }

    #[test]
    fn verify_exact_transaction_rejects_bad_compute_price() {
        let requirements = requirements("1000");
        let fee_payer = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let mut tx =
            build_exact_transaction(&requirements, &fee_payer, &owner, vec![], 1000, None, None);
        ix_mut(&mut tx, 1).data = vec![3];
        let err = verify_exact_transaction(&tx, &requirements, &[fee_payer]).unwrap_err();
        assert!(
            matches!(err, Error::Other(reason) if reason == "invalid_exact_svm_payload_transaction_instructions_compute_price_instruction")
        );
    }

    #[test]
    fn sponsored_priority_fee_bounds_limit_times_price() {
        let requirements = requirements("1000");
        let fee_payer = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let too_high =
            "invalid_exact_svm_payload_transaction_instructions_compute_price_instruction_too_high";
        let v0 = |units: u32, price: u64| {
            let mut tx = build_exact_transaction(
                &requirements,
                &fee_payer,
                &owner,
                vec![],
                1000,
                None,
                None,
            );
            ix_mut(&mut tx, 0).data = [vec![2], units.to_le_bytes().to_vec()].concat();
            ix_mut(&mut tx, 1).data = [vec![3], price.to_le_bytes().to_vec()].concat();
            verify_exact_transaction(&tx, &requirements, &[fee_payer])
        };
        // Each factor is within its own cap; the product is 1,000,000 lamports.
        let err = v0(MAX_COMPUTE_UNIT_LIMIT, MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS).unwrap_err();
        assert!(
            matches!(err, Error::Other(ref reason) if reason == too_high),
            "{err}"
        );
        assert!(v0(20_000, 100_001).is_err());
        v0(20_000, 100_000).unwrap();

        let v1 = |units: u32, price: u64| {
            let tx = build_exact_v1_transaction(
                &requirements,
                &fee_payer,
                &owner,
                vec![],
                crate::core::tx::ComputeBudget::new(units, price),
            );
            verify_exact_versioned_transaction(&tx, &requirements, &[fee_payer])
        };
        let err = v1(MAX_COMPUTE_UNIT_LIMIT, MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS).unwrap_err();
        assert!(
            matches!(err, Error::Other(ref reason) if reason == too_high),
            "{err}"
        );
        v1(20_000, 100_000).unwrap();
    }

    #[test]
    fn verify_exact_transaction_rejects_compute_price_too_high() {
        let requirements = requirements("1000");
        let fee_payer = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let mut tx =
            build_exact_transaction(&requirements, &fee_payer, &owner, vec![], 1000, None, None);
        ix_mut(&mut tx, 1).data = [
            vec![3],
            (MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS + 1)
                .to_le_bytes()
                .to_vec(),
        ]
        .concat();
        let err = verify_exact_transaction(&tx, &requirements, &[fee_payer]).unwrap_err();
        assert!(
            matches!(err, Error::Other(reason) if reason == "invalid_exact_svm_payload_transaction_instructions_compute_price_instruction_too_high")
        );
    }

    #[test]
    fn verify_exact_transaction_rejects_unknown_transfer_program() {
        let requirements = requirements("1000");
        let fee_payer = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let mut tx =
            build_exact_transaction(&requirements, &fee_payer, &owner, vec![], 1000, None, None);
        ix_mut(&mut tx, 2).program_id_index = 0;
        let err = verify_exact_transaction(&tx, &requirements, &[fee_payer]).unwrap_err();
        assert!(
            matches!(err, Error::Other(reason) if reason == "invalid_exact_svm_payload_no_transfer_instruction")
        );
    }

    #[test]
    fn verify_exact_transaction_rejects_managed_fee_payer_transferring_funds() {
        let requirements = requirements("1000");
        let fee_payer = Pubkey::new_unique();
        let tx = build_exact_transaction(
            &requirements,
            &fee_payer,
            &fee_payer,
            vec![],
            1000,
            None,
            None,
        );
        let err = verify_exact_transaction(&tx, &requirements, &[fee_payer]).unwrap_err();
        assert!(
            matches!(err, Error::Other(reason) if reason == "invalid_exact_svm_payload_transaction_fee_payer_transferring_funds")
        );
    }

    #[test]
    fn verify_exact_transaction_rejects_mint_mismatch() {
        let requirements = requirements("1000");
        let fee_payer = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let tx = build_exact_transaction(
            &requirements,
            &fee_payer,
            &owner,
            vec![],
            1000,
            None,
            Some(Pubkey::new_unique()),
        );
        let err = verify_exact_transaction(&tx, &requirements, &[fee_payer]).unwrap_err();
        assert!(
            matches!(err, Error::Other(reason) if reason == "invalid_exact_svm_payload_mint_mismatch")
        );
    }

    #[test]
    fn verify_exact_transaction_rejects_recipient_mismatch() {
        let requirements = requirements("1000");
        let fee_payer = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let tx = build_exact_transaction(
            &requirements,
            &fee_payer,
            &owner,
            vec![],
            1000,
            Some(Pubkey::new_unique()),
            None,
        );
        let err = verify_exact_transaction(&tx, &requirements, &[fee_payer]).unwrap_err();
        assert!(
            matches!(err, Error::Other(reason) if reason == "invalid_exact_svm_payload_recipient_mismatch")
        );
    }

    // Scheme §1.4: overpayment is tolerated (regression: rejected before).
    #[test]
    fn verify_exact_transaction_accepts_overpayment() {
        let requirements = requirements("1000");
        let fee_payer = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        for amount in [1000, 1001, u64::MAX] {
            let tx = build_exact_transaction(
                &requirements,
                &fee_payer,
                &owner,
                vec![],
                amount,
                None,
                None,
            );
            assert!(
                verify_exact_transaction(&tx, &requirements, &[fee_payer]).is_ok(),
                "{amount}"
            );
        }
    }

    #[test]
    fn verify_exact_transaction_rejects_amount_mismatch() {
        let requirements = requirements("1000");
        let fee_payer = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let tx =
            build_exact_transaction(&requirements, &fee_payer, &owner, vec![], 999, None, None);
        let err = verify_exact_transaction(&tx, &requirements, &[fee_payer]).unwrap_err();
        assert!(
            matches!(err, Error::Other(reason) if reason == "invalid_exact_svm_payload_amount_mismatch")
        );
    }

    #[test]
    fn verify_exact_transaction_rejects_unknown_optional_instruction() {
        let requirements = requirements("1000");
        let fee_payer = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let tx = build_exact_transaction(
            &requirements,
            &fee_payer,
            &owner,
            vec![unknown_ix()],
            1000,
            None,
            None,
        );
        let err = verify_exact_transaction(&tx, &requirements, &[fee_payer]).unwrap_err();
        assert!(
            matches!(err, Error::Other(reason) if reason == "invalid_exact_svm_payload_unknown_fourth_instruction")
        );
    }

    #[test]
    fn verify_exact_transaction_caps_v0_compute_unit_limit() {
        let requirements = requirements("1000");
        let fee_payer = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let with_limit = |units: u32| {
            let mut tx = build_exact_transaction(
                &requirements,
                &fee_payer,
                &owner,
                vec![],
                1000,
                None,
                None,
            );
            ix_mut(&mut tx, 0).data = [vec![2], units.to_le_bytes().to_vec()].concat();
            tx
        };

        assert!(verify_exact_transaction(
            &with_limit(MAX_COMPUTE_UNIT_LIMIT),
            &requirements,
            &[fee_payer]
        )
        .is_ok());
        for units in [MAX_COMPUTE_UNIT_LIMIT + 1, 1_400_000, u32::MAX] {
            let err = verify_exact_transaction(&with_limit(units), &requirements, &[fee_payer])
                .unwrap_err();
            assert!(
                matches!(err, Error::Other(ref reason) if reason == "invalid_exact_svm_payload_transaction_instructions_compute_limit_instruction_too_high"),
                "{units}: {err:?}"
            );
        }
    }

    /// A version-1 header without loadedAccountsDataSizeLimit is a malformed
    /// payload, not a price-cap violation: each budget rule keeps its own
    /// reason (x402-txv1 §1.5).
    #[test]
    fn verify_exact_v1_budget_errors_keep_their_reason() {
        let requirements = requirements("1000");
        let fee_payer = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let mut tx = build_exact_v1_transaction(
            &requirements,
            &fee_payer,
            &owner,
            vec![memo_ix()],
            crate::core::tx::ComputeBudget::new(20_000, 1),
        );
        assert!(verify_exact_versioned_transaction(&tx, &requirements, &[fee_payer]).is_ok());
        let solana_message::VersionedMessage::V1(message) = &mut tx.message else {
            panic!("version-1 message expected");
        };
        message.config.loaded_accounts_data_size_limit = None;
        let err = verify_exact_versioned_transaction(&tx, &requirements, &[fee_payer]).unwrap_err();
        let reason = err.to_string();
        assert!(
            reason.starts_with("invalid_exact_svm_payload_transaction: ")
                && reason.contains("loaded accounts data size limit"),
            "{reason}"
        );
    }

    #[test]
    fn verify_exact_transaction_caps_v1_compute_unit_limit() {
        let requirements = requirements("1000");
        let fee_payer = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let with_limit = |units: u32| {
            build_exact_v1_transaction(
                &requirements,
                &fee_payer,
                &owner,
                vec![],
                crate::core::tx::ComputeBudget::new(units, 1),
            )
        };

        assert!(verify_exact_versioned_transaction(
            &with_limit(MAX_COMPUTE_UNIT_LIMIT),
            &requirements,
            &[fee_payer]
        )
        .is_ok());
        for units in [MAX_COMPUTE_UNIT_LIMIT + 1, u32::MAX] {
            let err =
                verify_exact_versioned_transaction(&with_limit(units), &requirements, &[fee_payer])
                    .unwrap_err();
            assert!(err.to_string().contains("compute_limit"), "{units}: {err}");
        }
    }

    fn memo_with_signers(signers: &[Pubkey]) -> Instruction {
        Instruction {
            program_id: Pubkey::from_str(programs::MEMO_PROGRAM).unwrap(),
            accounts: signers
                .iter()
                .map(|signer| AccountMeta::new_readonly(*signer, true))
                .collect(),
            data: b"deadbeef".to_vec(),
        }
    }

    #[test]
    fn verify_exact_transaction_rejects_extra_required_signers() {
        let requirements = requirements("1000");
        let fee_payer = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let extra = [Pubkey::new_unique(), Pubkey::new_unique()];

        for memo in [memo_with_signers(&extra[..1]), memo_with_signers(&extra)] {
            for tx in [
                build_exact_transaction(
                    &requirements,
                    &fee_payer,
                    &owner,
                    vec![memo.clone()],
                    1000,
                    None,
                    None,
                ),
                build_exact_v1_transaction(
                    &requirements,
                    &fee_payer,
                    &owner,
                    vec![memo.clone()],
                    crate::core::tx::ComputeBudget::new(20_000, 1),
                ),
            ] {
                assert!(tx.message.header().num_required_signatures > 2);
                let err = verify_exact_versioned_transaction(&tx, &requirements, &[fee_payer])
                    .unwrap_err();
                assert!(
                    matches!(err, Error::Other(ref reason) if reason == "invalid_exact_svm_payload_transaction_unexpected_signer"),
                    "{err:?}"
                );
            }
        }
    }

    #[test]
    fn verify_exact_transaction_accepts_fee_payer_and_authority_signers() {
        let requirements = requirements("1000");
        let fee_payer = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        // A memo signed by an existing signer adds no signature.
        let tx = build_exact_transaction(
            &requirements,
            &fee_payer,
            &owner,
            vec![memo_with_signers(&[owner])],
            1000,
            None,
            None,
        );
        assert_eq!(tx.message.header().num_required_signatures, 2);
        assert!(verify_exact_versioned_transaction(&tx, &requirements, &[fee_payer]).is_ok());

        // Unsponsored: the authority pays its own fee.
        let tx = build_exact_transaction(&requirements, &owner, &owner, vec![], 1000, None, None);
        assert_eq!(tx.message.header().num_required_signatures, 1);
        assert!(verify_exact_versioned_transaction(&tx, &requirements, &[]).is_ok());
    }

    /// A confirmed raw (non-parsed) `transferChecked` carrying `decimals`.
    fn tx_with_raw_transfer(
        requirements: &PaymentRequirements,
        decimals: u8,
    ) -> EncodedConfirmedTransactionWithStatusMeta {
        let owner = Pubkey::new_unique();
        let mut with_decimals = requirements.clone();
        with_decimals.decimals = Some(decimals);
        let ix = transfer_checked_ix(&owner, &with_decimals, 1000, None, None);
        let mut keys: Vec<String> = ix.accounts.iter().map(|a| a.pubkey.to_string()).collect();
        keys.push(ix.program_id.to_string());
        let mut tx = tx_with_meta(None);
        tx.transaction.transaction = EncodedTransaction::Json(UiTransaction {
            signatures: vec!["sig".to_string()],
            message: UiMessage::Raw(UiRawMessage {
                header: MessageHeader {
                    num_required_signatures: 1,
                    num_readonly_signed_accounts: 0,
                    num_readonly_unsigned_accounts: 1,
                },
                account_keys: keys,
                recent_blockhash: "blockhash".to_string(),
                instructions: vec![
                    solana_transaction_status_client_types::UiCompiledInstruction {
                        program_id_index: 4,
                        accounts: vec![0, 1, 2, 3],
                        data: bs58::encode(&ix.data).into_string(),
                        stack_height: None,
                    },
                ],
                address_table_lookups: None,
                transaction_config: None,
            }),
        });
        tx
    }

    #[test]
    fn verify_transaction_details_binds_transfer_decimals() {
        let route = requirements("1000");

        // Same raw amount at a different precision moves a different value.
        let mut nine = route.clone();
        nine.decimals = Some(9);
        let parsed = tx_with_parsed_transfer_and_memos(&nine, &[]);
        assert!(verify_transaction_details(&parsed, &route).is_err());
        assert!(verify_transaction_details(&tx_with_raw_transfer(&route, 9), &route).is_err());
        assert!(verify_transaction_details(&tx_with_raw_transfer(&route, 5), &route).is_err());

        let parsed = tx_with_parsed_transfer_and_memos(&route, &[]);
        assert!(verify_transaction_details(&parsed, &route).is_ok());
        assert!(verify_transaction_details(&tx_with_raw_transfer(&route, 6), &route).is_ok());

        let mut unpriced = route.clone();
        unpriced.decimals = None;
        let err = verify_transaction_details(&parsed, &unpriced).unwrap_err();
        assert!(err.to_string().contains("decimals_missing"), "{err}");
    }

    #[test]
    fn verify_exact_transaction_binds_transfer_decimals() {
        let route = requirements("1000");
        let fee_payer = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        for decimals in [0u8, 5, 9] {
            let mut built = route.clone();
            built.decimals = Some(decimals);
            let tx = build_exact_transaction(&built, &fee_payer, &owner, vec![], 1000, None, None);
            let err = verify_exact_transaction(&tx, &route, &[fee_payer]).unwrap_err();
            assert!(
                matches!(err, Error::Other(ref reason) if reason == "invalid_exact_svm_payload_decimals_mismatch"),
                "{decimals}: {err:?}"
            );
        }
        let tx = build_exact_transaction(&route, &fee_payer, &owner, vec![], 1000, None, None);
        assert!(verify_exact_transaction(&tx, &route, &[fee_payer]).is_ok());
    }

    // ── scheme §2.1.1 fee payer isolation, §3.1 layout, §1.4 count ──

    const FEE_PAYER_IN_ACCOUNTS: &str =
        "invalid_exact_svm_payload_transaction_fee_payer_included_in_instruction_accounts";

    // Regression: a sponsor key referenced by a memo was accepted.
    #[test]
    fn verify_exact_transaction_rejects_fee_payer_in_any_instruction_accounts() {
        let requirements = requirements("1000");
        let fee_payer = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let readonly_memo = Instruction {
            program_id: Pubkey::from_str(programs::MEMO_PROGRAM).unwrap(),
            accounts: vec![AccountMeta::new_readonly(fee_payer, false)],
            data: b"deadbeef".to_vec(),
        };
        for memo in [memo_with_signers(&[owner, fee_payer]), readonly_memo] {
            let tx = build_exact_transaction(
                &requirements,
                &fee_payer,
                &owner,
                vec![memo],
                1000,
                None,
                None,
            );
            let err = verify_exact_transaction(&tx, &requirements, &[fee_payer]).unwrap_err();
            assert!(
                matches!(err, Error::Other(ref reason) if reason == FEE_PAYER_IN_ACCOUNTS),
                "{err:?}"
            );
        }
    }

    #[test]
    fn verify_exact_transaction_rejects_fee_payer_invoked_as_program() {
        let requirements = requirements("1000");
        let fee_payer = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let mut tx = build_exact_transaction(
            &requirements,
            &fee_payer,
            &owner,
            vec![memo_ix()],
            1000,
            None,
            None,
        );
        // Point the memo's program id at the fee payer (account key 0).
        ix_mut(&mut tx, 3).program_id_index = 0;
        let err = verify_exact_transaction(&tx, &requirements, &[fee_payer]).unwrap_err();
        assert!(
            matches!(err, Error::Other(ref reason) if reason == FEE_PAYER_IN_ACCOUNTS),
            "{err:?}"
        );
    }

    // Control: the sponsor may be the payee (feePayer == payTo).
    #[test]
    fn verify_exact_transaction_accepts_fee_payer_as_pay_to() {
        let fee_payer = Pubkey::new_unique();
        let mut requirements = requirements("1000");
        requirements.recipient = fee_payer.to_string();
        let owner = Pubkey::new_unique();
        let tx = build_exact_transaction(
            &requirements,
            &fee_payer,
            &owner,
            vec![memo_ix()],
            1000,
            None,
            None,
        );
        assert!(verify_exact_transaction(&tx, &requirements, &[fee_payer]).is_ok());
    }

    fn lighthouse_ix() -> Instruction {
        Instruction {
            program_id: Pubkey::from_str(programs::LIGHTHOUSE_PROGRAM).unwrap(),
            accounts: vec![],
            data: vec![0],
        }
    }

    // Scheme §3.1: up to 7 instructions; slots 4-6 Lighthouse or Memo, slot 7
    // Memo only.
    #[test]
    fn verify_exact_transaction_static_layout_allows_seven_instructions() {
        let requirements = requirements("1000");
        let fee_payer = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let build = |optional: Vec<Instruction>| {
            build_exact_transaction(
                &requirements,
                &fee_payer,
                &owner,
                optional,
                1000,
                None,
                None,
            )
        };
        let seven = build(vec![
            lighthouse_ix(),
            lighthouse_ix(),
            lighthouse_ix(),
            memo_ix(),
        ]);
        assert!(verify_exact_transaction(&seven, &requirements, &[fee_payer]).is_ok());

        let lighthouse_in_seventh = build(vec![
            lighthouse_ix(),
            lighthouse_ix(),
            lighthouse_ix(),
            lighthouse_ix(),
        ]);
        let err = verify_exact_transaction(&lighthouse_in_seventh, &requirements, &[fee_payer])
            .unwrap_err();
        assert!(
            matches!(err, Error::Other(ref reason) if reason == "invalid_exact_svm_payload_unknown_seventh_instruction"),
            "{err:?}"
        );

        let eight = build(vec![memo_ix(), memo_ix(), memo_ix(), memo_ix(), memo_ix()]);
        let err = verify_exact_transaction(&eight, &requirements, &[fee_payer]).unwrap_err();
        assert!(
            matches!(err, Error::Other(ref reason) if reason == "invalid_exact_svm_payload_transaction_instructions_length"),
            "{err:?}"
        );
    }

    // A second transferChecked (even an exact duplicate) is never accepted.
    #[test]
    fn verify_exact_transaction_rejects_second_transfer() {
        let requirements = requirements("1000");
        let fee_payer = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let duplicate = transfer_checked_ix(&owner, &requirements, 1000, None, None);
        let tx = build_exact_transaction(
            &requirements,
            &fee_payer,
            &owner,
            vec![duplicate],
            1000,
            None,
            None,
        );
        assert!(verify_exact_transaction(&tx, &requirements, &[fee_payer]).is_err());
    }

    /// A confirmed parsed transaction with `top` top-level and `inner` CPI
    /// matching transfers of `amount`.
    fn tx_with_transfers(
        requirements: &PaymentRequirements,
        amount: &str,
        top: usize,
        inner: usize,
    ) -> EncodedConfirmedTransactionWithStatusMeta {
        let mut paid = requirements.clone();
        paid.amount = amount.to_string();
        let mut tx = tx_with_parsed_transfer_and_memos(&paid, &[]);
        let EncodedTransaction::Json(ui) = &mut tx.transaction.transaction else {
            unreachable!()
        };
        let UiMessage::Parsed(message) = &mut ui.message else {
            unreachable!()
        };
        let transfer = message.instructions[0].clone();
        message.instructions = vec![transfer.clone(); top];
        let meta = tx.transaction.meta.as_mut().unwrap();
        meta.inner_instructions = OptionSerializer::Some(vec![
            solana_transaction_status_client_types::UiInnerInstructions {
                index: 0,
                instructions: vec![transfer; inner],
            },
        ]);
        tx
    }

    #[test]
    fn verify_transaction_details_requires_exactly_one_matching_transfer() {
        let route = requirements("1000");
        // Overpayment is tolerated (regression: rejected before).
        assert!(
            verify_transaction_details(&tx_with_transfers(&route, "1500", 1, 0), &route).is_ok()
        );
        // A CPI transfer counts (smart wallets).
        assert!(
            verify_transaction_details(&tx_with_transfers(&route, "1000", 0, 1), &route).is_ok()
        );
        // Regression: two matches were accepted.
        for (top, inner) in [(2, 0), (1, 1), (0, 2)] {
            let err =
                verify_transaction_details(&tx_with_transfers(&route, "1000", top, inner), &route)
                    .unwrap_err();
            assert!(
                matches!(err, Error::Other(ref reason) if reason == "invalid_exact_svm_payload_multiple_matching_transfers"),
                "{top}/{inner}: {err:?}"
            );
        }
        // Underpayment still finds no match.
        assert!(
            verify_transaction_details(&tx_with_transfers(&route, "999", 1, 0), &route).is_err()
        );
    }
}
