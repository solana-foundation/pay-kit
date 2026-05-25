//! Client-side multi-delegator transaction builders.
//!
//! Produces base64-encoded, fully-signed Solana transactions that the server
//! can submit on the client's behalf during a pull-mode session open.

use base64::Engine;
use solana_hash::Hash;
use solana_instruction::Instruction;
use solana_keychain::SolanaSigner;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_transaction::Transaction;

use crate::error::{Error, Result};
use crate::program::multi_delegator::{
    build_create_fixed_delegation_ix, build_init_multi_delegate_ix, find_fixed_delegation_pda,
    find_multi_delegate_pda,
};

/// Build + sign the `initMultiDelegateTx`.
///
/// Two instructions in one transaction:
/// 1. `InitMultiDelegate` — creates the `MultiDelegate` PDA and approves it as
///    `u64::MAX` SPL Token delegate on `user_ata`.
/// 2. `CreateFixedDelegation` — creates a `FixedDelegation` PDA capping the
///    operator's authority to `amount` tokens for `nonce` + `expiry_ts`.
///
/// The signer is the user/client; they pay fees.
/// Returns the serialized, signed transaction as a standard base64 string.
#[allow(clippy::too_many_arguments)]
pub async fn build_init_multi_delegate_tx(
    signer: &dyn SolanaSigner,
    mint: &Pubkey,
    user_ata: &Pubkey,
    operator: &Pubkey,
    program_id: &Pubkey,
    token_program: &Pubkey,
    nonce: u64,
    amount: u64,
    expiry_ts: i64,
    recent_blockhash: Hash,
) -> Result<String> {
    let user = signer.pubkey();
    let (multi_delegate_pda, _) = find_multi_delegate_pda(&user, mint, program_id);
    let (delegation_pda, _) =
        find_fixed_delegation_pda(&multi_delegate_pda, &user, operator, nonce, program_id);

    let init_ix = build_init_multi_delegate_ix(program_id, &user, mint, user_ata, token_program);
    let create_ix = build_create_fixed_delegation_ix(
        program_id,
        &user,
        &multi_delegate_pda,
        &delegation_pda,
        operator,
        nonce,
        amount,
        expiry_ts,
    );

    sign_and_encode(signer, &[init_ix, create_ix], recent_blockhash).await
}

/// Build + sign the `updateDelegationTx`.
///
/// One `CreateFixedDelegation` instruction, used to raise an existing cap or
/// create a new delegation at a fresh `nonce`.
///
/// Returns the serialized, signed transaction as a standard base64 string.
#[allow(clippy::too_many_arguments)]
pub async fn build_update_delegation_tx(
    signer: &dyn SolanaSigner,
    mint: &Pubkey,
    operator: &Pubkey,
    program_id: &Pubkey,
    nonce: u64,
    amount: u64,
    expiry_ts: i64,
    recent_blockhash: Hash,
) -> Result<String> {
    let user = signer.pubkey();
    let (multi_delegate_pda, _) = find_multi_delegate_pda(&user, mint, program_id);
    let (delegation_pda, _) =
        find_fixed_delegation_pda(&multi_delegate_pda, &user, operator, nonce, program_id);

    let ix = build_create_fixed_delegation_ix(
        program_id,
        &user,
        &multi_delegate_pda,
        &delegation_pda,
        operator,
        nonce,
        amount,
        expiry_ts,
    );

    sign_and_encode(signer, &[ix], recent_blockhash).await
}

// ── shared helper ─────────────────────────────────────────────────────────────

async fn sign_and_encode(
    signer: &dyn SolanaSigner,
    instructions: &[Instruction],
    recent_blockhash: Hash,
) -> Result<String> {
    let fee_payer = signer.pubkey();
    let message = Message::new_with_blockhash(instructions, Some(&fee_payer), &recent_blockhash);
    let mut tx = Transaction::new_unsigned(message);

    let sig_bytes = signer
        .sign_message(&tx.message_data())
        .await
        .map_err(|e| Error::Other(format!("signing failed: {e}")))?;
    let sig = Signature::from(<[u8; 64]>::from(sig_bytes));
    tx.signatures[0] = sig;

    let bytes = bincode::serialize(&tx)
        .map_err(|e| Error::Other(format!("tx serialization failed: {e}")))?;
    Ok(base64::engine::general_purpose::STANDARD.encode(bytes))
}
