//! Typed helpers for the payment-channels program.
//!
//! The generated Codama client is kept as a path dependency and re-exported
//! through this module.  Everything else here is hand-written adapter code: PDA
//! derivation, associated token derivation, distribution hashing, voucher bytes,
//! and convenience instruction/transaction builders.
//!
//! This module lives in `solana-pay-core` so both `solana-mpp` (which re-exports
//! it at `mpp::program::payment_channels`) and `solana-x402` (which uses it to
//! back the `upto` scheme) share one implementation without depending on each
//! other.

use std::str::FromStr;

use base64::Engine;
use solana_address::Address;
use solana_hash::Hash;
use solana_instruction::AccountMeta;
use solana_instruction::Instruction;
use solana_keychain::SolanaSigner;
use solana_message::compiled_instruction::CompiledInstruction;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_transaction::versioned::VersionedTransaction;
use solana_transaction::Transaction;

use crate::core::{Error, Result};

pub use crate::generated::payment_channels as generated;
use crate::generated::payment_channels::generated::instructions::{
    DistributeBuilder, OpenBuilder, ReclaimBuilder, RequestCloseBuilder, SealBuilder,
    SettleAndSealBuilder, SettleBuilder, TopUpBuilder,
};
use crate::generated::payment_channels::generated::types::{
    DistributeArgs, DistributionEntry, OpenArgs, SettleAndSealArgs, TopUpArgs, VoucherArgs,
};

/// Canonical payment-channels program ID deployed to Surfnet.
pub const PAYMENT_CHANNELS_PROGRAM_ID: &str = "CHNLxYvVA28MJP9PrFuDXccuoGXAx7jBacfLEkahyGsX";

/// Associated Token Account program ID.
pub const ASSOCIATED_TOKEN_PROGRAM: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";

/// System Program ID.
pub const SYSTEM_PROGRAM: &str = "11111111111111111111111111111111";

/// Default payment-channel close grace period, in seconds.
pub const DEFAULT_GRACE_PERIOD_SECONDS: u32 = 900;

/// Compute Budget program ID.
pub const COMPUTE_BUDGET_PROGRAM: &str = "ComputeBudget111111111111111111111111111111";

/// SPL Memo program ID.
pub const MEMO_PROGRAM: &str = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";

/// Phantom/Solflare Lighthouse program ID. Both wallets inject assertion
/// instructions after the instructions a dapp asked them to sign, so an `open`
/// signed through them arrives with a Lighthouse suffix the verifier must
/// tolerate rather than treat as a smuggled instruction.
pub const LIGHTHOUSE_PROGRAM: &str = "L2TExMFKdjpN9kozasaurPirfHy9P8sbXoAN1qA3S95";

/// `SetComputeUnitLimit` instruction type byte in Compute Budget data.
pub const COMPUTE_BUDGET_SET_UNIT_LIMIT: u8 = 2;

/// `SetComputeUnitPrice` instruction type byte in Compute Budget data.
pub const COMPUTE_BUDGET_SET_UNIT_PRICE: u8 = 3;

/// Ceiling on `SetComputeUnitLimit` in a channel-`open` transaction. An
/// observed open consumes ~51,000 CU; the ceiling is the runtime's own
/// per-transaction reservation for the open + memo pair.
pub const OPEN_MAX_COMPUTE_UNIT_LIMIT: u32 = 400_000;

/// Ceiling on `SetComputeUnitPrice` in a channel-`open` transaction. The
/// operator is the fee payer, so the payer picks a priority fee the operator
/// pays; 5,000,000 microlamports (5 lamports/CU) is the spec ceiling.
pub const MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS: u64 = 5_000_000;

/// Maximum Lighthouse assertion instructions accepted after `open`.
pub const OPEN_MAX_LIGHTHOUSE_INSTRUCTIONS: usize = 3;

/// Maximum optional instructions accepted after `open` (3 Lighthouse + 1 Memo).
pub const OPEN_MAX_OPTIONAL_SUFFIX: usize = 4;

/// Maximum byte length of a memo emitted after `open`. Narrower than the SPL
/// Memo program's own limit: it is the cap the canonical x402 client enforces
/// on `extra.memo`, so a longer memo would be built here only to be rejected
/// by the counterparty.
pub const OPEN_MAX_MEMO_BYTES: usize = 256;

/// Constant magic prefix of the signed voucher payload (`[0x56, 0x01]`).
///
/// The program rejects a voucher whose signed bytes do not start with it
/// (`VoucherBadMagic`). Wire/JSON voucher shapes are unchanged — the magic
/// exists only in the signed byte payload.
pub const VOUCHER_MAGIC: [u8; 2] = [0x56, 0x01];

/// Slot window enforced by the program around `openSlot`: `open` requires
/// `openSlot <= clock.slot && clock.slot - openSlot <= 1500` (future slots are
/// rejected), and `reclaim` unlocks only once `clock.slot > open_slot + 1500`.
pub const OPEN_SLOT_WINDOW: u64 = 1_500;

/// Maximum voucher-backed settlement operations in one legacy transaction.
///
/// Each operation contributes an Ed25519 verification plus a `settle` or
/// `settle_and_seal` instruction. Four fit below the 1,232-byte transaction
/// limit; five do not.
pub const MAX_VOUCHER_SETTLEMENTS_PER_TX: usize = 4;

/// Maximum `reclaim` operations in one legacy transaction when the fee payer
/// is also the shared rent payer. Twenty-eight serialize to 1,230 bytes;
/// twenty-nine require 1,268 bytes.
///
/// Reclaim batches with distinct rent payers may fit fewer operations; the
/// generic packer always enforces the serialized transaction-size limit too.
pub const MAX_RECLAIMS_PER_TX: usize = 28;

/// Channel PDA seed prefix.
pub const CHANNEL_SEED: &[u8] = b"channel";

/// Event authority PDA seed prefix.
pub const EVENT_AUTHORITY_SEED: &[u8] = b"event_authority";

/// Ed25519 precompile program ID.
pub const ED25519_PROGRAM_ID: &str = "Ed25519SigVerify111111111111111111111111111";

/// Instructions sysvar ID.
pub const INSTRUCTIONS_SYSVAR_ID: &str = "Sysvar1nstructions1111111111111111111111111";

/// Rent sysvar ID.
pub const RENT_SYSVAR_ID: &str = "SysvarRent111111111111111111111111111111111";

/// Treasury owner used by the current payment-channels program deployment.
// Cs2zdfUNonRdRGsiZUQQLdTxzxVvJZmgiX2mpLYKuEqP — the treasury owner baked into
// the deployed (mainnet-build) payment-channels program; `distribute` checks the
// treasury ATA against ATA(TREASURY_OWNER, mint, token_program).
pub const TREASURY_OWNER: [u8; 32] = [
    0xB0, 0x41, 0xD9, 0xD3, 0x37, 0xB7, 0x21, 0xBE, 0x57, 0x89, 0x4E, 0xB6, 0x9C, 0x3B, 0x68, 0x09,
    0xA5, 0x3A, 0x0E, 0x2B, 0x6A, 0x23, 0x99, 0xFC, 0x7D, 0x5B, 0x7E, 0xDA, 0x8C, 0xAC, 0x89, 0xAA,
];

/// Basis points denominating a distribution share; 10,000 is the whole amount.
pub const FULL_SHARE_BPS: u16 = 10_000;

/// The single-recipient distribution both channel schemes commit at `open`.
///
/// `upto` and `batch-settlement` each send 100% of settled funds to one
/// address, leaving the channel `payee` with a zero implicit remainder. The
/// program hashes this list into `distribution_hash` at `open` and re-checks it
/// at `distribute`, so the preimage has to be rebuilt identically at every site
/// that opens, verifies, or pays out a channel — which is exactly why it is
/// built here rather than spelled out at each one.
pub fn sole_recipient(recipient: &Pubkey) -> Vec<Distribution> {
    vec![Distribution {
        recipient: *recipient,
        bps: FULL_SHARE_BPS,
    }]
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Distribution {
    pub recipient: Pubkey,
    pub bps: u16,
}

#[derive(Debug, Clone)]
pub struct OpenChannelParams {
    pub payer: Pubkey,
    /// Operator / fee payer that funds the channel PDA + escrow-ATA rent at open
    /// (and recovers it at distribute/reclaim). Pinned to the same key that
    /// co-signs the open as fee payer, so one operator signature covers both
    /// roles — there is no separate wire field for it.
    pub rent_payer: Pubkey,
    pub payee: Pubkey,
    pub mint: Pubkey,
    pub authorized_signer: Pubkey,
    pub salt: u64,
    /// Slot at which the channel is opened — a channel-PDA seed and an `open`
    /// arg. Must be the current slot (fetched via RPC `getSlot`): the program
    /// rejects future slots and slots older than [`OPEN_SLOT_WINDOW`].
    pub open_slot: u64,
    pub deposit: u64,
    pub grace_period: u32,
    pub recipients: Vec<Distribution>,
    pub token_program: Pubkey,
    pub program_id: Pubkey,
}

#[derive(Debug, Clone)]
pub struct ChannelAddresses {
    pub channel: Pubkey,
    pub payer_token_account: Pubkey,
    pub channel_token_account: Pubkey,
    pub event_authority: Pubkey,
}

/// Output of [`build_open_payment_channel_tx`]: the derived channel PDA and the
/// base64-encoded (payer-signed, fee-payer-unsigned) open transaction.
#[derive(Debug, Clone)]
pub struct PaymentChannelOpenTransaction {
    pub channel_id: Pubkey,
    pub transaction: String,
}

pub fn default_program_id() -> Pubkey {
    Pubkey::from_str(PAYMENT_CHANNELS_PROGRAM_ID).expect("valid payment-channels program id")
}

/// Generate a random `u64` channel salt.
///
/// Used to derive a unique channel PDA per open. Uses the OS CSPRNG so salts
/// don't collide across processes or restarts.
pub fn random_salt() -> u64 {
    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes).expect("getrandom CSPRNG failure");
    u64::from_le_bytes(bytes)
}

pub fn associated_token_program_id() -> Pubkey {
    Pubkey::from_str(ASSOCIATED_TOKEN_PROGRAM).expect("valid associated token program id")
}

pub fn system_program_id() -> Pubkey {
    Pubkey::from_str(SYSTEM_PROGRAM).expect("valid system program id")
}

pub fn instructions_sysvar_id() -> Pubkey {
    Pubkey::from_str(INSTRUCTIONS_SYSVAR_ID).expect("valid instructions sysvar id")
}

pub fn compute_budget_program_id() -> Pubkey {
    Pubkey::from_str(COMPUTE_BUDGET_PROGRAM).expect("valid compute budget program id")
}

pub fn memo_program_id() -> Pubkey {
    Pubkey::from_str(MEMO_PROGRAM).expect("valid memo program id")
}

pub fn lighthouse_program_id() -> Pubkey {
    Pubkey::from_str(LIGHTHOUSE_PROGRAM).expect("valid lighthouse program id")
}

pub fn rent_sysvar_id() -> Pubkey {
    Pubkey::from_str(RENT_SYSVAR_ID).expect("valid rent sysvar id")
}

pub fn treasury_owner() -> Pubkey {
    Pubkey::from(TREASURY_OWNER)
}

pub fn parse_pubkey(value: &str) -> Result<Pubkey> {
    Pubkey::from_str(value).map_err(|e| Error::Other(format!("invalid pubkey {value}: {e}")))
}

pub fn pubkey_string(pubkey: &Pubkey) -> String {
    bs58::encode(pubkey.as_ref()).into_string()
}

pub fn to_address(pubkey: &Pubkey) -> Address {
    Address::from(pubkey.to_bytes())
}

pub fn from_address(address: &Address) -> Pubkey {
    Pubkey::from(address.to_bytes())
}

/// Decode a base64 (standard) bincode transaction, accepting both legacy and v0
/// versioned wire formats. Payment-channel opens are built by legacy clients
/// (the pay Rust client) and v0 clients (the canonical pay-kit JS client, which
/// builds `createTransactionMessage({ version: 0 })`), so any server that
/// broadcasts a client-built open must accept either. Shared by x402
/// (`upto`/`batch-settlement`) and the MPP session opener.
///
/// Decodes straight to `VersionedTransaction` — its message deserializer
/// dispatches on the version-prefix byte, so it handles both formats. (Trying
/// legacy `Transaction` first is unsound: bincode ignores trailing bytes, so a
/// long-enough v0 tx can deserialize as a *garbage* legacy tx — wrong account
/// keys — instead of failing through to the v0 path.)
pub fn decode_transaction(b64: &str) -> Result<VersionedTransaction> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| Error::Other(format!("invalid base64 transaction: {e}")))?;
    bincode::deserialize(&bytes).map_err(|e| Error::Other(format!("invalid transaction: {e}")))
}

/// Co-sign the operator's (fee-payer) slot of a partially-signed payment-channel
/// transaction. The operator must be the fee payer (the first static account
/// key); its signature slot is filled in place. Works on both legacy and v0
/// transactions (via [`VersionedTransaction`]). Shared by x402
/// (`upto`/`batch-settlement`) and the MPP session opener.
pub async fn cosign_fee_payer(
    signer: &dyn SolanaSigner,
    operator: &Pubkey,
    tx: &mut VersionedTransaction,
) -> Result<()> {
    if tx.message.static_account_keys().first() != Some(operator) {
        return Err(Error::Other(
            "open transaction fee payer must be the advertised fee payer".into(),
        ));
    }
    if signer.pubkey() != *operator {
        return Err(Error::Other(
            "fee payer signer must match the advertised fee payer".into(),
        ));
    }
    crate::core::signing::sign_versioned_transaction_slot(signer, tx).await
}

// `open_slot` is a PDA seed like the others; each parameter is an independent
// seed of the on-chain derivation, so the arity is inherent.
#[allow(clippy::too_many_arguments)]
pub fn find_channel_pda(
    payer: &Pubkey,
    payee: &Pubkey,
    mint: &Pubkey,
    authorized_signer: &Pubkey,
    salt: u64,
    open_slot: u64,
    program_id: &Pubkey,
) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[
            CHANNEL_SEED,
            payer.as_ref(),
            payee.as_ref(),
            mint.as_ref(),
            authorized_signer.as_ref(),
            &salt.to_le_bytes(),
            &open_slot.to_le_bytes(),
        ],
        program_id,
    )
}

pub fn find_event_authority_pda(program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[EVENT_AUTHORITY_SEED], program_id)
}

pub fn find_associated_token_address(
    owner: &Pubkey,
    mint: &Pubkey,
    token_program: &Pubkey,
) -> (Pubkey, u8) {
    let ata_program = associated_token_program_id();
    Pubkey::find_program_address(
        &[owner.as_ref(), token_program.as_ref(), mint.as_ref()],
        &ata_program,
    )
}

pub fn build_create_associated_token_account_instruction(
    payer: &Pubkey,
    wallet: &Pubkey,
    mint: &Pubkey,
    token_program: &Pubkey,
) -> Instruction {
    let (ata, _) = find_associated_token_address(wallet, mint, token_program);
    Instruction {
        program_id: to_address(&associated_token_program_id()),
        accounts: vec![
            AccountMeta::new(to_address(payer), true),
            AccountMeta::new(to_address(&ata), false),
            AccountMeta::new_readonly(to_address(wallet), false),
            AccountMeta::new_readonly(to_address(mint), false),
            AccountMeta::new_readonly(to_address(&system_program_id()), false),
            AccountMeta::new_readonly(to_address(token_program), false),
        ],
        data: vec![1],
    }
}

pub fn derive_channel_addresses(params: &OpenChannelParams) -> ChannelAddresses {
    let (channel, _) = find_channel_pda(
        &params.payer,
        &params.payee,
        &params.mint,
        &params.authorized_signer,
        params.salt,
        params.open_slot,
        &params.program_id,
    );
    let (payer_token_account, _) =
        find_associated_token_address(&params.payer, &params.mint, &params.token_program);
    let (channel_token_account, _) =
        find_associated_token_address(&channel, &params.mint, &params.token_program);
    let (event_authority, _) = find_event_authority_pda(&params.program_id);

    ChannelAddresses {
        channel,
        payer_token_account,
        channel_token_account,
        event_authority,
    }
}

/// SHA-256 of the distribution preimage `count(u32 LE) ‖ [recipient(32) ‖
/// bps(u16 LE)]…`, byte-for-byte matching what the on-chain program commits at
/// `open` (it uses `sol_sha256` over the same layout). MUST stay sha256: the
/// program rejects a mismatched commitment with `InvalidDistributionHash`.
pub fn distribution_hash(recipients: &[Distribution]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update((recipients.len() as u32).to_le_bytes());
    for recipient in recipients {
        hasher.update(recipient.recipient.as_ref());
        hasher.update(recipient.bps.to_le_bytes());
    }
    hasher.finalize().into()
}

pub fn voucher_message_bytes(
    channel_id: &Pubkey,
    cumulative_amount: u64,
    expires_at: i64,
) -> Result<Vec<u8>> {
    let voucher = VoucherArgs {
        magic: VOUCHER_MAGIC,
        channel_id: to_address(channel_id),
        cumulative_amount,
        expires_at,
    };
    borsh::to_vec(&voucher)
        .map_err(|e| Error::Serialization(format!("voucher Borsh serialization failed: {e}")))
}

/// Builds the `open` instruction.
///
/// `params.rent_payer` is the operator / fee payer: it funds the channel PDA +
/// escrow ATA rent at open (and recovers it at distribute/reclaim). It is
/// always the same key used as the transaction fee payer, so a single operator
/// signature covers both the fee-payer and `rentPayer` signer roles — there is
/// no separate wire field for it.
pub fn build_open_instruction(params: &OpenChannelParams) -> Instruction {
    let addresses = derive_channel_addresses(params);
    let recipients = params
        .recipients
        .iter()
        .map(|entry| DistributionEntry {
            recipient: to_address(&entry.recipient),
            bps: entry.bps,
        })
        .collect();

    let mut ix = OpenBuilder::new()
        .payer(to_address(&params.payer))
        .rent_payer(to_address(&params.rent_payer))
        .payee(to_address(&params.payee))
        .mint(to_address(&params.mint))
        .authorized_signer(to_address(&params.authorized_signer))
        .channel(to_address(&addresses.channel))
        .payer_token_account(to_address(&addresses.payer_token_account))
        .channel_token_account(to_address(&addresses.channel_token_account))
        .token_program(to_address(&params.token_program))
        .rent(to_address(&rent_sysvar_id()))
        .associated_token_program(to_address(&associated_token_program_id()))
        .event_authority(to_address(&addresses.event_authority))
        .self_program(to_address(&params.program_id))
        .open_args(OpenArgs {
            salt: params.salt,
            deposit: params.deposit,
            grace_period: params.grace_period,
            open_slot: params.open_slot,
            recipients,
        })
        .instruction();
    ix.program_id = to_address(&params.program_id);
    ix
}

pub fn build_top_up_instruction(
    payer: &Pubkey,
    channel: &Pubkey,
    mint: &Pubkey,
    amount: u64,
    token_program: &Pubkey,
    program_id: &Pubkey,
) -> Instruction {
    let (payer_token_account, _) = find_associated_token_address(payer, mint, token_program);
    let (channel_token_account, _) = find_associated_token_address(channel, mint, token_program);
    let mut ix = TopUpBuilder::new()
        .payer(to_address(payer))
        .channel(to_address(channel))
        .payer_token_account(to_address(&payer_token_account))
        .channel_token_account(to_address(&channel_token_account))
        .mint(to_address(mint))
        .token_program(to_address(token_program))
        .top_up_args(TopUpArgs { amount })
        .instruction();
    ix.program_id = to_address(program_id);
    ix
}

pub fn build_ed25519_verify_instruction(
    authorized_signer: &Pubkey,
    signature: &[u8; 64],
    message: &[u8],
) -> Instruction {
    let public_key_offset: u16 = 16;
    let signature_offset: u16 = public_key_offset + 32;
    let message_data_offset: u16 = signature_offset + 64;
    let message_data_size: u16 = message
        .len()
        .try_into()
        .expect("voucher message fits in ed25519 instruction");
    let current_instruction: u16 = u16::MAX;

    let mut data = Vec::with_capacity(message_data_offset as usize + message.len());
    data.push(1);
    data.push(0);
    data.extend_from_slice(&signature_offset.to_le_bytes());
    data.extend_from_slice(&current_instruction.to_le_bytes());
    data.extend_from_slice(&public_key_offset.to_le_bytes());
    data.extend_from_slice(&current_instruction.to_le_bytes());
    data.extend_from_slice(&message_data_offset.to_le_bytes());
    data.extend_from_slice(&message_data_size.to_le_bytes());
    data.extend_from_slice(&current_instruction.to_le_bytes());
    data.extend_from_slice(authorized_signer.as_ref());
    data.extend_from_slice(signature);
    data.extend_from_slice(message);

    Instruction {
        program_id: to_address(
            &Pubkey::from_str(ED25519_PROGRAM_ID).expect("valid ed25519 program id"),
        ),
        accounts: vec![],
        data,
    }
}

pub fn build_settle_instructions(
    channel: &Pubkey,
    authorized_signer: &Pubkey,
    signature: &[u8; 64],
    cumulative_amount: u64,
    expires_at: i64,
    program_id: &Pubkey,
) -> Result<Vec<Instruction>> {
    // The program reads the voucher from the ed25519 precompile instruction, so
    // `settle` itself carries no in-data args beyond its discriminator.
    let message = voucher_message_bytes(channel, cumulative_amount, expires_at)?;
    let verify = build_ed25519_verify_instruction(authorized_signer, signature, &message);
    let mut settle = SettleBuilder::new()
        .channel(to_address(channel))
        .instructions_sysvar(to_address(&instructions_sysvar_id()))
        .instruction();
    settle.program_id = to_address(program_id);
    Ok(vec![verify, settle])
}

pub fn build_settle_and_seal_instructions(
    payee: &Pubkey,
    channel: &Pubkey,
    authorized_signer: &Pubkey,
    signature: Option<&[u8; 64]>,
    cumulative_amount: u64,
    expires_at: i64,
    program_id: &Pubkey,
) -> Result<Vec<Instruction>> {
    let mut instructions = Vec::with_capacity(if signature.is_some() { 2 } else { 1 });
    let has_voucher = if let Some(signature) = signature {
        let message = voucher_message_bytes(channel, cumulative_amount, expires_at)?;
        instructions.push(build_ed25519_verify_instruction(
            authorized_signer,
            signature,
            &message,
        ));
        1
    } else {
        0
    };
    let mut settle_and_seal = SettleAndSealBuilder::new()
        .payee(to_address(payee))
        .channel(to_address(channel))
        .instructions_sysvar(to_address(&instructions_sysvar_id()))
        .settle_and_seal_args(SettleAndSealArgs { has_voucher })
        .instruction();
    settle_and_seal.program_id = to_address(program_id);
    instructions.push(settle_and_seal);
    Ok(instructions)
}

pub fn build_request_close_instruction(
    payer: &Pubkey,
    channel: &Pubkey,
    program_id: &Pubkey,
) -> Instruction {
    let mut ix = RequestCloseBuilder::new()
        .payer(to_address(payer))
        .channel(to_address(channel))
        .instruction();
    ix.program_id = to_address(program_id);
    ix
}

pub fn build_seal_instruction(channel: &Pubkey, program_id: &Pubkey) -> Instruction {
    let mut ix = SealBuilder::new()
        .channel(to_address(channel))
        .instruction();
    ix.program_id = to_address(program_id);
    ix
}

/// Builds the permissionless `reclaim` instruction: closes a `Distributed`
/// channel PDA and returns its rent lamports to `rent_payer`. The program
/// allows it only once `clock.slot > open_slot + OPEN_SLOT_WINDOW`.
pub fn build_reclaim_instruction(
    channel: &Pubkey,
    rent_payer: &Pubkey,
    program_id: &Pubkey,
) -> Instruction {
    let mut ix = ReclaimBuilder::new()
        .channel(to_address(channel))
        .rent_payer(to_address(rent_payer))
        .instruction();
    ix.program_id = to_address(program_id);
    ix
}

#[allow(clippy::too_many_arguments)]
pub fn build_distribute_instruction(
    channel: &Pubkey,
    payer: &Pubkey,
    rent_payer: &Pubkey,
    payee: &Pubkey,
    treasury: &Pubkey,
    mint: &Pubkey,
    recipients: &[Distribution],
    token_program: &Pubkey,
    program_id: &Pubkey,
) -> Instruction {
    let (channel_token_account, _) = find_associated_token_address(channel, mint, token_program);
    let (payer_token_account, _) = find_associated_token_address(payer, mint, token_program);
    let (payee_token_account, _) = find_associated_token_address(payee, mint, token_program);
    let (treasury_token_account, _) = find_associated_token_address(treasury, mint, token_program);
    let recipient_token_accounts = recipients
        .iter()
        .map(|entry| {
            let (token_account, _) =
                find_associated_token_address(&entry.recipient, mint, token_program);
            AccountMeta::new(to_address(&token_account), false)
        })
        .collect::<Vec<_>>();
    let recipients = recipients
        .iter()
        .map(|entry| DistributionEntry {
            recipient: to_address(&entry.recipient),
            bps: entry.bps,
        })
        .collect();

    let mut ix = DistributeBuilder::new()
        .channel(to_address(channel))
        .payer(to_address(payer))
        .rent_payer(to_address(rent_payer))
        .channel_token_account(to_address(&channel_token_account))
        .payer_token_account(to_address(&payer_token_account))
        .payee_token_account(to_address(&payee_token_account))
        .treasury_token_account(to_address(&treasury_token_account))
        .mint(to_address(mint))
        .token_program(to_address(token_program))
        .event_authority(to_address(&find_event_authority_pda(program_id).0))
        .add_remaining_accounts(&recipient_token_accounts)
        .distribute_args(DistributeArgs { recipients })
        .instruction();
    ix.program_id = to_address(program_id);
    ix
}

/// Optional instructions wrapping the `open` in the built transaction.
///
/// The default is a bare `open`: every pay-kit server accepts it, and adding
/// instructions a counterparty's verifier does not expect turns a valid payment
/// into a rejected one. Only set a field when the challenge asks for it.
#[derive(Debug, Clone, Default)]
pub struct OpenTxOptions {
    /// Seller-declared memo (`extra.memo`), emitted as one SPL Memo
    /// instruction after `open`. The x402 `upto` facilitator that declares it
    /// requires exactly one matching Memo, so the text is passed through
    /// verbatim.
    pub memo: Option<String>,
}

/// Build a payer-signed (fee-payer-unsigned) channel `open` transaction.
///
/// The `payer` (the `signer`) signs to authorize the deposit; `fee_payer` is the
/// account that pays the network fee and must co-sign before broadcast (e.g. the
/// operator). `open_slot` must be the current slot (RPC `getSlot`) — it is a
/// channel-PDA seed and the program rejects it outside [`OPEN_SLOT_WINDOW`].
/// Returns the derived channel PDA and the base64-encoded transaction.
#[allow(clippy::too_many_arguments)]
pub async fn build_open_payment_channel_tx(
    signer: &dyn SolanaSigner,
    payee: &Pubkey,
    mint: &Pubkey,
    authorized_signer: &Pubkey,
    salt: u64,
    open_slot: u64,
    deposit: u64,
    grace_period: u32,
    recipients: Vec<Distribution>,
    token_program: &Pubkey,
    program_id: &Pubkey,
    fee_payer: &Pubkey,
    recent_blockhash: Hash,
) -> Result<PaymentChannelOpenTransaction> {
    build_open_payment_channel_tx_with_options(
        signer,
        payee,
        mint,
        authorized_signer,
        salt,
        open_slot,
        deposit,
        grace_period,
        recipients,
        token_program,
        program_id,
        fee_payer,
        recent_blockhash,
        &OpenTxOptions::default(),
    )
    .await
}

/// [`build_open_payment_channel_tx`] with the optional wrapper instructions in
/// [`OpenTxOptions`] appended after `open`.
#[allow(clippy::too_many_arguments)]
pub async fn build_open_payment_channel_tx_with_options(
    signer: &dyn SolanaSigner,
    payee: &Pubkey,
    mint: &Pubkey,
    authorized_signer: &Pubkey,
    salt: u64,
    open_slot: u64,
    deposit: u64,
    grace_period: u32,
    recipients: Vec<Distribution>,
    token_program: &Pubkey,
    program_id: &Pubkey,
    fee_payer: &Pubkey,
    recent_blockhash: Hash,
    options: &OpenTxOptions,
) -> Result<PaymentChannelOpenTransaction> {
    let params = OpenChannelParams {
        payer: signer.pubkey(),
        // rentPayer is pinned to the operator / fee payer already in scope.
        rent_payer: *fee_payer,
        payee: *payee,
        mint: *mint,
        authorized_signer: *authorized_signer,
        salt,
        open_slot,
        deposit,
        grace_period,
        recipients,
        token_program: *token_program,
        program_id: *program_id,
    };
    let channel_id = derive_channel_addresses(&params).channel;
    let mut instructions = vec![build_open_instruction(&params)];
    if let Some(memo) = options.memo.as_deref() {
        if memo.len() > OPEN_MAX_MEMO_BYTES {
            return Err(Error::Other(format!(
                "channel open memo is {} bytes, over the {OPEN_MAX_MEMO_BYTES}-byte maximum",
                memo.len()
            )));
        }
        instructions.push(Instruction {
            program_id: memo_program_id(),
            accounts: vec![],
            data: memo.as_bytes().to_vec(),
        });
    }
    let message = Message::new_with_blockhash(&instructions, Some(fee_payer), &recent_blockhash);
    let mut tx = Transaction::new_unsigned(message);

    signer
        .sign_transaction(&mut tx)
        .await
        .map_err(|e| Error::Other(format!("payment-channel open signing failed: {e}")))?;

    let bytes = bincode::serialize(&tx).map_err(|e| {
        Error::Serialization(format!("payment-channel open tx serialization failed: {e}"))
    })?;
    Ok(PaymentChannelOpenTransaction {
        channel_id,
        transaction: base64::engine::general_purpose::STANDARD.encode(bytes),
    })
}

// ── Client-supplied transaction acceptance policy ──
//
// A sponsor co-signs a transaction the *client* built, so its signature can
// only be safely given to a transaction whose every top-level instruction is
// on a static allowlist. [`scan_channel_tx_layout`] is that allowlist check,
// shared by the x402 `upto` and `batch-settlement` sponsors: an optional
// ComputeBudget prefix, exactly one canonical payment-channels instruction,
// then a bounded Memo/Lighthouse suffix. Simulation is not a substitute — it
// runs only after the signature has already authorized fee (and, for `open`,
// rent) expenditure.

/// A decoded ComputeBudget instruction the sponsor policy permits: a unit
/// limit or a unit price.
///
/// The on-chain wire format (tag [`COMPUTE_BUDGET_SET_UNIT_LIMIT`], 5 bytes,
/// `u32`; tag [`COMPUTE_BUDGET_SET_UNIT_PRICE`], 9 bytes, `u64`) is the same
/// everywhere, so it is decoded once here. Callers apply their own caps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComputeBudgetOp {
    /// `SetComputeUnitLimit(units)`.
    UnitLimit(u32),
    /// `SetComputeUnitPrice(microLamportsPerComputeUnit)`.
    UnitPrice(u64),
}

/// Decode a `SetComputeUnitLimit` / `SetComputeUnitPrice` ComputeBudget
/// instruction. Returns `None` for any other opcode or a malformed length —
/// callers decide whether that is an error and how to report it.
pub fn decode_compute_budget_op(ix: &CompiledInstruction) -> Option<ComputeBudgetOp> {
    match (ix.data.first().copied(), ix.data.len()) {
        (Some(COMPUTE_BUDGET_SET_UNIT_LIMIT), 5) => Some(ComputeBudgetOp::UnitLimit(
            u32::from_le_bytes(ix.data[1..5].try_into().expect("4-byte slice")),
        )),
        (Some(COMPUTE_BUDGET_SET_UNIT_PRICE), 9) => Some(ComputeBudgetOp::UnitPrice(
            u64::from_le_bytes(ix.data[1..9].try_into().expect("8-byte slice")),
        )),
        _ => None,
    }
}

/// Minimum length of a random Memo nonce, in bytes, before hex encoding.
///
/// SVM `batch-settlement` requires the setup transaction to carry a Memo so the
/// sponsor can correlate it; absent a seller-declared `extra.memo` the client
/// supplies "a random nonce of at least 16 bytes encoded as hexadecimal text".
pub const MIN_MEMO_NONCE_BYTES: usize = 16;

/// How [`scan_channel_tx_layout`] polices the Memo suffix.
#[derive(Debug, Clone, Copy)]
pub enum MemoPolicy<'a> {
    /// A Memo may appear at most once and its contents are not inspected.
    ///
    /// Used by `upto`, whose server never declares `extra.memo`, so any memo
    /// the client chose is acceptable.
    Optional,
    /// Exactly one Memo is required.
    ///
    /// `Some(memo)` pins its UTF-8 data to the seller-declared `extra.memo`;
    /// `None` instead requires a random nonce of at least
    /// [`MIN_MEMO_NONCE_BYTES`] bytes encoded as hexadecimal text.
    Required(Option<&'a str>),
}

/// Enforce the sponsor's top-level instruction allowlist and return the single
/// canonical payment-channels instruction it wraps.
///
/// The accepted layout is exactly three ordered regions:
///
/// 1. An optional ComputeBudget prefix: at most one `SetComputeUnitLimit` and
///    at most one `SetComputeUnitPrice`, limit before price, each within
///    [`OPEN_MAX_COMPUTE_UNIT_LIMIT`] / [`MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS`].
/// 2. Exactly one instruction on `program_id` whose first data byte is
///    `discriminator`.
/// 3. A suffix of at most [`OPEN_MAX_LIGHTHOUSE_INSTRUCTIONS`] Lighthouse
///    assertions plus a Memo governed by `memo`, capped at
///    [`OPEN_MAX_OPTIONAL_SUFFIX`] instructions in total.
///
/// No wrapper instruction may name the transaction fee payer among its
/// accounts: outside the payment-channels instruction's own prescribed roles
/// the sponsor's signature must authorize network fees and nothing else.
///
/// `label` names the operation in error messages (`"open"`, `"top_up"`, …).
pub fn scan_channel_tx_layout<'tx>(
    tx: &'tx VersionedTransaction,
    keys: &[Pubkey],
    program_id: &Pubkey,
    discriminator: u8,
    label: &str,
    memo: MemoPolicy<'_>,
) -> Result<&'tx CompiledInstruction> {
    let instructions = tx.message.instructions();
    let fee_payer = *keys
        .first()
        .ok_or_else(|| Error::Other(format!("{label} transaction has no fee payer")))?;
    let program_of = |ix: &CompiledInstruction| -> Result<Pubkey> {
        keys.get(ix.program_id_index as usize)
            .copied()
            .ok_or_else(|| Error::Other(format!("{label} instruction program id out of range")))
    };
    let reject_fee_payer = |ix: &CompiledInstruction, wrapper: &str| -> Result<()> {
        if ix
            .accounts
            .iter()
            .any(|&i| keys.get(i as usize) == Some(&fee_payer))
        {
            return Err(Error::Other(format!(
                "{wrapper} instruction must not reference the fee payer"
            )));
        }
        Ok(())
    };

    let compute_budget = compute_budget_program_id();
    let mut index = 0usize;
    let (mut seen_limit, mut seen_price) = (false, false);
    while let Some(ix) = instructions.get(index) {
        if program_of(ix)? != compute_budget {
            break;
        }
        reject_fee_payer(ix, "ComputeBudget")?;
        match decode_compute_budget_op(ix) {
            Some(ComputeBudgetOp::UnitLimit(units)) => {
                if seen_limit {
                    return Err(Error::Other(format!(
                        "{label} transaction has a duplicate SetComputeUnitLimit instruction"
                    )));
                }
                if seen_price {
                    return Err(Error::Other(format!(
                        "{label} transaction SetComputeUnitLimit must precede SetComputeUnitPrice"
                    )));
                }
                if units > OPEN_MAX_COMPUTE_UNIT_LIMIT {
                    return Err(Error::Other(format!(
                        "{label} transaction compute unit limit {units} exceeds maximum {OPEN_MAX_COMPUTE_UNIT_LIMIT}"
                    )));
                }
                seen_limit = true;
            }
            Some(ComputeBudgetOp::UnitPrice(price)) => {
                if seen_price {
                    return Err(Error::Other(format!(
                        "{label} transaction has a duplicate SetComputeUnitPrice instruction"
                    )));
                }
                if price > MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS {
                    return Err(Error::Other(format!(
                        "{label} transaction compute unit price {price} exceeds maximum {MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS}"
                    )));
                }
                seen_price = true;
            }
            None => {
                return Err(Error::Other(format!(
                    "{label} transaction has an unsupported ComputeBudget instruction"
                )))
            }
        }
        index += 1;
    }

    let primary = instructions.get(index).ok_or_else(|| {
        Error::Other(format!(
            "{label} transaction contains no payment-channels instruction"
        ))
    })?;
    if program_of(primary)? != *program_id {
        return Err(Error::Other(format!(
            "{label} transaction targets an unexpected program"
        )));
    }
    if primary.data.first() != Some(&discriminator) {
        return Err(Error::Other(format!(
            "{label} transaction is not a payment-channels {label} instruction"
        )));
    }
    index += 1;

    let memo_program = memo_program_id();
    let lighthouse = lighthouse_program_id();
    let (mut lighthouse_count, mut optional_count, mut memo_count) = (0usize, 0usize, 0usize);
    while let Some(ix) = instructions.get(index) {
        optional_count += 1;
        if optional_count > OPEN_MAX_OPTIONAL_SUFFIX {
            return Err(Error::Other(format!(
                "{label} transaction allows at most {OPEN_MAX_OPTIONAL_SUFFIX} instructions after {label}"
            )));
        }
        let program = program_of(ix)?;
        if program == lighthouse {
            lighthouse_count += 1;
            if lighthouse_count > OPEN_MAX_LIGHTHOUSE_INSTRUCTIONS {
                return Err(Error::Other(format!(
                    "{label} transaction allows at most {OPEN_MAX_LIGHTHOUSE_INSTRUCTIONS} Lighthouse instructions after {label}"
                )));
            }
            reject_fee_payer(ix, "Lighthouse")?;
        } else if program == memo_program {
            memo_count += 1;
            if memo_count > 1 {
                return Err(Error::Other(format!(
                    "{label} transaction allows at most one Memo instruction"
                )));
            }
            reject_fee_payer(ix, "Memo")?;
            check_memo_data(&ix.data, label, memo)?;
        } else {
            return Err(Error::Other(format!(
                "{label} transaction instruction after {label} must be Lighthouse or Memo, found {}",
                pubkey_string(&program)
            )));
        }
        index += 1;
    }
    if memo_count == 0 && matches!(memo, MemoPolicy::Required(_)) {
        return Err(Error::Other(format!(
            "{label} transaction must carry exactly one Memo instruction"
        )));
    }

    Ok(primary)
}

/// Apply a [`MemoPolicy`] to one Memo instruction's data.
fn check_memo_data(data: &[u8], label: &str, memo: MemoPolicy<'_>) -> Result<()> {
    let MemoPolicy::Required(expected) = memo else {
        return Ok(());
    };
    if data.len() > OPEN_MAX_MEMO_BYTES {
        return Err(Error::Other(format!(
            "{label} transaction memo is {} bytes, over the {OPEN_MAX_MEMO_BYTES}-byte maximum",
            data.len()
        )));
    }
    let text = std::str::from_utf8(data)
        .map_err(|_| Error::Other(format!("{label} transaction memo is not valid UTF-8")))?;
    match expected {
        Some(expected) => {
            if text != expected {
                return Err(Error::Other(format!(
                    "{label} transaction memo does not match the declared extra.memo"
                )));
            }
        }
        // No seller-declared memo: the client must supply a random hex nonce,
        // which correlates the transaction without letting it carry a payload
        // the sponsor never agreed to.
        None => {
            if text.len() < MIN_MEMO_NONCE_BYTES * 2 || !text.bytes().all(|b| b.is_ascii_hexdigit())
            {
                return Err(Error::Other(format!(
                    "{label} transaction memo must be a hex nonce of at least {MIN_MEMO_NONCE_BYTES} bytes"
                )));
            }
        }
    }
    Ok(())
}

/// Fixed byte length of the payment-channels channel account layout this SDK
/// targets. `getProgramAccounts` discovery filters on it, and a different
/// length means an unsupported account version whose field offsets below no
/// longer hold.
pub const CHANNEL_ACCOUNT_SIZE: usize = 256;

/// `Channel.payer` byte offset — a client discovers its own channels here.
pub const CHANNEL_PAYER_OFFSET: usize = 88;

/// `Channel.payee` byte offset — the lifecycle authority seat.
pub const CHANNEL_PAYEE_OFFSET: usize = 120;

/// `Channel.authorized_signer` byte offset — the voucher signer.
pub const CHANNEL_AUTHORIZED_SIGNER_OFFSET: usize = 152;

/// `Channel.rent_payer` byte offset — a sponsor discovers the channels whose
/// rent it fronted here.
pub const CHANNEL_RENT_PAYER_OFFSET: usize = 216;

#[cfg(test)]
mod tests {
    use super::*;

    fn pk(byte: u8) -> Pubkey {
        Pubkey::from([byte; 32])
    }

    #[test]
    fn distribution_hash_matches_program_sha256_golden() {
        let recipients = vec![
            Distribution {
                recipient: pk(1),
                bps: 7_500,
            },
            Distribution {
                recipient: pk(2),
                bps: 2_500,
            },
        ];

        // Golden vector pinned as a literal (NOT re-derived in-test, so it would
        // catch a hash-algorithm or preimage drift): SHA-256 of
        // `count=2 (u32 LE) ‖ pk(1) ‖ 7500 (u16 LE) ‖ pk(2) ‖ 2500 (u16 LE)`,
        // the exact bytes the on-chain program commits via `sol_sha256`.
        let expected: [u8; 32] = [
            0x54, 0xc8, 0x97, 0x55, 0x87, 0x75, 0x0e, 0x88, 0x21, 0xe9, 0x3f, 0x5d, 0x4a, 0xf6,
            0x07, 0xd2, 0x0d, 0x55, 0xa5, 0x8b, 0xa1, 0xb9, 0xa4, 0xb4, 0x9f, 0x72, 0xa5, 0x42,
            0xed, 0x87, 0x4a, 0x3f,
        ];
        assert_eq!(distribution_hash(&recipients), expected);
    }

    #[test]
    fn voucher_message_is_program_borsh_layout() {
        let bytes = voucher_message_bytes(&pk(9), 42, 1234).unwrap();
        assert_eq!(bytes.len(), 50);
        assert_eq!(&bytes[..2], &VOUCHER_MAGIC);
        assert_eq!(&bytes[2..34], pk(9).as_ref());
        assert_eq!(&bytes[34..42], &42u64.to_le_bytes());
        assert_eq!(&bytes[42..50], &1234i64.to_le_bytes());
    }

    #[test]
    fn channel_pda_is_stable() {
        let program_id = default_program_id();
        let (channel, bump) =
            find_channel_pda(&pk(1), &pk(2), &pk(3), &pk(4), 99, 123_456, &program_id);
        let expected = Pubkey::create_program_address(
            &[
                CHANNEL_SEED,
                pk(1).as_ref(),
                pk(2).as_ref(),
                pk(3).as_ref(),
                pk(4).as_ref(),
                &99u64.to_le_bytes(),
                &123_456u64.to_le_bytes(),
                &[bump],
            ],
            &program_id,
        )
        .unwrap();
        assert_eq!(channel, expected);
    }

    #[test]
    fn channel_pda_is_per_incarnation() {
        // Same params + a different openSlot must yield a different address.
        let program_id = default_program_id();
        let (a, _) = find_channel_pda(&pk(1), &pk(2), &pk(3), &pk(4), 99, 100, &program_id);
        let (b, _) = find_channel_pda(&pk(1), &pk(2), &pk(3), &pk(4), 99, 101, &program_id);
        assert_ne!(a, b);
    }

    #[test]
    fn well_known_program_ids_parse() {
        // Each id is parsed from a literal, so a typo would only surface as a
        // panic at first use — in the middle of building or verifying an open.
        assert_eq!(
            pubkey_string(&compute_budget_program_id()),
            COMPUTE_BUDGET_PROGRAM
        );
        assert_eq!(pubkey_string(&memo_program_id()), MEMO_PROGRAM);
        assert_eq!(pubkey_string(&lighthouse_program_id()), LIGHTHOUSE_PROGRAM);
        assert_eq!(pubkey_string(&system_program_id()), SYSTEM_PROGRAM);
        assert_eq!(
            pubkey_string(&associated_token_program_id()),
            ASSOCIATED_TOKEN_PROGRAM
        );
        assert_eq!(pubkey_string(&rent_sysvar_id()), RENT_SYSVAR_ID);
        assert_eq!(
            pubkey_string(&instructions_sysvar_id()),
            INSTRUCTIONS_SYSVAR_ID
        );
        assert_eq!(
            pubkey_string(&treasury_owner()),
            "Cs2zdfUNonRdRGsiZUQQLdTxzxVvJZmgiX2mpLYKuEqP"
        );
        assert!(parse_pubkey("not-a-pubkey").is_err());
    }

    #[test]
    fn open_tx_options_default_to_a_bare_open() {
        // The default must stay memo-free: every pay-kit server accepts a bare
        // open, so wrapping instructions are opt-in per challenge.
        let options = OpenTxOptions::default();
        assert!(options.memo.is_none());
        assert!(options.clone().memo.is_none());
        assert!(format!("{options:?}").contains("memo"));
    }

    fn test_signer() -> Box<dyn SolanaSigner> {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let mut kp = [0u8; 64];
        kp[..32].copy_from_slice(sk.as_bytes());
        kp[32..].copy_from_slice(sk.verifying_key().as_bytes());
        Box::new(solana_keychain::MemorySigner::from_bytes(&kp).expect("valid keypair"))
    }

    async fn build_open(options: &OpenTxOptions) -> Result<PaymentChannelOpenTransaction> {
        let signer = test_signer();
        build_open_payment_channel_tx_with_options(
            &*signer,
            &pk(2),
            &pk(3),
            &pk(4),
            99,
            314,
            1_000_000,
            DEFAULT_GRACE_PERIOD_SECONDS,
            vec![Distribution {
                recipient: pk(5),
                bps: 10_000,
            }],
            &Pubkey::from_str("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").unwrap(),
            &default_program_id(),
            &pk(6),
            Hash::default(),
            options,
        )
        .await
    }

    #[tokio::test]
    async fn open_tx_carries_the_memo_only_when_requested() {
        // The bare open is what every pay-kit server verifies; a declared
        // `extra.memo` adds exactly one Memo instruction after it.
        let bare = build_open(&OpenTxOptions::default())
            .await
            .expect("bare open transaction");
        let tx = decode_transaction(&bare.transaction).expect("decodable");
        assert_eq!(tx.message.instructions().len(), 1);
        assert_eq!(tx.message.static_account_keys()[0], pk(6));

        let with_memo = build_open(&OpenTxOptions {
            memo: Some("order-4711".to_string()),
        })
        .await
        .expect("open transaction with a memo");
        assert_eq!(with_memo.channel_id, bare.channel_id);
        let tx = decode_transaction(&with_memo.transaction).expect("decodable");
        let keys = tx.message.static_account_keys();
        let instructions = tx.message.instructions();
        assert_eq!(instructions.len(), 2);
        let memo = &instructions[1];
        assert_eq!(keys[memo.program_id_index as usize], memo_program_id());
        assert_eq!(memo.data.as_slice(), b"order-4711");

        // Over the cap the counterparty enforces, so it fails here instead.
        let err = build_open(&OpenTxOptions {
            memo: Some("x".repeat(OPEN_MAX_MEMO_BYTES + 1)),
        })
        .await
        .expect_err("an over-long memo must be rejected");
        assert!(err.to_string().contains("memo"));
    }
}
