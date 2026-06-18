//! Typed helpers for the subscriptions program.
//!
//! Hand-written PDA derivations, program-ID constants, instruction
//! discriminators, instruction data structs, and `Instruction` builders for
//! the subscriptions program. The on-chain program is published at
//! `solana-program-subscriptions`; this module is intentionally
//! dependency-light so v0 of the mpp-sdk does not bind to the
//! Codama-generated client crate. A follow-up should adopt the Codama
//! client and re-export it the same way `payment_channels::generated` is
//! re-exported.
//!
//! ## Byte layouts
//!
//! On-chain structs use `#[repr(C, packed)]` with no padding. The
//! `to_bytes` methods on the data types in this module emit the matching
//! little-endian, no-padding wire form.

use std::str::FromStr;

use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use subscriptions_client::generated::instructions::{
    CreatePlan as GenCreatePlan, CreatePlanInstructionArgs,
    InitSubscriptionAuthority as GenInitSubscriptionAuthority, Subscribe as GenSubscribe,
    SubscribeInstructionArgs, TransferSubscription as GenTransferSubscription,
    TransferSubscriptionInstructionArgs,
};
use subscriptions_client::generated::types::{
    PlanData as GenPlanData, PlanTerms as GenPlanTerms, SubscribeData as GenSubscribeData,
    TransferData as GenTransferData,
};

use crate::error::{Error, Result};

/// Convert a `Pubkey` to the `solana_address::Address` used by the generated
/// subscriptions client.
fn to_addr(pubkey: &Pubkey) -> Address {
    Address::from(pubkey.to_bytes())
}

/// Canonical mainnet program ID for the subscriptions program.
pub const SUBSCRIPTIONS_PROGRAM_ID: &str = "De1egAFMkMWZSN5rYXRj9CAdheBamobVNubTsi9avR44";

/// PDA seed prefix for the `SubscriptionAuthority` account.
pub const SUBSCRIPTION_AUTHORITY_SEED: &[u8] = b"SubscriptionAuthority";

/// PDA seed prefix for the `SubscriptionDelegation` account.
pub const SUBSCRIPTION_DELEGATION_SEED: &[u8] = b"subscription";

/// PDA seed prefix for the `Plan` account.
pub const PLAN_SEED: &[u8] = b"plan";

/// PDA seed prefix for the `event_authority` account. The subscriptions
/// program emits events via self-CPI from a PDA derived with this seed.
pub const EVENT_AUTHORITY_SEED: &[u8] = b"event_authority";

/// Canonical Associated Token Program ID (shared between SPL Token and
/// Token-2022).
pub const ASSOCIATED_TOKEN_PROGRAM_ID: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";

/// System program ID.
pub const SYSTEM_PROGRAM_ID: &str = "11111111111111111111111111111111";

/// SPL memo program ID.
pub const MEMO_PROGRAM_ID: &str = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";

/// Compute budget program ID.
pub const COMPUTE_BUDGET_PROGRAM_ID: &str = "ComputeBudget111111111111111111111111111111";

// ── Instruction discriminators (single byte) ──
//
// These mirror the subscriptions program's instruction set. See
// `solana-program-subscriptions/program/src/instructions/mod.rs`.

pub const INSTRUCTION_INITIALIZE_SUBSCRIPTION_AUTHORITY: u8 = 0;
pub const INSTRUCTION_CREATE_FIXED_DELEGATION: u8 = 1;
pub const INSTRUCTION_CREATE_RECURRING_DELEGATION: u8 = 2;
pub const INSTRUCTION_REVOKE_DELEGATION: u8 = 3;
pub const INSTRUCTION_TRANSFER_FIXED: u8 = 4;
pub const INSTRUCTION_TRANSFER_RECURRING: u8 = 5;
pub const INSTRUCTION_CLOSE_SUBSCRIPTION_AUTHORITY: u8 = 6;
pub const INSTRUCTION_CREATE_PLAN: u8 = 7;
pub const INSTRUCTION_UPDATE_PLAN: u8 = 8;
pub const INSTRUCTION_DELETE_PLAN: u8 = 9;
pub const INSTRUCTION_TRANSFER_SUBSCRIPTION: u8 = 10;
pub const INSTRUCTION_SUBSCRIBE: u8 = 11;
pub const INSTRUCTION_CANCEL_SUBSCRIPTION: u8 = 12;

/// Parse the canonical program ID.
pub fn default_program_id() -> Pubkey {
    Pubkey::from_str(SUBSCRIPTIONS_PROGRAM_ID).expect("valid subscriptions program id")
}

/// Derive the `SubscriptionAuthority` PDA for `(subscriber, mint)`.
pub fn find_subscription_authority_pda(
    subscriber: &Pubkey,
    mint: &Pubkey,
    program_id: &Pubkey,
) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[
            SUBSCRIPTION_AUTHORITY_SEED,
            subscriber.as_ref(),
            mint.as_ref(),
        ],
        program_id,
    )
}

/// Derive the `Plan` PDA for `(owner, plan_id)`.
///
/// `plan_id` is treated as raw seed bytes. Callers using the program's
/// `PlanData.plan_id` field (a `u64`) should pass the little-endian
/// 8-byte encoding via [`plan_id_seed`].
pub fn find_plan_pda(owner: &Pubkey, plan_id: &[u8], program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[PLAN_SEED, owner.as_ref(), plan_id], program_id)
}

/// Encode a numeric `plan_id` as the byte seed expected by
/// [`find_plan_pda`]. The on-chain program treats `plan_id` as a `u64` and
/// derives the PDA from its 8-byte little-endian representation.
pub fn plan_id_seed(plan_id: u64) -> [u8; 8] {
    plan_id.to_le_bytes()
}

/// Derive the program's `event_authority` PDA — the program signs every
/// emitted event via self-CPI from this account.
pub fn find_event_authority_pda(program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[EVENT_AUTHORITY_SEED], program_id)
}

/// Derive the `SubscriptionDelegation` PDA for `(plan, subscriber)`.
pub fn find_subscription_pda(
    plan_pda: &Pubkey,
    subscriber: &Pubkey,
    program_id: &Pubkey,
) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[
            SUBSCRIPTION_DELEGATION_SEED,
            plan_pda.as_ref(),
            subscriber.as_ref(),
        ],
        program_id,
    )
}

/// Parse a base58 string into a `Pubkey`, returning a typed error on failure.
pub fn parse_pubkey(value: &str, field: &str) -> Result<Pubkey> {
    Pubkey::from_str(value).map_err(|e| Error::Other(format!("Invalid {field} pubkey: {e}")))
}

// ── Instruction data structs ────────────────────────────────────────────────
//
// Wire-form mirrors of the program's `#[repr(C, packed)]` data types.
// Each `to_bytes` emits the discriminator followed by the field bytes in
// little-endian order with no padding — matching the program's
// `*Data::load(rest)` path that parses the suffix of `instruction_data`.

/// Maximum number of `destinations` / `pullers` slots per [`PlanData`].
/// The program's on-chain layout reserves 4 each.
pub const MAX_PLAN_DESTINATIONS: usize = 4;
pub const MAX_PLAN_PULLERS: usize = 4;
pub const PLAN_METADATA_URI_LEN: usize = 128;

/// Immutable billing terms snapshotted into each `SubscriptionDelegation`
/// at subscribe time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlanTerms {
    /// Maximum token amount that can be pulled per billing period.
    pub amount: u64,
    /// Billing period length in hours (1..=8760).
    pub period_hours: u64,
    /// Unix timestamp when the plan was created on-chain. Set by the
    /// program at plan creation; clients pass `0` and the program
    /// overwrites it.
    pub created_at: i64,
}

/// Wire-shape of `CreatePlan` instruction data (the program's `PlanData`).
#[derive(Debug, Clone)]
pub struct CreatePlanData {
    /// Merchant-chosen identifier for the plan (unique per owner).
    pub plan_id: u64,
    /// SPL Token / Token-2022 mint.
    pub mint: Pubkey,
    /// Immutable billing terms. The `created_at` field is set by the
    /// program; pass `0` here.
    pub terms: PlanTerms,
    /// Optional unix timestamp after which the plan expires. `0` means
    /// no end.
    pub end_ts: i64,
    /// Whitelisted destination wallets for transfers. Slots set to the
    /// default `Pubkey` are ignored on chain; an all-zero whitelist
    /// allows any destination.
    pub destinations: [Pubkey; MAX_PLAN_DESTINATIONS],
    /// Addresses authorised to pull subscription transfers (in addition
    /// to the plan owner). Default `Pubkey` slots are ignored.
    pub pullers: [Pubkey; MAX_PLAN_PULLERS],
    /// UTF-8 metadata URI, zero-padded to 128 bytes.
    pub metadata_uri: [u8; PLAN_METADATA_URI_LEN],
}

/// Serialised length of `CreatePlan`'s data payload (matches the program's
/// `PLAN_DATA_LEN_V1 = 456`).
pub const CREATE_PLAN_DATA_LEN: usize = 8 + 32 + 24 + 8 + 128 + 128 + 128;
const _: () = assert!(CREATE_PLAN_DATA_LEN == 456);

impl CreatePlanData {
    /// Construct a `CreatePlanData` from a metadata URI string. The URI is
    /// zero-padded to 128 bytes; an over-long URI is rejected to surface
    /// the error at the call site rather than silently truncating.
    pub fn new(
        plan_id: u64,
        mint: Pubkey,
        terms: PlanTerms,
        end_ts: i64,
        destinations: [Pubkey; MAX_PLAN_DESTINATIONS],
        pullers: [Pubkey; MAX_PLAN_PULLERS],
        metadata_uri: &str,
    ) -> Result<Self> {
        if metadata_uri.len() > PLAN_METADATA_URI_LEN {
            return Err(Error::Other(format!(
                "metadata_uri is {} bytes; max is {PLAN_METADATA_URI_LEN}",
                metadata_uri.len()
            )));
        }
        let mut padded = [0u8; PLAN_METADATA_URI_LEN];
        padded[..metadata_uri.len()].copy_from_slice(metadata_uri.as_bytes());
        Ok(Self {
            plan_id,
            mint,
            terms,
            end_ts,
            destinations,
            pullers,
            metadata_uri: padded,
        })
    }

    /// Emit the discriminator-prefixed instruction data bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + CREATE_PLAN_DATA_LEN);
        out.push(INSTRUCTION_CREATE_PLAN);
        out.extend_from_slice(&self.plan_id.to_le_bytes());
        out.extend_from_slice(self.mint.as_ref());
        out.extend_from_slice(&self.terms.amount.to_le_bytes());
        out.extend_from_slice(&self.terms.period_hours.to_le_bytes());
        out.extend_from_slice(&self.terms.created_at.to_le_bytes());
        out.extend_from_slice(&self.end_ts.to_le_bytes());
        for d in &self.destinations {
            out.extend_from_slice(d.as_ref());
        }
        for p in &self.pullers {
            out.extend_from_slice(p.as_ref());
        }
        out.extend_from_slice(&self.metadata_uri);
        debug_assert_eq!(out.len(), 1 + CREATE_PLAN_DATA_LEN);
        out
    }
}

/// Wire-shape of `Subscribe` instruction data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubscribeData {
    /// The plan's `plan_id` (used together with the merchant address to
    /// derive the plan PDA).
    pub plan_id: u64,
    /// The plan PDA's bump seed (avoids an on-chain `find_program_address`
    /// call).
    pub plan_bump: u8,
    /// Plan terms the subscriber consents to. The program rejects if the
    /// live plan disagrees.
    pub expected_mint: Pubkey,
    pub expected_amount: u64,
    pub expected_period_hours: u64,
    pub expected_created_at: i64,
    /// `SubscriptionAuthority::init_id` snapshot the subscriber consents to.
    /// Set on-chain at SA creation from `Clock::slot`; the program rejects
    /// `Subscribe` if it has been reinitialised since. The caller must read
    /// the live value from the SA account before signing.
    pub expected_subscription_authority_init_id: i64,
}

pub const SUBSCRIBE_DATA_LEN: usize = 8 + 1 + 32 + 8 + 8 + 8 + 8;
const _: () = assert!(SUBSCRIBE_DATA_LEN == 73);

impl SubscribeData {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + SUBSCRIBE_DATA_LEN);
        out.push(INSTRUCTION_SUBSCRIBE);
        out.extend_from_slice(&self.plan_id.to_le_bytes());
        out.push(self.plan_bump);
        out.extend_from_slice(self.expected_mint.as_ref());
        out.extend_from_slice(&self.expected_amount.to_le_bytes());
        out.extend_from_slice(&self.expected_period_hours.to_le_bytes());
        out.extend_from_slice(&self.expected_created_at.to_le_bytes());
        out.extend_from_slice(&self.expected_subscription_authority_init_id.to_le_bytes());
        debug_assert_eq!(out.len(), 1 + SUBSCRIBE_DATA_LEN);
        out
    }
}

/// Wire-shape of `TransferSubscription` (and the other transfer
/// instructions). The program's `TransferData` is shared across `Fixed`,
/// `Recurring`, and `Subscription` transfers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransferData {
    /// Token amount to transfer (base units).
    pub amount: u64,
    /// The delegator (token owner) whose ATA to debit.
    pub delegator: Pubkey,
    /// The token mint.
    pub mint: Pubkey,
}

pub const TRANSFER_DATA_LEN: usize = 8 + 32 + 32;
const _: () = assert!(TRANSFER_DATA_LEN == 72);

impl TransferData {
    pub fn to_bytes(&self, discriminator: u8) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + TRANSFER_DATA_LEN);
        out.push(discriminator);
        out.extend_from_slice(&self.amount.to_le_bytes());
        out.extend_from_slice(self.delegator.as_ref());
        out.extend_from_slice(self.mint.as_ref());
        debug_assert_eq!(out.len(), 1 + TRANSFER_DATA_LEN);
        out
    }
}

// ── Instruction account layouts ─────────────────────────────────────────────
//
// Each builder mirrors the program's `TryFrom<&[AccountView]>` impl: the
// order, signer flag, and writable flag come directly from the program
// source at `solana-program-subscriptions/program/src/instructions/`.

/// Account inputs for [`build_create_plan_ix`].
#[derive(Debug, Clone, Copy)]
pub struct CreatePlanAccounts {
    pub merchant: Pubkey,
    pub plan_pda: Pubkey,
    pub token_mint: Pubkey,
    pub token_program: Pubkey,
}

/// Build a `CreatePlan` instruction. The system program is implied and
/// supplied here.
pub fn build_create_plan_ix(
    program_id: Pubkey,
    accounts: CreatePlanAccounts,
    data: &CreatePlanData,
) -> Instruction {
    let system_program = Pubkey::from_str(SYSTEM_PROGRAM_ID).expect("valid system program id");
    let plan_data = GenPlanData {
        plan_id: data.plan_id,
        mint: to_addr(&data.mint),
        terms: GenPlanTerms {
            amount: data.terms.amount,
            period_hours: data.terms.period_hours,
            created_at: data.terms.created_at,
        },
        end_ts: data.end_ts,
        destinations: data.destinations.map(|p| to_addr(&p)),
        pullers: data.pullers.map(|p| to_addr(&p)),
        metadata_uri: data.metadata_uri,
    };
    let mut ix = GenCreatePlan {
        merchant: to_addr(&accounts.merchant),
        plan_pda: to_addr(&accounts.plan_pda),
        token_mint: to_addr(&accounts.token_mint),
        system_program: to_addr(&system_program),
        token_program: to_addr(&accounts.token_program),
    }
    .instruction(CreatePlanInstructionArgs { plan_data });
    ix.program_id = to_addr(&program_id);
    ix
}

/// Account inputs for [`build_subscribe_ix`]. `payer` is optional — when
/// `None`, the subscriber funds rent.
#[derive(Debug, Clone, Copy)]
pub struct SubscribeAccounts {
    pub subscriber: Pubkey,
    pub merchant: Pubkey,
    pub plan_pda: Pubkey,
    pub subscription_pda: Pubkey,
    pub subscription_authority_pda: Pubkey,
    pub event_authority: Pubkey,
    pub payer: Option<Pubkey>,
}

/// Build a `Subscribe` instruction. Includes the optional `payer` account
/// when supplied (the program reads it via `resolve_optional_payer`).
pub fn build_subscribe_ix(
    program_id: Pubkey,
    accounts: SubscribeAccounts,
    data: &SubscribeData,
) -> Instruction {
    let system_program = Pubkey::from_str(SYSTEM_PROGRAM_ID).expect("valid system program id");
    let subscribe_data = GenSubscribeData {
        plan_id: data.plan_id,
        plan_bump: data.plan_bump,
        expected_mint: to_addr(&data.expected_mint),
        expected_amount: data.expected_amount,
        expected_period_hours: data.expected_period_hours,
        expected_created_at: data.expected_created_at,
        expected_subscription_authority_init_id: data.expected_subscription_authority_init_id,
    };
    let gen = GenSubscribe {
        subscriber: to_addr(&accounts.subscriber),
        merchant: to_addr(&accounts.merchant),
        plan_pda: to_addr(&accounts.plan_pda),
        subscription_pda: to_addr(&accounts.subscription_pda),
        subscription_authority_pda: to_addr(&accounts.subscription_authority_pda),
        system_program: to_addr(&system_program),
        event_authority: to_addr(&accounts.event_authority),
        self_program: to_addr(&program_id),
    };
    // The optional payer rides as a trailing (writable, signer) account, exactly
    // as the program's `resolve_optional_payer` expects.
    let remaining: Vec<AccountMeta> = accounts
        .payer
        .map(|payer| vec![AccountMeta::new(to_addr(&payer), true)])
        .unwrap_or_default();
    let mut ix = gen.instruction_with_remaining_accounts(
        SubscribeInstructionArgs { subscribe_data },
        &remaining,
    );
    ix.program_id = to_addr(&program_id);
    ix
}

/// Account inputs for [`build_transfer_subscription_ix`].
#[derive(Debug, Clone, Copy)]
pub struct TransferSubscriptionAccounts {
    pub subscription_pda: Pubkey,
    pub plan_pda: Pubkey,
    pub subscription_authority: Pubkey,
    pub delegator_ata: Pubkey,
    pub receiver_ata: Pubkey,
    /// Puller — the signer pulling the transfer. Must match
    /// `plan.owner` or appear in `plan.pullers`.
    pub caller: Pubkey,
    pub token_mint: Pubkey,
    pub token_program: Pubkey,
    pub event_authority: Pubkey,
}

/// Build a `TransferSubscription` instruction.
pub fn build_transfer_subscription_ix(
    program_id: Pubkey,
    accounts: TransferSubscriptionAccounts,
    data: &TransferData,
) -> Instruction {
    let transfer_data = GenTransferData {
        amount: data.amount,
        delegator: to_addr(&data.delegator),
        mint: to_addr(&data.mint),
    };
    let mut ix = GenTransferSubscription {
        subscription_pda: to_addr(&accounts.subscription_pda),
        plan_pda: to_addr(&accounts.plan_pda),
        subscription_authority: to_addr(&accounts.subscription_authority),
        delegator_ata: to_addr(&accounts.delegator_ata),
        receiver_ata: to_addr(&accounts.receiver_ata),
        caller: to_addr(&accounts.caller),
        token_mint: to_addr(&accounts.token_mint),
        token_program: to_addr(&accounts.token_program),
        event_authority: to_addr(&accounts.event_authority),
        self_program: to_addr(&program_id),
    }
    .instruction(TransferSubscriptionInstructionArgs { transfer_data });
    ix.program_id = to_addr(&program_id);
    ix
}

/// Account inputs for [`build_cancel_subscription_ix`].
#[derive(Debug, Clone, Copy)]
pub struct CancelSubscriptionAccounts {
    pub subscriber: Pubkey,
    pub plan_pda: Pubkey,
    pub subscription_pda: Pubkey,
    pub event_authority: Pubkey,
}

/// Build a `CancelSubscription` instruction. No instruction data beyond
/// the discriminator.
pub fn build_cancel_subscription_ix(
    program_id: Pubkey,
    accounts: CancelSubscriptionAccounts,
) -> Instruction {
    // NOTE: not delegated to the generated client. Both agree `subscriber` is a
    // signer, but the vendored IDL marks it read-only while the program treats
    // it as writable (rent is refunded to the subscriber on cancel). Adopting
    // the generated builder would make `subscriber` read-only and risk breaking
    // the refund. Until the IDL is fixed and regenerated, keep the hand-written
    // account metas — see `generated_cancel_subscription_idl_still_diverges_from_program`.
    Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(accounts.subscriber, true),
            AccountMeta::new_readonly(accounts.plan_pda, false),
            AccountMeta::new(accounts.subscription_pda, false),
            AccountMeta::new_readonly(accounts.event_authority, false),
            AccountMeta::new_readonly(program_id, false),
        ],
        data: vec![INSTRUCTION_CANCEL_SUBSCRIPTION],
    }
}

/// Account inputs for [`build_initialize_subscription_authority_ix`].
#[derive(Debug, Clone, Copy)]
pub struct InitializeSubscriptionAuthorityAccounts {
    pub owner: Pubkey,
    pub subscription_authority: Pubkey,
    pub token_mint: Pubkey,
    pub user_ata: Pubkey,
    pub token_program: Pubkey,
}

/// Build an `InitSubscriptionAuthority` instruction. No data beyond the
/// discriminator.
pub fn build_initialize_subscription_authority_ix(
    program_id: Pubkey,
    accounts: InitializeSubscriptionAuthorityAccounts,
) -> Instruction {
    let system_program = Pubkey::from_str(SYSTEM_PROGRAM_ID).expect("valid system program id");
    let mut ix = GenInitSubscriptionAuthority {
        owner: to_addr(&accounts.owner),
        subscription_authority: to_addr(&accounts.subscription_authority),
        token_mint: to_addr(&accounts.token_mint),
        user_ata: to_addr(&accounts.user_ata),
        system_program: to_addr(&system_program),
        token_program: to_addr(&accounts.token_program),
    }
    .instruction();
    ix.program_id = to_addr(&program_id);
    ix
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_program_id_parses() {
        let p = default_program_id();
        assert_eq!(p.to_string(), SUBSCRIPTIONS_PROGRAM_ID);
    }

    #[test]
    fn pda_derivations_are_deterministic() {
        let program = default_program_id();
        let subscriber = Pubkey::new_unique();
        let mint = Pubkey::new_unique();

        let (a1, _b1) = find_subscription_authority_pda(&subscriber, &mint, &program);
        let (a2, _b2) = find_subscription_authority_pda(&subscriber, &mint, &program);
        assert_eq!(a1, a2);

        let plan_id = b"my-plan";
        let owner = Pubkey::new_unique();
        let (plan, _) = find_plan_pda(&owner, plan_id, &program);
        let (sub, _) = find_subscription_pda(&plan, &subscriber, &program);
        let (sub2, _) = find_subscription_pda(&plan, &subscriber, &program);
        assert_eq!(sub, sub2);
    }

    #[test]
    fn pda_derivations_differ_for_distinct_inputs() {
        let program = default_program_id();
        let s1 = Pubkey::new_unique();
        let s2 = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let (a1, _) = find_subscription_authority_pda(&s1, &mint, &program);
        let (a2, _) = find_subscription_authority_pda(&s2, &mint, &program);
        assert_ne!(a1, a2);
    }

    #[test]
    fn instruction_discriminators_match_spec() {
        assert_eq!(INSTRUCTION_SUBSCRIBE, 11);
        assert_eq!(INSTRUCTION_TRANSFER_SUBSCRIPTION, 10);
        assert_eq!(INSTRUCTION_CANCEL_SUBSCRIPTION, 12);
        assert_eq!(INSTRUCTION_INITIALIZE_SUBSCRIPTION_AUTHORITY, 0);
    }

    #[test]
    fn parse_pubkey_errors_on_invalid() {
        assert!(parse_pubkey("not-a-pubkey", "test").is_err());
    }

    // ── Data struct byte-layout fixtures ────────────────────────────────

    #[test]
    fn create_plan_data_to_bytes_has_expected_length() {
        let data = CreatePlanData {
            plan_id: 0x0102030405060708,
            mint: Pubkey::new_unique(),
            terms: PlanTerms {
                amount: 1_000_000,
                period_hours: 720,
                created_at: 0,
            },
            end_ts: 0,
            destinations: [Pubkey::default(); MAX_PLAN_DESTINATIONS],
            pullers: [Pubkey::default(); MAX_PLAN_PULLERS],
            metadata_uri: [0u8; PLAN_METADATA_URI_LEN],
        };
        let bytes = data.to_bytes();
        assert_eq!(bytes.len(), 1 + CREATE_PLAN_DATA_LEN);
        assert_eq!(bytes[0], INSTRUCTION_CREATE_PLAN);
        // plan_id little-endian sits right after the discriminator.
        assert_eq!(&bytes[1..9], &0x0102030405060708u64.to_le_bytes());
    }

    #[test]
    fn create_plan_data_new_zero_pads_metadata_uri() {
        let mint = Pubkey::new_unique();
        let data = CreatePlanData::new(
            7,
            mint,
            PlanTerms {
                amount: 1,
                period_hours: 24,
                created_at: 0,
            },
            0,
            [Pubkey::default(); 4],
            [Pubkey::default(); 4],
            "https://example.com/plan.json",
        )
        .unwrap();
        // First 29 bytes match the URI; the rest is zero-padded.
        assert_eq!(&data.metadata_uri[..29], b"https://example.com/plan.json");
        assert!(data.metadata_uri[29..].iter().all(|b| *b == 0));
    }

    #[test]
    fn create_plan_data_new_rejects_over_length_uri() {
        let mint = Pubkey::new_unique();
        let too_long: String = "x".repeat(PLAN_METADATA_URI_LEN + 1);
        let err = CreatePlanData::new(
            7,
            mint,
            PlanTerms {
                amount: 1,
                period_hours: 24,
                created_at: 0,
            },
            0,
            [Pubkey::default(); 4],
            [Pubkey::default(); 4],
            &too_long,
        )
        .unwrap_err();
        assert!(format!("{err}").contains("metadata_uri"));
    }

    #[test]
    fn subscribe_data_to_bytes_layout_matches_program() {
        let mint = Pubkey::new_unique();
        let data = SubscribeData {
            plan_id: 42,
            plan_bump: 254,
            expected_mint: mint,
            expected_amount: 10_000_000,
            expected_period_hours: 720,
            expected_created_at: 1_700_000_000,
            expected_subscription_authority_init_id: 0,
        };
        let bytes = data.to_bytes();
        assert_eq!(bytes.len(), 1 + SUBSCRIBE_DATA_LEN);
        assert_eq!(bytes[0], INSTRUCTION_SUBSCRIBE);
        assert_eq!(&bytes[1..9], &42u64.to_le_bytes());
        assert_eq!(bytes[9], 254);
        assert_eq!(&bytes[10..42], mint.as_ref());
    }

    #[test]
    fn transfer_data_to_bytes_supports_each_transfer_discriminator() {
        let data = TransferData {
            amount: 1_000,
            delegator: Pubkey::new_unique(),
            mint: Pubkey::new_unique(),
        };
        let xfer_sub = data.to_bytes(INSTRUCTION_TRANSFER_SUBSCRIPTION);
        assert_eq!(xfer_sub[0], INSTRUCTION_TRANSFER_SUBSCRIPTION);
        assert_eq!(xfer_sub.len(), 1 + TRANSFER_DATA_LEN);
        let xfer_fixed = data.to_bytes(INSTRUCTION_TRANSFER_FIXED);
        assert_eq!(xfer_fixed[0], INSTRUCTION_TRANSFER_FIXED);
    }

    // ── Instruction builder shape ───────────────────────────────────────

    fn dummy_create_plan_data() -> CreatePlanData {
        CreatePlanData::new(
            7,
            Pubkey::new_unique(),
            PlanTerms {
                amount: 1,
                period_hours: 24,
                created_at: 0,
            },
            0,
            [Pubkey::default(); 4],
            [Pubkey::default(); 4],
            "",
        )
        .unwrap()
    }

    #[test]
    fn build_create_plan_ix_emits_five_account_metas_in_program_order() {
        let program = default_program_id();
        let merchant = Pubkey::new_unique();
        let plan_pda = Pubkey::new_unique();
        let token_mint = Pubkey::new_unique();
        let token_program =
            Pubkey::from_str(crate::protocol::solana::programs::TOKEN_PROGRAM).unwrap();
        let data = dummy_create_plan_data();
        let ix = build_create_plan_ix(
            program,
            CreatePlanAccounts {
                merchant,
                plan_pda,
                token_mint,
                token_program,
            },
            &data,
        );
        assert_eq!(ix.program_id, program);
        assert_eq!(ix.accounts.len(), 5);
        assert_eq!(ix.accounts[0].pubkey, merchant);
        assert!(ix.accounts[0].is_signer);
        assert!(ix.accounts[0].is_writable);
        assert_eq!(ix.accounts[1].pubkey, plan_pda);
        assert!(ix.accounts[1].is_writable);
        assert!(!ix.accounts[1].is_signer);
        assert_eq!(ix.accounts[2].pubkey, token_mint);
        assert!(!ix.accounts[2].is_writable);
        // System program at slot 3, token program at slot 4.
        assert_eq!(
            ix.accounts[3].pubkey,
            Pubkey::from_str(SYSTEM_PROGRAM_ID).unwrap()
        );
        assert_eq!(ix.accounts[4].pubkey, token_program);
        assert_eq!(ix.data[0], INSTRUCTION_CREATE_PLAN);
    }

    #[test]
    fn build_subscribe_ix_includes_optional_payer_when_set() {
        let program = default_program_id();
        let subscriber = Pubkey::new_unique();
        let accounts = SubscribeAccounts {
            subscriber,
            merchant: Pubkey::new_unique(),
            plan_pda: Pubkey::new_unique(),
            subscription_pda: Pubkey::new_unique(),
            subscription_authority_pda: Pubkey::new_unique(),
            event_authority: find_event_authority_pda(&program).0,
            payer: Some(Pubkey::new_unique()),
        };
        let data = SubscribeData {
            plan_id: 7,
            plan_bump: 255,
            expected_mint: Pubkey::new_unique(),
            expected_amount: 1,
            expected_period_hours: 24,
            expected_created_at: 0,
            expected_subscription_authority_init_id: 0,
        };
        let ix = build_subscribe_ix(program, accounts, &data);
        // 8 base accounts + payer = 9.
        assert_eq!(ix.accounts.len(), 9);
        assert!(ix.accounts[8].is_signer);
        assert!(ix.accounts[8].is_writable);
        assert_eq!(ix.data[0], INSTRUCTION_SUBSCRIBE);
    }

    #[test]
    fn build_subscribe_ix_omits_payer_when_unset() {
        let program = default_program_id();
        let accounts = SubscribeAccounts {
            subscriber: Pubkey::new_unique(),
            merchant: Pubkey::new_unique(),
            plan_pda: Pubkey::new_unique(),
            subscription_pda: Pubkey::new_unique(),
            subscription_authority_pda: Pubkey::new_unique(),
            event_authority: find_event_authority_pda(&program).0,
            payer: None,
        };
        let data = SubscribeData {
            plan_id: 7,
            plan_bump: 255,
            expected_mint: Pubkey::new_unique(),
            expected_amount: 1,
            expected_period_hours: 24,
            expected_created_at: 0,
            expected_subscription_authority_init_id: 0,
        };
        let ix = build_subscribe_ix(program, accounts, &data);
        assert_eq!(ix.accounts.len(), 8);
    }

    #[test]
    fn build_transfer_subscription_ix_marks_only_caller_as_signer() {
        let program = default_program_id();
        let accounts = TransferSubscriptionAccounts {
            subscription_pda: Pubkey::new_unique(),
            plan_pda: Pubkey::new_unique(),
            subscription_authority: Pubkey::new_unique(),
            delegator_ata: Pubkey::new_unique(),
            receiver_ata: Pubkey::new_unique(),
            caller: Pubkey::new_unique(),
            token_mint: Pubkey::new_unique(),
            token_program: Pubkey::from_str(crate::protocol::solana::programs::TOKEN_PROGRAM)
                .unwrap(),
            event_authority: find_event_authority_pda(&program).0,
        };
        let data = TransferData {
            amount: 1_000_000,
            delegator: Pubkey::new_unique(),
            mint: Pubkey::new_unique(),
        };
        let ix = build_transfer_subscription_ix(program, accounts, &data);
        assert_eq!(ix.accounts.len(), 10);
        // Exactly one signer: the caller (puller) at index 5.
        let signers: Vec<usize> = ix
            .accounts
            .iter()
            .enumerate()
            .filter_map(|(i, m)| if m.is_signer { Some(i) } else { None })
            .collect();
        assert_eq!(signers, vec![5]);
        assert_eq!(ix.data[0], INSTRUCTION_TRANSFER_SUBSCRIPTION);
    }

    #[test]
    fn build_cancel_subscription_ix_uses_subscriber_signer_only() {
        let program = default_program_id();
        let subscriber = Pubkey::new_unique();
        let ix = build_cancel_subscription_ix(
            program,
            CancelSubscriptionAccounts {
                subscriber,
                plan_pda: Pubkey::new_unique(),
                subscription_pda: Pubkey::new_unique(),
                event_authority: find_event_authority_pda(&program).0,
            },
        );
        assert_eq!(ix.accounts.len(), 5);
        assert!(ix.accounts[0].is_signer);
        assert!(ix.accounts[0].is_writable);
        // Subscription PDA writable at slot 2.
        assert!(ix.accounts[2].is_writable);
        assert_eq!(ix.data, vec![INSTRUCTION_CANCEL_SUBSCRIPTION]);
    }

    #[test]
    fn build_initialize_subscription_authority_ix_account_shape() {
        let program = default_program_id();
        let owner = Pubkey::new_unique();
        let token_program =
            Pubkey::from_str(crate::protocol::solana::programs::TOKEN_PROGRAM).unwrap();
        let ix = build_initialize_subscription_authority_ix(
            program,
            InitializeSubscriptionAuthorityAccounts {
                owner,
                subscription_authority: Pubkey::new_unique(),
                token_mint: Pubkey::new_unique(),
                user_ata: Pubkey::new_unique(),
                token_program,
            },
        );
        assert_eq!(ix.program_id, program);
        assert_eq!(ix.accounts.len(), 6);
        assert!(ix.accounts[0].is_signer && ix.accounts[0].is_writable); // owner
        assert!(ix.accounts[1].is_writable && !ix.accounts[1].is_signer); // authority PDA
        assert!(!ix.accounts[2].is_writable); // mint
        assert!(ix.accounts[3].is_writable && !ix.accounts[3].is_signer); // user ATA
        assert_eq!(ix.data, vec![INSTRUCTION_INITIALIZE_SUBSCRIPTION_AUTHORITY]);
    }

    /// Locks the known IDL discrepancy: `build_cancel_subscription_ix` is the one
    /// builder NOT delegated to the generated client because the vendored IDL
    /// marks the subscriber read-only, while the program treats it as a writable
    /// signer (rent refund). Both agree it is a signer. If the writable
    /// assertion fails the IDL was fixed — regenerate and switch
    /// `build_cancel_subscription_ix` to the generated builder.
    #[test]
    fn generated_cancel_subscription_idl_still_diverges_from_program() {
        use subscriptions_client::generated::instructions::CancelSubscription as Gen;
        let gen = Gen {
            subscriber: to_addr(&Pubkey::new_unique()),
            plan_pda: to_addr(&Pubkey::new_unique()),
            subscription_pda: to_addr(&Pubkey::new_unique()),
            event_authority: to_addr(&Pubkey::new_unique()),
            self_program: to_addr(&default_program_id()),
        }
        .instruction();
        // Both sides agree the subscriber signs.
        assert!(gen.accounts[0].is_signer);
        // The divergence: the IDL marks it read-only; we require writable.
        assert!(
            !gen.accounts[0].is_writable,
            "IDL cancel subscriber is now writable — migrate cancel to the generated builder"
        );
    }

    #[test]
    fn find_event_authority_pda_is_deterministic() {
        let program = default_program_id();
        let (a, _) = find_event_authority_pda(&program);
        let (b, _) = find_event_authority_pda(&program);
        assert_eq!(a, b);
    }

    #[test]
    fn plan_id_seed_round_trips_u64() {
        let id: u64 = 0xdeadbeef1234;
        let seed = plan_id_seed(id);
        assert_eq!(u64::from_le_bytes(seed), id);
    }
}
