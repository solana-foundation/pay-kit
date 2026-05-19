//! Typed helpers for the subscriptions program.
//!
//! Hand-written PDA derivations, program-ID constants, and instruction
//! discriminators for the subscriptions program. The on-chain program is
//! published at `solana-program-subscriptions`; this module is intentionally
//! dependency-light so v0 of the mpp-sdk does not bind to the Codama-generated
//! client crate. A follow-up should adopt the Codama client and re-export it
//! the same way `payment_channels::generated` is re-exported.

use std::str::FromStr;

use solana_pubkey::Pubkey;

use crate::error::{Error, Result};

/// Canonical mainnet program ID for the subscriptions program.
pub const SUBSCRIPTIONS_PROGRAM_ID: &str = "De1egAFMkMWZSN5rYXRj9CAdheBamobVNubTsi9avR44";

/// PDA seed prefix for the `SubscriptionAuthority` account.
pub const SUBSCRIPTION_AUTHORITY_SEED: &[u8] = b"SubscriptionAuthority";

/// PDA seed prefix for the `SubscriptionDelegation` account.
pub const SUBSCRIPTION_DELEGATION_SEED: &[u8] = b"subscription";

/// PDA seed prefix for the `Plan` account.
pub const PLAN_SEED: &[u8] = b"plan";

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
pub fn find_plan_pda(owner: &Pubkey, plan_id: &[u8], program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[PLAN_SEED, owner.as_ref(), plan_id], program_id)
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
}
