//! Multi-delegator program state assessment.
//!
//! Multi-delegator accounts are **long-lived** — they persist across many
//! sessions.  A client may already have a `MultiDelegate` PDA and a
//! `FixedDelegation` with sufficient cap from a previous session, in which
//! case no on-chain action is needed.
//!
//! When a client opens a pull-mode session they pre-sign **both** potential
//! setup transactions (`initMultiDelegateTx` and `updateDelegationTx`) and
//! attach them to the `open` payload.  The server fetches the current on-chain
//! state, calls [`assess_multi_delegate_setup`] to decide which action (if any)
//! to take, and submits the corresponding transaction.
//!
//! # Decision matrix
//!
//! | MultiDelegate PDA | FixedDelegation cap      | Action                    |
//! |-------------------|--------------------------|---------------------------|
//! | does not exist    | —                        | [`SubmitInit`]            |
//! | exists            | None or < required       | [`SubmitUpdate`]          |
//! | exists            | ≥ required               | [`AlreadySufficient`]     |
//!
//! Missing required payloads surface as [`MissingPayload`] errors so the
//! operator can return a descriptive 402 to the client.
//!
//! [`SubmitInit`]: MultiDelegateSetupAction::SubmitInit
//! [`SubmitUpdate`]: MultiDelegateSetupAction::SubmitUpdate
//! [`AlreadySufficient`]: MultiDelegateSetupAction::AlreadySufficient
//! [`MissingPayload`]: MultiDelegateSetupAction::MissingPayload

/// Current on-chain state for a (client, operator) multi-delegator pair.
///
/// Fetched by the server from the Solana RPC before deciding what action
/// to take.  Both fields are independent: a `MultiDelegate` PDA can exist
/// without a `FixedDelegation` for this specific operator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultiDelegateOnChainState {
    /// Whether the `MultiDelegate` PDA exists for `(owner, mint)`.
    pub multi_delegate_exists: bool,

    /// Current cap of the `FixedDelegation` PDA for this `(operator, owner)` pair.
    ///
    /// `None` means the account does not exist (no delegation set up yet).
    /// `Some(cap)` is the maximum amount the operator is currently authorised
    /// to transfer — this may be from a previous session.
    pub existing_delegation_cap: Option<u64>,
}

/// Reason a required transaction payload is absent from the client's `open` action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MissingPayloadReason {
    /// The `MultiDelegate` PDA does not exist but the client did not include
    /// `initMultiDelegateTx`.
    NoInitTx,
    /// The delegation cap is insufficient but the client did not include
    /// `updateDelegationTx`.
    NoUpdateTx,
}

impl std::fmt::Display for MissingPayloadReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoInitTx => write!(
                f,
                "MultiDelegate PDA does not exist — provide initMultiDelegateTx"
            ),
            Self::NoUpdateTx => write!(
                f,
                "delegation cap insufficient — provide updateDelegationTx"
            ),
        }
    }
}

/// The on-chain setup action the operator must perform before accepting a
/// pull-mode session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MultiDelegateSetupAction {
    /// Existing delegation already covers the session cap — no on-chain action
    /// needed.  The most common outcome for returning clients.
    AlreadySufficient,

    /// Submit `initMultiDelegateTx`: creates the `MultiDelegate` PDA and an
    /// initial `FixedDelegation`.  Required when the client has never delegated
    /// to this operator before.
    SubmitInit,

    /// Submit `updateDelegationTx`: creates or raises the `FixedDelegation`
    /// cap.  Required when the `MultiDelegate` PDA exists but the current cap
    /// is below the session amount.
    SubmitUpdate,

    /// A required transaction payload was not provided by the client.
    MissingPayload(MissingPayloadReason),
}

impl std::fmt::Display for MultiDelegateSetupAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadySufficient => write!(f, "already sufficient — no tx needed"),
            Self::SubmitInit => write!(f, "submit initMultiDelegateTx"),
            Self::SubmitUpdate => write!(f, "submit updateDelegationTx"),
            Self::MissingPayload(r) => write!(f, "missing payload: {r}"),
        }
    }
}

/// Determine the on-chain setup action required for a pull-mode session open.
///
/// This is a **pure function** — all IO (RPC fetches, tx submission) is the
/// caller's responsibility.
///
/// # Arguments
///
/// - `state`         — on-chain state fetched by the server
/// - `required_cap`  — the delegation amount the new session needs
/// - `has_init_tx`   — whether the client provided `initMultiDelegateTx`
/// - `has_update_tx` — whether the client provided `updateDelegationTx`
///
/// # Decision logic
///
/// ```text
/// if !multi_delegate_exists:
///     if has_init_tx  → SubmitInit
///     else            → MissingPayload(NoInitTx)
/// elif existing_cap < required_cap:   // includes None (no delegation)
///     if has_update_tx → SubmitUpdate
///     else             → MissingPayload(NoUpdateTx)
/// else:
///     AlreadySufficient
/// ```
pub fn assess_multi_delegate_setup(
    state: &MultiDelegateOnChainState,
    required_cap: u64,
    has_init_tx: bool,
    has_update_tx: bool,
) -> MultiDelegateSetupAction {
    if !state.multi_delegate_exists {
        if has_init_tx {
            MultiDelegateSetupAction::SubmitInit
        } else {
            MultiDelegateSetupAction::MissingPayload(MissingPayloadReason::NoInitTx)
        }
    } else {
        let cap_sufficient = state
            .existing_delegation_cap
            .is_some_and(|cap| cap >= required_cap);

        if cap_sufficient {
            MultiDelegateSetupAction::AlreadySufficient
        } else if has_update_tx {
            MultiDelegateSetupAction::SubmitUpdate
        } else {
            MultiDelegateSetupAction::MissingPayload(MissingPayloadReason::NoUpdateTx)
        }
    }
}

// ── Solana instruction builders ───────────────────────────────────────────────
//
// Pure functions: derive PDAs locally and encode instruction data in the exact
// layout expected by the on-chain multi-delegator program.  No I/O performed.

use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

/// Canonical mainnet multi-delegator program address.
pub const MULTI_DELEGATOR_PROGRAM_ID: &str = "EPEUTog1kptYkthDJF6MuB1aM4aDAwHYwoF32Rzv5rqg";

/// PDA seed prefix for `MultiDelegate` accounts.
pub const MULTI_DELEGATE_SEED: &[u8] = b"MultiDelegate";

/// PDA seed prefix for delegation accounts (fixed, recurring, etc.).
pub const DELEGATION_SEED: &[u8] = b"delegation";

/// Derive the `MultiDelegate` PDA for `(user, mint)`.
///
/// Seeds: `[b"MultiDelegate", user, mint]` → `program_id`
pub fn find_multi_delegate_pda(user: &Pubkey, mint: &Pubkey, program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[MULTI_DELEGATE_SEED, user.as_ref(), mint.as_ref()],
        program_id,
    )
}

/// Derive the `FixedDelegation` PDA for `(multi_delegate, delegator, delegatee, nonce)`.
///
/// Seeds: `[b"delegation", multi_delegate, delegator, delegatee, nonce_le_bytes]` → `program_id`
pub fn find_fixed_delegation_pda(
    multi_delegate: &Pubkey,
    delegator: &Pubkey,
    delegatee: &Pubkey,
    nonce: u64,
    program_id: &Pubkey,
) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[
            DELEGATION_SEED,
            multi_delegate.as_ref(),
            delegator.as_ref(),
            delegatee.as_ref(),
            &nonce.to_le_bytes(),
        ],
        program_id,
    )
}

/// Build an `InitMultiDelegate` instruction (disc = 0x00).
///
/// Creates the `MultiDelegate` PDA for `(user, mint)` and approves it as
/// the SPL Token delegate on `user_ata` with a `u64::MAX` allowance.
///
/// Account order (matches the on-chain program):
/// 0. `user`           — signer, writable
/// 1. `multi_delegate` — writable (PDA derived here)
/// 2. `token_mint`     — read-only
/// 3. `user_ata`       — writable
/// 4. `system_program` — read-only
/// 5. `token_program`  — read-only
pub fn build_init_multi_delegate_ix(
    program_id: &Pubkey,
    user: &Pubkey,
    mint: &Pubkey,
    user_ata: &Pubkey,
    token_program: &Pubkey,
) -> Instruction {
    let (multi_delegate_pda, _) = find_multi_delegate_pda(user, mint, program_id);
    // System program: 11111111111111111111111111111111 = all-zero bytes = Pubkey::default()
    let system_program = Pubkey::default();
    Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(*user, true),
            AccountMeta::new(multi_delegate_pda, false),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new(*user_ata, false),
            AccountMeta::new_readonly(system_program, false),
            AccountMeta::new_readonly(*token_program, false),
        ],
        data: vec![0x00],
    }
}

/// Build a `CreateFixedDelegation` instruction (disc = 0x01).
///
/// Creates a `FixedDelegation` PDA capping the delegatee to `amount` tokens,
/// expiring at `expiry_ts` (Unix seconds; `0` = never expires).
///
/// Instruction data layout: `[0x01] ++ nonce_le ++ amount_le ++ expiry_ts_le`
///
/// Account order:
/// 0. `delegator`      — signer, writable
/// 1. `multi_delegate` — read-only
/// 2. `delegation_pda` — writable (created by this instruction)
/// 3. `delegatee`      — read-only
/// 4. `system_program` — read-only
///
/// (No optional 6th payer — `delegator` pays rent.)
#[allow(clippy::too_many_arguments)]
pub fn build_create_fixed_delegation_ix(
    program_id: &Pubkey,
    delegator: &Pubkey,
    multi_delegate_pda: &Pubkey,
    delegation_pda: &Pubkey,
    delegatee: &Pubkey,
    nonce: u64,
    amount: u64,
    expiry_ts: i64,
) -> Instruction {
    let system_program = Pubkey::default();
    let mut data = Vec::with_capacity(25);
    data.push(0x01);
    data.extend_from_slice(&nonce.to_le_bytes());
    data.extend_from_slice(&amount.to_le_bytes());
    data.extend_from_slice(&expiry_ts.to_le_bytes());
    Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(*delegator, true),
            AccountMeta::new_readonly(*multi_delegate_pda, false),
            AccountMeta::new(*delegation_pda, false),
            AccountMeta::new_readonly(*delegatee, false),
            AccountMeta::new_readonly(system_program, false),
        ],
        data,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helper ────────────────────────────────────────────────────────────────

    fn state(exists: bool, cap: Option<u64>) -> MultiDelegateOnChainState {
        MultiDelegateOnChainState {
            multi_delegate_exists: exists,
            existing_delegation_cap: cap,
        }
    }

    const REQ: u64 = 1_000_000;

    // ── No MultiDelegate PDA ──────────────────────────────────────────────────

    #[test]
    fn no_multi_delegate_with_init_tx_returns_submit_init() {
        let action = assess_multi_delegate_setup(&state(false, None), REQ, true, false);
        assert_eq!(action, MultiDelegateSetupAction::SubmitInit);
    }

    #[test]
    fn no_multi_delegate_without_init_tx_returns_missing_init() {
        let action = assess_multi_delegate_setup(&state(false, None), REQ, false, false);
        assert_eq!(
            action,
            MultiDelegateSetupAction::MissingPayload(MissingPayloadReason::NoInitTx)
        );
    }

    #[test]
    fn no_multi_delegate_with_both_txs_uses_init_not_update() {
        // When MultiDelegate doesn't exist, init takes priority even if update tx is also present.
        let action = assess_multi_delegate_setup(&state(false, None), REQ, true, true);
        assert_eq!(action, MultiDelegateSetupAction::SubmitInit);
    }

    #[test]
    fn no_multi_delegate_with_update_tx_only_returns_missing_init() {
        // update_tx alone is insufficient when MultiDelegate doesn't exist yet.
        let action = assess_multi_delegate_setup(&state(false, None), REQ, false, true);
        assert_eq!(
            action,
            MultiDelegateSetupAction::MissingPayload(MissingPayloadReason::NoInitTx)
        );
    }

    // ── MultiDelegate exists, no FixedDelegation ──────────────────────────────

    #[test]
    fn multi_delegate_exists_no_delegation_with_update_tx_returns_submit_update() {
        let action = assess_multi_delegate_setup(&state(true, None), REQ, false, true);
        assert_eq!(action, MultiDelegateSetupAction::SubmitUpdate);
    }

    #[test]
    fn multi_delegate_exists_no_delegation_without_update_tx_returns_missing_update() {
        let action = assess_multi_delegate_setup(&state(true, None), REQ, false, false);
        assert_eq!(
            action,
            MultiDelegateSetupAction::MissingPayload(MissingPayloadReason::NoUpdateTx)
        );
    }

    #[test]
    fn multi_delegate_exists_no_delegation_with_both_txs_uses_update() {
        // MultiDelegate exists — only need to create the FixedDelegation.
        let action = assess_multi_delegate_setup(&state(true, None), REQ, true, true);
        assert_eq!(action, MultiDelegateSetupAction::SubmitUpdate);
    }

    // ── MultiDelegate + FixedDelegation: cap boundary checks ─────────────────

    #[test]
    fn exact_cap_returns_already_sufficient() {
        let action = assess_multi_delegate_setup(&state(true, Some(REQ)), REQ, false, false);
        assert_eq!(action, MultiDelegateSetupAction::AlreadySufficient);
    }

    #[test]
    fn cap_above_required_returns_already_sufficient() {
        let action = assess_multi_delegate_setup(&state(true, Some(REQ + 1)), REQ, false, false);
        assert_eq!(action, MultiDelegateSetupAction::AlreadySufficient);
    }

    #[test]
    fn large_existing_cap_always_sufficient() {
        let action = assess_multi_delegate_setup(&state(true, Some(u64::MAX)), REQ, false, false);
        assert_eq!(action, MultiDelegateSetupAction::AlreadySufficient);
    }

    #[test]
    fn cap_one_below_required_with_update_tx_returns_submit_update() {
        let action = assess_multi_delegate_setup(&state(true, Some(REQ - 1)), REQ, false, true);
        assert_eq!(action, MultiDelegateSetupAction::SubmitUpdate);
    }

    #[test]
    fn cap_one_below_required_without_update_tx_returns_missing_update() {
        let action = assess_multi_delegate_setup(&state(true, Some(REQ - 1)), REQ, false, false);
        assert_eq!(
            action,
            MultiDelegateSetupAction::MissingPayload(MissingPayloadReason::NoUpdateTx)
        );
    }

    #[test]
    fn zero_cap_with_update_tx_returns_submit_update() {
        let action = assess_multi_delegate_setup(&state(true, Some(0)), REQ, false, true);
        assert_eq!(action, MultiDelegateSetupAction::SubmitUpdate);
    }

    // ── AlreadySufficient ignores available txs ───────────────────────────────

    #[test]
    fn sufficient_cap_ignores_update_tx_if_provided() {
        // Even if the client sent an update tx, don't submit it — cap is fine.
        let action = assess_multi_delegate_setup(&state(true, Some(5 * REQ)), REQ, false, true);
        assert_eq!(action, MultiDelegateSetupAction::AlreadySufficient);
    }

    #[test]
    fn sufficient_cap_ignores_both_txs_if_provided() {
        let action = assess_multi_delegate_setup(&state(true, Some(5 * REQ)), REQ, true, true);
        assert_eq!(action, MultiDelegateSetupAction::AlreadySufficient);
    }

    // ── Zero required_cap edge case ───────────────────────────────────────────

    #[test]
    fn zero_required_cap_with_any_existing_cap_is_sufficient() {
        let action = assess_multi_delegate_setup(&state(true, Some(1)), 0, false, false);
        assert_eq!(action, MultiDelegateSetupAction::AlreadySufficient);
    }

    #[test]
    fn zero_required_cap_with_zero_existing_cap_is_sufficient() {
        // 0 >= 0
        let action = assess_multi_delegate_setup(&state(true, Some(0)), 0, false, false);
        assert_eq!(action, MultiDelegateSetupAction::AlreadySufficient);
    }

    // ── Display ───────────────────────────────────────────────────────────────

    #[test]
    fn display_already_sufficient_mentions_no_tx() {
        let s = MultiDelegateSetupAction::AlreadySufficient.to_string();
        assert!(s.contains("sufficient"), "got: {s}");
    }

    #[test]
    fn display_submit_init_mentions_init_tx() {
        let s = MultiDelegateSetupAction::SubmitInit.to_string();
        assert!(s.contains("initMultiDelegateTx"), "got: {s}");
    }

    #[test]
    fn display_submit_update_mentions_update_tx() {
        let s = MultiDelegateSetupAction::SubmitUpdate.to_string();
        assert!(s.contains("updateDelegationTx"), "got: {s}");
    }

    #[test]
    fn display_missing_init_mentions_init_tx() {
        let s =
            MultiDelegateSetupAction::MissingPayload(MissingPayloadReason::NoInitTx).to_string();
        assert!(s.contains("initMultiDelegateTx"), "got: {s}");
    }

    #[test]
    fn display_missing_update_mentions_update_tx() {
        let s =
            MultiDelegateSetupAction::MissingPayload(MissingPayloadReason::NoUpdateTx).to_string();
        assert!(s.contains("updateDelegationTx"), "got: {s}");
    }
}
