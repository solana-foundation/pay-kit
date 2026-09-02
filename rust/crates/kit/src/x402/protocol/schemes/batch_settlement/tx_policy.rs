//! Acceptance policy for client-supplied transactions the sponsor co-signs.
//!
//! A `deposit` or `refund` payload carries a transaction the *client* built and
//! signed. The sponsor adds the fee-payer signature and broadcasts it, so its
//! signature authorizes whatever that transaction does. Simulation is not a
//! substitute for these checks: it runs only after the signature already
//! authorized fee — and, for `open`, channel PDA and escrow ATA rent —
//! expenditure.
//!
//! So every transaction is validated statically and exactly: no address lookup
//! tables, a fixed signer set, a bounded ComputeBudget prefix, exactly one
//! canonical payment-channels instruction with a pinned account table and fully
//! decoded arguments, and a Memo/Lighthouse suffix that may not name the fee
//! payer. Outside the prescribed `open` rent roles, the sponsor's signature
//! authorizes network fees and nothing else.
//!
//! See `specs/schemes/batch-settlement/scheme_batch_settlement_svm.md` §5.

use solana_message::compiled_instruction::CompiledInstruction;
use solana_pubkey::Pubkey;
use solana_transaction::versioned::VersionedTransaction;

use crate::core::payment_channels as pc;

use super::errors::{self, BatchError};
use super::types::BatchChannelConfig;

type Result<T> = std::result::Result<T, BatchError>;

/// `open` instruction discriminator in the payment-channels program.
const OPEN_DISCRIMINATOR: u8 = 1;

/// `top_up` instruction discriminator.
const TOP_UP_DISCRIMINATOR: u8 = 3;

/// `request_close` instruction discriminator.
const REQUEST_CLOSE_DISCRIMINATOR: u8 = 5;

/// Serialized size of one `DistributionEntry`: a 32-byte recipient plus a
/// little-endian `u16` share.
const DISTRIBUTION_ENTRY_LEN: usize = 34;

/// Byte length of `open` args before the Borsh-encoded recipients vector:
/// discriminator, `salt`, `deposit`, `grace_period`, `open_slot`.
const OPEN_ARGS_PREFIX_LEN: usize = 1 + 8 + 8 + 4 + 8;

/// Which setup form a `deposit` payload carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupForm {
    /// A new channel: the program creates the PDA and escrow ATA, and debits
    /// their rent from the sponsor.
    Open,
    /// More escrow for an existing channel. The sponsor pays the network fee
    /// and nothing else.
    TopUp,
}

impl SetupForm {
    fn label(self) -> &'static str {
        match self {
            SetupForm::Open => "open",
            SetupForm::TopUp => "top_up",
        }
    }

    fn discriminator(self) -> u8 {
        match self {
            SetupForm::Open => OPEN_DISCRIMINATOR,
            SetupForm::TopUp => TOP_UP_DISCRIMINATOR,
        }
    }
}

/// Read the setup instruction discriminator from a client transaction.
///
/// The form is a property of the signed transaction, not of whether the
/// server happened to persist a channel record. This matters when an `open`
/// landed but its voucher commit did not: retrying that same transaction must
/// remain an `open`.
pub fn setup_form_from_transaction(
    transaction_b64: &str,
    program_id: &Pubkey,
) -> Result<SetupForm> {
    let tx = decode(transaction_b64, "setup")?;
    let keys = tx.message.static_account_keys();
    let forms: Vec<_> = tx
        .message
        .instructions()
        .iter()
        .filter_map(|ix| {
            (keys.get(usize::from(ix.program_id_index)) == Some(program_id))
                .then_some(ix.data.first().copied())
                .flatten()
        })
        .filter_map(|discriminator| match discriminator {
            OPEN_DISCRIMINATOR => Some(SetupForm::Open),
            TOP_UP_DISCRIMINATOR => Some(SetupForm::TopUp),
            _ => None,
        })
        .collect();
    match forms.as_slice() {
        [form] => Ok(*form),
        _ => Err(BatchError::new(
            errors::INVALID_SETUP_TRANSACTION,
            "transaction must contain exactly one open or top_up instruction",
        )),
    }
}

/// Everything a client-supplied transaction is checked against.
///
/// These come from the requirements the server advertised and the channel
/// configuration the client echoed back — never from the transaction itself.
#[derive(Debug, Clone)]
pub struct TransactionExpectations<'a> {
    /// Canonical payment-channels program for the selected network.
    pub program_id: &'a Pubkey,
    /// `extra.feePayer`: the sponsor, transaction fee payer, channel
    /// `rent_payer`, and zero-share `payee`.
    pub fee_payer: &'a Pubkey,
    /// The channel configuration carried on the payload.
    pub config: &'a BatchChannelConfig,
    /// The channel PDA derived from `config`.
    pub channel_id: &'a Pubkey,
    /// Onchain owner of the mint, already confirmed against `extra.tokenProgram`.
    pub token_program: &'a Pubkey,
    /// `payTo`: the sole distribution recipient, at 10,000 bps.
    pub receiver: &'a Pubkey,
    /// `extra.memo`, when the seller declared one.
    pub memo: Option<&'a str>,
}

/// A validated client transaction, ready for the sponsor to co-sign.
#[derive(Debug)]
pub struct ValidatedTransaction {
    /// The decoded transaction. Only the fee-payer signature slot is missing.
    pub transaction: VersionedTransaction,
    /// The channel payer, whose signature was verified.
    pub payer: Pubkey,
}

/// Validate a client-signed `open` or `top_up` transaction.
///
/// `deposit_amount` is the payload's declared `deposit.amount`; the decoded
/// instruction must fund exactly that. `recent_slot`, when known, bounds
/// `open_slot` to the program's freshness window so the sponsor rejects a stale
/// transaction before paying to learn the program would.
pub fn validate_setup_transaction(
    transaction_b64: &str,
    form: SetupForm,
    expected: &TransactionExpectations<'_>,
    deposit_amount: u64,
    recent_slot: Option<u64>,
) -> Result<ValidatedTransaction> {
    let label = form.label();
    let tx = decode(transaction_b64, label)?;
    let payer = check_envelope(&tx, expected, label)?;
    let keys = tx.message.static_account_keys();
    let ix = pc::scan_channel_tx_layout(
        &tx,
        keys,
        expected.program_id,
        form.discriminator(),
        label,
        // The Memo is required so the sponsor can correlate the transaction it
        // paid for; when the seller declared `extra.memo` its bytes are pinned.
        pc::MemoPolicy::Required(expected.memo),
    )
    .map_err(|e| BatchError::new(errors::INVALID_SETUP_TRANSACTION, e.to_string()))?;

    match form {
        SetupForm::Open => {
            check_open_accounts(ix, keys, &payer, expected, label)?;
            check_open_args(ix, expected, deposit_amount, recent_slot)?;
            // Positions 2 (payee) and 4 (authorized_signer) are deliberately
            // absent: message compilation deduplicates equal keys and unions
            // their privileges, so both are legitimately writable and signing
            // when they coincide with rent_payer / payer. Those prescribed
            // unions must not cause rejection.
            for (position, role) in [
                (0, "payer"),
                (1, "rent_payer"),
                (5, "channel"),
                (6, "payer_token_account"),
                (7, "channel_token_account"),
            ] {
                check_privileges(&tx, ix, position, Privilege::Writable, role, label)?;
            }
        }
        SetupForm::TopUp => {
            check_top_up_accounts(ix, keys, &payer, expected, label)?;
            check_top_up_args(ix, deposit_amount, label)?;
            for (position, role) in [
                (0, "payer"),
                (1, "channel"),
                (2, "payer_token_account"),
                (3, "channel_token_account"),
            ] {
                check_privileges(&tx, ix, position, Privilege::Writable, role, label)?;
            }
            // In this form the sponsor is not an instruction account at all: it
            // is not an authority, source, or delegate, and its signature
            // covers only the bounded network fee.
            reject_fee_payer_account(ix, keys, expected.fee_payer, label)?;
        }
    }
    Ok(ValidatedTransaction {
        transaction: tx,
        payer,
    })
}

/// Validate a client-signed `request_close` transaction.
///
/// The refund path is the interoperable channel close: the client authorizes
/// the transition, the sponsor only pays for it. The transaction must therefore
/// carry nothing but the `request_close` — no `seal`, `settle_and_seal`,
/// `distribute`, or token movement can ride along, since the sponsor's
/// signature would authorize those too.
pub fn validate_request_close_transaction(
    transaction_b64: &str,
    expected: &TransactionExpectations<'_>,
) -> Result<ValidatedTransaction> {
    let label = "request_close";
    let tx = decode(transaction_b64, label)
        .map_err(|e| BatchError::new(errors::INVALID_REFUND_TRANSACTION, e.detail))?;
    let payer = check_envelope(&tx, expected, label)
        .map_err(|e| BatchError::new(errors::INVALID_REFUND_TRANSACTION, e.detail))?;
    let keys = tx.message.static_account_keys();
    let ix = pc::scan_channel_tx_layout(
        &tx,
        keys,
        expected.program_id,
        REQUEST_CLOSE_DISCRIMINATOR,
        label,
        pc::MemoPolicy::Required(expected.memo),
    )
    .map_err(|e| BatchError::new(errors::INVALID_REFUND_TRANSACTION, e.to_string()))?;

    let refund_err = |detail: String| BatchError::new(errors::INVALID_REFUND_TRANSACTION, detail);
    if ix.accounts.len() != 2 {
        return Err(refund_err(format!(
            "request_close must have exactly 2 accounts, got {}",
            ix.accounts.len()
        )));
    }
    expect_account(ix, keys, 0, &payer, "payer", label).map_err(|e| refund_err(e.detail))?;
    expect_account(ix, keys, 1, expected.channel_id, "channel", label)
        .map_err(|e| refund_err(e.detail))?;
    if ix.data.len() != 1 {
        return Err(refund_err(format!(
            "request_close takes no arguments, got {} data bytes",
            ix.data.len()
        )));
    }
    check_privileges(&tx, ix, 1, Privilege::Writable, "channel", label)
        .map_err(|e| refund_err(e.detail))?;
    // The sponsor must not be an account of the close instruction: its
    // signature covers the network fee only.
    reject_fee_payer_account(ix, keys, expected.fee_payer, label)
        .map_err(|e| refund_err(e.detail))?;

    Ok(ValidatedTransaction {
        transaction: tx,
        payer,
    })
}

// ── Envelope ──

fn decode(transaction_b64: &str, label: &str) -> Result<VersionedTransaction> {
    pc::decode_transaction(transaction_b64).map_err(|e| {
        BatchError::new(
            errors::INVALID_SETUP_TRANSACTION,
            format!("{label} transaction could not be decoded: {e}"),
        )
    })
}

/// Check everything about the transaction envelope: no lookup tables, the
/// sponsor is the fee payer, the signer set is exactly the two expected keys,
/// and the payer's signature is present and valid.
///
/// Returns the channel payer.
fn check_envelope(
    tx: &VersionedTransaction,
    expected: &TransactionExpectations<'_>,
    label: &str,
) -> Result<Pubkey> {
    let err = |detail: String| BatchError::new(errors::INVALID_SETUP_TRANSACTION, detail);

    // A lookup table would resolve accounts this validator cannot see, so every
    // account guard below could be satisfied while the real instruction touched
    // something else. The canonical forms need only static keys.
    if tx
        .message
        .address_table_lookups()
        .is_some_and(|lookups| !lookups.is_empty())
    {
        return Err(err(format!(
            "{label} transaction must not use address lookup tables"
        )));
    }

    let payer = pc::parse_pubkey(&expected.config.payer)
        .map_err(|e| err(format!("channelConfig.payer: {e}")))?;
    if payer == *expected.fee_payer {
        return Err(BatchError::new(
            errors::INVALID_FEE_PAYER_MISMATCH,
            "channelConfig.payer must not equal extra.feePayer",
        ));
    }

    let keys = tx.message.static_account_keys();
    if keys.first() != Some(expected.fee_payer) {
        return Err(err(format!(
            "{label} transaction fee payer must be {}",
            pc::pubkey_string(expected.fee_payer)
        )));
    }

    // The complete required-signer set must be exactly {feePayer, payer}. Any
    // additional required signature is one the sponsor cannot account for, and
    // a missing one would let an unsigned account be treated as authorizing.
    let required = tx.message.header().num_required_signatures as usize;
    if required != 2 {
        return Err(err(format!(
            "{label} transaction must require exactly 2 signatures, got {required}"
        )));
    }
    if keys.get(1) != Some(&payer) {
        return Err(err(format!(
            "{label} transaction second signer must be the channel payer {}",
            pc::pubkey_string(&payer)
        )));
    }
    if tx.signatures.len() != required {
        return Err(err(format!(
            "{label} transaction has {} signature slots but requires {required}",
            tx.signatures.len()
        )));
    }

    // The payer signature must already be valid: the sponsor adds only its own
    // slot, and co-signing a transaction the payer never authorized would let
    // anyone spend the payer's escrow.
    let message = tx.message.serialize();
    let signature = tx.signatures[1];
    if !signature.verify(payer.as_ref(), &message) {
        return Err(err(format!(
            "{label} transaction is missing a valid channel-payer signature"
        )));
    }
    Ok(payer)
}

// ── Account tables ──

fn account_at(ix: &CompiledInstruction, keys: &[Pubkey], position: usize) -> Option<Pubkey> {
    ix.accounts
        .get(position)
        .and_then(|&i| keys.get(i as usize))
        .copied()
}

fn expect_account(
    ix: &CompiledInstruction,
    keys: &[Pubkey],
    position: usize,
    want: &Pubkey,
    role: &str,
    label: &str,
) -> Result<()> {
    match account_at(ix, keys, position) {
        Some(got) if got == *want => Ok(()),
        other => Err(BatchError::new(
            errors::INVALID_SETUP_TRANSACTION,
            format!(
                "{label} {role} mismatch: expected {}, got {}",
                pc::pubkey_string(want),
                other
                    .map(|p| pc::pubkey_string(&p))
                    .unwrap_or_else(|| "<none>".to_string())
            ),
        )),
    }
}

fn reject_fee_payer_account(
    ix: &CompiledInstruction,
    keys: &[Pubkey],
    fee_payer: &Pubkey,
    label: &str,
) -> Result<()> {
    if ix
        .accounts
        .iter()
        .any(|&i| keys.get(i as usize) == Some(fee_payer))
    {
        return Err(BatchError::new(
            errors::INVALID_SETUP_TRANSACTION,
            format!("{label} instruction must not reference the fee payer"),
        ));
    }
    Ok(())
}

fn check_open_accounts(
    ix: &CompiledInstruction,
    keys: &[Pubkey],
    payer: &Pubkey,
    expected: &TransactionExpectations<'_>,
    label: &str,
) -> Result<()> {
    if ix.accounts.len() != 14 {
        return Err(BatchError::new(
            errors::INVALID_SETUP_TRANSACTION,
            format!(
                "open must have exactly 14 accounts and no remaining accounts, got {}",
                ix.accounts.len()
            ),
        ));
    }
    let mint = pc::parse_pubkey(&expected.config.token).map_err(|e| {
        BatchError::new(
            errors::INVALID_SETUP_TRANSACTION,
            format!("channelConfig.token: {e}"),
        )
    })?;
    let authorized_signer = pc::parse_pubkey(&expected.config.payer_authorizer).map_err(|e| {
        BatchError::new(
            errors::INVALID_SETUP_TRANSACTION,
            format!("channelConfig.payerAuthorizer: {e}"),
        )
    })?;
    let (payer_token, _) = pc::find_associated_token_address(payer, &mint, expected.token_program);
    let (channel_token, _) =
        pc::find_associated_token_address(expected.channel_id, &mint, expected.token_program);

    expect_account(ix, keys, 0, payer, "payer", label)?;
    // The sponsor occupies both the rent_payer and the zero-share payee seat:
    // that is what lets it seal and reclaim an abandoned channel without ever
    // being able to advance the settled watermark.
    expect_account(ix, keys, 1, expected.fee_payer, "rent_payer", label)?;
    expect_account(ix, keys, 2, expected.fee_payer, "payee", label)?;
    expect_account(ix, keys, 3, &mint, "mint", label)?;
    expect_account(ix, keys, 4, &authorized_signer, "authorized_signer", label)?;
    expect_account(ix, keys, 5, expected.channel_id, "channel", label)?;
    expect_account(ix, keys, 6, &payer_token, "payer_token_account", label)?;
    expect_account(ix, keys, 7, &channel_token, "channel_token_account", label)?;
    expect_account(ix, keys, 8, expected.token_program, "token_program", label)?;
    expect_account(
        ix,
        keys,
        9,
        &pc::system_program_id(),
        "system_program",
        label,
    )?;
    expect_account(ix, keys, 10, &pc::rent_sysvar_id(), "rent", label)?;
    expect_account(
        ix,
        keys,
        11,
        &pc::associated_token_program_id(),
        "associated_token_program",
        label,
    )?;
    expect_account(
        ix,
        keys,
        12,
        &pc::find_event_authority_pda(expected.program_id).0,
        "event_authority",
        label,
    )?;
    expect_account(ix, keys, 13, expected.program_id, "self_program", label)?;
    Ok(())
}

fn check_top_up_accounts(
    ix: &CompiledInstruction,
    keys: &[Pubkey],
    payer: &Pubkey,
    expected: &TransactionExpectations<'_>,
    label: &str,
) -> Result<()> {
    if ix.accounts.len() != 6 {
        return Err(BatchError::new(
            errors::INVALID_SETUP_TRANSACTION,
            format!(
                "top_up must have exactly 6 accounts and no remaining accounts, got {}",
                ix.accounts.len()
            ),
        ));
    }
    let mint = pc::parse_pubkey(&expected.config.token).map_err(|e| {
        BatchError::new(
            errors::INVALID_SETUP_TRANSACTION,
            format!("channelConfig.token: {e}"),
        )
    })?;
    let (payer_token, _) = pc::find_associated_token_address(payer, &mint, expected.token_program);
    let (channel_token, _) =
        pc::find_associated_token_address(expected.channel_id, &mint, expected.token_program);

    expect_account(ix, keys, 0, payer, "payer", label)?;
    expect_account(ix, keys, 1, expected.channel_id, "channel", label)?;
    expect_account(ix, keys, 2, &payer_token, "payer_token_account", label)?;
    expect_account(ix, keys, 3, &channel_token, "channel_token_account", label)?;
    expect_account(ix, keys, 4, &mint, "mint", label)?;
    expect_account(ix, keys, 5, expected.token_program, "token_program", label)?;
    Ok(())
}

// ── Instruction arguments ──

fn check_open_args(
    ix: &CompiledInstruction,
    expected: &TransactionExpectations<'_>,
    deposit_amount: u64,
    recent_slot: Option<u64>,
) -> Result<()> {
    let err = |detail: String| BatchError::new(errors::INVALID_SETUP_TRANSACTION, detail);
    // Exactly one recipient at 10,000 bps, so the encoded length is fixed. A
    // short read would let undecoded bytes carry arguments; a long one would
    // leave trailing bytes the program might interpret differently.
    let want_len = OPEN_ARGS_PREFIX_LEN + 4 + DISTRIBUTION_ENTRY_LEN;
    if ix.data.len() != want_len {
        return Err(err(format!(
            "open args must be exactly {want_len} bytes for a single-recipient \
             distribution, got {}",
            ix.data.len()
        )));
    }
    let salt = u64::from_le_bytes(ix.data[1..9].try_into().expect("8-byte slice"));
    let deposit = u64::from_le_bytes(ix.data[9..17].try_into().expect("8-byte slice"));
    let grace_period = u32::from_le_bytes(ix.data[17..21].try_into().expect("4-byte slice"));
    let open_slot = u64::from_le_bytes(ix.data[21..29].try_into().expect("8-byte slice"));

    let want_salt = expected
        .config
        .salt()
        .map_err(|e| err(format!("channelConfig.salt: {e}")))?;
    if salt != want_salt {
        return Err(err(format!(
            "open salt {salt} does not match channelConfig.salt {want_salt}"
        )));
    }
    if deposit != deposit_amount {
        return Err(err(format!(
            "open deposit {deposit} does not match deposit.amount {deposit_amount}"
        )));
    }
    if grace_period != expected.config.withdraw_delay {
        return Err(BatchError::new(
            errors::INVALID_WITHDRAW_DELAY_MISMATCH,
            format!(
                "open grace_period {grace_period} does not match withdrawDelay {}",
                expected.config.withdraw_delay
            ),
        ));
    }
    if open_slot != expected.config.open_slot {
        return Err(err(format!(
            "open open_slot {open_slot} does not match channelConfig.openSlot {}",
            expected.config.open_slot
        )));
    }

    let count = u32::from_le_bytes(
        ix.data[OPEN_ARGS_PREFIX_LEN..OPEN_ARGS_PREFIX_LEN + 4]
            .try_into()
            .expect("4-byte slice"),
    );
    if count != 1 {
        return Err(err(format!(
            "open distribution must have exactly one recipient, got {count}"
        )));
    }
    let entry = &ix.data[OPEN_ARGS_PREFIX_LEN + 4..];
    let recipient = Pubkey::try_from(&entry[..32])
        .map_err(|_| err("open distribution recipient is not a pubkey".to_string()))?;
    let bps = u16::from_le_bytes(entry[32..34].try_into().expect("2-byte slice"));
    // The distribution is committed at `open` and re-checked at `distribute`,
    // so this is the one moment the payout destination can be pinned. Anything
    // other than all of it to `payTo` diverts settled funds.
    if recipient != *expected.receiver || bps != pc::FULL_SHARE_BPS {
        return Err(err(format!(
            "open distribution must pay 100% to {}, got {} at {bps} bps",
            pc::pubkey_string(expected.receiver),
            pc::pubkey_string(&recipient)
        )));
    }

    // The channel PDA must be the one these exact args derive, not merely the
    // account the payload named.
    let derived = derive_from_args(expected, salt, open_slot)?;
    if derived != *expected.channel_id {
        return Err(BatchError::new(
            errors::INVALID_CHANNEL_ID_MISMATCH,
            format!(
                "open channel {} is not the PDA derived from its own args ({})",
                pc::pubkey_string(expected.channel_id),
                pc::pubkey_string(&derived)
            ),
        ));
    }

    if let Some(recent_slot) = recent_slot {
        if open_slot > recent_slot {
            return Err(err(format!(
                "open open_slot {open_slot} is ahead of the current slot {recent_slot}"
            )));
        }
        if recent_slot - open_slot > pc::OPEN_SLOT_WINDOW {
            return Err(err(format!(
                "open open_slot {open_slot} is outside the {}-slot window of the \
                 current slot {recent_slot}",
                pc::OPEN_SLOT_WINDOW
            )));
        }
    }
    Ok(())
}

fn derive_from_args(
    expected: &TransactionExpectations<'_>,
    salt: u64,
    open_slot: u64,
) -> Result<Pubkey> {
    let err = |detail: String| BatchError::new(errors::INVALID_SETUP_TRANSACTION, detail);
    let payer = pc::parse_pubkey(&expected.config.payer).map_err(|e| err(e.to_string()))?;
    let mint = pc::parse_pubkey(&expected.config.token).map_err(|e| err(e.to_string()))?;
    let authorized_signer =
        pc::parse_pubkey(&expected.config.payer_authorizer).map_err(|e| err(e.to_string()))?;
    Ok(pc::find_channel_pda(
        &payer,
        expected.fee_payer,
        &mint,
        &authorized_signer,
        salt,
        open_slot,
        expected.program_id,
    )
    .0)
}

fn check_top_up_args(ix: &CompiledInstruction, deposit_amount: u64, label: &str) -> Result<()> {
    let err = |detail: String| BatchError::new(errors::INVALID_SETUP_TRANSACTION, detail);
    if ix.data.len() != 9 {
        return Err(err(format!(
            "{label} args must be exactly 9 bytes, got {}",
            ix.data.len()
        )));
    }
    let amount = u64::from_le_bytes(ix.data[1..9].try_into().expect("8-byte slice"));
    if amount != deposit_amount {
        return Err(err(format!(
            "{label} amount {amount} does not match deposit.amount {deposit_amount}"
        )));
    }
    Ok(())
}

// ── Account privileges ──

/// The privilege an account position must carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Privilege {
    Writable,
}

/// Whether the static account at `index` is writable, from the message header.
///
/// Solana's account layout is positional: signers come first, and within both
/// the signed and unsigned halves the read-only accounts come last. Address
/// lookup tables are already rejected, so every account is a static key.
fn is_writable(tx: &VersionedTransaction, index: usize) -> bool {
    let header = tx.message.header();
    let signers = header.num_required_signatures as usize;
    let total = tx.message.static_account_keys().len();
    if index < signers {
        index < signers - header.num_readonly_signed_accounts as usize
    } else {
        index < total.saturating_sub(header.num_readonly_unsigned_accounts as usize)
    }
}

fn check_privileges(
    tx: &VersionedTransaction,
    ix: &CompiledInstruction,
    position: usize,
    privilege: Privilege,
    role: &str,
    label: &str,
) -> Result<()> {
    let index = *ix.accounts.get(position).ok_or_else(|| {
        BatchError::new(
            errors::INVALID_SETUP_TRANSACTION,
            format!("{label} {role} account position {position} is missing"),
        )
    })? as usize;
    match privilege {
        Privilege::Writable if !is_writable(tx, index) => Err(BatchError::new(
            errors::INVALID_SETUP_TRANSACTION,
            format!("{label} {role} must be writable"),
        )),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use solana_hash::Hash;
    use solana_instruction::Instruction;
    use solana_message::{Message, VersionedMessage};
    use solana_signature::Signature;

    const PAY_TO: &str = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY";
    const MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";

    struct Fixture {
        payer_key: SigningKey,
        payer: Pubkey,
        fee_payer: Pubkey,
        program_id: Pubkey,
        token_program: Pubkey,
        mint: Pubkey,
        receiver: Pubkey,
        channel_id: Pubkey,
        config: BatchChannelConfig,
    }

    fn fixture() -> Fixture {
        let payer_key = SigningKey::from_bytes(&[3u8; 32]);
        let payer = Pubkey::from(payer_key.verifying_key().to_bytes());
        let fee_payer = Pubkey::new_unique();
        let program_id = pc::default_program_id();
        let token_program =
            pc::parse_pubkey(crate::x402::protocol::schemes::exact::programs::TOKEN_PROGRAM)
                .unwrap();
        let mint = pc::parse_pubkey(MINT).unwrap();
        let receiver = pc::parse_pubkey(PAY_TO).unwrap();
        let (channel_id, _) = pc::find_channel_pda(
            &payer,
            &fee_payer,
            &mint,
            &payer,
            42,
            341_000_000,
            &program_id,
        );
        let config = BatchChannelConfig {
            payer: pc::pubkey_string(&payer),
            payer_authorizer: pc::pubkey_string(&payer),
            receiver: PAY_TO.to_string(),
            receiver_authorizer: None,
            token: MINT.to_string(),
            withdraw_delay: 3600,
            salt: "42".to_string(),
            open_slot: 341_000_000,
        };
        Fixture {
            payer_key,
            payer,
            fee_payer,
            program_id,
            token_program,
            mint,
            receiver,
            channel_id,
            config,
        }
    }

    impl Fixture {
        fn expectations(&self) -> TransactionExpectations<'_> {
            TransactionExpectations {
                program_id: &self.program_id,
                fee_payer: &self.fee_payer,
                config: &self.config,
                channel_id: &self.channel_id,
                token_program: &self.token_program,
                receiver: &self.receiver,
                memo: None,
            }
        }

        fn open_params(&self, deposit: u64) -> pc::OpenChannelParams {
            pc::OpenChannelParams {
                payer: self.payer,
                rent_payer: self.fee_payer,
                payee: self.fee_payer,
                mint: self.mint,
                authorized_signer: self.payer,
                salt: 42,
                open_slot: 341_000_000,
                deposit,
                grace_period: 3600,
                recipients: pc::sole_recipient(&self.receiver),
                token_program: self.token_program,
                program_id: self.program_id,
            }
        }

        /// Compile `instructions` with the sponsor as fee payer and the payer as
        /// the second signer, then sign the payer slot for real.
        fn sign(&self, instructions: &[Instruction]) -> String {
            let message = Message::new_with_blockhash(
                instructions,
                Some(&self.fee_payer),
                &Hash::new_unique(),
            );
            let message = VersionedMessage::Legacy(message);
            let bytes = message.serialize();
            let signature = Signature::from(self.payer_key.sign(&bytes).to_bytes());
            let signer_index = message
                .static_account_keys()
                .iter()
                .position(|k| *k == self.payer)
                .expect("payer is a signer");
            let mut signatures =
                vec![Signature::default(); message.header().num_required_signatures as usize];
            signatures[signer_index] = signature;
            encode(&VersionedTransaction {
                signatures,
                message,
            })
        }
    }

    fn encode(tx: &VersionedTransaction) -> String {
        base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            bincode::serialize(tx).unwrap(),
        )
    }

    fn memo_ix(text: &str) -> Instruction {
        Instruction {
            program_id: pc::to_address(&pc::memo_program_id()),
            accounts: vec![],
            data: text.as_bytes().to_vec(),
        }
    }

    fn nonce_memo() -> Instruction {
        memo_ix("0123456789abcdef0123456789abcdef")
    }

    fn cu_limit_ix(units: u32) -> Instruction {
        let mut data = vec![pc::COMPUTE_BUDGET_SET_UNIT_LIMIT];
        data.extend_from_slice(&units.to_le_bytes());
        Instruction {
            program_id: pc::to_address(&pc::compute_budget_program_id()),
            accounts: vec![],
            data,
        }
    }

    #[test]
    fn accepts_a_canonical_open() {
        let f = fixture();
        let tx = f.sign(&[
            cu_limit_ix(90_000),
            pc::build_open_instruction(&f.open_params(100_000)),
            nonce_memo(),
        ]);
        let validated = validate_setup_transaction(
            &tx,
            SetupForm::Open,
            &f.expectations(),
            100_000,
            Some(341_000_100),
        )
        .expect("canonical open is accepted");
        assert_eq!(validated.payer, f.payer);
    }

    #[test]
    fn open_requires_a_memo_the_sponsor_can_correlate() {
        let f = fixture();
        // No memo at all.
        let tx = f.sign(&[pc::build_open_instruction(&f.open_params(100_000))]);
        let err =
            validate_setup_transaction(&tx, SetupForm::Open, &f.expectations(), 100_000, None)
                .unwrap_err();
        assert_eq!(err.code, errors::INVALID_SETUP_TRANSACTION);
        assert!(err.detail.contains("Memo"), "{}", err.detail);

        // A memo that is neither the declared value nor a hex nonce.
        let tx = f.sign(&[
            pc::build_open_instruction(&f.open_params(100_000)),
            memo_ix("hello"),
        ]);
        assert!(
            validate_setup_transaction(&tx, SetupForm::Open, &f.expectations(), 100_000, None)
                .is_err()
        );

        // A declared memo must match exactly.
        let mut expected = f.expectations();
        expected.memo = Some("invoice-123");
        let tx = f.sign(&[
            pc::build_open_instruction(&f.open_params(100_000)),
            memo_ix("invoice-124"),
        ]);
        assert!(
            validate_setup_transaction(&tx, SetupForm::Open, &expected, 100_000, None).is_err()
        );
        let tx = f.sign(&[
            pc::build_open_instruction(&f.open_params(100_000)),
            memo_ix("invoice-123"),
        ]);
        assert!(validate_setup_transaction(&tx, SetupForm::Open, &expected, 100_000, None).is_ok());
    }

    #[test]
    fn open_binds_the_declared_deposit_and_channel_args() {
        let f = fixture();
        let tx = f.sign(&[
            pc::build_open_instruction(&f.open_params(100_000)),
            nonce_memo(),
        ]);
        // The payload's declared deposit must be what the instruction escrows,
        // or the server would cap vouchers against a deposit that never landed.
        let err = validate_setup_transaction(&tx, SetupForm::Open, &f.expectations(), 99_999, None)
            .unwrap_err();
        assert!(
            err.detail.contains("does not match deposit.amount"),
            "{}",
            err.detail
        );

        // A grace period diverging from the advertised withdrawDelay is its own
        // code: the client's escape hatch is exactly that value.
        let mut params = f.open_params(100_000);
        params.grace_period = 1800;
        let tx = f.sign(&[pc::build_open_instruction(&params), nonce_memo()]);
        let err =
            validate_setup_transaction(&tx, SetupForm::Open, &f.expectations(), 100_000, None)
                .unwrap_err();
        assert_eq!(err.code, errors::INVALID_WITHDRAW_DELAY_MISMATCH);
    }

    #[test]
    fn open_rejects_a_distribution_that_diverts_settled_funds() {
        let f = fixture();
        // A second recipient, or a single recipient that is not payTo, would
        // send part of the settled funds somewhere the server never agreed to.
        for recipients in [
            vec![pc::Distribution {
                recipient: Pubkey::new_unique(),
                bps: pc::FULL_SHARE_BPS,
            }],
            vec![
                pc::Distribution {
                    recipient: f.receiver,
                    bps: 9_000,
                },
                pc::Distribution {
                    recipient: Pubkey::new_unique(),
                    bps: 1_000,
                },
            ],
        ] {
            let mut params = f.open_params(100_000);
            params.recipients = recipients;
            // Recompute the channel for the params so the failure is the
            // distribution, not the PDA.
            let expectations = f.expectations();
            let tx = f.sign(&[pc::build_open_instruction(&params), nonce_memo()]);
            let err =
                validate_setup_transaction(&tx, SetupForm::Open, &expectations, 100_000, None)
                    .unwrap_err();
            assert_eq!(err.code, errors::INVALID_SETUP_TRANSACTION);
            assert!(
                err.detail.contains("distribution") || err.detail.contains("recipient"),
                "{}",
                err.detail
            );
        }
    }

    #[test]
    fn open_rejects_a_stale_or_future_open_slot() {
        let f = fixture();
        let tx = f.sign(&[
            pc::build_open_instruction(&f.open_params(100_000)),
            nonce_memo(),
        ]);
        // Ahead of the chain.
        assert!(validate_setup_transaction(
            &tx,
            SetupForm::Open,
            &f.expectations(),
            100_000,
            Some(340_999_999)
        )
        .is_err());
        // Older than the program's window.
        assert!(validate_setup_transaction(
            &tx,
            SetupForm::Open,
            &f.expectations(),
            100_000,
            Some(341_000_000 + pc::OPEN_SLOT_WINDOW + 1)
        )
        .is_err());
    }

    #[test]
    fn rejects_a_smuggled_instruction_or_a_foreign_program() {
        let f = fixture();
        // A System transfer draining the sponsor, hidden behind a valid open.
        let drain = solana_system_interface::instruction::transfer(
            &pc::to_address(&f.fee_payer),
            &pc::to_address(&f.payer),
            1_000_000,
        );
        let tx = f.sign(&[
            pc::build_open_instruction(&f.open_params(100_000)),
            nonce_memo(),
            drain,
        ]);
        let err =
            validate_setup_transaction(&tx, SetupForm::Open, &f.expectations(), 100_000, None)
                .unwrap_err();
        assert_eq!(err.code, errors::INVALID_SETUP_TRANSACTION);

        // Two channel instructions: the second could be anything.
        let tx = f.sign(&[
            pc::build_open_instruction(&f.open_params(100_000)),
            pc::build_open_instruction(&f.open_params(100_000)),
            nonce_memo(),
        ]);
        assert!(
            validate_setup_transaction(&tx, SetupForm::Open, &f.expectations(), 100_000, None)
                .is_err()
        );
    }

    #[test]
    fn rejects_an_envelope_the_sponsor_cannot_account_for() {
        let f = fixture();
        let ixs = [
            pc::build_open_instruction(&f.open_params(100_000)),
            nonce_memo(),
        ];

        // Fee payer is not the sponsor.
        let message = VersionedMessage::Legacy(Message::new_with_blockhash(
            &ixs,
            Some(&f.payer),
            &Hash::new_unique(),
        ));
        let signatures =
            vec![Signature::default(); message.header().num_required_signatures as usize];
        let tx = encode(&VersionedTransaction {
            signatures,
            message,
        });
        let err =
            validate_setup_transaction(&tx, SetupForm::Open, &f.expectations(), 100_000, None)
                .unwrap_err();
        assert!(err.detail.contains("fee payer"), "{}", err.detail);

        // Valid layout, but the payer signature slot was never filled: the
        // sponsor must never co-sign a transaction the payer did not authorize.
        let message = VersionedMessage::Legacy(Message::new_with_blockhash(
            &ixs,
            Some(&f.fee_payer),
            &Hash::new_unique(),
        ));
        let signatures =
            vec![Signature::default(); message.header().num_required_signatures as usize];
        let tx = encode(&VersionedTransaction {
            signatures,
            message,
        });
        let err =
            validate_setup_transaction(&tx, SetupForm::Open, &f.expectations(), 100_000, None)
                .unwrap_err();
        assert!(
            err.detail.contains("channel-payer signature"),
            "{}",
            err.detail
        );
    }

    #[test]
    fn accepts_a_canonical_top_up_and_binds_its_amount() {
        let f = fixture();
        let top_up = pc::build_top_up_instruction(
            &f.payer,
            &f.channel_id,
            &f.mint,
            25_000,
            &f.token_program,
            &f.program_id,
        );
        let tx = f.sign(&[top_up.clone(), nonce_memo()]);
        assert!(
            validate_setup_transaction(&tx, SetupForm::TopUp, &f.expectations(), 25_000, None)
                .is_ok()
        );
        let err =
            validate_setup_transaction(&tx, SetupForm::TopUp, &f.expectations(), 24_000, None)
                .unwrap_err();
        assert!(
            err.detail.contains("does not match deposit.amount"),
            "{}",
            err.detail
        );

        // A top-up naming the sponsor as an instruction account would put its
        // signature behind a token authority it never granted.
        let mut smuggled = top_up;
        smuggled.accounts.push(solana_instruction::AccountMeta::new(
            pc::to_address(&f.fee_payer),
            false,
        ));
        let tx = f.sign(&[smuggled, nonce_memo()]);
        assert!(
            validate_setup_transaction(&tx, SetupForm::TopUp, &f.expectations(), 25_000, None)
                .is_err()
        );
    }

    #[test]
    fn accepts_a_canonical_request_close_and_rejects_extra_instructions() {
        let f = fixture();
        let close = pc::build_request_close_instruction(&f.payer, &f.channel_id, &f.program_id);
        let tx = f.sign(&[close.clone(), nonce_memo()]);
        let validated = validate_request_close_transaction(&tx, &f.expectations())
            .expect("canonical request_close is accepted");
        assert_eq!(validated.payer, f.payer);

        // A seal riding along with the close would let the sponsor's signature
        // finalize the channel at a watermark the server never claimed.
        let seal = pc::build_seal_instruction(&f.channel_id, &f.program_id);
        let tx = f.sign(&[close, seal, nonce_memo()]);
        let err = validate_request_close_transaction(&tx, &f.expectations()).unwrap_err();
        assert_eq!(err.code, errors::INVALID_REFUND_TRANSACTION);
    }

    #[test]
    fn request_close_binds_the_derived_channel() {
        let f = fixture();
        let other = Pubkey::new_unique();
        let close = pc::build_request_close_instruction(&f.payer, &other, &f.program_id);
        let tx = f.sign(&[close, nonce_memo()]);
        let err = validate_request_close_transaction(&tx, &f.expectations()).unwrap_err();
        assert_eq!(err.code, errors::INVALID_REFUND_TRANSACTION);
        assert!(err.detail.contains("channel mismatch"), "{}", err.detail);
    }
}
