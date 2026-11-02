//! The SPL token account layout shared by Token and Token-2022, read as the
//! payment-channels program reads a payout destination.

use solana_pubkey::Pubkey;

/// Base length of an SPL token account. Token-2022 appends its extensions
/// after the same fixed layout, so one decoder covers both programs.
pub(crate) const TOKEN_ACCOUNT_LEN: usize = 165;

/// `AccountState::Initialized`, at offset 108.
pub(crate) const TOKEN_ACCOUNT_INITIALIZED: u8 = 1;

/// `AccountState::Frozen`: the account cannot receive or send.
pub(crate) const TOKEN_ACCOUNT_FROZEN: u8 = 2;

/// `AccountType::Account`, the discriminant a Token-2022 account carries at
/// offset 165 before its extensions.
pub(crate) const TOKEN_ACCOUNT_TYPE: u8 = 2;

/// `ExtensionType::ImmutableOwner`.
///
/// The only account extension a settlement destination may carry. It is inert
/// — it fixes the owner, nothing else — and every associated token account has
/// it, so requiring its absence would reject ordinary ATAs.
pub(crate) const EXTENSION_IMMUTABLE_OWNER: u16 = 7;

/// The fields of an SPL token account this server cares about.
pub(crate) struct TokenAccount {
    pub(crate) mint: Pubkey,
    pub(crate) owner: Pubkey,
    pub(crate) state: u8,
    /// An account extension this server will not settle through, if any.
    pub(crate) unsupported_extension: Option<u16>,
}

/// Decode a token account, or `None` when the data is too short to be one —
/// which is what an uninitialized (or non-token) account looks like.
///
/// Token-2022 appends a type byte and a TLV extension list after the same
/// 165-byte base. Those extensions are not cosmetic: one can withhold part of a
/// transfer, require a memo to precede it, block it from a CPI, or move the
/// balance out of the classic ledger entirely — so an account carrying one is
/// reported rather than silently accepted as a payout destination.
pub(crate) fn decode_token_account(data: &[u8]) -> Option<TokenAccount> {
    if data.len() < TOKEN_ACCOUNT_LEN {
        return None;
    }
    Some(TokenAccount {
        mint: Pubkey::try_from(&data[0..32]).ok()?,
        owner: Pubkey::try_from(&data[32..64]).ok()?,
        state: data[108],
        unsupported_extension: unsupported_account_extension(data),
    })
}

/// The first account extension outside the allowlist, if the account has one.
///
/// A malformed or truncated TLV is reported as unsupported rather than skipped:
/// this decides whether to accept an escrow, so anything it cannot read is
/// something it should not settle through.
fn unsupported_account_extension(data: &[u8]) -> Option<u16> {
    // A classic SPL Token account is exactly the base length and has no
    // extension list at all.
    if data.len() == TOKEN_ACCOUNT_LEN {
        return None;
    }
    if data[TOKEN_ACCOUNT_LEN] != TOKEN_ACCOUNT_TYPE {
        return Some(u16::from(data[TOKEN_ACCOUNT_LEN]));
    }
    let mut cursor = TOKEN_ACCOUNT_LEN + 1;
    while cursor < data.len() {
        // A run of zero padding is the end of the list, not an extension.
        if data[cursor..].iter().all(|byte| *byte == 0) {
            return None;
        }
        let Some(header) = data.get(cursor..cursor + 4) else {
            return Some(u16::MAX);
        };
        let extension = u16::from_le_bytes([header[0], header[1]]);
        let length = usize::from(u16::from_le_bytes([header[2], header[3]]));
        if extension != EXTENSION_IMMUTABLE_OWNER {
            return Some(extension);
        }
        let Some(next) = cursor.checked_add(4).and_then(|c| c.checked_add(length)) else {
            return Some(u16::MAX);
        };
        if next > data.len() {
            return Some(u16::MAX);
        }
        cursor = next;
    }
    None
}
