pub mod batch_settlement;
pub mod exact;
pub mod upto;

/// In-process Solana JSON-RPC mock for exercising the settlement broadcast /
/// confirm / account-fetch paths in unit tests (test builds only).
#[cfg(test)]
pub(crate) mod mock_rpc;

/// Maximum accepted `PAYMENT-SIGNATURE` header length, in bytes. Mirrors the
/// MPP header parsers' `MAX_TOKEN_LEN` (16 KiB) so a hostile client cannot drive
/// unbounded base64 + JSON decode work with an oversized credential header. The
/// `exact` / `upto` / `batch_settlement` header parsers all gate on this before
/// any base64 / JSON work.
pub(crate) const MAX_PAYMENT_SIGNATURE_HEADER_LEN: usize = 16 * 1024;

/// A single currency the `exact` / `upto` server backends are willing to accept.
///
/// Replaces the awkward singular `currency` + `decimals` + `token_program` plus
/// a parallel `accepted_currencies` list: a server is configured with a
/// non-empty `Vec<CurrencyConfig>`, where `[0]` is the primary/default currency
/// and every entry yields one advertised `accepts[]` option.
#[derive(Debug, Clone)]
pub struct CurrencyConfig {
    /// Currency symbol ("USDC") or mint address. Mint + token program are
    /// resolved from this (token_program override below wins).
    pub currency: String,
    /// Token decimals (e.g. 6 for USDC).
    pub decimals: u8,
    /// Token program override; `None` derives it from `currency`
    /// (legacy SPL Token vs Token-2022).
    pub token_program: Option<String>,
}

pub use batch_settlement::{BatchConfig, BatchOutcome, X402BatchSettlement};
pub use exact::{
    check_network_blockhash, Config, ExactOptions, VerifiedExactPayment, LOCALNET_NETWORK,
    SURFPOOL_BLOCKHASH_PREFIX, X402,
};
pub use upto::{UptoConfig, UptoPayout, VerifiedUptoOpen, X402Upto};
