pub mod batch_settlement;
pub mod exact;
pub mod upto;

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
