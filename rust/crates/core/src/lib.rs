//! Shared Solana primitives for the pay-kit crates.
//!
//! Holds transaction helpers extracted from `solana-mpp` and `solana-x402` so
//! both protocol crates (and the unified `solana-pay-kit` gate) can build on the
//! same on-chain plumbing without depending on each other.
//!
//! Currently exposes [`payment_channels`]: PDA derivation, voucher bytes,
//! distribution hashing, and instruction/transaction builders for the on-chain
//! payment-channels program. `solana-mpp` re-exports this module at
//! `mpp::program::payment_channels`, and `solana-x402` uses it to back the
//! `upto` scheme.

pub mod payment_channels;
pub mod units;

pub use units::{parse_units, MAX_DECIMALS};

/// Errors produced by the shared pay-kit core helpers.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A Borsh (de)serialization step failed.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// Catch-all for anything else (invalid pubkey, signing failure, …).
    #[error("{0}")]
    Other(String),
}

/// Convenience result alias over [`Error`].
pub type Result<T> = std::result::Result<T, Error>;
