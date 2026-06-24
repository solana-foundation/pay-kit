//! Shared Solana primitives for the pay-kit crates.
//!
//! Holds transaction helpers extracted from `solana-mpp` and `solana-x402` so
//! both protocol crates (and the unified `solana-pay-kit` gate) can build on the
//! same on-chain plumbing without depending on each other.
//!
//! Exposes:
//! - [`payment_channels`]: PDA derivation, voucher bytes, distribution hashing,
//!   and instruction/transaction builders for the on-chain payment-channels
//!   program (`solana-mpp` re-exports it at `mpp::program::payment_channels`;
//!   `solana-x402` uses it for the `upto` and `batch-settlement` schemes).
//! - [`store`]: replay-protection + payment-channel session state stores
//!   (`solana-mpp` re-exports at `mpp::store`).
//! - [`voucher`] / [`session`]: wire-agnostic cumulative-voucher verification and
//!   acceptance, shared by the MPP `session` intent and the x402
//!   `batch-settlement` scheme.

#[cfg(feature = "otel")]
pub mod otel;
pub mod payment_channels;
pub mod session;
pub mod settlement;
pub mod store;
pub mod units;
pub mod voucher;

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
