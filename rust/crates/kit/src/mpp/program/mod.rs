pub mod subscriptions;

/// Payment-channels helpers live in `solana-pay-core` so they can be shared with
/// `solana-x402` (the `upto` scheme) without either protocol crate depending on
/// the other. Re-exported here to preserve the `crate::mpp::program::payment_channels`
/// path used across this crate.
pub use crate::core::payment_channels;
