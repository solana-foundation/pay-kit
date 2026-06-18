pub mod subscriptions;

/// Payment-channels helpers live in `solana-pay-core` so they can be shared with
/// `solana-x402` (the `upto` scheme) without either protocol crate depending on
/// the other. Re-exported here to preserve the `crate::program::payment_channels`
/// path used across this crate.
pub use solana_pay_core::payment_channels;
