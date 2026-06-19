//! Pluggable key-value and channel state stores.
//!
//! The implementation now lives in [`solana_pay_core::store`] so it can be
//! shared with `solana-x402` (the `batch-settlement` scheme) without either
//! protocol crate depending on the other. This module re-exports it unchanged,
//! preserving the `crate::store::*` and `mpp::*` paths used across this crate.

pub use solana_pay_core::store::*;
