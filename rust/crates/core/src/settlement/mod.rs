//! Batched on-chain settlement — shared by the mpp session and x402 paths.
//!
//! [`packing`] is the pure, always-available size-bounded grouping of
//! per-channel settlement instructions into legacy transactions. The background
//! [`worker`] (feature `worker`) accumulates channels and flushes them on a size
//! cap or a linger timer, signing with the operator and broadcasting.

pub mod packing;

#[cfg(feature = "worker")]
pub mod worker;
