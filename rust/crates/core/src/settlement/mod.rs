//! Batched on-chain settlement — shared by the mpp session and x402 paths.
//!
//! [`packing`] is the pure, always-available size-bounded grouping of
//! per-channel settlement instructions into legacy transactions. The background
//! [`worker`] (feature `worker`) accumulates channels and flushes them on a size
//! cap or a linger timer, signing with the operator and broadcasting.

pub mod packing;

#[cfg(feature = "worker")]
pub mod worker;

/// Test/demo harness (open real channels, fund via cheatcodes, drive + observe
/// packing). Shared by the x402/mpp tests and the pay bench.
#[cfg(feature = "testkit")]
pub mod testkit;
