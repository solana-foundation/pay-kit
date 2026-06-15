//! Solana payment SDK: MPP and x402 behind feature flags.
//!
//! # Features
//! - `mpp` — enable the Machine Payments Protocol module (default).
//! - `x402` — enable the x402 / HTTP 402 module (default).

#[cfg(feature = "mpp")]
pub use solana_mpp as mpp;

#[cfg(feature = "x402")]
pub use solana_x402 as x402;

/// Unified, dual-protocol payment gate for axum.
///
/// One gated route accepts both MPP charge and x402; an unpaid request gets a
/// 402 carrying both challenges. See [`paid_get`].
#[cfg(feature = "axum")]
mod gate;

#[cfg(feature = "axum")]
pub use gate::{
    paid_get, paid_post, PayKit, PayKitConfig, PayKitError, Payment, Price, PriceCtx, Protocol,
};
