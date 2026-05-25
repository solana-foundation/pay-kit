//! Solana payment SDK: MPP and x402 behind feature flags.
//!
//! # Features
//! - `mpp` — enable the Machine Payments Protocol module (default).
//! - `x402` — enable the x402 / HTTP 402 module (default).

#[cfg(feature = "mpp")]
pub use solana_mpp as mpp;

#[cfg(feature = "x402")]
pub use solana_x402 as x402;
