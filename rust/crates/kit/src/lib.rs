//! Solana payment SDK: MPP and x402 behind feature flags.
//!
//! # Features
//! - `mpp` — enable the Machine Payments Protocol module (default).
//! - `x402` — enable the x402 / HTTP 402 module (default).

#[cfg(feature = "mpp")]
pub use solana_mpp as mpp;

#[cfg(feature = "x402")]
pub use solana_x402 as x402;

/// Cross-protocol, balance-aware payment selection (MPP charge + x402 accepts).
///
/// Picks a charge option the wallet can fund across *both* protocols, honoring
/// a token-preference [`select::OrderingStrategy`]. See [`select::select_payment`].
#[cfg(all(feature = "mpp", feature = "x402", feature = "client"))]
pub mod select;

#[cfg(all(feature = "mpp", feature = "x402", feature = "client"))]
pub use select::{
    select_payment, select_payment_parsed, AcceptableToken, OfferedOption, OrderingStrategy,
    SelectError, SelectedPayment,
};

/// Unified, dual-protocol payment gate for axum.
///
/// One gated route accepts both MPP charge and x402; an unpaid request gets a
/// 402 carrying both challenges. See [`paid_get`].
#[cfg(feature = "axum")]
mod gate;

#[cfg(feature = "axum")]
pub use gate::{
    paid_batch_get, paid_batch_post, paid_get, paid_post, paid_upto_get, paid_upto_post, Charge,
    PayKit, PayKitConfig, PayKitError, Payment, Price, PriceCtx, Protocol,
};
