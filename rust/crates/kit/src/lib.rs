//! Solana payment SDK: MPP and x402 behind feature flags.
//!
//! Everything ships in this single crate. The protocol layers are gated by
//! cargo features so consumers only compile what they use:
//!
//! # Features
//! - `mpp` — enable the Machine Payments Protocol module (default).
//! - `x402` — enable the x402 / HTTP 402 module (default).
//! - `server` / `client` — server-side verification / client-side building.
//! - `axum` — unified dual-protocol payment gate (needs both protocols).
//! - `confidential` — Token-2022 confidential transfers (mpp).
//! - `settlement` — batched on-chain settlement worker.
//! - `gcp_kms` — GCP KMS signer support.
//! - `otel` — OpenTelemetry init.
//! - `testkit` — settlement test/demo harness.
//!
//! The inlined modules are:
//! - [`core`]: shared Solana primitives (PDA/voucher/instruction builders,
//!   stores, settlement). Available whenever `mpp` or `x402` is enabled.
//! - [`mpp`]: the Machine Payments Protocol implementation (`mpp` feature).
//! - [`x402`]: the x402 / HTTP 402 implementation (`x402` feature).
//! - [`generated`]: Codama-generated program clients (payment-channels +
//!   subscriptions), consumed by `core`/`mpp`.

/// Codama-generated program clients (payment-channels + subscriptions).
#[cfg(any(feature = "mpp", feature = "x402"))]
pub mod generated;

/// Shared Solana primitives for the pay-kit protocol layers.
#[cfg(any(feature = "mpp", feature = "x402"))]
pub mod core;

/// Machine Payments Protocol (Solana `charge`/`session`/`subscription`).
#[cfg(feature = "mpp")]
pub mod mpp;

/// x402 / HTTP 402 protocol for Solana resources.
#[cfg(feature = "x402")]
pub mod x402;

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
