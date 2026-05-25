//! Solana support for the x402 (HTTP 402) protocol.
//!
//! This crate is intentionally Solana-only. It implements x402 schemes for
//! Solana resources, where a server responds with HTTP 402 Payment Required
//! and the client builds and submits a payment transaction to unlock the
//! resource.
//!
//! # Features
//!
//! - `server` — Server-side verification helpers (enabled by default)
//! - `client` — Client-side transaction building (enabled by default)

pub mod protocol;

#[cfg(feature = "client")]
pub mod client;

#[cfg(feature = "server")]
pub mod server;

pub mod constants;
pub mod error;
pub mod siwx;

pub use constants::*;
pub use error::Error;
pub use protocol::schemes::exact;
pub use siwx::*;

// Re-export crates callers need to use with the payment builder.
pub use solana_keychain;
pub use solana_rpc_client;
