//! Codama-generated Rust client for the Solana payment-channels program.
//!
//! All of [`generated`] is produced by `@codama/renderers-rust` from the
//! `Moonsong-Labs/solana-payment-channels` IDL vendored at the repo root in
//! `idl/payment-channels.json`. Regenerate via `just payment-channels-generate-rs`.
//!
//! Hand-written PDA helpers, seed constants, and convenience instruction
//! builders live in `mpp::program::payment_channels` so the codegen output
//! stays a pure pass-through and `just payment-channels-generate-rs` can
//! wipe `src/generated/` without touching anything authored.

pub mod generated;

pub use generated::*;
