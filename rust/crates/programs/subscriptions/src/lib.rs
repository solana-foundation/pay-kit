//! Codama-generated Rust client for the Solana subscriptions program.
//!
//! All of [`generated`] is produced by `@codama/renderers-rust` from the
//! `solana-foundation/subscriptions` IDL vendored at the repo root in
//! `idl/subscriptions.json`. Regenerate via `just subscriptions-generate-rs`.
//!
//! This module deliberately has nothing else in it: hand-written PDA helpers,
//! seed constants, and convenience instruction builders live in
//! `mpp::program::subscriptions` so the codegen output stays a pure
//! pass-through and `just subscriptions-generate-rs` can wipe `src/generated/`
//! without touching anything authored.

pub mod generated;

pub use generated::*;
