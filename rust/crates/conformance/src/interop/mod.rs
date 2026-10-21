//! `pkc run --tier interop` (PLAN phase 3): real client adapters pay real
//! server adapters over HTTP against one local surfpool per run, through a
//! fault proxy, with every assertion made here in Rust.
//!
//! - [`claims`], [`adapters`], [`scenarios`], [`cases`]: the registry, and
//!   reconciliation of cases against `harness/expectations/<lang>.toml`;
//! - [`plan`]: the CI shards (`pkc plan --tier interop`) and the README
//!   interop table;
//! - behind the `interop` feature (it links surfpool): [`chain`] (the
//!   validator and per-case accounts), [`process`] (the adapter process
//!   contract), [`proxy`] (capture, replay and fault injection), [`settle`]
//!   (structural settlement assertions) and [`runner`].

pub mod adapters;
pub mod cases;
pub mod claims;
pub mod plan;
pub mod scenarios;

#[cfg(feature = "interop")]
pub mod chain;
#[cfg(feature = "interop")]
pub mod process;
#[cfg(feature = "interop")]
pub mod proxy;
#[cfg(feature = "interop")]
pub mod runner;
#[cfg(feature = "interop")]
pub mod settle;
