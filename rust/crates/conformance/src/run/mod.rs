//! `pkc run`: the vector driver (DESIGN.md §3.2, PLAN phases 2 and 2b).
//!
//! - [`vectors`]: load and validate the filled corpus;
//! - [`expectations`]: `harness/expectations/<lang>.toml`, exact-set
//!   reconciliation;
//! - [`testee`]: the process boundary (ABI v2 `--serve`, legacy one-shot);
//! - [`result`]: the `RunnerResult` contract;
//! - [`judge`]: assertions, plus the Rust verifier and instruction-multiset
//!   comparison for builds;
//! - [`explain`]: the six-element failure report;
//! - [`driver`]: orchestration, results JSON, JUnit;
//! - [`cross`]: offline client x server cross-verification;
//! - [`next`]: failure grouping for `pkc next`;
//! - [`scaffold`]: testee skeletons.

pub mod cross;
pub mod cross_gate;
pub mod driver;
pub mod expectations;
pub mod explain;
pub mod judge;
pub mod next;
pub mod result;
pub mod scaffold;
pub mod testee;
pub mod vectors;
