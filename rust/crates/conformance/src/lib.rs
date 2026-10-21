//! pay-kit conformance: the case registry, the filler that turns cases into
//! the shared vectors under `harness/vectors/`, and the requirements lint.
//!
//! See `harness/DESIGN.md` and `harness/PLAN.md` (phase 1).

pub mod annotate;
pub mod case;
pub mod cases;
pub mod classify;
pub mod fill;
pub mod fixture_rpc;
pub mod interop;
pub mod keys;
pub mod mutate;
pub mod realize;
pub mod report;
pub mod reqlint;
pub mod run;
pub mod tx;

use std::path::PathBuf;

/// The pay-kit repository root (this crate lives at `rust/crates/conformance`).
pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .expect("repository root")
}
