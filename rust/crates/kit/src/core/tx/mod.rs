//! One transaction path: version selection, compute budget, compile, wire
//! encoding, and the envelope checks every verifier runs first.
//!
//! The kit builds and accepts two Solana message versions, `0` and `1`
//! (SIMD-0385). Legacy messages are not built and not accepted: version 0
//! without address lookup tables is a strict superset, and rejecting legacy
//! removes the legacy-first decode ambiguity from every verifier. Address
//! lookup tables are never used either; every account is a static key, so a
//! sponsor sees exactly what it co-signs.
//!
//! Servers advertise the versions they accept (`transactionVersions` in the
//! challenge / `extra`); clients build the highest advertised version their
//! signer supports. When the field is absent the accepted set is `[0]`.

pub mod budget;
pub mod build;
pub mod policy;
pub mod version;
pub mod wire;

pub use budget::{
    decode_compute_budget_op, unit_limit_instruction, unit_price_instruction, ComputeBudget,
    ComputeBudgetOp, DeclaredBudget, COMPUTE_BUDGET_PROGRAM_ID,
};
pub use build::{build_unsigned, build_unsigned_unchecked, check_limits, measure};
pub use policy::{check_envelope, require_static_accounts};
pub use version::{accepted_versions, TxLimits, TxVersion, DEFAULT_ACCEPTED_VERSIONS};
pub use wire::{decode, decode_bytes, encode, serialize, serialized_size};
