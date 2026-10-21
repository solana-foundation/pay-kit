//! Kit paths for `subscription` vectors: what `pkc fill` runs to realize a case
//! and what the build judge runs against an SDK's build.

use serde_json::Value;

use super::Observed;
use crate::case::Mode;
use crate::run::judge::Failure;
use crate::run::vectors::Vector;

/// The result field an accepted `subscription` build carries.
pub const BUILD_ARTIFACT: &str = "transaction";

pub async fn run(mode: Mode, _input: &Value) -> Result<Observed, String> {
    Ok(Observed::NotExpressible(format!(
        "no kit path for subscription {}",
        mode.as_str()
    )))
}

/// Judge an accepted SDK build of a `subscription` vector.
pub async fn judge_build(_vector: &Vector, _artifact: &str) -> Result<(), Failure> {
    Ok(())
}
