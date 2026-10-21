//! `subscription` vectors: the testee passes the vector's input to the kit
//! unchanged (harness/AGENTS.md "Never put logic in the testee").

use serde_json::Value;

use super::{Outcome, Rejection};

pub async fn run(mode: &str, _input: &Value) -> Result<Outcome, Rejection> {
    Ok(Outcome::Unsupported(format!(
        "no Rust runner path for intent \"subscription\" mode {mode:?}"
    )))
}
