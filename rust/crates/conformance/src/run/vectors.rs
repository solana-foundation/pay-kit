//! Load the filled vectors (`harness/vectors/*.json`) and validate their
//! envelope, the Rust port of `harness/src/conformance/load.ts` plus the
//! `conformanceVectorSchema` checks of `contract-schema.ts`.

use std::path::Path;

use serde_json::{json, Map, Value};

use crate::case::RejectCode;

/// Keys a vector may carry (`conformanceVectorSchema`, additionalProperties false).
const VECTOR_KEYS: [&str; 12] = [
    "id",
    "intent",
    "mode",
    "description",
    "spec",
    "requirements",
    "bugType",
    "tier",
    "role",
    "provenance",
    "input",
    "expect",
];

/// The keys a testee receives: the v1 vector ABI without traceability
/// metadata and without `expect` (a testee never sees what it is judged on).
pub const TESTEE_KEYS: [&str; 5] = ["id", "intent", "mode", "description", "input"];

#[derive(Debug, Clone)]
pub struct Vector {
    pub id: String,
    pub intent: String,
    pub mode: String,
    /// The file it came from, relative to the vectors directory.
    pub file: String,
    pub raw: Value,
}

impl Vector {
    pub fn input(&self) -> &Value {
        &self.raw["input"]
    }

    pub fn expect(&self) -> &Value {
        &self.raw["expect"]
    }

    pub fn expect_outcome(&self) -> &str {
        self.raw["expect"]["outcome"].as_str().unwrap_or_default()
    }

    pub fn reject_code(&self) -> Option<&str> {
        self.raw["expect"]["rejectCode"].as_str()
    }

    pub fn requirements(&self) -> Vec<String> {
        self.raw["requirements"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn bug_type(&self) -> &str {
        self.raw["bugType"].as_str().unwrap_or("unknown")
    }

    /// Cases whose verdict depends on a clock the vector pins. A testee that
    /// does not honour pinned clocks cannot be judged on them.
    pub fn needs_clock(&self) -> bool {
        self.input()
            .pointer("/sessionVoucherVerify/nowSeconds")
            .is_some()
    }

    /// The v1 vector a testee receives, with the fixture RPC URL injected.
    pub fn for_testee(&self, rpc_url: Option<&str>) -> Value {
        let mut out = Map::new();
        for key in TESTEE_KEYS {
            if let Some(value) = self.raw.get(key) {
                out.insert(key.to_string(), value.clone());
            }
        }
        if let Some(url) = rpc_url {
            out["input"]["rpcUrl"] = json!(url);
        }
        Value::Object(out)
    }

    /// The ABI v2 op for this vector's mode.
    pub fn op(&self) -> &'static str {
        match self.mode.as_str() {
            "build-transaction" => "build",
            "verify-transaction" => "verify",
            _ => "canonical-bytes",
        }
    }
}

fn check_id(id: &str) -> bool {
    id.len() >= 2
        && id.starts_with(|c: char| c.is_ascii_lowercase())
        && id.ends_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
        && id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

fn check_doc(doc: &str) -> bool {
    let rest = doc
        .strip_prefix("mpp-specs/specs/")
        .or_else(|| doc.strip_prefix("x402/specs/"));
    matches!(rest, Some(r) if !r.starts_with('.') && r.ends_with(".md") && !r.chars().any(char::is_whitespace))
}

fn check_req(id: &str) -> bool {
    let hex = id.strip_prefix("MPP-").or_else(|| id.strip_prefix("X402-"));
    matches!(hex, Some(h) if h.len() == 10 && h.chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)))
}

fn one_of(value: &Value, allowed: &[&str]) -> bool {
    value.as_str().is_some_and(|v| allowed.contains(&v))
}

/// Validate one vector's envelope; `Err` names the first violation.
pub fn validate(vector: &Value) -> Result<(), String> {
    let Some(obj) = vector.as_object() else {
        return Err("vector must be an object".into());
    };
    for key in obj.keys() {
        if !VECTOR_KEYS.contains(&key.as_str()) {
            return Err(format!("unknown key {key:?}"));
        }
    }
    for key in ["id", "intent", "mode", "spec", "input", "expect"] {
        if !obj.contains_key(key) {
            return Err(format!("missing {key}"));
        }
    }
    if !obj["id"].as_str().is_some_and(check_id) {
        return Err("id must match ^[a-z][a-z0-9-]*[a-z0-9]$".into());
    }
    if !one_of(&obj["intent"], &["charge", "x402-exact", "session"]) {
        return Err("unknown intent".into());
    }
    if !one_of(
        &obj["mode"],
        &["build-transaction", "verify-transaction", "canonical-bytes"],
    ) {
        return Err("unknown mode".into());
    }
    if let Some(d) = obj.get("description") {
        if !d.is_string() {
            return Err("description must be a string".into());
        }
    }
    let spec = obj["spec"]
        .as_object()
        .ok_or("spec must be an object; add it in rust/crates/conformance and run pkc fill")?;
    for key in spec.keys() {
        if !["doc", "section", "quote"].contains(&key.as_str()) {
            return Err(format!("unknown spec key {key:?}"));
        }
    }
    if !spec
        .get("doc")
        .and_then(Value::as_str)
        .is_some_and(check_doc)
    {
        return Err("spec.doc must be mpp-specs/specs/... or x402/specs/....md".into());
    }
    if spec
        .get("section")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        return Err("spec.section must be non-empty".into());
    }
    if spec
        .get("quote")
        .and_then(Value::as_str)
        .is_none_or(|q| q.chars().count() < 12)
    {
        return Err("spec.quote must be at least 12 characters".into());
    }
    if let Some(reqs) = obj.get("requirements") {
        let ok = reqs
            .as_array()
            .is_some_and(|a| a.iter().all(|r| r.as_str().is_some_and(check_req)));
        if !ok {
            return Err("requirements must be MPP-/X402- ids".into());
        }
    }
    let enums: [(&str, &[&str]); 4] = [
        (
            "bugType",
            &[
                "replay",
                "auth-bypass",
                "settlement",
                "wire",
                "defaults",
                "malleability",
                "precedence",
            ],
        ),
        ("tier", &["offline", "interop", "onchain"]),
        ("role", &["client", "server", "both"]),
        ("provenance", &["generated", "authored"]),
    ];
    for (key, allowed) in enums {
        if let Some(v) = obj.get(key) {
            if !one_of(v, allowed) {
                return Err(format!("{key} must be one of {allowed:?}"));
            }
        }
    }
    if !obj["input"].is_object() {
        return Err("input must be an object".into());
    }
    let expect = obj["expect"]
        .as_object()
        .ok_or("expect must be an object")?;
    if !expect
        .get("outcome")
        .is_some_and(|o| one_of(o, &["accept", "reject"]))
    {
        return Err("expect.outcome must be accept or reject".into());
    }
    if let Some(code) = expect.get("rejectCode") {
        let known: Vec<&str> = RejectCode::ALL.iter().map(|c| c.as_str()).collect();
        if !one_of(code, &known) {
            return Err("expect.rejectCode is not in the shared vocabulary".into());
        }
    }
    Ok(())
}

/// Every vector under `dir/*.json`, files sorted, ids unique.
pub fn load(dir: &Path) -> Result<Vec<Vector>, String> {
    let mut files: Vec<_> = std::fs::read_dir(dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_file() && p.extension().is_some_and(|e| e == "json"))
        .collect();
    files.sort();
    let mut out: Vec<Vector> = Vec::new();
    for path in files {
        let file = path
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_default();
        let text = std::fs::read_to_string(&path).map_err(|e| format!("{file}: {e}"))?;
        let parsed: Value = serde_json::from_str(&text).map_err(|e| format!("{file}: {e}"))?;
        let list = parsed
            .as_array()
            .ok_or_else(|| format!("{file}: must be an array of vectors"))?;
        for raw in list {
            let label = format!(
                "{file}:{}",
                raw.get("id").and_then(Value::as_str).unwrap_or("(no id)")
            );
            validate(raw)
                .map_err(|e| format!("vector {label} violates the conformance ABI: {e}"))?;
            let id = raw["id"].as_str().unwrap_or_default().to_string();
            if out.iter().any(|v| v.id == id) {
                return Err(format!("duplicate vector id {id} ({file})"));
            }
            out.push(Vector {
                id,
                intent: raw["intent"].as_str().unwrap_or_default().to_string(),
                mode: raw["mode"].as_str().unwrap_or_default().to_string(),
                file: file.clone(),
                raw: raw.clone(),
            });
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn committed_vectors_load_and_cover_every_mode() {
        let vectors = load(&crate::repo_root().join("harness/vectors")).unwrap();
        assert!(vectors.len() >= 10);
        for mode in ["build-transaction", "verify-transaction", "canonical-bytes"] {
            assert!(vectors.iter().any(|v| v.mode == mode), "{mode}");
        }
        for v in &vectors {
            assert!(
                crate::run::expectations::VECTOR_INTENTS.contains(&v.intent.as_str()),
                "{} has an unclaimable intent",
                v.id
            );
        }
    }

    #[test]
    fn testee_input_strips_expect_and_metadata() {
        let vectors = load(&crate::repo_root().join("harness/vectors")).unwrap();
        let sent = vectors[0].for_testee(Some("http://127.0.0.1:1"));
        for key in sent.as_object().unwrap().keys() {
            assert!(TESTEE_KEYS.contains(&key.as_str()), "{key}");
        }
        assert_eq!(sent["input"]["rpcUrl"], "http://127.0.0.1:1");
    }

    #[test]
    fn validation_rejects_a_missing_spec_and_stray_keys() {
        let mut v = load(&crate::repo_root().join("harness/vectors")).unwrap()[0]
            .raw
            .clone();
        assert!(validate(&v).is_ok());
        v["stray"] = json!(1);
        assert!(validate(&v).unwrap_err().contains("stray"));
        v.as_object_mut().unwrap().remove("stray");
        v.as_object_mut().unwrap().remove("spec");
        assert!(validate(&v).unwrap_err().contains("spec"));
    }
}
