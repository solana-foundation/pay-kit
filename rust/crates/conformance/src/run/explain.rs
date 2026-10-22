//! Failures explain themselves (DESIGN.md §6.2). Every failing case renders,
//! in this order:
//!
//! 1. the requirement: quoted sentence(s), document, section, pinned SHA;
//! 2. the mutation, in words, with the code it must produce;
//! 3. expected vs actual, decoded, with the first divergent path;
//! 4. the reference: `file:line` of the Rust code that produced the expected
//!    value (resolved from a search string at report time, so line numbers
//!    never rot; `tests::every_reference_resolves` fails when one stops
//!    resolving);
//! 5. the testee's own stderr for that case;
//! 6. the replay command and the raw request line.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;

use serde::Serialize;
use serde_json::{json, Value};

use crate::case::{Case, Expect, Input};
use crate::run::judge::Failure;
use crate::run::vectors::Vector;

/// Where two decoded trees first differ.
#[derive(Debug, Clone, PartialEq)]
pub struct Divergence {
    pub path: String,
    pub expected: Value,
    pub actual: Value,
}

/// The first divergent path between two decoded trees. Arrays named
/// `instructions` are compared as multisets first (identical instructions in
/// another order do not diverge); the remainder is paired in order.
pub fn first_divergence(expected: &Value, actual: &Value) -> Option<Divergence> {
    walk("", expected, actual)
}

fn join(path: &str, key: &str) -> String {
    if path.is_empty() {
        key.to_string()
    } else {
        format!("{path}.{key}")
    }
}

fn walk(path: &str, expected: &Value, actual: &Value) -> Option<Divergence> {
    match (expected, actual) {
        (Value::Object(e), Value::Object(a)) => {
            for (key, ev) in e {
                match a.get(key) {
                    Some(av) => {
                        if let Some(d) = walk(&join(path, key), ev, av) {
                            return Some(d);
                        }
                    }
                    None => {
                        return Some(Divergence {
                            path: join(path, key),
                            expected: ev.clone(),
                            actual: Value::Null,
                        })
                    }
                }
            }
            a.iter()
                .find(|(k, _)| !e.contains_key(*k))
                .map(|(k, av)| Divergence {
                    path: join(path, k),
                    expected: Value::Null,
                    actual: av.clone(),
                })
        }
        (Value::Array(e), Value::Array(a)) => {
            let multiset = path.ends_with("instructions");
            let mut e_left: Vec<(usize, &Value)> = e.iter().enumerate().collect();
            let mut a_left: Vec<(usize, &Value)> = a.iter().enumerate().collect();
            if multiset {
                e_left.retain(|(_, ev)| match a_left.iter().position(|(_, av)| av == ev) {
                    Some(at) => {
                        a_left.remove(at);
                        false
                    }
                    None => true,
                });
            }
            for (n, (i, ev)) in e_left.iter().enumerate() {
                let here = format!("{path}[{i}]");
                match a_left.get(n) {
                    Some((_, av)) => {
                        if let Some(d) = walk(&here, ev, av) {
                            return Some(d);
                        }
                    }
                    None => {
                        return Some(Divergence {
                            path: here,
                            expected: (*ev).clone(),
                            actual: Value::Null,
                        })
                    }
                }
            }
            a_left.get(e_left.len()).map(|(i, av)| Divergence {
                path: format!("{path}[{i}]"),
                expected: Value::Null,
                actual: (*av).clone(),
            })
        }
        (e, a) if e == a => None,
        (e, a) => Some(Divergence {
            path: if path.is_empty() {
                "(root)".into()
            } else {
                path.into()
            },
            expected: e.clone(),
            actual: a.clone(),
        }),
    }
}

/// A place in the Rust tree: a file and a search string that identifies the
/// function (or registry entry). Resolved to a line at report time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SourceRef {
    pub file: String,
    pub needle: String,
    pub what: &'static str,
}

impl SourceRef {
    fn new(file: impl Into<String>, needle: impl Into<String>, what: &'static str) -> Self {
        Self {
            file: file.into(),
            needle: needle.into(),
            what,
        }
    }

    /// `file:line` when the needle still appears.
    pub fn resolve(&self, root: &Path) -> Option<String> {
        let text = std::fs::read_to_string(root.join(&self.file)).ok()?;
        let line = text.lines().position(|l| l.contains(&self.needle))? + 1;
        Some(format!("{}:{line}", self.file))
    }
}

const KIT: &str = "rust/crates/kit/src";
const FILLER: &str = "rust/crates/conformance/src/realize.rs";

/// The Rust code that decides a vector's expected value.
pub fn references(vector: &Vector) -> Vec<SourceRef> {
    let mut refs = Vec::new();
    let input = vector.input();
    let entry = match vector.file.as_str() {
        f if f.starts_with("x402-upto-") => "rust/crates/conformance/src/cases/x402_upto.rs",
        f if f.starts_with("batch-") => "rust/crates/conformance/src/cases/x402_batch.rs",
        "charge-tx-versions.json" => "rust/crates/conformance/src/cases/charge_tx_versions.rs",
        "session-tx-versions.json" => "rust/crates/conformance/src/cases/session_tx_versions.rs",
        f if f.starts_with("session-server-")
            || f == "session-build.json"
            || f == "session-wire-strict.json" =>
        {
            "rust/crates/conformance/src/cases/session_server.rs"
        }
        "x402-tx-versions.json" => "rust/crates/conformance/src/cases/x402_tx_versions.rs",
        f if f.ends_with("-policy.json") && f.starts_with("x402") => {
            "rust/crates/conformance/src/cases/x402_policy.rs"
        }
        f if f.ends_with("-policy.json") => "rust/crates/conformance/src/cases/charge_policy.rs",
        f if f.starts_with("x402") => "rust/crates/conformance/src/cases/x402_exact.rs",
        f if f.starts_with("session") => "rust/crates/conformance/src/cases/session.rs",
        f if f.starts_with("charge") => "rust/crates/conformance/src/cases/charge.rs",
        f if f.starts_with("subscription") => "rust/crates/conformance/src/cases/subscription.rs",
        _ => "rust/crates/conformance/src/cases/canonical.rs",
    };
    refs.push(SourceRef::new(
        entry,
        format!("{} =>", vector.id.replace('-', "_")),
        "registry entry (input, verdict, spec)",
    ));
    match (vector.intent.as_str(), vector.mode.as_str()) {
        ("charge", "build-transaction") => refs.push(SourceRef::new(
            concat_kit("mpp/client/charge.rs"),
            "pub async fn build_charge_transaction_with_options(",
            "kit client builder",
        )),
        ("charge", "verify-transaction") => refs.push(SourceRef::new(
            concat_kit("mpp/server/charge.rs"),
            "pub fn verify_transaction_pre_broadcast(",
            "kit pre-broadcast verifier",
        )),
        ("x402-exact", "build-transaction") => refs.push(SourceRef::new(
            concat_kit("x402/client/exact/payment.rs"),
            if input.get("x402Version").and_then(Value::as_u64) == Some(1) {
                "pub async fn build_payment_header_v1("
            } else {
                "pub async fn build_payment_header("
            },
            "kit x402 client builder",
        )),
        ("x402-exact", "verify-transaction") => refs.push(SourceRef::new(
            concat_kit("x402/server/exact.rs"),
            "pub async fn verify_payment_signature_for_requirements(",
            "kit x402 verifier",
        )),
        ("x402-upto", "build-transaction") => refs.push(SourceRef::new(
            concat_kit("x402/client/upto/payment.rs"),
            "pub async fn build_upto_payload(",
            "kit upto client builder",
        )),
        ("x402-upto", "verify-transaction") => refs.push(SourceRef::new(
            concat_kit("x402/server/upto.rs"),
            "fn prepare_open(",
            "kit upto pre-broadcast verifier",
        )),
        ("x402-batch-settlement", "build-transaction") => refs.push(SourceRef::new(
            concat_kit("x402/client/batch_settlement/payment.rs"),
            "pub async fn build_deposit(",
            "kit batch-settlement client builders",
        )),
        ("x402-batch-settlement", "verify-transaction") => refs.push(SourceRef::new(
            concat_kit("x402/server/batch_settlement.rs"),
            "pub async fn verify_and_reserve_payment(",
            "kit batch-settlement server verifier",
        )),
        ("x402-batch-settlement", "canonical-bytes") => refs.push(SourceRef::new(
            "rust/crates/conformance/src/realize/batch.rs",
            "fn canonical(input: &Value)",
            "kit batch-settlement encoders and wire types",
        )),
        ("session", "verify-transaction") if input.get("sessionServerVerify").is_some() => refs
            .push(SourceRef::new(
                concat_kit("mpp/server/session.rs"),
                match input
                    .pointer("/sessionServerVerify/credential/action")
                    .and_then(Value::as_str)
                {
                    Some("open") => "fn validate_open_request(",
                    Some("topUp") => "async fn prepare_topup_transaction(",
                    Some("close") => "pub async fn process_close(",
                    _ => "async fn verify_voucher_priced(",
                },
                "kit session server",
            )),
        ("session", "verify-transaction") => refs.push(SourceRef::new(
            concat_kit("core/session.rs"),
            "pub async fn accept_voucher(",
            "kit voucher verifier",
        )),
        ("session", "build-transaction") => refs.push(SourceRef::new(
            concat_kit("mpp/client/session.rs"),
            "pub async fn create_payment_channel_session_opener(",
            "kit session client opener",
        )),
        ("subscription", "build-transaction") => refs.push(SourceRef::new(
            concat_kit("mpp/client/subscription.rs"),
            "pub async fn build_subscription_activation_credential(",
            "kit subscription client",
        )),
        ("subscription", "verify-transaction") => {
            refs.push(if input.get("subscriptionActive").is_some() {
                SourceRef::new(
                    concat_kit("mpp/server/subscription.rs"),
                    "pub async fn verify_active_subscription_at(",
                    "kit subscription usability check",
                )
            } else if input.get("subscriptionProof").is_some() {
                SourceRef::new(
                    concat_kit("mpp/protocol/intents/subscription.rs"),
                    "pub fn verify(&self, subscription_delegation: &str)",
                    "kit bearer-proof verifier",
                )
            } else {
                SourceRef::new(
                    concat_kit("mpp/server/subscription.rs"),
                    "pub async fn verify_activation_pre_broadcast(",
                    "kit subscription activation verifier (pre-broadcast)",
                )
            })
        }
        (_, _) => {
            if input.get("voucherPreimage").is_some() {
                refs.push(SourceRef::new(
                    concat_kit("mpp/protocol/intents/session.rs"),
                    "pub fn message_bytes(&self) ->",
                    "kit voucher preimage encoder",
                ));
            }
            if input.get("challengeId").is_some() {
                refs.push(SourceRef::new(
                    concat_kit("mpp/protocol/core/challenge.rs"),
                    "pub fn compute_challenge_id(",
                    "kit challenge id",
                ));
            }
            if input.get("value").is_some() || input.get("sessionWire").is_some() {
                refs.push(SourceRef::new(
                    concat_kit("mpp/protocol/core/types.rs"),
                    "pub fn from_value(value: &serde_json::Value)",
                    "kit JCS encoder (Base64UrlJson)",
                ));
            }
            if input.get("encodeBase64Url").is_some() {
                refs.push(SourceRef::new(
                    "rust/crates/conformance/src/realize.rs",
                    "fn canonical_bytes(",
                    "filler base64url path",
                ));
            }
        }
    }
    let session = "rust/crates/conformance/src/realize/session.rs";
    let (file, needle) = match (vector.intent.as_str(), vector.mode.as_str()) {
        ("charge", "build-transaction") => (FILLER, "async fn charge_build("),
        ("charge", "verify-transaction") => (FILLER, "async fn charge_verify("),
        ("x402-exact", "build-transaction") => (FILLER, "async fn x402_build("),
        ("x402-exact", "verify-transaction") => (FILLER, "async fn x402_verify("),
        ("session", "verify-transaction") if input.get("sessionServerVerify").is_some() => {
            (session, "pub async fn verify(input: &Value)")
        }
        ("session", "build-transaction") => (session, "pub async fn build(input: &Value)"),
        ("session", "verify-transaction") => (FILLER, "async fn session_verify("),
        _ => (FILLER, "fn canonical_bytes("),
    };
    refs.push(SourceRef::new(
        file,
        needle,
        "how the filler drives the kit for this vector",
    ));
    refs
}

fn concat_kit(path: &str) -> String {
    format!("{KIT}/{path}")
}

/// The mutation a case applies, in words, with the code it must produce.
pub fn mutation_words(case: &Case) -> Option<String> {
    let code = match &case.expect {
        Expect::Reject { code, .. } => format!("; expected `{code}`"),
        _ => "; expected accept".into(),
    };
    match &case.input {
        Input::ChargeTransaction {
            mutation: Some(m), ..
        } => Some(format!(
            "valid kit-built transaction, then `{m:?}` ({}){code}",
            m.describe()
        )),
        Input::X402Header(spec) => {
            let mut parts = Vec::new();
            if let Some(m) = &spec.mutation {
                parts.push(format!("`{m:?}` ({})", m.describe()));
            }
            for (key, value) in &spec.accepted_overrides {
                parts.push(format!("accepted.{key} set to {value}"));
            }
            if let Some(pays) = &spec.pays {
                parts.push(format!(
                    "transaction pays {} of {} to {} instead of the route",
                    pays.amount, pays.mint, pays.recipient
                ));
            }
            (!parts.is_empty()).then(|| {
                format!(
                    "valid §3.1 static-layout credential, then {}{code}",
                    parts.join(", ")
                )
            })
        }
        Input::Session(recipe) => recipe
            .describe()
            .map(|what| format!("valid kit-built session credential, then {what}{code}")),
        Input::SessionBuild(recipe) => (!recipe.edits.is_empty()).then(|| {
            let edits: Vec<String> = recipe.edits.iter().map(|e| e.describe()).collect();
            format!(
                "the kit server's challenge, then {}{code}",
                edits.join("; ").replace("credential ", "challenge ")
            )
        }),
        _ => None,
    }
}

/// Pinned SHA of a spec submodule, from the superproject's index.
pub fn pinned_sha(root: &Path, doc: &str) -> Option<String> {
    let checkout = crate::case::SpecRepo::ALL
        .into_iter()
        .find(|repo| {
            doc.strip_prefix(repo.prefix())
                .is_some_and(|rest| rest.starts_with('/'))
        })?
        .checkout();
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["ls-tree", "HEAD", checkout])
        .output()
        .ok()?;
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .nth(2)
        .map(str::to_string)
}

/// Requirement id to text, from `harness/requirements/*.toml`.
pub fn requirement_texts(root: &Path) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for name in ["mpp", "x402", "mpp-solana", "mpp-txv1", "x402-txv1"] {
        let Ok(raw) =
            std::fs::read_to_string(root.join(format!("harness/requirements/{name}.toml")))
        else {
            continue;
        };
        if let Ok(file) = toml::from_str::<crate::reqlint::RequirementsFile>(&raw) {
            for r in file.requirements {
                out.insert(r.id, r.text);
            }
        }
    }
    out
}

/// Everything §6.2 asks a failing case to say.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Explanation {
    pub sdk: String,
    pub case: String,
    pub requirement: Value,
    pub mutation: Option<String>,
    pub message: String,
    pub divergent_path: Option<String>,
    pub expected: Option<Value>,
    pub actual: Option<Value>,
    pub reference: Vec<String>,
    pub stderr: String,
    pub replay: Value,
}

pub struct Context {
    pub root: std::path::PathBuf,
    pub requirements: BTreeMap<String, String>,
    pub cases: BTreeMap<String, Case>,
    pub shas: BTreeMap<String, String>,
}

impl Context {
    pub fn load(root: &Path) -> Self {
        let cases = crate::cases::all()
            .into_iter()
            .map(|c| (c.id.to_string(), c))
            .collect();
        let shas = crate::case::SpecRepo::ALL
            .iter()
            .map(|repo| format!("{}/", repo.prefix()))
            .filter_map(|d| pinned_sha(root, &d).map(|s| (d, s)))
            .collect();
        Self {
            root: root.to_path_buf(),
            requirements: requirement_texts(root),
            cases,
            shas,
        }
    }

    pub fn requirement(&self, vector: &Vector) -> Value {
        let spec = &vector.raw["spec"];
        let doc = spec["doc"].as_str().unwrap_or_default();
        let sha = self
            .shas
            .iter()
            .find(|(prefix, _)| doc.starts_with(prefix.as_str()))
            .map(|(_, s)| s.clone());
        let ids: Vec<Value> = vector
            .requirements()
            .into_iter()
            .map(|id| {
                json!({ "id": id, "text": self.requirements.get(&id).cloned().unwrap_or_default() })
            })
            .collect();
        json!({
            "doc": doc,
            "section": spec["section"],
            "quote": spec["quote"],
            "pinnedSha": sha,
            "requirements": ids,
        })
    }

    pub fn references(&self, vector: &Vector) -> Vec<String> {
        references(vector)
            .into_iter()
            .map(|r| match r.resolve(&self.root) {
                Some(at) => format!("{at} ({})", r.what),
                None => format!("{} `{}` (unresolved; {})", r.file, r.needle, r.what),
            })
            .collect()
    }

    pub fn explain(
        &self,
        sdk: &str,
        vector: &Vector,
        failure: &Failure,
        stderr: &str,
        request_line: &str,
    ) -> Explanation {
        Explanation {
            sdk: sdk.to_string(),
            case: vector.id.clone(),
            requirement: self.requirement(vector),
            mutation: self.cases.get(&vector.id).and_then(mutation_words),
            message: failure.message.clone(),
            divergent_path: failure.path.clone(),
            expected: failure.expected.clone(),
            actual: failure.actual.clone(),
            reference: self.references(vector),
            stderr: stderr.to_string(),
            replay: json!({
                "command": format!("pkc case run --sdk {sdk} {}", vector.id),
                "request": request_line,
            }),
        }
    }
}

fn trimmed(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.to_string();
    }
    let mut cut = max;
    while !text.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}\n... ({} more bytes)", &text[..cut], text.len() - cut)
}

impl Explanation {
    /// Markdown with the six sections, in §6.2 order. `verbose` prints the
    /// full decoded trees; otherwise only the first divergent field.
    pub fn markdown(&self, verbose: bool) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "### {} / {}\n", self.sdk, self.case);
        let _ = writeln!(out, "{}\n", self.message);
        let r = &self.requirement;
        let _ = writeln!(out, "**1. Requirement**\n");
        let _ = writeln!(
            out,
            "> {}\n\n`{}` § {} (pinned {})",
            r["quote"].as_str().unwrap_or_default(),
            r["doc"].as_str().unwrap_or_default(),
            r["section"].as_str().unwrap_or_default(),
            r["pinnedSha"].as_str().unwrap_or("unknown")
        );
        for req in r["requirements"].as_array().into_iter().flatten() {
            let _ = writeln!(
                out,
                "- {}: {}",
                req["id"].as_str().unwrap_or_default(),
                req["text"].as_str().unwrap_or_default()
            );
        }
        let _ = writeln!(out, "\n**2. Mutation**\n");
        let _ = writeln!(
            out,
            "{}\n",
            self.mutation
                .as_deref()
                .unwrap_or("none: the input is the valid case itself")
        );
        let _ = writeln!(out, "**3. Expected vs actual (decoded)**\n");
        let _ = writeln!(
            out,
            "first divergent path: `{}`\n",
            self.divergent_path.as_deref().unwrap_or("(none recorded)")
        );
        let show = |v: &Option<Value>| -> String {
            match v {
                None => "(none)".into(),
                Some(v) => serde_json::to_string_pretty(v).unwrap_or_default(),
            }
        };
        let (expected, actual) = match (&self.divergent_path, verbose) {
            (Some(path), false) => (pick(&self.expected, path), pick(&self.actual, path)),
            _ => (self.expected.clone(), self.actual.clone()),
        };
        let _ = writeln!(
            out,
            "expected:\n```json\n{}\n```\nactual:\n```json\n{}\n```\n",
            trimmed(&show(&expected), 4000),
            trimmed(&show(&actual), 4000)
        );
        let _ = writeln!(out, "**4. Reference**\n");
        for r in &self.reference {
            let _ = writeln!(out, "- {r}");
        }
        let _ = writeln!(out, "\n**5. Testee stderr**\n");
        let stderr = if self.stderr.trim().is_empty() {
            "(empty)".to_string()
        } else {
            trimmed(self.stderr.trim(), 4000)
        };
        let _ = writeln!(out, "```\n{stderr}\n```\n");
        let _ = writeln!(out, "**6. Replay**\n");
        let _ = writeln!(
            out,
            "```sh\n{}\n```\nrequest:\n```json\n{}\n```",
            self.replay["command"].as_str().unwrap_or_default(),
            trimmed(self.replay["request"].as_str().unwrap_or_default(), 8000)
        );
        out
    }
}

/// The sub-tree at a dotted/indexed path, or the whole value.
fn pick(value: &Option<Value>, path: &str) -> Option<Value> {
    let mut current = value.as_ref()?;
    let mut prefix = String::new();
    for segment in path.split('.') {
        let (key, indexes) = match segment.find('[') {
            Some(at) => (&segment[..at], &segment[at..]),
            None => (segment, ""),
        };
        if !key.is_empty() {
            match current.get(key) {
                Some(next) => current = next,
                None => return value.clone(),
            }
        }
        for index in indexes
            .split(['[', ']'])
            .filter(|s| !s.is_empty())
            .filter_map(|s| s.parse::<usize>().ok())
        {
            match current.get(index) {
                Some(next) => current = next,
                None => return Some(current.clone()),
            }
        }
        prefix.push_str(segment);
    }
    Some(current.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::run::vectors;

    #[test]
    fn names_the_first_divergent_field() {
        let e =
            json!({"instructions": [{"instruction": "A", "amount": "1"}, {"instruction": "B"}]});
        let a =
            json!({"instructions": [{"instruction": "B"}, {"instruction": "A", "amount": "2"}]});
        let d = first_divergence(&e, &a).unwrap();
        assert_eq!(d.path, "instructions[0].amount");
        assert_eq!(d.expected, json!("1"));
        assert_eq!(d.actual, json!("2"));
        assert!(first_divergence(&e, &e).is_none());
        // Reordered but identical instructions do not diverge.
        let r =
            json!({"instructions": [{"instruction": "B"}, {"instruction": "A", "amount": "1"}]});
        assert!(first_divergence(&e, &r).is_none());
        let missing = json!({"instructions": [{"instruction": "A", "amount": "1"}]});
        assert_eq!(
            first_divergence(&e, &missing).unwrap().path,
            "instructions[1]"
        );
    }

    #[test]
    fn every_reference_resolves() {
        let root = crate::repo_root();
        for v in vectors::load(&root.join("harness/vectors")).unwrap() {
            for r in references(&v) {
                assert!(
                    r.resolve(&root).is_some(),
                    "{}: {} no longer contains {:?}",
                    v.id,
                    r.file,
                    r.needle
                );
            }
        }
    }

    // A planted failure renders all six §6.2 sections, in order.
    #[test]
    fn a_failure_renders_the_six_elements() {
        let root = crate::repo_root();
        let ctx = Context::load(&root);
        let v = vectors::load(&root.join("harness/vectors"))
            .unwrap()
            .into_iter()
            .find(|v| v.id == "charge-verify-wrong-amount-reject")
            .unwrap();
        let failure = Failure {
            message: "planted".into(),
            path: Some("outcome".into()),
            expected: Some(json!({"outcome": "reject"})),
            actual: Some(json!({"outcome": "accept"})),
        };
        let explanation = ctx.explain("planted", &v, &failure, "Traceback: boom", "{\"id\":1}");
        let md = explanation.markdown(false);
        let mut at = 0;
        for section in [
            "**1. Requirement**",
            "**2. Mutation**",
            "**3. Expected vs actual (decoded)**",
            "**4. Reference**",
            "**5. Testee stderr**",
            "**6. Replay**",
        ] {
            let found = md[at..]
                .find(section)
                .unwrap_or_else(|| panic!("{section} missing or out of order:\n{md}"));
            at += found;
        }
        assert!(md.contains("BumpAmount"), "{md}");
        assert!(md.contains("pkc case run --sdk planted charge-verify-wrong-amount-reject"));
        assert!(md.contains("Traceback: boom"));
        assert!(
            md.contains("rust/crates/kit/src/mpp/server/charge.rs:"),
            "{md}"
        );
        assert!(explanation.requirement["quote"]
            .as_str()
            .is_some_and(|q| !q.is_empty()));
    }
}
