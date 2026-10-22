//! Per-SDK conformance expectations with exact-set reconciliation, the Rust
//! port of `harness/src/expectations.ts` (which the vitest protocol and flow
//! drivers still use; both parse every committed file in their tests, so the
//! two stay in lockstep).
//!
//! Each SDK declares, in `harness/expectations/<language>.toml`, which suites
//! it claims, which cases it cannot express (`unsupported`) and which cases it
//! is known to fail. The reconciliation is exact in both directions:
//!
//! - a claimed case that fails and is not listed fails the run;
//! - a `known_failing` case that passes fails the run ("remove it");
//! - an `unsupported` case is still executed and must report unsupported, so
//!   a stale entry fails the run;
//! - every list entry must match at least one real case.
//!
//! Nothing is skipped. A case is either executed and asserted, or recorded as
//! `unclaimed` (the SDK does not claim that suite or intent).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::Path;

use serde::Serialize;
use toml::Value;

/// Vector intents an SDK may claim. A claim outside this list is a typo that
/// would otherwise leave every vector of the intended intent unclaimed.
pub const VECTOR_INTENTS: [&str; 6] = [
    "charge",
    "x402-exact",
    "session",
    "x402-upto",
    "x402-batch-settlement",
    "subscription",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Suite {
    Vector,
    Protocol,
    Flow,
    /// Offline cross-verification (`pkc run --cross`), claimed by the
    /// verifying (server) SDK. Case key `cross/<case>/<client>/<server>`;
    /// a cell passes when the server agrees with the Rust judge.
    Cross,
    /// `pkc run --tier interop`: case ids `<scenario>/<client>/<server>`,
    /// claims `<protocol>:<scheme>:<role>` (`crate::interop::claims`).
    Interop,
}

impl Suite {
    pub const ALL: [Suite; 5] = [
        Suite::Vector,
        Suite::Protocol,
        Suite::Flow,
        Suite::Cross,
        Suite::Interop,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Suite::Vector => "vector",
            Suite::Protocol => "protocol",
            Suite::Flow => "flow",
            Suite::Cross => "cross",
            Suite::Interop => "interop",
        }
    }

    fn parse(name: &str) -> Option<Self> {
        Suite::ALL.into_iter().find(|s| s.as_str() == name)
    }
}

impl fmt::Display for Suite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A case as the reconciler sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaseRef {
    pub suite: Suite,
    pub id: String,
    /// Capability bucket inside the suite: the intent for vectors, the suite
    /// name for protocol and flow.
    pub capability: String,
}

impl CaseRef {
    pub fn vector(id: &str, intent: &str) -> Self {
        Self {
            suite: Suite::Vector,
            id: id.to_string(),
            capability: intent.to_string(),
        }
    }

    pub fn key(&self) -> String {
        format!("{}/{}", self.suite, self.id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Unclaimed,
    Unsupported { reason: String },
    KnownFailing { reason: String, tracking: String },
    Pass,
}

impl Decision {
    pub fn kind(&self) -> &'static str {
        match self {
            Decision::Unclaimed => "unclaimed",
            Decision::Unsupported { .. } => "unsupported",
            Decision::KnownFailing { .. } => "known_failing",
            Decision::Pass => "pass",
        }
    }
}

/// What actually happened when a case was executed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Observed {
    Pass,
    Fail { detail: String },
    Unsupported { detail: String },
}

impl Observed {
    pub fn kind(&self) -> &'static str {
        match self {
            Observed::Pass => "pass",
            Observed::Fail { .. } => "fail",
            Observed::Unsupported { .. } => "unsupported",
        }
    }

    pub fn detail(&self) -> Option<&str> {
        match self {
            Observed::Pass => None,
            Observed::Fail { detail } | Observed::Unsupported { detail } => Some(detail),
        }
    }
}

#[derive(Debug, Clone)]
enum Matcher {
    Id(String),
    Glob(Vec<String>),
}

impl Matcher {
    fn matches(&self, key: &str) -> bool {
        match self {
            Matcher::Id(id) => id == key,
            Matcher::Glob(parts) => glob_match(parts, key),
        }
    }
}

/// `*` matches any run of characters; everything else is literal. `parts`
/// is the pattern split on `*`.
fn glob_match(parts: &[String], key: &str) -> bool {
    let Some((first, rest)) = parts.split_first() else {
        return key.is_empty();
    };
    let Some(mut remaining) = key.strip_prefix(first.as_str()) else {
        return false;
    };
    let Some((last, middle)) = rest.split_last() else {
        return remaining.is_empty();
    };
    for part in middle {
        match remaining.find(part.as_str()) {
            Some(at) => remaining = &remaining[at + part.len()..],
            None => return false,
        }
    }
    remaining.ends_with(last.as_str())
}

#[derive(Debug, Clone)]
pub struct UnsupportedEntry {
    pub label: String,
    pub suite: Suite,
    pub reason: String,
    matcher: Matcher,
}

impl UnsupportedEntry {
    pub fn matches(&self, key: &str) -> bool {
        self.matcher.matches(key)
    }
}

#[derive(Debug, Clone)]
pub struct KnownFailing {
    pub reason: String,
    pub tracking: String,
}

/// One parsed `harness/expectations/<language>.toml`.
#[derive(Debug, Clone)]
pub struct Expectations {
    pub language: String,
    capabilities: BTreeMap<Suite, BTreeSet<String>>,
    /// Whether the SDK's testee drives the SDK at the clock a vector pins
    /// (`sessionVoucherVerify.nowSeconds`). Required when the vector suite is
    /// claimed (no default); cross-checked against the testee's
    /// `capabilities` op.
    pub honours_clock: Option<bool>,
    pub unsupported: Vec<UnsupportedEntry>,
    pub known_failing: BTreeMap<String, KnownFailing>,
    pub source: String,
}

fn fail<T>(source: &str, message: impl fmt::Display) -> Result<T, String> {
    Err(format!("{source}: {message}"))
}

/// Every id and pattern names its suite, so each entry is checked by exactly
/// one driver and none escapes the dangling-entry check.
fn suite_of(key: &str, source: &str) -> Result<Suite, String> {
    let prefix = key.split('/').next().unwrap_or_default();
    match Suite::parse(prefix) {
        Some(suite) if key.starts_with(&format!("{prefix}/")) => Ok(suite),
        _ => fail(
            source,
            format!("\"{key}\" must start with one of vector/, protocol/, flow/, cross/, interop/"),
        ),
    }
}

/// `https://github.com/<repo>/issues/<n>` or `FINDINGS.md#<anchor>`.
fn valid_tracking(tracking: &str) -> bool {
    if let Some(rest) = tracking.strip_prefix("https://github.com/") {
        if rest.chars().any(char::is_whitespace) {
            return false;
        }
        return match rest.rsplit_once("/issues/") {
            Some((repo, number)) => {
                !repo.is_empty() && !number.is_empty() && number.chars().all(|c| c.is_ascii_digit())
            }
            None => false,
        };
    }
    match tracking.strip_prefix("FINDINGS.md#") {
        Some(anchor) => {
            !anchor.is_empty()
                && anchor
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        }
        None => false,
    }
}

fn string_array(value: &Value, source: &str, field: &str) -> Result<Vec<String>, String> {
    match value.as_array() {
        Some(items) if items.iter().all(Value::is_str) => Ok(items
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect()),
        _ => fail(source, format!("{field} must be an array of strings")),
    }
}

const KNOWN_FAILING_SHAPE: &str =
    "every [[known_failing]] needs exactly one of a string `id` or a non-empty `ids` array, and a non-empty reason";

impl Expectations {
    pub fn parse(text: &str, source: &str) -> Result<Self, String> {
        let raw: toml::Table = text
            .parse()
            .map_err(|e| format!("{source}: invalid TOML: {e}"))?;
        for key in raw.keys() {
            if !["language", "capabilities", "unsupported", "known_failing"].contains(&key.as_str())
            {
                return fail(source, format!("unknown top-level key \"{key}\""));
            }
        }
        let language = match raw.get("language").and_then(Value::as_str) {
            Some(l) if !l.is_empty() => l.to_string(),
            _ => return fail(source, "language must be a non-empty string"),
        };

        let mut capabilities: BTreeMap<Suite, BTreeSet<String>> =
            Suite::ALL.iter().map(|s| (*s, BTreeSet::new())).collect();
        let mut honours_clock = None;
        if let Some(caps) = raw.get("capabilities") {
            let Some(caps) = caps.as_table() else {
                return fail(source, "capabilities must be a table");
            };
            for (name, value) in caps {
                if name == "honours_clock" {
                    match value.as_bool() {
                        Some(b) => honours_clock = Some(b),
                        None => {
                            return fail(source, "capabilities.honours_clock must be a boolean")
                        }
                    }
                    continue;
                }
                let Some(suite) = Suite::parse(name) else {
                    return fail(source, format!("unknown capability suite \"{name}\""));
                };
                let claimed = capabilities.entry(suite).or_default();
                if suite == Suite::Interop {
                    for claim in string_array(value, source, "capabilities.interop")? {
                        if crate::interop::claims::Claim::parse(&claim).is_none() {
                            let all: Vec<String> = crate::interop::claims::Claim::all()
                                .iter()
                                .map(ToString::to_string)
                                .collect();
                            return fail(
                                source,
                                format!(
                                    "unknown interop claim \"{claim}\" (expected <protocol>:<scheme>:<role>, one of {})",
                                    all.join(", ")
                                ),
                            );
                        }
                        if !claimed.insert(claim.clone()) {
                            return fail(source, format!("duplicate interop claim {claim}"));
                        }
                    }
                } else if suite == Suite::Vector {
                    for intent in string_array(value, source, "capabilities.vector")? {
                        if !VECTOR_INTENTS.contains(&intent.as_str()) {
                            return fail(
                                source,
                                format!(
                                    "unknown vector intent \"{intent}\" (expected one of {})",
                                    VECTOR_INTENTS.join(", ")
                                ),
                            );
                        }
                        claimed.insert(intent);
                    }
                } else {
                    match value.as_bool() {
                        Some(true) => {
                            claimed.insert(name.clone());
                        }
                        Some(false) => {}
                        None => {
                            return fail(source, format!("capabilities.{name} must be a boolean"))
                        }
                    }
                }
            }
        }
        if !capabilities[&Suite::Vector].is_empty() && honours_clock.is_none() {
            return fail(
                source,
                "claims vector intents, so capabilities.honours_clock must say whether the testee honours the clock a vector pins",
            );
        }

        let mut unsupported = Vec::new();
        let mut seen_ids = BTreeSet::new();
        let entries = raw
            .get("unsupported")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for entry in entries {
            let Some(entry) = entry.as_table() else {
                return fail(source, "every [[unsupported]] must be a table");
            };
            let reason = match entry.get("reason").and_then(Value::as_str) {
                Some(r) if !r.is_empty() => r.to_string(),
                _ => return fail(source, "every [[unsupported]] needs a non-empty reason"),
            };
            let pattern = entry.get("pattern").and_then(Value::as_str);
            let ids = entry.get("ids");
            if pattern.is_some() == ids.is_some() {
                return fail(
                    source,
                    "every [[unsupported]] needs exactly one of `pattern` or `ids`",
                );
            }
            for key in entry.keys() {
                if !["reason", "pattern", "ids"].contains(&key.as_str()) {
                    return fail(source, format!("unknown [[unsupported]] key \"{key}\""));
                }
            }
            match (pattern, ids) {
                (Some(pattern), _) => unsupported.push(UnsupportedEntry {
                    label: format!("pattern \"{pattern}\""),
                    suite: suite_of(pattern, source)?,
                    reason,
                    matcher: Matcher::Glob(pattern.split('*').map(str::to_string).collect()),
                }),
                (None, Some(ids)) => {
                    let ids = string_array(ids, source, "unsupported.ids")?;
                    for id in &ids {
                        if !seen_ids.insert(id.clone()) {
                            return fail(source, format!("duplicate unsupported id {id}"));
                        }
                    }
                    // One entry per id, so a stale id is reported individually.
                    for id in ids {
                        unsupported.push(UnsupportedEntry {
                            label: format!("id \"{id}\""),
                            suite: suite_of(&id, source)?,
                            reason: reason.clone(),
                            matcher: Matcher::Id(id),
                        });
                    }
                }
                (None, None) => unreachable!("checked above"),
            }
        }

        let mut known_failing = BTreeMap::new();
        let entries = raw
            .get("known_failing")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for entry in entries {
            let Some(table) = entry.as_table() else {
                return fail(source, KNOWN_FAILING_SHAPE);
            };
            for key in table.keys() {
                if !["id", "ids", "reason", "tracking"].contains(&key.as_str()) {
                    return fail(source, format!("unknown [[known_failing]] key \"{key}\""));
                }
            }
            // `ids` lists several cases sharing one cause (an interop gap
            // usually fails every pair of one adapter); each id is still
            // reconciled, and reported stale, on its own.
            let ids: Vec<String> = match (table.get("id"), table.get("ids")) {
                (Some(id), None) => match id.as_str() {
                    Some(id) => vec![id.to_string()],
                    None => return fail(source, KNOWN_FAILING_SHAPE),
                },
                (None, Some(ids)) => {
                    let ids = string_array(ids, source, "known_failing.ids")?;
                    if ids.is_empty() {
                        return fail(source, KNOWN_FAILING_SHAPE);
                    }
                    ids
                }
                _ => return fail(source, KNOWN_FAILING_SHAPE),
            };
            let reason = match table.get("reason").and_then(Value::as_str) {
                Some(r) if !r.is_empty() => r,
                _ => return fail(source, KNOWN_FAILING_SHAPE),
            };
            let tracking = table.get("tracking").and_then(Value::as_str);
            let Some(tracking) = tracking.filter(|t| valid_tracking(t)) else {
                return fail(
                    source,
                    format!(
                        "known_failing {} needs tracking = a GitHub issue URL or \"FINDINGS.md#<anchor>\"",
                        ids[0]
                    ),
                );
            };
            for id in ids {
                if known_failing.contains_key(&id) {
                    return fail(source, format!("duplicate known_failing {id}"));
                }
                suite_of(&id, source)?;
                known_failing.insert(
                    id,
                    KnownFailing {
                        reason: reason.to_string(),
                        tracking: tracking.to_string(),
                    },
                );
            }
        }

        // An entry for a suite the SDK does not claim would never be executed,
        // so it could never be found stale.
        let mut entry_suites: BTreeSet<Suite> = unsupported.iter().map(|u| u.suite).collect();
        for id in known_failing.keys() {
            entry_suites.insert(suite_of(id, source)?);
        }
        for suite in entry_suites {
            if capabilities[&suite].is_empty() {
                return fail(
                    source,
                    format!("has {suite}/ entries but does not claim the {suite} suite"),
                );
            }
        }

        Ok(Self {
            language,
            capabilities,
            honours_clock,
            unsupported,
            known_failing,
            source: source.to_string(),
        })
    }

    pub fn load(path: &Path) -> Result<Self, String> {
        let file = path
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_default();
        let text = std::fs::read_to_string(path).map_err(|e| format!("{file}: {e}"))?;
        let exp = Self::parse(&text, &file)?;
        if format!("{}.toml", exp.language) != file {
            return fail(
                &file,
                format!("language \"{}\" does not match the file name", exp.language),
            );
        }
        Ok(exp)
    }

    /// Claimed capability buckets of a suite.
    pub fn claims(&self, suite: Suite) -> &BTreeSet<String> {
        &self.capabilities[&suite]
    }

    pub fn decide(&self, case: &CaseRef) -> Result<Decision, String> {
        if !self.capabilities[&case.suite].contains(&case.capability) {
            return Ok(Decision::Unclaimed);
        }
        let key = case.key();
        let unsupported = self.unsupported.iter().find(|u| u.matches(&key));
        let known = self.known_failing.get(&key);
        match (unsupported, known) {
            (Some(_), Some(_)) => fail(
                &self.source,
                format!("{key} is both unsupported and known_failing"),
            ),
            (Some(u), None) => Ok(Decision::Unsupported {
                reason: u.reason.clone(),
            }),
            (None, Some(k)) => Ok(Decision::KnownFailing {
                reason: k.reason.clone(),
                tracking: k.tracking.clone(),
            }),
            (None, None) => Ok(Decision::Pass),
        }
    }

    /// Every list entry for `suite` must match a real case of a claimed
    /// capability, so a renamed or deleted case cannot leave a silent hole.
    pub fn dangling(&self, suite: Suite, cases: &[CaseRef]) -> Vec<String> {
        let claimed: Vec<String> = cases
            .iter()
            .filter(|c| self.capabilities[&c.suite].contains(&c.capability))
            .map(CaseRef::key)
            .collect();
        let mut problems = Vec::new();
        for u in self.unsupported.iter().filter(|u| u.suite == suite) {
            if !claimed.iter().any(|k| u.matches(k)) {
                problems.push(format!("unsupported {} matches no claimed case", u.label));
            }
        }
        for id in self.known_failing.keys() {
            if id.starts_with(&format!("{suite}/")) && !claimed.contains(id) {
                problems.push(format!("known_failing \"{id}\" matches no claimed case"));
            }
        }
        problems
    }

    /// Turn (decision, observation) into a verdict. `Err` means the run must
    /// fail, with a message that says exactly which file to edit.
    pub fn reconcile(
        &self,
        case: &CaseRef,
        decision: &Decision,
        observed: &Observed,
    ) -> Result<(), String> {
        let key = case.key();
        let at = format!("harness/expectations/{}", self.source);
        match (decision, observed) {
            (Decision::Unclaimed, _) => Err(format!("{key}: unclaimed cases must not be executed")),
            (Decision::Unsupported { .. }, Observed::Unsupported { .. })
            | (Decision::KnownFailing { .. }, Observed::Fail { .. })
            | (Decision::Pass, Observed::Pass) => Ok(()),
            (Decision::Unsupported { .. }, Observed::Pass) => Err(format!(
                "{key} is listed unsupported in {at} but the runner passed it; remove or narrow the unsupported pattern"
            )),
            (Decision::Unsupported { .. }, Observed::Fail { detail }) => Err(format!(
                "{key} is listed unsupported in {at} but the runner handled and failed it; remove or narrow the unsupported pattern ({detail})"
            )),
            (Decision::KnownFailing { .. }, Observed::Pass) => Err(format!(
                "{key} now passes; remove it from known_failing in {at}"
            )),
            (Decision::KnownFailing { .. }, Observed::Unsupported { detail }) => Err(format!(
                "{key} is known_failing but the runner reports unsupported: {detail}"
            )),
            (Decision::Pass, Observed::Unsupported { detail }) => Err(format!(
                "{key}: runner reports unsupported ({detail}) but {at} does not list it; add an [[unsupported]] entry with a reason or implement it"
            )),
            (Decision::Pass, Observed::Fail { detail }) => Err(format!(
                "{key} failed: {detail}\n(if this is a known gap, add it to known_failing in {at} with tracking)"
            )),
        }
    }
}

/// Every expectations file, keyed by language.
pub fn load_all(dir: &Path) -> Result<BTreeMap<String, Expectations>, String> {
    let mut files: Vec<_> = std::fs::read_dir(dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "toml"))
        .collect();
    files.sort();
    let mut out = BTreeMap::new();
    for path in files {
        let exp = Expectations::load(&path)?;
        out.insert(exp.language.clone(), exp);
    }
    Ok(out)
}

/// Completeness under `--require`: every claimed case must have been
/// observed. Catches a narrowed run (`--case` filters, an aborted testee, a
/// language dropped from the selection) that would otherwise look green.
pub fn missing_claimed<'a>(
    exp: &Expectations,
    cases: &'a [CaseRef],
    observed: &BTreeSet<String>,
) -> Result<Vec<&'a CaseRef>, String> {
    let mut missing = Vec::new();
    for case in cases {
        if exp.decide(case)? != Decision::Unclaimed && !observed.contains(&case.key()) {
            missing.push(case);
        }
    }
    Ok(missing)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOML: &str = r#"
language = "fake"
[capabilities]
vector = ["charge"]
protocol = true
honours_clock = true
[[unsupported]]
pattern = "vector/charge-verify-*"
reason = "client-only"
[[known_failing]]
id = "vector/charge-build-broken"
reason = "decimals default"
tracking = "FINDINGS.md#fake-decimals"
"#;

    fn exp() -> Expectations {
        Expectations::parse(TOML, "fake.toml").unwrap()
    }

    fn r(id: &str) -> CaseRef {
        CaseRef::vector(id, "charge")
    }

    fn err(text: &str) -> String {
        Expectations::parse(text, "x.toml").unwrap_err()
    }

    #[test]
    fn rejects_unknown_keys_missing_tracking_and_bad_tracking() {
        assert!(err("language=\"x\"\nfoo=1").contains("unknown top-level"));
        assert!(
            err("language=\"x\"\n[[known_failing]]\nid=\"vector/a\"\nreason=\"r\"")
                .contains("tracking")
        );
        assert!(err(
            "language=\"x\"\n[[known_failing]]\nid=\"vector/a\"\nreason=\"r\"\ntracking=\"TODO\""
        )
        .contains("tracking"));
    }

    #[test]
    fn accepts_issue_and_findings_tracking_only() {
        assert!(valid_tracking(
            "https://github.com/solana-foundation/pay-kit/issues/12"
        ));
        assert!(valid_tracking("FINDINGS.md#ts-x402-accepted-not-bound"));
        assert!(!valid_tracking("https://github.com/a/b/pull/12"));
        assert!(!valid_tracking("FINDINGS.md#Upper"));
        assert!(!valid_tracking("TODO"));
    }

    #[test]
    fn rejects_a_misspelled_vector_intent_claim() {
        assert!(
            err("language=\"x\"\n[capabilities]\nvector=[\"x402-exat\"]\nhonours_clock=true")
                .contains("unknown vector intent \"x402-exat\"")
        );
        let ok = Expectations::parse(
            "language=\"x\"\n[capabilities]\nvector=[\"x402-exact\"]\nhonours_clock=false",
            "x.toml",
        )
        .unwrap();
        assert!(ok.claims(Suite::Vector).contains("x402-exact"));
    }

    #[test]
    fn a_vector_claim_must_state_honours_clock() {
        assert!(
            err("language=\"x\"\n[capabilities]\nvector=[\"charge\"]").contains("honours_clock")
        );
    }

    #[test]
    fn rejects_entries_for_an_unclaimed_suite() {
        assert!(
            err("language=\"x\"\n[[unsupported]]\nids=[\"protocol/a\"]\nreason=\"r\"")
                .contains("does not claim the protocol suite")
        );
    }

    #[test]
    fn rejects_ids_without_a_suite_prefix() {
        assert!(
            err("language=\"x\"\n[[unsupported]]\nids=[\"charge-a\"]\nreason=\"r\"")
                .contains("must start with")
        );
    }

    #[test]
    fn rejects_an_unsupported_entry_without_a_reason() {
        assert!(
            err("language=\"x\"\n[[unsupported]]\npattern=\"vector/*\"\nreason=\"\"")
                .contains("reason")
        );
    }

    #[test]
    fn decide_classifies_every_case_into_exactly_one_bucket() {
        let exp = exp();
        let kind = |c: &CaseRef| exp.decide(c).unwrap().kind();
        assert_eq!(
            kind(&CaseRef::vector("x402-basic", "x402-exact")),
            "unclaimed"
        );
        assert_eq!(kind(&r("charge-verify-ok")), "unsupported");
        assert_eq!(kind(&r("charge-build-broken")), "known_failing");
        assert_eq!(kind(&r("charge-build-ok")), "pass");
        let flow = CaseRef {
            suite: Suite::Flow,
            id: "flow-a".into(),
            capability: "flow".into(),
        };
        assert_eq!(kind(&flow), "unclaimed");
    }

    fn verdict(exp: &Expectations, id: &str, observed: Observed) -> Result<(), String> {
        let case = r(id);
        exp.reconcile(&case, &exp.decide(&case).unwrap(), &observed)
    }

    fn failed() -> Observed {
        Observed::Fail {
            detail: "boom".into(),
        }
    }

    fn unsupported() -> Observed {
        Observed::Unsupported {
            detail: "unsupported-mode".into(),
        }
    }

    #[test]
    fn reconcile_positive_controls() {
        let exp = exp();
        assert!(verdict(&exp, "charge-build-ok", Observed::Pass).is_ok());
        assert!(verdict(&exp, "charge-build-broken", failed()).is_ok());
        assert!(verdict(&exp, "charge-verify-ok", unsupported()).is_ok());
    }

    #[test]
    fn an_unlisted_failure_fails() {
        let message = verdict(&exp(), "charge-build-ok", failed()).unwrap_err();
        assert!(
            message.contains("known_failing in harness/expectations/fake.toml"),
            "{message}"
        );
    }

    #[test]
    fn a_listed_failure_that_passes_fails() {
        let message = verdict(&exp(), "charge-build-broken", Observed::Pass).unwrap_err();
        assert!(message.contains("now passes; remove it"), "{message}");
    }

    #[test]
    fn an_unlisted_unsupported_result_fails() {
        assert!(verdict(&exp(), "charge-build-ok", unsupported()).is_err());
    }

    #[test]
    fn a_stale_unsupported_entry_fails() {
        let exp = exp();
        assert!(verdict(&exp, "charge-verify-ok", Observed::Pass).is_err());
        assert!(verdict(&exp, "charge-verify-ok", failed()).is_err());
    }

    #[test]
    fn a_known_failure_reported_unsupported_fails() {
        assert!(verdict(&exp(), "charge-build-broken", unsupported()).is_err());
    }

    #[test]
    fn dangling_only_checks_entries_of_the_suite_being_run() {
        assert!(exp().dangling(Suite::Protocol, &[]).is_empty());
    }

    #[test]
    fn dangling_flags_entries_that_match_no_claimed_case() {
        let exp = exp();
        assert_eq!(
            exp.dangling(Suite::Vector, &[r("charge-build-ok")]),
            vec![
                "unsupported pattern \"vector/charge-verify-*\" matches no claimed case"
                    .to_string(),
                "known_failing \"vector/charge-build-broken\" matches no claimed case".to_string(),
            ]
        );
        assert!(exp
            .dangling(
                Suite::Vector,
                &[r("charge-verify-ok"), r("charge-build-broken")]
            )
            .is_empty());
    }

    fn listed() -> Expectations {
        Expectations::parse(
            "language=\"y\"\n[capabilities]\nvector=[\"charge\"]\nhonours_clock=true\n[[unsupported]]\nids=[\"vector/a\",\"vector/b\"]\nreason=\"server-only\"",
            "y.toml",
        )
        .unwrap()
    }

    #[test]
    fn unsupported_ids_match_exactly_the_listed_ids() {
        let listed = listed();
        assert_eq!(listed.decide(&r("a")).unwrap().kind(), "unsupported");
        assert_eq!(listed.decide(&r("b")).unwrap().kind(), "unsupported");
        assert_eq!(listed.decide(&r("ab")).unwrap().kind(), "pass");
    }

    #[test]
    fn each_stale_id_is_reported_individually() {
        assert_eq!(
            listed().dangling(Suite::Vector, &[r("a")]),
            vec!["unsupported id \"vector/b\" matches no claimed case".to_string()]
        );
    }

    #[test]
    fn rejects_pattern_and_ids_together_and_duplicate_ids() {
        assert!(err(
            "language=\"y\"\n[[unsupported]]\nids=[\"vector/a\"]\npattern=\"x\"\nreason=\"r\""
        )
        .contains("exactly one"));
        assert!(err("language=\"y\"\n[[unsupported]]\nids=[\"vector/a\"]\nreason=\"r\"\n[[unsupported]]\nids=[\"vector/a\"]\nreason=\"s\"").contains("duplicate"));
    }

    #[test]
    fn a_case_both_unsupported_and_known_failing_is_an_error() {
        let both = Expectations::parse(
            "language=\"z\"\n[capabilities]\nvector=[\"charge\"]\nhonours_clock=true\n[[unsupported]]\nids=[\"vector/a\"]\nreason=\"r\"\n[[known_failing]]\nid=\"vector/a\"\nreason=\"r\"\ntracking=\"FINDINGS.md#a\"",
            "z.toml",
        )
        .unwrap();
        assert!(both.decide(&r("a")).unwrap_err().contains("both"));
    }

    #[test]
    fn glob_matching_is_literal_except_star() {
        let g =
            |p: &str, k: &str| glob_match(&p.split('*').map(str::to_string).collect::<Vec<_>>(), k);
        assert!(g("vector/*", "vector/a"));
        assert!(g("vector/charge-*-reject", "vector/charge-x-reject"));
        assert!(!g("vector/charge-*-reject", "vector/charge-x-accept"));
        assert!(g("vector/a*b*c", "vector/aXbYc"));
        assert!(!g("vector/a*b*c", "vector/aXc"));
        assert!(g("vector/a.b", "vector/a.b"));
        assert!(!g("vector/a.b", "vector/aXb"));
        assert!(!g("vector/ab*ab", "vector/ab"));
        assert!(g("vector/ab*ab", "vector/abab"));
    }

    // Completeness under --require: a narrowed run (a language filtered out,
    // or part of its cases) fails; a full run passes (control).
    #[test]
    fn completeness_fails_when_claimed_cases_were_not_executed() {
        let claimed = Expectations::parse(
            "language=\"a\"\n[capabilities]\nvector=[\"charge\"]\nhonours_clock=true",
            "a.toml",
        )
        .unwrap();
        let cases = vec![r("c1"), r("c2"), CaseRef::vector("x", "session")];
        let missing = missing_claimed(&claimed, &cases, &BTreeSet::new()).unwrap();
        assert_eq!(
            missing.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(),
            vec!["c1", "c2"]
        );
        let all: BTreeSet<String> = ["vector/c1", "vector/c2"].map(String::from).into();
        assert!(missing_claimed(&claimed, &cases, &all).unwrap().is_empty());
    }

    #[test]
    fn parses_every_committed_file() {
        let all = load_all(&crate::repo_root().join("harness/expectations")).unwrap();
        assert!(all.contains_key("rust"), "{:?}", all.keys());
        for exp in all.values() {
            if !exp.claims(Suite::Vector).is_empty() {
                assert!(exp.honours_clock.is_some(), "{}", exp.source);
            }
        }
    }
}
