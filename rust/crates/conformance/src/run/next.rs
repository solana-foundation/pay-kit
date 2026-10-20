//! `pkc next --sdk <x>`: the agent's next unit of work (DESIGN.md §6.3).
//!
//! Failures (unexpected ones and the `known_failing` work queue) are grouped
//! by `(requirement, bugType, expected code)`. Blocking groups come first
//! (the testee timed out, crashed, broke the ABI or contradicted its
//! capabilities: nothing else can be judged until they are fixed), then the
//! smallest group, so a fix to one class is verified by re-running its group.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use serde_json::Value;

use crate::run::explain::Context;
use crate::run::vectors::Vector;

/// Markers of a testee-level failure that blocks judging anything else.
const BLOCKING: [&str; 6] = [
    "timeout",
    "testee exited",
    "violates the conformance ABI",
    "failed to start",
    "testee error",
    "testee closed its stdin",
];

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct GroupKey {
    /// 0 for blocking groups, so they sort first.
    pub rank: u8,
    pub requirements: String,
    pub bug_type: String,
    pub code: String,
}

#[derive(Debug, Clone)]
pub struct Group {
    pub key: GroupKey,
    pub cases: Vec<String>,
    pub detail: String,
}

/// Group the failing cases of a results file (`harness/results/<sdk>.json`).
pub fn groups(results: &Value) -> Vec<Group> {
    let mut map: BTreeMap<GroupKey, Group> = BTreeMap::new();
    for problem in results["problems"].as_array().into_iter().flatten() {
        let text = problem.as_str().unwrap_or_default().to_string();
        let key = GroupKey {
            rank: 0,
            requirements: "testee".into(),
            bug_type: "harness".into(),
            code: "run-level".into(),
        };
        map.entry(key.clone())
            .or_insert_with(|| Group {
                key,
                cases: Vec::new(),
                detail: text.clone(),
            })
            .cases
            .push(text.lines().next().unwrap_or_default().to_string());
    }
    for case in results["cases"].as_array().into_iter().flatten() {
        let failing = case["observed"] == "fail" || case["ok"] == false;
        if !failing {
            continue;
        }
        let detail = case["detail"]
            .as_str()
            .or(case["problem"].as_str())
            .unwrap_or_default()
            .to_string();
        let blocking = BLOCKING.iter().any(|m| detail.contains(m));
        let requirements = case["requirements"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .unwrap_or_default();
        let key = GroupKey {
            rank: u8::from(!blocking),
            requirements: if blocking {
                "testee".into()
            } else {
                requirements
            },
            bug_type: case["bugType"].as_str().unwrap_or("unknown").to_string(),
            code: case["rejectCode"].as_str().unwrap_or("accept").to_string(),
        };
        let id = case["key"]
            .as_str()
            .unwrap_or_default()
            .trim_start_matches("vector/")
            .to_string();
        map.entry(key.clone())
            .or_insert_with(|| Group {
                key,
                cases: Vec::new(),
                detail,
            })
            .cases
            .push(id);
    }
    let mut groups: Vec<Group> = map.into_values().collect();
    groups.sort_by(|a, b| {
        (a.key.rank, a.cases.len(), &a.key).cmp(&(b.key.rank, b.cases.len(), &b.key))
    });
    groups
}

/// The fix brief for one group.
pub fn brief(sdk: &str, group: &Group, ctx: &Context, vectors: &[Vector]) -> String {
    let mut out = String::new();
    let blocking = group.key.rank == 0;
    let _ = writeln!(
        out,
        "{} group: {} case(s), bugType {}, expected {}{}",
        sdk,
        group.cases.len(),
        group.key.bug_type,
        group.key.code,
        if blocking {
            " (BLOCKING: fix first)"
        } else {
            ""
        }
    );
    for id in &group.cases {
        let _ = writeln!(out, "  - {id}");
    }
    let representative = vectors.iter().find(|v| group.cases.contains(&v.id));
    if let Some(v) = representative {
        let req = ctx.requirement(v);
        let _ = writeln!(
            out,
            "\nrequirement: \"{}\"\n  {} § {}",
            req["quote"].as_str().unwrap_or_default(),
            req["doc"].as_str().unwrap_or_default(),
            req["section"].as_str().unwrap_or_default()
        );
        for r in req["requirements"].as_array().into_iter().flatten() {
            let _ = writeln!(
                out,
                "  {}: {}",
                r["id"].as_str().unwrap_or_default(),
                r["text"].as_str().unwrap_or_default()
            );
        }
        if let Some(words) = ctx
            .cases
            .get(&v.id)
            .and_then(crate::run::explain::mutation_words)
        {
            let _ = writeln!(out, "mutation: {words}");
        }
        let _ = writeln!(out, "reference:");
        for r in ctx.references(v) {
            let _ = writeln!(out, "  {r}");
        }
        let _ = writeln!(out, "replay: pkc case run --sdk {sdk} {}", v.id);
    }
    let first = group.detail.lines().next().unwrap_or_default();
    let _ = writeln!(out, "first failure: {first}");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn case(id: &str, req: &str, code: &str, detail: &str) -> Value {
        json!({
            "key": format!("vector/{id}"),
            "observed": "fail",
            "ok": true,
            "decision": "known_failing",
            "requirements": [req],
            "bugType": "settlement",
            "rejectCode": code,
            "detail": detail,
        })
    }

    // A planted class of 10 failures (one broken operator) comes back as one
    // group of 10; a smaller unrelated group sorts first, a blocking one
    // before both.
    #[test]
    fn groups_a_planted_class_and_orders_blocking_then_smallest() {
        let mut cases: Vec<Value> = (0..10)
            .map(|i| {
                case(
                    &format!("c{i}"),
                    "MPP-0000000001",
                    "amount-mismatch",
                    "expected reject",
                )
            })
            .collect();
        cases.push(case(
            "x",
            "MPP-0000000002",
            "invalid-payload",
            "expected reject",
        ));
        cases.push(case(
            "t",
            "MPP-0000000003",
            "wrong-network",
            "timeout: no response",
        ));
        cases.push(json!({"key": "vector/ok", "observed": "pass", "ok": true}));
        let results = json!({ "problems": [], "cases": cases });
        let groups = groups(&results);
        assert_eq!(groups.len(), 3);
        assert_eq!(groups[0].cases, vec!["t"]);
        assert_eq!(groups[0].key.rank, 0);
        assert_eq!(groups[1].cases, vec!["x"]);
        assert_eq!(groups[2].cases.len(), 10);
    }
}
