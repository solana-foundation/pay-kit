//! `pkc run --cross [--require]` as a gate: every cross-verification cell is
//! reconciled against the verifying SDK's expectations file, with the same
//! exact-set semantics as the vector suite (DESIGN.md §3.4).
//!
//! - The verifier claims the matrix with `capabilities.cross = true`.
//! - A cell's key is `cross/<case>/<client>/<server>`; it passes when the
//!   server agrees with the Rust judge on the client's build.
//! - `[[unsupported]]` cells must report unsupported, `[[known_failing]]`
//!   cells must disagree, and every entry must match a real cell.
//! - Under `--require` the matrix must also be complete: every SDK that
//!   verifies an intent claims `cross`, and every build a client's
//!   expectations promise (a claimed accept build vector) is present under
//!   `harness/results/<sdk>/builds/`, so a CI leg whose artifact did not
//!   arrive cannot shrink the matrix to green.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::run::cross::{server_capable, CrossReport};
use crate::run::driver::SavedBuild;
use crate::run::expectations::{CaseRef, Decision, Expectations, Observed, Suite};
use crate::run::vectors::Vector;

/// Intents the cross matrix covers (the ones with saved builds).
pub const INTENTS: [&str; 2] = ["charge", "x402-exact"];

pub fn cell_ref(case: &str, client: &str, server: &str) -> CaseRef {
    CaseRef {
        suite: Suite::Cross,
        id: format!("{case}/{client}/{server}"),
        capability: "cross".into(),
    }
}

fn observed(cell: &crate::run::cross::Cell) -> Observed {
    let detail = || {
        format!(
            "{} built by {} verified by {}: expected {}, got {} {}",
            cell.case,
            cell.client,
            cell.server,
            cell.expected,
            cell.observed,
            cell.detail.as_deref().unwrap_or_default()
        )
        .trim()
        .to_string()
    };
    if cell.observed == "unsupported" {
        Observed::Unsupported { detail: detail() }
    } else if cell.agree {
        Observed::Pass
    } else {
        Observed::Fail { detail: detail() }
    }
}

/// Builds `exp` promises: claimed (decision pass) accept build vectors of a
/// cross intent.
pub fn promised_builds<'a>(exp: &Expectations, vectors: &'a [Vector]) -> Vec<&'a Vector> {
    vectors
        .iter()
        .filter(|v| {
            INTENTS.contains(&v.intent.as_str())
                && v.mode == "build-transaction"
                && v.expect_outcome() == "accept"
        })
        .filter(|v| exp.decide(&CaseRef::vector(&v.id, &v.intent)) == Ok(Decision::Pass))
        .collect()
}

#[derive(Debug, Default)]
pub struct GateOutcome {
    /// Cells reconciled against a `known_failing` or `unsupported` entry.
    pub expected_failures: usize,
    pub problems: Vec<String>,
}

pub fn reconcile(
    report: &CrossReport,
    all_exp: &BTreeMap<String, Expectations>,
    vectors: &[Vector],
    builds: &[SavedBuild],
    require: bool,
) -> GateOutcome {
    let mut out = GateOutcome::default();
    for cell in &report.cells {
        let case = cell_ref(&cell.case, &cell.client, &cell.server);
        let Some(exp) = all_exp.get(&cell.server) else {
            out.problems.push(format!(
                "{}: no expectations file for server {}",
                case.key(),
                cell.server
            ));
            continue;
        };
        let decision = match exp.decide(&case) {
            Ok(d) => d,
            Err(e) => {
                out.problems.push(e);
                continue;
            }
        };
        if decision == Decision::Unclaimed {
            out.problems.push(format!(
                "{}: {} does not claim the cross suite but was run as a server",
                case.key(),
                cell.server
            ));
            continue;
        }
        match exp.reconcile(&case, &decision, &observed(cell)) {
            Ok(()) if decision != Decision::Pass => out.expected_failures += 1,
            Ok(()) => {}
            Err(problem) => out.problems.push(problem),
        }
    }

    let have: BTreeSet<(&str, &str)> = builds
        .iter()
        .map(|b| (b.sdk.as_str(), b.case.as_str()))
        .collect();
    let mut missing_builds = Vec::new();
    for (sdk, exp) in all_exp {
        for v in promised_builds(exp, vectors) {
            if !have.contains(&(sdk.as_str(), v.id.as_str())) {
                missing_builds.push(format!("{sdk}/builds/{}.json", v.id));
            }
        }
    }
    if require {
        for (sdk, exp) in all_exp {
            let verifies: Vec<&str> = INTENTS
                .into_iter()
                .filter(|i| exp.claims(Suite::Vector).contains(*i))
                .filter(|i| server_capable(exp, i, vectors))
                .collect();
            let claims = exp.claims(Suite::Cross).contains("cross");
            if !verifies.is_empty() && !claims {
                out.problems.push(format!(
                    "{sdk} verifies {} vectors but harness/expectations/{sdk}.toml does not claim `cross = true`; claim it so its verifier is cross-checked",
                    verifies.join(", ")
                ));
            }
            if claims && verifies.is_empty() {
                out.problems.push(format!(
                    "harness/expectations/{sdk}.toml claims `cross` but verifies no charge or x402-exact vector"
                ));
            }
            if claims && !report.servers.values().flatten().any(|s| s == sdk) {
                out.problems.push(format!(
                    "{sdk} claims `cross` but was not run as a server (narrowed with --sdk?)"
                ));
            }
        }
        for m in &missing_builds {
            out.problems.push(format!(
                "missing build harness/results/{m}: the client's offline run (or its CI artifact) did not produce it"
            ));
        }
    }

    // Stale entries can only be judged on a complete matrix.
    if missing_builds.is_empty() {
        let refs: Vec<CaseRef> = report
            .cells
            .iter()
            .map(|c| cell_ref(&c.case, &c.client, &c.server))
            .collect();
        for server in report.servers.values().flatten().collect::<BTreeSet<_>>() {
            if let Some(exp) = all_exp.get(server) {
                let own: Vec<CaseRef> = refs
                    .iter()
                    .filter(|r| r.id.ends_with(&format!("/{server}")))
                    .cloned()
                    .collect();
                for p in exp.dangling(Suite::Cross, &own) {
                    out.problems
                        .push(format!("harness/expectations/{server}.toml: {p}"));
                }
            }
        }
    }
    out
}

/// [`reconcile`] with the committed expectations, the corpus and the builds
/// under `opts.results_dir`; `opts.require` asks for completeness.
pub fn gate(
    root: &Path,
    opts: &crate::run::driver::Options,
    report: &CrossReport,
) -> Result<GateOutcome, String> {
    let all_exp = crate::run::expectations::load_all(&root.join("harness/expectations"))?;
    let vectors = crate::run::vectors::load(&opts.vectors_dir)?;
    let builds = crate::run::cross::load_builds(&opts.results_dir)?;
    Ok(reconcile(report, &all_exp, &vectors, &builds, opts.require))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::run::cross::Cell;

    fn exp(extra: &str) -> Expectations {
        Expectations::parse(
            &format!(
                "language = \"srv\"\n[capabilities]\nvector = [\"charge\"]\nhonours_clock = true\ncross = true\n{extra}"
            ),
            "srv.toml",
        )
        .unwrap()
    }

    fn cell(case: &str, agree: bool, observed: &str) -> Cell {
        Cell {
            intent: "charge".into(),
            client: "cli".into(),
            server: "srv".into(),
            case: case.into(),
            expected: "accept",
            observed: observed.into(),
            agree,
            detail: None,
        }
    }

    fn run(exp: Expectations, cells: Vec<Cell>) -> GateOutcome {
        let report = CrossReport {
            clients: vec!["cli".into()],
            servers: [("charge".to_string(), vec!["srv".to_string()])].into(),
            cells,
        };
        let all: BTreeMap<String, Expectations> = [("srv".to_string(), exp)].into();
        reconcile(&report, &all, &[], &[], false)
    }

    #[test]
    fn an_unlisted_disagreement_fails() {
        let out = run(exp(""), vec![cell("a", false, "reject")]);
        assert_eq!(out.problems.len(), 1, "{:?}", out.problems);
        assert!(out.problems[0].contains("cross/a/cli/srv failed"));
    }

    #[test]
    fn agreement_passes() {
        let out = run(exp(""), vec![cell("a", true, "accept")]);
        assert!(out.problems.is_empty(), "{:?}", out.problems);
    }

    #[test]
    fn known_failing_cells_must_still_disagree() {
        let kf = "[[known_failing]]\nid = \"cross/a/cli/srv\"\nreason = \"r\"\ntracking = \"FINDINGS.md#x\"\n";
        let out = run(exp(kf), vec![cell("a", false, "reject")]);
        assert!(out.problems.is_empty(), "{:?}", out.problems);
        assert_eq!(out.expected_failures, 1);
        let out = run(exp(kf), vec![cell("a", true, "accept")]);
        assert!(out.problems[0].contains("now passes"), "{:?}", out.problems);
    }

    #[test]
    fn unsupported_cells_must_report_unsupported_and_entries_must_match() {
        let u = "[[unsupported]]\npattern = \"cross/v1-*/*/srv\"\nreason = \"v2 only\"\n";
        let out = run(exp(u), vec![cell("v1-build", false, "unsupported")]);
        assert!(out.problems.is_empty(), "{:?}", out.problems);
        // An unsupported verdict nobody declared fails.
        let out = run(exp(""), vec![cell("v1-build", false, "unsupported")]);
        assert!(
            out.problems[0].contains("does not list it"),
            "{:?}",
            out.problems
        );
        // A declared pattern matching no cell is stale.
        let out = run(exp(u), vec![cell("a", true, "accept")]);
        assert!(
            out.problems
                .iter()
                .any(|p| p.contains("matches no claimed case")),
            "{:?}",
            out.problems
        );
    }

    #[test]
    fn require_flags_a_verifier_that_does_not_claim_cross() {
        let exp = Expectations::parse(
            "language = \"srv\"\n[capabilities]\nvector = [\"charge\"]\nhonours_clock = true\n",
            "srv.toml",
        )
        .unwrap();
        let vectors =
            crate::run::vectors::load(&crate::repo_root().join("harness/vectors")).unwrap();
        let report = CrossReport {
            clients: vec![],
            servers: BTreeMap::new(),
            cells: vec![],
        };
        let all: BTreeMap<String, Expectations> = [("srv".to_string(), exp)].into();
        let out = reconcile(&report, &all, &vectors, &[], true);
        assert!(
            out.problems
                .iter()
                .any(|p| p.contains("does not claim `cross = true`")),
            "{:?}",
            out.problems
        );
        // srv promises every charge accept build and has none.
        assert!(
            out.problems.iter().any(|p| p.contains("missing build")),
            "{:?}",
            out.problems
        );
        // Without --require the same matrix is reported, not failed.
        let out = reconcile(&report, &all, &vectors, &[], false);
        assert!(out.problems.is_empty(), "{:?}", out.problems);
    }
}
