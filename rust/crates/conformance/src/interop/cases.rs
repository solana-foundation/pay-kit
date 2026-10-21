//! Interop cases: every scenario crossed with every admitted client and
//! server adapter of its intent, keyed `interop/<scenario>/<client>/<server>`,
//! and their reconciliation against both SDKs' expectations files.
//!
//! A case is claimed when the client's language claims
//! `<protocol>:<scheme>:client` and the server's language claims
//! `<protocol>:<scheme>:server`. An `[[unsupported]]` or `[[known_failing]]`
//! entry for the case lives in exactly one of the two files (the side the
//! gap belongs to); listing it in both is an error, so is listing it in the
//! file of a language that is not part of the pair.

use std::collections::{BTreeMap, BTreeSet};

use crate::run::expectations::{CaseRef, Decision, Expectations, Suite};

use super::adapters::{self, Adapter};
use super::claims::Role;
use super::scenarios::{Scenario, SCENARIOS};

#[derive(Debug, Clone, Copy)]
pub struct Case {
    pub scenario: &'static Scenario,
    pub client: &'static Adapter,
    pub server: &'static Adapter,
}

impl Case {
    /// `<scenario>/<client>/<server>`.
    pub fn id(&self) -> String {
        format!("{}/{}/{}", self.scenario.id, self.client.id, self.server.id)
    }

    /// `interop/<scenario>/<client>/<server>`.
    pub fn key(&self) -> String {
        format!("interop/{}", self.id())
    }

    pub fn languages(&self) -> BTreeSet<&'static str> {
        [self.client.language, self.server.language].into()
    }

    fn side(&self, role: Role) -> &'static Adapter {
        match role {
            Role::Client => self.client,
            Role::Server => self.server,
        }
    }

    /// The case as `lang`'s expectations file sees it in `role`.
    fn reference(&self, role: Role) -> CaseRef {
        CaseRef {
            suite: Suite::Interop,
            id: self.id(),
            capability: self.side(role).claim().to_string(),
        }
    }
}

/// The reference counterparty: every case has the Rust adapter on at least
/// one side (an SDK's client against the Rust server, the Rust client
/// against its server, and Rust against Rust as the control). There are no
/// pairs between two other SDKs.
pub const REFERENCE: &str = "rust";

/// Every case the registry can produce, claimed or not, in a stable order.
pub fn all() -> Vec<Case> {
    let mut out = Vec::new();
    for scenario in SCENARIOS {
        for client in adapters::of(scenario.intent, Role::Client) {
            if !scenario.clients.admits(client.id) {
                continue;
            }
            for server in adapters::of(scenario.intent, Role::Server) {
                if !scenario.servers.admits(server.id)
                    || (client.language != REFERENCE && server.language != REFERENCE)
                {
                    continue;
                }
                out.push(Case {
                    scenario,
                    client,
                    server,
                });
            }
        }
    }
    out
}

/// What to do with a case, and which file holds its entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairDecision {
    pub decision: Decision,
    /// The language whose toml lists the case (`None` for pass/unclaimed).
    pub holder: Option<String>,
}

fn exp_for<'a>(
    exps: &'a BTreeMap<String, Expectations>,
    language: &str,
) -> Option<&'a Expectations> {
    exps.get(language)
}

pub fn decide(exps: &BTreeMap<String, Expectations>, case: &Case) -> Result<PairDecision, String> {
    let unclaimed = PairDecision {
        decision: Decision::Unclaimed,
        holder: None,
    };
    let (Some(client), Some(server)) = (
        exp_for(exps, case.client.language),
        exp_for(exps, case.server.language),
    ) else {
        return Ok(unclaimed);
    };
    let dc = client.decide(&case.reference(Role::Client))?;
    let ds = server.decide(&case.reference(Role::Server))?;
    if dc == Decision::Unclaimed || ds == Decision::Unclaimed {
        return Ok(unclaimed);
    }
    let same_file = case.client.language == case.server.language;
    match (dc, ds) {
        (Decision::Pass, Decision::Pass) => Ok(PairDecision {
            decision: Decision::Pass,
            holder: None,
        }),
        (d, Decision::Pass) => Ok(PairDecision {
            decision: d,
            holder: Some(case.client.language.to_string()),
        }),
        (Decision::Pass, d) => Ok(PairDecision {
            decision: d,
            holder: Some(case.server.language.to_string()),
        }),
        (a, b) if same_file && a == b => Ok(PairDecision {
            decision: a,
            holder: Some(case.client.language.to_string()),
        }),
        _ => Err(format!(
            "{} is listed in both harness/expectations/{}.toml and {}.toml; keep it on the side the gap belongs to",
            case.key(),
            case.client.language,
            case.server.language
        )),
    }
}

/// Claimed cases, i.e. both sides claim their role.
pub fn claimed(exps: &BTreeMap<String, Expectations>) -> Result<Vec<Case>, String> {
    let mut out = Vec::new();
    for case in all() {
        if decide(exps, &case)?.decision != Decision::Unclaimed {
            out.push(case);
        }
    }
    Ok(out)
}

/// Every `interop/` entry of every file must match a claimed case in which
/// that file's language takes part.
pub fn dangling(exps: &BTreeMap<String, Expectations>) -> Result<Vec<String>, String> {
    let claimed = claimed(exps)?;
    let mut problems = Vec::new();
    for (language, exp) in exps {
        let mut refs = Vec::new();
        for case in &claimed {
            for role in [Role::Client, Role::Server] {
                if case.side(role).language == language {
                    refs.push(case.reference(role));
                }
            }
        }
        for p in exp.dangling(Suite::Interop, &refs) {
            problems.push(format!("harness/expectations/{}: {p}", exp.source));
        }
    }
    Ok(problems)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exps(files: &[(&str, &str)]) -> BTreeMap<String, Expectations> {
        files
            .iter()
            .map(|(lang, body)| {
                let text = format!("language = \"{lang}\"\n{body}");
                (
                    lang.to_string(),
                    Expectations::parse(&text, &format!("{lang}.toml")).unwrap(),
                )
            })
            .collect()
    }

    fn case(id: &str) -> Case {
        all()
            .into_iter()
            .find(|c| c.id() == id)
            .unwrap_or_else(|| panic!("no case {id}"))
    }

    #[test]
    fn keys_are_unique() {
        let keys: Vec<String> = all().iter().map(Case::key).collect();
        let unique: BTreeSet<&String> = keys.iter().collect();
        assert_eq!(keys.len(), unique.len());
        assert!(keys.contains(&"interop/charge-basic/typescript/rust".to_string()));
    }

    #[test]
    fn a_case_needs_both_sides_to_claim() {
        let e = exps(&[
            ("go", "[capabilities]\ninterop = [\"mpp:charge:client\"]"),
            ("rust", "[capabilities]\ninterop = [\"mpp:charge:server\"]"),
            ("php", "[capabilities]\ninterop = []"),
        ]);
        assert_eq!(
            decide(&e, &case("charge-basic/go/rust")).unwrap().decision,
            Decision::Pass
        );
        assert_eq!(
            decide(&e, &case("charge-basic/rust/php")).unwrap().decision,
            Decision::Unclaimed
        );
        assert_eq!(
            decide(&e, &case("charge-basic/rust/rust"))
                .unwrap()
                .decision,
            Decision::Unclaimed
        );
    }

    const KF: &str = "[[known_failing]]\nids = [\"interop/charge-basic/go/rust\"]\nreason = \"r\"\ntracking = \"FINDINGS.md#x\"";

    #[test]
    fn an_entry_on_either_side_decides_and_names_its_holder() {
        let client_side = exps(&[
            (
                "go",
                &format!("[capabilities]\ninterop = [\"mpp:charge:client\"]\n{KF}"),
            ),
            ("rust", "[capabilities]\ninterop = [\"mpp:charge:server\"]"),
        ]);
        let d = decide(&client_side, &case("charge-basic/go/rust")).unwrap();
        assert_eq!(d.decision.kind(), "known_failing");
        assert_eq!(d.holder.as_deref(), Some("go"));
        let server_side = exps(&[
            ("go", "[capabilities]\ninterop = [\"mpp:charge:client\"]"),
            (
                "rust",
                &format!("[capabilities]\ninterop = [\"mpp:charge:server\"]\n{KF}"),
            ),
        ]);
        let d = decide(&server_side, &case("charge-basic/go/rust")).unwrap();
        assert_eq!(d.holder.as_deref(), Some("rust"));
        assert!(dangling(&server_side).unwrap().is_empty());
    }

    #[test]
    fn an_entry_on_both_sides_is_an_error() {
        let both = exps(&[
            (
                "go",
                &format!("[capabilities]\ninterop = [\"mpp:charge:client\"]\n{KF}"),
            ),
            (
                "rust",
                &format!("[capabilities]\ninterop = [\"mpp:charge:server\"]\n{KF}"),
            ),
        ]);
        assert!(decide(&both, &case("charge-basic/go/rust"))
            .unwrap_err()
            .contains("listed in both"));
    }

    #[test]
    fn an_entry_in_a_bystander_file_or_for_an_unclaimed_pair_dangles() {
        let bystander = exps(&[
            ("go", "[capabilities]\ninterop = [\"mpp:charge:client\"]"),
            ("rust", "[capabilities]\ninterop = [\"mpp:charge:server\"]"),
            (
                "php",
                &format!("[capabilities]\ninterop = [\"mpp:charge:server\"]\n{KF}"),
            ),
        ]);
        let problems = dangling(&bystander).unwrap();
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].contains("php.toml"), "{problems:?}");
        let half = exps(&[
            (
                "go",
                &format!("[capabilities]\ninterop = [\"mpp:charge:client\"]\n{KF}"),
            ),
            ("rust", "[capabilities]\ninterop = []"),
        ]);
        assert_eq!(dangling(&half).unwrap().len(), 1);
    }

    #[test]
    fn interop_claims_are_validated() {
        assert!(Expectations::parse(
            "language = \"x\"\n[capabilities]\ninterop = [\"mpp:charge:clients\"]",
            "x.toml"
        )
        .unwrap_err()
        .contains("unknown interop claim"));
        assert!(Expectations::parse(
            "language = \"x\"\n[capabilities]\ninterop = [\"mpp:charge:client\", \"mpp:charge:client\"]",
            "x.toml"
        )
        .unwrap_err()
        .contains("duplicate"));
    }

    #[test]
    fn committed_files_reconcile_without_dangling_entries() {
        let all =
            crate::run::expectations::load_all(&crate::repo_root().join("harness/expectations"))
                .unwrap();
        let problems = dangling(&all).unwrap();
        assert!(problems.is_empty(), "{problems:#?}");
        for case in claimed(&all).unwrap() {
            decide(&all, &case).unwrap();
        }
    }
}
