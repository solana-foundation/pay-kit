//! `pkc fill [--check]`: write (or verify) the vector files.
//!
//! Output is a pure function of the registry and the kit: fixed keys,
//! blockhash and clocks, no randomness, no commit sha in the compared
//! content. Every filled file's SHA-256 is recorded in
//! `harness/vectors/FILL.sha256`, which `--check` compares too.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::annotate;
use crate::case::{Case, Intent, Mode, Provenance};
use crate::realize::{realize, Observed};

/// Bumped when the filler's output format changes.
pub const FILLER_VERSION: &str = "1";

pub const MANIFEST: &str = "FILL.sha256";
pub const ANNOTATED_DIR: &str = "annotated";

#[derive(Serialize)]
struct SpecJson {
    doc: String,
    section: String,
    quote: String,
}

/// One vector in the ABI of `harness/src/conformance/schema.ts`, plus the
/// additive traceability fields.
#[derive(Serialize)]
struct VectorJson<'a> {
    id: &'a str,
    intent: &'static str,
    mode: &'static str,
    description: &'a str,
    spec: SpecJson,
    requirements: Vec<&'a str>,
    #[serde(rename = "bugType")]
    bug_type: &'static str,
    tier: &'static str,
    role: &'static str,
    provenance: &'static str,
    input: Value,
    expect: Value,
}

pub fn render(case: &Case, input: Value, expect: Value) -> Value {
    let vector = VectorJson {
        id: case.id.as_str(),
        intent: case.intent.as_str(),
        mode: case.mode.as_str(),
        description: &case.description,
        spec: SpecJson {
            doc: case.spec.doc(),
            section: case.spec.section().to_string(),
            quote: case.spec.quote().to_string(),
        },
        requirements: case.requirements.iter().map(|r| r.as_str()).collect(),
        bug_type: case.bug_type.as_str(),
        tier: case.tier.as_str(),
        role: case.role.as_str(),
        provenance: case.provenance.as_str(),
        input,
        expect,
    };
    serde_json::to_value(&vector).expect("vector serializes")
}

/// Every file `fill` owns, relative to `harness/vectors/`, with contents.
pub type Files = BTreeMap<String, String>;

fn pretty(value: &impl Serialize) -> String {
    // serde_json's pretty printer writes objects in insertion order for
    // structs and sorted order for maps, both deterministic.
    let mut out = serde_json::to_string_pretty(value).expect("json");
    out.push('\n');
    out
}

pub async fn generate(cases: &[Case]) -> Result<Files, Vec<String>> {
    let mut errors = Vec::new();
    let mut by_file: BTreeMap<&str, Vec<Value>> = BTreeMap::new();
    let mut files = Files::new();
    let mut ids = BTreeSet::new();
    for case in cases {
        if !ids.insert(case.id.as_str()) {
            errors.push(format!("duplicate case id {}", case.id));
            continue;
        }
        match realize(case).await {
            Ok(realized) => {
                let reference = match (&realized.observed, case.intent, case.mode) {
                    (
                        Observed::Accept(output),
                        Intent::Charge | Intent::Session,
                        Mode::BuildTransaction,
                    ) => output.transaction.clone(),
                    _ => None,
                };
                let vector = render(case, realized.input, realized.expect);
                if let Some(text) = annotate::vector(&vector, reference.as_deref()) {
                    files.insert(format!("{ANNOTATED_DIR}/{}.txt", case.id), text);
                }
                by_file.entry(case.file).or_default().push(vector);
            }
            Err(error) => errors.push(error),
        }
    }
    if !errors.is_empty() {
        return Err(errors);
    }
    for (file, vectors) in by_file {
        files.insert(file.to_string(), pretty(&vectors));
    }
    let mut manifest = format!(
        "# SHA-256 of every file written by `pkc fill` (filler version {FILLER_VERSION}).\n# Generated; do not edit. `pkc fill --check` fails on any difference.\n"
    );
    for (name, content) in &files {
        let digest = Sha256::digest(content.as_bytes());
        let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        manifest.push_str(&format!("{hex}  {name}\n"));
    }
    files.insert(MANIFEST.to_string(), manifest);
    Ok(files)
}

/// Files under `vectors_dir` that `fill` owns: top-level `*.json`, the
/// manifest, and everything under `annotated/`. Vendored subdirectories
/// (`mpp-protocol*`) and the README are not touched.
pub fn owned_on_disk(vectors_dir: &Path) -> Result<BTreeSet<String>, String> {
    let mut out = BTreeSet::new();
    for entry in fs::read_dir(vectors_dir)
        .map_err(|e| e.to_string())?
        .flatten()
    {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        if path.is_file() && (name.ends_with(".json") || name == MANIFEST) {
            out.insert(name);
        }
    }
    let annotated = vectors_dir.join(ANNOTATED_DIR);
    if annotated.is_dir() {
        for entry in fs::read_dir(&annotated)
            .map_err(|e| e.to_string())?
            .flatten()
        {
            out.insert(format!(
                "{ANNOTATED_DIR}/{}",
                entry.file_name().to_string_lossy()
            ));
        }
    }
    Ok(out)
}

/// Differences between generated files and disk, as human lines.
pub fn diff(vectors_dir: &Path, files: &Files) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let on_disk = owned_on_disk(vectors_dir)?;
    for name in &on_disk {
        if !files.contains_key(name) {
            out.push(format!("{name}: on disk but not produced by any case"));
        }
    }
    for (name, content) in files {
        match fs::read_to_string(vectors_dir.join(name)) {
            Ok(current) if current == *content => {}
            Ok(_) => out.push(format!("{name}: differs from the filled content")),
            Err(_) => out.push(format!("{name}: missing")),
        }
    }
    Ok(out)
}

pub fn write(vectors_dir: &Path, files: &Files) -> Result<(), String> {
    fs::create_dir_all(vectors_dir.join(ANNOTATED_DIR)).map_err(|e| e.to_string())?;
    for name in owned_on_disk(vectors_dir)? {
        if !files.contains_key(&name) {
            fs::remove_file(vectors_dir.join(&name)).map_err(|e| format!("{name}: {e}"))?;
        }
    }
    for (name, content) in files {
        let path: PathBuf = vectors_dir.join(name);
        let unchanged = fs::read_to_string(&path).is_ok_and(|c| c == *content);
        if !unchanged {
            fs::write(&path, content).map_err(|e| format!("{name}: {e}"))?;
        }
    }
    Ok(())
}

/// `git status --porcelain` of `harness/vectors/`; empty means clean.
pub fn dirty(root: &Path) -> Result<Vec<String>, String> {
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args([
            "status",
            "--porcelain",
            "--untracked-files=all",
            "--",
            "harness/vectors",
        ])
        .output()
        .map_err(|e| format!("git status: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "git status failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::to_string)
        .filter(|l| !l.is_empty())
        .collect())
}

/// Count of cases by (suite, provenance, outcome), for `pkc fill --list`.
pub fn summary(cases: &[Case]) -> Vec<String> {
    let mut counts: BTreeMap<(String, &'static str, &'static str), usize> = BTreeMap::new();
    for case in cases {
        let outcome = match case.expect {
            crate::case::Expect::Reject { .. } => "reject",
            _ => "accept",
        };
        let provenance = match case.provenance {
            Provenance::Generated => "generated",
            Provenance::Authored { .. } => "authored",
        };
        *counts
            .entry((case.suite.as_str().to_string(), provenance, outcome))
            .or_default() += 1;
    }
    counts
        .into_iter()
        .map(|((suite, provenance, outcome), n)| {
            format!("{suite:<16} {provenance:<9} {outcome:<6} {n}")
        })
        .collect()
}
