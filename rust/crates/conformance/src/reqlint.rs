//! `pkc req-lint`: the spec is the denominator.
//!
//! Extracts every normative sentence (MUST, MUST NOT, SHALL, REQUIRED) from
//! the SVM-relevant files of the pinned spec repositories, gives each a
//! stable id (hash of the normalised sentence), and reconciles them with
//! `harness/requirements/<repo>.toml` and the vectors:
//!
//! - unmapped sentences (neither mapped nor ignored): counted, not fatal;
//! - mapped ids with zero cases: counted, not fatal, unless the entry says
//!   `required = true`: then FATAL, so a covered requirement cannot quietly
//!   lose its last case;
//! - mapped ids whose text changed (the id no longer hashes from the pinned
//!   text): FATAL;
//! - vector `spec.quote`s and `harness/expectations/RULINGS.md` quotes that
//!   no longer appear verbatim (whitespace-normalised) in the pinned text:
//!   FATAL.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::case::SpecRepo;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequirementsFile {
    pub repo: String,
    pub commit: String,
    pub files: Vec<String>,
    #[serde(default, rename = "requirement")]
    pub requirements: Vec<Requirement>,
    #[serde(default, rename = "ignore")]
    pub ignores: Vec<Ignore>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Requirement {
    pub id: String,
    pub doc: String,
    pub text: String,
    /// The requirement must keep at least one case: `pkc req-lint` fails
    /// when no vector maps it.
    #[serde(default)]
    pub required: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ignore {
    pub id: String,
    pub reason: String,
}

/// One extracted normative sentence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sentence {
    pub id: String,
    pub doc: String,
    /// Innermost heading above the sentence, without `#` marks or a
    /// trailing `{#anchor}`; empty before the first heading.
    pub section: String,
    pub text: String,
}

/// Normalise for hashing and matching: drop markdown emphasis and code
/// markers, collapse whitespace.
pub fn normalise(text: &str) -> String {
    text.replace(['`', '*'], "")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn sentence_id(repo: SpecRepo, sentence: &str) -> String {
    let digest = Sha256::digest(normalise(sentence).as_bytes());
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    format!("{}-{}", repo.req_prefix(), &hex[..10])
}

fn is_normative(sentence: &str) -> bool {
    sentence
        .split(|c: char| !c.is_ascii_alphabetic())
        .any(|word| matches!(word, "MUST" | "SHALL" | "REQUIRED"))
}

/// Remove YAML front matter and fenced code blocks; keep line structure.
fn prose_lines(markdown: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut lines = markdown.lines().peekable();
    if lines.peek().map(|l| l.trim() == "---").unwrap_or(false) {
        lines.next();
        for line in lines.by_ref() {
            if line.trim() == "---" {
                break;
            }
        }
    }
    let mut in_fence = false;
    for line in lines {
        let trimmed = line.trim_start();
        if trimmed.starts_with("```") || trimmed.starts_with("~~~") {
            in_fence = !in_fence;
            out.push(String::new());
            continue;
        }
        out.push(if in_fence {
            String::new()
        } else {
            line.to_string()
        });
    }
    out
}

fn starts_unit(trimmed: &str) -> bool {
    let list = trimmed.starts_with("- ")
        || trimmed.starts_with("* ")
        || trimmed.starts_with("+ ")
        || trimmed.starts_with(": ")
        || trimmed.starts_with('|')
        || trimmed.starts_with('#')
        || trimmed.starts_with('>');
    let numbered = trimmed
        .split_once(". ")
        .is_some_and(|(n, _)| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()));
    list || numbered
}

/// Drop a leading list, definition or blockquote marker.
fn strip_marker(unit: &str) -> &str {
    for marker in ["- ", "* ", "+ ", ": ", "> "] {
        if let Some(rest) = unit.strip_prefix(marker) {
            return rest.trim_start();
        }
    }
    if let Some((n, rest)) = unit.split_once(". ") {
        if !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()) {
            return rest.trim_start();
        }
    }
    unit
}

/// A heading line's text without the `#` marks and a trailing `{#anchor}`.
fn heading_text(trimmed: &str) -> String {
    let text = trimmed.trim_start_matches('#').trim();
    let text = match text.rfind("{#") {
        Some(at) if text.ends_with('}') => text[..at].trim_end(),
        _ => text,
    };
    normalise(text)
}

/// Paragraphs, list items, definition bodies and table rows, each joined
/// into one line and paired with the innermost heading above it. Headings
/// are not units.
fn units(markdown: &str) -> Vec<(String, String)> {
    let mut units = Vec::new();
    let mut current = String::new();
    let mut section = String::new();
    let flush = |current: &mut String, section: &str, units: &mut Vec<(String, String)>| {
        let unit = strip_marker(current.trim()).to_string();
        if !unit.is_empty() {
            units.push((section.to_string(), unit));
        }
        current.clear();
    };
    for line in prose_lines(markdown) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            flush(&mut current, &section, &mut units);
            continue;
        }
        if starts_unit(trimmed) {
            flush(&mut current, &section, &mut units);
        }
        if trimmed.starts_with('#') {
            section = heading_text(trimmed);
            continue;
        }
        current.push(' ');
        current.push_str(trimmed);
        if trimmed.starts_with('|') {
            flush(&mut current, &section, &mut units);
        }
    }
    flush(&mut current, &section, &mut units);
    units
}

/// Split a unit into sentences at `. ` / `! ` / `? ` followed by an
/// uppercase letter, a quote or a parenthesis. Abbreviations like "e.g." are
/// followed by lowercase or a comma and stay intact.
fn split_sentences(unit: &str) -> Vec<String> {
    let chars: Vec<char> = unit.chars().collect();
    let mut out = Vec::new();
    let mut start = 0;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if matches!(c, '.' | '!' | '?')
            && chars.get(i + 1) == Some(&' ')
            && chars
                .get(i + 2)
                .is_some_and(|n| n.is_uppercase() || matches!(n, '"' | '(' | '`' | '*'))
        {
            out.push(chars[start..=i].iter().collect::<String>());
            start = i + 2;
            i += 2;
            continue;
        }
        i += 1;
    }
    if start < chars.len() {
        out.push(chars[start..].iter().collect());
    }
    out.into_iter()
        .map(|s| normalise(&s))
        .filter(|s| !s.is_empty())
        .collect()
}

pub fn extract(repo: SpecRepo, doc: &str, markdown: &str) -> Vec<Sentence> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for (section, unit) in units(markdown) {
        for sentence in split_sentences(&unit) {
            if !is_normative(&sentence) {
                continue;
            }
            let id = sentence_id(repo, &sentence);
            if seen.insert(id.clone()) {
                out.push(Sentence {
                    id,
                    doc: doc.to_string(),
                    section: section.clone(),
                    text: sentence,
                });
            }
        }
    }
    out
}

/// `dir/*` and `dir/prefix-*` globs, one `*` in the file name at most.
pub fn expand(checkout: &Path, pattern: &str) -> Result<Vec<String>, String> {
    let (dir, file) = pattern.rsplit_once('/').unwrap_or(("", pattern));
    let (prefix, suffix) = file.split_once('*').unwrap_or((file, ""));
    let exact = !file.contains('*');
    let dir_path = checkout.join(dir);
    let mut out = Vec::new();
    let entries = fs::read_dir(&dir_path).map_err(|e| format!("{}: {e}", dir_path.display()))?;
    for entry in entries {
        let name = entry.map_err(|e| e.to_string())?.file_name();
        let name = name.to_string_lossy();
        let matches = if exact {
            name == file
        } else {
            name.starts_with(prefix) && name.ends_with(suffix) && name.ends_with(".md")
        };
        if matches {
            out.push(format!("{dir}/{name}"));
        }
    }
    out.sort();
    if out.is_empty() {
        return Err(format!(
            "pattern {pattern} matched no file in {}",
            checkout.display()
        ));
    }
    Ok(out)
}

/// Verbatim (normalised) containment, with `...` / `…` elisions: every
/// fragment must appear, in order.
pub fn quote_found(haystack_normalised: &str, quote: &str) -> bool {
    let quote = quote.replace('…', "...");
    let mut from = 0;
    for fragment in quote.split("...") {
        let fragment = normalise(fragment);
        let fragment = fragment.trim_matches(|c: char| c == ',' || c == ' ');
        if fragment.is_empty() {
            continue;
        }
        match haystack_normalised[from..].find(fragment) {
            Some(at) => from += at + fragment.len(),
            None => return false,
        }
    }
    true
}

/// Curly-quoted passages of RULINGS.md.
pub fn rulings_quotes(rulings: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = rulings;
    while let Some(start) = rest.find('“') {
        let after = &rest[start + '“'.len_utf8()..];
        match after.find('”') {
            Some(end) => {
                out.push(after[..end].to_string());
                rest = &after[end + '”'.len_utf8()..];
            }
            None => break,
        }
    }
    out
}

pub struct Report {
    pub lines: Vec<String>,
    pub failures: Vec<String>,
}

fn repo_of(name: &str) -> Result<SpecRepo, String> {
    SpecRepo::ALL
        .into_iter()
        .find(|r| r.prefix() == name)
        .ok_or_else(|| format!("unknown spec repo {name}"))
}

fn all_markdown(dir: &Path, base: &Path, out: &mut Vec<(String, String)>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            all_markdown(&path, base, out);
        } else if path.extension().is_some_and(|e| e == "md") {
            if let Ok(text) = fs::read_to_string(&path) {
                let rel = path
                    .strip_prefix(base)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .to_string();
                out.push((rel, normalise(&text)));
            }
        }
    }
}

/// Requirement id -> ids of the vectors citing it.
pub type ByRequirement = BTreeMap<String, Vec<String>>;
/// (vector id, `spec` object) per vector.
pub type VectorSpecs = Vec<(String, Value)>;

/// Requirement ids each vector maps, keyed by id → vector ids.
pub fn vector_requirements(vectors_dir: &Path) -> Result<(ByRequirement, VectorSpecs), String> {
    let mut by_req: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut specs = Vec::new();
    let mut files: Vec<PathBuf> = fs::read_dir(vectors_dir)
        .map_err(|e| e.to_string())?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    files.sort();
    for file in files {
        let text = fs::read_to_string(&file).map_err(|e| e.to_string())?;
        let vectors: Vec<Value> =
            serde_json::from_str(&text).map_err(|e| format!("{}: {e}", file.display()))?;
        for vector in vectors {
            let id = vector["id"].as_str().unwrap_or_default().to_string();
            for req in vector["requirements"]
                .as_array()
                .cloned()
                .unwrap_or_default()
            {
                if let Some(req) = req.as_str() {
                    by_req.entry(req.to_string()).or_default().push(id.clone());
                }
            }
            if let Some(spec) = vector.get("spec") {
                specs.push((id, spec.clone()));
            }
        }
    }
    Ok((by_req, specs))
}

pub fn lint(root: &Path) -> Result<Report, String> {
    let mut lines = Vec::new();
    let mut failures = Vec::new();
    let (by_req, specs) = vector_requirements(&root.join("harness/vectors"))?;
    let mut all_mapped = BTreeSet::new();
    // Normalised text of every markdown file per repo, for quote checks.
    let mut corpus: BTreeMap<SpecRepo, Vec<(String, String)>> = BTreeMap::new();

    for repo in SpecRepo::ALL {
        let analysis = analyse(root, repo)?;
        let (file, sentences, docs) = (&analysis.file, &analysis.sentences, &analysis.docs);
        let checkout = root.join(repo.checkout());
        if let Some(head) = git_head(&checkout) {
            if !head.starts_with(&file.commit) {
                lines.push(format!(
                    "warning: {} is at {head}, requirements pinned at {}",
                    repo.checkout(),
                    file.commit
                ));
            }
        }
        let ignored: BTreeSet<&str> = file.ignores.iter().map(|i| i.id.as_str()).collect();
        for ignore in &file.ignores {
            if ignore.reason.trim().is_empty() {
                failures.push(format!(
                    "{}: ignore {} has no reason",
                    repo.prefix(),
                    ignore.id
                ));
            }
        }
        let drifted = analysis.drifted();
        for req in &file.requirements {
            all_mapped.insert(req.id.clone());
        }
        for req in &drifted {
            failures.push(format!(
                "{}: mapped requirement {} ({}) no longer matches the pinned text: {:?}",
                repo.prefix(),
                req.id,
                req.doc,
                req.text
            ));
        }
        let coverage = case_coverage(&file.requirements, &by_req);
        for id in &coverage.required_without_cases {
            failures.push(format!(
                "{}: requirement {id} is marked required = true but no case maps it; restore its case or drop `required` in harness/requirements/{}.toml (the PR description must say why)",
                repo.prefix(),
                toml_name(repo)
            ));
        }
        lines.push(format!(
            "{}: {} normative sentences in {} files; {} mapped ({} required), {} ignored, {} unmapped; {} mapped with zero cases",
            repo.prefix(),
            sentences.len(),
            docs.len(),
            file.requirements.len() - drifted.len(),
            file.requirements.iter().filter(|r| r.required).count(),
            ignored.len(),
            analysis.unmapped().len(),
            coverage.zero_cases.len()
        ));
        for id in coverage.zero_cases {
            lines.push(format!("  zero cases: {id}"));
        }
        let mut texts = Vec::new();
        all_markdown(&checkout.join("specs"), &checkout, &mut texts);
        corpus.insert(repo, texts);
    }

    for (req, vectors) in &by_req {
        if !all_mapped.contains(req) {
            lines.push(format!(
                "warning: vectors {} cite requirement {req}, which no requirements file maps",
                vectors.join(", ")
            ));
        }
    }

    let mut quotes_checked = 0;
    for (id, spec) in &specs {
        let doc = spec["doc"].as_str().unwrap_or_default();
        let quote = spec["quote"].as_str().unwrap_or_default();
        let Some((repo_name, path)) = doc.split_once('/') else {
            failures.push(format!("{id}: spec.doc {doc:?} names no repo"));
            continue;
        };
        let repo = repo_of(repo_name)?;
        let text = corpus
            .get(&repo)
            .and_then(|docs| docs.iter().find(|(rel, _)| rel == path))
            .map(|(_, text)| text.as_str());
        quotes_checked += 1;
        match text {
            None => failures.push(format!(
                "{id}: spec.doc {doc} does not exist at the pinned commit"
            )),
            Some(text) if !quote_found(text, quote) => {
                failures.push(format!("{id}: spec.quote not found in {doc}: {quote:?}"))
            }
            Some(_) => {}
        }
    }

    let rulings_path = root.join("harness/expectations/RULINGS.md");
    let rulings = fs::read_to_string(&rulings_path).map_err(|e| e.to_string())?;
    let quotes = rulings_quotes(&rulings);
    for quote in &quotes {
        let found = corpus
            .values()
            .flatten()
            .any(|(_, text)| quote_found(text, quote));
        if !found {
            failures.push(format!(
                "RULINGS.md quote not found in any pinned spec: {quote:?}"
            ));
        }
    }
    lines.push(format!(
        "quotes: {quotes_checked} vector quotes and {} RULINGS quotes checked; {} not found",
        quotes.len(),
        failures.iter().filter(|f| f.contains("not found")).count()
    ));
    Ok(Report { lines, failures })
}

pub fn toml_name(repo: SpecRepo) -> &'static str {
    match repo {
        SpecRepo::MppSpecs => "mpp",
        SpecRepo::X402 => "x402",
    }
}

fn git_head(checkout: &Path) -> Option<String> {
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(checkout)
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// One requirements file reconciled with the pinned text of its scoped
/// documents. Shared by `pkc req-lint` and `pkc report`.
#[derive(Debug, Clone)]
pub struct RepoAnalysis {
    pub repo: SpecRepo,
    pub file: RequirementsFile,
    /// Scoped documents, in `files` order.
    pub docs: Vec<String>,
    /// Every normative sentence of `docs`, in document order.
    pub sentences: Vec<Sentence>,
}

impl RepoAnalysis {
    /// The extracted sentence a mapped requirement points at, when its id,
    /// text and document still agree with the pinned text.
    pub fn sentence_of(&self, req: &Requirement) -> Option<&Sentence> {
        self.sentences
            .iter()
            .find(|s| s.id == req.id)
            .filter(|s| s.doc == req.doc && sentence_id(self.repo, &req.text) == req.id)
    }

    /// Mapped requirements whose id, text or document no longer match the
    /// pinned text.
    pub fn drifted(&self) -> Vec<&Requirement> {
        self.file
            .requirements
            .iter()
            .filter(|r| self.sentence_of(r).is_none())
            .collect()
    }

    /// Sentences neither mapped nor ignored.
    pub fn unmapped(&self) -> Vec<&Sentence> {
        let known: BTreeSet<&str> = self
            .file
            .requirements
            .iter()
            .map(|r| r.id.as_str())
            .chain(self.file.ignores.iter().map(|i| i.id.as_str()))
            .collect();
        self.sentences
            .iter()
            .filter(|s| !known.contains(s.id.as_str()))
            .collect()
    }

    pub fn ignored(&self, id: &str) -> bool {
        self.file.ignores.iter().any(|i| i.id == id)
    }
}

/// Load `harness/requirements/<repo>.toml` and extract the sentences of the
/// documents it scopes.
pub fn analyse(root: &Path, repo: SpecRepo) -> Result<RepoAnalysis, String> {
    let toml_path = root.join(format!("harness/requirements/{}.toml", toml_name(repo)));
    let raw =
        fs::read_to_string(&toml_path).map_err(|e| format!("{}: {e}", toml_path.display()))?;
    let file: RequirementsFile =
        toml::from_str(&raw).map_err(|e| format!("{}: {e}", toml_path.display()))?;
    if repo_of(&file.repo)? != repo {
        return Err(format!(
            "{}: repo must be {}",
            toml_path.display(),
            repo.prefix()
        ));
    }
    let checkout = root.join(repo.checkout());
    let mut docs = Vec::new();
    for pattern in &file.files {
        docs.extend(expand(&checkout, pattern)?);
    }
    let mut sentences = Vec::new();
    for doc in &docs {
        let text = fs::read_to_string(checkout.join(doc)).map_err(|e| format!("{doc}: {e}"))?;
        sentences.extend(extract(repo, doc, &text));
    }
    Ok(RepoAnalysis {
        repo,
        file,
        docs,
        sentences,
    })
}

/// Mapped requirements without a case, split by whether that is fatal.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct CaseCoverage {
    /// Every mapped id no vector cites (reported).
    pub zero_cases: Vec<String>,
    /// The subset marked `required = true` (fails the lint).
    pub required_without_cases: Vec<String>,
}

pub fn case_coverage(requirements: &[Requirement], by_req: &ByRequirement) -> CaseCoverage {
    let mut out = CaseCoverage::default();
    for req in requirements {
        if by_req.get(&req.id).is_some_and(|cases| !cases.is_empty()) {
            continue;
        }
        out.zero_cases.push(req.id.clone());
        if req.required {
            out.required_without_cases.push(req.id.clone());
        }
    }
    out
}

/// All extracted sentences of a repo's scoped files (for `pkc req-lint
/// --list`, which is how requirement entries are written).
pub fn list(root: &Path, repo: SpecRepo) -> Result<Vec<Sentence>, String> {
    Ok(analyse(root, repo)?.sentences)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_normative_sentences_across_wrapped_lines() {
        let md = "---\ntitle: x\n---\n\n# Head MUST be skipped\n\nThe value MUST be a\npositive integer. It is fine.\n\n- `decimals` is REQUIRED\n  for mints.\n\n```\ncode MUST be ignored\n```\n\n| a | MUST |\n";
        let got: Vec<String> = extract(SpecRepo::MppSpecs, "d.md", md)
            .into_iter()
            .map(|s| s.text)
            .collect();
        assert_eq!(
            got,
            vec![
                "The value MUST be a positive integer.",
                "decimals is REQUIRED for mints.",
                "| a | MUST |",
            ]
        );
    }

    #[test]
    fn ids_are_stable_and_text_sensitive() {
        let a = sentence_id(SpecRepo::X402, "Clients MUST  do `x`.");
        assert_eq!(a, sentence_id(SpecRepo::X402, "Clients MUST do x."));
        assert_ne!(a, sentence_id(SpecRepo::X402, "Clients MUST do y."));
        assert!(a.starts_with("X402-") && a.len() == 15);
    }

    #[test]
    fn quotes_match_with_elisions() {
        let text = normalise("If omitted, clients MUST fetch the mint ... and if that lookup\nfails, clients MUST reject.");
        assert!(quote_found(
            &text,
            "If omitted, clients MUST fetch the mint ... clients MUST reject."
        ));
        assert!(!quote_found(&text, "clients MUST reject ... If omitted"));
    }

    #[test]
    fn rulings_quotes_use_curly_marks() {
        assert_eq!(
            rulings_quotes("a “one” b “two `\"x\"`” c"),
            vec!["one", "two `\"x\"`"]
        );
    }

    #[test]
    fn sentences_carry_their_innermost_section() {
        let md = "Intro MUST a.\n\n# Verification Procedure {#verification}\n\nServers MUST b.\n\n## Native SOL `transfer`\n\n- Each leg MUST c.\n";
        let got: Vec<(String, String)> = extract(SpecRepo::MppSpecs, "d.md", md)
            .into_iter()
            .map(|s| (s.section, s.text))
            .collect();
        assert_eq!(
            got,
            vec![
                (String::new(), "Intro MUST a.".to_string()),
                ("Verification Procedure".into(), "Servers MUST b.".into()),
                ("Native SOL transfer".into(), "Each leg MUST c.".into()),
            ]
        );
    }

    fn requirement(id: &str, required: bool) -> Requirement {
        Requirement {
            id: id.into(),
            doc: "d.md".into(),
            text: "t".into(),
            required,
        }
    }

    #[test]
    fn a_required_requirement_without_cases_fails() {
        let reqs = [requirement("MPP-0000000001", true)];
        let coverage = case_coverage(&reqs, &ByRequirement::new());
        assert_eq!(coverage.required_without_cases, vec!["MPP-0000000001"]);
        // An empty case list (a vector entry with no ids) is still zero.
        let empty: ByRequirement = [("MPP-0000000001".to_string(), vec![])].into();
        assert_eq!(
            case_coverage(&reqs, &empty).required_without_cases,
            vec!["MPP-0000000001"]
        );
    }

    #[test]
    fn covered_or_unrequired_requirements_pass() {
        let reqs = [
            requirement("MPP-0000000001", true),
            requirement("MPP-0000000002", false),
        ];
        let by_req: ByRequirement = [("MPP-0000000001".to_string(), vec!["case-a".into()])].into();
        let coverage = case_coverage(&reqs, &by_req);
        assert!(coverage.required_without_cases.is_empty());
        assert_eq!(coverage.zero_cases, vec!["MPP-0000000002"]);
    }

    #[test]
    fn requirement_entries_reject_unknown_keys() {
        let toml = "repo = \"x402\"\ncommit = \"c\"\nfiles = []\n[[requirement]]\nid = \"X402-0000000001\"\ndoc = \"d\"\ntext = \"t\"\nrequried = true\n";
        assert!(toml::from_str::<RequirementsFile>(toml).is_err());
        let ok = toml.replace("requried", "required");
        let file: RequirementsFile = toml::from_str(&ok).unwrap();
        assert!(file.requirements[0].required);
    }

    /// Every committed requirement that has cases today is marked required,
    /// so losing its last case fails CI.
    #[test]
    fn committed_requirements_with_cases_are_required() {
        let root = crate::repo_root();
        let (by_req, _) = vector_requirements(&root.join("harness/vectors")).unwrap();
        for repo in SpecRepo::ALL {
            let raw = fs::read_to_string(
                root.join(format!("harness/requirements/{}.toml", toml_name(repo))),
            )
            .unwrap();
            let file: RequirementsFile = toml::from_str(&raw).unwrap();
            for req in &file.requirements {
                if by_req.contains_key(&req.id) {
                    assert!(req.required, "{} has cases but is not required", req.id);
                }
            }
        }
    }
}
