//! `pkc req-lint`: the spec is the denominator.
//!
//! Extracts every normative sentence (MUST, MUST NOT, SHALL, REQUIRED) from
//! the SVM-relevant files of the pinned spec repositories, gives each a
//! stable id (hash of the normalised sentence), and reconciles them with
//! `harness/requirements/<repo>.toml` and the vectors:
//!
//! - unmapped sentences (neither mapped nor ignored): counted, not fatal;
//! - mapped ids with zero cases: counted, not fatal;
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

#[derive(Debug, Deserialize)]
pub struct RequirementsFile {
    pub repo: String,
    pub commit: String,
    pub files: Vec<String>,
    #[serde(default, rename = "requirement")]
    pub requirements: Vec<Requirement>,
    #[serde(default, rename = "ignore")]
    pub ignores: Vec<Ignore>,
}

#[derive(Debug, Deserialize)]
pub struct Requirement {
    pub id: String,
    pub doc: String,
    pub text: String,
}

#[derive(Debug, Deserialize)]
pub struct Ignore {
    pub id: String,
    pub reason: String,
}

/// One extracted normative sentence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sentence {
    pub id: String,
    pub doc: String,
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

/// Paragraphs, list items, definition bodies and table rows, each joined
/// into one line. Headings are dropped.
fn units(markdown: &str) -> Vec<String> {
    let mut units = Vec::new();
    let mut current = String::new();
    let flush = |current: &mut String, units: &mut Vec<String>| {
        let unit = strip_marker(current.trim()).to_string();
        if !unit.is_empty() && !current.trim().starts_with('#') {
            units.push(unit);
        }
        current.clear();
    };
    for line in prose_lines(markdown) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            flush(&mut current, &mut units);
            continue;
        }
        if starts_unit(trimmed) {
            flush(&mut current, &mut units);
        }
        current.push(' ');
        current.push_str(trimmed);
        if trimmed.starts_with('|') || trimmed.starts_with('#') {
            flush(&mut current, &mut units);
        }
    }
    flush(&mut current, &mut units);
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
    for unit in units(markdown) {
        for sentence in split_sentences(&unit) {
            if !is_normative(&sentence) {
                continue;
            }
            let id = sentence_id(repo, &sentence);
            if seen.insert(id.clone()) {
                out.push(Sentence {
                    id,
                    doc: doc.to_string(),
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
type ByRequirement = BTreeMap<String, Vec<String>>;
/// (vector id, `spec` object) per vector.
type VectorSpecs = Vec<(String, Value)>;

/// Requirement ids each vector maps, keyed by id → vector ids.
fn vector_requirements(vectors_dir: &Path) -> Result<(ByRequirement, VectorSpecs), String> {
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
        if let Some(head) = git_head(&checkout) {
            if !head.starts_with(&file.commit) {
                lines.push(format!(
                    "warning: {} is at {head}, requirements pinned at {}",
                    repo.checkout(),
                    file.commit
                ));
            }
        }
        let mut docs = Vec::new();
        for pattern in &file.files {
            docs.extend(expand(&checkout, pattern)?);
        }
        let mut sentences = Vec::new();
        for doc in &docs {
            let text = fs::read_to_string(checkout.join(doc)).map_err(|e| format!("{doc}: {e}"))?;
            sentences.extend(extract(repo, doc, &text));
        }
        let extracted: BTreeMap<&str, &Sentence> =
            sentences.iter().map(|s| (s.id.as_str(), s)).collect();
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
        let mut mapped = 0;
        let mut zero_cases = Vec::new();
        for req in &file.requirements {
            all_mapped.insert(req.id.clone());
            let hashed = sentence_id(repo, &req.text);
            match extracted.get(req.id.as_str()) {
                Some(sentence) if hashed == req.id && sentence.doc == req.doc => mapped += 1,
                _ => failures.push(format!(
                    "{}: mapped requirement {} ({}) no longer matches the pinned text: {:?}",
                    repo.prefix(),
                    req.id,
                    req.doc,
                    req.text
                )),
            }
            if !by_req.contains_key(&req.id) {
                zero_cases.push(req.id.clone());
            }
        }
        let unmapped = sentences
            .iter()
            .filter(|s| {
                !ignored.contains(s.id.as_str()) && !file.requirements.iter().any(|r| r.id == s.id)
            })
            .count();
        lines.push(format!(
            "{}: {} normative sentences in {} files; {} mapped, {} ignored, {} unmapped; {} mapped with zero cases",
            repo.prefix(),
            sentences.len(),
            docs.len(),
            mapped,
            ignored.len(),
            unmapped,
            zero_cases.len()
        ));
        for id in zero_cases {
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

/// All extracted sentences of a repo's scoped files (for `pkc req-lint
/// --list`, which is how requirement entries are written).
pub fn list(root: &Path, repo: SpecRepo) -> Result<Vec<Sentence>, String> {
    let toml_path = root.join(format!("harness/requirements/{}.toml", toml_name(repo)));
    let raw =
        fs::read_to_string(&toml_path).map_err(|e| format!("{}: {e}", toml_path.display()))?;
    let file: RequirementsFile = toml::from_str(&raw).map_err(|e| e.to_string())?;
    let checkout = root.join(repo.checkout());
    let mut out = Vec::new();
    for pattern in &file.files {
        for doc in expand(&checkout, pattern)? {
            let text = fs::read_to_string(checkout.join(&doc)).map_err(|e| e.to_string())?;
            out.extend(extract(repo, &doc, &text));
        }
    }
    Ok(out)
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
}
