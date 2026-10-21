//! `pkc run --tier offline`: drive one or more SDK testees over the vector
//! corpus, judge every result, reconcile against the expectations files and
//! write `harness/results/<sdk>.json` plus JUnit XML.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::{json, Value};

use crate::fixture_rpc::{Fixtures, HttpFixture};
use crate::run::expectations::{self, CaseRef, Decision, Expectations, Observed, Suite};
use crate::run::explain::{Context, Explanation};
use crate::run::judge::{self, Failure, Verdict};
use crate::run::testee::{Abi, Manifest, Testee};
use crate::run::vectors::{self, Vector};

#[derive(Debug, Clone)]
pub struct Options {
    pub root: PathBuf,
    pub sdks: Vec<String>,
    pub require: bool,
    pub discover: bool,
    pub abi: Abi,
    pub cases: Vec<String>,
    pub timeout: Duration,
    pub startup_timeout: Duration,
    pub vectors_dir: PathBuf,
    pub results_dir: PathBuf,
    pub prebuilt: Option<PathBuf>,
    pub verbose: bool,
    pub diff_expectations: bool,
    /// Write results and builds (false for `pkc case run`).
    pub write: bool,
}

impl Options {
    pub fn new(root: &Path) -> Self {
        let env_on = |k: &str| std::env::var(k).is_ok_and(|v| v == "1");
        Self {
            root: root.to_path_buf(),
            sdks: Vec::new(),
            require: env_on("HARNESS_REQUIRE"),
            discover: env_on("HARNESS_EXPECTATIONS_DISCOVER"),
            abi: Abi::Serve,
            cases: Vec::new(),
            timeout: Duration::from_secs(10),
            startup_timeout: Duration::from_secs(600),
            vectors_dir: root.join("harness/vectors"),
            results_dir: root.join("harness/results"),
            prebuilt: std::env::var("HARNESS_PREBUILT_DIR")
                .ok()
                .filter(|v| !v.is_empty())
                .map(PathBuf::from),
            verbose: false,
            diff_expectations: false,
            write: true,
        }
    }
}

/// One (SDK, case) outcome, as written to `harness/results/<sdk>.json`. The
/// first five fields are the shape the TS recorder wrote; the rest are
/// additive.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Record {
    pub key: String,
    pub capability: String,
    pub decision: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reject_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bug_type: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub requirements: Vec<String>,
    /// Reconciliation verdict: false fails the run.
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub problem: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stderr: Option<String>,
    #[serde(skip)]
    pub explanation: Option<Explanation>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SdkReport {
    pub suite: &'static str,
    pub language: String,
    pub discovery: bool,
    pub tier: &'static str,
    pub abi: &'static str,
    pub capabilities: Option<Value>,
    pub duration_ms: u64,
    /// Run-level problems (capabilities mismatch, dangling entries,
    /// incompleteness). Any entry fails the run.
    pub problems: Vec<String>,
    pub cases: Vec<Record>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diff: Option<Value>,
}

impl SdkReport {
    pub fn failed(&self) -> bool {
        !self.discovery && (!self.problems.is_empty() || self.cases.iter().any(|c| !c.ok))
    }

    pub fn counts(&self) -> BTreeMap<&'static str, usize> {
        let mut counts = BTreeMap::new();
        for c in &self.cases {
            *counts.entry(c.decision).or_default() += 1;
        }
        counts
    }
}

/// A build an SDK produced, saved for `--cross`.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SavedBuild {
    pub sdk: String,
    pub case: String,
    pub intent: String,
    /// `transaction` (charge) or `x402PaymentHeader` (x402).
    pub artifact: String,
    /// Whether a server must accept it: the Rust judge accepted it, or it is
    /// a valid build in another advertised message version
    /// (`judge::alternative_version_accepted`).
    pub judged: bool,
}

pub fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("tokio runtime")
}

/// Execute one vector against a testee and judge it.
pub struct CaseRun {
    pub observed: Observed,
    pub failure: Option<Failure>,
    pub stderr: String,
    pub request: String,
    pub duration: Duration,
    pub result: Option<Value>,
    pub artifact: Option<(String, bool)>,
}

pub fn run_case(testee: &mut Testee, vector: &Vector, rt: &tokio::runtime::Runtime) -> CaseRun {
    let started = Instant::now();
    let fixtures = match Fixtures::from_input(vector.input()) {
        Ok(f) => f,
        Err(e) => {
            let failure = Failure::new(format!("vector rpcFixtures: {e}"));
            return CaseRun {
                observed: Observed::Fail {
                    detail: failure.message.clone(),
                },
                failure: Some(failure),
                stderr: String::new(),
                request: String::new(),
                duration: started.elapsed(),
                result: None,
                artifact: None,
            };
        }
    };
    let rpc = match HttpFixture::start(&fixtures) {
        Ok(rpc) => rpc,
        Err(e) => panic!("fixture RPC failed to bind: {e}"),
    };
    let sent = vector.for_testee(Some(rpc.url()));
    let exchange = testee.run(vector.op(), &sent);
    let calls = rpc.calls();
    drop(rpc);
    let mut artifact = None;
    let judged: Result<Verdict, Failure> = match &exchange.result {
        Err(e) => Err(Failure::new(e.clone())),
        Ok(result) => match crate::run::result::validate(result) {
            Err(e) => Err(Failure::new(format!(
                "runner result for {} violates the conformance ABI: {e}",
                vector.id
            ))),
            Ok(()) => match judge::judge_expect(vector, result) {
                Ok(Verdict::Pass)
                    if vector.mode == "build-transaction" && result["outcome"] == "accept" =>
                {
                    match judge::build_artifact(vector, result) {
                        Err(f) => Err(f),
                        Ok(None) => Ok(Verdict::Pass),
                        Ok(Some(built)) => {
                            let verdict = rt.block_on(judge::judge_build(vector, &built));
                            // What a server must decide on this build: the
                            // judge's verdict, except that a valid build in
                            // another advertised version stays an accept.
                            let must_accept = verdict.is_ok()
                                || rt.block_on(judge::alternative_version_accepted(vector, &built));
                            artifact = Some((built, must_accept));
                            verdict.map(|()| Verdict::Pass)
                        }
                    }
                }
                other => other,
            },
        },
    };
    let (observed, failure) = match judged {
        Ok(Verdict::Pass) => (Observed::Pass, None),
        Ok(Verdict::Unsupported(detail)) => (Observed::Unsupported { detail }, None),
        Err(mut failure) => {
            let rpc_calls = if calls.is_empty() {
                "none".to_string()
            } else {
                calls.join(", ")
            };
            failure.message = format!("{}\n(fixture RPC calls: {rpc_calls})", failure.message);
            (
                Observed::Fail {
                    detail: failure.message.clone(),
                },
                Some(failure),
            )
        }
    };
    CaseRun {
        observed,
        failure,
        stderr: exchange.stderr,
        request: exchange.request,
        duration: exchange.duration,
        result: exchange.result.ok(),
        artifact,
    }
}

fn refs(vectors: &[Vector]) -> Vec<CaseRef> {
    vectors
        .iter()
        .map(|v| CaseRef::vector(&v.id, &v.intent))
        .collect()
}

/// Cross-check the testee's `capabilities` against the expectations file.
pub fn capability_problems(exp: &Expectations, caps: &Value) -> Vec<String> {
    let mut problems = Vec::new();
    let claimed: BTreeSet<String> = exp.claims(Suite::Vector).clone();
    let reported: Option<BTreeSet<String>> = caps["intents"].as_array().map(|a| {
        a.iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect()
    });
    match reported {
        None => problems.push("capabilities.intents is missing or not an array".into()),
        Some(reported) if reported != claimed => problems.push(format!(
            "testee capabilities claim intents {reported:?} but harness/expectations/{} claims {claimed:?}",
            exp.source
        )),
        Some(_) => {}
    }
    match (caps["honoursClock"].as_bool(), exp.honours_clock) {
        (None, _) => problems.push("capabilities.honoursClock is missing or not a boolean".into()),
        (Some(reported), Some(declared)) if reported != declared => problems.push(format!(
            "testee reports honoursClock={reported} but harness/expectations/{} declares honours_clock={declared}",
            exp.source
        )),
        _ => {}
    }
    problems
}

/// Run every selected vector for one SDK.
pub fn run_sdk(
    opts: &Options,
    ctx: &Context,
    manifest: &Manifest,
    exp: &Expectations,
    vectors: &[Vector],
    rt: &tokio::runtime::Runtime,
) -> SdkReport {
    let started = Instant::now();
    let all_refs = refs(vectors);
    let mut report = SdkReport {
        suite: "vector",
        language: exp.language.clone(),
        discovery: opts.discover,
        tier: "offline",
        abi: opts.abi.as_str(),
        capabilities: None,
        duration_ms: 0,
        problems: Vec::new(),
        cases: Vec::new(),
        diff: None,
    };
    if !opts.discover {
        report
            .problems
            .extend(exp.dangling(Suite::Vector, &all_refs));
    }
    let mut testee = match Testee::new(
        manifest,
        &opts.root,
        opts.abi,
        opts.prebuilt.as_deref(),
        opts.timeout,
        opts.startup_timeout,
    ) {
        Ok(t) => t,
        Err(e) => {
            report.problems.push(e);
            return report;
        }
    };
    let selected: Vec<&Vector> = vectors
        .iter()
        .filter(|v| opts.cases.is_empty() || opts.cases.iter().any(|c| c == &v.id))
        .collect();
    let any_claimed = opts.discover
        || selected.iter().any(|v| {
            exp.decide(&CaseRef::vector(&v.id, &v.intent)).ok() != Some(Decision::Unclaimed)
        });
    if any_claimed {
        match testee.capabilities() {
            Ok(Some(caps)) => {
                let problems = capability_problems(exp, &caps);
                if opts.discover {
                    for p in &problems {
                        eprintln!("warning: {}: {p}", exp.language);
                    }
                } else {
                    report.problems.extend(problems);
                }
                report.capabilities = Some(caps);
            }
            Ok(None) => {}
            Err(e) => report
                .problems
                .push(format!("testee failed to answer `capabilities`: {e}")),
        }
    }
    let builds_dir = opts.results_dir.join(&exp.language).join("builds");
    if opts.write {
        let _ = std::fs::remove_dir_all(&builds_dir);
    }
    let mut observed_keys = BTreeSet::new();
    for vector in selected {
        let case = CaseRef::vector(&vector.id, &vector.intent);
        let decision = if opts.discover {
            Ok(Decision::Pass)
        } else {
            exp.decide(&case)
        };
        let decision = match decision {
            Ok(d) => d,
            Err(e) => {
                report.problems.push(e);
                continue;
            }
        };
        let base = Record {
            key: case.key(),
            capability: case.capability.clone(),
            decision: decision.kind(),
            observed: None,
            detail: None,
            duration_ms: None,
            reject_code: vector.reject_code().map(str::to_string),
            bug_type: Some(vector.bug_type().to_string()),
            requirements: vector.requirements(),
            ok: true,
            problem: None,
            stderr: None,
            explanation: None,
        };
        if decision == Decision::Unclaimed {
            report.cases.push(base);
            continue;
        }
        if exp.honours_clock == Some(false)
            && vector.needs_clock()
            && !matches!(decision, Decision::Unsupported { .. })
            && !opts.discover
        {
            report.problems.push(format!(
                "{} needs a pinned clock but harness/expectations/{} declares honours_clock = false; list it under [[unsupported]]",
                case.key(),
                exp.source
            ));
        }
        let run = run_case(&mut testee, vector, rt);
        observed_keys.insert(case.key());
        if let (Some((artifact, judged)), true) = (&run.artifact, opts.write) {
            let saved = SavedBuild {
                sdk: exp.language.clone(),
                case: vector.id.clone(),
                intent: vector.intent.clone(),
                artifact: artifact.clone(),
                judged: *judged,
            };
            let _ = std::fs::create_dir_all(&builds_dir);
            let _ = std::fs::write(
                builds_dir.join(format!("{}.json", vector.id)),
                format!(
                    "{}\n",
                    serde_json::to_string_pretty(&saved).unwrap_or_default()
                ),
            );
        }
        let verdict = if opts.discover {
            Ok(())
        } else {
            exp.reconcile(&case, &decision, &run.observed)
        };
        let mut record = base;
        record.observed = Some(run.observed.kind());
        record.detail = run.observed.detail().map(str::to_string);
        record.duration_ms = Some(run.duration.as_millis() as u64);
        record.ok = verdict.is_ok();
        record.problem = verdict.err();
        if !matches!(run.observed, Observed::Pass) {
            let stderr = run.stderr.trim();
            if !stderr.is_empty() {
                record.stderr = Some(stderr.chars().take(8000).collect());
            }
        }
        if let Some(failure) = &run.failure {
            record.explanation =
                Some(ctx.explain(&exp.language, vector, failure, &run.stderr, &run.request));
        }
        report.cases.push(record);
    }
    if opts.require && !opts.discover {
        match expectations::missing_claimed(exp, &all_refs, &observed_keys) {
            Ok(missing) if !missing.is_empty() => report.problems.push(format!(
                "{}: {} claimed vector case(s) were not executed under --require:\n  {}",
                exp.language,
                missing.len(),
                missing
                    .iter()
                    .map(|c| c.key())
                    .collect::<Vec<_>>()
                    .join("\n  ")
            )),
            Ok(_) => {}
            Err(e) => report.problems.push(e),
        }
    }
    if !testee.stray_stdout.is_empty() {
        eprintln!(
            "warning: {} wrote {} non-response line(s) to stdout; diagnostics belong on stderr (first: {:?})",
            exp.language,
            testee.stray_stdout.len(),
            testee.stray_stdout[0].chars().take(200).collect::<String>()
        );
    }
    drop(testee);
    report.duration_ms = started.elapsed().as_millis() as u64;
    if opts.diff_expectations {
        report.diff = Some(diff_expectations(&report));
    }
    report
}

/// `--diff-expectations`: what flipped relative to the expectations file.
pub fn diff_expectations(report: &SdkReport) -> Value {
    let mut newly_passing = Vec::new();
    let mut newly_failing = Vec::new();
    let mut still_failing = Vec::new();
    for c in &report.cases {
        match (c.decision, c.observed) {
            ("known_failing", Some("pass")) | ("unsupported", Some("pass")) => {
                newly_passing.push(c.key.clone())
            }
            ("pass", Some("fail")) | ("pass", Some("unsupported")) => {
                newly_failing.push(c.key.clone())
            }
            ("known_failing", Some("fail")) => still_failing.push(c.key.clone()),
            _ => {}
        }
    }
    json!({
        "newly_passing": newly_passing,
        "newly_failing": newly_failing,
        "still_failing": still_failing,
    })
}

fn xml(text: &str) -> String {
    text.chars()
        .filter(|c| !c.is_control() || matches!(c, '\n' | '\t'))
        .collect::<String>()
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// JUnit XML: one test case per executed vector (unclaimed vectors are not
/// test cases), plus one `expectations` case carrying run-level problems.
pub fn junit(reports: &[SdkReport]) -> String {
    let mut out =
        String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<testsuites name=\"pkc\">\n");
    for r in reports {
        let executed: Vec<&Record> = r.cases.iter().filter(|c| c.observed.is_some()).collect();
        let failures =
            executed.iter().filter(|c| !c.ok).count() + usize::from(!r.problems.is_empty());
        let _ = writeln!(
            out,
            "  <testsuite name=\"pkc.{}.offline\" tests=\"{}\" failures=\"{failures}\" time=\"{:.3}\">",
            xml(&r.language),
            executed.len() + 1,
            r.duration_ms as f64 / 1000.0
        );
        for c in executed {
            let _ = write!(
                out,
                "    <testcase classname=\"pkc.{}\" name=\"{}\" time=\"{:.3}\"",
                xml(&r.language),
                xml(&c.key),
                c.duration_ms.unwrap_or(0) as f64 / 1000.0
            );
            if c.ok {
                let note = match c.decision {
                    "known_failing" => " (known failing, as declared)",
                    "unsupported" => " (unsupported, as declared)",
                    _ => "",
                };
                if note.is_empty() {
                    out.push_str("/>\n");
                } else {
                    let _ = writeln!(
                        out,
                        "><system-out>{}</system-out></testcase>",
                        xml(note.trim())
                    );
                }
            } else {
                let body = match &c.explanation {
                    Some(e) => e.markdown(false),
                    None => c.detail.clone().unwrap_or_default(),
                };
                let _ = writeln!(
                    out,
                    "><failure message=\"{}\">{}</failure></testcase>",
                    xml(c
                        .problem
                        .as_deref()
                        .unwrap_or("failed")
                        .lines()
                        .next()
                        .unwrap_or_default()),
                    xml(&body)
                );
            }
        }
        let _ = write!(
            out,
            "    <testcase classname=\"pkc.{}\" name=\"expectations\"",
            xml(&r.language)
        );
        if r.problems.is_empty() {
            out.push_str("/>\n");
        } else {
            let _ = writeln!(
                out,
                "><failure message=\"{} run-level problem(s)\">{}</failure></testcase>",
                r.problems.len(),
                xml(&r.problems.join("\n"))
            );
        }
        out.push_str("  </testsuite>\n");
    }
    out.push_str("</testsuites>\n");
    out
}

/// Human summary and failure explanations, plus GitHub annotations in CI.
pub fn print_report(report: &SdkReport, verbose: bool) {
    let counts = report.counts();
    let executed = report.cases.iter().filter(|c| c.observed.is_some()).count();
    let status = if report.discovery {
        "discovery (not judged)"
    } else if report.failed() {
        "FAILED"
    } else {
        "ok"
    };
    println!(
        "{}: {} vectors ({executed} executed): {} pass, {} known_failing, {} unsupported, {} unclaimed [{}] {:.1}s, {status}",
        report.language,
        report.cases.len(),
        counts.get("pass").unwrap_or(&0),
        counts.get("known_failing").unwrap_or(&0),
        counts.get("unsupported").unwrap_or(&0),
        counts.get("unclaimed").unwrap_or(&0),
        report.abi,
        report.duration_ms as f64 / 1000.0
    );
    let ci = std::env::var("GITHUB_ACTIONS").is_ok_and(|v| v == "true");
    for p in &report.problems {
        eprintln!("  FAIL {}: {p}", report.language);
        if ci {
            println!(
                "::error title=pkc {}::{}",
                report.language,
                p.replace('\n', "%0A")
            );
        }
    }
    for c in report.cases.iter().filter(|c| !c.ok) {
        let problem = c.problem.as_deref().unwrap_or("failed");
        eprintln!("  FAIL {}", problem.lines().next().unwrap_or_default());
        if let Some(e) = &c.explanation {
            if c.decision == "pass" {
                eprintln!("{}", indent(&e.markdown(verbose)));
            }
        } else if let Some(detail) = &c.detail {
            eprintln!("    {detail}");
        }
        if ci {
            println!(
                "::error title=pkc {} {}::{}",
                report.language,
                c.key,
                problem.replace('\n', "%0A")
            );
        }
    }
    if let Some(diff) = &report.diff {
        for key in ["newly_passing", "newly_failing", "still_failing"] {
            let ids = diff[key].as_array().cloned().unwrap_or_default();
            println!("  {key} ({}):", ids.len());
            for id in ids {
                println!("    {}", id.as_str().unwrap_or_default());
            }
        }
    }
}

fn indent(text: &str) -> String {
    text.lines()
        .map(|l| format!("    {l}"))
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn write_results(opts: &Options, reports: &[SdkReport]) -> Result<(), String> {
    std::fs::create_dir_all(&opts.results_dir).map_err(|e| e.to_string())?;
    for r in reports {
        let mut sorted = r.clone();
        sorted.cases.sort_by(|a, b| a.key.cmp(&b.key));
        std::fs::write(
            opts.results_dir.join(format!("{}.json", r.language)),
            format!(
                "{}\n",
                serde_json::to_string_pretty(&sorted).map_err(|e| e.to_string())?
            ),
        )
        .map_err(|e| e.to_string())?;
        let failures: Vec<&Explanation> = r
            .cases
            .iter()
            .filter_map(|c| c.explanation.as_ref())
            .collect();
        let explained = r.results_failures_path(&opts.results_dir);
        if failures.is_empty() {
            let _ = std::fs::remove_file(&explained);
        } else {
            std::fs::write(
                &explained,
                format!(
                    "{}\n",
                    serde_json::to_string_pretty(&failures).map_err(|e| e.to_string())?
                ),
            )
            .map_err(|e| e.to_string())?;
        }
    }
    let name = if reports.len() == 1 {
        format!("junit-{}.xml", reports[0].language)
    } else {
        "junit.xml".to_string()
    };
    std::fs::write(opts.results_dir.join(name), junit(reports)).map_err(|e| e.to_string())
}

impl SdkReport {
    /// `harness/results/<sdk>.failures.json`: every failure explained.
    pub fn results_failures_path(&self, dir: &Path) -> PathBuf {
        dir.join(format!("{}.failures.json", self.language))
    }
}

/// Load the corpus and the per-SDK inputs, then run every selected SDK in
/// parallel (one testee process each).
pub fn run(opts: &Options) -> Result<Vec<SdkReport>, String> {
    let vectors = vectors::load(&opts.vectors_dir)?;
    let expectations = expectations::load_all(&opts.root.join("harness/expectations"))?;
    let manifests = Manifest::discover(&opts.root)?;
    for c in &opts.cases {
        if !vectors.iter().any(|v| &v.id == c) {
            return Err(format!("no vector with id {c:?}"));
        }
    }
    // Every runner manifest has an expectations file, and every expectations
    // file that claims vectors has a runner manifest.
    let with_manifest: BTreeSet<&str> = manifests.iter().map(|m| m.language.as_str()).collect();
    for m in &with_manifest {
        if !expectations.contains_key(*m) {
            return Err(format!(
                "harness/runners/{m}.json has no harness/expectations/{m}.toml"
            ));
        }
    }
    for e in expectations.values() {
        if !e.claims(Suite::Vector).is_empty() && !with_manifest.contains(e.language.as_str()) {
            return Err(format!(
                "harness/expectations/{} claims vectors but there is no harness/runners/{}.json",
                e.source, e.language
            ));
        }
    }
    let mut jobs = Vec::new();
    for sdk in &opts.sdks {
        let manifest = manifests
            .iter()
            .find(|m| &m.language == sdk)
            .ok_or_else(|| format!("no harness/runners/{sdk}.json"))?
            .clone();
        let exp = expectations
            .get(sdk)
            .ok_or_else(|| format!("no harness/expectations/{sdk}.toml"))?
            .clone();
        jobs.push((manifest, exp));
    }
    let ctx = Context::load(&opts.root);
    let rt = runtime();
    let reports = std::thread::scope(|scope| {
        let handles: Vec<_> = jobs
            .iter()
            .map(|(manifest, exp)| {
                let (ctx, rt, vectors) = (&ctx, &rt, &vectors);
                scope.spawn(move || run_sdk(opts, ctx, manifest, exp, vectors, rt))
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().expect("sdk thread panicked"))
            .collect::<Vec<_>>()
    });
    if opts.write {
        write_results(opts, &reports)?;
    }
    Ok(reports)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exp(intents: &str, clock: bool) -> Expectations {
        Expectations::parse(
            &format!("language=\"t\"\n[capabilities]\nvector=[{intents}]\nhonours_clock={clock}"),
            "t.toml",
        )
        .unwrap()
    }

    #[test]
    fn capabilities_must_match_the_expectations_file() {
        let e = exp("\"charge\", \"session\"", true);
        assert!(capability_problems(
            &e,
            &json!({"intents": ["session", "charge"], "honoursClock": true})
        )
        .is_empty());
        let wrong_intents =
            capability_problems(&e, &json!({"intents": ["charge"], "honoursClock": true}));
        assert!(
            wrong_intents[0].contains("claim intents"),
            "{wrong_intents:?}"
        );
        let wrong_clock = capability_problems(
            &e,
            &json!({"intents": ["charge", "session"], "honoursClock": false}),
        );
        assert!(wrong_clock[0].contains("honoursClock"), "{wrong_clock:?}");
        assert_eq!(capability_problems(&e, &json!({})).len(), 2);
    }

    #[test]
    fn diff_expectations_buckets_flips() {
        let rec = |key: &str, decision: &'static str, observed: &'static str| Record {
            key: key.into(),
            capability: "charge".into(),
            decision,
            observed: Some(observed),
            detail: None,
            duration_ms: None,
            reject_code: None,
            bug_type: None,
            requirements: vec![],
            ok: true,
            problem: None,
            stderr: None,
            explanation: None,
        };
        let report = SdkReport {
            suite: "vector",
            language: "t".into(),
            discovery: false,
            tier: "offline",
            abi: "serve",
            capabilities: None,
            duration_ms: 0,
            problems: vec![],
            cases: vec![
                rec("vector/a", "known_failing", "pass"),
                rec("vector/b", "pass", "fail"),
                rec("vector/c", "known_failing", "fail"),
                rec("vector/d", "pass", "pass"),
            ],
            diff: None,
        };
        let diff = diff_expectations(&report);
        assert_eq!(diff["newly_passing"], json!(["vector/a"]));
        assert_eq!(diff["newly_failing"], json!(["vector/b"]));
        assert_eq!(diff["still_failing"], json!(["vector/c"]));
        let xml = junit(&[report]);
        assert!(xml.contains("name=\"vector/a\""));
        assert!(xml.contains("<testsuite name=\"pkc.t.offline\""));
    }
}
