//! `pkc`: pay-kit conformance.
//!
//! ```text
//! pkc fill                      regenerate harness/vectors/ from the case registry
//! pkc fill --check              fail on any difference (refuses a dirty harness/vectors/)
//! pkc fill --list               print case ids and counts
//! pkc fill --seed N --out DIR   seeded variant (different memo nonces and mutation
//!                               magnitudes, same verdicts) into DIR, never the committed tree
//! pkc req-lint                  requirements lint over the pinned spec repositories
//! pkc req-lint --list mpp|x402  print every extracted normative sentence with its id
//! pkc report [--check]         requirement x SDK traceability (README table, results/report.json)
//! pkc run --sdk <lang>[,..]|all --tier offline [--require] [...]   drive SDK testees
//! pkc run --cross [--sdk <servers>] [--check] [--require]          client x server matrix
//! pkc case show <id>            input, decoded expectation, mutation, spec, reference
//! pkc case run --sdk <lang> <id>
//! pkc next --sdk <lang>         the smallest failing class, blocking classes first
//! pkc scaffold --lang <template> [--sdk <name>] [--dir <path>]
//! ```
//!
//! See `pkc help` and `harness/AGENTS.md`.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use paykit_conformance::case::SpecRepo;
use paykit_conformance::run::driver::{self, Options};
use paykit_conformance::run::testee::{Abi, Manifest};
use paykit_conformance::run::{cross, cross_gate, explain, next, scaffold, vectors};
use paykit_conformance::{annotate, cases, fill, realize, repo_root, report, reqlint};

const HELP: &str = "pkc: pay-kit conformance

  pkc fill [--check | --list | --seed N --out DIR]
  pkc req-lint [--list mpp|x402]
  pkc report [--check | --unmapped [mpp|x402]]
      requirement x SDK traceability into harness/README.md (--check: fail if stale)
      and harness/results/report.json (with observed outcomes); --unmapped prints the gap list

  pkc run --sdk <lang>[,<lang>...]|all --tier offline [options]
      --require              every claimed case must execute (also HARNESS_REQUIRE=1)
      --discover             run every vector regardless of claims, judge nothing
                             (also HARNESS_EXPECTATIONS_DISCOVER=1); seeds expectations
      --case <id>            only this vector (repeatable); incompatible with --require
      --diff-expectations    print newly_passing / newly_failing / still_failing
      --legacy               one process per case (ABI v1 shim) instead of --serve
      --timeout <secs>       per-case timeout (default 10)
      --startup-timeout <s>  testee start + first case (default 600)
      --seed <n>             fill a seeded variant corpus and run against it
      --vectors <dir>        corpus directory (default harness/vectors)
      --results <dir>        results directory (default harness/results)
      --prebuilt <dir>       prebuilt native runners (default $HARNESS_PREBUILT_DIR)
      --cross                after the run, cross-verify every build on every server
      --verbose              full decoded trees in failure output
  pkc run --cross [--sdk <servers>] [--check] [--require]
      feed every saved build (harness/results/<sdk>/builds) to every server-capable
      SDK's verify; writes harness/results/cross.json and the README table
      (--check: fail if the table in harness/README.md is stale). Each cell
      cross/<case>/<client>/<server> is reconciled against the server's
      expectations (claim `cross = true`; unsupported / known_failing as for
      vectors). --require: also fail when a verifier does not claim cross or
      a promised client build is missing from harness/results/<sdk>/builds

  pkc case show <id>
  pkc case run --sdk <lang> <id> [--legacy] [--verbose]
  pkc next --sdk <lang> [--cached] [--all]
  pkc scaffold --lang <python|typescript|go|ruby|php|lua> [--sdk <name>] [--dir <path>]

examples:
  pkc run --sdk python --tier offline              # one SDK, under a minute
  pkc run --sdk all --tier offline --require       # what CI runs, per language
  pkc next --sdk python                            # smallest failing class + fix brief
  pkc case run --sdk python charge-verify-wrong-amount-reject
  pkc run --sdk python --diff-expectations         # what flipped vs the toml
";

fn usage() -> ExitCode {
    eprint!("{HELP}");
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let root = repo_root();
    match args.first().map(String::as_str) {
        Some("fill") => fill_cmd(&root, &args[1..]),
        Some("req-lint") => req_lint_cmd(&root, &args[1..]),
        Some("report") => report_cmd(&root, &args[1..]),
        Some("run") => run_cmd(&root, &args[1..]),
        Some("case") => case_cmd(&root, &args[1..]),
        Some("next") => next_cmd(&root, &args[1..]),
        Some("scaffold") => scaffold_cmd(&root, &args[1..]),
        Some("plan") => plan_cmd(&root, &args[1..]),
        Some("adapters") => adapters_cmd(&root, &args[1..]),
        Some("help" | "--help" | "-h") => {
            print!("{HELP}");
            ExitCode::SUCCESS
        }
        _ => usage(),
    }
}

fn flag_values(args: &[String], flag: &str) -> Vec<String> {
    args.iter()
        .enumerate()
        .filter(|(_, a)| *a == flag)
        .filter_map(|(i, _)| args.get(i + 1).cloned())
        .collect()
}

fn has(args: &[String], flag: &str) -> bool {
    args.iter().any(|a| a == flag)
}

/// Positional arguments (not flags and not flag values).
fn positionals(args: &[String], valued: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    let mut skip = false;
    for a in args {
        if skip {
            skip = false;
            continue;
        }
        if valued.contains(&a.as_str()) {
            skip = true;
            continue;
        }
        if !a.starts_with("--") {
            out.push(a.clone());
        }
    }
    out
}

const RUN_VALUED: [&str; 9] = [
    "--sdk",
    "--tier",
    "--case",
    "--timeout",
    "--startup-timeout",
    "--seed",
    "--vectors",
    "--results",
    "--prebuilt",
];

fn options(root: &Path, args: &[String]) -> Result<Options, String> {
    let mut opts = Options::new(root);
    let manifests = Manifest::discover(root)?;
    for sdk in flag_values(args, "--sdk") {
        for s in sdk.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            if s == "all" {
                opts.sdks
                    .extend(manifests.iter().map(|m| m.language.clone()));
            } else {
                opts.sdks.push(s.to_string());
            }
        }
    }
    opts.sdks.dedup();
    if let Some(tier) = flag_values(args, "--tier").pop() {
        if tier != "offline" {
            return Err(format!(
                "--tier {tier}: expected offline or interop (the onchain tier is phase 4)"
            ));
        }
    }
    opts.require |= has(args, "--require");
    opts.discover |= has(args, "--discover");
    opts.verbose = has(args, "--verbose");
    opts.diff_expectations = has(args, "--diff-expectations");
    if has(args, "--legacy") {
        opts.abi = Abi::Legacy;
    }
    opts.cases = flag_values(args, "--case");
    let secs = |flag: &str| -> Result<Option<Duration>, String> {
        flag_values(args, flag)
            .pop()
            .map(|v| {
                v.parse::<f64>()
                    .map(Duration::from_secs_f64)
                    .map_err(|_| format!("{flag} {v}: not a number of seconds"))
            })
            .transpose()
    };
    if let Some(t) = secs("--timeout")? {
        opts.timeout = t;
    }
    if let Some(t) = secs("--startup-timeout")? {
        opts.startup_timeout = t;
    }
    if let Some(dir) = flag_values(args, "--vectors").pop() {
        opts.vectors_dir = PathBuf::from(dir);
    }
    if let Some(dir) = flag_values(args, "--results").pop() {
        opts.results_dir = PathBuf::from(dir);
    }
    if let Some(dir) = flag_values(args, "--prebuilt").pop() {
        opts.prebuilt = Some(PathBuf::from(dir)).filter(|p| !p.as_os_str().is_empty());
    }
    if opts.require && !opts.cases.is_empty() {
        return Err("--require runs every claimed case; it cannot be combined with --case".into());
    }
    Ok(opts)
}

fn seeded_corpus(opts: &mut Options, seed: &str) -> Result<(), String> {
    let seed: u64 = seed
        .parse()
        .map_err(|_| format!("--seed {seed}: not a number"))?;
    realize::set_seed(seed);
    let files = driver::runtime()
        .block_on(fill::generate(&cases::all()))
        .map_err(|errors| errors.join("\n"))?;
    let dir = opts
        .results_dir
        .join(format!("seed-{seed}"))
        .join("vectors");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    fill::write(&dir, &files)?;
    eprintln!("pkc: seeded corpus (seed {seed}) in {}", dir.display());
    opts.vectors_dir = dir;
    Ok(())
}

fn run_cmd(root: &Path, args: &[String]) -> ExitCode {
    if flag_values(args, "--tier").last().map(String::as_str) == Some("interop") {
        return interop_run_cmd(root, args);
    }
    let mut opts = match options(root, args) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("pkc run: {e}");
            return ExitCode::from(2);
        }
    };
    if let Some(seed) = flag_values(args, "--seed").pop() {
        if let Err(e) = seeded_corpus(&mut opts, &seed) {
            eprintln!("pkc run --seed: {e}");
            return ExitCode::FAILURE;
        }
    }
    let wants_cross = has(args, "--cross");
    let mut failed = false;
    let cross_check_only = wants_cross && has(args, "--check");
    if !opts.sdks.is_empty() && !cross_check_only {
        match driver::run(&opts) {
            Ok(reports) => {
                for r in &reports {
                    driver::print_report(r, opts.verbose);
                    failed |= r.failed();
                }
            }
            Err(e) => {
                eprintln!("pkc run: {e}");
                return ExitCode::FAILURE;
            }
        }
    } else if !wants_cross {
        eprintln!("pkc run: --sdk is required (or --cross)");
        return ExitCode::from(2);
    }
    if wants_cross {
        failed |= cross_cmd(root, &opts, has(args, "--check")).is_err();
    }
    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn cross_cmd(root: &Path, opts: &Options, check: bool) -> Result<(), ()> {
    let report = cross::cross(opts).map_err(|e| eprintln!("pkc run --cross: {e}"))?;
    let disagreements: Vec<&cross::Cell> = report
        .cells
        .iter()
        .filter(|c| !c.agree && c.observed != "unsupported")
        .collect();
    println!(
        "cross: {} builds x servers checked, {} disagree",
        report.cells.len(),
        disagreements.len()
    );
    for c in &disagreements {
        println!(
            "  {} {} built by {} verified by {}: expected {}, got {} {}",
            c.intent,
            c.case,
            c.client,
            c.server,
            c.expected,
            c.observed,
            c.detail.as_deref().unwrap_or_default()
        );
    }
    let _ = std::fs::create_dir_all(&opts.results_dir);
    let _ = std::fs::write(
        opts.results_dir.join("cross.json"),
        format!(
            "{}\n",
            serde_json::to_string_pretty(&report).unwrap_or_default()
        ),
    );
    let readme_path = root.join("harness/README.md");
    let readme = std::fs::read_to_string(&readme_path).map_err(|e| eprintln!("{e}"))?;
    let next = cross::rewrite(&readme, &cross::render(&report)).map_err(|e| eprintln!("{e}"))?;
    if check {
        if next != readme {
            eprintln!("harness/README.md cross-verification table is stale; run `pkc run --cross`");
            return Err(());
        }
    } else if next != readme {
        std::fs::write(&readme_path, next).map_err(|e| eprintln!("{e}"))?;
        println!("cross: rewrote the table in harness/README.md");
    }
    // Every cell, including one whose server could not start, is reconciled
    // against the server's expectations (`cross/<case>/<client>/<server>`).
    let gate =
        cross_gate::gate(root, opts, &report).map_err(|e| eprintln!("pkc run --cross: {e}"))?;
    println!(
        "cross: {} cells reconciled, {} expected failures (known_failing / unsupported), {} problems",
        report.cells.len(),
        gate.expected_failures,
        gate.problems.len()
    );
    for p in &gate.problems {
        eprintln!("FAIL {p}");
    }
    if gate.problems.is_empty() {
        Ok(())
    } else {
        Err(())
    }
}

fn case_cmd(root: &Path, args: &[String]) -> ExitCode {
    match args.first().map(String::as_str) {
        Some("show") => {
            let Some(id) = args.get(1) else {
                return usage();
            };
            case_show(root, id)
        }
        Some("run") => {
            let ids = positionals(&args[1..], &RUN_VALUED);
            let [id] = ids.as_slice() else {
                eprintln!("pkc case run --sdk <lang> <id>");
                return ExitCode::from(2);
            };
            let mut rest: Vec<String> = args[1..].to_vec();
            rest.retain(|a| a != id);
            let mut opts = match options(root, &rest) {
                Ok(o) => o,
                Err(e) => {
                    eprintln!("pkc case run: {e}");
                    return ExitCode::from(2);
                }
            };
            if opts.sdks.len() != 1 {
                eprintln!("pkc case run needs exactly one --sdk");
                return ExitCode::from(2);
            }
            opts.cases = vec![id.clone()];
            opts.require = false;
            opts.write = false;
            opts.verbose = true;
            match driver::run(&opts) {
                Ok(reports) => {
                    let r = &reports[0];
                    let mut failed = false;
                    for c in r.cases.iter().filter(|c| c.observed.is_some()) {
                        println!(
                            "{} {}: decision {}, observed {} ({} ms)",
                            r.language,
                            c.key,
                            c.decision,
                            c.observed.unwrap_or_default(),
                            c.duration_ms.unwrap_or(0)
                        );
                        if let Some(e) = &c.explanation {
                            println!("{}", e.markdown(true));
                        } else if let Some(d) = &c.detail {
                            println!("{d}");
                        }
                        if let Some(p) = &c.problem {
                            println!("reconciliation: {p}");
                        }
                        failed |= !c.ok;
                    }
                    if r.cases.iter().all(|c| c.observed.is_none()) {
                        println!(
                            "{} does not claim {id}; nothing executed (use --discover to run it anyway)",
                            r.language
                        );
                    }
                    for p in &r.problems {
                        eprintln!("FAIL {p}");
                        failed = true;
                    }
                    if failed {
                        ExitCode::FAILURE
                    } else {
                        ExitCode::SUCCESS
                    }
                }
                Err(e) => {
                    eprintln!("pkc case run: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        _ => usage(),
    }
}

fn case_show(root: &Path, id: &str) -> ExitCode {
    let vectors = match vectors::load(&root.join("harness/vectors")) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    let Some(vector) = vectors.iter().find(|v| v.id == id) else {
        eprintln!("no vector with id {id:?} (pkc fill --list prints them)");
        return ExitCode::FAILURE;
    };
    let ctx = explain::Context::load(root);
    let case = ctx.cases.get(id);
    println!(
        "# {id}\n{} {} -> expect {}{}\nfile harness/vectors/{}\n",
        vector.intent,
        vector.mode,
        vector.expect_outcome(),
        vector
            .reject_code()
            .map(|c| format!(" {c}"))
            .unwrap_or_default(),
        vector.file
    );
    if let Some(d) = vector.raw["description"].as_str() {
        println!("{d}\n");
    }
    let req = ctx.requirement(vector);
    println!(
        "## Spec\n> {}\n`{}` § {} (pinned {})",
        req["quote"].as_str().unwrap_or_default(),
        req["doc"].as_str().unwrap_or_default(),
        req["section"].as_str().unwrap_or_default(),
        req["pinnedSha"].as_str().unwrap_or("unknown")
    );
    for r in req["requirements"].as_array().into_iter().flatten() {
        println!(
            "- {}: {}",
            r["id"].as_str().unwrap_or_default(),
            r["text"].as_str().unwrap_or_default()
        );
    }
    println!(
        "\n## Mutation\n{}",
        case.and_then(explain::mutation_words)
            .unwrap_or_else(|| "none".into())
    );
    let provenance = match case.map(|c| &c.provenance) {
        Some(paykit_conformance::case::Provenance::Authored {
            kit_divergence: Some(reason),
        }) => format!("authored (the Rust kit diverges: {reason})"),
        Some(paykit_conformance::case::Provenance::Authored { .. }) => "authored".into(),
        _ => "generated (expected value computed by the Rust kit)".into(),
    };
    println!(
        "\n## Provenance\n{provenance}, bugType {}",
        vector.bug_type()
    );
    println!("\n## Reference");
    for r in ctx.references(vector) {
        println!("- {r}");
    }
    println!(
        "\n## Input\n```json\n{}\n```",
        serde_json::to_string_pretty(vector.input()).unwrap_or_default()
    );
    println!(
        "\n## Expected\n```json\n{}\n```",
        serde_json::to_string_pretty(vector.expect()).unwrap_or_default()
    );
    let reference = if vector.mode == "build-transaction" && vector.intent == "charge" {
        let input = vector.input().clone();
        match driver::runtime().block_on(realize::run(
            paykit_conformance::case::Intent::Charge,
            paykit_conformance::case::Mode::BuildTransaction,
            &input,
        )) {
            realize::Observed::Accept(o) => o.transaction,
            _ => None,
        }
    } else {
        None
    };
    if let Some(text) = annotate::vector(&vector.raw, reference.as_deref()) {
        println!("\n## Decoded\n```\n{text}```");
    }
    println!("\nreplay: pkc case run --sdk <lang> {id}");
    ExitCode::SUCCESS
}

fn next_cmd(root: &Path, args: &[String]) -> ExitCode {
    let opts = match options(root, args) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("pkc next: {e}");
            return ExitCode::from(2);
        }
    };
    let [sdk] = opts.sdks.as_slice() else {
        eprintln!("pkc next needs exactly one --sdk");
        return ExitCode::from(2);
    };
    let path = opts.results_dir.join(format!("{sdk}.json"));
    if !has(args, "--cached") || !path.exists() {
        if let Err(e) = driver::run(&opts) {
            eprintln!("pkc next: {e}");
            return ExitCode::FAILURE;
        }
    }
    let results: serde_json::Value = match std::fs::read_to_string(&path)
        .map_err(|e| e.to_string())
        .and_then(|t| serde_json::from_str(&t).map_err(|e| e.to_string()))
    {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{}: {e}", path.display());
            return ExitCode::FAILURE;
        }
    };
    let groups = next::groups(&results);
    if groups.is_empty() {
        println!("{sdk}: nothing failing and nothing known_failing. Claim the next intent or remove an [[unsupported]] entry.");
        return ExitCode::SUCCESS;
    }
    let ctx = explain::Context::load(root);
    let vectors = vectors::load(&opts.vectors_dir).unwrap_or_default();
    println!("{sdk}: {} failing class(es)\n", groups.len());
    let shown = if has(args, "--all") { groups.len() } else { 1 };
    for g in groups.iter().take(shown) {
        println!("{}", next::brief(sdk, g, &ctx, &vectors));
    }
    if shown < groups.len() {
        println!("({} more; --all prints every class)", groups.len() - shown);
    }
    ExitCode::SUCCESS
}

fn scaffold_cmd(root: &Path, args: &[String]) -> ExitCode {
    let Some(lang) = flag_values(args, "--lang").pop() else {
        eprintln!(
            "pkc scaffold --lang <{}> [--sdk <name>] [--dir <path>]",
            scaffold::TEMPLATES.join("|")
        );
        return ExitCode::from(2);
    };
    let sdk = flag_values(args, "--sdk")
        .pop()
        .unwrap_or_else(|| lang.clone());
    let dir = flag_values(args, "--dir")
        .pop()
        .unwrap_or_else(|| sdk.clone());
    match scaffold::write(root, &lang, &sdk, &dir) {
        Ok(files) => {
            for f in files {
                println!("wrote {}", f.display());
            }
            println!(
                "next: pkc run --sdk {sdk} --tier offline --discover   (every vector reports unsupported)"
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("pkc scaffold: {e}");
            ExitCode::FAILURE
        }
    }
}

fn flag_value(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn fill_cmd(root: &std::path::Path, args: &[String]) -> ExitCode {
    let registry = cases::all();
    if args.iter().any(|a| a == "--list") {
        for case in &registry {
            println!("{}", case.id);
        }
        for line in fill::summary(&registry) {
            eprintln!("{line}");
        }
        eprintln!("{} cases", registry.len());
        return ExitCode::SUCCESS;
    }
    let check = args.iter().any(|a| a == "--check");
    let seed = flag_value(args, "--seed");
    let out = flag_value(args, "--out").map(PathBuf::from);
    let vectors_dir = root.join("harness/vectors");
    if let Some(seed) = &seed {
        let Ok(seed) = seed.parse::<u64>() else {
            return usage();
        };
        if out.is_none() || check {
            eprintln!(
                "pkc fill --seed writes a variant corpus and needs --out DIR (and no --check)"
            );
            return ExitCode::from(2);
        }
        realize::set_seed(seed);
    }
    if check {
        match fill::dirty(root) {
            Ok(dirty) if dirty.is_empty() => {}
            Ok(dirty) => {
                eprintln!("pkc fill --check refuses to run on a dirty harness/vectors/:");
                for line in dirty {
                    eprintln!("  {line}");
                }
                return ExitCode::FAILURE;
            }
            Err(e) => {
                eprintln!("{e}");
                return ExitCode::FAILURE;
            }
        }
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("tokio runtime");
    let files = match runtime.block_on(fill::generate(&registry)) {
        Ok(files) => files,
        Err(errors) => {
            for e in errors {
                eprintln!("error: {e}");
            }
            return ExitCode::FAILURE;
        }
    };
    let target = out.unwrap_or(vectors_dir);
    if check {
        match fill::diff(&target, &files) {
            Ok(diff) if diff.is_empty() => {
                println!("pkc fill --check: {} files up to date", files.len());
                ExitCode::SUCCESS
            }
            Ok(diff) => {
                eprintln!("pkc fill --check: vectors are stale; run `cargo run -p paykit-conformance --bin pkc -- fill`");
                for line in diff {
                    eprintln!("  {line}");
                }
                ExitCode::FAILURE
            }
            Err(e) => {
                eprintln!("{e}");
                ExitCode::FAILURE
            }
        }
    } else {
        if let Err(e) = std::fs::create_dir_all(&target)
            .map_err(|e| e.to_string())
            .and_then(|_| fill::write(&target, &files))
        {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
        println!(
            "pkc fill: wrote {} files to {}",
            files.len(),
            target.display()
        );
        ExitCode::SUCCESS
    }
}

fn sdk_list(args: &[String]) -> Vec<String> {
    let mut out: Vec<String> = flag_values(args, "--sdk")
        .iter()
        .flat_map(|v| {
            v.split(',')
                .map(str::trim)
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .filter(|s| !s.is_empty() && s != "all")
        .collect();
    out.sort();
    out.dedup();
    out
}

#[cfg(feature = "interop")]
fn interop_run_cmd(root: &Path, args: &[String]) -> ExitCode {
    use paykit_conformance::interop::runner;
    let mut opts = runner::Options::new(root);
    opts.sdks = sdk_list(args);
    opts.shard = flag_values(args, "--shard").pop();
    opts.cases = flag_values(args, "--case");
    opts.require |= has(args, "--require");
    opts.discover |= has(args, "--discover");
    opts.verbose = has(args, "--verbose");
    if opts.require && !opts.cases.is_empty() {
        eprintln!("pkc run: --require runs every claimed case; it cannot be combined with --case");
        return ExitCode::from(2);
    }
    if let Some(j) = flag_values(args, "--jobs").pop() {
        match j.parse::<usize>() {
            Ok(n) if n > 0 => opts.jobs = n,
            _ => {
                eprintln!("pkc run: --jobs {j}: not a positive number");
                return ExitCode::from(2);
            }
        }
    }
    if let Some(t) = flag_values(args, "--timeout").pop() {
        match t.parse::<f64>() {
            Ok(s) => opts.timeout = Duration::from_secs_f64(s),
            Err(_) => {
                eprintln!("pkc run: --timeout {t}: not a number of seconds");
                return ExitCode::from(2);
            }
        }
    }
    if let Some(dir) = flag_values(args, "--prebuilt").pop() {
        opts.prebuilt = Some(PathBuf::from(dir)).filter(|p| !p.as_os_str().is_empty());
    }
    if let Some(so) = flag_values(args, "--program-so").pop() {
        opts.program_so = Some(PathBuf::from(so));
    }
    if let Some(dir) = flag_values(args, "--results").pop() {
        opts.results_dir = PathBuf::from(dir);
    }
    match runner::run(&opts) {
        Ok(report) => {
            runner::print(&report);
            if report.failed() {
                ExitCode::FAILURE
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(e) => {
            eprintln!("pkc run --tier interop: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(feature = "interop"))]
fn interop_run_cmd(_root: &Path, _args: &[String]) -> ExitCode {
    eprintln!(
        "pkc run --tier interop needs the validator: rebuild with `cargo build -p paykit-conformance --features interop`"
    );
    ExitCode::from(2)
}

fn plan_cmd(root: &Path, args: &[String]) -> ExitCode {
    use paykit_conformance::interop::plan;
    if flag_values(args, "--tier").last().map(String::as_str) != Some("interop") {
        eprintln!("pkc plan --tier interop [--matrix | --github-output] [--only <sdk>,..] [--write | --check]");
        return ExitCode::from(2);
    }
    let exps =
        match paykit_conformance::run::expectations::load_all(&root.join("harness/expectations")) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("{e}");
                return ExitCode::FAILURE;
            }
        };
    let p = match plan::plan(&exps) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("pkc plan: {e}");
            return ExitCode::FAILURE;
        }
    };
    if has(args, "--write") || has(args, "--check") {
        let table = match plan::render(&exps, &p) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("pkc plan: {e}");
                return ExitCode::FAILURE;
            }
        };
        let readme_path = root.join("harness/README.md");
        let readme = std::fs::read_to_string(&readme_path).unwrap_or_default();
        let next_readme = match plan::rewrite(&readme, &table) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("pkc plan: {e}");
                return ExitCode::FAILURE;
            }
        };
        let plan_path = root.join(plan::PLAN_FILE);
        let json = p.to_json();
        if has(args, "--check") {
            let mut stale = Vec::new();
            if std::fs::read_to_string(&plan_path).unwrap_or_default() != json {
                stale.push(plan::PLAN_FILE);
            }
            if next_readme != readme {
                stale.push("harness/README.md (interop table)");
            }
            if !stale.is_empty() {
                eprintln!(
                    "pkc plan: {} stale; run `pkc plan --tier interop --write`",
                    stale.join(" and ")
                );
                return ExitCode::FAILURE;
            }
            println!(
                "pkc plan: {} and the README interop table are up to date",
                plan::PLAN_FILE
            );
        } else {
            if let Err(e) = std::fs::write(&plan_path, json)
                .and_then(|_| std::fs::write(&readme_path, next_readme))
            {
                eprintln!("{e}");
                return ExitCode::FAILURE;
            }
            println!(
                "pkc plan: wrote {} and the README interop table",
                plan::PLAN_FILE
            );
        }
    }
    if has(args, "--matrix") || has(args, "--github-output") {
        // `--only a,b`: the SDKs whose paths changed (the workflow's
        // `changes` job); `all` or absent keeps every shard.
        let only = sdk_list(
            &flag_values(args, "--only")
                .iter()
                .flat_map(|v| ["--sdk".to_string(), v.clone()])
                .collect::<Vec<_>>(),
        );
        let mut p = p;
        if !only.is_empty() && !flag_values(args, "--only").iter().any(|v| v == "all") {
            p.shards.retain(|s| only.contains(&s.id));
        }
        let matrix = p.matrix().to_string();
        if has(args, "--github-output") {
            let Ok(path) = std::env::var("GITHUB_OUTPUT") else {
                eprintln!("--github-output needs GITHUB_OUTPUT");
                return ExitCode::FAILURE;
            };
            use std::io::Write as _;
            let any = !p.shards.is_empty();
            if let Err(e) = std::fs::OpenOptions::new()
                .append(true)
                .create(true)
                .open(path)
                .and_then(|mut f| {
                    writeln!(
                        f,
                        "matrix={matrix}
any={any}"
                    )
                })
            {
                eprintln!("{e}");
                return ExitCode::FAILURE;
            }
        }
        println!("{matrix}");
    } else if !has(args, "--write") && !has(args, "--check") {
        for s in &p.shards {
            println!(
                "{} ({} interop cases, {}, toolchains {})",
                s.id,
                s.case_count,
                s.runner,
                s.toolchains.join(",")
            );
        }
        println!("{} claimed interop cases", p.cases.len());
    }
    ExitCode::SUCCESS
}

fn adapters_cmd(root: &Path, args: &[String]) -> ExitCode {
    use paykit_conformance::interop::{adapters, cases, plan};
    if args.first().map(String::as_str) != Some("build") {
        eprintln!("pkc adapters build (--shard <id> | --sdk <lang>[,..]) --out <dir>");
        return ExitCode::from(2);
    }
    let Some(out) = flag_values(args, "--out").pop() else {
        eprintln!("pkc adapters build: --out <dir> is required");
        return ExitCode::from(2);
    };
    let exps =
        match paykit_conformance::run::expectations::load_all(&root.join("harness/expectations")) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("{e}");
                return ExitCode::FAILURE;
            }
        };
    let claimed = match cases::claimed(&exps) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    let selected: Vec<cases::Case> = if let Some(shard) = flag_values(args, "--shard").pop() {
        let p = match plan::plan(&exps) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("{e}");
                return ExitCode::FAILURE;
            }
        };
        let Some(s) = p.find(&shard) else {
            eprintln!("no interop shard {shard:?}");
            return ExitCode::FAILURE;
        };
        claimed
            .into_iter()
            .filter(|c| s.cases.contains(&c.key()))
            .collect()
    } else {
        let sdks = sdk_list(args);
        claimed
            .into_iter()
            .filter(|c| {
                sdks.is_empty() || c.languages().iter().all(|l| sdks.iter().any(|s| s == l))
            })
            .collect()
    };
    let targets = adapters::native_targets(selected.iter().flat_map(|c| [c.client, c.server]));
    match adapters::build(root, &targets, Path::new(&out), true) {
        Ok(()) => {
            println!(
                "pkc adapters: built {} native target(s) into {out}",
                targets.len()
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("pkc adapters build: {e}");
            ExitCode::FAILURE
        }
    }
}

fn req_lint_cmd(root: &std::path::Path, args: &[String]) -> ExitCode {
    if let Some(repo) = flag_value(args, "--list") {
        let repo = match repo.as_str() {
            "mpp" => SpecRepo::MppSpecs,
            "x402" => SpecRepo::X402,
            "mpp-solana" => SpecRepo::MppSpecsSolana,
            "mpp-txv1" => SpecRepo::MppSpecsTxV1,
            "x402-txv1" => SpecRepo::X402TxV1,
            _ => return usage(),
        };
        return match reqlint::list(root, repo) {
            Ok(sentences) => {
                for s in sentences {
                    println!("{}\t{}\t{}", s.id, s.doc, s.text);
                }
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("{e}");
                ExitCode::FAILURE
            }
        };
    }
    match reqlint::lint(root) {
        Ok(report) => {
            for line in &report.lines {
                println!("{line}");
            }
            if report.failures.is_empty() {
                println!("req-lint: ok");
                ExitCode::SUCCESS
            } else {
                for failure in &report.failures {
                    eprintln!("FAIL {failure}");
                }
                eprintln!("req-lint: {} failures", report.failures.len());
                ExitCode::FAILURE
            }
        }
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

fn report_cmd(root: &Path, args: &[String]) -> ExitCode {
    let unmapped =
        has(args, "--unmapped").then(|| flag_value(args, "--unmapped").unwrap_or_default());
    match report::command(root, has(args, "--check"), unmapped.as_deref()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("pkc report: {e}");
            ExitCode::FAILURE
        }
    }
}
