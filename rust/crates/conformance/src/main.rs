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
//! ```

use std::path::PathBuf;
use std::process::ExitCode;

use paykit_conformance::case::SpecRepo;
use paykit_conformance::{cases, fill, realize, repo_root, reqlint};

fn usage() -> ExitCode {
    eprintln!(
        "usage: pkc fill [--check | --list | --seed N --out DIR]\n       pkc req-lint [--list mpp|x402]"
    );
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let root = repo_root();
    match args.first().map(String::as_str) {
        Some("fill") => fill_cmd(&root, &args[1..]),
        Some("req-lint") => req_lint_cmd(&root, &args[1..]),
        _ => usage(),
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

fn req_lint_cmd(root: &std::path::Path, args: &[String]) -> ExitCode {
    if let Some(repo) = flag_value(args, "--list") {
        let repo = match repo.as_str() {
            "mpp" => SpecRepo::MppSpecs,
            "x402" => SpecRepo::X402,
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
