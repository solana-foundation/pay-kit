//! The interop testees: the per-language process adapters under `harness/`
//! (README "Process adapter contract"), unchanged, plus how to build and
//! launch each one. This is the Rust port of `harness/src/implementations.ts`
//! and the payment-adapter half of `harness/src/artifacts.ts`.
//!
//! Native adapters (Rust, Go, Swift, Kotlin) are compiled once per run into a
//! prebuilt directory ([`build`]) and launched from there, so no compiler
//! runs inside a case timeout. Interpreted adapters (TypeScript, Python,
//! Ruby, Lua, PHP) run from source with their language runtime.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::claims::{Claim, Intent, Role};

/// The toolchains CI sets up per shard (`.github/workflows/harness-interop*.yml`).
pub const TOOLCHAINS: [&str; 9] = [
    "typescript",
    "rust",
    "go",
    "swift",
    "kotlin",
    "python",
    "ruby",
    "lua",
    "php",
];

/// A compiled adapter: one build target, possibly shared by several
/// adapters (the Go client binary serves every intent).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Native {
    /// Directory under the prebuilt root, `<toolchain>-<role>-<first id>`
    /// (the layout `build-adapters.ts` used, so existing artifacts resolve).
    pub key: &'static str,
    pub toolchain: &'static str,
    /// Source directory relative to `harness/` (`../rust` for the harness bins).
    pub directory: &'static str,
    /// Cargo bin, Go output, SwiftPM product or Gradle distribution name.
    pub product: &'static str,
}

impl Native {
    /// Executable path relative to the prebuilt root.
    pub fn executable(&self) -> String {
        if self.toolchain == "kotlin" {
            format!("{}/bin/{}", self.key, self.product)
        } else {
            format!("{}/{}", self.key, self.product)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Launch {
    Native(Native),
    /// Run from source; argv relative to `harness/`.
    Source(&'static [&'static str]),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Adapter {
    /// The name in case keys (`interop/<scenario>/<client>/<server>`).
    pub id: &'static str,
    /// The SDK whose `harness/expectations/<language>.toml` claims it.
    pub language: &'static str,
    pub role: Role,
    pub intent: Intent,
    /// The `implementation` the adapter must report in its ready/result
    /// JSON; a mismatch means it is wired to the wrong binary.
    pub reports_as: &'static str,
    pub launch: Launch,
}

impl Adapter {
    pub fn claim(&self) -> Claim {
        Claim::new(self.intent, self.role)
    }

    pub fn toolchain(&self) -> &'static str {
        match self.launch {
            Launch::Native(n) => n.toolchain,
            Launch::Source(_) => self.language,
        }
    }
}

const fn native(
    key: &'static str,
    toolchain: &'static str,
    directory: &'static str,
    product: &'static str,
) -> Native {
    Native {
        key,
        toolchain,
        directory,
        product,
    }
}

const RUST_MPP_CLIENT: Native = native("rust-client-rust", "rust", "../rust", "mpp_harness_client");
const RUST_MPP_SERVER: Native = native("rust-server-rust", "rust", "../rust", "mpp_harness_server");
const RUST_X402_CLIENT: Native = native(
    "rust-client-rust-x402",
    "rust",
    "../rust",
    "x402_harness_client",
);
const RUST_X402_SERVER: Native = native(
    "rust-server-rust-x402",
    "rust",
    "../rust",
    "x402_harness_server",
);
const RUST_UPTO_CLIENT: Native = native(
    "rust-client-rust-x402-upto",
    "rust",
    "../rust",
    "x402_harness_upto_client",
);
const RUST_UPTO_SERVER: Native = native(
    "rust-server-rust-x402-upto",
    "rust",
    "../rust",
    "x402_harness_upto_server",
);
const GO_CLIENT: Native = native("go-client-go", "go", "go-client", "paykit-client");
const GO_SERVER: Native = native("go-server-go", "go", "go-server", "paykit-server");
const SWIFT_CLIENT: Native = native(
    "swift-client-swift",
    "swift",
    "swift-client",
    "SwiftHarnessClient",
);
const SWIFT_X402_CLIENT: Native = native(
    "swift-client-swift-x402",
    "swift",
    "swift-x402-client",
    "SwiftX402Client",
);
const SWIFT_UPTO_CLIENT: Native = native(
    "swift-client-swift-x402-upto",
    "swift",
    "swift-x402-upto-client",
    "SwiftX402UptoClient",
);
const KOTLIN_CLIENT: Native = native(
    "kotlin-client-kotlin",
    "kotlin",
    "kotlin-client",
    "mpp-kotlin-harness-client",
);
const KOTLIN_X402_CLIENT: Native = native(
    "kotlin-client-kotlin-x402",
    "kotlin",
    "kotlin-x402-client",
    "mpp-kotlin-x402-harness-client",
);
const KOTLIN_UPTO_CLIENT: Native = native(
    "kotlin-client-kotlin-x402-upto",
    "kotlin",
    "kotlin-x402-upto-client",
    "mpp-kotlin-x402-upto-harness-client",
);

const TS_CHARGE_CLIENT: &[&str] = &[
    "pnpm",
    "exec",
    "node",
    "--import",
    "tsx",
    "src/fixtures/typescript/charge-client.ts",
];
const TS_CHARGE_SERVER: &[&str] = &[
    "pnpm",
    "exec",
    "node",
    "--import",
    "tsx",
    "src/fixtures/typescript/charge-server.ts",
];
const TS_EXACT_CLIENT: &[&str] = &[
    "pnpm",
    "exec",
    "node",
    "--import",
    "tsx",
    "src/fixtures/typescript/exact-client.ts",
];
const TS_EXACT_SERVER: &[&str] = &[
    "pnpm",
    "exec",
    "node",
    "--import",
    "tsx",
    "src/fixtures/typescript/exact-server.ts",
];
const PY_SERVER: &[&str] = &[
    "uv",
    "run",
    "--project",
    "../python",
    "python",
    "python-server/server.py",
];
const PY_X402_CLIENT: &[&str] = &[
    "uv",
    "run",
    "--project",
    "../python",
    "python",
    "python-x402-client/main.py",
];
const PY_UPTO_CLIENT: &[&str] = &[
    "uv",
    "run",
    "--project",
    "../python",
    "python",
    "python-x402-upto-client/main.py",
];
const PY_SESSION_CLIENT: &[&str] = &[
    "uv",
    "run",
    "--project",
    "../python",
    "python",
    "python-session-client/main.py",
];
const RUBY_SERVER: &[&str] = &[
    "sh",
    "-c",
    "cd ../ruby && bundle exec ruby ../harness/ruby-server/server.rb",
];
const RUBY_X402_SERVER: &[&str] = &[
    "sh",
    "-c",
    "cd ../ruby && bundle exec ruby ../harness/ruby-x402-server/server.rb",
];
const LUA_SERVER: &[&str] = &[
    "sh",
    "-c",
    "cd ../lua && eval \"$(luarocks --lua-version=5.1 --tree lua_modules path)\" && luajit ../harness/lua-server/server.lua",
];
const PHP_SERVER: &[&str] = &["php", "php-server/server.php"];

const fn a(
    id: &'static str,
    language: &'static str,
    role: Role,
    intent: Intent,
    reports_as: &'static str,
    launch: Launch,
) -> Adapter {
    Adapter {
        id,
        language,
        role,
        intent,
        reports_as,
        launch,
    }
}

use Intent::{Charge, Session, X402Exact, X402Upto};
use Launch::{Native as N, Source as S};
use Role::{Client as C, Server as Sv};

/// Every interop adapter. Ids are unique per (intent, role).
pub const ADAPTERS: &[Adapter] = &[
    // MPP charge clients.
    a(
        "typescript",
        "typescript",
        C,
        Charge,
        "typescript",
        S(TS_CHARGE_CLIENT),
    ),
    a("rust", "rust", C, Charge, "rust", N(RUST_MPP_CLIENT)),
    a("go", "go", C, Charge, "go", N(GO_CLIENT)),
    a("swift", "swift", C, Charge, "swift", N(SWIFT_CLIENT)),
    a("kotlin", "kotlin", C, Charge, "kotlin", N(KOTLIN_CLIENT)),
    // MPP charge servers.
    a(
        "typescript",
        "typescript",
        Sv,
        Charge,
        "typescript",
        S(TS_CHARGE_SERVER),
    ),
    a("rust", "rust", Sv, Charge, "rust", N(RUST_MPP_SERVER)),
    a("go", "go", Sv, Charge, "go-paykit", N(GO_SERVER)),
    a("python", "python", Sv, Charge, "python", S(PY_SERVER)),
    a("ruby", "ruby", Sv, Charge, "ruby", S(RUBY_SERVER)),
    a("lua", "lua", Sv, Charge, "lua", S(LUA_SERVER)),
    a("php", "php", Sv, Charge, "php", S(PHP_SERVER)),
    // x402 exact clients.
    a(
        "typescript",
        "typescript",
        C,
        X402Exact,
        "typescript",
        S(TS_EXACT_CLIENT),
    ),
    a("rust", "rust", C, X402Exact, "rust", N(RUST_X402_CLIENT)),
    a("go", "go", C, X402Exact, "go", N(GO_CLIENT)),
    a(
        "python",
        "python",
        C,
        X402Exact,
        "python",
        S(PY_X402_CLIENT),
    ),
    a(
        "swift",
        "swift",
        C,
        X402Exact,
        "swift-x402",
        N(SWIFT_X402_CLIENT),
    ),
    a(
        "kotlin",
        "kotlin",
        C,
        X402Exact,
        "kotlin-x402",
        N(KOTLIN_X402_CLIENT),
    ),
    // x402 exact servers.
    a(
        "typescript",
        "typescript",
        Sv,
        X402Exact,
        "typescript",
        S(TS_EXACT_SERVER),
    ),
    a("rust", "rust", Sv, X402Exact, "rust", N(RUST_X402_SERVER)),
    a("go", "go", Sv, X402Exact, "go-paykit", N(GO_SERVER)),
    a("python", "python", Sv, X402Exact, "python", S(PY_SERVER)),
    a("ruby", "ruby", Sv, X402Exact, "ruby", S(RUBY_SERVER)),
    a(
        "ruby-x402-server",
        "ruby",
        Sv,
        X402Exact,
        "ruby",
        S(RUBY_X402_SERVER),
    ),
    a("lua", "lua", Sv, X402Exact, "lua", S(LUA_SERVER)),
    a("php", "php", Sv, X402Exact, "php", S(PHP_SERVER)),
    // x402 upto clients.
    a("rust", "rust", C, X402Upto, "rust", N(RUST_UPTO_CLIENT)),
    a("go", "go", C, X402Upto, "go", N(GO_CLIENT)),
    a("python", "python", C, X402Upto, "python", S(PY_UPTO_CLIENT)),
    a("swift", "swift", C, X402Upto, "swift", N(SWIFT_UPTO_CLIENT)),
    a(
        "kotlin",
        "kotlin",
        C,
        X402Upto,
        "kotlin",
        N(KOTLIN_UPTO_CLIENT),
    ),
    // x402 upto servers.
    a("rust", "rust", Sv, X402Upto, "rust", N(RUST_UPTO_SERVER)),
    a("go", "go", Sv, X402Upto, "go-paykit", N(GO_SERVER)),
    a("python", "python", Sv, X402Upto, "python", S(PY_SERVER)),
    // MPP session.
    a(
        "python",
        "python",
        C,
        Session,
        "python-session",
        S(PY_SESSION_CLIENT),
    ),
    a("python", "python", Sv, Session, "python", S(PY_SERVER)),
];

/// The adapters of one (intent, role), in registry order.
pub fn of(intent: Intent, role: Role) -> impl Iterator<Item = &'static Adapter> {
    ADAPTERS
        .iter()
        .filter(move |a| a.intent == intent && a.role == role)
}

pub fn find(intent: Intent, role: Role, id: &str) -> Option<&'static Adapter> {
    of(intent, role).find(|a| a.id == id)
}

/// Every language that ships an adapter.
pub fn languages() -> BTreeSet<&'static str> {
    ADAPTERS.iter().map(|a| a.language).collect()
}

/// Distinct native build targets of a set of adapters.
pub fn native_targets<'a>(adapters: impl IntoIterator<Item = &'a Adapter>) -> Vec<Native> {
    let mut out: Vec<Native> = Vec::new();
    for adapter in adapters {
        if let Launch::Native(n) = adapter.launch {
            if !out.iter().any(|t| t.key == n.key) {
                out.push(n);
            }
        }
    }
    out.sort_by_key(|n| n.key);
    out
}

/// argv and cwd to launch `adapter`: a prebuilt executable for native
/// adapters (missing one is an error, never a compiler fallback), the
/// source command for interpreted ones.
pub fn command(
    adapter: &Adapter,
    harness: &Path,
    prebuilt: &Path,
) -> Result<(Vec<String>, PathBuf), String> {
    match adapter.launch {
        Launch::Source(argv) => Ok((
            argv.iter().map(|s| s.to_string()).collect(),
            harness.to_path_buf(),
        )),
        Launch::Native(n) => {
            let exe = prebuilt.join(n.executable());
            if !exe.is_file() {
                return Err(format!(
                    "missing prebuilt {} {} adapter {}: {} (build it with `pkc adapters build`)",
                    adapter.intent,
                    adapter.role,
                    adapter.id,
                    exe.display()
                ));
            }
            Ok((
                vec![exe.to_string_lossy().to_string()],
                harness.to_path_buf(),
            ))
        }
    }
}

fn run(cmd: &mut Command, what: &str) -> Result<String, String> {
    eprintln!("pkc adapters: {what}");
    let out = cmd
        .stderr(std::process::Stdio::inherit())
        .output()
        .map_err(|e| format!("{what}: {e}"))?;
    if !out.status.success() {
        return Err(format!("{what} failed ({})", out.status));
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

fn copy_dir(from: &Path, to: &Path) -> Result<(), String> {
    std::fs::create_dir_all(to).map_err(|e| format!("{}: {e}", to.display()))?;
    for entry in std::fs::read_dir(from).map_err(|e| format!("{}: {e}", from.display()))? {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        let dest = to.join(entry.file_name());
        // Follow symlinks: SwiftPM bundles and Gradle libs must be real files
        // once relocated.
        if std::fs::metadata(&path)
            .map(|m| m.is_dir())
            .unwrap_or(false)
        {
            copy_dir(&path, &dest)?;
        } else {
            std::fs::copy(&path, &dest)
                .map_err(|e| format!("{} -> {}: {e}", path.display(), dest.display()))?;
        }
    }
    Ok(())
}

/// Compile each distinct native target once into `out` (the layout
/// [`command`] resolves). Targets whose executable already exists are kept
/// unless `force`.
pub fn build(root: &Path, targets: &[Native], out: &Path, force: bool) -> Result<(), String> {
    let harness = root.join("harness");
    std::fs::create_dir_all(out).map_err(|e| format!("{}: {e}", out.display()))?;
    let todo: Vec<&Native> = targets
        .iter()
        .filter(|t| force || !out.join(t.executable()).is_file())
        .collect();
    let rust: Vec<&&Native> = todo.iter().filter(|t| t.toolchain == "rust").collect();
    if !rust.is_empty() {
        // The workspace target directory, so the bins share the dependencies
        // `pkc` itself was built with (and the cargo cache).
        let target_dir = root.join("rust/target");
        let mut cmd = Command::new("cargo");
        cmd.current_dir(&harness).args([
            "build",
            "--manifest-path",
            "../rust/Cargo.toml",
            "-p",
            "paykit-harness-bins",
        ]);
        for t in &rust {
            cmd.args(["--bin", t.product]);
        }
        run(&mut cmd, "cargo build -p paykit-harness-bins")?;
        for t in &rust {
            let dest = out.join(t.key);
            std::fs::create_dir_all(&dest).map_err(|e| e.to_string())?;
            std::fs::copy(
                target_dir.join("debug").join(t.product),
                out.join(t.executable()),
            )
            .map_err(|e| format!("copy {}: {e}", t.product))?;
        }
    }
    for t in todo.iter().filter(|t| t.toolchain != "rust") {
        let cwd = harness.join(t.directory);
        let dest = out.join(t.key);
        std::fs::create_dir_all(&dest).map_err(|e| e.to_string())?;
        match t.toolchain {
            "go" => {
                run(
                    Command::new("go")
                        .current_dir(&cwd)
                        .args(["build", "-o"])
                        .arg(out.join(t.executable()))
                        .arg("."),
                    &format!("go build {}", t.directory),
                )?;
            }
            "swift" => {
                run(
                    Command::new("swift").current_dir(&cwd).args([
                        "build",
                        "--configuration",
                        "debug",
                        "--product",
                        t.product,
                    ]),
                    &format!("swift build {}", t.product),
                )?;
                let bin = run(
                    Command::new("swift").current_dir(&cwd).args([
                        "build",
                        "--configuration",
                        "debug",
                        "--show-bin-path",
                    ]),
                    "swift build --show-bin-path",
                )?;
                let bin = PathBuf::from(bin.trim());
                std::fs::copy(bin.join(t.product), out.join(t.executable()))
                    .map_err(|e| format!("copy {}: {e}", t.product))?;
                // SwiftPM locates resources beside the executable.
                for entry in std::fs::read_dir(&bin)
                    .map_err(|e| e.to_string())?
                    .flatten()
                {
                    let name = entry.file_name().to_string_lossy().to_string();
                    if [".bundle", ".resources", ".dylib", ".so"]
                        .iter()
                        .any(|s| name.ends_with(s))
                    {
                        let from = entry.path();
                        if from.is_dir() {
                            copy_dir(&from, &dest.join(&name))?;
                        } else {
                            std::fs::copy(&from, dest.join(&name)).map_err(|e| e.to_string())?;
                        }
                    }
                }
            }
            "kotlin" => {
                run(
                    Command::new("gradle")
                        .current_dir(&cwd)
                        .args(["--no-daemon", "installDist"]),
                    &format!("gradle installDist {}", t.directory),
                )?;
                copy_dir(&cwd.join("build/install").join(t.product), &dest)?;
            }
            other => return Err(format!("no native build for toolchain {other}")),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_unique_per_intent_and_role() {
        for intent in Intent::ALL {
            for role in [Role::Client, Role::Server] {
                let ids: Vec<&str> = of(intent, role).map(|a| a.id).collect();
                let unique: BTreeSet<&str> = ids.iter().copied().collect();
                assert_eq!(ids.len(), unique.len(), "{intent} {role}: {ids:?}");
                assert!(!ids.is_empty(), "{intent} {role} has no adapter");
            }
        }
    }

    #[test]
    fn every_adapter_language_is_a_ci_toolchain() {
        for adapter in ADAPTERS {
            assert!(
                TOOLCHAINS.contains(&adapter.language),
                "{}",
                adapter.language
            );
            assert!(TOOLCHAINS.contains(&adapter.toolchain()));
        }
    }

    #[test]
    fn every_source_adapter_and_native_directory_exists() {
        let harness = crate::repo_root().join("harness");
        for adapter in ADAPTERS {
            match adapter.launch {
                Launch::Native(n) => assert!(
                    harness.join(n.directory).is_dir(),
                    "{} {}",
                    adapter.id,
                    n.directory
                ),
                Launch::Source(argv) => {
                    // The script is the last argument (or named inside `sh -c`).
                    let script = argv
                        .iter()
                        .rev()
                        .find_map(|a| {
                            a.split_whitespace().rev().find(|w| {
                                w.ends_with(".ts")
                                    || w.ends_with(".py")
                                    || w.ends_with(".rb")
                                    || w.ends_with(".lua")
                                    || w.ends_with(".php")
                            })
                        })
                        .unwrap_or_else(|| panic!("{} names no script", adapter.id));
                    let script = script.trim_start_matches("../harness/");
                    assert!(harness.join(script).is_file(), "{} {script}", adapter.id);
                }
            }
        }
    }

    #[test]
    fn native_executables_follow_the_prebuilt_layout() {
        assert_eq!(
            KOTLIN_CLIENT.executable(),
            "kotlin-client-kotlin/bin/mpp-kotlin-harness-client"
        );
        assert_eq!(GO_SERVER.executable(), "go-server-go/paykit-server");
        let go: Vec<Native> = native_targets(
            of(Intent::X402Exact, Role::Client).chain(of(Intent::Charge, Role::Client)),
        )
        .into_iter()
        .filter(|n| n.toolchain == "go")
        .collect();
        assert_eq!(go.len(), 1, "the Go client binary is shared across intents");
    }
}
