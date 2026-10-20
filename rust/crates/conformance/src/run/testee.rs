//! The process boundary to an SDK's testee.
//!
//! **ABI v2** (`serve`): one long-lived process per SDK, newline-delimited
//! JSON on stdin/stdout.
//!
//! ```text
//! -> {"id":"7","op":"capabilities","input":{}}
//! <- {"id":"7","ok":true,"result":{"abi":2,"intents":["charge"],"honoursClock":true}}
//! -> {"id":"8","op":"verify","input":<v1 vector: id, intent, mode, description, input>}
//! <- {"id":"8","ok":true,"result":<RunnerResult>}
//! <- {"id":"9","ok":false,"error":"bad-request","detail":"..."}
//! ```
//!
//! `op` is `build`, `verify` or `canonical-bytes` (the vector's mode);
//! `result` is exactly the v1 `RunnerResult`, so a testee wraps its existing
//! one-shot handler in a read loop. `ok: false` is reserved for testee-level
//! errors (unparseable request, unknown op); an SDK reject is an `ok: true`
//! result with `outcome: "reject"`.
//!
//! **Legacy** (`command`): one process per case, the v1 vector on stdin, one
//! `RunnerResult` line on stdout. Kept as a shim so a language can migrate
//! on its own schedule; both paths produce identical results.
//!
//! Every exchange has a timeout (the process group is killed and the case
//! reported as `timeout`), and stderr is drained on its own thread and
//! attached per case, so a chatty testee can neither deadlock nor hide.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::{json, Value};

/// `harness/runners/<language>.json`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub language: String,
    /// Legacy one-shot command (one process per case).
    pub command: Vec<String>,
    /// ABI v2 long-lived command.
    #[serde(default)]
    pub serve: Option<Vec<String>>,
    /// Working directory relative to the repository root.
    #[serde(default)]
    pub cwd: Option<String>,
}

/// Prebuilt native runners (`HARNESS_PREBUILT_DIR`, laid out by
/// `harness/build-adapters.ts`): language to executable, relative to the
/// artifact directory. Mirrors `nativeTargets` role `conformance` in
/// `harness/src/artifacts.ts`.
const PREBUILT: [(&str, &str); 3] = [
    ("go", "go-conformance-go/paykit-conformance"),
    ("swift", "swift-conformance-swift/mpp-conformance"),
    (
        "kotlin",
        "kotlin-conformance-kotlin/bin/mpp-kotlin-conformance",
    ),
];

/// Languages that always run from source, even with prebuilt artifacts.
const SOURCE_RUN: [&str; 6] = ["lua", "php", "python", "ruby", "typescript", "rust"];

impl Manifest {
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let manifest: Manifest = serde_json::from_str(&text)
            .map_err(|e| format!("runner manifest {} is malformed: {e}", path.display()))?;
        if manifest.command.is_empty() || manifest.serve.as_ref().is_some_and(Vec::is_empty) {
            return Err(format!(
                "runner manifest {} has an empty command",
                path.display()
            ));
        }
        Ok(manifest)
    }

    /// Every manifest under `harness/runners/`, by language.
    pub fn discover(root: &Path) -> Result<Vec<Self>, String> {
        let dir = root.join("harness/runners");
        let mut files: Vec<_> = std::fs::read_dir(&dir)
            .map_err(|e| format!("{}: {e}", dir.display()))?
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|e| e == "json"))
            .collect();
        files.sort();
        files.iter().map(|p| Self::load(p)).collect()
    }

    pub fn cwd(&self, root: &Path) -> PathBuf {
        match &self.cwd {
            Some(cwd) => root.join(cwd),
            None => root.to_path_buf(),
        }
    }

    /// The command for `mode`, honouring prebuilt artifacts.
    pub fn resolve(&self, mode: Abi, prebuilt: Option<&Path>) -> Result<Vec<String>, String> {
        if let Some(dir) = prebuilt {
            if let Some((_, exe)) = PREBUILT.iter().find(|(l, _)| *l == self.language) {
                let exe = dir.join(exe);
                if !exe.is_file() {
                    return Err(format!(
                        "missing prebuilt conformance runner {}; rebuild with build-adapters.ts (HARNESS_PREBUILT_DIR forbids compiler fallback)",
                        exe.display()
                    ));
                }
                let exe = exe.to_string_lossy().to_string();
                return Ok(match mode {
                    Abi::Serve => vec![exe, "--serve".into()],
                    Abi::Legacy => vec![exe],
                });
            }
            if !SOURCE_RUN.contains(&self.language.as_str()) {
                return Err(format!(
                    "unclassified conformance runner {:?}: HARNESS_PREBUILT_DIR forbids compiler fallback",
                    self.language
                ));
            }
        }
        match mode {
            Abi::Legacy => Ok(self.command.clone()),
            Abi::Serve => self.serve.clone().ok_or_else(|| {
                format!(
                    "harness/runners/{}.json has no `serve` command; run with --legacy",
                    self.language
                )
            }),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Abi {
    Serve,
    Legacy,
}

impl Abi {
    pub fn as_str(self) -> &'static str {
        match self {
            Abi::Serve => "serve",
            Abi::Legacy => "legacy",
        }
    }
}

/// One request/response with the testee.
#[derive(Debug, Clone)]
pub struct Exchange {
    /// The `RunnerResult` (or an error describing why there is none).
    pub result: Result<Value, String>,
    pub stderr: String,
    pub duration: Duration,
    /// The exact line sent (serve) or stdin (legacy), for the replay command.
    pub request: String,
}

type SharedLog = Arc<Mutex<String>>;

fn drain<R: Read + Send + 'static>(stream: R, log: SharedLog, prefix: &'static str) {
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stream);
        let mut line = Vec::new();
        loop {
            line.clear();
            match reader.read_until(b'\n', &mut line) {
                Ok(0) | Err(_) => return,
                Ok(_) => {
                    let mut log = log.lock().expect("stderr log");
                    log.push_str(prefix);
                    log.push_str(&String::from_utf8_lossy(&line));
                }
            }
        }
    });
}

fn spawn(argv: &[String], cwd: &Path) -> Result<Child, String> {
    let (bin, args) = argv.split_first().ok_or("empty command")?;
    Command::new(bin)
        .args(args)
        .current_dir(cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // Own process group, so a timeout kills `uv run python`, `bundle
        // exec ruby` and friends together with their children.
        .process_group(0)
        .spawn()
        .map_err(|e| format!("failed to start {}: {e}", argv.join(" ")))
}

fn kill_group(child: &mut Child) {
    let pid = child.id() as i32;
    let _ = Command::new("kill")
        .args(["-KILL", &format!("-{pid}")])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    let _ = child.kill();
    let _ = child.wait();
}

struct Serving {
    child: Child,
    stdin: ChildStdin,
    lines: Receiver<String>,
    stderr: SharedLog,
}

impl Serving {
    fn start(argv: &[String], cwd: &Path) -> Result<Self, String> {
        let mut child = spawn(argv, cwd)?;
        let stdin = child.stdin.take().ok_or("no stdin")?;
        let stdout = child.stdout.take().ok_or("no stdout")?;
        let stderr: SharedLog = Arc::default();
        drain(child.stderr.take().ok_or("no stderr")?, stderr.clone(), "");
        let (tx, lines) = channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { return };
                if tx.send(line).is_err() {
                    return;
                }
            }
        });
        Ok(Self {
            child,
            stdin,
            lines,
            stderr,
        })
    }
}

/// A started testee for one SDK.
pub struct Testee {
    pub language: String,
    pub abi: Abi,
    argv: Vec<String>,
    cwd: PathBuf,
    timeout: Duration,
    startup_timeout: Duration,
    serving: Option<Serving>,
    next_id: u64,
    /// Lines a serving testee wrote to stdout that were not responses.
    pub stray_stdout: Vec<String>,
}

impl Testee {
    pub fn new(
        manifest: &Manifest,
        root: &Path,
        abi: Abi,
        prebuilt: Option<&Path>,
        timeout: Duration,
        startup_timeout: Duration,
    ) -> Result<Self, String> {
        Ok(Self {
            language: manifest.language.clone(),
            abi,
            argv: manifest.resolve(abi, prebuilt)?,
            cwd: manifest.cwd(root),
            timeout,
            startup_timeout,
            serving: None,
            next_id: 0,
            stray_stdout: Vec::new(),
        })
    }

    pub fn command_line(&self) -> String {
        format!("(cd {} && {})", self.cwd.display(), self.argv.join(" "))
    }

    /// ABI v2 `capabilities`. Legacy testees have none.
    pub fn capabilities(&mut self) -> Result<Option<Value>, String> {
        if self.abi == Abi::Legacy {
            return Ok(None);
        }
        let exchange = self.serve_request("capabilities", json!({}), self.startup_timeout);
        exchange
            .result
            .map(Some)
            .map_err(|e| format!("{e}\nstderr:\n{}", exchange.stderr))
    }

    /// Run one vector (the v1 testee view, `rpcUrl` injected).
    pub fn run(&mut self, op: &str, vector: &Value) -> Exchange {
        match self.abi {
            Abi::Serve => {
                // The first case after a (re)start also pays the startup.
                let timeout = if self.serving.is_none() {
                    self.startup_timeout.max(self.timeout)
                } else {
                    self.timeout
                };
                self.serve_request(op, vector.clone(), timeout)
            }
            Abi::Legacy => self.legacy(vector),
        }
    }

    fn serve_request(&mut self, op: &str, input: Value, timeout: Duration) -> Exchange {
        let started = Instant::now();
        self.next_id += 1;
        let id = self.next_id.to_string();
        let request = json!({ "id": id, "op": op, "input": input }).to_string();
        if self.serving.is_none() {
            match Serving::start(&self.argv, &self.cwd) {
                Ok(s) => self.serving = Some(s),
                Err(e) => {
                    return Exchange {
                        result: Err(e),
                        stderr: String::new(),
                        duration: started.elapsed(),
                        request,
                    }
                }
            }
        }
        let serving = self.serving.as_mut().expect("started");
        let mark = serving.stderr.lock().expect("stderr").len();
        let stderr_since = |s: &Serving| -> String {
            let log = s.stderr.lock().expect("stderr");
            log.get(mark..).unwrap_or_default().to_string()
        };
        if let Err(e) = writeln!(serving.stdin, "{request}").and_then(|_| serving.stdin.flush()) {
            let stderr = stderr_since(serving);
            self.restart();
            return Exchange {
                result: Err(format!("testee closed its stdin: {e}")),
                stderr,
                duration: started.elapsed(),
                request,
            };
        }
        let deadline = started + timeout;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match serving.lines.recv_timeout(left) {
                Ok(line) => {
                    let parsed: Option<Value> = serde_json::from_str(line.trim()).ok();
                    let Some(response) = parsed.filter(|v| v.get("id").is_some()) else {
                        // Chatter on stdout breaks the ABI for line-oriented
                        // peers; keep it visible but keep reading.
                        self.stray_stdout.push(line.clone());
                        serving
                            .stderr
                            .lock()
                            .expect("stderr")
                            .push_str(&format!("[stdout, not a response] {line}\n"));
                        continue;
                    };
                    if response["id"].as_str() != Some(id.as_str()) {
                        continue; // a late answer to a request that timed out
                    }
                    // Give stderr written just before the response a moment.
                    std::thread::sleep(Duration::from_millis(2));
                    let stderr = stderr_since(serving);
                    let result = match response.get("ok").and_then(Value::as_bool) {
                        Some(true) => response
                            .get("result")
                            .cloned()
                            .ok_or_else(|| "ABI v2 response has ok:true but no result".to_string()),
                        Some(false) => Err(format!(
                            "testee error {}: {}",
                            response["error"].as_str().unwrap_or("(no error code)"),
                            response["detail"].as_str().unwrap_or_default()
                        )),
                        None => Err(format!("ABI v2 response without a boolean `ok`: {line}")),
                    };
                    return Exchange {
                        result,
                        stderr,
                        duration: started.elapsed(),
                        request,
                    };
                }
                Err(RecvTimeoutError::Timeout) => {
                    let stderr = stderr_since(serving);
                    self.restart();
                    return Exchange {
                        result: Err(format!(
                            "timeout: no response within {:.1}s; the testee was killed and restarts for the next case",
                            timeout.as_secs_f64()
                        )),
                        stderr,
                        duration: started.elapsed(),
                        request,
                    };
                }
                Err(RecvTimeoutError::Disconnected) => {
                    std::thread::sleep(Duration::from_millis(50));
                    let stderr = stderr_since(serving);
                    let status = serving.child.try_wait().ok().flatten();
                    self.restart();
                    return Exchange {
                        result: Err(format!(
                            "testee exited ({}) before answering",
                            status
                                .map(|s| s.to_string())
                                .unwrap_or_else(|| "closed stdout".into())
                        )),
                        stderr,
                        duration: started.elapsed(),
                        request,
                    };
                }
            }
        }
    }

    fn restart(&mut self) {
        if let Some(mut serving) = self.serving.take() {
            kill_group(&mut serving.child);
        }
    }

    fn legacy(&mut self, vector: &Value) -> Exchange {
        let started = Instant::now();
        let request = vector.to_string();
        let mut child = match spawn(&self.argv, &self.cwd) {
            Ok(child) => child,
            Err(e) => {
                return Exchange {
                    result: Err(e),
                    stderr: String::new(),
                    duration: started.elapsed(),
                    request,
                }
            }
        };
        let stdout: SharedLog = Arc::default();
        let stderr: SharedLog = Arc::default();
        drain(child.stdout.take().expect("stdout"), stdout.clone(), "");
        drain(child.stderr.take().expect("stderr"), stderr.clone(), "");
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(request.as_bytes());
        }
        let timeout = self.startup_timeout.max(self.timeout);
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Some(status),
                Ok(None) if started.elapsed() > timeout => break None,
                Ok(None) => std::thread::sleep(Duration::from_millis(5)),
                Err(_) => break None,
            }
        };
        // Let the drain threads see EOF.
        std::thread::sleep(Duration::from_millis(5));
        let err_text = stderr.lock().expect("stderr").clone();
        let out_text = stdout.lock().expect("stdout").clone();
        let result = match status {
            None => {
                kill_group(&mut child);
                Err(format!(
                    "timeout: no result within {:.1}s",
                    timeout.as_secs_f64()
                ))
            }
            Some(status) if !status.success() => Err(format!(
                "runner exited with {status} for vector {}",
                vector["id"].as_str().unwrap_or_default()
            )),
            Some(_) => match out_text.lines().rfind(|l| !l.trim().is_empty()) {
                None => Err("runner produced no output".into()),
                Some(line) => serde_json::from_str(line.trim())
                    .map_err(|e| format!("failed to parse runner output: {line}\n{e}")),
            },
        };
        Exchange {
            result,
            stderr: err_text,
            duration: started.elapsed(),
            request,
        }
    }
}

impl Drop for Testee {
    fn drop(&mut self) {
        if let Some(mut serving) = self.serving.take() {
            // EOF on stdin ends a serve loop; give it a moment, then kill.
            drop(serving.stdin);
            let deadline = Instant::now() + Duration::from_millis(500);
            while Instant::now() < deadline {
                if let Ok(Some(_)) = serving.child.try_wait() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            kill_group(&mut serving.child);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sh(script: &str, serve: bool) -> Manifest {
        let argv = vec!["sh".to_string(), "-c".to_string(), script.to_string()];
        Manifest {
            language: "sh".into(),
            command: argv.clone(),
            serve: serve.then_some(argv),
            cwd: None,
        }
    }

    fn testee(m: &Manifest, abi: Abi, timeout_ms: u64) -> Testee {
        Testee::new(
            m,
            Path::new("/"),
            abi,
            None,
            Duration::from_millis(timeout_ms),
            Duration::from_millis(timeout_ms),
        )
        .unwrap()
    }

    #[test]
    fn manifests_parse_and_reject_unknown_keys() {
        let root = crate::repo_root();
        let all = Manifest::discover(&root).unwrap();
        assert!(all.iter().any(|m| m.language == "rust"));
        let bad =
            serde_json::from_str::<Manifest>(r#"{"language":"x","command":["a"],"intents":[]}"#);
        assert!(bad.is_err());
    }

    #[test]
    fn serve_round_trip_echoes_ids_and_attaches_stderr() {
        // A tiny serve loop: answer every line with ok + the id.
        let m = sh(
            r#"while IFS= read -r line; do id=$(printf '%s' "$line" | sed 's/.*"id":"\([0-9]*\)".*/\1/'); echo "note $id" >&2; echo "{\"id\":\"$id\",\"ok\":true,\"result\":{\"id\":\"v\",\"outcome\":\"accept\"}}"; done"#,
            true,
        );
        let mut t = testee(&m, Abi::Serve, 5_000);
        let caps = t.capabilities().unwrap().unwrap();
        assert_eq!(caps["outcome"], "accept");
        let ex = t.run("verify", &json!({"id": "v"}));
        assert_eq!(ex.result.unwrap()["outcome"], "accept");
        assert!(ex.stderr.contains("note 2"), "{:?}", ex.stderr);
    }

    #[test]
    fn a_hung_testee_times_out_and_restarts() {
        let m = sh("sleep 30", true);
        let mut t = testee(&m, Abi::Serve, 300);
        let started = Instant::now();
        let ex = t.run("verify", &json!({"id": "v"}));
        assert!(ex.result.unwrap_err().starts_with("timeout"));
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(t.serving.is_none(), "killed for restart");
    }

    #[test]
    fn a_crashing_testee_is_reported_with_its_stderr() {
        let m = sh("echo boom >&2; exit 3", true);
        let mut t = testee(&m, Abi::Serve, 2_000);
        let ex = t.run("verify", &json!({"id": "v"}));
        assert!(ex.result.unwrap_err().contains("exited"));
        assert!(ex.stderr.contains("boom"));
    }

    #[test]
    fn a_stderr_flood_does_not_deadlock() {
        let m = sh(
            r#"head -c 2000000 /dev/zero | tr '\0' x >&2; read -r line; echo '{"id":"1","ok":true,"result":{"id":"v","outcome":"accept"}}'"#,
            true,
        );
        let mut t = testee(&m, Abi::Serve, 10_000);
        let ex = t.run("verify", &json!({"id": "v"}));
        assert_eq!(ex.result.unwrap()["outcome"], "accept");
        assert!(ex.stderr.len() >= 2_000_000);
    }

    #[test]
    fn legacy_reads_the_last_stdout_line() {
        let m = sh(
            r#"cat >/dev/null; echo noise; echo '{"id":"v","outcome":"reject"}'"#,
            false,
        );
        let mut t = testee(&m, Abi::Legacy, 5_000);
        let ex = t.run("verify", &json!({"id": "v"}));
        assert_eq!(ex.result.unwrap()["outcome"], "reject");
    }
}
