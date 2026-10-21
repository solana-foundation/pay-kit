//! The process adapter contract (harness/README.md "Process adapter
//! contract"), driven exactly as `harness/src/process.ts` did: environment
//! in, newline JSON out (`ready` for servers, one `result` for clients),
//! diagnostics on stderr, a timeout on every wait, the stderr tail attached
//! to every failure, and the reported `implementation` checked against the
//! registry so an adapter wired to the wrong binary cannot pass.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::Value;

use super::adapters::{self, Adapter};

const STDERR_TAIL_BYTES: usize = 4096;

#[derive(Clone, Default)]
struct Tail(Arc<Mutex<String>>);

impl Tail {
    fn push(&self, text: &str) {
        let mut buf = self.0.lock().expect("stderr tail");
        buf.push_str(text);
        if buf.len() > STDERR_TAIL_BYTES * 4 {
            let cut = buf.len() - STDERR_TAIL_BYTES;
            let cut = (cut..buf.len())
                .find(|i| buf.is_char_boundary(*i))
                .unwrap_or(cut);
            buf.drain(..cut);
        }
    }

    fn snapshot(&self) -> String {
        let buf = self.0.lock().expect("stderr tail");
        let start = buf.len().saturating_sub(STDERR_TAIL_BYTES);
        let start = (start..buf.len())
            .find(|i| buf.is_char_boundary(*i))
            .unwrap_or(start);
        buf[start..].to_string()
    }
}

fn drain<R: Read + Send + 'static>(stream: R, tail: Tail) {
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stream);
        let mut line = Vec::new();
        loop {
            line.clear();
            match reader.read_until(b'\n', &mut line) {
                Ok(0) | Err(_) => return,
                Ok(_) => tail.push(&String::from_utf8_lossy(&line)),
            }
        }
    });
}

/// A running adapter process (own process group, killed on drop).
pub struct Running {
    adapter: &'static Adapter,
    child: Child,
    lines: Receiver<String>,
    stderr: Tail,
}

/// Everything an adapter failure report needs.
#[derive(Debug, Clone)]
pub struct AdapterError {
    pub message: String,
    pub stderr: String,
    /// The client adapter exited non-zero, before or after its result: the
    /// SDK refused (threw). Timeouts, signals, unparsable output and spawn
    /// failures are not refusals.
    pub refused: bool,
}

impl std::fmt::Display for AdapterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)?;
        if !self.stderr.trim().is_empty() {
            write!(f, "\nlast stderr:\n{}", self.stderr.trim_end())?;
        }
        Ok(())
    }
}

pub struct Launcher<'a> {
    pub harness: &'a Path,
    pub prebuilt: &'a Path,
    pub timeout: Duration,
}

impl Launcher<'_> {
    fn spawn(
        &self,
        adapter: &'static Adapter,
        env: &BTreeMap<String, String>,
    ) -> Result<Running, AdapterError> {
        let (argv, cwd) =
            adapters::command(adapter, self.harness, self.prebuilt).map_err(|e| AdapterError {
                message: e,
                stderr: String::new(),
                refused: false,
            })?;
        let (bin, args) = argv.split_first().expect("non-empty argv");
        let mut cmd = Command::new(bin);
        cmd.args(args)
            .current_dir(cwd)
            .envs(env)
            // pnpm 11 would otherwise print install banners into the
            // adapters' JSON stdout.
            .env("pnpm_config_verify_deps_before_run", "false")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // Own process group, so `uv run python`, `bundle exec ruby` and
        // `pnpm exec node` die with their children.
        std::os::unix::process::CommandExt::process_group(&mut cmd, 0);
        let mut child = cmd.spawn().map_err(|e| AdapterError {
            message: format!(
                "failed to start {} {} adapter {}: {e}",
                adapter.intent, adapter.role, adapter.id
            ),
            stderr: String::new(),
            refused: false,
        })?;
        let stderr = Tail::default();
        drain(child.stderr.take().expect("stderr"), stderr.clone());
        let stdout = child.stdout.take().expect("stdout");
        let (tx, lines) = channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { return };
                if tx.send(line).is_err() {
                    return;
                }
            }
        });
        Ok(Running {
            adapter,
            child,
            lines,
            stderr,
        })
    }

    /// Start a server adapter and wait for its `ready` message.
    pub fn start_server(
        &self,
        adapter: &'static Adapter,
        env: &BTreeMap<String, String>,
    ) -> Result<(Running, u16), AdapterError> {
        let mut running = self.spawn(adapter, env)?;
        let msg = running.next_message(self.timeout)?;
        // `process.ts` interpolated the port into a URL, so a numeric string
        // (the Lua adapter's) was accepted; keep accepting it.
        let port = msg["port"]
            .as_u64()
            .or_else(|| msg["port"].as_str().and_then(|p| p.parse().ok()))
            .filter(|p| *p > 0 && *p <= u16::MAX as u64);
        match (msg["type"].as_str(), msg["role"].as_str(), port) {
            (Some("ready"), Some("server"), Some(port)) => Ok((running, port as u16)),
            _ => Err(running.fail(format!(
                "unexpected server readiness payload from {}: {msg}",
                adapter.id
            ))),
        }
    }

    /// Run a client adapter against `target` and return its `result`.
    pub fn run_client(
        &self,
        adapter: &'static Adapter,
        target: &str,
        env: &BTreeMap<String, String>,
    ) -> Result<ClientResult, AdapterError> {
        let mut env = env.clone();
        // Both namespaces, so an MPP and an x402 client each find theirs.
        env.insert("MPP_HARNESS_TARGET_URL".into(), target.into());
        env.insert("X402_HARNESS_TARGET_URL".into(), target.into());
        let mut running = self.spawn(adapter, &env)?;
        let msg = running.next_message(self.timeout)?;
        if msg["type"] != "result" || msg["role"] != "client" {
            return Err(running.fail(format!(
                "unexpected client result payload from {}: {msg}",
                adapter.id
            )));
        }
        let status = running.wait(Duration::from_secs(30));
        let stderr = running.stderr.snapshot();
        match status {
            Some(0) => {}
            Some(code) => {
                return Err(AdapterError {
                    message: format!(
                        "client adapter {} exited with code {code} after its result",
                        adapter.id
                    ),
                    stderr,
                    refused: code > 0,
                })
            }
            None => {
                return Err(AdapterError {
                    message: format!(
                        "client adapter {} did not exit within 30s of its result",
                        adapter.id
                    ),
                    stderr,
                    refused: false,
                })
            }
        }
        Ok(ClientResult::from_message(msg, stderr))
    }
}

/// A client adapter's `result`, header keys lower-cased at the boundary.
#[derive(Debug, Clone)]
pub struct ClientResult {
    pub ok: bool,
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: Value,
    pub settlement: Option<String>,
    pub raw: Value,
    pub stderr: String,
}

impl ClientResult {
    fn from_message(msg: Value, stderr: String) -> Self {
        let headers = msg["responseHeaders"]
            .as_object()
            .map(|h| {
                h.iter()
                    .map(|(k, v)| {
                        (
                            k.to_ascii_lowercase(),
                            v.as_str()
                                .map(str::to_string)
                                .unwrap_or_else(|| v.to_string()),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        Self {
            ok: msg["ok"].as_bool().unwrap_or(false),
            status: msg["status"].as_u64().unwrap_or(0) as u16,
            headers,
            body: msg["responseBody"].clone(),
            settlement: msg["settlement"]
                .as_str()
                .filter(|s| !s.is_empty())
                .map(str::to_string),
            raw: msg,
            stderr,
        }
    }

    /// The canonical code in the body, if any.
    pub fn code(&self) -> Option<&str> {
        self.body["code"].as_str()
    }
}

impl Running {
    fn fail(&mut self, message: String) -> AdapterError {
        self.fail_with(false, message)
    }

    fn fail_with(&mut self, refused: bool, message: String) -> AdapterError {
        self.kill();
        AdapterError {
            message,
            stderr: self.stderr.snapshot(),
            refused,
        }
    }

    /// The next stdout message, which must be JSON naming this adapter.
    fn next_message(&mut self, timeout: Duration) -> Result<Value, AdapterError> {
        let deadline = Instant::now() + timeout;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.lines.recv_timeout(left) {
                Ok(line) if line.trim().is_empty() => continue,
                Ok(line) => {
                    let msg: Value = serde_json::from_str(&line).map_err(|e| {
                        self.fail(format!(
                            "failed to parse adapter {} output as JSON ({e}): {line}",
                            self.adapter.id
                        ))
                    })?;
                    if let Some(reported) = msg["implementation"].as_str() {
                        if reported != self.adapter.reports_as {
                            return Err(self.fail(format!(
                                "adapter identity mismatch: {} {} adapter {} reported implementation=\"{reported}\" but the registry expects \"{}\"; it is wired to the wrong binary",
                                self.adapter.intent, self.adapter.role, self.adapter.id, self.adapter.reports_as
                            )));
                        }
                    }
                    return Ok(msg);
                }
                Err(RecvTimeoutError::Timeout) => {
                    return Err(self.fail(format!(
                        "timed out waiting for adapter {} output after {:.0}s",
                        self.adapter.id,
                        timeout.as_secs_f64()
                    )))
                }
                Err(RecvTimeoutError::Disconnected) => {
                    let code = self.wait(Duration::from_secs(5));
                    let refused = matches!(code, Some(c) if c > 0);
                    return Err(self.fail_with(
                        refused,
                        format!(
                            "adapter {} exited with code {} before {}",
                            self.adapter.id,
                            code.map(|c| c.to_string()).unwrap_or_else(|| "?".into()),
                            match self.adapter.role {
                                super::claims::Role::Server => "readiness",
                                super::claims::Role::Client => "its result",
                            }
                        ),
                    ));
                }
            }
        }
    }

    fn wait(&mut self, timeout: Duration) -> Option<i32> {
        let deadline = Instant::now() + timeout;
        loop {
            match self.child.try_wait() {
                Ok(Some(status)) => return Some(status.code().unwrap_or(-1)),
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(50))
                }
                _ => return None,
            }
        }
    }

    pub fn stderr(&self) -> String {
        self.stderr.snapshot()
    }

    /// SIGTERM the process group, SIGKILL after 5 s.
    pub fn stop(&mut self) {
        if matches!(self.child.try_wait(), Ok(Some(_))) {
            return;
        }
        let pgid = format!("-{}", self.child.id());
        let _ = Command::new("kill")
            .args(["-TERM", &pgid])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        if self.wait(Duration::from_secs(5)).is_none() {
            self.kill();
        }
    }

    fn kill(&mut self) {
        let pgid = format!("-{}", self.child.id());
        let _ = Command::new("kill")
            .args(["-KILL", &pgid])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.stop();
        // Children of the group outlive a TERM-ignoring parent otherwise.
        let pgid = format!("-{}", self.child.id());
        let _ = Command::new("kill")
            .args(["-KILL", &pgid])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

#[cfg(test)]
mod tests {
    use super::super::adapters::Launch;
    use super::super::claims::{Intent, Role};
    use super::*;

    const fn fake(role: Role, script: &'static [&'static str]) -> Adapter {
        Adapter {
            id: "fake",
            language: "rust",
            role,
            intent: Intent::Charge,
            reports_as: "fake",
            launch: Launch::Source(script),
        }
    }

    static READY: Adapter = fake(
        Role::Server,
        &["sh", "-c", "echo '{\"type\":\"ready\",\"implementation\":\"fake\",\"role\":\"server\",\"port\":4242}'; sleep 30"],
    );
    static IMPOSTOR: Adapter = fake(
        Role::Server,
        &["sh", "-c", "echo '{\"type\":\"ready\",\"implementation\":\"typescript\",\"role\":\"server\",\"port\":4242}'; sleep 30"],
    );
    static NOISY: Adapter = fake(
        Role::Server,
        &["sh", "-c", "echo 'Listening on 4242'; sleep 30"],
    );
    static DIES: Adapter = fake(Role::Server, &["sh", "-c", "echo boom >&2; exit 3"]);
    static CLIENT: Adapter = fake(
        Role::Client,
        &["sh", "-c", "echo \"{\\\"type\\\":\\\"result\\\",\\\"implementation\\\":\\\"fake\\\",\\\"role\\\":\\\"client\\\",\\\"ok\\\":true,\\\"status\\\":200,\\\"responseHeaders\\\":{\\\"X-Fixture-Settlement\\\":\\\"sig\\\"},\\\"responseBody\\\":{\\\"ok\\\":true},\\\"settlement\\\":\\\"$MPP_HARNESS_TARGET_URL\\\"}\""],
    );
    static SILENT: Adapter = fake(Role::Server, &["sh", "-c", "sleep 30"]);
    static REFUSES: Adapter = fake(
        Role::Client,
        &["sh", "-c", "echo 'challenge rejected' >&2; exit 1"],
    );
    static HANGS: Adapter = fake(Role::Client, &["sh", "-c", "sleep 30"]);

    fn launcher(timeout: Duration) -> Launcher<'static> {
        let harness: &'static Path = Box::leak(std::env::temp_dir().into_boxed_path());
        Launcher {
            harness,
            prebuilt: harness,
            timeout,
        }
    }

    #[test]
    fn a_server_reports_ready_with_its_port_positive_control() {
        let (mut running, port) = launcher(Duration::from_secs(10))
            .start_server(&READY, &BTreeMap::new())
            .unwrap();
        assert_eq!(port, 4242);
        running.stop();
    }

    #[test]
    fn an_adapter_reporting_another_implementation_fails() {
        let err = launcher(Duration::from_secs(10))
            .start_server(&IMPOSTOR, &BTreeMap::new())
            .err()
            .unwrap();
        assert!(err.message.contains("identity mismatch"), "{err}");
    }

    #[test]
    fn non_json_stdout_fails() {
        let err = launcher(Duration::from_secs(10))
            .start_server(&NOISY, &BTreeMap::new())
            .err()
            .unwrap();
        assert!(err.message.contains("as JSON"), "{err}");
    }

    #[test]
    fn exiting_before_readiness_fails_with_the_stderr_tail() {
        let err = launcher(Duration::from_secs(10))
            .start_server(&DIES, &BTreeMap::new())
            .err()
            .unwrap();
        assert!(err.message.contains("before readiness"), "{err}");
        std::thread::sleep(Duration::from_millis(100));
        assert!(
            err.stderr.contains("boom") || err.to_string().contains("exited"),
            "{err}"
        );
    }

    #[test]
    fn a_silent_adapter_times_out() {
        let started = Instant::now();
        let err = launcher(Duration::from_millis(300))
            .start_server(&SILENT, &BTreeMap::new())
            .err()
            .unwrap();
        assert!(err.message.contains("timed out"), "{err}");
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn a_client_gets_the_target_and_headers_are_lower_cased() {
        let r = launcher(Duration::from_secs(10))
            .run_client(&CLIENT, "http://127.0.0.1:1/protected", &BTreeMap::new())
            .unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(
            r.settlement.as_deref(),
            Some("http://127.0.0.1:1/protected")
        );
        assert_eq!(r.headers["x-fixture-settlement"], "sig");
    }

    // Client fault cases accept a refusal (non-zero exit before a result)
    // but not a hang: a stuck client did not refuse the tampered challenge.
    #[test]
    fn a_client_that_exits_non_zero_refused_one_that_hangs_did_not() {
        let err = launcher(Duration::from_secs(10))
            .run_client(&REFUSES, "http://127.0.0.1:1/", &BTreeMap::new())
            .err()
            .unwrap();
        assert!(err.refused, "{err}");
        let err = launcher(Duration::from_millis(300))
            .run_client(&HANGS, "http://127.0.0.1:1/", &BTreeMap::new())
            .err()
            .unwrap();
        assert!(!err.refused && err.message.contains("timed out"), "{err}");
    }
}
