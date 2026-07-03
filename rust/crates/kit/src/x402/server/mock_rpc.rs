//! A tiny in-process Solana JSON-RPC mock, for unit-testing the x402 settlement
//! servers (`exact` / `upto` / `batch-settlement`) end to end without a live
//! validator.
//!
//! The x402 handlers hold a concrete blocking `solana_rpc_client::RpcClient`
//! pointed at `config.rpc_url`. That URL is the only seam we need: point it at
//! this mock and the broadcast / confirm / account-fetch paths become
//! exercisable with **zero production change**.
//!
//! The blocking `RpcClient` makes synchronous HTTP calls, so we serve the mock
//! on a dedicated OS thread (a plain [`std::net::TcpListener`], no async, no new
//! dependency). The `#[tokio::test]` runtime thread can then block on a
//! `send_and_confirm_transaction` call while the mock answers it from its own
//! thread — no runtime interference, no deadlock.
//!
//! Only the four methods the settlement paths touch are implemented:
//! `getLatestBlockhash`, `sendTransaction`, `getSignatureStatuses`, and
//! `getAccountInfo`. `sendTransaction` echoes back the submitted transaction's
//! own signature (the real client rejects a mismatched signature), and
//! `getSignatureStatuses` reports an immediately-finalized status so the confirm
//! loop returns on the first poll.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use solana_transaction::versioned::VersionedTransaction;

/// A valid base58-encoded 32-byte blockhash the mock hands out.
const MOCK_BLOCKHASH: &str = "11111111111111111111111111111111";

/// How the mock answers each RPC method. Everything is behind an `Arc<Mutex<..>>`
/// so a test can tweak the canned responses after the server is running.
#[derive(Default)]
struct MockState {
    /// `getAccountInfo` → account data keyed by base58 pubkey. Missing keys
    /// return `null` (account-not-found).
    accounts: HashMap<String, MockAccount>,
    /// When set, `sendTransaction` fails with this JSON-RPC error message
    /// (drives the broadcast-error branch).
    send_error: Option<String>,
    /// When set, `getAccountInfo` fails with this JSON-RPC error message
    /// (drives the account-fetch-error branch).
    account_error: Option<String>,
    /// When set, `getLatestBlockhash` fails with this JSON-RPC error message.
    blockhash_error: Option<String>,
    /// When true, `getSignatureStatuses` reports the transaction failed
    /// on-chain (drives the confirm-failure branch).
    signature_failed: bool,
}

#[derive(Clone)]
struct MockAccount {
    /// Raw (already-borsh-serialized) account data.
    data: Vec<u8>,
    /// Base58 owner program.
    owner: String,
}

/// A handle to the running mock. The listener thread is detached and stops when
/// [`MockRpc::shutdown`] is called (or the process exits).
pub struct MockRpc {
    url: String,
    state: Arc<Mutex<MockState>>,
    running: Arc<AtomicBool>,
}

impl MockRpc {
    /// Bind an ephemeral loopback port and start serving on a background thread.
    pub fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock rpc");
        let addr = listener.local_addr().expect("mock rpc addr");
        let url = format!("http://{addr}");
        let state = Arc::new(Mutex::new(MockState::default()));
        let running = Arc::new(AtomicBool::new(true));

        let thread_state = state.clone();
        let thread_running = running.clone();
        thread::spawn(move || {
            for stream in listener.incoming() {
                if !thread_running.load(Ordering::Relaxed) {
                    break;
                }
                match stream {
                    Ok(stream) => {
                        let s = thread_state.clone();
                        // One short-lived request per connection (we answer with
                        // `Connection: close`), so no per-connection thread pool
                        // is needed — handle inline.
                        let _ = handle_connection(stream, &s);
                    }
                    Err(_) => break,
                }
            }
        });

        Self {
            url,
            state,
            running,
        }
    }

    /// The `http://127.0.0.1:<port>` URL to hand to `rpc_url`.
    pub fn url(&self) -> String {
        self.url.clone()
    }

    /// Register a canned account for `getAccountInfo` on `pubkey` (base58).
    pub fn set_account(&self, pubkey: &str, data: Vec<u8>, owner: &str) {
        self.state.lock().unwrap().accounts.insert(
            pubkey.to_string(),
            MockAccount {
                data,
                owner: owner.to_string(),
            },
        );
    }

    /// Make `sendTransaction` fail (broadcast-error branch).
    pub fn fail_send(&self, message: &str) {
        self.state.lock().unwrap().send_error = Some(message.to_string());
    }

    /// Make `getAccountInfo` fail (account-fetch-error branch).
    pub fn fail_account(&self, message: &str) {
        self.state.lock().unwrap().account_error = Some(message.to_string());
    }

    /// Make `getLatestBlockhash` fail (blockhash-fetch-error branch).
    pub fn fail_blockhash(&self, message: &str) {
        self.state.lock().unwrap().blockhash_error = Some(message.to_string());
    }

    /// Make `getSignatureStatuses` report the transaction failed on-chain
    /// (confirm-failure branch).
    pub fn fail_confirmation(&self) {
        self.state.lock().unwrap().signature_failed = true;
    }

    fn shutdown(&self) {
        self.running.store(false, Ordering::Relaxed);
        // Nudge the accept loop so it observes the flag and exits.
        let _ = TcpStream::connect(self.url.trim_start_matches("http://"));
    }
}

impl Drop for MockRpc {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn handle_connection(mut stream: TcpStream, state: &Arc<Mutex<MockState>>) -> std::io::Result<()> {
    // Read the full HTTP request (headers + Content-Length body).
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let body = loop {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            break Vec::new();
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = find_header_end(&buf) {
            let headers = &buf[..pos];
            let content_len = parse_content_length(headers).unwrap_or(0);
            let body_start = pos + 4;
            while buf.len() < body_start + content_len {
                let n = stream.read(&mut chunk)?;
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            break buf[body_start..(body_start + content_len).min(buf.len())].to_vec();
        }
    };

    let response_json = dispatch(&body, state);
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        response_json.len(),
        response_json
    );
    stream.write_all(response.as_bytes())?;
    stream.flush()?;
    Ok(())
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn parse_content_length(headers: &[u8]) -> Option<usize> {
    let text = String::from_utf8_lossy(headers);
    for line in text.lines() {
        if let Some(rest) = line
            .to_ascii_lowercase()
            .strip_prefix("content-length:")
            .map(|r| r.trim().to_string())
        {
            return rest.parse().ok();
        }
    }
    None
}

/// Build the JSON-RPC response body for a request body.
fn dispatch(body: &[u8], state: &Arc<Mutex<MockState>>) -> String {
    let req: serde_json::Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return error_response(serde_json::Value::Null, -32700, "parse error"),
    };
    let id = req.get("id").cloned().unwrap_or(serde_json::Value::Null);
    let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
    let params = req
        .get("params")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let st = state.lock().unwrap();

    match method {
        "getLatestBlockhash" => {
            if let Some(msg) = &st.blockhash_error {
                return error_response(id, -32000, msg);
            }
            result_response(
                id,
                serde_json::json!({
                    "context": {"slot": 1},
                    "value": {"blockhash": MOCK_BLOCKHASH, "lastValidBlockHeight": 1000},
                }),
            )
        }
        "sendTransaction" => {
            if let Some(msg) = &st.send_error {
                return error_response(id, -32002, msg);
            }
            // Echo the transaction's own first signature — the real client
            // rejects a signature that doesn't match what it submitted.
            match signature_of(&params) {
                Some(sig) => result_response(id, serde_json::Value::String(sig)),
                None => error_response(id, -32602, "could not decode transaction"),
            }
        }
        "getSignatureStatuses" => {
            let status = if st.signature_failed {
                serde_json::json!({
                    "slot": 1,
                    "confirmations": serde_json::Value::Null,
                    "status": {"Err": {"InstructionError": [0, "Custom"]}},
                    "err": {"InstructionError": [0, {"Custom": 6}]},
                    "confirmationStatus": "finalized",
                })
            } else {
                serde_json::json!({
                    "slot": 1,
                    "confirmations": serde_json::Value::Null,
                    "status": {"Ok": serde_json::Value::Null},
                    "err": serde_json::Value::Null,
                    "confirmationStatus": "finalized",
                })
            };
            result_response(
                id,
                serde_json::json!({"context": {"slot": 1}, "value": [status]}),
            )
        }
        "getAccountInfo" => {
            if let Some(msg) = &st.account_error {
                return error_response(id, -32000, msg);
            }
            let pubkey = params
                .get(0)
                .and_then(|p| p.as_str())
                .unwrap_or("")
                .to_string();
            match st.accounts.get(&pubkey) {
                Some(acct) => {
                    let data_b64 = base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        &acct.data,
                    );
                    result_response(
                        id,
                        serde_json::json!({
                            "context": {"slot": 1},
                            "value": {
                                "lamports": 2_039_280u64,
                                "data": [data_b64, "base64"],
                                "owner": acct.owner,
                                "executable": false,
                                "rentEpoch": 0,
                                "space": acct.data.len(),
                            },
                        }),
                    )
                }
                None => result_response(
                    id,
                    serde_json::json!({"context": {"slot": 1}, "value": serde_json::Value::Null}),
                ),
            }
        }
        // Unknown method: report success-shaped null so a stray call never hangs
        // the client. The settlement paths only touch the four above.
        _ => result_response(id, serde_json::Value::Null),
    }
}

/// Decode a `sendTransaction` params array `[base64_tx, config]` and return the
/// transaction's first signature (base58), matching what the real client
/// submitted so the client's signature-echo check passes.
fn signature_of(params: &serde_json::Value) -> Option<String> {
    let encoded = params.get(0)?.as_str()?;
    let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded).ok()?;
    let tx: VersionedTransaction = bincode::deserialize(&bytes).ok()?;
    let sig = tx.signatures.first()?;
    Some(sig.to_string())
}

fn result_response(id: serde_json::Value, result: serde_json::Value) -> String {
    serde_json::json!({"jsonrpc": "2.0", "result": result, "id": id}).to_string()
}

fn error_response(id: serde_json::Value, code: i64, message: &str) -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "error": {"code": code, "message": message},
        "id": id,
    })
    .to_string()
}
