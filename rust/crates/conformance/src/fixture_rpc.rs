//! Deterministic Solana JSON-RPC fixture. `pkc fill` runs the kit against
//! it, and `pkc run` serves one per vector to the SDK testee as
//! `input.rpcUrl` (it replaced `harness/src/conformance/fixture-rpc.ts`).
//!
//! The filler runs the kit's real builders and verifiers against the same
//! chain state every SDK runner sees: the vector's `input.rpcFixtures`
//! (blockhash, mints in the 82-byte SPL layout, raw program accounts), rent,
//! slot, and whether a blockhash is the fixture's latest. Any other method
//! is refused with an error that names it, so a builder reaching for the
//! network on the offline path fails loudly instead of silently succeeding.
//! Every call is recorded.
//!
//! Two transports share one handler:
//! - [`FixtureSender`], an in-process `RpcSender` for `RpcClient`s the
//!   filler constructs (client builders);
//! - [`HttpFixture`], a loopback HTTP endpoint for kit servers that build
//!   their own client from a URL (`mpp::server::Config::rpc_url`).

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use base64::Engine;
use serde_json::{json, Value};
use solana_rpc_client::rpc_client::{RpcClient, RpcClientConfig};
use solana_rpc_client::rpc_sender::{RpcSender, RpcTransportStats};
use solana_rpc_client_api::client_error::Result as ClientResult;
use solana_rpc_client_api::request::{RpcError, RpcRequest, RpcResponseErrorData};

use crate::keys::{TOKEN_2022_PROGRAM, TOKEN_PROGRAM};

/// Blockhash served when a vector pins none (same as the TS fixture).
pub const DEFAULT_BLOCKHASH: &str = "11111111111111111111111111111111";
const DEFAULT_LAST_VALID_BLOCK_HEIGHT: u64 = 1_000;
const DEFAULT_SLOT: u64 = 100;
const MINT_SIZE: usize = 82;

/// The JSON-RPC methods the fixture serves. Anything else is refused.
pub const SERVED_METHODS: [&str; 7] = [
    "getLatestBlockhash",
    "getAccountInfo",
    "getMultipleAccounts",
    "getMinimumBalanceForRentExemption",
    "getSlot",
    "getHealth",
    "isBlockhashValid",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixtureMint {
    pub owner: String,
    pub decimals: u8,
}

/// A raw account (`rpcFixtures.accounts.<address>`): program-owned state a
/// verifier reads, e.g. a payment channel or a subscription plan. The data
/// is the account's exact bytes, base64.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixtureAccount {
    pub owner: String,
    pub data: Vec<u8>,
    pub lamports: u64,
}

/// Chain state for one vector (`input.rpcFixtures`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Fixtures {
    pub recent_blockhash: Option<String>,
    pub last_valid_block_height: Option<u64>,
    pub slot: Option<u64>,
    pub mints: BTreeMap<String, FixtureMint>,
    pub accounts: BTreeMap<String, FixtureAccount>,
}

impl Fixtures {
    /// Parse `input.rpcFixtures`, defaulting the blockhash to the charge
    /// request's `methodDetails.recentBlockhash` (what the retired TS driver
    /// did, so every SDK sees the chain state it always saw).
    pub fn from_input(input: &Value) -> Result<Self, String> {
        let raw = input.get("rpcFixtures").cloned().unwrap_or(json!({}));
        let mut mints = BTreeMap::new();
        if let Some(map) = raw.get("mints").and_then(Value::as_object) {
            for (address, mint) in map {
                let owner = mint
                    .get("owner")
                    .and_then(Value::as_str)
                    .ok_or_else(|| format!("rpcFixtures.mints.{address}.owner missing"))?;
                let decimals = mint
                    .get("decimals")
                    .and_then(Value::as_u64)
                    .and_then(|d| u8::try_from(d).ok())
                    .ok_or_else(|| format!("rpcFixtures.mints.{address}.decimals missing"))?;
                mints.insert(
                    address.clone(),
                    FixtureMint {
                        owner: owner.to_string(),
                        decimals,
                    },
                );
            }
        }
        let mut accounts = BTreeMap::new();
        if let Some(map) = raw.get("accounts").and_then(Value::as_object) {
            for (address, account) in map {
                if mints.contains_key(address) {
                    return Err(format!(
                        "rpcFixtures: {address} is both a mint and a raw account"
                    ));
                }
                let owner = account
                    .get("owner")
                    .and_then(Value::as_str)
                    .ok_or_else(|| format!("rpcFixtures.accounts.{address}.owner missing"))?;
                let data = account
                    .get("data")
                    .and_then(Value::as_str)
                    .ok_or_else(|| format!("rpcFixtures.accounts.{address}.data missing"))
                    .and_then(|d| {
                        base64::engine::general_purpose::STANDARD
                            .decode(d)
                            .map_err(|e| format!("rpcFixtures.accounts.{address}.data: {e}"))
                    })?;
                let lamports = account
                    .get("lamports")
                    .and_then(Value::as_u64)
                    .unwrap_or_else(|| rent_exempt(data.len() as u64));
                accounts.insert(
                    address.clone(),
                    FixtureAccount {
                        owner: owner.to_string(),
                        data,
                        lamports,
                    },
                );
            }
        }
        let recent_blockhash = raw
            .get("recentBlockhash")
            .and_then(Value::as_str)
            .map(str::to_string)
            .or_else(|| {
                input
                    .pointer("/request/methodDetails/recentBlockhash")
                    .and_then(Value::as_str)
                    .map(str::to_string)
            });
        Ok(Self {
            recent_blockhash,
            last_valid_block_height: raw.get("lastValidBlockHeight").and_then(Value::as_u64),
            slot: raw.get("slot").and_then(Value::as_u64),
            mints,
            accounts,
        })
    }
}

/// `lamports_per_byte_year (3480) * 2 years` over 128 bytes of storage
/// overhead plus `size`, identical to the TS fixture.
pub fn rent_exempt(size: u64) -> u64 {
    (128 + size) * 3480 * 2
}

/// SPL mint layout: `COption<Pubkey>` mint authority (36), `u64` supply,
/// `u8` decimals at 44, `bool` initialized at 45, `COption<Pubkey>` freeze.
pub fn mint_account_data(decimals: u8) -> [u8; MINT_SIZE] {
    let mut data = [0u8; MINT_SIZE];
    data[44] = decimals;
    data[45] = 1;
    data
}

fn raw_account_value(account: &FixtureAccount, encoding: Option<&str>) -> Value {
    let data = match encoding {
        Some("base58") => json!([bs58::encode(&account.data).into_string(), "base58"]),
        _ => json!([
            base64::engine::general_purpose::STANDARD.encode(&account.data),
            "base64"
        ]),
    };
    json!({
        "data": data,
        "executable": false,
        "lamports": account.lamports,
        "owner": account.owner,
        "rentEpoch": 0,
        "space": account.data.len(),
    })
}

fn account_value(fixtures: &Fixtures, address: &str, encoding: Option<&str>) -> Value {
    if let Some(account) = fixtures.accounts.get(address) {
        return raw_account_value(account, encoding);
    }
    let Some(mint) = fixtures.mints.get(address) else {
        return Value::Null;
    };
    let mut value = json!({
        "executable": false,
        "lamports": rent_exempt(MINT_SIZE as u64),
        "owner": mint.owner,
        "rentEpoch": 0,
        "space": MINT_SIZE,
    });
    let token_owned = mint.owner == TOKEN_PROGRAM || mint.owner == TOKEN_2022_PROGRAM;
    let data = mint_account_data(mint.decimals);
    value["data"] = match encoding {
        Some("jsonParsed") if token_owned => json!({
            "program": if mint.owner == TOKEN_PROGRAM { "spl-token" } else { "spl-token-2022" },
            "parsed": {
                "type": "mint",
                "info": {
                    "decimals": mint.decimals,
                    "freezeAuthority": null,
                    "isInitialized": true,
                    "mintAuthority": null,
                    "supply": "0",
                },
            },
            "space": MINT_SIZE,
        }),
        Some("base58") => json!([bs58::encode(data).into_string(), "base58"]),
        _ => json!([
            base64::engine::general_purpose::STANDARD.encode(data),
            "base64"
        ]),
    };
    value
}

/// Serve one JSON-RPC method. `Err` carries the message of a `-32601` error
/// naming the refused method.
pub fn handle(fixtures: &Fixtures, method: &str, params: &Value) -> Result<Value, String> {
    let slot = fixtures.slot.unwrap_or(DEFAULT_SLOT);
    let context = json!({ "apiVersion": "2.0.0", "slot": slot });
    let params = params.as_array().cloned().unwrap_or_default();
    let encoding = params
        .iter()
        .find(|p| p.is_object())
        .and_then(|p| p.get("encoding"))
        .and_then(Value::as_str)
        .map(str::to_string);
    match method {
        "getLatestBlockhash" => Ok(json!({
            "context": context,
            "value": {
                "blockhash": fixtures.recent_blockhash.as_deref().unwrap_or(DEFAULT_BLOCKHASH),
                "lastValidBlockHeight": fixtures
                    .last_valid_block_height
                    .unwrap_or(DEFAULT_LAST_VALID_BLOCK_HEIGHT),
            },
        })),
        "getAccountInfo" => {
            let address = params.first().and_then(Value::as_str).unwrap_or_default();
            Ok(json!({
                "context": context,
                "value": account_value(fixtures, address, encoding.as_deref()),
            }))
        }
        "getMultipleAccounts" => {
            let addresses = params
                .first()
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let values: Vec<Value> = addresses
                .iter()
                .map(|a| {
                    account_value(
                        fixtures,
                        a.as_str().unwrap_or_default(),
                        encoding.as_deref(),
                    )
                })
                .collect();
            Ok(json!({ "context": context, "value": values }))
        }
        "getMinimumBalanceForRentExemption" => {
            let size = params.first().and_then(Value::as_u64).unwrap_or(0);
            Ok(json!(rent_exempt(size)))
        }
        "getSlot" => Ok(json!(slot)),
        "getHealth" => Ok(json!("ok")),
        // The fixture's chain knows one blockhash: its latest.
        "isBlockhashValid" => {
            let latest = fixtures
                .recent_blockhash
                .as_deref()
                .unwrap_or(DEFAULT_BLOCKHASH);
            let asked = params.first().and_then(Value::as_str).unwrap_or_default();
            Ok(json!({ "context": context, "value": asked == latest }))
        }
        other => Err(refusal(other)),
    }
}

/// The refusal message. `realize.rs` matches on it to recognise that a kit
/// verifier finished every offline check and reached the network step.
pub fn refusal(method: &str) -> String {
    format!("method {method} is not served by the conformance fixture RPC")
}

/// Calls recorded by a fixture, in order.
#[derive(Debug, Clone, Default)]
pub struct CallLog(Arc<Mutex<Vec<String>>>);

impl CallLog {
    pub fn push(&self, method: &str) {
        self.0
            .lock()
            .expect("call log poisoned")
            .push(method.to_string());
    }

    pub fn calls(&self) -> Vec<String> {
        self.0.lock().expect("call log poisoned").clone()
    }
}

/// In-process transport for `RpcClient`.
pub struct FixtureSender {
    fixtures: Fixtures,
    log: CallLog,
}

#[async_trait::async_trait]
impl RpcSender for FixtureSender {
    async fn send(&self, request: RpcRequest, params: Value) -> ClientResult<Value> {
        let method = request.to_string();
        self.log.push(&method);
        handle(&self.fixtures, &method, &params).map_err(|message| {
            RpcError::RpcResponseError {
                code: -32601,
                message,
                data: RpcResponseErrorData::Empty,
            }
            .into()
        })
    }

    fn get_transport_stats(&self) -> RpcTransportStats {
        RpcTransportStats::default()
    }

    fn url(&self) -> String {
        "fixture://conformance".to_string()
    }
}

/// An `RpcClient` backed by the fixture, plus its call log.
pub fn rpc_client(fixtures: &Fixtures) -> (RpcClient, CallLog) {
    let log = CallLog::default();
    let sender = FixtureSender {
        fixtures: fixtures.clone(),
        log: log.clone(),
    };
    (
        RpcClient::new_sender(sender, RpcClientConfig::default()),
        log,
    )
}

/// Loopback HTTP JSON-RPC endpoint serving the fixture. Stops when dropped.
pub struct HttpFixture {
    url: String,
    log: CallLog,
    stop: Arc<std::sync::atomic::AtomicBool>,
    handle: Option<JoinHandle<()>>,
    port: u16,
}

impl HttpFixture {
    pub fn start(fixtures: &Fixtures) -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        let log = CallLog::default();
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let thread_log = log.clone();
        let thread_stop = stop.clone();
        let fixtures = fixtures.clone();
        let handle = std::thread::spawn(move || {
            for stream in listener.incoming() {
                if thread_stop.load(std::sync::atomic::Ordering::SeqCst) {
                    break;
                }
                let Ok(stream) = stream else { continue };
                let fixtures = fixtures.clone();
                let log = thread_log.clone();
                std::thread::spawn(move || {
                    let _ = serve_connection(stream, &fixtures, &log);
                });
            }
        });
        Ok(Self {
            url: format!("http://127.0.0.1:{port}"),
            log,
            stop,
            handle: Some(handle),
            port,
        })
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn calls(&self) -> Vec<String> {
        self.log.calls()
    }
}

impl Drop for HttpFixture {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        // Wake the accept loop so it observes the stop flag.
        let _ = TcpStream::connect(("127.0.0.1", self.port));
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn dispatch(fixtures: &Fixtures, log: &CallLog, request: &Value) -> Value {
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    let method = request
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or_default();
    log.push(method);
    let params = request.get("params").cloned().unwrap_or(json!([]));
    match handle(fixtures, method, &params) {
        Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
        Err(message) => json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": { "code": -32601, "message": message },
        }),
    }
}

/// Read a `Transfer-Encoding: chunked` body.
fn read_chunked(reader: &mut impl BufRead) -> std::io::Result<Vec<u8>> {
    let mut body = Vec::new();
    loop {
        let mut size = String::new();
        reader.read_line(&mut size)?;
        let size = usize::from_str_radix(size.trim().split(';').next().unwrap_or("0"), 16)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        if size == 0 {
            // Trailers end with an empty line.
            loop {
                let mut trailer = String::new();
                if reader.read_line(&mut trailer)? == 0 || trailer.trim().is_empty() {
                    return Ok(body);
                }
            }
        }
        let start = body.len();
        body.resize(start + size, 0);
        reader.read_exact(&mut body[start..])?;
        let mut crlf = String::new();
        reader.read_line(&mut crlf)?;
    }
}

/// Minimal HTTP/1.1 (the subset SDK HTTP clients send to a JSON-RPC
/// endpoint, as Node's server in the retired TS fixture accepted it):
/// keep-alive unless `Connection: close`, `Content-Length` or chunked
/// bodies, `Expect: 100-continue`.
fn serve_connection(stream: TcpStream, fixtures: &Fixtures, log: &CallLog) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut writer = stream;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            return Ok(());
        }
        if line.trim().is_empty() {
            continue;
        }
        let mut content_length = 0usize;
        let mut chunked = false;
        let mut close = line.trim_end().ends_with("HTTP/1.0");
        let mut expect_continue = false;
        loop {
            let mut header = String::new();
            if reader.read_line(&mut header)? == 0 {
                return Ok(());
            }
            let header = header.trim_end();
            if header.is_empty() {
                break;
            }
            if let Some((name, value)) = header.split_once(':') {
                let value = value.trim();
                if name.eq_ignore_ascii_case("content-length") {
                    content_length = value.parse().unwrap_or(0);
                } else if name.eq_ignore_ascii_case("transfer-encoding") {
                    chunked = value.to_ascii_lowercase().contains("chunked");
                } else if name.eq_ignore_ascii_case("connection") {
                    let value = value.to_ascii_lowercase();
                    if value.contains("close") {
                        close = true;
                    } else if value.contains("keep-alive") {
                        close = false;
                    }
                } else if name.eq_ignore_ascii_case("expect") {
                    expect_continue = value.eq_ignore_ascii_case("100-continue");
                }
            }
        }
        if expect_continue {
            writer.write_all(b"HTTP/1.1 100 Continue\r\n\r\n")?;
            writer.flush()?;
        }
        let body = if chunked {
            read_chunked(&mut reader)?
        } else {
            let mut body = vec![0u8; content_length];
            reader.read_exact(&mut body)?;
            body
        };
        let response = match serde_json::from_slice::<Value>(&body) {
            Ok(Value::Array(batch)) => {
                Value::Array(batch.iter().map(|r| dispatch(fixtures, log, r)).collect())
            }
            Ok(request) => dispatch(fixtures, log, &request),
            Err(error) => json!({
                "jsonrpc": "2.0",
                "id": null,
                "error": { "code": -32700, "message": format!("parse error: {error}") },
            }),
        };
        let payload = response.to_string();
        write!(
            writer,
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n{}\r\n{}",
            payload.len(),
            if close { "connection: close\r\n" } else { "" },
            payload
        )?;
        writer.flush()?;
        if close {
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::MINT;

    fn fixtures() -> Fixtures {
        let mut mints = BTreeMap::new();
        mints.insert(
            MINT.to_string(),
            FixtureMint {
                owner: TOKEN_PROGRAM.to_string(),
                decimals: 6,
            },
        );
        Fixtures {
            mints,
            ..Default::default()
        }
    }

    #[test]
    fn refuses_unserved_methods_by_name() {
        let err = handle(&fixtures(), "sendTransaction", &json!([])).unwrap_err();
        assert!(err.contains("sendTransaction"), "{err}");
    }

    #[test]
    fn serves_mint_in_spl_layout() {
        let value = handle(
            &fixtures(),
            "getAccountInfo",
            &json!([MINT, { "encoding": "base64" }]),
        )
        .unwrap();
        let data = value["value"]["data"][0].as_str().unwrap();
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(data)
            .unwrap();
        assert_eq!(bytes.len(), 82);
        assert_eq!(bytes[44], 6);
        assert_eq!(bytes[45], 1);
        let missing = handle(
            &fixtures(),
            "getAccountInfo",
            &json!(["11111111111111111111111111111112"]),
        )
        .unwrap();
        assert!(missing["value"].is_null());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn in_process_client_reads_the_fixture() {
        let (rpc, log) = rpc_client(&fixtures());
        let account = rpc
            .get_inner_client()
            .get_account(&crate::keys::pubkey(MINT))
            .await
            .unwrap();
        assert_eq!(account.data[44], 6);
        assert_eq!(log.calls(), vec!["getAccountInfo".to_string()]);
    }

    // SDK HTTP clients differ: chunked bodies, `Expect: 100-continue` and
    // `Connection: close` must all be served like Node's server did.
    #[test]
    fn http_fixture_accepts_chunked_expect_continue_and_close() {
        let fixture = HttpFixture::start(&fixtures()).unwrap();
        let addr = fixture.url().trim_start_matches("http://").to_string();
        let mut stream = TcpStream::connect(&addr).unwrap();
        let body = r#"{"jsonrpc":"2.0","id":1,"method":"getSlot"}"#;
        write!(
            stream,
            "POST / HTTP/1.1\r\nhost: x\r\ntransfer-encoding: chunked\r\nexpect: 100-continue\r\nconnection: close\r\n\r\n{:x}\r\n{body}\r\n0\r\n\r\n",
            body.len()
        )
        .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 100 Continue"), "{response}");
        assert!(response.contains(r#""result":100"#), "{response}");
        assert_eq!(fixture.calls(), vec!["getSlot"]);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn http_fixture_serves_and_refuses() {
        let fixture = HttpFixture::start(&fixtures()).unwrap();
        let rpc =
            solana_rpc_client::nonblocking::rpc_client::RpcClient::new(fixture.url().to_string());
        let hash = rpc.get_latest_blockhash().await.unwrap();
        assert_eq!(hash.to_string(), DEFAULT_BLOCKHASH);
        let err = rpc
            .get_balance(&crate::keys::pubkey(MINT))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("getBalance"), "{err}");
        assert_eq!(fixture.calls(), vec!["getLatestBlockhash", "getBalance"]);
    }
}
