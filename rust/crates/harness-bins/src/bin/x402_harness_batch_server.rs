//! Interop server for x402 `batch-settlement`.
//!
//! Serves the paid resource through the scheme's verify / reserve / commit
//! steps (as the axum gate does), remembers every channel it served, and on
//! `POST /redeem` runs its out-of-band redemption over all of them: one
//! `claim` pass then one `settle` (distribute) pass. Redemption is built as
//! transaction v1, so the claim and distribute pack up to the version-1
//! capacity.

use std::{
    collections::{BTreeSet, HashMap},
    env,
    io::{BufRead, BufReader, Write},
    net::{TcpListener, TcpStream},
    sync::{Arc, Mutex},
    thread,
};

use serde_json::json;
use solana_pay_kit::solana_keychain::{memory::MemorySigner, TransactionSigner};
use solana_pay_kit::x402::{
    server::{BatchAccess, BatchConfig, X402BatchSettlement},
    PAYMENT_SIGNATURE_HEADER,
};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

const DEFAULT_RESOURCE_PATH: &str = "/protected";
const HEALTH_PATH: &str = "/health";
const REDEEM_PATH: &str = "/redeem";
const TOKEN_DECIMALS: u8 = 6;

struct BatchHarnessState {
    batch: X402BatchSettlement,
    price: String,
    resource_path: String,
    /// Channels this server served, in the order it first saw them.
    channels: Mutex<BTreeSet<String>>,
    runtime: tokio::runtime::Runtime,
}

fn main() -> Result<(), BoxError> {
    let state = Arc::new(read_state()?);
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();

    println!(
        "{}",
        serde_json::to_string(&json!({
            "type": "ready",
            "implementation": "rust",
            "role": "server",
            "port": port,
            "capabilities": ["batch-settlement"],
        }))?
    );

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let state = Arc::clone(&state);
                thread::spawn(move || {
                    if let Err(error) = handle_connection(stream, &state) {
                        eprintln!("harness rust batch server error: {error}");
                    }
                });
            }
            Err(error) => eprintln!("harness rust batch server accept error: {error}"),
        }
    }
    Ok(())
}

fn read_state() -> Result<BatchHarnessState, BoxError> {
    let rpc_url = read_required_env("X402_HARNESS_RPC_URL")?;
    // Surfpool runs a payment-channels build whose treasury owner is patched
    // to the mainnet constant, so the cluster label is `localnet`, not devnet
    // (see the upto harness server).
    let cluster = "localnet".to_string();
    let mint = env::var("X402_HARNESS_MINT")
        .unwrap_or_else(|_| "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU".to_string());
    let pay_to = read_required_env("X402_HARNESS_PAY_TO")?;
    let fee_payer: Arc<dyn TransactionSigner> =
        Arc::new(read_memory_signer("X402_HARNESS_FACILITATOR_SECRET_KEY")?);
    let price =
        normalize_price(&env::var("X402_HARNESS_PRICE").unwrap_or_else(|_| "0.001".into()))?;
    let resource_path = env::var("X402_HARNESS_RESOURCE_PATH")
        .unwrap_or_else(|_| DEFAULT_RESOURCE_PATH.to_string());

    let mut config = BatchConfig::new(pay_to, cluster, fee_payer);
    config.currency = mint;
    config.decimals = TOKEN_DECIMALS;
    config.rpc_url = Some(rpc_url);
    config.resource = resource_path.clone();
    config.description = Some("Surfpool-backed batch-settlement endpoint".to_string());
    config.program_id = env::var("PAYMENT_CHANNELS_PROGRAM_ID").ok();
    let batch = X402BatchSettlement::new(config)?
        // Accept and advertise version 1, and build redemptions as version 1.
        // Surfpool executes version 1 but does not expose the `enable_tx_v1`
        // feature account, so `Auto` would read it as inactive.
        .with_tx_v1(solana_pay_kit::core::tx::TxV1Mode::On);

    Ok(BatchHarnessState {
        batch,
        price,
        resource_path,
        channels: Mutex::new(BTreeSet::new()),
        runtime: tokio::runtime::Runtime::new()?,
    })
}

fn handle_connection(mut stream: TcpStream, state: &BatchHarnessState) -> Result<(), BoxError> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    if request_line.trim().is_empty() {
        return Ok(());
    }
    let mut headers = HashMap::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        if let Some((name, value)) = trimmed.split_once(':') {
            headers.insert(name.to_ascii_lowercase(), value.trim().to_string());
        }
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let path = parts.next().unwrap_or_default();

    match (method, path) {
        ("GET", HEALTH_PATH) => write_json(&mut stream, 200, &[], &json!({ "ok": true })),
        ("POST", REDEEM_PATH) => match redeem(state) {
            Ok(body) => write_json(&mut stream, 200, &[], &body),
            Err(error) => write_json(
                &mut stream,
                500,
                &[],
                &json!({ "error": "redeem_failed", "message": error.to_string() }),
            ),
        },
        ("GET", path) if path == state.resource_path => {
            match headers.get(&PAYMENT_SIGNATURE_HEADER.to_ascii_lowercase()) {
                Some(header) => match serve(state, header) {
                    Ok((name, value)) => write_json(
                        &mut stream,
                        200,
                        &[(name.as_str(), value.as_str())],
                        &json!({ "ok": true, "paid": true }),
                    ),
                    Err(error) => challenge(
                        &mut stream,
                        state,
                        &json!({ "error": "payment_invalid", "message": error.to_string() }),
                    ),
                },
                None => challenge(&mut stream, state, &json!({ "error": "payment_required" })),
            }
        }
        _ => write_json(&mut stream, 404, &[], &json!({ "error": "not_found" })),
    }
}

/// Verify, reserve, serve and commit one paid request, returning the
/// `PAYMENT-RESPONSE` header.
fn serve(state: &BatchHarnessState, header: &str) -> Result<(String, String), BoxError> {
    let access = state
        .runtime
        .block_on(state.batch.verify_and_reserve_payment(header, &state.price))?;
    let settlement = match access {
        BatchAccess::Serve(outcome) | BatchAccess::Resume(outcome) => {
            let channel_id = outcome.channel_id.clone();
            state
                .runtime
                .block_on(state.batch.mark_handler_succeeded(&outcome))?;
            let settlement = state
                .runtime
                .block_on(state.batch.finish_commit(&outcome))?;
            state
                .channels
                .lock()
                .map_err(|_| "channel set poisoned")?
                .insert(channel_id);
            settlement
        }
        BatchAccess::Replay(settlement, _) => settlement,
        BatchAccess::InProgress => return Err("authorization in progress".into()),
        BatchAccess::Control(_) => return Err("refunds are not part of this scenario".into()),
    };
    Ok(state.batch.settlement_header(&settlement)?)
}

/// Redeem every served channel: claim its latest voucher, then distribute.
fn redeem(state: &BatchHarnessState) -> Result<serde_json::Value, BoxError> {
    let channels: Vec<String> = state
        .channels
        .lock()
        .map_err(|_| "channel set poisoned")?
        .iter()
        .cloned()
        .collect();
    let claims = state.runtime.block_on(state.batch.claim(&channels))?;
    let distributes = state.runtime.block_on(state.batch.settle(&channels))?;
    Ok(json!({
        "channels": channels,
        "claims": claims,
        "distributes": distributes,
    }))
}

fn challenge(
    stream: &mut TcpStream,
    state: &BatchHarnessState,
    body: &serde_json::Value,
) -> Result<(), BoxError> {
    let (name, value) = state
        .batch
        .payment_required_header(&state.price, Some(&state.resource_path))?;
    write_json(stream, 402, &[(name.as_str(), value.as_str())], body)
}

fn write_json(
    stream: &mut TcpStream,
    status: u16,
    headers: &[(&str, &str)],
    body: &serde_json::Value,
) -> Result<(), BoxError> {
    let body = serde_json::to_vec(body)?;
    let reason = match status {
        200 => "OK",
        402 => "Payment Required",
        404 => "Not Found",
        _ => "Internal Server Error",
    };
    write!(stream, "HTTP/1.1 {status} {reason}\r\n")?;
    write!(stream, "content-type: application/json\r\n")?;
    write!(stream, "content-length: {}\r\n", body.len())?;
    write!(stream, "connection: close\r\n")?;
    for (name, value) in headers {
        write!(stream, "{name}: {value}\r\n")?;
    }
    write!(stream, "\r\n")?;
    stream.write_all(&body)?;
    stream.flush()?;
    Ok(())
}

fn read_required_env(name: &str) -> Result<String, BoxError> {
    env::var(name).map_err(|_| format!("{name} is required").into())
}

fn read_memory_signer(name: &str) -> Result<MemorySigner, BoxError> {
    let raw = read_required_env(name)?;
    let bytes: Vec<u8> = serde_json::from_str(&raw)?;
    Ok(MemorySigner::from_bytes(&bytes)?)
}

fn normalize_price(price: &str) -> Result<String, BoxError> {
    let amount = price.trim().strip_prefix('$').unwrap_or(price.trim());
    if amount.is_empty() || !amount.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return Err(format!("invalid price: {price}").into());
    }
    Ok(amount.to_string())
}
