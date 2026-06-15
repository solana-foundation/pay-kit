use std::{
    collections::HashMap,
    env,
    io::{self, BufRead, BufReader, Write},
    net::{TcpListener, TcpStream},
    process,
    sync::Arc,
    thread,
};

use serde_json::json;

/// Write a line to stdout, swallowing `BrokenPipe` (EPIPE) errors instead of
/// panicking the way Rust's default `println!` macro would when the harness
/// has stopped reading our pipe. Any other I/O error is fatal.
fn write_stdout_line(line: &str) {
    let stdout = io::stdout();
    let mut handle = stdout.lock();
    match writeln!(handle, "{line}") {
        Ok(()) => {
            let _ = handle.flush();
        }
        Err(err) if err.kind() == io::ErrorKind::BrokenPipe => {
            // Harness already torn down; exit cleanly so we do not surface a
            // panic that propagates into the vitest worker.
            process::exit(0);
        }
        Err(err) => panic!("failed printing to stdout: {err}"),
    }
}

/// Same as `write_stdout_line` but for stderr. Used by background threads so a
/// post-teardown stderr write does not kill the process.
fn write_stderr_line(line: &str) {
    let stderr = io::stderr();
    let mut handle = stderr.lock();
    match writeln!(handle, "{line}") {
        Ok(()) => {
            let _ = handle.flush();
        }
        Err(err) if err.kind() == io::ErrorKind::BrokenPipe => {
            // Drop the line silently.
        }
        Err(_) => {}
    }
}
use solana_mpp::protocol::intents::ChargeRequest;
use solana_mpp::protocol::solana::Split;
use solana_mpp::server::{ChargeOptions, Config, Mpp};
use solana_mpp::solana_keychain::{memory::MemorySigner, SolanaSigner};
use solana_mpp::{
    format_www_authenticate, parse_authorization, AUTHORIZATION_HEADER, PAYMENT_RECEIPT_HEADER,
    WWW_AUTHENTICATE_HEADER,
};

const DEFAULT_RESOURCE_PATH: &str = "/protected";
const HEALTH_PATH: &str = "/health";
const DEFAULT_PRICE: &str = "0.001";
// Audit #24: ≥32 bytes for HMAC-SHA256 keys. Pad to keep the harness
// default usable when no MPP_HARNESS_SECRET_KEY is set in the env.
const DEFAULT_SECRET_KEY: &str = "mpp-harness-secret-key-with-32b-pad";
const DEFAULT_SETTLEMENT_HEADER: &str = "x-fixture-settlement";
const DEFAULT_TOKEN_DECIMALS: u8 = 6;

#[derive(Clone)]
struct HarnessState {
    mpp: Mpp,
    price: String,
    push_mode: bool,
    replay_source: Option<ReplaySource>,
    resource_path: String,
    settlement_header: String,
    splits: Vec<Split>,
}

#[derive(Clone)]
struct ReplaySource {
    price: String,
    resource_path: String,
}

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let state = Arc::new(read_state()?);
    let runtime = Arc::new(tokio::runtime::Runtime::new()?);
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();

    write_stdout_line(&serde_json::to_string(&json!({
        "type": "ready",
        "implementation": "rust",
        "role": "server",
        "port": port,
        "capabilities": ["charge"],
    }))?);

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let state = Arc::clone(&state);
                let runtime = Arc::clone(&runtime);
                thread::spawn(move || {
                    if let Err(error) = handle_connection(stream, &state, &runtime) {
                        write_stderr_line(&format!("harness rust server error: {error}"));
                    }
                });
            }
            Err(error) => {
                write_stderr_line(&format!("harness rust server accept error: {error}"));
            }
        }
    }

    Ok(())
}

fn read_state() -> Result<HarnessState, Box<dyn std::error::Error + Send + Sync>> {
    let rpc_url = read_required_env("MPP_HARNESS_RPC_URL")?;
    let network = env::var("MPP_HARNESS_NETWORK").unwrap_or_else(|_| "localnet".to_string());
    let mint = read_required_env("MPP_HARNESS_MINT")?;
    let pay_to = read_required_env("MPP_HARNESS_PAY_TO")?;
    // B34 / push-mode: routes driven in push mode must not advertise a
    // server-side fee payer (see charge.rs: push credentials are rejected
    // when method_details.fee_payer == true). The fee payer secret key is
    // still required for pull-mode runs; we just keep `fee_payer` off the
    // Config so the challenge omits feePayer/feePayerKey.
    let push_mode = env::var("MPP_HARNESS_PAYMENT_MODE")
        .map(|v| v == "push")
        .unwrap_or(false);
    let fee_payer: Arc<dyn SolanaSigner> =
        Arc::new(read_memory_signer("MPP_HARNESS_FEE_PAYER_SECRET_KEY")?);
    let price = env::var("MPP_HARNESS_PRICE").unwrap_or_else(|_| DEFAULT_PRICE.to_string());
    let replay_source = match (
        env::var("MPP_HARNESS_REPLAY_SOURCE_PATH"),
        env::var("MPP_HARNESS_REPLAY_SOURCE_PRICE"),
    ) {
        (Ok(resource_path), Ok(price)) => Some(ReplaySource {
            price,
            resource_path,
        }),
        _ => None,
    };
    let challenge_binding_secret =
        env::var("MPP_HARNESS_SECRET_KEY").unwrap_or_else(|_| DEFAULT_SECRET_KEY.to_string());
    let decimals = match env::var("MPP_HARNESS_DECIMALS") {
        Ok(raw) if !raw.is_empty() => raw.parse::<u8>()?,
        _ => DEFAULT_TOKEN_DECIMALS,
    };
    let splits = read_splits()?;
    // Refuse to boot with invalid splits (audit #21). The harness
    // misconfig scenario depends on this — every server SDK should
    // reject the misconfig consistently, and refusing to start is the
    // earliest possible signal.
    solana_mpp::protocol::solana::validate_splits(&splits)?;

    Ok(HarnessState {
        mpp: Mpp::new(Config {
            recipient: pay_to,
            currency: mint,
            decimals,
            network,
            rpc_url: Some(rpc_url),
            challenge_binding_secret: Some(challenge_binding_secret),
            realm: Some("MPP Harness".to_string()),
            fee_payer: !push_mode,
            fee_payer_signer: if push_mode { None } else { Some(fee_payer) },
            store: None,
            html: false,
            // Interop tests exercise push mode end-to-end; the gate is
            // opt-in (audit #5) so we set it explicitly here.
            accept_push_mode: push_mode,
        })?,
        price,
        push_mode,
        replay_source,
        resource_path: env::var("MPP_HARNESS_RESOURCE_PATH")
            .unwrap_or_else(|_| DEFAULT_RESOURCE_PATH.to_string()),
        settlement_header: env::var("MPP_HARNESS_SETTLEMENT_HEADER")
            .unwrap_or_else(|_| DEFAULT_SETTLEMENT_HEADER.to_string()),
        splits,
    })
}

fn handle_connection(
    mut stream: TcpStream,
    state: &HarnessState,
    runtime: &tokio::runtime::Runtime,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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
        ("GET", HEALTH_PATH) => write_json_response(&mut stream, 200, &[], &json!({ "ok": true }))?,
        ("GET", path) if route_price(state, path).is_some() => {
            let price = route_price(state, path).expect("route price checked above");
            if let Some(authorization) = headers.get(AUTHORIZATION_HEADER) {
                match settle_payment(state, runtime, authorization, price) {
                    Ok((receipt_header, settlement)) => {
                        write_json_response(
                            &mut stream,
                            200,
                            &[
                                (PAYMENT_RECEIPT_HEADER, receipt_header.as_str()),
                                (state.settlement_header.as_str(), settlement.as_str()),
                            ],
                            &json!({
                                "ok": true,
                                "paid": true,
                                "settlement": {
                                    "success": true,
                                    "transaction": settlement,
                                }
                            }),
                        )?;
                    }
                    Err(error) => {
                        let challenge_header = payment_challenge_header(state, price)?;
                        let message = error.to_string();
                        // G39: surface a canonical L6 code on every 402 so
                        // the harness fault matrix can assert cross-SDK
                        // agreement on the code emitted for each failure
                        // class. The Rust spine VerificationError carries
                        // a kebab-case code today; classify_canonical_code
                        // maps it to the canonical snake_case form.
                        let code = classify_canonical_code(&message);
                        write_json_response(
                            &mut stream,
                            402,
                            &[(WWW_AUTHENTICATE_HEADER, challenge_header.as_str())],
                            &json!({
                                "code": code,
                                "error": code,
                                "message": message,
                            }),
                        )?;
                    }
                }
            } else {
                let challenge_header = payment_challenge_header(state, price)?;
                write_json_response(
                    &mut stream,
                    402,
                    &[(WWW_AUTHENTICATE_HEADER, challenge_header.as_str())],
                    &json!({ "error": "payment_required" }),
                )?;
            }
        }
        _ => write_json_response(&mut stream, 404, &[], &json!({ "error": "not_found" }))?,
    }

    Ok(())
}

fn payment_challenge_header(
    state: &HarnessState,
    price: &str,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let challenge = state.mpp.charge_with_options(
        price,
        ChargeOptions {
            description: Some("Surfpool-backed protected content"),
            fee_payer: !state.push_mode,
            splits: state.splits.clone(),
            ..Default::default()
        },
    )?;
    Ok(format_www_authenticate(&challenge)?)
}

fn settle_payment(
    state: &HarnessState,
    runtime: &tokio::runtime::Runtime,
    authorization: &str,
    price: &str,
) -> Result<(String, String), Box<dyn std::error::Error + Send + Sync>> {
    let credential = parse_authorization(authorization)?;
    // Build the route's expected request and use the route-aware verification
    // path. With a single resource path this server isn't itself vulnerable to
    // cross-route replay, but we model the safe pattern so anyone copying the
    // example onto a multi-route server is protected by default.
    let expected = expected_request_for_route(state, price)?;
    let receipt = runtime.block_on(
        state
            .mpp
            .verify_credential_with_expected(&credential, &expected),
    )?;
    let settlement = receipt.reference.clone();
    Ok((receipt.to_header()?, settlement))
}

fn expected_request_for_route(
    state: &HarnessState,
    price: &str,
) -> Result<ChargeRequest, Box<dyn std::error::Error + Send + Sync>> {
    let challenge = state.mpp.charge_with_options(
        price,
        ChargeOptions {
            description: Some("Surfpool-backed protected content"),
            fee_payer: !state.push_mode,
            splits: state.splits.clone(),
            ..Default::default()
        },
    )?;
    Ok(challenge.request.decode()?)
}

fn route_price<'a>(state: &'a HarnessState, path: &str) -> Option<&'a str> {
    if path == state.resource_path {
        return Some(state.price.as_str());
    }
    if let Some(replay_source) = &state.replay_source {
        if path == replay_source.resource_path {
            return Some(replay_source.price.as_str());
        }
    }
    None
}

fn write_json_response(
    stream: &mut TcpStream,
    status: u16,
    headers: &[(&str, &str)],
    body: &serde_json::Value,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let body = serde_json::to_string(body)?;
    let reason = match status {
        200 => "OK",
        402 => "Payment Required",
        404 => "Not Found",
        _ => "Internal Server Error",
    };

    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\ncontent-length: {}\r\n",
        body.len()
    )?;
    for (name, value) in headers {
        write!(stream, "{name}: {value}\r\n")?;
    }
    write!(stream, "\r\n{body}")?;
    stream.flush()?;
    Ok(())
}

fn read_required_env(name: &str) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    env::var(name).map_err(|_| format!("{name} is required").into())
}

fn read_splits() -> Result<Vec<Split>, Box<dyn std::error::Error + Send + Sync>> {
    match env::var("MPP_HARNESS_SPLITS") {
        Ok(raw) if !raw.trim().is_empty() => Ok(serde_json::from_str(&raw)?),
        _ => Ok(Vec::new()),
    }
}

fn read_memory_signer(
    name: &str,
) -> Result<MemorySigner, Box<dyn std::error::Error + Send + Sync>> {
    let raw = read_required_env(name)?;
    let bytes: Vec<u8> = serde_json::from_str(&raw)?;
    Ok(MemorySigner::from_bytes(&bytes)?)
}

/// Classify a free-text error message into a canonical L6 structured
/// error code. Mirrors harness/src/canonical-codes.ts and the
/// Python / Ruby SDK helpers. The G39 fault matrix asserts cross-SDK
/// agreement on this code.
fn classify_canonical_code(message: &str) -> &'static str {
    let lower = message.to_ascii_lowercase();
    if lower.contains("already consumed")
        || lower.contains("signature already consumed")
        // Pull-mode replay surfaces as the RPC's "already been
        // processed" error before the L4 replay-store reservation
        // fires. Canonically the same outcome as a replay-store hit.
        || lower.contains("already been processed")
        || lower.contains("transaction already processed")
    {
        return "signature_consumed";
    }
    if lower.contains("challenge id mismatch")
        || lower.contains("not issued by this server")
        || lower.contains("challenge verification failed")
    {
        return "challenge_verification_failed";
    }
    if lower.contains("challenge expired") || lower.contains("expired at") {
        return "challenge_expired";
    }
    if lower.contains("signed against localnet but the server expects")
        || lower.contains("network mismatch")
        || lower.contains("wrong network")
    {
        return "wrong_network";
    }
    if lower.contains("amount mismatch")
        || lower.contains("currency mismatch")
        || lower.contains("recipient mismatch")
        || lower.contains("method details mismatch")
        || lower.contains("split amounts exceed")
        || lower.contains("splits cannot exceed")
        || lower.contains("too many splits")
        || lower.contains("push-mode credentials are not allowed")
        || lower.contains("unexpected program instruction")
    {
        return "charge_request_mismatch";
    }
    // Compute-budget allowlist violations fall through to `payment_invalid`
    // rather than `charge_request_mismatch`. The message already names the
    // observed value and the configured cap (see
    // `validate_compute_budget_instruction` in `server/charge.rs`), so the
    // harness can assert cross-SDK agreement on the canonical code without
    // conflating tx-shape mismatch with a server policy rejection.
    if lower.contains("credential method does not match")
        || lower.contains("credential intent is not a charge")
        || lower.contains("credential realm does not match")
        || (lower.contains("intent")
            && (lower.contains("not a charge") || lower.contains("does not match")))
    {
        return "challenge_route_mismatch";
    }
    "payment_invalid"
}
