use std::{
    env,
    io::{BufRead, BufReader, Write},
    net::{TcpListener, TcpStream},
    sync::Arc,
    thread,
};

use serde_json::json;
use solana_keychain::memory::MemorySigner;
use solana_x402::{
    protocol::schemes::upto::UptoSettlementResponse,
    server::upto::{UptoConfig, X402Upto},
    PAYMENT_REQUIRED_HEADER, PAYMENT_RESPONSE_HEADER, PAYMENT_SIGNATURE_HEADER,
};

const DEFAULT_RESOURCE_PATH: &str = "/protected";
const HEALTH_PATH: &str = "/health";
const DEFAULT_SETTLEMENT_HEADER: &str = "x-fixture-settlement";
const TOKEN_DECIMALS: u8 = 6;

#[derive(Clone)]
struct UptoHarnessState {
    upto: X402Upto,
    price: String,
    resource_path: String,
    settlement_header: String,
    actual_amount: String,
    runtime: Arc<tokio::runtime::Runtime>,
}

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let runtime = Arc::new(tokio::runtime::Runtime::new()?);
    let state = Arc::new(read_state(runtime.clone())?);
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();

    println!(
        "{}",
        serde_json::to_string(&json!({
            "type": "ready",
            "implementation": "rust",
            "role": "server",
            "port": port,
            "capabilities": ["upto"],
        }))?
    );

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let state = Arc::clone(&state);
                thread::spawn(move || {
                    if let Err(error) = handle_connection(stream, &state) {
                        eprintln!("harness rust upto server error: {error}");
                    }
                });
            }
            Err(error) => eprintln!("harness rust upto server accept error: {error}"),
        }
    }

    Ok(())
}

fn read_state(
    runtime: Arc<tokio::runtime::Runtime>,
) -> Result<UptoHarnessState, Box<dyn std::error::Error + Send + Sync>> {
    let rpc_url = read_required_env("X402_HARNESS_RPC_URL")?;
    let network = env::var("X402_HARNESS_NETWORK").unwrap_or_else(|_| "devnet".to_string());
    let mint = env::var("X402_HARNESS_MINT")
        .unwrap_or_else(|_| "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU".to_string());
    let pay_to = read_required_env("X402_HARNESS_PAY_TO")?;
    let operator_signer = Arc::new(read_memory_signer("X402_HARNESS_FACILITATOR_SECRET_KEY")?);
    let price =
        normalize_price(&env::var("X402_HARNESS_PRICE").unwrap_or_else(|_| "$0.10".to_string()))?;
    let actual_amount = env::var("X402_HARNESS_ACTUAL_AMOUNT").unwrap_or_else(|_| "0".to_string());
    let resource_path = env::var("X402_HARNESS_RESOURCE_PATH")
        .unwrap_or_else(|_| DEFAULT_RESOURCE_PATH.to_string());
    let settlement_header = env::var("X402_HARNESS_SETTLEMENT_HEADER")
        .unwrap_or_else(|_| DEFAULT_SETTLEMENT_HEADER.to_string());
    let program_id = env::var("PAYMENT_CHANNELS_PROGRAM_ID").ok();

    let upto = X402Upto::new(UptoConfig {
        recipient: pay_to,
        currency: mint,
        decimals: TOKEN_DECIMALS,
        cluster: network,
        rpc_url: Some(rpc_url),
        resource: resource_path.clone(),
        description: Some("Surfpool-backed usage endpoint".to_string()),
        max_timeout_seconds: 300,
        token_program: None,
        program_id,
        operator_signer,
    })?;

    Ok(UptoHarnessState {
        upto,
        price,
        resource_path,
        settlement_header,
        actual_amount,
        runtime,
    })
}

fn handle_connection(
    mut stream: TcpStream,
    state: &UptoHarnessState,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut reader = BufReader::new(stream.try_clone()?);

    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    if request_line.trim().is_empty() {
        return Ok(());
    }

    let mut headers = std::collections::HashMap::new();
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
        ("GET", path) if path == state.resource_path => {
            let max_amount = state.price.clone();
            if let Some(payment_header) =
                headers.get(&PAYMENT_SIGNATURE_HEADER.to_ascii_lowercase())
            {
                match settle_upto_payment(state, payment_header, &max_amount) {
                    Ok((settlement, settlement_header_value)) => {
                        write_json_response(
                            &mut stream,
                            200,
                            &[
                                (
                                    state.settlement_header.as_str(),
                                    settlement.transaction.as_str(),
                                ),
                                (PAYMENT_RESPONSE_HEADER, settlement_header_value.as_str()),
                            ],
                            &json!({
                                "ok": true,
                                "paid": true,
                                "settlement": {
                                    "success": true,
                                    "transaction": settlement.transaction,
                                    "network": settlement.network,
                                    "amount": settlement.amount,
                                },
                            }),
                        )?;
                    }
                    Err(error) => {
                        let (_, header_value) = state.upto.payment_required_header(&max_amount)?;
                        write_json_response(
                            &mut stream,
                            402,
                            &[(PAYMENT_REQUIRED_HEADER, header_value.as_str())],
                            &json!({
                                "error": "payment_invalid",
                                "message": error.to_string(),
                            }),
                        )?;
                    }
                }
            } else {
                let (_, header_value) = state.upto.payment_required_header(&max_amount)?;
                write_json_response(
                    &mut stream,
                    402,
                    &[(PAYMENT_REQUIRED_HEADER, header_value.as_str())],
                    &json!({ "error": "payment_required" }),
                )?;
            }
        }
        _ => write_json_response(&mut stream, 404, &[], &json!({ "error": "not_found" }))?,
    }

    Ok(())
}

fn settle_upto_payment(
    state: &UptoHarnessState,
    payment_header: &str,
    max_amount: &str,
) -> Result<(UptoSettlementResponse, String), Box<dyn std::error::Error + Send + Sync>> {
    let verified = state
        .runtime
        .block_on(state.upto.verify_open(payment_header, max_amount))?;
    let actual: u64 = state.actual_amount.parse().unwrap_or(0);
    let settlement = state
        .runtime
        .block_on(state.upto.settle_actual(&verified, actual))?;
    let (_, header_value) = state.upto.settlement_header(&settlement)?;
    Ok((settlement, header_value))
}

fn write_json_response(
    stream: &mut TcpStream,
    status: u16,
    headers: &[(&str, &str)],
    body: &serde_json::Value,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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

fn read_required_env(name: &str) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    env::var(name).map_err(|_| format!("{name} is required").into())
}

fn read_memory_signer(
    name: &str,
) -> Result<MemorySigner, Box<dyn std::error::Error + Send + Sync>> {
    let raw = read_required_env(name)?;
    let bytes: Vec<u8> = serde_json::from_str(&raw)?;
    Ok(MemorySigner::from_bytes(&bytes)?)
}

fn normalize_price(price: &str) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let without_symbol = price.trim().strip_prefix('$').unwrap_or(price.trim());
    let amount = without_symbol
        .split_whitespace()
        .next()
        .ok_or_else(|| "price is required".to_string())?;
    if amount.is_empty()
        || amount.matches('.').count() > 1
        || !amount.chars().all(|c| c.is_ascii_digit() || c == '.')
    {
        return Err(format!("invalid price: {price}").into());
    }
    Ok(amount.to_string())
}
