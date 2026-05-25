use std::{
    collections::HashMap,
    env,
    io::{BufRead, BufReader, Write},
    net::{TcpListener, TcpStream},
    sync::Arc,
    thread,
};

use base64::Engine as _;
use serde_json::json;
use solana_keychain::{memory::MemorySigner, SolanaSigner};
use solana_rpc_client::rpc_client::RpcClient;
use solana_signature::Signature;
use solana_transaction::versioned::VersionedTransaction;
use solana_x402::{
    protocol::schemes::exact::{PaymentRequiredEnvelope, PaymentRequirements},
    server::{exact::PaymentOption, Config, ExactOptions, VerifiedExactPayment, X402},
    PAYMENT_REQUIRED_HEADER, PAYMENT_RESPONSE_HEADER, PAYMENT_SIGNATURE_HEADER, X402_VERSION_V2,
};

const DEFAULT_RESOURCE_PATH: &str = "/protected";
const HEALTH_PATH: &str = "/health";
const DEFAULT_PRICE: &str = "$0.001";
const DEFAULT_SETTLEMENT_HEADER: &str = "x-fixture-settlement";
const TOKEN_DECIMALS: u8 = 6;
const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

#[derive(Clone)]
struct InteropState {
    x402: X402,
    rpc_url: String,
    fee_payer: Arc<MemorySigner>,
    price: String,
    resource_path: String,
    settlement_header: String,
    /// Additional currencies (beyond `Config.currency`) this server offers
    /// for the same route. Populated from `X402_INTEROP_EXTRA_OFFERED_MINTS`
    /// (comma-separated mint addresses). Empty for single-currency runs.
    extra_offered_mints: Vec<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let state = Arc::new(read_state()?);
    let runtime = Arc::new(tokio::runtime::Runtime::new()?);
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();

    println!(
        "{}",
        serde_json::to_string(&json!({
            "type": "ready",
            "implementation": "rust",
            "role": "server",
            "port": port,
            "capabilities": ["exact"],
        }))?
    );

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let state = Arc::clone(&state);
                let runtime = Arc::clone(&runtime);
                thread::spawn(move || {
                    if let Err(error) = handle_connection(stream, &state, &runtime) {
                        eprintln!("interop rust server error: {error}");
                    }
                });
            }
            Err(error) => eprintln!("interop rust server accept error: {error}"),
        }
    }

    Ok(())
}

fn read_state() -> Result<InteropState, Box<dyn std::error::Error + Send + Sync>> {
    let rpc_url = read_required_env("X402_INTEROP_RPC_URL")?;
    let network = env::var("X402_INTEROP_NETWORK")
        .unwrap_or_else(|_| solana_x402::exact::SOLANA_DEVNET.to_string());
    let mint = env::var("X402_INTEROP_MINT")
        .unwrap_or_else(|_| solana_x402::exact::mints::USDC_DEVNET.to_string());
    let pay_to = read_required_env("X402_INTEROP_PAY_TO")?;
    let fee_payer = Arc::new(read_memory_signer("X402_INTEROP_FACILITATOR_SECRET_KEY")?);
    let price = normalize_price(
        &env::var("X402_INTEROP_PRICE").unwrap_or_else(|_| DEFAULT_PRICE.to_string()),
    )?;

    let extra_offered_mints: Vec<String> = env::var("X402_INTEROP_EXTRA_OFFERED_MINTS")
        .ok()
        .map(|raw| {
            raw.split(',')
                .map(|entry| entry.trim().to_string())
                .filter(|entry| !entry.is_empty())
                .collect()
        })
        .unwrap_or_default();

    // When extra mints are advertised, expand `accepted_currencies` so the
    // Tier-2 backstop allows any of them.
    let accepted_currencies = if extra_offered_mints.is_empty() {
        None
    } else {
        let mut all = vec![mint.clone()];
        all.extend(extra_offered_mints.iter().cloned());
        Some(all)
    };

    Ok(InteropState {
        x402: X402::new(Config {
            recipient: pay_to,
            currency: mint,
            decimals: TOKEN_DECIMALS,
            network,
            rpc_url: Some(rpc_url.clone()),
            resource: DEFAULT_RESOURCE_PATH.to_string(),
            description: Some("Surfpool-backed protected content".to_string()),
            max_age: Some(60),
            token_program: Some(TOKEN_PROGRAM.to_string()),
            accepted_currencies,
            fee_payer_key: Some(fee_payer.pubkey().to_string()),
        })?,
        rpc_url,
        fee_payer,
        price,
        resource_path: DEFAULT_RESOURCE_PATH.to_string(),
        settlement_header: DEFAULT_SETTLEMENT_HEADER.to_string(),
        extra_offered_mints,
    })
}

/// Build the full list of payment options this server advertises. The
/// primary currency comes from `Config.currency`; any additional mints in
/// `X402_INTEROP_EXTRA_OFFERED_MINTS` are appended.
fn payment_options(state: &InteropState) -> Vec<PaymentOption<'static>> {
    // SAFETY: the strings live as long as the leaked allocation does. We
    // leak intentionally because adapter binaries are short-lived and the
    // allocations need 'static lifetimes for `PaymentOption<'static>`.
    let primary_currency: &'static str = Box::leak(state.x402.currency().to_string().into_boxed_str());
    let price: &'static str = Box::leak(state.price.clone().into_boxed_str());
    let resource_path: &'static str =
        Box::leak(state.resource_path.clone().into_boxed_str());

    let extras: Vec<PaymentOption<'static>> = state
        .extra_offered_mints
        .iter()
        .map(|mint| {
            let mint_static: &'static str = Box::leak(mint.clone().into_boxed_str());
            PaymentOption {
                amount: price,
                currency: Some(mint_static),
                decimals: Some(TOKEN_DECIMALS),
                token_program: None, // resolved via stablecoin lookup
                extra: ExactOptions {
                    description: Some("Surfpool-backed protected content"),
                    resource: Some(resource_path),
                    max_age: Some(60),
                },
            }
        })
        .collect();

    let mut options = vec![PaymentOption {
        amount: price,
        currency: Some(primary_currency),
        decimals: Some(TOKEN_DECIMALS),
        token_program: Some(TOKEN_PROGRAM),
        extra: ExactOptions {
            description: Some("Surfpool-backed protected content"),
            resource: Some(resource_path),
            max_age: Some(60),
        },
    }];
    options.extend(extras);
    options
}

fn handle_connection(
    mut stream: TcpStream,
    state: &InteropState,
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
        ("GET", path) if path == state.resource_path => {
            let offered = payment_options(state);
            let requirements_list = build_offered_requirements(state, &offered)?;
            let primary_network = requirements_list[0].network.clone();
            if let Some(payment_header) =
                headers.get(&PAYMENT_SIGNATURE_HEADER.to_ascii_lowercase())
            {
                match settle_payment(state, runtime, payment_header, &offered) {
                    Ok(settlement) => {
                        let payment_response = serde_json::to_string(&json!({
                            "success": true,
                            "network": primary_network,
                            "transaction": settlement,
                        }))?;
                        write_json_response(
                            &mut stream,
                            200,
                            &[
                                (state.settlement_header.as_str(), settlement.as_str()),
                                (PAYMENT_RESPONSE_HEADER, payment_response.as_str()),
                            ],
                            &json!({
                                "ok": true,
                                "paid": true,
                                "settlement": {
                                    "success": true,
                                    "transaction": settlement,
                                    "network": primary_network,
                                }
                            }),
                        )?;
                    }
                    Err(error) => {
                        let (_, header_value) =
                            payment_required_header_for(&requirements_list)?;
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
                let (_, header_value) = payment_required_header_for(&requirements_list)?;
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

/// Build the freshly-enriched `PaymentRequirements` for each offered option.
/// `Config.fee_payer_key` makes `exact_requirements_for_option` set the
/// `fee_payer` fields automatically — same value at 402-time and verify-time
/// so the deepEqual binding match is stable.
fn build_offered_requirements(
    state: &InteropState,
    offered: &[PaymentOption<'_>],
) -> Result<Vec<PaymentRequirements>, Box<dyn std::error::Error + Send + Sync>> {
    offered
        .iter()
        .map(|option| {
            state
                .x402
                .exact_requirements_for_option(option)
                .map_err(|err| -> Box<dyn std::error::Error + Send + Sync> { Box::new(err) })
        })
        .collect()
}

fn payment_required_header_for(
    requirements: &[PaymentRequirements],
) -> Result<(String, String), Box<dyn std::error::Error + Send + Sync>> {
    let envelope = PaymentRequiredEnvelope {
        x402_version: X402_VERSION_V2,
        resource: requirements.first().and_then(|r| r.resource_info()),
        accepts: requirements.to_vec(),
        error: None,
        extensions: None,
    };
    let json = serde_json::to_string(&envelope)?;
    Ok((
        PAYMENT_REQUIRED_HEADER.to_string(),
        base64::engine::general_purpose::STANDARD.encode(json.as_bytes()),
    ))
}

fn settle_payment(
    state: &InteropState,
    runtime: &tokio::runtime::Runtime,
    payment_header: &str,
    offered: &[PaymentOption<'_>],
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let verified = runtime.block_on(
        state
            .x402
            .process_payment_with_options(payment_header, offered),
    )?;

    match verified {
        VerifiedExactPayment::Transaction(tx) => {
            let signed_tx = runtime.block_on(sign_fee_payer(tx, state.fee_payer.as_ref()))?;
            let rpc = RpcClient::new(state.rpc_url.clone());
            let simulation = rpc.simulate_transaction(&signed_tx)?;
            if let Some(error) = simulation.value.err {
                return Err(format!("transaction simulation failed: {error:?}").into());
            }
            Ok(rpc.send_and_confirm_transaction(&signed_tx)?.to_string())
        }
        VerifiedExactPayment::Signature(signature) => Ok(signature),
    }
}

async fn sign_fee_payer(
    mut tx: VersionedTransaction,
    fee_payer: &MemorySigner,
) -> Result<VersionedTransaction, Box<dyn std::error::Error + Send + Sync>> {
    let fee_payer_key = fee_payer.pubkey();
    let signer_index = tx
        .message
        .static_account_keys()
        .iter()
        .position(|key| key == &fee_payer_key)
        .ok_or_else(|| "fee payer not found in transaction accounts".to_string())?;
    if signer_index >= tx.signatures.len() {
        return Err("fee payer is not a required transaction signer".into());
    }

    let signature = fee_payer.sign_message(&tx.message.serialize()).await?;
    tx.signatures[signer_index] = Signature::from(<[u8; 64]>::from(signature));
    Ok(tx)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_price_accepts_interop_money_shape() {
        assert_eq!(normalize_price("$0.001").unwrap(), "0.001");
        assert_eq!(normalize_price("0.001 USDC").unwrap(), "0.001");
    }

    #[test]
    fn normalize_price_rejects_invalid_values() {
        assert!(normalize_price("USDC").is_err());
        assert!(normalize_price("1.2.3").is_err());
    }
}
