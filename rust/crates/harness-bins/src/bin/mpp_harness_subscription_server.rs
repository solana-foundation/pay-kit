//! Harness server for the MPP `subscription` intent, backed by the Rust
//! `SubscriptionServer`.
//!
//! Before it reports ready it publishes its own on-chain `Plan`: the harness
//! fee payer is the plan owner, the puller and the fee payer, and the scenario
//! `MPP_HARNESS_PAY_TO` is the single destination. The Rust server co-signs
//! only the fee-payer slot, so `fee_payer = true` with the fee payer equal to
//! the puller is what gets the puller signature onto the activation.

use std::{
    collections::HashMap,
    env,
    io::{self, BufRead, BufReader, Write},
    net::{TcpListener, TcpStream},
    process,
    sync::Arc,
    thread,
    time::{SystemTime, UNIX_EPOCH},
};

use serde_json::json;
use solana_pay_kit::core::signing::cosign_versioned_fee_payer;
use solana_pay_kit::core::tx::{build_unsigned_unchecked, TxVersion};
use solana_pay_kit::mpp::program::subscriptions::{
    build_create_plan_ix, default_program_id, find_plan_pda, parse_pubkey, plan_id_seed,
    CreatePlanAccounts, CreatePlanData, PlanTerms,
};
use solana_pay_kit::mpp::server::{SubscriptionConfig, SubscriptionServer};
use solana_pay_kit::mpp::{
    format_receipt, format_www_authenticate, parse_authorization, SubscriptionPeriodUnit,
    AUTHORIZATION_HEADER, PAYMENT_RECEIPT_HEADER, WWW_AUTHENTICATE_HEADER,
};
use solana_pay_kit::solana_keychain::{memory::MemorySigner, SolanaSigner};
use solana_rpc_client::rpc_client::RpcClient;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

const HEALTH_PATH: &str = "/health";
const DEFAULT_RESOURCE_PATH: &str = "/subscription";
const DEFAULT_SECRET_KEY: &str = "mpp-harness-secret-key-with-32b-pad";
const DEFAULT_SETTLEMENT_HEADER: &str = "x-subscription-reference";
const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
/// All-zero pubkey: the unused `destinations` / `pullers` slots.
const ZERO_PUBKEY: &str = "11111111111111111111111111111111";
const PLAN_PERIOD_HOURS: u64 = 24;
/// `Plan` layout: discriminator(1) owner(32) bump(1) status(1) plan_id(8)
/// mint(32) amount(8) period_hours(8), then `created_at` (i64 LE).
const PLAN_CREATED_AT_OFFSET: usize = 91;

struct HarnessState {
    server: SubscriptionServer,
    amount: String,
    resource_path: String,
    settlement_header: String,
}

fn write_line(line: &str, to_stderr: bool) {
    let result = if to_stderr {
        writeln!(io::stderr().lock(), "{line}")
    } else {
        let mut stdout = io::stdout().lock();
        writeln!(stdout, "{line}").and_then(|()| stdout.flush())
    };
    if let Err(err) = result {
        if err.kind() == io::ErrorKind::BrokenPipe && !to_stderr {
            // The harness stopped reading; exit instead of panicking.
            process::exit(0);
        }
    }
}

fn main() -> Result<(), BoxError> {
    let runtime = Arc::new(tokio::runtime::Runtime::new()?);
    let state = Arc::new(read_state(&runtime)?);
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    write_line(
        &serde_json::to_string(&json!({
            "type": "ready",
            "implementation": "rust-subscription",
            "role": "server",
            "port": port,
            "capabilities": ["subscription"],
        }))?,
        false,
    );

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let state = Arc::clone(&state);
                let runtime = Arc::clone(&runtime);
                thread::spawn(move || {
                    if let Err(error) = handle_connection(stream, &state, &runtime) {
                        write_line(
                            &format!("harness rust subscription server error: {error}"),
                            true,
                        );
                    }
                });
            }
            Err(error) => write_line(&format!("accept error: {error}"), true),
        }
    }
    Ok(())
}

fn read_state(runtime: &tokio::runtime::Runtime) -> Result<HarnessState, BoxError> {
    let rpc_url = required_env("MPP_HARNESS_RPC_URL")?;
    let mint = required_env("MPP_HARNESS_MINT")?;
    let pay_to = required_env("MPP_HARNESS_PAY_TO")?;
    let amount = required_env("MPP_HARNESS_AMOUNT")?;
    let owner_signer = MemorySigner::from_bytes(&serde_json::from_str::<Vec<u8>>(&required_env(
        "MPP_HARNESS_FEE_PAYER_SECRET_KEY",
    )?)?)?;
    let owner = owner_signer.pubkey();

    // Publish a fresh plan so every run starts from its own subscription PDA.
    let program = default_program_id();
    let zero = parse_pubkey(ZERO_PUBKEY, "zero")?;
    let mint_key = parse_pubkey(&mint, "mint")?;
    let token_program = parse_pubkey(TOKEN_PROGRAM, "token_program")?;
    let plan_id = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos() as u64 & (u64::MAX >> 1);
    let (plan_pda, plan_bump) = find_plan_pda(&owner, &plan_id_seed(plan_id), &program);
    let plan_data = CreatePlanData::new(
        plan_id,
        mint_key,
        PlanTerms {
            amount: amount.parse()?,
            period_hours: PLAN_PERIOD_HOURS,
            created_at: 0,
        },
        0,
        [parse_pubkey(&pay_to, "pay_to")?, zero, zero, zero],
        [zero; 4],
        "",
    )?;
    let create_plan = build_create_plan_ix(
        program,
        CreatePlanAccounts {
            merchant: owner,
            plan_pda,
            token_mint: mint_key,
            token_program,
        },
        &plan_data,
    );
    let rpc = RpcClient::new(rpc_url.clone());
    let mut tx = build_unsigned_unchecked(
        TxVersion::V0,
        &owner,
        &[create_plan],
        rpc.get_latest_blockhash()?,
        None,
    )?;
    runtime.block_on(cosign_versioned_fee_payer(&owner_signer, &owner, &mut tx))?;
    rpc.send_and_confirm_transaction(&tx)?;
    let plan_account = rpc.get_account(&plan_pda)?;
    let created_at = i64::from_le_bytes(
        plan_account.data[PLAN_CREATED_AT_OFFSET..PLAN_CREATED_AT_OFFSET + 8].try_into()?,
    );

    let server = SubscriptionServer::new(SubscriptionConfig {
        plan_id: plan_pda.to_string(),
        mint,
        decimals: match env::var("MPP_HARNESS_DECIMALS") {
            Ok(raw) if !raw.is_empty() => raw.parse()?,
            _ => 6,
        },
        token_program: TOKEN_PROGRAM.to_string(),
        puller: owner.to_string(),
        recipient: pay_to,
        period_unit: SubscriptionPeriodUnit::Day,
        period_count: 1,
        network: env::var("MPP_HARNESS_NETWORK").unwrap_or_else(|_| "localnet".to_string()),
        rpc_url: Some(rpc_url),
        challenge_binding_secret: env::var("MPP_HARNESS_SECRET_KEY")
            .unwrap_or_else(|_| DEFAULT_SECRET_KEY.to_string()),
        realm: "MPP Harness".to_string(),
        // The Rust server signs only the fee-payer slot; with the fee payer
        // equal to the puller that one signature also covers the puller.
        fee_payer: true,
        fee_payer_signer: Some(Arc::new(owner_signer)),
        plan_id_numeric: Some(plan_id),
        plan_bump: Some(plan_bump),
        plan_created_at: Some(created_at),
        ..Default::default()
    })?;

    Ok(HarnessState {
        server,
        amount,
        resource_path: env::var("MPP_HARNESS_RESOURCE_PATH")
            .unwrap_or_else(|_| DEFAULT_RESOURCE_PATH.to_string()),
        settlement_header: env::var("MPP_HARNESS_SETTLEMENT_HEADER")
            .unwrap_or_else(|_| DEFAULT_SETTLEMENT_HEADER.to_string()),
    })
}

fn handle_connection(
    mut stream: TcpStream,
    state: &HarnessState,
    runtime: &tokio::runtime::Runtime,
) -> Result<(), BoxError> {
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

    if (method, path) == ("GET", HEALTH_PATH) {
        return write_json(&mut stream, 200, &[], &json!({ "ok": true }));
    }
    if method != "GET" || path != state.resource_path {
        return write_json(&mut stream, 404, &[], &json!({ "error": "not_found" }));
    }

    let outcome = headers.get(AUTHORIZATION_HEADER).map(|authorization| {
        let credential = parse_authorization(authorization)?;
        let receipt = runtime.block_on(state.server.verify_credential(&credential))?;
        Ok::<_, BoxError>((format_receipt(&receipt)?, receipt.base().reference.clone()))
    });
    match outcome {
        Some(Ok((receipt_header, reference))) => write_json(
            &mut stream,
            200,
            &[
                (PAYMENT_RECEIPT_HEADER, receipt_header.as_str()),
                (state.settlement_header.as_str(), reference.as_str()),
                ("cache-control", "private"),
            ],
            &json!({ "ok": true, "paid": true, "protocol": "subscription", "reference": reference }),
        ),
        Some(Err(error)) => payment_required(&mut stream, state, &error.to_string()),
        None => payment_required(&mut stream, state, "payment_required"),
    }
}

fn payment_required(
    stream: &mut TcpStream,
    state: &HarnessState,
    message: &str,
) -> Result<(), BoxError> {
    let challenge = format_www_authenticate(&state.server.subscription_challenge(&state.amount)?)?;
    write_json(
        stream,
        402,
        &[
            (WWW_AUTHENTICATE_HEADER, challenge.as_str()),
            ("cache-control", "no-store"),
        ],
        &json!({ "code": "payment_invalid", "error": "payment_invalid", "message": message }),
    )
}

fn write_json(
    stream: &mut TcpStream,
    status: u16,
    headers: &[(&str, &str)],
    body: &serde_json::Value,
) -> Result<(), BoxError> {
    let body = serde_json::to_string(body)?;
    let reason = match status {
        200 => "OK",
        402 => "Payment Required",
        _ => "Not Found",
    };
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n",
        body.len()
    )?;
    for (name, value) in headers {
        write!(stream, "{name}: {value}\r\n")?;
    }
    write!(stream, "\r\n{body}")?;
    stream.flush()?;
    Ok(())
}

fn required_env(name: &str) -> Result<String, BoxError> {
    env::var(name).map_err(|_| format!("{name} is required").into())
}
