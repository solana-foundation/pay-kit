//! MPP `session` harness client (wire-only path).
//!
//! Mirrors `harness/python-session-client` and the TypeScript
//! `session-client.ts` fixture against the Python session server:
//!
//!   GET /session → 402 WWW-Authenticate (intent=session)
//!   Authorization: Payment open → 200
//!   POST /__402/session/deliveries → reserve
//!   POST /__402/session/commit → voucher
//!   POST /__402/session/close → settlement reference
//!
//! Status is **402 Payment Required**, not 401. Authorization scheme is
//! `Payment <base64url>` (not `MPP credential=`). Env: `MPP_HARNESS_*`,
//! including `MPP_HARNESS_DELIVERY_COUNT` (default 1; multi-delivery sets 3).

use std::{
    collections::HashMap,
    env,
    io::{self, Write},
    process,
};

use serde_json::json;
use solana_keypair::Keypair;
use solana_pay_kit::mpp::client::{
    create_payment_channel_session_opener, PaymentChannelSessionOpenOptions,
};
use solana_pay_kit::mpp::protocol::core::{format_authorization, PaymentCredential};
use solana_pay_kit::mpp::protocol::intents::session::{
    ClosePayload, SessionAction, SessionRequest,
};
use solana_pay_kit::mpp::{
    parse_www_authenticate_all, AUTHORIZATION_HEADER, WWW_AUTHENTICATE_HEADER,
};
use solana_pay_kit::solana_keychain::memory::MemorySigner;
use solana_pay_kit::solana_keychain::SolanaSigner;

const DEFAULT_SETTLEMENT_HEADER: &str = "x-session-settlement-signature";

/// Write a line to stdout, swallowing `BrokenPipe` (EPIPE) like the charge client.
fn write_stdout_line(line: &str) {
    let stdout = io::stdout();
    let mut handle = stdout.lock();
    match writeln!(handle, "{line}") {
        Ok(()) => {
            let _ = handle.flush();
        }
        Err(err) if err.kind() == io::ErrorKind::BrokenPipe => process::exit(0),
        Err(err) => panic!("failed printing to stdout: {err}"),
    }
}

fn emit_result(
    ok: bool,
    status: u16,
    headers: HashMap<String, String>,
    body: serde_json::Value,
    settlement: Option<String>,
    error: Option<String>,
) {
    let mut map = json!({
        "type": "result",
        "implementation": "rust",
        "role": "client",
        "ok": ok,
        "status": status,
        "responseHeaders": headers,
        "responseBody": body,
    });
    if let Some(s) = settlement {
        map["settlement"] = json!(s);
    }
    if let Some(e) = error {
        map["error"] = json!(e);
    }
    write_stdout_line(&map.to_string());
}

fn random_memory_signer() -> Result<MemorySigner, Box<dyn std::error::Error + Send + Sync>> {
    // Ephemeral harness wallets — no secret is injected for session-basic
    // (Python/TS fixtures also generate throwaway keypairs).
    let kp = Keypair::new();
    Ok(MemorySigner::from_bytes(&kp.to_bytes())?)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if let Err(err) = run().await {
        emit_result(
            false,
            0,
            HashMap::new(),
            serde_json::Value::Null,
            None,
            Some(err.to_string()),
        );
    }
    Ok(())
}

async fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let target_url = read_required_env("MPP_HARNESS_TARGET_URL")?;
    let amount: u64 = env::var("MPP_HARNESS_AMOUNT")
        .unwrap_or_else(|_| "700".into())
        .parse()
        .map_err(|_| "MPP_HARNESS_AMOUNT must be a u64".to_string())?;
    let delivery_count: usize = env::var("MPP_HARNESS_DELIVERY_COUNT")
        .unwrap_or_else(|_| "1".into())
        .parse()
        .map_err(|_| "MPP_HARNESS_DELIVERY_COUNT must be a usize".to_string())?;
    if delivery_count < 1 {
        return Err("MPP_HARNESS_DELIVERY_COUNT must be >= 1".into());
    }
    let settlement_header = env::var("MPP_HARNESS_SETTLEMENT_HEADER")
        .unwrap_or_else(|_| DEFAULT_SETTLEMENT_HEADER.to_string());

    let base = target_url
        .rsplit_once('/')
        .map(|(b, _)| b.to_string())
        .unwrap_or_else(|| target_url.clone());
    let reserve_url = format!("{base}/__402/session/deliveries");
    let commit_url = format!("{base}/__402/session/commit");
    let close_url = format!("{base}/__402/session/close");

    let http = reqwest::Client::new();

    // ── 1) Unauthenticated GET → expect 402 + session challenge ────────────
    let first = http.get(&target_url).send().await?;
    let first_status = first.status().as_u16();
    // Keep multi-value headers as a Vec so every WWW-Authenticate is visible
    // to parse_www_authenticate_all (HashMap would collapse duplicates).
    let first_header_pairs = response_headers(first.headers())?;
    let first_headers = headers_to_map(first_header_pairs.clone());
    let first_body_raw = first.text().await?;
    let first_body = parse_body(&first_body_raw);

    if first_status != 402 {
        emit_result(
            false,
            first_status,
            first_headers,
            first_body,
            None,
            Some("expected 402 session challenge".into()),
        );
        return Ok(());
    }

    let challenge_values = first_header_pairs
        .iter()
        .filter(|(name, _)| name == WWW_AUTHENTICATE_HEADER)
        .map(|(_, value)| value.as_str());
    let challenge = parse_www_authenticate_all(challenge_values)
        .into_iter()
        .filter_map(Result::ok)
        .find(|c| c.method.as_str() == "solana" && c.intent.as_str() == "session")
        .ok_or_else(|| "server did not return a solana/session Payment challenge".to_string())?;

    let request: SessionRequest = challenge
        .request
        .decode()
        .map_err(|e| format!("decode session challenge request: {e}"))?;

    // ── 2) Build open action (client-built open tx; harness server wire-only) ─
    let payer = random_memory_signer()?;
    let session_signer: Box<dyn SolanaSigner> = Box::new(random_memory_signer()?);
    let opened = create_payment_channel_session_opener(
        &request,
        &payer,
        session_signer,
        None, // use challenged recentBlockhash/slot
        PaymentChannelSessionOpenOptions::default(),
    )
    .await
    .map_err(|e| format!("create_payment_channel_session_opener: {e}"))?;

    let open_auth = format_authorization(&PaymentCredential::new(
        challenge.to_echo(),
        &opened.action,
    ))
    .map_err(|e| format!("format open authorization: {e}"))?;

    let open_resp = http
        .get(&target_url)
        .header(AUTHORIZATION_HEADER, &open_auth)
        .send()
        .await?;
    let open_status = open_resp.status().as_u16();
    let open_headers = headers_to_map(response_headers(open_resp.headers())?);
    let open_body = parse_body(&open_resp.text().await?);
    if !(200..300).contains(&open_status) {
        emit_result(
            false,
            open_status,
            open_headers,
            open_body,
            None,
            Some("session open rejected".into()),
        );
        return Ok(());
    }

    let mut session = opened.session;
    let channel_id = session.channel_id_str();

    // ── 3–4) Reserve + commit N times (cumulative watermark) ───────────────
    // session-basic: DELIVERY_COUNT=1. session-multi-delivery: 3 × amount.
    let mut last_voucher = None;
    for _ in 0..delivery_count {
        let reserve_resp = http
            .post(&reserve_url)
            .json(&json!({ "sessionId": channel_id, "amount": amount.to_string() }))
            .send()
            .await?;
        let reserve_status = reserve_resp.status().as_u16();
        let reserve_headers = headers_to_map(response_headers(reserve_resp.headers())?);
        let reserve_body = parse_body(&reserve_resp.text().await?);
        let delivery_id = reserve_body
            .get("deliveryId")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        if !(200..300).contains(&reserve_status) || delivery_id.is_none() {
            emit_result(
                false,
                reserve_status,
                reserve_headers,
                reserve_body,
                None,
                Some("session delivery reserve failed".into()),
            );
            return Ok(());
        }
        let delivery_id = delivery_id.unwrap();

        let voucher = session
            .prepare_increment(amount)
            .await
            .map_err(|e| format!("prepare_increment: {e}"))?;
        let commit_resp = http
            .post(&commit_url)
            .json(&json!({
                "deliveryId": delivery_id,
                "voucher": voucher,
            }))
            .send()
            .await?;
        let commit_status = commit_resp.status().as_u16();
        let commit_headers = headers_to_map(response_headers(commit_resp.headers())?);
        let commit_body = parse_body(&commit_resp.text().await?);
        if !(200..300).contains(&commit_status) {
            emit_result(
                false,
                commit_status,
                commit_headers,
                commit_body,
                None,
                Some("session commit failed".into()),
            );
            return Ok(());
        }
        session
            .record_voucher(&voucher)
            .map_err(|e| format!("record_voucher: {e}"))?;
        last_voucher = Some(voucher);
    }
    let voucher = last_voucher.ok_or("no voucher produced")?;

    // ── 5) Close with the last committed (highest-watermark) voucher ───────
    let close_action = SessionAction::Close(ClosePayload {
        channel_id: channel_id.clone(),
        authentication: None,
        voucher: Some(voucher),
    });
    let close_auth = format_authorization(&PaymentCredential::new(
        challenge.to_echo(),
        &close_action,
    ))
    .map_err(|e| format!("format close authorization: {e}"))?;

    let close_resp = http
        .post(&close_url)
        .header(AUTHORIZATION_HEADER, &close_auth)
        .send()
        .await?;
    let close_status = close_resp.status().as_u16();
    let close_headers = headers_to_map(response_headers(close_resp.headers())?);
    let close_body_raw = close_resp.text().await?;
    let close_body = parse_body(&close_body_raw);

    let mut settlement = close_body
        .get("reference")
        .or_else(|| close_body.get("settledSignature"))
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .unwrap_or_default();
    if settlement.is_empty() {
        settlement = close_headers
            .get(&settlement_header)
            .cloned()
            .unwrap_or_default();
    }

    emit_result(
        (200..300).contains(&close_status),
        close_status,
        close_headers,
        close_body,
        if settlement.is_empty() {
            None
        } else {
            Some(settlement)
        },
        None,
    );
    Ok(())
}

fn parse_body(raw: &str) -> serde_json::Value {
    serde_json::from_str(raw).unwrap_or_else(|_| json!(raw))
}

fn response_headers(
    headers: &reqwest::header::HeaderMap,
) -> Result<Vec<(String, String)>, Box<dyn std::error::Error + Send + Sync>> {
    headers
        .iter()
        .map(|(name, value)| {
            Ok((
                name.as_str().to_ascii_lowercase(),
                value.to_str()?.to_string(),
            ))
        })
        .collect()
}

fn headers_to_map(headers: Vec<(String, String)>) -> HashMap<String, String> {
    headers.into_iter().collect()
}

fn read_required_env(name: &str) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    env::var(name).map_err(|_| format!("{name} is required").into())
}
