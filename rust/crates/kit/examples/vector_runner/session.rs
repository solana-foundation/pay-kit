//! Session server and client vectors (`input.sessionServerVerify`,
//! `input.sessionOpenBuild`). The testee passes the vector's input to the
//! kit unchanged (harness/AGENTS.md "Never put logic in the testee").
//!
//! - verify: a `SessionServer` configured from `sessionServerVerify.server`
//!   over a channel store holding `sessionServerVerify.channel` (the
//!   server's per-channel state), and the client's `credential` parsed with
//!   the kit's wire types (`SessionAction`), then: `open` through
//!   `server::session::testkit::verify_open_pre_broadcast` against
//!   `challenge`, `voucher` through `verify_voucher_for_amount` at the
//!   challenged `amount`, `topUp` through
//!   `testkit::verify_topup_pre_broadcast`, `close` through
//!   `process_close`.
//! - build: `client::session::create_payment_channel_session_opener` on
//!   `sessionOpenBuild.request`, with the salt its options take; the result
//!   carries the `open` action as `sessionCredential`.
//!
//! Mirrors rust/crates/conformance/src/realize/session.rs.

use std::str::FromStr;

use serde_json::{json, Map, Value};
use solana_pay_kit::core::store::{
    ChannelState, ChannelStore, MemoryChannelStore, CHANNEL_STATE_SCHEMA_VERSION,
};
use solana_pay_kit::core::tx::{TxV1Mode, TxVersion};
use solana_pay_kit::mpp::client::session::{
    create_payment_channel_session_opener, PaymentChannelOpenOptions,
    PaymentChannelSessionOpenOptions,
};
use solana_pay_kit::mpp::protocol::intents::session::{
    SessionAction, SessionAuthentication, SessionRequest,
};
use solana_pay_kit::mpp::server::session::{
    testkit, SessionConfig, SessionOpenContext, SessionServer, Split, VoucherSigner,
};
use solana_pay_kit::mpp::solana_keychain::memory::MemorySigner;
use solana_pay_kit::mpp::solana_keychain::SolanaSigner;
use solana_pubkey::Pubkey;

use super::{Outcome, Rejection};

pub async fn run(mode: &str, input: &Value) -> Result<Outcome, Rejection> {
    match mode {
        "verify-transaction" => verify(input).await,
        "build-transaction" => build(input).await,
        other => Ok(Outcome::Unsupported(format!(
            "no Rust runner path for session mode {other:?}"
        ))),
    }
}

fn u64_field(value: &Value, key: &str) -> Result<Option<u64>, String> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => s.parse().map(Some).map_err(|_| format!("invalid {key}")),
        Some(v) => v.as_u64().map(Some).ok_or_else(|| format!("invalid {key}")),
    }
}

fn signer_from(input: &Value, key: &str) -> Result<MemorySigner, String> {
    let bytes: Vec<u8> = input
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("input.{key} missing"))?
        .iter()
        .map(|b| b.as_u64().and_then(|b| u8::try_from(b).ok()))
        .collect::<Option<_>>()
        .ok_or_else(|| format!("input.{key} must be bytes"))?;
    MemorySigner::from_bytes(&bytes).map_err(|e| format!("invalid {key}: {e}"))
}

/// The kit session server `server` describes, over `store`.
fn kit_server(
    server: &Value,
    fee_payer: Option<MemorySigner>,
    store: MemoryChannelStore,
) -> Result<SessionServer<MemoryChannelStore>, String> {
    let text = |key: &str| {
        server
            .get(key)
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| format!("server.{key} missing"))
    };
    let voucher_signer = match server.get("voucherSigner").and_then(Value::as_str) {
        None | Some("client") => VoucherSigner::Client,
        Some("operator") => VoucherSigner::Operator,
        Some(other) => return Err(format!("invalid server.voucherSigner {other:?}")),
    };
    let splits = match server.get("distributionSplits") {
        None | Some(Value::Null) => vec![],
        Some(Value::Array(entries)) => entries
            .iter()
            .map(|entry| {
                Ok(Split {
                    recipient: Pubkey::from_str(entry["recipient"].as_str().unwrap_or_default())
                        .map_err(|e| format!("invalid split recipient: {e}"))?,
                    bps: entry["shareBps"]
                        .as_u64()
                        .and_then(|b| u16::try_from(b).ok())
                        .ok_or("invalid split shareBps")?,
                })
            })
            .collect::<Result<_, String>>()?,
        Some(_) => return Err("server.distributionSplits must be an array".into()),
    };
    let token_program = match server.get("tokenProgram").and_then(Value::as_str) {
        None => None,
        Some(program) => {
            Some(Pubkey::from_str(program).map_err(|e| format!("invalid tokenProgram: {e}"))?)
        }
    };
    let idle_options = match server.get("idleTimeoutOptionsSeconds") {
        None | Some(Value::Null) => None,
        Some(v) => Some(
            serde_json::from_value::<Vec<u32>>(v.clone())
                .map_err(|e| format!("invalid idleTimeoutOptionsSeconds: {e}"))?,
        ),
    };
    let fee_payer_signer: Option<
        std::sync::Arc<dyn solana_pay_kit::solana_keychain::TransactionSigner>,
    > = match (server.get("feePayer").and_then(Value::as_str), fee_payer) {
        (None, _) => None,
        (Some(expected), Some(signer)) => {
            if signer.pubkey().to_string() != expected {
                return Err("sessionServerFeePayerSecretKey is not server.feePayer".into());
            }
            Some(std::sync::Arc::new(signer))
        }
        (Some(_), None) => return Err("server.feePayer without its secret key".into()),
    };
    let config = SessionConfig {
        operator: text("operator")?,
        recipient: text("recipient")?,
        currency: text("currency")?,
        network: text("network")?,
        decimals: u8::try_from(u64_field(server, "decimals")?.ok_or("decimals missing")?)
            .map_err(|_| "invalid decimals")?,
        amount: u64_field(server, "amount")?.ok_or("amount missing")?,
        minimum_deposit: u64_field(server, "minimumDeposit")?,
        suggested_deposit: u64_field(server, "suggestedDeposit")?,
        grace_period_seconds: u32::try_from(
            u64_field(server, "gracePeriodSeconds")?.ok_or("gracePeriodSeconds missing")?,
        )
        .map_err(|_| "invalid gracePeriodSeconds")?,
        idle_timeout_seconds: u32::try_from(
            u64_field(server, "idleTimeoutSeconds")?.ok_or("idleTimeoutSeconds missing")?,
        )
        .map_err(|_| "invalid idleTimeoutSeconds")?,
        idle_timeout_options_seconds: idle_options,
        voucher_signer,
        splits,
        token_program,
        fee_payer_signer,
        ..SessionConfig::default()
    };
    let mut versions: Vec<TxVersion> = match server.get("transactionVersions") {
        None | Some(Value::Null) => vec![TxVersion::V0],
        Some(v) => serde_json::from_value(v.clone())
            .map_err(|e| format!("invalid transactionVersions: {e}"))?,
    };
    versions.sort();
    versions.dedup();
    let mode = match versions.as_slice() {
        [TxVersion::V0] => TxV1Mode::Off,
        [TxVersion::V0, TxVersion::V1] => TxV1Mode::On,
        other => return Err(format!("the kit cannot accept exactly {other:?}")),
    };
    Ok(SessionServer::new(config, store).with_tx_v1(mode))
}

/// The server's per-channel state (`channel`) as the kit stores it.
fn stored_channel(channel: &Value) -> Result<ChannelState, String> {
    let text = |key: &str| {
        channel
            .get(key)
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| format!("channel.{key} missing"))
    };
    let number = |key: &str| -> Result<u64, String> {
        u64_field(channel, key)?.ok_or_else(|| format!("channel.{key} missing"))
    };
    let highest = channel.get("highestVoucher");
    let proof = channel.get("authentication").filter(|v| !v.is_null());
    Ok(ChannelState {
        channel_id: text("channelId")?,
        authorized_signer: text("authorizedSigner")?,
        deposit: number("escrowedAmount")?,
        cumulative: number("acceptedCumulative")?,
        sealed: text("status")? == "closed",
        highest_voucher_signature: highest
            .and_then(|v| v.get("signature"))
            .and_then(Value::as_str)
            .map(str::to_string),
        highest_voucher_expires_at: highest.map(|v| {
            v.pointer("/voucher/expiresAt")
                .and_then(Value::as_i64)
                .unwrap_or(0)
        }),
        close_requested_at: channel.get("closureStartedAt").and_then(Value::as_u64),
        final_cumulative: None,
        open_slot: u64_field(channel, "openSlot")?,
        payer: text("payer")?,
        rent_payer: text("rentPayer")?,
        opening_challenge_id: channel
            .get("openingChallengeId")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        // The proof bound at open, stored as the kit's server stores it.
        authentication: proof
            .map(|v| {
                serde_json::from_value::<SessionAuthentication>(v.clone())
                    .and_then(|a| serde_json::to_string(&a))
                    .map_err(|e| format!("invalid channel.authentication: {e}"))
            })
            .transpose()?,
        voucher_signer: text("voucherSigner")?,
        idle_timeout_seconds: u64_field(channel, "idleTimeoutSeconds")?
            .map(|s| u32::try_from(s).map_err(|_| "invalid idleTimeoutSeconds"))
            .transpose()?,
        last_activity_at: 0,
        spent_amount: number("spentAmount")?,
        settled_on_chain: number("settledOnChain")?,
        distributed_on_chain: 0,
        processed_uses: vec![],
        processed_topup_signatures: vec![],
        next_delivery_sequence: 0,
        pending_deliveries: vec![],
        committed_deliveries: Default::default(),
        pending_setup: None,
        onchain_checked_at: 0,
        lifecycle: None,
        schema_version: CHANNEL_STATE_SCHEMA_VERSION,
        extra: Default::default(),
    })
}

/// The shared code for a kit session server error (mirrors `code_for` in
/// rust/crates/conformance/src/realize/session.rs).
fn code_for(message: &str) -> Option<&'static str> {
    let m = message.to_ascii_lowercase();
    let has = |n: &str| m.contains(n);
    Some(if has("transaction version") && has("not accepted") {
        "unsupported-version"
    } else if has("compute unit price") && (has("exceed") || has("maximum")) {
        "compute-price-over-cap"
    } else if has("compute unit limit") && (has("exceed") || has("maximum")) {
        "compute-limit-over-cap"
    } else if has("invalid payload") || has("unknown field") || has("missing field") {
        "invalid-payload"
    } else if has("client close requires a final voucher")
        || has("client close must not include")
        || has("operator close must not include")
        || has("operator close requires")
    {
        "close-authorization"
    } else if has("authentication") || has("does not authenticate") {
        "authentication-invalid"
    } else if has("fee payer does not match") || has("fee payer must be") {
        "fee-payer-mismatch"
    } else if has("does not match the derived channel pda")
        || has("does not match derived channel pda")
        || has("action channelid does not match")
        || has("close voucher channelid does not match")
        || has("do not match the stored channel")
    {
        "channel-id-mismatch"
    } else if has("unexpected instruction")
        || has("does not contain the expected open instruction")
        || has("top-up instruction not found")
        || has("unsupported compute budget")
    {
        "unexpected-instruction"
    } else if has("below minimumdeposit")
        || has("deposit must be greater than zero")
        || has("additionalamount must be positive")
        || has("does not match additionalamount")
        || has("insufficient authorized voucher availability")
    {
        "amount-mismatch"
    } else if has("open transaction")
        || has("open instruction")
        || has("payment-channel open")
        || has("opensl")
        || has("idletimeoutseconds")
        || has("authorizedsigner")
        || has("privileges")
    {
        "open-binding-mismatch"
    } else if has("signature verification failed")
        || has("signer does not match")
        || has("invalid voucher signature")
    {
        "voucher-signature"
    } else if has("must exceed watermark") || has("already accepted") {
        "cumulative-amount-mismatch"
    } else if has("exceeds deposit") {
        "cumulative-exceeds-deposit"
    } else if has("voucher has expired") {
        "voucher-expired"
    } else if has("settlement window") {
        "voucher-expires-before-settlement"
    } else if has("close is pending") || has("close already requested") {
        "channel-closing"
    } else if has("already sealed") || has("closed or close") {
        "close-state"
    } else if has("not found") {
        "channel-state"
    } else if has("address lookup tables")
        || has("byte limit")
        || has("session transaction")
        || has("invalid")
        || has("decode")
    {
        "invalid-payload"
    } else {
        return None;
    })
}

fn reject(message: String) -> Rejection {
    let code = code_for(&message);
    Rejection { message, code }
}

async fn verify(input: &Value) -> Result<Outcome, Rejection> {
    let Some(params) = input.get("sessionServerVerify") else {
        return Ok(Outcome::Unsupported(
            "session verify vector without sessionServerVerify".into(),
        ));
    };
    let store = MemoryChannelStore::new();
    if let Some(channel) = params.get("channel") {
        let state = stored_channel(channel)?;
        store
            .put_channel(&state.channel_id.clone(), state)
            .await
            .map_err(|e| format!("seed channel: {e}"))?;
    }
    let fee_payer = input
        .get("sessionServerFeePayerSecretKey")
        .map(|_| signer_from(input, "sessionServerFeePayerSecretKey"))
        .transpose()?;
    let server_json = params.get("server").cloned().unwrap_or(Value::Null);
    let server = match kit_server(&server_json, fee_payer, store) {
        Ok(server) => server,
        Err(e) => return Ok(Outcome::Unsupported(e)),
    };
    let action: SessionAction = serde_json::from_value(params["credential"].clone())
        .map_err(|e| reject(format!("invalid payload: session credential: {e}")))?;
    let result = match &action {
        SessionAction::Open(open) => {
            let challenge = params.get("challenge").ok_or("challenge missing")?;
            let recent_slot = u64_field(challenge, "recentSlot")?.ok_or("recentSlot missing")?;
            testkit::verify_open_pre_broadcast(
                &server,
                open,
                SessionOpenContext {
                    challenge_id: challenge["id"].as_str().unwrap_or_default(),
                    expires: None,
                    recent_blockhash: challenge["recentBlockhash"].as_str().unwrap_or_default(),
                    recent_slot,
                },
            )
            .await
        }
        SessionAction::Voucher(voucher) => {
            let amount = u64_field(&server_json, "amount")?.ok_or("amount missing")?;
            server
                .verify_voucher_for_amount(voucher, amount)
                .await
                .map(|_| ())
        }
        SessionAction::TopUp(topup) => testkit::verify_topup_pre_broadcast(&server, topup).await,
        SessionAction::Close(close) => server.process_close(close).await.map(|_| ()),
        SessionAction::Use(_) => {
            return Ok(Outcome::Unsupported(
                "the use action needs an Idempotency-Key and the operator signing key".into(),
            ))
        }
    };
    result.map_err(|e| reject(e.to_string()))?;
    Ok(Outcome::Accept(Map::new()))
}

/// The shared code for a kit session client refusal (mirrors
/// `build_code_for` in rust/crates/conformance/src/realize/session.rs).
fn build_code_for(message: &str) -> Option<&'static str> {
    let m = message.to_ascii_lowercase();
    let has = |n: &str| m.contains(n);
    (has("challenge")
        || has("network")
        || has("program")
        || has("tokenprogram")
        || has("feepayerkey")
        || has("operator")
        || has("spl token")
        || has("graceperiod")
        || has("decimals")
        || has("invalid"))
    .then_some("invalid-challenge")
}

async fn build(input: &Value) -> Result<Outcome, Rejection> {
    let Some(params) = input.get("sessionOpenBuild") else {
        return Ok(Outcome::Unsupported(
            "session build vector without sessionOpenBuild".into(),
        ));
    };
    let refuse = |message: String| {
        let code = build_code_for(&message);
        Rejection { message, code }
    };
    let request: SessionRequest = serde_json::from_value(params["request"].clone())
        .map_err(|e| refuse(format!("invalid challenge: {e}")))?;
    let payer = signer_from(input, "signerSecretKey")?;
    let session = signer_from(input, "sessionSignerSecretKey")?;
    let opened = create_payment_channel_session_opener(
        &request,
        &payer,
        Box::new(session),
        None,
        PaymentChannelSessionOpenOptions {
            open: PaymentChannelOpenOptions {
                salt: u64_field(params, "salt")?,
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .await
    .map_err(|e| refuse(e.to_string()))?;
    let action = serde_json::to_value(&opened.action).map_err(|e| e.to_string())?;
    let mut out = Map::new();
    out.insert("sessionCredential".into(), json!(action.to_string()));
    Ok(Outcome::Accept(out))
}
