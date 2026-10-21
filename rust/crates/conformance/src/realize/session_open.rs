//! Session `open` transaction vectors (`input.sessionOpenVerify`): the kit's
//! session server configured from `sessionOpenVerify.server`, the challenge it
//! issues, the kit client's `open` action for that challenge, and the server's
//! offline open checks
//! (`mpp::server::session::testkit::verify_open_transaction_pre_broadcast`).
//!
//! `server` is the verifying server's configuration: `operator`,
//! `recipient`, `currency`, `decimals`, `network`, `amount`,
//! `minimumDeposit`, `suggestedDeposit`, `gracePeriodSeconds` and
//! `transactionVersions` (the versions it accepts for client-submitted
//! `open` / `topUp` transactions and advertises; absent means `[0]`). The
//! challenge's blockhash and slot are pinned ([`BLOCKHASH`], [`RECENT_SLOT`]).

use serde_json::{json, Value};
use solana_pay_kit::core::store::MemoryChannelStore;
use solana_pay_kit::core::tx::{TxV1Mode, TxVersion};
use solana_pay_kit::mpp::client::session::{
    create_payment_channel_session_opener, PaymentChannelOpenOptions,
    PaymentChannelSessionOpenOptions,
};
use solana_pay_kit::mpp::protocol::intents::session::{OpenPayload, SessionAction};
use solana_pay_kit::mpp::server::session::{SessionConfig, SessionServer, VoucherSigner};
use solana_pay_kit::solana_keychain::memory::MemorySigner;

use super::{Observed, Output};
use crate::case::{Case, SessionOpenSpec};
use crate::keys;
use crate::tx::{decode_b64, encode_b64};

/// The challenge's `recentBlockhash` (the server's blockhash cache).
pub const BLOCKHASH: &str = "EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N";
/// The challenge's `recentSlot`, the channel's `openSlot`.
pub const RECENT_SLOT: u64 = 250_000_000;
/// The session (voucher) key the client authorizes; it never signs the
/// open transaction.
pub const SESSION_SIGNER_SEED: [u8; 32] = [13; 32];
/// The channel salt the client picks (deterministic vectors).
pub const SALT: u64 = 7;

fn u64_field(value: &Value, key: &str) -> Result<Option<u64>, String> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => s.parse().map(Some).map_err(|_| format!("invalid {key}")),
        Some(v) => v.as_u64().map(Some).ok_or_else(|| format!("invalid {key}")),
    }
}

/// The session server `server` describes, accepting its `transactionVersions`
/// (the kit's server takes `[0]` or `[0, 1]`).
pub fn server(server: &Value) -> Result<SessionServer<MemoryChannelStore>, String> {
    let text = |key: &str| {
        server
            .get(key)
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| format!("sessionOpenVerify.server.{key} missing"))
    };
    let mut config = SessionConfig {
        operator: text("operator")?,
        recipient: text("recipient")?,
        currency: text("currency")?,
        network: text("network")?,
        decimals: u8::try_from(u64_field(server, "decimals")?.ok_or("decimals missing")?)
            .map_err(|_| "invalid decimals")?,
        amount: u64_field(server, "amount")?.ok_or("amount missing")?,
        minimum_deposit: u64_field(server, "minimumDeposit")?,
        suggested_deposit: u64_field(server, "suggestedDeposit")?,
        voucher_signer: VoucherSigner::Client,
        ..SessionConfig::default()
    };
    if let Some(grace) = u64_field(server, "gracePeriodSeconds")? {
        config.grace_period_seconds =
            u32::try_from(grace).map_err(|_| "invalid gracePeriodSeconds")?;
    }
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
        other => {
            return Err(format!(
                "the kit's session server cannot accept exactly {other:?}"
            ))
        }
    };
    let cache = solana_pay_kit::core::blockhash::BlockhashCache::new();
    cache.set(BLOCKHASH.to_string(), 0, RECENT_SLOT);
    Ok(SessionServer::new(config, MemoryChannelStore::new())
        .with_tx_v1(mode)
        .with_blockhash_cache(cache))
}

/// The kit client's `open` action (JSON) for the challenge `server` issues.
async fn build_open(server_value: &Value) -> Result<Value, String> {
    let request = server(server_value)?
        .build_challenge_request()
        .map_err(|e| format!("session challenge: {e}"))?;
    let payer = MemorySigner::from_bytes(&keys::keypair_bytes(keys::CLIENT_SEED))
        .map_err(|e| e.to_string())?;
    let session = MemorySigner::from_bytes(&keys::keypair_bytes(SESSION_SIGNER_SEED))
        .map_err(|e| e.to_string())?;
    let opened = create_payment_channel_session_opener(
        &request,
        &payer,
        Box::new(session),
        None,
        PaymentChannelSessionOpenOptions {
            open: PaymentChannelOpenOptions {
                salt: Some(SALT),
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .await
    .map_err(|e| format!("session open: {e}"))?;
    match opened.action {
        SessionAction::Open(payload) => serde_json::to_value(payload).map_err(|e| e.to_string()),
        other => Err(format!("opener returned {other:?}")),
    }
}

pub async fn materialize(case: &Case, spec: &SessionOpenSpec) -> Result<Value, String> {
    let mut open = build_open(spec.built_from.as_ref().unwrap_or(&spec.server)).await?;
    if let Some(mutation) = &spec.mutation {
        super::check_pairing(case, mutation)?;
        let tx = decode_b64(open["transaction"].as_str().unwrap_or_default())?;
        open["transaction"] = json!(encode_b64(&mutation.apply(&tx, &[keys::CLIENT_SEED])?)?);
    }
    Ok(json!({
        "signerSecretKey": crate::cases::client_secret(),
        "sessionOpenVerify": {
            "server": spec.server,
            "challengedBlockhash": BLOCKHASH,
            "open": open,
        },
    }))
}

pub async fn verify(input: &Value) -> Result<Observed, String> {
    let params = input
        .get("sessionOpenVerify")
        .ok_or("input.sessionOpenVerify missing")?;
    let srv = match server(params.get("server").unwrap_or(&Value::Null)) {
        Ok(srv) => srv,
        Err(e) => return Ok(Observed::NotExpressible(e)),
    };
    let open: OpenPayload = match serde_json::from_value(params["open"].clone()) {
        Ok(open) => open,
        Err(e) => return Ok(Observed::reject(format!("invalid payload: open: {e}"))),
    };
    let blockhash = params
        .get("challengedBlockhash")
        .and_then(Value::as_str)
        .ok_or("sessionOpenVerify.challengedBlockhash missing")?;
    Ok(
        match solana_pay_kit::mpp::server::session::testkit::verify_open_transaction_pre_broadcast(
            &srv, &open, blockhash,
        )
        .await
        {
            Ok(()) => Observed::Accept(Output::default()),
            Err(e) => Observed::reject(e.to_string()),
        },
    )
}
