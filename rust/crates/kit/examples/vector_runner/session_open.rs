//! Session `open` verify vectors (`input.sessionOpenVerify`): configure the
//! kit's session server from `sessionOpenVerify.server` and run its offline
//! open checks (`mpp::server::session::testkit`) on the vector's `open`
//! action, against the challenged blockhash.

use serde_json::Value;
use solana_pay_kit::core::store::MemoryChannelStore;
use solana_pay_kit::core::tx::{TxV1Mode, TxVersion};
use solana_pay_kit::mpp::protocol::intents::session::OpenPayload;
use solana_pay_kit::mpp::server::session::{SessionConfig, SessionServer, VoucherSigner};

use super::{Outcome, Rejection};

fn u64_field(value: &Value, key: &str) -> Result<Option<u64>, String> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => s.parse().map(Some).map_err(|_| format!("invalid {key}")),
        Some(v) => v.as_u64().map(Some).ok_or_else(|| format!("invalid {key}")),
    }
}

pub async fn verify(input: &Value) -> Result<Outcome, Rejection> {
    let params = input
        .get("sessionOpenVerify")
        .ok_or("input.sessionOpenVerify missing")?;
    let server = params.get("server").cloned().unwrap_or(Value::Null);
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
        decimals: u8::try_from(u64_field(&server, "decimals")?.ok_or("decimals missing")?)
            .map_err(|_| "invalid decimals")?,
        amount: u64_field(&server, "amount")?.ok_or("amount missing")?,
        minimum_deposit: u64_field(&server, "minimumDeposit")?,
        suggested_deposit: u64_field(&server, "suggestedDeposit")?,
        voucher_signer: VoucherSigner::Client,
        ..SessionConfig::default()
    };
    if let Some(grace) = u64_field(&server, "gracePeriodSeconds")? {
        config.grace_period_seconds =
            u32::try_from(grace).map_err(|_| "invalid gracePeriodSeconds")?;
    }
    // The accepted versions: `TxV1Mode::Off` ([0]) or `On` ([0, 1]).
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
            return Ok(Outcome::Unsupported(format!(
                "the Rust session server cannot accept exactly {other:?} (only [0] or [0, 1])"
            )))
        }
    };
    let server = SessionServer::new(config, MemoryChannelStore::new()).with_tx_v1(mode);
    let open: OpenPayload = serde_json::from_value(params["open"].clone())
        .map_err(|e| format!("invalid payload: open: {e}"))?;
    let blockhash = params
        .get("challengedBlockhash")
        .and_then(Value::as_str)
        .ok_or("sessionOpenVerify.challengedBlockhash missing")?;
    solana_pay_kit::mpp::server::session::testkit::verify_open_transaction_pre_broadcast(
        &server, &open, blockhash,
    )
    .await
    .map_err(|e| Rejection::from(e.to_string()))?;
    Ok(Outcome::Accept(serde_json::Map::new()))
}
