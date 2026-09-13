//! Shared RPC send policies and the canonical send path.
//!
//! Every transaction leaves the kit through the helpers here, which encode it
//! with [`crate::core::tx::wire`] and hand the base64 string to the RPC
//! method directly. `solana-rpc-client`'s own `send_transaction` and
//! `simulate_transaction` serialize with bincode, which cannot encode a
//! version-1 transaction.
//!
//! Most payment transactions should use the node's default preflight. A few
//! server-side flows already have stronger local/on-chain validation and can
//! hit false-negative preflight simulations when the RPC bank lags a confirmed
//! dependency. Those flows broadcast directly and rely on the existing
//! confirmation/reconciliation path for the durable result.

use std::time::Duration;

use serde_json::json;
use solana_client::rpc_config::{
    RpcSendTransactionConfig, RpcSimulateTransactionConfig, RpcTransactionConfig,
};
use solana_client::rpc_request::RpcRequest;
use solana_client::rpc_response::{Response, RpcSimulateTransactionResult};
use solana_commitment_config::CommitmentConfig;
use solana_rpc_client::rpc_client::RpcClient;
use solana_rpc_client_api::client_error::{Error as ClientError, ErrorKind as ClientErrorKind};
use solana_signature::Signature;
use solana_transaction::versioned::VersionedTransaction;
use solana_transaction_status_client_types::UiTransactionEncoding;

#[derive(Debug, Clone, Copy)]
pub(crate) struct RpcSendPolicy {
    pub(crate) name: &'static str,
    pub(crate) skip_preflight: bool,
}

impl RpcSendPolicy {
    pub(crate) fn config(self) -> RpcSendTransactionConfig {
        RpcSendTransactionConfig {
            skip_preflight: self.skip_preflight,
            ..RpcSendTransactionConfig::default()
        }
    }
}

pub(crate) const SKIP_PREFLIGHT_SEND: RpcSendPolicy = RpcSendPolicy {
    name: "skip_preflight",
    skip_preflight: true,
};

/// `getTransaction` config for reading back a settlement: JSON-parsed, and
/// explicitly accepting transaction version 1. Without
/// `maxSupportedTransactionVersion` the RPC refuses to return any versioned
/// transaction, and with `0` it refuses version 1.
pub fn parsed_transaction_config() -> RpcTransactionConfig {
    RpcTransactionConfig {
        encoding: Some(UiTransactionEncoding::JsonParsed),
        commitment: None,
        max_supported_transaction_version: Some(1),
    }
}

/// Node-default preflight at the client's commitment: what
/// `RpcClient::send_transaction` does.
pub fn preflight_config(rpc: &RpcClient) -> RpcSendTransactionConfig {
    RpcSendTransactionConfig {
        preflight_commitment: Some(rpc.commitment().commitment),
        ..RpcSendTransactionConfig::default()
    }
}

fn encoded(tx: &VersionedTransaction) -> Result<String, ClientError> {
    crate::core::tx::encode(tx)
        .map_err(|e| ClientErrorKind::Custom(format!("transaction encoding failed: {e}")).into())
}

/// Broadcast `tx` with `config`, returning its signature.
pub fn send_transaction(
    rpc: &RpcClient,
    tx: &VersionedTransaction,
    config: RpcSendTransactionConfig,
) -> Result<Signature, ClientError> {
    let config = RpcSendTransactionConfig {
        encoding: Some(UiTransactionEncoding::Base64),
        ..config
    };
    let signature: String = rpc.send(RpcRequest::SendTransaction, json!([encoded(tx)?, config]))?;
    signature
        .parse()
        .map_err(|e| ClientErrorKind::Custom(format!("invalid signature in response: {e}")).into())
}

/// Simulate `tx` at the client's commitment, signatures unchecked: what
/// `RpcClient::simulate_transaction` does.
pub fn simulate_transaction(
    rpc: &RpcClient,
    tx: &VersionedTransaction,
) -> Result<Response<RpcSimulateTransactionResult>, ClientError> {
    let config = RpcSimulateTransactionConfig {
        commitment: Some(rpc.commitment()),
        encoding: Some(UiTransactionEncoding::Base64),
        ..RpcSimulateTransactionConfig::default()
    };
    rpc.send(
        RpcRequest::SimulateTransaction,
        json!([encoded(tx)?, config]),
    )
}

/// Broadcast with node preflight, then poll the signature at the client's
/// commitment every 500 ms until it lands, fails, or its blockhash expires:
/// what `RpcClient::send_and_confirm_transaction` does.
pub fn send_and_confirm_transaction(
    rpc: &RpcClient,
    tx: &VersionedTransaction,
) -> Result<Signature, ClientError> {
    let blockhash = *tx.message.recent_blockhash();
    let signature = send_transaction(rpc, tx, preflight_config(rpc))?;
    loop {
        match rpc.get_signature_status_with_commitment(&signature, rpc.commitment())? {
            Some(Ok(())) => return Ok(signature),
            Some(Err(e)) => return Err(e.into()),
            None => {
                if !rpc.is_blockhash_valid(&blockhash, CommitmentConfig::processed())? {
                    return Err(ClientErrorKind::Custom(
                        "unable to confirm transaction: its blockhash expired".into(),
                    )
                    .into());
                }
                std::thread::sleep(Duration::from_millis(500));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skip_preflight_send_policy_only_skips_preflight() {
        let policy = SKIP_PREFLIGHT_SEND;
        let config = policy.config();

        assert_eq!(policy.name, "skip_preflight");
        assert!(policy.skip_preflight);
        assert!(config.skip_preflight);
        assert_eq!(config.preflight_commitment, None);
        assert_eq!(config.encoding, None);
        assert_eq!(config.max_retries, None);
        assert_eq!(config.min_context_slot, None);
    }
}
