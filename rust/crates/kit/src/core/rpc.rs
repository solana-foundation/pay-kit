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
///
/// The signature is `tx`'s own first (fee-payer) signature, derived locally.
/// A response naming any other signature is an error: the node (or something
/// in between) is reporting on a different transaction, and confirming,
/// claiming or receipting that one would attribute this payment to it.
pub fn send_transaction(
    rpc: &RpcClient,
    tx: &VersionedTransaction,
    config: RpcSendTransactionConfig,
) -> Result<Signature, ClientError> {
    let local = *tx.signatures.first().ok_or_else(|| {
        ClientError::from(ClientErrorKind::Custom(
            "transaction is missing its fee-payer signature".into(),
        ))
    })?;
    let config = RpcSendTransactionConfig {
        encoding: Some(UiTransactionEncoding::Base64),
        ..config
    };
    let signature: String = rpc.send(RpcRequest::SendTransaction, json!([encoded(tx)?, config]))?;
    let returned: Signature = signature.parse().map_err(|e| {
        ClientError::from(ClientErrorKind::Custom(format!(
            "invalid signature in response: {e}"
        )))
    })?;
    if returned != local {
        return Err(ClientErrorKind::Custom(format!(
            "RPC returned signature {returned} for a different transaction (expected {local})"
        ))
        .into());
    }
    Ok(returned)
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
    send_and_confirm_with_outcome(rpc, tx, PriorBroadcast::Possible)
        .map_err(BroadcastFailure::into_error)
}

/// Whether `tx`'s exact bytes may already have reached a node before this
/// broadcast.
///
/// A preflight rejection proves only that *this* send was not forwarded. If an
/// earlier send of the same transaction may have been, the rejection (for
/// instance an expired blockhash, or funds an earlier landing already moved)
/// says nothing about whether the transaction executed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PriorBroadcast {
    /// No earlier send of these bytes can have reached a node.
    None,
    /// An earlier send may have reached a node (a resumed settlement).
    Possible,
}

/// Why [`send_and_confirm_with_outcome`] did not confirm a transaction.
///
/// Only [`BroadcastFailure::NotLanded`] proves the transaction can no longer
/// move funds. A missing signature status is never that proof on its own: the
/// queried node may lag or lack history for a transaction that committed. A caller holding a replay claim on the signature may release
/// it for that variant alone; on [`BroadcastFailure::Unknown`] the
/// transaction may still land and the claim must be kept until the
/// signature's status is reconciled.
#[derive(Debug)]
pub enum BroadcastFailure {
    /// The node's preflight refused the first broadcast of these bytes, so no
    /// node was ever handed the transaction: it can never land.
    NotLanded(ClientError),
    /// It landed and failed; its instructions moved nothing.
    FailedOnChain(ClientError),
    /// The outcome is unknown: a transport error after the request may have
    /// reached the node, a refusal other than a first-broadcast preflight
    /// rejection, a blockhash that expired with no status recorded, or a
    /// failed status/blockhash read.
    Unknown(ClientError),
}

impl BroadcastFailure {
    /// The underlying RPC error.
    pub fn into_error(self) -> ClientError {
        match self {
            Self::NotLanded(error) | Self::FailedOnChain(error) | Self::Unknown(error) => error,
        }
    }
}

impl std::fmt::Display for BroadcastFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotLanded(error) => write!(f, "not landed: {error}"),
            Self::FailedOnChain(error) => write!(f, "failed on-chain: {error}"),
            Self::Unknown(error) => write!(f, "outcome unknown: {error}"),
        }
    }
}

/// Whether a send error is the node's preflight simulation refusing the
/// transaction (JSON-RPC `-32002`): the one send failure that proves the node
/// did not forward it. Matched on the code, so a simulation payload this
/// client cannot decode still counts.
pub(crate) fn is_preflight_rejection(error: &ClientError) -> bool {
    matches!(
        error.kind(),
        ClientErrorKind::RpcError(solana_rpc_client_api::request::RpcError::RpcResponseError {
            code: solana_rpc_client_api::custom_error::JSON_RPC_SERVER_ERROR_SEND_TRANSACTION_PREFLIGHT_FAILURE,
            ..
        })
    )
}

/// [`send_and_confirm_transaction`], classifying a failure by whether the
/// transaction could still land.
///
/// Only an explicit outcome resolves it: a recorded status, or a preflight
/// rejection of a first broadcast ([`PriorBroadcast::None`]). A missing status
/// is never proof of non-execution, even once the blockhash has expired.
pub fn send_and_confirm_with_outcome(
    rpc: &RpcClient,
    tx: &VersionedTransaction,
    prior: PriorBroadcast,
) -> Result<Signature, BroadcastFailure> {
    send_and_confirm_settlement(rpc, tx, prior).map(|settled| match settled {
        Settled::Confirmed(signature) | Settled::AlreadyLanded(signature) => signature,
    })
}

/// How [`send_and_confirm_settlement`] saw a transaction confirm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Settled {
    /// This broadcast (or a resumed earlier one) landed it.
    Confirmed(Signature),
    /// The node's preflight refused the first broadcast of these bytes and
    /// the signature already has a successful status: someone else landed
    /// the same transaction before this caller ever sent it (another server
    /// with its own replay ledger, or a run whose record was lost). A
    /// settlement claimed fresh must not be served again for it.
    AlreadyLanded(Signature),
}

/// [`send_and_confirm_with_outcome`] that also tells a transaction this
/// caller landed from one it found already landed ([`Settled`]).
pub fn send_and_confirm_settlement(
    rpc: &RpcClient,
    tx: &VersionedTransaction,
    prior: PriorBroadcast,
) -> Result<Settled, BroadcastFailure> {
    let blockhash = *tx.message.recent_blockhash();
    let signature = match send_transaction(rpc, tx, preflight_config(rpc)) {
        Ok(signature) => signature,
        // A JSON-RPC error response is the node refusing this send. It may
        // still have landed: the refusal can be the node seeing an earlier
        // send of the same signature. Only a preflight rejection of the first
        // broadcast proves no node was ever handed it; any other refusal, or
        // one after a send that may have been forwarded, leaves it unknown.
        Err(error)
            if matches!(
                error.kind(),
                ClientErrorKind::RpcError(
                    solana_rpc_client_api::request::RpcError::RpcResponseError { .. }
                )
            ) =>
        {
            let Some(&signature) = tx.signatures.first() else {
                return Err(BroadcastFailure::NotLanded(error));
            };
            let never_sent = prior == PriorBroadcast::None && is_preflight_rejection(&error);
            match rpc
                .get_signature_status_with_commitment_and_history(
                    &signature,
                    CommitmentConfig::processed(),
                    true,
                )
                .map_err(BroadcastFailure::Unknown)?
            {
                None if never_sent => return Err(BroadcastFailure::NotLanded(error)),
                None => return Err(BroadcastFailure::Unknown(error)),
                Some(Err(e)) => return Err(BroadcastFailure::FailedOnChain(e.into())),
                // Refused at preflight, so never sent by this caller, yet it
                // landed: the landing is someone else's.
                Some(Ok(())) if never_sent => return Ok(Settled::AlreadyLanded(signature)),
                Some(Ok(())) => signature,
            }
        }
        Err(error) => return Err(BroadcastFailure::Unknown(error)),
    };
    loop {
        match rpc
            .get_signature_status_with_commitment(&signature, rpc.commitment())
            .map_err(BroadcastFailure::Unknown)?
        {
            Some(Ok(())) => return Ok(Settled::Confirmed(signature)),
            Some(Err(e)) => return Err(BroadcastFailure::FailedOnChain(e.into())),
            None => {
                let valid = rpc
                    .is_blockhash_valid(&blockhash, CommitmentConfig::processed())
                    .map_err(BroadcastFailure::Unknown)?;
                if !valid {
                    // It may have landed between the two reads. A status still
                    // missing after expiry is not proof that it never landed:
                    // the queried node may lag or lack its history.
                    match rpc
                        .get_signature_status_with_commitment_and_history(
                            &signature,
                            CommitmentConfig::processed(),
                            true,
                        )
                        .map_err(BroadcastFailure::Unknown)?
                    {
                        None => {
                            return Err(BroadcastFailure::Unknown(
                                ClientErrorKind::Custom(
                                    "blockhash expired with no status recorded for the transaction"
                                        .into(),
                                )
                                .into(),
                            ))
                        }
                        Some(Err(e)) => return Err(BroadcastFailure::FailedOnChain(e.into())),
                        Some(Ok(())) => {}
                    }
                }
                std::thread::sleep(Duration::from_millis(500));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signed_tx(signature: Signature) -> VersionedTransaction {
        let payer = solana_pubkey::Pubkey::new_unique();
        let message = solana_message::Message::new(&[], Some(&payer));
        let mut tx =
            VersionedTransaction::from(solana_transaction::Transaction::new_unsigned(message));
        tx.signatures[0] = signature;
        tx
    }

    fn rpc_answering(signature: Signature) -> RpcClient {
        let mut mocks = std::collections::HashMap::new();
        mocks.insert(
            RpcRequest::SendTransaction,
            serde_json::json!(signature.to_string()),
        );
        RpcClient::new_mock_with_mocks("succeeds".to_string(), mocks)
    }

    #[test]
    fn send_transaction_rejects_a_signature_for_another_transaction() {
        let local = Signature::from([1u8; 64]);
        let tx = signed_tx(local);

        let err = send_transaction(
            &rpc_answering(Signature::from([2u8; 64])),
            &tx,
            RpcSendTransactionConfig::default(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("different transaction"), "{err}");

        let sent = send_transaction(
            &rpc_answering(local),
            &tx,
            RpcSendTransactionConfig::default(),
        )
        .unwrap();
        assert_eq!(sent, local);
    }

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
