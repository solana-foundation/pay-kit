//! Outcome verification for the opt-in channel charge, before co-signing and
//! after confirmation. A successful `distribute` can redirect an invalid
//! beneficiary ATA to treasury, so its instruction arguments are not a receipt.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use solana_rpc_client_api::request::RpcRequest;
use solana_transaction::versioned::VersionedTransaction;

use super::charge::{Mpp, VerificationError};
use crate::core::{payment_channel::v1, tx};
use crate::mpp::protocol::{core::ChallengeEcho, intents::ChargeRequest, solana::MethodDetails};

fn invalid(message: impl Into<String>) -> VerificationError {
    VerificationError::invalid_payload(message)
}

#[derive(Serialize, Deserialize)]
struct Submission {
    credential_transaction: String,
    signed_transaction: String,
    signature: String,
    settlement: ChannelChargeSettlement,
}

/// Operational metadata for payment reconciliation and channel-rent recovery.
/// The escrow ATA closes atomically, but the Distributed channel remains until
/// `current_slot > open_slot + 1500` and needs permissionless reclaim.
/// This metadata alone does not prove payment confirmation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelChargeSettlement {
    pub channel: String,
    pub channel_program: String,
    pub channel_version: u8,
    pub rent_payer: String,
    pub open_slot: u64,
    pub signature: String,
}

fn submission_key(id: &str) -> String {
    format!("solana-channel-charge:submitted:{id}")
}
fn receipt_key(id: &str) -> String {
    format!("solana-channel-charge:receipt:{id}")
}

fn pending(signature: &str, error: impl std::fmt::Display) -> VerificationError {
    VerificationError::settlement_in_progress(format!(
        "Channel transaction {signature} requires outcome reconciliation; do not pay again: {error}",
    ))
}

/// Recheck after simulation and immediately before each send attempt. The
/// write-ahead record remains available for reconciliation after expiry.
pub(crate) fn ensure_send_allowed(
    challenge: &ChallengeEcho,
    transaction: &VersionedTransaction,
) -> Result<(), VerificationError> {
    let expires = challenge
        .expires
        .as_deref()
        .ok_or_else(|| invalid("missing channel expiry"))?;
    let expires =
        time::OffsetDateTime::parse(expires, &time::format_description::well_known::Rfc3339)
            .map_err(|e| invalid(e.to_string()))?;
    if expires <= time::OffsetDateTime::now_utc() {
        let signature = transaction
            .signatures
            .first()
            .ok_or_else(|| invalid("missing channel signature"))?;
        return Err(pending(
            &signature.to_string(),
            "challenge expired; only already-landed outcome reconciliation is permitted",
        ));
    }
    Ok(())
}

fn validate_metadata(
    meta: &Value,
    transaction: &VersionedTransaction,
    challenge: &ChallengeEcho,
) -> Result<(), VerificationError> {
    let request: ChargeRequest = challenge
        .request
        .decode()
        .map_err(|e| invalid(e.to_string()))?;
    let details: MethodDetails = serde_json::from_value(
        request
            .method_details
            .ok_or_else(|| invalid("missing channel methodDetails"))?,
    )
    .map_err(|e| invalid(e.to_string()))?;
    let mint = v1::parse_pubkey(&request.currency).map_err(|e| invalid(e.to_string()))?;
    let token = v1::parse_pubkey(crate::mpp::protocol::solana::programs::TOKEN_PROGRAM)
        .map_err(|e| invalid(e.to_string()))?;
    let total = request
        .amount
        .parse::<u64>()
        .map_err(|_| invalid("invalid channel total"))?;
    let splits = details.splits.unwrap_or_default();
    let mut primary = total;
    let mut expected = Vec::new();
    for split in splits {
        let amount = split
            .amount
            .parse::<u64>()
            .map_err(|_| invalid("invalid channel split"))?;
        primary = primary
            .checked_sub(amount)
            .ok_or_else(|| invalid("channel splits exceed total"))?;
        let owner = v1::parse_pubkey(&split.recipient).map_err(|e| invalid(e.to_string()))?;
        expected.push((
            v1::find_associated_token_address(&owner, &mint, &token)
                .0
                .to_string(),
            owner.to_string(),
            amount,
        ));
    }
    let owner = v1::parse_pubkey(
        request
            .recipient
            .as_deref()
            .ok_or_else(|| invalid("missing recipient"))?,
    )
    .map_err(|e| invalid(e.to_string()))?;
    expected.push((
        v1::find_associated_token_address(&owner, &mint, &token)
            .0
            .to_string(),
        owner.to_string(),
        primary,
    ));
    let keys: Vec<String> = transaction
        .message
        .static_account_keys()
        .iter()
        .map(ToString::to_string)
        .collect();
    crate::mpp::protocol::channel_charge_outcome::validate_channel_charge_outcome(
        meta,
        &keys,
        &mint.to_string(),
        &expected,
    )
    .map_err(|e| invalid(e.to_string()))
}

impl Mpp {
    /// Immutable write-ahead record. This uses the store's existing atomic
    /// insert, not the lease-reclaiming native-charge reservation. It is never
    /// replaced by a new message, even across crashes and concurrent retries.
    pub(crate) async fn record_channel_submission(
        &self,
        challenge: &ChallengeEcho,
        original: &str,
        signed: &VersionedTransaction,
    ) -> Result<(), VerificationError> {
        let request: ChargeRequest = challenge
            .request
            .decode()
            .map_err(|e| invalid(e.to_string()))?;
        let details: MethodDetails = serde_json::from_value(
            request
                .method_details
                .ok_or_else(|| invalid("missing channel details"))?,
        )
        .map_err(|e| invalid(e.to_string()))?;
        let profile = details
            .channel_charge
            .ok_or_else(|| invalid("missing channel profile"))?;
        let open = signed
            .message
            .instructions()
            .first()
            .ok_or_else(|| invalid("missing channel open"))?;
        let keys = signed.message.static_account_keys();
        let account = |position: usize| {
            open.accounts
                .get(position)
                .and_then(|index| keys.get(*index as usize))
                .map(ToString::to_string)
                .ok_or_else(|| invalid("invalid channel account index"))
        };
        let signature = signed
            .signatures
            .first()
            .ok_or_else(|| invalid("missing channel signature"))?
            .to_string();
        let submission = Submission {
            credential_transaction: original.into(),
            signed_transaction: tx::encode(signed).map_err(|e| invalid(e.to_string()))?,
            signature: signature.clone(),
            settlement: ChannelChargeSettlement {
                channel: account(5)?,
                channel_program: profile.channel_program,
                channel_version: profile.channel_version,
                rent_payer: account(1)?,
                open_slot: profile.recent_slot,
                signature,
            },
        };
        let inserted = self
            .store
            .put_if_absent(
                &submission_key(&challenge.id),
                serde_json::to_value(&submission).map_err(|e| invalid(e.to_string()))?,
            )
            .await
            .map_err(|e| {
                VerificationError::new(format!("Cannot persist channel submission: {e}"))
            })?;
        if !inserted {
            return Err(pending(
                &submission.signature,
                "another request already owns this submission",
            ));
        }
        Ok(())
    }

    /// Read persisted operational metadata after submission or settlement.
    /// Queue the channel for permissionless reclaim after its slot window.
    /// Keep this separate from session authorization: a charge is not a session.
    pub async fn channel_charge_settlement(
        &self,
        challenge_id: &str,
    ) -> Result<Option<ChannelChargeSettlement>, VerificationError> {
        self.store
            .get(&submission_key(challenge_id))
            .await
            .map_err(|e| VerificationError::new(format!("Cannot read channel settlement: {e}")))?
            .map(|value| {
                serde_json::from_value::<Submission>(value)
                    .map(|submission| submission.settlement)
                    .map_err(|e| invalid(e.to_string()))
            })
            .transpose()
    }

    /// Exactly one concurrent initial attempt or reconciliation may issue a
    /// receipt. A crash after this claim is conservative: payment stays consumed.
    pub(crate) async fn claim_channel_receipt(
        &self,
        id: &str,
        signature: &str,
    ) -> Result<(), VerificationError> {
        let claimed = self
            .store
            .put_if_absent(&receipt_key(id), json!({"signature":signature}))
            .await
            .map_err(|e| pending(signature, e))?;
        if !claimed {
            return Err(VerificationError::signature_consumed(
                "Transaction signature already consumed",
            ));
        }
        Ok(())
    }

    /// Recover only the recorded signed bytes. A pre-broadcast crash can resend
    /// the identical transaction, never refresh its blockhash or sign a new one.
    pub(crate) async fn reconcile_channel_submission(
        &self,
        challenge: &ChallengeEcho,
        original: &str,
    ) -> Result<Option<String>, VerificationError> {
        let Some(value) = self
            .store
            .get(&submission_key(&challenge.id))
            .await
            .map_err(|e| VerificationError::new(format!("Cannot read channel submission: {e}")))?
        else {
            return Ok(None);
        };
        let submission: Submission =
            serde_json::from_value(value).map_err(|e| invalid(e.to_string()))?;
        if submission.credential_transaction != original {
            return Err(VerificationError::challenge_conflict(
                "Channel challenge was submitted with a different credential",
            ));
        }
        if self
            .store
            .get(&receipt_key(&challenge.id))
            .await
            .map_err(|e| pending(&submission.signature, e))?
            .is_some()
        {
            return Err(VerificationError::signature_consumed(
                "Transaction signature already consumed",
            ));
        }
        let signed =
            tx::decode(&submission.signed_transaction).map_err(|e| invalid(e.to_string()))?;
        let config = self
            .channel_charge
            .as_ref()
            .ok_or_else(|| invalid("channel charges are disabled"))?;
        crate::mpp::protocol::channel_charge::verify_transaction(&signed, challenge, &config.hooks)
            .map_err(|e| invalid(e.to_string()))?;
        signed
            .verify_and_hash_message()
            .map_err(|e| invalid(e.to_string()))?;
        if signed
            .signatures
            .first()
            .map(ToString::to_string)
            .as_deref()
            != Some(&submission.signature)
        {
            return Err(invalid("stored channel signature mismatch"));
        }
        if !self
            .confirmed_channel_outcome(&submission.signature, original, challenge)
            .map_err(|e| pending(&submission.signature, e))?
        {
            ensure_send_allowed(challenge, &signed)?;
            self.simulate_channel_charge(&signed, challenge)
                .map_err(|e| pending(&submission.signature, e))?;
            ensure_send_allowed(challenge, &signed)?;
            let signature = crate::core::rpc::send_transaction(
                &self.rpc,
                &signed,
                crate::core::rpc::preflight_config(&self.rpc),
            )
            .map_err(|e| pending(&submission.signature, e))?;
            if signature.to_string() != submission.signature {
                return Err(pending(
                    &submission.signature,
                    "RPC returned another transaction signature",
                ));
            }
            self.await_pull_confirmation(&submission.signature)
                .map_err(|e| pending(&submission.signature, e))?;
            self.verify_confirmed_channel_charge(&submission.signature, original, challenge)
                .map_err(|e| pending(&submission.signature, e))?;
        }
        self.claim_channel_receipt(&challenge.id, &submission.signature)
            .await?;
        Ok(Some(submission.signature))
    }

    /// The unsigned server slots are intentional. Client/voucher signatures have
    /// already been checked locally. Never replace the signed recent blockhash.
    pub(crate) fn simulate_channel_charge(
        &self,
        transaction: &VersionedTransaction,
        challenge: &ChallengeEcho,
    ) -> Result<(), VerificationError> {
        let encoded = tx::encode(transaction).map_err(|e| invalid(e.to_string()))?;
        let response: Value = self
            .rpc
            .send(
                RpcRequest::SimulateTransaction,
                json!([
                    encoded,
                    {
                        "encoding": "base64",
                        "commitment": "confirmed",
                        "sigVerify": false,
                        "replaceRecentBlockhash": false,
                        "innerInstructions": true
                    }
                ]),
            )
            .map_err(|e| {
                VerificationError::network_error(format!("Channel simulation RPC failed: {e}"))
            })?;
        let meta = response
            .get("value")
            .ok_or_else(|| invalid("missing channel simulation value"))?;
        validate_metadata(meta, transaction, challenge)
    }

    /// Require the exact submitted transaction and its successful, complete,
    /// confirmed token balance evidence before issuing the charge receipt.
    pub(crate) fn verify_confirmed_channel_charge(
        &self,
        signature: &str,
        submitted: &str,
        challenge: &ChallengeEcho,
    ) -> Result<(), VerificationError> {
        if self.confirmed_channel_outcome(signature, submitted, challenge)? {
            Ok(())
        } else {
            Err(pending(
                signature,
                "confirmed transaction metadata is not available",
            ))
        }
    }

    fn confirmed_channel_outcome(
        &self,
        signature: &str,
        submitted: &str,
        challenge: &ChallengeEcho,
    ) -> Result<bool, VerificationError> {
        let response: Value = self
            .rpc
            .send(
                RpcRequest::GetTransaction,
                json!([
                    signature,
                    {
                        "encoding": "base64",
                        "commitment": "confirmed",
                        "maxSupportedTransactionVersion": 1
                    }
                ]),
            )
            .map_err(|e| {
                VerificationError::network_error(format!("Channel outcome RPC failed: {e}"))
            })?;
        if response.is_null() {
            return Ok(false);
        }
        let encoded = response
            .get("transaction")
            .and_then(Value::as_array)
            .filter(|pair| pair.len() == 2 && pair[1].as_str() == Some("base64"))
            .and_then(|pair| pair[0].as_str())
            .ok_or_else(|| invalid("missing confirmed channel transaction"))?;
        let actual = tx::decode(encoded).map_err(|e| invalid(e.to_string()))?;
        let submitted = tx::decode(submitted).map_err(|e| invalid(e.to_string()))?;
        if actual.message != submitted.message
            || actual
                .signatures
                .first()
                .map(ToString::to_string)
                .as_deref()
                != Some(signature)
        {
            return Err(invalid("confirmed channel transaction mismatch"));
        }
        actual
            .verify_and_hash_message()
            .map_err(|e| invalid(format!("invalid confirmed signatures: {e}")))?;
        let meta = response
            .get("meta")
            .ok_or_else(|| invalid("missing confirmed channel metadata"))?;
        validate_metadata(meta, &actual, challenge)?;
        Ok(true)
    }
}
