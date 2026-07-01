//! Token-2022 confidential-transfer settlement (opt-in `confidential` feature).
//!
//! Split out of `charge.rs` (behavior-preserving move): gateway-paid bundle
//! settlement (`Mpp::settle_confidential_bundle`), the orphan sweeper
//! (`Mpp::sweep_confidential_orphans` + `broadcast_close`), and the per-tx
//! bundle allow-list (`verify_confidential_bundle_tx`). The rest of the charge
//! handler — and the shared helpers this module imports — stays in `charge.rs`.

use std::str::FromStr;

use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_transaction::{versioned::VersionedTransaction, Transaction};

use crate::mpp::protocol::intents::ChargeRequest;
use crate::mpp::protocol::solana::{programs, MethodDetails};
use crate::mpp::store::Store;

use super::charge::{
    check_network_blockhash, decode_compute_budget_op, reject_address_lookup_tables,
    resolve_expected_mint, ComputeBudgetOp, Mpp, VerificationError, COMPUTE_BUDGET_PROGRAM,
    MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS_FEE_SPONSORED,
};

/// Upper bound on transactions in a gateway-paid confidential bundle. The
/// builder emits ~5 (3 proof contexts + range-proof record staging + the
/// transfer/close tx); the headroom covers multi-chunk range-proof writes.
#[cfg(feature = "confidential")]
pub(crate) const MAX_CONFIDENTIAL_BUNDLE_TXS: usize = 16;
/// ZK ElGamal Proof program id (proof verification + close_context_state).
#[cfg(feature = "confidential")]
pub(crate) const ZK_ELGAMAL_PROOF_PROGRAM: &str = "ZkE1Gama1Proof11111111111111111111111111111";
/// Caps on a gateway-funded `create_account` in a confidential bundle. The
/// largest legitimate proof/record account is ~1.5 KB (the range-proof record);
/// these leave generous headroom while preventing a malicious client from
/// forcing the gateway to fund an oversized/expensive account.
#[cfg(feature = "confidential")]
pub(crate) const MAX_CT_CREATE_ACCOUNT_SPACE: u64 = 4096;
#[cfg(feature = "confidential")]
pub(crate) const MAX_CT_CREATE_ACCOUNT_LAMPORTS: u64 = 50_000_000; // ~0.05 SOL
/// Max base64 length of a single bundle transaction. Each tx must fit Solana's
/// 1232-byte wire limit (~1644 base64 chars); this caps decode/deserialize
/// allocation so a client can't force large allocations with oversized strings.
#[cfg(feature = "confidential")]
pub(crate) const MAX_BUNDLE_TX_BASE64_LEN: usize = 2048;
/// Confirmation polling for confidential bundle submission and orphan close:
/// poll `confirm_transaction` up to N times, sleeping between attempts.
#[cfg(feature = "confidential")]
pub(crate) const CONFIDENTIAL_CONFIRM_MAX_ATTEMPTS: usize = 30;
#[cfg(feature = "confidential")]
pub(crate) const CONFIDENTIAL_CONFIRM_POLL_INTERVAL_MS: u64 = 200;
/// Max `SetComputeUnitLimit` a confidential bundle tx may request. The
/// confidential transfer + proof CPIs can exceed the 200k default, so this is
/// higher than the non-confidential `MAX_COMPUTE_UNIT_LIMIT`; it is bounded by
/// Solana's per-tx ceiling. The gateway is the fee payer, but priority cost is
/// `price * units` and the price is capped at the fee-sponsored limit, so even
/// at this ceiling the worst-case priority fee is negligible (~14k lamports).
#[cfg(feature = "confidential")]
pub(crate) const MAX_CONFIDENTIAL_COMPUTE_UNIT_LIMIT: u32 = 1_400_000;

/// Outcome of one [`Mpp::sweep_confidential_orphans`] pass.
#[cfg(feature = "worker")]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ConfidentialSweepReport {
    /// Orphaned ZK proof-context accounts closed this pass.
    pub closed_contexts: u64,
    /// Orphaned spl-record accounts closed this pass.
    pub closed_records: u64,
    /// Gateway-owned accounts seen for the first time — marked and deferred to
    /// the next sweep so an in-flight settlement is never closed out from under.
    pub deferred: u64,
    /// Accounts confirmed orphaned but whose close failed (retried next sweep).
    pub failed: u64,
}

impl Mpp {
    /// Settle a confidential-transfer bundle (recipient-key verification).
    ///
    /// The gateway is the payee: it confirms it was paid by decrypting its OWN
    /// received amount with its OWN recipient ElGamal key — no auditor key is
    /// involved. The bundle's transactions are fully client-signed (the client
    /// is the fee payer in the bundle builder), so the server just submits
    /// them in order and reads its confidential account's pending balance
    /// before and after to recover the delta.
    ///
    /// Returns the final (transfer) transaction signature.
    #[cfg(feature = "confidential")]
    pub(crate) async fn settle_confidential_bundle(
        &self,
        transactions: &[String],
        request: &ChargeRequest,
        method_details: &MethodDetails,
    ) -> Result<String, VerificationError> {
        use solana_commitment_config::CommitmentConfig;
        use spl_associated_token_account::get_associated_token_address_with_program_id;
        use spl_token_2022::{
            extension::{
                confidential_transfer::ConfidentialTransferAccount, BaseStateWithExtensions,
                StateWithExtensions,
            },
            state::Account as TokenAccount,
        };

        // Only accept a bundle when the challenge was actually issued in
        // confidential mode. Without this, a client could present a Bundle
        // credential against an ordinary Token-2022 charge; in facilitator mode
        // (no amount enforcement) it would settle with a near-zero confidential
        // transfer, claiming any non-confidential charge for a trivial amount.
        if method_details.confidential != Some(true) {
            return Err(VerificationError::credential_mismatch(
                "Bundle credentials are only valid for challenges issued with confidential mode enabled",
            ));
        }

        if transactions.is_empty() {
            return Err(VerificationError::invalid_payload(
                "Confidential bundle contains no transactions",
            ));
        }

        // Confidential transfers are Token-2022 only. Resolve the mint and the
        // recipient's confidential ATA under the Token-2022 program.
        let token_program_str = method_details
            .token_program
            .as_deref()
            .unwrap_or(programs::TOKEN_2022_PROGRAM);
        let token_program = Pubkey::from_str(token_program_str).map_err(|e| {
            VerificationError::invalid_payload(format!("Invalid token program: {e}"))
        })?;
        let mint = resolve_expected_mint(&request.currency, method_details.network.as_deref())?;
        let recipient = Pubkey::from_str(&self.recipient)
            .map_err(|e| VerificationError::invalid_recipient(format!("Invalid recipient: {e}")))?;
        let recipient_ata =
            get_associated_token_address_with_program_id(&recipient, &mint, &token_program);

        // Clients hold no SOL: the gateway is the fee payer, rent funder, and
        // proof/record-account authority for every bundle tx. A fee-payer signer
        // is therefore REQUIRED — we co-sign each tx's empty fee-payer slot.
        let fee_payer_signer = self.fee_payer_signer.as_ref().ok_or_else(|| {
            VerificationError::new(
                "Confidential settlement requires a fee-payer signer (the gateway pays bundle fees)",
            )
        })?;
        let gateway_pubkey = fee_payer_signer.pubkey();

        // Two settlement modes:
        //   * recipient_signer SET (the gateway controls the payee) ⇒ derive the
        //     recipient ElGamal key and ENFORCE the exact amount by decrypting
        //     the recipient's own pending-balance delta.
        //   * recipient_signer ABSENT (facilitator settling to an arbitrary
        //     recipient) ⇒ trust-proofs: the gateway cannot decrypt the amount,
        //     so it only verifies the transfer targets the recipient and that
        //     the bundle lands (the on-chain ZK program guarantees the proofs
        //     are valid); the recipient reconciles the amount out of band.
        let recipient_keys = match self.recipient_signer.as_ref() {
            Some(signer) => Some(
                crate::mpp::protocol::confidential::derive_confidential_keys(
                    signer.as_ref(),
                    &recipient_ata,
                )
                .await
                .map_err(|e| {
                    VerificationError::new(format!(
                        "Failed to derive recipient confidential keys: {e}"
                    ))
                })?,
            ),
            None => None,
        };

        // Decrypt the recipient's pending balance from raw account data with the
        // recipient key (used only in amount-enforcing mode).
        let read_pending = |data: &[u8],
                            keys: &crate::mpp::protocol::confidential::ConfidentialKeys|
         -> Result<Option<u64>, VerificationError> {
            let state = StateWithExtensions::<TokenAccount>::unpack(data).map_err(|e| {
                VerificationError::invalid_payload(format!(
                    "Failed to unpack recipient token account: {e}"
                ))
            })?;
            let ext = state
                .get_extension::<ConfidentialTransferAccount>()
                .map_err(|e| {
                    VerificationError::invalid_payload(format!(
                        "Recipient account has no ConfidentialTransfer extension: {e}"
                    ))
                })?;
            Ok(crate::mpp::protocol::confidential::recover_split_amount(
                &keys.elgamal,
                bytemuck::bytes_of(&ext.pending_balance_lo),
                bytemuck::bytes_of(&ext.pending_balance_hi),
            ))
        };

        // Bound the bundle size so a client can't make the operator spin on a
        // huge bundle (the builder emits ~5 txs; allow generous headroom for
        // multi-chunk range-proof staging).
        if transactions.len() > MAX_CONFIDENTIAL_BUNDLE_TXS {
            return Err(VerificationError::invalid_payload(format!(
                "Confidential bundle has {} transactions (max {MAX_CONFIDENTIAL_BUNDLE_TXS})",
                transactions.len()
            )));
        }

        // PASS 1 — decode and hard-verify EVERY transaction with no network
        // calls and no signing. This rejects a bundle that lacks exactly one
        // valid confidential transfer (e.g. an all-`create_account` bundle that
        // would otherwise cost the gateway rent + fees across 16 co-signed txs)
        // before the gateway spends anything. Each tx is allow-listed, the
        // gateway is asserted as fee payer and sole rent funder, and any
        // transfer destination is checked here — all before co-signing in pass 2.
        let mut decoded: Vec<VersionedTransaction> = Vec::with_capacity(transactions.len());
        let mut transfer_count = 0usize;
        for (idx, tx_b64) in transactions.iter().enumerate() {
            // Bound the per-tx string before decoding so a client can't force a
            // large allocation with a multi-MB base64 blob (each real bundle tx
            // is well under the 1232-byte wire limit).
            if tx_b64.len() > MAX_BUNDLE_TX_BASE64_LEN {
                return Err(VerificationError::invalid_payload(format!(
                    "Bundle tx {idx} exceeds the {MAX_BUNDLE_TX_BASE64_LEN}-byte base64 cap"
                )));
            }
            let tx_bytes =
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, tx_b64)
                    .map_err(|e| {
                        VerificationError::invalid_payload(format!(
                            "Invalid base64 transaction at index {idx}: {e}"
                        ))
                    })?;
            let tx: VersionedTransaction = bincode::deserialize::<Transaction>(&tx_bytes)
                .map(VersionedTransaction::from)
                .or_else(|_| bincode::deserialize::<VersionedTransaction>(&tx_bytes))
                .map_err(|e| {
                    VerificationError::invalid_payload(format!(
                        "Invalid transaction at index {idx}: {e}"
                    ))
                })?;

            check_network_blockhash(&self.network, &tx.message.recent_blockhash().to_string())?;

            // Allow-list every instruction, assert the gateway is fee payer and
            // the only rent funder, and validate any confidential-transfer
            // destination — all before any co-sign/broadcast in pass 2.
            transfer_count +=
                verify_confidential_bundle_tx(&tx, &gateway_pubkey, &token_program, &recipient_ata)
                    .map_err(|e| {
                        VerificationError::credential_mismatch(format!("Bundle tx {idx}: {e}"))
                    })?;
            if transfer_count > 1 {
                return Err(VerificationError::credential_mismatch(
                    "Confidential bundle contains more than one transfer",
                ));
            }
            decoded.push(tx);
        }

        // The bundle must contain EXACTLY ONE confidential transfer to the
        // expected recipient (checked pre-co-sign above). Reject a transfer-less
        // bundle (which would "settle" with no payment) or a decoy here — before
        // the gateway co-signs/funds/broadcasts a single tx.
        if transfer_count != 1 {
            return Err(VerificationError::credential_mismatch(format!(
                "Confidential bundle must contain exactly one transfer (found {transfer_count})"
            )));
        }

        // In amount-enforcing mode, snapshot the recipient's pending balance
        // BEFORE the bundle. A not-yet-existing account, or a freshly-configured
        // one whose pending ciphertext is still the uninitialized/zero default
        // (so it doesn't decrypt), is treated as zero — only the *after* read
        // must decrypt, since the bundle's transfer credits it.
        let before: u64 = match &recipient_keys {
            // Use get_account_with_commitment so a genuinely-missing account
            // (Ok(None)) reads as zero, while a transient RPC/network error
            // propagates instead of silently disabling amount enforcement.
            Some(keys) => match self
                .rpc
                .get_account_with_commitment(&recipient_ata, CommitmentConfig::confirmed())
            {
                Ok(resp) => match resp.value {
                    Some(account) => read_pending(&account.data, keys)?.unwrap_or(0),
                    None => 0,
                },
                Err(e) => {
                    return Err(VerificationError::network_error(format!(
                        "Failed to read recipient account (before): {e}"
                    )))
                }
            },
            None => 0,
        };

        // PASS 2 — co-sign the empty gateway fee-payer slot, simulate, broadcast,
        // and confirm each (already-validated) tx IN ORDER. The final tx carries
        // the confidential transfer; its signature is the settlement signature.
        let mut final_sig = String::new();
        for (idx, tx) in decoded.iter_mut().enumerate() {
            let msg_data = tx.message.serialize();
            let sig_bytes = fee_payer_signer
                .sign_message(&msg_data)
                .await
                .map_err(|e| {
                    VerificationError::new(format!("Gateway fee-payer signing failed: {e}"))
                })?;
            let gw_idx = tx
                .message
                .static_account_keys()
                .iter()
                .position(|k| k == &gateway_pubkey)
                .ok_or_else(|| {
                    VerificationError::invalid_payload(format!(
                        "Bundle tx {idx}: gateway not in account keys"
                    ))
                })?;
            tx.signatures[gw_idx] = Signature::from(<[u8; 64]>::from(sig_bytes));

            // Simulate before broadcasting to avoid fee loss / partial bundles.
            let sim = self.rpc.simulate_transaction(&*tx).map_err(|e| {
                VerificationError::network_error(format!(
                    "Simulation RPC error for bundle tx {idx}: {e}"
                ))
            })?;
            if let Some(err) = sim.value.err {
                let logs = sim
                    .value
                    .logs
                    .as_deref()
                    .unwrap_or(&[])
                    .iter()
                    .filter(|l| l.contains("Error") || l.contains("error") || l.contains("failed"))
                    .cloned()
                    .collect::<Vec<_>>();
                let log_detail = if logs.is_empty() {
                    String::new()
                } else {
                    format!(" — {}", logs.join("; "))
                };
                return Err(VerificationError::transaction_failed(format!(
                    "Bundle tx {idx} simulation failed: {err}{log_detail}"
                )));
            }

            let signature = self.rpc.send_transaction(&*tx).map_err(|e| {
                VerificationError::network_error(format!("Bundle tx {idx} broadcast failed: {e}"))
            })?;
            let signature_str = signature.to_string();

            // Confirm at `confirmed` before moving on: later txs in the bundle
            // (and the final balance read) depend on earlier ones landing.
            let commitment = CommitmentConfig::confirmed();
            let mut confirmed = false;
            for _ in 0..CONFIDENTIAL_CONFIRM_MAX_ATTEMPTS {
                if let Ok(resp) = self
                    .rpc
                    .confirm_transaction_with_commitment(&signature, commitment)
                {
                    if resp.value {
                        confirmed = true;
                        break;
                    }
                }
                // Non-blocking: confidential settlement is driven by the worker
                // run-loop, so yield rather than block the tokio executor.
                tokio::time::sleep(std::time::Duration::from_millis(
                    CONFIDENTIAL_CONFIRM_POLL_INTERVAL_MS,
                ))
                .await;
            }
            if !confirmed {
                return Err(VerificationError::network_error(format!(
                    "Bundle tx {idx} ({signature_str}) was not confirmed in time"
                )));
            }

            final_sig = signature_str;
        }

        // Amount enforcement (only when the gateway controls the recipient):
        // read the recipient's pending balance AFTER and require the delta to
        // equal the charged amount. In facilitator (trust-proofs) mode the
        // gateway can't decrypt the amount, so it relies on the on-chain proofs
        // and the recipient reconciling out of band.
        if let Some(keys) = &recipient_keys {
            // Read at `confirmed` — the same commitment used to confirm the
            // bundle and to snapshot the `before` balance. Using the default
            // `finalized` here would fail valid payments during the ~6-12s gap
            // between a transfer being confirmed and finalized.
            let after_account = self
                .rpc
                .get_account_with_commitment(&recipient_ata, CommitmentConfig::confirmed())
                .map_err(|e| {
                    VerificationError::network_error(format!(
                        "Failed to read recipient account after settlement: {e}"
                    ))
                })?
                .value
                .ok_or_else(|| {
                    VerificationError::new("Recipient token account missing after settlement")
                })?;
            let after = read_pending(&after_account.data, keys)?.ok_or_else(|| {
                VerificationError::new(
                    "Failed to decrypt recipient pending balance (after) with recipient key",
                )
            })?;
            let delta = after.saturating_sub(before);
            let expected: u64 = request.amount.parse().map_err(|_| {
                VerificationError::invalid_amount(format!("Invalid amount: {}", request.amount))
            })?;
            if delta != expected {
                return Err(VerificationError::invalid_amount(format!(
                    "Confidential amount mismatch: recovered {delta}, expected {expected}"
                )));
            }
        }

        self.consume_signature(&final_sig).await?;
        Ok(final_sig)
    }

    /// Sweep gateway-owned orphaned confidential proof/record accounts left by
    /// partially-failed bundles and reclaim their rent back to the gateway.
    ///
    /// A confidential bundle creates ZK proof-context accounts and an spl-record
    /// account — all funded by and authored by the gateway — and closes them in
    /// its final transaction. If a bundle fails partway (e.g. the blockhash
    /// expires mid-bundle), those accounts are orphaned with the gateway's rent
    /// locked inside. Because the gateway is their authority, it can close them.
    ///
    /// Race safety: a bundle that is currently settling also has live context
    /// accounts, but it creates and closes them within one bounded
    /// `settle_confidential_bundle` call (well under the blockhash window). To
    /// avoid closing those, this uses a two-pass guard backed by the store: an
    /// account is closed only if it was already seen in a PRIOR sweep. First
    /// sighting ⇒ record + defer; still present next sweep ⇒ orphaned ⇒ close.
    /// Schedule this with an interval comfortably larger than settlement latency.
    #[cfg(feature = "worker")]
    pub async fn sweep_confidential_orphans(
        &self,
    ) -> Result<ConfidentialSweepReport, VerificationError> {
        use solana_rpc_client_api::config::{
            RpcAccountInfoConfig, RpcProgramAccountsConfig, UiAccountEncoding, UiDataSliceConfig,
        };
        use solana_rpc_client_api::filter::{Memcmp, RpcFilterType};
        use solana_rpc_client_api::request::RpcRequest;
        use solana_rpc_client_api::response::RpcKeyedAccount;

        let signer = self.fee_payer_signer.as_ref().ok_or_else(|| {
            VerificationError::new("Confidential sweep requires a fee-payer signer")
        })?;
        let gateway = signer.pubkey();
        let zk_program = Pubkey::from_str(ZK_ELGAMAL_PROOF_PROGRAM).expect("valid zk program id");
        let record_program = spl_record::id();

        // Scan a program for accounts whose authority field equals the gateway.
        // ZK ProofContextState stores its authority at offset 0; spl-record's
        // RecordData stores it at offset 1 (after the version byte). We slice
        // zero data bytes — only the pubkeys are needed, and a full-data scan
        // would force base64 on large accounts for nothing.
        let scan =
            |program: &Pubkey, authority_offset: usize| -> Result<Vec<Pubkey>, VerificationError> {
                let config = RpcProgramAccountsConfig {
                    filters: Some(vec![RpcFilterType::Memcmp(Memcmp::new_raw_bytes(
                        authority_offset,
                        gateway.to_bytes().to_vec(),
                    ))]),
                    account_config: RpcAccountInfoConfig {
                        encoding: Some(UiAccountEncoding::Base64),
                        data_slice: Some(UiDataSliceConfig {
                            offset: 0,
                            length: 0,
                        }),
                        ..Default::default()
                    },
                    ..Default::default()
                };
                // The blocking RpcClient 4.0 exposes no with-config variant, so
                // issue the request directly. with_context defaults to None ⇒ a bare
                // array of keyed accounts; we only need their pubkeys.
                let params = serde_json::json!([program.to_string(), config]);
                let keyed: Vec<RpcKeyedAccount> = self
                    .rpc
                    .send(RpcRequest::GetProgramAccounts, params)
                    .map_err(|e| {
                        VerificationError::network_error(format!("getProgramAccounts failed: {e}"))
                    })?;
                Ok(keyed
                    .into_iter()
                    .filter_map(|k| Pubkey::from_str(&k.pubkey).ok())
                    .collect())
            };

        let candidates: Vec<(Pubkey, bool)> = scan(&zk_program, 0)?
            .into_iter()
            .map(|pk| (pk, false))
            .chain(scan(&record_program, 1)?.into_iter().map(|pk| (pk, true)))
            .collect();

        let mut report = ConfidentialSweepReport::default();
        for (pubkey, is_record) in candidates {
            // First sighting ⇒ mark + defer (it could be an in-flight bundle);
            // already seen ⇒ it survived a full sweep interval ⇒ orphaned.
            if !confirm_orphan_seen(self.store.as_ref(), &pubkey).await? {
                report.deferred += 1;
                continue;
            }
            // Survived a full sweep interval ⇒ orphaned. Close it to the gateway.
            let ix = if is_record {
                spl_record::instruction::close_account(&pubkey, &gateway, &gateway)
            } else {
                let gw = solana_address::Address::from(gateway.to_bytes());
                solana_zk_elgamal_proof_interface::instruction::close_context_state(
                    solana_zk_elgamal_proof_interface::instruction::ContextStateInfo {
                        context_state_account: &solana_address::Address::from(pubkey.to_bytes()),
                        context_state_authority: &gw,
                    },
                    &gw,
                )
            };
            match self.broadcast_close(signer.as_ref(), &gateway, ix).await {
                Ok(()) => {
                    self.store.delete(&orphan_seen_key(&pubkey)).await.ok();
                    if is_record {
                        report.closed_records += 1;
                    } else {
                        report.closed_contexts += 1;
                    }
                }
                Err(e) => {
                    // Leave the seen-mark so the next sweep retries the close.
                    report.failed += 1;
                    tracing::warn!(account = %pubkey, error = %e, "confidential orphan close failed");
                }
            }
        }
        Ok(report)
    }

    /// Build, gateway-sign, simulate, broadcast, and confirm a single close
    /// instruction. Used by the orphan sweeper.
    #[cfg(feature = "worker")]
    pub(crate) async fn broadcast_close(
        &self,
        signer: &dyn solana_keychain::SolanaSigner,
        gateway: &Pubkey,
        ix: solana_instruction::Instruction,
    ) -> Result<(), VerificationError> {
        use solana_commitment_config::CommitmentConfig;
        let blockhash = self
            .rpc
            .get_latest_blockhash()
            .map_err(|e| VerificationError::network_error(format!("get_latest_blockhash: {e}")))?;
        let message = solana_message::Message::new_with_blockhash(&[ix], Some(gateway), &blockhash);
        let mut tx = Transaction::new_unsigned(message);
        let sig_bytes = signer
            .sign_message(&tx.message_data())
            .await
            .map_err(|e| VerificationError::new(format!("sign close: {e}")))?;
        tx.signatures[0] = Signature::from(<[u8; 64]>::from(sig_bytes));
        let tx = VersionedTransaction::from(tx);

        let sim = self
            .rpc
            .simulate_transaction(&tx)
            .map_err(|e| VerificationError::network_error(format!("simulate close: {e}")))?;
        if let Some(err) = sim.value.err {
            return Err(VerificationError::transaction_failed(format!(
                "close simulation failed: {err}"
            )));
        }
        let sig = self
            .rpc
            .send_transaction(&tx)
            .map_err(|e| VerificationError::network_error(format!("broadcast close: {e}")))?;
        for _ in 0..CONFIDENTIAL_CONFIRM_MAX_ATTEMPTS {
            if let Ok(resp) = self
                .rpc
                .confirm_transaction_with_commitment(&sig, CommitmentConfig::confirmed())
            {
                if resp.value {
                    return Ok(());
                }
            }
            // tokio sleep, not std::thread::sleep: broadcast_close is only built
            // under the `worker` feature (tokio runtime), and the sweeper runs on
            // the worker run-loop — a blocking sleep would stall the executor.
            tokio::time::sleep(std::time::Duration::from_millis(
                CONFIDENTIAL_CONFIRM_POLL_INTERVAL_MS,
            ))
            .await;
        }
        Err(VerificationError::network_error(format!(
            "close tx {sig} not confirmed in time"
        )))
    }
}

/// Store key marking that the orphan sweeper has seen `pubkey` in a prior pass.
#[cfg(feature = "worker")]
pub(crate) fn orphan_seen_key(pubkey: &Pubkey) -> String {
    format!("confidential-orphan:seen:{pubkey}")
}

/// Two-pass orphan guard: returns `true` only if `pubkey` was already recorded
/// in a previous sweep (⇒ it has survived a full interval and is genuinely
/// orphaned, not an in-flight settlement's transient account). On the first
/// sighting it records the mark and returns `false` (defer to the next sweep).
#[cfg(feature = "worker")]
pub(crate) async fn confirm_orphan_seen(
    store: &dyn Store,
    pubkey: &Pubkey,
) -> Result<bool, VerificationError> {
    let key = orphan_seen_key(pubkey);
    let seen = store
        .get(&key)
        .await
        .map_err(|e| VerificationError::new(format!("Store error: {e}")))?
        .is_some();
    if !seen {
        store
            .put(&key, serde_json::json!(true))
            .await
            .map_err(|e| VerificationError::new(format!("Store error: {e}")))?;
        return Ok(false);
    }
    Ok(true)
}

#[cfg(feature = "confidential")]
/// Per-tx structural verification for a gateway-paid confidential bundle.
///
/// Because the gateway pays and funds every transaction, a malicious client
/// could otherwise slip in instructions that drain the operator (a System
/// transfer out of the fee payer, a priority-fee bomb) or mislead it (an
/// arbitrary CPI). We therefore require, for each tx:
///
/// 1. the fee payer (account_keys[0]) is the gateway;
/// 2. every instruction belongs to an allow-listed program — the ZK proof
///    program, spl-record, Token-2022, or the System program; and
/// 3. each System instruction is `create_account` only, funded by the gateway,
///    assigning the new account to the ZK or record program (so it is a
///    closeable proof/record account, never a free-floating account the gateway
///    funds for nothing).
///
/// Anything else (System transfer, Memo, ComputeBudget price, unknown program)
/// is rejected. Memo is intentionally disallowed: confidential charges
/// reconcile by signature, not an on-chain order-id marker (privacy).
/// Verify one bundle tx is safe for the gateway to co-sign. Returns the number
/// of confidential-transfer instructions it contains (each validated to target
/// `recipient_ata`), so the caller can require exactly one across the bundle.
pub(crate) fn verify_confidential_bundle_tx(
    tx: &VersionedTransaction,
    gateway: &Pubkey,
    token_program: &Pubkey,
    recipient_ata: &Pubkey,
) -> Result<usize, VerificationError> {
    // Token-2022 ConfidentialTransferExtension (TokenInstruction = 27) +
    // ConfidentialTransferInstruction discriminants: Transfer = 7,
    // TransferWithFee = 13. These are the ONLY Token-2022 opcodes a bundle may
    // carry — see the destination/drain reasoning below.
    const CT_EXTENSION: u8 = 27;
    const CT_TRANSFER: u8 = 7;
    const CT_TRANSFER_WITH_FEE: u8 = 13;
    // Token-2022 confidential transfer account order: [source, mint, dest, ...].
    const DEST_ACCOUNT_INDEX: usize = 2;
    // ZK ElGamal Proof program: CloseContextState is ProofInstruction 0; its
    // accounts are [context, destination, authority]. spl-record: CloseAccount
    // is RecordInstruction 3; its accounts are [record, authority, receiver].
    const ZK_CLOSE_CONTEXT_STATE: u8 = 0;
    const RECORD_CLOSE_ACCOUNT: u8 = 3;

    reject_address_lookup_tables(tx)?;

    let zk_program = Pubkey::from_str(ZK_ELGAMAL_PROOF_PROGRAM).expect("valid zk program id");
    let record_program = spl_record::id();
    let system_program = solana_system_interface::program::ID;
    let compute_budget_program =
        Pubkey::from_str(COMPUTE_BUDGET_PROGRAM).expect("valid compute budget program id");

    let keys = tx.message.static_account_keys();
    if keys.first() != Some(gateway) {
        return Err(VerificationError::credential_mismatch(
            "fee payer is not the gateway",
        ));
    }

    let mut transfer_count = 0usize;
    for ix in tx.message.instructions() {
        let program = keys.get(ix.program_id_index as usize).ok_or_else(|| {
            VerificationError::invalid_payload("instruction references unknown program")
        })?;

        if *program == system_program {
            // create_account is System instruction tag 0 (little-endian u32),
            // data layout: tag(4) | lamports(8) | space(8) | owner(32), so the
            // assigned owner is at byte offset 20..52.
            let tag = ix
                .data
                .get(0..4)
                .map(|b| u32::from_le_bytes(b.try_into().expect("4 bytes")));
            if tag != Some(0) {
                return Err(VerificationError::credential_mismatch(
                    "only System create_account is allowed",
                ));
            }
            let funder = ix.accounts.first().and_then(|i| keys.get(*i as usize));
            if funder != Some(gateway) {
                return Err(VerificationError::credential_mismatch(
                    "create_account is not funded by the gateway",
                ));
            }
            let owner = ix
                .data
                .get(20..52)
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
                .map(Pubkey::from);
            if owner != Some(zk_program) && owner != Some(record_program) {
                return Err(VerificationError::credential_mismatch(
                    "create_account assigns a non-proof/record account",
                ));
            }
            // Bound the rent the gateway (the funder) is asked to put up, so a
            // malicious client can't force it to create an oversized/expensive
            // account (locking large SOL, or a DoS if the bundle partially fails
            // and the account is left open). Layout: lamports at 4..12, space at
            // 12..20. Proof/record accounts are well under these caps.
            let lamports = ix
                .data
                .get(4..12)
                .and_then(|b| <[u8; 8]>::try_from(b).ok())
                .map(u64::from_le_bytes);
            let space = ix
                .data
                .get(12..20)
                .and_then(|b| <[u8; 8]>::try_from(b).ok())
                .map(u64::from_le_bytes);
            if space.is_none_or(|s| s > MAX_CT_CREATE_ACCOUNT_SPACE)
                || lamports.is_none_or(|l| l > MAX_CT_CREATE_ACCOUNT_LAMPORTS)
            {
                return Err(VerificationError::credential_mismatch(
                    "create_account exceeds the allowed size/rent for a proof/record account",
                ));
            }
        } else if *program == zk_program {
            // Every gateway-funded context account must be OWNED by the gateway,
            // both on the way in (verify-with-context sets context_state_authority)
            // and on the way out (CloseContextState). Otherwise a client could set
            // itself as authority during the verify and later close the account
            // externally, redirecting the gateway's rent to itself.
            if ix.data.first() == Some(&ZK_CLOSE_CONTEXT_STATE) {
                // Accounts: [context, destination, authority].
                let dest = ix.accounts.get(1).and_then(|i| keys.get(*i as usize));
                let auth = ix.accounts.get(2).and_then(|i| keys.get(*i as usize));
                if dest != Some(gateway) || auth != Some(gateway) {
                    return Err(VerificationError::credential_mismatch(
                        "close_context_state must return rent to and be authorized by the gateway",
                    ));
                }
            } else {
                // Verify-with-context. The context_state_authority sits at a
                // fixed index that depends on where the proof is read from — the
                // program reads it by position, so we check that exact position
                // (a trailing decoy account can't shift it):
                //   * proof in instruction data  → [context(w), authority]
                //   * proof in a separate account → [proof, context(w), authority]
                // The from-account form is the one whose data is just the
                // discriminant + a u32 byte offset (5 bytes); inline proof data
                // is hundreds of bytes. A context-less verify writes no
                // persistent account, so it has no authority slot at that index
                // and is rejected (the builder always verifies into a context).
                let authority_index = if ix.data.len() == 5 { 2 } else { 1 };
                let auth = ix
                    .accounts
                    .get(authority_index)
                    .and_then(|i| keys.get(*i as usize));
                if auth != Some(gateway) {
                    return Err(VerificationError::credential_mismatch(
                        "ZK verify context_state_authority must be the gateway",
                    ));
                }
            }
        } else if *program == record_program {
            // spl-record discriminants: Initialize=0, Write=1, SetAuthority=2,
            // CloseAccount=3. The record account is gateway-funded, so the
            // gateway must be its authority on Initialize (else a client sets
            // itself and drains rent later), SetAuthority is forbidden (the
            // gateway co-signs, so it would otherwise reassign authority to the
            // client), and CloseAccount must return rent to + be authorized by
            // the gateway. Write changes no authority and is fine.
            const RECORD_INITIALIZE: u8 = 0;
            const RECORD_SET_AUTHORITY: u8 = 2;
            match ix.data.first().copied() {
                Some(RECORD_INITIALIZE) => {
                    // Accounts: [record, authority].
                    let auth = ix.accounts.get(1).and_then(|i| keys.get(*i as usize));
                    if auth != Some(gateway) {
                        return Err(VerificationError::credential_mismatch(
                            "spl-record initialize authority must be the gateway",
                        ));
                    }
                }
                Some(RECORD_SET_AUTHORITY) => {
                    return Err(VerificationError::credential_mismatch(
                        "spl-record set_authority is not allowed in a confidential bundle",
                    ));
                }
                Some(RECORD_CLOSE_ACCOUNT) => {
                    // Accounts: [record, authority, receiver].
                    let auth = ix.accounts.get(1).and_then(|i| keys.get(*i as usize));
                    let receiver = ix.accounts.get(2).and_then(|i| keys.get(*i as usize));
                    if auth != Some(gateway) || receiver != Some(gateway) {
                        return Err(VerificationError::credential_mismatch(
                            "spl-record close_account must return rent to and be authorized by the gateway",
                        ));
                    }
                }
                _ => {}
            }
        } else if *program == compute_budget_program {
            // Allow a CU limit + priority fee so bundle txs aren't dropped under
            // congestion and the confidential transfer (which can exceed the 200k
            // default) gets enough compute. The gateway is the fee payer, so the
            // price is capped at the fee-sponsored limit to bound what a client
            // can spend on its behalf; only SetComputeUnitLimit (2) and
            // SetComputeUnitPrice (3) are permitted.
            match decode_compute_budget_op(ix) {
                Some(ComputeBudgetOp::UnitLimit(units)) => {
                    if units > MAX_CONFIDENTIAL_COMPUTE_UNIT_LIMIT {
                        return Err(VerificationError::credential_mismatch(format!(
                            "compute unit limit {units} exceeds maximum {MAX_CONFIDENTIAL_COMPUTE_UNIT_LIMIT}"
                        )));
                    }
                }
                Some(ComputeBudgetOp::UnitPrice(price)) => {
                    if price > MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS_FEE_SPONSORED {
                        return Err(VerificationError::credential_mismatch(format!(
                            "compute unit price {price} exceeds the fee-sponsored maximum {MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS_FEE_SPONSORED}"
                        )));
                    }
                }
                None => {
                    return Err(VerificationError::credential_mismatch(
                        "only SetComputeUnitLimit / SetComputeUnitPrice are allowed on ComputeBudget",
                    ));
                }
            }
        } else if *program == *token_program {
            // The gateway co-signs this tx's fee-payer slot, and that same
            // Ed25519 signature authorises ANY Token-2022 instruction in the tx
            // that names the gateway as a required signer. So we permit ONLY the
            // confidential Transfer / TransferWithFee opcode — never
            // transfer_checked / burn / close_account, which a malicious client
            // could otherwise use (authority = gateway) to drain gateway tokens.
            let is_confidential_transfer = matches!(
                (ix.data.first().copied(), ix.data.get(1).copied()),
                (Some(CT_EXTENSION), Some(CT_TRANSFER))
                    | (Some(CT_EXTENSION), Some(CT_TRANSFER_WITH_FEE))
            );
            if !is_confidential_transfer {
                return Err(VerificationError::credential_mismatch(
                    "only the confidential Transfer instruction is allowed on Token-2022",
                ));
            }
            // Verify the transfer destination BEFORE the gateway co-signs and
            // broadcasts — once landed it is irreversible. Tied to this specific
            // transfer instruction, not "any Token-2022 ix with the right index".
            let dest = ix
                .accounts
                .get(DEST_ACCOUNT_INDEX)
                .and_then(|i| keys.get(*i as usize));
            if dest != Some(recipient_ata) {
                return Err(VerificationError::credential_mismatch(
                    "confidential transfer destination is not the expected recipient",
                ));
            }
            transfer_count += 1;
        } else {
            return Err(VerificationError::credential_mismatch(format!(
                "disallowed program {program}"
            )));
        }
    }

    Ok(transfer_count)
}
