//! Token-2022 confidential-transfer settlement (opt-in `confidential` feature).
//!
//! Split out of `charge.rs` (behavior-preserving move): gateway-paid bundle
//! settlement (`Mpp::settle_confidential_bundle`), the orphan sweeper
//! (`Mpp::sweep_confidential_orphans` + `broadcast_close`, gated by `orphan`), and the per-tx
//! bundle allow-list (`verify_confidential_bundle_tx`). The rest of the charge
//! handler — and the shared helpers this module imports — stays in `charge.rs`.

use std::str::FromStr;

use solana_message::compiled_instruction::CompiledInstruction;
use solana_pubkey::Pubkey;
use solana_transaction::versioned::VersionedTransaction;

use crate::mpp::protocol::intents::ChargeRequest;
use crate::mpp::protocol::solana::{programs, MethodDetails};

use super::charge::{
    check_network_blockhash, decode_compute_budget_op, resolve_expected_mint, BroadcastFence,
    ComputeBudgetOp, Mpp, SettleFailure, VerificationError, COMPUTE_BUDGET_PROGRAM,
    MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS_FEE_SPONSORED,
};

/// Outcome of broadcasting a validated confidential bundle.
#[cfg(feature = "confidential")]
#[derive(Debug)]
pub(crate) enum BundleSettlement {
    /// The final (transfer) transaction confirmed.
    Confirmed(String),
    /// The final transaction was broadcast but its outcome is unknown.
    Unconfirmed {
        signature: String,
        error: VerificationError,
    },
}

/// Upper bound on transactions in a gateway-paid confidential bundle. A
/// version-1 bundle is one transaction (proofs verified inline); the version-0
/// builder emits ~5 (3 proof contexts + range-proof record staging + the
/// transfer/close tx), and the headroom covers multi-chunk range-proof writes.
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
/// A fee-bearing version-0 transfer creates five proof contexts and one record.
/// Bound the aggregate exposure as well as each individual account.
#[cfg(feature = "confidential")]
pub(crate) const MAX_CT_BUNDLE_FUNDED_ACCOUNTS: usize = 6;
#[cfg(feature = "confidential")]
pub(crate) const MAX_CT_BUNDLE_CREATE_LAMPORTS: u64 =
    MAX_CT_CREATE_ACCOUNT_LAMPORTS * MAX_CT_BUNDLE_FUNDED_ACCOUNTS as u64;
/// Max base64 length of a single bundle transaction, by the largest accepted
/// version: 1232 wire bytes (~1644 base64 chars) for version 0, 4096 (5464)
/// for version 1. Caps decode/deserialize allocation so a client can't force
/// large allocations with oversized strings; the exact per-version byte limit
/// is enforced on the decoded transaction.
#[cfg(feature = "confidential")]
pub(crate) const MAX_BUNDLE_TX_BASE64_LEN: usize = 2048;
#[cfg(feature = "confidential")]
pub(crate) const MAX_BUNDLE_TX_BASE64_LEN_V1: usize = 5464;

#[cfg(feature = "confidential")]
pub(crate) fn max_bundle_tx_base64_len(accepted: &[crate::core::tx::TxVersion]) -> usize {
    if accepted.contains(&crate::core::tx::TxVersion::V1) {
        MAX_BUNDLE_TX_BASE64_LEN_V1
    } else {
        MAX_BUNDLE_TX_BASE64_LEN
    }
}
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
    /// The gateway is the payee: it confirms the amount by decrypting the
    /// recipient handle of the transfer's own validity proof with its recipient
    /// ElGamal key, before co-signing. The amount is the gross transfer amount,
    /// matching cleartext `transferChecked` semantics on fee-bearing mints.
    ///
    /// Returns the final (transfer) transaction signature.
    #[cfg(feature = "confidential")]
    pub(crate) async fn settle_confidential_bundle_inner(
        &self,
        transactions: &[String],
        request: &ChargeRequest,
        method_details: &MethodDetails,
        fence: &mut BroadcastFence,
    ) -> Result<String, SettleFailure> {
        match self
            .settle_confidential_bundle(transactions, request, method_details, fence)
            .await?
        {
            BundleSettlement::Confirmed(signature) => Ok(signature),
            BundleSettlement::Unconfirmed { signature, error } => {
                Err(SettleFailure::Unconfirmed { signature, error })
            }
        }
    }

    #[cfg(feature = "confidential")]
    pub(crate) async fn settle_confidential_bundle(
        &self,
        transactions: &[String],
        request: &ChargeRequest,
        method_details: &MethodDetails,
        fence: &mut BroadcastFence,
    ) -> Result<BundleSettlement, VerificationError> {
        use solana_commitment_config::CommitmentConfig;
        use spl_associated_token_account::get_associated_token_address_with_program_id;

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
        if self.accepted_versions == [crate::core::tx::TxVersion::V1] && transactions.len() != 1 {
            return Err(VerificationError::invalid_payload(
                "Version-1 confidential settlement requires exactly one transaction",
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
        // Recheck the challenge's sponsorship policy right before the gateway
        // commits to funding anything.
        let gateway_pubkey = self
            .confidential_sponsor(method_details)
            .map_err(VerificationError::credential_mismatch)?;
        debug_assert_eq!(gateway_pubkey, fee_payer_signer.pubkey());

        // Amount enforcement, before the gateway signs or pays for anything:
        //   * recipient_signer SET (the gateway controls the payee) ⇒ decrypt
        //     the transfer's recipient ciphertext.
        //   * confidential_auditor SET (facilitator for an arbitrary recipient
        //     on a mint whose auditor key it holds) ⇒ decrypt the auditor one.
        //   * neither ⇒ the amount is unverifiable; reject unless explicitly
        //     opted in (the recipient then reconciles out of band).
        if self.recipient_signer.is_none()
            && self.confidential_auditor.is_none()
            && !self.accept_unverified_confidential_amount
        {
            return Err(VerificationError::credential_mismatch(
                "Cannot verify the confidential transfer amount: configure recipient_signer or \
                 confidential_auditor (or explicitly accept_unverified_confidential_amount)",
            ));
        }
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
        let mut transfer_tx = None;
        let max_b64 = max_bundle_tx_base64_len(&self.accepted_versions);
        for (idx, tx_b64) in transactions.iter().enumerate() {
            // Bound the per-tx string before decoding so a client can't force a
            // large allocation with a multi-MB base64 blob (each real bundle tx
            // is under the accepted versions' wire limit).
            if tx_b64.len() > max_b64 {
                return Err(VerificationError::invalid_payload(format!(
                    "Bundle tx {idx} exceeds the {max_b64}-byte base64 cap"
                )));
            }
            let tx_bytes =
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, tx_b64)
                    .map_err(|e| {
                        VerificationError::invalid_payload(format!(
                            "Invalid base64 transaction at index {idx}: {e}"
                        ))
                    })?;
            let tx = crate::core::tx::decode_bytes(&tx_bytes).map_err(|e| {
                VerificationError::invalid_payload(format!(
                    "Invalid transaction at index {idx}: {e}"
                ))
            })?;

            check_network_blockhash(&self.network, &tx.message.recent_blockhash().to_string())?;

            // Allow-list every instruction, assert the gateway is fee payer and
            // the only rent funder, and validate any confidential-transfer
            // destination — all before any co-sign/broadcast in pass 2.
            let transfers = verify_confidential_bundle_tx(
                &tx,
                &gateway_pubkey,
                &token_program,
                &recipient_ata,
                &self.accepted_versions,
            )
            .map_err(|e| VerificationError::credential_mismatch(format!("Bundle tx {idx}: {e}")))?;
            // Every client and ephemeral signature must already verify: the
            // bundle lands one transaction at a time, so a bad signature found
            // at broadcast would leave the gateway paying for earlier setup.
            crate::core::tx::require_presigned(&tx, Some(&gateway_pubkey)).map_err(|e| {
                VerificationError::credential_mismatch(format!("Bundle tx {idx}: {e}"))
            })?;
            if transfers > 0 {
                transfer_tx = Some(idx);
            }
            transfer_count += transfers;
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
        // Bundle transactions land one by one and cannot roll back together.
        // With the transfer (and every close) in the final transaction, a
        // failure anywhere leaves the payer's funds untouched.
        if transfer_tx != Some(decoded.len() - 1) {
            return Err(VerificationError::credential_mismatch(
                "The confidential transfer must be in the bundle's final transaction",
            ));
        }

        verify_confidential_account_lifecycle(&decoded, &gateway_pubkey)?;

        // Recover the amount from the validity proof the transfer itself
        // consumes. An account-wide balance delta cannot attribute a credit to
        // this transfer (fees, concurrent settlements, external deposits).
        let amount_key = match (&recipient_keys, &self.confidential_auditor) {
            (Some(keys), _) => Some((&keys.elgamal, AmountHandle::Destination)),
            (None, Some(auditor)) => Some((auditor.as_ref(), AmountHandle::Auditor)),
            (None, None) => None,
        };
        if let Some((key, handle)) = amount_key {
            let expected: u64 = request.amount.parse().map_err(|_| {
                VerificationError::invalid_amount(format!("Invalid amount: {}", request.amount))
            })?;
            let recovered = recover_bundle_transfer_amount(&decoded, &token_program, key, handle)?;
            if recovered != expected {
                return Err(VerificationError::invalid_amount(format!(
                    "Confidential amount mismatch: recovered {recovered}, expected {expected}"
                )));
            }
        }

        // PASS 2 — co-sign the empty gateway fee-payer slot, simulate, broadcast,
        // and confirm each (already-validated) tx IN ORDER. The final tx carries
        // the confidential transfer; its signature is the settlement signature.
        let mut final_sig = String::new();
        let bundle_len = decoded.len();
        for (idx, tx) in decoded.iter_mut().enumerate() {
            // The gateway is every bundle tx's fee payer, so it is account key
            // zero. Keep that as an `invalid_payload` diagnostic naming the tx.
            if tx.message.static_account_keys().first() != Some(&gateway_pubkey) {
                return Err(VerificationError::invalid_payload(format!(
                    "Bundle tx {idx}: gateway not in account keys"
                )));
            }
            // Routes through `sign_transaction` rather than raw-signing the
            // serialized message, so a hardware gateway signer works.
            crate::core::signing::cosign_versioned_fee_payer(
                fee_payer_signer.as_ref(),
                &gateway_pubkey,
                tx,
            )
            .await
            .map_err(|e| {
                VerificationError::new(format!("Gateway fee-payer signing failed: {e}"))
            })?;

            // Simulate before broadcasting to avoid fee loss / partial bundles.
            let sim = crate::core::rpc::simulate_transaction(&self.rpc, &*tx).map_err(|e| {
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

            let is_final = idx + 1 == bundle_len;
            let local_signature = super::charge::final_signature(tx)?;
            if is_final {
                // Claim before sending, as pull settlement does, so the
                // transfer is recorded whatever happens after it leaves.
                fence.begin(self, &local_signature).await?;
            }
            let signature = match crate::core::rpc::send_transaction(
                &self.rpc,
                &*tx,
                crate::core::rpc::preflight_config(&self.rpc),
            ) {
                Ok(signature) => signature,
                Err(e) => {
                    let error = VerificationError::network_error(format!(
                        "Bundle tx {idx} broadcast failed: {e}"
                    ));
                    // Only a preflight rejection proves the transfer was not
                    // forwarded; any other error leaves it to reconcile.
                    if is_final {
                        if !super::charge::is_preflight_rejection(&e) {
                            return Ok(BundleSettlement::Unconfirmed {
                                signature: local_signature,
                                error,
                            });
                        }
                        fence.abandon(self).await;
                    }
                    return Err(error);
                }
            };
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
                let error = VerificationError::network_error(format!(
                    "Bundle tx {idx} ({signature_str}) was not confirmed in time"
                ));
                // Earlier transactions move no funds; only the final transfer
                // can have landed unseen.
                if is_final {
                    return Ok(BundleSettlement::Unconfirmed {
                        signature: signature_str,
                        error,
                    });
                }
                return Err(error);
            }

            final_sig = signature_str;
        }

        Ok(BundleSettlement::Confirmed(final_sig))
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
    /// `settle_confidential_bundle` call. The shared store records when each
    /// account was first seen, by any replica; it is closed only once it has
    /// outlived [`orphan::GRACE_SECS`] from that first sighting.
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

        let candidates: Vec<(Pubkey, orphan::OrphanKind)> = scan(&zk_program, 0)?
            .into_iter()
            .map(|pk| (pk, orphan::OrphanKind::ProofContext))
            .chain(
                scan(&record_program, 1)?
                    .into_iter()
                    .map(|pk| (pk, orphan::OrphanKind::Record)),
            )
            .collect();

        let mut report = ConfidentialSweepReport::default();
        for (pubkey, kind) in candidates {
            // Defer until it outlives the grace period (it could be in flight).
            let Some(confirmed) = orphan::confirm(self.store.as_ref(), pubkey, kind).await? else {
                report.deferred += 1;
                continue;
            };
            match self
                .broadcast_close(signer.as_ref(), &gateway, &confirmed)
                .await
            {
                Ok(()) => {
                    self.store.delete(&orphan::seen_key(&pubkey)).await.ok();
                    match kind {
                        orphan::OrphanKind::Record => report.closed_records += 1,
                        orphan::OrphanKind::ProofContext => report.closed_contexts += 1,
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

    /// Build, gateway-sign, simulate, broadcast, and confirm the close of a
    /// confirmed orphan. Used by the orphan sweeper.
    #[cfg(feature = "worker")]
    pub(crate) async fn broadcast_close(
        &self,
        signer: &dyn solana_keychain::TransactionSigner,
        gateway: &Pubkey,
        confirmed: &orphan::OrphanConfirmed,
    ) -> Result<(), VerificationError> {
        use solana_commitment_config::CommitmentConfig;
        let ix = confirmed.close_instruction(gateway);
        let blockhash = self
            .rpc
            .get_latest_blockhash()
            .map_err(|e| VerificationError::network_error(format!("get_latest_blockhash: {e}")))?;
        let mut tx = crate::core::tx::build_unsigned(
            crate::core::tx::TxVersion::V0,
            gateway,
            &[ix],
            blockhash,
            None,
        )
        .map_err(|e| VerificationError::new(format!("build close: {e}")))?;
        // The gateway is the sole signer and the fee payer. Routing it through
        // `sign_transaction` is what lets a hardware gateway run the sweeper.
        crate::core::signing::cosign_versioned_fee_payer(signer, gateway, &mut tx)
            .await
            .map_err(|e| VerificationError::new(format!("sign close: {e}")))?;

        let sim = crate::core::rpc::simulate_transaction(&self.rpc, &tx)
            .map_err(|e| VerificationError::network_error(format!("simulate close: {e}")))?;
        if let Some(err) = sim.value.err {
            return Err(VerificationError::transaction_failed(format!(
                "close simulation failed: {err}"
            )));
        }
        let sig = crate::core::rpc::send_transaction(
            &self.rpc,
            &tx,
            crate::core::rpc::preflight_config(&self.rpc),
        )
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

#[cfg(feature = "confidential")]
#[derive(Clone, Copy, PartialEq, Eq)]
enum FundedAccountKind {
    ProofContext,
    Record,
}

#[cfg(feature = "confidential")]
struct FundedAccount {
    kind: FundedAccountKind,
    initialized: bool,
    closed: bool,
    /// Allocated bytes, and record payload bytes written so far.
    space: u64,
    written: u64,
}

/// The spl-record instructions a confidential bundle may carry.
#[cfg(feature = "confidential")]
#[derive(Debug, PartialEq, Eq)]
enum RecordIx {
    Initialize,
    /// A write of `length` payload bytes; an empty write is never valid.
    Write {
        length: std::num::NonZeroU32,
    },
    CloseAccount,
}

#[cfg(feature = "confidential")]
impl RecordIx {
    fn parse(data: &[u8]) -> Result<Self, VerificationError> {
        let malformed =
            || VerificationError::credential_mismatch("spl-record write has malformed data");
        match data.first().copied() {
            Some(0) => Ok(Self::Initialize),
            Some(1) => {
                // tag | offset u64 | length u32 | data
                let length = data
                    .get(9..13)
                    .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
                    .map(u32::from_le_bytes)
                    .ok_or_else(malformed)?;
                let length = std::num::NonZeroU32::new(length).ok_or_else(|| {
                    VerificationError::credential_mismatch("spl-record write is empty")
                })?;
                if data.len() as u64 != 13 + u64::from(length.get()) {
                    return Err(malformed());
                }
                Ok(Self::Write { length })
            }
            Some(3) => Ok(Self::CloseAccount),
            _ => Err(VerificationError::credential_mismatch(
                "unsupported spl-record instruction in confidential bundle",
            )),
        }
    }
}

#[cfg(feature = "confidential")]
pub(crate) fn verify_confidential_account_lifecycle(
    transactions: &[VersionedTransaction],
    gateway: &Pubkey,
) -> Result<(), VerificationError> {
    use std::collections::{HashMap, HashSet};

    let zk_program = Pubkey::from_str(ZK_ELGAMAL_PROOF_PROGRAM).expect("valid zk program id");
    let record_program = spl_record::id();
    let system_program = solana_system_interface::program::ID;
    let mut funded = HashMap::<Pubkey, FundedAccount>::new();
    let mut total_lamports = 0u64;
    let final_tx = transactions.len().saturating_sub(1);

    for (tx_index, tx) in transactions.iter().enumerate() {
        let mut created_in_transaction = HashSet::new();
        // Every transaction before the final transfer must advance a
        // gateway-funded account; anything else only spends sponsored fees.
        let mut advances_lifecycle = false;
        let keys = tx.message.static_account_keys();
        for ix in tx.message.instructions() {
            let program = keys.get(ix.program_id_index as usize).ok_or_else(|| {
                VerificationError::invalid_payload("instruction references unknown program")
            })?;

            if *program == system_program {
                let account = ix
                    .accounts
                    .get(1)
                    .and_then(|index| keys.get(*index as usize))
                    .copied()
                    .ok_or_else(|| {
                        VerificationError::credential_mismatch(
                            "create_account is missing its new account",
                        )
                    })?;
                let owner = ix
                    .data
                    .get(20..52)
                    .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
                    .map(Pubkey::from)
                    .ok_or_else(|| {
                        VerificationError::credential_mismatch(
                            "create_account has malformed owner data",
                        )
                    })?;
                let kind = if owner == zk_program {
                    FundedAccountKind::ProofContext
                } else {
                    FundedAccountKind::Record
                };
                let lamports = ix
                    .data
                    .get(4..12)
                    .and_then(|bytes| <[u8; 8]>::try_from(bytes).ok())
                    .map(u64::from_le_bytes)
                    .ok_or_else(|| {
                        VerificationError::credential_mismatch(
                            "create_account has malformed lamport data",
                        )
                    })?;
                total_lamports = total_lamports.checked_add(lamports).ok_or_else(|| {
                    VerificationError::credential_mismatch(
                        "confidential bundle account funding overflows",
                    )
                })?;
                if total_lamports > MAX_CT_BUNDLE_CREATE_LAMPORTS {
                    return Err(VerificationError::credential_mismatch(format!(
                        "confidential bundle funds {total_lamports} lamports of temporary accounts (max {MAX_CT_BUNDLE_CREATE_LAMPORTS})"
                    )));
                }
                let space = ix
                    .data
                    .get(12..20)
                    .and_then(|bytes| <[u8; 8]>::try_from(bytes).ok())
                    .map(u64::from_le_bytes)
                    .ok_or_else(|| {
                        VerificationError::credential_mismatch(
                            "create_account has malformed space data",
                        )
                    })?;
                if account == *gateway
                    || funded
                        .insert(
                            account,
                            FundedAccount {
                                kind,
                                initialized: false,
                                closed: false,
                                space,
                                written: 0,
                            },
                        )
                        .is_some()
                {
                    return Err(VerificationError::credential_mismatch(
                        "confidential bundle creates the same temporary account more than once",
                    ));
                }
                // Each funded account also adds a sponsored signature.
                if funded.len() > MAX_CT_BUNDLE_FUNDED_ACCOUNTS {
                    return Err(VerificationError::credential_mismatch(format!(
                        "confidential bundle creates more than {MAX_CT_BUNDLE_FUNDED_ACCOUNTS} temporary accounts"
                    )));
                }
                created_in_transaction.insert(account);
                advances_lifecycle = true;
                continue;
            }

            let transition = |account: Pubkey,
                              expected_kind: FundedAccountKind,
                              close: bool,
                              created_in_transaction: &HashSet<Pubkey>,
                              funded: &mut HashMap<Pubkey, FundedAccount>|
             -> Result<(), VerificationError> {
                let state = funded.get_mut(&account).ok_or_else(|| {
                    VerificationError::credential_mismatch(
                        "confidential bundle uses a temporary account it did not create",
                    )
                })?;
                if state.kind != expected_kind || state.closed || (!close && state.initialized) {
                    return Err(VerificationError::credential_mismatch(
                        "confidential bundle has an invalid temporary-account lifecycle",
                    ));
                }
                if !close && !created_in_transaction.contains(&account) {
                    return Err(VerificationError::credential_mismatch(
                        "gateway-funded temporary accounts must be created and initialized in the same transaction",
                    ));
                }
                if close {
                    if tx_index != final_tx {
                        return Err(VerificationError::credential_mismatch(
                            "gateway-funded temporary accounts must be closed in the final transaction",
                        ));
                    }
                    if !state.initialized {
                        return Err(VerificationError::credential_mismatch(
                            "confidential bundle closes an uninitialized temporary account",
                        ));
                    }
                    state.closed = true;
                } else {
                    state.initialized = true;
                }
                Ok(())
            };

            if *program == zk_program {
                if ix.accounts.is_empty() {
                    continue;
                }
                let (account_index, close) = if ix.data.first() == Some(&0) {
                    (0, true)
                } else if ix.data.len() == 5 {
                    (1, false)
                } else {
                    (0, false)
                };
                let account = ix
                    .accounts
                    .get(account_index)
                    .and_then(|index| keys.get(*index as usize))
                    .copied()
                    .ok_or_else(|| {
                        VerificationError::credential_mismatch(
                            "ZK instruction is missing its context account",
                        )
                    })?;
                transition(
                    account,
                    FundedAccountKind::ProofContext,
                    close,
                    &created_in_transaction,
                    &mut funded,
                )?;
                advances_lifecycle |= !close;
            } else if *program == record_program {
                let account = ix
                    .accounts
                    .first()
                    .and_then(|index| keys.get(*index as usize))
                    .copied()
                    .ok_or_else(|| {
                        VerificationError::credential_mismatch(
                            "spl-record instruction is missing its record account",
                        )
                    })?;
                match RecordIx::parse(&ix.data)? {
                    RecordIx::Initialize => {
                        transition(
                            account,
                            FundedAccountKind::Record,
                            false,
                            &created_in_transaction,
                            &mut funded,
                        )?;
                        advances_lifecycle = true;
                    }
                    RecordIx::Write { length } => {
                        let state = funded.get_mut(&account).ok_or_else(|| {
                            VerificationError::credential_mismatch(
                                "confidential bundle writes a record it did not create",
                            )
                        })?;
                        if state.kind != FundedAccountKind::Record
                            || !state.initialized
                            || state.closed
                        {
                            return Err(VerificationError::credential_mismatch(
                                "confidential bundle writes outside an initialized record lifecycle",
                            ));
                        }
                        // Each payload byte is staged once, so the total
                        // written is bounded by the record's capacity.
                        state.written = state.written.saturating_add(u64::from(length.get()));
                        let capacity = state.space.saturating_sub(
                            spl_record::state::RecordData::WRITABLE_START_INDEX as u64,
                        );
                        if state.written > capacity {
                            return Err(VerificationError::credential_mismatch(
                                "confidential bundle writes more record data than the record holds",
                            ));
                        }
                        advances_lifecycle = true;
                    }
                    RecordIx::CloseAccount => transition(
                        account,
                        FundedAccountKind::Record,
                        true,
                        &created_in_transaction,
                        &mut funded,
                    )?,
                }
            }
        }
        if tx_index != final_tx && !advances_lifecycle {
            return Err(VerificationError::credential_mismatch(format!(
                "confidential bundle transaction {tx_index} advances no temporary account"
            )));
        }
    }

    if funded
        .values()
        .any(|account| !account.initialized || !account.closed)
    {
        return Err(VerificationError::credential_mismatch(
            "every gateway-funded temporary account must be initialized and closed back to the gateway",
        ));
    }
    Ok(())
}

/// Orphan guard. An account may be closed only through an [`orphan::OrphanConfirmed`],
/// which only [`orphan::confirm`] issues once the grace period has elapsed.
#[cfg(feature = "worker")]
pub(crate) mod orphan {
    use solana_pubkey::Pubkey;

    use super::{
        VerificationError, CONFIDENTIAL_CONFIRM_MAX_ATTEMPTS,
        CONFIDENTIAL_CONFIRM_POLL_INTERVAL_MS, MAX_CONFIDENTIAL_BUNDLE_TXS,
    };
    use crate::mpp::store::Store;

    /// How long an account must have been seen before it counts as orphaned.
    /// Far above a bundle's worst-case settlement time, so a replica never
    /// closes accounts another replica's in-flight bundle still needs.
    pub(crate) const GRACE_SECS: u64 = 600;

    const _: () = assert!(
        GRACE_SECS * 1_000
            > (MAX_CONFIDENTIAL_BUNDLE_TXS * CONFIDENTIAL_CONFIRM_MAX_ATTEMPTS) as u64
                * CONFIDENTIAL_CONFIRM_POLL_INTERVAL_MS
    );

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum OrphanKind {
        ProofContext,
        Record,
    }

    /// An account that outlived the grace period from its first sighting.
    #[derive(Debug)]
    pub(crate) struct OrphanConfirmed {
        pubkey: Pubkey,
        kind: OrphanKind,
    }

    impl OrphanConfirmed {
        /// The instruction closing this account back to the gateway.
        pub(crate) fn close_instruction(
            &self,
            gateway: &Pubkey,
        ) -> solana_instruction::Instruction {
            match self.kind {
                OrphanKind::Record => {
                    spl_record::instruction::close_account(&self.pubkey, gateway, gateway)
                }
                OrphanKind::ProofContext => {
                    let gw = solana_address::Address::from(gateway.to_bytes());
                    solana_zk_elgamal_proof_interface::instruction::close_context_state(
                        solana_zk_elgamal_proof_interface::instruction::ContextStateInfo {
                            context_state_account: &solana_address::Address::from(
                                self.pubkey.to_bytes(),
                            ),
                            context_state_authority: &gw,
                        },
                        &gw,
                    )
                }
            }
        }
    }

    /// Shared-store key holding the unix time `pubkey` was first seen.
    pub(crate) fn seen_key(pubkey: &Pubkey) -> String {
        format!("confidential-orphan:seen:{pubkey}")
    }

    /// Record the first sighting of `pubkey` (by any replica) and confirm it
    /// once [`GRACE_SECS`] have passed since then.
    pub(crate) async fn confirm(
        store: &dyn Store,
        pubkey: Pubkey,
        kind: OrphanKind,
    ) -> Result<Option<OrphanConfirmed>, VerificationError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| VerificationError::new(format!("system clock: {e}")))?
            .as_secs();
        confirm_at(store, pubkey, kind, now).await
    }

    pub(crate) async fn confirm_at(
        store: &dyn Store,
        pubkey: Pubkey,
        kind: OrphanKind,
        now: u64,
    ) -> Result<Option<OrphanConfirmed>, VerificationError> {
        let store_err =
            |e: crate::core::store::StoreError| VerificationError::new(format!("Store error: {e}"));
        let key = seen_key(&pubkey);
        if store
            .put_if_absent(&key, serde_json::json!(now))
            .await
            .map_err(store_err)?
        {
            return Ok(None);
        }
        match store
            .get(&key)
            .await
            .map_err(store_err)?
            .and_then(|v| v.as_u64())
        {
            Some(first_seen) if now.saturating_sub(first_seen) >= GRACE_SECS => {
                Ok(Some(OrphanConfirmed { pubkey, kind }))
            }
            Some(_) => Ok(None),
            None => {
                // Untimed mark (legacy or deleted concurrently): restart the clock.
                store
                    .put(&key, serde_json::json!(now))
                    .await
                    .map_err(store_err)?;
                Ok(None)
            }
        }
    }
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
    accepted_versions: &[crate::core::tx::TxVersion],
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

    crate::core::tx::check_envelope(tx, accepted_versions)
        .map_err(|e| VerificationError::invalid_payload(e.to_string()))?;
    crate::core::tx::check_v1_budget_caps(
        &tx.message,
        MAX_CONFIDENTIAL_COMPUTE_UNIT_LIMIT,
        crate::mpp::server::charge::MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS_FEE_SPONSORED,
    )
    .map_err(|e| VerificationError::invalid_payload(e.to_string()))?;

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
    let mut created_accounts = std::collections::HashSet::<Pubkey>::new();
    let mut transfer_accounts = std::collections::HashSet::<Pubkey>::new();
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
            if let Some(created) = ix.accounts.get(1).and_then(|i| keys.get(*i as usize)) {
                created_accounts.insert(*created);
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
            } else if ix.accounts.is_empty() {
                // Verify without a context account: the proof is checked from
                // instruction data and nothing persistent is written, so there
                // is no authority to pin. A version-1 bundle carries all of its
                // proofs this way.
            } else {
                // Verify-with-context. The context_state_authority sits at a
                // fixed index that depends on where the proof is read from — the
                // program reads it by position, so we check that exact position
                // (a trailing decoy account can't shift it):
                //   * proof in instruction data  → [context(w), authority]
                //   * proof in a separate account → [proof, context(w), authority]
                // The from-account form is the one whose data is just the
                // discriminant + a u32 byte offset (5 bytes); inline proof data
                // is hundreds of bytes.
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
                Some(ComputeBudgetOp::LoadedAccountsDataSizeLimit(_)) | None => {
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
            transfer_accounts.extend(
                ix.accounts
                    .iter()
                    .filter_map(|i| keys.get(*i as usize).copied()),
            );
        } else {
            return Err(VerificationError::credential_mismatch(format!(
                "disallowed program {program}"
            )));
        }
    }

    // The gateway pays one signature fee per required signer. Beyond its own
    // slot, only ephemeral accounts this transaction creates and a single
    // transfer authority may sign; anything else authorizes nothing.
    let required = usize::from(tx.message.header().num_required_signatures);
    let mut transfer_signers = 0usize;
    for signer in keys.iter().take(required).skip(1) {
        if created_accounts.contains(signer) {
            continue;
        }
        if transfer_accounts.contains(signer) {
            transfer_signers += 1;
            continue;
        }
        return Err(VerificationError::credential_mismatch(
            "unexpected signer in confidential bundle transaction",
        ));
    }
    if transfer_signers > 1 {
        return Err(VerificationError::credential_mismatch(
            "confidential transfer has more than one authority signer",
        ));
    }

    Ok(transfer_count)
}

/// Decrypt handle opened to recover a confidential transfer amount.
#[cfg(feature = "confidential")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AmountHandle {
    /// The recipient's handle (the validity proof's second pubkey).
    Destination,
    /// The mint auditor's handle (the validity proof's third pubkey).
    Auditor,
}

/// Token-2022 confidential `Transfer` / `TransferWithFee` instruction data:
/// two discriminant bytes, then a 36-byte decryptable balance and two 64-byte
/// auditor ciphertexts, then one `i8` proof offset per proof.
#[cfg(feature = "confidential")]
const CT_TRANSFER_OFFSETS_START: usize = 2 + 36 + 64 + 64;

/// Proof offsets of a confidential transfer, in the order Token-2022 consumes
/// their accounts: equality, transfer-amount validity, [fee sigma, fee
/// validity,] range.
#[cfg(feature = "confidential")]
fn ct_transfer_proof_offsets(data: &[u8]) -> Option<&[u8]> {
    let proofs = match data.get(..2)? {
        [27, 7] => 3,
        [27, 13] => 5,
        _ => return None,
    };
    let offsets = data.get(CT_TRANSFER_OFFSETS_START..)?;
    (offsets.len() == proofs).then_some(offsets)
}

/// Recover the amount carried by the bundle's sole confidential transfer by
/// opening `handle` of the 3-handle validity proof that transfer consumes,
/// located exactly as Token-2022 locates it (instruction offset or context
/// state account). The proof is verified on chain, so the opened ciphertext is
/// the one the program credits.
#[cfg(feature = "confidential")]
pub(crate) fn recover_bundle_transfer_amount(
    transactions: &[VersionedTransaction],
    token_program: &Pubkey,
    key: &solana_zk_sdk::encryption::elgamal::ElGamalKeypair,
    handle: AmountHandle,
) -> Result<u64, VerificationError> {
    use solana_zk_elgamal_proof_interface::instruction::ProofInstruction;
    use solana_zk_elgamal_proof_interface::proof_data::{
        BatchedGroupedCiphertext3HandlesValidityProofContext as ValidityContext,
        BatchedGroupedCiphertext3HandlesValidityProofData as ValidityData,
    };

    let zk_program = Pubkey::from_str(ZK_ELGAMAL_PROOF_PROGRAM).expect("valid zk program id");
    let program_of = |tx: &VersionedTransaction, ix: &CompiledInstruction| {
        tx.message
            .static_account_keys()
            .get(ix.program_id_index as usize)
            .copied()
    };
    let is_validity = |data: &[u8]| {
        ProofInstruction::instruction_type(data)
            == Some(ProofInstruction::VerifyBatchedGroupedCiphertext3HandlesValidity)
    };
    let decode = |data: &[u8]| -> Result<ValidityContext, VerificationError> {
        ProofInstruction::proof_data::<ValidityData, ValidityContext>(data)
            .map(|proof| proof.context)
            .ok_or_else(|| {
                VerificationError::credential_mismatch(
                    "confidential transfer validity proof must be carried inline in the bundle",
                )
            })
    };

    let mut transfer = None;
    for (tx_idx, tx) in transactions.iter().enumerate() {
        for (ix_idx, ix) in tx.message.instructions().iter().enumerate() {
            if program_of(tx, ix) == Some(*token_program)
                && ct_transfer_proof_offsets(&ix.data).is_some()
            {
                if transfer.is_some() {
                    return Err(VerificationError::credential_mismatch(
                        "Confidential bundle contains more than one transfer",
                    ));
                }
                transfer = Some((tx_idx, ix_idx));
            }
        }
    }
    let (tx_idx, ix_idx) = transfer.ok_or_else(|| {
        VerificationError::credential_mismatch("Confidential bundle contains no transfer")
    })?;
    let tx = &transactions[tx_idx];
    let ix = &tx.message.instructions()[ix_idx];
    let offsets = ct_transfer_proof_offsets(&ix.data).expect("matched above");
    let validity_offset = offsets[1] as i8;

    let context = if validity_offset != 0 {
        let proof_ix = i64::try_from(ix_idx)
            .ok()
            .and_then(|idx| idx.checked_add(i64::from(validity_offset)))
            .and_then(|idx| usize::try_from(idx).ok())
            .and_then(|idx| tx.message.instructions().get(idx))
            .filter(|proof_ix| {
                program_of(tx, proof_ix) == Some(zk_program) && is_validity(&proof_ix.data)
            })
            .ok_or_else(|| {
                VerificationError::credential_mismatch(
                    "confidential transfer validity proof instruction not found",
                )
            })?;
        decode(&proof_ix.data)?
    } else {
        // Accounts: [source, mint, destination, (instructions sysvar),
        // (equality context), validity context, ...].
        let position = 3
            + usize::from(offsets.iter().any(|offset| *offset != 0))
            + usize::from(offsets[0] == 0);
        let context_account = ix
            .accounts
            .get(position)
            .and_then(|index| tx.message.static_account_keys().get(*index as usize))
            .copied()
            .ok_or_else(|| {
                VerificationError::credential_mismatch(
                    "confidential transfer is missing its validity context account",
                )
            })?;
        let mut found = None;
        for tx in transactions {
            let keys = tx.message.static_account_keys();
            for proof_ix in tx.message.instructions() {
                if program_of(tx, proof_ix) != Some(zk_program) || !is_validity(&proof_ix.data) {
                    continue;
                }
                // Verify-from-account carries a 5-byte locator and names the
                // context second; the inline form names it first.
                let index = if proof_ix.data.len() == 5 { 1 } else { 0 };
                let account = proof_ix
                    .accounts
                    .get(index)
                    .and_then(|index| keys.get(*index as usize));
                if account != Some(&context_account) {
                    continue;
                }
                if found.is_some() {
                    return Err(VerificationError::credential_mismatch(
                        "confidential validity context is verified more than once",
                    ));
                }
                found = Some(decode(&proof_ix.data)?);
            }
        }
        found.ok_or_else(|| {
            VerificationError::credential_mismatch(
                "confidential validity context is not verified in this bundle",
            )
        })?
    };

    let (pubkey, slot) = match handle {
        AmountHandle::Destination => (&context.second_pubkey, 1),
        AmountHandle::Auditor => (&context.third_pubkey, 2),
    };
    if pubkey.0 != <[u8; 32]>::from(key.pubkey()) {
        return Err(VerificationError::credential_mismatch(
            "confidential transfer is not encrypted to this server's key",
        ));
    }
    // Grouped ciphertext: commitment || handle_0 || handle_1 || handle_2.
    let open = |grouped: &[u8]| -> Option<Vec<u8>> {
        let commitment = grouped.get(..32)?;
        let handle = grouped.get(32 * (slot + 1)..32 * (slot + 2))?;
        Some([commitment, handle].concat())
    };
    let lo = open(&context.grouped_ciphertext_lo.0);
    let hi = open(&context.grouped_ciphertext_hi.0);
    lo.zip(hi)
        .and_then(|(lo, hi)| {
            crate::mpp::protocol::confidential::recover_split_amount(key, &lo, &hi)
        })
        .ok_or_else(|| {
            VerificationError::invalid_amount("Failed to decrypt the confidential transfer amount")
        })
}

#[cfg(all(test, feature = "client"))]
pub(crate) mod tests {
    use super::*;
    use crate::core::tx::{ComputeBudget, TxVersion};
    use crate::mpp::client::confidential::{
        cast_ae_ciphertext_v7_to_legacy, inline_transfer_instructions,
        inline_transfer_with_fee_instructions,
    };
    use crate::mpp::protocol::confidential::{derive_confidential_keys, ConfidentialKeys};
    use solana_zk_sdk::encryption::{
        auth_encryption::AeKey,
        elgamal::{ElGamalKeypair, ElGamalPubkey},
    };
    use spl_associated_token_account::get_associated_token_address_with_program_id;
    use spl_token_confidential_transfer_proof_generation::{
        transfer::transfer_split_proof_data, transfer_with_fee::transfer_with_fee_split_proof_data,
    };
    use std::sync::Arc;

    const SENDER_BALANCE: u64 = 10_000_000;

    /// Secret keys of the client and ephemeral signers the fixtures mint, so
    /// [`sign_clients`] can fill their slots the way a real client would.
    static CLIENT_KEYS: std::sync::LazyLock<
        std::sync::Mutex<std::collections::HashMap<Pubkey, ed25519_dalek::SigningKey>>,
    > = std::sync::LazyLock::new(Default::default);

    /// A fresh signer key, registered for [`sign_clients`].
    pub(crate) fn client_key() -> Pubkey {
        let key = ed25519_dalek::SigningKey::from_bytes(&Pubkey::new_unique().to_bytes());
        let pubkey = Pubkey::from(key.verifying_key().to_bytes());
        CLIENT_KEYS.lock().unwrap().insert(pubkey, key);
        pubkey
    }

    /// Sign every required slot whose key came from [`client_key`], leaving
    /// the gateway's fee-payer slot empty for the server to co-sign.
    pub(crate) fn sign_clients(tx: &mut VersionedTransaction) {
        use ed25519_dalek::Signer;
        let message = tx.message.serialize();
        let required = usize::from(tx.message.header().num_required_signatures);
        let keys = CLIENT_KEYS.lock().unwrap();
        for (slot, key) in tx
            .message
            .static_account_keys()
            .iter()
            .take(required)
            .enumerate()
        {
            if let Some(secret) = keys.get(key) {
                tx.signatures[slot] =
                    solana_signature::Signature::from(secret.sign(&message).to_bytes());
            }
        }
    }

    /// One version-1 transaction moving `amount` confidentially to
    /// `recipient_ata`, with every proof verified inline. `fee` selects the
    /// fee-bearing `TransferWithFee` variant (basis points, maximum fee).
    pub(crate) fn inline_transfer_tx(
        gateway: &Pubkey,
        mint: &Pubkey,
        recipient_ata: &Pubkey,
        recipient: &ElGamalPubkey,
        auditor: Option<&ElGamalPubkey>,
        amount: u64,
        fee: Option<(u16, u64)>,
    ) -> VersionedTransaction {
        let token_program = Pubkey::from_str(programs::TOKEN_2022_PROGRAM).unwrap();
        let sender_elgamal = ElGamalKeypair::new_rand();
        let sender_ae = AeKey::new_rand();
        let sender = client_key();
        let sender_ata = Pubkey::new_unique();
        let available = sender_elgamal.pubkey().encrypt(SENDER_BALANCE);
        let decryptable = sender_ae.encrypt(SENDER_BALANCE);
        let new_decryptable =
            cast_ae_ciphertext_v7_to_legacy(&sender_ae.encrypt(SENDER_BALANCE - amount));
        let ixs = match fee {
            None => {
                let proof = transfer_split_proof_data(
                    &available,
                    &decryptable,
                    amount,
                    &sender_elgamal,
                    &sender_ae,
                    recipient,
                    auditor,
                )
                .unwrap();
                inline_transfer_instructions(
                    &token_program,
                    &sender_ata,
                    mint,
                    recipient_ata,
                    &sender,
                    &proof,
                    &new_decryptable,
                )
                .unwrap()
            }
            Some((basis_points, maximum_fee)) => {
                let withheld = ElGamalKeypair::new_rand();
                let proof = transfer_with_fee_split_proof_data(
                    &available,
                    &decryptable,
                    amount,
                    &sender_elgamal,
                    &sender_ae,
                    recipient,
                    auditor,
                    withheld.pubkey(),
                    basis_points,
                    maximum_fee,
                )
                .unwrap();
                inline_transfer_with_fee_instructions(
                    &token_program,
                    &sender_ata,
                    mint,
                    recipient_ata,
                    &sender,
                    &proof,
                    &new_decryptable,
                )
                .unwrap()
            }
        };
        let mut tx = crate::core::tx::build_unsigned(
            TxVersion::V1,
            gateway,
            &ixs,
            solana_hash::Hash::new_unique(),
            Some(&ComputeBudget::new(700_000, 0)),
        )
        .unwrap();
        sign_clients(&mut tx);
        tx
    }

    fn signer(seed: u8) -> Arc<solana_keychain::MemorySigner> {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        let mut kp = [0u8; 64];
        kp[..32].copy_from_slice(sk.as_bytes());
        kp[32..].copy_from_slice(sk.verifying_key().as_bytes());
        Arc::new(solana_keychain::MemorySigner::from_bytes(&kp).unwrap())
    }

    /// A recipient-key settlement server plus everything a client needs to
    /// build a bundle against it. No RPC is reachable.
    pub(crate) struct RecipientKeyServer {
        pub mpp: Mpp,
        pub gateway: Pubkey,
        pub mint: Pubkey,
        pub recipient_ata: Pubkey,
        pub recipient_keys: ConfidentialKeys,
        pub method_details: MethodDetails,
    }

    pub(crate) async fn recipient_key_server() -> RecipientKeyServer {
        confidential_server(true, None, false).await
    }

    /// `recipient_key` selects recipient-key mode; otherwise the server is a
    /// facilitator, optionally holding the mint's auditor key.
    pub(crate) async fn confidential_server(
        recipient_key: bool,
        auditor: Option<Arc<ElGamalKeypair>>,
        accept_unverified: bool,
    ) -> RecipientKeyServer {
        use solana_keychain::SolanaSigner;
        let gateway_signer = signer(11);
        let recipient_signer = signer(12);
        let gateway = gateway_signer.pubkey();
        let recipient = recipient_signer.pubkey();
        let mint = Pubkey::new_unique();
        let token_program = Pubkey::from_str(programs::TOKEN_2022_PROGRAM).unwrap();
        let recipient_ata =
            get_associated_token_address_with_program_id(&recipient, &mint, &token_program);
        let recipient_keys = derive_confidential_keys(recipient_signer.as_ref(), &recipient_ata)
            .await
            .unwrap();
        let mut mpp = Mpp::new(super::super::charge::Config {
            recipient: recipient.to_string(),
            currency: "SOL".to_string(),
            decimals: 6,
            network: "localnet".to_string(),
            rpc_url: Some("http://127.0.0.1:1".to_string()),
            challenge_binding_secret: Some("x".repeat(32)),
            realm: Some("test".to_string()),
            fee_payer: true,
            fee_payer_signer: Some(gateway_signer),
            recipient_signer: recipient_key
                .then_some(recipient_signer as Arc<dyn solana_keychain::SolanaSigner>),
            confidential_auditor: auditor.map(|keypair| <[u8; 64]>::from(keypair.as_ref())),
            accept_unverified_confidential_amount: accept_unverified,
            store: Some(std::sync::Arc::new(crate::mpp::store::MemoryStore::new())),
            ..Default::default()
        })
        .unwrap();
        mpp.accepted_versions = vec![TxVersion::V1];
        RecipientKeyServer {
            mpp,
            gateway,
            mint,
            recipient_ata,
            recipient_keys,
            method_details: MethodDetails {
                token_program: Some(programs::TOKEN_2022_PROGRAM.to_string()),
                confidential: Some(true),
                fee_payer: Some(true),
                fee_payer_key: Some(gateway.to_string()),
                ..Default::default()
            },
        }
    }

    pub(crate) fn encode_bundle(txs: &[VersionedTransaction]) -> Vec<String> {
        txs.iter()
            .map(|tx| crate::core::tx::encode(tx).unwrap())
            .collect()
    }

    pub(crate) fn request(amount: u64, mint: &Pubkey, recipient: &str) -> ChargeRequest {
        ChargeRequest {
            amount: amount.to_string(),
            currency: mint.to_string(),
            recipient: Some(recipient.to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn transfer_offsets_layout_matches_token_2022() {
        use spl_token_2022::extension::confidential_transfer::instruction::{
            TransferInstructionData, TransferWithFeeInstructionData,
        };
        assert_eq!(
            CT_TRANSFER_OFFSETS_START + 3,
            2 + std::mem::size_of::<TransferInstructionData>()
        );
        assert_eq!(
            CT_TRANSFER_OFFSETS_START + 5,
            2 + std::mem::size_of::<TransferWithFeeInstructionData>()
        );
    }

    #[test]
    fn recovers_inline_transfer_amount_with_recipient_key() {
        let recipient = ElGamalKeypair::new_rand();
        let (gateway, mint, ata) = (
            Pubkey::new_unique(),
            Pubkey::new_unique(),
            Pubkey::new_unique(),
        );
        let token_program = Pubkey::from_str(programs::TOKEN_2022_PROGRAM).unwrap();
        for amount in [1u64, 65_535, 65_536, 1_000_000] {
            let tx = inline_transfer_tx(
                &gateway,
                &mint,
                &ata,
                recipient.pubkey(),
                None,
                amount,
                None,
            );
            assert_eq!(
                recover_bundle_transfer_amount(
                    &[tx],
                    &token_program,
                    &recipient,
                    AmountHandle::Destination
                )
                .unwrap(),
                amount
            );
        }
    }

    // A 1% fee credits the recipient 990 of a 1_000 transfer; the verifier
    // checks the gross amount the payer authorized, like `transferChecked`.
    #[test]
    fn fee_bearing_transfer_recovers_gross_amount() {
        let recipient = ElGamalKeypair::new_rand();
        let (gateway, mint, ata) = (
            Pubkey::new_unique(),
            Pubkey::new_unique(),
            Pubkey::new_unique(),
        );
        let token_program = Pubkey::from_str(programs::TOKEN_2022_PROGRAM).unwrap();
        let tx = inline_transfer_tx(
            &gateway,
            &mint,
            &ata,
            recipient.pubkey(),
            None,
            1_000,
            Some((100, 1_000_000)),
        );
        assert_eq!(
            recover_bundle_transfer_amount(
                &[tx],
                &token_program,
                &recipient,
                AmountHandle::Destination
            )
            .unwrap(),
            1_000
        );
    }

    #[test]
    fn recovery_rejects_a_transfer_encrypted_to_another_key() {
        let recipient = ElGamalKeypair::new_rand();
        let other = ElGamalKeypair::new_rand();
        let (gateway, mint, ata) = (
            Pubkey::new_unique(),
            Pubkey::new_unique(),
            Pubkey::new_unique(),
        );
        let token_program = Pubkey::from_str(programs::TOKEN_2022_PROGRAM).unwrap();
        let tx = inline_transfer_tx(&gateway, &mint, &ata, other.pubkey(), None, 500, None);
        let err = recover_bundle_transfer_amount(
            &[tx],
            &token_program,
            &recipient,
            AmountHandle::Destination,
        )
        .unwrap_err();
        assert!(err.message.contains("not encrypted"), "{}", err.message);
    }

    // Version-0 layout: the validity proof is verified into a context account
    // in an earlier transaction and the transfer names that account.
    #[test]
    fn recovers_amount_from_context_state_account() {
        use solana_address::Address;
        use solana_zk_elgamal_proof_interface::instruction::{ContextStateInfo, ProofInstruction};
        use spl_token_2022::extension::confidential_transfer::instruction::inner_transfer;
        use spl_token_confidential_transfer_proof_extraction::instruction::ProofLocation;

        let recipient = ElGamalKeypair::new_rand();
        let gateway = Pubkey::new_unique();
        let (mint, ata) = (Pubkey::new_unique(), Pubkey::new_unique());
        let token_program = Pubkey::from_str(programs::TOKEN_2022_PROGRAM).unwrap();
        let sender_elgamal = ElGamalKeypair::new_rand();
        let sender_ae = AeKey::new_rand();
        let amount = 70_000;
        let proof = transfer_split_proof_data(
            &sender_elgamal.pubkey().encrypt(SENDER_BALANCE),
            &sender_ae.encrypt(SENDER_BALANCE),
            amount,
            &sender_elgamal,
            &sender_ae,
            recipient.pubkey(),
            None,
        )
        .unwrap();
        let (equality_ctx, validity_ctx, range_ctx) = (
            Pubkey::new_unique(),
            Pubkey::new_unique(),
            Pubkey::new_unique(),
        );
        let gateway_addr = Address::from(gateway.to_bytes());
        let validity_addr = Address::from(validity_ctx.to_bytes());
        let verify = |context: &Address, amount_proof: &_| {
            ProofInstruction::VerifyBatchedGroupedCiphertext3HandlesValidity.encode_verify_proof(
                Some(ContextStateInfo {
                    context_state_account: context,
                    context_state_authority: &gateway_addr,
                }),
                amount_proof,
            )
        };
        let validity_tx = crate::core::tx::build_unsigned(
            TxVersion::V0,
            &gateway,
            &[verify(
                &validity_addr,
                &proof
                    .ciphertext_validity_proof_data_with_ciphertext
                    .proof_data,
            )],
            solana_hash::Hash::new_unique(),
            None,
        )
        .unwrap();
        let validity = &proof.ciphertext_validity_proof_data_with_ciphertext;
        let transfer = inner_transfer(
            &token_program,
            &Pubkey::new_unique(),
            &mint,
            &ata,
            &cast_ae_ciphertext_v7_to_legacy(&sender_ae.encrypt(SENDER_BALANCE - amount)),
            &crate::mpp::client::confidential::cast_elgamal_ciphertext_v7_to_legacy(
                &validity.ciphertext_lo,
            ),
            &crate::mpp::client::confidential::cast_elgamal_ciphertext_v7_to_legacy(
                &validity.ciphertext_hi,
            ),
            &Pubkey::new_unique(),
            &[],
            ProofLocation::ContextStateAccount(&equality_ctx),
            ProofLocation::ContextStateAccount(&validity_ctx),
            ProofLocation::ContextStateAccount(&range_ctx),
        )
        .unwrap();
        let transfer_tx = crate::core::tx::build_unsigned(
            TxVersion::V0,
            &gateway,
            &[transfer],
            solana_hash::Hash::new_unique(),
            None,
        )
        .unwrap();
        let bundle = [validity_tx.clone(), transfer_tx.clone()];
        assert_eq!(
            recover_bundle_transfer_amount(
                &bundle,
                &token_program,
                &recipient,
                AmountHandle::Destination
            )
            .unwrap(),
            amount
        );

        // A context the bundle never verifies cannot be attributed.
        let err = recover_bundle_transfer_amount(
            std::slice::from_ref(&transfer_tx),
            &token_program,
            &recipient,
            AmountHandle::Destination,
        )
        .unwrap_err();
        assert!(err.message.contains("not verified"), "{}", err.message);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn recipient_key_settlement_accepts_gross_amount_of_fee_bearing_transfer() {
        let server = recipient_key_server().await;
        let tx = inline_transfer_tx(
            &server.gateway,
            &server.mint,
            &server.recipient_ata,
            server.recipient_keys.elgamal.pubkey(),
            None,
            1_000,
            Some((100, 1_000_000)),
        );
        let err = server
            .mpp
            .settle_confidential_bundle(
                &encode_bundle(&[tx]),
                &request(1_000, &server.mint, server.mpp.recipient()),
                &server.method_details,
                &mut server.mpp.test_fence().await,
            )
            .await
            .unwrap_err();
        // Past the amount check: the next step is the (unreachable) RPC.
        assert!(
            err.message.contains("Simulation RPC error"),
            "{}",
            err.message
        );
    }

    async fn settle_error(
        server: &RecipientKeyServer,
        tx: VersionedTransaction,
        amount: u64,
    ) -> String {
        server
            .mpp
            .settle_confidential_bundle(
                &encode_bundle(&[tx]),
                &request(amount, &server.mint, server.mpp.recipient()),
                &server.method_details,
                &mut server.mpp.test_fence().await,
            )
            .await
            .unwrap_err()
            .message
    }

    // A facilitator that can decrypt nothing must not co-sign, pay for, and
    // receipt a transfer whose amount it cannot check.
    #[tokio::test(flavor = "multi_thread")]
    async fn facilitator_without_an_amount_key_rejects_bundles() {
        let server = confidential_server(false, None, false).await;
        let tx = inline_transfer_tx(
            &server.gateway,
            &server.mint,
            &server.recipient_ata,
            ElGamalKeypair::new_rand().pubkey(),
            None,
            1_000_000,
            None,
        );
        let message = settle_error(&server, tx, 1_000_000).await;
        assert!(message.contains("Cannot verify"), "{message}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn facilitator_with_auditor_key_enforces_the_amount() {
        let auditor = Arc::new(ElGamalKeypair::new_rand());
        let server = confidential_server(false, Some(auditor.clone()), false).await;
        let recipient = ElGamalKeypair::new_rand();
        let transfer = |amount| {
            inline_transfer_tx(
                &server.gateway,
                &server.mint,
                &server.recipient_ata,
                recipient.pubkey(),
                Some(auditor.pubkey()),
                amount,
                None,
            )
        };
        let message = settle_error(&server, transfer(499_999), 1_000_000).await;
        assert!(
            message.contains("recovered 499999, expected 1000000"),
            "{message}"
        );
        let message = settle_error(&server, transfer(1_000_001), 1_000_000).await;
        assert!(message.contains("amount mismatch"), "{message}");
        let message = settle_error(&server, transfer(1_000_000), 1_000_000).await;
        assert!(message.contains("Simulation RPC error"), "{message}");

        // A transfer without this auditor's handle cannot be verified.
        let tx = inline_transfer_tx(
            &server.gateway,
            &server.mint,
            &server.recipient_ata,
            recipient.pubkey(),
            None,
            1_000_000,
            None,
        );
        let message = settle_error(&server, tx, 1_000_000).await;
        assert!(message.contains("not encrypted"), "{message}");
    }

    #[test]
    fn malformed_auditor_keypair_is_rejected_at_boot() {
        let result = Mpp::new(super::super::charge::Config {
            realm: Some("test-realm".to_string()),
            recipient: Pubkey::new_unique().to_string(),
            currency: "SOL".to_string(),
            network: "localnet".to_string(),
            rpc_url: Some("http://127.0.0.1:1".to_string()),
            challenge_binding_secret: Some("x".repeat(32)),
            confidential_auditor: Some([0xff; 64]),
            store: Some(std::sync::Arc::new(crate::mpp::store::MemoryStore::new())),
            ..Default::default()
        });
        assert!(result.is_err());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn unverified_amount_requires_an_explicit_opt_in() {
        let server = confidential_server(false, None, true).await;
        let tx = inline_transfer_tx(
            &server.gateway,
            &server.mint,
            &server.recipient_ata,
            ElGamalKeypair::new_rand().pubkey(),
            None,
            1,
            None,
        );
        let message = settle_error(&server, tx, 1_000_000).await;
        assert!(message.contains("Simulation RPC error"), "{message}");
    }

    // Two concurrent half-amount settlements for the same recipient: the old
    // before/after pending-balance snapshot could see both credits as one
    // full payment each. The amount is bound to each bundle's own transfer, so
    // both are rejected before the gateway signs, independent of timing.
    #[tokio::test(flavor = "multi_thread")]
    async fn concurrent_half_amount_settlements_are_each_rejected() {
        let server = recipient_key_server().await;
        let charged = 1_000_000;
        let half = || {
            inline_transfer_tx(
                &server.gateway,
                &server.mint,
                &server.recipient_ata,
                server.recipient_keys.elgamal.pubkey(),
                None,
                charged / 2,
                None,
            )
        };
        let (first, second) = tokio::join!(
            settle_error(&server, half(), charged),
            settle_error(&server, half(), charged)
        );
        for message in [first, second] {
            assert!(
                message.contains("recovered 500000, expected 1000000"),
                "{message}"
            );
        }

        let full = inline_transfer_tx(
            &server.gateway,
            &server.mint,
            &server.recipient_ata,
            server.recipient_keys.elgamal.pubkey(),
            None,
            charged,
            None,
        );
        let message = settle_error(&server, full, charged).await;
        assert!(message.contains("Simulation RPC error"), "{message}");
    }

    /// Gateway-funded spl-record lifecycle pieces plus a minimal confidential
    /// transfer to `recipient_ata`, for layout tests.
    pub(crate) struct LayoutPieces {
        pub create: solana_instruction::Instruction,
        pub initialize: solana_instruction::Instruction,
        pub close: solana_instruction::Instruction,
        pub transfer: solana_instruction::Instruction,
    }

    pub(crate) fn layout_pieces(gateway: &Pubkey, recipient_ata: &Pubkey) -> LayoutPieces {
        use solana_instruction::{AccountMeta, Instruction};
        let record = client_key();
        let record_program = spl_record::id();
        LayoutPieces {
            create: solana_system_interface::instruction::create_account(
                gateway,
                &record,
                1_000,
                100,
                &record_program,
            ),
            initialize: Instruction {
                program_id: record_program,
                accounts: vec![
                    AccountMeta::new(record, false),
                    AccountMeta::new_readonly(*gateway, false),
                ],
                data: vec![0],
            },
            close: Instruction {
                program_id: record_program,
                accounts: vec![
                    AccountMeta::new(record, false),
                    AccountMeta::new_readonly(*gateway, true),
                    AccountMeta::new(*gateway, false),
                ],
                data: vec![3],
            },
            transfer: Instruction {
                program_id: Pubkey::from_str(programs::TOKEN_2022_PROGRAM).unwrap(),
                accounts: vec![
                    AccountMeta::new(Pubkey::new_unique(), false),
                    AccountMeta::new_readonly(Pubkey::new_unique(), false),
                    AccountMeta::new(*recipient_ata, false),
                ],
                data: vec![27, 7],
            },
        }
    }

    pub(crate) fn v0_tx(
        gateway: &Pubkey,
        ixs: &[solana_instruction::Instruction],
    ) -> VersionedTransaction {
        let mut tx = crate::core::tx::build_unsigned(
            TxVersion::V0,
            gateway,
            ixs,
            solana_hash::Hash::new_unique(),
            None,
        )
        .unwrap();
        sign_clients(&mut tx);
        tx
    }

    #[test]
    fn temporary_accounts_must_close_in_the_final_transaction() {
        let gateway = Pubkey::new_unique();
        let p = layout_pieces(&gateway, &Pubkey::new_unique());
        let setup = v0_tx(&gateway, &[p.create.clone(), p.initialize.clone()]);
        let early_close = v0_tx(
            &gateway,
            &[p.create.clone(), p.initialize.clone(), p.close.clone()],
        );
        let err = verify_confidential_account_lifecycle(
            &[
                early_close,
                v0_tx(&gateway, std::slice::from_ref(&p.transfer)),
            ],
            &gateway,
        )
        .unwrap_err();
        assert!(err.message.contains("final transaction"), "{}", err.message);

        verify_confidential_account_lifecycle(
            &[setup, v0_tx(&gateway, &[p.transfer, p.close])],
            &gateway,
        )
        .unwrap();
    }

    // A transfer that confirms before a later cleanup transaction fails would
    // leave the payer charged without a receipt; it must ride the final one.
    #[tokio::test(flavor = "multi_thread")]
    async fn version_zero_transfer_must_be_in_the_final_transaction() {
        let mut server = confidential_server(false, None, true).await;
        server.mpp.accepted_versions = vec![TxVersion::V0];
        let p = layout_pieces(&server.gateway, &server.recipient_ata);
        let settle = |txs: Vec<VersionedTransaction>| {
            let bundle = encode_bundle(&txs);
            let server = &server;
            async move {
                server
                    .mpp
                    .settle_confidential_bundle(
                        &bundle,
                        &request(1_000, &server.mint, server.mpp.recipient()),
                        &server.method_details,
                        &mut server.mpp.test_fence().await,
                    )
                    .await
                    .unwrap_err()
                    .message
            }
        };

        let transfer_first = vec![
            v0_tx(
                &server.gateway,
                &[p.create.clone(), p.initialize.clone(), p.transfer.clone()],
            ),
            v0_tx(&server.gateway, std::slice::from_ref(&p.close)),
        ];
        let message = settle(transfer_first).await;
        assert!(message.contains("final transaction"), "{message}");

        let builder_layout = vec![
            v0_tx(&server.gateway, &[p.create, p.initialize]),
            v0_tx(&server.gateway, &[p.transfer, p.close]),
        ];
        let message = settle(builder_layout).await;
        assert!(message.contains("Simulation RPC error"), "{message}");
    }

    // Bundle transactions land one at a time, so every client signature in
    // the bundle must verify before the gateway co-signs or pays for any.
    #[tokio::test(flavor = "multi_thread")]
    async fn bundle_signatures_are_verified_before_any_cosigning() {
        let mut server = confidential_server(false, None, true).await;
        server.mpp.accepted_versions = vec![TxVersion::V0];
        let p = layout_pieces(&server.gateway, &server.recipient_ata);
        let bundle = vec![
            v0_tx(&server.gateway, &[p.create, p.initialize]),
            v0_tx(&server.gateway, &[p.transfer, p.close]),
        ];
        let settle = |txs: Vec<VersionedTransaction>| {
            let bundle = encode_bundle(&txs);
            let server = &server;
            async move {
                server
                    .mpp
                    .settle_confidential_bundle(
                        &bundle,
                        &request(1_000, &server.mint, server.mpp.recipient()),
                        &server.method_details,
                        &mut server.mpp.test_fence().await,
                    )
                    .await
                    .unwrap_err()
                    .message
            }
        };

        // The ephemeral record signature on the setup transaction is corrupt.
        let mut corrupt = bundle.clone();
        corrupt[0].signatures[1] = solana_signature::Signature::from([1; 64]);
        let message = settle(corrupt).await;
        assert!(
            message.contains("Bundle tx 0: invalid client transaction signature"),
            "{message}"
        );

        // A pre-filled gateway slot is not the server's signature to trust.
        let mut prefilled = bundle.clone();
        prefilled[1].signatures[0] = solana_signature::Signature::from([2; 64]);
        let message = settle(prefilled).await;
        assert!(message.contains("must be empty"), "{message}");

        let message = settle(bundle).await;
        assert!(message.contains("Simulation RPC error"), "{message}");
    }

    fn record_write(
        record: &Pubkey,
        gateway: &Pubkey,
        offset: u64,
        len: usize,
    ) -> solana_instruction::Instruction {
        spl_record::instruction::write(record, gateway, offset, &vec![7u8; len])
    }

    // A fee-only (empty / compute-budget / stateless-proof) transaction before
    // the transfer costs the sponsor a signature fee and does nothing.
    #[test]
    fn non_final_transactions_must_advance_a_temporary_account() {
        let gateway = Pubkey::new_unique();
        let p = layout_pieces(&gateway, &Pubkey::new_unique());
        let final_tx = v0_tx(&gateway, &[p.transfer.clone(), p.close.clone()]);
        let setup = v0_tx(&gateway, &[p.create.clone(), p.initialize.clone()]);
        let budget = crate::core::tx::ComputeBudget::new(1_000_001, 10_000);
        let compute_only = crate::core::tx::build_unsigned(
            TxVersion::V0,
            &gateway,
            &[],
            solana_hash::Hash::new_unique(),
            Some(&budget),
        )
        .unwrap();
        let stateless_proof = v0_tx(
            &gateway,
            &[solana_instruction::Instruction {
                program_id: Pubkey::from_str(ZK_ELGAMAL_PROOF_PROGRAM).unwrap(),
                accounts: vec![],
                data: vec![12, 0, 0],
            }],
        );
        for filler in [v0_tx(&gateway, &[]), compute_only, stateless_proof] {
            let err = verify_confidential_account_lifecycle(
                &[setup.clone(), filler, final_tx.clone()],
                &gateway,
            )
            .unwrap_err();
            assert!(
                err.message.contains("advances no temporary account"),
                "{}",
                err.message
            );
        }
        verify_confidential_account_lifecycle(&[setup, final_tx], &gateway).unwrap();
    }

    // An empty record write advances nothing, so it cannot carry a filler tx.
    #[test]
    fn record_writes_must_carry_data() {
        let gateway = Pubkey::new_unique();
        let record = Pubkey::new_unique();
        let space = (100 + spl_record::state::RecordData::WRITABLE_START_INDEX) as u64;
        let create = solana_system_interface::instruction::create_account(
            &gateway,
            &record,
            1_000,
            space,
            &spl_record::id(),
        );
        let initialize = spl_record::instruction::initialize(&record, &gateway);
        let close = spl_record::instruction::close_account(&record, &gateway, &gateway);
        let p = layout_pieces(&gateway, &Pubkey::new_unique());
        let bundle = |len: usize| {
            [
                v0_tx(&gateway, &[create.clone(), initialize.clone()]),
                v0_tx(&gateway, &[record_write(&record, &gateway, 0, len)]),
                v0_tx(&gateway, &[p.create.clone(), p.initialize.clone()]),
                v0_tx(
                    &gateway,
                    &[p.transfer.clone(), p.close.clone(), close.clone()],
                ),
            ]
        };
        let err = verify_confidential_account_lifecycle(&bundle(0), &gateway).unwrap_err();
        assert!(
            err.message.contains("spl-record write is empty"),
            "{}",
            err.message
        );
        verify_confidential_account_lifecycle(&bundle(1), &gateway).unwrap();

        assert_eq!(
            RecordIx::parse(&spl_record::instruction::write(&record, &gateway, 0, &[7; 3]).data)
                .unwrap(),
            RecordIx::Write {
                length: std::num::NonZeroU32::new(3).unwrap()
            }
        );
        let mut trailing = spl_record::instruction::write(&record, &gateway, 0, &[7; 3]).data;
        trailing.push(0);
        assert!(RecordIx::parse(&trailing).is_err());
        assert!(RecordIx::parse(&trailing[..12]).is_err());
    }

    #[test]
    fn record_writes_are_bounded_by_the_record_capacity() {
        let gateway = Pubkey::new_unique();
        let record = Pubkey::new_unique();
        let record_program = spl_record::id();
        let capacity = 100usize;
        let space = (capacity + spl_record::state::RecordData::WRITABLE_START_INDEX) as u64;
        let create = solana_system_interface::instruction::create_account(
            &gateway,
            &record,
            1_000,
            space,
            &record_program,
        );
        let initialize = spl_record::instruction::initialize(&record, &gateway);
        let close = spl_record::instruction::close_account(&record, &gateway, &gateway);
        let p = layout_pieces(&gateway, &Pubkey::new_unique());
        let bundle = |writes: &[usize]| {
            let mut txs = vec![v0_tx(
                &gateway,
                &[
                    create.clone(),
                    initialize.clone(),
                    record_write(&record, &gateway, 0, writes[0]),
                ],
            )];
            let mut offset = writes[0] as u64;
            for len in &writes[1..] {
                txs.push(v0_tx(
                    &gateway,
                    &[record_write(&record, &gateway, offset, *len)],
                ));
                offset += *len as u64;
            }
            txs.push(v0_tx(&gateway, &[p.transfer.clone(), close.clone()]));
            txs
        };
        // Staging exactly the capacity in chunks is the builder's layout.
        verify_confidential_account_lifecycle(&bundle(&[60, 40]), &gateway).unwrap();
        // Re-writing chunks to pad the bundle with fee-bearing transactions.
        let err =
            verify_confidential_account_lifecycle(&bundle(&[60, 40, 1]), &gateway).unwrap_err();
        assert!(err.message.contains("more record data"), "{}", err.message);
        let err = verify_confidential_account_lifecycle(&bundle(&[60, 40, 40, 40]), &gateway)
            .unwrap_err();
        assert!(err.message.contains("more record data"), "{}", err.message);
    }

    /// Splice `extra` into the signer prefix without referencing it.
    fn insert_unreferenced_signers(tx: &mut VersionedTransaction, extra: &[Pubkey]) {
        use solana_message::VersionedMessage;
        let inserted = extra.len() as u8;
        let (header, account_keys, instructions) = match &mut tx.message {
            VersionedMessage::V0(m) => (&mut m.header, &mut m.account_keys, &mut m.instructions),
            VersionedMessage::Legacy(m) => {
                (&mut m.header, &mut m.account_keys, &mut m.instructions)
            }
            _ => panic!("expected a version-0 or legacy message"),
        };
        account_keys.splice(1..1, extra.iter().copied());
        for ix in instructions.iter_mut() {
            if ix.program_id_index >= 1 {
                ix.program_id_index += inserted;
            }
            for account in &mut ix.accounts {
                if *account >= 1 {
                    *account += inserted;
                }
            }
        }
        header.num_required_signatures += inserted;
        tx.signatures.splice(
            1..1,
            std::iter::repeat_n(solana_signature::Signature::default(), extra.len()),
        );
    }

    fn accepts(
        tx: &VersionedTransaction,
        gateway: &Pubkey,
        recipient_ata: &Pubkey,
    ) -> Result<usize, VerificationError> {
        verify_confidential_bundle_tx(
            tx,
            gateway,
            &Pubkey::from_str(programs::TOKEN_2022_PROGRAM).unwrap(),
            recipient_ata,
            &[TxVersion::V0, TxVersion::V1],
        )
    }

    // Fresh signer keys referenced by no instruction each add a sponsored
    // signature fee without authorizing anything.
    #[test]
    fn unreferenced_signers_are_rejected() {
        let gateway = Pubkey::new_unique();
        let ata = Pubkey::new_unique();
        let p = layout_pieces(&gateway, &ata);
        let mut tx = v0_tx(&gateway, &[p.transfer, p.close]);
        assert_eq!(accepts(&tx, &gateway, &ata).unwrap(), 1);
        insert_unreferenced_signers(
            &mut tx,
            &[
                Pubkey::new_unique(),
                Pubkey::new_unique(),
                Pubkey::new_unique(),
            ],
        );
        tx.sanitize().unwrap();
        let err = accepts(&tx, &gateway, &ata).unwrap_err();
        assert!(err.message.contains("unexpected signer"), "{}", err.message);

        let mut setup = v0_tx(&gateway, &[p.create, p.initialize]);
        assert_eq!(accepts(&setup, &gateway, &ata).unwrap(), 0);
        insert_unreferenced_signers(&mut setup, &[Pubkey::new_unique()]);
        let err = accepts(&setup, &gateway, &ata).unwrap_err();
        assert!(err.message.contains("unexpected signer"), "{}", err.message);
    }

    #[test]
    fn transfer_may_carry_only_one_authority_signer() {
        use solana_instruction::AccountMeta;
        let gateway = Pubkey::new_unique();
        let ata = Pubkey::new_unique();
        let mut transfer = layout_pieces(&gateway, &ata).transfer;
        transfer
            .accounts
            .push(AccountMeta::new_readonly(Pubkey::new_unique(), true));
        assert_eq!(
            accepts(&v0_tx(&gateway, &[transfer.clone()]), &gateway, &ata).unwrap(),
            1
        );
        transfer
            .accounts
            .push(AccountMeta::new_readonly(Pubkey::new_unique(), true));
        let err = accepts(&v0_tx(&gateway, &[transfer]), &gateway, &ata).unwrap_err();
        assert!(
            err.message.contains("more than one authority"),
            "{}",
            err.message
        );
    }

    // The builder's own transactions: gateway + sender for the inline
    // transfer, gateway + ephemeral account for a proof context.
    #[test]
    fn builder_signer_layouts_pass() {
        let gateway = Pubkey::new_unique();
        let ata = Pubkey::new_unique();
        let tx = inline_transfer_tx(
            &gateway,
            &Pubkey::new_unique(),
            &ata,
            ElGamalKeypair::new_rand().pubkey(),
            None,
            1_000,
            None,
        );
        assert_eq!(tx.message.header().num_required_signatures, 2);
        assert_eq!(accepts(&tx, &gateway, &ata).unwrap(), 1);
        let p = layout_pieces(&gateway, &ata);
        let setup = v0_tx(&gateway, &[p.create, p.initialize]);
        assert_eq!(setup.message.header().num_required_signatures, 2);
        assert_eq!(accepts(&setup, &gateway, &ata).unwrap(), 0);
    }

    #[test]
    fn bundle_funded_account_count_is_bounded() {
        let gateway = Pubkey::new_unique();
        let record_program = spl_record::id();
        let lifecycle = |count: usize| {
            let records: Vec<Pubkey> = (0..count).map(|_| Pubkey::new_unique()).collect();
            let mut txs: Vec<_> = records
                .iter()
                .map(|record| {
                    v0_tx(
                        &gateway,
                        &[
                            solana_system_interface::instruction::create_account(
                                &gateway,
                                record,
                                1_000,
                                100,
                                &record_program,
                            ),
                            spl_record::instruction::initialize(record, &gateway),
                        ],
                    )
                })
                .collect();
            let closes: Vec<_> = records
                .iter()
                .map(|record| spl_record::instruction::close_account(record, &gateway, &gateway))
                .collect();
            txs.push(v0_tx(&gateway, &closes));
            verify_confidential_account_lifecycle(&txs, &gateway)
        };
        lifecycle(MAX_CT_BUNDLE_FUNDED_ACCOUNTS).unwrap();
        let err = lifecycle(MAX_CT_BUNDLE_FUNDED_ACCOUNTS + 1).unwrap_err();
        assert!(
            err.message.contains("temporary accounts"),
            "{}",
            err.message
        );
    }
}
