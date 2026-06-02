//! Server-side payment verification for the Solana charge intent.
//!
//! # Quick Start
//!
//! ```ignore
//! use solana_mpp::server::Mpp;
//!
//! let mpp = Mpp::new(solana_mpp::server::Config {
//!     recipient: "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY".to_string(),
//!     ..Default::default()
//! })?;
//!
//! // Generate a charge challenge (returns HTTP 402)
//! let challenge = mpp.charge("0.10")?;
//!
//! // Verify a credential from Authorization header
//! let credential = solana_mpp::PaymentCredential::from_header(&auth_header)?;
//! let receipt = mpp.verify_credential(&credential).await?;
//! ```

use std::{collections::HashSet, sync::Arc};

use solana_message::compiled_instruction::CompiledInstruction;
use solana_pubkey::Pubkey;
use solana_rpc_client::rpc_client::RpcClient;
use solana_signature::Signature;
use solana_transaction::{versioned::VersionedTransaction, Transaction};
use solana_transaction_status::UiTransactionEncoding;
use std::str::FromStr;

use crate::error::Error;
use crate::protocol::core::{
    compute_challenge_id, Base64UrlJson, PaymentChallenge, PaymentCredential, Receipt,
};
use crate::protocol::intents::ChargeRequest;
use crate::protocol::solana::{programs, CredentialPayload, MethodDetails, Split};
use crate::store::{MemoryStore, Store};

const SECRET_KEY_ENV_VAR: &str = "MPP_SECRET_KEY";
const METHOD_NAME: &str = "solana";
const COMPUTE_BUDGET_PROGRAM: &str = "ComputeBudget111111111111111111111111111111";
const MAX_COMPUTE_UNIT_LIMIT: u32 = 200_000;
const MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS: u64 = 5_000_000;
const SIMULATION_MAX_ATTEMPTS: usize = 3;
const SIMULATION_RETRY_DELAY_MS: u64 = 400;

const DEFAULT_REALM: &str = "MPP Payment";

fn detect_challenge_binding_secret() -> Result<String, Error> {
    std::env::var(SECRET_KEY_ENV_VAR).map_err(|_| {
        Error::InvalidConfig(format!(
            "Missing {SECRET_KEY_ENV_VAR} env var. Set it or pass challenge_binding_secret explicitly."
        ))
    })
}

fn default_rpc_url(network: &str) -> &'static str {
    match network {
        "devnet" => "https://api.devnet.solana.com",
        "localnet" => "http://localhost:8899",
        _ => "https://api.mainnet-beta.solana.com",
    }
}

// ── Configuration ──

/// Server configuration.
#[derive(Clone)]
pub struct Config {
    /// Base58-encoded recipient public key.
    pub recipient: String,
    /// Currency: "sol" for native, mint address or symbol for SPL tokens.
    pub currency: String,
    /// Token decimals (default: 6 for USDC-like tokens).
    pub decimals: u8,
    /// Solana network: mainnet, devnet, or localnet.
    pub network: String,
    /// RPC URL (overrides default for the network).
    pub rpc_url: Option<String>,
    /// Server secret key for HMAC challenge IDs.
    pub challenge_binding_secret: Option<String>,
    /// Server realm.
    pub realm: Option<String>,
    /// Whether server pays transaction fees.
    pub fee_payer: bool,
    /// Fee payer signer (if fee_payer is true).
    pub fee_payer_signer: Option<Arc<dyn solana_keychain::SolanaSigner>>,
    /// Replay protection store (defaults to in-memory).
    pub store: Option<Arc<dyn Store>>,
    /// Enable HTML payment link pages for browser requests.
    pub html: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            recipient: String::new(),
            currency: "USDC".to_string(),
            decimals: 6,
            network: "mainnet".to_string(),
            rpc_url: None,
            challenge_binding_secret: None,
            realm: None,
            fee_payer: false,
            fee_payer_signer: None,
            store: None,
            html: false,
        }
    }
}

/// Options for generating a charge challenge.
#[derive(Debug, Clone, Default)]
pub struct ChargeOptions<'a> {
    pub description: Option<&'a str>,
    pub external_id: Option<&'a str>,
    pub expires: Option<&'a str>,
    pub fee_payer: bool,
    /// Resolved payment splits to embed in `methodDetails.splits`.
    pub splits: Vec<crate::protocol::solana::Split>,
}

// ── Mpp handler ──

/// Server-side payment handler for Solana.
///
/// Handles challenge generation and credential verification using
/// stateless HMAC-bound challenge IDs.
#[derive(Clone)]
pub struct Mpp {
    rpc: Arc<RpcClient>,
    rpc_url: String,
    realm: String,
    challenge_binding_secret: String,
    currency: String,
    recipient: String,
    decimals: u32,
    network: String,
    fee_payer: bool,
    fee_payer_signer: Option<Arc<dyn solana_keychain::SolanaSigner>>,
    store: Arc<dyn Store>,
    html: bool,
}

impl Mpp {
    /// Create a new payment handler from config.
    pub fn new(config: Config) -> Result<Self, Error> {
        if config.recipient.is_empty() {
            return Err(Error::InvalidConfig("recipient is required".into()));
        }
        Pubkey::from_str(&config.recipient)
            .map_err(|e| Error::InvalidConfig(format!("Invalid recipient pubkey: {e}")))?;

        let rpc_url = config
            .rpc_url
            .unwrap_or_else(|| default_rpc_url(&config.network).to_string());
        let challenge_binding_secret = config
            .challenge_binding_secret
            .map_or_else(detect_challenge_binding_secret, Ok)?;
        let realm = config.realm.unwrap_or_else(|| DEFAULT_REALM.to_string());
        let store: Arc<dyn Store> = config.store.unwrap_or_else(|| Arc::new(MemoryStore::new()));

        Ok(Mpp {
            rpc: Arc::new(RpcClient::new(rpc_url.clone())),
            rpc_url,
            realm,
            challenge_binding_secret,
            currency: config.currency,
            recipient: config.recipient,
            decimals: config.decimals as u32,
            network: config.network,
            fee_payer: config.fee_payer,
            fee_payer_signer: config.fee_payer_signer,
            store,
            html: config.html,
        })
    }

    // ── Accessors ──

    pub fn realm(&self) -> &str {
        &self.realm
    }

    pub fn currency(&self) -> &str {
        &self.currency
    }

    pub fn recipient(&self) -> &str {
        &self.recipient
    }

    pub fn decimals(&self) -> u32 {
        self.decimals
    }

    pub fn network(&self) -> &str {
        &self.network
    }

    pub fn rpc_url(&self) -> &str {
        &self.rpc_url
    }

    /// Whether HTML payment link pages are enabled.
    pub fn html_enabled(&self) -> bool {
        self.html
    }

    // ── Challenge generation ──

    /// Generate a charge challenge for a dollar amount (e.g., `"0.10"`).
    ///
    /// Amount is automatically converted from dollars to base units using
    /// the configured decimals (default: 6).
    pub fn charge(&self, amount: &str) -> Result<PaymentChallenge, Error> {
        self.charge_with_options(amount, ChargeOptions::default())
    }

    /// Generate a charge challenge with additional options.
    pub fn charge_with_options(
        &self,
        amount: &str,
        options: ChargeOptions<'_>,
    ) -> Result<PaymentChallenge, Error> {
        self.validate_charge_options(&options)?;
        let base_units = crate::protocol::intents::parse_units(amount, self.decimals as u8)?;

        let mut request = ChargeRequest {
            amount: base_units,
            currency: self.currency.clone(),
            recipient: Some(self.recipient.clone()),
            description: options.description.map(|s| s.to_string()),
            external_id: options.external_id.map(|s| s.to_string()),
            ..Default::default()
        };

        // Build Solana-specific method details.
        let mut details = serde_json::Map::new();
        details.insert("network".into(), serde_json::json!(self.network));
        details.insert("decimals".into(), serde_json::json!(self.decimals));

        if options.fee_payer || self.fee_payer {
            details.insert("feePayer".into(), serde_json::json!(true));
            if let Some(ref signer) = self.fee_payer_signer {
                details.insert(
                    "feePayerKey".into(),
                    serde_json::json!(signer.pubkey().to_string()),
                );
            }
        }

        // Include token program so the client doesn't need to look up the mint account.
        if self.currency.to_uppercase() != "SOL" {
            details.insert(
                "tokenProgram".into(),
                serde_json::json!(crate::protocol::solana::default_token_program_for_currency(
                    &self.currency,
                    Some(&self.network),
                )),
            );
        }

        // Embed payment splits so the client can build multi-transfer transactions.
        if !options.splits.is_empty() {
            details.insert(
                "splits".into(),
                serde_json::to_value(&options.splits).unwrap(),
            );
        }

        // Pre-fetch blockhash so the client doesn't need an extra RPC call.
        if let Ok(blockhash) = self.rpc.get_latest_blockhash() {
            details.insert(
                "recentBlockhash".into(),
                serde_json::json!(blockhash.to_string()),
            );
        }

        request.method_details = Some(serde_json::Value::Object(details));

        let encoded = Base64UrlJson::from_typed(&request)?;
        let default_expires = crate::expires::minutes(5);
        let expires = options.expires.unwrap_or(&default_expires);

        Ok(PaymentChallenge::with_challenge_binding_secret_full(
            &self.challenge_binding_secret,
            &self.realm,
            METHOD_NAME,
            "charge",
            encoded,
            Some(expires),
            None,
            options.description,
            None,
        ))
    }

    /// Generate the complete challenge set for a charge.
    pub fn charge_variants_with_options(
        &self,
        amount: &str,
        options: ChargeOptions<'_>,
    ) -> Result<Vec<PaymentChallenge>, Error> {
        self.charge_with_options(amount, options)
            .map(|challenge| vec![challenge])
    }

    fn validate_charge_options(&self, options: &ChargeOptions<'_>) -> Result<(), Error> {
        let has_ata_creation_splits = options
            .splits
            .iter()
            .any(|split| split.ata_creation_required == Some(true));
        if !has_ata_creation_splits {
            return Ok(());
        }

        if self.currency.eq_ignore_ascii_case("SOL") {
            return Err(Error::InvalidConfig(
                "ataCreationRequired requires an SPL token currency".into(),
            ));
        }
        if crate::protocol::solana::resolve_stablecoin_mint(&self.currency, Some(&self.network))
            != Some(self.currency.as_str())
        {
            return Err(Error::InvalidConfig(
                "ataCreationRequired requires currency to be an SPL token mint address".into(),
            ));
        }
        Pubkey::from_str(&self.currency).map_err(|e| {
            Error::InvalidConfig(format!(
                "ataCreationRequired requires a valid SPL token mint address: {e}"
            ))
        })?;

        Ok(())
    }

    /// Generate a charge challenge with explicit base-unit parameters.
    pub fn charge_challenge(&self, request: &ChargeRequest) -> Result<PaymentChallenge, Error> {
        self.charge_challenge_with_options(request, None, None)
    }

    /// Generate a charge challenge from a full request with options.
    pub fn charge_challenge_with_options(
        &self,
        request: &ChargeRequest,
        expires: Option<&str>,
        description: Option<&str>,
    ) -> Result<PaymentChallenge, Error> {
        let encoded = Base64UrlJson::from_typed(request)?;
        let default_expires = crate::expires::minutes(5);
        let expires = expires.unwrap_or(&default_expires);

        Ok(PaymentChallenge::with_challenge_binding_secret_full(
            &self.challenge_binding_secret,
            &self.realm,
            METHOD_NAME,
            "charge",
            encoded,
            Some(expires),
            None,
            description,
            None,
        ))
    }

    // ── Verification ──

    /// Verify a payment credential (simple API).
    ///
    /// Decodes the charge request from the echoed challenge automatically.
    pub async fn verify_credential(
        &self,
        credential: &PaymentCredential,
    ) -> Result<Receipt, VerificationError> {
        let request: ChargeRequest = credential
            .challenge
            .request
            .decode()
            .map_err(|e| VerificationError::new(format!("Failed to decode request: {e}")))?;
        self.verify(credential, &request).await
    }

    /// Verify with cross-route protection — ensures the credential matches
    /// the expected charge parameters for this endpoint.
    pub async fn verify_credential_with_expected(
        &self,
        credential: &PaymentCredential,
        expected: &ChargeRequest,
    ) -> Result<Receipt, VerificationError> {
        let request: ChargeRequest = credential
            .challenge
            .request
            .decode()
            .map_err(|e| VerificationError::new(format!("Failed to decode request: {e}")))?;

        if request.amount != expected.amount {
            return Err(VerificationError::credential_mismatch(format!(
                "Amount mismatch: credential has {} but endpoint expects {}",
                request.amount, expected.amount
            )));
        }
        if request.currency != expected.currency {
            return Err(VerificationError::credential_mismatch(format!(
                "Currency mismatch: credential has {} but endpoint expects {}",
                request.currency, expected.currency
            )));
        }
        if request.recipient != expected.recipient {
            return Err(VerificationError::credential_mismatch("Recipient mismatch"));
        }

        // Pass the route's expected request — not the credential-decoded one —
        // through to `verify`. From this point on, on-chain settlement checks
        // (transfer routing, splits, fee payer, token program) compare the
        // transaction against the route's configured method_details rather
        // than whatever the credential happens to claim.
        self.verify(credential, expected).await
    }

    /// Tier-2 pinned-field check.
    ///
    /// After Tier 1 (HMAC) confirms the echoed challenge was issued by this
    /// server, this compares economically-significant fields against the
    /// pinned `Mpp` configuration. It is the safety net for callers who use
    /// the simple `verify_credential` API: even when the credential's
    /// claimed request is trusted as-is, fields fixed at server construction
    /// (method, intent, realm, currency, recipient) cannot silently diverge.
    fn verify_pinned_fields(
        &self,
        credential: &PaymentCredential,
        request: &ChargeRequest,
    ) -> Result<(), VerificationError> {
        if credential.challenge.method.as_str() != METHOD_NAME {
            return Err(VerificationError::credential_mismatch(format!(
                "Credential method '{}' does not match this server (expected '{METHOD_NAME}')",
                credential.challenge.method
            )));
        }

        if !credential.challenge.intent.is_charge() {
            return Err(VerificationError::credential_mismatch(format!(
                "Credential intent '{}' is not a charge",
                credential.challenge.intent
            )));
        }

        // The HMAC ID is computed using the server's own realm (not the echoed
        // one), so a tampered realm would otherwise pass HMAC and reach
        // settlement unflagged. Pin it explicitly.
        if credential.challenge.realm != self.realm {
            return Err(VerificationError::credential_mismatch(format!(
                "Credential realm '{}' does not match this server (expected '{}')",
                credential.challenge.realm, self.realm
            )));
        }

        if request.currency != self.currency {
            return Err(VerificationError::credential_mismatch(format!(
                "Credential currency '{}' does not match this server (expected '{}')",
                request.currency, self.currency
            )));
        }

        if request.recipient.as_deref() != Some(self.recipient.as_str()) {
            return Err(VerificationError::credential_mismatch(
                "Credential recipient does not match this server",
            ));
        }

        Ok(())
    }

    /// Verify a charge credential with an explicit request.
    pub async fn verify(
        &self,
        credential: &PaymentCredential,
        request: &ChargeRequest,
    ) -> Result<Receipt, VerificationError> {
        // Tier 1: Verify HMAC.
        let expected_id = compute_challenge_id(
            &self.challenge_binding_secret,
            &self.realm,
            credential.challenge.method.as_str(),
            credential.challenge.intent.as_str(),
            credential.challenge.request.raw(),
            credential.challenge.expires.as_deref(),
            credential.challenge.digest.as_deref(),
            credential.challenge.opaque.as_ref().map(|o| o.raw()),
        );
        if credential.challenge.id != expected_id {
            return Err(VerificationError::credential_mismatch(
                "Challenge ID mismatch — not issued by this server",
            ));
        }

        // Check expiry.
        if let Some(ref expires) = credential.challenge.expires {
            if let Ok(expires_at) =
                time::OffsetDateTime::parse(expires, &time::format_description::well_known::Rfc3339)
            {
                if expires_at <= time::OffsetDateTime::now_utc() {
                    return Err(VerificationError::expired(format!(
                        "Challenge expired at {expires}"
                    )));
                }
            } else {
                return Err(VerificationError::new(
                    "Invalid expires timestamp in challenge",
                ));
            }
        }

        // Tier 2: Pinned-field backstop. Runs unconditionally so even simple
        // `verify_credential` callers are protected against cross-route replay
        // for the fields that are pinned at `Mpp` construction time.
        self.verify_pinned_fields(credential, request)?;

        // Deserialize the credential payload.
        let payload: CredentialPayload = serde_json::from_value(credential.payload.clone())
            .map_err(|e| {
                VerificationError::invalid_payload(format!("Invalid credential payload: {e}"))
            })?;

        let method_details: MethodDetails = request
            .method_details
            .as_ref()
            .map(|v| serde_json::from_value(v.clone()))
            .transpose()
            .map_err(|e| {
                VerificationError::invalid_payload(format!("Invalid method details: {e}"))
            })?
            .unwrap_or_default();

        // Settle, with the consume_signature reservation sitting between
        // broadcast and confirmation polling. If the server crashes or the
        // poll loop times out after the transaction has already landed,
        // the signature is still reserved so a retry of the same credential
        // cannot trigger a second broadcast. See PR #85 Greptile P1 and
        // audit gap G05.
        let signature_str = match payload {
            CredentialPayload::Transaction { ref transaction } => {
                let signature = self
                    .broadcast_pull(transaction, request, &method_details)
                    .await?;
                self.consume_signature(&signature).await?;
                self.await_pull_confirmation(&signature)?;
                signature
            }
            CredentialPayload::Signature { ref signature } => {
                // B34: reject push-mode credentials (`type=signature`) on
                // routes that require a server-side fee payer. A signature-
                // only credential references an already-landed transaction
                // that the client has paid the fee for, defeating the
                // purpose of a server-funded charge. Reject before any RPC
                // call so a partially-validated push credential never
                // touches the network. Ludo's spec lock; mirrors PHP #100
                // and Python #106.
                if method_details.fee_payer.unwrap_or(false) {
                    return Err(VerificationError::credential_mismatch(
                        "Push-mode credentials are not allowed when the route uses a server-side fee payer",
                    ));
                }
                let signature_str = self.verify_push(signature, request, &method_details)?;
                self.consume_signature(&signature_str).await?;
                signature_str
            }
        };

        Ok(Receipt::success(
            METHOD_NAME,
            &signature_str,
            credential.challenge.id.clone(),
        ))
    }

    // ── Settlement ──

    /// Reserve the settlement signature in the replay store. Returns an
    /// error if the same signature has already been consumed by an earlier
    /// successful settlement (replay attack) or an earlier broadcast whose
    /// confirmation poll timed out (split-brain double-pay window).
    async fn consume_signature(&self, signature_str: &str) -> Result<(), VerificationError> {
        let consumed_key = format!("solana-charge:consumed:{signature_str}");
        let inserted = self
            .store
            .put_if_absent(&consumed_key, serde_json::json!(true))
            .await
            .map_err(|e| VerificationError::new(format!("Store error: {e}")))?;
        if !inserted {
            return Err(VerificationError::signature_consumed(
                "Transaction signature already consumed",
            ));
        }
        Ok(())
    }

    /// Pull mode: deserialize tx, optionally co-sign, simulate, broadcast.
    /// Returns the signature once the broadcast is accepted. Confirmation
    /// polling lives in `await_pull_confirmation` so the caller can reserve
    /// the signature in the replay store between broadcast and poll.
    async fn broadcast_pull(
        &self,
        transaction_b64: &str,
        request: &ChargeRequest,
        method_details: &MethodDetails,
    ) -> Result<String, VerificationError> {
        let tx_bytes =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, transaction_b64)
                .map_err(|e| {
                    VerificationError::invalid_payload(format!("Invalid base64 transaction: {e}"))
                })?;

        // Accept legacy transactions and v0 transactions. For v0, we only
        // allow static account keys so the pre-broadcast verifier can inspect
        // the exact account set without resolving address lookup tables.
        let mut tx: VersionedTransaction = bincode::deserialize::<Transaction>(&tx_bytes)
            .map(VersionedTransaction::from)
            .or_else(|_| bincode::deserialize::<VersionedTransaction>(&tx_bytes))
            .map_err(|e| VerificationError::invalid_payload(format!("Invalid transaction: {e}")))?;

        let t0 = std::time::Instant::now();

        // Reject up-front if the client signed against the wrong network
        // (e.g. mainnet keypair pointed at a sandbox-configured server, or
        // vice versa). Cheaper and clearer than letting the broadcast fail.
        check_network_blockhash(&self.network, &tx.message.recent_blockhash().to_string())?;

        // Verify the transaction instructions BEFORE co-signing or broadcasting.
        verify_versioned_transaction_pre_broadcast(&tx, request, method_details)?;
        tracing::info!(elapsed_ms = %t0.elapsed().as_millis(), step = "pre_broadcast_check", "verify_pull");

        // Co-sign if server is fee payer (only after verification passes).
        if method_details.fee_payer.unwrap_or(false) {
            let signer = self.fee_payer_signer.as_ref().ok_or_else(|| {
                VerificationError::new("Fee payer enabled but no signer configured")
            })?;
            let msg_data = tx.message.serialize();
            let sig_bytes = signer
                .sign_message(&msg_data)
                .await
                .map_err(|e| VerificationError::new(format!("Fee payer signing failed: {e}")))?;
            let sig = Signature::from(<[u8; 64]>::from(sig_bytes));
            let fee_payer_pubkey = signer.pubkey();
            let account_keys = tx.message.static_account_keys();
            let idx = tx
                .message
                .static_account_keys()
                .iter()
                .position(|k| k == &fee_payer_pubkey)
                .ok_or_else(|| {
                    VerificationError::invalid_payload(
                        "Fee payer not found in transaction accounts",
                    )
                })?;
            if idx >= tx.signatures.len() || account_keys.get(idx) != Some(&fee_payer_pubkey) {
                return Err(VerificationError::invalid_payload(
                    "Fee payer is not a required signer in the transaction",
                ));
            }
            tx.signatures[idx] = sig;
        }
        tracing::info!(elapsed_ms = %t0.elapsed().as_millis(), step = "cosign", "verify_pull");

        // Simulate before broadcasting (prevent fee loss). Retry a few times:
        // RPC backends can briefly lag after a just-confirmed transaction
        // creates an account that this payment now depends on.
        let mut simulated = false;
        for attempt in 1..=SIMULATION_MAX_ATTEMPTS {
            let sim = match self.rpc.simulate_transaction(&tx) {
                Ok(sim) => sim,
                Err(err) => {
                    let message = format!("Simulation RPC error: {err}");
                    let retrying = attempt < SIMULATION_MAX_ATTEMPTS;
                    tracing::warn!(
                        elapsed_ms = %t0.elapsed().as_millis(),
                        attempt,
                        max_attempts = SIMULATION_MAX_ATTEMPTS,
                        retrying,
                        error = %err,
                        "verify_pull simulation rpc error"
                    );
                    if retrying {
                        std::thread::sleep(std::time::Duration::from_millis(
                            SIMULATION_RETRY_DELAY_MS,
                        ));
                        continue;
                    }
                    return Err(VerificationError::network_error(message));
                }
            };

            if let Some(err) = sim.value.err {
                // Include program logs for actionable diagnostics.
                // Solana's TransactionError alone is opaque (e.g. "custom program
                // error: 0x1"), but the logs reveal the actual cause.
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

                let retrying = attempt < SIMULATION_MAX_ATTEMPTS;
                // Best-effort balance diagnostics add extra RPC calls, so only
                // run them when this failure is about to be returned.
                let balance_detail = if retrying {
                    String::new()
                } else {
                    diagnose_balances(&self.rpc, &tx, request, method_details)
                };
                let message = format!("Simulation failed: {err}{log_detail}{balance_detail}");
                tracing::warn!(
                    elapsed_ms = %t0.elapsed().as_millis(),
                    attempt,
                    max_attempts = SIMULATION_MAX_ATTEMPTS,
                    retrying,
                    error = %err,
                    logs = ?logs,
                    detail = %message,
                    "verify_pull simulation failed"
                );
                if retrying {
                    std::thread::sleep(std::time::Duration::from_millis(SIMULATION_RETRY_DELAY_MS));
                    continue;
                }
                return Err(VerificationError::transaction_failed(message));
            }

            simulated = true;
            break;
        }
        if !simulated {
            return Err(VerificationError::network_error(
                "Simulation did not complete".to_string(),
            ));
        }
        tracing::info!(elapsed_ms = %t0.elapsed().as_millis(), step = "simulate", "verify_pull");

        // Broadcast. Confirmation polling moved into await_pull_confirmation
        // so the caller can reserve the signature in the replay store
        // between broadcast acceptance and confirmation polling.
        let signature = self
            .rpc
            .send_transaction(&tx)
            .map_err(|e| VerificationError::network_error(format!("Broadcast failed: {e}")))?;
        tracing::info!(elapsed_ms = %t0.elapsed().as_millis(), step = "send", "broadcast_pull");
        Ok(signature.to_string())
    }

    /// Poll for `Confirmed` commitment on a signature that broadcast_pull
    /// already accepted. Surfpool typically confirms within a single tick;
    /// a real RPC may need up to ~32 slots (~12 seconds).
    fn await_pull_confirmation(&self, signature_str: &str) -> Result<(), VerificationError> {
        use solana_commitment_config::CommitmentConfig;
        use std::str::FromStr;
        let signature = Signature::from_str(signature_str).map_err(|e| {
            VerificationError::invalid_payload(format!("Invalid settlement signature: {e}"))
        })?;
        let commitment = CommitmentConfig::confirmed();
        let t0 = std::time::Instant::now();
        for _ in 0..30 {
            match self
                .rpc
                .confirm_transaction_with_commitment(&signature, commitment)
            {
                Ok(resp) if resp.value => {
                    tracing::info!(elapsed_ms = %t0.elapsed().as_millis(), step = "confirmed", "await_pull_confirmation");
                    return Ok(());
                }
                _ => std::thread::sleep(std::time::Duration::from_millis(200)),
            }
        }
        Err(VerificationError::network_error(
            "Transaction not confirmed within timeout".to_string(),
        ))
    }

    /// Push mode: fetch tx by signature, verify on-chain.
    fn verify_push(
        &self,
        signature_str: &str,
        request: &ChargeRequest,
        method_details: &MethodDetails,
    ) -> Result<String, VerificationError> {
        self.verify_on_chain(signature_str, request, method_details)?;
        Ok(signature_str.to_string())
    }

    /// Verify that the on-chain transaction matches the expected charge parameters.
    fn verify_on_chain(
        &self,
        signature_str: &str,
        request: &ChargeRequest,
        method_details: &MethodDetails,
    ) -> Result<(), VerificationError> {
        let signature = Signature::from_str(signature_str)
            .map_err(|e| VerificationError::invalid_payload(format!("Invalid signature: {e}")))?;

        let tx = self
            .rpc
            .get_transaction(&signature, UiTransactionEncoding::JsonParsed)
            .map_err(|e| {
                if e.to_string().contains("not found") {
                    VerificationError::not_found("Transaction not found or not yet confirmed")
                } else {
                    VerificationError::network_error(format!("RPC error: {e}"))
                }
            })?;

        // Check for on-chain error.
        if let Some(meta) = &tx.transaction.meta {
            if meta.err.is_some() {
                return Err(VerificationError::transaction_failed(format!(
                    "Transaction failed: {:?}",
                    meta.err
                )));
            }
        }

        let total_amount: u64 = request.amount.parse().map_err(|_| {
            VerificationError::invalid_amount(format!("Invalid amount: {}", request.amount))
        })?;

        let splits = method_details.splits.as_deref().unwrap_or(&[]);
        let splits_total: u64 = splits
            .iter()
            .filter_map(|s| s.amount.parse::<u64>().ok())
            .sum();
        let primary_amount = total_amount.checked_sub(splits_total).ok_or_else(|| {
            VerificationError::invalid_amount("Split amounts exceed total amount")
        })?;
        if primary_amount == 0 {
            return Err(VerificationError::invalid_amount(
                "Primary amount is zero after splits",
            ));
        }

        let recipient = request.recipient.as_deref().ok_or_else(|| {
            VerificationError::invalid_recipient("No recipient in charge request")
        })?;

        let is_native_sol = request.currency.to_uppercase() == "SOL";
        let instructions = extract_parsed_instructions(&tx)?;
        let expected_ata_payer = if method_details.fee_payer.unwrap_or(false) {
            method_details.fee_payer_key.as_deref()
        } else {
            None
        };
        let fee_payer_pubkey = expected_ata_payer
            .map(|key| {
                Pubkey::from_str(key).map_err(|e| {
                    VerificationError::invalid_payload(format!("Invalid fee payer: {e}"))
                })
            })
            .transpose()?;
        let _recipient_pubkey = Pubkey::from_str(recipient)
            .map_err(|e| VerificationError::invalid_recipient(format!("Invalid recipient: {e}")))?;
        let ata_policy = expected_ata_creation_policy(splits, fee_payer_pubkey.as_ref())?;
        let allowed_ata_owners = ata_policy
            .allowed_owners
            .iter()
            .map(ToString::to_string)
            .collect::<HashSet<_>>();
        let required_ata_owners = ata_policy
            .required_owners
            .iter()
            .map(ToString::to_string)
            .collect::<HashSet<_>>();

        if is_native_sol {
            if splits
                .iter()
                .any(|split| split.ata_creation_required == Some(true))
            {
                return Err(VerificationError::invalid_payload(
                    "ataCreationRequired requires an SPL token charge",
                ));
            }
            let matched = verify_sol_transfers(&instructions, recipient, primary_amount, splits)?;
            let mut matched = matched;
            verify_parsed_memo_instructions(
                &instructions,
                request.external_id.as_deref(),
                splits,
                &mut matched,
            )?;
            validate_parsed_instruction_allowlist(
                &instructions,
                &matched,
                None,
                &allowed_ata_owners,
                None,
                expected_ata_payer,
                &required_ata_owners,
            )?;
        } else {
            let expected_mint =
                resolve_expected_mint(&request.currency, method_details.network.as_deref())?;
            if !required_ata_owners.is_empty() && request.currency != expected_mint.to_string() {
                return Err(VerificationError::invalid_payload(
                    "ataCreationRequired requires currency to be an SPL token mint address",
                ));
            }
            let expected_token_program =
                method_details.token_program.as_deref().unwrap_or_else(|| {
                    crate::protocol::solana::default_token_program_for_currency(
                        &request.currency,
                        method_details.network.as_deref(),
                    )
                });
            let mut matched = verify_spl_transfers(
                &instructions,
                recipient,
                &expected_mint.to_string(),
                primary_amount,
                splits,
                Some(expected_token_program),
            )?;
            verify_parsed_memo_instructions(
                &instructions,
                request.external_id.as_deref(),
                splits,
                &mut matched,
            )?;
            validate_parsed_instruction_allowlist(
                &instructions,
                &matched,
                Some(&expected_mint.to_string()),
                &allowed_ata_owners,
                Some(expected_token_program),
                expected_ata_payer,
                &required_ata_owners,
            )?;
        }

        Ok(())
    }
}

// ── Network / blockhash sanity check ──
//
// The Surfpool localnet implementation embeds a recognizable prefix into
// every blockhash it returns. We use this to catch the common footgun
// where a client signs a transaction against a Surfpool RPC and submits
// it to a server configured for a real cluster (mainnet/devnet).
//
// The check is asymmetric:
//
// - If the blockhash starts with the Surfpool prefix, the transaction
//   was DEFINITELY signed against a Surfpool localnet. The only network
//   slug for which that's valid is `localnet` — any other slug must
//   reject the credential up-front, before wasting an RPC round trip
//   on a doomed broadcast that will surface as a confusing "transaction
//   not found" error.
//
// - If the blockhash does NOT start with the Surfpool prefix, we can't
//   tell what cluster it came from (real localnet doesn't add a prefix
//   either), so we accept it and let the broadcast/simulate path
//   surface any genuine mismatch.

/// Base58 prefix embedded in every blockhash returned by the Surfpool
/// localnet implementation. Servers configured for any network OTHER than
/// `localnet` use this prefix to detect wrong-RPC client mistakes.
pub const SURFPOOL_BLOCKHASH_PREFIX: &str = "SURFNETxSAFEHASH";

/// Network slug for Solana's local validator. The only network for which
/// a Surfpool-prefixed blockhash is valid.
pub const LOCALNET_NETWORK: &str = "localnet";

/// Pure check: rejects a credential if the signed blockhash carries the
/// Surfpool prefix and the server is configured for any network other
/// than `localnet`.
///
/// Returns `Ok(())` in every other case — a non-Surfpool blockhash is
/// undetectable as wrong-cluster from the slug alone, so we let the
/// downstream broadcast handle it.
pub fn check_network_blockhash(
    network: &str,
    blockhash_b58: &str,
) -> Result<(), VerificationError> {
    if !blockhash_b58.starts_with(SURFPOOL_BLOCKHASH_PREFIX) {
        return Ok(());
    }
    if network == LOCALNET_NETWORK {
        return Ok(());
    }
    Err(VerificationError::wrong_network(format!(
        "Signed against localnet but the server expects {network}. \
         Switch your client RPC to {network} and re-sign."
    )))
}

// ── Pre-broadcast verification ──
//
// Inspects the raw Transaction instructions to verify amounts and recipients
// BEFORE broadcasting, preventing fund loss on invalid credentials.

#[cfg(test)]
fn verify_transaction_pre_broadcast(
    tx: &Transaction,
    request: &ChargeRequest,
    method_details: &MethodDetails,
) -> Result<(), VerificationError> {
    verify_versioned_transaction_pre_broadcast(
        &VersionedTransaction::from(tx.clone()),
        request,
        method_details,
    )
}

fn verify_versioned_transaction_pre_broadcast(
    tx: &VersionedTransaction,
    request: &ChargeRequest,
    method_details: &MethodDetails,
) -> Result<(), VerificationError> {
    reject_address_lookup_tables(tx)?;

    let splits = method_details.splits.as_deref().unwrap_or(&[]);
    if splits.len() > 8 {
        return Err(VerificationError::too_many_splits(format!(
            "Too many splits: {} (maximum 8)",
            splits.len()
        )));
    }

    let total_amount: u64 = request.amount.parse().map_err(|_| {
        VerificationError::invalid_amount(format!("Invalid amount: {}", request.amount))
    })?;
    let splits_total: u64 = splits
        .iter()
        .filter_map(|s| s.amount.parse::<u64>().ok())
        .sum();
    let primary_amount = total_amount
        .checked_sub(splits_total)
        .ok_or_else(|| VerificationError::invalid_amount("Split amounts exceed total amount"))?;
    if primary_amount == 0 {
        return Err(VerificationError::invalid_amount(
            "Primary amount is zero after splits",
        ));
    }

    let recipient = request
        .recipient
        .as_deref()
        .ok_or_else(|| VerificationError::invalid_recipient("No recipient in charge request"))?;
    let recipient_pk = Pubkey::from_str(recipient)
        .map_err(|e| VerificationError::invalid_recipient(format!("Invalid recipient: {e}")))?;

    let fee_payer = expected_fee_payer(tx, method_details)?;
    let is_native_sol = request.currency.to_uppercase() == "SOL";
    if is_native_sol
        && splits
            .iter()
            .any(|split| split.ata_creation_required == Some(true))
    {
        return Err(VerificationError::invalid_payload(
            "ataCreationRequired requires an SPL token charge",
        ));
    }
    let account_keys = tx.message.static_account_keys();
    let mut matched_instruction_indexes = HashSet::new();
    let mut expected_recipients = vec![recipient_pk];
    let ata_policy = expected_ata_creation_policy(splits, fee_payer.as_ref())?;

    if is_native_sol {
        verify_sol_transfer_instructions(
            tx,
            account_keys,
            &recipient_pk,
            primary_amount,
            fee_payer.as_ref(),
            &mut matched_instruction_indexes,
        )?;
        for split in splits {
            let split_pk = Pubkey::from_str(&split.recipient).map_err(|e| {
                VerificationError::invalid_recipient(format!("Invalid split recipient: {e}"))
            })?;
            expected_recipients.push(split_pk);
            let amt: u64 = split
                .amount
                .parse()
                .map_err(|_| VerificationError::invalid_amount("Invalid split amount"))?;
            verify_sol_transfer_instructions(
                tx,
                account_keys,
                expected_recipients.last().unwrap(),
                amt,
                fee_payer.as_ref(),
                &mut matched_instruction_indexes,
            )?;
        }
        verify_memo_instructions(
            tx,
            account_keys,
            request.external_id.as_deref(),
            splits,
            &mut matched_instruction_indexes,
        )?;
        validate_instruction_allowlist(
            tx,
            account_keys,
            &matched_instruction_indexes,
            None,
            &ata_policy.allowed_owners,
            None,
            fee_payer.as_ref(),
            &ata_policy.required_owners,
        )?;
    } else {
        let expected_mint =
            resolve_expected_mint(&request.currency, method_details.network.as_deref())?;
        if !ata_policy.required_owners.is_empty() && request.currency != expected_mint.to_string() {
            return Err(VerificationError::invalid_payload(
                "ataCreationRequired requires currency to be an SPL token mint address",
            ));
        }
        let expected_token_program = expected_token_program(method_details)?;
        verify_spl_transfer_instructions(
            tx,
            account_keys,
            &recipient_pk,
            &expected_mint,
            primary_amount,
            expected_token_program.as_ref(),
            method_details.decimals,
            fee_payer.as_ref(),
            &mut matched_instruction_indexes,
        )?;
        for split in splits {
            let split_pk = Pubkey::from_str(&split.recipient).map_err(|e| {
                VerificationError::invalid_recipient(format!("Invalid split recipient: {e}"))
            })?;
            expected_recipients.push(split_pk);
            let amt: u64 = split
                .amount
                .parse()
                .map_err(|_| VerificationError::invalid_amount("Invalid split amount"))?;
            verify_spl_transfer_instructions(
                tx,
                account_keys,
                expected_recipients.last().unwrap(),
                &expected_mint,
                amt,
                expected_token_program.as_ref(),
                method_details.decimals,
                fee_payer.as_ref(),
                &mut matched_instruction_indexes,
            )?;
        }
        verify_memo_instructions(
            tx,
            account_keys,
            request.external_id.as_deref(),
            splits,
            &mut matched_instruction_indexes,
        )?;
        validate_instruction_allowlist(
            tx,
            account_keys,
            &matched_instruction_indexes,
            Some(&expected_mint),
            &ata_policy.allowed_owners,
            expected_token_program.as_ref(),
            fee_payer.as_ref(),
            &ata_policy.required_owners,
        )?;
    }

    Ok(())
}

struct AtaCreationPolicy {
    allowed_owners: HashSet<Pubkey>,
    required_owners: HashSet<Pubkey>,
}

fn expected_ata_creation_policy(
    splits: &[Split],
    fee_payer: Option<&Pubkey>,
) -> Result<AtaCreationPolicy, VerificationError> {
    let mut required_owners = HashSet::new();
    let mut split_owners = Vec::with_capacity(splits.len());
    for split in splits {
        let owner = Pubkey::from_str(&split.recipient).map_err(|e| {
            VerificationError::invalid_recipient(format!("Invalid split recipient: {e}"))
        })?;
        if split.ata_creation_required == Some(true) {
            required_owners.insert(owner);
        }
        split_owners.push(owner);
    }

    let allowed_owners = if fee_payer.is_some() {
        required_owners.clone()
    } else {
        split_owners.into_iter().collect()
    };

    Ok(AtaCreationPolicy {
        allowed_owners,
        required_owners,
    })
}

fn reject_address_lookup_tables(tx: &VersionedTransaction) -> Result<(), VerificationError> {
    if tx
        .message
        .address_table_lookups()
        .is_some_and(|lookups| !lookups.is_empty())
    {
        return Err(VerificationError::invalid_payload(
            "v0 transactions with address lookup tables are not supported",
        ));
    }

    Ok(())
}

fn expected_fee_payer(
    tx: &VersionedTransaction,
    method_details: &MethodDetails,
) -> Result<Option<Pubkey>, VerificationError> {
    if !method_details.fee_payer.unwrap_or(false) {
        return Ok(None);
    }

    let fee_payer_key = method_details.fee_payer_key.as_deref().ok_or_else(|| {
        VerificationError::invalid_payload("feePayer=true requires feePayerKey in methodDetails")
    })?;
    let fee_payer = Pubkey::from_str(fee_payer_key)
        .map_err(|e| VerificationError::invalid_payload(format!("Invalid fee payer: {e}")))?;
    let tx_fee_payer = tx
        .message
        .static_account_keys()
        .first()
        .ok_or_else(|| VerificationError::invalid_payload("Transaction has no fee payer"))?;

    if tx_fee_payer != &fee_payer {
        return Err(VerificationError::invalid_payload(format!(
            "Transaction fee payer must be {fee_payer}"
        )));
    }

    Ok(Some(fee_payer))
}

fn expected_token_program(
    method_details: &MethodDetails,
) -> Result<Option<Pubkey>, VerificationError> {
    let Some(token_program) = method_details.token_program.as_deref() else {
        return Ok(None);
    };

    if token_program != programs::TOKEN_PROGRAM && token_program != programs::TOKEN_2022_PROGRAM {
        return Err(VerificationError::invalid_payload(format!(
            "Unsupported token program: {token_program}"
        )));
    }

    Pubkey::from_str(token_program)
        .map(Some)
        .map_err(|e| VerificationError::invalid_payload(format!("Invalid token program: {e}")))
}

fn account_key<'a>(
    account_keys: &'a [Pubkey],
    index: u8,
    label: &str,
) -> Result<&'a Pubkey, VerificationError> {
    account_keys
        .get(index as usize)
        .ok_or_else(|| VerificationError::invalid_payload(format!("Invalid {label} index")))
}

#[allow(clippy::too_many_arguments)]
fn validate_instruction_allowlist(
    tx: &VersionedTransaction,
    account_keys: &[Pubkey],
    matched_payment_instruction_indexes: &HashSet<usize>,
    expected_mint: Option<&Pubkey>,
    allowed_ata_owners: &HashSet<Pubkey>,
    expected_token_program: Option<&Pubkey>,
    fee_payer: Option<&Pubkey>,
    required_ata_owners: &HashSet<Pubkey>,
) -> Result<(), VerificationError> {
    let compute_budget_program = Pubkey::from_str(COMPUTE_BUDGET_PROGRAM).unwrap();
    let system_program = Pubkey::from_str(programs::SYSTEM_PROGRAM).unwrap();
    let token_program = Pubkey::from_str(programs::TOKEN_PROGRAM).unwrap();
    let token_2022_program = Pubkey::from_str(programs::TOKEN_2022_PROGRAM).unwrap();
    let ata_program = Pubkey::from_str(programs::ASSOCIATED_TOKEN_PROGRAM).unwrap();
    let tx_fee_payer = tx
        .message
        .static_account_keys()
        .first()
        .ok_or_else(|| VerificationError::invalid_payload("Transaction has no fee payer"))?;
    let expected_ata_payer = fee_payer.unwrap_or(tx_fee_payer);
    let mut created_ata_owners = HashSet::new();

    for (index, ix) in tx.message.instructions().iter().enumerate() {
        let program_id = account_keys
            .get(ix.program_id_index as usize)
            .ok_or_else(|| VerificationError::invalid_payload("Invalid program_id_index"))?;

        if program_id == &compute_budget_program {
            validate_compute_budget_instruction(ix)?;
            continue;
        }

        if program_id == &Pubkey::from_str(programs::MEMO_PROGRAM).unwrap() {
            if matched_payment_instruction_indexes.contains(&index) {
                continue;
            }
            return Err(VerificationError::invalid_payload(
                "Unexpected Memo Program instruction in payment transaction",
            ));
        }

        if program_id == &system_program {
            if matched_payment_instruction_indexes.contains(&index) {
                continue;
            }
            return Err(VerificationError::invalid_payload(
                "Unexpected System Program instruction in payment transaction",
            ));
        }

        if program_id == &token_program || program_id == &token_2022_program {
            if matched_payment_instruction_indexes.contains(&index) {
                continue;
            }
            return Err(VerificationError::invalid_payload(
                "Unexpected Token Program instruction in payment transaction",
            ));
        }

        if program_id == &ata_program {
            let owner = validate_create_ata_idempotent_instruction(
                ix,
                account_keys,
                expected_mint,
                allowed_ata_owners,
                expected_token_program,
                expected_ata_payer,
            )?;
            created_ata_owners.insert(owner);
            continue;
        }

        return Err(VerificationError::invalid_payload(format!(
            "Unexpected program instruction in payment transaction: {program_id}"
        )));
    }

    for owner in required_ata_owners {
        if !created_ata_owners.contains(owner) {
            return Err(VerificationError::invalid_payload(format!(
                "Missing required ATA creation instruction for split recipient {owner}"
            )));
        }
    }

    Ok(())
}

fn validate_compute_budget_instruction(ix: &CompiledInstruction) -> Result<(), VerificationError> {
    if !ix.accounts.is_empty() {
        return Err(VerificationError::invalid_payload(
            "Compute budget instruction must not have accounts",
        ));
    }

    match ix.data.first().copied() {
        Some(2) if ix.data.len() == 5 => {
            let units = u32::from_le_bytes(ix.data[1..5].try_into().unwrap());
            if units > MAX_COMPUTE_UNIT_LIMIT {
                return Err(VerificationError::invalid_payload(format!(
                    "Compute unit limit {units} exceeds maximum {MAX_COMPUTE_UNIT_LIMIT}"
                )));
            }
            Ok(())
        }
        Some(3) if ix.data.len() == 9 => {
            let price = u64::from_le_bytes(ix.data[1..9].try_into().unwrap());
            if price > MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS {
                return Err(VerificationError::invalid_payload(format!(
                    "Compute unit price {price} exceeds maximum {MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS}"
                )));
            }
            Ok(())
        }
        _ => Err(VerificationError::invalid_payload(
            "Unsupported compute budget instruction",
        )),
    }
}

fn validate_create_ata_idempotent_instruction(
    ix: &CompiledInstruction,
    account_keys: &[Pubkey],
    expected_mint: Option<&Pubkey>,
    allowed_ata_owners: &HashSet<Pubkey>,
    expected_token_program: Option<&Pubkey>,
    expected_payer: &Pubkey,
) -> Result<Pubkey, VerificationError> {
    let Some(expected_mint) = expected_mint else {
        return Err(VerificationError::invalid_payload(
            "ATA creation is not allowed for native SOL payments",
        ));
    };

    if ix.data.as_slice() != [1] {
        return Err(VerificationError::invalid_payload(
            "Only idempotent ATA creation is allowed",
        ));
    }
    if ix.accounts.len() != 6 {
        return Err(VerificationError::invalid_payload(
            "Unexpected ATA creation account layout",
        ));
    }

    let payer = account_key(account_keys, ix.accounts[0], "ATA payer")?;
    let ata = account_key(account_keys, ix.accounts[1], "ATA address")?;
    let owner = account_key(account_keys, ix.accounts[2], "ATA owner")?;
    let mint = account_key(account_keys, ix.accounts[3], "ATA mint")?;
    let system_program = account_key(account_keys, ix.accounts[4], "ATA system program")?;
    let token_program = account_key(account_keys, ix.accounts[5], "ATA token program")?;

    if payer != expected_payer {
        return Err(VerificationError::invalid_payload(
            "ATA payer must match the transaction fee payer",
        ));
    }
    if mint != expected_mint {
        return Err(VerificationError::invalid_payload(
            "ATA creation mint does not match the charge currency",
        ));
    }
    if !allowed_ata_owners.contains(owner) {
        return Err(VerificationError::invalid_payload(
            "ATA creation owner is not authorized by the challenge",
        ));
    }
    if system_program.to_string() != programs::SYSTEM_PROGRAM {
        return Err(VerificationError::invalid_payload(
            "ATA creation must reference the System Program",
        ));
    }
    if token_program.to_string() != programs::TOKEN_PROGRAM
        && token_program.to_string() != programs::TOKEN_2022_PROGRAM
    {
        return Err(VerificationError::invalid_payload(
            "ATA creation uses an unsupported token program",
        ));
    }
    if expected_token_program.is_some_and(|expected| token_program != expected) {
        return Err(VerificationError::invalid_payload(
            "ATA creation token program does not match methodDetails.tokenProgram",
        ));
    }

    let ata_program = Pubkey::from_str(programs::ASSOCIATED_TOKEN_PROGRAM).unwrap();
    let (expected_ata, _) = Pubkey::find_program_address(
        &[owner.as_ref(), token_program.as_ref(), mint.as_ref()],
        &ata_program,
    );
    if ata != &expected_ata {
        return Err(VerificationError::invalid_payload(
            "ATA creation address does not match owner/mint/token program",
        ));
    }

    Ok(*owner)
}

/// Check that the transaction contains a System Program transfer of `amount` to `recipient`.
fn verify_sol_transfer_instructions(
    tx: &VersionedTransaction,
    account_keys: &[Pubkey],
    recipient: &Pubkey,
    amount: u64,
    fee_payer: Option<&Pubkey>,
    matched_instruction_indexes: &mut HashSet<usize>,
) -> Result<(), VerificationError> {
    let system_program = Pubkey::from_str(programs::SYSTEM_PROGRAM).unwrap();

    for (index, ix) in tx.message.instructions().iter().enumerate() {
        if matched_instruction_indexes.contains(&index) {
            continue;
        }
        let program_id = account_keys
            .get(ix.program_id_index as usize)
            .ok_or_else(|| VerificationError::invalid_payload("Invalid program_id_index"))?;
        if program_id != &system_program {
            continue;
        }
        // System program Transfer instruction: 4 bytes type (2u32 LE) + 8 bytes amount (u64 LE)
        if ix.data.len() < 12 {
            continue;
        }
        let ix_type = u32::from_le_bytes(ix.data[0..4].try_into().unwrap());
        if ix_type != 2 {
            // 2 = Transfer
            continue;
        }
        let ix_amount = u64::from_le_bytes(ix.data[4..12].try_into().unwrap());
        if ix.accounts.len() < 2 {
            continue;
        }
        let source = account_keys
            .get(ix.accounts[0] as usize)
            .ok_or_else(|| VerificationError::invalid_payload("Invalid source index"))?;
        let dest = account_keys
            .get(ix.accounts[1] as usize)
            .ok_or_else(|| VerificationError::invalid_payload("Invalid destination index"))?;
        if dest == recipient && ix_amount == amount {
            if fee_payer.is_some_and(|fee_payer| source == fee_payer) {
                return Err(VerificationError::invalid_payload(
                    "Fee payer cannot fund the SOL payment transfer",
                ));
            }
            matched_instruction_indexes.insert(index);
            return Ok(());
        }
    }
    Err(VerificationError::invalid_amount(format!(
        "No matching SOL transfer of {amount} lamports to {recipient}"
    )))
}

fn verify_memo_instructions(
    tx: &VersionedTransaction,
    account_keys: &[Pubkey],
    external_id: Option<&str>,
    splits: &[Split],
    matched_instruction_indexes: &mut HashSet<usize>,
) -> Result<(), VerificationError> {
    let memo_program = Pubkey::from_str(programs::MEMO_PROGRAM).unwrap();
    for (label, memo) in expected_memos(external_id, splits) {
        let expected_data = memo.as_bytes();
        if expected_data.len() > 566 {
            return Err(VerificationError::invalid_payload(
                "memo cannot exceed 566 bytes",
            ));
        }

        let mut found = false;
        for (index, ix) in tx.message.instructions().iter().enumerate() {
            if matched_instruction_indexes.contains(&index) {
                continue;
            }
            let program_id = account_keys
                .get(ix.program_id_index as usize)
                .ok_or_else(|| VerificationError::invalid_payload("Invalid program_id_index"))?;
            if program_id == &memo_program && ix.data.as_slice() == expected_data {
                matched_instruction_indexes.insert(index);
                found = true;
                break;
            }
        }
        if !found {
            return Err(VerificationError::invalid_payload(format!(
                "No memo instruction found for {label} memo \"{memo}\""
            )));
        }
    }
    Ok(())
}

/// Check that the transaction contains an SPL Token transferChecked of `amount` to `recipient`'s ATA.
#[allow(clippy::too_many_arguments)]
fn verify_spl_transfer_instructions(
    tx: &VersionedTransaction,
    account_keys: &[Pubkey],
    recipient: &Pubkey,
    expected_mint: &Pubkey,
    amount: u64,
    expected_token_program: Option<&Pubkey>,
    expected_decimals: Option<u8>,
    fee_payer: Option<&Pubkey>,
    matched_instruction_indexes: &mut HashSet<usize>,
) -> Result<(), VerificationError> {
    let token_program = Pubkey::from_str(programs::TOKEN_PROGRAM).unwrap();
    let token_2022_program = Pubkey::from_str(programs::TOKEN_2022_PROGRAM).unwrap();
    let ata_program = Pubkey::from_str(programs::ASSOCIATED_TOKEN_PROGRAM).unwrap();

    for (index, ix) in tx.message.instructions().iter().enumerate() {
        if matched_instruction_indexes.contains(&index) {
            continue;
        }
        let program_id = account_keys
            .get(ix.program_id_index as usize)
            .ok_or_else(|| VerificationError::invalid_payload("Invalid program_id_index"))?;
        if program_id != &token_program && program_id != &token_2022_program {
            continue;
        }
        if expected_token_program.is_some_and(|expected| program_id != expected) {
            continue;
        }
        // SPL Token TransferChecked instruction:
        //   data[0] = 12 (instruction type)
        //   data[1..9] = amount (u64 LE)
        //   data[9] = decimals (u8)
        // Accounts: [source, mint, destination, authority, ...]
        if ix.data.is_empty() || ix.data[0] != 12 {
            continue;
        }
        if ix.data.len() < 10 || ix.accounts.len() < 4 {
            continue;
        }
        let ix_amount = u64::from_le_bytes(ix.data[1..9].try_into().unwrap());
        if ix_amount != amount {
            continue;
        }
        if expected_decimals.is_some_and(|decimals| ix.data[9] != decimals) {
            continue;
        }
        // Verify the destination ATA belongs to the recipient
        let source_ata = account_keys
            .get(ix.accounts[0] as usize)
            .ok_or_else(|| VerificationError::invalid_payload("Invalid source index"))?;
        let dest_ata = account_keys
            .get(ix.accounts[2] as usize)
            .ok_or_else(|| VerificationError::invalid_payload("Invalid destination index"))?;
        let mint = account_keys
            .get(ix.accounts[1] as usize)
            .ok_or_else(|| VerificationError::invalid_payload("Invalid mint index"))?;
        if mint != expected_mint {
            continue;
        }
        let authority = account_keys
            .get(ix.accounts[3] as usize)
            .ok_or_else(|| VerificationError::invalid_payload("Invalid authority index"))?;
        if let Some(fee_payer) = fee_payer {
            if authority == fee_payer {
                return Err(VerificationError::invalid_payload(
                    "Fee payer cannot authorize the SPL payment transfer",
                ));
            }

            let (fee_payer_ata, _) = Pubkey::find_program_address(
                &[fee_payer.as_ref(), program_id.as_ref(), mint.as_ref()],
                &ata_program,
            );
            if source_ata == &fee_payer_ata {
                return Err(VerificationError::invalid_payload(
                    "Fee payer token account cannot fund the SPL payment transfer",
                ));
            }
        }
        // Derive expected ATA: PDA([owner, token_program, mint], ata_program)
        let (expected_ata, _) = Pubkey::find_program_address(
            &[recipient.as_ref(), program_id.as_ref(), mint.as_ref()],
            &ata_program,
        );
        if dest_ata == &expected_ata {
            matched_instruction_indexes.insert(index);
            return Ok(());
        }
    }
    Err(VerificationError::invalid_amount(format!(
        "No matching SPL transferChecked of {amount} to {recipient}"
    )))
}

// ── On-chain verification helpers ──

fn verify_sol_transfers(
    instructions: &[serde_json::Value],
    recipient: &str,
    primary_amount: u64,
    splits: &[Split],
) -> Result<HashSet<usize>, VerificationError> {
    let mut matched_instruction_indexes = HashSet::new();
    find_sol_transfer(
        instructions,
        recipient,
        primary_amount,
        &mut matched_instruction_indexes,
    )?;
    for split in splits {
        let amt: u64 = split
            .amount
            .parse()
            .map_err(|_| VerificationError::invalid_amount("Invalid split amount"))?;
        find_sol_transfer(
            instructions,
            &split.recipient,
            amt,
            &mut matched_instruction_indexes,
        )
        .map_err(|_| {
            VerificationError::invalid_amount(format!(
                "Missing split transfer to {}",
                split.recipient
            ))
        })?;
    }
    Ok(matched_instruction_indexes)
}

fn find_sol_transfer(
    instructions: &[serde_json::Value],
    recipient: &str,
    amount: u64,
    matched_instruction_indexes: &mut HashSet<usize>,
) -> Result<(), VerificationError> {
    for (index, ix) in instructions.iter().enumerate() {
        if matched_instruction_indexes.contains(&index) {
            continue;
        }
        if let Some(parsed) = ix.get("parsed").and_then(|p| p.as_object()) {
            if parsed.get("type").and_then(|t| t.as_str()) != Some("transfer") {
                continue;
            }
            if let Some(info) = parsed.get("info").and_then(|i| i.as_object()) {
                let dest = info
                    .get("destination")
                    .and_then(|d| d.as_str())
                    .unwrap_or("");
                let lamports = info.get("lamports").and_then(|l| l.as_u64()).unwrap_or(0);
                if dest == recipient && lamports == amount {
                    matched_instruction_indexes.insert(index);
                    return Ok(());
                }
            }
        }
    }
    Err(VerificationError::invalid_amount(format!(
        "No matching SOL transfer of {amount} lamports to {recipient}"
    )))
}

fn verify_spl_transfers(
    instructions: &[serde_json::Value],
    recipient: &str,
    mint: &str,
    primary_amount: u64,
    splits: &[Split],
    expected_token_program: Option<&str>,
) -> Result<HashSet<usize>, VerificationError> {
    let mut matched_instruction_indexes = HashSet::new();
    find_spl_transfer(
        instructions,
        recipient,
        mint,
        primary_amount,
        expected_token_program,
        &mut matched_instruction_indexes,
    )?;
    for split in splits {
        let amt: u64 = split
            .amount
            .parse()
            .map_err(|_| VerificationError::invalid_amount("Invalid split amount"))?;
        find_spl_transfer(
            instructions,
            &split.recipient,
            mint,
            amt,
            expected_token_program,
            &mut matched_instruction_indexes,
        )
        .map_err(|_| {
            VerificationError::invalid_amount(format!(
                "Missing split SPL transfer to {}",
                split.recipient
            ))
        })?;
    }
    Ok(matched_instruction_indexes)
}

fn find_spl_transfer(
    instructions: &[serde_json::Value],
    recipient: &str,
    expected_mint: &str,
    amount: u64,
    expected_token_program: Option<&str>,
    matched_instruction_indexes: &mut HashSet<usize>,
) -> Result<(), VerificationError> {
    for (index, ix) in instructions.iter().enumerate() {
        if matched_instruction_indexes.contains(&index) {
            continue;
        }
        let program = ix.get("programId").and_then(|p| p.as_str()).unwrap_or("");
        if program != programs::TOKEN_PROGRAM && program != programs::TOKEN_2022_PROGRAM {
            continue;
        }
        if expected_token_program.is_some_and(|expected| program != expected) {
            continue;
        }
        if let Some(parsed) = ix.get("parsed").and_then(|p| p.as_object()) {
            if parsed.get("type").and_then(|t| t.as_str()) != Some("transferChecked") {
                continue;
            }
            if let Some(info) = parsed.get("info").and_then(|i| i.as_object()) {
                let token_amount = info
                    .get("tokenAmount")
                    .and_then(|t| t.as_object())
                    .and_then(|t| t.get("amount"))
                    .and_then(|a| a.as_str())
                    .and_then(|a| a.parse::<u64>().ok())
                    .unwrap_or(0);
                if token_amount == amount {
                    // Verify ATA belongs to expected recipient by deriving it.
                    let dest = info
                        .get("destination")
                        .and_then(|d| d.as_str())
                        .unwrap_or("");
                    let mint = info.get("mint").and_then(|m| m.as_str()).unwrap_or("");
                    if mint == expected_mint && verify_ata_owner(dest, recipient, mint, program) {
                        matched_instruction_indexes.insert(index);
                        return Ok(());
                    }
                }
            }
        }
    }
    Err(VerificationError::invalid_amount(format!(
        "No matching SPL transferChecked of {amount} to {recipient}"
    )))
}

/// Verify ATA derivation: PDA([owner, token_program, mint], ATA_PROGRAM) == ata_address.
fn verify_ata_owner(
    ata_address: &str,
    expected_owner: &str,
    mint: &str,
    token_program: &str,
) -> bool {
    let Ok(owner) = Pubkey::from_str(expected_owner) else {
        return false;
    };
    let Ok(mint_pk) = Pubkey::from_str(mint) else {
        return false;
    };
    let Ok(tp) = Pubkey::from_str(token_program) else {
        return false;
    };
    let Ok(ata_pk) = Pubkey::from_str(ata_address) else {
        return false;
    };
    let ata_program = Pubkey::from_str(programs::ASSOCIATED_TOKEN_PROGRAM).unwrap();
    let (expected_ata, _) = Pubkey::find_program_address(
        &[owner.as_ref(), tp.as_ref(), mint_pk.as_ref()],
        &ata_program,
    );
    expected_ata == ata_pk
}

fn validate_parsed_instruction_allowlist(
    instructions: &[serde_json::Value],
    matched_payment_instruction_indexes: &HashSet<usize>,
    expected_mint: Option<&str>,
    allowed_ata_owners: &HashSet<String>,
    expected_token_program: Option<&str>,
    expected_ata_payer: Option<&str>,
    required_ata_owners: &HashSet<String>,
) -> Result<(), VerificationError> {
    let mut created_ata_owners = HashSet::new();

    for (index, ix) in instructions.iter().enumerate() {
        let program_id = parsed_program_id(ix);

        if program_id == Some(programs::COMPUTE_BUDGET_PROGRAM) {
            continue;
        }

        if program_id == Some(programs::MEMO_PROGRAM) {
            if matched_payment_instruction_indexes.contains(&index) {
                continue;
            }
            return Err(VerificationError::invalid_payload(
                "Unexpected Memo Program instruction in payment transaction",
            ));
        }

        if program_id == Some(programs::SYSTEM_PROGRAM) {
            if matched_payment_instruction_indexes.contains(&index) {
                continue;
            }
            return Err(VerificationError::invalid_payload(
                "Unexpected System Program instruction in payment transaction",
            ));
        }

        if program_id == Some(programs::TOKEN_PROGRAM)
            || program_id == Some(programs::TOKEN_2022_PROGRAM)
        {
            if matched_payment_instruction_indexes.contains(&index) {
                continue;
            }
            return Err(VerificationError::invalid_payload(
                "Unexpected Token Program instruction in payment transaction",
            ));
        }

        if program_id == Some(programs::ASSOCIATED_TOKEN_PROGRAM) {
            let owner = validate_parsed_ata_creation_instruction(
                ix,
                expected_mint,
                allowed_ata_owners,
                expected_token_program,
                expected_ata_payer,
            )?;
            created_ata_owners.insert(owner);
            continue;
        }

        return Err(VerificationError::invalid_payload(format!(
            "Unexpected program instruction in payment transaction: {}",
            program_id.unwrap_or("unknown")
        )));
    }

    for owner in required_ata_owners {
        if !created_ata_owners.contains(owner) {
            return Err(VerificationError::invalid_payload(format!(
                "Missing required ATA creation instruction for split recipient {owner}"
            )));
        }
    }

    Ok(())
}

fn parsed_program_id(ix: &serde_json::Value) -> Option<&str> {
    if let Some(program_id) = ix
        .get("programId")
        .and_then(|program_id| program_id.as_str())
    {
        return Some(program_id);
    }

    match ix.get("program").and_then(|program| program.as_str()) {
        Some("system") => Some(programs::SYSTEM_PROGRAM),
        Some("compute-budget") => Some(programs::COMPUTE_BUDGET_PROGRAM),
        Some("spl-memo") => Some(programs::MEMO_PROGRAM),
        Some("spl-associated-token-account") => Some(programs::ASSOCIATED_TOKEN_PROGRAM),
        _ => None,
    }
}

fn verify_parsed_memo_instructions(
    instructions: &[serde_json::Value],
    external_id: Option<&str>,
    splits: &[Split],
    matched_instruction_indexes: &mut HashSet<usize>,
) -> Result<(), VerificationError> {
    for (label, memo) in expected_memos(external_id, splits) {
        if memo.as_bytes().len() > 566 {
            return Err(VerificationError::invalid_payload(
                "memo cannot exceed 566 bytes",
            ));
        }

        let mut found = false;
        for (index, ix) in instructions.iter().enumerate() {
            if matched_instruction_indexes.contains(&index) {
                continue;
            }
            if parsed_program_id(ix) != Some(programs::MEMO_PROGRAM) {
                continue;
            }
            if parsed_memo_text(ix) == Some(memo) {
                matched_instruction_indexes.insert(index);
                found = true;
                break;
            }
        }
        if !found {
            return Err(VerificationError::invalid_payload(format!(
                "No memo instruction found for {label} memo \"{memo}\""
            )));
        }
    }
    Ok(())
}

fn expected_memos<'a>(
    external_id: Option<&'a str>,
    splits: &'a [Split],
) -> Vec<(&'static str, &'a str)> {
    let mut memos = Vec::new();
    if let Some(external_id) = external_id.filter(|value| !value.is_empty()) {
        memos.push(("externalId", external_id));
    }
    for split in splits {
        if let Some(memo) = split.memo.as_deref().filter(|value| !value.is_empty()) {
            memos.push(("split", memo));
        }
    }
    memos
}

fn parsed_memo_text(ix: &serde_json::Value) -> Option<&str> {
    match ix.get("parsed") {
        Some(serde_json::Value::String(memo)) => Some(memo.as_str()),
        Some(serde_json::Value::Object(parsed)) => parsed
            .get("info")
            .and_then(|info| info.as_object())
            .and_then(|info| string_field(info, &["memo", "data"])),
        _ => None,
    }
}

fn validate_parsed_ata_creation_instruction(
    ix: &serde_json::Value,
    expected_mint: Option<&str>,
    allowed_ata_owners: &HashSet<String>,
    expected_token_program: Option<&str>,
    expected_payer: Option<&str>,
) -> Result<String, VerificationError> {
    let expected_mint = expected_mint.ok_or_else(|| {
        VerificationError::invalid_payload("ATA creation is not allowed for native SOL payments")
    })?;
    let parsed = ix
        .get("parsed")
        .and_then(|parsed| parsed.as_object())
        .ok_or_else(|| {
            VerificationError::invalid_payload("ATA creation instruction is missing parsed data")
        })?;
    if parsed.get("type").and_then(|ty| ty.as_str()) != Some("createIdempotent") {
        return Err(VerificationError::invalid_payload(
            "Only idempotent ATA creation is allowed",
        ));
    }
    let info = parsed
        .get("info")
        .and_then(|info| info.as_object())
        .ok_or_else(|| {
            VerificationError::invalid_payload("ATA creation parsed instruction is missing info")
        })?;

    let payer = string_field(info, &["source", "payer"]).ok_or_else(|| {
        VerificationError::invalid_payload("ATA creation parsed instruction is missing payer")
    })?;
    let ata = string_field(
        info,
        &["account", "associatedAccount", "associatedTokenAddress"],
    )
    .ok_or_else(|| {
        VerificationError::invalid_payload("ATA creation parsed instruction is missing account")
    })?;
    let owner = string_field(info, &["wallet", "owner"]).ok_or_else(|| {
        VerificationError::invalid_payload("ATA creation parsed instruction is missing owner")
    })?;
    let mint = string_field(info, &["mint"]).ok_or_else(|| {
        VerificationError::invalid_payload("ATA creation parsed instruction is missing mint")
    })?;
    let token_program = string_field(info, &["tokenProgram"])
        .or(expected_token_program)
        .ok_or_else(|| {
            VerificationError::invalid_payload(
                "ATA creation parsed instruction is missing token program",
            )
        })?;

    if expected_payer.is_some_and(|expected| payer != expected) {
        return Err(VerificationError::invalid_payload(
            "ATA payer must match the transaction fee payer",
        ));
    }
    if mint != expected_mint {
        return Err(VerificationError::invalid_payload(
            "ATA creation mint does not match the charge currency",
        ));
    }
    if token_program != programs::TOKEN_PROGRAM && token_program != programs::TOKEN_2022_PROGRAM {
        return Err(VerificationError::invalid_payload(
            "ATA creation uses an unsupported token program",
        ));
    }
    if expected_token_program.is_some_and(|expected| token_program != expected) {
        return Err(VerificationError::invalid_payload(
            "ATA creation token program does not match methodDetails.tokenProgram",
        ));
    }
    if !verify_ata_owner(ata, owner, mint, token_program) {
        return Err(VerificationError::invalid_payload(
            "ATA creation address does not match owner/mint/token program",
        ));
    }

    if !allowed_ata_owners.contains(owner) {
        return Err(VerificationError::invalid_payload(
            "ATA creation owner is not authorized by the challenge",
        ));
    }

    Ok(owner.to_string())
}

fn string_field<'a>(
    info: &'a serde_json::Map<String, serde_json::Value>,
    keys: &[&str],
) -> Option<&'a str> {
    keys.iter().find_map(|key| info.get(*key)?.as_str())
}

/// Best-effort balance check when simulation fails.
///
/// Queries the payer's token balance (USDC) and the fee payer's SOL balance
/// to produce an actionable diagnostic like:
///   " | payer USDC balance: 0.00 (need 0.10), fee payer SOL: 0.005"
///
/// Never fails — returns an empty string if any RPC call errors.
fn diagnose_balances(
    rpc: &RpcClient,
    tx: &VersionedTransaction,
    request: &ChargeRequest,
    method_details: &MethodDetails,
) -> String {
    let mut parts: Vec<String> = Vec::new();

    // Identify the payer (first signer that isn't the fee payer).
    let fee_payer_pk = method_details
        .fee_payer_key
        .as_deref()
        .and_then(|k| Pubkey::from_str(k).ok());
    let payer_pk = tx
        .message
        .static_account_keys()
        .iter()
        .find(|k| Some(*k) != fee_payer_pk.as_ref())
        .or(tx.message.static_account_keys().first());

    // Check payer's token balance.
    if let Some(payer) = payer_pk {
        if request.currency.to_uppercase() != "SOL" {
            if let Ok(mint) =
                resolve_expected_mint(&request.currency, method_details.network.as_deref())
            {
                let token_program = Pubkey::from_str(programs::TOKEN_PROGRAM).unwrap();
                let ata_program = Pubkey::from_str(programs::ASSOCIATED_TOKEN_PROGRAM).unwrap();
                let (ata, _) = Pubkey::find_program_address(
                    &[payer.as_ref(), token_program.as_ref(), mint.as_ref()],
                    &ata_program,
                );
                let decimals = method_details.decimals.unwrap_or(6) as u32;
                let divisor = 10u64.pow(decimals) as f64;
                let needed = request.amount.parse::<u64>().unwrap_or(0) as f64 / divisor;
                match rpc.get_token_account_balance(&ata) {
                    Ok(bal) => {
                        let actual: f64 = bal.ui_amount.unwrap_or(0.0);
                        if actual < needed {
                            parts.push(format!(
                                "payer {} balance: {:.2} (need {:.2})",
                                request.currency, actual, needed,
                            ));
                        }
                    }
                    Err(_) => {
                        parts.push(format!(
                            "payer {} token account not found (need {:.2})",
                            request.currency, needed,
                        ));
                    }
                }
            }
        }
    }

    // Check fee payer SOL balance (for tx fees).
    if let Some(fp) = fee_payer_pk {
        if let Ok(lamports) = rpc.get_balance(&fp) {
            let sol = lamports as f64 / 1_000_000_000.0;
            if sol < 0.01 {
                parts.push(format!("fee payer SOL: {sol:.4} (low)"));
            }
        }
    }

    if parts.is_empty() {
        String::new()
    } else {
        format!(" | {}", parts.join(", "))
    }
}

fn resolve_expected_mint(
    currency: &str,
    network: Option<&str>,
) -> Result<Pubkey, VerificationError> {
    let Some(mint) = crate::protocol::solana::resolve_stablecoin_mint(currency, network) else {
        return Err(VerificationError::invalid_payload(
            "SOL does not use an SPL mint".to_string(),
        ));
    };

    Pubkey::from_str(mint)
        .map_err(|e| VerificationError::invalid_payload(format!("Invalid currency/mint: {e}")))
}

/// Extract parsed instructions from an encoded transaction.
fn extract_parsed_instructions(
    tx: &solana_transaction_status::EncodedConfirmedTransactionWithStatusMeta,
) -> Result<Vec<serde_json::Value>, VerificationError> {
    let tx_json = serde_json::to_value(&tx.transaction.transaction)
        .map_err(|e| VerificationError::new(format!("Failed to serialize transaction: {e}")))?;

    let mut all = tx_json
        .get("message")
        .and_then(|m| m.get("instructions"))
        .and_then(|i| i.as_array())
        .cloned()
        .unwrap_or_default();

    // Include inner instructions.
    if let Some(meta) = &tx.transaction.meta {
        let meta_json = serde_json::to_value(meta)
            .map_err(|e| VerificationError::new(format!("Failed to serialize meta: {e}")))?;
        if let Some(inner) = meta_json
            .get("innerInstructions")
            .and_then(|i| i.as_array())
        {
            for group in inner {
                if let Some(ixs) = group.get("instructions").and_then(|i| i.as_array()) {
                    all.extend(ixs.iter().cloned());
                }
            }
        }
    }

    Ok(all)
}

// ── VerificationError ──

/// Error returned when payment verification fails.
///
/// Includes RFC 9457 Problem Details fields for spec-compliant error responses.
#[derive(Debug, Clone)]
pub struct VerificationError {
    pub message: String,
    pub code: Option<&'static str>,
    pub retryable: bool,
    /// RFC 9457 `type` URI identifying the error class.
    pub type_uri: &'static str,
    /// RFC 9457 short human-readable summary.
    pub title: String,
    /// RFC 9457 HTTP status code (402 for payment errors).
    pub status: u16,
}

impl VerificationError {
    pub fn new(message: impl Into<String>) -> Self {
        let message = message.into();
        Self {
            title: "Payment Verification Error".to_string(),
            message,
            code: None,
            retryable: false,
            type_uri: "tag:paymentauth.org,2024:verification-failed",
            status: 402,
        }
    }

    fn with_code(
        message: impl Into<String>,
        code: &'static str,
        title: &str,
        type_uri: &'static str,
    ) -> Self {
        let message = message.into();
        Self {
            title: title.to_string(),
            message,
            code: Some(code),
            retryable: false,
            type_uri,
            status: 402,
        }
    }

    fn retryable(mut self) -> Self {
        self.retryable = true;
        self
    }

    pub fn expired(msg: impl Into<String>) -> Self {
        Self::with_code(
            msg,
            "payment-expired",
            "Payment Challenge Expired",
            "tag:paymentauth.org,2024:payment-expired",
        )
    }

    pub fn invalid_amount(msg: impl Into<String>) -> Self {
        Self::with_code(
            msg,
            "verification-failed",
            "Verification Failed",
            "tag:paymentauth.org,2024:verification-failed",
        )
    }

    pub fn invalid_recipient(msg: impl Into<String>) -> Self {
        Self::with_code(
            msg,
            "verification-failed",
            "Verification Failed",
            "tag:paymentauth.org,2024:verification-failed",
        )
    }

    pub fn transaction_failed(msg: impl Into<String>) -> Self {
        Self::with_code(
            msg,
            "verification-failed",
            "Transaction Failed",
            "tag:paymentauth.org,2024:verification-failed",
        )
    }

    pub fn not_found(msg: impl Into<String>) -> Self {
        Self::with_code(
            msg,
            "verification-failed",
            "Transaction Not Found",
            "tag:paymentauth.org,2024:verification-failed",
        )
    }

    pub fn network_error(msg: impl Into<String>) -> Self {
        Self::with_code(
            msg,
            "verification-failed",
            "Network Error",
            "tag:paymentauth.org,2024:verification-failed",
        )
        .retryable()
    }

    pub fn credential_mismatch(msg: impl Into<String>) -> Self {
        Self::with_code(
            msg,
            "malformed-credential",
            "Malformed Credential",
            "tag:paymentauth.org,2024:malformed-credential",
        )
    }

    pub fn invalid_payload(msg: impl Into<String>) -> Self {
        Self::with_code(
            msg,
            "malformed-credential",
            "Invalid Payload",
            "tag:paymentauth.org,2024:malformed-credential",
        )
    }

    pub fn wrong_network(msg: impl Into<String>) -> Self {
        Self::with_code(
            msg,
            "wrong-network",
            "Wrong Network",
            "tag:paymentauth.org,2024:wrong-network",
        )
    }

    pub fn signature_consumed(msg: impl Into<String>) -> Self {
        Self::with_code(
            msg,
            "signature-consumed",
            "Signature Already Consumed",
            "tag:paymentauth.org,2024:signature-consumed",
        )
    }

    pub fn too_many_splits(msg: impl Into<String>) -> Self {
        Self::with_code(
            msg,
            "verification-failed",
            "Too Many Splits",
            "tag:paymentauth.org,2024:verification-failed",
        )
    }

    /// Return an RFC 9457 Problem Details JSON object.
    pub fn to_problem_json(&self) -> serde_json::Value {
        let mut obj = serde_json::json!({
            "type": self.type_uri,
            "title": self.title,
            "status": self.status,
            "detail": self.message,
        });
        if let Some(code) = self.code {
            obj["code"] = serde_json::Value::String(code.to_string());
        }
        obj
    }
}

impl std::fmt::Display for VerificationError {
    /// Render just the human-readable message. Callers that need the
    /// stable error code branch on `self.code` directly — including a
    /// `[code]` prefix in Display would make UI surfaces look like log
    /// lines.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for VerificationError {}

#[cfg(test)]
mod tests {
    use super::*;

    // ── check_network_blockhash ────────────────────────────────────────────
    //
    // Pure function — no I/O, no async, no fixtures. The check is asymmetric:
    // a Surfpool-prefixed blockhash is only valid on `localnet`, but a
    // non-prefixed blockhash is accepted on any network (we can't tell
    // from a non-prefixed hash what real cluster it came from).

    // Happy paths.

    #[test]
    fn verification_error_display_omits_code_prefix() {
        // The Display impl is the user-facing error string. It must not
        // prepend `[<code>]` — that's debug noise that leaks log-line
        // formatting into UI surfaces (the "Payment rejected by verifier"
        // notice in the pay CLI being the original report).
        let err = VerificationError::wrong_network(
            "Signed against localnet but the server expects mainnet.",
        );
        let displayed = err.to_string();
        assert!(!displayed.starts_with("["), "leading bracket: {displayed}");
        assert!(
            !displayed.contains("[wrong-network]"),
            "code in display: {displayed}"
        );
        assert_eq!(
            displayed,
            "Signed against localnet but the server expects mainnet."
        );
        // The structured code is still available on the field for
        // callers that need to branch on it programmatically.
        assert_eq!(err.code, Some("wrong-network"));
    }

    #[test]
    fn network_check_localnet_with_surfpool_hash_ok() {
        assert!(
            check_network_blockhash("localnet", "SURFNETxSAFEHASHxxxxxxxxxxxxxxxxxxx1892bcad")
                .is_ok()
        );
    }

    #[test]
    fn network_check_localnet_with_real_hash_ok() {
        // Real localnet validator (not Surfpool) — also valid.
        assert!(check_network_blockhash("localnet", "11111111111111111111111111111111").is_ok());
    }

    #[test]
    fn network_check_mainnet_with_real_hash_ok() {
        assert!(
            check_network_blockhash("mainnet", "9zrUHnA1nCByPksy3aL8tQ47vqdaG2vnFs4HrxgcZj4F")
                .is_ok()
        );
    }

    #[test]
    fn network_check_devnet_with_real_hash_ok() {
        assert!(
            check_network_blockhash("devnet", "EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N")
                .is_ok()
        );
    }

    // The actual bug surface: Surfpool-signed hash on a non-localnet server.

    #[test]
    fn network_check_mainnet_rejects_surfpool_hash() {
        let err = check_network_blockhash("mainnet", "SURFNETxSAFEHASHxxxxxxxxxxxxxxxxxxx1892bcad")
            .unwrap_err();
        assert_eq!(err.code, Some("wrong-network"));
        assert!(!err.retryable);
        // Message should name both sides of the mismatch + give an
        // actionable next step.
        assert!(
            err.message.contains("Signed against localnet"),
            "missing received-side: {}",
            err.message
        );
        assert!(
            err.message.contains("server expects mainnet"),
            "missing expected-side: {}",
            err.message
        );
        assert!(
            err.message.contains("re-sign"),
            "missing actionable hint: {}",
            err.message
        );
    }

    #[test]
    fn network_check_devnet_rejects_surfpool_hash() {
        let err = check_network_blockhash("devnet", "SURFNETxSAFEHASHxxxxxxxxxxxxxxxxxxx1892bcad")
            .unwrap_err();
        assert_eq!(err.code, Some("wrong-network"));
        assert!(err.message.contains("server expects devnet"));
    }

    // Edge cases.

    #[test]
    fn network_check_partial_prefix_does_not_match() {
        // "SURFNETx" alone (8 chars) is NOT the full prefix and must not
        // be misclassified as a Surfpool blockhash.
        assert!(check_network_blockhash("mainnet", "SURFNETx9zrUHnA1nCByPksy").is_ok());
    }

    #[test]
    fn network_check_exact_prefix_only_is_treated_as_surfpool() {
        // A blockhash equal to (or starting with) exactly the prefix counts.
        assert!(check_network_blockhash("localnet", SURFPOOL_BLOCKHASH_PREFIX).is_ok());
        assert!(check_network_blockhash("mainnet", SURFPOOL_BLOCKHASH_PREFIX).is_err());
    }

    #[test]
    fn network_check_non_surfpool_hash_passes_anywhere() {
        // The check is asymmetric: a real-cluster-looking blockhash is
        // accepted on every network because we can't tell from a
        // non-prefixed hash which real cluster it came from. This test
        // pins the design intent.
        assert!(check_network_blockhash("mainnet", "11111111111111111111111111111111").is_ok());
        assert!(check_network_blockhash("devnet", "11111111111111111111111111111111").is_ok());
        assert!(check_network_blockhash("localnet", "11111111111111111111111111111111").is_ok());
    }

    #[test]
    fn ata_derivation_verification() {
        // Known ATA derivation for a well-known pubkey/mint combo.
        let owner = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY";
        let mint = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"; // USDC mainnet
        let tp = programs::TOKEN_PROGRAM;

        let owner_pk = Pubkey::from_str(owner).unwrap();
        let mint_pk = Pubkey::from_str(mint).unwrap();
        let tp_pk = Pubkey::from_str(tp).unwrap();
        let ata_program = Pubkey::from_str(programs::ASSOCIATED_TOKEN_PROGRAM).unwrap();
        let (expected_ata, _) = Pubkey::find_program_address(
            &[owner_pk.as_ref(), tp_pk.as_ref(), mint_pk.as_ref()],
            &ata_program,
        );

        assert!(verify_ata_owner(&expected_ata.to_string(), owner, mint, tp));
        assert!(!verify_ata_owner(
            "11111111111111111111111111111111",
            owner,
            mint,
            tp
        ));
    }

    // ── Helpers for building test transactions ──

    use solana_hash::Hash;
    use solana_instruction::{AccountMeta, Instruction};
    use solana_message::{v0, Message, VersionedMessage};

    fn system_program_id() -> Pubkey {
        Pubkey::from_str(programs::SYSTEM_PROGRAM).unwrap()
    }
    fn token_program_id() -> Pubkey {
        Pubkey::from_str(programs::TOKEN_PROGRAM).unwrap()
    }
    fn memo_program_id() -> Pubkey {
        Pubkey::from_str(programs::MEMO_PROGRAM).unwrap()
    }
    fn ata_program_id() -> Pubkey {
        Pubkey::from_str(programs::ASSOCIATED_TOKEN_PROGRAM).unwrap()
    }

    /// Build a raw System Program transfer instruction.
    fn system_transfer_ix(from: &Pubkey, to: &Pubkey, lamports: u64) -> Instruction {
        let mut data = Vec::with_capacity(12);
        data.extend_from_slice(&2u32.to_le_bytes()); // Transfer = 2
        data.extend_from_slice(&lamports.to_le_bytes());
        Instruction {
            program_id: system_program_id(),
            accounts: vec![AccountMeta::new(*from, true), AccountMeta::new(*to, false)],
            data,
        }
    }

    fn compute_unit_limit_ix(units: u32) -> Instruction {
        let mut data = Vec::with_capacity(5);
        data.push(2);
        data.extend_from_slice(&units.to_le_bytes());
        Instruction {
            program_id: Pubkey::from_str(COMPUTE_BUDGET_PROGRAM).unwrap(),
            accounts: vec![],
            data,
        }
    }

    fn compute_unit_price_ix(micro_lamports: u64) -> Instruction {
        let mut data = Vec::with_capacity(9);
        data.push(3);
        data.extend_from_slice(&micro_lamports.to_le_bytes());
        Instruction {
            program_id: Pubkey::from_str(COMPUTE_BUDGET_PROGRAM).unwrap(),
            accounts: vec![],
            data,
        }
    }

    fn memo_ix(memo: &str) -> Instruction {
        Instruction {
            program_id: memo_program_id(),
            accounts: vec![],
            data: memo.as_bytes().to_vec(),
        }
    }

    /// Build a raw SPL Token transferChecked instruction.
    fn spl_transfer_checked_ix(
        source: &Pubkey,
        mint: &Pubkey,
        destination: &Pubkey,
        authority: &Pubkey,
        amount: u64,
        decimals: u8,
    ) -> Instruction {
        let mut data = Vec::with_capacity(10);
        data.push(12); // TransferChecked = 12
        data.extend_from_slice(&amount.to_le_bytes());
        data.push(decimals);
        Instruction {
            program_id: token_program_id(),
            accounts: vec![
                AccountMeta::new(*source, false),
                AccountMeta::new_readonly(*mint, false),
                AccountMeta::new(*destination, false),
                AccountMeta::new_readonly(*authority, true),
            ],
            data,
        }
    }

    fn create_ata_ix(
        payer: &Pubkey,
        owner: &Pubkey,
        mint: &Pubkey,
        token_program: &Pubkey,
    ) -> Instruction {
        Instruction {
            program_id: ata_program_id(),
            accounts: vec![
                AccountMeta::new(*payer, true),
                AccountMeta::new(derive_ata(owner, mint, token_program), false),
                AccountMeta::new_readonly(*owner, false),
                AccountMeta::new_readonly(*mint, false),
                AccountMeta::new_readonly(system_program_id(), false),
                AccountMeta::new_readonly(*token_program, false),
            ],
            data: vec![1],
        }
    }

    fn dummy_tx(instructions: Vec<Instruction>, payer: &Pubkey) -> Transaction {
        let message = Message::new_with_blockhash(&instructions, Some(payer), &Hash::default());
        Transaction {
            signatures: vec![Signature::default(); message.header.num_required_signatures as usize],
            message,
        }
    }

    fn dummy_v0_tx(
        instructions: Vec<Instruction>,
        payer: &Pubkey,
        address_table_lookups: Vec<v0::MessageAddressTableLookup>,
    ) -> VersionedTransaction {
        let legacy_message =
            Message::new_with_blockhash(&instructions, Some(payer), &Hash::default());
        let message = v0::Message {
            header: legacy_message.header,
            account_keys: legacy_message.account_keys,
            recent_blockhash: legacy_message.recent_blockhash,
            instructions: legacy_message.instructions,
            address_table_lookups,
        };
        VersionedTransaction {
            signatures: vec![Signature::default(); message.header.num_required_signatures as usize],
            message: VersionedMessage::V0(message),
        }
    }

    fn charge_request(amount: u64, currency: &str, recipient: &Pubkey) -> ChargeRequest {
        ChargeRequest {
            amount: amount.to_string(),
            currency: currency.to_string(),
            recipient: Some(recipient.to_string()),
            ..Default::default()
        }
    }

    // ── Pre-broadcast SOL verification tests ──

    #[test]
    fn sol_transfer_correct_amount_passes() {
        let sender = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        let amount = 1_000_000u64;

        let tx = dummy_tx(
            vec![system_transfer_ix(&sender, &recipient, amount)],
            &sender,
        );
        let request = charge_request(amount, "SOL", &recipient);
        let method_details = MethodDetails::default();

        assert!(verify_transaction_pre_broadcast(&tx, &request, &method_details).is_ok());
    }

    #[test]
    fn v0_sol_transfer_without_lookup_tables_passes() {
        let sender = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        let amount = 1_000_000u64;

        let tx = dummy_v0_tx(
            vec![system_transfer_ix(&sender, &recipient, amount)],
            &sender,
            vec![],
        );
        let request = charge_request(amount, "SOL", &recipient);
        let method_details = MethodDetails::default();

        assert!(verify_versioned_transaction_pre_broadcast(&tx, &request, &method_details).is_ok());
    }

    #[test]
    fn v0_transactions_with_lookup_tables_rejected() {
        let sender = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        let amount = 1_000_000u64;

        let tx = dummy_v0_tx(
            vec![system_transfer_ix(&sender, &recipient, amount)],
            &sender,
            vec![v0::MessageAddressTableLookup {
                account_key: Pubkey::new_unique(),
                writable_indexes: vec![0],
                readonly_indexes: vec![],
            }],
        );
        let request = charge_request(amount, "SOL", &recipient);
        let method_details = MethodDetails::default();

        let err =
            verify_versioned_transaction_pre_broadcast(&tx, &request, &method_details).unwrap_err();
        assert!(err.message.contains("address lookup tables"));
    }

    #[test]
    fn sol_transfer_wrong_amount_rejected() {
        let sender = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();

        let tx = dummy_tx(
            vec![system_transfer_ix(&sender, &recipient, 1)], // 1 lamport
            &sender,
        );
        let request = charge_request(1_000_000, "SOL", &recipient); // expects 1M
        let method_details = MethodDetails::default();

        let err = verify_transaction_pre_broadcast(&tx, &request, &method_details).unwrap_err();
        assert!(err.message.contains("No matching SOL transfer"));
    }

    #[test]
    fn sol_transfer_wrong_recipient_rejected() {
        let sender = Pubkey::new_unique();
        let wrong_recipient = Pubkey::new_unique();
        let real_recipient = Pubkey::new_unique();
        let amount = 1_000_000u64;

        let tx = dummy_tx(
            vec![system_transfer_ix(&sender, &wrong_recipient, amount)],
            &sender,
        );
        let request = charge_request(amount, "SOL", &real_recipient);
        let method_details = MethodDetails::default();

        let err = verify_transaction_pre_broadcast(&tx, &request, &method_details).unwrap_err();
        assert!(err.message.contains("No matching SOL transfer"));
    }

    #[test]
    fn sol_transfer_no_transfer_instruction_rejected() {
        let sender = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();

        // Empty transaction (no instructions)
        let tx = dummy_tx(vec![], &sender);
        let request = charge_request(1_000_000, "SOL", &recipient);
        let method_details = MethodDetails::default();

        let err = verify_transaction_pre_broadcast(&tx, &request, &method_details).unwrap_err();
        assert!(err.message.contains("No matching SOL transfer"));
    }

    #[test]
    fn sol_transfer_with_valid_compute_budget_passes() {
        let sender = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        let amount = 500_000u64;

        let tx = dummy_tx(
            vec![
                compute_unit_price_ix(1),
                compute_unit_limit_ix(MAX_COMPUTE_UNIT_LIMIT),
                system_transfer_ix(&sender, &recipient, amount),
            ],
            &sender,
        );
        let request = charge_request(amount, "SOL", &recipient);
        let method_details = MethodDetails::default();

        assert!(verify_transaction_pre_broadcast(&tx, &request, &method_details).is_ok());
    }

    #[test]
    fn sol_transfer_with_unmatched_extra_transfer_rejected() {
        let sender = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        let attacker = Pubkey::new_unique();
        let amount = 500_000u64;

        let tx = dummy_tx(
            vec![
                system_transfer_ix(&sender, &recipient, amount),
                system_transfer_ix(&sender, &attacker, 1),
            ],
            &sender,
        );
        let request = charge_request(amount, "SOL", &recipient);
        let method_details = MethodDetails::default();

        let err = verify_transaction_pre_broadcast(&tx, &request, &method_details).unwrap_err();
        assert!(err
            .message
            .contains("Unexpected System Program instruction"));
    }

    #[test]
    fn compute_unit_price_above_limit_rejected() {
        let sender = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        let amount = 500_000u64;

        let tx = dummy_tx(
            vec![
                compute_unit_price_ix(MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS + 1),
                system_transfer_ix(&sender, &recipient, amount),
            ],
            &sender,
        );
        let request = charge_request(amount, "SOL", &recipient);
        let method_details = MethodDetails::default();

        let err = verify_transaction_pre_broadcast(&tx, &request, &method_details).unwrap_err();
        assert!(err.message.contains("Compute unit price"));
    }

    #[test]
    fn fee_payer_must_be_transaction_fee_payer() {
        let sender = Pubkey::new_unique();
        let fee_payer = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        let amount = 500_000u64;

        let tx = dummy_tx(
            vec![system_transfer_ix(&sender, &recipient, amount)],
            &sender,
        );
        let request = charge_request(amount, "SOL", &recipient);
        let method_details = MethodDetails {
            fee_payer: Some(true),
            fee_payer_key: Some(fee_payer.to_string()),
            ..Default::default()
        };

        let err = verify_transaction_pre_broadcast(&tx, &request, &method_details).unwrap_err();
        assert!(err.message.contains("Transaction fee payer must be"));
    }

    #[test]
    fn fee_payer_cannot_fund_sol_payment_transfer() {
        let fee_payer = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        let amount = 500_000u64;

        let tx = dummy_tx(
            vec![system_transfer_ix(&fee_payer, &recipient, amount)],
            &fee_payer,
        );
        let request = charge_request(amount, "SOL", &recipient);
        let method_details = MethodDetails {
            fee_payer: Some(true),
            fee_payer_key: Some(fee_payer.to_string()),
            ..Default::default()
        };

        let err = verify_transaction_pre_broadcast(&tx, &request, &method_details).unwrap_err();
        assert!(err.message.contains("Fee payer cannot fund"));
    }

    // ── Pre-broadcast SPL verification tests ──

    #[test]
    fn spl_transfer_correct_amount_passes() {
        let sender = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        let mint = Pubkey::from_str("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v").unwrap();
        let amount = 1_000_000u64; // 1 USDC

        let tp = token_program_id();
        let source_ata = derive_ata(&sender, &mint, &tp);
        let dest_ata = derive_ata(&recipient, &mint, &tp);

        let tx = dummy_tx(
            vec![spl_transfer_checked_ix(
                &source_ata,
                &mint,
                &dest_ata,
                &sender,
                amount,
                6,
            )],
            &sender,
        );
        let request = charge_request(amount, "USDC", &recipient);
        let method_details = MethodDetails::default();

        assert!(verify_transaction_pre_broadcast(&tx, &request, &method_details).is_ok());
    }

    #[test]
    fn spl_transfer_wrong_amount_rejected() {
        let sender = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        let mint = Pubkey::from_str("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v").unwrap();

        let tp = token_program_id();
        let source_ata = derive_ata(&sender, &mint, &tp);
        let dest_ata = derive_ata(&recipient, &mint, &tp);

        let tx = dummy_tx(
            vec![spl_transfer_checked_ix(
                &source_ata,
                &mint,
                &dest_ata,
                &sender,
                1, // wrong: 1 base unit
                6,
            )],
            &sender,
        );
        let request = charge_request(1_000_000, "USDC", &recipient); // expects 1M
        let method_details = MethodDetails::default();

        let err = verify_transaction_pre_broadcast(&tx, &request, &method_details).unwrap_err();
        assert!(err.message.contains("No matching SPL transferChecked"));
    }

    #[test]
    fn spl_transfer_wrong_recipient_rejected() {
        let sender = Pubkey::new_unique();
        let wrong_recipient = Pubkey::new_unique();
        let real_recipient = Pubkey::new_unique();
        let mint = Pubkey::from_str("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v").unwrap();
        let amount = 1_000_000u64;

        let tp = token_program_id();
        let source_ata = derive_ata(&sender, &mint, &tp);
        let wrong_dest_ata = derive_ata(&wrong_recipient, &mint, &tp);

        let tx = dummy_tx(
            vec![spl_transfer_checked_ix(
                &source_ata,
                &mint,
                &wrong_dest_ata,
                &sender,
                amount,
                6,
            )],
            &sender,
        );
        let request = charge_request(amount, "USDC", &real_recipient);
        let method_details = MethodDetails::default();

        let err = verify_transaction_pre_broadcast(&tx, &request, &method_details).unwrap_err();
        assert!(err.message.contains("No matching SPL transferChecked"));
    }

    #[test]
    fn spl_client_paid_split_ata_creation_passes() {
        let sender = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        let split_recipient = Pubkey::new_unique();
        let mint = Pubkey::from_str("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v").unwrap();
        let primary_amount = 950_000u64;
        let split_amount = 50_000u64;
        let total = primary_amount + split_amount;

        let tp = token_program_id();
        let source_ata = derive_ata(&sender, &mint, &tp);
        let recipient_ata = derive_ata(&recipient, &mint, &tp);
        let split_ata = derive_ata(&split_recipient, &mint, &tp);

        let tx = dummy_tx(
            vec![
                spl_transfer_checked_ix(
                    &source_ata,
                    &mint,
                    &recipient_ata,
                    &sender,
                    primary_amount,
                    6,
                ),
                create_ata_ix(&sender, &split_recipient, &mint, &tp),
                spl_transfer_checked_ix(&source_ata, &mint, &split_ata, &sender, split_amount, 6),
            ],
            &sender,
        );
        let request = charge_request(total, &mint.to_string(), &recipient);
        let method_details = MethodDetails {
            token_program: Some(programs::TOKEN_PROGRAM.to_string()),
            splits: Some(vec![Split {
                recipient: split_recipient.to_string(),
                amount: split_amount.to_string(),
                ata_creation_required: None,
                label: None,
                memo: None,
            }]),
            ..Default::default()
        };

        assert!(verify_transaction_pre_broadcast(&tx, &request, &method_details).is_ok());
    }

    #[test]
    fn spl_client_paid_rejects_top_level_ata_creation() {
        let sender = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        let mint = Pubkey::from_str("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v").unwrap();
        let amount = 1_000_000u64;

        let tp = token_program_id();
        let source_ata = derive_ata(&sender, &mint, &tp);
        let recipient_ata = derive_ata(&recipient, &mint, &tp);

        let tx = dummy_tx(
            vec![
                create_ata_ix(&sender, &recipient, &mint, &tp),
                spl_transfer_checked_ix(&source_ata, &mint, &recipient_ata, &sender, amount, 6),
            ],
            &sender,
        );
        let request = charge_request(amount, &mint.to_string(), &recipient);
        let method_details = MethodDetails {
            token_program: Some(programs::TOKEN_PROGRAM.to_string()),
            ..Default::default()
        };

        let err = verify_transaction_pre_broadcast(&tx, &request, &method_details).unwrap_err();
        assert!(err.message.contains("ATA creation owner is not authorized"));
    }

    #[test]
    fn spl_fee_payer_split_ata_creation_passes_when_split_requires_it() {
        let sender = Pubkey::new_unique();
        let fee_payer = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        let split_recipient = Pubkey::new_unique();
        let mint = Pubkey::from_str("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v").unwrap();
        let primary_amount = 950_000u64;
        let split_amount = 50_000u64;
        let total = primary_amount + split_amount;

        let tp = token_program_id();
        let source_ata = derive_ata(&sender, &mint, &tp);
        let recipient_ata = derive_ata(&recipient, &mint, &tp);
        let split_ata = derive_ata(&split_recipient, &mint, &tp);

        let tx = dummy_tx(
            vec![
                spl_transfer_checked_ix(
                    &source_ata,
                    &mint,
                    &recipient_ata,
                    &sender,
                    primary_amount,
                    6,
                ),
                create_ata_ix(&fee_payer, &split_recipient, &mint, &tp),
                spl_transfer_checked_ix(&source_ata, &mint, &split_ata, &sender, split_amount, 6),
            ],
            &fee_payer,
        );
        let request = charge_request(total, &mint.to_string(), &recipient);
        let method_details = MethodDetails {
            fee_payer: Some(true),
            fee_payer_key: Some(fee_payer.to_string()),
            token_program: Some(programs::TOKEN_PROGRAM.to_string()),
            splits: Some(vec![Split {
                recipient: split_recipient.to_string(),
                amount: split_amount.to_string(),
                ata_creation_required: Some(true),
                label: None,
                memo: None,
            }]),
            ..Default::default()
        };

        assert!(verify_transaction_pre_broadcast(&tx, &request, &method_details).is_ok());
    }

    #[test]
    fn spl_fee_payer_rejects_top_level_ata_creation() {
        let sender = Pubkey::new_unique();
        let fee_payer = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        let mint = Pubkey::from_str("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v").unwrap();
        let amount = 1_000_000u64;

        let tp = token_program_id();
        let source_ata = derive_ata(&sender, &mint, &tp);
        let recipient_ata = derive_ata(&recipient, &mint, &tp);

        let tx = dummy_tx(
            vec![
                create_ata_ix(&fee_payer, &recipient, &mint, &tp),
                spl_transfer_checked_ix(&source_ata, &mint, &recipient_ata, &sender, amount, 6),
            ],
            &fee_payer,
        );
        let request = charge_request(amount, &mint.to_string(), &recipient);
        let method_details = MethodDetails {
            fee_payer: Some(true),
            fee_payer_key: Some(fee_payer.to_string()),
            token_program: Some(programs::TOKEN_PROGRAM.to_string()),
            ..Default::default()
        };

        let err = verify_transaction_pre_broadcast(&tx, &request, &method_details).unwrap_err();
        assert!(err.message.contains("ATA creation owner is not authorized"));
    }

    #[test]
    fn spl_fee_payer_split_ata_creation_requires_marked_split_create() {
        let sender = Pubkey::new_unique();
        let fee_payer = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        let split_recipient = Pubkey::new_unique();
        let mint = Pubkey::from_str("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v").unwrap();
        let primary_amount = 950_000u64;
        let split_amount = 50_000u64;
        let total = primary_amount + split_amount;

        let tp = token_program_id();
        let source_ata = derive_ata(&sender, &mint, &tp);
        let recipient_ata = derive_ata(&recipient, &mint, &tp);
        let split_ata = derive_ata(&split_recipient, &mint, &tp);

        let tx = dummy_tx(
            vec![
                spl_transfer_checked_ix(
                    &source_ata,
                    &mint,
                    &recipient_ata,
                    &sender,
                    primary_amount,
                    6,
                ),
                spl_transfer_checked_ix(&source_ata, &mint, &split_ata, &sender, split_amount, 6),
            ],
            &fee_payer,
        );
        let request = charge_request(total, &mint.to_string(), &recipient);
        let method_details = MethodDetails {
            fee_payer: Some(true),
            fee_payer_key: Some(fee_payer.to_string()),
            token_program: Some(programs::TOKEN_PROGRAM.to_string()),
            splits: Some(vec![Split {
                recipient: split_recipient.to_string(),
                amount: split_amount.to_string(),
                ata_creation_required: Some(true),
                label: None,
                memo: None,
            }]),
            ..Default::default()
        };

        let err = verify_transaction_pre_broadcast(&tx, &request, &method_details).unwrap_err();
        assert!(err.message.contains("Missing required ATA creation"));
    }

    #[test]
    fn spl_split_ata_creation_requires_mint_address_currency() {
        let sender = Pubkey::new_unique();
        let fee_payer = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        let split_recipient = Pubkey::new_unique();
        let mint = Pubkey::from_str("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v").unwrap();
        let primary_amount = 950_000u64;
        let split_amount = 50_000u64;
        let total = primary_amount + split_amount;

        let tp = token_program_id();
        let source_ata = derive_ata(&sender, &mint, &tp);
        let recipient_ata = derive_ata(&recipient, &mint, &tp);
        let split_ata = derive_ata(&split_recipient, &mint, &tp);

        let tx = dummy_tx(
            vec![
                spl_transfer_checked_ix(
                    &source_ata,
                    &mint,
                    &recipient_ata,
                    &sender,
                    primary_amount,
                    6,
                ),
                create_ata_ix(&fee_payer, &split_recipient, &mint, &tp),
                spl_transfer_checked_ix(&source_ata, &mint, &split_ata, &sender, split_amount, 6),
            ],
            &fee_payer,
        );
        let request = charge_request(total, "USDC", &recipient);
        let method_details = MethodDetails {
            fee_payer: Some(true),
            fee_payer_key: Some(fee_payer.to_string()),
            token_program: Some(programs::TOKEN_PROGRAM.to_string()),
            splits: Some(vec![Split {
                recipient: split_recipient.to_string(),
                amount: split_amount.to_string(),
                ata_creation_required: Some(true),
                label: None,
                memo: None,
            }]),
            ..Default::default()
        };

        let err = verify_transaction_pre_broadcast(&tx, &request, &method_details).unwrap_err();
        assert!(err.message.contains("mint address"));
    }

    #[test]
    fn zero_primary_amount_rejected() {
        let sender = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();

        let tx = dummy_tx(vec![], &sender);
        let request = charge_request(0, "SOL", &recipient);
        let method_details = MethodDetails::default();

        let err = verify_transaction_pre_broadcast(&tx, &request, &method_details).unwrap_err();
        assert!(
            err.message.contains("Primary amount is zero")
                || err.message.contains("Invalid amount")
        );
    }

    #[test]
    fn missing_recipient_rejected() {
        let sender = Pubkey::new_unique();
        let tx = dummy_tx(vec![], &sender);
        let request = ChargeRequest {
            amount: "1000000".to_string(),
            currency: "SOL".to_string(),
            recipient: None,
            ..Default::default()
        };
        let method_details = MethodDetails::default();

        let err = verify_transaction_pre_broadcast(&tx, &request, &method_details).unwrap_err();
        assert!(err.message.contains("No recipient"));
    }

    fn derive_ata(owner: &Pubkey, mint: &Pubkey, token_program: &Pubkey) -> Pubkey {
        let ata_program = ata_program_id();
        let (ata, _) = Pubkey::find_program_address(
            &[owner.as_ref(), token_program.as_ref(), mint.as_ref()],
            &ata_program,
        );
        ata
    }

    // ── Helper: create an Mpp instance for testing ──

    const TEST_SECRET: &str = "test-secret-key-for-unit-tests";
    const TEST_RECIPIENT: &str = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY";

    fn test_mpp() -> Mpp {
        Mpp::new(Config {
            recipient: TEST_RECIPIENT.to_string(),
            challenge_binding_secret: Some(TEST_SECRET.to_string()),
            network: "devnet".to_string(),
            ..Default::default()
        })
        .unwrap()
    }

    fn test_mpp_sol() -> Mpp {
        Mpp::new(Config {
            recipient: TEST_RECIPIENT.to_string(),
            challenge_binding_secret: Some(TEST_SECRET.to_string()),
            currency: "SOL".to_string(),
            decimals: 9,
            network: "devnet".to_string(),
            ..Default::default()
        })
        .unwrap()
    }

    fn test_fee_payer_signer() -> Arc<dyn solana_keychain::SolanaSigner> {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let mut kp = [0u8; 64];
        kp[..32].copy_from_slice(sk.as_bytes());
        kp[32..].copy_from_slice(sk.verifying_key().as_bytes());
        Arc::new(solana_keychain::MemorySigner::from_bytes(&kp).expect("valid keypair"))
    }

    // ── Mpp::new() config validation tests ──

    /// Guard so that tests touching SECRET_KEY_ENV_VAR don't race each other.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn new_missing_recipient_errors() {
        let err = Mpp::new(Config {
            recipient: String::new(),
            challenge_binding_secret: Some("key".to_string()),
            ..Default::default()
        })
        .err()
        .expect("should fail");
        assert!(
            err.to_string().contains("recipient is required"),
            "got: {err}"
        );
    }

    #[test]
    fn new_invalid_recipient_pubkey_errors() {
        let err = Mpp::new(Config {
            recipient: "not-a-valid-pubkey!!!".to_string(),
            challenge_binding_secret: Some("key".to_string()),
            ..Default::default()
        })
        .err()
        .expect("should fail");
        assert!(
            err.to_string().contains("Invalid recipient pubkey"),
            "got: {err}"
        );
    }

    #[test]
    fn new_missing_challenge_binding_secret_without_env_errors() {
        let _guard = ENV_LOCK.lock().unwrap();
        // Temporarily ensure the env var is not set.
        let prev = std::env::var(SECRET_KEY_ENV_VAR).ok();
        unsafe { std::env::remove_var(SECRET_KEY_ENV_VAR) };

        let err = Mpp::new(Config {
            recipient: TEST_RECIPIENT.to_string(),
            challenge_binding_secret: None,
            ..Default::default()
        })
        .err()
        .expect("should fail");
        assert!(err.to_string().contains("MPP_SECRET_KEY"), "got: {err}");

        // Restore.
        if let Some(v) = prev {
            unsafe { std::env::set_var(SECRET_KEY_ENV_VAR, v) };
        }
    }

    #[test]
    fn new_challenge_binding_secret_from_env() {
        let _guard = ENV_LOCK.lock().unwrap();
        let prev = std::env::var(SECRET_KEY_ENV_VAR).ok();
        unsafe { std::env::set_var(SECRET_KEY_ENV_VAR, "env-secret") };

        let result = Mpp::new(Config {
            recipient: TEST_RECIPIENT.to_string(),
            challenge_binding_secret: None,
            ..Default::default()
        });

        // Restore before asserting (so we don't leak state on failure).
        if let Some(v) = prev {
            unsafe { std::env::set_var(SECRET_KEY_ENV_VAR, v) };
        } else {
            unsafe { std::env::remove_var(SECRET_KEY_ENV_VAR) };
        }

        assert!(result.is_ok());
    }

    #[test]
    fn new_valid_config_succeeds() {
        let mpp = test_mpp();
        assert_eq!(mpp.realm(), DEFAULT_REALM);
        assert_eq!(mpp.currency(), "USDC");
        assert_eq!(mpp.recipient(), TEST_RECIPIENT);
        assert_eq!(mpp.decimals(), 6);
    }

    #[test]
    fn new_custom_realm() {
        let mpp = Mpp::new(Config {
            recipient: TEST_RECIPIENT.to_string(),
            challenge_binding_secret: Some("key".to_string()),
            realm: Some("Custom Realm".to_string()),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(mpp.realm(), "Custom Realm");
    }

    #[test]
    fn new_custom_rpc_url() {
        // Should not fail — just verifying it accepts a custom RPC URL.
        let mpp = Mpp::new(Config {
            recipient: TEST_RECIPIENT.to_string(),
            challenge_binding_secret: Some("key".to_string()),
            rpc_url: Some("http://custom:8899".to_string()),
            ..Default::default()
        });
        assert!(mpp.is_ok());
    }

    #[test]
    fn new_custom_store() {
        let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
        let result = Mpp::new(Config {
            recipient: TEST_RECIPIENT.to_string(),
            challenge_binding_secret: Some("key".to_string()),
            store: Some(store),
            ..Default::default()
        });
        assert!(result.is_ok());
    }

    // ── default_rpc_url tests ──

    #[test]
    fn default_rpc_url_devnet() {
        assert_eq!(default_rpc_url("devnet"), "https://api.devnet.solana.com");
    }

    #[test]
    fn default_rpc_url_localnet() {
        assert_eq!(default_rpc_url("localnet"), "http://localhost:8899");
    }

    #[test]
    fn default_rpc_url_mainnet() {
        // Canonical slug.
        assert_eq!(
            default_rpc_url("mainnet"),
            "https://api.mainnet-beta.solana.com"
        );
        // Legacy alias still resolves so clients that send the older
        // slug don't break.
        assert_eq!(
            default_rpc_url("mainnet-beta"),
            "https://api.mainnet-beta.solana.com"
        );
    }

    #[test]
    fn default_rpc_url_unknown_defaults_to_mainnet() {
        assert_eq!(
            default_rpc_url("anything"),
            "https://api.mainnet-beta.solana.com"
        );
    }

    // ── charge() and charge_with_options() tests ──

    #[test]
    fn charge_generates_valid_challenge() {
        let mpp = test_mpp();
        let challenge = mpp.charge("0.10").unwrap();

        assert_eq!(challenge.realm, DEFAULT_REALM);
        assert_eq!(challenge.method.as_str(), "solana");
        assert_eq!(challenge.intent.as_str(), "charge");
        assert!(!challenge.id.is_empty());
        assert!(challenge.expires.is_some());

        // Decode the request and verify fields.
        let request: ChargeRequest = challenge.request.decode().unwrap();
        assert_eq!(request.amount, "100000"); // 0.10 * 10^6
        assert_eq!(request.currency, "USDC");
        assert_eq!(request.recipient.as_deref(), Some(TEST_RECIPIENT));
    }

    #[test]
    fn charge_sol_amount_conversion() {
        let mpp = test_mpp_sol();
        let challenge = mpp.charge("1.0").unwrap();

        let request: ChargeRequest = challenge.request.decode().unwrap();
        assert_eq!(request.amount, "1000000000"); // 1 SOL = 10^9 lamports
        assert_eq!(request.currency, "SOL");
    }

    #[test]
    fn charge_integer_amount() {
        let mpp = test_mpp();
        let challenge = mpp.charge("5").unwrap();

        let request: ChargeRequest = challenge.request.decode().unwrap();
        assert_eq!(request.amount, "5000000"); // 5 * 10^6
    }

    #[test]
    fn charge_with_options_description() {
        let mpp = test_mpp();
        let challenge = mpp
            .charge_with_options(
                "1.00",
                ChargeOptions {
                    description: Some("Test payment"),
                    ..Default::default()
                },
            )
            .unwrap();

        assert_eq!(challenge.description.as_deref(), Some("Test payment"));
    }

    #[test]
    fn charge_with_options_external_id() {
        let mpp = test_mpp();
        let challenge = mpp
            .charge_with_options(
                "1.00",
                ChargeOptions {
                    external_id: Some("order-123"),
                    ..Default::default()
                },
            )
            .unwrap();

        let request: ChargeRequest = challenge.request.decode().unwrap();
        assert_eq!(request.external_id.as_deref(), Some("order-123"));
    }

    #[test]
    fn charge_with_options_splits() {
        let mpp = test_mpp();
        let splits = vec![
            crate::protocol::solana::Split {
                recipient: "VendorPayoutsWaLLetxxxxxxxxxxxxxxxxxxxxxx1111".to_string(),
                amount: "500000".to_string(),
                ata_creation_required: None,
                label: None,
                memo: Some("Vendor payout".to_string()),
            },
            crate::protocol::solana::Split {
                recipient: "ProcessorFeeWaLLetxxxxxxxxxxxxxxxxxxxxxxx1111".to_string(),
                amount: "29000".to_string(),
                ata_creation_required: None,
                label: None,
                memo: Some("Processing fee".to_string()),
            },
        ];
        let challenge = mpp
            .charge_with_options(
                "1.00",
                ChargeOptions {
                    splits,
                    ..Default::default()
                },
            )
            .unwrap();

        let request: ChargeRequest = challenge.request.decode().unwrap();
        let details = request.method_details.unwrap();
        let splits_val = details
            .get("splits")
            .expect("splits should be in methodDetails");
        let splits_arr = splits_val.as_array().unwrap();
        assert_eq!(splits_arr.len(), 2);
        assert_eq!(splits_arr[0]["amount"], "500000");
        assert_eq!(splits_arr[0]["memo"], "Vendor payout");
        assert_eq!(splits_arr[1]["amount"], "29000");
    }

    #[test]
    fn charge_with_options_no_splits_omitted() {
        let mpp = test_mpp();
        let challenge = mpp
            .charge_with_options("1.00", ChargeOptions::default())
            .unwrap();

        let request: ChargeRequest = challenge.request.decode().unwrap();
        let details = request.method_details.unwrap();
        assert!(
            details.get("splits").is_none(),
            "splits should not be present when empty"
        );
    }

    #[test]
    fn charge_with_options_custom_expiry() {
        let mpp = test_mpp();
        let custom_expires = crate::expires::minutes(30);
        let challenge = mpp
            .charge_with_options(
                "1.00",
                ChargeOptions {
                    expires: Some(&custom_expires),
                    ..Default::default()
                },
            )
            .unwrap();

        assert_eq!(challenge.expires.as_deref(), Some(custom_expires.as_str()));
    }

    #[test]
    fn charge_invalid_amount_errors() {
        let mpp = test_mpp();
        let result = mpp.charge("not-a-number");
        assert!(result.is_err());
    }

    #[test]
    fn charge_too_many_decimals_errors() {
        let mpp = test_mpp();
        // 6 decimals configured, but providing 7.
        let result = mpp.charge("1.1234567");
        assert!(result.is_err());
    }

    // ── charge_challenge() tests ──

    #[test]
    fn charge_challenge_from_request() {
        let mpp = test_mpp();
        let request = ChargeRequest {
            amount: "500000".to_string(),
            currency: "USDC".to_string(),
            recipient: Some(TEST_RECIPIENT.to_string()),
            ..Default::default()
        };
        let challenge = mpp.charge_challenge(&request).unwrap();

        assert_eq!(challenge.method.as_str(), "solana");
        assert_eq!(challenge.intent.as_str(), "charge");
        assert!(challenge.expires.is_some());

        let decoded: ChargeRequest = challenge.request.decode().unwrap();
        assert_eq!(decoded.amount, "500000");
    }

    #[test]
    fn charge_challenge_with_options() {
        let mpp = test_mpp();
        let request = ChargeRequest {
            amount: "500000".to_string(),
            currency: "USDC".to_string(),
            recipient: Some(TEST_RECIPIENT.to_string()),
            ..Default::default()
        };
        let custom_expires = crate::expires::minutes(10);
        let challenge = mpp
            .charge_challenge_with_options(&request, Some(&custom_expires), Some("Premium access"))
            .unwrap();

        assert_eq!(challenge.expires.as_deref(), Some(custom_expires.as_str()));
        assert_eq!(challenge.description.as_deref(), Some("Premium access"));
    }

    // ── Challenge HMAC verification tests ──

    #[test]
    fn challenge_hmac_verifies_with_correct_secret() {
        let mpp = test_mpp();
        let challenge = mpp.charge("1.00").unwrap();
        assert!(challenge.verify(TEST_SECRET));
    }

    #[test]
    fn challenge_hmac_fails_with_wrong_secret() {
        let mpp = test_mpp();
        let challenge = mpp.charge("1.00").unwrap();
        assert!(!challenge.verify("wrong-secret"));
    }

    #[test]
    fn challenge_hmac_deterministic() {
        // Two challenges with same parameters should have same ID
        // (except for expires timestamp, which varies).
        let mpp = test_mpp();
        let request = ChargeRequest {
            amount: "100000".to_string(),
            currency: "USDC".to_string(),
            recipient: Some(TEST_RECIPIENT.to_string()),
            ..Default::default()
        };
        let expires = "2099-01-01T00:00:00Z";
        let c1 = mpp
            .charge_challenge_with_options(&request, Some(expires), None)
            .unwrap();
        let c2 = mpp
            .charge_challenge_with_options(&request, Some(expires), None)
            .unwrap();
        assert_eq!(c1.id, c2.id);
    }

    #[test]
    fn challenge_hmac_different_amounts_different_ids() {
        let mpp = test_mpp();
        let expires = "2099-01-01T00:00:00Z";

        let r1 = ChargeRequest {
            amount: "100000".to_string(),
            currency: "USDC".to_string(),
            recipient: Some(TEST_RECIPIENT.to_string()),
            ..Default::default()
        };
        let r2 = ChargeRequest {
            amount: "200000".to_string(),
            currency: "USDC".to_string(),
            recipient: Some(TEST_RECIPIENT.to_string()),
            ..Default::default()
        };

        let c1 = mpp
            .charge_challenge_with_options(&r1, Some(expires), None)
            .unwrap();
        let c2 = mpp
            .charge_challenge_with_options(&r2, Some(expires), None)
            .unwrap();
        assert_ne!(c1.id, c2.id);
    }

    // ── verify() — HMAC mismatch, expiry, replay protection ──

    fn build_credential(
        mpp: &Mpp,
        request: &ChargeRequest,
        payload: serde_json::Value,
    ) -> PaymentCredential {
        let challenge = mpp.charge_challenge(request).unwrap();
        PaymentCredential {
            challenge: challenge.to_echo(),
            source: None,
            payload,
        }
    }

    fn build_credential_with_expires(
        mpp: &Mpp,
        request: &ChargeRequest,
        expires: &str,
        payload: serde_json::Value,
    ) -> PaymentCredential {
        let challenge = mpp
            .charge_challenge_with_options(request, Some(expires), None)
            .unwrap();
        PaymentCredential {
            challenge: challenge.to_echo(),
            source: None,
            payload,
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn verify_rejects_tampered_challenge_id() {
        let mpp = test_mpp();
        let request = ChargeRequest {
            amount: "100000".to_string(),
            currency: "USDC".to_string(),
            recipient: Some(TEST_RECIPIENT.to_string()),
            ..Default::default()
        };
        let payload = serde_json::json!({"type": "signature", "signature": "fakesig"});
        let mut cred = build_credential(&mpp, &request, payload);
        cred.challenge.id = "tampered-id".to_string();

        let err = mpp.verify(&cred, &request).await.unwrap_err();
        assert_eq!(err.code, Some("malformed-credential"));
        assert!(err.message.contains("Challenge ID mismatch"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn verify_rejects_expired_challenge() {
        let mpp = test_mpp();
        let request = ChargeRequest {
            amount: "100000".to_string(),
            currency: "USDC".to_string(),
            recipient: Some(TEST_RECIPIENT.to_string()),
            ..Default::default()
        };
        // Use an already-expired timestamp.
        let expired = "2020-01-01T00:00:00Z";
        let payload = serde_json::json!({"type": "signature", "signature": "fakesig"});
        let cred = build_credential_with_expires(&mpp, &request, expired, payload);

        let err = mpp.verify(&cred, &request).await.unwrap_err();
        assert_eq!(err.code, Some("payment-expired"));
        assert!(err.message.contains("expired"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn verify_rejects_invalid_expires_format() {
        let mpp = test_mpp();
        let request = ChargeRequest {
            amount: "100000".to_string(),
            currency: "USDC".to_string(),
            recipient: Some(TEST_RECIPIENT.to_string()),
            ..Default::default()
        };
        let payload = serde_json::json!({"type": "signature", "signature": "fakesig"});
        let mut cred = build_credential(&mpp, &request, payload);
        // Manually set an invalid expires but recompute the HMAC to match.
        let bad_expires = "not-a-date";
        let new_id = compute_challenge_id(
            TEST_SECRET,
            &mpp.realm,
            cred.challenge.method.as_str(),
            cred.challenge.intent.as_str(),
            cred.challenge.request.raw(),
            Some(bad_expires),
            None,
            None,
        );
        cred.challenge.expires = Some(bad_expires.to_string());
        cred.challenge.id = new_id;

        let err = mpp.verify(&cred, &request).await.unwrap_err();
        assert!(err.message.contains("Invalid expires timestamp"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn verify_rejects_invalid_payload() {
        let mpp = test_mpp();
        let request = ChargeRequest {
            amount: "100000".to_string(),
            currency: "USDC".to_string(),
            recipient: Some(TEST_RECIPIENT.to_string()),
            ..Default::default()
        };
        // Payload missing the "type" tag needed for CredentialPayload deserialization.
        let bad_payload = serde_json::json!({"foo": "bar"});
        let cred =
            build_credential_with_expires(&mpp, &request, "2099-01-01T00:00:00Z", bad_payload);

        let err = mpp.verify(&cred, &request).await.unwrap_err();
        assert_eq!(err.code, Some("malformed-credential"));
        assert!(err.message.contains("Invalid credential payload"));
    }

    // ── verify_credential() tests ──

    #[tokio::test(flavor = "multi_thread")]
    async fn verify_credential_rejects_tampered_id() {
        let mpp = test_mpp();
        let challenge = mpp.charge("0.10").unwrap();
        let mut cred = PaymentCredential {
            challenge: challenge.to_echo(),
            source: None,
            payload: serde_json::json!({"type": "signature", "signature": "x"}),
        };
        cred.challenge.id = "bad".to_string();

        let err = mpp.verify_credential(&cred).await.unwrap_err();
        assert_eq!(err.code, Some("malformed-credential"));
    }

    // ── verify_credential_with_expected() tests ──

    #[tokio::test(flavor = "multi_thread")]
    async fn verify_credential_with_expected_amount_mismatch() {
        let mpp = test_mpp();
        let challenge = mpp.charge("0.10").unwrap();
        let cred = PaymentCredential {
            challenge: challenge.to_echo(),
            source: None,
            payload: serde_json::json!({"type": "signature", "signature": "x"}),
        };

        let expected = ChargeRequest {
            amount: "999999".to_string(), // different from 100000
            currency: "USDC".to_string(),
            recipient: Some(TEST_RECIPIENT.to_string()),
            ..Default::default()
        };

        let err = mpp
            .verify_credential_with_expected(&cred, &expected)
            .await
            .unwrap_err();
        assert_eq!(err.code, Some("malformed-credential"));
        assert!(err.message.contains("Amount mismatch"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn verify_credential_with_expected_currency_mismatch() {
        let mpp = test_mpp();
        let challenge = mpp.charge("0.10").unwrap();
        let cred = PaymentCredential {
            challenge: challenge.to_echo(),
            source: None,
            payload: serde_json::json!({"type": "signature", "signature": "x"}),
        };

        let expected = ChargeRequest {
            amount: "100000".to_string(),
            currency: "SOL".to_string(), // mismatch: challenge has USDC
            recipient: Some(TEST_RECIPIENT.to_string()),
            ..Default::default()
        };

        let err = mpp
            .verify_credential_with_expected(&cred, &expected)
            .await
            .unwrap_err();
        assert_eq!(err.code, Some("malformed-credential"));
        assert!(err.message.contains("Currency mismatch"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn verify_credential_with_expected_recipient_mismatch() {
        let mpp = test_mpp();
        let challenge = mpp.charge("0.10").unwrap();
        let cred = PaymentCredential {
            challenge: challenge.to_echo(),
            source: None,
            payload: serde_json::json!({"type": "signature", "signature": "x"}),
        };

        let expected = ChargeRequest {
            amount: "100000".to_string(),
            currency: "USDC".to_string(),
            recipient: Some(Pubkey::new_unique().to_string()), // different recipient
            ..Default::default()
        };

        let err = mpp
            .verify_credential_with_expected(&cred, &expected)
            .await
            .unwrap_err();
        assert_eq!(err.code, Some("malformed-credential"));
        assert!(err.message.contains("Recipient mismatch"));
    }

    /// Behavioral proof that `verify_credential_with_expected` routes the
    /// route's `expected` request into `verify` (not the credential-decoded
    /// one). The credential carries valid method_details, but `expected`
    /// carries malformed ones — if the SDK is using `expected` as the
    /// source of truth during settlement, parsing fails on `expected`'s
    /// method_details. If it were still using the credential's request
    /// (the pre-fix behavior), this test would not produce that error.
    #[tokio::test(flavor = "multi_thread")]
    async fn verify_credential_with_expected_routes_expected_into_verify() {
        let mpp = test_mpp();
        let challenge = mpp.charge("0.10").unwrap();
        let cred = PaymentCredential {
            challenge: challenge.to_echo(),
            source: None,
            payload: serde_json::json!({"type": "signature", "signature": "x"}),
        };

        let mut expected: ChargeRequest = challenge.request.decode().unwrap();
        // `network` is Option<String>; a number won't deserialize into MethodDetails.
        expected.method_details = Some(serde_json::json!({"network": 12345}));

        let err = mpp
            .verify_credential_with_expected(&cred, &expected)
            .await
            .unwrap_err();
        assert!(
            err.message.contains("Invalid method details"),
            "expected `expected` request to be parsed, got: {err:?}"
        );
    }

    // ── Tier-2 pinned-field tests ──
    //
    // Each test forges a credential where one pinned field differs from what
    // the server has configured, then re-signs the HMAC so Tier-1 passes. The
    // Tier-2 backstop must reject every case even via the simple
    // `verify_credential` API.

    fn resign_challenge(
        secret: &str,
        realm: &str,
        echo: &mut crate::protocol::core::ChallengeEcho,
    ) {
        echo.id = compute_challenge_id(
            secret,
            realm,
            echo.method.as_str(),
            echo.intent.as_str(),
            echo.request.raw(),
            echo.expires.as_deref(),
            echo.digest.as_deref(),
            echo.opaque.as_ref().map(|o| o.raw()),
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn tier2_rejects_tampered_realm() {
        let mpp = test_mpp();
        let challenge = mpp.charge("0.10").unwrap();
        let mut echo = challenge.to_echo();
        echo.realm = "Attacker Realm".to_string();
        // HMAC uses the *server's* realm, not the echoed one, so re-signing
        // with the server's realm produces an ID that Tier-1 accepts.
        resign_challenge(TEST_SECRET, &mpp.realm, &mut echo);

        let cred = PaymentCredential {
            challenge: echo,
            source: None,
            payload: serde_json::json!({"type": "signature", "signature": "x"}),
        };
        let err = mpp.verify_credential(&cred).await.unwrap_err();
        assert_eq!(err.code, Some("malformed-credential"));
        assert!(err.message.to_lowercase().contains("realm"), "got: {err:?}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn tier2_rejects_tampered_currency() {
        let mpp = test_mpp();
        let challenge = mpp.charge("0.10").unwrap();
        let mut request: ChargeRequest = challenge.request.decode().unwrap();
        request.currency = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".to_string();
        let encoded = Base64UrlJson::from_typed(&request).unwrap();

        let mut echo = challenge.to_echo();
        echo.request = encoded;
        resign_challenge(TEST_SECRET, &mpp.realm, &mut echo);

        let cred = PaymentCredential {
            challenge: echo,
            source: None,
            payload: serde_json::json!({"type": "signature", "signature": "x"}),
        };
        let err = mpp.verify_credential(&cred).await.unwrap_err();
        assert_eq!(err.code, Some("malformed-credential"));
        assert!(err.message.contains("currency"), "got: {err:?}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn tier2_rejects_tampered_recipient() {
        let mpp = test_mpp();
        let challenge = mpp.charge("0.10").unwrap();
        let mut request: ChargeRequest = challenge.request.decode().unwrap();
        request.recipient = Some(Pubkey::new_unique().to_string());
        let encoded = Base64UrlJson::from_typed(&request).unwrap();

        let mut echo = challenge.to_echo();
        echo.request = encoded;
        resign_challenge(TEST_SECRET, &mpp.realm, &mut echo);

        let cred = PaymentCredential {
            challenge: echo,
            source: None,
            payload: serde_json::json!({"type": "signature", "signature": "x"}),
        };
        let err = mpp.verify_credential(&cred).await.unwrap_err();
        assert_eq!(err.code, Some("malformed-credential"));
        assert!(err.message.contains("recipient"), "got: {err:?}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn tier2_rejects_tampered_method() {
        let mpp = test_mpp();
        let challenge = mpp.charge("0.10").unwrap();
        let mut echo = challenge.to_echo();
        echo.method = "stripe".into();
        resign_challenge(TEST_SECRET, &mpp.realm, &mut echo);

        let cred = PaymentCredential {
            challenge: echo,
            source: None,
            payload: serde_json::json!({"type": "signature", "signature": "x"}),
        };
        let err = mpp.verify_credential(&cred).await.unwrap_err();
        assert_eq!(err.code, Some("malformed-credential"));
        assert!(err.message.contains("method"), "got: {err:?}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn tier2_rejects_non_charge_intent() {
        let mpp = test_mpp();
        let challenge = mpp.charge("0.10").unwrap();
        let mut echo = challenge.to_echo();
        echo.intent = "session".into();
        resign_challenge(TEST_SECRET, &mpp.realm, &mut echo);

        let cred = PaymentCredential {
            challenge: echo,
            source: None,
            payload: serde_json::json!({"type": "signature", "signature": "x"}),
        };
        let err = mpp.verify_credential(&cred).await.unwrap_err();
        assert_eq!(err.code, Some("malformed-credential"));
        assert!(err.message.contains("intent"), "got: {err:?}");
    }

    // ── B34: push-mode credentials rejected on fee-payer routes ──
    //
    // A signature-only credential references an already-landed transaction
    // that the client paid the fee for. A route that uses a server-side fee
    // payer expects the server to fund the transaction; accepting a push
    // credential there means the route paid no fee, defeating the purpose
    // of a server-funded charge. The reject runs before any RPC call so a
    // partially-validated push credential never touches the network.
    //
    // Ludo's spec lock. Mirrors PHP #100 and Python #106.

    #[tokio::test(flavor = "multi_thread")]
    async fn b34_rejects_push_credential_on_fee_payer_route() {
        let mpp = Mpp::new(Config {
            recipient: TEST_RECIPIENT.to_string(),
            challenge_binding_secret: Some(TEST_SECRET.to_string()),
            currency: crate::protocol::solana::mints::USDC_DEVNET.to_string(),
            fee_payer: true,
            fee_payer_signer: Some(test_fee_payer_signer()),
            network: "devnet".to_string(),
            ..Default::default()
        })
        .unwrap();
        let challenge = mpp.charge("0.10").unwrap();
        let request: ChargeRequest = challenge.request.decode().unwrap();
        let cred = PaymentCredential {
            challenge: challenge.to_echo(),
            source: None,
            payload: serde_json::json!({
                "type": "signature",
                "signature": "3yZe7d2X1bxYjP6kJtNJzC8mFqLgK6vQ9zR3hT5wXdAfVjY8nW1qB4uHpM2sC3rTzJtNeWfDqRmKxYjP6kJtNJzC",
            }),
        };

        let err = mpp.verify(&cred, &request).await.unwrap_err();
        assert_eq!(err.code, Some("malformed-credential"));
        assert!(
            err.message
                .to_lowercase()
                .contains("push-mode credentials are not allowed"),
            "got: {err:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn b34_accepts_pull_credential_on_fee_payer_route() {
        // Sanity check: the B34 reject is gated on the credential type, not
        // on fee_payer alone. A pull-mode (transaction) credential against
        // the same fee-payer route must still reach the broadcast path.
        // We do not drive broadcast here, only assert the early reject does
        // not fire: any error must come from broadcast, not from B34.
        let mpp = Mpp::new(Config {
            recipient: TEST_RECIPIENT.to_string(),
            challenge_binding_secret: Some(TEST_SECRET.to_string()),
            currency: crate::protocol::solana::mints::USDC_DEVNET.to_string(),
            fee_payer: true,
            fee_payer_signer: Some(test_fee_payer_signer()),
            network: "devnet".to_string(),
            ..Default::default()
        })
        .unwrap();
        let challenge = mpp.charge("0.10").unwrap();
        let request: ChargeRequest = challenge.request.decode().unwrap();
        let cred = PaymentCredential {
            challenge: challenge.to_echo(),
            source: None,
            payload: serde_json::json!({
                "type": "transaction",
                "transaction": "AAAA",
            }),
        };

        let err = mpp.verify(&cred, &request).await.unwrap_err();
        assert!(
            !err.message
                .to_lowercase()
                .contains("push-mode credentials are not allowed"),
            "B34 fired on a pull credential: {err:?}"
        );
    }

    // ── Replay protection tests ──

    #[tokio::test(flavor = "multi_thread")]
    async fn replay_protection_marks_and_detects_consumed() {
        let store = Arc::new(MemoryStore::new());
        let _mpp = Mpp::new(Config {
            recipient: TEST_RECIPIENT.to_string(),
            challenge_binding_secret: Some(TEST_SECRET.to_string()),
            store: Some(store.clone()),
            network: "devnet".to_string(),
            ..Default::default()
        })
        .unwrap();

        let key = "solana-charge:consumed:testsig123";
        // Not consumed yet.
        assert!(store.get(key).await.unwrap().is_none());

        // Mark as consumed.
        store.put(key, serde_json::json!(true)).await.unwrap();

        // Now it should be detected.
        assert!(store.get(key).await.unwrap().is_some());
    }

    // ── Receipt tests ──

    #[test]
    fn receipt_success_format() {
        let receipt = Receipt::success("solana", "5UfDuX123", "challenge-id-abc");
        assert!(receipt.is_success());
        assert_eq!(receipt.method.as_str(), "solana");
        assert_eq!(receipt.reference, "5UfDuX123");
        assert_eq!(receipt.challenge_id, "challenge-id-abc");
        assert!(!receipt.timestamp.is_empty());
        // Timestamp should be RFC 3339.
        assert!(receipt.timestamp.contains('T'));
    }

    #[test]
    fn receipt_serializes_correctly() {
        let receipt = Receipt::success("solana", "sig-abc", "cid-123");
        let json = serde_json::to_value(&receipt).unwrap();
        assert_eq!(json["status"], "success");
        assert_eq!(json["method"], "solana");
        assert_eq!(json["reference"], "sig-abc");
        assert_eq!(json["challengeId"], "cid-123");
    }

    // ── VerificationError tests ──

    #[test]
    fn verification_error_new_has_no_code() {
        let err = VerificationError::new("Something went wrong");
        assert_eq!(err.message, "Something went wrong");
        assert!(err.code.is_none());
        assert!(!err.retryable);
    }

    #[test]
    fn verification_error_expired() {
        let err = VerificationError::expired("expired at X");
        assert_eq!(err.code, Some("payment-expired"));
        assert!(!err.retryable);
    }

    #[test]
    fn verification_error_invalid_amount() {
        let err = VerificationError::invalid_amount("bad amount");
        assert_eq!(err.code, Some("verification-failed"));
        assert!(!err.retryable);
    }

    #[test]
    fn verification_error_invalid_recipient() {
        let err = VerificationError::invalid_recipient("wrong recipient");
        assert_eq!(err.code, Some("verification-failed"));
    }

    #[test]
    fn verification_error_transaction_failed() {
        let err = VerificationError::transaction_failed("tx failed");
        assert_eq!(err.code, Some("verification-failed"));
    }

    #[test]
    fn verification_error_not_found() {
        let err = VerificationError::not_found("tx not found");
        assert_eq!(err.code, Some("verification-failed"));
    }

    #[test]
    fn verification_error_network_error_is_retryable() {
        let err = VerificationError::network_error("timeout");
        assert_eq!(err.code, Some("verification-failed"));
        assert!(err.retryable);
    }

    #[test]
    fn verification_error_credential_mismatch() {
        let err = VerificationError::credential_mismatch("id mismatch");
        assert_eq!(err.code, Some("malformed-credential"));
    }

    #[test]
    fn verification_error_invalid_payload() {
        let err = VerificationError::invalid_payload("bad payload");
        assert_eq!(err.code, Some("malformed-credential"));
    }

    #[test]
    fn verification_error_signature_consumed() {
        let err = VerificationError::signature_consumed("already used");
        assert_eq!(err.code, Some("signature-consumed"));
    }

    #[test]
    fn verification_error_display_omits_code_even_when_present() {
        // Display is the user-facing message — the structured `code`
        // field stays accessible for callers that need to branch on it.
        let err = VerificationError::expired("at time X");
        assert_eq!(format!("{err}"), "at time X");
        assert_eq!(err.code, Some("payment-expired"));
    }

    #[test]
    fn verification_error_display_without_code() {
        let err = VerificationError::new("generic");
        assert_eq!(format!("{err}"), "generic");
    }

    #[test]
    fn verification_error_is_std_error() {
        let err = VerificationError::new("test");
        let _: &dyn std::error::Error = &err;
    }

    // ── On-chain parsed-instruction helpers (find_sol_transfer, find_spl_transfer) ──

    #[test]
    fn find_sol_transfer_success() {
        let mut matched = HashSet::new();
        let instructions = vec![serde_json::json!({
            "parsed": {
                "type": "transfer",
                "info": {
                    "destination": "RecipientPubkey",
                    "lamports": 1000000
                }
            }
        })];
        assert!(
            find_sol_transfer(&instructions, "RecipientPubkey", 1_000_000, &mut matched).is_ok()
        );
    }

    #[test]
    fn find_sol_transfer_wrong_amount() {
        let mut matched = HashSet::new();
        let instructions = vec![serde_json::json!({
            "parsed": {
                "type": "transfer",
                "info": {
                    "destination": "RecipientPubkey",
                    "lamports": 500000
                }
            }
        })];
        assert!(
            find_sol_transfer(&instructions, "RecipientPubkey", 1_000_000, &mut matched).is_err()
        );
    }

    #[test]
    fn find_sol_transfer_wrong_recipient() {
        let mut matched = HashSet::new();
        let instructions = vec![serde_json::json!({
            "parsed": {
                "type": "transfer",
                "info": {
                    "destination": "WrongPubkey",
                    "lamports": 1000000
                }
            }
        })];
        assert!(
            find_sol_transfer(&instructions, "RecipientPubkey", 1_000_000, &mut matched).is_err()
        );
    }

    #[test]
    fn find_sol_transfer_empty_instructions() {
        let mut matched = HashSet::new();
        assert!(find_sol_transfer(&[], "RecipientPubkey", 1_000_000, &mut matched).is_err());
    }

    #[test]
    fn find_sol_transfer_ignores_non_transfer_types() {
        let mut matched = HashSet::new();
        let instructions = vec![serde_json::json!({
            "parsed": {
                "type": "createAccount",
                "info": {
                    "destination": "RecipientPubkey",
                    "lamports": 1000000
                }
            }
        })];
        assert!(
            find_sol_transfer(&instructions, "RecipientPubkey", 1_000_000, &mut matched).is_err()
        );
    }

    #[test]
    fn verify_sol_transfers_with_splits() {
        let primary_recipient = "PrimaryRecipient";
        let split_recipient = "SplitRecipient";
        let instructions = vec![
            serde_json::json!({
                "parsed": {
                    "type": "transfer",
                    "info": {
                        "destination": primary_recipient,
                        "lamports": 800000
                    }
                }
            }),
            serde_json::json!({
                "parsed": {
                    "type": "transfer",
                    "info": {
                        "destination": split_recipient,
                        "lamports": 200000
                    }
                }
            }),
        ];

        let splits = vec![Split {
            recipient: split_recipient.to_string(),
            amount: "200000".to_string(),
            ata_creation_required: None,
            label: None,
            memo: None,
        }];

        assert!(verify_sol_transfers(&instructions, primary_recipient, 800000, &splits).is_ok());
    }

    #[test]
    fn verify_sol_transfers_missing_split() {
        let instructions = vec![serde_json::json!({
            "parsed": {
                "type": "transfer",
                "info": {
                    "destination": "PrimaryRecipient",
                    "lamports": 800000
                }
            }
        })];

        let splits = vec![Split {
            recipient: "SplitRecipient".to_string(),
            amount: "200000".to_string(),
            ata_creation_required: None,
            label: None,
            memo: None,
        }];

        let err =
            verify_sol_transfers(&instructions, "PrimaryRecipient", 800000, &splits).unwrap_err();
        assert!(err.message.contains("Missing split transfer"));
    }

    #[test]
    fn verify_sol_transfers_rejects_reusing_single_instruction_for_duplicate_splits() {
        let instructions = vec![
            serde_json::json!({
                "parsed": {
                    "type": "transfer",
                    "info": {
                        "destination": "PrimaryRecipient",
                        "lamports": 800000
                    }
                }
            }),
            serde_json::json!({
                "parsed": {
                    "type": "transfer",
                    "info": {
                        "destination": "SplitRecipient",
                        "lamports": 100000
                    }
                }
            }),
        ];

        let splits = vec![
            Split {
                recipient: "SplitRecipient".to_string(),
                amount: "100000".to_string(),
                ata_creation_required: None,
                label: None,
                memo: None,
            },
            Split {
                recipient: "SplitRecipient".to_string(),
                amount: "100000".to_string(),
                ata_creation_required: None,
                label: None,
                memo: None,
            },
        ];

        let err =
            verify_sol_transfers(&instructions, "PrimaryRecipient", 800000, &splits).unwrap_err();
        assert!(err.message.contains("Missing split transfer"));
    }

    #[test]
    fn verify_parsed_memo_instructions_accepts_string_and_info_forms() {
        let instructions = vec![
            parsed_memo_ix("platform fee"),
            serde_json::json!({
                "program": "spl-memo",
                "parsed": {
                    "info": {
                        "memo": "referrer fee"
                    }
                }
            }),
        ];
        let splits = vec![
            Split {
                recipient: "PlatformRecipient".to_string(),
                amount: "30000".to_string(),
                ata_creation_required: None,
                label: None,
                memo: Some("platform fee".to_string()),
            },
            Split {
                recipient: "ReferrerRecipient".to_string(),
                amount: "20000".to_string(),
                ata_creation_required: None,
                label: None,
                memo: Some("referrer fee".to_string()),
            },
        ];
        let mut matched = HashSet::new();

        verify_parsed_memo_instructions(&instructions, None, &splits, &mut matched).unwrap();

        assert_eq!(matched, HashSet::from([0, 1]));
    }

    #[test]
    fn verify_parsed_memo_instructions_accepts_info_data_form() {
        let instructions = vec![serde_json::json!({
            "programId": programs::MEMO_PROGRAM,
            "parsed": {
                "info": {
                    "data": "platform fee"
                }
            }
        })];
        let splits = vec![Split {
            recipient: "PlatformRecipient".to_string(),
            amount: "50000".to_string(),
            ata_creation_required: None,
            label: None,
            memo: Some("platform fee".to_string()),
        }];
        let mut matched = HashSet::new();

        verify_parsed_memo_instructions(&instructions, None, &splits, &mut matched).unwrap();

        assert_eq!(matched, HashSet::from([0]));
    }

    #[test]
    fn verify_parsed_memo_instructions_accepts_external_id() {
        let instructions = vec![parsed_memo_ix("order-123")];
        let splits = vec![];
        let mut matched = HashSet::new();

        verify_parsed_memo_instructions(&instructions, Some("order-123"), &splits, &mut matched)
            .unwrap();

        assert_eq!(matched, HashSet::from([0]));
    }

    #[test]
    fn verify_parsed_memo_instructions_rejects_missing_external_id() {
        let instructions = vec![parsed_memo_ix("wrong order")];
        let splits = vec![];
        let mut matched = HashSet::new();

        let err = verify_parsed_memo_instructions(
            &instructions,
            Some("order-123"),
            &splits,
            &mut matched,
        )
        .unwrap_err();

        assert!(err
            .message
            .contains("No memo instruction found for externalId memo"));
    }

    #[test]
    fn verify_parsed_memo_instructions_requires_distinct_external_id_and_split_memos() {
        let instructions = vec![parsed_memo_ix("same")];
        let splits = vec![Split {
            recipient: "PlatformRecipient".to_string(),
            amount: "50000".to_string(),
            ata_creation_required: None,
            label: None,
            memo: Some("same".to_string()),
        }];
        let mut matched = HashSet::new();

        let err =
            verify_parsed_memo_instructions(&instructions, Some("same"), &splits, &mut matched)
                .unwrap_err();

        assert!(err
            .message
            .contains("No memo instruction found for split memo"));
    }

    #[test]
    fn verify_parsed_memo_instructions_rejects_missing_memo() {
        let instructions = vec![parsed_memo_ix("wrong memo")];
        let splits = vec![Split {
            recipient: "PlatformRecipient".to_string(),
            amount: "50000".to_string(),
            ata_creation_required: None,
            label: None,
            memo: Some("platform fee".to_string()),
        }];
        let mut matched = HashSet::new();

        let err = verify_parsed_memo_instructions(&instructions, None, &splits, &mut matched)
            .unwrap_err();

        assert!(err.message.contains("No memo instruction found"));
    }

    #[test]
    fn verify_parsed_memo_instructions_requires_distinct_memos_for_duplicate_split_memos() {
        let instructions = vec![parsed_memo_ix("platform fee")];
        let splits = vec![
            Split {
                recipient: "PlatformRecipient".to_string(),
                amount: "30000".to_string(),
                ata_creation_required: None,
                label: None,
                memo: Some("platform fee".to_string()),
            },
            Split {
                recipient: "ReferrerRecipient".to_string(),
                amount: "20000".to_string(),
                ata_creation_required: None,
                label: None,
                memo: Some("platform fee".to_string()),
            },
        ];
        let mut matched = HashSet::new();

        let err = verify_parsed_memo_instructions(&instructions, None, &splits, &mut matched)
            .unwrap_err();

        assert!(err.message.contains("No memo instruction found"));
    }

    #[test]
    fn parsed_allowlist_rejects_unrequested_memo() {
        let instructions = vec![parsed_memo_ix("not requested")];

        let err = validate_parsed_instruction_allowlist(
            &instructions,
            &HashSet::new(),
            None,
            &HashSet::new(),
            None,
            None,
            &HashSet::new(),
        )
        .unwrap_err();

        assert!(err.message.contains("Unexpected Memo Program instruction"));
    }

    // ── find_spl_transfer tests ──

    #[test]
    fn find_spl_transfer_success() {
        let mut matched = HashSet::new();
        let owner = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY";
        let mint = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
        let tp = programs::TOKEN_PROGRAM;

        // Derive expected ATA.
        let owner_pk = Pubkey::from_str(owner).unwrap();
        let mint_pk = Pubkey::from_str(mint).unwrap();
        let tp_pk = Pubkey::from_str(tp).unwrap();
        let ata_program = Pubkey::from_str(programs::ASSOCIATED_TOKEN_PROGRAM).unwrap();
        let (dest_ata, _) = Pubkey::find_program_address(
            &[owner_pk.as_ref(), tp_pk.as_ref(), mint_pk.as_ref()],
            &ata_program,
        );

        let instructions = vec![serde_json::json!({
            "programId": tp,
            "parsed": {
                "type": "transferChecked",
                "info": {
                    "destination": dest_ata.to_string(),
                    "mint": mint,
                    "tokenAmount": {
                        "amount": "1000000"
                    }
                }
            }
        })];

        assert!(
            find_spl_transfer(&instructions, owner, mint, 1_000_000, None, &mut matched).is_ok()
        );
    }

    #[test]
    fn find_spl_transfer_wrong_program() {
        let mut matched = HashSet::new();
        let instructions = vec![serde_json::json!({
            "programId": "WrongProgram111111111111111111111111111111",
            "parsed": {
                "type": "transferChecked",
                "info": {
                    "destination": "SomeAta",
                    "mint": "SomeMint",
                    "tokenAmount": {
                        "amount": "1000000"
                    }
                }
            }
        })];
        assert!(find_spl_transfer(
            &instructions,
            "SomeOwner",
            "SomeMint",
            1_000_000,
            None,
            &mut matched
        )
        .is_err());
    }

    #[test]
    fn find_spl_transfer_wrong_type() {
        let mut matched = HashSet::new();
        let instructions = vec![serde_json::json!({
            "programId": programs::TOKEN_PROGRAM,
            "parsed": {
                "type": "transfer",
                "info": {
                    "destination": "SomeAta",
                    "mint": "SomeMint",
                    "tokenAmount": {
                        "amount": "1000000"
                    }
                }
            }
        })];
        assert!(find_spl_transfer(
            &instructions,
            "SomeOwner",
            "SomeMint",
            1_000_000,
            None,
            &mut matched
        )
        .is_err());
    }

    #[test]
    fn find_spl_transfer_wrong_mint() {
        let mut matched = HashSet::new();
        let owner = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY";
        let mint = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
        let wrong_mint = "CXk2AMBfi3TwaEL2468s6zP8xq9NxTXjp9gjMgzeUynM";
        let tp = programs::TOKEN_PROGRAM;

        let owner_pk = Pubkey::from_str(owner).unwrap();
        let mint_pk = Pubkey::from_str(mint).unwrap();
        let tp_pk = Pubkey::from_str(tp).unwrap();
        let ata_program = Pubkey::from_str(programs::ASSOCIATED_TOKEN_PROGRAM).unwrap();
        let (dest_ata, _) = Pubkey::find_program_address(
            &[owner_pk.as_ref(), tp_pk.as_ref(), mint_pk.as_ref()],
            &ata_program,
        );

        let instructions = vec![serde_json::json!({
            "programId": tp,
            "parsed": {
                "type": "transferChecked",
                "info": {
                    "destination": dest_ata.to_string(),
                    "mint": mint,
                    "tokenAmount": {
                        "amount": "1000000"
                    }
                }
            }
        })];

        assert!(find_spl_transfer(
            &instructions,
            owner,
            wrong_mint,
            1_000_000,
            None,
            &mut matched
        )
        .is_err());
    }

    #[test]
    fn verify_spl_transfers_rejects_reusing_single_instruction_for_duplicate_splits() {
        let owner = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY";
        let split_owner = "3pF8QfAS8gM8f3yr8zvHqZqMFKmMZxN4n3K7uP5Q4L8S";
        let mint = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
        let tp = programs::TOKEN_PROGRAM;

        let ata_program = Pubkey::from_str(programs::ASSOCIATED_TOKEN_PROGRAM).unwrap();
        let owner_pk = Pubkey::from_str(owner).unwrap();
        let split_owner_pk = Pubkey::from_str(split_owner).unwrap();
        let mint_pk = Pubkey::from_str(mint).unwrap();
        let tp_pk = Pubkey::from_str(tp).unwrap();
        let (owner_ata, _) = Pubkey::find_program_address(
            &[owner_pk.as_ref(), tp_pk.as_ref(), mint_pk.as_ref()],
            &ata_program,
        );
        let (split_ata, _) = Pubkey::find_program_address(
            &[split_owner_pk.as_ref(), tp_pk.as_ref(), mint_pk.as_ref()],
            &ata_program,
        );

        let instructions = vec![
            serde_json::json!({
                "programId": tp,
                "parsed": {
                    "type": "transferChecked",
                    "info": {
                        "destination": owner_ata.to_string(),
                        "mint": mint,
                        "tokenAmount": {
                            "amount": "800000"
                        }
                    }
                }
            }),
            serde_json::json!({
                "programId": tp,
                "parsed": {
                    "type": "transferChecked",
                    "info": {
                        "destination": split_ata.to_string(),
                        "mint": mint,
                        "tokenAmount": {
                            "amount": "100000"
                        }
                    }
                }
            }),
        ];

        let splits = vec![
            Split {
                recipient: split_owner.to_string(),
                amount: "100000".to_string(),
                ata_creation_required: None,
                label: None,
                memo: None,
            },
            Split {
                recipient: split_owner.to_string(),
                amount: "100000".to_string(),
                ata_creation_required: None,
                label: None,
                memo: None,
            },
        ];

        let err =
            verify_spl_transfers(&instructions, owner, mint, 800000, &splits, None).unwrap_err();
        assert!(err.message.contains("Missing split SPL transfer"));
    }

    #[test]
    fn parsed_allowlist_rejects_extra_spl_transfer_after_required_transfer() {
        let owner = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY";
        let attacker = Pubkey::new_unique();
        let mint = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
        let tp = programs::TOKEN_PROGRAM;

        let owner_pk = Pubkey::from_str(owner).unwrap();
        let mint_pk = Pubkey::from_str(mint).unwrap();
        let tp_pk = Pubkey::from_str(tp).unwrap();
        let owner_ata = derive_ata(&owner_pk, &mint_pk, &tp_pk);
        let attacker_ata = derive_ata(&attacker, &mint_pk, &tp_pk);

        let instructions = vec![
            serde_json::json!({
                "programId": tp,
                "parsed": {
                    "type": "transferChecked",
                    "info": {
                        "destination": owner_ata.to_string(),
                        "mint": mint,
                        "tokenAmount": { "amount": "1000000" }
                    }
                }
            }),
            serde_json::json!({
                "programId": tp,
                "parsed": {
                    "type": "transferChecked",
                    "info": {
                        "destination": attacker_ata.to_string(),
                        "mint": mint,
                        "tokenAmount": { "amount": "1" }
                    }
                }
            }),
        ];
        let matched =
            verify_spl_transfers(&instructions, owner, mint, 1_000_000, &[], Some(tp)).unwrap();
        let allowed_ata_owners = HashSet::from([owner.to_string()]);
        let required_ata_owners = HashSet::new();

        let err = validate_parsed_instruction_allowlist(
            &instructions,
            &matched,
            Some(mint),
            &allowed_ata_owners,
            Some(tp),
            None,
            &required_ata_owners,
        )
        .unwrap_err();
        assert!(err.message.contains("Unexpected Token Program instruction"));
    }

    #[test]
    fn parsed_allowlist_accepts_required_split_ata_creation() {
        let payer = Pubkey::new_unique();
        let split_owner = Pubkey::new_unique();
        let mint = Pubkey::from_str("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v").unwrap();
        let tp = token_program_id();
        let instructions = vec![parsed_ata_create_ix(&payer, &split_owner, &mint, &tp)];
        let allowed_ata_owners = HashSet::from([split_owner.to_string()]);
        let required_ata_owners = HashSet::from([split_owner.to_string()]);

        validate_parsed_instruction_allowlist(
            &instructions,
            &HashSet::new(),
            Some(&mint.to_string()),
            &allowed_ata_owners,
            Some(programs::TOKEN_PROGRAM),
            Some(&payer.to_string()),
            &required_ata_owners,
        )
        .unwrap();
    }

    #[test]
    fn parsed_allowlist_rejects_missing_required_split_ata_creation() {
        let payer = Pubkey::new_unique();
        let split_owner = Pubkey::new_unique();
        let mint = Pubkey::from_str("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v").unwrap();
        let instructions = vec![];
        let allowed_ata_owners = HashSet::from([split_owner.to_string()]);
        let required_ata_owners = HashSet::from([split_owner.to_string()]);

        let err = validate_parsed_instruction_allowlist(
            &instructions,
            &HashSet::new(),
            Some(&mint.to_string()),
            &allowed_ata_owners,
            Some(programs::TOKEN_PROGRAM),
            Some(&payer.to_string()),
            &required_ata_owners,
        )
        .unwrap_err();
        assert!(err.message.contains("Missing required ATA creation"));
    }

    fn parsed_ata_create_ix(
        payer: &Pubkey,
        owner: &Pubkey,
        mint: &Pubkey,
        token_program: &Pubkey,
    ) -> serde_json::Value {
        serde_json::json!({
            "program": "spl-associated-token-account",
            "programId": programs::ASSOCIATED_TOKEN_PROGRAM,
            "parsed": {
                "type": "createIdempotent",
                "info": {
                    "account": derive_ata(owner, mint, token_program).to_string(),
                    "mint": mint.to_string(),
                    "source": payer.to_string(),
                    "systemProgram": programs::SYSTEM_PROGRAM,
                    "tokenProgram": token_program.to_string(),
                    "wallet": owner.to_string()
                }
            }
        })
    }

    fn parsed_memo_ix(memo: &str) -> serde_json::Value {
        serde_json::json!({
            "program": "spl-memo",
            "programId": programs::MEMO_PROGRAM,
            "parsed": memo
        })
    }

    // ── verify_ata_owner edge cases ──

    #[test]
    fn verify_ata_owner_invalid_owner_returns_false() {
        assert!(!verify_ata_owner(
            "abc",
            "invalid!!!",
            "mint",
            programs::TOKEN_PROGRAM
        ));
    }

    #[test]
    fn verify_ata_owner_invalid_mint_returns_false() {
        assert!(!verify_ata_owner(
            "abc",
            "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
            "invalid!!!",
            programs::TOKEN_PROGRAM
        ));
    }

    #[test]
    fn verify_ata_owner_invalid_token_program_returns_false() {
        assert!(!verify_ata_owner(
            "abc",
            "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
            "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
            "invalid!!!"
        ));
    }

    // ── Pre-broadcast: splits tests ──

    #[test]
    fn sol_transfer_with_splits_passes() {
        let sender = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        let split_recipient = Pubkey::new_unique();
        let primary_amount = 800_000u64;
        let split_amount = 200_000u64;
        let total = primary_amount + split_amount;

        let tx = dummy_tx(
            vec![
                system_transfer_ix(&sender, &recipient, primary_amount),
                system_transfer_ix(&sender, &split_recipient, split_amount),
            ],
            &sender,
        );
        let request = charge_request(total, "SOL", &recipient);
        let method_details = MethodDetails {
            splits: Some(vec![Split {
                recipient: split_recipient.to_string(),
                amount: split_amount.to_string(),
                ata_creation_required: None,
                label: None,
                memo: None,
            }]),
            ..Default::default()
        };

        assert!(verify_transaction_pre_broadcast(&tx, &request, &method_details).is_ok());
    }

    #[test]
    fn sol_transfer_with_split_memo_passes_pre_broadcast() {
        let sender = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        let split_recipient = Pubkey::new_unique();
        let primary_amount = 800_000u64;
        let split_amount = 200_000u64;
        let total = primary_amount + split_amount;

        let tx = dummy_tx(
            vec![
                system_transfer_ix(&sender, &recipient, primary_amount),
                system_transfer_ix(&sender, &split_recipient, split_amount),
                memo_ix("platform fee"),
            ],
            &sender,
        );
        let request = charge_request(total, "SOL", &recipient);
        let method_details = MethodDetails {
            splits: Some(vec![Split {
                recipient: split_recipient.to_string(),
                amount: split_amount.to_string(),
                ata_creation_required: None,
                label: None,
                memo: Some("platform fee".to_string()),
            }]),
            ..Default::default()
        };

        assert!(verify_transaction_pre_broadcast(&tx, &request, &method_details).is_ok());
    }

    #[test]
    fn sol_transfer_missing_split_memo_rejected_pre_broadcast() {
        let sender = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        let split_recipient = Pubkey::new_unique();
        let primary_amount = 800_000u64;
        let split_amount = 200_000u64;
        let total = primary_amount + split_amount;

        let tx = dummy_tx(
            vec![
                system_transfer_ix(&sender, &recipient, primary_amount),
                system_transfer_ix(&sender, &split_recipient, split_amount),
            ],
            &sender,
        );
        let request = charge_request(total, "SOL", &recipient);
        let method_details = MethodDetails {
            splits: Some(vec![Split {
                recipient: split_recipient.to_string(),
                amount: split_amount.to_string(),
                ata_creation_required: None,
                label: None,
                memo: Some("platform fee".to_string()),
            }]),
            ..Default::default()
        };

        let err = verify_transaction_pre_broadcast(&tx, &request, &method_details).unwrap_err();
        assert!(err.message.contains("No memo instruction found"));
    }

    #[test]
    fn sol_transfer_wrong_split_memo_rejected_pre_broadcast() {
        let sender = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        let split_recipient = Pubkey::new_unique();
        let primary_amount = 800_000u64;
        let split_amount = 200_000u64;
        let total = primary_amount + split_amount;

        let tx = dummy_tx(
            vec![
                system_transfer_ix(&sender, &recipient, primary_amount),
                system_transfer_ix(&sender, &split_recipient, split_amount),
                memo_ix("wrong memo"),
            ],
            &sender,
        );
        let request = charge_request(total, "SOL", &recipient);
        let method_details = MethodDetails {
            splits: Some(vec![Split {
                recipient: split_recipient.to_string(),
                amount: split_amount.to_string(),
                ata_creation_required: None,
                label: None,
                memo: Some("platform fee".to_string()),
            }]),
            ..Default::default()
        };

        let err = verify_transaction_pre_broadcast(&tx, &request, &method_details).unwrap_err();
        assert!(err.message.contains("No memo instruction found"));
    }

    #[test]
    fn sol_transfer_unrequested_memo_rejected_pre_broadcast() {
        let sender = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        let amount = 500_000u64;

        let tx = dummy_tx(
            vec![
                system_transfer_ix(&sender, &recipient, amount),
                memo_ix("not requested"),
            ],
            &sender,
        );
        let request = charge_request(amount, "SOL", &recipient);
        let method_details = MethodDetails::default();

        let err = verify_transaction_pre_broadcast(&tx, &request, &method_details).unwrap_err();
        assert!(err.message.contains("Unexpected Memo Program instruction"));
    }

    #[test]
    fn splits_exceeding_total_rejected() {
        let sender = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        let split_recipient = Pubkey::new_unique();

        let tx = dummy_tx(vec![], &sender);
        let request = charge_request(100, "SOL", &recipient);
        let method_details = MethodDetails {
            splits: Some(vec![Split {
                recipient: split_recipient.to_string(),
                amount: "200".to_string(), // exceeds total of 100
                ata_creation_required: None,
                label: None,
                memo: None,
            }]),
            ..Default::default()
        };

        let err = verify_transaction_pre_broadcast(&tx, &request, &method_details).unwrap_err();
        assert!(err.message.contains("Split amounts exceed total amount"));
    }

    #[test]
    fn splits_consuming_entire_amount_rejected() {
        let sender = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        let split_recipient = Pubkey::new_unique();

        let tx = dummy_tx(vec![], &sender);
        let request = charge_request(1000, "SOL", &recipient);
        let method_details = MethodDetails {
            splits: Some(vec![Split {
                recipient: split_recipient.to_string(),
                amount: "1000".to_string(), // exactly equals total => primary = 0
                ata_creation_required: None,
                label: None,
                memo: None,
            }]),
            ..Default::default()
        };

        let err = verify_transaction_pre_broadcast(&tx, &request, &method_details).unwrap_err();
        assert!(err.message.contains("Primary amount is zero"));
    }

    #[test]
    fn invalid_amount_string_rejected() {
        let sender = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();

        let tx = dummy_tx(vec![], &sender);
        let request = ChargeRequest {
            amount: "not-a-number".to_string(),
            currency: "SOL".to_string(),
            recipient: Some(recipient.to_string()),
            ..Default::default()
        };
        let method_details = MethodDetails::default();

        let err = verify_transaction_pre_broadcast(&tx, &request, &method_details).unwrap_err();
        assert!(err.message.contains("Invalid amount"));
    }

    #[test]
    fn invalid_recipient_pubkey_in_request_rejected() {
        let sender = Pubkey::new_unique();
        let tx = dummy_tx(
            vec![system_transfer_ix(&sender, &Pubkey::new_unique(), 1000)],
            &sender,
        );
        let request = ChargeRequest {
            amount: "1000".to_string(),
            currency: "SOL".to_string(),
            recipient: Some("not-a-valid-pubkey!!!".to_string()),
            ..Default::default()
        };
        let method_details = MethodDetails::default();

        let err = verify_transaction_pre_broadcast(&tx, &request, &method_details).unwrap_err();
        assert!(err.message.contains("Invalid recipient"));
    }

    // ── SPL with splits pre-broadcast ──

    #[test]
    fn spl_transfer_with_splits_passes() {
        let sender = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        let split_recipient = Pubkey::new_unique();
        let mint = Pubkey::from_str("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v").unwrap();
        let primary_amount = 800_000u64;
        let split_amount = 200_000u64;
        let total = primary_amount + split_amount;

        let tp = token_program_id();
        let source_ata = derive_ata(&sender, &mint, &tp);
        let dest_ata = derive_ata(&recipient, &mint, &tp);
        let split_dest_ata = derive_ata(&split_recipient, &mint, &tp);

        let tx = dummy_tx(
            vec![
                spl_transfer_checked_ix(&source_ata, &mint, &dest_ata, &sender, primary_amount, 6),
                spl_transfer_checked_ix(
                    &source_ata,
                    &mint,
                    &split_dest_ata,
                    &sender,
                    split_amount,
                    6,
                ),
            ],
            &sender,
        );
        let request = charge_request(total, "USDC", &recipient);
        let method_details = MethodDetails {
            splits: Some(vec![Split {
                recipient: split_recipient.to_string(),
                amount: split_amount.to_string(),
                ata_creation_required: None,
                label: None,
                memo: None,
            }]),
            ..Default::default()
        };

        assert!(verify_transaction_pre_broadcast(&tx, &request, &method_details).is_ok());
    }

    #[test]
    fn spl_transfer_with_split_memo_passes_pre_broadcast() {
        let sender = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        let split_recipient = Pubkey::new_unique();
        let mint = Pubkey::from_str("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v").unwrap();
        let primary_amount = 800_000u64;
        let split_amount = 200_000u64;
        let total = primary_amount + split_amount;

        let tp = token_program_id();
        let source_ata = derive_ata(&sender, &mint, &tp);
        let dest_ata = derive_ata(&recipient, &mint, &tp);
        let split_dest_ata = derive_ata(&split_recipient, &mint, &tp);

        let tx = dummy_tx(
            vec![
                spl_transfer_checked_ix(&source_ata, &mint, &dest_ata, &sender, primary_amount, 6),
                spl_transfer_checked_ix(
                    &source_ata,
                    &mint,
                    &split_dest_ata,
                    &sender,
                    split_amount,
                    6,
                ),
                memo_ix("platform fee"),
            ],
            &sender,
        );
        let request = charge_request(total, "USDC", &recipient);
        let method_details = MethodDetails {
            splits: Some(vec![Split {
                recipient: split_recipient.to_string(),
                amount: split_amount.to_string(),
                ata_creation_required: None,
                label: None,
                memo: Some("platform fee".to_string()),
            }]),
            ..Default::default()
        };

        assert!(verify_transaction_pre_broadcast(&tx, &request, &method_details).is_ok());
    }

    #[test]
    fn spl_transfer_missing_split_memo_rejected_pre_broadcast() {
        let sender = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        let split_recipient = Pubkey::new_unique();
        let mint = Pubkey::from_str("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v").unwrap();
        let primary_amount = 800_000u64;
        let split_amount = 200_000u64;
        let total = primary_amount + split_amount;

        let tp = token_program_id();
        let source_ata = derive_ata(&sender, &mint, &tp);
        let dest_ata = derive_ata(&recipient, &mint, &tp);
        let split_dest_ata = derive_ata(&split_recipient, &mint, &tp);

        let tx = dummy_tx(
            vec![
                spl_transfer_checked_ix(&source_ata, &mint, &dest_ata, &sender, primary_amount, 6),
                spl_transfer_checked_ix(
                    &source_ata,
                    &mint,
                    &split_dest_ata,
                    &sender,
                    split_amount,
                    6,
                ),
            ],
            &sender,
        );
        let request = charge_request(total, "USDC", &recipient);
        let method_details = MethodDetails {
            splits: Some(vec![Split {
                recipient: split_recipient.to_string(),
                amount: split_amount.to_string(),
                ata_creation_required: None,
                label: None,
                memo: Some("platform fee".to_string()),
            }]),
            ..Default::default()
        };

        let err = verify_transaction_pre_broadcast(&tx, &request, &method_details).unwrap_err();
        assert!(err.message.contains("No memo instruction found"));
    }

    // ── ChargeOptions fee_payer flag in method details ──

    #[test]
    fn charge_with_fee_payer_includes_method_details() {
        let mpp = Mpp::new(Config {
            recipient: TEST_RECIPIENT.to_string(),
            challenge_binding_secret: Some(TEST_SECRET.to_string()),
            fee_payer: true,
            network: "devnet".to_string(),
            ..Default::default()
        })
        .unwrap();
        let challenge = mpp.charge("1.00").unwrap();
        let request: ChargeRequest = challenge.request.decode().unwrap();

        let details: MethodDetails =
            serde_json::from_value(request.method_details.unwrap()).unwrap();
        assert_eq!(details.fee_payer, Some(true));
    }

    #[test]
    fn charge_options_fee_payer_flag() {
        let mpp = test_mpp();
        let challenge = mpp
            .charge_with_options(
                "1.00",
                ChargeOptions {
                    fee_payer: true,
                    ..Default::default()
                },
            )
            .unwrap();
        let request: ChargeRequest = challenge.request.decode().unwrap();
        let details: MethodDetails =
            serde_json::from_value(request.method_details.unwrap()).unwrap();
        assert_eq!(details.fee_payer, Some(true));
    }

    #[test]
    fn charge_with_split_ata_creation_includes_method_details() {
        let split_recipient = Pubkey::new_unique();
        let mpp = Mpp::new(Config {
            recipient: TEST_RECIPIENT.to_string(),
            challenge_binding_secret: Some(TEST_SECRET.to_string()),
            currency: crate::protocol::solana::mints::USDC_DEVNET.to_string(),
            fee_payer: true,
            fee_payer_signer: Some(test_fee_payer_signer()),
            network: "devnet".to_string(),
            ..Default::default()
        })
        .unwrap();
        let challenge = mpp
            .charge_with_options(
                "1.00",
                ChargeOptions {
                    splits: vec![Split {
                        recipient: split_recipient.to_string(),
                        amount: "50000".to_string(),
                        ata_creation_required: Some(true),
                        label: None,
                        memo: None,
                    }],
                    ..Default::default()
                },
            )
            .unwrap();
        let request: ChargeRequest = challenge.request.decode().unwrap();
        let details: MethodDetails =
            serde_json::from_value(request.method_details.unwrap()).unwrap();

        assert_eq!(
            request.currency,
            crate::protocol::solana::mints::USDC_DEVNET
        );
        assert_eq!(details.fee_payer, Some(true));
        assert!(details.fee_payer_key.is_some());
        let splits = details.splits.unwrap();
        assert_eq!(splits.len(), 1);
        assert_eq!(splits[0].ata_creation_required, Some(true));
    }

    #[test]
    fn charge_variants_with_options_returns_single_challenge() {
        let split_recipient = Pubkey::new_unique();
        let mpp = Mpp::new(Config {
            recipient: TEST_RECIPIENT.to_string(),
            challenge_binding_secret: Some(TEST_SECRET.to_string()),
            currency: crate::protocol::solana::mints::USDC_DEVNET.to_string(),
            fee_payer: true,
            fee_payer_signer: Some(test_fee_payer_signer()),
            network: "devnet".to_string(),
            ..Default::default()
        })
        .unwrap();
        let challenges = mpp
            .charge_variants_with_options(
                "1.00",
                ChargeOptions {
                    splits: vec![Split {
                        recipient: split_recipient.to_string(),
                        amount: "50000".to_string(),
                        ata_creation_required: Some(true),
                        label: None,
                        memo: None,
                    }],
                    ..Default::default()
                },
            )
            .unwrap();

        assert_eq!(challenges.len(), 1);
    }

    #[test]
    fn charge_with_split_ata_creation_rejects_symbol_currency() {
        let split_recipient = Pubkey::new_unique();
        let mpp = Mpp::new(Config {
            recipient: TEST_RECIPIENT.to_string(),
            challenge_binding_secret: Some(TEST_SECRET.to_string()),
            currency: "USDC".to_string(),
            fee_payer: true,
            fee_payer_signer: Some(test_fee_payer_signer()),
            network: "devnet".to_string(),
            ..Default::default()
        })
        .unwrap();

        let err = mpp
            .charge_with_options(
                "1.00",
                ChargeOptions {
                    splits: vec![Split {
                        recipient: split_recipient.to_string(),
                        amount: "50000".to_string(),
                        ata_creation_required: Some(true),
                        label: None,
                        memo: None,
                    }],
                    ..Default::default()
                },
            )
            .unwrap_err();
        assert!(err.to_string().contains("mint address"));
    }

    // ── Method details include network and decimals ──

    #[test]
    fn charge_method_details_contain_network_and_decimals() {
        let mpp = test_mpp();
        let challenge = mpp.charge("1.00").unwrap();
        let request: ChargeRequest = challenge.request.decode().unwrap();
        let details = request.method_details.unwrap();
        assert_eq!(details["network"], "devnet");
        assert_eq!(details["decimals"], 6);
    }
}
