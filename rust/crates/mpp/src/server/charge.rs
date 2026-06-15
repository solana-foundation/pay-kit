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
//! // Verify a credential from Authorization header. The expected ChargeRequest
//! // pins the route's amount/currency/recipient so a credential paid for one
//! // route can't be replayed against another (audit #2).
//! let credential = solana_mpp::PaymentCredential::from_header(&auth_header)?;
//! let expected = solana_mpp::ChargeRequest {
//!     amount: "100000".to_string(),
//!     currency: "USDC".to_string(),
//!     recipient: Some("...".to_string()),
//!     ..Default::default()
//! };
//! let receipt = mpp.verify_credential_with_expected(&credential, &expected).await?;
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
use crate::protocol::solana::{
    default_rpc_url, programs, CredentialPayload, MethodDetails, Split, MAX_MEMO_BYTES,
};
use crate::store::{MemoryStore, Store};

const SECRET_KEY_ENV_VAR: &str = "MPP_SECRET_KEY";
const METHOD_NAME: &str = "solana";
const COMPUTE_BUDGET_PROGRAM: &str = "ComputeBudget111111111111111111111111111111";
const MAX_COMPUTE_UNIT_LIMIT: u32 = 200_000;
const MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS: u64 = 5_000_000;
/// Tighter price cap applied when the *server* is the fee payer.
///
/// In fee-sponsored pull mode the server signs the transaction before it is
/// broadcast, so the priority fee is paid out of the merchant's wallet. The
/// global cap above (5_000_000) is fine when the client pays its own gas,
/// but at that ceiling an attacker could burn `ceil(5_000_000 * 200_000 /
/// 1_000_000)` = 1_000_000 lamports of merchant SOL per "valid" charge.
/// 10_000 caps the worst case at ~2_000 lamports per request — about 20% of
/// the 5_000-lamport base fee per signature, which leaves enough headroom
/// for honest clients to bump priority during congestion without letting
/// the merchant be drained.
const MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS_FEE_SPONSORED: u64 = 10_000;
const SIMULATION_MAX_ATTEMPTS: usize = 3;
const SIMULATION_RETRY_DELAY_MS: u64 = 400;

/// Audit #15: derive a per-app default realm from the recipient pubkey.
///
/// `realm` is part of the HMAC ID input. With a fixed default of
/// `"MPP Payment"`, two services that shared `MPP_SECRET_KEY` and both
/// kept the default would participate in one shared credential namespace,
/// enabling cross-service credential replay. Deriving from `recipient`
/// (a Solana pubkey, unique per merchant) means two services with the
/// same secret but different recipients automatically get different
/// realms, so cross-service replay fails at HMAC verification.
///
/// Format: `"App Id - #<8-digit decimal>"`. Decimal is `u32::from_be_bytes`
/// over the first 4 bytes of `SHA-256(recipient)`, modulo 10^8 for a
/// compact display. Deterministic for a given recipient.
fn derive_default_realm(recipient: &str) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(recipient.as_bytes());
    let first_four = u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]]);
    let app_id = first_four % 100_000_000;
    format!("App Id - #{app_id}")
}

/// Minimum length, in bytes, for the HMAC-SHA256 key used to bind
/// challenge IDs. NIST SP 800-107 recommends a key at least as long as
/// the hash output (256 bits = 32 bytes); below that the key is the
/// weakest link, not the hash.
const MIN_SECRET_KEY_BYTES: usize = 32;

fn detect_challenge_binding_secret() -> Result<String, Error> {
    std::env::var(SECRET_KEY_ENV_VAR).map_err(|_| {
        Error::InvalidConfig(format!(
            "Missing {SECRET_KEY_ENV_VAR} env var. Set it or pass challenge_binding_secret explicitly."
        ))
    })
}

/// Reject empty / short challenge-binding secrets before they are used as
/// the HMAC key for challenge IDs. Audit #24: a weak key lets an attacker
/// forge challenges. We require at least `MIN_SECRET_KEY_BYTES` bytes of
/// input; callers SHOULD pass ≥32 bytes of cryptographically-random data
/// (e.g. `openssl rand -base64 32`).
fn validate_challenge_binding_secret(secret: &str) -> Result<(), Error> {
    if secret.len() < MIN_SECRET_KEY_BYTES {
        return Err(Error::InvalidConfig(format!(
            "Secret key is too short ({} bytes): require at least {MIN_SECRET_KEY_BYTES} bytes \
             of cryptographically-random data (e.g. `openssl rand -base64 32`)",
            secret.len()
        )));
    }
    Ok(())
}

// Audit #37: this used to be a private duplicate of the same function
// in `protocol/solana.rs`. Consolidated — callers in this file now use
// the public one via `crate::protocol::solana::default_rpc_url`.

/// Resolve the SPL token program governing `currency`, once, at server
/// boot. Returns `None` for native SOL. For well-known stablecoins the
/// answer comes from the static table; for an arbitrary mint address the
/// owner is fetched on-chain and validated, per spec §7.2 (rather than
/// silently falling back to the legacy Token Program).
fn resolve_server_token_program(
    rpc: &RpcClient,
    currency: &str,
    network: Option<&str>,
) -> Result<Option<&'static str>, Error> {
    if currency.eq_ignore_ascii_case("SOL") {
        return Ok(None);
    }

    if let Some(mint) = crate::protocol::solana::resolve_stablecoin_mint(currency, network) {
        if crate::protocol::solana::is_known_stablecoin_mint(mint) {
            return Ok(Some(
                crate::protocol::solana::default_token_program_for_currency(currency, network),
            ));
        }
    }

    let mint_pk = Pubkey::from_str(currency).map_err(|e| {
        Error::InvalidConfig(format!(
            "Currency {currency} is neither a known symbol nor a valid mint address: {e}"
        ))
    })?;
    let account = rpc.get_account(&mint_pk).map_err(|e| {
        Error::InvalidConfig(format!(
            "Failed to fetch mint account for currency {currency}: {e}"
        ))
    })?;
    let owner = account.owner.to_string();
    match owner.as_str() {
        programs::TOKEN_PROGRAM => Ok(Some(programs::TOKEN_PROGRAM)),
        programs::TOKEN_2022_PROGRAM => Ok(Some(programs::TOKEN_2022_PROGRAM)),
        _ => Err(Error::InvalidConfig(format!(
            "Mint {currency} is owned by unsupported program {owner}; expected the Token or Token-2022 program"
        ))),
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
    /// Solana network: one of "mainnet", "devnet", "localnet" (spec §7.2).
    /// Validated at `Mpp::new` time. "mainnet-beta" is the RPC hostname,
    /// not a canonical slug.
    pub network: String,
    /// RPC URL (overrides default for the network).
    pub rpc_url: Option<String>,
    /// Server challenge-binding secret for HMAC-SHA256 challenge IDs.
    ///
    /// MUST be at least 32 bytes of cryptographically-random data. Generate
    /// with e.g. `openssl rand -base64 32`. Short or low-entropy keys are
    /// rejected at `Mpp::new` time. If `None`, the value is read from the
    /// `MPP_SECRET_KEY` environment variable.
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
    /// Audit #5: accept push-mode (`type=signature`) credentials.
    ///
    /// Push mode matches credentials to challenges by *shape* (recipient,
    /// amount, currency, splits) — the on-chain tx is not bound to a
    /// specific challenge id. Per spec §13.5 this is the accepted base
    /// flow ("first accepted presentation wins"), but the lack of
    /// cryptographic binding means any matching-shape transaction can
    /// claim any matching-shape challenge. Routes that don't need push
    /// mode should leave this off (default).
    ///
    /// Audit B34 already rejects push mode on fee-sponsored routes; this
    /// gate runs first and covers the non-fee-sponsored case the audit
    /// flagged.
    pub accept_push_mode: bool,
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
            accept_push_mode: false,
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
    /// Token program governing `currency`. `None` for native SOL. Resolved
    /// once at `Mpp::new` time — either from the hardcoded stablecoin table
    /// or via an on-chain mint-owner lookup for arbitrary mint addresses
    /// (spec §7.2). Reused at challenge generation and at verification so
    /// the two sides stay in lockstep.
    token_program: Option<&'static str>,
    recipient: String,
    decimals: u32,
    network: String,
    fee_payer: bool,
    fee_payer_signer: Option<Arc<dyn solana_keychain::SolanaSigner>>,
    store: Arc<dyn Store>,
    html: bool,
    /// Audit #5: opt-in for push-mode credentials.
    accept_push_mode: bool,
}

impl Mpp {
    /// Create a new payment handler from config.
    pub fn new(config: Config) -> Result<Self, Error> {
        if config.recipient.is_empty() {
            return Err(Error::InvalidConfig("recipient is required".into()));
        }
        Pubkey::from_str(&config.recipient)
            .map_err(|e| Error::InvalidConfig(format!("Invalid recipient pubkey: {e}")))?;

        // Audit #16: spec §7.2 requires `feePayerKey` when `feePayer` is
        // true. Reject the boot-time misconfig at the source so
        // `charge_with_options` can never emit a spec-violating challenge.
        if config.fee_payer && config.fee_payer_signer.is_none() {
            return Err(Error::InvalidConfig(
                "Config.fee_payer is true but fee_payer_signer is None (spec §7.2 requires feePayerKey)".into(),
            ));
        }

        // Audit #37: spec §7.2 allows only `mainnet`, `devnet`, `localnet`.
        // Rejecting `mainnet-beta`/`testnet`/typos at boot keeps the wire
        // format canonical and stops the silent "everything unknown
        // defaults to mainnet" behaviour that used to live in default_rpc_url.
        crate::protocol::solana::validate_network(&config.network)?;

        let rpc_url = config
            .rpc_url
            .unwrap_or_else(|| default_rpc_url(&config.network).to_string());
        let challenge_binding_secret = config
            .challenge_binding_secret
            .map_or_else(detect_challenge_binding_secret, Ok)?;
        validate_challenge_binding_secret(&challenge_binding_secret)?;
        let realm = match config.realm {
            Some(r) if r.is_empty() => {
                return Err(Error::InvalidConfig(
                    "Config.realm must be non-empty when provided".into(),
                ));
            }
            Some(r) => r,
            None => derive_default_realm(&config.recipient),
        };
        let store: Arc<dyn Store> = config.store.unwrap_or_else(|| Arc::new(MemoryStore::new()));

        let rpc = Arc::new(RpcClient::new(rpc_url.clone()));
        let token_program =
            resolve_server_token_program(&rpc, &config.currency, Some(&config.network))?;

        Ok(Mpp {
            rpc,
            rpc_url,
            realm,
            challenge_binding_secret,
            currency: config.currency,
            token_program,
            recipient: config.recipient,
            decimals: config.decimals as u32,
            network: config.network,
            fee_payer: config.fee_payer,
            fee_payer_signer: config.fee_payer_signer,
            store,
            html: config.html,
            accept_push_mode: config.accept_push_mode,
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

    /// Verify a payment credential against a route priced at `amount`.
    ///
    /// Convenience wrapper for the common "gate this route at `amount`" flow:
    /// it parses the `Authorization: Payment` header value, rebuilds this
    /// route's expected request from `amount` (via [`charge`](Self::charge)),
    /// and verifies the credential against it with
    /// [`verify_credential_with_expected`](Self::verify_credential_with_expected).
    /// Because the expected request is rebuilt from `amount`, a credential
    /// issued for a different price on the same server is rejected — this is the
    /// cross-route replay protection the axum helpers ([`paid_get`]) rely on.
    ///
    /// [`paid_get`]: crate::server::axum::paid_get
    pub async fn verify_payment_for_amount(
        &self,
        credential_str: &str,
        amount: &str,
    ) -> Result<Receipt, VerificationError> {
        let credential = crate::protocol::core::headers::parse_authorization(credential_str)
            .map_err(|e| VerificationError::new(format!("Failed to parse Authorization: {e}")))?;
        let challenge = self
            .charge(amount)
            .map_err(|e| VerificationError::new(format!("Failed to build route challenge: {e}")))?;
        let expected: ChargeRequest = challenge.request.decode().map_err(|e| {
            VerificationError::new(format!("Failed to decode expected request: {e}"))
        })?;
        self.verify_credential_with_expected(&credential, &expected)
            .await
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
        // For arbitrary mints this was resolved on-chain at Mpp::new time and
        // cached on the struct — never guessed from the currency string.
        if let Some(token_program) = self.token_program {
            details.insert("tokenProgram".into(), serde_json::json!(token_program));
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
        // Audit #16: per-call fee-payer override is only honorable when a
        // signer is configured on this server. Mpp::new already enforces
        // the invariant for `self.fee_payer`; this catches the override
        // case where Config.fee_payer is false but ChargeOptions.fee_payer
        // is true.
        if options.fee_payer && self.fee_payer_signer.is_none() {
            return Err(Error::InvalidConfig(
                "ChargeOptions.fee_payer is true but this server has no fee_payer_signer configured".into(),
            ));
        }

        // Audit #21: validate the splits up-front so malformed entries
        // (bad pubkey, unparseable/zero amount, overflowing aggregate,
        // duplicate recipients, too many splits) fail at challenge issuance
        // instead of at on-chain settlement.
        crate::protocol::solana::validate_splits(&options.splits)?;

        // Audit #38: spec §9.5 forbids fee-payer-funded ATA creation for the
        // top-level recipient. A split that names the primary recipient AND
        // sets `ataCreationRequired: true` is the misconfig shape that, in
        // fee-sponsored mode, lets the recipient close/recreate its own ATA
        // to keep draining server-funded rent. We still allow the primary
        // recipient to appear in splits without the flag (legitimate when
        // the merchant takes part of the funds as a regular split).
        for (idx, split) in options.splits.iter().enumerate() {
            if split.ata_creation_required == Some(true) && split.recipient == self.recipient {
                return Err(Error::InvalidConfig(format!(
                    "splits[{idx}]: ataCreationRequired must not be true for the top-level recipient"
                )));
            }
        }

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
    ///
    /// The override-point on the high-level `charge_with_options` path:
    /// the caller supplies a fully-formed `ChargeRequest` and we issue a
    /// challenge against *this* server's route. Audit #19: the request
    /// is validated for internal consistency AND against the server's
    /// own configuration before HMAC-signing, so a malformed or
    /// off-route request cannot produce a cryptographically-valid
    /// challenge. Callers who need to issue challenges for an unrelated
    /// route should construct a `PaymentChallenge` directly via
    /// `PaymentChallenge::with_secret_key_full`.
    pub fn charge_challenge_with_options(
        &self,
        request: &ChargeRequest,
        expires: Option<&str>,
        description: Option<&str>,
    ) -> Result<PaymentChallenge, Error> {
        self.validate_charge_request(request)?;
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

    /// Audit #19: ensure a caller-built `ChargeRequest` parses and binds
    /// to this server's route before we HMAC-sign it. Fields covered:
    /// `amount`, `currency`, `recipient`, and the `methodDetails`
    /// fragments that pin the server-side configuration
    /// (`network`, `decimals`, `tokenProgram`, splits).
    fn validate_charge_request(&self, request: &ChargeRequest) -> Result<(), Error> {
        request.parse_amount()?;

        if !request.currency.eq_ignore_ascii_case(&self.currency) {
            return Err(Error::InvalidConfig(format!(
                "ChargeRequest.currency `{}` does not match server-configured currency `{}`",
                request.currency, self.currency
            )));
        }

        let recipient = request
            .recipient
            .as_deref()
            .ok_or_else(|| Error::InvalidConfig("ChargeRequest.recipient is required".into()))?;
        Pubkey::from_str(recipient)
            .map_err(|e| Error::InvalidConfig(format!("Invalid recipient pubkey: {e}")))?;

        if let Some(md_value) = &request.method_details {
            let md: MethodDetails = serde_json::from_value(md_value.clone())
                .map_err(|e| Error::InvalidConfig(format!("Invalid methodDetails: {e}")))?;

            if let Some(network) = md.network.as_deref() {
                if network != self.network {
                    return Err(Error::InvalidConfig(format!(
                        "methodDetails.network `{network}` does not match server-configured network `{}`",
                        self.network
                    )));
                }
            }

            if let Some(decimals) = md.decimals {
                if u32::from(decimals) != self.decimals {
                    return Err(Error::InvalidConfig(format!(
                        "methodDetails.decimals {decimals} does not match server-configured decimals {}",
                        self.decimals
                    )));
                }
            }

            if let Some(tp) = md.token_program.as_deref() {
                if Some(tp) != self.token_program {
                    return Err(Error::InvalidConfig(format!(
                        "methodDetails.tokenProgram `{tp}` does not match server-resolved token program {:?}",
                        self.token_program
                    )));
                }
            }

            // Audit #21: shared split validation with the
            // `charge_with_options` path. Failure modes (bad pubkey,
            // unparseable/zero amount, overflowing aggregate, duplicate
            // recipients, too many splits) all surface here.
            if let Some(splits) = md.splits.as_deref() {
                crate::protocol::solana::validate_splits(splits)?;
            }
        }

        Ok(())
    }

    // ── Verification ──

    /// Verify a payment credential against the expected charge for *this*
    /// route. This is the canonical entry point for credential verification.
    ///
    /// **Audit #2 — why no simpler "trust the echoed challenge" variant.**
    /// We deliberately do not offer a method that decodes the credential's
    /// embedded request and verifies against *that*. A server that issues
    /// multiple priced routes (the common case) would otherwise accept a
    /// credential paid for the $1 route against the $100 route — same
    /// currency, same recipient, same server-issued HMAC, but the wrong
    /// resource. Callers must pass an `expected` `ChargeRequest` built
    /// from this route's static configuration, so the amount and other
    /// payment-constraining fields are pinned at the call site.
    ///
    /// Single-resource servers construct the same `expected` once and reuse
    /// it; the boilerplate is small. The compile-time cost of the explicit
    /// argument is the whole point.
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

        compare_expected_to_request(&request, expected)?;

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
    /// pinned `Mpp` configuration. Defense-in-depth against a route that
    /// hands `verify` a request decoded from a tampered credential: fields
    /// fixed at server construction (method, intent, realm, currency,
    /// recipient) cannot silently diverge.
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
        // Audit #41: the HMAC id comparison must be constant-time —
        // otherwise a timing oracle could leak how many leading bytes
        // of an attacker-controlled `id` match an actually-issued one.
        // The same helper backs `PaymentChallenge::verify`.
        if !crate::protocol::core::challenge::constant_time_eq(
            &credential.challenge.id,
            &expected_id,
        ) {
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

        // Audit #22: HMAC authenticates `credential.challenge.request` — the
        // request the server originally issued. Settlement then runs against
        // the caller-supplied `request`. Without binding the two, a direct
        // caller could authenticate one request and verify settlement
        // against a different one. Require equality on every
        // payment-constraining field (reuses the audit #1 helper).
        let credential_request: ChargeRequest =
            credential.challenge.request.decode().map_err(|e| {
                VerificationError::invalid_payload(format!(
                    "Failed to decode credential request: {e}"
                ))
            })?;
        compare_expected_to_request(&credential_request, request)?;

        // Tier 2: Pinned-field backstop. Runs unconditionally so callers of
        // the lower-level `verify` are protected against cross-route replay
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
                // Audit #5: push-mode acceptance is opt-in. Spec §13.5 names
                // "first accepted presentation wins" as the model — any
                // matching-shape on-chain tx can claim any matching-shape
                // challenge. Servers that don't need push mode should leave
                // `accept_push_mode = false` (default) to reduce surface.
                if !self.accept_push_mode {
                    return Err(VerificationError::credential_mismatch(
                        "Push-mode credentials are disabled on this server (Config.accept_push_mode is false; spec §13.5)",
                    ));
                }
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

        // Audit #3: the polling RPC may be lagging or load-balanced behind an
        // endpoint that hasn't observed the signature yet, while the tx is
        // actually on-chain. Do one definitive status check before declaring
        // a timeout — otherwise we'd return network_error for a payment the
        // user has already made (the signature is reserved in the replay
        // store, so a retry would also fail).
        let final_status = self
            .rpc
            .get_signature_status(&signature)
            .map(|opt| opt.map(|inner| inner.map_err(|e| e.to_string())))
            .map_err(|e| e.to_string());
        let result = interpret_post_timeout_status(final_status);
        if result.is_ok() {
            tracing::info!(
                elapsed_ms = %t0.elapsed().as_millis(),
                step = "confirmed_via_status_recovery",
                "await_pull_confirmation"
            );
        }
        result
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
        let splits_total = crate::protocol::solana::checked_sum_split_amounts(splits)
            .ok_or_else(|| VerificationError::invalid_amount("Split amounts overflow u64"))?;
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
            let matched = verify_sol_transfers(
                &instructions,
                recipient,
                primary_amount,
                splits,
                expected_ata_payer,
            )?;
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
            // Audit #34: check the property we care about directly —
            // `request.currency` must parse as a Pubkey (i.e. be an actual
            // mint address, not a symbol). The previous "currency !=
            // expected_mint" check was equivalent in outcome but expressed
            // the intent obliquely.
            if !required_ata_owners.is_empty() && Pubkey::from_str(&request.currency).is_err() {
                return Err(VerificationError::invalid_payload(
                    "ataCreationRequired requires currency to be an SPL token mint address",
                ));
            }
            // Prefer the challenge's tokenProgram hint. If the credential
            // came from a challenge we didn't sign (or one missing the
            // hint), fall back to the boot-time resolution we did against
            // our own currency — never to a guess based on the currency
            // string (spec §7.2).
            let expected_token_program = method_details
                .token_program
                .as_deref()
                .or(self.token_program)
                .ok_or_else(|| {
                    VerificationError::invalid_payload(
                        "Missing tokenProgram and server has no resolved token program for this currency",
                    )
                })?;
            let mut matched = verify_spl_transfers(
                &instructions,
                recipient,
                &expected_mint.to_string(),
                primary_amount,
                splits,
                Some(expected_token_program),
                expected_ata_payer,
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
    if splits.len() > crate::protocol::solana::MAX_SPLITS {
        return Err(VerificationError::too_many_splits(format!(
            "Too many splits: {} (maximum {})",
            splits.len(),
            crate::protocol::solana::MAX_SPLITS,
        )));
    }

    let total_amount: u64 = request.amount.parse().map_err(|_| {
        VerificationError::invalid_amount(format!("Invalid amount: {}", request.amount))
    })?;
    let splits_total = crate::protocol::solana::checked_sum_split_amounts(splits)
        .ok_or_else(|| VerificationError::invalid_amount("Split amounts overflow u64"))?;
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
        // Audit #34: see the matching block above — check that
        // `request.currency` parses as a Pubkey directly.
        if !ata_policy.required_owners.is_empty() && Pubkey::from_str(&request.currency).is_err() {
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

/// Audit #1: exhaustively compare the credential's decoded request against
/// the route's expected request before any settlement work.
///
/// Why up-front (when `verify_credential_with_expected` already passes
/// `expected` to `verify` and on-chain settlement checks against it):
/// 1. Earlier, clearer failure — `splits mismatch` beats `no matching SPL
///    transferChecked instruction` for an operator chasing a bug.
/// 2. Defense in depth — any field added to `ChargeRequest` or `MethodDetails`
///    in the future is forced into this comparison, so a divergence cannot
///    silently slip past the settlement layer.
///
/// `recent_blockhash` is deliberately *not* compared: it's per-challenge
/// state, not per-route policy, and an `expected` built from a route's
/// static config carries no blockhash.
fn compare_expected_to_request(
    request: &ChargeRequest,
    expected: &ChargeRequest,
) -> Result<(), VerificationError> {
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
    if request.external_id != expected.external_id {
        return Err(VerificationError::credential_mismatch(
            "externalId mismatch",
        ));
    }
    if request.description != expected.description {
        return Err(VerificationError::credential_mismatch(
            "description mismatch",
        ));
    }

    let request_md = parse_method_details_for_compare(&request.method_details, "credential")?;
    let expected_md = parse_method_details_for_compare(&expected.method_details, "expected")?;

    if request_md.network != expected_md.network {
        return Err(VerificationError::credential_mismatch(
            "methodDetails.network mismatch",
        ));
    }
    if request_md.decimals != expected_md.decimals {
        return Err(VerificationError::credential_mismatch(
            "methodDetails.decimals mismatch",
        ));
    }
    if request_md.token_program != expected_md.token_program {
        return Err(VerificationError::credential_mismatch(
            "methodDetails.tokenProgram mismatch",
        ));
    }
    if request_md.fee_payer != expected_md.fee_payer {
        return Err(VerificationError::credential_mismatch(
            "methodDetails.feePayer mismatch",
        ));
    }
    if request_md.fee_payer_key != expected_md.fee_payer_key {
        return Err(VerificationError::credential_mismatch(
            "methodDetails.feePayerKey mismatch",
        ));
    }
    // Splits compared element-wise (order-sensitive). A route that pins
    // `[A, B]` will reject a credential carrying `[B, A]`.
    if !splits_eq(request_md.splits.as_deref(), expected_md.splits.as_deref()) {
        return Err(VerificationError::credential_mismatch(
            "methodDetails.splits mismatch",
        ));
    }
    // recent_blockhash intentionally NOT compared — see helper docstring.

    Ok(())
}

fn parse_method_details_for_compare(
    md: &Option<serde_json::Value>,
    label: &str,
) -> Result<MethodDetails, VerificationError> {
    match md {
        Some(v) => serde_json::from_value(v.clone()).map_err(|e| {
            VerificationError::credential_mismatch(format!("Invalid {label} methodDetails: {e}"))
        }),
        None => Ok(MethodDetails::default()),
    }
}

fn splits_eq(a: Option<&[Split]>, b: Option<&[Split]>) -> bool {
    let a = a.unwrap_or(&[]);
    let b = b.unwrap_or(&[]);
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b.iter()).all(|(x, y)| {
        x.recipient == y.recipient
            && x.amount == y.amount
            && x.ata_creation_required == y.ata_creation_required
            && x.label == y.label
            && x.memo == y.memo
    })
}

/// Audit #3: interpret a post-timeout `get_signature_status` result.
///
/// Pulled out as a pure function so the four cases — landed, landed-but-failed,
/// not-found, RPC-error — can be unit-tested without needing a live RPC.
/// Errors are stringified at the call site so this helper stays free of
/// `solana-rpc-client` types.
fn interpret_post_timeout_status(
    status: Result<Option<Result<(), String>>, String>,
) -> Result<(), VerificationError> {
    match status {
        Ok(Some(Ok(()))) => Ok(()),
        Ok(Some(Err(on_chain_err))) => Err(VerificationError::transaction_failed(format!(
            "Transaction landed on-chain but failed: {on_chain_err}"
        ))),
        Ok(None) => Err(VerificationError::network_error(
            "Transaction not confirmed within timeout".to_string(),
        )),
        Err(rpc_err) => Err(VerificationError::network_error(format!(
            "Transaction not confirmed within timeout; final status check failed: {rpc_err}"
        ))),
    }
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
            validate_compute_budget_instruction(ix, fee_payer.is_some())?;
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

fn validate_compute_budget_instruction(
    ix: &CompiledInstruction,
    fee_sponsored: bool,
) -> Result<(), VerificationError> {
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
            let max = if fee_sponsored {
                MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS_FEE_SPONSORED
            } else {
                MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS
            };
            if price > max {
                return Err(VerificationError::invalid_payload(format!(
                    "Compute unit price {price} exceeds maximum {max}"
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
        if expected_data.len() > MAX_MEMO_BYTES {
            return Err(VerificationError::invalid_payload(format!(
                "memo cannot exceed {MAX_MEMO_BYTES} bytes"
            )));
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
    fee_payer: Option<&str>,
) -> Result<HashSet<usize>, VerificationError> {
    let mut matched_instruction_indexes = HashSet::new();
    find_sol_transfer(
        instructions,
        recipient,
        primary_amount,
        fee_payer,
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
            fee_payer,
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
    fee_payer: Option<&str>,
    matched_instruction_indexes: &mut HashSet<usize>,
) -> Result<(), VerificationError> {
    for (index, ix) in instructions.iter().enumerate() {
        if matched_instruction_indexes.contains(&index) {
            continue;
        }
        if parsed_program_id(ix) != Some(programs::SYSTEM_PROGRAM) {
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
                let source = info.get("source").and_then(|s| s.as_str()).unwrap_or("");
                let lamports = info.get("lamports").and_then(|l| l.as_u64()).unwrap_or(0);
                if dest == recipient && lamports == amount {
                    if fee_payer.is_some_and(|fp| source == fp) {
                        return Err(VerificationError::invalid_payload(
                            "Fee payer cannot fund the SOL payment transfer",
                        ));
                    }
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
    fee_payer: Option<&str>,
) -> Result<HashSet<usize>, VerificationError> {
    let mut matched_instruction_indexes = HashSet::new();
    find_spl_transfer(
        instructions,
        recipient,
        mint,
        primary_amount,
        expected_token_program,
        fee_payer,
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
            fee_payer,
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
    fee_payer: Option<&str>,
    matched_instruction_indexes: &mut HashSet<usize>,
) -> Result<(), VerificationError> {
    let ata_program = Pubkey::from_str(programs::ASSOCIATED_TOKEN_PROGRAM).unwrap();
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
                    let source = info.get("source").and_then(|s| s.as_str()).unwrap_or("");
                    let authority = info.get("authority").and_then(|a| a.as_str()).unwrap_or("");
                    let mint = info.get("mint").and_then(|m| m.as_str()).unwrap_or("");
                    if mint == expected_mint && verify_ata_owner(dest, recipient, mint, program) {
                        if let Some(fee_payer) = fee_payer {
                            if authority == fee_payer {
                                return Err(VerificationError::invalid_payload(
                                    "Fee payer cannot authorize the SPL payment transfer",
                                ));
                            }
                            if let (Ok(fee_payer_pk), Ok(mint_pk), Ok(program_pk)) = (
                                Pubkey::from_str(fee_payer),
                                Pubkey::from_str(mint),
                                Pubkey::from_str(program),
                            ) {
                                let (fee_payer_ata, _) = Pubkey::find_program_address(
                                    &[fee_payer_pk.as_ref(), program_pk.as_ref(), mint_pk.as_ref()],
                                    &ata_program,
                                );
                                if source == fee_payer_ata.to_string() {
                                    return Err(VerificationError::invalid_payload(
                                        "Fee payer token account cannot fund the SPL payment transfer",
                                    ));
                                }
                            }
                        }
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
        if memo.len() > MAX_MEMO_BYTES {
            return Err(VerificationError::invalid_payload(format!(
                "memo cannot exceed {MAX_MEMO_BYTES} bytes"
            )));
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
/// Audit #8: convert a base-unit amount to a UI amount for diagnostic
/// rendering. Returns `None` when `10u64.pow(decimals)` would overflow,
/// so the caller can omit that diagnostic line instead of panicking
/// (debug) or wrapping silently (release) — `diagnose_balances` only
/// runs after settlement already failed and is best-effort.
fn to_ui_amount(amount_base_units: u64, decimals: u8) -> Option<f64> {
    let divisor = 10u64.checked_pow(decimals as u32)?;
    Some(amount_base_units as f64 / divisor as f64)
}

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
    // Audit #13: derive the ATA against the actual token program for this
    // currency, not a hardcoded TOKEN_PROGRAM. For Token-2022 mints (PYUSD,
    // USDG on Token-2022, CASH, …) the legacy program produces the wrong
    // ATA, so the diagnostic would silently lie about the payer's balance.
    // The token program was already resolved at boot (audit #28) and
    // embedded in `methodDetails.tokenProgram` for every SPL challenge this
    // server issues; we just use it. If it's missing (lower-level
    // ChargeRequest construction edge case), skip the token-balance hint —
    // the fee-payer SOL diagnostic below still runs.
    let token_program = method_details
        .token_program
        .as_deref()
        .and_then(|s| Pubkey::from_str(s).ok());

    if let (Some(payer), Some(token_program)) = (payer_pk, token_program.as_ref()) {
        if request.currency.to_uppercase() != "SOL" {
            if let Ok(mint) =
                resolve_expected_mint(&request.currency, method_details.network.as_deref())
            {
                let ata_program = Pubkey::from_str(programs::ASSOCIATED_TOKEN_PROGRAM).unwrap();
                let (ata, _) = Pubkey::find_program_address(
                    &[payer.as_ref(), token_program.as_ref(), mint.as_ref()],
                    &ata_program,
                );
                // Audit #42: spec mandates `decimals` on SPL challenges;
                // pretending 6 would silently lie. Skip the diagnostic
                // instead — fee-payer SOL hint below still runs.
                // Audit #8: skip the token-balance hint when the divisor
                // can't be represented — see `to_ui_amount` for the why.
                let needed_base = request.amount.parse::<u64>().unwrap_or(0);
                if let Some(needed) = method_details
                    .decimals
                    .and_then(|d| to_ui_amount(needed_base, d))
                {
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
        // Audit #11: title aligned to the function name. Code stays
        // `verification-failed` so callers grouping by code keep working.
        Self::with_code(
            msg,
            "verification-failed",
            "Invalid Amount",
            "tag:paymentauth.org,2024:verification-failed",
        )
    }

    pub fn invalid_recipient(msg: impl Into<String>) -> Self {
        // Audit #11: title aligned to the function name.
        Self::with_code(
            msg,
            "verification-failed",
            "Invalid Recipient",
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
        // Audit #11: title aligned to the function name. Code stays
        // `malformed-credential` (shared with `invalid_payload`).
        Self::with_code(
            msg,
            "malformed-credential",
            "Credential Mismatch",
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

    // ── Audit #8: to_ui_amount ──

    #[test]
    fn to_ui_amount_typical_decimals() {
        // 1 USDC = 1_000_000 base units with 6 decimals.
        let v = to_ui_amount(1_000_000, 6).unwrap();
        assert!((v - 1.0).abs() < 1e-9);
    }

    #[test]
    fn to_ui_amount_zero_decimals() {
        // No fractional rendering — divisor is 1.
        let v = to_ui_amount(42, 0).unwrap();
        assert!((v - 42.0).abs() < 1e-9);
    }

    #[test]
    fn to_ui_amount_returns_none_when_divisor_overflows_u64() {
        // 10^20 overflows u64. Helper must skip rather than panic.
        assert!(to_ui_amount(1, 20).is_none());
        assert!(to_ui_amount(0, 255).is_none());
    }

    #[test]
    fn to_ui_amount_safe_high_decimals_succeed() {
        // 10^19 fits in u64 (< 1.84e19); 10^20 doesn't.
        assert!(to_ui_amount(1, 19).is_some());
        assert!(to_ui_amount(1, 20).is_none());
    }

    // ── Audit #3: post-timeout status recovery ──

    #[test]
    fn interpret_post_timeout_status_landed_returns_ok() {
        // Polling timed out but the final status check shows the tx landed
        // successfully — recover and report success.
        assert!(interpret_post_timeout_status(Ok(Some(Ok(())))).is_ok());
    }

    #[test]
    fn interpret_post_timeout_status_landed_with_onchain_err_returns_failed() {
        // Tx landed on-chain but the runtime rejected it. This is a real
        // transaction failure, not a timeout — surface the on-chain error.
        let err = interpret_post_timeout_status(Ok(Some(Err("InsufficientFundsForFee".into()))))
            .err()
            .expect("on-chain failure should be reported");
        let msg = format!("{err}");
        assert!(
            msg.contains("landed on-chain but failed"),
            "unexpected error: {msg}"
        );
        assert!(
            msg.contains("InsufficientFundsForFee"),
            "expected on-chain error to be propagated: {msg}"
        );
    }

    #[test]
    fn interpret_post_timeout_status_not_found_returns_timeout() {
        // Final check confirms the tx is genuinely not on-chain — keep the
        // timeout error.
        let err = interpret_post_timeout_status(Ok(None))
            .err()
            .expect("not-found should still error");
        let msg = format!("{err}");
        assert!(
            msg.contains("not confirmed within timeout"),
            "unexpected error: {msg}"
        );
        // Must NOT claim landed-but-failed.
        assert!(!msg.contains("landed on-chain"), "wrong shape: {msg}");
    }

    #[test]
    fn interpret_post_timeout_status_rpc_error_returns_timeout_with_detail() {
        // The final status call itself failed (e.g. RPC unreachable). We
        // can't tell whether the tx landed, so we keep the timeout error
        // but include the RPC failure in the message for ops.
        let err = interpret_post_timeout_status(Err("connection refused".into()))
            .err()
            .expect("rpc failure should error");
        let msg = format!("{err}");
        assert!(
            msg.contains("not confirmed within timeout"),
            "unexpected error: {msg}"
        );
        assert!(
            msg.contains("final status check failed"),
            "expected detail about the status RPC failure: {msg}"
        );
        assert!(
            msg.contains("connection refused"),
            "expected underlying RPC error to be propagated: {msg}"
        );
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
    fn compute_unit_price_fee_sponsored_under_tight_cap_passes() {
        // Audit #25: in fee-sponsored mode the merchant pays the priority
        // fee, so we apply MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS_FEE_SPONSORED
        // instead of the general cap. A price right at the tight cap is
        // allowed.
        let fee_payer = Pubkey::new_unique();
        let sender = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        let amount = 500_000u64;

        let tx = dummy_tx(
            vec![
                compute_unit_price_ix(MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS_FEE_SPONSORED),
                system_transfer_ix(&sender, &recipient, amount),
            ],
            &fee_payer,
        );
        let request = charge_request(amount, "SOL", &recipient);
        let method_details = MethodDetails {
            fee_payer: Some(true),
            fee_payer_key: Some(fee_payer.to_string()),
            ..Default::default()
        };

        assert!(verify_transaction_pre_broadcast(&tx, &request, &method_details).is_ok());
    }

    #[test]
    fn compute_unit_price_fee_sponsored_above_tight_cap_rejected() {
        // Audit #25: a price between the tight fee-sponsored cap and the
        // general cap is what an attacker would use to drain the merchant.
        // Must be rejected before the server co-signs.
        let fee_payer = Pubkey::new_unique();
        let sender = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        let amount = 500_000u64;

        let tx = dummy_tx(
            vec![
                compute_unit_price_ix(MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS_FEE_SPONSORED + 1),
                system_transfer_ix(&sender, &recipient, amount),
            ],
            &fee_payer,
        );
        let request = charge_request(amount, "SOL", &recipient);
        let method_details = MethodDetails {
            fee_payer: Some(true),
            fee_payer_key: Some(fee_payer.to_string()),
            ..Default::default()
        };

        let err = verify_transaction_pre_broadcast(&tx, &request, &method_details).unwrap_err();
        assert!(err.message.contains("Compute unit price"));
    }

    #[test]
    fn compute_unit_price_client_paid_above_tight_cap_passes() {
        // The tight cap only applies when the server is the fee payer.
        // Without fee-sponsorship the client is paying their own gas, so
        // the general (5_000_000) cap still applies and a price just above
        // the tight cap must be accepted.
        let sender = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        let amount = 500_000u64;

        let tx = dummy_tx(
            vec![
                compute_unit_price_ix(MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS_FEE_SPONSORED + 1),
                system_transfer_ix(&sender, &recipient, amount),
            ],
            &sender,
        );
        let request = charge_request(amount, "SOL", &recipient);
        let method_details = MethodDetails::default();

        assert!(verify_transaction_pre_broadcast(&tx, &request, &method_details).is_ok());
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

    const TEST_SECRET: &str = "test-secret-key-for-unit-tests-with-32b-padding";
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
            challenge_binding_secret: Some(TEST_SECRET.to_string()),
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
            challenge_binding_secret: Some(TEST_SECRET.to_string()),
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
        unsafe {
            std::env::set_var(
                SECRET_KEY_ENV_VAR,
                "env-secret-key-long-enough-for-hmac-binding-32b",
            )
        };

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
    fn new_rejects_empty_secret_key() {
        // Audit #24: short keys weaken the HMAC binding.
        let err = Mpp::new(Config {
            recipient: TEST_RECIPIENT.to_string(),
            challenge_binding_secret: Some(String::new()),
            ..Default::default()
        })
        .err()
        .expect("should fail");
        assert!(
            err.to_string().contains("Secret key is too short"),
            "got: {err}"
        );
    }

    #[test]
    fn new_rejects_short_secret_key() {
        // Just below the 32-byte minimum.
        let short = "a".repeat(MIN_SECRET_KEY_BYTES - 1);
        let err = Mpp::new(Config {
            recipient: TEST_RECIPIENT.to_string(),
            challenge_binding_secret: Some(short),
            ..Default::default()
        })
        .err()
        .expect("should fail");
        assert!(
            err.to_string().contains("Secret key is too short"),
            "got: {err}"
        );
    }

    #[test]
    fn new_accepts_secret_key_at_minimum_length() {
        let exact = "a".repeat(MIN_SECRET_KEY_BYTES);
        let result = Mpp::new(Config {
            recipient: TEST_RECIPIENT.to_string(),
            challenge_binding_secret: Some(exact),
            ..Default::default()
        });
        assert!(result.is_ok());
    }

    #[test]
    fn new_rejects_short_env_secret_key() {
        // Env-var path must apply the same gate as the explicit-config path.
        let _guard = ENV_LOCK.lock().unwrap();
        let prev = std::env::var(SECRET_KEY_ENV_VAR).ok();
        unsafe { std::env::set_var(SECRET_KEY_ENV_VAR, "too-short") };

        let result = Mpp::new(Config {
            recipient: TEST_RECIPIENT.to_string(),
            challenge_binding_secret: None,
            ..Default::default()
        });

        if let Some(v) = prev {
            unsafe { std::env::set_var(SECRET_KEY_ENV_VAR, v) };
        } else {
            unsafe { std::env::remove_var(SECRET_KEY_ENV_VAR) };
        }

        let err = result.err().expect("should fail");
        assert!(
            err.to_string().contains("Secret key is too short"),
            "got: {err}"
        );
    }

    #[test]
    fn new_valid_config_succeeds() {
        let mpp = test_mpp();
        // Audit #15: default realm now derives from recipient.
        assert_eq!(mpp.realm(), derive_default_realm(TEST_RECIPIENT));
        assert_eq!(mpp.currency(), "USDC");
        assert_eq!(mpp.recipient(), TEST_RECIPIENT);
        assert_eq!(mpp.decimals(), 6);
    }

    #[test]
    fn new_custom_realm() {
        let mpp = Mpp::new(Config {
            recipient: TEST_RECIPIENT.to_string(),
            challenge_binding_secret: Some(TEST_SECRET.to_string()),
            realm: Some("Custom Realm".to_string()),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(mpp.realm(), "Custom Realm");
    }

    // ── Audit #15: derived default realm ──

    #[test]
    fn new_default_realm_format() {
        // The derived default looks like "App Id - #<digits>" (max 8).
        let realm = derive_default_realm(TEST_RECIPIENT);
        assert!(
            realm.starts_with("App Id - #"),
            "unexpected realm format: {realm}"
        );
        let digits = realm.trim_start_matches("App Id - #");
        assert!(digits.chars().all(|c| c.is_ascii_digit()), "got: {realm}");
        assert!(!digits.is_empty() && digits.len() <= 8, "got: {realm}");
    }

    #[test]
    fn new_default_realm_deterministic_for_same_recipient() {
        // Restart-safe: same recipient must always derive to the same realm,
        // otherwise in-flight challenges would fail to verify after a deploy.
        let a = derive_default_realm(TEST_RECIPIENT);
        let b = derive_default_realm(TEST_RECIPIENT);
        assert_eq!(a, b);
    }

    #[test]
    fn new_default_realm_differs_across_recipients() {
        // Two servers with shared secret but different recipients must end
        // up with different default realms — closes the audit threat shape
        // (shared MPP_SECRET_KEY + shared default realm == shared
        // credential namespace).
        let other = "8tNDNRkk3JG1WK9NSRwUjytkGwY6Jq6gqQwNFmKt3pkP";
        assert_ne!(
            derive_default_realm(TEST_RECIPIENT),
            derive_default_realm(other),
        );
    }

    #[test]
    fn new_rejects_empty_realm() {
        // Explicitly providing an empty realm bypasses the derivation —
        // reject so an operator can't reintroduce the audit threat with a
        // typo.
        let err = Mpp::new(Config {
            recipient: TEST_RECIPIENT.to_string(),
            challenge_binding_secret: Some(TEST_SECRET.to_string()),
            realm: Some(String::new()),
            ..Default::default()
        })
        .err()
        .expect("empty realm should be rejected");
        assert!(
            err.to_string().contains("realm must be non-empty"),
            "got: {err}"
        );
    }

    // ── Audit #37: network allowlist + mainnet canonicalization ──

    #[test]
    fn new_accepts_canonical_networks() {
        for net in ["mainnet", "devnet", "localnet"] {
            Mpp::new(Config {
                recipient: TEST_RECIPIENT.to_string(),
                challenge_binding_secret: Some(TEST_SECRET.to_string()),
                network: net.to_string(),
                ..Default::default()
            })
            .unwrap_or_else(|e| panic!("{net} should be accepted: {e}"));
        }
    }

    #[test]
    fn new_rejects_unknown_network() {
        let err = Mpp::new(Config {
            recipient: TEST_RECIPIENT.to_string(),
            challenge_binding_secret: Some(TEST_SECRET.to_string()),
            network: "testnet".to_string(),
            ..Default::default()
        })
        .err()
        .expect("testnet should be rejected");
        assert!(err.to_string().contains("Unknown network"), "got: {err}");
    }

    #[test]
    fn new_rejects_empty_network() {
        let err = Mpp::new(Config {
            recipient: TEST_RECIPIENT.to_string(),
            challenge_binding_secret: Some(TEST_SECRET.to_string()),
            network: String::new(),
            ..Default::default()
        })
        .err()
        .expect("empty network should be rejected");
        assert!(
            err.to_string().contains("network must not be empty"),
            "got: {err}"
        );
    }

    #[test]
    fn new_rejects_mainnet_beta_slug() {
        // Audit #37: canonicalize on "mainnet" — the legacy "mainnet-beta"
        // is an RPC hostname, not a wire-format slug.
        let err = Mpp::new(Config {
            recipient: TEST_RECIPIENT.to_string(),
            challenge_binding_secret: Some(TEST_SECRET.to_string()),
            network: "mainnet-beta".to_string(),
            ..Default::default()
        })
        .err()
        .expect("mainnet-beta should be rejected as a slug");
        assert!(err.to_string().contains("Unknown network"), "got: {err}");
    }

    #[test]
    fn new_custom_rpc_url() {
        // Should not fail — just verifying it accepts a custom RPC URL.
        let mpp = Mpp::new(Config {
            recipient: TEST_RECIPIENT.to_string(),
            challenge_binding_secret: Some(TEST_SECRET.to_string()),
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
            challenge_binding_secret: Some(TEST_SECRET.to_string()),
            store: Some(store),
            ..Default::default()
        });
        assert!(result.is_ok());
    }

    // ── resolve_server_token_program tests (sync branches only) ──

    #[test]
    fn new_resolves_token_program_for_sol_currency() {
        let mpp = Mpp::new(Config {
            recipient: TEST_RECIPIENT.to_string(),
            challenge_binding_secret: Some(TEST_SECRET.to_string()),
            currency: "SOL".to_string(),
            decimals: 9,
            ..Default::default()
        })
        .unwrap();
        assert_eq!(mpp.token_program, None);
    }

    #[test]
    fn new_resolves_token_program_for_usdc() {
        // Default config is USDC.
        let mpp = test_mpp();
        assert_eq!(mpp.token_program, Some(programs::TOKEN_PROGRAM));
    }

    #[test]
    fn new_resolves_token_program_for_pyusd_token_2022() {
        // PYUSD is Token-2022; if this returns the legacy Token Program
        // (the old bug), the regression is back.
        let mpp = Mpp::new(Config {
            recipient: TEST_RECIPIENT.to_string(),
            challenge_binding_secret: Some(TEST_SECRET.to_string()),
            currency: "PYUSD".to_string(),
            network: "mainnet".to_string(),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(mpp.token_program, Some(programs::TOKEN_2022_PROGRAM));
    }

    #[test]
    fn new_rejects_unparseable_currency_without_rpc() {
        // Not a known symbol and not a valid base58 pubkey — must reject
        // up front, never silently fall back to the legacy Token Program.
        let err = Mpp::new(Config {
            recipient: TEST_RECIPIENT.to_string(),
            challenge_binding_secret: Some(TEST_SECRET.to_string()),
            currency: "not-a-symbol-or-mint!!".to_string(),
            ..Default::default()
        })
        .err()
        .expect("should fail");
        assert!(
            err.to_string().contains("neither a known symbol nor"),
            "got: {err}"
        );
    }

    // ── Audit #16: fee_payer without signer ──

    #[test]
    fn new_rejects_fee_payer_true_without_signer() {
        let err = Mpp::new(Config {
            recipient: TEST_RECIPIENT.to_string(),
            challenge_binding_secret: Some(TEST_SECRET.to_string()),
            fee_payer: true,
            fee_payer_signer: None,
            network: "devnet".to_string(),
            ..Default::default()
        })
        .err()
        .expect("fee_payer=true without signer should be rejected");
        assert!(
            err.to_string().contains("fee_payer_signer is None"),
            "got: {err}"
        );
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
    fn new_accepts_fee_payer_false_without_signer() {
        // Regression: the default config has no signer and fee_payer=false;
        // it must keep working.
        let mpp = Mpp::new(Config {
            recipient: TEST_RECIPIENT.to_string(),
            challenge_binding_secret: Some(TEST_SECRET.to_string()),
            fee_payer: false,
            fee_payer_signer: None,
            network: "devnet".to_string(),
            ..Default::default()
        })
        .expect("default fee_payer=false should be accepted");
        assert!(!mpp.fee_payer);
    }

    #[test]
    fn charge_options_rejects_fee_payer_without_signer() {
        // Mpp is configured fee_payer=false, no signer. A per-call
        // ChargeOptions.fee_payer = true override must be rejected.
        let mpp = Mpp::new(Config {
            recipient: TEST_RECIPIENT.to_string(),
            challenge_binding_secret: Some(TEST_SECRET.to_string()),
            fee_payer: false,
            fee_payer_signer: None,
            network: "devnet".to_string(),
            ..Default::default()
        })
        .unwrap();
        let err = mpp
            .charge_with_options(
                "1.00",
                ChargeOptions {
                    fee_payer: true,
                    ..Default::default()
                },
            )
            .err()
            .expect("per-call fee_payer without signer should be rejected");
        assert!(
            err.to_string().contains("no fee_payer_signer"),
            "got: {err}"
        );
    }

    #[test]
    fn charge_options_fee_payer_succeeds_when_signer_configured() {
        // Happy path: server has a signer, per-call override works.
        let mpp = Mpp::new(Config {
            recipient: TEST_RECIPIENT.to_string(),
            challenge_binding_secret: Some(TEST_SECRET.to_string()),
            fee_payer: false,
            fee_payer_signer: Some(test_fee_payer_signer()),
            network: "devnet".to_string(),
            ..Default::default()
        })
        .unwrap();
        let challenge = mpp
            .charge_with_options(
                "1.00",
                ChargeOptions {
                    fee_payer: true,
                    ..Default::default()
                },
            )
            .expect("per-call fee_payer with signer should succeed");
        let request: ChargeRequest = challenge.request.decode().unwrap();
        let details: MethodDetails =
            serde_json::from_value(request.method_details.unwrap()).unwrap();
        assert_eq!(details.fee_payer, Some(true));
        assert!(details.fee_payer_key.is_some(), "feePayerKey must be set");
    }

    // ── default_rpc_url ──
    //
    // The previous private duplicate is gone; tests for the canonical
    // implementation live next to it in `protocol/solana.rs`.

    // ── charge() and charge_with_options() tests ──

    #[test]
    fn charge_generates_valid_challenge() {
        let mpp = test_mpp();
        let challenge = mpp.charge("0.10").unwrap();

        assert_eq!(challenge.realm, derive_default_realm(TEST_RECIPIENT));
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
        // Audit #21: split recipients must be parseable pubkeys; the old
        // fixture strings were placeholders and now correctly fail
        // validation. Use real base58 keypairs.
        let vendor = Pubkey::new_unique().to_string();
        let processor = Pubkey::new_unique().to_string();
        let splits = vec![
            crate::protocol::solana::Split {
                recipient: vendor.clone(),
                amount: "500000".to_string(),
                ata_creation_required: None,
                label: None,
                memo: Some("Vendor payout".to_string()),
            },
            crate::protocol::solana::Split {
                recipient: processor.clone(),
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

    // ── Audit #21: split validation wired into both server entry points ──

    fn split_helper(recipient: &str, amount: &str) -> crate::protocol::solana::Split {
        crate::protocol::solana::Split {
            recipient: recipient.to_string(),
            amount: amount.to_string(),
            ata_creation_required: None,
            label: None,
            memo: None,
        }
    }

    #[test]
    fn charge_with_options_rejects_invalid_split_recipient() {
        let mpp = test_mpp();
        let err = mpp
            .charge_with_options(
                "1.00",
                ChargeOptions {
                    splits: vec![split_helper("not-a-pubkey!!", "1000")],
                    ..Default::default()
                },
            )
            .err()
            .expect("invalid split recipient should be rejected");
        assert!(
            format!("{err}").contains("invalid recipient pubkey"),
            "got: {err}"
        );
    }

    #[test]
    fn charge_with_options_rejects_zero_split_amount() {
        let mpp = test_mpp();
        let err = mpp
            .charge_with_options(
                "1.00",
                ChargeOptions {
                    splits: vec![split_helper(&Pubkey::new_unique().to_string(), "0")],
                    ..Default::default()
                },
            )
            .err()
            .expect("zero split amount should be rejected");
        assert!(format!("{err}").contains("greater than zero"), "got: {err}");
    }

    #[test]
    fn charge_with_options_rejects_duplicate_split_recipient() {
        let mpp = test_mpp();
        let dup = Pubkey::new_unique().to_string();
        let err = mpp
            .charge_with_options(
                "1.00",
                ChargeOptions {
                    splits: vec![split_helper(&dup, "100"), split_helper(&dup, "200")],
                    ..Default::default()
                },
            )
            .err()
            .expect("duplicate split recipient should be rejected");
        assert!(
            format!("{err}").contains("duplicate recipient"),
            "got: {err}"
        );
    }

    #[test]
    fn charge_with_options_rejects_too_many_splits() {
        let mpp = test_mpp();
        let splits: Vec<_> = (0..(crate::protocol::solana::MAX_SPLITS + 1))
            .map(|_| split_helper(&Pubkey::new_unique().to_string(), "1"))
            .collect();
        let err = mpp
            .charge_with_options(
                "1.00",
                ChargeOptions {
                    splits,
                    ..Default::default()
                },
            )
            .err()
            .expect("too many splits should be rejected");
        assert!(matches!(err, Error::TooManySplits));
    }

    #[test]
    fn charge_with_options_rejects_primary_recipient_with_ata_creation_required() {
        // Audit #38: a split whose recipient duplicates the top-level
        // recipient AND requests `ataCreationRequired: true` is the misconfig
        // shape that, in fee-sponsored mode, lets the primary recipient drain
        // server-funded ATA rent by closing/recreating its own ATA.
        let mpp = test_mpp();
        let splits = vec![crate::protocol::solana::Split {
            recipient: TEST_RECIPIENT.to_string(),
            amount: "10000".to_string(),
            ata_creation_required: Some(true),
            label: None,
            memo: None,
        }];
        let err = mpp
            .charge_with_options(
                "1.00",
                ChargeOptions {
                    splits,
                    ..Default::default()
                },
            )
            .err()
            .expect("should reject primary recipient with ataCreationRequired");
        let msg = err.to_string();
        assert!(
            msg.contains("top-level recipient"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn charge_with_options_allows_primary_recipient_in_splits_without_ata_creation() {
        // Legitimate use case the audit recommendation would have over-banned:
        // the merchant takes part of the funds as a regular split alongside
        // other payees. Allowed as long as the ATA-creation flag isn't set.
        let mpp = test_mpp();
        let splits = vec![crate::protocol::solana::Split {
            recipient: TEST_RECIPIENT.to_string(),
            amount: "10000".to_string(),
            ata_creation_required: None,
            label: None,
            memo: Some("merchant cut".to_string()),
        }];
        let challenge = mpp
            .charge_with_options(
                "1.00",
                ChargeOptions {
                    splits,
                    ..Default::default()
                },
            )
            .expect("primary recipient as a regular split is allowed");
        let request: ChargeRequest = challenge.request.decode().unwrap();
        let details = request.method_details.unwrap();
        let splits_arr = details.get("splits").unwrap().as_array().unwrap();
        assert_eq!(splits_arr.len(), 1);
        assert_eq!(splits_arr[0]["recipient"], TEST_RECIPIENT);
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

    // ── charge_challenge validation (audit #19) ──

    #[test]
    fn charge_challenge_rejects_mismatched_currency() {
        let mpp = test_mpp(); // USDC
        let request = ChargeRequest {
            amount: "100".to_string(),
            currency: "USDT".to_string(),
            recipient: Some(TEST_RECIPIENT.to_string()),
            ..Default::default()
        };
        let err = mpp.charge_challenge(&request).unwrap_err();
        assert!(format!("{err}").contains("does not match server-configured currency"));
    }

    #[test]
    fn charge_challenge_rejects_missing_recipient() {
        let mpp = test_mpp();
        let request = ChargeRequest {
            amount: "100".to_string(),
            currency: "USDC".to_string(),
            recipient: None,
            ..Default::default()
        };
        let err = mpp.charge_challenge(&request).unwrap_err();
        assert!(format!("{err}").contains("recipient is required"));
    }

    #[test]
    fn charge_challenge_rejects_invalid_recipient() {
        let mpp = test_mpp();
        let request = ChargeRequest {
            amount: "100".to_string(),
            currency: "USDC".to_string(),
            recipient: Some("not-a-pubkey!!".to_string()),
            ..Default::default()
        };
        let err = mpp.charge_challenge(&request).unwrap_err();
        assert!(format!("{err}").contains("Invalid recipient pubkey"));
    }

    #[test]
    fn charge_challenge_rejects_unparseable_amount() {
        let mpp = test_mpp();
        let request = ChargeRequest {
            amount: "abc".to_string(),
            currency: "USDC".to_string(),
            recipient: Some(TEST_RECIPIENT.to_string()),
            ..Default::default()
        };
        let err = mpp.charge_challenge(&request).unwrap_err();
        assert!(format!("{err}").contains("Invalid amount"));
    }

    #[test]
    fn charge_challenge_rejects_mismatched_network_in_method_details() {
        let mpp = test_mpp(); // network: devnet
        let md = MethodDetails {
            network: Some("mainnet".to_string()),
            ..Default::default()
        };
        let request = ChargeRequest {
            amount: "100".to_string(),
            currency: "USDC".to_string(),
            recipient: Some(TEST_RECIPIENT.to_string()),
            method_details: Some(serde_json::to_value(md).unwrap()),
            ..Default::default()
        };
        let err = mpp.charge_challenge(&request).unwrap_err();
        assert!(format!("{err}").contains("does not match server-configured network"));
    }

    #[test]
    fn charge_challenge_rejects_mismatched_token_program() {
        let mpp = test_mpp(); // USDC -> TOKEN_PROGRAM
        let md = MethodDetails {
            token_program: Some(programs::TOKEN_2022_PROGRAM.to_string()),
            ..Default::default()
        };
        let request = ChargeRequest {
            amount: "100".to_string(),
            currency: "USDC".to_string(),
            recipient: Some(TEST_RECIPIENT.to_string()),
            method_details: Some(serde_json::to_value(md).unwrap()),
            ..Default::default()
        };
        let err = mpp.charge_challenge(&request).unwrap_err();
        assert!(format!("{err}").contains("does not match server-resolved token program"));
    }

    #[test]
    fn charge_challenge_rejects_invalid_split_recipient() {
        let mpp = test_mpp();
        let md = MethodDetails {
            splits: Some(vec![Split {
                recipient: "not-a-pubkey!!".to_string(),
                amount: "10".to_string(),
                ata_creation_required: None,
                label: None,
                memo: None,
            }]),
            ..Default::default()
        };
        let request = ChargeRequest {
            amount: "100".to_string(),
            currency: "USDC".to_string(),
            recipient: Some(TEST_RECIPIENT.to_string()),
            method_details: Some(serde_json::to_value(md).unwrap()),
            ..Default::default()
        };
        let err = mpp.charge_challenge(&request).unwrap_err();
        // Audit #21 unified the error string via the shared validate_splits helper.
        assert!(
            format!("{err}").contains("splits[0]: invalid recipient pubkey"),
            "got: {err}"
        );
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

    // ── verify() tier-1 (HMAC) tests ──

    #[tokio::test(flavor = "multi_thread")]
    async fn verify_rejects_tampered_id() {
        let mpp = test_mpp();
        let challenge = mpp.charge("0.10").unwrap();
        let request: ChargeRequest = challenge.request.decode().unwrap();
        let mut cred = PaymentCredential {
            challenge: challenge.to_echo(),
            source: None,
            payload: serde_json::json!({"type": "signature", "signature": "x"}),
        };
        cred.challenge.id = "bad".to_string();

        let err = mpp.verify(&cred, &request).await.unwrap_err();
        assert_eq!(err.code, Some("malformed-credential"));
    }

    /// Audit #22: `verify` must reject when the caller-supplied request
    /// diverges from the request HMAC-authenticated by the credential —
    /// otherwise direct callers could authenticate one request shape and
    /// settle against a different one.
    #[tokio::test(flavor = "multi_thread")]
    async fn verify_rejects_request_diverging_from_credential() {
        let mpp = test_mpp();
        let challenge = mpp.charge("0.10").unwrap(); // credential carries amount=100000
        let cred = PaymentCredential {
            challenge: challenge.to_echo(),
            source: None,
            payload: serde_json::json!({"type": "signature", "signature": "x"}),
        };

        // Caller passes a request with a different amount than what the
        // credential's HMAC-authenticated request carries. HMAC tier-1
        // still passes (we didn't tamper with the credential), so the
        // audit #22 binding check is the only thing that catches the
        // divergence.
        let divergent = ChargeRequest {
            amount: "999999".to_string(),
            currency: "USDC".to_string(),
            recipient: Some(TEST_RECIPIENT.to_string()),
            ..Default::default()
        };

        let err = mpp.verify(&cred, &divergent).await.unwrap_err();
        assert_eq!(err.code, Some("malformed-credential"));
        assert!(
            err.message.contains("Amount mismatch"),
            "expected amount mismatch from the binding check, got: {err:?}"
        );
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

    // Audit #1: every payment-constraining field comparison.

    fn expected_from_challenge(challenge: &PaymentChallenge) -> ChargeRequest {
        challenge.request.decode().unwrap()
    }

    fn mutate_method_details(
        req: &mut ChargeRequest,
        f: impl FnOnce(&mut crate::protocol::solana::MethodDetails),
    ) {
        use crate::protocol::solana::MethodDetails;
        let mut md: MethodDetails = req
            .method_details
            .as_ref()
            .map(|v| serde_json::from_value(v.clone()).unwrap_or_default())
            .unwrap_or_default();
        f(&mut md);
        req.method_details = Some(serde_json::to_value(&md).unwrap());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn verify_credential_with_expected_external_id_mismatch() {
        let mpp = test_mpp();
        let challenge = mpp
            .charge_with_options(
                "0.10",
                ChargeOptions {
                    external_id: Some("order-1"),
                    ..Default::default()
                },
            )
            .unwrap();
        let cred = PaymentCredential {
            challenge: challenge.to_echo(),
            source: None,
            payload: serde_json::json!({"type": "signature", "signature": "x"}),
        };
        let mut expected = expected_from_challenge(&challenge);
        expected.external_id = Some("order-2".to_string());

        let err = mpp
            .verify_credential_with_expected(&cred, &expected)
            .await
            .unwrap_err();
        assert!(err.message.contains("externalId mismatch"), "got: {err:?}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn verify_credential_with_expected_description_mismatch() {
        let mpp = test_mpp();
        let challenge = mpp
            .charge_with_options(
                "0.10",
                ChargeOptions {
                    description: Some("A"),
                    ..Default::default()
                },
            )
            .unwrap();
        let cred = PaymentCredential {
            challenge: challenge.to_echo(),
            source: None,
            payload: serde_json::json!({"type": "signature", "signature": "x"}),
        };
        let mut expected = expected_from_challenge(&challenge);
        expected.description = Some("B".to_string());

        let err = mpp
            .verify_credential_with_expected(&cred, &expected)
            .await
            .unwrap_err();
        assert!(err.message.contains("description mismatch"), "got: {err:?}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn verify_credential_with_expected_network_mismatch() {
        let mpp = test_mpp();
        let challenge = mpp.charge("0.10").unwrap();
        let cred = PaymentCredential {
            challenge: challenge.to_echo(),
            source: None,
            payload: serde_json::json!({"type": "signature", "signature": "x"}),
        };
        let mut expected = expected_from_challenge(&challenge);
        mutate_method_details(&mut expected, |md| md.network = Some("mainnet".into()));

        let err = mpp
            .verify_credential_with_expected(&cred, &expected)
            .await
            .unwrap_err();
        assert!(
            err.message.contains("methodDetails.network mismatch"),
            "got: {err:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn verify_credential_with_expected_decimals_mismatch() {
        let mpp = test_mpp();
        let challenge = mpp.charge("0.10").unwrap();
        let cred = PaymentCredential {
            challenge: challenge.to_echo(),
            source: None,
            payload: serde_json::json!({"type": "signature", "signature": "x"}),
        };
        let mut expected = expected_from_challenge(&challenge);
        mutate_method_details(&mut expected, |md| md.decimals = Some(9));

        let err = mpp
            .verify_credential_with_expected(&cred, &expected)
            .await
            .unwrap_err();
        assert!(
            err.message.contains("methodDetails.decimals mismatch"),
            "got: {err:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn verify_credential_with_expected_token_program_mismatch() {
        let mpp = test_mpp();
        let challenge = mpp.charge("0.10").unwrap();
        let cred = PaymentCredential {
            challenge: challenge.to_echo(),
            source: None,
            payload: serde_json::json!({"type": "signature", "signature": "x"}),
        };
        let mut expected = expected_from_challenge(&challenge);
        mutate_method_details(&mut expected, |md| {
            md.token_program = Some("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb".into())
        });

        let err = mpp
            .verify_credential_with_expected(&cred, &expected)
            .await
            .unwrap_err();
        assert!(
            err.message.contains("methodDetails.tokenProgram mismatch"),
            "got: {err:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn verify_credential_with_expected_fee_payer_mismatch() {
        let mpp = test_mpp();
        let challenge = mpp.charge("0.10").unwrap();
        let cred = PaymentCredential {
            challenge: challenge.to_echo(),
            source: None,
            payload: serde_json::json!({"type": "signature", "signature": "x"}),
        };
        let mut expected = expected_from_challenge(&challenge);
        mutate_method_details(&mut expected, |md| md.fee_payer = Some(true));

        let err = mpp
            .verify_credential_with_expected(&cred, &expected)
            .await
            .unwrap_err();
        assert!(
            err.message.contains("methodDetails.feePayer mismatch"),
            "got: {err:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn verify_credential_with_expected_fee_payer_key_mismatch() {
        let mpp = test_mpp();
        let challenge = mpp.charge("0.10").unwrap();
        let cred = PaymentCredential {
            challenge: challenge.to_echo(),
            source: None,
            payload: serde_json::json!({"type": "signature", "signature": "x"}),
        };
        let mut expected = expected_from_challenge(&challenge);
        mutate_method_details(&mut expected, |md| {
            md.fee_payer_key = Some(Pubkey::new_unique().to_string())
        });

        let err = mpp
            .verify_credential_with_expected(&cred, &expected)
            .await
            .unwrap_err();
        assert!(
            err.message.contains("methodDetails.feePayerKey mismatch"),
            "got: {err:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn verify_credential_with_expected_splits_mismatch() {
        let mpp = test_mpp();
        let challenge = mpp.charge("0.10").unwrap();
        let cred = PaymentCredential {
            challenge: challenge.to_echo(),
            source: None,
            payload: serde_json::json!({"type": "signature", "signature": "x"}),
        };
        let mut expected = expected_from_challenge(&challenge);
        mutate_method_details(&mut expected, |md| {
            md.splits = Some(vec![crate::protocol::solana::Split {
                recipient: Pubkey::new_unique().to_string(),
                amount: "1".to_string(),
                ata_creation_required: None,
                label: None,
                memo: None,
            }])
        });

        let err = mpp
            .verify_credential_with_expected(&cred, &expected)
            .await
            .unwrap_err();
        assert!(
            err.message.contains("methodDetails.splits mismatch"),
            "got: {err:?}"
        );
    }

    /// Audit #1: `recent_blockhash` is per-challenge state, not per-route
    /// policy. A mismatch must NOT trigger a rejection, otherwise honest
    /// flows (where the route's expected has no blockhash and the
    /// credential's request has a fresh one) would break.
    #[tokio::test(flavor = "multi_thread")]
    async fn verify_credential_with_expected_ignores_recent_blockhash() {
        let mpp = test_mpp();
        let challenge = mpp.charge("0.10").unwrap();
        let cred = PaymentCredential {
            challenge: challenge.to_echo(),
            source: None,
            payload: serde_json::json!({"type": "signature", "signature": "x"}),
        };
        let mut expected = expected_from_challenge(&challenge);
        // Strip the blockhash from `expected` even though the credential
        // carries one. The comparison must pass; downstream `verify` will
        // fail on the dummy signature payload, which is fine — we only care
        // that we got *past* the comparison layer.
        mutate_method_details(&mut expected, |md| md.recent_blockhash = None);

        let err = mpp
            .verify_credential_with_expected(&cred, &expected)
            .await
            .unwrap_err();
        let msg = format!("{}", err.message);
        assert!(
            !msg.contains("recentBlockhash mismatch") && !msg.contains("recent_blockhash mismatch"),
            "comparison should not reject on blockhash, got: {err:?}"
        );
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
        // Audit #1 now catches the bad expected.method_details at the
        // up-front comparison layer (before settlement); the error string
        // changed accordingly. The point of the test still holds: `expected`
        // (not the credential's request) is being parsed.
        assert!(
            err.message.contains("Invalid expected methodDetails"),
            "expected `expected` request to be parsed, got: {err:?}"
        );
    }

    // ── Tier-2 pinned-field tests ──
    //
    // Each test forges a credential where one pinned field differs from what
    // the server has configured, then re-signs the HMAC so Tier-1 passes. The
    // Tier-2 backstop must reject every case. Called via `verify` directly
    // (the lowest-level public API) so the pinned-field layer is exercised
    // in isolation regardless of the higher-level convenience entry points.

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
        let request: ChargeRequest = challenge.request.decode().unwrap();
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
        let err = mpp.verify(&cred, &request).await.unwrap_err();
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
        let err = mpp.verify(&cred, &request).await.unwrap_err();
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
        let err = mpp.verify(&cred, &request).await.unwrap_err();
        assert_eq!(err.code, Some("malformed-credential"));
        assert!(err.message.contains("recipient"), "got: {err:?}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn tier2_rejects_tampered_method() {
        let mpp = test_mpp();
        let challenge = mpp.charge("0.10").unwrap();
        let request: ChargeRequest = challenge.request.decode().unwrap();
        let mut echo = challenge.to_echo();
        echo.method = "stripe".into();
        resign_challenge(TEST_SECRET, &mpp.realm, &mut echo);

        let cred = PaymentCredential {
            challenge: echo,
            source: None,
            payload: serde_json::json!({"type": "signature", "signature": "x"}),
        };
        let err = mpp.verify(&cred, &request).await.unwrap_err();
        assert_eq!(err.code, Some("malformed-credential"));
        assert!(err.message.contains("method"), "got: {err:?}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn tier2_rejects_non_charge_intent() {
        let mpp = test_mpp();
        let challenge = mpp.charge("0.10").unwrap();
        let request: ChargeRequest = challenge.request.decode().unwrap();
        let mut echo = challenge.to_echo();
        echo.intent = "session".into();
        resign_challenge(TEST_SECRET, &mpp.realm, &mut echo);

        let cred = PaymentCredential {
            challenge: echo,
            source: None,
            payload: serde_json::json!({"type": "signature", "signature": "x"}),
        };
        let err = mpp.verify(&cred, &request).await.unwrap_err();
        assert_eq!(err.code, Some("malformed-credential"));
        assert!(err.message.contains("intent"), "got: {err:?}");
    }

    // ── Audit #5: push-mode acceptance is opt-in ──
    //
    // Spec §13.5: push mode matches by shape; any matching-shape on-chain
    // transaction can claim any matching-shape challenge. Gate runs before
    // B34 (which catches the narrower fee-payer-route case).

    #[tokio::test(flavor = "multi_thread")]
    async fn verify_rejects_push_credential_when_accept_push_mode_off() {
        // Default config: accept_push_mode is false. No fee-sponsor either,
        // so B34 wouldn't fire — only the audit #5 gate should reject.
        let mpp = test_mpp();
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
            err.message.contains("Push-mode credentials are disabled"),
            "got: {err:?}"
        );
        // The error message should also point at the spec for ops triage.
        assert!(
            err.message.contains("§13.5"),
            "expected spec §13.5 callout, got: {err:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn verify_passes_audit_5_gate_when_accept_push_mode_on() {
        // Opt in. The audit #5 gate should NOT fire — any later error
        // (e.g. on-chain verification against a fake signature) is fine,
        // just not the "Push-mode credentials are disabled" one.
        let mpp = Mpp::new(Config {
            recipient: TEST_RECIPIENT.to_string(),
            challenge_binding_secret: Some(TEST_SECRET.to_string()),
            currency: crate::protocol::solana::mints::USDC_DEVNET.to_string(),
            network: "devnet".to_string(),
            accept_push_mode: true,
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
        assert!(
            !err.message.contains("Push-mode credentials are disabled"),
            "audit #5 gate should not fire when opted in: {err:?}"
        );
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
        // Audit #5 added an earlier `accept_push_mode` gate. To exercise
        // the B34 fee-payer-specific path in isolation, opt push mode in
        // here so the audit #5 gate passes and B34 fires.
        let mpp = Mpp::new(Config {
            recipient: TEST_RECIPIENT.to_string(),
            challenge_binding_secret: Some(TEST_SECRET.to_string()),
            currency: crate::protocol::solana::mints::USDC_DEVNET.to_string(),
            fee_payer: true,
            fee_payer_signer: Some(test_fee_payer_signer()),
            network: "devnet".to_string(),
            accept_push_mode: true,
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
            "program": "system",
            "parsed": {
                "type": "transfer",
                "info": {
                    "source": "PayerPubkey",
                    "destination": "RecipientPubkey",
                    "lamports": 1000000
                }
            }
        })];
        assert!(find_sol_transfer(
            &instructions,
            "RecipientPubkey",
            1_000_000,
            None,
            &mut matched
        )
        .is_ok());
    }

    #[test]
    fn find_sol_transfer_wrong_amount() {
        let mut matched = HashSet::new();
        let instructions = vec![serde_json::json!({
            "program": "system",
            "parsed": {
                "type": "transfer",
                "info": {
                    "source": "PayerPubkey",
                    "destination": "RecipientPubkey",
                    "lamports": 500000
                }
            }
        })];
        assert!(find_sol_transfer(
            &instructions,
            "RecipientPubkey",
            1_000_000,
            None,
            &mut matched
        )
        .is_err());
    }

    #[test]
    fn find_sol_transfer_wrong_recipient() {
        let mut matched = HashSet::new();
        let instructions = vec![serde_json::json!({
            "program": "system",
            "parsed": {
                "type": "transfer",
                "info": {
                    "source": "PayerPubkey",
                    "destination": "WrongPubkey",
                    "lamports": 1000000
                }
            }
        })];
        assert!(find_sol_transfer(
            &instructions,
            "RecipientPubkey",
            1_000_000,
            None,
            &mut matched
        )
        .is_err());
    }

    #[test]
    fn find_sol_transfer_empty_instructions() {
        let mut matched = HashSet::new();
        assert!(find_sol_transfer(&[], "RecipientPubkey", 1_000_000, None, &mut matched).is_err());
    }

    #[test]
    fn find_sol_transfer_ignores_non_transfer_types() {
        let mut matched = HashSet::new();
        let instructions = vec![serde_json::json!({
            "program": "system",
            "parsed": {
                "type": "createAccount",
                "info": {
                    "source": "PayerPubkey",
                    "destination": "RecipientPubkey",
                    "lamports": 1000000
                }
            }
        })];
        assert!(find_sol_transfer(
            &instructions,
            "RecipientPubkey",
            1_000_000,
            None,
            &mut matched
        )
        .is_err());
    }

    #[test]
    fn find_sol_transfer_rejects_non_system_program() {
        let mut matched = HashSet::new();
        // A "transfer" with a lamports field, but on the wrong program. The
        // legacy implementation matched on parsed.type + info.lamports alone
        // and would accept this; the hardened implementation must not.
        let instructions = vec![serde_json::json!({
            "programId": programs::TOKEN_PROGRAM,
            "parsed": {
                "type": "transfer",
                "info": {
                    "source": "PayerPubkey",
                    "destination": "RecipientPubkey",
                    "lamports": 1_000_000
                }
            }
        })];
        assert!(find_sol_transfer(
            &instructions,
            "RecipientPubkey",
            1_000_000,
            None,
            &mut matched
        )
        .is_err());
    }

    #[test]
    fn find_sol_transfer_rejects_source_equals_fee_payer() {
        let mut matched = HashSet::new();
        let instructions = vec![serde_json::json!({
            "program": "system",
            "parsed": {
                "type": "transfer",
                "info": {
                    "source": "FeePayerPubkey",
                    "destination": "RecipientPubkey",
                    "lamports": 1_000_000
                }
            }
        })];
        let err = find_sol_transfer(
            &instructions,
            "RecipientPubkey",
            1_000_000,
            Some("FeePayerPubkey"),
            &mut matched,
        )
        .unwrap_err();
        assert!(err.message.contains("Fee payer cannot fund"));
    }

    #[test]
    fn verify_sol_transfers_with_splits() {
        let primary_recipient = "PrimaryRecipient";
        let split_recipient = "SplitRecipient";
        let instructions = vec![
            serde_json::json!({
                "program": "system",
                "parsed": {
                    "type": "transfer",
                    "info": {
                        "source": "PayerPubkey",
                        "destination": primary_recipient,
                        "lamports": 800000
                    }
                }
            }),
            serde_json::json!({
                "program": "system",
                "parsed": {
                    "type": "transfer",
                    "info": {
                        "source": "PayerPubkey",
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

        assert!(
            verify_sol_transfers(&instructions, primary_recipient, 800000, &splits, None).is_ok()
        );
    }

    #[test]
    fn verify_sol_transfers_missing_split() {
        let instructions = vec![serde_json::json!({
            "program": "system",
            "parsed": {
                "type": "transfer",
                "info": {
                    "source": "PayerPubkey",
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

        let err = verify_sol_transfers(&instructions, "PrimaryRecipient", 800000, &splits, None)
            .unwrap_err();
        assert!(err.message.contains("Missing split transfer"));
    }

    #[test]
    fn verify_sol_transfers_rejects_reusing_single_instruction_for_duplicate_splits() {
        let instructions = vec![
            serde_json::json!({
                "program": "system",
                "parsed": {
                    "type": "transfer",
                    "info": {
                        "source": "PayerPubkey",
                        "destination": "PrimaryRecipient",
                        "lamports": 800000
                    }
                }
            }),
            serde_json::json!({
                "program": "system",
                "parsed": {
                    "type": "transfer",
                    "info": {
                        "source": "PayerPubkey",
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

        let err = verify_sol_transfers(&instructions, "PrimaryRecipient", 800000, &splits, None)
            .unwrap_err();
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

        assert!(find_spl_transfer(
            &instructions,
            owner,
            mint,
            1_000_000,
            None,
            None,
            &mut matched
        )
        .is_ok());
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

        let err = verify_spl_transfers(&instructions, owner, mint, 800000, &splits, None, None)
            .unwrap_err();
        assert!(err.message.contains("Missing split SPL transfer"));
    }

    #[test]
    fn find_spl_transfer_rejects_authority_equals_fee_payer() {
        let mut matched = HashSet::new();
        let owner = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY";
        let mint = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
        let fee_payer = "9XHRopERTd4LfQ8b6e3p9bN2WhxgQzDxFRtbq1XwQ4mP";
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
                    "source": "SomeSourceAta1111111111111111111111111111111",
                    "authority": fee_payer,
                    "destination": dest_ata.to_string(),
                    "mint": mint,
                    "tokenAmount": { "amount": "1000000" }
                }
            }
        })];

        let err = find_spl_transfer(
            &instructions,
            owner,
            mint,
            1_000_000,
            None,
            Some(fee_payer),
            &mut matched,
        )
        .unwrap_err();
        assert!(err.message.contains("Fee payer cannot authorize"));
    }

    #[test]
    fn find_spl_transfer_rejects_source_equals_fee_payer_ata() {
        let mut matched = HashSet::new();
        let owner = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY";
        let mint = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
        let fee_payer = "9XHRopERTd4LfQ8b6e3p9bN2WhxgQzDxFRtbq1XwQ4mP";
        let tp = programs::TOKEN_PROGRAM;

        let owner_pk = Pubkey::from_str(owner).unwrap();
        let fee_payer_pk = Pubkey::from_str(fee_payer).unwrap();
        let mint_pk = Pubkey::from_str(mint).unwrap();
        let tp_pk = Pubkey::from_str(tp).unwrap();
        let ata_program = Pubkey::from_str(programs::ASSOCIATED_TOKEN_PROGRAM).unwrap();
        let (dest_ata, _) = Pubkey::find_program_address(
            &[owner_pk.as_ref(), tp_pk.as_ref(), mint_pk.as_ref()],
            &ata_program,
        );
        let (fee_payer_ata, _) = Pubkey::find_program_address(
            &[fee_payer_pk.as_ref(), tp_pk.as_ref(), mint_pk.as_ref()],
            &ata_program,
        );

        let instructions = vec![serde_json::json!({
            "programId": tp,
            "parsed": {
                "type": "transferChecked",
                "info": {
                    "source": fee_payer_ata.to_string(),
                    // Authority is a different account (e.g. a delegate) so the
                    // first check passes; the source-ATA check must still fire.
                    "authority": owner,
                    "destination": dest_ata.to_string(),
                    "mint": mint,
                    "tokenAmount": { "amount": "1000000" }
                }
            }
        })];

        let err = find_spl_transfer(
            &instructions,
            owner,
            mint,
            1_000_000,
            None,
            Some(fee_payer),
            &mut matched,
        )
        .unwrap_err();
        assert!(err.message.contains("Fee payer token account cannot fund"));
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
            verify_spl_transfers(&instructions, owner, mint, 1_000_000, &[], Some(tp), None)
                .unwrap();
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
            // Audit #16: signer is now required alongside fee_payer = true.
            fee_payer_signer: Some(test_fee_payer_signer()),
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
        // Audit #16: per-call ChargeOptions.fee_payer requires the server
        // to have a signer configured.
        let mpp = Mpp::new(Config {
            recipient: TEST_RECIPIENT.to_string(),
            challenge_binding_secret: Some(TEST_SECRET.to_string()),
            fee_payer_signer: Some(test_fee_payer_signer()),
            network: "devnet".to_string(),
            ..Default::default()
        })
        .unwrap();
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
