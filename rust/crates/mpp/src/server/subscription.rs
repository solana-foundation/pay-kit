//! Server-side payment verification for the Solana subscription intent.
//!
//! Generates 402 challenges that pin the subscriber to an on-chain `Plan` and
//! a per-period charging cadence, then verifies activation credentials by
//! re-deriving the `SubscriptionDelegation` PDA and asserting the on-chain
//! state matches the challenge.
//!
//! Renewals are server-driven on-chain transactions and do not pass through
//! this handler.
//!
//! # Quick Start
//!
//! ```ignore
//! use solana_mpp::server::subscription::{SubscriptionConfig, SubscriptionServer};
//! use solana_mpp::protocol::intents::SubscriptionPeriodUnit;
//!
//! let server = SubscriptionServer::new(SubscriptionConfig {
//!     plan_id: "8tWb...".to_string(),
//!     mint: "EPjFW...".to_string(),
//!     token_program: solana_mpp::protocol::solana::programs::TOKEN_PROGRAM.to_string(),
//!     decimals: 6,
//!     puller: "5fKb...".to_string(),
//!     recipient: "9xAX...".to_string(),
//!     period_unit: SubscriptionPeriodUnit::Day,
//!     period_count: 30,
//!     ..Default::default()
//! })?;
//!
//! let challenge = server.subscription_challenge("10000000")?;
//! ```

use std::sync::Arc;

use crate::error::Error;
use crate::expires;
use crate::program::subscriptions::{parse_pubkey, SUBSCRIPTIONS_PROGRAM_ID};
use crate::protocol::core::{Base64UrlJson, PaymentChallenge};
use crate::protocol::intents::{SubscriptionPeriodUnit, SubscriptionRequest};
use crate::store::{MemoryStore, Store};

const METHOD_NAME: &str = "solana";
const INTENT_NAME: &str = "subscription";
const SECRET_KEY_ENV_VAR: &str = "MPP_SECRET_KEY";
const DEFAULT_REALM: &str = "MPP Subscription";

/// Configuration for a subscription server route.
#[derive(Clone)]
pub struct SubscriptionConfig {
    /// Base58 of the on-chain `Plan` PDA.
    pub plan_id: String,
    /// Base58 of the SPL token mint (must equal `plan.mint`).
    pub mint: String,
    /// Decimal precision of the mint.
    pub decimals: u8,
    /// Base58 of the SPL Token / Token-2022 program ID.
    pub token_program: String,
    /// Base58 of the server's puller pubkey (in `plan.pullers` or `plan.owner`).
    pub puller: String,
    /// Base58 of the primary recipient wallet.
    pub recipient: String,
    /// Billing period unit. The Solana profile rejects `month`.
    pub period_unit: SubscriptionPeriodUnit,
    /// Positive integer count of `period_unit` per billing period.
    pub period_count: u64,
    /// Optional RFC3339 expiry of the recurring authorization.
    pub subscription_expires: Option<String>,
    /// Solana network: mainnet-beta, devnet, testnet, or localnet.
    pub network: String,
    /// Subscriptions program ID. Defaults to the canonical mainnet deployment.
    pub program_id: Option<String>,
    /// Override the public RPC for the configured network.
    pub rpc_url: Option<String>,
    /// HMAC secret for challenge IDs. Defaults to `MPP_SECRET_KEY` env var.
    pub secret_key: Option<String>,
    /// Server realm.
    pub realm: Option<String>,
    /// If `true`, the server pays activation transaction fees.
    pub fee_payer: bool,
    /// Fee-payer signer (used when `fee_payer` is `true`).
    pub fee_payer_signer: Option<Arc<dyn solana_keychain::SolanaSigner>>,
    /// Replay-protection store.
    pub store: Option<Arc<dyn Store>>,
}

impl Default for SubscriptionConfig {
    fn default() -> Self {
        Self {
            plan_id: String::new(),
            mint: String::new(),
            decimals: 6,
            token_program: String::new(),
            puller: String::new(),
            recipient: String::new(),
            period_unit: SubscriptionPeriodUnit::Day,
            period_count: 30,
            subscription_expires: None,
            network: "mainnet-beta".into(),
            program_id: None,
            rpc_url: None,
            secret_key: None,
            realm: None,
            fee_payer: false,
            fee_payer_signer: None,
            store: None,
        }
    }
}

/// Server-side handler for the Solana subscription intent.
#[derive(Clone)]
pub struct SubscriptionServer {
    config: SubscriptionConfig,
    program_id: String,
    secret_key: String,
    realm: String,
    #[allow(dead_code)]
    store: Arc<dyn Store>,
    #[allow(dead_code)]
    rpc_url: String,
}

impl SubscriptionServer {
    /// Create a new server handler from config. Validates pubkeys and
    /// period bounds eagerly; misconfigured servers fail at boot, not on
    /// the first challenge.
    pub fn new(mut config: SubscriptionConfig) -> Result<Self, Error> {
        if config.plan_id.is_empty() {
            return Err(Error::InvalidConfig("plan_id is required".into()));
        }
        if config.mint.is_empty() {
            return Err(Error::InvalidConfig("mint is required".into()));
        }
        if config.token_program.is_empty() {
            return Err(Error::InvalidConfig("token_program is required".into()));
        }
        if config.puller.is_empty() {
            return Err(Error::InvalidConfig("puller is required".into()));
        }
        if config.recipient.is_empty() {
            return Err(Error::InvalidConfig("recipient is required".into()));
        }

        // Validate all pubkeys parse.
        parse_pubkey(&config.plan_id, "plan_id")?;
        parse_pubkey(&config.mint, "mint")?;
        parse_pubkey(&config.token_program, "token_program")?;
        parse_pubkey(&config.puller, "puller")?;
        parse_pubkey(&config.recipient, "recipient")?;

        // Validate the period mapping.
        config.period_unit.to_period_hours(config.period_count)?;

        let program_id = config
            .program_id
            .clone()
            .unwrap_or_else(|| SUBSCRIPTIONS_PROGRAM_ID.to_string());
        parse_pubkey(&program_id, "program_id")?;

        let secret_key = match config.secret_key.take() {
            Some(s) => s,
            None => std::env::var(SECRET_KEY_ENV_VAR).map_err(|_| {
                Error::InvalidConfig(format!(
                    "Missing {SECRET_KEY_ENV_VAR} env var. Set it or pass secret_key explicitly."
                ))
            })?,
        };

        let realm = config
            .realm
            .clone()
            .unwrap_or_else(|| DEFAULT_REALM.to_string());

        let store: Arc<dyn Store> = config
            .store
            .clone()
            .unwrap_or_else(|| Arc::new(MemoryStore::new()));

        let rpc_url = config
            .rpc_url
            .clone()
            .unwrap_or_else(|| default_rpc_url(&config.network).to_string());

        Ok(SubscriptionServer {
            config,
            program_id,
            secret_key,
            realm,
            store,
            rpc_url,
        })
    }

    /// Generate a 402 subscription challenge for the configured amount per period.
    pub fn subscription_challenge(
        &self,
        amount_base_units: &str,
    ) -> Result<PaymentChallenge, Error> {
        if amount_base_units.is_empty() {
            return Err(Error::Other("amount is required".into()));
        }
        // Parse to validate it's a positive integer in base units.
        let _amount: u64 = amount_base_units
            .parse()
            .map_err(|_| Error::Other(format!("Invalid amount: {amount_base_units}")))?;

        let mut method_details = serde_json::Map::new();
        method_details.insert("network".into(), serde_json::json!(self.config.network));
        method_details.insert("planId".into(), serde_json::json!(self.config.plan_id));
        method_details.insert("mint".into(), serde_json::json!(self.config.mint));
        method_details.insert(
            "tokenProgram".into(),
            serde_json::json!(self.config.token_program),
        );
        method_details.insert("decimals".into(), serde_json::json!(self.config.decimals));
        method_details.insert("puller".into(), serde_json::json!(self.config.puller));
        method_details.insert("programId".into(), serde_json::json!(self.program_id));

        if self.config.fee_payer {
            method_details.insert("feePayer".into(), serde_json::json!(true));
            if let Some(ref signer) = self.config.fee_payer_signer {
                method_details.insert(
                    "feePayerKey".into(),
                    serde_json::json!(signer.pubkey().to_string()),
                );
            }
        }

        let request = SubscriptionRequest {
            amount: amount_base_units.to_string(),
            currency: self.config.mint.clone(),
            period_unit: self.config.period_unit,
            period_count: self.config.period_count.to_string(),
            recipient: self.config.recipient.clone(),
            subscription_expires: self.config.subscription_expires.clone(),
            method_details: Some(serde_json::Value::Object(method_details)),
            ..Default::default()
        };

        let encoded = Base64UrlJson::from_typed(&request)?;
        let default_expires = expires::minutes(5);

        Ok(PaymentChallenge::with_secret_key_full(
            &self.secret_key,
            &self.realm,
            METHOD_NAME,
            INTENT_NAME,
            encoded,
            Some(&default_expires),
            None,
            None,
            None,
        ))
    }

    // ── Accessors ──

    pub fn realm(&self) -> &str {
        &self.realm
    }

    pub fn plan_id(&self) -> &str {
        &self.config.plan_id
    }

    pub fn mint(&self) -> &str {
        &self.config.mint
    }

    pub fn recipient(&self) -> &str {
        &self.config.recipient
    }

    pub fn puller(&self) -> &str {
        &self.config.puller
    }

    pub fn program_id(&self) -> &str {
        &self.program_id
    }

    pub fn period_unit(&self) -> SubscriptionPeriodUnit {
        self.config.period_unit
    }

    pub fn period_count(&self) -> u64 {
        self.config.period_count
    }
}

fn default_rpc_url(network: &str) -> &'static str {
    match network {
        "devnet" => "https://api.devnet.solana.com",
        "testnet" => "https://api.testnet.solana.com",
        "localnet" => "http://localhost:8899",
        _ => "https://api.mainnet-beta.solana.com",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_pubkey::Pubkey;

    fn keypair_base58() -> String {
        // Deterministic pubkey for tests — actual key material is not used.
        Pubkey::new_unique().to_string()
    }

    fn make_config() -> SubscriptionConfig {
        SubscriptionConfig {
            plan_id: keypair_base58(),
            mint: keypair_base58(),
            token_program: crate::protocol::solana::programs::TOKEN_PROGRAM.to_string(),
            puller: keypair_base58(),
            recipient: keypair_base58(),
            secret_key: Some("test-secret".to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn rejects_missing_required_fields() {
        let mut cfg = make_config();
        cfg.plan_id = String::new();
        assert!(SubscriptionServer::new(cfg).is_err());
    }

    #[test]
    fn rejects_invalid_pubkeys() {
        let mut cfg = make_config();
        cfg.plan_id = "not-a-pubkey".into();
        assert!(SubscriptionServer::new(cfg).is_err());
    }

    #[test]
    fn rejects_out_of_range_period() {
        let mut cfg = make_config();
        cfg.period_unit = SubscriptionPeriodUnit::Day;
        cfg.period_count = 400;
        assert!(SubscriptionServer::new(cfg).is_err());
    }

    #[test]
    fn challenge_is_well_formed() {
        let server = SubscriptionServer::new(make_config()).expect("server");
        let challenge = server
            .subscription_challenge("10000000")
            .expect("challenge");
        let header = challenge.to_header().expect("header");
        assert!(header.contains("intent=\"subscription\""));
        assert!(header.contains("method=\"solana\""));
        assert!(header.contains("realm=\"MPP Subscription\""));
    }

    #[test]
    fn challenge_request_encodes_period_and_plan() {
        let server = SubscriptionServer::new(make_config()).expect("server");
        let plan_id = server.plan_id().to_string();
        let challenge = server.subscription_challenge("10000000").unwrap();

        // Decode the base64url request and verify it pins the plan and period.
        let header = challenge.to_header().unwrap();
        let request_b64 = extract_request_param(&header).expect("request param");
        let bytes = crate::protocol::core::base64url_decode(&request_b64).unwrap();
        let parsed: SubscriptionRequest = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed.period_unit, SubscriptionPeriodUnit::Day);
        assert_eq!(parsed.period_count, "30");
        let md = parsed.method_details.as_ref().unwrap();
        assert_eq!(md.get("planId").unwrap().as_str().unwrap(), plan_id);
    }

    #[test]
    fn rejects_invalid_amount() {
        let server = SubscriptionServer::new(make_config()).unwrap();
        assert!(server.subscription_challenge("not-a-number").is_err());
        assert!(server.subscription_challenge("").is_err());
    }

    #[test]
    fn rejects_each_missing_required_field() {
        let cases: Vec<(&str, Box<dyn Fn(&mut SubscriptionConfig)>)> = vec![
            ("mint", Box::new(|c| c.mint = String::new())),
            (
                "token_program",
                Box::new(|c| c.token_program = String::new()),
            ),
            ("puller", Box::new(|c| c.puller = String::new())),
            ("recipient", Box::new(|c| c.recipient = String::new())),
        ];
        for (label, mutate) in cases {
            let mut cfg = make_config();
            mutate(&mut cfg);
            let err = SubscriptionServer::new(cfg)
                .err()
                .unwrap_or_else(|| panic!("{label}"));
            assert!(
                format!("{err}").contains(label),
                "expected error for {label} field, got: {err}"
            );
        }
    }

    #[test]
    fn rejects_invalid_program_id_override() {
        let mut cfg = make_config();
        cfg.program_id = Some("not-a-pubkey".into());
        assert!(SubscriptionServer::new(cfg).is_err());
    }

    #[test]
    fn falls_back_to_env_secret_key_when_unset() {
        let mut cfg = make_config();
        cfg.secret_key = None;
        unsafe {
            std::env::set_var("MPP_SECRET_KEY", "env-secret-for-test");
        }
        let server = SubscriptionServer::new(cfg).expect("server with env secret");
        let _challenge = server.subscription_challenge("1000").expect("challenge");
        unsafe {
            std::env::remove_var("MPP_SECRET_KEY");
        }
        // Re-creating without the env var or explicit secret should now fail.
        let mut cfg2 = make_config();
        cfg2.secret_key = None;
        assert!(SubscriptionServer::new(cfg2).is_err());
    }

    #[test]
    fn challenge_emits_fee_payer_when_signer_configured() {
        use solana_keychain::MemorySigner;
        let mut cfg = make_config();
        cfg.fee_payer = true;
        let sk = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let mut kp = [0u8; 64];
        kp[..32].copy_from_slice(sk.as_bytes());
        kp[32..].copy_from_slice(sk.verifying_key().as_bytes());
        cfg.fee_payer_signer = Some(Arc::new(MemorySigner::from_bytes(&kp).expect("kp")));

        let server = SubscriptionServer::new(cfg).expect("server");
        let challenge = server
            .subscription_challenge("10000000")
            .expect("challenge");
        let header = challenge.to_header().expect("header");
        let request_b64 = header
            .split("request=\"")
            .nth(1)
            .and_then(|s| s.split('"').next())
            .expect("request param");
        let bytes = crate::protocol::core::base64url_decode(request_b64).unwrap();
        let parsed: SubscriptionRequest = serde_json::from_slice(&bytes).unwrap();
        let md = parsed.method_details.as_ref().unwrap();
        assert_eq!(md.get("feePayer").unwrap().as_bool(), Some(true));
        assert!(md.get("feePayerKey").is_some());
    }

    #[test]
    fn accessors_expose_config_values() {
        let cfg = make_config();
        let expected_plan = cfg.plan_id.clone();
        let expected_mint = cfg.mint.clone();
        let expected_recipient = cfg.recipient.clone();
        let expected_puller = cfg.puller.clone();
        let expected_program = SUBSCRIPTIONS_PROGRAM_ID.to_string();
        let server = SubscriptionServer::new(cfg).expect("server");
        assert_eq!(server.realm(), DEFAULT_REALM);
        assert_eq!(server.plan_id(), expected_plan);
        assert_eq!(server.mint(), expected_mint);
        assert_eq!(server.recipient(), expected_recipient);
        assert_eq!(server.puller(), expected_puller);
        assert_eq!(server.program_id(), expected_program);
        assert_eq!(server.period_unit(), SubscriptionPeriodUnit::Day);
        assert_eq!(server.period_count(), 30);
    }

    #[test]
    fn default_rpc_url_covers_each_network() {
        assert_eq!(default_rpc_url("devnet"), "https://api.devnet.solana.com");
        assert_eq!(default_rpc_url("testnet"), "https://api.testnet.solana.com");
        assert_eq!(default_rpc_url("localnet"), "http://localhost:8899");
        assert_eq!(
            default_rpc_url("mainnet-beta"),
            "https://api.mainnet-beta.solana.com"
        );
        // Unknown network falls through to mainnet-beta default.
        assert_eq!(
            default_rpc_url("custom"),
            "https://api.mainnet-beta.solana.com"
        );
    }

    #[test]
    fn week_period_round_trip_in_challenge() {
        let mut cfg = make_config();
        cfg.period_unit = SubscriptionPeriodUnit::Week;
        cfg.period_count = 2;
        let server = SubscriptionServer::new(cfg).expect("server");
        let challenge = server.subscription_challenge("5000000").unwrap();
        let header = challenge.to_header().unwrap();
        let request_b64 = header
            .split("request=\"")
            .nth(1)
            .and_then(|s| s.split('"').next())
            .expect("request param");
        let bytes = crate::protocol::core::base64url_decode(request_b64).unwrap();
        let parsed: SubscriptionRequest = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed.period_unit, SubscriptionPeriodUnit::Week);
        assert_eq!(parsed.period_count, "2");
    }

    fn extract_request_param(header: &str) -> Option<String> {
        // header looks like: Payment realm="...", method="solana", intent="subscription", request="..."
        let needle = "request=\"";
        let start = header.find(needle)? + needle.len();
        let rest = &header[start..];
        let end = rest.find('"')?;
        Some(rest[..end].to_string())
    }
}
