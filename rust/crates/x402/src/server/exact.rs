use std::sync::Arc;

use solana_pubkey::Pubkey;
use solana_rpc_client::rpc_client::RpcClient;
use solana_transaction::versioned::VersionedTransaction;
use std::str::FromStr;

use crate::{
    error::Error,
    protocol::schemes::exact::{
        caip2_network_for_cluster, cluster_for_caip2_network, default_rpc_url, fetch_transaction,
        verify_exact_versioned_transaction, verify_transaction_details, PaymentConfig,
        PaymentProof, PaymentRequiredEnvelope, PaymentRequirements, PaymentSignatureEnvelope,
        EXACT_SCHEME,
    },
    PAYMENT_REQUIRED_HEADER, PAYMENT_SIGNATURE_HEADER, X402_VERSION_V1, X402_VERSION_V2,
};

/// Server configuration for Solana x402 `exact`.
#[derive(Debug, Clone)]
pub struct Config {
    pub recipient: String,
    /// Default currency. Routes that don't specify a per-option override use
    /// this value.
    pub currency: String,
    /// Default decimals for the configured currency.
    pub decimals: u8,
    pub network: String,
    pub rpc_url: Option<String>,
    pub resource: String,
    pub description: Option<String>,
    pub max_age: Option<u64>,
    pub token_program: Option<String>,
    /// Universe of currencies this server is willing to accept.
    ///
    /// `None` means single-currency mode and only `currency` is accepted —
    /// the Tier-2 backstop in `verify_pinned_fields` checks for an exact
    /// match against `currency`. To accept multiple currencies (e.g.
    /// USDC plus PYUSD) set this to `Some(vec!["USDC".into(), "PYUSD".into()])`.
    /// Tier-2 then checks that the matched route requirement's currency is
    /// in this list.
    pub accepted_currencies: Option<Vec<String>>,
    /// Address of the facilitator that will co-sign as fee payer. When
    /// `Some`, every requirement built by `exact_requirements*` is
    /// automatically enhanced with `fee_payer: true` and
    /// `fee_payer_key: <this>` — mirrors the canonical x402 SVM scheme's
    /// `enhancePaymentRequirements`. Build the 402 envelope and rebuild
    /// the route's expected requirements at verify time go through the
    /// same path, so structural deepEqual matching is stable.
    pub fee_payer_key: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            recipient: String::new(),
            currency: "USDC".to_string(),
            decimals: 6,
            network: "mainnet-beta".to_string(),
            rpc_url: None,
            resource: String::new(),
            description: None,
            max_age: None,
            token_program: None,
            accepted_currencies: None,
            fee_payer_key: None,
        }
    }
}

/// Options for generating an `exact` payment requirement.
#[derive(Debug, Clone, Default)]
pub struct ExactOptions<'a> {
    pub description: Option<&'a str>,
    pub resource: Option<&'a str>,
    pub max_age: Option<u64>,
}

/// One payment option offered by a multi-currency route.
///
/// Mirrors the canonical x402 TS `buildPaymentRequirementsFromOptions` shape:
/// a route can advertise multiple currency/amount pairs, and the client
/// picks one to pay in. Combine with [`X402::process_payment_with_options`]
/// to verify a credential against the offered set.
#[derive(Debug, Clone)]
pub struct PaymentOption<'a> {
    /// Human-decimal amount in the option's currency (e.g. `"1.0"`).
    pub amount: &'a str,
    /// Override `Config.currency` for this option. Falls back to
    /// `Config.currency` when `None`.
    pub currency: Option<&'a str>,
    /// Override `Config.decimals` for this option (required when overriding
    /// `currency` if the new currency uses different decimals).
    pub decimals: Option<u8>,
    /// Override `Config.token_program` for this option.
    pub token_program: Option<&'a str>,
    /// Per-option presentation/binding fields (description, resource,
    /// max_age) — same as [`ExactOptions`].
    pub extra: ExactOptions<'a>,
}

impl<'a> PaymentOption<'a> {
    /// Construct the simplest possible option: just an amount, using the
    /// X402 instance's default currency/decimals.
    pub fn new(amount: &'a str) -> Self {
        Self {
            amount,
            currency: None,
            decimals: None,
            token_program: None,
            extra: ExactOptions::default(),
        }
    }
}

/// Parsed and validated x402 payment proof for the Solana `exact` scheme.
#[derive(Debug)]
pub enum VerifiedExactPayment {
    Transaction(VersionedTransaction),
    Signature(String),
}

/// Server-side payment handler for Solana x402.
#[derive(Clone)]
pub struct X402 {
    rpc: Arc<RpcClient>,
    config: Config,
}

impl X402 {
    pub fn new(config: Config) -> Result<Self, Error> {
        if config.recipient.is_empty() {
            return Err(Error::Other("recipient is required".into()));
        }
        Pubkey::from_str(&config.recipient)
            .map_err(|e| Error::Other(format!("Invalid recipient pubkey: {e}")))?;

        let rpc_url = config
            .rpc_url
            .clone()
            .unwrap_or_else(|| default_rpc_url(&config.network).to_string());

        Ok(Self {
            rpc: Arc::new(RpcClient::new(rpc_url)),
            config,
        })
    }

    pub fn recipient(&self) -> &str {
        &self.config.recipient
    }

    pub fn currency(&self) -> &str {
        &self.config.currency
    }

    pub fn decimals(&self) -> u8 {
        self.config.decimals
    }

    pub fn network(&self) -> &str {
        &self.config.network
    }

    pub fn rpc_url(&self) -> String {
        self.config
            .rpc_url
            .clone()
            .unwrap_or_else(|| default_rpc_url(&self.config.network).to_string())
    }

    pub fn exact(&self, amount: &str) -> Result<PaymentRequiredEnvelope, Error> {
        self.exact_with_options(amount, ExactOptions::default())
    }

    pub fn exact_with_options(
        &self,
        amount: &str,
        options: ExactOptions<'_>,
    ) -> Result<PaymentRequiredEnvelope, Error> {
        let requirements = self.exact_requirements(amount, options)?;
        Ok(PaymentRequiredEnvelope {
            x402_version: X402_VERSION_V2,
            resource: requirements.resource_info(),
            accepts: vec![requirements],
            error: None,
            extensions: None,
        })
    }

    pub fn exact_requirements(
        &self,
        amount: &str,
        options: ExactOptions<'_>,
    ) -> Result<PaymentRequirements, Error> {
        self.exact_requirements_for_option(&PaymentOption {
            amount,
            currency: None,
            decimals: None,
            token_program: None,
            extra: options,
        })
    }

    /// Build requirements for one specific payment option. Used by the
    /// multi-currency entry [`X402::exact_with_payment_options`] and
    /// [`X402::process_payment_with_options`].
    pub fn exact_requirements_for_option(
        &self,
        option: &PaymentOption<'_>,
    ) -> Result<PaymentRequirements, Error> {
        let currency = option.currency.unwrap_or(self.config.currency.as_str());
        let decimals = option.decimals.unwrap_or(self.config.decimals);
        // `Config.token_program` is the override for `Config.currency`. When
        // an option supplies a different currency, fall back to None and let
        // `PaymentConfig::to_requirements` derive the correct token program
        // (TOKEN vs TOKEN_2022) from the per-option currency.
        let token_program = option.token_program.map(str::to_string).or_else(|| {
            if option.currency.is_some() {
                None
            } else {
                self.config.token_program.clone()
            }
        });

        let base_units = parse_units(option.amount, decimals)?;
        let cluster = cluster_for_caip2_network(&self.config.network)
            .map(|_| self.config.network.as_str())
            .unwrap_or(self.config.network.as_str());

        let payment_config = PaymentConfig {
            recipient: self.config.recipient.clone(),
            cluster: cluster.to_string(),
            rpc_url: self.config.rpc_url.clone(),
            currency: currency.to_string(),
            decimals: Some(decimals),
            token_program,
            amount: base_units,
            resource: option
                .extra
                .resource
                .map(str::to_string)
                .unwrap_or_else(|| self.config.resource.clone()),
            description: option
                .extra
                .description
                .map(str::to_string)
                .or_else(|| self.config.description.clone()),
            max_age: option.extra.max_age.or(self.config.max_age),
        };

        let mut requirements = payment_config.to_requirements();
        requirements.network = caip2_network_for_cluster(cluster).to_string();
        requirements.cluster = Some(cluster.to_string());
        // Apply the facilitator-fee-payer enhancement so the 402 envelope
        // and the verify-time rebuild produce structurally identical
        // requirements (no extra post-processing required by the caller).
        if let Some(key) = &self.config.fee_payer_key {
            requirements.fee_payer = Some(true);
            requirements.fee_payer_key = Some(key.clone());
        }
        Ok(requirements)
    }

    /// Build a 402 envelope advertising multiple payment options.
    ///
    /// The client picks one option, echoes its `accepted` shape, and submits
    /// a credential. Use [`X402::process_payment_with_options`] (with the
    /// same options list) to verify.
    pub fn exact_with_payment_options(
        &self,
        options: &[PaymentOption<'_>],
    ) -> Result<PaymentRequiredEnvelope, Error> {
        if options.is_empty() {
            return Err(Error::Other("at least one payment option is required".into()));
        }
        let mut accepts = Vec::with_capacity(options.len());
        for option in options {
            accepts.push(self.exact_requirements_for_option(option)?);
        }
        let resource = accepts[0].resource_info();
        Ok(PaymentRequiredEnvelope {
            x402_version: X402_VERSION_V2,
            resource,
            accepts,
            error: None,
            extensions: None,
        })
    }

    pub fn payment_required_header(
        &self,
        amount: &str,
        options: ExactOptions<'_>,
    ) -> Result<(String, String), Error> {
        let envelope = self.exact_with_options(amount, options)?;
        let json = serde_json::to_string(&envelope)
            .map_err(|e| Error::InvalidPaymentRequired(e.to_string()))?;
        Ok((
            PAYMENT_REQUIRED_HEADER.to_string(),
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, json.as_bytes()),
        ))
    }

    pub fn parse_payment_signature(&self, header: &str) -> Result<PaymentSignatureEnvelope, Error> {
        let decoded = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, header)
            .map_err(|e| Error::InvalidPaymentRequired(e.to_string()))?;
        let envelope: PaymentSignatureEnvelope = serde_json::from_slice(&decoded)
            .map_err(|e| Error::InvalidPaymentRequired(e.to_string()))?;

        let expected_network = caip2_network_for_cluster(&self.config.network);

        match envelope.x402_version {
            X402_VERSION_V1 => {
                let scheme = envelope.scheme.as_deref().unwrap_or_default();
                if scheme != EXACT_SCHEME {
                    return Err(Error::InvalidPayloadType(scheme.to_string()));
                }
                let network = envelope.network.as_deref().unwrap_or_default();
                if caip2_network_for_cluster(network) != expected_network {
                    return Err(Error::Other(format!(
                        "Network mismatch: expected {expected_network}, got {network}"
                    )));
                }
            }
            X402_VERSION_V2 => {
                let accepted = envelope
                    .accepted
                    .as_ref()
                    .ok_or_else(|| Error::InvalidPaymentRequired("missing accepted".to_string()))?;
                let requirements: PaymentRequirements = serde_json::from_value(accepted.clone())
                    .map_err(|e| Error::InvalidPaymentRequired(e.to_string()))?;
                if requirements.network != expected_network {
                    return Err(Error::Other(format!(
                        "Network mismatch: expected {expected_network}, got {}",
                        requirements.network
                    )));
                }
            }
            other => {
                return Err(Error::InvalidPaymentRequired(format!(
                    "Unsupported x402 version: {other}"
                )));
            }
        }

        Ok(envelope)
    }

    /// Verify a payment-signature header for a route configured with the
    /// given amount and options.
    ///
    /// This is the convenience entry point: it builds the route's expected
    /// requirements from `(amount, options)`, then verifies the credential
    /// against them. The safe path is also the easy path — the developer
    /// can never forget to thread the route's amount through verification.
    ///
    /// For advanced cases (custom `extra` fields, post-processed requirements,
    /// pre-built requirements that should not be reconstructed), use
    /// [`X402::verify_payment_signature_for_requirements`] directly.
    pub async fn process_payment(
        &self,
        header: &str,
        amount: &str,
        options: ExactOptions<'_>,
    ) -> Result<VerifiedExactPayment, Error> {
        let requirements = self.exact_requirements(amount, options)?;
        self.verify_payment_signature_for_requirements(header, &requirements)
            .await
    }

    /// Verify a credential against a multi-option route.
    ///
    /// Builds the requirements for each offered option, then finds the one
    /// the credential's `accepted` matches structurally (canonical x402 v2
    /// `findMatchingRequirements` deepEqual semantics). On match, settles
    /// using the matched option's requirements.
    ///
    /// `Config.accepted_currencies` should list every currency in `options`
    /// — Tier-2 enforces it as a defense-in-depth backstop against
    /// miswired routes that offer currencies the server isn't actually
    /// configured for.
    pub async fn process_payment_with_options(
        &self,
        header: &str,
        options: &[PaymentOption<'_>],
    ) -> Result<VerifiedExactPayment, Error> {
        if options.is_empty() {
            return Err(Error::Other("at least one payment option is required".into()));
        }
        let mut available = Vec::with_capacity(options.len());
        for option in options {
            available.push(self.exact_requirements_for_option(option)?);
        }
        let envelope = self.parse_payment_signature(header)?;
        let matched = self.find_matching_requirement(&available, &envelope)?;
        // Clone so the borrow on `available` ends before the async call.
        let matched = matched.clone();
        self.verify_envelope_payload(envelope, &matched).await
    }

    fn find_matching_requirement<'r>(
        &self,
        available: &'r [PaymentRequirements],
        envelope: &PaymentSignatureEnvelope,
    ) -> Result<&'r PaymentRequirements, Error> {
        match envelope.x402_version {
            X402_VERSION_V2 => {
                let accepted = envelope.accepted.as_ref().ok_or_else(|| {
                    Error::InvalidPaymentRequired("v2 envelope missing accepted".into())
                })?;
                // Round-trip the credential's accepted through the typed
                // PaymentRequirements so both sides are normalized via the
                // same Serialize impl, then compare canonical JSON values.
                let accepted_requirements: PaymentRequirements =
                    serde_json::from_value(accepted.clone())
                        .map_err(|e| Error::InvalidPaymentRequired(e.to_string()))?;
                let accepted_json = serde_json::to_value(&accepted_requirements)
                    .map_err(|e| Error::Other(format!("Failed to serialize accepted: {e}")))?;
                available
                    .iter()
                    .find(|requirement| {
                        serde_json::to_value(requirement)
                            .map(|json| json == accepted_json)
                            .unwrap_or(false)
                    })
                    .ok_or_else(|| {
                        Error::Other(
                            "Credential's accepted does not match any offered payment option"
                                .into(),
                        )
                    })
            }
            X402_VERSION_V1 => {
                // v1 has no per-option `accepted` — the envelope only commits
                // to a scheme + network. Every offered option for this server
                // is on the same network and scheme, so v1 multi-option means
                // "the credential accepts any of these"; pick the first.
                available.first().ok_or_else(|| {
                    Error::Other("at least one payment option is required".into())
                })
            }
            other => Err(Error::InvalidPaymentRequired(format!(
                "Unsupported x402 version: {other}"
            ))),
        }
    }

    /// Verify a payment-signature header against the route's expected
    /// requirements.
    ///
    /// `requirements` MUST come from the resource being gated — typically by
    /// calling [`X402::exact_requirements`] with the route's amount, or via
    /// the [`X402::process_payment`] convenience method. Callers must not
    /// derive `requirements` from the credential itself: x402 has no
    /// HMAC-bound challenge id, so the credential's `accepted` field is
    /// fully attacker-controlled. Trusting it would let any submitted
    /// payment (including a $0 transferChecked) satisfy any route.
    pub async fn verify_payment_signature_for_requirements(
        &self,
        header: &str,
        requirements: &PaymentRequirements,
    ) -> Result<VerifiedExactPayment, Error> {
        let envelope = self.parse_payment_signature(header)?;
        self.verify_envelope_payload(envelope, requirements).await
    }

    pub fn payment_signature_header_name(&self) -> &'static str {
        PAYMENT_SIGNATURE_HEADER
    }

    async fn verify_envelope_payload(
        &self,
        envelope: PaymentSignatureEnvelope,
        requirements: &PaymentRequirements,
    ) -> Result<VerifiedExactPayment, Error> {
        // Tier-2 pinned-field check.
        //
        // Confirms that the route's `requirements` haven't drifted from the
        // X402 instance's pinned config (e.g. a route accidentally constructs
        // requirements for a different recipient or the wrong network).
        // Defense in depth: even with a correct caller, this catches misuse
        // before a transaction is broadcast against the wrong destination.
        self.verify_pinned_fields(requirements)?;

        if let Some(accepted) = &envelope.accepted {
            let accepted_requirements: PaymentRequirements =
                serde_json::from_value(accepted.clone())
                    .map_err(|e| Error::InvalidPaymentRequired(e.to_string()))?;
            // The credential echoes the requirements it claims to be paying
            // for. We compare against the *route's* requirements (passed in
            // by the caller) — never the other way around — so a credential
            // that lies about its `accepted` is rejected before settlement.
            //
            // Targeted field checks first (give actionable error messages),
            // then a structural deepEqual backstop catches drift on any
            // field we haven't enumerated. Mirrors the canonical x402 TS
            // resource server's `findMatchingRequirements` deepEqual gate.
            if accepted_requirements.network != requirements.network {
                return Err(Error::Other(format!(
                    "Network mismatch: expected {}, got {}",
                    requirements.network, accepted_requirements.network
                )));
            }
            if accepted_requirements.amount != requirements.amount {
                return Err(Error::Other(format!(
                    "Amount mismatch: expected {}, got {}",
                    requirements.amount, accepted_requirements.amount
                )));
            }
            if accepted_requirements.recipient != requirements.recipient {
                return Err(Error::Other(
                    "Recipient mismatch: credential claims a different recipient".into(),
                ));
            }
            if accepted_requirements.currency != requirements.currency {
                return Err(Error::Other(format!(
                    "Currency mismatch: expected {}, got {}",
                    requirements.currency, accepted_requirements.currency
                )));
            }

            // Structural backstop. After the targeted checks above pass, any
            // remaining drift between credential's accepted and route's
            // requirements (description, max_age, extra, fee_payer_key,
            // resource, decimals, token_program, …) is a binding mismatch
            // by protocol. Compared via JSON values so unknown future
            // fields are covered automatically.
            let accepted_json = serde_json::to_value(&accepted_requirements)
                .map_err(|e| Error::Other(format!("Failed to serialize accepted: {e}")))?;
            let route_json = serde_json::to_value(requirements)
                .map_err(|e| Error::Other(format!("Failed to serialize requirements: {e}")))?;
            if accepted_json != route_json {
                return Err(Error::Other(
                    "Credential's accepted requirements do not structurally match this route's expected requirements".into(),
                ));
            }
        }

        match envelope.payload {
            PaymentProof::Transaction { transaction } => {
                let decoded =
                    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, transaction)
                        .map_err(|e| Error::Other(format!("Invalid transaction payload: {e}")))?;
                let tx: VersionedTransaction = bincode::deserialize(&decoded)
                    .map_err(|e| Error::Other(format!("Invalid transaction payload: {e}")))?;

                // Reject up-front if the client signed against the wrong
                // network (e.g. localnet keypair pointed at a mainnet
                // server). Cheaper and clearer than letting broadcast fail.
                //
                // Skip when the server's RPC is loopback: the check exists
                // to catch "production server saw a Surfpool-localnet
                // keypair", which is impossible to even encounter when the
                // server itself is talking to a local simulator (e.g. CI/
                // interop runs against Surfpool on 127.0.0.1).
                if !is_loopback_rpc(&self.rpc_url()) {
                    check_network_blockhash(
                        &self.config.network,
                        &tx.message.recent_blockhash().to_string(),
                    )?;
                }

                let managed_signers = managed_signers_for_requirements(requirements)?;
                verify_exact_versioned_transaction(&tx, requirements, &managed_signers)?;
                Ok(VerifiedExactPayment::Transaction(tx))
            }
            PaymentProof::Signature { signature } => {
                let tx = fetch_transaction(&self.rpc, &signature)?;
                verify_transaction_details(&tx, requirements)?;
                Ok(VerifiedExactPayment::Signature(signature))
            }
        }
    }

    /// Tier-2 pinned-field check.
    ///
    /// Compares the route's expected `requirements` against the X402
    /// instance's pinned configuration. A miswired route (e.g. one that
    /// hand-builds `PaymentRequirements` and accidentally drops the wrong
    /// recipient address) cannot accept a payment to a destination the
    /// server isn't actually configured for.
    fn verify_pinned_fields(&self, requirements: &PaymentRequirements) -> Result<(), Error> {
        let expected_network = caip2_network_for_cluster(&self.config.network);
        if requirements.network != expected_network {
            return Err(Error::Other(format!(
                "Requirements network {} does not match server-configured network {}",
                requirements.network, expected_network
            )));
        }
        if requirements.recipient != self.config.recipient {
            return Err(Error::Other(
                "Requirements recipient does not match server-configured recipient".into(),
            ));
        }
        if !self.is_accepted_currency(&requirements.currency) {
            return Err(Error::Other(format!(
                "Requirements currency {} is not in this server's accepted-currency list",
                requirements.currency
            )));
        }
        // Token program is only pinned when (a) the server config doesn't
        // declare a per-currency override list AND (b) a token program is
        // configured. Multi-currency setups vary token program per currency
        // and rely on the per-option requirement to carry the correct one.
        if self.config.accepted_currencies.is_none() {
            if let (Some(server_token_program), Some(req_token_program)) =
                (&self.config.token_program, &requirements.token_program)
            {
                if req_token_program != server_token_program {
                    return Err(Error::Other(
                        "Requirements token program does not match server-configured token program"
                            .into(),
                    ));
                }
            }
        }
        Ok(())
    }

    /// True if `currency` is one this X402 instance is configured to accept.
    /// Single-currency mode (`accepted_currencies = None`) only accepts an
    /// exact match against `Config.currency`. Multi-currency mode checks
    /// the explicit list.
    fn is_accepted_currency(&self, currency: &str) -> bool {
        if let Some(list) = &self.config.accepted_currencies {
            list.iter().any(|c| c == currency)
        } else {
            currency == self.config.currency
        }
    }
}

/// Surfpool localnet validators stamp every blockhash with this prefix so
/// servers configured for any non-`localnet` cluster can detect a
/// wrong-RPC client mistake before broadcast.
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
pub fn check_network_blockhash(network: &str, blockhash_b58: &str) -> Result<(), Error> {
    if !blockhash_b58.starts_with(SURFPOOL_BLOCKHASH_PREFIX) {
        return Ok(());
    }
    if network == LOCALNET_NETWORK {
        return Ok(());
    }
    Err(Error::WrongNetwork {
        expected: network.to_string(),
        received: LOCALNET_NETWORK.to_string(),
    })
}

/// Returns true if the URL points at a loopback host (`127.0.0.1`, `::1`,
/// or `localhost`). Used to disable the wrong-cluster anti-mistake check
/// when the server is provably running against a local simulator (Surfpool,
/// solana-test-validator, etc.).
fn is_loopback_rpc(rpc_url: &str) -> bool {
    let stripped = rpc_url
        .trim()
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .trim_start_matches("ws://")
        .trim_start_matches("wss://");
    let host_and_rest = stripped.split('/').next().unwrap_or("");
    // Strip port. IPv6 hosts are bracketed: `[::1]:8899`.
    let host = if let Some(rest) = host_and_rest.strip_prefix('[') {
        rest.split_once(']').map(|(h, _)| h).unwrap_or(rest)
    } else {
        host_and_rest.split(':').next().unwrap_or("")
    };
    matches!(host, "127.0.0.1" | "localhost" | "::1" | "0.0.0.0")
}

fn managed_signers_for_requirements(
    requirements: &PaymentRequirements,
) -> Result<Vec<Pubkey>, Error> {
    requirements
        .fee_payer_key
        .as_deref()
        .map(|fee_payer| {
            Pubkey::from_str(fee_payer)
                .map(|key| vec![key])
                .map_err(|e| Error::Other(format!("Invalid fee payer: {e}")))
        })
        .unwrap_or_else(|| Ok(Vec::new()))
}

fn parse_units(amount: &str, decimals: u8) -> Result<String, Error> {
    if amount.is_empty() {
        return Err(Error::Other("amount is required".into()));
    }
    if amount.starts_with('-') {
        return Err(Error::Other("amount must be non-negative".into()));
    }

    let mut parts = amount.split('.');
    let whole = parts.next().unwrap_or_default();
    let fractional = parts.next();
    if parts.next().is_some() {
        return Err(Error::Other(format!("Invalid amount: {amount}")));
    }

    if !whole.chars().all(|c| c.is_ascii_digit()) {
        return Err(Error::Other(format!("Invalid amount: {amount}")));
    }

    let fractional = fractional.unwrap_or_default();
    if !fractional.chars().all(|c| c.is_ascii_digit()) {
        return Err(Error::Other(format!("Invalid amount: {amount}")));
    }
    if fractional.len() > decimals as usize {
        return Err(Error::Other(format!(
            "Too many decimal places for amount: {amount}"
        )));
    }

    let mut units = whole.to_string();
    units.push_str(fractional);
    while units.len() < whole.len() + decimals as usize {
        units.push('0');
    }

    let normalized = units.trim_start_matches('0');
    Ok(if normalized.is_empty() {
        "0".to_string()
    } else {
        normalized.to_string()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        protocol::schemes::exact::{
            PaymentProof, PaymentSignatureEnvelope, EXACT_SCHEME, SOLANA_DEVNET,
        },
        X402_VERSION_V1, X402_VERSION_V2,
    };
    use solana_hash::Hash;
    use solana_message::Message;
    use solana_pubkey::Pubkey;
    use solana_system_interface::instruction as system_instruction;
    use solana_transaction::versioned::VersionedTransaction;
    use solana_transaction::Transaction;

    fn config() -> Config {
        Config {
            recipient: "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY".to_string(),
            currency: "USDC".to_string(),
            decimals: 6,
            network: "devnet".to_string(),
            rpc_url: Some("http://localhost:8899".to_string()),
            resource: "/fortune".to_string(),
            description: Some("Fortune".to_string()),
            max_age: Some(60),
            token_program: None,
            accepted_currencies: None,
            fee_payer_key: None,
        }
    }

    #[test]
    fn exact_builds_payment_required_envelope() {
        let x402 = X402::new(config()).unwrap();
        let envelope = x402.exact("1.25").unwrap();
        let req = &envelope.accepts[0];

        assert_eq!(envelope.x402_version, X402_VERSION_V2);
        assert_eq!(
            envelope.resource.as_ref().map(|r| r.url.as_str()),
            Some("/fortune")
        );
        assert_eq!(req.amount, "1250000");
        assert_eq!(req.currency, "USDC");
        assert_eq!(req.network, SOLANA_DEVNET);
        assert_eq!(req.resource, "/fortune");
    }

    #[test]
    fn constructor_and_accessors_work() {
        let cfg = config();
        let x402 = X402::new(cfg.clone()).unwrap();
        assert_eq!(x402.recipient(), cfg.recipient);
        assert_eq!(x402.currency(), cfg.currency);
        assert_eq!(x402.decimals(), cfg.decimals);
        assert_eq!(x402.network(), cfg.network);
        assert_eq!(x402.rpc_url(), cfg.rpc_url.unwrap());
    }

    #[test]
    fn constructor_rejects_invalid_recipient() {
        let mut cfg = config();
        cfg.recipient = "bad-recipient".to_string();
        assert!(X402::new(cfg).is_err());
    }

    #[test]
    fn exact_with_options_overrides_defaults() {
        let x402 = X402::new(config()).unwrap();
        let envelope = x402
            .exact_with_options(
                "2.0",
                ExactOptions {
                    description: Some("Override"),
                    resource: Some("/override"),
                    max_age: Some(120),
                },
            )
            .unwrap();
        let req = &envelope.accepts[0];
        assert_eq!(req.amount, "2000000");
        assert_eq!(req.description.as_deref(), Some("Override"));
        assert_eq!(req.resource, "/override");
        assert_eq!(req.max_age, Some(120));
    }

    #[test]
    fn exact_rejects_invalid_amounts() {
        let x402 = X402::new(config()).unwrap();
        assert!(x402.exact("").is_err());
        assert!(x402.exact("-1").is_err());
        assert!(x402.exact("abc").is_err());
        assert!(x402.exact("1.0000001").is_err());
    }

    #[test]
    fn exact_header_is_base64_json() {
        let x402 = X402::new(config()).unwrap();
        let (name, value) = x402
            .payment_required_header("0.5", ExactOptions::default())
            .unwrap();
        assert_eq!(name, PAYMENT_REQUIRED_HEADER);

        let decoded =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, value).unwrap();
        let envelope: PaymentRequiredEnvelope = serde_json::from_slice(&decoded).unwrap();
        assert_eq!(envelope.accepts[0].amount, "500000");
    }

    #[test]
    fn parse_units_handles_edges() {
        assert_eq!(parse_units("0", 6).unwrap(), "0");
        assert_eq!(parse_units("1", 6).unwrap(), "1000000");
        assert_eq!(parse_units("1.5", 6).unwrap(), "1500000");
        assert_eq!(parse_units("0.000001", 6).unwrap(), "1");
        assert!(parse_units("1.2.3", 6).is_err());
        assert!(parse_units("-1", 6).is_err());
        assert!(parse_units("1.0000001", 6).is_err());
    }

    #[test]
    fn parse_payment_header_checks_scheme_and_network() {
        let x402 = X402::new(config()).unwrap();
        let envelope = PaymentSignatureEnvelope {
            scheme: Some(EXACT_SCHEME.to_string()),
            network: Some(SOLANA_DEVNET.to_string()),
            x402_version: X402_VERSION_V1,
            accepted: None,
            resource: None,
            payload: PaymentProof::Signature {
                signature: "sig".to_string(),
            },
        };
        let header = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            serde_json::to_vec(&envelope).unwrap(),
        );

        let parsed = x402.parse_payment_signature(&header).unwrap();
        assert_eq!(parsed.scheme.as_deref(), Some(EXACT_SCHEME));
        assert_eq!(
            x402.payment_signature_header_name(),
            PAYMENT_SIGNATURE_HEADER
        );
    }

    #[test]
    fn parse_payment_signature_rejects_invalid_inputs() {
        let x402 = X402::new(config()).unwrap();
        assert!(x402.parse_payment_signature("%%%").is_err());

        let bad_json =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"not-json");
        assert!(x402.parse_payment_signature(&bad_json).is_err());

        let wrong_scheme = PaymentSignatureEnvelope {
            scheme: Some("session".to_string()),
            network: Some(SOLANA_DEVNET.to_string()),
            x402_version: X402_VERSION_V1,
            accepted: None,
            resource: None,
            payload: PaymentProof::Signature {
                signature: "sig".to_string(),
            },
        };
        let wrong_scheme = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            serde_json::to_vec(&wrong_scheme).unwrap(),
        );
        assert!(x402.parse_payment_signature(&wrong_scheme).is_err());
    }

    #[tokio::test]
    async fn verify_transaction_header_rejects_non_exact_transaction() {
        let x402 = X402::new(config()).unwrap();
        let payer = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        let ix = system_instruction::transfer(&payer, &recipient, 1000);
        let message =
            Message::new_with_blockhash(&[ix], Some(&payer), &Hash::new_from_array([9u8; 32]));
        let tx = Transaction::new_unsigned(message);
        let envelope = PaymentSignatureEnvelope {
            scheme: Some(EXACT_SCHEME.to_string()),
            network: Some(SOLANA_DEVNET.to_string()),
            x402_version: X402_VERSION_V1,
            accepted: None,
            resource: None,
            payload: PaymentProof::Transaction {
                transaction: base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    bincode::serialize(&VersionedTransaction::from(tx)).unwrap(),
                ),
            },
        };
        let header = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            serde_json::to_vec(&envelope).unwrap(),
        );

        let requirements = x402.exact_requirements("0", ExactOptions::default()).unwrap();
        assert!(x402
            .verify_payment_signature_for_requirements(&header, &requirements)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn verify_payment_signature_rejects_invalid_transaction_payload() {
        let x402 = X402::new(config()).unwrap();
        let envelope = PaymentSignatureEnvelope {
            scheme: Some(EXACT_SCHEME.to_string()),
            network: Some(SOLANA_DEVNET.to_string()),
            x402_version: X402_VERSION_V1,
            accepted: None,
            resource: None,
            payload: PaymentProof::Transaction {
                transaction: "%%%".to_string(),
            },
        };
        let header = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            serde_json::to_vec(&envelope).unwrap(),
        );
        let requirements = x402.exact_requirements("0", ExactOptions::default()).unwrap();
        assert!(x402
            .verify_payment_signature_for_requirements(&header, &requirements)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn verify_payment_signature_rejects_invalid_signature_before_rpc() {
        let x402 = X402::new(config()).unwrap();
        let envelope = PaymentSignatureEnvelope {
            scheme: Some(EXACT_SCHEME.to_string()),
            network: Some(SOLANA_DEVNET.to_string()),
            x402_version: X402_VERSION_V1,
            accepted: None,
            resource: None,
            payload: PaymentProof::Signature {
                signature: "not-a-signature".to_string(),
            },
        };
        let header = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            serde_json::to_vec(&envelope).unwrap(),
        );
        let requirements = x402.exact_requirements("0", ExactOptions::default()).unwrap();
        assert!(x402
            .verify_payment_signature_for_requirements(&header, &requirements)
            .await
            .is_err());
    }

    // ── Cross-route / Tier-2 regression tests ──────────────────────────────
    //
    // The unsafe `verify_payment_signature(header)` API was removed because
    // x402 has no HMAC binding on the envelope: trusting `envelope.accepted`
    // for the route's expected requirements would let any submitted payment
    // (including a 0-amount transferChecked) satisfy any route.
    //
    // The remaining safe entry, `verify_payment_signature_for_requirements`,
    // takes the route's expected requirements explicitly. These tests
    // confirm:
    //   1. A V2 envelope whose `accepted` lies about amount/currency/recipient
    //      is rejected before settlement, even though the rest of the
    //      envelope is well-formed.
    //   2. Tier-2 rejects a miswired route whose `requirements` don't match
    //      the X402 instance's pinned config (recipient/currency/network/
    //      token program).

    fn make_envelope_with_accepted(accepted: serde_json::Value) -> String {
        let envelope = PaymentSignatureEnvelope {
            scheme: Some(EXACT_SCHEME.to_string()),
            network: Some(SOLANA_DEVNET.to_string()),
            x402_version: X402_VERSION_V2,
            accepted: Some(accepted),
            resource: None,
            payload: PaymentProof::Signature {
                signature: "5UfDuX6nSqMzMR8W7n6K3b1GKLmaqEisBFCcYPRLjNHrCbVQJF3BVjkE7aQJMQ2Kx".to_string(),
            },
        };
        base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            serde_json::to_vec(&envelope).unwrap(),
        )
    }

    // ── Multi-currency / multi-option tests ────────────────────────────────

    /// A multi-option 402 envelope advertises every offered currency.
    #[test]
    fn exact_with_payment_options_advertises_each_option() {
        let mut cfg = config();
        cfg.accepted_currencies = Some(vec!["USDC".to_string(), "PYUSD".to_string()]);
        let x402 = X402::new(cfg).unwrap();

        let envelope = x402
            .exact_with_payment_options(&[
                PaymentOption::new("1.0"),
                PaymentOption {
                    amount: "1.0",
                    currency: Some("PYUSD"),
                    decimals: Some(6),
                    token_program: None,
                    extra: ExactOptions::default(),
                },
            ])
            .unwrap();
        assert_eq!(envelope.accepts.len(), 2);
        assert_eq!(envelope.accepts[0].currency, "USDC");
        assert_eq!(envelope.accepts[1].currency, "PYUSD");
    }

    /// A credential whose `accepted` doesn't match ANY offered option must
    /// be rejected before settlement. Differs from the single-route case in
    /// that it's specifically a "no offer matches" rejection, not a "this
    /// one offer doesn't match".
    #[tokio::test]
    async fn process_payment_with_options_rejects_unmatched_credential() {
        let mut cfg = config();
        cfg.accepted_currencies = Some(vec!["USDC".to_string(), "PYUSD".to_string()]);
        let x402 = X402::new(cfg).unwrap();

        let options = [
            PaymentOption::new("1.0"),
            PaymentOption {
                amount: "1.0",
                currency: Some("PYUSD"),
                decimals: Some(6),
                token_program: None,
                extra: ExactOptions::default(),
            },
        ];
        // Build a credential whose `accepted` claims a third currency the
        // server didn't offer.
        let mut bad_accepted = x402.exact_requirements_for_option(&options[0]).unwrap();
        bad_accepted.currency = "USDT".to_string();
        let header =
            make_envelope_with_accepted(serde_json::to_value(&bad_accepted).unwrap());

        let err = x402
            .process_payment_with_options(&header, &options)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("does not match any offered"),
            "got: {err:?}"
        );
    }

    /// Tier-2 backstop for multi-currency: even if a route hand-builds
    /// requirements with a currency the X402 instance isn't configured to
    /// accept, the verifier rejects.
    #[tokio::test]
    async fn tier2_rejects_currency_not_in_accepted_list() {
        let mut cfg = config();
        cfg.accepted_currencies = Some(vec!["USDC".to_string(), "PYUSD".to_string()]);
        let x402 = X402::new(cfg).unwrap();

        // Forge requirements for USDG (not in the accepted list).
        let mut hand_built = x402.exact_requirements("1.0", ExactOptions::default()).unwrap();
        hand_built.currency = "USDG".to_string();
        let header = make_envelope_with_accepted(serde_json::to_value(&hand_built).unwrap());

        let err = x402
            .verify_payment_signature_for_requirements(&header, &hand_built)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("not in this server's accepted-currency list"),
            "got: {err:?}"
        );
    }

    /// Single-currency mode (`accepted_currencies = None`) still works
    /// exactly as before — no regression on the default flow.
    #[tokio::test]
    async fn single_currency_mode_unchanged() {
        let x402 = X402::new(config()).unwrap();
        let route_requirements = x402.exact_requirements("1.0", ExactOptions::default()).unwrap();
        // Verify Tier-2 rejects a non-USDC route requirement when in
        // single-currency mode.
        let mut wrong = route_requirements.clone();
        wrong.currency = "PYUSD".to_string();
        let header = make_envelope_with_accepted(serde_json::to_value(&wrong).unwrap());

        let err = x402
            .verify_payment_signature_for_requirements(&header, &wrong)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not in this server's accepted-currency list"));
    }

    /// `process_payment` is the convenience entry that builds requirements
    /// from `(amount, options)` internally. A credential lying about the
    /// route's amount must be rejected the same way as via the lower-level
    /// `verify_payment_signature_for_requirements` path.
    #[tokio::test]
    async fn process_payment_rejects_cross_route_replay() {
        let x402 = X402::new(config()).unwrap();
        let route_requirements = x402.exact_requirements("1.0", ExactOptions::default()).unwrap();

        let mut lying_accepted = route_requirements.clone();
        lying_accepted.amount = "0".to_string();
        let header = make_envelope_with_accepted(serde_json::to_value(&lying_accepted).unwrap());

        let err = x402
            .process_payment(&header, "1.0", ExactOptions::default())
            .await
            .unwrap_err();
        assert!(err.to_string().to_lowercase().contains("amount"), "got: {err:?}");
    }

    /// `process_payment` and `verify_payment_signature_for_requirements`
    /// should reach the same outcome on a malformed transaction payload.
    #[tokio::test]
    async fn process_payment_threads_route_amount_into_verify() {
        let x402 = X402::new(config()).unwrap();
        let envelope = PaymentSignatureEnvelope {
            scheme: Some(EXACT_SCHEME.to_string()),
            network: Some(SOLANA_DEVNET.to_string()),
            x402_version: X402_VERSION_V1,
            accepted: None,
            resource: None,
            payload: PaymentProof::Transaction {
                transaction: "%%%".to_string(),
            },
        };
        let header = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            serde_json::to_vec(&envelope).unwrap(),
        );
        // Both paths should reject the malformed transaction payload.
        assert!(x402
            .process_payment(&header, "0", ExactOptions::default())
            .await
            .is_err());
    }

    /// Structural backstop: a wire-form field outside the targeted-check
    /// list (amount/recipient/currency/network) that drifts between the
    /// credential's `accepted` and the route's `requirements` must be
    /// caught. `maxTimeoutSeconds` (= `max_age`) is one such field; it's
    /// part of the canonical x402 v2 accepted shape but not in the
    /// targeted comparisons.
    #[tokio::test]
    async fn structural_backstop_rejects_drift_on_unenumerated_field() {
        let x402 = X402::new(config()).unwrap();
        let route_requirements = x402.exact_requirements("1.0", ExactOptions::default()).unwrap();

        let mut drifting_accepted = route_requirements.clone();
        drifting_accepted.max_age = Some(999_999);
        let header =
            make_envelope_with_accepted(serde_json::to_value(&drifting_accepted).unwrap());

        let err = x402
            .verify_payment_signature_for_requirements(&header, &route_requirements)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("structurally match"),
            "expected structural-mismatch error, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn cross_route_v2_attacker_lying_about_amount_rejected() {
        // The route gates a $1.00 payment, but the credential carries an
        // `accepted` claiming $0. Without the Tier-2 check, the verifier
        // would have used the credential's claim as the source of truth.
        let x402 = X402::new(config()).unwrap();
        let route_requirements = x402.exact_requirements("1.0", ExactOptions::default()).unwrap();

        let mut lying_accepted = route_requirements.clone();
        lying_accepted.amount = "0".to_string();
        let header = make_envelope_with_accepted(serde_json::to_value(&lying_accepted).unwrap());

        let err = x402
            .verify_payment_signature_for_requirements(&header, &route_requirements)
            .await
            .unwrap_err();
        let msg = err.to_string().to_lowercase();
        assert!(msg.contains("amount mismatch"), "got: {err:?}");
    }

    #[tokio::test]
    async fn cross_route_v2_attacker_lying_about_recipient_rejected() {
        let x402 = X402::new(config()).unwrap();
        let route_requirements = x402.exact_requirements("1.0", ExactOptions::default()).unwrap();

        let mut lying_accepted = route_requirements.clone();
        lying_accepted.recipient = Pubkey::new_unique().to_string();
        let header = make_envelope_with_accepted(serde_json::to_value(&lying_accepted).unwrap());

        let err = x402
            .verify_payment_signature_for_requirements(&header, &route_requirements)
            .await
            .unwrap_err();
        assert!(err.to_string().to_lowercase().contains("recipient"), "got: {err:?}");
    }

    #[tokio::test]
    async fn cross_route_v2_attacker_lying_about_currency_rejected() {
        let x402 = X402::new(config()).unwrap();
        let route_requirements = x402.exact_requirements("1.0", ExactOptions::default()).unwrap();

        let mut lying_accepted = route_requirements.clone();
        lying_accepted.currency = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".to_string();
        let header = make_envelope_with_accepted(serde_json::to_value(&lying_accepted).unwrap());

        let err = x402
            .verify_payment_signature_for_requirements(&header, &route_requirements)
            .await
            .unwrap_err();
        assert!(err.to_string().to_lowercase().contains("currency"), "got: {err:?}");
    }

    #[tokio::test]
    async fn tier2_rejects_miswired_route_with_wrong_recipient() {
        // Caller passes requirements with a recipient that doesn't match the
        // X402 instance's configured recipient. Even with no envelope-side
        // tampering, this must fail-closed.
        let x402 = X402::new(config()).unwrap();
        let mut wrong = x402.exact_requirements("1.0", ExactOptions::default()).unwrap();
        wrong.recipient = Pubkey::new_unique().to_string();

        let header = make_envelope_with_accepted(serde_json::to_value(&wrong).unwrap());
        let err = x402
            .verify_payment_signature_for_requirements(&header, &wrong)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("recipient"), "got: {err:?}");
    }

    #[tokio::test]
    async fn tier2_rejects_miswired_route_with_wrong_currency() {
        let x402 = X402::new(config()).unwrap();
        let mut wrong = x402.exact_requirements("1.0", ExactOptions::default()).unwrap();
        wrong.currency = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".to_string();

        let header = make_envelope_with_accepted(serde_json::to_value(&wrong).unwrap());
        let err = x402
            .verify_payment_signature_for_requirements(&header, &wrong)
            .await
            .unwrap_err();
        assert!(err.to_string().to_lowercase().contains("currency"), "got: {err:?}");
    }

    #[tokio::test]
    async fn tier2_rejects_miswired_route_with_wrong_network() {
        let x402 = X402::new(config()).unwrap();
        let mut wrong = x402.exact_requirements("1.0", ExactOptions::default()).unwrap();
        wrong.network = "solana:mainnet".to_string();

        // Envelope still claims devnet so we don't fail at parse-time.
        let header = make_envelope_with_accepted(serde_json::to_value(&wrong).unwrap());
        let err = x402
            .verify_payment_signature_for_requirements(&header, &wrong)
            .await
            .unwrap_err();
        assert!(err.to_string().to_lowercase().contains("network"), "got: {err:?}");
    }

    // ── is_loopback_rpc ────────────────────────────────────────────────────

    #[test]
    fn is_loopback_rpc_recognizes_common_local_hosts() {
        assert!(is_loopback_rpc("http://127.0.0.1:8899"));
        assert!(is_loopback_rpc("http://localhost:8899"));
        assert!(is_loopback_rpc("http://[::1]:8899"));
        assert!(is_loopback_rpc("http://0.0.0.0:8899"));
        assert!(is_loopback_rpc("ws://localhost:8900"));
        assert!(is_loopback_rpc("https://127.0.0.1/rpc"));
    }

    #[test]
    fn is_loopback_rpc_rejects_real_clusters() {
        assert!(!is_loopback_rpc("https://api.devnet.solana.com"));
        assert!(!is_loopback_rpc("https://api.mainnet-beta.solana.com"));
        assert!(!is_loopback_rpc("https://example.com:8899"));
        assert!(!is_loopback_rpc("https://127.0.0.1.attacker.com"));
    }

    // ── check_network_blockhash ────────────────────────────────────────────
    //
    // Pure function — no I/O, no async, no fixtures. The check is asymmetric:
    // a Surfpool-prefixed blockhash is only valid on `localnet`, but a
    // non-prefixed blockhash is accepted on any network (we can't tell
    // from a non-prefixed hash what real cluster it came from).

    #[test]
    fn network_check_localnet_with_surfpool_hash_ok() {
        assert!(
            check_network_blockhash("localnet", "SURFNETxSAFEHASHxxxxxxxxxxxxxxxxxxx1892bcad")
                .is_ok()
        );
    }

    #[test]
    fn network_check_localnet_with_real_hash_ok() {
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

    #[test]
    fn network_check_mainnet_rejects_surfpool_hash() {
        let err = check_network_blockhash("mainnet", "SURFNETxSAFEHASHxxxxxxxxxxxxxxxxxxx1892bcad")
            .unwrap_err();
        match &err {
            Error::WrongNetwork { expected, received } => {
                assert_eq!(expected, "mainnet");
                assert_eq!(received, "localnet");
            }
            other => panic!("expected WrongNetwork, got {other:?}"),
        }
        // The Display impl must name both sides of the mismatch and give
        // an actionable next step.
        let displayed = err.to_string();
        assert!(
            displayed.contains("Signed against localnet"),
            "missing received-side: {displayed}"
        );
        assert!(
            displayed.contains("server expects mainnet"),
            "missing expected-side: {displayed}"
        );
        assert!(
            displayed.contains("re-sign"),
            "missing actionable hint: {displayed}"
        );
    }

    #[test]
    fn network_check_devnet_rejects_surfpool_hash() {
        let err = check_network_blockhash("devnet", "SURFNETxSAFEHASHxxxxxxxxxxxxxxxxxxx1892bcad")
            .unwrap_err();
        assert!(matches!(err, Error::WrongNetwork { ref expected, .. } if expected == "devnet"));
        assert!(err.to_string().contains("server expects devnet"));
    }

    #[test]
    fn network_check_partial_prefix_does_not_match() {
        // "SURFNETx" alone (8 chars) is NOT the full prefix and must not
        // be misclassified as a Surfpool blockhash.
        assert!(check_network_blockhash("mainnet", "SURFNETx9zrUHnA1nCByPksy").is_ok());
    }

    #[test]
    fn network_check_exact_prefix_only_is_treated_as_surfpool() {
        assert!(check_network_blockhash("localnet", SURFPOOL_BLOCKHASH_PREFIX).is_ok());
        assert!(check_network_blockhash("mainnet", SURFPOOL_BLOCKHASH_PREFIX).is_err());
    }

    #[test]
    fn network_check_non_surfpool_hash_passes_anywhere() {
        // The check is asymmetric: a real-cluster-looking blockhash is
        // accepted on every network because we can't tell from a
        // non-prefixed hash which real cluster it came from.
        assert!(check_network_blockhash("mainnet", "11111111111111111111111111111111").is_ok());
        assert!(check_network_blockhash("devnet", "11111111111111111111111111111111").is_ok());
        assert!(check_network_blockhash("localnet", "11111111111111111111111111111111").is_ok());
    }
}
