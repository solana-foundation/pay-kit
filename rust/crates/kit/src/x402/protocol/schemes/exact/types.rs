use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::x402::SOLANA_NETWORK;

/// Exact payment scheme identifier.
pub const EXACT_SCHEME: &str = "exact";

/// Maximum memo bytes accepted by the canonical SVM exact scheme.
pub const MAX_MEMO_BYTES: usize = 256;

/// Solana mainnet CAIP-2 network identifier.
pub const SOLANA_MAINNET: &str = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";

/// Solana devnet CAIP-2 network identifier.
pub const SOLANA_DEVNET: &str = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1";

/// Solana testnet CAIP-2 network identifier.
pub const SOLANA_TESTNET: &str = "solana:4uhcVJyU9pJkvQyS88uRDiswHXSCkY3z";

/// Default RPC URLs per Solana cluster.
pub fn default_rpc_url(cluster: &str) -> &'static str {
    match cluster {
        "devnet" | "solana-devnet" | SOLANA_DEVNET => "https://api.devnet.solana.com",
        "testnet" | "solana-testnet" | SOLANA_TESTNET => "https://api.testnet.solana.com",
        "localnet" => "http://localhost:8899",
        _ => "https://api.mainnet-beta.solana.com",
    }
}

/// Map a cluster name to the corresponding CAIP-2 network identifier.
pub fn caip2_network_for_cluster(cluster: &str) -> &'static str {
    match cluster {
        SOLANA_MAINNET | SOLANA_NETWORK | "mainnet" | "mainnet-beta" => SOLANA_MAINNET,
        SOLANA_TESTNET | "testnet" | "solana-testnet" => SOLANA_TESTNET,
        "devnet" | "localnet" => SOLANA_DEVNET,
        SOLANA_DEVNET | "solana-devnet" => SOLANA_DEVNET,
        _ => SOLANA_MAINNET,
    }
}

/// Map a CAIP-2 network identifier back to a Solana cluster name.
pub fn cluster_for_caip2_network(network: &str) -> Option<&'static str> {
    match network {
        SOLANA_NETWORK | "mainnet" | "mainnet-beta" => Some("mainnet-beta"),
        "solana-devnet" | "devnet" | "localnet" => Some("devnet"),
        "solana-testnet" | "testnet" => Some("testnet"),
        SOLANA_MAINNET => Some("mainnet-beta"),
        SOLANA_DEVNET => Some("devnet"),
        SOLANA_TESTNET => Some("testnet"),
        _ if network.starts_with("solana:") => Some("mainnet-beta"),
        _ => None,
    }
}

/// Well-known program addresses.
pub mod programs {
    pub const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
    pub const TOKEN_2022_PROGRAM: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
    pub const ASSOCIATED_TOKEN_PROGRAM: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
    pub const COMPUTE_BUDGET_PROGRAM: &str = "ComputeBudget111111111111111111111111111111";
    pub const SYSTEM_PROGRAM: &str = "11111111111111111111111111111111";
    pub const MEMO_PROGRAM: &str = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";
    pub const LIGHTHOUSE_PROGRAM: &str = "L2TExMFKdjpN9kozasaurPirfHy9P8sbXoAN1qA3S95";
}

/// Well-known stablecoin mint addresses.
/// Canonical stablecoin mint addresses.
///
/// Re-exported from [`crate::core::mints`] — the single source of truth
/// shared with `solana-mpp`. Don't add literals here; add them in core.
pub mod mints {
    pub use crate::core::mints::*;
}

/// True if `currency` (symbol or mint address) represents native SOL.
///
/// Centralizes what was scattered as `currency.eq_ignore_ascii_case("SOL")`
/// across the codebase. Use this anywhere you need to branch on the
/// SOL-vs-SPL distinction.
pub fn is_native_sol(currency: &str) -> bool {
    currency.eq_ignore_ascii_case("SOL")
}

/// Resolve a stablecoin symbol to a mint address for a cluster.
///
/// Returns `None` for native SOL and passes through unknown symbols/mints.
pub fn resolve_stablecoin_mint<'a>(currency: &'a str, cluster: Option<&str>) -> Option<&'a str> {
    if is_native_sol(currency) {
        return None;
    }
    match currency.to_uppercase().as_str() {
        "USDC" => Some(match cluster {
            Some(SOLANA_DEVNET) | Some("devnet") | Some("localnet") => mints::USDC_DEVNET,
            Some(SOLANA_TESTNET) | Some("testnet") => mints::USDC_TESTNET,
            _ => mints::USDC_MAINNET,
        }),
        "USDT" => Some(mints::USDT_MAINNET),
        "USDG" => Some(match cluster {
            Some(SOLANA_DEVNET) | Some("devnet") | Some("localnet") => mints::USDG_DEVNET,
            Some(SOLANA_TESTNET) | Some("testnet") => mints::USDG_TESTNET,
            _ => mints::USDG_MAINNET,
        }),
        "PYUSD" => Some(match cluster {
            Some(SOLANA_DEVNET) | Some("devnet") | Some("localnet") => mints::PYUSD_DEVNET,
            Some(SOLANA_TESTNET) | Some("testnet") => mints::PYUSD_TESTNET,
            _ => mints::PYUSD_MAINNET,
        }),
        "CASH" => Some(mints::CASH_MAINNET),
        _ => Some(currency),
    }
}

/// Reverse lookup: given a known mint address or stablecoin symbol, return
/// the canonical symbol. Returns `None` for native SOL or unknown values.
///
/// Mirrors the Python and Lua MPP SDK helpers — useful for displaying a
/// human-readable currency next to a credential's claimed mint, or for
/// branching on the family of known stablecoins.
pub fn stablecoin_symbol(currency_or_mint: &str) -> Option<&'static str> {
    if is_native_sol(currency_or_mint) {
        return None;
    }
    let upper = currency_or_mint.to_uppercase();
    match upper.as_str() {
        "USDC" => Some("USDC"),
        "USDT" => Some("USDT"),
        "USDG" => Some("USDG"),
        "PYUSD" => Some("PYUSD"),
        "CASH" => Some("CASH"),
        _ => match currency_or_mint {
            mints::USDC_MAINNET | mints::USDC_DEVNET => Some("USDC"),
            mints::USDT_MAINNET => Some("USDT"),
            mints::USDG_MAINNET | mints::USDG_DEVNET => Some("USDG"),
            mints::PYUSD_MAINNET | mints::PYUSD_DEVNET => Some("PYUSD"),
            mints::CASH_MAINNET => Some("CASH"),
            _ => None,
        },
    }
}

/// True if a stablecoin (by symbol or mint) uses the SPL Token-2022 program
/// rather than the legacy SPL Token program. Default for unknowns is
/// `false` (legacy program).
pub fn stablecoin_uses_token_2022(currency_or_mint: &str) -> bool {
    matches!(
        stablecoin_symbol(currency_or_mint),
        Some("USDG") | Some("PYUSD") | Some("CASH")
    )
}

/// Default token program for a currency or mint.
pub fn default_token_program_for_currency(currency: &str, cluster: Option<&str>) -> &'static str {
    let mint = resolve_stablecoin_mint(currency, cluster).unwrap_or(currency);
    if stablecoin_uses_token_2022(mint) {
        programs::TOKEN_2022_PROGRAM
    } else {
        programs::TOKEN_PROGRAM
    }
}

/// Resource metadata carried by canonical x402 v2 payment-required responses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceInfo {
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
}

/// Solana payment requirements for the x402 `exact` scheme.
///
/// The Rust API keeps normalized field names for older callers, while serde
/// accepts legacy v1 and canonical v2 wire shapes. Serialization emits the
/// canonical v2 `PaymentRequirements` shape expected by `@x402/svm`.
#[derive(Debug, Clone)]
pub struct PaymentRequirements {
    /// CAIP-2 network identifier.
    pub network: String,

    /// Solana cluster: mainnet-beta, devnet, or localnet.
    pub cluster: Option<String>,

    /// Base58-encoded recipient public key.
    pub recipient: String,

    /// Amount in base units (lamports or token smallest unit).
    pub amount: String,

    /// Currency: "SOL", "USDC", or a mint address.
    pub currency: String,

    /// Token decimals (required for SPL tokens).
    pub decimals: Option<u8>,

    /// Token program address.
    pub token_program: Option<String>,

    /// Unique resource identifier for this payment.
    pub resource: String,

    /// Human-readable description of what is being paid for.
    pub description: Option<String>,

    /// Maximum age in seconds for the payment to remain valid.
    pub max_age: Option<u64>,

    /// Server-provided recent blockhash.
    pub recent_blockhash: Option<String>,

    /// If true, server pays transaction fees.
    pub fee_payer: Option<bool>,

    /// Server's fee payer public key.
    pub fee_payer_key: Option<String>,

    /// Extra protocol-specific data.
    pub extra: Option<serde_json::Value>,

    /// Original canonical accepted object from a v2 challenge, when parsed.
    pub accepted: Option<serde_json::Value>,

    /// Original v2 resource metadata, when parsed.
    pub resource_info: Option<ResourceInfo>,
}

impl PaymentRequirements {
    /// Canonical v2 accepted object for the selected SVM exact requirement.
    pub fn to_accepted_value(&self) -> serde_json::Value {
        if let Some(accepted) = &self.accepted {
            return accepted.clone();
        }

        serde_json::json!({
            "scheme": "exact",
            "network": self.network.clone(),
            "amount": self.amount.clone(),
            "asset": self.currency.clone(),
            "payTo": self.recipient.clone(),
            "maxTimeoutSeconds": self.max_age.unwrap_or(300),
            "extra": self.canonical_extra_value(),
        })
    }

    /// Canonical v2 resource object associated with this requirement.
    pub fn resource_info(&self) -> Option<ResourceInfo> {
        self.resource_info.clone().or_else(|| {
            if self.resource.is_empty() {
                None
            } else {
                Some(ResourceInfo {
                    url: self.resource.clone(),
                    description: self.description.clone(),
                    mime_type: None,
                })
            }
        })
    }

    fn canonical_extra_value(&self) -> serde_json::Value {
        let mut extra = self
            .extra
            .as_ref()
            .and_then(|value| value.as_object().cloned())
            .unwrap_or_default();

        if let Some(fee_payer) = &self.fee_payer_key {
            extra
                .entry("feePayer".to_string())
                .or_insert_with(|| serde_json::Value::String(fee_payer.clone()));
        }
        if let Some(recent_blockhash) = &self.recent_blockhash {
            extra
                .entry("recentBlockhash".to_string())
                .or_insert_with(|| serde_json::Value::String(recent_blockhash.clone()));
        }
        if let Some(token_program) = &self.token_program {
            extra
                .entry("tokenProgram".to_string())
                .or_insert_with(|| serde_json::Value::String(token_program.clone()));
        }
        if let Some(decimals) = self.decimals {
            extra
                .entry("decimals".to_string())
                .or_insert_with(|| serde_json::Value::from(decimals));
        }

        serde_json::Value::Object(extra)
    }
}

impl Serialize for PaymentRequirements {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.to_accepted_value().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for PaymentRequirements {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        let object = value
            .as_object()
            .ok_or_else(|| serde::de::Error::custom("payment requirement must be an object"))?;

        let raw_network =
            string_field(object, "network").unwrap_or_else(|| SOLANA_NETWORK.to_string());
        let network = normalize_network_identifier(&raw_network);
        let cluster = string_field(object, "cluster").or_else(|| {
            cluster_for_caip2_network(&network).map(|cluster| {
                if raw_network.starts_with("solana:") {
                    raw_network.clone()
                } else {
                    cluster.to_string()
                }
            })
        });

        let extra = object.get("extra").cloned();
        let extra_object = extra.as_ref().and_then(|value| value.as_object());

        let recipient = string_field(object, "recipient")
            .or_else(|| string_field(object, "payTo"))
            .unwrap_or_default();
        let amount = string_field(object, "amount")
            .or_else(|| string_field(object, "maxAmountRequired"))
            .unwrap_or_default();
        let currency = string_field(object, "currency")
            .or_else(|| string_field(object, "asset"))
            .unwrap_or_else(|| "SOL".to_string());

        let decimals = u8_field(object, "decimals")
            .or_else(|| extra_object.and_then(|extra| u8_field(extra, "decimals")));
        let token_program = string_field(object, "tokenProgram")
            .or_else(|| extra_object.and_then(|extra| string_field(extra, "tokenProgram")));
        let recent_blockhash = string_field(object, "recentBlockhash")
            .or_else(|| extra_object.and_then(|extra| string_field(extra, "recentBlockhash")));
        let fee_payer_key = string_field(object, "feePayerKey")
            .or_else(|| extra_object.and_then(|extra| string_field(extra, "feePayer")));
        let fee_payer =
            bool_field(object, "feePayer").or_else(|| fee_payer_key.as_ref().map(|_| true));
        let max_age =
            u64_field(object, "maxAge").or_else(|| u64_field(object, "maxTimeoutSeconds"));

        let accepted = if object.contains_key("amount")
            && object.contains_key("asset")
            && object.contains_key("payTo")
        {
            Some(value.clone())
        } else {
            None
        };

        Ok(Self {
            network,
            cluster,
            recipient,
            amount,
            currency,
            decimals,
            token_program,
            resource: string_field(object, "resource").unwrap_or_default(),
            description: string_field(object, "description"),
            max_age,
            recent_blockhash,
            fee_payer,
            fee_payer_key,
            extra,
            accepted,
            resource_info: None,
        })
    }
}

fn normalize_network_identifier(network: &str) -> String {
    match network {
        SOLANA_NETWORK | "mainnet" | "mainnet-beta" => SOLANA_MAINNET.to_string(),
        "solana-devnet" | "devnet" | "localnet" => SOLANA_DEVNET.to_string(),
        "solana-testnet" | "testnet" => SOLANA_TESTNET.to_string(),
        value if value.starts_with("solana:") => value.to_string(),
        value => value.to_string(),
    }
}

fn string_field(object: &serde_json::Map<String, serde_json::Value>, key: &str) -> Option<String> {
    object
        .get(key)
        .and_then(|value| value.as_str())
        .map(str::to_string)
}

fn u64_field(object: &serde_json::Map<String, serde_json::Value>, key: &str) -> Option<u64> {
    object.get(key).and_then(|value| value.as_u64())
}

fn u8_field(object: &serde_json::Map<String, serde_json::Value>, key: &str) -> Option<u8> {
    u64_field(object, key).and_then(|value| u8::try_from(value).ok())
}

fn bool_field(object: &serde_json::Map<String, serde_json::Value>, key: &str) -> Option<bool> {
    object.get(key).and_then(|value| value.as_bool())
}

/// Solana payment payload sent by the client for the x402 `exact` scheme.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentPayload {
    /// CAIP-2 network identifier (must match requirements).
    pub network: String,

    /// The payment proof.
    #[serde(flatten)]
    pub proof: PaymentProof,
}

/// Payment proof — either a signed transaction or a confirmed signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PaymentProof {
    /// Client sends signed transaction bytes for server to broadcast.
    #[serde(rename = "transaction")]
    Transaction {
        /// Base64-encoded serialized signed transaction.
        transaction: String,
    },
    /// Client broadcasts and sends confirmed signature.
    #[serde(rename = "signature")]
    Signature {
        /// Base58-encoded transaction signature.
        signature: String,
    },
}

/// Wire envelope carried in `PAYMENT-REQUIRED`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentRequiredEnvelope {
    pub x402_version: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<ResourceInfo>,
    #[serde(default)]
    pub accepts: Vec<PaymentRequirements>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<serde_json::Value>,
}

impl PaymentRequiredEnvelope {
    /// Attach top-level v2 resource metadata to parsed accepts.
    pub fn with_resource_on_accepts(mut self) -> Self {
        if let Some(resource) = &self.resource {
            for accept in &mut self.accepts {
                accept.resource_info = Some(resource.clone());
                if accept.resource.is_empty() {
                    accept.resource = resource.url.clone();
                }
                if accept.description.is_none() {
                    accept.description = resource.description.clone();
                }
            }
        }
        self
    }
}

/// Client/server-side fields of the `payment-identifier` extension.
/// See <https://github.com/coinbase/x402/blob/main/specs/extensions/payment_identifier.md>.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentIdentifierInfo {
    /// Server-side: whether clients MUST populate `id`. When `true` and
    /// `id` is missing, the server returns 400.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
    /// Client-side idempotency key. Must match `^[A-Za-z0-9_-]{16,128}$`.
    /// Canonical Solana implementations use a `pay_` prefix, e.g.
    /// `pay_7d5d747be160e280504c099d984bcfe0`. Generate with
    /// [`generate_payment_identifier_id`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

/// The `payment-identifier` extension. Echoed by the client into the
/// outbound `PAYMENT-SIGNATURE` with `info.id` populated.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentIdentifierExtension {
    #[serde(default)]
    pub info: PaymentIdentifierInfo,
    /// JSON Schema published by the server describing the required
    /// client-side fields. Echoed verbatim per x402 v2 §5.1.2.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<serde_json::Value>,
}

/// Typed view over the x402 v2 `extensions` object on
/// [`PaymentSignatureEnvelope`]. Known extensions are fielded out
/// directly; unknown ones flow through `other` so the echo-and-append
/// rule (§5.1.2) doesn't drop forward-compatible payloads.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PaymentExtensions {
    /// The `payment-identifier` idempotency extension. Some providers
    /// (e.g. Birdeye) mark this `info.required = true` and reject
    /// requests that don't echo a `pay_…` id back.
    #[serde(
        rename = "payment-identifier",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub payment_identifier: Option<PaymentIdentifierExtension>,
    /// Forward-compatible storage for extensions this crate does not
    /// type natively. Captured during echo, re-emitted verbatim.
    #[serde(flatten)]
    pub other: std::collections::BTreeMap<String, serde_json::Value>,
}

impl PaymentExtensions {
    /// True when no fields are populated. Useful so callers can avoid
    /// emitting an empty `extensions: {}` object on outbound envelopes.
    pub fn is_empty(&self) -> bool {
        self.payment_identifier.is_none() && self.other.is_empty()
    }

    /// `payment-identifier.info.required == Some(true)`.
    pub fn requires_payment_identifier(&self) -> bool {
        self.payment_identifier
            .as_ref()
            .and_then(|p| p.info.required)
            .unwrap_or(false)
    }

    /// Set (or overwrite) the client-side `payment-identifier.info.id`.
    /// Creates the extension entry if the server didn't advertise one
    /// — uncommon but spec-allowed.
    pub fn with_payment_identifier_id(mut self, id: impl Into<String>) -> Self {
        let entry = self.payment_identifier.get_or_insert_with(Default::default);
        entry.info.id = Some(id.into());
        self
    }

    /// Echo a server's inbound extensions blob (e.g. the
    /// `extensions: serde_json::Value` carried on
    /// [`PaymentRequiredEnvelope`]) into a typed
    /// [`PaymentExtensions`]. Returns `Ok(None)` when the inbound is
    /// `None`. Errors only if the inbound is not a JSON object.
    pub fn echoing(inbound: Option<&serde_json::Value>) -> Result<Option<Self>, serde_json::Error> {
        match inbound {
            Some(value) => serde_json::from_value(value.clone()).map(Some),
            None => Ok(None),
        }
    }
}

/// Generate a fresh `pay_`-prefixed idempotency id (32 hex chars after
/// the prefix; 36 total). Satisfies the `payment-identifier` spec
/// pattern `^[A-Za-z0-9_-]{16,128}$` and the canonical Solana
/// `^pay_[a-zA-Z0-9_-]{10,120}$` shape.
///
/// Per the spec, callers must reuse the same id across retries of the
/// same logical request so the server can return a cached 200 instead
/// of charging twice.
pub fn generate_payment_identifier_id() -> String {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).expect("getrandom CSPRNG failure");
    let mut id = String::with_capacity(4 + 32);
    id.push_str("pay_");
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(id, "{b:02x}");
    }
    id
}

/// Wire envelope carried in `PAYMENT-SIGNATURE`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentSignatureEnvelope {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scheme: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    pub x402_version: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accepted: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<ResourceInfo>,
    pub payload: PaymentProof,
    /// Echoed extensions from the inbound `PAYMENT-REQUIRED` envelope,
    /// with any required client-supplied fields filled in
    /// (e.g. `payment-identifier.info.id`). Per x402 v2 §5.1.2, the
    /// client "must include at least the info received; it may append
    /// additional info but cannot delete or overwrite existing info".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<PaymentExtensions>,
}

/// Server-side payment configuration for x402-protected resources.
#[derive(Debug, Clone)]
pub struct PaymentConfig {
    /// Base58-encoded recipient public key.
    pub recipient: String,
    /// Solana cluster.
    pub cluster: String,
    /// RPC URL (overrides default for the cluster).
    pub rpc_url: Option<String>,
    /// Currency: "SOL", "USDC", or a mint address.
    pub currency: String,
    /// Token decimals.
    pub decimals: Option<u8>,
    /// Token program address.
    pub token_program: Option<String>,
    /// Amount in base units.
    pub amount: String,
    /// Resource identifier.
    pub resource: String,
    /// Human-readable description.
    pub description: Option<String>,
    /// Maximum age in seconds for payment validity.
    pub max_age: Option<u64>,
}

impl PaymentConfig {
    /// Get the effective RPC URL.
    pub fn rpc_url(&self) -> String {
        self.rpc_url
            .clone()
            .unwrap_or_else(|| default_rpc_url(&self.cluster).to_string())
    }

    /// Get the effective token program.
    pub fn token_program(&self) -> &str {
        self.token_program.as_deref().unwrap_or_else(|| {
            default_token_program_for_currency(&self.currency, Some(&self.cluster))
        })
    }

    /// Build the `PaymentRequirements` to include in a 402 response.
    pub fn to_requirements(&self) -> PaymentRequirements {
        let token_program = self.token_program.clone().or_else(|| {
            let default = default_token_program_for_currency(&self.currency, Some(&self.cluster));
            (default != programs::TOKEN_PROGRAM).then(|| default.to_string())
        });

        PaymentRequirements {
            network: caip2_network_for_cluster(&self.cluster).to_string(),
            cluster: Some(self.cluster.clone()),
            recipient: self.recipient.clone(),
            amount: self.amount.clone(),
            currency: self.currency.clone(),
            decimals: self.decimals,
            token_program,
            resource: self.resource.clone(),
            description: self.description.clone(),
            max_age: self.max_age,
            recent_blockhash: None,
            fee_payer: None,
            fee_payer_key: None,
            extra: None,
            accepted: None,
            resource_info: Some(ResourceInfo {
                url: self.resource.clone(),
                description: self.description.clone(),
                mime_type: None,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x402::{
        PAYMENT_REQUIRED_HEADER, PAYMENT_RESPONSE_HEADER, PAYMENT_SIGNATURE_HEADER,
        X402_VERSION_FIELD, X402_VERSION_V2,
    };

    #[test]
    fn header_constants_match_x402_v2() {
        assert_eq!(PAYMENT_REQUIRED_HEADER, "PAYMENT-REQUIRED");
        assert_eq!(PAYMENT_SIGNATURE_HEADER, "PAYMENT-SIGNATURE");
        assert_eq!(PAYMENT_RESPONSE_HEADER, "PAYMENT-RESPONSE");
    }

    #[test]
    fn default_rpc_url_resolves_expected_clusters() {
        assert_eq!(default_rpc_url("devnet"), "https://api.devnet.solana.com");
        assert_eq!(default_rpc_url("localnet"), "http://localhost:8899");
        assert_eq!(
            default_rpc_url("mainnet-beta"),
            "https://api.mainnet-beta.solana.com"
        );
        assert_eq!(
            default_rpc_url("unknown"),
            "https://api.mainnet-beta.solana.com"
        );
    }

    #[test]
    fn cluster_and_network_mapping_round_trip() {
        assert_eq!(caip2_network_for_cluster("mainnet-beta"), SOLANA_MAINNET);
        assert_eq!(caip2_network_for_cluster("devnet"), SOLANA_DEVNET);
        assert_eq!(caip2_network_for_cluster("localnet"), SOLANA_DEVNET);

        assert_eq!(
            cluster_for_caip2_network(SOLANA_MAINNET),
            Some("mainnet-beta")
        );
        assert_eq!(cluster_for_caip2_network(SOLANA_DEVNET), Some("devnet"));
        assert_eq!(
            cluster_for_caip2_network("solana:custom-cluster-id"),
            Some("mainnet-beta")
        );
        assert_eq!(cluster_for_caip2_network("foo:bar"), None);
    }

    #[test]
    fn stablecoin_mint_constants_are_valid_pubkeys() {
        use solana_pubkey::Pubkey;
        use std::str::FromStr;

        assert!(Pubkey::from_str(mints::USDC_MAINNET).is_ok());
        assert!(Pubkey::from_str(mints::USDC_DEVNET).is_ok());
        assert!(Pubkey::from_str(mints::USDT_MAINNET).is_ok());
        assert!(Pubkey::from_str(mints::USDG_MAINNET).is_ok());
        assert!(Pubkey::from_str(mints::USDG_DEVNET).is_ok());
        assert!(Pubkey::from_str(mints::PYUSD_MAINNET).is_ok());
        assert!(Pubkey::from_str(mints::PYUSD_DEVNET).is_ok());
        assert!(Pubkey::from_str(mints::CASH_MAINNET).is_ok());
    }

    #[test]
    fn stablecoin_symbols_resolve_to_mints() {
        assert_eq!(
            resolve_stablecoin_mint("USDC", Some("devnet")),
            Some(mints::USDC_DEVNET)
        );
        assert_eq!(
            resolve_stablecoin_mint("PYUSD", Some("devnet")),
            Some(mints::PYUSD_DEVNET)
        );
        assert_eq!(
            resolve_stablecoin_mint("USDT", None),
            Some(mints::USDT_MAINNET)
        );
        assert_eq!(
            resolve_stablecoin_mint("USDG", Some("devnet")),
            Some(mints::USDG_DEVNET)
        );
        assert_eq!(
            resolve_stablecoin_mint("CASH", None),
            Some(mints::CASH_MAINNET)
        );
        assert_eq!(resolve_stablecoin_mint("SOL", None), None);
        assert_eq!(
            resolve_stablecoin_mint(mints::CASH_MAINNET, None),
            Some(mints::CASH_MAINNET)
        );
    }

    #[test]
    fn token_2022_stablecoins_default_to_token_2022() {
        assert_eq!(
            default_token_program_for_currency("USDC", None),
            programs::TOKEN_PROGRAM
        );
        assert_eq!(
            default_token_program_for_currency("USDT", None),
            programs::TOKEN_PROGRAM
        );
        assert_eq!(
            default_token_program_for_currency("USDG", Some("devnet")),
            programs::TOKEN_2022_PROGRAM
        );
        assert_eq!(
            default_token_program_for_currency(mints::USDG_MAINNET, None),
            programs::TOKEN_2022_PROGRAM
        );
        assert_eq!(
            default_token_program_for_currency("PYUSD", Some("devnet")),
            programs::TOKEN_2022_PROGRAM
        );
        assert_eq!(
            default_token_program_for_currency(mints::PYUSD_MAINNET, None),
            programs::TOKEN_2022_PROGRAM
        );
        assert_eq!(
            default_token_program_for_currency("CASH", None),
            programs::TOKEN_2022_PROGRAM
        );
        assert_eq!(
            default_token_program_for_currency(mints::CASH_MAINNET, None),
            programs::TOKEN_2022_PROGRAM
        );
    }

    #[test]
    fn is_native_sol_recognizes_case_variants() {
        assert!(is_native_sol("SOL"));
        assert!(is_native_sol("sol"));
        assert!(is_native_sol("Sol"));
        assert!(!is_native_sol("USDC"));
        assert!(!is_native_sol(mints::USDC_MAINNET));
    }

    #[test]
    fn stablecoin_symbol_round_trips_symbols() {
        for sym in ["USDC", "USDT", "USDG", "PYUSD", "CASH"] {
            assert_eq!(stablecoin_symbol(sym), Some(sym));
            assert_eq!(stablecoin_symbol(&sym.to_lowercase()), Some(sym));
        }
    }

    #[test]
    fn stablecoin_symbol_resolves_known_mints() {
        assert_eq!(stablecoin_symbol(mints::USDC_MAINNET), Some("USDC"));
        assert_eq!(stablecoin_symbol(mints::USDC_DEVNET), Some("USDC"));
        assert_eq!(stablecoin_symbol(mints::USDT_MAINNET), Some("USDT"));
        assert_eq!(stablecoin_symbol(mints::USDG_MAINNET), Some("USDG"));
        assert_eq!(stablecoin_symbol(mints::USDG_DEVNET), Some("USDG"));
        assert_eq!(stablecoin_symbol(mints::PYUSD_MAINNET), Some("PYUSD"));
        assert_eq!(stablecoin_symbol(mints::PYUSD_DEVNET), Some("PYUSD"));
        assert_eq!(stablecoin_symbol(mints::CASH_MAINNET), Some("CASH"));
    }

    #[test]
    fn stablecoin_symbol_returns_none_for_unknown_or_sol() {
        assert_eq!(stablecoin_symbol("SOL"), None);
        assert_eq!(stablecoin_symbol("sol"), None);
        // Unknown mint passes through resolve, unknown symbol does not match any.
        assert_eq!(stablecoin_symbol("11111111111111111111111111111111"), None);
        assert_eq!(stablecoin_symbol("UNKNOWN_TOKEN"), None);
    }

    #[test]
    fn stablecoin_uses_token_2022_matches_token_extension_stables() {
        assert!(stablecoin_uses_token_2022("USDG"));
        assert!(stablecoin_uses_token_2022("PYUSD"));
        assert!(stablecoin_uses_token_2022("CASH"));
        assert!(stablecoin_uses_token_2022(mints::USDG_MAINNET));
        assert!(stablecoin_uses_token_2022(mints::PYUSD_DEVNET));
        // Legacy stablecoins use the original SPL Token program.
        assert!(!stablecoin_uses_token_2022("USDC"));
        assert!(!stablecoin_uses_token_2022("USDT"));
        assert!(!stablecoin_uses_token_2022("SOL"));
    }

    #[test]
    fn payment_config_uses_defaults() {
        let config = PaymentConfig {
            recipient: "recipient".to_string(),
            cluster: "devnet".to_string(),
            rpc_url: None,
            currency: "USDC".to_string(),
            decimals: Some(6),
            token_program: None,
            amount: "1000".to_string(),
            resource: "/weather".to_string(),
            description: Some("Weather".to_string()),
            max_age: Some(60),
        };

        assert_eq!(config.rpc_url(), "https://api.devnet.solana.com");
        assert_eq!(config.token_program(), programs::TOKEN_PROGRAM);

        let requirements = config.to_requirements();
        assert_eq!(requirements.network, SOLANA_DEVNET);
        assert_eq!(requirements.cluster.as_deref(), Some("devnet"));
        assert_eq!(requirements.recipient, "recipient");
        assert_eq!(requirements.amount, "1000");
        assert_eq!(requirements.currency, "USDC");
        assert_eq!(requirements.decimals, Some(6));
        assert_eq!(requirements.resource, "/weather");
        assert_eq!(requirements.description.as_deref(), Some("Weather"));
        assert_eq!(requirements.max_age, Some(60));
        assert!(requirements.recent_blockhash.is_none());
    }

    #[test]
    fn payment_config_defaults_cash_to_token_2022() {
        let config = PaymentConfig {
            recipient: "recipient".to_string(),
            cluster: "mainnet-beta".to_string(),
            rpc_url: None,
            currency: "CASH".to_string(),
            decimals: Some(6),
            token_program: None,
            amount: "1000".to_string(),
            resource: "/cash".to_string(),
            description: None,
            max_age: None,
        };

        assert_eq!(config.token_program(), programs::TOKEN_2022_PROGRAM);
        assert_eq!(
            config.to_requirements().token_program.as_deref(),
            Some(programs::TOKEN_2022_PROGRAM)
        );
    }

    #[test]
    fn payment_config_respects_overrides() {
        let config = PaymentConfig {
            recipient: "recipient".to_string(),
            cluster: "mainnet-beta".to_string(),
            rpc_url: Some("https://rpc.example".to_string()),
            currency: "SOL".to_string(),
            decimals: None,
            token_program: Some(programs::TOKEN_2022_PROGRAM.to_string()),
            amount: "42".to_string(),
            resource: "/resource".to_string(),
            description: None,
            max_age: None,
        };

        assert_eq!(config.rpc_url(), "https://rpc.example");
        assert_eq!(config.token_program(), programs::TOKEN_2022_PROGRAM);
    }

    #[test]
    fn envelopes_and_payloads_serialize() {
        let proof = PaymentProof::Transaction {
            transaction: "abc".to_string(),
        };
        let required = PaymentRequiredEnvelope {
            x402_version: X402_VERSION_V2,
            resource: Some(ResourceInfo {
                url: "/joke".to_string(),
                description: None,
                mime_type: None,
            }),
            accepts: vec![PaymentRequirements {
                network: SOLANA_MAINNET.to_string(),
                cluster: Some("mainnet-beta".to_string()),
                recipient: "recipient".to_string(),
                amount: "100".to_string(),
                currency: "SOL".to_string(),
                decimals: None,
                token_program: None,
                resource: "/joke".to_string(),
                description: None,
                max_age: None,
                recent_blockhash: None,
                fee_payer: None,
                fee_payer_key: None,
                extra: None,
                accepted: None,
                resource_info: None,
            }],
            error: Some("required".to_string()),
            extensions: Some(serde_json::json!({
                "sign-in-with-x": {
                    "domain": "example.com",
                    "uri": "https://example.com",
                    "version": "1",
                    "nonce": "nonce",
                    "issuedAt": "2026-04-27T00:00:00Z",
                    "supportedChains": [{
                        "chainId": SOLANA_DEVNET,
                        "type": "ed25519",
                        "signatureScheme": "siws"
                    }]
                }
            })),
        };
        let signature = PaymentSignatureEnvelope {
            scheme: None,
            network: None,
            x402_version: X402_VERSION_V2,
            accepted: Some(required.accepts[0].to_accepted_value()),
            resource: required.resource.clone(),
            payload: proof.clone(),
            extensions: None,
        };
        let payload = PaymentPayload {
            network: SOLANA_MAINNET.to_string(),
            proof,
        };

        let required_json = serde_json::to_string(&required).unwrap();
        let signature_json = serde_json::to_string(&signature).unwrap();
        let payload_json = serde_json::to_string(&payload).unwrap();

        assert!(required_json.contains(&format!("\"{X402_VERSION_FIELD}\":{X402_VERSION_V2}")));
        assert!(required_json.contains("\"accepts\""));
        assert!(required_json.contains("\"sign-in-with-x\""));
        assert!(required_json.contains("\"payTo\":\"recipient\""));
        assert!(required_json.contains("\"asset\":\"SOL\""));
        assert!(signature_json.contains("\"accepted\""));
        assert!(payload_json.contains("\"transaction\":\"abc\""));
    }

    #[test]
    fn generate_payment_identifier_id_matches_spec_pattern() {
        // Spec: ^pay_[a-zA-Z0-9_-]{10,120}$ — see
        // specs/extensions/payment_identifier.md.
        let re_chars = |c: char| c.is_ascii_alphanumeric() || c == '_' || c == '-';
        for _ in 0..32 {
            let id = generate_payment_identifier_id();
            assert!(id.starts_with("pay_"), "missing prefix: {id}");
            let suffix = &id["pay_".len()..];
            assert_eq!(suffix.len(), 32, "unexpected suffix length in {id}");
            assert!(suffix.chars().all(re_chars), "bad chars in {id}");
            assert!(id.len() >= 16 && id.len() <= 128);
        }
    }

    #[test]
    fn generate_payment_identifier_id_is_unique() {
        // Birthday collision on 128-bit randomness is statistically zero;
        // this guards against a future refactor accidentally returning a
        // constant.
        let a = generate_payment_identifier_id();
        let b = generate_payment_identifier_id();
        assert_ne!(a, b);
    }

    #[test]
    fn payment_extensions_echoes_unknown_keys_verbatim() {
        // Forward-compatibility: an extension we don't type natively
        // must round-trip through `other` and be re-emitted unchanged
        // (x402 v2 §5.1.2 echo rule).
        let inbound = serde_json::json!({
            "future-extension": { "info": { "foo": "bar" } },
            "bazaar": { "info": {} }
        });
        let ext = PaymentExtensions::echoing(Some(&inbound)).unwrap().unwrap();
        assert!(ext.payment_identifier.is_none());
        assert_eq!(ext.other.len(), 2);
        let serialized = serde_json::to_value(&ext).unwrap();
        assert_eq!(serialized, inbound);
    }

    #[test]
    fn payment_extensions_typed_payment_identifier_round_trip() {
        let inbound = serde_json::json!({
            "payment-identifier": {
                "info": { "required": true },
                "schema": { "type": "object" }
            }
        });
        let ext = PaymentExtensions::echoing(Some(&inbound)).unwrap().unwrap();
        assert!(ext.requires_payment_identifier());
        let pid = ext.payment_identifier.as_ref().unwrap();
        assert_eq!(pid.info.required, Some(true));
        assert!(pid.info.id.is_none());
        assert!(pid.schema.is_some());
    }

    #[test]
    fn with_payment_identifier_id_appends_without_overwriting_server_fields() {
        let inbound = serde_json::json!({
            "payment-identifier": {
                "info": { "required": true },
                "schema": { "type": "object", "required": ["id"] }
            }
        });
        let ext = PaymentExtensions::echoing(Some(&inbound))
            .unwrap()
            .unwrap()
            .with_payment_identifier_id("pay_abcdef1234567890abcdef1234567890");
        let pid = ext.payment_identifier.as_ref().unwrap();
        // Server-side info preserved per §5.1.2.
        assert_eq!(pid.info.required, Some(true));
        // Schema echoed verbatim.
        assert!(pid.schema.is_some());
        // Client-side id appended.
        assert_eq!(
            pid.info.id.as_deref(),
            Some("pay_abcdef1234567890abcdef1234567890")
        );
    }

    #[test]
    fn with_payment_identifier_id_creates_entry_when_server_didnt_advertise() {
        // Uncommon but spec-allowed: client may set the id even if the
        // server didn't list `payment-identifier` in extensions.
        let ext = PaymentExtensions::default().with_payment_identifier_id("pay_0000000000000000");
        assert_eq!(
            ext.payment_identifier.as_ref().unwrap().info.id.as_deref(),
            Some("pay_0000000000000000")
        );
    }

    #[test]
    fn payment_extensions_echoing_returns_none_when_inbound_absent() {
        assert!(PaymentExtensions::echoing(None).unwrap().is_none());
    }

    #[test]
    fn payment_extensions_serializes_with_correct_key_casing() {
        // Spec uses `payment-identifier` (kebab-case) as the JSON key.
        let ext = PaymentExtensions::default().with_payment_identifier_id("pay_aaaaaaaaaaaaaaaa");
        let s = serde_json::to_string(&ext).unwrap();
        assert!(s.contains("\"payment-identifier\""), "got {s}");
    }
}
