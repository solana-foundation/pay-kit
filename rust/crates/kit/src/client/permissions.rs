//! Permission types used by the high-level payment client.
//!
//! The public types are re-exported from [`super`]. Prefer
//! [`ClientPermissions::builder`] for validated construction.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    str::FromStr,
};

use solana_pubkey::Pubkey;
use url::Url;

use crate::mpp::{protocol::solana::is_known_stablecoin_mint, resolve_stablecoin_mint};

const USD_DECIMALS: u32 = 6;
const DEFAULT_MAX_AMOUNT_MICRO_USD: u64 = 1_000_000;

/// Solana clusters accepted by the PayKit client API.
///
/// PayKit is Solana-only, so these values intentionally use the short public
/// slugs. x402 CAIP-2 network identifiers are converted inside its adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SolanaNetwork {
    /// Solana mainnet, serialized for protocol checks as `mainnet`.
    Mainnet,
    /// Solana devnet.
    Devnet,
    /// A local Solana validator or Surfpool environment.
    Localnet,
}

impl SolanaNetwork {
    /// Canonical public slug for this cluster.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Devnet => "devnet",
            Self::Localnet => "localnet",
        }
    }
}

impl fmt::Display for SolanaNetwork {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for SolanaNetwork {
    type Err = PermissionConfigError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "mainnet" => Ok(Self::Mainnet),
            "devnet" => Ok(Self::Devnet),
            "localnet" => Ok(Self::Localnet),
            _ => Err(PermissionConfigError::InvalidNetwork(value.to_string())),
        }
    }
}

/// A positive decimal USD limit stored as integer micro-dollars.
///
/// Parse values such as `"1"`, `"1.25"`, or `"$1.25"`. Parsing rejects
/// signs, scientific notation, zero, and more than six fractional digits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct UsdAmount(u64);

impl UsdAmount {
    /// Construct a USD limit from integer micro-dollars.
    pub fn from_micro_usd(value: u64) -> Result<Self, PermissionConfigError> {
        if value == 0 {
            return Err(PermissionConfigError::InvalidUsdAmount(
                "USD limits must be greater than zero".to_string(),
            ));
        }
        Ok(Self(value))
    }

    /// Return this limit in integer micro-dollars.
    pub const fn as_micro_usd(self) -> u64 {
        self.0
    }
}

impl FromStr for UsdAmount {
    type Err = PermissionConfigError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let value = value.strip_prefix('$').unwrap_or(value);
        if value.is_empty() || value.starts_with('-') || value.starts_with('+') {
            return Err(PermissionConfigError::InvalidUsdAmount(value.to_string()));
        }
        let mut parts = value.split('.');
        let whole = parts.next().unwrap_or_default();
        let fraction = parts.next();
        if parts.next().is_some()
            || whole.is_empty()
            || !whole.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(PermissionConfigError::InvalidUsdAmount(value.to_string()));
        }
        let fraction = fraction.unwrap_or_default();
        if fraction.len() > USD_DECIMALS as usize
            || !fraction.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(PermissionConfigError::InvalidUsdAmount(value.to_string()));
        }
        let whole = whole
            .parse::<u64>()
            .map_err(|_| PermissionConfigError::InvalidUsdAmount(value.to_string()))?;
        let scale = 10u64.pow(USD_DECIMALS);
        let fractional = if fraction.is_empty() {
            0
        } else {
            fraction
                .parse::<u64>()
                .map_err(|_| PermissionConfigError::InvalidUsdAmount(value.to_string()))?
                .checked_mul(10u64.pow(USD_DECIMALS - fraction.len() as u32))
                .ok_or_else(|| PermissionConfigError::InvalidUsdAmount(value.to_string()))?
        };
        let micro_usd = whole
            .checked_mul(scale)
            .and_then(|base| base.checked_add(fractional))
            .ok_or_else(|| PermissionConfigError::InvalidUsdAmount(value.to_string()))?;
        Self::from_micro_usd(micro_usd)
    }
}

impl fmt::Display for UsdAmount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let scale = 10u64.pow(USD_DECIMALS);
        let whole = self.0 / scale;
        let fraction = self.0 % scale;
        write!(f, "${whole}.{fraction:06}")
    }
}

/// One explicitly allowed SPL asset and its optional atomic cap.
///
/// `asset` may be a known stablecoin symbol or a base58 mint address. Atomic
/// caps are used for custom mints because PayKit cannot safely infer their USD
/// value or decimals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssetPermission {
    network: SolanaNetwork,
    mint: Pubkey,
    max_amount_per_payment: Option<u64>,
}

impl AssetPermission {
    /// Allow an asset without an atomic per-payment cap.
    pub fn new(
        network: SolanaNetwork,
        asset: impl AsRef<str>,
    ) -> Result<Self, PermissionConfigError> {
        Self::with_optional_cap(network, asset.as_ref(), None)
    }

    /// Allow an asset with an atomic per-payment cap.
    pub fn with_cap(
        network: SolanaNetwork,
        asset: impl AsRef<str>,
        max_amount_per_payment: u64,
    ) -> Result<Self, PermissionConfigError> {
        if max_amount_per_payment == 0 {
            return Err(PermissionConfigError::InvalidAtomicCap);
        }
        Self::with_optional_cap(network, asset.as_ref(), Some(max_amount_per_payment))
    }

    fn with_optional_cap(
        network: SolanaNetwork,
        asset: &str,
        max_amount_per_payment: Option<u64>,
    ) -> Result<Self, PermissionConfigError> {
        let mint = resolve_stablecoin_mint(asset, Some(network.as_str())).unwrap_or(asset);
        let mint = mint
            .parse::<Pubkey>()
            .map_err(|_| PermissionConfigError::InvalidAsset(asset.to_string()))?;
        Ok(Self {
            network,
            mint,
            max_amount_per_payment,
        })
    }

    fn matches(&self, network: SolanaNetwork, mint: &Pubkey) -> bool {
        self.network == network && self.mint == *mint
    }
}

/// Per-origin cap overrides.
///
/// The origin must still pass the global origin allowlist. Values normalize to
/// `scheme://host[:port]`; paths, queries, and fragments do not form separate
/// trust domains.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OriginPermissionOverride {
    origin: String,
    max_amount_per_payment: Option<Option<UsdAmount>>,
    asset_caps: Vec<AssetPermission>,
}

impl OriginPermissionOverride {
    /// Start an override for one exact HTTP(S) origin.
    pub fn builder(origin: impl AsRef<str>) -> OriginPermissionOverrideBuilder {
        OriginPermissionOverrideBuilder {
            origin: origin.as_ref().to_string(),
            max_amount_per_payment: None,
            asset_caps: Vec::new(),
        }
    }
}

/// Builder for [`OriginPermissionOverride`].
#[derive(Debug, Clone)]
pub struct OriginPermissionOverrideBuilder {
    origin: String,
    max_amount_per_payment: Option<Option<UsdAmount>>,
    asset_caps: Vec<AssetPermission>,
}

impl OriginPermissionOverrideBuilder {
    /// Override the global USD cap for known stablecoins at this origin.
    pub fn max_amount_per_payment(mut self, cap: UsdAmount) -> Self {
        self.max_amount_per_payment = Some(Some(cap));
        self
    }

    /// Remove the global USD cap for this exact origin.
    pub fn without_amount_cap(mut self) -> Self {
        self.max_amount_per_payment = Some(None);
        self
    }

    /// Override an asset's global atomic cap for this exact origin.
    pub fn asset_cap(
        mut self,
        network: SolanaNetwork,
        asset: impl AsRef<str>,
        cap: u64,
    ) -> Result<Self, PermissionConfigError> {
        self.asset_caps
            .push(AssetPermission::with_cap(network, asset, cap)?);
        Ok(self)
    }

    /// Validate and build the origin override.
    pub fn build(self) -> Result<OriginPermissionOverride, PermissionConfigError> {
        Ok(OriginPermissionOverride {
            origin: normalize_origin(&self.origin)?,
            max_amount_per_payment: self.max_amount_per_payment,
            asset_caps: self.asset_caps,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum AllowedOrigins {
    Any,
    Only(BTreeSet<String>),
}

/// Permissions checked before PayKit builds or signs an automatic payment.
///
/// Defaults allow any HTTP(S) origin, mainnet, known PayKit stablecoins, and a
/// USD 1.00 per-payment cap. A [`PayKitClient`](super::PayKitClient) replaces
/// the default network with its configured network when no explicit permission
/// set is supplied.
///
/// Caps resolve in this order:
///
/// 1. exact-origin asset cap;
/// 2. exact-origin stablecoin cap;
/// 3. global asset cap; and
/// 4. global stablecoin cap.
///
/// An origin override changes a cap but never grants access to the origin.
/// Unknown mints require [`ClientPermissionsBuilder::allow_asset`] or
/// [`ClientPermissionsBuilder::allow_any_asset`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientPermissions {
    allowed_origins: AllowedOrigins,
    allowed_networks: BTreeSet<SolanaNetwork>,
    max_amount_per_payment: Option<UsdAmount>,
    allow_any_asset: bool,
    allowed_assets: Vec<AssetPermission>,
    origin_overrides: BTreeMap<String, OriginPermissionOverride>,
}

impl Default for ClientPermissions {
    fn default() -> Self {
        Self::builder()
            .build()
            .expect("default client permissions are valid")
    }
}

impl ClientPermissions {
    /// Start with safe defaults: any origin, mainnet, known stablecoins, and a $1 cap.
    pub fn builder() -> ClientPermissionsBuilder {
        ClientPermissionsBuilder {
            allowed_origins: AllowedOrigins::Any,
            allowed_networks: BTreeSet::from([SolanaNetwork::Mainnet]),
            max_amount_per_payment: Some(UsdAmount(DEFAULT_MAX_AMOUNT_MICRO_USD)),
            allow_any_asset: false,
            allowed_assets: Vec::new(),
            origin_overrides: BTreeMap::new(),
        }
    }

    /// Allow any payment supported by the high-level client.
    ///
    /// This permits any HTTP(S) origin, Solana cluster, SPL mint, and amount.
    /// It does not enable unsupported x402 channel schemes.
    pub fn unrestricted() -> Self {
        Self {
            allowed_origins: AllowedOrigins::Any,
            allowed_networks: BTreeSet::new(),
            max_amount_per_payment: None,
            allow_any_asset: true,
            allowed_assets: Vec::new(),
            origin_overrides: BTreeMap::new(),
        }
    }

    /// Check one fully resolved payment offer without constructing or signing
    /// a transaction.
    ///
    /// This is the same boundary used by [`PayKitClient`](super::PayKitClient)
    /// and is public so higher-level clients (for example an MCP server) can
    /// apply the permission model to their own protocol negotiation path.
    pub fn authorize(
        &self,
        candidate: &PaymentCandidate<'_>,
    ) -> Result<AuthorizedPayment, PermissionRejection> {
        let origin = normalize_origin(candidate.origin)
            .map_err(|_| PermissionRejection::invalid_terms("invalid response origin"))?;
        if let AllowedOrigins::Only(allowed) = &self.allowed_origins {
            if !allowed.contains(&origin) {
                return Err(PermissionRejection::new(
                    PermissionDeniedCode::OriginNotAllowed,
                    format!("origin {origin} is not allowed"),
                ));
            }
        }
        if !self.allowed_networks.is_empty() && !self.allowed_networks.contains(&candidate.network)
        {
            return Err(PermissionRejection::new(
                PermissionDeniedCode::NetworkNotAllowed,
                format!("network {} is not allowed", candidate.network),
            ));
        }

        let mint = candidate.mint.parse::<Pubkey>().map_err(|_| {
            PermissionRejection::invalid_terms("challenge asset is not a valid Solana mint")
        })?;
        let global_asset = self
            .allowed_assets
            .iter()
            .find(|permission| permission.matches(candidate.network, &mint));
        let known_asset = is_known_stablecoin_mint(candidate.mint);
        if !self.allow_any_asset && !known_asset && global_asset.is_none() {
            return Err(PermissionRejection::new(
                PermissionDeniedCode::AssetNotAllowed,
                format!(
                    "asset {} is not allowed on {}",
                    candidate.mint, candidate.network
                ),
            ));
        }

        let origin_override = self.origin_overrides.get(&origin);
        let origin_asset_cap = origin_override.and_then(|entry| {
            entry
                .asset_caps
                .iter()
                .find(|permission| permission.matches(candidate.network, &mint))
                .and_then(|permission| permission.max_amount_per_payment)
        });
        let cap = if let Some(cap) = origin_asset_cap {
            Some(cap)
        } else if known_asset {
            if let Some(cap) = origin_override.and_then(|entry| entry.max_amount_per_payment) {
                cap.map(UsdAmount::as_micro_usd)
            } else if let Some(permission) = global_asset {
                permission.max_amount_per_payment
            } else {
                self.max_amount_per_payment.map(UsdAmount::as_micro_usd)
            }
        } else {
            global_asset.and_then(|permission| permission.max_amount_per_payment)
        };

        if let Some(cap) = cap {
            if candidate.amount > cap {
                return Err(PermissionRejection {
                    code: PermissionDeniedCode::AmountExceedsLimit,
                    message: format!(
                        "payment amount {} exceeds cap {cap} for {origin}",
                        candidate.amount
                    ),
                    actual: Some(candidate.amount),
                    limit: Some(cap),
                });
            }
        }

        Ok(AuthorizedPayment {
            max_amount_atomic: cap,
        })
    }
}

/// Fluent, validated builder for [`ClientPermissions`].
#[derive(Debug, Clone)]
pub struct ClientPermissionsBuilder {
    allowed_origins: AllowedOrigins,
    allowed_networks: BTreeSet<SolanaNetwork>,
    max_amount_per_payment: Option<UsdAmount>,
    allow_any_asset: bool,
    allowed_assets: Vec<AssetPermission>,
    origin_overrides: BTreeMap<String, OriginPermissionOverride>,
}

impl ClientPermissionsBuilder {
    /// Restrict payments to an exact HTTP(S) origin. The first call changes the
    /// default from any origin to an allowlist.
    pub fn allow_origin(mut self, origin: impl AsRef<str>) -> Result<Self, PermissionConfigError> {
        let origin = normalize_origin(origin.as_ref())?;
        match &mut self.allowed_origins {
            AllowedOrigins::Any => {
                self.allowed_origins = AllowedOrigins::Only(BTreeSet::from([origin]));
            }
            AllowedOrigins::Only(origins) => {
                origins.insert(origin);
            }
        }
        Ok(self)
    }

    /// Permit challenges from any HTTP(S) origin.
    pub fn allow_any_origin(mut self) -> Self {
        self.allowed_origins = AllowedOrigins::Any;
        self
    }

    /// Add a permitted Solana cluster.
    pub fn allow_network(mut self, network: SolanaNetwork) -> Self {
        self.allowed_networks.insert(network);
        self
    }

    /// Replace the default network set with one Solana cluster.
    pub fn only_network(mut self, network: SolanaNetwork) -> Self {
        self.allowed_networks = BTreeSet::from([network]);
        self
    }

    /// Set the global per-payment cap for known stablecoins.
    ///
    /// Exact-origin and per-asset caps can replace this value.
    pub fn max_amount_per_payment(mut self, cap: UsdAmount) -> Self {
        self.max_amount_per_payment = Some(cap);
        self
    }

    /// Remove the global per-payment cap for known stablecoins.
    pub fn without_amount_cap(mut self) -> Self {
        self.max_amount_per_payment = None;
        self
    }

    /// Permit every SPL asset. Existing amount caps still apply to known stablecoins.
    pub fn allow_any_asset(mut self) -> Self {
        self.allow_any_asset = true;
        self
    }

    /// Permit one non-default asset, optionally with its own atomic cap.
    pub fn allow_asset(mut self, permission: AssetPermission) -> Self {
        self.allowed_assets.push(permission);
        self
    }

    /// Add an exact-origin cap override.
    ///
    /// This does not add the origin to the allowlist.
    pub fn override_origin(mut self, permission: OriginPermissionOverride) -> Self {
        self.origin_overrides
            .insert(permission.origin.clone(), permission);
        self
    }

    /// Validate and build the permission set.
    pub fn build(self) -> Result<ClientPermissions, PermissionConfigError> {
        if matches!(&self.allowed_origins, AllowedOrigins::Only(origins) if origins.is_empty()) {
            return Err(PermissionConfigError::EmptyOriginAllowlist);
        }
        Ok(ClientPermissions {
            allowed_origins: self.allowed_origins,
            allowed_networks: self.allowed_networks,
            max_amount_per_payment: self.max_amount_per_payment,
            allow_any_asset: self.allow_any_asset,
            allowed_assets: self.allowed_assets,
            origin_overrides: self.origin_overrides,
        })
    }
}

/// A resolved payment offer presented to [`ClientPermissions::authorize`].
///
/// `amount` is expressed in the asset's atomic units. Known stablecoins use
/// six decimal places, so their atomic amount is also micro-USD for cap checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PaymentCandidate<'a> {
    origin: &'a str,
    network: SolanaNetwork,
    mint: &'a str,
    amount: u64,
}

impl<'a> PaymentCandidate<'a> {
    /// Describe a payment after protocol parsing and asset resolution.
    pub const fn new(origin: &'a str, network: SolanaNetwork, mint: &'a str, amount: u64) -> Self {
        Self {
            origin,
            network,
            mint,
            amount,
        }
    }
}

/// Permission result for an allowed payment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorizedPayment {
    max_amount_atomic: Option<u64>,
}

impl AuthorizedPayment {
    /// The effective atomic cap to enforce again at the signing boundary.
    pub const fn max_amount_atomic(self) -> Option<u64> {
        self.max_amount_atomic
    }
}

/// Stable reason code for a denied payment candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionDeniedCode {
    /// The final URL that returned the 402 is outside the origin allowlist.
    OriginNotAllowed,
    /// The challenge targets a Solana cluster outside the network allowlist.
    NetworkNotAllowed,
    /// The mint is neither a known stablecoin nor explicitly permitted.
    AssetNotAllowed,
    /// The atomic payment amount exceeds the resolved cap.
    AmountExceedsLimit,
    /// A candidate contains malformed terms at the authorization boundary.
    InvalidChallengeTerms,
}

/// One rejected payment option.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionRejection {
    /// Stable machine-readable reason for the refusal.
    pub code: PermissionDeniedCode,
    /// Human-readable refusal detail. It never includes signer secrets.
    pub message: String,
    /// Advertised atomic amount, when the refusal concerns a cap.
    pub actual: Option<u64>,
    /// Resolved atomic cap, when the refusal concerns a cap.
    pub limit: Option<u64>,
}

impl PermissionRejection {
    fn new(code: PermissionDeniedCode, message: String) -> Self {
        Self {
            code,
            message,
            actual: None,
            limit: None,
        }
    }

    pub(crate) fn invalid_terms(message: impl Into<String>) -> Self {
        Self::new(PermissionDeniedCode::InvalidChallengeTerms, message.into())
    }
}

/// No advertised payment option passed the configured client permissions.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("no server payment challenge is permitted")]
pub struct PermissionDenied {
    /// Refusal details in server-offer order.
    pub rejections: Vec<PermissionRejection>,
}

/// Invalid client permission configuration.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PermissionConfigError {
    /// A network string was not a supported Solana cluster slug.
    #[error("invalid Solana network `{0}`; expected `mainnet`, `devnet`, or `localnet`")]
    InvalidNetwork(String),
    /// A USD limit was zero, malformed, too precise, or out of range.
    #[error("invalid USD amount `{0}`")]
    InvalidUsdAmount(String),
    /// An atomic asset cap was zero.
    #[error("atomic caps must be greater than zero")]
    InvalidAtomicCap,
    /// An asset was neither a known symbol nor a valid base58 mint.
    #[error("invalid Solana asset `{0}`")]
    InvalidAsset(String),
    /// An origin was not a valid HTTP(S) URL without user information.
    #[error("origin must be an exact HTTP(S) origin: {0}")]
    InvalidOrigin(String),
    /// An explicit origin allowlist contained no origins.
    #[error("origin allowlist must not be empty")]
    EmptyOriginAllowlist,
}

fn normalize_origin(value: &str) -> Result<String, PermissionConfigError> {
    let url =
        Url::parse(value).map_err(|_| PermissionConfigError::InvalidOrigin(value.to_string()))?;
    if !matches!(url.scheme(), "http" | "https")
        || url.cannot_be_a_base()
        || url.username() != ""
        || url.password().is_some()
    {
        return Err(PermissionConfigError::InvalidOrigin(value.to_string()));
    }
    Ok(url.origin().ascii_serialization())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::mints::{PYUSD_MAINNET, USDC_MAINNET};

    fn candidate<'a>(origin: &'a str, mint: &'a str, amount: u64) -> PaymentCandidate<'a> {
        PaymentCandidate {
            origin,
            network: SolanaNetwork::Mainnet,
            mint,
            amount,
        }
    }

    #[test]
    fn usd_amount_is_strict_and_integer_backed() {
        assert_eq!(
            "$1.25".parse::<UsdAmount>().unwrap().as_micro_usd(),
            1_250_000
        );
        assert_eq!("0.000001".parse::<UsdAmount>().unwrap().as_micro_usd(), 1);
        for invalid in ["0", "1.0000001", "1e2", "-1", "1.2.3", ""] {
            assert!(invalid.parse::<UsdAmount>().is_err(), "accepted {invalid}");
        }
    }

    #[test]
    fn defaults_allow_known_stablecoins_up_to_one_dollar() {
        let permissions = ClientPermissions::default();
        assert!(permissions
            .authorize(&candidate(
                "https://api.example.com",
                USDC_MAINNET,
                1_000_000
            ))
            .is_ok());
        let rejection = permissions
            .authorize(&candidate(
                "https://api.example.com",
                USDC_MAINNET,
                1_000_001,
            ))
            .unwrap_err();
        assert_eq!(rejection.code, PermissionDeniedCode::AmountExceedsLimit);
    }

    #[test]
    fn unknown_assets_require_an_explicit_permission() {
        let mint = Pubkey::new_unique().to_string();
        let rejection = ClientPermissions::default()
            .authorize(&candidate("https://api.example.com", &mint, 1))
            .unwrap_err();
        assert_eq!(rejection.code, PermissionDeniedCode::AssetNotAllowed);

        let permissions = ClientPermissions::builder()
            .allow_asset(AssetPermission::with_cap(SolanaNetwork::Mainnet, &mint, 10).unwrap())
            .build()
            .unwrap();
        assert!(permissions
            .authorize(&candidate("https://api.example.com", &mint, 10))
            .is_ok());
        assert_eq!(
            permissions
                .authorize(&candidate("https://api.example.com", &mint, 11))
                .unwrap_err()
                .code,
            PermissionDeniedCode::AmountExceedsLimit
        );
    }

    #[test]
    fn exact_origin_override_can_raise_global_cap() {
        let override_ = OriginPermissionOverride::builder("https://api.example.com/path")
            .max_amount_per_payment("5".parse().unwrap())
            .build()
            .unwrap();
        let permissions = ClientPermissions::builder()
            .max_amount_per_payment("1".parse().unwrap())
            .override_origin(override_)
            .build()
            .unwrap();

        assert!(permissions
            .authorize(&candidate(
                "https://api.example.com/v1",
                PYUSD_MAINNET,
                5_000_000
            ))
            .is_ok());
        assert_eq!(
            permissions
                .authorize(&candidate(
                    "https://other.example.com",
                    PYUSD_MAINNET,
                    5_000_000
                ))
                .unwrap_err()
                .code,
            PermissionDeniedCode::AmountExceedsLimit
        );
    }

    #[test]
    fn origin_override_does_not_grant_the_origin() {
        let override_ = OriginPermissionOverride::builder("https://other.example.com")
            .max_amount_per_payment("5".parse().unwrap())
            .build()
            .unwrap();
        let permissions = ClientPermissions::builder()
            .allow_origin("https://api.example.com")
            .unwrap()
            .override_origin(override_)
            .build()
            .unwrap();
        assert_eq!(
            permissions
                .authorize(&candidate("https://other.example.com", USDC_MAINNET, 1))
                .unwrap_err()
                .code,
            PermissionDeniedCode::OriginNotAllowed
        );
    }

    #[test]
    fn origin_asset_cap_has_highest_precedence() {
        let mint = Pubkey::new_unique().to_string();
        let override_ = OriginPermissionOverride::builder("https://api.example.com")
            .asset_cap(SolanaNetwork::Mainnet, &mint, 25)
            .unwrap()
            .build()
            .unwrap();
        let permissions = ClientPermissions::builder()
            .allow_asset(AssetPermission::with_cap(SolanaNetwork::Mainnet, &mint, 10).unwrap())
            .override_origin(override_)
            .build()
            .unwrap();

        assert!(permissions
            .authorize(&candidate("https://api.example.com", &mint, 25))
            .is_ok());
        assert_eq!(
            permissions
                .authorize(&candidate("https://other.example.com", &mint, 11))
                .unwrap_err()
                .limit,
            Some(10)
        );
    }

    #[test]
    fn network_and_origin_permissions_fail_closed() {
        let permissions = ClientPermissions::builder()
            .allow_origin("https://api.example.com")
            .unwrap()
            .build()
            .unwrap();
        let mut wrong_network = candidate("https://api.example.com", USDC_MAINNET, 1);
        wrong_network.network = SolanaNetwork::Devnet;
        assert_eq!(
            permissions.authorize(&wrong_network).unwrap_err().code,
            PermissionDeniedCode::NetworkNotAllowed
        );
        assert_eq!(
            permissions
                .authorize(&candidate("https://evil.example", USDC_MAINNET, 1))
                .unwrap_err()
                .code,
            PermissionDeniedCode::OriginNotAllowed
        );
    }

    #[test]
    fn unrestricted_allows_supported_payments() {
        let permissions = ClientPermissions::unrestricted();
        let custom_mint = Pubkey::new_unique().to_string();
        assert!(permissions
            .authorize(&candidate("https://any.example", &custom_mint, u64::MAX))
            .is_ok());
    }

    #[test]
    fn allow_any_asset_does_not_treat_atomic_units_as_micro_dollars() {
        let permissions = ClientPermissions::builder()
            .allow_any_asset()
            .build()
            .unwrap();
        let custom_mint = Pubkey::new_unique().to_string();

        assert!(permissions
            .authorize(&candidate(
                "https://api.example.com",
                &custom_mint,
                u64::MAX
            ))
            .is_ok());
    }
}
