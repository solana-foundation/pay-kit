//! Unified, protocol-agnostic payment gate for axum.
//!
//! A single gated route speaks **both** MPP charge and x402. An unpaid request
//! gets a 402 carrying both challenges — the MPP `WWW-Authenticate` header and
//! the x402 `PAYMENT-REQUIRED` header — and the client pays with whichever
//! protocol it supports. The headers are disjoint, so the paid request is
//! unambiguous: an `Authorization: Payment` credential is verified as MPP, a
//! `PAYMENT-SIGNATURE` / `X-PAYMENT` header as x402.
//!
//! ```no_run
//! use solana_pay_kit::mpp::store::MemoryStore;
//! use solana_pay_kit::{paid_get, PayKit, PayKitConfig, Payment};
//! use axum::Router;
//! use std::sync::Arc;
//!
//! async fn report(payment: Payment) -> String {
//!     format!("paid {} via {}: {}", payment.amount, payment.protocol, payment.reference)
//! }
//!
//! let pay = PayKit::new(PayKitConfig {
//!     realm: Some("my-service".to_string()),
//!     store: Some(Arc::new(MemoryStore::new())),
//!     recipient: "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY".to_string(),
//!     ..Default::default()
//! })
//! .unwrap();
//!
//! // One line gates the route on either protocol.
//! let app: Router = Router::new().route("/report", paid_get(report, "0.10", &pay));
//! ```

use std::sync::{Arc, Mutex};

use axum::body::{to_bytes, Body, HttpBody};
use axum::extract::{FromRequestParts, Request, State};
use axum::handler::Handler;
use axum::http::request::Parts;
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri};
use axum::middleware::{from_fn_with_state, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, MethodRouter};

use crate::core::credit_provider::{
    validate_credit_providers, CreditProvider, CreditProviderError,
};
use crate::core::tx::TxV1Mode;
use crate::mpp::server::axum::{
    charge_route, is_settlement_in_progress, settlement_in_progress_response,
};
use crate::mpp::server::{Config as MppConfig, Mpp};
use crate::mpp::solana_keychain::TransactionSigner;
use crate::mpp::store::Store;
use crate::mpp::{format_receipt, format_www_authenticate, Receipt, ReceiptKind};
use crate::x402::server::{
    BatchAccess, BatchConfig, Config as X402Config, CurrencyConfig, ExactOptions, UptoConfig,
    UptoPayout, VerifiedExactPayment, X402BatchSettlement, X402Upto, X402,
};
use crate::x402::{PAYMENT_RESPONSE_HEADER, PAYMENT_SIGNATURE_HEADER, X402_V1_PAYMENT_HEADER};

const PAYMENT_RECEIPT_HEADER: &str = "Payment-Receipt";

/// Marks a response whose authorization was already charged and served.
const PAYMENT_REPLAY_HEADER: HeaderName = HeaderName::from_static("payment-replay");

/// Avoid turning the channel store into an unbounded response-body cache.
const MAX_CACHED_RESPONSE_BYTES: u64 = 1024 * 1024;

/// Error returned when a [`PayKit`] can't be built from its config.
#[derive(Debug)]
pub enum PayKitError {
    /// A selected credit provider is unavailable.
    CreditProvider(CreditProviderError),
    /// The MPP charge handler rejected the config.
    Mpp(String),
    /// The x402 handler rejected the config.
    X402(String),
}

impl std::fmt::Display for PayKitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CreditProvider(e) => write!(f, "{e}"),
            Self::Mpp(e) => write!(f, "MPP config error: {e}"),
            Self::X402(e) => write!(f, "x402 config error: {e}"),
        }
    }
}

impl std::error::Error for PayKitError {}

/// Shared configuration that derives both an MPP charge handler and an x402
/// handler, so one [`PayKit`] gate accepts either protocol.
///
/// The defaults mirror the per-protocol crates: USDC, six decimals, mainnet.
/// Set [`fee_payer_signer`](Self::fee_payer_signer) to sponsor network fees —
/// it drives MPP's fee-sponsored mode and supplies x402's fee-payer address.
pub struct PayKitConfig {
    /// The merchant wallet address that receives payment.
    pub recipient: String,
    /// Currency symbol or mint address (default `"USDC"`).
    pub currency: String,
    /// Named credit providers accepted alongside currency (default empty).
    /// Coinflow is recognized but unavailable; selecting it fails construction.
    /// This policy is separate from advanced payment-channel hook configuration.
    pub credit_providers: Vec<CreditProvider>,
    /// Token decimals for `currency` (default `6`).
    pub decimals: u8,
    /// Network: `"mainnet"`, `"devnet"`, or `"localnet"` (default `"mainnet"`).
    pub network: String,
    /// RPC endpoint; falls back to a per-network default when `None`.
    pub rpc_url: Option<String>,
    /// MPP HMAC challenge-binding secret (>= 32 bytes). Reads `MPP_SECRET_KEY`
    /// when `None`.
    pub challenge_binding_secret: Option<String>,
    /// MPP realm (credential namespace). REQUIRED and unique per service.
    pub realm: Option<String>,
    /// Replay store for MPP charges and x402 exact payments. REQUIRED and
    /// shared by every verifier of the same challenges.
    pub store: Option<Arc<dyn Store>>,
    /// When set, the server sponsors the network fee: drives MPP fee-sponsored
    /// mode and is used as the x402 fee-payer address.
    pub fee_payer_signer: Option<Arc<dyn TransactionSigner>>,
    /// Accept push-mode MPP credentials (off by default; see audit §13.5).
    /// Requires [`store`](Self::store).
    pub accept_push_mode: bool,
    /// Currencies the server is willing to accept (x402 multi-currency).
    pub accepted_currencies: Option<Vec<String>>,
    /// Whether version-1 transactions (SIMD-0385) are accepted, advertised
    /// and used for settlement. `Auto` probes the feature gate once.
    pub tx_v1: TxV1Mode,
    /// Disable advisory setup guidance on PayKit-owned 402 responses (default `false`).
    pub disable_hint: bool,
    /// Channel store for the x402 `batch-settlement` routes. It is the only
    /// record of accepted vouchers, so production deployments should pass a
    /// durable store shared by every replica. `None` keeps an in-memory store:
    /// its channels are refused after a restart and must be reopened.
    pub batch_channel_store: Option<Arc<dyn crate::core::store::ChannelStore>>,
}

impl Default for PayKitConfig {
    fn default() -> Self {
        Self {
            recipient: String::new(),
            currency: "USDC".to_string(),
            credit_providers: Vec::new(),
            decimals: 6,
            network: "mainnet".to_string(),
            rpc_url: None,
            challenge_binding_secret: None,
            realm: None,
            store: None,
            fee_payer_signer: None,
            accept_push_mode: false,
            accepted_currencies: None,
            tx_v1: TxV1Mode::Auto,
            disable_hint: false,
            batch_channel_store: None,
        }
    }
}

/// A dual-protocol payment gate.
///
/// Holds an MPP charge handler and an x402 handler derived from a single
/// [`PayKitConfig`]. Hand a reference to [`paid_get`] / [`paid_post`] to gate a
/// route on either protocol. Cheap to clone (two `Arc`s).
#[derive(Clone)]
pub struct PayKit {
    mpp: Arc<Mpp>,
    x402: Arc<X402>,
    /// Usage-based x402 `upto` handler. `Some` only when `fee_payer_signer` is
    /// set — the operator signs `settle_and_seal` as the zero-share channel
    /// payee and, by default, the settlement vouchers, so `upto` routes
    /// require a signer.
    x402_upto: Option<Arc<X402Upto>>,
    /// High-throughput x402 `batch-settlement` handler. `Some` only when
    /// `fee_payer_signer` is set (the operator signs settlement transactions).
    x402_batch: Option<Arc<X402BatchSettlement>>,
    /// Co-signs and broadcasts x402 `exact` transaction payments.
    fee_payer_signer: Option<Arc<dyn TransactionSigner>>,
    disable_hint: bool,
}

/// Default `upto` completion window (seconds) advertised in `maxTimeoutSeconds`.
const UPTO_MAX_TIMEOUT_SECONDS: u64 = 300;

impl PayKit {
    /// Build both protocol handlers from one config.
    pub fn new(config: PayKitConfig) -> Result<Self, PayKitError> {
        validate_credit_providers(&config.credit_providers).map_err(PayKitError::CreditProvider)?;

        // A consumed push signature is only remembered by the store; a
        // process-local default would let another replica accept it again.
        if config.accept_push_mode && config.store.is_none() {
            return Err(PayKitError::Mpp(
                "accept_push_mode requires an explicit replay store (PayKitConfig.store) shared across replicas".into(),
            ));
        }

        // x402's fee payer is an address; derive it from the shared signer so a
        // single config configures fee sponsorship for both protocols.
        let fee_payer_key = config
            .fee_payer_signer
            .as_ref()
            .map(|s| s.pubkey().to_string());

        // Map the gate's own currency fields into the x402 servers' currency
        // list. When `accepted_currencies` is set it is the full universe of
        // offered symbols (its first entry is the primary); otherwise the gate
        // offers a single currency. Each entry inherits the gate's `decimals`
        // and derives its token program from the symbol.
        let currencies: Vec<CurrencyConfig> = match config.accepted_currencies.as_ref() {
            Some(list) if !list.is_empty() => list
                .iter()
                .map(|currency| CurrencyConfig {
                    currency: currency.clone(),
                    decimals: config.decimals,
                    token_program: None,
                })
                .collect(),
            _ => vec![CurrencyConfig {
                currency: config.currency.clone(),
                decimals: config.decimals,
                token_program: None,
            }],
        };

        let mpp = Mpp::new(MppConfig {
            realm: config.realm.clone(),
            recipient: config.recipient.clone(),
            currency: config.currency.clone(),
            decimals: config.decimals,
            network: config.network.clone(),
            rpc_url: config.rpc_url.clone(),
            challenge_binding_secret: config.challenge_binding_secret.clone(),
            fee_payer: config.fee_payer_signer.is_some(),
            fee_payer_signer: config.fee_payer_signer.clone(),
            accept_push_mode: config.accept_push_mode,
            store: config.store.clone(),
            ..Default::default()
        })
        .map_err(|e| PayKitError::Mpp(e.to_string()))?
        .with_tx_v1(config.tx_v1);

        let x402 = X402::new(X402Config {
            recipient: config.recipient.clone(),
            currencies: currencies.clone(),
            network: config.network.clone(),
            rpc_url: config.rpc_url.clone(),
            fee_payer_key,
            ..Default::default()
        })
        .map_err(|e| PayKitError::X402(e.to_string()))?
        .with_tx_v1(config.tx_v1);
        // Consumed exact signatures must be visible to every replica too.
        let x402 = match config.store.clone() {
            Some(store) => x402.with_store(store),
            None => x402,
        };

        // The `upto` scheme needs an operator signer to sign `settle_and_seal`
        // (as the zero-share channel payee) and the settlement vouchers, so it
        // is only available when the gate sponsors fees with a signer.
        let x402_upto = config
            .fee_payer_signer
            .as_ref()
            .map(|signer| {
                X402Upto::new(UptoConfig {
                    payout: UptoPayout::Beneficiary {
                        address: config.recipient.clone(),
                    },
                    currencies: currencies.clone(),
                    cluster: config.network.clone(),
                    rpc_url: config.rpc_url.clone(),
                    resource: String::new(),
                    description: None,
                    max_timeout_seconds: UPTO_MAX_TIMEOUT_SECONDS,
                    max_channel_lifetime: crate::x402::upto::MaxChannelLifetime::ONE_HOUR,
                    program_id: None,
                    withdraw_delay: 0,
                    fee_payer_signer: signer.clone(),
                    receiver_authorizer_signer: None,
                })
                .map(|upto| Arc::new(upto.with_tx_v1(config.tx_v1)))
                .map_err(|e| PayKitError::X402(e.to_string()))
            })
            .transpose()?;

        // `batch-settlement` likewise needs an operator signer for settlement.
        let x402_batch = config
            .fee_payer_signer
            .as_ref()
            .map(|signer| {
                let mut batch = BatchConfig::new(
                    config.recipient.clone(),
                    config.network.clone(),
                    signer.clone(),
                );
                batch.currency = config.currency.clone();
                batch.decimals = config.decimals;
                batch.rpc_url = config.rpc_url.clone();
                match config.batch_channel_store.clone() {
                    Some(store) => X402BatchSettlement::with_store(batch, store),
                    None => X402BatchSettlement::new(batch),
                }
                .map(|batch| Arc::new(batch.with_tx_v1(config.tx_v1)))
                .map_err(|e| PayKitError::X402(e.to_string()))
            })
            .transpose()?;

        Ok(Self {
            mpp: Arc::new(mpp),
            x402: Arc::new(x402),
            x402_upto,
            x402_batch,
            fee_payer_signer: config.fee_payer_signer,
            disable_hint: config.disable_hint,
        })
    }

    /// The underlying MPP charge handler.
    pub fn mpp(&self) -> &Arc<Mpp> {
        &self.mpp
    }

    /// The underlying x402 handler.
    pub fn x402(&self) -> &Arc<X402> {
        &self.x402
    }

    /// The underlying x402 `upto` handler, when a fee-payer signer is configured.
    pub fn x402_upto(&self) -> Option<&Arc<X402Upto>> {
        self.x402_upto.as_ref()
    }

    /// The underlying x402 `batch-settlement` handler, when a fee-payer signer is
    /// configured. Drive `claim` / `settle` and close lifecycle work out of band.
    pub fn x402_batch(&self) -> Option<&Arc<X402BatchSettlement>> {
        self.x402_batch.as_ref()
    }
}

/// The protocol a [`Payment`] was made with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    /// Machine Payments Protocol (charge intent).
    Mpp,
    /// x402 (exact scheme).
    X402,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Mpp => "mpp",
            Self::X402 => "x402",
        })
    }
}

/// A verified payment, injected by [`paid_get`] / [`paid_post`] and available
/// as a handler argument.
///
/// Infallible on a protected route: the gate returns 402 before the handler
/// runs, so the payment is always present.
#[derive(Clone, Debug)]
pub struct Payment {
    /// The price the route charged (dollar string, e.g. `"0.10"`).
    pub amount: String,
    /// Which protocol the client paid with.
    pub protocol: Protocol,
    /// Settlement reference — the MPP receipt reference or the x402 signature.
    pub reference: String,
}

impl<S: Send + Sync> FromRequestParts<S> for Payment {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts.extensions.get::<Payment>().cloned().ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Payment extractor used on a route not gated by paid_get/paid_post",
            )
                .into_response()
        })
    }
}

/// A [`paid_batch_get`] / [`paid_batch_post`] handler's declaration that an
/// error response performed no paid effect, so its voucher is released for a
/// retry instead of being charged.
///
/// Insert it as a response extension on a 4xx/5xx response, for example
/// `(StatusCode::SERVICE_UNAVAILABLE, Extension(PaymentNotConsumed))`. The
/// gate cannot tell a failure before any effect from one after it, so every
/// other response, including an error without this marker, is charged and
/// replayed for a retry of the same voucher rather than run again.
#[derive(Clone, Copy, Debug)]
pub struct PaymentNotConsumed;

/// Usage meter for [`paid_upto_get`] / [`paid_upto_post`] routes.
///
/// The route handler reports the actual amount consumed (in base units) by
/// calling [`Charge::charge`], either before returning or while its response
/// body is produced. The gate buffers the body (up to 16 MiB), then settles
/// that amount — never more than the authorized ceiling — and refunds the
/// remainder. If the handler never calls `charge`, the settled amount is `0`.
#[derive(Clone)]
pub struct Charge {
    cell: Arc<Mutex<Option<u64>>>,
    max_base_units: u64,
}

impl Charge {
    /// Record the actual amount consumed, in token base units. Values above the
    /// authorized maximum are clamped to it.
    pub fn charge(&self, base_units: u64) {
        let clamped = base_units.min(self.max_base_units);
        // Recover from a poisoned lock (a panicked handler) rather than dropping
        // the charge — otherwise a panic after `charge()` would settle for zero.
        *self.cell.lock().unwrap_or_else(|e| e.into_inner()) = Some(clamped);
    }

    /// The authorized maximum for this request, in base units.
    pub fn max_base_units(&self) -> u64 {
        self.max_base_units
    }
}

impl<S: Send + Sync> FromRequestParts<S> for Charge {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts.extensions.get::<Charge>().cloned().ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Charge extractor used on a route not gated by paid_upto_get/paid_upto_post",
            )
                .into_response()
        })
    }
}

/// The price a [`paid_get`] / [`paid_post`] route charges: a fixed amount or a
/// per-request closure.
///
/// A `&str` or `String` converts straight into a fixed price, so the common
/// case reads as `paid_get(handler, "0.10", &pay)`. For per-request pricing use
/// [`Price::dynamic`].
#[derive(Clone)]
pub enum Price {
    /// A fixed dollar amount (e.g. `"0.10"`).
    Fixed(Arc<str>),
    /// Per-request pricing from a closure of the request context.
    Dynamic(Arc<dyn Fn(&PriceCtx<'_>) -> String + Send + Sync>),
}

impl Price {
    /// Build a per-request price from a closure.
    pub fn dynamic<F>(f: F) -> Self
    where
        F: Fn(&PriceCtx<'_>) -> String + Send + Sync + 'static,
    {
        Self::Dynamic(Arc::new(f))
    }

    fn resolve(&self, ctx: &PriceCtx<'_>) -> String {
        match self {
            Self::Fixed(amount) => amount.to_string(),
            Self::Dynamic(f) => f(ctx),
        }
    }
}

impl From<&str> for Price {
    fn from(amount: &str) -> Self {
        Self::Fixed(Arc::from(amount))
    }
}

impl From<String> for Price {
    fn from(amount: String) -> Self {
        Self::Fixed(Arc::from(amount.as_str()))
    }
}

impl std::fmt::Debug for Price {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Fixed(amount) => f.debug_tuple("Fixed").field(amount).finish(),
            Self::Dynamic(_) => f.write_str("Dynamic(<closure>)"),
        }
    }
}

/// Read-only view of the request passed to a [`Price::dynamic`] closure.
pub struct PriceCtx<'a> {
    /// The request method.
    pub method: &'a Method,
    /// The public request URI (path and query), including any `Router::nest`
    /// prefix.
    pub uri: &'a Uri,
    /// The request headers.
    pub headers: &'a HeaderMap,
}

impl PriceCtx<'_> {
    /// The raw query string, if present.
    pub fn query(&self) -> Option<&str> {
        self.uri.query()
    }

    /// Look up a single query parameter by name.
    ///
    /// Names and values are `application/x-www-form-urlencoded`-decoded (`%XX`
    /// escapes and `+` as space), as axum's `Query` extractor decodes them, so
    /// `?%74ier=premi%75m` matches `"tier"` / `"premium"` instead of falling
    /// through to a cheaper default price. Gated routes reject malformed
    /// escapes and repeated parameter names before the price is resolved.
    pub fn query_param(&self, name: &str) -> Option<String> {
        url::form_urlencoded::parse(self.uri.query()?.as_bytes())
            .find_map(|(key, value)| (key == name).then(|| value.into_owned()))
    }
}

/// Reject query strings a dynamic price could read differently from the handler.
fn validate_price_query(query: Option<&str>) -> Result<(), &'static str> {
    let Some(query) = query else {
        return Ok(());
    };
    let bytes = query.as_bytes();
    for (i, _) in bytes.iter().enumerate().filter(|(_, b)| **b == b'%') {
        let escape = bytes.get(i + 1..i + 3);
        if !escape.is_some_and(|hex| hex.iter().all(u8::is_ascii_hexdigit)) {
            return Err("malformed percent-encoding in query string");
        }
    }
    // Extractors disagree on which duplicate wins (axum's `Query<HashMap>`
    // keeps the last, `query_param` the first), so refuse to choose.
    let mut names = std::collections::HashSet::new();
    if !url::form_urlencoded::parse(bytes).all(|(name, _)| names.insert(name)) {
        return Err("duplicate query parameter");
    }
    Ok(())
}

/// The request URI as the client sent it. `Router::nest` strips the mount
/// prefix from `req.uri()`; axum keeps the original in [`OriginalUri`](axum::extract::OriginalUri).
fn external_uri(req: &Request) -> &Uri {
    req.extensions()
        .get::<axum::extract::OriginalUri>()
        .map_or(req.uri(), |original| &original.0)
}

/// The route an MPP charge on this request is bound to (see [`charge_route`]).
fn mpp_route(req: &Request) -> String {
    charge_route(req.method(), external_uri(req), req.headers())
}

/// Resolve the route price, or why the request can't be priced.
fn resolve_amount(price: &Price, req: &Request) -> Result<String, &'static str> {
    let uri = external_uri(req);
    if matches!(price, Price::Dynamic(_)) {
        validate_price_query(uri.query())?;
    }
    let ctx = PriceCtx {
        method: req.method(),
        uri,
        headers: req.headers(),
    };
    Ok(price.resolve(&ctx))
}

#[derive(Clone)]
struct GateState {
    pay: PayKit,
    price: Price,
}

/// Build the shared 402 body before protocol challenge headers are attached.
fn hint_response(pay: &PayKit, req: &Request) -> Response {
    if pay.disable_hint {
        return (StatusCode::PAYMENT_REQUIRED, "Payment Required").into_response();
    }
    let browser = recommends_browser(req.headers());
    let mut browser_url = url::Url::parse("https://connect.pay.sh/mcp").unwrap();
    // Advisory, untrusted context only: reuse the challenge's resource identity,
    // without changing payment authorization or sending a request to Connect.
    if let Some(resource) = resource_url(req) {
        if let (Ok(parsed), Ok(uri)) = (url::Url::parse(&resource), resource.parse::<Uri>()) {
            if matches!(parsed.scheme(), "http" | "https")
                && uri
                    .authority()
                    .is_some_and(|authority| !authority.as_str().contains('@'))
                && parsed.host_str().is_some_and(|host| !host.is_empty())
                && parsed.username().is_empty()
                && parsed.password().is_none()
                && parsed.fragment().is_none()
                && resource.len() <= 4096
                && !resource.contains('\\')
                && !resource
                    .chars()
                    .any(|c| c.is_control() || c.is_whitespace())
            {
                browser_url
                    .query_pairs_mut()
                    .append_pair("resource_uri", &resource);
            }
        }
    }
    let mut response = (
        StatusCode::PAYMENT_REQUIRED,
        axum::Json(serde_json::json!({
            "error": "payment_required",
            "hint": {
                "recommended": if browser { "browser" } else { "cli" },
                "message": if browser {
                    "This endpoint requires a stablecoin payment. Open the browser setup URL to configure Pay using OAuth, then retry this request."
                } else {
                    "This endpoint requires a stablecoin payment. Install Pay, run pay setup, then retry this request with a payment-capable client. Ask the user before installing software or approving payments."
                },
                "cli": {
                    "install": "npm install -g @solana/pay",
                    "setup": "pay setup",
                    "docs_url": "https://pay.sh"
                },
                "browser": { "url": browser_url.as_str() }
            }
        })),
    )
        .into_response();
    response.headers_mut().insert(
        header::VARY,
        HeaderValue::from_static("User-Agent, Sec-Fetch-Mode"),
    );
    response
}

fn recommends_browser(headers: &HeaderMap) -> bool {
    // Fetch metadata takes precedence, including malformed/non-navigation values.
    if let Some(mode) = headers.get("sec-fetch-mode") {
        return mode
            .to_str()
            .is_ok_and(|mode| mode.trim().eq_ignore_ascii_case("navigate"));
    }
    let agent = headers
        .get(header::USER_AGENT)
        .and_then(|agent| agent.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if [
        "curl", "wget", "httpie", "python", "node", "undici", "fetch", "claude", "codex",
    ]
    .iter()
    .any(|client| agent.contains(client))
    {
        return false;
    }
    agent.contains("mozilla/")
}

/// Build the 402 response carrying *both* protocol challenges.
fn challenge_response(pay: &PayKit, amount: &str, req: &Request) -> Response {
    let mut resp = hint_response(pay, req);
    let headers = resp.headers_mut();

    // MPP: WWW-Authenticate. A failure here drops the MPP challenge from the
    // 402 (x402 clients are unaffected), so log it for operators.
    let route = mpp_route(req);
    let options = crate::mpp::server::ChargeOptions {
        route: Some(&route),
        ..Default::default()
    };
    match pay.mpp.charge_with_options(amount, options) {
        Ok(challenge) => match format_www_authenticate(&challenge) {
            Ok(www_auth) => match HeaderValue::from_str(&www_auth) {
                Ok(v) => {
                    headers.insert(header::WWW_AUTHENTICATE, v);
                }
                Err(e) => {
                    tracing::warn!(amount = %amount, error = %e, "invalid MPP challenge header value")
                }
            },
            Err(e) => {
                tracing::warn!(amount = %amount, error = %e, "failed to format MPP challenge")
            }
        },
        Err(e) => tracing::warn!(amount = %amount, error = %e, "failed to build MPP challenge"),
    }

    // x402: PAYMENT-REQUIRED.
    let binding = ExactBinding::of(req);
    match pay.x402.payment_required_header(amount, binding.options()) {
        Ok((name, value)) => match (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(&value),
        ) {
            (Ok(n), Ok(v)) => {
                headers.insert(n, v);
            }
            _ => tracing::warn!(amount = %amount, "invalid x402 PAYMENT-REQUIRED header"),
        },
        Err(e) => tracing::warn!(amount = %amount, error = %e, "failed to build x402 challenge"),
    }

    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

/// Keep a paid response out of shared caches, which key on the URL and would
/// serve it to later requests that carry no payment.
fn prevent_shared_caching(resp: &mut Response) {
    let restrictive = resp
        .headers()
        .get_all(header::CACHE_CONTROL)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|directive| {
            let directive = directive.trim();
            directive.eq_ignore_ascii_case("private") || directive.eq_ignore_ascii_case("no-store")
        });
    if !restrictive {
        resp.headers_mut().insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("private, no-store"),
        );
    }
}

fn attach_mpp_receipt(resp: &mut Response, receipt: &Receipt) {
    let kind = ReceiptKind::Charge(receipt.clone());
    if let Ok(value) = format_receipt(&kind) {
        if let (Ok(n), Ok(v)) = (
            HeaderName::from_bytes(PAYMENT_RECEIPT_HEADER.as_bytes()),
            HeaderValue::from_str(&value),
        ) {
            resp.headers_mut().insert(n, v);
        }
    }
}

/// Settle a verified x402 `exact` payment and return its confirmed signature.
/// A transaction proof moves no funds until it is broadcast, so it is never
/// served without a fee-payer signer to settle it.
async fn settle_x402(
    pay: &PayKit,
    verified: VerifiedExactPayment,
) -> Result<String, crate::x402::Error> {
    match (&verified, pay.fee_payer_signer.as_deref()) {
        (VerifiedExactPayment::Signature(signature), _) => {
            pay.x402.consume_signature(signature).await?;
            Ok(signature.clone())
        }
        (VerifiedExactPayment::Transaction(_), Some(signer)) => {
            pay.x402.settle_exact(verified, signer).await
        }
        (VerifiedExactPayment::Transaction(_), None) => Err(crate::x402::Error::Other(
            "x402 transaction payments require a fee_payer_signer".into(),
        )),
    }
}

fn attach_x402_response(resp: &mut Response, reference: &str) {
    if let (Ok(n), Ok(v)) = (
        HeaderName::from_bytes(PAYMENT_RESPONSE_HEADER.as_bytes()),
        HeaderValue::from_str(reference),
    ) {
        resp.headers_mut().insert(n, v);
    }
}

async fn gate_middleware(State(state): State<GateState>, mut req: Request, next: Next) -> Response {
    // Resolve the price first — dynamic routes price off the request, and the
    // resolved amount is what each protocol pins the credential against.
    let amount = match resolve_amount(&state.price, &req) {
        Ok(amount) => amount,
        Err(reason) => return (StatusCode::BAD_REQUEST, reason).into_response(),
    };

    // Detect the protocol from disjoint headers.
    let mpp_credential = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .filter(|s| s.starts_with("Payment "))
        .map(str::to_string);

    let x402_header = req
        .headers()
        .get(PAYMENT_SIGNATURE_HEADER)
        .or_else(|| req.headers().get(X402_V1_PAYMENT_HEADER))
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    // MPP path.
    if let Some(credential) = mpp_credential {
        return match state
            .pay
            .mpp
            .verify_payment_for_route(&credential, &amount, &mpp_route(&req))
            .await
        {
            Ok(receipt) => {
                req.extensions_mut().insert(Payment {
                    amount,
                    protocol: Protocol::Mpp,
                    reference: receipt.reference.clone(),
                });
                let mut resp = next.run(req).await;
                prevent_shared_caching(&mut resp);
                attach_mpp_receipt(&mut resp, &receipt);
                resp
            }
            Err(e) if is_settlement_in_progress(&e) => settlement_in_progress_response(&e),
            Err(_) => challenge_response(&state.pay, &amount, &req),
        };
    }

    // x402 path.
    if let Some(header_value) = x402_header {
        let binding = ExactBinding::of(&req);
        return match state
            .pay
            .x402
            .process_payment(&header_value, &amount, binding.options())
            .await
        {
            Ok(verified) => match settle_x402(&state.pay, verified).await {
                Ok(reference) => {
                    req.extensions_mut().insert(Payment {
                        amount,
                        protocol: Protocol::X402,
                        reference: reference.clone(),
                    });
                    let mut resp = next.run(req).await;
                    prevent_shared_caching(&mut resp);
                    attach_x402_response(&mut resp, &reference);
                    resp
                }
                // The payment may still land: a fresh challenge would invite
                // a second payment for this request.
                Err(e @ crate::x402::Error::SettlementPending(_)) => {
                    tracing::warn!(amount = %amount, error = %e, "x402 settlement pending");
                    let mut resp = (StatusCode::SERVICE_UNAVAILABLE, e.to_string()).into_response();
                    resp.headers_mut()
                        .insert(header::RETRY_AFTER, HeaderValue::from_static("2"));
                    resp
                }
                Err(e) => {
                    tracing::warn!(amount = %amount, error = %e, "x402 settlement failed");
                    challenge_response(&state.pay, &amount, &req)
                }
            },
            Err(_) => challenge_response(&state.pay, &amount, &req),
        };
    }

    // No credential of either protocol — advertise both challenges.
    challenge_response(&state.pay, &amount, &req)
}

/// Gate a `GET` handler behind payment verification at `price`, accepting
/// either MPP charge or x402.
pub fn paid_get<H, T, S>(handler: H, price: impl Into<Price>, pay: &PayKit) -> MethodRouter<S>
where
    H: Handler<T, S>,
    T: 'static,
    S: Clone + Send + Sync + 'static,
{
    get(handler).layer(from_fn_with_state(
        GateState {
            pay: pay.clone(),
            price: price.into(),
        },
        gate_middleware,
    ))
}

/// Gate a `POST` handler behind payment verification at `price`, accepting
/// either MPP charge or x402.
pub fn paid_post<H, T, S>(handler: H, price: impl Into<Price>, pay: &PayKit) -> MethodRouter<S>
where
    H: Handler<T, S>,
    T: 'static,
    S: Clone + Send + Sync + 'static,
{
    post(handler).layer(from_fn_with_state(
        GateState {
            pay: pay.clone(),
            price: price.into(),
        },
        gate_middleware,
    ))
}

/// Build the 402 response advertising the x402 `upto` challenge.
///
/// If the challenge can't be built — e.g. the operator's RPC is down so no
/// recent blockhash is available — return a retryable `503` instead of a `402`
/// carrying no challenge the client could act on.
fn upto_challenge_response(upto: &X402Upto, amount: &str, pay: &PayKit, req: &Request) -> Response {
    let route = upto_route(req);
    let (name, value) = match upto.payment_required_header_for_route(amount, Some(&route)) {
        Ok(header) => header,
        Err(e) => {
            tracing::warn!(amount = %amount, error = %e, "failed to build upto challenge");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "payment challenge temporarily unavailable",
            )
                .into_response();
        }
    };
    let mut resp = hint_response(pay, req);
    match (
        HeaderName::from_bytes(name.as_bytes()),
        HeaderValue::from_str(&value),
    ) {
        (Ok(n), Ok(v)) => {
            resp.headers_mut().insert(n, v);
        }
        _ => tracing::warn!(amount = %amount, "invalid x402 upto PAYMENT-REQUIRED header"),
    }
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

/// The request identity an `upto` authorization is bound to: method and the
/// pre-nesting path and query. The host is left out because it is
/// client-supplied and does not select the handler.
fn upto_route(req: &Request) -> String {
    let uri = req
        .extensions()
        .get::<axum::extract::OriginalUri>()
        .map_or(req.uri(), |original| &original.0);
    let path = uri.path_and_query().map_or("/", |pq| pq.as_str());
    format!("{} {path}", req.method())
}

/// Usage-based gate: verify the authorization and broadcast the channel open,
/// run the handler, then settle the actual metered amount and refund the rest.
async fn upto_gate_middleware(
    State(state): State<GateState>,
    mut req: Request,
    next: Next,
) -> Response {
    let amount = match resolve_amount(&state.price, &req) {
        Ok(amount) => amount,
        Err(reason) => return (StatusCode::BAD_REQUEST, reason).into_response(),
    };

    let Some(upto) = state.pay.x402_upto.clone() else {
        tracing::error!("paid_upto route used but no fee_payer_signer configured");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "upto routes require a fee_payer_signer",
        )
            .into_response();
    };

    let x402_header = req
        .headers()
        .get(PAYMENT_SIGNATURE_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    let Some(header_value) = x402_header else {
        return upto_challenge_response(&upto, &amount, &state.pay, &req);
    };

    // Verify the authorization and broadcast + confirm the channel open. The
    // challenge bound it to this route, so another route's authorization fails.
    let route = upto_route(&req);
    let open = match upto
        .verify_open_for_route(&header_value, &amount, Some(&route))
        .await
    {
        Ok(open) => open,
        Err(e) => {
            tracing::warn!(amount = %amount, error = %e, "upto open verification failed");
            return upto_challenge_response(&upto, &amount, &state.pay, &req);
        }
    };

    // Run the handler with a usage meter; default to a zero charge.
    let cell = Arc::new(Mutex::new(None));
    let charge = Charge {
        cell: cell.clone(),
        max_base_units: open.max_amount,
    };
    req.extensions_mut().insert(Payment {
        amount: amount.clone(),
        protocol: Protocol::X402,
        reference: open.channel_id.to_string(),
    });
    req.extensions_mut().insert(charge);
    // A lazy body may meter while it is polled, after the handler future has
    // returned, so the charge is read only once the body is complete.
    let metered = buffer_metered_response(next.run(req).await).await;

    // Recover from poisoning so a handler that panicked *after* recording a
    // charge still settles the amount it consumed (not a silent zero refund).
    let actual = (*cell.lock().unwrap_or_else(|e| e.into_inner())).unwrap_or(0);
    let metered = metered.map(|mut resp| {
        prevent_shared_caching(&mut resp);
        resp
    });
    ServedUpto::settle(&upto, open, actual, metered, UPTO_SETTLEMENT_RETRY)
        .respond(&upto)
        .await
}

/// A served `upto` request whose settlement already runs on its own task, so
/// dropping the request future (a client disconnect) cannot cancel it. The
/// gate's response is built only by [`ServedUpto::respond`], which releases
/// the metered body only against a confirmed settlement.
struct ServedUpto {
    body: Result<Response, axum::Error>,
    settlement: tokio::task::JoinHandle<Option<crate::x402::upto::UptoSettlementResponse>>,
}

impl ServedUpto {
    /// Settle `actual` and refund the remainder of `open`.
    fn settle(
        upto: &Arc<X402Upto>,
        open: crate::x402::server::VerifiedUptoOpen,
        actual: u64,
        body: Result<Response, axum::Error>,
        retry: UptoSettlementRetry,
    ) -> Self {
        let upto = Arc::clone(upto);
        let settlement =
            tokio::spawn(async move { settle_served_upto(&upto, open, actual, retry).await });
        Self { body, settlement }
    }

    /// Wait for the inline settlement, then release the response through
    /// [`release_upto_response`].
    async fn respond(self, upto: &X402Upto) -> Response {
        let settlement = self.settlement.await.unwrap_or_else(|error| {
            tracing::error!(error = %error, "upto settlement task failed");
            None
        });
        release_upto_response(upto, self.body, settlement)
    }
}

/// The protected body leaves the gate together with a settlement receipt:
/// a confirmed one, or one naming a submitted settlement that may still land
/// (`settlement_pending`). Without either, no attempt can have charged the
/// payer, so the body is withheld (502) rather than served unpaid and the
/// background retry refunds the channel in full (see [`settle_served_upto`]).
/// A body that never completed also answers 502.
fn release_upto_response(
    upto: &X402Upto,
    body: Result<Response, axum::Error>,
    settlement: Option<crate::x402::upto::UptoSettlementResponse>,
) -> Response {
    let mut resp = match body {
        Ok(resp) => resp,
        Err(error) => {
            tracing::warn!(error = %error, "upto response body did not complete");
            return (
                StatusCode::BAD_GATEWAY,
                "resource response body failed or exceeded the metered size limit",
            )
                .into_response();
        }
    };
    let receipt = settlement
        .ok_or("settlement is not confirmed")
        .and_then(|settlement| {
            let (name, value) = upto
                .settlement_header(&settlement)
                .map_err(|_| "settlement header could not be encoded")?;
            Ok((
                HeaderName::from_bytes(name.as_bytes())
                    .map_err(|_| "settlement header name is invalid")?,
                HeaderValue::from_str(&value).map_err(|_| "settlement header value is invalid")?,
            ))
        });
    match receipt {
        Ok((name, value)) => {
            resp.headers_mut().insert(name, value);
            resp
        }
        Err(reason) => {
            tracing::error!(
                reason,
                "upto response withheld without a settlement receipt"
            );
            let mut withheld = (
                StatusCode::BAD_GATEWAY,
                "payment settlement could not be confirmed; the response is withheld",
            )
                .into_response();
            prevent_shared_caching(&mut withheld);
            withheld
        }
    }
}

/// Largest `upto` response body the gate buffers to observe its metering.
const MAX_UPTO_METERED_BODY_BYTES: usize = 16 * 1024 * 1024;

/// Drive `response`'s body to completion so a charge recorded while it is
/// produced is seen before settlement. Bodies over
/// [`MAX_UPTO_METERED_BODY_BYTES`] are refused rather than settled early.
async fn buffer_metered_response(response: Response) -> Result<Response, axum::Error> {
    let (parts, body) = response.into_parts();
    let bytes = to_bytes(body, MAX_UPTO_METERED_BODY_BYTES).await?;
    Ok(Response::from_parts(parts, Body::from(bytes)))
}

/// How hard a served `upto` request's settlement is retried: inline before
/// answering, then in the background holding the channel's in-flight guard.
#[derive(Clone, Copy)]
struct UptoSettlementRetry {
    inline_attempts: u32,
    background_attempts: u32,
    base_delay: std::time::Duration,
}

const UPTO_SETTLEMENT_RETRY: UptoSettlementRetry = UptoSettlementRetry {
    inline_attempts: 3,
    background_attempts: 8,
    base_delay: std::time::Duration::from_millis(250),
};

/// Run `settle` up to `attempts` times with exponential backoff.
async fn retry_upto_settlement<F, Fut>(
    attempts: u32,
    base_delay: std::time::Duration,
    mut settle: F,
) -> Result<crate::x402::upto::UptoSettlementResponse, crate::x402::Error>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<
        Output = Result<crate::x402::upto::UptoSettlementResponse, crate::x402::Error>,
    >,
{
    let mut last = None;
    for attempt in 0..attempts.max(1) {
        if attempt > 0 {
            tokio::time::sleep(base_delay.saturating_mul(1 << (attempt - 1).min(16))).await;
        }
        match settle().await {
            Ok(settlement) => return Ok(settlement),
            Err(error) => {
                tracing::warn!(attempt, error = %error, "upto settlement attempt failed");
                last = Some(error);
            }
        }
    }
    Err(last.unwrap_or_else(|| crate::x402::Error::Other("settlement did not run".into())))
}

/// Resolves a settlement whose outcome was unknown: its receipt once it
/// landed, `None` once it failed, an error while still unknown.
type UptoResolver = Arc<
    dyn for<'a> Fn(
            &'a crate::x402::server::VerifiedUptoOpen,
            u64,
            &'a str,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<
                            Option<crate::x402::upto::UptoSettlementResponse>,
                            crate::x402::Error,
                        >,
                    > + Send
                    + 'a,
            >,
        > + Send
        + Sync,
>;

/// Settles one amount against a verified open; the seam tests observe.
type UptoSettler = Arc<
    dyn for<'a> Fn(
            &'a crate::x402::server::VerifiedUptoOpen,
            u64,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<
                            crate::x402::upto::UptoSettlementResponse,
                            crate::x402::Error,
                        >,
                    > + Send
                    + 'a,
            >,
        > + Send
        + Sync,
>;

/// Settle a request whose handler already ran. The handler's effects cannot be
/// undone, so a failed settlement is never dropped: after the inline attempts
/// the verified open moves into a background task that keeps retrying while
/// holding the channel's in-flight guard, so the authorization cannot be
/// presented again in the meantime. Returns the receipt when settled inline.
///
/// A payer who may be charged gets the response. A confirmed settlement
/// releases the body with its receipt. A submitted settlement whose outcome
/// is still unknown may land, so the body is released with a receipt naming
/// it as `settlement_pending` and the background keeps settling `actual`.
/// Only when no attempt can have landed is the response withheld (502) and
/// the background settles **zero**, refunding the whole deposit: charging
/// for a response the payer never received would be payment without
/// delivery, and `upto` has no replay path to deliver it later.
async fn settle_served_upto(
    upto: &Arc<X402Upto>,
    open: crate::x402::server::VerifiedUptoOpen,
    actual: u64,
    retry: UptoSettlementRetry,
) -> Option<crate::x402::upto::UptoSettlementResponse> {
    let settler: UptoSettler = {
        let upto = Arc::clone(upto);
        Arc::new(move |open, amount| {
            let upto = Arc::clone(&upto);
            Box::pin(async move { upto.settle_actual(open, amount).await })
        })
    };
    let resolver: UptoResolver = {
        let upto = Arc::clone(upto);
        Arc::new(move |open, amount, signature| {
            let upto = Arc::clone(&upto);
            Box::pin(async move { upto.settlement_outcome(open, amount, signature).await })
        })
    };
    settle_served_upto_with(settler, resolver, open, actual, retry).await
}

/// Resolve each signature in `pending`: return the receipt of one that
/// landed, and drop those that failed on chain (they charged nothing). The
/// signatures left are still unknown and may land.
async fn resolve_pending(
    resolve: &UptoResolver,
    open: &crate::x402::server::VerifiedUptoOpen,
    actual: u64,
    pending: &mut Vec<String>,
) -> Option<crate::x402::upto::UptoSettlementResponse> {
    let mut unknown = Vec::with_capacity(pending.len());
    for signature in pending.drain(..) {
        match resolve(open, actual, &signature).await {
            Ok(Some(settlement)) => return Some(settlement),
            Ok(None) => {}
            Err(_) => unknown.push(signature),
        }
    }
    *pending = unknown;
    None
}

async fn settle_served_upto_with(
    settle: UptoSettler,
    resolve: UptoResolver,
    open: crate::x402::server::VerifiedUptoOpen,
    actual: u64,
    retry: UptoSettlementRetry,
) -> Option<crate::x402::upto::UptoSettlementResponse> {
    // Every attempt whose outcome is unknown may still have paid `actual`,
    // and a later attempt then fails only because the channel is sealed.
    let submitted = std::sync::Mutex::new(Vec::<String>::new());
    let outcome = retry_upto_settlement(retry.inline_attempts, retry.base_delay, || {
        let attempt = settle(&open, actual);
        let submitted = &submitted;
        async move {
            let result = attempt.await;
            if let Err(crate::x402::Error::SettlementPending(signature)) = &result {
                submitted
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(signature.clone());
            }
            result
        }
    })
    .await;
    let mut submitted = submitted.into_inner().unwrap_or_else(|e| e.into_inner());
    let outcome = match outcome {
        Ok(settlement) => Ok(settlement),
        // Resolve those settlements before choosing between the body and a
        // refund: one that landed charged the payer, so the response is owed;
        // one that failed on chain charged nothing and is dropped.
        Err(error) => {
            let mut landed = None;
            for attempt in 0..retry.inline_attempts.max(1) {
                if submitted.is_empty() {
                    break;
                }
                if attempt > 0 {
                    tokio::time::sleep(retry.base_delay.saturating_mul(1 << (attempt - 1).min(16)))
                        .await;
                }
                landed = resolve_pending(&resolve, &open, actual, &mut submitted).await;
                if landed.is_some() {
                    break;
                }
            }
            landed.ok_or(error)
        }
    };
    match outcome {
        Ok(settlement) => Some(settlement),
        // A submitted settlement of `actual` may still land, so the payer may
        // be charged: the response is owed. It is released with a receipt
        // naming that transaction as not yet confirmed, and the background
        // keeps settling `actual` (never zero) until one lands.
        Err(error) if !submitted.is_empty() => {
            tracing::warn!(
                channel = %open.channel_id,
                actual,
                error = %error,
                unresolved = ?submitted,
                "upto settlement outcome unknown after the handler ran; the response is \
                 released and `actual` is settled in the background"
            );
            let pending = crate::x402::upto::UptoSettlementResponse {
                success: false,
                error_reason: Some("settlement_pending".into()),
                payer: Some(open.payer.to_string()),
                transaction: submitted.last().cloned().unwrap_or_default(),
                network: open.network.clone(),
                amount: actual.to_string(),
            };
            tokio::spawn(async move {
                let mut submitted = submitted;
                let delay = retry
                    .base_delay
                    .saturating_mul(1 << retry.inline_attempts.min(16));
                for attempt in 0..retry.background_attempts.max(1) {
                    tokio::time::sleep(delay.saturating_mul(1 << attempt.min(16))).await;
                    if let Some(settlement) =
                        resolve_pending(&resolve, &open, actual, &mut submitted).await
                    {
                        tracing::info!(
                            channel = %open.channel_id,
                            tx = %settlement.transaction,
                            "pending upto settlement landed"
                        );
                        return;
                    }
                    // A new settlement cannot double-charge: the channel
                    // seals once, so it fails if an earlier one landed. One
                    // whose outcome is unknown joins the signatures resolved.
                    match settle(&open, actual).await {
                        Ok(settlement) => {
                            tracing::info!(
                                channel = %open.channel_id,
                                tx = %settlement.transaction,
                                "released upto response settled in the background"
                            );
                            return;
                        }
                        Err(crate::x402::Error::SettlementPending(signature)) => {
                            submitted.push(signature)
                        }
                        Err(_) => {}
                    }
                }
                tracing::error!(
                    channel = %open.channel_id,
                    actual,
                    unresolved = ?submitted,
                    "released upto response is still unsettled; reconcile these signatures"
                );
            });
            Some(pending)
        }
        Err(error) => {
            tracing::error!(
                channel = %open.channel_id,
                actual,
                error = %error,
                "upto settlement failed after the handler ran; the response is withheld and \
                 the deposit is refunded in the background"
            );
            tokio::spawn(async move {
                let delay = retry
                    .base_delay
                    .saturating_mul(1 << retry.inline_attempts.min(16));
                match retry_upto_settlement(retry.background_attempts, delay, || settle(&open, 0))
                    .await
                {
                    Ok(settlement) => tracing::info!(
                        channel = %open.channel_id,
                        tx = %settlement.transaction,
                        "withheld upto response refunded in the background"
                    ),
                    Err(error) => tracing::error!(
                        channel = %open.channel_id,
                        actual,
                        error = %error,
                        "upto refund abandoned; the deposit stays locked until the channel expires"
                    ),
                }
            });
            None
        }
    }
}

/// Gate a `GET` handler behind x402 `upto` (usage-based) payment at the given
/// **maximum** price. The handler reports actual usage via the [`Charge`]
/// extractor; the gate settles that amount and refunds the rest.
///
/// Requires a `fee_payer_signer` on [`PayKitConfig`] (the operator signs the
/// settlement, as the channel's zero-share payee, and the vouchers).
pub fn paid_upto_get<H, T, S>(
    handler: H,
    max_price: impl Into<Price>,
    pay: &PayKit,
) -> MethodRouter<S>
where
    H: Handler<T, S>,
    T: 'static,
    S: Clone + Send + Sync + 'static,
{
    get(handler).layer(from_fn_with_state(
        GateState {
            pay: pay.clone(),
            price: max_price.into(),
        },
        upto_gate_middleware,
    ))
}

/// Gate a `POST` handler behind x402 `upto` (usage-based) payment at the given
/// **maximum** price. See [`paid_upto_get`].
pub fn paid_upto_post<H, T, S>(
    handler: H,
    max_price: impl Into<Price>,
    pay: &PayKit,
) -> MethodRouter<S>
where
    H: Handler<T, S>,
    T: 'static,
    S: Clone + Send + Sync + 'static,
{
    post(handler).layer(from_fn_with_state(
        GateState {
            pay: pay.clone(),
            price: max_price.into(),
        },
        upto_gate_middleware,
    ))
}

/// Build the 402 advertising the x402 `batch-settlement` challenge, or a
/// retryable `503` if it can't be built (e.g. the operator RPC is down).
///
/// `failure` carries the rejected payment header and its error, so a cumulative
/// mismatch is answered with the corrective challenge the client resynchronizes
/// from instead of a bare re-offer it would fail against again.
fn batch_challenge_response<'a>(
    batch: &'a X402BatchSettlement,
    amount: &'a str,
    resource: Option<&'a str>,
    failure: Option<(&'a str, crate::x402::Error)>,
    pay: &PayKit,
    req: &Request,
) -> impl std::future::Future<Output = Response> + Send + 'a {
    // Build the hint before awaiting: a borrowed request body is not Sync.
    let mut resp = hint_response(pay, req);
    async move {
        let header = match failure {
            Some((payment_header, error)) => {
                batch
                    .challenge_for_failure(payment_header, amount, &error, resource)
                    .await
            }
            None => batch.payment_required_header(amount, resource),
        };
        let (name, value) = match header {
            Ok(header) => header,
            Err(e) => {
                tracing::warn!(amount = %amount, error = %e, "failed to build batch-settlement challenge");
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "payment challenge temporarily unavailable",
                )
                    .into_response();
            }
        };
        if let (Ok(n), Ok(v)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(&value),
        ) {
            resp.headers_mut().insert(n, v);
        }
        resp.headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        resp
    }
}

/// The absolute URL of the routed request, for the x402 v2 `resource` field.
///
/// A request line usually carries only a path, so the authority comes from the
/// forwarded scheme and `Host`. Both are client-supplied; the resource is an
/// identifier echoed in the challenge, not a trust anchor — what a voucher
/// authorizes is bound to the channel and the price, never to this string.
/// The browser hint also echoes this untrusted context. Proxies must sanitize
/// `Host` and `x-forwarded-proto` if deployment-canonical URLs are required.
fn resource_url(req: &Request) -> Option<String> {
    let uri = external_uri(req);
    if uri.authority().is_some() {
        return Some(uri.to_string());
    }
    let host = req.headers().get(header::HOST)?.to_str().ok()?;
    let scheme = req
        .headers()
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("https");
    Some(format!("{scheme}://{host}{}", uri.path_and_query()?))
}

/// The x402 `exact` resource a request is challenged and verified against, so
/// a credential paid for one route cannot be presented on another.
fn exact_resource(req: &Request) -> String {
    resource_url(req).unwrap_or_else(|| {
        req.extensions()
            .get::<axum::extract::OriginalUri>()
            .map_or(req.uri(), |original| &original.0)
            .path_and_query()
            .map_or_else(|| "/".to_string(), ToString::to_string)
    })
}

/// What an x402 `exact` payment is challenged and verified against: the
/// route's resource and HTTP method. The resource in a credential is not
/// signed, so the binding the transaction carries is its memo
/// (`extra.memo`), derived from both: a payment made for `GET /x` cannot pay
/// for `POST /x` at the same price.
struct ExactBinding {
    resource: String,
    memo: String,
}

impl ExactBinding {
    fn of(req: &Request) -> Self {
        let resource = exact_resource(req);
        let memo = exact_memo(req.method(), &resource);
        Self { resource, memo }
    }

    fn options(&self) -> ExactOptions<'_> {
        ExactOptions {
            resource: Some(&self.resource),
            memo: Some(&self.memo),
            ..ExactOptions::default()
        }
    }
}

/// `"<METHOD> <base58 sha256(METHOD SP resource)>"`: within the 256-byte
/// `extra.memo` limit whatever the URL length.
fn exact_memo(method: &Method, resource: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(format!("{method} {resource}").as_bytes());
    format!("{method} {}", bs58::encode(digest).into_string())
}

/// Answer a request whose authorization was already charged and served.
///
/// The payment result is authoritative and is returned verbatim. When the
/// original resource response was cached, restore that representation too.
fn replayed_response(
    batch: &X402BatchSettlement,
    settlement: &crate::x402::batch_settlement::BatchSettlementResponse,
    cached: Option<&crate::core::store::CachedUpstreamResponse>,
) -> Response {
    let mut resp = if let Some(cached) = cached {
        let status = StatusCode::from_u16(cached.status).unwrap_or(StatusCode::OK);
        let mut response = (status, cached.body.clone()).into_response();
        if let Some(content_type) = &cached.content_type {
            if let Ok(value) = HeaderValue::from_str(content_type) {
                response.headers_mut().insert(header::CONTENT_TYPE, value);
            }
        }
        for (name, value) in &cached.headers {
            if let (Ok(name), Ok(value)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(value),
            ) {
                response.headers_mut().append(name, value);
            }
        }
        response
    } else {
        StatusCode::OK.into_response()
    };
    prevent_shared_caching(&mut resp);
    resp.headers_mut()
        .insert(PAYMENT_REPLAY_HEADER, HeaderValue::from_static("true"));
    attach_settlement_header(batch, settlement, &mut resp);
    resp
}

/// Headers whose meaning belongs to the stored representation rather than to
/// this particular transport hop or payment attempt.
fn is_replayable_response_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "accept-ranges"
            | "cache-control"
            | "content-security-policy"
            | "content-security-policy-report-only"
            | "content-disposition"
            | "content-encoding"
            | "content-language"
            | "content-location"
            | "content-range"
            | "cross-origin-embedder-policy"
            | "cross-origin-opener-policy"
            | "cross-origin-resource-policy"
            | "etag"
            | "expires"
            | "last-modified"
            | "location"
            | "permissions-policy"
            | "referrer-policy"
            | "reporting-endpoints"
            | "strict-transport-security"
            | "vary"
            | "x-content-type-options"
            | "x-frame-options"
            | "x-permitted-cross-domain-policies"
            | "x-xss-protection"
    )
}

/// Buffer a small, finite handler response so an authorization replay can
/// return the same representation. Streaming and large responses pass through
/// untouched and retain settlement-only replay semantics.
async fn cacheable_response(
    response: Response,
) -> Result<(Response, Option<crate::core::store::CachedUpstreamResponse>), axum::Error> {
    let size = response.body().size_hint();
    if size
        .upper()
        .is_none_or(|upper| upper > MAX_CACHED_RESPONSE_BYTES)
    {
        return Ok((response, None));
    }

    let (parts, body) = response.into_parts();
    let bytes = to_bytes(body, MAX_CACHED_RESPONSE_BYTES as usize).await?;
    let content_type = parts
        .headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);
    let headers = parts
        .headers
        .iter()
        .filter(|(name, _)| is_replayable_response_header(name))
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_owned(), value.to_owned()))
        })
        .collect();
    let cached = crate::core::store::CachedUpstreamResponse {
        status: parts.status.as_u16(),
        content_type,
        headers,
        body: bytes.to_vec(),
    };
    Ok((Response::from_parts(parts, Body::from(bytes)), Some(cached)))
}

/// High-throughput gate for x402 `batch-settlement`, under the scheme's
/// `authorization` payment flow.
///
/// The authorization is reserved durably before the handler runs, and charged
/// only after it succeeds — so a failed handler leaves the client uncharged and
/// free to retry the same voucher, a successful one is charged exactly once,
/// and a crash in between can only finish the charge, never re-serve.
///
/// Onchain redemption is deferred: drive `claim` / `settle` out of band via
/// [`PayKit::x402_batch`].
async fn batch_gate_middleware(
    State(state): State<GateState>,
    mut req: Request,
    next: Next,
) -> Response {
    let amount = match resolve_amount(&state.price, &req) {
        Ok(amount) => amount,
        Err(reason) => return (StatusCode::BAD_REQUEST, reason).into_response(),
    };

    let Some(batch) = state.pay.x402_batch.clone() else {
        tracing::error!("paid_batch route used but no fee_payer_signer configured");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "batch-settlement routes require a fee_payer_signer",
        )
            .into_response();
    };

    let x402_header = req
        .headers()
        .get(PAYMENT_SIGNATURE_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let resource = resource_url(&req);
    let Some(header_value) = x402_header else {
        return batch_challenge_response(
            &batch,
            &amount,
            resource.as_deref(),
            None,
            &state.pay,
            &req,
        )
        .await;
    };

    let access = match batch
        .verify_and_reserve_payment(&header_value, &amount)
        .await
    {
        Ok(access) => access,
        Err(e) => {
            tracing::warn!(amount = %amount, error = %e, "batch-settlement verification failed");
            // A cumulative mismatch comes back as a corrective 402 carrying the
            // server's snapshot, so the client can resynchronize and retry.
            return batch_challenge_response(
                &batch,
                &amount,
                resource.as_deref(),
                Some((&header_value, e)),
                &state.pay,
                &req,
            )
            .await;
        }
    };

    let outcome = match access {
        // Already charged and served. The client lost the response, not the
        // payment, so it gets the original result — never a second charge and
        // never a second execution.
        BatchAccess::Replay(settlement, cached) => {
            return replayed_response(&batch, &settlement, cached.as_ref());
        }

        // Another in-flight request owns this authorization. The retryable
        // scheme code is the body so a client can act on it without parsing
        // prose.
        BatchAccess::InProgress => {
            let mut resp = (
                StatusCode::CONFLICT,
                crate::x402::batch_settlement::errors::DUPLICATE_SETTLEMENT,
            )
                .into_response();
            resp.headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
            return resp;
        }

        // An earlier attempt's handler already succeeded; only its charge is
        // unfinished. Finishing it is the one safe continuation.
        BatchAccess::Resume(outcome) => {
            return match batch.finish_commit(&outcome).await {
                Ok(settlement) => replayed_response(&batch, &settlement, None),
                Err(e) => {
                    tracing::error!(error = %e, "batch-settlement commit could not be resumed");
                    (
                        StatusCode::BAD_GATEWAY,
                        "payment authorization could not be committed",
                    )
                        .into_response()
                }
            };
        }

        // A refund is a payment-control operation, not a paid request: the
        // application handler is bypassed entirely.
        BatchAccess::Control(outcome) => {
            return match batch.settle_payment(outcome).await {
                Ok(settlement) => {
                    let mut resp = (StatusCode::OK, "channel close initiated").into_response();
                    attach_settlement_header(&batch, &settlement, &mut resp);
                    resp
                }
                Err(e) => {
                    tracing::warn!(error = %e, "batch-settlement refund failed");
                    (StatusCode::BAD_GATEWAY, "channel close failed").into_response()
                }
            };
        }

        BatchAccess::Serve(outcome) => outcome,
    };

    let channel_id = outcome.channel_id.clone();
    req.extensions_mut().insert(Payment {
        amount: amount.clone(),
        protocol: Protocol::X402,
        reference: channel_id.clone(),
    });
    let mut resp = next.run(req).await;
    prevent_shared_caching(&mut resp);

    // A handler that declared it consumed nothing charges nothing: release the
    // authorization so the same voucher can be presented again. Any other
    // response, an error included, may follow a committed effect, so it is
    // charged and replayed rather than letting the voucher run the handler twice.
    if releases_batch_authorization(&resp) {
        if let Err(e) = batch.release_authorization(outcome).await {
            tracing::error!(
                channel = %channel_id,
                error = %e,
                "batch-settlement authorization could not be released after a failed handler"
            );
            // The reservation stands, and an unreleased one is never taken
            // over — serving another request on it would run the handler
            // twice. The client is uncharged but this voucher is spent.
            return (
                StatusCode::BAD_GATEWAY,
                "payment authorization could not be released; this voucher cannot be reused",
            )
                .into_response();
        }
        return resp;
    }

    let (mut resp, cached) = match cacheable_response(resp).await {
        Ok(response) => response,
        Err(error) => {
            tracing::warn!(channel = %channel_id, error = %error, "could not buffer handler response for replay");
            (
                (StatusCode::BAD_GATEWAY, "resource response body failed").into_response(),
                None,
            )
        }
    };

    // The crash boundary: past this point a retry may only finish the charge.
    //
    // A marker that fails to write is not a reason to abandon the charge. This
    // process watched the handler succeed; the marker only makes that durable
    // for a crash, and committing needs the reservation, not the marker. So a
    // failure here is logged and the charge is attempted anyway — otherwise a
    // store hiccup would serve the request for free and leave the client's
    // channel stuck at a watermark nothing can advance.
    if let Err(e) = batch.mark_handler_succeeded(&outcome).await {
        tracing::error!(
            channel = %channel_id,
            error = %e,
            "batch-settlement could not record a served handler; charging anyway"
        );
    }

    match commit_served_request(&batch, &outcome, &channel_id).await {
        Ok(settlement) => {
            if let Some(cached) = cached {
                if let Err(error) = batch.cache_response(&outcome, cached).await {
                    tracing::warn!(
                        channel = %channel_id,
                        error = %error,
                        "batch-settlement response cache write failed"
                    );
                }
            }
            attach_settlement_header(&batch, &settlement, &mut resp);
            resp
        }
        Err(e) => {
            // The handler already ran, so the client must not be told this
            // succeeded: a retry finishes the charge without re-serving.
            tracing::error!(
                channel = %channel_id,
                error = %e,
                "batch-settlement commit failed after the resource was served"
            );
            (
                StatusCode::BAD_GATEWAY,
                "payment authorization could not be committed; retry the same voucher",
            )
                .into_response()
        }
    }
}

/// Whether a batch handler's response proves it failed before delivering the
/// paid effect, so its authorization is released rather than charged: an
/// error status alone is not proof, it must carry [`PaymentNotConsumed`].
fn releases_batch_authorization(resp: &Response) -> bool {
    let status = resp.status();
    (status.is_client_error() || status.is_server_error())
        && resp.extensions().get::<PaymentNotConsumed>().is_some()
}

/// Attempts a served request's charge is willing to make before giving up.
const COMMIT_ATTEMPTS: u32 = 3;

/// Charge a request whose handler has already run, retrying a store that is
/// only briefly unavailable.
///
/// This is the last write standing between a served request and the payment
/// for it, and it is idempotent: committing an authorization that is already
/// committed leaves it alone, and a deposit's setup transaction is recovered
/// by its signature rather than broadcast again. So a store that blinks costs
/// a little latency instead of the charge.
///
/// What no number of attempts can cover is a store that stays unavailable, or
/// a process that exits mid-charge. Nothing durable can be written then, and
/// the authorization stays unreported — which a later retry treats as
/// terminal rather than serving it a second time. That direction is
/// deliberate: the scheme requires that one authorization never runs the
/// handler twice, so an outage costs the operator a served request rather
/// than costing the payer a duplicate execution.
async fn commit_served_request(
    batch: &X402BatchSettlement,
    outcome: &crate::x402::server::BatchOutcome,
    channel_id: &str,
) -> Result<crate::x402::batch_settlement::BatchSettlementResponse, crate::x402::Error> {
    let mut last = None;
    for attempt in 1..=COMMIT_ATTEMPTS {
        match batch.finish_commit(outcome).await {
            Ok(settlement) => return Ok(settlement),
            Err(error) => {
                tracing::warn!(
                    channel = %channel_id,
                    attempt,
                    error = %error,
                    "batch-settlement charge failed; retrying"
                );
                last = Some(error);
                if attempt < COMMIT_ATTEMPTS {
                    tokio::time::sleep(std::time::Duration::from_millis(100 * u64::from(attempt)))
                        .await;
                }
            }
        }
    }
    Err(last.unwrap_or_else(|| crate::x402::Error::Other("commit did not run".into())))
}

/// Attach the `PAYMENT-RESPONSE` settlement header to `resp`.
fn attach_settlement_header(
    batch: &X402BatchSettlement,
    response: &crate::x402::batch_settlement::BatchSettlementResponse,
    resp: &mut Response,
) {
    let Ok((name, value)) = batch.settlement_header(response) else {
        return;
    };
    if let (Ok(n), Ok(v)) = (
        HeaderName::from_bytes(name.as_bytes()),
        HeaderValue::from_str(&value),
    ) {
        resp.headers_mut().insert(n, v);
    }
}

/// Gate a `GET` handler behind x402 `batch-settlement` at the per-request
/// `price`. Requires a `fee_payer_signer`; settlement is batched out of band.
/// Every response is charged, error statuses included, unless it carries
/// [`PaymentNotConsumed`].
pub fn paid_batch_get<H, T, S>(handler: H, price: impl Into<Price>, pay: &PayKit) -> MethodRouter<S>
where
    H: Handler<T, S>,
    T: 'static,
    S: Clone + Send + Sync + 'static,
{
    get(handler).layer(from_fn_with_state(
        GateState {
            pay: pay.clone(),
            price: price.into(),
        },
        batch_gate_middleware,
    ))
}

/// Gate a `POST` handler behind x402 `batch-settlement`. See [`paid_batch_get`].
pub fn paid_batch_post<H, T, S>(
    handler: H,
    price: impl Into<Price>,
    pay: &PayKit,
) -> MethodRouter<S>
where
    H: Handler<T, S>,
    T: 'static,
    S: Clone + Send + Sync + 'static,
{
    post(handler).layer(from_fn_with_state(
        GateState {
            pay: pay.clone(),
            price: price.into(),
        },
        batch_gate_middleware,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::Router;
    use tower::ServiceExt; // oneshot

    const TEST_RECIPIENT: &str = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY";
    const TEST_SECRET: &str = "paykit-gate-test-secret-key-with-32b-padding";

    #[test]
    fn hint_classification() {
        for (mode, agent, browser) in [
            (None, None, false),
            (None, Some("unknown"), false),
            (None, Some("Mozilla/5.0"), true),
            (Some(" Navigate "), Some("curl"), true),
            (Some("cors"), Some("Mozilla/5.0"), false),
            (Some(""), Some("Mozilla/5.0"), false),
            (Some("same-origin"), None, false),
        ] {
            let mut headers = HeaderMap::new();
            if let Some(mode) = mode {
                headers.insert("sec-fetch-mode", mode.parse().unwrap());
            }
            if let Some(agent) = agent {
                headers.insert(header::USER_AGENT, agent.parse().unwrap());
            }
            assert_eq!(recommends_browser(&headers), browser);
        }
        for client in [
            "CURL", "Wget", "HTTPie", "Python", "Node", "Undici", "Fetch", "Claude", "Codex",
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(
                header::USER_AGENT,
                format!("Mozilla/5.0 {client}").parse().unwrap(),
            );
            assert!(!recommends_browser(&headers));
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn hint_default_and_config_optout() {
        assert!(!PayKitConfig::default().disable_hint);
        for disabled in [false, true] {
            let pay = PayKit::new(PayKitConfig {
                realm: Some("test-realm".to_string()),
                store: Some(Arc::new(crate::mpp::store::MemoryStore::new())),
                recipient: TEST_RECIPIENT.to_string(),
                challenge_binding_secret: Some(TEST_SECRET.to_string()),
                network: "devnet".to_string(),
                disable_hint: disabled,
                ..Default::default()
            })
            .unwrap();
            for browser in [false, true] {
                let app: Router = Router::new().route("/r", paid_get(report, "0.10", &pay));
                let response = app
                    .oneshot(
                        Request::builder()
                            .uri("/r")
                            .header("sec-fetch-mode", if browser { "navigate" } else { "cors" })
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
                assert!(response.headers().contains_key(header::WWW_AUTHENTICATE));
                assert!(response.headers().contains_key("payment-required"));
                assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
                if disabled {
                    assert!(!response.headers().contains_key(header::VARY));
                    assert_eq!(
                        response.headers()[header::CONTENT_TYPE],
                        "text/plain; charset=utf-8"
                    );
                } else {
                    assert_eq!(
                        response.headers()[header::VARY],
                        "User-Agent, Sec-Fetch-Mode"
                    );
                    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
                }
                let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
                if disabled {
                    assert_eq!(body.as_ref(), b"Payment Required");
                } else {
                    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
                    assert!(json.get("onboarding").is_none());
                    assert_eq!(json["error"], "payment_required");
                    assert_eq!(
                        json["hint"]["recommended"],
                        if browser { "browser" } else { "cli" }
                    );
                    assert_eq!(
                        json["hint"]["cli"],
                        serde_json::json!({
                            "install": "npm install -g @solana/pay",
                            "setup": "pay setup",
                            "docs_url": "https://pay.sh"
                        })
                    );
                    assert_eq!(
                        json["hint"]["browser"],
                        serde_json::json!({"url": "https://connect.pay.sh/mcp"})
                    );
                    assert_eq!(
                        json["hint"]["message"],
                        if browser {
                            "This endpoint requires a stablecoin payment. Open the browser setup URL to configure Pay using OAuth, then retry this request."
                        } else {
                            "This endpoint requires a stablecoin payment. Install Pay, run pay setup, then retry this request with a payment-capable client. Ask the user before installing software or approving payments."
                        }
                    );
                }
            }
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn exact_hint_resource_url_roundtrips_and_invalid_resources_fall_back() {
        let pay = test_paykit();
        let query = "/r?x=1&next=https%3A%2F%2Fother.test%2Fp%3Fa%3D1%26b%3D2&raw=%2520";
        let absolute = format!("http://absolute.test:8080{query}");
        let forwarded = format!("http://example.test:8080{query}");
        let oversized = format!("/r?x={}", "x".repeat(4096));
        for (uri, host, scheme, expected) in [
            (
                absolute.as_str(),
                Some("ignored.test"),
                Some("https"),
                Some(absolute.as_str()),
            ),
            (
                query,
                Some("example.test:8080"),
                Some("http"),
                Some(forwarded.as_str()),
            ),
            (
                "/r",
                Some("example.test"),
                None,
                Some("https://example.test/r"),
            ),
            ("/r", None, None, None),
            ("/r", Some(""), None, None),
            ("/r", Some("[invalid"), None, None),
            ("/r", Some("bad host"), None, None),
            ("/r", Some("user:password@example.test"), None, None),
            ("/r", Some("@example.test"), None, None),
            (oversized.as_str(), Some("example.test"), None, None),
            ("/r", Some("example.test"), Some("ftp"), None),
            ("/r", Some("example.test"), Some("https,http"), None),
        ] {
            let mut request = Request::builder().uri(uri);
            if let Some(host) = host {
                request = request.header(header::HOST, host);
            }
            if let Some(scheme) = scheme {
                request = request.header("x-forwarded-proto", scheme);
            }
            let app: Router = Router::new().route("/r", paid_get(report, "0.10", &pay));
            let response = app
                .oneshot(request.body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
            assert!(!response.headers().contains_key(header::LOCATION));
            let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert!(json.get("onboarding").is_none());
            let browser =
                url::Url::parse(json["hint"]["browser"]["url"].as_str().unwrap()).unwrap();
            assert_eq!(
                browser.origin().ascii_serialization(),
                "https://connect.pay.sh"
            );
            assert_eq!(browser.path(), "/mcp");
            let pairs: Vec<_> = browser
                .query_pairs()
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .collect();
            assert_eq!(
                pairs,
                expected
                    .map(|value| vec![("resource_uri".to_string(), value.to_string())])
                    .unwrap_or_default(),
                "{uri}, {host:?}, {scheme:?}"
            );
            if expected.is_none() {
                assert_eq!(browser.as_str(), "https://connect.pay.sh/mcp");
            }
        }
    }

    #[test]
    fn credit_provider_default_preserves_currency_defaults() {
        let config = PayKitConfig::default();
        assert!(config.credit_providers.is_empty());
        assert_eq!(config.currency, "USDC");
        assert_eq!(config.decimals, 6);
        assert_eq!(config.network, "mainnet");
    }

    #[test]
    fn credit_provider_selection_fails_before_handler_construction() {
        for network in ["mainnet", "devnet", "localnet"] {
            for currency in ["USDC", "USDT", "custom-mint"] {
                // Deliberately omit recipient/secret: provider policy is checked
                // before protocol configuration, environment access or RPC.
                let result = PayKit::new(PayKitConfig {
                    realm: Some("test-realm".to_string()),
                    store: Some(Arc::new(crate::mpp::store::MemoryStore::new())),
                    currency: currency.to_string(),
                    network: network.to_string(),
                    credit_providers: vec![CreditProvider::Coinflow],
                    accepted_currencies: Some(vec!["USDC".to_string(), "USDT".to_string()]),
                    ..Default::default()
                });
                assert!(matches!(
                    result,
                    Err(PayKitError::CreditProvider(
                        CreditProviderError::Unavailable {
                            provider: CreditProvider::Coinflow,
                        }
                    ))
                ));
            }
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn hint_resource_url_keeps_nested_route_prefix() {
        let pay = test_paykit();
        let app: Router = Router::new().nest(
            "/api",
            Router::new().route("/report", paid_get(report, "0.10", &pay)),
        );
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/report?x=1")
                    .header(header::HOST, "example.test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let browser = url::Url::parse(json["hint"]["browser"]["url"].as_str().unwrap()).unwrap();
        let resource: Vec<_> = browser
            .query_pairs()
            .filter(|(k, _)| k == "resource_uri")
            .map(|(_, v)| v.into_owned())
            .collect();
        assert_eq!(resource, ["https://example.test/api/report?x=1"]);
    }

    fn test_paykit_config() -> PayKitConfig {
        PayKitConfig {
            realm: Some("test-realm".to_string()),
            store: Some(Arc::new(crate::mpp::store::MemoryStore::new())),
            recipient: TEST_RECIPIENT.to_string(),
            challenge_binding_secret: Some(TEST_SECRET.to_string()),
            network: "devnet".to_string(),
            ..Default::default()
        }
    }

    fn test_paykit() -> PayKit {
        PayKit::new(test_paykit_config()).expect("valid paykit config")
    }

    async fn report(_payment: Payment) -> &'static str {
        "ok"
    }

    fn push_config(store: Option<Arc<dyn Store>>) -> PayKitConfig {
        PayKitConfig {
            recipient: TEST_RECIPIENT.to_string(),
            challenge_binding_secret: Some(TEST_SECRET.to_string()),
            network: "devnet".to_string(),
            realm: Some("test-realm".to_string()),
            accept_push_mode: true,
            store,
            ..Default::default()
        }
    }

    #[test]
    fn push_mode_without_shared_store_is_rejected() {
        let err = PayKit::new(push_config(None))
            .err()
            .expect("must fail closed");
        assert!(
            matches!(err, PayKitError::Mpp(ref m) if m.contains("store")),
            "{err}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn push_signature_consumed_on_one_replica_is_rejected_on_another() {
        let shared: Arc<dyn Store> = Arc::new(crate::mpp::store::MemoryStore::new());
        let replica_a = PayKit::new(push_config(Some(shared.clone()))).unwrap();
        let replica_b = PayKit::new(push_config(Some(shared))).unwrap();
        let signature = "5VERv8NMvzbJMEkV8xnrLkEaWRtSz9CosKDYjCJjBRnbJLgp8uirBgmQpjKhoR4tjF3ZpRzrFmBV6UjKdiSZkQUW";

        replica_a.mpp().consume_signature(signature).await.unwrap();
        assert!(replica_b.mpp().consume_signature(signature).await.is_err());
        // A different signature is still accepted.
        replica_b
            .mpp()
            .consume_signature("other-signature")
            .await
            .unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn x402_signature_consumed_on_one_replica_is_rejected_on_another() {
        let shared: Arc<dyn Store> = Arc::new(crate::mpp::store::MemoryStore::new());
        let replica_a = PayKit::new(push_config(Some(shared.clone()))).unwrap();
        let replica_b = PayKit::new(push_config(Some(shared))).unwrap();
        let signature = "5VERv8NMvzbJMEkV8xnrLkEaWRtSz9CosKDYjCJjBRnbJLgp8uirBgmQpjKhoR4tjF3ZpRzrFmBV6UjKdiSZkQUW";

        replica_a.x402().consume_signature(signature).await.unwrap();
        assert!(replica_b.x402().consume_signature(signature).await.is_err());
        replica_b
            .x402()
            .consume_signature("other-signature")
            .await
            .unwrap();
    }

    // One on-chain payment authorizes one request across protocols: a
    // signature settled through MPP cannot be presented again as an x402
    // proof on a gate sharing the store, nor the other way round.
    #[tokio::test(flavor = "multi_thread")]
    async fn signature_consumed_by_one_protocol_is_rejected_by_the_other() {
        let pay = PayKit::new(push_config(Some(Arc::new(
            crate::mpp::store::MemoryStore::new(),
        ))))
        .unwrap();
        let mpp_paid = "5VERv8NMvzbJMEkV8xnrLkEaWRtSz9CosKDYjCJjBRnbJLgp8uirBgmQpjKhoR4tjF3ZpRzrFmBV6UjKdiSZkQUW";
        let x402_paid = "other-signature";

        pay.mpp().consume_signature(mpp_paid).await.unwrap();
        let err = pay.x402().consume_signature(mpp_paid).await.unwrap_err();
        assert!(err.to_string().contains("already consumed"), "{err}");

        pay.x402().consume_signature(x402_paid).await.unwrap();
        let err = pay.mpp().consume_signature(x402_paid).await.unwrap_err();
        assert_eq!(err.code, Some("signature-consumed"), "{err:?}");

        // An unrelated payment is still accepted by either protocol.
        pay.mpp()
            .consume_signature("third-signature")
            .await
            .unwrap();
    }

    // An x402 settlement whose broadcast outcome is unknown keeps its claim
    // pending; MPP must treat that signature as taken until it resolves.
    #[tokio::test(flavor = "multi_thread")]
    async fn mpp_rejects_a_signature_with_a_pending_x402_settlement() {
        use crate::core::store::{ConsumedSignatures, PendingClaim};
        let store: Arc<dyn Store> = Arc::new(crate::mpp::store::MemoryStore::new());
        let pay = PayKit::new(push_config(Some(store.clone()))).unwrap();
        let ledger = ConsumedSignatures::new(store);
        let (pending, released) = ("pending-signature", "released-signature");

        for signature in [pending, released] {
            assert_eq!(
                ledger.claim_pending(signature).await.unwrap(),
                PendingClaim::Fresh
            );
            let err = pay.mpp().consume_signature(signature).await.unwrap_err();
            assert_eq!(err.code, Some("signature-consumed"), "{err:?}");
        }
        assert_eq!(
            ledger.claim_pending(pending).await.unwrap(),
            PendingClaim::ResumePending
        );

        // It landed: consumed for good, by either protocol.
        assert!(ledger.confirm(pending).await.unwrap());
        assert!(!ledger.confirm(pending).await.unwrap());
        assert_eq!(
            ledger.claim_pending(pending).await.unwrap(),
            PendingClaim::Consumed
        );
        assert!(pay.mpp().consume_signature(pending).await.is_err());

        // It provably never landed: the signature is free again.
        assert!(ledger.release_pending(released).await.unwrap());
        pay.mpp().consume_signature(released).await.unwrap();
    }

    #[test]
    fn store_is_required_even_when_push_mode_is_off() {
        let err = PayKit::new(PayKitConfig {
            accept_push_mode: false,
            store: None,
            ..push_config(None)
        })
        .err()
        .expect("must fail closed");
        assert!(
            matches!(err, PayKitError::Mpp(ref m) if m.contains("store")),
            "{err}"
        );
        assert!(PayKit::new(PayKitConfig {
            accept_push_mode: false,
            ..push_config(Some(Arc::new(crate::mpp::store::MemoryStore::new())))
        })
        .is_ok());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn upto_and_batch_challenges_include_hint() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let rpc_url = format!("http://{}", listener.local_addr().unwrap());
        let rpc = Router::new().route(
            "/",
            post(
                |axum::Json(request): axum::Json<serde_json::Value>| async move {
                    assert_eq!(request["method"], "getLatestBlockhash");
                    axum::Json(serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": request["id"],
                        "result": {
                            "context": { "slot": 314 },
                            "value": {
                                "blockhash": "11111111111111111111111111111111",
                                "lastValidBlockHeight": 400
                            }
                        }
                    }))
                },
            ),
        );
        let server = tokio::spawn(async move { axum::serve(listener, rpc).await.unwrap() });
        for disabled in [false, true] {
            let pay = PayKit::new(PayKitConfig {
                realm: Some("test-realm".to_string()),
                store: Some(Arc::new(crate::mpp::store::MemoryStore::new())),
                recipient: TEST_RECIPIENT.to_string(),
                challenge_binding_secret: Some(TEST_SECRET.to_string()),
                network: "devnet".to_string(),
                rpc_url: Some(rpc_url.clone()),
                fee_payer_signer: Some(test_signer()),
                tx_v1: TxV1Mode::Off,
                disable_hint: disabled,
                ..Default::default()
            })
            .unwrap();
            let app: Router = Router::new()
                .route("/u", paid_upto_get(report, "1.00", &pay))
                .route("/b", paid_batch_get(report, "0.01", &pay))
                .route("/health", get(|| async { "healthy" }));
            for path in ["/u", "/b", "/health", "/missing"] {
                let request_uri = format!("{path}?x=1&next=%2Fp%3Fa%3D1%26b%3D2&encoded=%2520");
                let response = app
                    .clone()
                    .oneshot(
                        Request::builder()
                            .uri(&request_uri)
                            .header(header::HOST, "example.test:8080")
                            .header("x-forwarded-proto", "http")
                            .header("sec-fetch-mode", "navigate")
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                if path == "/health" || path == "/missing" {
                    assert_eq!(
                        response.status(),
                        if path == "/health" {
                            StatusCode::OK
                        } else {
                            StatusCode::NOT_FOUND
                        }
                    );
                    assert!(!response.headers().contains_key(header::VARY));
                    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
                    assert_eq!(
                        body.as_ref(),
                        if path == "/health" {
                            &b"healthy"[..]
                        } else {
                            &b""[..]
                        }
                    );
                    continue;
                }
                assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
                assert!(response.headers().contains_key("payment-required"));
                assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
                assert_eq!(response.headers().contains_key(header::VARY), !disabled);
                let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
                if disabled {
                    assert_eq!(body.as_ref(), b"Payment Required");
                } else {
                    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
                    assert_eq!(json["hint"]["recommended"], "browser");
                    assert_eq!(json["error"], "payment_required");
                    assert!(json.get("onboarding").is_none());
                    let browser =
                        url::Url::parse(json["hint"]["browser"]["url"].as_str().unwrap()).unwrap();
                    assert_eq!(
                        browser.query_pairs().collect::<Vec<_>>(),
                        vec![(
                            "resource_uri".into(),
                            format!("http://example.test:8080{request_uri}").into()
                        )]
                    );
                }
            }
        }
        server.abort();
        assert!(server.await.unwrap_err().is_cancelled());
    }

    fn test_signer() -> Arc<dyn TransactionSigner> {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let mut kp = [0u8; 64];
        kp[..32].copy_from_slice(sk.as_bytes());
        kp[32..].copy_from_slice(sk.verifying_key().as_bytes());
        Arc::new(crate::mpp::solana_keychain::MemorySigner::from_bytes(&kp).expect("valid keypair"))
    }

    /// PayKit with an operator signer (enables `upto`). A bogus RPC URL makes
    /// the recent-blockhash fetch fail fast — so the challenge can't be built
    /// offline and the gate surfaces a retryable 503.
    fn upto_paykit() -> PayKit {
        PayKit::new(PayKitConfig {
            realm: Some("test-realm".to_string()),
            store: Some(Arc::new(crate::mpp::store::MemoryStore::new())),
            recipient: TEST_RECIPIENT.to_string(),
            challenge_binding_secret: Some(TEST_SECRET.to_string()),
            network: "devnet".to_string(),
            rpc_url: Some("http://127.0.0.1:1".to_string()),
            fee_payer_signer: Some(test_signer()),
            ..Default::default()
        })
        .expect("valid paykit config")
    }

    #[tokio::test]
    async fn upto_settlement_retries_until_it_lands() {
        let calls = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let counter = Arc::clone(&calls);
        let settled = retry_upto_settlement(3, std::time::Duration::ZERO, || {
            let attempt = counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            async move {
                if attempt < 2 {
                    Err(crate::x402::Error::Rpc("blockhash fetch failed".into()))
                } else {
                    Ok(crate::x402::upto::UptoSettlementResponse {
                        success: true,
                        error_reason: None,
                        payer: None,
                        transaction: "sig".into(),
                        network: "solana:devnet".into(),
                        amount: "7".into(),
                    })
                }
            }
        })
        .await
        .expect("the third attempt settles");
        assert_eq!(settled.transaction, "sig");
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 3);

        let calls = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let counter = Arc::clone(&calls);
        let failed = retry_upto_settlement(4, std::time::Duration::ZERO, || {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            async { Err(crate::x402::Error::Rpc("down".into())) }
        })
        .await;
        assert!(failed.is_err());
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 4);
    }

    /// A served request whose settlement fails is not dropped: the open moves
    /// into a background retry that keeps the channel reserved, so the same
    /// authorization cannot run the handler again while it is unpaid.
    #[tokio::test(flavor = "multi_thread")]
    async fn failed_upto_settlement_keeps_the_channel_reserved_while_it_retries() {
        let pay = upto_paykit();
        let upto = pay.x402_upto().expect("signer enables upto").clone();
        let channel = solana_pubkey::Pubkey::new_unique();
        let open = upto.test_open(channel, 1_000);
        let retry = UptoSettlementRetry {
            inline_attempts: 1,
            background_attempts: 2,
            base_delay: std::time::Duration::from_millis(200),
        };

        assert!(settle_served_upto(&upto, open, 500, retry).await.is_none());
        assert!(
            upto.is_in_flight(&channel),
            "the background retry must hold the channel"
        );

        for _ in 0..50 {
            if !upto.is_in_flight(&channel) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(
            !upto.is_in_flight(&channel),
            "the slot is released once the retries are exhausted"
        );
    }

    /// A response whose settlement is left to the background retry has not
    /// been paid for, so its body is withheld while the retry still settles.
    #[tokio::test(flavor = "multi_thread")]
    async fn pending_upto_settlement_withholds_the_response() {
        let pay = upto_paykit();
        let upto = pay.x402_upto().expect("signer enables upto").clone();
        let channel = solana_pubkey::Pubkey::new_unique();
        let open = upto.test_open(channel, 1_000);
        let retry = UptoSettlementRetry {
            inline_attempts: 1,
            background_attempts: 2,
            base_delay: std::time::Duration::from_millis(200),
        };

        let resp = ServedUpto::settle(
            &upto,
            open,
            500,
            Ok(Response::new(Body::from("served"))),
            retry,
        )
        .respond(&upto)
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
        assert!(!resp.headers().contains_key(PAYMENT_RESPONSE_HEADER));
        assert!(
            upto.is_in_flight(&channel),
            "the background retry still refunds the open"
        );
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        assert!(!body.as_ref().windows(6).any(|w| w == b"served"));
    }

    /// A withheld response must not be charged: the inline attempts settle the
    /// metered amount, and once they fail (the body is withheld) the
    /// background retry settles zero, refunding the deposit.
    #[tokio::test(flavor = "multi_thread")]
    async fn withheld_upto_response_is_refunded_not_charged() {
        let pay = upto_paykit();
        let upto = pay.x402_upto().expect("signer enables upto").clone();
        let channel = solana_pubkey::Pubkey::new_unique();
        let open = upto.test_open(channel, 1_000);
        let amounts = Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen = Arc::clone(&amounts);
        let settle: UptoSettler = Arc::new(move |_open, amount| {
            let seen = Arc::clone(&seen);
            Box::pin(async move {
                let mut seen = seen.lock().unwrap();
                seen.push(amount);
                // Inline attempts fail; the background refund lands.
                if seen.len() <= 2 {
                    return Err(crate::x402::Error::Rpc("node unreachable".into()));
                }
                Ok(crate::x402::upto::UptoSettlementResponse {
                    success: true,
                    error_reason: None,
                    payer: None,
                    transaction: "refund".into(),
                    network: "solana:devnet".into(),
                    amount: amount.to_string(),
                })
            })
        });
        let retry = UptoSettlementRetry {
            inline_attempts: 2,
            background_attempts: 2,
            base_delay: std::time::Duration::from_millis(1),
        };

        assert!(
            settle_served_upto_with(settle, never_resolved(), open, 500, retry)
                .await
                .is_none()
        );
        for _ in 0..100 {
            if amounts.lock().unwrap().len() >= 3 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert_eq!(*amounts.lock().unwrap(), vec![500, 500, 0]);
    }

    fn never_resolved() -> UptoResolver {
        Arc::new(|_open, _amount, signature| {
            let signature = signature.to_string();
            Box::pin(async move { Err(crate::x402::Error::SettlementPending(signature)) })
        })
    }

    /// An inline settlement whose outcome was unknown but which landed has
    /// charged the payer: the body is released with its receipt, and no zero
    /// settlement is attempted.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_landed_settlement_with_an_unknown_outcome_releases_the_response() {
        let pay = upto_paykit();
        let upto = pay.x402_upto().expect("signer enables upto").clone();
        let open = upto.test_open(solana_pubkey::Pubkey::new_unique(), 1_000);
        let amounts = Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen = Arc::clone(&amounts);
        let settle: UptoSettler = Arc::new(move |_open, amount| {
            let seen = Arc::clone(&seen);
            Box::pin(async move {
                let mut seen = seen.lock().unwrap();
                seen.push(amount);
                // The first send is accepted but never observed; the retry
                // fails because the channel is already sealed.
                if seen.len() == 1 {
                    Err(crate::x402::Error::SettlementPending("landed".into()))
                } else {
                    Err(crate::x402::Error::Rpc("channel sealed".into()))
                }
            })
        });
        let resolve: UptoResolver = Arc::new(|_open, amount, signature| {
            let landed = signature == "landed";
            Box::pin(async move {
                Ok(landed.then(|| crate::x402::upto::UptoSettlementResponse {
                    success: true,
                    error_reason: None,
                    payer: None,
                    transaction: "landed".into(),
                    network: "solana:devnet".into(),
                    amount: amount.to_string(),
                }))
            })
        });
        let retry = UptoSettlementRetry {
            inline_attempts: 2,
            background_attempts: 2,
            base_delay: std::time::Duration::from_millis(1),
        };

        let settled = settle_served_upto_with(settle, resolve, open, 500, retry)
            .await
            .expect("the landed settlement is the receipt");
        assert_eq!(settled.transaction, "landed");
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(
            *amounts.lock().unwrap(),
            vec![500, 500],
            "no zero settlement"
        );
    }

    /// A settlement whose outcome stays unknown may land and charge the
    /// payer, so the body is released with a pending receipt and the
    /// background keeps settling `actual`, never zero.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_unresolved_settlement_releases_the_response_and_never_refunds() {
        let pay = upto_paykit();
        let upto = pay.x402_upto().expect("signer enables upto").clone();
        let open = upto.test_open(solana_pubkey::Pubkey::new_unique(), 1_000);
        let amounts = Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen = Arc::clone(&amounts);
        let settle: UptoSettler = Arc::new(move |_open, amount| {
            let seen = Arc::clone(&seen);
            Box::pin(async move {
                seen.lock().unwrap().push(amount);
                Err(crate::x402::Error::SettlementPending("unknown".into()))
            })
        });
        let retry = UptoSettlementRetry {
            inline_attempts: 2,
            background_attempts: 2,
            base_delay: std::time::Duration::from_millis(1),
        };

        let pending = settle_served_upto_with(settle, never_resolved(), open, 500, retry)
            .await
            .expect("a settlement that may land releases the response");
        assert!(!pending.success);
        assert_eq!(pending.error_reason.as_deref(), Some("settlement_pending"));
        assert_eq!(pending.transaction, "unknown");
        for _ in 0..100 {
            if amounts.lock().unwrap().len() >= 4 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let amounts = amounts.lock().unwrap().clone();
        assert!(amounts.len() >= 3, "{amounts:?}");
        assert!(
            amounts.iter().all(|a| *a == 500),
            "never a zero settlement: {amounts:?}"
        );
    }

    /// A submitted settlement that failed on chain charged nothing: the body
    /// is withheld and the deposit refunded, as when nothing was submitted.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_settlement_that_failed_on_chain_withholds_the_response() {
        let pay = upto_paykit();
        let upto = pay.x402_upto().expect("signer enables upto").clone();
        let open = upto.test_open(solana_pubkey::Pubkey::new_unique(), 1_000);
        let amounts = Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen = Arc::clone(&amounts);
        let settle: UptoSettler = Arc::new(move |_open, amount| {
            let seen = Arc::clone(&seen);
            Box::pin(async move {
                seen.lock().unwrap().push(amount);
                if amount == 0 {
                    return Ok(crate::x402::upto::UptoSettlementResponse {
                        success: true,
                        error_reason: None,
                        payer: None,
                        transaction: "refund".into(),
                        network: "solana:devnet".into(),
                        amount: "0".into(),
                    });
                }
                Err(crate::x402::Error::SettlementPending("failed".into()))
            })
        });
        let failed: UptoResolver =
            Arc::new(|_open, _amount, _signature| Box::pin(async { Ok(None) }));
        let retry = UptoSettlementRetry {
            inline_attempts: 2,
            background_attempts: 2,
            base_delay: std::time::Duration::from_millis(1),
        };

        assert!(settle_served_upto_with(settle, failed, open, 500, retry)
            .await
            .is_none());
        for _ in 0..100 {
            if amounts.lock().unwrap().contains(&0) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert_eq!(*amounts.lock().unwrap(), vec![500, 500, 0]);
    }

    /// A background settlement whose own outcome is unknown is resolved
    /// later too: if it is the one that landed, recovery finds it.
    #[tokio::test(flavor = "multi_thread")]
    async fn background_recovery_resolves_its_own_pending_settlements() {
        let pay = upto_paykit();
        let upto = pay.x402_upto().expect("signer enables upto").clone();
        let open = upto.test_open(solana_pubkey::Pubkey::new_unique(), 1_000);
        let calls = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let counter = Arc::clone(&calls);
        let settle: UptoSettler = Arc::new(move |_open, _amount| {
            let n = counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async move {
                Err(crate::x402::Error::SettlementPending(if n == 0 {
                    "inline".into()
                } else {
                    format!("background-{n}")
                }))
            })
        });
        let found = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = Arc::clone(&found);
        let resolve: UptoResolver = Arc::new(move |_open, amount, signature| {
            let landed = signature == "background-1";
            if landed {
                flag.store(true, std::sync::atomic::Ordering::SeqCst);
            }
            let signature = signature.to_string();
            Box::pin(async move {
                if landed {
                    Ok(Some(crate::x402::upto::UptoSettlementResponse {
                        success: true,
                        error_reason: None,
                        payer: None,
                        transaction: signature,
                        network: "solana:devnet".into(),
                        amount: amount.to_string(),
                    }))
                } else {
                    Err(crate::x402::Error::SettlementPending(signature))
                }
            })
        });
        let retry = UptoSettlementRetry {
            inline_attempts: 1,
            background_attempts: 4,
            base_delay: std::time::Duration::from_millis(1),
        };

        let pending = settle_served_upto_with(settle, resolve, open, 500, retry)
            .await
            .expect("an unknown settlement releases the response");
        assert_eq!(pending.transaction, "inline");
        for _ in 0..200 {
            if found.load(std::sync::atomic::Ordering::SeqCst) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(
            found.load(std::sync::atomic::Ordering::SeqCst),
            "background-1 was never resolved"
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "no settlement after it landed"
        );
    }

    /// Positive control: a confirmed settlement releases the body with its
    /// receipt.
    #[test]
    fn confirmed_upto_settlement_releases_the_response() {
        let pay = upto_paykit();
        let upto = pay.x402_upto().expect("signer enables upto").clone();
        let settlement = crate::x402::upto::UptoSettlementResponse {
            success: true,
            error_reason: None,
            payer: None,
            transaction: "sig".into(),
            network: "solana:devnet".into(),
            amount: "500".into(),
        };
        let resp = release_upto_response(
            &upto,
            Ok(Response::new(Body::from("served"))),
            Some(settlement),
        );
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().contains_key(PAYMENT_RESPONSE_HEADER));

        let withheld = release_upto_response(&upto, Ok(Response::new(Body::from("served"))), None);
        assert_eq!(withheld.status(), StatusCode::BAD_GATEWAY);
    }

    /// A body that never completed has nothing to deliver: 502, while what was
    /// metered still settles.
    #[tokio::test(flavor = "multi_thread")]
    async fn incomplete_upto_body_answers_502_and_still_settles() {
        let pay = upto_paykit();
        let upto = pay.x402_upto().expect("signer enables upto").clone();
        let channel = solana_pubkey::Pubkey::new_unique();
        let open = upto.test_open(channel, 1_000);
        let retry = UptoSettlementRetry {
            inline_attempts: 1,
            background_attempts: 2,
            base_delay: std::time::Duration::from_millis(200),
        };

        let body = Err(axum::Error::new("body exceeded the metered size limit"));
        let resp = ServedUpto::settle(&upto, open, 500, body, retry)
            .respond(&upto)
            .await;
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
        assert!(
            upto.is_in_flight(&channel),
            "the metered amount still settles"
        );
    }

    /// A client disconnect during the inline retries drops the request future;
    /// the settlement keeps running and keeps the channel reserved.
    #[tokio::test(flavor = "multi_thread")]
    async fn dropped_request_does_not_cancel_upto_settlement() {
        let pay = upto_paykit();
        let upto = pay.x402_upto().expect("signer enables upto").clone();
        let channel = solana_pubkey::Pubkey::new_unique();
        let open = upto.test_open(channel, 1_000);
        let retry = UptoSettlementRetry {
            inline_attempts: 2,
            background_attempts: 1,
            base_delay: std::time::Duration::from_millis(400),
        };

        let served = ServedUpto::settle(&upto, open, 500, Ok(Response::new(Body::empty())), retry)
            .respond(&upto);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), served)
                .await
                .is_err(),
            "still inside the inline retries"
        );
        assert!(
            upto.is_in_flight(&channel),
            "settlement outlives the dropped request"
        );

        for _ in 0..100 {
            if !upto.is_in_flight(&channel) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(!upto.is_in_flight(&channel));
    }

    fn batch_channel_state(channel_id: &str, payer: &str) -> crate::core::store::ChannelState {
        crate::core::store::ChannelState {
            channel_id: channel_id.to_string(),
            authorized_signer: payer.to_string(),
            deposit: 5_000,
            cumulative: 0,
            sealed: false,
            highest_voucher_signature: None,
            highest_voucher_expires_at: None,
            close_requested_at: None,
            final_cumulative: None,
            open_slot: Some(341_000_000),
            payer: payer.to_string(),
            rent_payer: String::new(),
            opening_challenge_id: String::new(),
            authentication: None,
            voucher_signer: "client".to_string(),
            idle_timeout_seconds: None,
            last_activity_at: 0,
            spent_amount: 0,
            settled_on_chain: 0,
            distributed_on_chain: 0,
            processed_uses: vec![],
            processed_topup_signatures: vec![],
            next_delivery_sequence: 0,
            pending_deliveries: vec![],
            committed_deliveries: Default::default(),
            pending_setup: None,
            onchain_checked_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            lifecycle: None,
            schema_version: crate::core::store::CHANNEL_STATE_SCHEMA_VERSION,
            extra: Default::default(),
        }
    }

    /// A seeded batch channel and a `PAYMENT-SIGNATURE` paying its first
    /// 1,000-unit step.
    async fn batch_paid_request(pay: &PayKit) -> (String, String) {
        use crate::core::payment_channels as pc;
        use crate::core::store::ChannelStore as _;
        use crate::x402::batch_settlement::{
            derive_channel_id, BatchChannelConfig, BatchPayload, BatchPaymentPayload, BatchVoucher,
            VOUCHER_EXPIRES_AT,
        };
        use ed25519_dalek::Signer as _;

        let batch = pay.x402_batch().expect("signer enables batch");
        let requirements = batch.requirements("0.001").unwrap();
        let requirements_delay = requirements.extra.withdraw_delay;
        let key = ed25519_dalek::SigningKey::from_bytes(&[22u8; 32]);
        let payer = bs58::encode(key.verifying_key().as_bytes()).into_string();
        let config = BatchChannelConfig {
            payer: payer.clone(),
            payer_authorizer: payer.clone(),
            receiver: requirements.pay_to.clone(),
            receiver_authorizer: requirements.extra.receiver_authorizer.clone(),
            token: requirements.asset.clone(),
            withdraw_delay: requirements.extra.withdraw_delay,
            salt: "42".to_string(),
            open_slot: 341_000_000,
            voucher_signer: None,
        };
        let channel =
            derive_channel_id(&config, &batch.fee_payer(), &pc::default_program_id()).unwrap();
        let channel_id = pc::pubkey_string(&channel);
        let message = pc::voucher_message_bytes(&channel, 1_000, VOUCHER_EXPIRES_AT).unwrap();
        let payment = BatchPaymentPayload {
            x402_version: crate::x402::X402_VERSION_V2,
            accepted: requirements,
            payload: BatchPayload::Voucher {
                channel_config: config,
                voucher: BatchVoucher {
                    channel_id: channel_id.clone(),
                    max_claimable_amount: "1000".to_string(),
                    expires_at: VOUCHER_EXPIRES_AT,
                    signature: bs58::encode(key.sign(&message).to_bytes()).into_string(),
                },
            },
        };
        batch
            .store()
            .put_channel(&channel_id, {
                let mut state = batch_channel_state(&channel_id, &payer);
                state.set_binding(&batch.binding());
                state.set_grace_period(requirements_delay);
                state.record_onchain_observation(
                    crate::core::store::OnchainObservation {
                        slot: None,
                        lifecycle: crate::core::store::ObservedLifecycle::Open,
                    },
                    state.onchain_checked_at,
                );
                state
            })
            .await
            .unwrap();
        let header = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            serde_json::to_vec(&payment).unwrap(),
        );
        (channel_id, header)
    }

    async fn post_twice(app: Router, header: &str) -> Vec<Response> {
        let mut responses = Vec::new();
        for _ in 0..2 {
            responses.push(
                app.clone()
                    .oneshot(
                        Request::builder()
                            .method("POST")
                            .uri("/orders")
                            .header(PAYMENT_SIGNATURE_HEADER, header)
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap(),
            );
        }
        responses
    }

    /// A state-changing handler that answers with a redirect is charged, so
    /// the same voucher cannot run it a second time for free.
    #[tokio::test(flavor = "multi_thread")]
    async fn batch_redirect_is_charged_and_not_reexecuted() {
        use crate::core::store::ChannelStore as _;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let pay = upto_paykit();
        let (channel_id, header) = batch_paid_request(&pay).await;
        let executions = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&executions);
        let handler = move || {
            let counter = Arc::clone(&counter);
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                (
                    StatusCode::SEE_OTHER,
                    [(header::LOCATION, "/orders/created")],
                    "created",
                )
                    .into_response()
            }
        };
        let app: Router = Router::new().route("/orders", paid_batch_post(handler, "0.001", &pay));

        let responses = post_twice(app, &header).await;
        assert_eq!(responses[0].status(), StatusCode::SEE_OTHER);
        assert!(responses[0].headers().contains_key(PAYMENT_RESPONSE_HEADER));
        // The retry replays the committed redirect instead of re-running it.
        assert_eq!(responses[1].status(), StatusCode::SEE_OTHER);
        assert_eq!(responses[1].headers()[PAYMENT_REPLAY_HEADER], "true");
        assert_eq!(responses[1].headers()[header::LOCATION], "/orders/created");
        assert_eq!(executions.load(Ordering::SeqCst), 1);

        let state = pay
            .x402_batch()
            .unwrap()
            .store()
            .get_channel(&channel_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(state.cumulative, 1_000, "the redirect was charged");
    }

    /// An error response may follow a committed effect, so it is charged and
    /// replayed: the same voucher cannot run the handler a second time.
    #[tokio::test(flavor = "multi_thread")]
    async fn batch_error_response_is_charged_and_not_reexecuted() {
        use crate::core::store::ChannelStore as _;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let pay = upto_paykit();
        let (channel_id, header) = batch_paid_request(&pay).await;
        let executions = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&executions);
        let handler = move || {
            let counter = Arc::clone(&counter);
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                StatusCode::SERVICE_UNAVAILABLE
            }
        };
        let app: Router = Router::new().route("/orders", paid_batch_post(handler, "0.001", &pay));

        let responses = post_twice(app, &header).await;
        assert!(responses
            .iter()
            .all(|r| r.status() == StatusCode::SERVICE_UNAVAILABLE));
        assert_eq!(responses[1].headers()[PAYMENT_REPLAY_HEADER], "true");
        assert_eq!(executions.load(Ordering::SeqCst), 1);
        let state = pay
            .x402_batch()
            .unwrap()
            .store()
            .get_channel(&channel_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(state.cumulative, 1_000);
        assert!(state.pending_deliveries.is_empty());
    }

    /// An error response that declares [`PaymentNotConsumed`] releases the
    /// authorization for a retry.
    #[tokio::test(flavor = "multi_thread")]
    async fn batch_unconsumed_error_releases_the_voucher() {
        use crate::core::store::ChannelStore as _;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let pay = upto_paykit();
        let (channel_id, header) = batch_paid_request(&pay).await;
        let executions = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&executions);
        let handler = move || {
            let counter = Arc::clone(&counter);
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    axum::Extension(PaymentNotConsumed),
                )
            }
        };
        let app: Router = Router::new().route("/orders", paid_batch_post(handler, "0.001", &pay));

        let responses = post_twice(app, &header).await;
        assert!(responses
            .iter()
            .all(|r| r.status() == StatusCode::SERVICE_UNAVAILABLE));
        assert_eq!(executions.load(Ordering::SeqCst), 2);
        let state = pay
            .x402_batch()
            .unwrap()
            .store()
            .get_channel(&channel_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(state.cumulative, 0);
        assert!(state.pending_deliveries.is_empty());
    }

    #[test]
    fn only_declared_unconsumed_errors_release_a_batch_authorization() {
        fn resp(status: StatusCode, unconsumed: bool) -> Response {
            let mut resp = status.into_response();
            if unconsumed {
                resp.extensions_mut().insert(PaymentNotConsumed);
            }
            resp
        }
        assert!(!releases_batch_authorization(&resp(StatusCode::OK, true)));
        assert!(!releases_batch_authorization(&resp(
            StatusCode::SEE_OTHER,
            true
        )));
        assert!(!releases_batch_authorization(&resp(
            StatusCode::BAD_REQUEST,
            false
        )));
        assert!(!releases_batch_authorization(&resp(
            StatusCode::INTERNAL_SERVER_ERROR,
            false
        )));
        assert!(releases_batch_authorization(&resp(
            StatusCode::BAD_REQUEST,
            true
        )));
        assert!(releases_batch_authorization(&resp(
            StatusCode::INTERNAL_SERVER_ERROR,
            true
        )));
    }

    #[test]
    fn batch_routes_use_the_configured_channel_store() {
        let store: Arc<dyn crate::core::store::ChannelStore> =
            Arc::new(crate::core::store::MemoryChannelStore::new());
        let pay = PayKit::new(PayKitConfig {
            recipient: TEST_RECIPIENT.to_string(),
            challenge_binding_secret: Some(TEST_SECRET.to_string()),
            network: "devnet".to_string(),
            rpc_url: Some("http://127.0.0.1:1".to_string()),
            realm: Some("test-realm".to_string()),
            store: Some(Arc::new(crate::mpp::store::MemoryStore::new())),
            fee_payer_signer: Some(test_signer()),
            batch_channel_store: Some(Arc::clone(&store)),
            ..Default::default()
        })
        .unwrap();
        assert!(Arc::ptr_eq(pay.x402_batch().unwrap().store(), &store));
    }

    /// A body that records its usage only when it is polled.
    struct MeteredBody {
        charge: Charge,
        done: bool,
    }

    impl HttpBody for MeteredBody {
        type Data = axum::body::Bytes;
        type Error = std::convert::Infallible;

        fn poll_frame(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
            if self.done {
                return std::task::Poll::Ready(None);
            }
            self.done = true;
            self.charge.charge(250);
            std::task::Poll::Ready(Some(Ok(http_body::Frame::data(
                axum::body::Bytes::from_static(b"streamed"),
            ))))
        }
    }

    /// Usage metered while a lazy body streams is observed before settlement
    /// instead of settling the request at zero.
    #[tokio::test]
    async fn upto_metering_waits_for_a_lazy_body() {
        let cell = Arc::new(Mutex::new(None));
        let charge = Charge {
            cell: cell.clone(),
            max_base_units: 1_000,
        };
        let lazy = Response::new(Body::new(MeteredBody {
            charge,
            done: false,
        }));
        assert_eq!(*cell.lock().unwrap(), None, "nothing is metered yet");

        let buffered = buffer_metered_response(lazy).await.unwrap();
        assert_eq!(*cell.lock().unwrap(), Some(250));
        assert_eq!(
            to_bytes(buffered.into_body(), usize::MAX)
                .await
                .unwrap()
                .as_ref(),
            b"streamed"
        );

        let oversized = Response::new(Body::from(vec![0u8; MAX_UPTO_METERED_BODY_BYTES + 1]));
        assert!(buffer_metered_response(oversized).await.is_err());
    }

    #[test]
    fn upto_route_binds_method_path_and_query() {
        let req = |method: &str, uri: &str| {
            Request::builder()
                .method(method)
                .uri(uri)
                .header(header::HOST, "attacker.example")
                .body(Body::empty())
                .unwrap()
        };
        assert_eq!(upto_route(&req("GET", "/route-a?x=1")), "GET /route-a?x=1");
        assert_ne!(
            upto_route(&req("GET", "/route-a")),
            upto_route(&req("GET", "/route-b"))
        );
        assert_ne!(
            upto_route(&req("GET", "/orders")),
            upto_route(&req("POST", "/orders"))
        );
        let mut nested = req("GET", "/inner");
        nested
            .extensions_mut()
            .insert(axum::extract::OriginalUri("/api/inner".parse().unwrap()));
        assert_eq!(upto_route(&nested), "GET /api/inner");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn paid_upto_without_signer_returns_500() {
        // No fee_payer_signer → no upto handler → misconfiguration surfaces as 500.
        let pay = test_paykit();
        let app: Router = Router::new().route("/u", paid_upto_get(report, "1.00", &pay));
        let resp = app
            .oneshot(Request::builder().uri("/u").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn paid_upto_unpaid_returns_503_when_challenge_rpc_unavailable() {
        // With the operator RPC unreachable, no recent blockhash can be embedded
        // in the challenge, so the gate returns a retryable 503 rather than a
        // 402 carrying a challenge the in-SDK client could not act on.
        let pay = upto_paykit();
        let app: Router = Router::new().route("/u", paid_upto_get(report, "1.00", &pay));
        let resp = app
            .oneshot(Request::builder().uri("/u").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(!resp.headers().contains_key(header::VARY));
        assert_eq!(
            to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap()
                .as_ref(),
            b"payment challenge temporarily unavailable"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn paid_batch_without_signer_returns_500() {
        let pay = test_paykit();
        let app: Router = Router::new().route("/b", paid_batch_get(report, "0.01", &pay));
        let resp = app
            .oneshot(Request::builder().uri("/b").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn paid_batch_unpaid_returns_503_when_challenge_rpc_unavailable() {
        // The batch challenge embeds a recent blockhash; with the operator RPC
        // unreachable the gate returns a retryable 503 rather than a 402.
        let pay = upto_paykit();
        let app: Router = Router::new().route("/b", paid_batch_get(report, "0.01", &pay));
        let resp = app
            .oneshot(Request::builder().uri("/b").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(!resp.headers().contains_key(header::VARY));
        assert_eq!(
            to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap()
                .as_ref(),
            b"payment challenge temporarily unavailable"
        );
    }

    fn ctx<'a>(method: &'a Method, uri: &'a Uri, headers: &'a HeaderMap) -> PriceCtx<'a> {
        PriceCtx {
            method,
            uri,
            headers,
        }
    }

    #[test]
    fn price_fixed_from_str() {
        let method = Method::GET;
        let uri: Uri = "/x".parse().unwrap();
        let headers = HeaderMap::new();
        assert_eq!(
            Price::from("0.10").resolve(&ctx(&method, &uri, &headers)),
            "0.10"
        );
    }

    #[test]
    fn price_dynamic_reads_query_param() {
        let price = Price::dynamic(|c| match c.query_param("tier").as_deref() {
            Some("premium") => "5.00".to_string(),
            _ => "0.10".to_string(),
        });
        let method = Method::GET;
        let headers = HeaderMap::new();
        let premium: Uri = "/q?tier=premium".parse().unwrap();
        assert_eq!(price.resolve(&ctx(&method, &premium, &headers)), "5.00");
        let basic: Uri = "/q".parse().unwrap();
        assert_eq!(price.resolve(&ctx(&method, &basic, &headers)), "0.10");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn unpaid_returns_402_with_both_protocol_challenges() {
        let pay = test_paykit();
        let app: Router = Router::new().route("/r", paid_get(report, "0.10", &pay));
        let resp = app
            .oneshot(Request::builder().uri("/r").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
        // Both protocol challenges are advertised.
        assert!(resp.headers().contains_key(header::WWW_AUTHENTICATE));
        assert!(resp.headers().contains_key("payment-required"));
        assert_eq!(
            resp.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn payment_extractor_without_gate_is_500() {
        // The Payment extractor on an ungated route has no extension to read.
        let app: Router = Router::new().route("/r", get(report));
        let resp = app
            .oneshot(Request::builder().uri("/r").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn mpp_cross_route_replay_returns_402() {
        use crate::mpp::{format_authorization, PaymentCredential};

        let pay = test_paykit();
        // A credential minted for the $0.01 route...
        let cheap = pay.mpp().charge("0.01").unwrap();
        let cred = PaymentCredential::new(
            cheap.to_echo(),
            serde_json::json!({"type": "signature", "signature": "fakesig"}),
        );
        let auth = format_authorization(&cred).unwrap();

        // ...must not be accepted on the $1.00 route.
        let app: Router = Router::new().route("/r", paid_get(report, "1.00", &pay));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/r")
                    .header(header::AUTHORIZATION, auth)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
    }

    // A charge that may already be paid is never answered with a fresh
    // challenge: the client would pay it again. It retries the credential.
    #[tokio::test(flavor = "multi_thread")]
    async fn mpp_settlement_in_progress_is_not_rechallenged() {
        use crate::mpp::protocol::solana::CredentialPayload;
        use crate::mpp::store::{ChargeReplayStore, CHARGE_RESERVATION_LEASE};
        use crate::mpp::{format_authorization, PaymentCredential};

        let store: Arc<dyn Store> = Arc::new(crate::mpp::store::MemoryStore::new());
        let pay = PayKit::new(PayKitConfig {
            store: Some(store.clone()),
            ..test_paykit_config()
        })
        .unwrap();
        let app: Router = Router::new().route("/r", paid_get(report, "0.10", &pay));
        let send = |cred: PaymentCredential| {
            let app = app.clone();
            async move {
                app.oneshot(
                    Request::builder()
                        .uri("/r")
                        .header(header::AUTHORIZATION, format_authorization(&cred).unwrap())
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap()
            }
        };
        let credential = || {
            let options = crate::mpp::server::ChargeOptions {
                route: Some("GET /r"),
                ..Default::default()
            };
            PaymentCredential::new(
                pay.mpp()
                    .charge_with_options("0.10", options)
                    .unwrap()
                    .to_echo(),
                serde_json::json!({"type": "signature", "signature": "fakesig"}),
            )
        };

        // Another request is settling this exact credential.
        let busy = credential();
        let payload: CredentialPayload = serde_json::from_value(busy.payload.clone()).unwrap();
        let digest = crate::mpp::server::charge::normalized_request_digest(
            &busy.challenge.id,
            busy.challenge.request.raw(),
            &payload,
        )
        .unwrap();
        ChargeReplayStore::new(store)
            .reserve(&busy.challenge.id, &digest, CHARGE_RESERVATION_LEASE)
            .await
            .unwrap();
        let resp = send(busy).await;
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        assert!(!resp.headers().contains_key(header::WWW_AUTHENTICATE));
        assert!(!resp.headers().contains_key("payment-required"));
        assert_eq!(resp.headers()[header::RETRY_AFTER], "1");

        // A plainly rejected credential is still re-challenged.
        let resp = send(credential()).await;
        assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
        assert!(resp.headers().contains_key(header::WWW_AUTHENTICATE));
    }

    // An MPP credential is bound to the full host it was issued for: a second
    // authority serving the same path and price does not accept it.
    #[tokio::test(flavor = "multi_thread")]
    async fn mpp_credential_is_bound_to_the_issuing_host() {
        use crate::mpp::protocol::solana::CredentialPayload;
        use crate::mpp::store::{ChargeReplayStore, CHARGE_RESERVATION_LEASE};
        use crate::mpp::{format_authorization, PaymentCredential};

        let store: Arc<dyn Store> = Arc::new(crate::mpp::store::MemoryStore::new());
        let pay = PayKit::new(PayKitConfig {
            store: Some(store.clone()),
            ..test_paykit_config()
        })
        .unwrap();
        let app: Router = Router::new().route("/r", paid_get(report, "0.10", &pay));

        // Issued for host A. Hold it in progress so a credential that passes
        // the route check is observable (409) without settling anything.
        let mut host_a = HeaderMap::new();
        host_a.insert(header::HOST, HeaderValue::from_static("api.example"));
        let route = charge_route(&Method::GET, &"/r".parse().unwrap(), &host_a);
        let options = crate::mpp::server::ChargeOptions {
            route: Some(&route),
            ..Default::default()
        };
        let cred = PaymentCredential::new(
            pay.mpp()
                .charge_with_options("0.10", options)
                .unwrap()
                .to_echo(),
            serde_json::json!({"type": "signature", "signature": "fakesig"}),
        );
        let payload: CredentialPayload = serde_json::from_value(cred.payload.clone()).unwrap();
        let digest = crate::mpp::server::charge::normalized_request_digest(
            &cred.challenge.id,
            cred.challenge.request.raw(),
            &payload,
        )
        .unwrap();
        ChargeReplayStore::new(store)
            .reserve(&cred.challenge.id, &digest, CHARGE_RESERVATION_LEASE)
            .await
            .unwrap();
        let auth = format_authorization(&cred).unwrap();
        let send = |host: &'static str| {
            let app = app.clone();
            let auth = auth.clone();
            async move {
                app.oneshot(
                    Request::builder()
                        .uri("/r")
                        .header(header::HOST, host)
                        .header(header::AUTHORIZATION, auth)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap()
                .status()
            }
        };

        assert_eq!(
            send("api.attacker.example").await,
            StatusCode::PAYMENT_REQUIRED
        );
        assert_eq!(send("API.example").await, StatusCode::CONFLICT);
    }

    #[test]
    fn query_param_percent_decodes() {
        // A percent-encoded tier must decode so it can't dodge the premium
        // price by landing on the cheaper default.
        let price = Price::dynamic(|c| match c.query_param("tier").as_deref() {
            Some("premium") => "5.00".to_string(),
            _ => "0.10".to_string(),
        });
        let method = Method::GET;
        let headers = HeaderMap::new();
        let encoded: Uri = "/q?tier=premi%75m".parse().unwrap();
        assert_eq!(price.resolve(&ctx(&method, &encoded, &headers)), "5.00");
    }

    fn tier_price() -> Price {
        Price::dynamic(|c| match c.query_param("tier").as_deref() {
            Some("premium") => "5.00".to_string(),
            _ => "0.10".to_string(),
        })
    }

    /// Status and MPP challenge amount (base units) for an unpaid request.
    async fn challenged_amount(app: Router, uri: &str) -> (StatusCode, Option<String>) {
        let resp = app
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let amount = resp.headers().get(header::WWW_AUTHENTICATE).map(|value| {
            let challenge = crate::mpp::parse_www_authenticate(value.to_str().unwrap()).unwrap();
            let request: crate::mpp::ChargeRequest = challenge.request.decode().unwrap();
            request.amount
        });
        (resp.status(), amount)
    }

    #[test]
    fn query_param_decodes_names_and_values() {
        let method = Method::GET;
        let headers = HeaderMap::new();
        for raw in [
            "/q?tier=premium",
            "/q?%74ier=premium",
            "/q?%74%69%65%72=premi%75m",
            "/q?other=1&ti%65r=premium",
        ] {
            let uri: Uri = raw.parse().unwrap();
            assert_eq!(
                ctx(&method, &uri, &headers).query_param("tier").as_deref(),
                Some("premium"),
                "{raw}"
            );
        }
        let plus: Uri = "/q?a+b=c+d".parse().unwrap();
        assert_eq!(
            ctx(&method, &plus, &headers).query_param("a b").as_deref(),
            Some("c d")
        );
        let empty: Uri = "/q?tier".parse().unwrap();
        assert_eq!(
            ctx(&method, &empty, &headers)
                .query_param("tier")
                .as_deref(),
            Some("")
        );
        let none: Uri = "/q?tiers=premium".parse().unwrap();
        assert_eq!(ctx(&method, &none, &headers).query_param("tier"), None);
    }

    #[test]
    fn price_query_validation_rejects_malformed_escapes() {
        for ok in [
            None,
            Some(""),
            Some("tier=premium"),
            Some("t=%41%7a"),
            Some("a=%2B"),
        ] {
            assert!(validate_price_query(ok).is_ok(), "{ok:?}");
        }
        for bad in [
            "tier=%",
            "tier=%7",
            "%7gier=premium",
            "tier=premium%",
            "t=%%41",
        ] {
            assert!(validate_price_query(Some(bad)).is_err(), "{bad}");
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn encoded_query_name_gets_the_premium_challenge() {
        let pay = test_paykit();
        let app: Router = Router::new().route("/quote", paid_get(report, tier_price(), &pay));
        for uri in [
            "/quote?tier=premium",
            "/quote?%74ier=premium",
            "/quote?%74ier=premi%75m",
        ] {
            assert_eq!(
                challenged_amount(app.clone(), uri).await,
                (StatusCode::PAYMENT_REQUIRED, Some("5000000".to_string())),
                "{uri}"
            );
        }
        assert_eq!(
            challenged_amount(app.clone(), "/quote?tier=basic").await,
            (StatusCode::PAYMENT_REQUIRED, Some("100000".to_string()))
        );
        assert_eq!(
            challenged_amount(app, "/quote?%7tier=premium").await,
            (StatusCode::BAD_REQUEST, None)
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn fixed_price_ignores_query_encoding() {
        let pay = test_paykit();
        let app: Router = Router::new().route("/r", paid_get(report, "0.10", &pay));
        assert_eq!(
            challenged_amount(app, "/r?x=%zz").await,
            (StatusCode::PAYMENT_REQUIRED, Some("100000".to_string()))
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn x402_invalid_signature_returns_402() {
        // A PAYMENT-SIGNATURE header that doesn't verify takes the x402 path
        // and is rejected with a fresh 402 (it must not fall through to MPP).
        let pay = test_paykit();
        let app: Router = Router::new().route("/r", paid_get(report, "0.10", &pay));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/r")
                    .header("PAYMENT-SIGNATURE", "not-a-valid-x402-envelope")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
    }

    /// Decode the x402 `PAYMENT-REQUIRED` challenge from a 402 response.
    fn x402_challenge(resp: &Response) -> crate::x402::exact::PaymentRequiredEnvelope {
        let value = resp.headers().get("payment-required").unwrap();
        let decoded = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            value.to_str().unwrap(),
        )
        .unwrap();
        serde_json::from_slice::<crate::x402::exact::PaymentRequiredEnvelope>(&decoded)
            .unwrap()
            .with_resource_on_accepts()
    }

    fn get_with_host(uri: &str, payment: Option<&str>) -> Request {
        let mut request = Request::builder()
            .uri(uri)
            .header(header::HOST, "api.example.test");
        if let Some(payment) = payment {
            request = request.header("PAYMENT-SIGNATURE", payment);
        }
        request.body(Body::empty()).unwrap()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn x402_credential_for_one_route_is_rejected_on_another() {
        use crate::x402::server::exact::test_support::{
            exact_transaction, test_client, transaction_header,
        };

        let pay = test_paykit();
        let app: Router = Router::new()
            .route("/route-a", paid_get(report, "0.01", &pay))
            .route("/route-b", paid_get(report, "0.01", &pay));

        let challenge_a = x402_challenge(
            &app.clone()
                .oneshot(get_with_host("/route-a", None))
                .await
                .unwrap(),
        );
        let challenge_b = x402_challenge(
            &app.clone()
                .oneshot(get_with_host("/route-b", None))
                .await
                .unwrap(),
        );
        assert_eq!(
            challenge_a.resource.as_ref().map(|r| r.url.as_str()),
            Some("https://api.example.test/route-a")
        );
        assert_eq!(
            challenge_b.resource.as_ref().map(|r| r.url.as_str()),
            Some("https://api.example.test/route-b")
        );

        let requirement = &challenge_a.accepts[0];
        let payer = test_client();
        let tx = exact_transaction(requirement, &payer, &payer);
        let header = transaction_header(requirement, requirement.resource_info(), &tx);

        let replay = app
            .clone()
            .oneshot(get_with_host("/route-b", Some(&header)))
            .await
            .unwrap();
        assert_eq!(replay.status(), StatusCode::PAYMENT_REQUIRED);
        assert!(!replay.headers().contains_key(PAYMENT_RESPONSE_HEADER));
    }

    /// Minimal JSON-RPC node: confirms every broadcast unless `reject_sends`.
    async fn mock_rpc(reject_sends: bool) -> (String, Arc<std::sync::atomic::AtomicUsize>) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let sends = Arc::new(AtomicUsize::new(0));
        let counter = sends.clone();
        let app = Router::new().route(
            "/",
            post(move |axum::Json(body): axum::Json<serde_json::Value>| {
                let counter = counter.clone();
                async move {
                    let id = body["id"].clone();
                    let ok = |result: serde_json::Value| {
                        axum::Json(
                            serde_json::json!({"jsonrpc": "2.0", "id": id, "result": result}),
                        )
                    };
                    match body["method"].as_str().unwrap_or_default() {
                        "sendTransaction" if reject_sends => axum::Json(serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": body["id"],
                            "error": {"code": -32002, "message": "Transaction simulation failed"}
                        })),
                        "sendTransaction" => {
                            counter.fetch_add(1, Ordering::SeqCst);
                            let encoded = body["params"][0].as_str().unwrap();
                            let tx = crate::core::tx::decode(encoded).unwrap();
                            ok(serde_json::json!(tx.signatures[0].to_string()))
                        }
                        // A rejected send never lands.
                        "getSignatureStatuses" if reject_sends => ok(serde_json::json!({
                            "context": {"slot": 1},
                            "value": [null]
                        })),
                        "getSignatureStatuses" => ok(serde_json::json!({
                            "context": {"slot": 1},
                            "value": [{
                                "slot": 1,
                                "confirmations": null,
                                "err": null,
                                "status": {"Ok": null},
                                "confirmationStatus": "confirmed"
                            }]
                        })),
                        "getLatestBlockhash" => ok(serde_json::json!({
                            "context": {"slot": 1},
                            "value": {
                                "blockhash": solana_hash::Hash::new_unique().to_string(),
                                "lastValidBlockHeight": 100
                            }
                        })),
                        _ => axum::Json(serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": body["id"],
                            "error": {"code": -32601, "message": "method not found"}
                        })),
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{address}"), sends)
    }

    fn fee_payer_signer() -> Arc<dyn TransactionSigner> {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
        let mut keypair = [0u8; 64];
        keypair[..32].copy_from_slice(signing_key.as_bytes());
        keypair[32..].copy_from_slice(signing_key.verifying_key().as_bytes());
        Arc::new(crate::mpp::solana_keychain::MemorySigner::from_bytes(&keypair).unwrap())
    }

    fn exact_paykit(rpc_url: String, fee_payer: Option<Arc<dyn TransactionSigner>>) -> PayKit {
        PayKit::new(PayKitConfig {
            recipient: TEST_RECIPIENT.to_string(),
            challenge_binding_secret: Some(TEST_SECRET.to_string()),
            network: "devnet".to_string(),
            rpc_url: Some(rpc_url),
            realm: Some("test-realm".to_string()),
            store: Some(Arc::new(crate::mpp::store::MemoryStore::new())),
            fee_payer_signer: fee_payer,
            tx_v1: TxV1Mode::Off,
            ..Default::default()
        })
        .unwrap()
    }

    /// A route that counts how often the protected handler runs.
    fn counted_route(pay: &PayKit) -> (Router, Arc<std::sync::atomic::AtomicUsize>) {
        let served = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = served.clone();
        let handler = move |_payment: Payment| {
            let counter = counter.clone();
            async move {
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                "protected-content"
            }
        };
        (
            Router::new().route("/paid", paid_get(handler, "0.01", pay)),
            served,
        )
    }

    /// Pay the route's challenge with an unsigned client transaction.
    async fn unsigned_exact_payment(app: &Router) -> (String, solana_pubkey::Pubkey) {
        use crate::x402::server::exact::test_support::{
            exact_transaction, test_client, transaction_header,
        };
        let challenge = x402_challenge(
            &app.clone()
                .oneshot(get_with_host("/paid", None))
                .await
                .unwrap(),
        );
        let requirement = &challenge.accepts[0];
        let fee_payer = requirement
            .fee_payer_key
            .as_deref()
            .map(|key| key.parse().unwrap())
            .unwrap_or_else(solana_pubkey::Pubkey::new_unique);
        let tx = exact_transaction(requirement, &test_client(), &fee_payer);
        // The sponsor's slot is left for the server; the client's is signed.
        assert_eq!(tx.signatures[0], Default::default());
        (
            transaction_header(requirement, requirement.resource_info(), &tx),
            fee_payer,
        )
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn x402_payment_for_get_cannot_pay_for_post_on_the_same_path() {
        let (rpc_url, sends) = mock_rpc(false).await;
        let pay = exact_paykit(rpc_url, Some(fee_payer_signer()));
        let served = Arc::new(std::sync::Mutex::new(Vec::new()));
        let handler = |method: &'static str| {
            let served = served.clone();
            move |_payment: Payment| {
                let served = served.clone();
                async move {
                    served.lock().unwrap().push(method);
                    "protected-content"
                }
            }
        };
        let app: Router = Router::new().route(
            "/paid",
            paid_get(handler("GET"), "0.01", &pay).merge(paid_post(handler("POST"), "0.01", &pay)),
        );
        let challenge_for = |method: Method| {
            let app = app.clone();
            async move {
                let mut request = get_with_host("/paid", None);
                *request.method_mut() = method;
                x402_challenge(&app.oneshot(request).await.unwrap())
            }
        };
        let get = challenge_for(Method::GET).await;
        let post = challenge_for(Method::POST).await;
        let memo = |challenge: &crate::x402::exact::PaymentRequiredEnvelope| {
            challenge.accepts[0].extra.as_ref().unwrap()["memo"].clone()
        };
        assert_ne!(memo(&get), memo(&post));

        let (header, _) = unsigned_exact_payment(&app).await;
        let mut replayed = get_with_host("/paid", Some(&header));
        *replayed.method_mut() = Method::POST;
        let resp = app.clone().oneshot(replayed).await.unwrap();
        assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
        assert_eq!(sends.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert!(served.lock().unwrap().is_empty());

        // The same payment is good for the method it was made for.
        let resp = app
            .oneshot(get_with_host("/paid", Some(&header)))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(*served.lock().unwrap(), ["GET"]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn x402_transaction_without_fee_payer_signer_is_not_served() {
        let pay = exact_paykit("http://127.0.0.1:1".to_string(), None);
        let (app, served) = counted_route(&pay);
        let (header, _) = unsigned_exact_payment(&app).await;

        let resp = app
            .oneshot(get_with_host("/paid", Some(&header)))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
        assert!(!resp.headers().contains_key(PAYMENT_RESPONSE_HEADER));
        assert_eq!(served.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn x402_transaction_is_settled_before_the_handler_runs() {
        let (rpc_url, sends) = mock_rpc(false).await;
        let signer = fee_payer_signer();
        let pay = exact_paykit(rpc_url, Some(signer.clone()));
        let (app, served) = counted_route(&pay);
        let (header, fee_payer) = unsigned_exact_payment(&app).await;
        assert_eq!(fee_payer, signer.pubkey());

        let resp = app
            .clone()
            .oneshot(get_with_host("/paid", Some(&header)))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(sends.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(served.load(std::sync::atomic::Ordering::SeqCst), 1);
        let reference = resp.headers()[PAYMENT_RESPONSE_HEADER].to_str().unwrap();
        assert_ne!(
            reference,
            solana_signature::Signature::default().to_string(),
            "the reference is the co-signed, broadcast signature"
        );

        // The same payment cannot be served twice.
        let replay = app
            .oneshot(get_with_host("/paid", Some(&header)))
            .await
            .unwrap();
        assert_eq!(replay.status(), StatusCode::PAYMENT_REQUIRED);
        assert_eq!(served.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn x402_settlement_failure_does_not_run_the_handler() {
        let (rpc_url, _) = mock_rpc(true).await;
        let pay = exact_paykit(rpc_url, Some(fee_payer_signer()));
        let (app, served) = counted_route(&pay);
        let (header, _) = unsigned_exact_payment(&app).await;

        let resp = app
            .oneshot(get_with_host("/paid", Some(&header)))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
        assert!(!resp.headers().contains_key(PAYMENT_RESPONSE_HEADER));
        assert_eq!(served.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn batch_response_cache_keeps_representation_headers_only() {
        let mut response = (StatusCode::TEMPORARY_REDIRECT, "moved").into_response();
        response
            .headers_mut()
            .insert(header::LOCATION, HeaderValue::from_static("/destination"));
        response.headers_mut().insert(
            header::CONTENT_DISPOSITION,
            HeaderValue::from_static("attachment; filename=report.txt"),
        );
        response.headers_mut().insert(
            HeaderName::from_static("content-security-policy"),
            HeaderValue::from_static("default-src 'none'"),
        );
        response.headers_mut().insert(
            HeaderName::from_static("x-content-type-options"),
            HeaderValue::from_static("nosniff"),
        );
        response.headers_mut().insert(
            HeaderName::from_static("x-frame-options"),
            HeaderValue::from_static("DENY"),
        );
        response
            .headers_mut()
            .insert(header::CONNECTION, HeaderValue::from_static("close"));
        response.headers_mut().insert(
            HeaderName::from_static("payment-response"),
            HeaderValue::from_static("attempt-specific"),
        );

        let (_, cached) = cacheable_response(response).await.unwrap();
        let cached = cached.expect("small finite response is cached");
        assert_eq!(cached.status, StatusCode::TEMPORARY_REDIRECT.as_u16());
        assert!(cached
            .headers
            .contains(&("location".to_string(), "/destination".to_string())));
        assert!(cached.headers.contains(&(
            "content-disposition".to_string(),
            "attachment; filename=report.txt".to_string()
        )));
        assert!(cached.headers.contains(&(
            "content-security-policy".to_string(),
            "default-src 'none'".to_string()
        )));
        assert!(cached
            .headers
            .contains(&("x-content-type-options".to_string(), "nosniff".to_string())));
        assert!(cached
            .headers
            .contains(&("x-frame-options".to_string(), "DENY".to_string())));
        assert!(!cached.headers.iter().any(|(name, _)| name == "connection"));
        assert!(!cached
            .headers
            .iter()
            .any(|(name, _)| name == "payment-response"));
        assert_eq!(cached.body, b"moved");
    }
}
