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
//! use solana_pay_kit::{paid_get, PayKit, PayKitConfig, Payment};
//! use axum::Router;
//!
//! async fn report(payment: Payment) -> String {
//!     format!("paid {} via {}: {}", payment.amount, payment.protocol, payment.reference)
//! }
//!
//! let pay = PayKit::new(PayKitConfig {
//!     recipient: "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY".to_string(),
//!     ..Default::default()
//! })
//! .unwrap();
//!
//! // One line gates the route on either protocol.
//! let app: Router = Router::new().route("/report", paid_get(report, "0.10", &pay));
//! ```

use std::sync::{Arc, Mutex};

use axum::extract::{FromRequestParts, Request, State};
use axum::handler::Handler;
use axum::http::request::Parts;
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri};
use axum::middleware::{from_fn_with_state, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, MethodRouter};

use crate::mpp::server::{Config as MppConfig, Mpp};
use crate::mpp::solana_keychain::SolanaSigner;
use crate::mpp::{format_receipt, format_www_authenticate, Receipt, ReceiptKind};
use crate::x402::server::{
    BatchConfig, Config as X402Config, CurrencyConfig, ExactOptions, UptoConfig, UptoPayout,
    VerifiedExactPayment, X402BatchSettlement, X402Upto, X402,
};
use crate::x402::{PAYMENT_RESPONSE_HEADER, PAYMENT_SIGNATURE_HEADER, X402_V1_PAYMENT_HEADER};

const PAYMENT_RECEIPT_HEADER: &str = "Payment-Receipt";

/// Error returned when a [`PayKit`] can't be built from its config.
#[derive(Debug)]
pub enum PayKitError {
    /// The MPP charge handler rejected the config.
    Mpp(String),
    /// The x402 handler rejected the config.
    X402(String),
}

impl std::fmt::Display for PayKitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
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
    /// Token decimals for `currency` (default `6`).
    pub decimals: u8,
    /// Network: `"mainnet"`, `"devnet"`, or `"localnet"` (default `"mainnet"`).
    pub network: String,
    /// RPC endpoint; falls back to a per-network default when `None`.
    pub rpc_url: Option<String>,
    /// MPP HMAC challenge-binding secret (>= 32 bytes). Reads `MPP_SECRET_KEY`
    /// when `None`.
    pub challenge_binding_secret: Option<String>,
    /// When set, the server sponsors the network fee: drives MPP fee-sponsored
    /// mode and is used as the x402 fee-payer address.
    pub fee_payer_signer: Option<Arc<dyn SolanaSigner>>,
    /// Accept push-mode MPP credentials (off by default; see audit §13.5).
    pub accept_push_mode: bool,
    /// Currencies the server is willing to accept (x402 multi-currency).
    pub accepted_currencies: Option<Vec<String>>,
}

impl Default for PayKitConfig {
    fn default() -> Self {
        Self {
            recipient: String::new(),
            currency: "USDC".to_string(),
            decimals: 6,
            network: "mainnet".to_string(),
            rpc_url: None,
            challenge_binding_secret: None,
            fee_payer_signer: None,
            accept_push_mode: false,
            accepted_currencies: None,
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
    /// set — the operator must sign settlement vouchers, so `upto` routes
    /// require a signer.
    x402_upto: Option<Arc<X402Upto>>,
    /// High-throughput x402 `batch-settlement` handler. `Some` only when
    /// `fee_payer_signer` is set (the operator signs settlement transactions).
    x402_batch: Option<Arc<X402BatchSettlement>>,
}

/// Default `upto` completion window (seconds) advertised in `maxTimeoutSeconds`.
const UPTO_MAX_TIMEOUT_SECONDS: u64 = 300;

impl PayKit {
    /// Build both protocol handlers from one config.
    pub fn new(config: PayKitConfig) -> Result<Self, PayKitError> {
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
            recipient: config.recipient.clone(),
            currency: config.currency.clone(),
            decimals: config.decimals,
            network: config.network.clone(),
            rpc_url: config.rpc_url.clone(),
            challenge_binding_secret: config.challenge_binding_secret.clone(),
            fee_payer: config.fee_payer_signer.is_some(),
            fee_payer_signer: config.fee_payer_signer.clone(),
            accept_push_mode: config.accept_push_mode,
            ..Default::default()
        })
        .map_err(|e| PayKitError::Mpp(e.to_string()))?;

        let x402 = X402::new(X402Config {
            recipient: config.recipient.clone(),
            currencies: currencies.clone(),
            network: config.network.clone(),
            rpc_url: config.rpc_url.clone(),
            fee_payer_key,
            ..Default::default()
        })
        .map_err(|e| PayKitError::X402(e.to_string()))?;

        // The `upto` scheme needs an operator signer to settle vouchers, so it
        // is only available when the gate sponsors fees with a signer.
        let x402_upto = config
            .fee_payer_signer
            .as_ref()
            .map(|signer| {
                X402Upto::new(UptoConfig {
                    // The channel payee is always the operator (the only key
                    // the gate can sign settlement with); the gate's configured
                    // recipient is the real beneficiary, paid the full settled
                    // amount via the bound distribution (operator keeps 0 bps).
                    payout: UptoPayout::Beneficiary {
                        address: config.recipient.clone(),
                        operator_fee_bps: 0,
                    },
                    currencies: currencies.clone(),
                    cluster: config.network.clone(),
                    rpc_url: config.rpc_url.clone(),
                    resource: String::new(),
                    description: None,
                    max_timeout_seconds: UPTO_MAX_TIMEOUT_SECONDS,
                    program_id: None,
                    operator_signer: signer.clone(),
                })
                .map(Arc::new)
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
                X402BatchSettlement::new(batch)
                    .map(Arc::new)
                    .map_err(|e| PayKitError::X402(e.to_string()))
            })
            .transpose()?;

        Ok(Self {
            mpp: Arc::new(mpp),
            x402: Arc::new(x402),
            x402_upto,
            x402_batch,
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
    /// configured. Drive `settle_batch` / `distribute` on it out of band.
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

/// Usage meter for [`paid_upto_get`] / [`paid_upto_post`] routes.
///
/// The route handler reports the actual amount consumed (in base units) by
/// calling [`Charge::charge`]. The gate settles that amount — never more than
/// the authorized ceiling — after the handler returns, refunding the remainder.
/// If the handler never calls `charge`, the settled amount is `0`.
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
    /// The request URI (path and query).
    pub uri: &'a Uri,
    /// The request headers.
    pub headers: &'a HeaderMap,
}

impl PriceCtx<'_> {
    /// The raw query string, if present.
    pub fn query(&self) -> Option<&str> {
        self.uri.query()
    }

    /// Look up a single query parameter by name, percent-decoded.
    ///
    /// The value is `application/x-www-form-urlencoded`-decoded (`%XX` escapes
    /// and `+` as space) so a tier like `?tier=premi%75m` matches a literal
    /// `"premium"` comparison instead of silently falling through to a cheaper
    /// default price.
    pub fn query_param(&self, name: &str) -> Option<String> {
        self.uri.query()?.split('&').find_map(|pair| {
            let mut kv = pair.splitn(2, '=');
            match kv.next() {
                Some(key) if key == name => Some(percent_decode(kv.next().unwrap_or(""))),
                _ => None,
            }
        })
    }
}

/// Decode an `application/x-www-form-urlencoded` query value: `%XX` escapes and
/// `+` as space. Pricing closures compare decoded values, so a percent-encoded
/// tier (e.g. `premi%75m`) can't bypass the match and land on a cheaper price.
fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                match (
                    (bytes[i + 1] as char).to_digit(16),
                    (bytes[i + 2] as char).to_digit(16),
                ) {
                    (Some(hi), Some(lo)) => {
                        out.push((hi * 16 + lo) as u8);
                        i += 3;
                    }
                    _ => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[derive(Clone)]
struct GateState {
    pay: PayKit,
    price: Price,
}

/// Build the 402 response carrying *both* protocol challenges.
fn challenge_response(pay: &PayKit, amount: &str) -> Response {
    let mut resp = (StatusCode::PAYMENT_REQUIRED, "Payment Required").into_response();
    let headers = resp.headers_mut();

    // MPP: WWW-Authenticate. A failure here drops the MPP challenge from the
    // 402 (x402 clients are unaffected), so log it for operators.
    match pay.mpp.charge(amount) {
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
    match pay
        .x402
        .payment_required_header(amount, ExactOptions::default())
    {
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

/// Extract a settlement reference from a verified x402 payment. Returns `None`
/// when the transaction carries no signature (an unsigned tx), so the gate can
/// reject rather than hand the handler an empty reference.
fn x402_reference(verified: &VerifiedExactPayment) -> Option<String> {
    let reference = match verified {
        VerifiedExactPayment::Signature(sig) => sig.clone(),
        VerifiedExactPayment::Transaction(tx) => tx
            .signatures
            .first()
            .map(|s| s.to_string())
            .unwrap_or_default(),
    };
    (!reference.is_empty()).then_some(reference)
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
    let amount = {
        let ctx = PriceCtx {
            method: req.method(),
            uri: req.uri(),
            headers: req.headers(),
        };
        state.price.resolve(&ctx)
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
            .verify_payment_for_amount(&credential, &amount)
            .await
        {
            Ok(receipt) => {
                req.extensions_mut().insert(Payment {
                    amount,
                    protocol: Protocol::Mpp,
                    reference: receipt.reference.clone(),
                });
                let mut resp = next.run(req).await;
                attach_mpp_receipt(&mut resp, &receipt);
                resp
            }
            Err(_) => challenge_response(&state.pay, &amount),
        };
    }

    // x402 path.
    if let Some(header_value) = x402_header {
        return match state
            .pay
            .x402
            .process_payment(&header_value, &amount, ExactOptions::default())
            .await
        {
            Ok(verified) => match x402_reference(&verified) {
                Some(reference) => {
                    req.extensions_mut().insert(Payment {
                        amount,
                        protocol: Protocol::X402,
                        reference: reference.clone(),
                    });
                    let mut resp = next.run(req).await;
                    attach_x402_response(&mut resp, &reference);
                    resp
                }
                None => {
                    tracing::warn!(
                        amount = %amount,
                        "x402 payment verified but carried no settlement reference"
                    );
                    challenge_response(&state.pay, &amount)
                }
            },
            Err(_) => challenge_response(&state.pay, &amount),
        };
    }

    // No credential of either protocol — advertise both challenges.
    challenge_response(&state.pay, &amount)
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
fn upto_challenge_response(upto: &X402Upto, amount: &str) -> Response {
    let (name, value) = match upto.payment_required_header(amount) {
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
    let mut resp = (StatusCode::PAYMENT_REQUIRED, "Payment Required").into_response();
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

/// Usage-based gate: verify the authorization and broadcast the channel open,
/// run the handler, then settle the actual metered amount and refund the rest.
async fn upto_gate_middleware(
    State(state): State<GateState>,
    mut req: Request,
    next: Next,
) -> Response {
    let amount = {
        let ctx = PriceCtx {
            method: req.method(),
            uri: req.uri(),
            headers: req.headers(),
        };
        state.price.resolve(&ctx)
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
        return upto_challenge_response(&upto, &amount);
    };

    // Verify the authorization and broadcast + confirm the channel open.
    let open = match upto.verify_open(&header_value, &amount).await {
        Ok(open) => open,
        Err(e) => {
            tracing::warn!(amount = %amount, error = %e, "upto open verification failed");
            return upto_challenge_response(&upto, &amount);
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
    let mut resp = next.run(req).await;

    // Recover from poisoning so a handler that panicked *after* recording a
    // charge still settles the amount it consumed (not a silent zero refund).
    let actual = (*cell.lock().unwrap_or_else(|e| e.into_inner())).unwrap_or(0);

    // Settle the actual amount and refund the remainder.
    match upto.settle_actual(&open, actual).await {
        Ok(settlement) => match upto.settlement_header(&settlement) {
            Ok((name, value)) => {
                if let (Ok(n), Ok(v)) = (
                    HeaderName::from_bytes(name.as_bytes()),
                    HeaderValue::from_str(&value),
                ) {
                    resp.headers_mut().insert(n, v);
                }
                resp
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to encode upto settlement header");
                resp
            }
        },
        Err(e) => {
            tracing::error!(actual, error = %e, "upto settlement failed after handler ran");
            (
                StatusCode::BAD_GATEWAY,
                "payment settlement failed; the channel can be reclaimed after its grace period",
            )
                .into_response()
        }
    }
}

/// Gate a `GET` handler behind x402 `upto` (usage-based) payment at the given
/// **maximum** price. The handler reports actual usage via the [`Charge`]
/// extractor; the gate settles that amount and refunds the rest.
///
/// Requires a `fee_payer_signer` on [`PayKitConfig`] (the operator signs
/// settlement vouchers).
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

/// Build the 402 response advertising the x402 `batch-settlement` challenge, or
/// a retryable `503` if it can't be built (e.g. the operator RPC is down).
fn batch_challenge_response(batch: &X402BatchSettlement, amount: &str) -> Response {
    let (name, value) = match batch.payment_required_header(amount) {
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
    let mut resp = (StatusCode::PAYMENT_REQUIRED, "Payment Required").into_response();
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

/// High-throughput gate: verify the cumulative voucher (or process a deposit /
/// cooperative refund) and serve. On-chain settlement is deferred — the operator
/// drives `settle_batch` / `distribute` out of band via [`PayKit::x402_batch`].
async fn batch_gate_middleware(
    State(state): State<GateState>,
    mut req: Request,
    next: Next,
) -> Response {
    let amount = {
        let ctx = PriceCtx {
            method: req.method(),
            uri: req.uri(),
            headers: req.headers(),
        };
        state.price.resolve(&ctx)
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
    let Some(header_value) = x402_header else {
        return batch_challenge_response(&batch, &amount);
    };

    let outcome = match batch.verify_payment(&header_value, &amount).await {
        Ok(outcome) => outcome,
        Err(e) => {
            tracing::warn!(amount = %amount, error = %e, "batch-settlement verification failed");
            return batch_challenge_response(&batch, &amount);
        }
    };

    let settlement_header = batch.settlement_header(&outcome.response).ok();
    let mut resp = if outcome.serve {
        req.extensions_mut().insert(Payment {
            amount: amount.clone(),
            protocol: Protocol::X402,
            reference: outcome
                .response
                .channel_state
                .as_ref()
                .map(|c| c.channel_id.clone())
                .unwrap_or_default(),
        });
        next.run(req).await
    } else {
        // A cooperative refund is a payment-control operation, not a paid
        // request — acknowledge it without invoking the protected handler.
        (StatusCode::OK, "channel closed").into_response()
    };
    if let Some((name, value)) = settlement_header {
        if let (Ok(n), Ok(v)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(&value),
        ) {
            resp.headers_mut().insert(n, v);
        }
    }
    resp
}

/// Gate a `GET` handler behind x402 `batch-settlement` at the per-request
/// `price`. Requires a `fee_payer_signer`; settlement is batched out of band.
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

    fn test_paykit() -> PayKit {
        PayKit::new(PayKitConfig {
            recipient: TEST_RECIPIENT.to_string(),
            challenge_binding_secret: Some(TEST_SECRET.to_string()),
            network: "devnet".to_string(),
            ..Default::default()
        })
        .expect("valid paykit config")
    }

    async fn report(_payment: Payment) -> &'static str {
        "ok"
    }

    fn test_signer() -> Arc<dyn SolanaSigner> {
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
            recipient: TEST_RECIPIENT.to_string(),
            challenge_binding_secret: Some(TEST_SECRET.to_string()),
            network: "devnet".to_string(),
            rpc_url: Some("http://127.0.0.1:1".to_string()),
            fee_payer_signer: Some(test_signer()),
            ..Default::default()
        })
        .expect("valid paykit config")
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
}
