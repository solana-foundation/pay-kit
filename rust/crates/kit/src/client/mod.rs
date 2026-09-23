//! Permissioned, payment-aware HTTP client.
//!
//! [`PayKitClient`](crate::client::PayKitClient) sends an HTTP request, recognizes MPP `charge` and x402
//! `exact` challenges, checks every offer against
//! [`ClientPermissions`](crate::client::ClientPermissions), signs
//! the first permitted option, and retries the request once. Permission checks
//! happen before transaction construction and wallet invocation.
//!
//! # Defaults
//!
//! Unless replaced on [`PayKitClientBuilder`](crate::client::PayKitClientBuilder), permissions allow known PayKit
//! stablecoins on the configured Solana cluster with a USD 1.00 per-payment
//! cap. Any HTTP(S) origin is accepted by default. Production clients can pin
//! exact origins and replace the global cap for a particular origin.
//!
//! # Example
//!
//! ```no_run
//! use std::error::Error;
//! use solana_pay_kit::{
//!     client::{
//!         ClientPermissions, ClientProtocol, OriginPermissionOverride,
//!         PayKitClient, SolanaNetwork,
//!     },
//!     solana_keychain::TransactionSigner,
//! };
//!
//! async fn fetch_report(
//!     signer: impl TransactionSigner + 'static,
//! ) -> Result<(), Box<dyn Error>> {
//!     let origin = "https://api.example.com";
//!     let permissions = ClientPermissions::builder()
//!         .allow_origin(origin)?
//!         .only_network(SolanaNetwork::Mainnet)
//!         .max_amount_per_payment("$1.00".parse()?)
//!         .override_origin(
//!             OriginPermissionOverride::builder(origin)
//!                 .max_amount_per_payment("$5.00".parse()?)
//!                 .build()?,
//!         )
//!         .build()?;
//!
//!     let client = PayKitClient::builder()
//!         .signer(signer)
//!         .rpc_url("https://api.mainnet-beta.solana.com")
//!         .network(SolanaNetwork::Mainnet)
//!         .accept([ClientProtocol::Mpp, ClientProtocol::X402])
//!         .permissions(permissions)
//!         .build()?;
//!
//!     client.get(format!("{origin}/report")).send().await?;
//!     Ok(())
//! }
//! ```
//!
//! Global and exact-origin cap precedence is documented on
//! [`ClientPermissions`](crate::client::ClientPermissions). Stateful x402 `upto` and `batch-settlement` flows
//! remain available through [`crate::x402::client`].

mod permissions;

use std::{collections::BTreeSet, sync::Arc};

use reqwest::{header::HeaderValue, Method, Request, Response, Url};
use serde::Serialize;
use solana_keychain::TransactionSigner;
use solana_rpc_client::rpc_client::RpcClient;

use crate::{
    mpp::{
        client::{build_credential_header_with_options, is_solana_charge_challenge},
        parse_www_authenticate_all,
        protocol::{intents::ChargeRequest, solana::MethodDetails},
        resolve_stablecoin_mint, WWW_AUTHENTICATE_HEADER,
    },
    x402::{
        client::exact::{build_payment_header, parse_x402_accepts},
        exact::{cluster_for_caip2_network, PaymentRequirements, EXACT_SCHEME},
    },
};

pub use permissions::{
    AssetPermission, AuthorizedPayment, ClientPermissions, ClientPermissionsBuilder,
    OriginPermissionOverride, OriginPermissionOverrideBuilder, PaymentCandidate,
    PermissionConfigError, PermissionDenied, PermissionDeniedCode, PermissionRejection,
    SolanaNetwork, UsdAmount,
};

/// Payment protocols the high-level client can answer automatically.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ClientProtocol {
    /// Machine Payments Protocol `charge` challenges.
    Mpp,
    /// x402 `exact` payment requirements.
    X402,
}

/// A payment-aware HTTP client with mandatory pre-signing permission checks.
#[derive(Clone)]
pub struct PayKitClient {
    inner: Arc<PayKitClientInner>,
}

struct PayKitClientInner {
    http: reqwest::Client,
    signer: Arc<dyn TransactionSigner>,
    rpc_url: String,
    permissions: ClientPermissions,
    protocols: BTreeSet<ClientProtocol>,
}

impl PayKitClient {
    /// Start a client builder.
    pub fn builder() -> PayKitClientBuilder {
        PayKitClientBuilder::default()
    }

    /// Start a permissioned GET request.
    pub fn get(&self, url: impl reqwest::IntoUrl) -> PayKitRequestBuilder {
        self.request(Method::GET, url)
    }

    /// Start a permissioned POST request.
    pub fn post(&self, url: impl reqwest::IntoUrl) -> PayKitRequestBuilder {
        self.request(Method::POST, url)
    }

    /// Start a permissioned request with an arbitrary HTTP method.
    pub fn request(&self, method: Method, url: impl reqwest::IntoUrl) -> PayKitRequestBuilder {
        PayKitRequestBuilder {
            client: self.clone(),
            request: self.inner.http.request(method, url),
        }
    }

    async fn execute(&self, request: Request) -> Result<Response, ClientError> {
        let request_url = request.url().clone();
        let mut retry = request
            .try_clone()
            .ok_or(ClientError::RequestBodyNotReplayable)?;
        let response = self.inner.http.execute(request).await?;
        if response.status() != reqwest::StatusCode::PAYMENT_REQUIRED {
            return Ok(response);
        }

        let response_url = response.url().clone();
        // reqwest follows redirects internally, so the response does not
        // expose the effective method/body/header state used for the final
        // hop. Replaying the original request at that URL could leak caller
        // credentials cross-origin or turn a 303's effective GET back into a
        // POST. Fail closed instead of guessing at redirect semantics.
        if response_url != request_url {
            return Err(ClientError::RedirectedChallenge {
                from: request_url.to_string(),
                to: response_url.to_string(),
            });
        }
        let origin = response_url.origin().ascii_serialization();
        let headers = response_headers(response.headers());
        let body = response.bytes().await?;
        let body = std::str::from_utf8(&body).ok();
        let (offers, mut rejections) = self.collect_offers(&headers, body, &origin);
        if offers.is_empty() {
            return if rejections.is_empty() {
                Err(ClientError::NoSupportedChallenge)
            } else {
                Err(ClientError::PermissionDenied(PermissionDenied {
                    rejections,
                }))
            };
        }

        let mut selected = None;
        for offer in offers {
            match self.inner.permissions.authorize(&offer.candidate()) {
                Ok(authorization) => {
                    selected = Some((offer, authorization));
                    break;
                }
                Err(rejection) => rejections.push(rejection),
            }
        }
        let (offer, _) = selected
            .ok_or_else(|| ClientError::PermissionDenied(PermissionDenied { rejections }))?;

        // Selection-time filtering enables fallback. This second evaluation is
        // the signing boundary and protects future selection refactors from
        // accidentally bypassing the permission layer.
        let authorization = self
            .inner
            .permissions
            .authorize(&offer.candidate())
            .map_err(|rejection| {
                ClientError::PermissionDenied(PermissionDenied {
                    rejections: vec![rejection],
                })
            })?;
        let (header_name, header_value) = self.payment_header(&offer, authorization).await?;
        *retry.url_mut() = response_url;
        retry
            .headers_mut()
            .insert(header_name, HeaderValue::from_str(&header_value)?);
        Ok(self.inner.http.execute(retry).await?)
    }

    fn collect_offers(
        &self,
        headers: &[(String, String)],
        body: Option<&str>,
        origin: &str,
    ) -> (Vec<PaymentOffer>, Vec<PermissionRejection>) {
        let mut offers = Vec::new();
        let mut rejections = Vec::new();
        if self.inner.protocols.contains(&ClientProtocol::Mpp) {
            let values = headers
                .iter()
                .filter(|(name, _)| name.eq_ignore_ascii_case(WWW_AUTHENTICATE_HEADER))
                .map(|(_, value)| value.as_str());
            for challenge in parse_www_authenticate_all(values)
                .into_iter()
                .filter_map(Result::ok)
            {
                match PaymentOffer::from_mpp(challenge, origin) {
                    Ok(Some(offer)) => offers.push(offer),
                    Ok(None) => {}
                    Err(rejection) => rejections.push(rejection),
                }
            }
        }
        if self.inner.protocols.contains(&ClientProtocol::X402) {
            for requirement in parse_x402_accepts(headers, body) {
                match PaymentOffer::from_x402(requirement, origin) {
                    Ok(Some(offer)) => offers.push(offer),
                    Ok(None) => {}
                    Err(rejection) => rejections.push(rejection),
                }
            }
        }
        (offers, rejections)
    }

    async fn payment_header(
        &self,
        offer: &PaymentOffer,
        authorization: AuthorizedPayment,
    ) -> Result<(reqwest::header::HeaderName, String), ClientError> {
        let rpc = RpcClient::new(self.inner.rpc_url.clone());
        match &offer.source {
            PaymentSource::Mpp(challenge) => {
                let value = build_credential_header_with_options(
                    self.inner.signer.as_ref(),
                    &rpc,
                    challenge,
                    crate::mpp::client::BuildChargeTransactionOptions {
                        max_amount_base_units: authorization.max_amount_atomic(),
                        expected_network: Some(offer.network.to_string()),
                        ..Default::default()
                    },
                )
                .await?;
                Ok((reqwest::header::AUTHORIZATION, value))
            }
            PaymentSource::X402(requirement) => {
                let value =
                    build_payment_header(self.inner.signer.as_ref(), &rpc, requirement, None, None)
                        .await?;
                Ok((
                    reqwest::header::HeaderName::from_static("payment-signature"),
                    value,
                ))
            }
        }
    }
}

/// Builder for [`PayKitClient`].
#[derive(Default)]
pub struct PayKitClientBuilder {
    http: Option<reqwest::Client>,
    signer: Option<Arc<dyn TransactionSigner>>,
    rpc_url: Option<String>,
    permissions: Option<ClientPermissions>,
    network: Option<SolanaNetwork>,
    protocols: Option<BTreeSet<ClientProtocol>>,
}

impl PayKitClientBuilder {
    /// Set an owned transaction signer.
    pub fn signer<S>(mut self, signer: S) -> Self
    where
        S: TransactionSigner + 'static,
    {
        self.signer = Some(Arc::new(signer));
        self
    }

    /// Set a shared transaction signer.
    pub fn shared_signer(mut self, signer: Arc<dyn TransactionSigner>) -> Self {
        self.signer = Some(signer);
        self
    }

    /// Set the Solana RPC used to build payment transactions.
    pub fn rpc_url(mut self, rpc_url: impl Into<String>) -> Self {
        self.rpc_url = Some(rpc_url.into());
        self
    }

    /// Set the client's Solana cluster. Defaults to `mainnet`.
    pub fn network(mut self, network: SolanaNetwork) -> Self {
        self.network = Some(network);
        self
    }

    /// Replace the default client permissions.
    pub fn permissions(mut self, permissions: ClientPermissions) -> Self {
        self.permissions = Some(permissions);
        self
    }

    /// Restrict which payment protocols this client may answer.
    pub fn accept(mut self, protocols: impl IntoIterator<Item = ClientProtocol>) -> Self {
        self.protocols = Some(protocols.into_iter().collect());
        self
    }

    /// Use a preconfigured HTTP client.
    pub fn http_client(mut self, client: reqwest::Client) -> Self {
        self.http = Some(client);
        self
    }

    /// Validate the configuration and build the client.
    pub fn build(self) -> Result<PayKitClient, ClientBuildError> {
        let signer = self.signer.ok_or(ClientBuildError::MissingSigner)?;
        let rpc_url = self.rpc_url.ok_or(ClientBuildError::MissingRpcUrl)?;
        Url::parse(&rpc_url).map_err(|_| ClientBuildError::InvalidRpcUrl)?;
        let network = self.network.unwrap_or(SolanaNetwork::Mainnet);
        let permissions = self.permissions.unwrap_or_else(|| {
            ClientPermissions::builder()
                .only_network(network)
                .build()
                .expect("default client permissions are valid")
        });
        let protocols = self
            .protocols
            .unwrap_or_else(|| BTreeSet::from([ClientProtocol::Mpp, ClientProtocol::X402]));
        if protocols.is_empty() {
            return Err(ClientBuildError::NoAcceptedProtocols);
        }
        Ok(PayKitClient {
            inner: Arc::new(PayKitClientInner {
                http: self.http.unwrap_or_default(),
                signer,
                rpc_url,
                permissions,
                protocols,
            }),
        })
    }
}

/// Builder for one payment-aware HTTP request.
pub struct PayKitRequestBuilder {
    client: PayKitClient,
    request: reqwest::RequestBuilder,
}

impl PayKitRequestBuilder {
    /// Add one request header.
    pub fn header(mut self, key: impl AsRef<str>, value: impl AsRef<str>) -> Self {
        self.request = self.request.header(key.as_ref(), value.as_ref());
        self
    }

    /// Set a replayable request body.
    pub fn body<T: Into<reqwest::Body>>(mut self, body: T) -> Self {
        self.request = self.request.body(body);
        self
    }

    /// Serialize a JSON request body.
    pub fn json<T: Serialize + ?Sized>(mut self, value: &T) -> Self {
        self.request = self.request.json(value);
        self
    }

    /// Send the request, answer one permitted 402 challenge, and retry once.
    pub async fn send(self) -> Result<Response, ClientError> {
        let request = self.request.build()?;
        self.client.execute(request).await
    }
}

enum PaymentSource {
    Mpp(Box<crate::mpp::PaymentChallenge>),
    X402(Box<PaymentRequirements>),
}

struct PaymentOffer {
    origin: String,
    network: SolanaNetwork,
    mint: String,
    amount: u64,
    source: PaymentSource,
}

impl PaymentOffer {
    fn from_mpp(
        challenge: crate::mpp::PaymentChallenge,
        origin: &str,
    ) -> Result<Option<Self>, PermissionRejection> {
        if !is_solana_charge_challenge(&challenge) {
            return Ok(None);
        }
        let request = challenge
            .request
            .decode::<ChargeRequest>()
            .map_err(|_| PermissionRejection::invalid_terms("invalid MPP charge request"))?;
        if request.currency.eq_ignore_ascii_case("SOL") {
            return Ok(None);
        }
        let details: MethodDetails = request
            .method_details
            .clone()
            .map(serde_json::from_value)
            .transpose()
            .map_err(|_| PermissionRejection::invalid_terms("invalid MPP method details"))?
            .unwrap_or_default();
        let network = parse_network(details.network.as_deref().unwrap_or("mainnet"))
            .ok_or_else(|| PermissionRejection::invalid_terms("unsupported MPP network"))?;
        let mint = resolve_stablecoin_mint(&request.currency, Some(network.as_str()))
            .ok_or_else(|| PermissionRejection::invalid_terms("unsupported MPP asset"))?;
        let mint = mint
            .parse::<solana_pubkey::Pubkey>()
            .map_err(|_| PermissionRejection::invalid_terms("invalid MPP asset mint"))?
            .to_string();
        let amount = request
            .amount
            .parse()
            .map_err(|_| PermissionRejection::invalid_terms("invalid MPP payment amount"))?;
        Ok(Some(Self {
            origin: origin.to_string(),
            network,
            mint,
            amount,
            source: PaymentSource::Mpp(Box::new(challenge)),
        }))
    }

    fn from_x402(
        mut requirement: PaymentRequirements,
        origin: &str,
    ) -> Result<Option<Self>, PermissionRejection> {
        if requirement.currency.eq_ignore_ascii_case("SOL") || !is_exact(&requirement) {
            return Ok(None);
        }
        let network = cluster_for_caip2_network(&requirement.network)
            .and_then(parse_network)
            .ok_or_else(|| PermissionRejection::invalid_terms("unsupported x402 network"))?;
        if let Some(value) = requirement.cluster.as_deref() {
            let cluster = parse_network(value).ok_or_else(|| {
                PermissionRejection::invalid_terms("unsupported explicit x402 cluster")
            })?;
            if cluster != network {
                return Err(PermissionRejection::invalid_terms(
                    "x402 cluster does not match network",
                ));
            }
        }
        // The signing path must consume the same canonical cluster that was
        // authorized above; never retain an unchecked wire value.
        requirement.cluster = Some(network.as_str().to_string());
        let mint = resolve_stablecoin_mint(&requirement.currency, Some(network.as_str()))
            .ok_or_else(|| PermissionRejection::invalid_terms("unsupported x402 asset"))?;
        let mint = mint
            .parse::<solana_pubkey::Pubkey>()
            .map_err(|_| PermissionRejection::invalid_terms("invalid x402 asset mint"))?
            .to_string();
        let amount = requirement
            .amount
            .parse()
            .map_err(|_| PermissionRejection::invalid_terms("invalid x402 payment amount"))?;
        Ok(Some(Self {
            origin: origin.to_string(),
            network,
            mint,
            amount,
            source: PaymentSource::X402(Box::new(requirement)),
        }))
    }

    fn candidate(&self) -> PaymentCandidate<'_> {
        PaymentCandidate::new(&self.origin, self.network, &self.mint, self.amount)
    }
}

fn is_exact(requirement: &PaymentRequirements) -> bool {
    requirement
        .accepted
        .as_ref()
        .and_then(|value| value.get("scheme"))
        .and_then(serde_json::Value::as_str)
        .map(|scheme| scheme == EXACT_SCHEME)
        .unwrap_or(true)
}

fn parse_network(value: &str) -> Option<SolanaNetwork> {
    match value {
        "mainnet" | "mainnet-beta" => Some(SolanaNetwork::Mainnet),
        "devnet" => Some(SolanaNetwork::Devnet),
        "localnet" => Some(SolanaNetwork::Localnet),
        _ => cluster_for_caip2_network(value)
            .filter(|cluster| *cluster != value)
            .and_then(parse_network),
    }
}

fn response_headers(headers: &reqwest::header::HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_string(), value.to_string()))
        })
        .collect()
}

/// Invalid high-level client construction.
#[derive(Debug, thiserror::Error)]
pub enum ClientBuildError {
    /// No transaction signer was configured.
    #[error("PayKitClient requires a transaction signer")]
    MissingSigner,
    /// No Solana RPC URL was configured.
    #[error("PayKitClient requires an RPC URL")]
    MissingRpcUrl,
    /// The configured Solana RPC URL is not an absolute URL.
    #[error("PayKitClient RPC URL is invalid")]
    InvalidRpcUrl,
    /// The accepted-protocol set was explicitly configured as empty.
    #[error("PayKitClient must accept at least one payment protocol")]
    NoAcceptedProtocols,
}

/// Failure while sending or paying a client request.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// Sending the initial or paid HTTP request failed.
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    /// A generated payment credential was not a valid HTTP header value.
    #[error("payment header is invalid: {0}")]
    InvalidHeader(#[from] reqwest::header::InvalidHeaderValue),
    /// The request body cannot be cloned for the paid retry.
    #[error("request body cannot be replayed after payment")]
    RequestBodyNotReplayable,
    /// The 402 was reached through a redirect whose effective request state is
    /// unavailable for a safe replay.
    #[error("refusing to pay redirected challenge from {from} to {to}")]
    RedirectedChallenge {
        /// Original request URL.
        from: String,
        /// Final URL that returned the 402.
        to: String,
    },
    /// The 402 did not contain a supported MPP charge or x402 exact offer.
    #[error("402 response contains no supported Solana payment challenge")]
    NoSupportedChallenge,
    /// Every supported offer was rejected by the configured permissions.
    #[error(transparent)]
    PermissionDenied(#[from] PermissionDenied),
    /// MPP challenge parsing or payment construction failed.
    #[error("MPP payment failed: {0}")]
    Mpp(#[from] crate::mpp::Error),
    /// x402 challenge parsing or payment construction failed.
    #[error("x402 payment failed: {0}")]
    X402(#[from] crate::x402::Error),
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    };

    use async_trait::async_trait;
    use axum::{
        extract::State,
        http::{HeaderMap, StatusCode},
        response::{IntoResponse, Redirect},
        routing::get,
        Router,
    };
    use base64::Engine;
    use solana_hash::Hash;
    use solana_keychain::{memory::MemorySigner, SignTransactionResult, SignerError, SolanaSigner};
    use solana_pubkey::Pubkey;
    use solana_signature::Signature;
    use solana_transaction::versioned::VersionedTransaction;

    use super::*;
    use crate::{
        core::mints::USDC_MAINNET,
        mpp::{
            protocol::{core::Base64UrlJson, solana::programs::TOKEN_PROGRAM},
            PaymentChallenge,
        },
        x402::exact::{SOLANA_DEVNET, SOLANA_MAINNET},
    };

    #[derive(Clone)]
    struct ChallengeState {
        payment_required: String,
        saw_payment: Arc<AtomicBool>,
    }

    #[derive(Clone)]
    struct DualChallengeState {
        mpp: String,
        x402: String,
        saw_x402_payment: Arc<AtomicBool>,
    }

    async fn paid_resource(
        State(state): State<ChallengeState>,
        headers: HeaderMap,
    ) -> impl IntoResponse {
        if headers.contains_key("payment-signature") {
            state.saw_payment.store(true, Ordering::SeqCst);
            return (StatusCode::OK, "paid").into_response();
        }
        (
            StatusCode::PAYMENT_REQUIRED,
            [("payment-required", state.payment_required)],
            "payment required",
        )
            .into_response()
    }

    async fn challenge_server(
        amount: u64,
        recipient: Pubkey,
    ) -> (String, Arc<AtomicBool>, tokio::task::JoinHandle<()>) {
        let envelope = serde_json::json!({
            "x402Version": 2,
            "accepts": [{
                "scheme": "exact",
                "network": SOLANA_MAINNET,
                "amount": amount.to_string(),
                "asset": USDC_MAINNET,
                "payTo": recipient.to_string(),
                "maxTimeoutSeconds": 300,
                "extra": {
                    "decimals": 6,
                    "tokenProgram": TOKEN_PROGRAM,
                    "recentBlockhash": Hash::new_unique().to_string(),
                }
            }]
        });
        let payment_required = base64::engine::general_purpose::STANDARD
            .encode(serde_json::to_vec(&envelope).unwrap());
        let saw_payment = Arc::new(AtomicBool::new(false));
        let app = Router::new()
            .route("/report", get(paid_resource))
            .with_state(ChallengeState {
                payment_required,
                saw_payment: saw_payment.clone(),
            });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{address}/report"), saw_payment, task)
    }

    async fn mpp_paid_resource(
        State(state): State<ChallengeState>,
        headers: HeaderMap,
    ) -> impl IntoResponse {
        if headers.contains_key(reqwest::header::AUTHORIZATION) {
            state.saw_payment.store(true, Ordering::SeqCst);
            return (StatusCode::OK, "paid").into_response();
        }
        (
            StatusCode::PAYMENT_REQUIRED,
            [(WWW_AUTHENTICATE_HEADER, state.payment_required)],
            "payment required",
        )
            .into_response()
    }

    async fn mpp_challenge_server(
        amount: u64,
        recipient: Pubkey,
    ) -> (String, Arc<AtomicBool>, tokio::task::JoinHandle<()>) {
        mpp_challenge_server_with_network(amount, recipient, Some("mainnet")).await
    }

    async fn mpp_challenge_server_with_network(
        amount: u64,
        recipient: Pubkey,
        network: Option<&str>,
    ) -> (String, Arc<AtomicBool>, tokio::task::JoinHandle<()>) {
        let details = MethodDetails {
            network: network.map(str::to_string),
            decimals: Some(6),
            token_program: Some(TOKEN_PROGRAM.to_string()),
            recent_blockhash: Some(Hash::new_unique().to_string()),
            ..Default::default()
        };
        let request = ChargeRequest {
            amount: amount.to_string(),
            currency: "USDC".to_string(),
            recipient: Some(recipient.to_string()),
            method_details: Some(serde_json::to_value(details).unwrap()),
            ..Default::default()
        };
        let challenge = PaymentChallenge::new(
            "permission-test",
            "127.0.0.1",
            "solana",
            "charge",
            Base64UrlJson::from_typed(&request).unwrap(),
        );
        let saw_payment = Arc::new(AtomicBool::new(false));
        let app = Router::new()
            .route("/report", get(mpp_paid_resource))
            .with_state(ChallengeState {
                payment_required: challenge.to_header().unwrap(),
                saw_payment: saw_payment.clone(),
            });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{address}/report"), saw_payment, task)
    }

    async fn malformed_x402_server() -> (String, tokio::task::JoinHandle<()>) {
        let envelope = serde_json::json!({
            "x402Version": 2,
            "accepts": [{
                "scheme": "exact",
                "network": SOLANA_MAINNET,
                "amount": "not-an-integer",
                "asset": USDC_MAINNET,
                "payTo": Pubkey::new_unique().to_string(),
                "maxTimeoutSeconds": 300,
                "extra": { "decimals": 6, "tokenProgram": TOKEN_PROGRAM }
            }]
        });
        let payment_required = base64::engine::general_purpose::STANDARD
            .encode(serde_json::to_vec(&envelope).unwrap());
        let app = Router::new().route(
            "/report",
            get(move || {
                let payment_required = payment_required.clone();
                async move {
                    (
                        StatusCode::PAYMENT_REQUIRED,
                        [("payment-required", payment_required)],
                        "payment required",
                    )
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{address}/report"), task)
    }

    async fn explicit_cluster_x402_server(
        cluster: &'static str,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let envelope = serde_json::json!({
            "x402Version": 2,
            "accepts": [{
                "scheme": "exact",
                "network": SOLANA_DEVNET,
                "cluster": cluster,
                "amount": "500000",
                "asset": "USDC",
                "payTo": Pubkey::new_unique().to_string(),
                "maxTimeoutSeconds": 300,
                "extra": {
                    "decimals": 6,
                    "tokenProgram": TOKEN_PROGRAM,
                    "recentBlockhash": Hash::new_unique().to_string(),
                }
            }]
        });
        let payment_required = base64::engine::general_purpose::STANDARD
            .encode(serde_json::to_vec(&envelope).unwrap());
        let app = Router::new().route(
            "/report",
            get(move || {
                let payment_required = payment_required.clone();
                async move {
                    (
                        StatusCode::PAYMENT_REQUIRED,
                        [("payment-required", payment_required)],
                        "payment required",
                    )
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{address}/report"), task)
    }

    async fn redirected_challenge_server(
        recipient: Pubkey,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let envelope = serde_json::json!({
            "x402Version": 2,
            "accepts": [{
                "scheme": "exact",
                "network": SOLANA_MAINNET,
                "amount": "500000",
                "asset": USDC_MAINNET,
                "payTo": recipient.to_string(),
                "maxTimeoutSeconds": 300,
                "extra": {
                    "decimals": 6,
                    "tokenProgram": TOKEN_PROGRAM,
                    "recentBlockhash": Hash::new_unique().to_string(),
                }
            }]
        });
        let payment_required = base64::engine::general_purpose::STANDARD
            .encode(serde_json::to_vec(&envelope).unwrap());
        let app = Router::new()
            .route("/start", get(|| async { Redirect::temporary("/report") }))
            .route(
                "/report",
                get(move || {
                    let payment_required = payment_required.clone();
                    async move {
                        (
                            StatusCode::PAYMENT_REQUIRED,
                            [("payment-required", payment_required)],
                            "payment required",
                        )
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{address}/start"), task)
    }

    async fn dual_paid_resource(
        State(state): State<DualChallengeState>,
        headers: HeaderMap,
    ) -> impl IntoResponse {
        if headers.contains_key("payment-signature") {
            state.saw_x402_payment.store(true, Ordering::SeqCst);
            return (StatusCode::OK, "paid").into_response();
        }
        (
            StatusCode::PAYMENT_REQUIRED,
            [
                (WWW_AUTHENTICATE_HEADER, state.mpp),
                ("payment-required", state.x402),
            ],
            "payment required",
        )
            .into_response()
    }

    async fn dual_challenge_server(
        recipient: Pubkey,
    ) -> (String, Arc<AtomicBool>, tokio::task::JoinHandle<()>) {
        let mpp_request = ChargeRequest {
            amount: "2000000".to_string(),
            currency: "USDC".to_string(),
            recipient: Some(recipient.to_string()),
            method_details: Some(
                serde_json::to_value(MethodDetails {
                    network: Some("mainnet".to_string()),
                    decimals: Some(6),
                    token_program: Some(TOKEN_PROGRAM.to_string()),
                    recent_blockhash: Some(Hash::new_unique().to_string()),
                    ..Default::default()
                })
                .unwrap(),
            ),
            ..Default::default()
        };
        let mpp = PaymentChallenge::new(
            "fallback-test",
            "127.0.0.1",
            "solana",
            "charge",
            Base64UrlJson::from_typed(&mpp_request).unwrap(),
        )
        .to_header()
        .unwrap();
        let envelope = serde_json::json!({
            "x402Version": 2,
            "accepts": [{
                "scheme": "exact",
                "network": SOLANA_MAINNET,
                "amount": "500000",
                "asset": USDC_MAINNET,
                "payTo": recipient.to_string(),
                "maxTimeoutSeconds": 300,
                "extra": {
                    "decimals": 6,
                    "tokenProgram": TOKEN_PROGRAM,
                    "recentBlockhash": Hash::new_unique().to_string(),
                }
            }]
        });
        let x402 = base64::engine::general_purpose::STANDARD
            .encode(serde_json::to_vec(&envelope).unwrap());
        let saw_x402_payment = Arc::new(AtomicBool::new(false));
        let app = Router::new()
            .route("/report", get(dual_paid_resource))
            .with_state(DualChallengeState {
                mpp,
                x402,
                saw_x402_payment: saw_x402_payment.clone(),
            });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{address}/report"), saw_x402_payment, task)
    }

    fn test_signer() -> MemorySigner {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let mut keypair = [0u8; 64];
        keypair[..32].copy_from_slice(signing_key.as_bytes());
        keypair[32..].copy_from_slice(signing_key.verifying_key().as_bytes());
        MemorySigner::from_bytes(&keypair).unwrap()
    }

    struct CountingSigner {
        calls: Arc<AtomicUsize>,
        pubkey: Pubkey,
    }

    #[async_trait]
    impl SolanaSigner for CountingSigner {
        fn pubkey(&self) -> Pubkey {
            self.pubkey
        }

        async fn sign_message(&self, _message: &[u8]) -> Result<Signature, SignerError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(SignerError::SigningFailed("must not sign".to_string()))
        }

        async fn is_available(&self) -> bool {
            true
        }
    }

    #[async_trait]
    impl TransactionSigner for CountingSigner {
        async fn sign_transaction(
            &self,
            _transaction: &mut VersionedTransaction,
        ) -> Result<SignTransactionResult, SignerError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(SignerError::SigningFailed("must not sign".to_string()))
        }
    }

    #[test]
    fn client_builder_requires_signer_rpc_and_protocol() {
        assert!(matches!(
            PayKitClient::builder()
                .rpc_url("http://localhost:8899")
                .build(),
            Err(ClientBuildError::MissingSigner)
        ));
        assert!(matches!(
            PayKitClient::builder().signer(test_signer()).build(),
            Err(ClientBuildError::MissingRpcUrl)
        ));
        assert!(matches!(
            PayKitClient::builder()
                .signer(test_signer())
                .rpc_url("http://localhost:8899")
                .accept([])
                .build(),
            Err(ClientBuildError::NoAcceptedProtocols)
        ));
    }

    #[tokio::test]
    async fn permitted_x402_challenge_is_signed_and_retried() {
        let signer = test_signer();
        let (url, saw_payment, task) = challenge_server(500_000, Pubkey::new_unique()).await;
        let client = PayKitClient::builder()
            .signer(signer)
            .rpc_url("http://127.0.0.1:1")
            .accept([ClientProtocol::X402])
            .build()
            .unwrap();

        let response = client.get(url).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(saw_payment.load(Ordering::SeqCst));
        task.abort();
    }

    #[tokio::test]
    async fn permitted_mpp_challenge_is_signed_and_retried() {
        let signer = test_signer();
        let (url, saw_payment, task) = mpp_challenge_server(500_000, Pubkey::new_unique()).await;
        let client = PayKitClient::builder()
            .signer(signer)
            .rpc_url("http://127.0.0.1:1")
            .accept([ClientProtocol::Mpp])
            .build()
            .unwrap();

        let response = client.get(url).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(saw_payment.load(Ordering::SeqCst));
        task.abort();
    }

    #[tokio::test]
    async fn omitted_mpp_network_uses_the_mainnet_default_at_signing() {
        let signer = test_signer();
        let (url, saw_payment, task) =
            mpp_challenge_server_with_network(500_000, Pubkey::new_unique(), None).await;
        let client = PayKitClient::builder()
            .signer(signer)
            .rpc_url("http://127.0.0.1:1")
            .accept([ClientProtocol::Mpp])
            .build()
            .unwrap();

        let response = client.get(url).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(saw_payment.load(Ordering::SeqCst));
        task.abort();
    }

    #[tokio::test]
    async fn malformed_supported_offer_returns_structured_denial() {
        let (url, task) = malformed_x402_server().await;
        let client = PayKitClient::builder()
            .signer(test_signer())
            .rpc_url("http://127.0.0.1:1")
            .accept([ClientProtocol::X402])
            .build()
            .unwrap();

        let error = client.get(url).send().await.unwrap_err();
        let ClientError::PermissionDenied(denial) = error else {
            panic!("expected permission denial");
        };
        assert_eq!(
            denial.rejections[0].code,
            PermissionDeniedCode::InvalidChallengeTerms
        );
        task.abort();
    }

    #[tokio::test]
    async fn unsupported_explicit_x402_cluster_is_denied_before_signing() {
        let calls = Arc::new(AtomicUsize::new(0));
        let signer = CountingSigner {
            calls: calls.clone(),
            pubkey: Pubkey::new_unique(),
        };
        let (url, task) = explicit_cluster_x402_server("bogus").await;
        let client = PayKitClient::builder()
            .signer(signer)
            .rpc_url("http://127.0.0.1:1")
            .network(SolanaNetwork::Devnet)
            .accept([ClientProtocol::X402])
            .build()
            .unwrap();

        let error = client.get(url).send().await.unwrap_err();
        let ClientError::PermissionDenied(denial) = error else {
            panic!("expected permission denial");
        };
        assert_eq!(
            denial.rejections[0].code,
            PermissionDeniedCode::InvalidChallengeTerms
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        task.abort();
    }

    #[tokio::test]
    async fn conflicting_x402_cluster_is_denied_before_signing() {
        let calls = Arc::new(AtomicUsize::new(0));
        let signer = CountingSigner {
            calls: calls.clone(),
            pubkey: Pubkey::new_unique(),
        };
        let (url, task) = explicit_cluster_x402_server("localnet").await;
        let client = PayKitClient::builder()
            .signer(signer)
            .rpc_url("http://127.0.0.1:1")
            .network(SolanaNetwork::Localnet)
            .accept([ClientProtocol::X402])
            .build()
            .unwrap();

        let error = client.get(url).send().await.unwrap_err();
        let ClientError::PermissionDenied(denial) = error else {
            panic!("expected permission denial");
        };
        assert_eq!(
            denial.rejections[0].code,
            PermissionDeniedCode::InvalidChallengeTerms
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        task.abort();
    }

    #[tokio::test]
    async fn redirected_402_fails_closed_before_signing() {
        let calls = Arc::new(AtomicUsize::new(0));
        let signer = CountingSigner {
            calls: calls.clone(),
            pubkey: Pubkey::new_unique(),
        };
        let (url, task) = redirected_challenge_server(Pubkey::new_unique()).await;
        let client = PayKitClient::builder()
            .signer(signer)
            .rpc_url("http://127.0.0.1:1")
            .accept([ClientProtocol::X402])
            .build()
            .unwrap();

        assert!(matches!(
            client.get(url).send().await,
            Err(ClientError::RedirectedChallenge { .. })
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        task.abort();
    }

    #[tokio::test]
    async fn denied_mpp_offer_falls_back_to_permitted_x402_offer() {
        let signer = test_signer();
        let (url, saw_x402_payment, task) = dual_challenge_server(Pubkey::new_unique()).await;
        let client = PayKitClient::builder()
            .signer(signer)
            .rpc_url("http://127.0.0.1:1")
            .build()
            .unwrap();

        let response = client.get(url).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(saw_x402_payment.load(Ordering::SeqCst));
        task.abort();
    }

    #[tokio::test]
    async fn denied_challenge_never_invokes_the_signer() {
        let calls = Arc::new(AtomicUsize::new(0));
        let signer = CountingSigner {
            calls: calls.clone(),
            pubkey: Pubkey::new_unique(),
        };
        let (url, saw_payment, task) = challenge_server(1_000_001, Pubkey::new_unique()).await;
        let client = PayKitClient::builder()
            .signer(signer)
            .rpc_url("http://127.0.0.1:1")
            .accept([ClientProtocol::X402])
            .build()
            .unwrap();

        let error = client.get(url).send().await.unwrap_err();
        let ClientError::PermissionDenied(denial) = error else {
            panic!("expected permission denial");
        };
        assert_eq!(
            denial.rejections[0].code,
            PermissionDeniedCode::AmountExceedsLimit
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(!saw_payment.load(Ordering::SeqCst));
        task.abort();
    }
}
