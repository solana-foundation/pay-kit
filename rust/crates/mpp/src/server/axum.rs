//! Axum extractor for payment-gated routes.
//!
//! [`MppCharge<C>`] handles the full 402 challenge/verify flow:
//!
//! - No `Authorization: Payment` header → 402 with `WWW-Authenticate` challenge
//! - Invalid or mismatched credential → 402 with a fresh challenge
//! - Valid credential → extracts the [`Receipt`] for the handler
//!
//! The `C: ChargeConfig` type parameter pins the route's amount at compile
//! time. The extractor builds the route's expected request from `C::amount()`
//! and passes it to [`Mpp::verify_credential_with_expected`], so a credential
//! issued for a cheaper route on the same server cannot be replayed here.
//!
//! # Example
//!
//! ```ignore
//! use solana_mpp::server::axum::{ChargeConfig, MppCharge};
//! use solana_mpp::server::{Config, Mpp};
//! use axum::{routing::get, Router};
//! use std::sync::Arc;
//!
//! struct OneCent;
//! impl ChargeConfig for OneCent {
//!     fn amount() -> &'static str { "0.01" }
//! }
//!
//! async fn handler(charge: MppCharge<OneCent>) -> String {
//!     format!("paid: {}", charge.receipt.reference)
//! }
//!
//! let mpp = Arc::new(Mpp::new(Config {
//!     recipient: "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY".to_string(),
//!     ..Default::default()
//! }).unwrap());
//!
//! let app: Router = Router::new()
//!     .route("/api/cheap", get(handler))
//!     .with_state(mpp);
//! ```

use std::marker::PhantomData;
use std::sync::Arc;

use axum::extract::{FromRef, FromRequestParts};
use axum::http::request::Parts;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::protocol::core::headers::{
    format_receipt, format_www_authenticate, parse_authorization, PAYMENT_RECEIPT_HEADER,
    WWW_AUTHENTICATE_HEADER,
};
use crate::protocol::core::{PaymentChallenge, Receipt};
use crate::server::{ChargeOptions, Mpp};

/// Per-route charge configuration.
///
/// Implement on a marker type to pin a route's amount at compile time.
/// Server-level settings (recipient, currency, fee payer) live on the
/// [`Mpp`] instance, not per route.
pub trait ChargeConfig: Send + Sync + 'static {
    /// Dollar amount to charge (e.g., `"0.01"`).
    fn amount() -> &'static str;

    /// Optional human-readable description embedded in the challenge.
    fn description() -> Option<&'static str> {
        None
    }
}

/// 402 Payment Required response wrapping a [`PaymentChallenge`].
#[derive(Debug)]
pub struct PaymentRequired(pub PaymentChallenge);

impl IntoResponse for PaymentRequired {
    fn into_response(self) -> Response {
        let www_auth = match format_www_authenticate(&self.0) {
            Ok(s) => s,
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Failed to format challenge: {e}"),
                )
                    .into_response();
            }
        };

        let body = serde_json::to_string(&self.0).unwrap_or_else(|_| "{}".to_string());
        let mut resp = (StatusCode::PAYMENT_REQUIRED, body).into_response();
        let headers = resp.headers_mut();
        if let Ok(v) = HeaderValue::from_str(&www_auth) {
            headers.insert(WWW_AUTHENTICATE_HEADER, v);
        }
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        // Per RFC 9111 §4.2.2, 402 responses must not be cached when they
        // carry a single-use challenge.
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        resp
    }
}

/// Axum extractor that gates a handler behind payment verification.
#[derive(Debug)]
pub struct MppCharge<C: ChargeConfig> {
    pub receipt: Receipt,
    _c: PhantomData<C>,
}

/// Rejection returned by [`MppCharge`] when the request isn't paid.
#[derive(Debug)]
#[non_exhaustive]
pub enum MppChargeRejection {
    /// No (or unrecognised) credential — return 402 with a fresh challenge.
    Challenge(PaymentRequired),
    /// Credential present but failed verification — return 402 with a fresh challenge.
    VerificationFailed(PaymentRequired),
    /// Server couldn't generate a challenge — return 500.
    InternalError(String),
}

impl IntoResponse for MppChargeRejection {
    fn into_response(self) -> Response {
        match self {
            Self::Challenge(pr) | Self::VerificationFailed(pr) => pr.into_response(),
            Self::InternalError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg).into_response(),
        }
    }
}

impl<S, C> FromRequestParts<S> for MppCharge<C>
where
    Arc<Mpp>: FromRef<S>,
    C: ChargeConfig,
    S: Send + Sync,
{
    type Rejection = MppChargeRejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let mpp: Arc<Mpp> = Arc::<Mpp>::from_ref(state);

        // Build the route's authoritative challenge once. We need it whether
        // we 402 (no credential, bad credential, failed verify) or pass it
        // through verification — and crucially, decoding its request gives us
        // the `expected` value that pins this route's amount/currency/recipient
        // for `verify_credential_with_expected`.
        let challenge = mpp
            .charge_with_options(
                C::amount(),
                ChargeOptions {
                    description: C::description(),
                    ..Default::default()
                },
            )
            .map_err(|e| MppChargeRejection::InternalError(format!("charge failed: {e}")))?;

        let auth_str = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);

        let auth_str = match auth_str {
            Some(s) if s.starts_with("Payment ") => s,
            _ => return Err(MppChargeRejection::Challenge(PaymentRequired(challenge))),
        };

        let credential = match parse_authorization(&auth_str) {
            Ok(c) => c,
            Err(_) => return Err(MppChargeRejection::Challenge(PaymentRequired(challenge))),
        };

        let expected = match challenge.request.decode() {
            Ok(r) => r,
            Err(e) => {
                return Err(MppChargeRejection::InternalError(format!(
                    "failed to decode expected request: {e}"
                )))
            }
        };

        match mpp
            .verify_credential_with_expected(&credential, &expected)
            .await
        {
            Ok(receipt) => Ok(Self {
                receipt,
                _c: PhantomData,
            }),
            Err(_) => Err(MppChargeRejection::VerificationFailed(PaymentRequired(
                challenge,
            ))),
        }
    }
}

/// Wrap a handler response with the `Payment-Receipt` header attached.
pub struct WithReceipt<T> {
    pub receipt: Receipt,
    pub body: T,
}

impl<T: IntoResponse> IntoResponse for WithReceipt<T> {
    fn into_response(self) -> Response {
        let mut resp = self.body.into_response();
        if let Ok(header_val) = format_receipt(&self.receipt) {
            if let Ok(v) = HeaderValue::from_str(&header_val) {
                resp.headers_mut().insert(PAYMENT_RECEIPT_HEADER, v);
            }
        }
        resp
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format_authorization;
    use crate::protocol::core::PaymentCredential;
    use crate::server::Config;
    use axum::http::Request;

    const TEST_RECIPIENT: &str = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY";
    const TEST_SECRET: &str = "axum-extractor-test-secret-key";

    fn test_mpp() -> Arc<Mpp> {
        Arc::new(
            Mpp::new(Config {
                recipient: TEST_RECIPIENT.to_string(),
                secret_key: Some(TEST_SECRET.to_string()),
                network: "devnet".to_string(),
                ..Default::default()
            })
            .unwrap(),
        )
    }

    struct OneCent;
    impl ChargeConfig for OneCent {
        fn amount() -> &'static str {
            "0.01"
        }
    }

    struct OneDollar;
    impl ChargeConfig for OneDollar {
        fn amount() -> &'static str {
            "1.00"
        }
    }

    fn parts_with_header(header_value: Option<&str>) -> Parts {
        let mut builder = Request::builder().uri("/protected");
        if let Some(v) = header_value {
            builder = builder.header(header::AUTHORIZATION, v);
        }
        let req = builder.body(()).unwrap();
        req.into_parts().0
    }

    #[test]
    fn payment_required_returns_402_with_challenge_headers() {
        let mpp = test_mpp();
        let challenge = mpp.charge("0.01").unwrap();
        let resp = PaymentRequired(challenge).into_response();
        assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
        assert!(resp.headers().contains_key(WWW_AUTHENTICATE_HEADER));
        assert_eq!(
            resp.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        assert_eq!(
            resp.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn missing_authorization_returns_challenge_rejection() {
        let state = test_mpp();
        let mut parts = parts_with_header(None);

        let err = MppCharge::<OneCent>::from_request_parts(&mut parts, &state)
            .await
            .err()
            .expect("should reject");
        match err {
            MppChargeRejection::Challenge(_) => {}
            other => panic!("expected Challenge, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn non_payment_scheme_returns_challenge_rejection() {
        let state = test_mpp();
        let mut parts = parts_with_header(Some("Bearer abc"));

        let err = MppCharge::<OneCent>::from_request_parts(&mut parts, &state)
            .await
            .err()
            .expect("should reject");
        assert!(matches!(err, MppChargeRejection::Challenge(_)));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn malformed_payment_header_returns_challenge_rejection() {
        let state = test_mpp();
        let mut parts = parts_with_header(Some("Payment !!!not-base64!!!"));

        let err = MppCharge::<OneCent>::from_request_parts(&mut parts, &state)
            .await
            .err()
            .expect("should reject");
        assert!(matches!(err, MppChargeRejection::Challenge(_)));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn cross_route_replay_rejected_with_verification_failed() {
        // Issue a credential for the cheap route, then submit it to the
        // expensive route. The extractor must reject — this is the whole
        // point of the route-aware verification.
        let state = test_mpp();
        let cheap_challenge = state.charge(OneCent::amount()).unwrap();
        let cred = PaymentCredential::new(
            cheap_challenge.to_echo(),
            serde_json::json!({"type": "signature", "signature": "fakesig"}),
        );
        let auth_header = format_authorization(&cred).unwrap();
        let mut parts = parts_with_header(Some(&auth_header));

        let err = MppCharge::<OneDollar>::from_request_parts(&mut parts, &state)
            .await
            .err()
            .expect("should reject");
        match err {
            MppChargeRejection::VerificationFailed(_) => {}
            other => panic!("expected VerificationFailed, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn verification_failed_rejection_returns_402_with_challenge() {
        let state = test_mpp();
        let cheap_challenge = state.charge(OneCent::amount()).unwrap();
        let cred = PaymentCredential::new(
            cheap_challenge.to_echo(),
            serde_json::json!({"type": "signature", "signature": "fakesig"}),
        );
        let auth_header = format_authorization(&cred).unwrap();
        let mut parts = parts_with_header(Some(&auth_header));

        let rejection = MppCharge::<OneDollar>::from_request_parts(&mut parts, &state)
            .await
            .err()
            .expect("should reject");
        let resp = rejection.into_response();
        assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
        assert!(resp.headers().contains_key(WWW_AUTHENTICATE_HEADER));
    }

    #[test]
    fn with_receipt_attaches_payment_receipt_header() {
        let receipt = Receipt::success("solana", "5UfDuX123", "challenge-id");
        let resp = WithReceipt {
            receipt,
            body: "ok",
        }
        .into_response();
        assert!(resp.headers().contains_key(PAYMENT_RECEIPT_HEADER));
    }

    #[test]
    fn rejection_internal_error_returns_500() {
        let resp = MppChargeRejection::InternalError("boom".to_string()).into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
