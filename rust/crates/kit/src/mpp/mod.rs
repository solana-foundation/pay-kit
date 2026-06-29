//! Solana payment method for the Machine Payments Protocol.
//!
//! This crate implements the `charge` intent for Solana, supporting
//! native SOL and SPL token transfers with two settlement modes:
//!
//! - **Pull mode** (`type="transaction"`): Client signs, server broadcasts.
//! - **Push mode** (`type="signature"`): Client broadcasts, server verifies.
//!
//! # Features
//!
//! - `server` — Server-side verification (enabled by default)
//! - `client` — Client-side transaction building (enabled by default)
//!
//! # Quick Start (Server)
//!
//! ```ignore
//! use crate::mpp::server::{Mpp, Config};
//!
//! let mpp = Mpp::new(Config {
//!     recipient: "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY".to_string(),
//!     ..Default::default()
//! })?;
//!
//! // Generate a charge challenge (returns HTTP 402)
//! let challenge = mpp.charge("0.10")?;
//! let header = challenge.to_header()?;
//!
//! // Verify a credential from Authorization header. The expected
//! // ChargeRequest pins this route's amount/currency/recipient (audit #2).
//! let credential = PaymentCredential::from_header(&auth_header)?;
//! let expected = ChargeRequest {
//!     amount: "100000".to_string(),
//!     currency: "USDC".to_string(),
//!     recipient: Some("CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY".to_string()),
//!     ..Default::default()
//! };
//! let receipt = mpp.verify_credential_with_expected(&credential, &expected).await?;
//! ```

pub mod error;
pub mod expires;
pub mod program;
pub mod protocol;
pub mod store;

/// Batched on-chain settlement — packing always; the background worker under
/// the `settlement` feature. Shared with x402 via `solana-pay-core`.
pub use crate::core::settlement;

#[cfg(feature = "client")]
pub mod client;

#[cfg(feature = "server")]
pub mod server;

// ── Re-exports ──

pub use error::{Error, Result};

// Core protocol types
pub use protocol::core::{
    base64url_decode, base64url_encode, compute_challenge_id, Base64UrlJson, ChallengeEcho,
    IntentName, MethodName, PaymentChallenge, PaymentCredential, Receipt, ReceiptKind,
    ReceiptStatus,
};

// Header parsing/formatting
pub use protocol::core::{
    extract_payment_scheme, format_authorization, format_receipt, format_www_authenticate,
    format_www_authenticate_many, parse_authorization, parse_receipt, parse_www_authenticate,
    parse_www_authenticate_all, AUTHORIZATION_HEADER, PAYMENT_RECEIPT_HEADER, PAYMENT_SCHEME,
    WWW_AUTHENTICATE_HEADER,
};

// Intent types
pub use protocol::intents::{
    parse_units, ActivatePayload, AuthenticateMethodDetails, AuthenticatePayload,
    AuthenticateRequest, ChargeRequest, ClosePayload, CommitPayload, CommitReceipt, CommitStatus,
    MeteredEnvelope, MeteringDirective, MeteringUsage, OpenPayload, SessionAction, SessionMode,
    SessionPullVoucherStrategy, SessionRequest, SessionSplit, SignedVoucher, SubscriptionAction,
    SubscriptionPeriodUnit, SubscriptionReceiptExtensions, SubscriptionRequest, TopUpPayload,
    VoucherData, VoucherPayload, DEFAULT_SESSION_EXPIRES_AT, RESOURCE_SCHEME_HTTP,
    RESOURCE_SCHEME_SOLANA_SESSION, RESOURCE_SCHEME_SOLANA_SUBSCRIPTION, SIGNATURE_SCHEME_SIWMPP,
    SIGNATURE_TYPE_ED25519, SIWMPP_VERSION,
};

pub use protocol::solana::{
    default_token_program_for_currency, mints, programs, resolve_stablecoin_mint,
};

// Store types
pub use store::{
    ChannelState, ChannelStore, CommittedDelivery, MemoryChannelStore, MemoryStore,
    PendingDelivery, Store, StoreError,
};

// Re-export crates callers need to use with the charge builder.
pub use solana_keychain;
pub use solana_rpc_client;

/// Reusable OpenTelemetry init (feature `otel`), shared with x402/pay so spans
/// + metrics from every layer land in one collector.
#[cfg(feature = "otel")]
pub use crate::core::otel;
