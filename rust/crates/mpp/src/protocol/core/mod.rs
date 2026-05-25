//! Core Web Payment Auth protocol types and parsing.
//!
//! Zero heavy dependencies — only serde, serde_json, hmac, sha2, base64, time.

pub mod challenge;
pub mod headers;
pub mod types;

pub use challenge::{
    compute_challenge_id, ChallengeEcho, PaymentChallenge, PaymentCredential, Receipt,
};
pub use headers::{
    extract_payment_scheme, format_authorization, format_receipt, format_www_authenticate,
    format_www_authenticate_many, parse_authorization, parse_receipt, parse_www_authenticate,
    parse_www_authenticate_all, AUTHORIZATION_HEADER, PAYMENT_RECEIPT_HEADER, PAYMENT_SCHEME,
    WWW_AUTHENTICATE_HEADER,
};
pub use types::{
    base64url_decode, base64url_encode, Base64UrlJson, IntentName, MethodName, ReceiptStatus,
};
