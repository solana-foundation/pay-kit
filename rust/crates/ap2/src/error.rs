//! Errors raised by the AP2 layer.
//!
//! All `Ap2Error` variants are recoverable from the merchant's
//! standpoint: they correspond to a 4xx-class refusal to settle, not a
//! 5xx-class server fault. The Rack/Sinatra/Express integration in
//! pay-kit's umbrella surface translates these into HTTP responses
//! (`402 Payment Required` for chain failures, `403 Forbidden` for
//! signature/expiry/replay failures).

use thiserror::Error;

/// All failure modes in the mandate lifecycle.
#[derive(Debug, Error)]
pub enum Ap2Error {
    /// The mandate JSON did not match the expected schema.
    #[error("malformed mandate: {0}")]
    Malformed(String),

    /// The mandate's `valid_after` is in the future, or its
    /// `valid_before` is in the past.
    #[error("mandate {what} outside validity window")]
    OutsideValidityWindow { what: &'static str },

    /// Ed25519 signature failed verification.
    #[error("signature verification failed for {what}")]
    SignatureInvalid { what: &'static str },

    /// `cart.intent_mandate_id` does not match `intent.id`.
    #[error("cart references intent {cart_ref} but verifier was given intent {actual}")]
    IntentMismatch { cart_ref: String, actual: String },

    /// `payment.cart_mandate_id` does not match `cart.id`.
    #[error("payment references cart {payment_ref} but verifier was given cart {actual}")]
    CartMismatch { payment_ref: String, actual: String },

    /// `payment.cart_mandate_hash` does not match SHA-256 of the
    /// canonical cart — the payment is bound to a different cart than
    /// the one the verifier is checking against. Defense against
    /// amount/recipient swap at proof time.
    #[error("payment is bound to a different cart snapshot than the one provided")]
    CartHashMismatch,

    /// The cart's total exceeds the intent's `max_amount_minor`.
    #[error("cart total {cart_total} exceeds intent max {intent_max}")]
    AmountExceedsIntent { cart_total: u64, intent_max: u64 },

    /// The cart's merchant pubkey isn't in the intent's allowlist.
    #[error("merchant {merchant} not authorized by intent's allowed_merchants")]
    MerchantNotAuthorized { merchant: String },

    /// The cart's payment method isn't in the intent's allowed methods.
    #[error("payment method {method} not authorized by intent's allowed_methods")]
    PaymentMethodNotAuthorized { method: String },

    /// `payment.payload`'s `supported_methods` URI doesn't match the
    /// cart's. The user signed approval for one rail but presented a
    /// proof on a different rail.
    #[error("payload method {payload_method} does not match cart method {cart_method}")]
    PaymentMethodKindMismatch {
        cart_method: String,
        payload_method: String,
    },

    /// The mandate ID has already been settled — replay refused.
    #[error("mandate {0} already consumed")]
    Replayed(String),

    /// The downstream protocol verifier refused the payload (invalid
    /// x402 tx, MPP simulation failure, etc.). Carries the protocol-
    /// specific reason string.
    #[error("downstream {protocol} verifier rejected: {reason}")]
    DownstreamVerifierRejected {
        protocol: &'static str,
        reason: String,
    },
}
