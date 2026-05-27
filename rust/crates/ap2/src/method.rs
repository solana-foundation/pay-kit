//! `PaymentMethod` + `PaymentPayload` — the bridge to x402 and MPP.
//!
//! AP2's `payment_request.method_data[].data` is a typed envelope that
//! identifies a payment rail via a `supported_methods` URI and carries
//! a rail-specific blob in `data`. We serialize the Rust enum into
//! exactly that shape so the wire format matches `a2a-x402` v0.2 for
//! the x402 variant and our own extension URI for the MPP variant.
//!
//! Adding a third rail (cards, Lightning, etc.) is a new variant on
//! both enums + a const for the URI; no other code changes.

use serde::{Deserialize, Serialize};

use solana_mpp::ChargeRequest;
use solana_x402::exact::PaymentRequirements;

/// `supported_methods` URI for the x402 rail. Defined by upstream
/// a2a-x402 v0.2 in `spec/v0.2/spec.md`.
pub const X402_METHOD_URI: &str = "https://www.x402.org/";

/// `supported_methods` URI for the MPP rail. **pay-kit extension** —
/// not yet defined upstream. Tracked for spec PR.
pub const MPP_METHOD_URI: &str = "https://paymentauth.org/mpp";

/// Stringly-typed copy of the URI carried alongside the
/// `IntentConstraints.allowed_methods` list. Lets a verifier compare
/// the cart's method against the intent's allowlist without round-
/// tripping through enum discriminants.
pub type PaymentMethodId = String;

/// Identifier helper — returns the URI string for a method variant
/// without owning a value of it.
pub trait MethodUri {
    fn method_uri(&self) -> &'static str;
}

/// What the merchant proposes in a [`CartMandate`]. Embeds either an
/// x402 `PaymentRequirements` block or an MPP `ChargeRequest` block.
///
/// On the wire this serializes as `{ "supported_methods": "<uri>",
/// "data": { … } }` which matches the AP2 `method_data[]` shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "supported_methods", content = "data")]
pub enum PaymentMethod {
    /// x402 `exact` scheme. Matches upstream a2a-x402.
    #[serde(rename = "https://www.x402.org/")]
    X402(PaymentRequirements),

    /// MPP charge intent. pay-kit extension.
    #[serde(rename = "https://paymentauth.org/mpp")]
    Mpp(ChargeRequest),
}

impl MethodUri for PaymentMethod {
    fn method_uri(&self) -> &'static str {
        match self {
            Self::X402(_) => X402_METHOD_URI,
            Self::Mpp(_) => MPP_METHOD_URI,
        }
    }
}

/// The signed-proof side of the rail bridge. Same `supported_methods`
/// envelope, but the payload is the rail's signed-payment value: an
/// x402 `PaymentPayload` (which carries the signed Solana transaction)
/// or an MPP `PaymentCredential` (which carries the signed credential).
///
/// The `data` body is held as a raw `serde_json::Value` so this crate
/// doesn't have to copy the shape of every protocol's payload — the
/// downstream verifier deserializes its own type. The chain validator
/// only needs the URI to discriminate rails.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "supported_methods", content = "data")]
pub enum PaymentPayload {
    /// x402 signed payload. The body deserializes to
    /// `solana_x402::exact::PaymentPayload` on the verify path.
    #[serde(rename = "https://www.x402.org/")]
    X402(serde_json::Value),

    /// MPP signed credential. The body deserializes to a
    /// `solana_mpp::PaymentCredential` on the verify path.
    #[serde(rename = "https://paymentauth.org/mpp")]
    Mpp(serde_json::Value),
}

impl MethodUri for PaymentPayload {
    fn method_uri(&self) -> &'static str {
        match self {
            Self::X402(_) => X402_METHOD_URI,
            Self::Mpp(_) => MPP_METHOD_URI,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use solana_mpp::ChargeRequest;

    #[test]
    fn x402_method_serializes_with_canonical_uri() {
        let method = PaymentMethod::X402(crate::mandate::sample_x402_requirements());

        let wire = serde_json::to_value(&method).unwrap();
        assert_eq!(wire["supported_methods"], json!(X402_METHOD_URI));
        assert!(wire.get("data").is_some(), "data envelope must be present");
    }

    #[test]
    fn mpp_method_uses_paykit_extension_uri() {
        let mut req = ChargeRequest::default();
        req.amount = "100000".to_string();
        req.currency = "USDC".to_string();
        req.recipient = Some("11111111111111111111111111111112".to_string());
        let method = PaymentMethod::Mpp(req);

        let wire = serde_json::to_value(&method).unwrap();
        assert_eq!(wire["supported_methods"], json!(MPP_METHOD_URI));
    }

    #[test]
    fn method_uri_matches_serialized_tag() {
        let req = ChargeRequest::default();
        let method = PaymentMethod::Mpp(req);
        assert_eq!(method.method_uri(), MPP_METHOD_URI);
    }
}
