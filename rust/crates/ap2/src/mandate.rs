//! The three AP2 Mandate types: Intent, Cart, Payment.
//!
//! Each Mandate is a verifiable digital credential — a piece of JSON
//! that the verifier checks via [`crate::signature::canonicalize`] +
//! Ed25519. The signature is stored as a sibling field on the mandate,
//! not nested inside the signed payload, so canonicalization is over
//! the "everything except `signature`" view.
//!
//! See `docs/SPEC.md` for the on-the-wire JSON shape this crate emits.

use serde::{Deserialize, Serialize};

use crate::method::{PaymentMethod, PaymentMethodId, PaymentPayload};
use crate::signature::SignedBytes;

/// Opaque mandate identifier. Format is up to the issuer; pay-kit
/// produces UUIDv4 strings by default but anything 1–128 bytes works.
/// The verifier treats this as a replay-cache key.
pub type MandateId = String;

// =============================================================================
//   IntentMandate
// =============================================================================

/// The user delegates spending authority to an agent.
///
/// Issued by the user (signed with the user's Solana key) before any
/// merchant is involved. Bounds what the agent can spend, on which
/// rails, with which merchants, and for how long. Pay-kit treats this
/// as the top of the trust chain; subsequent mandates must reference
/// its `id` and stay within its `constraints`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentMandate {
    /// Opaque identifier (UUID-ish).
    pub id: MandateId,

    /// Base58 user pubkey — must match `user_signature.signer_pubkey`.
    pub user_pubkey: String,

    /// Base58 pubkey of the agent the user is delegating to. Carried
    /// for audit; not enforced by the chain validator today.
    pub agent_pubkey: String,

    /// Spend bounds.
    pub constraints: IntentConstraints,

    /// Unix seconds. Mandate is not valid before this.
    pub valid_after: i64,

    /// Unix seconds. Mandate is not valid after this.
    pub valid_before: i64,

    /// Ed25519 signature over the canonical-JSON encoding of every
    /// field above. The signed view excludes this field — see
    /// [`IntentMandate::signed_view`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_signature: Option<SignedBytes>,
}

/// What the user authorized.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentConstraints {
    /// Maximum total spend, in smallest units of `currency`.
    pub max_amount_minor: u64,

    /// e.g. "USDC", "USDT". Matches pay-kit's currency vocabulary.
    pub currency: String,

    /// If `Some`, only carts payable to one of these pubkeys are
    /// authorized. `None` means "any merchant".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_merchants: Option<Vec<String>>,

    /// `supported_methods` URIs the user pre-approved (e.g.
    /// `["https://www.x402.org/", "https://paymentauth.org/mpp"]`).
    pub allowed_methods: Vec<PaymentMethodId>,
}

impl IntentMandate {
    /// The view that gets canonicalized + signed. Drops the signature
    /// itself so verification can check the sig against the bytes
    /// without circularity.
    pub fn signed_view(&self) -> serde_json::Value {
        let mut v = serde_json::to_value(self).expect("IntentMandate serializes");
        if let serde_json::Value::Object(ref mut map) = v {
            map.remove("user_signature");
        }
        v
    }
}

// =============================================================================
//   CartMandate
// =============================================================================

/// The merchant proposes a specific cart at a specific price.
///
/// Created by the merchant in response to the agent's request,
/// references the user's `IntentMandate`, and embeds an x402 or MPP
/// payment-method block via [`PaymentMethod`]. Signed by the merchant.
///
/// The merchant signature is non-negotiable: it binds the merchant to
/// the exact line items + price + rail. If the merchant tries to swap
/// the cart before settlement, the user's `PaymentMandate` (which
/// hashes the cart) won't match.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CartMandate {
    /// Opaque identifier.
    pub id: MandateId,

    /// References the [`IntentMandate::id`] this cart was authorized by.
    pub intent_mandate_id: MandateId,

    /// Base58 merchant pubkey — must match `merchant_signature.signer_pubkey`.
    pub merchant_pubkey: String,

    /// What's being bought.
    pub cart: Cart,

    /// Which rail and what the rail-specific challenge looks like.
    pub payment_method: PaymentMethod,

    /// Unix seconds. Cart offer expires at this point.
    pub valid_until: i64,

    /// Ed25519 signature by the merchant.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub merchant_signature: Option<SignedBytes>,
}

/// Line-items + total. Kept minimal at the AP2 layer; merchants can
/// stuff catalog-specific metadata into `metadata`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cart {
    pub items: Vec<CartItem>,

    /// Total in smallest units of `IntentConstraints.currency`. The
    /// verifier compares this against `IntentConstraints.max_amount_minor`.
    pub total_minor: u64,

    pub currency: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CartItem {
    pub sku: String,
    pub description: String,
    pub quantity: u32,
    pub unit_price_minor: u64,
}

impl CartMandate {
    /// Signed view (everything except the merchant signature).
    pub fn signed_view(&self) -> serde_json::Value {
        let mut v = serde_json::to_value(self).expect("CartMandate serializes");
        if let serde_json::Value::Object(ref mut map) = v {
            map.remove("merchant_signature");
        }
        v
    }

    /// SHA-256 of the canonical-JSON `signed_view`. The
    /// [`PaymentMandate`] stores this hash so a tampered cart at proof
    /// time can be detected. Returns 32 raw bytes; callers usually
    /// hex- or base58-encode for transport.
    pub fn snapshot_hash(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let bytes = serde_json_canonicalizer::to_vec(&self.signed_view())
            .expect("canonical encoding of signed view");
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        hasher.finalize().into()
    }
}

// =============================================================================
//   PaymentMandate
// =============================================================================

/// The user approves a specific cart and attaches a rail-signed
/// payment proof to it.
///
/// Created by the user's wallet/trusted-surface after they've reviewed
/// the cart. Signed twice: the rail-level signature lives inside
/// `payment_payload` (e.g. the signed Solana transaction for x402, or
/// the signed credential for MPP), and the user's AP2-layer signature
/// lives at the top level binding the whole `PaymentMandate` to the
/// cart hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentMandate {
    /// Opaque identifier — also the replay-cache key.
    pub id: MandateId,

    /// References the [`CartMandate::id`] being approved.
    pub cart_mandate_id: MandateId,

    /// Base58-encoded SHA-256 of the cart's `signed_view`. Defense
    /// against a merchant swapping the cart between offer and settle.
    pub cart_mandate_hash: String,

    /// Rail-bound payment proof.
    pub payment_payload: PaymentPayload,

    /// Ed25519 signature by the user.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_signature: Option<SignedBytes>,
}

impl PaymentMandate {
    pub fn signed_view(&self) -> serde_json::Value {
        let mut v = serde_json::to_value(self).expect("PaymentMandate serializes");
        if let serde_json::Value::Object(ref mut map) = v {
            map.remove("user_signature");
        }
        v
    }
}

#[cfg(test)]
pub(crate) fn sample_x402_requirements() -> solana_x402::exact::PaymentRequirements {
    solana_x402::exact::PaymentRequirements {
        network: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp".to_string(),
        cluster: Some("mainnet-beta".to_string()),
        recipient: "11111111111111111111111111111114".to_string(),
        amount: "100000".to_string(),
        currency: "USDC".to_string(),
        decimals: Some(6),
        token_program: None,
        resource: "https://example.com/r".to_string(),
        description: None,
        max_age: Some(60),
        recent_blockhash: None,
        fee_payer: None,
        fee_payer_key: None,
        extra: None,
        accepted: None,
        resource_info: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::method::{PaymentMethod, X402_METHOD_URI};

    fn sample_intent() -> IntentMandate {
        IntentMandate {
            id: "intent-1".into(),
            user_pubkey: "11111111111111111111111111111112".into(),
            agent_pubkey: "11111111111111111111111111111113".into(),
            constraints: IntentConstraints {
                max_amount_minor: 10_000_000,
                currency: "USDC".into(),
                allowed_merchants: None,
                allowed_methods: vec![X402_METHOD_URI.into()],
            },
            valid_after: 0,
            valid_before: i64::MAX,
            user_signature: None,
        }
    }

    fn sample_cart() -> CartMandate {
        CartMandate {
            id: "cart-1".into(),
            intent_mandate_id: "intent-1".into(),
            merchant_pubkey: "11111111111111111111111111111114".into(),
            cart: Cart {
                items: vec![CartItem {
                    sku: "SKU-A".into(),
                    description: "Premium report".into(),
                    quantity: 1,
                    unit_price_minor: 100_000,
                }],
                total_minor: 100_000,
                currency: "USDC".into(),
                metadata: None,
            },
            payment_method: PaymentMethod::X402(sample_x402_requirements()),
            valid_until: i64::MAX,
            merchant_signature: None,
        }
    }

    #[test]
    fn signed_view_excludes_signature() {
        let intent = sample_intent();
        let view = intent.signed_view();
        assert!(view.get("user_signature").is_none());
        assert!(view.get("id").is_some());
    }

    #[test]
    fn cart_snapshot_hash_is_deterministic() {
        let cart = sample_cart();
        let h1 = cart.snapshot_hash();
        let h2 = cart.snapshot_hash();
        assert_eq!(h1, h2, "hash must be stable across calls");
    }

    #[test]
    fn cart_snapshot_hash_changes_with_total() {
        let mut a = sample_cart();
        let mut b = sample_cart();
        b.cart.total_minor += 1;

        // Add a signature to one and not the other; hash must be
        // identical because signed_view drops the signature.
        a.merchant_signature = None;
        b.merchant_signature = None;

        assert_ne!(a.snapshot_hash(), b.snapshot_hash());
    }

    #[test]
    fn cart_snapshot_hash_ignores_signature_field() {
        use crate::signature::SignedBytes;
        let mut a = sample_cart();
        let b = sample_cart();
        a.merchant_signature = Some(SignedBytes {
            signature: "1".into(),
            signer_pubkey: "1".into(),
        });

        assert_eq!(
            a.snapshot_hash(),
            b.snapshot_hash(),
            "snapshot_hash must drop signature so a freshly-signed cart hashes the same as an unsigned one"
        );
    }
}
