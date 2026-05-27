//! Mandate-chain verifier + replay store.
//!
//! `MandateVerifier` is the single entry point a server uses before
//! settling: it validates all three signatures, walks the chain
//! (intent ⊇ cart ⊇ payment), and consumes the payment mandate ID
//! against a replay store. It **does not** call the downstream x402 or
//! MPP verifier — that's the caller's responsibility once chain
//! validation succeeds. Splitting the two layers keeps this crate
//! focused on the AP2 semantics; downstream protocols already have
//! their own configs and constructors.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use thiserror::Error;

use crate::error::Ap2Error;
use crate::mandate::{CartMandate, IntentMandate, MandateId, PaymentMandate};
use crate::method::MethodUri;

// =============================================================================
//   Replay store
// =============================================================================

/// Refusal reason from the replay store. The verifier translates this
/// into `Ap2Error::Replayed` for callers.
#[derive(Debug, Error)]
pub enum MandateReplayError {
    #[error("mandate {0} already consumed")]
    AlreadyConsumed(MandateId),
}

/// Pluggable "have I settled this mandate before?" cache. Implementors
/// are responsible for their own TTL pruning + transactional semantics.
///
/// The verifier calls `consume` exactly once per successful payment;
/// duplicate calls must return `AlreadyConsumed`. There's no `release`
/// hook because mandate IDs are write-once for replay-protection.
pub trait MandateReplayStore: Send + Sync {
    fn consume(&self, id: &MandateId, now: SystemTime) -> Result<(), MandateReplayError>;
}

/// In-memory store with TTL pruning. Stores `(id, inserted_at)` and
/// drops entries older than `ttl_seconds`. Suitable for single-process
/// servers and tests; production multi-process deploys want a Redis-
/// or Postgres-backed implementation.
pub struct InMemoryMandateReplayStore {
    ttl_seconds: u64,
    entries: Mutex<HashMap<MandateId, SystemTime>>,
}

impl InMemoryMandateReplayStore {
    pub fn new(ttl_seconds: u64) -> Self {
        Self { ttl_seconds, entries: Mutex::new(HashMap::new()) }
    }
}

impl Default for InMemoryMandateReplayStore {
    /// 24-hour TTL. AP2 cart mandates are short-lived; a day is wider
    /// than any realistic settlement window.
    fn default() -> Self {
        Self::new(24 * 60 * 60)
    }
}

impl MandateReplayStore for InMemoryMandateReplayStore {
    fn consume(&self, id: &MandateId, now: SystemTime) -> Result<(), MandateReplayError> {
        let mut entries = self.entries.lock().expect("replay store mutex");
        let cutoff = now
            .checked_sub(std::time::Duration::from_secs(self.ttl_seconds))
            .unwrap_or(UNIX_EPOCH);
        entries.retain(|_, &mut inserted| inserted >= cutoff);

        if entries.contains_key(id) {
            return Err(MandateReplayError::AlreadyConsumed(id.clone()));
        }
        entries.insert(id.clone(), now);
        Ok(())
    }
}

// =============================================================================
//   MandateVerifier
// =============================================================================

/// Walks the AP2 chain and gatekeeps settlement.
pub struct MandateVerifier<'a> {
    replay_store: &'a dyn MandateReplayStore,
}

impl<'a> MandateVerifier<'a> {
    pub fn new(replay_store: &'a dyn MandateReplayStore) -> Self {
        Self { replay_store }
    }

    /// Verify the full chain. On success, the caller can hand the
    /// payment payload off to its downstream x402 / MPP verifier.
    ///
    /// **Side effect**: marks `payment.id` consumed in the replay store
    /// *before* delegating to the downstream protocol. If the
    /// downstream verifier later rejects, that's a no-op as far as
    /// replay state is concerned — the mandate is "burned" on first
    /// presentation regardless of on-chain outcome, matching the
    /// x402 SettlementCache + MPP replay-store convention.
    pub fn verify_chain(
        &self,
        intent: &IntentMandate,
        cart: &CartMandate,
        payment: &PaymentMandate,
        now_unix: i64,
    ) -> Result<(), Ap2Error> {
        // 1. Signatures.
        if let Some(sig) = &intent.user_signature {
            sig.verify(&intent.signed_view(), "intent")?;
        } else {
            return Err(Ap2Error::SignatureInvalid { what: "intent (no signature attached)" });
        }
        if let Some(sig) = &cart.merchant_signature {
            sig.verify(&cart.signed_view(), "cart")?;
        } else {
            return Err(Ap2Error::SignatureInvalid { what: "cart (no signature attached)" });
        }
        if let Some(sig) = &payment.user_signature {
            sig.verify(&payment.signed_view(), "payment")?;
        } else {
            return Err(Ap2Error::SignatureInvalid { what: "payment (no signature attached)" });
        }

        // 2. Lifetime windows.
        if now_unix < intent.valid_after || now_unix > intent.valid_before {
            return Err(Ap2Error::OutsideValidityWindow { what: "intent" });
        }
        if now_unix > cart.valid_until {
            return Err(Ap2Error::OutsideValidityWindow { what: "cart" });
        }

        // 3. Chain reference integrity.
        if cart.intent_mandate_id != intent.id {
            return Err(Ap2Error::IntentMismatch {
                cart_ref: cart.intent_mandate_id.clone(),
                actual: intent.id.clone(),
            });
        }
        if payment.cart_mandate_id != cart.id {
            return Err(Ap2Error::CartMismatch {
                payment_ref: payment.cart_mandate_id.clone(),
                actual: cart.id.clone(),
            });
        }

        // 4. Cart-snapshot binding. Hash the cart's signed view and
        //    compare against the hash the user signed off on.
        let expected = bs58::encode(cart.snapshot_hash()).into_string();
        if payment.cart_mandate_hash != expected {
            return Err(Ap2Error::CartHashMismatch);
        }

        // 5. Constraint checks.
        if cart.cart.total_minor > intent.constraints.max_amount_minor {
            return Err(Ap2Error::AmountExceedsIntent {
                cart_total: cart.cart.total_minor,
                intent_max: intent.constraints.max_amount_minor,
            });
        }
        if let Some(allow) = &intent.constraints.allowed_merchants {
            if !allow.contains(&cart.merchant_pubkey) {
                return Err(Ap2Error::MerchantNotAuthorized { merchant: cart.merchant_pubkey.clone() });
            }
        }
        let cart_method = cart.payment_method.method_uri();
        if !intent.constraints.allowed_methods.iter().any(|m| m == cart_method) {
            return Err(Ap2Error::PaymentMethodNotAuthorized { method: cart_method.into() });
        }

        // 6. Rail match between cart and payment payload.
        let payload_method = payment.payment_payload.method_uri();
        if cart_method != payload_method {
            return Err(Ap2Error::PaymentMethodKindMismatch {
                cart_method: cart_method.into(),
                payload_method: payload_method.into(),
            });
        }

        // 7. Consume — write-once. Replay-protected from this point on.
        self.replay_store
            .consume(&payment.id, SystemTime::now())
            .map_err(|MandateReplayError::AlreadyConsumed(id)| Ap2Error::Replayed(id))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mandate::{Cart, CartItem, sample_x402_requirements};
    use crate::method::{PaymentMethod, PaymentPayload, X402_METHOD_URI};
    use crate::signature::Ed25519Signer;

    fn build_chain() -> (Ed25519Signer, Ed25519Signer, IntentMandate, CartMandate, PaymentMandate) {
        let user = Ed25519Signer::from_seed(&[1; 32]);
        let merchant = Ed25519Signer::from_seed(&[2; 32]);

        let mut intent = IntentMandate {
            id: "intent-x".into(),
            user_pubkey: user.pubkey(),
            agent_pubkey: "agent".into(),
            constraints: crate::mandate::IntentConstraints {
                max_amount_minor: 1_000_000,
                currency: "USDC".into(),
                allowed_merchants: None,
                allowed_methods: vec![X402_METHOD_URI.into()],
            },
            valid_after: 0,
            valid_before: i64::MAX,
            user_signature: None,
        };
        intent.user_signature = Some(user.sign(&intent.signed_view()).unwrap());

        let mut cart = CartMandate {
            id: "cart-x".into(),
            intent_mandate_id: "intent-x".into(),
            merchant_pubkey: merchant.pubkey(),
            cart: Cart {
                items: vec![CartItem {
                    sku: "S".into(),
                    description: "".into(),
                    quantity: 1,
                    unit_price_minor: 100_000,
                }],
                total_minor: 100_000,
                currency: "USDC".into(),
                metadata: None,
            },
            payment_method: PaymentMethod::X402({
                let mut r = sample_x402_requirements();
                r.recipient = merchant.pubkey();
                r
            }),
            valid_until: i64::MAX,
            merchant_signature: None,
        };
        cart.merchant_signature = Some(merchant.sign(&cart.signed_view()).unwrap());

        let mut payment = PaymentMandate {
            id: "payment-x".into(),
            cart_mandate_id: "cart-x".into(),
            cart_mandate_hash: bs58::encode(cart.snapshot_hash()).into_string(),
            payment_payload: PaymentPayload::X402(serde_json::json!({"placeholder": true})),
            user_signature: None,
        };
        payment.user_signature = Some(user.sign(&payment.signed_view()).unwrap());

        (user, merchant, intent, cart, payment)
    }

    #[test]
    fn happy_path_chain_verifies() {
        let store = InMemoryMandateReplayStore::default();
        let v = MandateVerifier::new(&store);
        let (_u, _m, intent, cart, payment) = build_chain();

        v.verify_chain(&intent, &cart, &payment, 100).expect("clean chain");
    }

    #[test]
    fn replayed_payment_is_refused() {
        let store = InMemoryMandateReplayStore::default();
        let v = MandateVerifier::new(&store);
        let (_u, _m, intent, cart, payment) = build_chain();

        v.verify_chain(&intent, &cart, &payment, 100).unwrap();
        let err = v.verify_chain(&intent, &cart, &payment, 100).unwrap_err();
        assert!(matches!(err, Ap2Error::Replayed(_)));
    }

    #[test]
    fn cart_total_above_intent_max_is_refused() {
        let store = InMemoryMandateReplayStore::default();
        let v = MandateVerifier::new(&store);
        let (user, merchant, mut intent, mut cart, _) = build_chain();

        intent.constraints.max_amount_minor = 50_000;
        cart.cart.total_minor = 100_000;
        // Re-sign after mutating
        intent.user_signature = None;
        intent.user_signature = Some(user.sign(&intent.signed_view()).unwrap());
        cart.merchant_signature = None;
        cart.merchant_signature = Some(merchant.sign(&cart.signed_view()).unwrap());

        let mut payment = PaymentMandate {
            id: "p2".into(),
            cart_mandate_id: cart.id.clone(),
            cart_mandate_hash: bs58::encode(cart.snapshot_hash()).into_string(),
            payment_payload: PaymentPayload::X402(serde_json::json!({})),
            user_signature: None,
        };
        payment.user_signature = Some(user.sign(&payment.signed_view()).unwrap());

        let err = v.verify_chain(&intent, &cart, &payment, 100).unwrap_err();
        assert!(matches!(err, Ap2Error::AmountExceedsIntent { .. }));
    }

    #[test]
    fn cart_snapshot_tampering_is_refused() {
        let store = InMemoryMandateReplayStore::default();
        let v = MandateVerifier::new(&store);
        let (_u, merchant, intent, mut cart, payment) = build_chain();

        // Mutate the cart total after the user signed the payment.
        cart.cart.total_minor += 1;
        cart.merchant_signature = Some(merchant.sign(&cart.signed_view()).unwrap());

        let err = v.verify_chain(&intent, &cart, &payment, 100).unwrap_err();
        assert!(matches!(err, Ap2Error::CartHashMismatch));
    }

    #[test]
    fn payload_method_mismatch_is_refused() {
        let store = InMemoryMandateReplayStore::default();
        let v = MandateVerifier::new(&store);
        let (user, _m, intent, cart, _) = build_chain();

        // Re-sign payment with an MPP payload but the cart says x402.
        let mut payment = PaymentMandate {
            id: "p3".into(),
            cart_mandate_id: cart.id.clone(),
            cart_mandate_hash: bs58::encode(cart.snapshot_hash()).into_string(),
            payment_payload: PaymentPayload::Mpp(serde_json::json!({})),
            user_signature: None,
        };
        payment.user_signature = Some(user.sign(&payment.signed_view()).unwrap());

        let err = v.verify_chain(&intent, &cart, &payment, 100).unwrap_err();
        assert!(matches!(err, Ap2Error::PaymentMethodKindMismatch { .. }));
    }

    #[test]
    fn merchant_not_in_allowlist_is_refused() {
        let store = InMemoryMandateReplayStore::default();
        let v = MandateVerifier::new(&store);
        let (user, merchant, mut intent, cart, payment) = build_chain();
        let _ = merchant;

        intent.constraints.allowed_merchants =
            Some(vec!["different-merchant".into()]);
        intent.user_signature = None;
        intent.user_signature = Some(user.sign(&intent.signed_view()).unwrap());

        let err = v.verify_chain(&intent, &cart, &payment, 100).unwrap_err();
        assert!(matches!(err, Ap2Error::MerchantNotAuthorized { .. }));
    }
}
