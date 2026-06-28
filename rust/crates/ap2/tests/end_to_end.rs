//! End-to-end mandate chain tests, exercising both the x402 and MPP
//! rails through a single mandate verifier. Mirrors what a server
//! would do at request time: build → sign → verify.

use solana_ap2::{
    Ap2Error, Cart, CartItem, CartMandate, Ed25519Signer, InMemoryMandateReplayStore,
    IntentConstraints, IntentMandate, MPP_METHOD_URI, MandateVerifier, PaymentMandate,
    PaymentMethod, PaymentPayload, X402_METHOD_URI,
};
use solana_mpp::ChargeRequest;
use solana_x402::exact::PaymentRequirements;

fn x402_payment_method(recipient: &str) -> PaymentMethod {
    PaymentMethod::X402(PaymentRequirements {
        network: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp".into(),
        cluster: Some("mainnet-beta".into()),
        recipient: recipient.into(),
        amount: "100000".into(),
        currency: "USDC".into(),
        decimals: Some(6),
        token_program: None,
        resource: "https://example.com/report".into(),
        description: None,
        max_age: Some(60),
        recent_blockhash: None,
        fee_payer: None,
        fee_payer_key: None,
        extra: None,
        accepted: None,
        resource_info: None,
    })
}

fn mpp_payment_method(recipient: &str) -> PaymentMethod {
    let mut req = ChargeRequest::default();
    req.amount = "100000".into();
    req.currency = "USDC".into();
    req.recipient = Some(recipient.into());
    PaymentMethod::Mpp(req)
}

fn build_intent_and_cart(
    user: &Ed25519Signer,
    merchant: &Ed25519Signer,
    method: PaymentMethod,
    method_uri: &str,
) -> (IntentMandate, CartMandate) {
    let mut intent = IntentMandate {
        id: "intent-e2e".into(),
        user_pubkey: user.pubkey(),
        agent_pubkey: "agent-1".into(),
        constraints: IntentConstraints {
            max_amount_minor: 5_000_000,
            currency: "USDC".into(),
            allowed_merchants: Some(vec![merchant.pubkey()]),
            allowed_methods: vec![method_uri.into()],
        },
        valid_after: 0,
        valid_before: i64::MAX,
        user_signature: None,
    };
    intent.user_signature = Some(user.sign(&intent.signed_view()).unwrap());

    let mut cart = CartMandate {
        id: "cart-e2e".into(),
        intent_mandate_id: intent.id.clone(),
        merchant_pubkey: merchant.pubkey(),
        cart: Cart {
            items: vec![CartItem {
                sku: "REPORT-1".into(),
                description: "Premium report".into(),
                quantity: 1,
                unit_price_minor: 100_000,
            }],
            total_minor: 100_000,
            currency: "USDC".into(),
            metadata: None,
        },
        payment_method: method,
        valid_until: i64::MAX,
        merchant_signature: None,
    };
    cart.merchant_signature = Some(merchant.sign(&cart.signed_view()).unwrap());

    (intent, cart)
}

fn sign_payment(
    user: &Ed25519Signer,
    cart: &CartMandate,
    payload: PaymentPayload,
) -> PaymentMandate {
    let mut payment = PaymentMandate {
        id: format!("payment-{}", rand_id()),
        cart_mandate_id: cart.id.clone(),
        cart_mandate_hash: bs58::encode(cart.snapshot_hash()).into_string(),
        payment_payload: payload,
        user_signature: None,
    };
    payment.user_signature = Some(user.sign(&payment.signed_view()).unwrap());
    payment
}

fn rand_id() -> String {
    use rand::Rng;
    let n: u128 = rand::thread_rng().gen();
    format!("{n:032x}")
}

#[test]
fn x402_rail_chain_verifies() {
    let user = Ed25519Signer::generate();
    let merchant = Ed25519Signer::generate();
    let (intent, cart) =
        build_intent_and_cart(&user, &merchant, x402_payment_method(&merchant.pubkey()), X402_METHOD_URI);
    let payment = sign_payment(
        &user,
        &cart,
        PaymentPayload::X402(serde_json::json!({
            "x402Version": 2,
            "network": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
            "scheme": "exact",
            "payload": "<signed tx placeholder>"
        })),
    );

    let store = InMemoryMandateReplayStore::default();
    MandateVerifier::new(&store)
        .verify_chain(&intent, &cart, &payment, 100)
        .expect("x402 chain must verify");
}

#[test]
fn mpp_rail_chain_verifies() {
    let user = Ed25519Signer::generate();
    let merchant = Ed25519Signer::generate();
    let (intent, cart) =
        build_intent_and_cart(&user, &merchant, mpp_payment_method(&merchant.pubkey()), MPP_METHOD_URI);
    let payment = sign_payment(
        &user,
        &cart,
        PaymentPayload::Mpp(serde_json::json!({
            "signature": "<base58 sig>",
            "transaction": "<base64 tx>"
        })),
    );

    let store = InMemoryMandateReplayStore::default();
    MandateVerifier::new(&store)
        .verify_chain(&intent, &cart, &payment, 100)
        .expect("MPP chain must verify");
}

#[test]
fn payload_attached_for_wrong_rail_is_refused() {
    // Cart says x402; payload claims MPP. Should be caught.
    let user = Ed25519Signer::generate();
    let merchant = Ed25519Signer::generate();
    let (intent, cart) =
        build_intent_and_cart(&user, &merchant, x402_payment_method(&merchant.pubkey()), X402_METHOD_URI);
    let payment = sign_payment(&user, &cart, PaymentPayload::Mpp(serde_json::json!({})));

    let store = InMemoryMandateReplayStore::default();
    let err = MandateVerifier::new(&store)
        .verify_chain(&intent, &cart, &payment, 100)
        .unwrap_err();
    assert!(matches!(err, Ap2Error::PaymentMethodKindMismatch { .. }));
}

#[test]
fn intent_disallowing_mpp_refuses_mpp_cart() {
    // Intent allows only x402; cart proposes MPP.
    let user = Ed25519Signer::generate();
    let merchant = Ed25519Signer::generate();
    let mut intent = IntentMandate {
        id: "intent-x-only".into(),
        user_pubkey: user.pubkey(),
        agent_pubkey: "a".into(),
        constraints: IntentConstraints {
            max_amount_minor: 5_000_000,
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
        id: "cart-mpp".into(),
        intent_mandate_id: intent.id.clone(),
        merchant_pubkey: merchant.pubkey(),
        cart: Cart {
            items: vec![],
            total_minor: 100_000,
            currency: "USDC".into(),
            metadata: None,
        },
        payment_method: mpp_payment_method(&merchant.pubkey()),
        valid_until: i64::MAX,
        merchant_signature: None,
    };
    cart.merchant_signature = Some(merchant.sign(&cart.signed_view()).unwrap());

    let payment = sign_payment(&user, &cart, PaymentPayload::Mpp(serde_json::json!({})));

    let store = InMemoryMandateReplayStore::default();
    let err = MandateVerifier::new(&store)
        .verify_chain(&intent, &cart, &payment, 100)
        .unwrap_err();
    assert!(matches!(err, Ap2Error::PaymentMethodNotAuthorized { .. }));
}
