# solana-ap2

Agent Payments Protocol (AP2) helpers for Solana — Intent / Cart /
Payment Mandates over x402 + MPP.

`AP2` is Google's open protocol for attaching a cryptographically-signed,
user-authorized audit trail to a payment. It doesn't move money on its
own; it sits on top of an existing payment rail (cards, stablecoins,
…) and proves *who authorized what, within what limits*.

This crate ships the **Solana stablecoin profile** of AP2:

- Three Mandate types (Intent / Cart / Payment) with Ed25519 over
  RFC 8785 canonical JSON.
- A pluggable `MandateReplayStore` for write-once mandate IDs.
- A `MandateVerifier` that walks the chain.
- A `PaymentMethod` enum that bridges to **either** `solana-x402` or
  `solana-mpp` — same mandate envelope, two rails.

It's deliberately **rail-thin**: chain validation lives here; settlement
stays in the existing `x402::Server::Exact` and `mpp::Server::Charge`
crates. You call `MandateVerifier::verify_chain` first, then hand the
proof off to the rail's existing verifier.

## At a glance

```rust
use solana_ap2::{
    Ed25519Signer, IntentMandate, IntentConstraints,
    CartMandate, Cart, CartItem, PaymentMandate,
    PaymentMethod, PaymentPayload, X402_METHOD_URI,
    InMemoryMandateReplayStore, MandateVerifier,
};

// 1. User issues an Intent Mandate (delegates spending authority).
let user = Ed25519Signer::from_seed(&[1; 32]);
let mut intent = IntentMandate { /* fields */ };
intent.user_signature = Some(user.sign(&intent.signed_view())?);

// 2. Merchant builds a Cart Mandate that references the intent and
//    embeds an x402 (or MPP) payment-method block.
let merchant = Ed25519Signer::from_seed(&[2; 32]);
let mut cart = CartMandate { /* fields */ };
cart.merchant_signature = Some(merchant.sign(&cart.signed_view())?);

// 3. User signs a Payment Mandate that hashes the cart and carries
//    the rail-level signed payload.
let mut payment = PaymentMandate {
    cart_mandate_hash: bs58::encode(cart.snapshot_hash()).into_string(),
    /* ... */
};
payment.user_signature = Some(user.sign(&payment.signed_view())?);

// 4. Server validates the chain in one call.
let store = InMemoryMandateReplayStore::default();
MandateVerifier::new(&store)
    .verify_chain(&intent, &cart, &payment, now_unix())?;
//  Chain OK — hand `payment.payment_payload` to x402/mpp to settle.
```

See `docs/SPEC.md` for the wire format and signature scheme.

## Status

- **Phase 1 (this release)**: mandate types, Ed25519 signing,
  canonical JSON, replay store, x402+MPP `PaymentMethod` enum, chain
  verifier. ✅ Shipping.
- Phase 2: A2A envelope (parsing `x402.payment.*` metadata on A2A
  Tasks/Messages). Stub.
- Phase 3: `Ap2Server` orchestrator that wraps `x402::Server::Exact` +
  `mpp::Server::Charge`. Stub.
- Phase 4: Pay-kit umbrella integration (`c.ap2 do |a|…end` config
  block, per-gate `require_ap2: true`). Stub.

## Compatibility with upstream a2a-x402

| Feature | Upstream `a2a-x402` v0.2 | This crate |
|---------|--------------------------|------------|
| `PaymentMethod` URI `https://www.x402.org/` | ✅ | ✅ |
| `PaymentMethod` URI `https://paymentauth.org/mpp` | ❌ (pay-kit extension) | ✅ |
| Signature scheme | Unspecified | Ed25519 / RFC 8785 (documented) |
| A2A `Task` / `Message` envelope | Specified | Phase 2 |
| MCP transport variant | In development upstream | Out of scope until upstream stabilizes |

The MPP variant and the Ed25519 signature scheme need a spec PR to
upstream a2a-x402 before declaring wire-portable interop with
non-pay-kit AP2 clients. See `docs/SPEC.md` § "Open spec items".

## Layout

```text
src/
├── lib.rs           # umbrella + re-exports
├── error.rs         # Ap2Error
├── signature.rs     # Ed25519Signer, SignedBytes, canonicalize
├── method.rs        # PaymentMethod + PaymentPayload (x402 | MPP)
├── mandate.rs       # IntentMandate, CartMandate, PaymentMandate, Cart
└── verify.rs        # MandateVerifier + MandateReplayStore
docs/
└── SPEC.md          # Wire format, signature scheme, open spec items
```

## License

MIT
