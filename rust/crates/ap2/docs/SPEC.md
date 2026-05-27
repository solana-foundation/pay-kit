# AP2 wire format — Solana profile

This document specifies the on-wire shape this crate emits and accepts.
It's the source of truth for cross-language interop and for any future
spec PR upstream.

Tracks `google-agentic-commerce/a2a-x402` **v0.2** for the `PaymentMethod`
URI and embedded-flow envelope; defines pay-kit-specific items in their
own section.

## Mandate JSON shapes

### IntentMandate

```json
{
  "id": "ap2-intent-3f29…",
  "user_pubkey": "ALtYSsZuYyKrNSe6GnVCzxj1T2RPMTPzXMe51xhbmXEq",
  "agent_pubkey": "DUbW52JykLtwVhzEwDURmjgzepth2CcwCkTsra1cqxA7",
  "constraints": {
    "max_amount_minor": 10000000,
    "currency": "USDC",
    "allowed_merchants": ["AyNAa2VPe2t5pgg8M61iE6kqMudkV98zsT4rkAZuU6tj"],
    "allowed_methods": [
      "https://www.x402.org/",
      "https://paymentauth.org/mpp"
    ]
  },
  "valid_after": 1735689600,
  "valid_before": 1735776000,
  "user_signature": {
    "signature": "<base58 Ed25519 signature>",
    "signer_pubkey": "ALtYSsZuYyKrNSe6GnVCzxj1T2RPMTPzXMe51xhbmXEq"
  }
}
```

Signed bytes: RFC 8785 canonical JSON of the object with
`user_signature` removed.

### CartMandate

```json
{
  "id": "ap2-cart-be12…",
  "intent_mandate_id": "ap2-intent-3f29…",
  "merchant_pubkey": "AyNAa2VPe2t5pgg8M61iE6kqMudkV98zsT4rkAZuU6tj",
  "cart": {
    "items": [
      { "sku": "REPORT-1", "description": "Premium report", "quantity": 1, "unit_price_minor": 100000 }
    ],
    "total_minor": 100000,
    "currency": "USDC"
  },
  "payment_method": {
    "supported_methods": "https://www.x402.org/",
    "data": {
      "network": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
      "cluster": "mainnet-beta",
      "recipient": "AyNAa2VPe2t5pgg8M61iE6kqMudkV98zsT4rkAZuU6tj",
      "currency": "USDC",
      "amount": "100000",
      "resource": "https://example.com/report"
    }
  },
  "valid_until": 1735690200,
  "merchant_signature": { "signature": "…", "signer_pubkey": "Ay…" }
}
```

For MPP, swap the `payment_method` body for:

```json
"payment_method": {
  "supported_methods": "https://paymentauth.org/mpp",
  "data": {
    "amount": "100000",
    "currency": "USDC",
    "recipient": "Ay…",
    "methodDetails": { "network": "mainnet", "decimals": 6 }
  }
}
```

### PaymentMandate

```json
{
  "id": "ap2-payment-cd45…",
  "cart_mandate_id": "ap2-cart-be12…",
  "cart_mandate_hash": "8ChyXgYxV…",
  "payment_payload": {
    "supported_methods": "https://www.x402.org/",
    "data": {
      "x402Version": 2,
      "network": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
      "scheme": "exact",
      "payload": "<base64 signed Solana tx>"
    }
  },
  "user_signature": { "signature": "…", "signer_pubkey": "ALt…" }
}
```

`cart_mandate_hash` is the **base58-encoded SHA-256** of the canonical
JSON of the cart's signed view (i.e., cart serialized with
`merchant_signature` removed). This binds the payment to a specific
cart snapshot so a merchant cannot swap the cart between offer and
settlement.

## Signature scheme

- Algorithm: **Ed25519** (RFC 8032).
- Encoding of signature + verifying key: **base58** (Solana convention).
- Input to the signer: **RFC 8785 canonical JSON** of the mandate's
  `signed_view()` — the mandate minus its own signature field.

This matches what `solana-mpp` uses for its credential signatures.
Sharing the canonicalizer means a Solana wallet key that signs MPP
credentials also signs AP2 mandates, against the same pubkey, with no
re-tooling.

## Chain validation (what `MandateVerifier::verify_chain` checks)

For a tuple `(intent, cart, payment)` and a `now_unix` timestamp:

1. **Signatures**: each mandate's signature verifies against
   `signed_view()` and `signer_pubkey`.
2. **Validity windows**:
   - `intent.valid_after ≤ now ≤ intent.valid_before`
   - `now ≤ cart.valid_until`
3. **Chain references**:
   - `cart.intent_mandate_id == intent.id`
   - `payment.cart_mandate_id == cart.id`
4. **Snapshot binding**: `payment.cart_mandate_hash == base58(sha256(canonical(cart.signed_view)))`.
5. **Constraints**:
   - `cart.cart.total_minor ≤ intent.constraints.max_amount_minor`
   - if `intent.constraints.allowed_merchants` is set,
     `cart.merchant_pubkey ∈ allowed_merchants`
   - `cart.payment_method.supported_methods ∈ intent.constraints.allowed_methods`
6. **Rail consistency**: `payment.payment_payload.supported_methods == cart.payment_method.supported_methods`.
7. **Replay**: `replay_store.consume(payment.id)` — write-once.

What the verifier **does not** check:

- The rail-level signature inside `payment.payment_payload`. That's
  the downstream verifier's job (`x402::Server::Exact::settle_*` or
  `mpp::Server::Charge::verify_*`).
- On-chain settlement. Same.
- That `intent.user_pubkey == payment.user_signature.signer_pubkey` —
  AP2 v0.2 doesn't require it. A user with two keys (cold + hot) could
  delegate cold → hot for signing payments. The merchant decides
  whether to enforce sameness; we don't bake it in.

## Open spec items (pay-kit extensions)

Two items need an upstream spec PR before we can claim wire-portable
interop with non-pay-kit AP2 clients:

### 1. MPP `supported_methods` URI

We chose `https://paymentauth.org/mpp`. Upstream a2a-x402 v0.2 only
specifies `https://www.x402.org/`. Spec PR should:

- Reserve the URI in the a2a-x402 `payment_request.method_data[]`
  registry.
- Document the `ChargeRequest` JSON shape as the `data` body.

### 2. Signature scheme + canonicalizer

AP2's `signature` field is unstructured today. Real interop needs:

- A `signature_scheme` field on every mandate carrying the algorithm
  identifier (`"ed25519-jcs"`, `"ecdsa-secp256k1-eip712"`, …).
- A registry of canonicalizers per scheme. We use RFC 8785 JCS; EVM
  AP2 uses EIP-712 typed-data hashing.

Until that lands upstream, Solana mandates from this crate won't
verify in EVM-only AP2 implementations even when the chain validation
would pass.

## Versioning

The crate-level constant `AP2_WIRE_VERSION` pins the upstream version
this code targets (currently `0.2`). When upstream churns we'll add
versioned modules (`v0_2`, `v0_3`, …) and gate them behind features so
consumers don't break.
