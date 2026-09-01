# `mpp/subscription`

**Status: implemented in Rust and TypeScript.** Use the public sources instead
of treating subscription semantics as an unpublished draft.

Spec and protocol context: <https://paymentauth.org>

## References

- Rust wire types: `rust/crates/kit/src/mpp/protocol/intents/subscription.rs`
- Rust client: `rust/crates/kit/src/mpp/client/subscription.rs`
- Rust server: `rust/crates/kit/src/mpp/server/subscription.rs`
- Generated Solana program client:
  `rust/crates/kit/src/mpp/program/subscriptions.rs`
- TypeScript shared implementation and tests:
  `typescript/packages/mpp/src/shared/subscription.ts` and
  `typescript/packages/mpp/src/__tests__/subscription*.test.ts`

## Porting order

1. Read both public implementations and the subscriptions IDL under `idl/`.
2. Port the protocol types and canonical header/payload encoding.
3. Generate the target-language program client from the checked-in IDL; do not
   hand-write account or instruction layouts.
4. Port client lifecycle operations and server verification.
5. Add replay-safe persistence, expiry, cancellation, and retry tests.
6. Register any available harness vectors and keep unsupported README cells at
   `—` until their proof exists.

## Guardrails

- Treat subscription state, caps, renewal windows, and cancellation rules as
  wire-level behavior. Copy them from current code and tests, not intuition.
- Pin recipient, currency, network, subscription identity, and authorized cap
  before accepting a credential.
- Make create, renew, charge, cancel, and retry paths idempotent where the
  reference is idempotent.
- Do not infer support in another language from the Rust or TypeScript matrix.
