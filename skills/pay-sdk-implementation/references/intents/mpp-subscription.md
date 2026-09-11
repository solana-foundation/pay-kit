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

## Transaction versions

Solana message versions `0` and `1` (SIMD-0385) are accepted; legacy
messages are rejected before any instruction is inspected. The server
advertises the versions it accepts as `transactionVersions` (an array of
`0` and/or `1`) — in MPP `methodDetails`, in x402 `extra` — and omits the
field when it accepts version 0 only. Clients build the highest advertised
version, `0` when the field is absent, and never use address lookup
tables. Version 1 carries its compute budget in the message header:
`computeUnitLimit` and `loadedAccountsDataSizeLimit` MUST be set, the
priority fee is a total in lamports, ComputeBudget instructions are
rejected, and the size limit is 4096 bytes (1232 for version 0). Verifiers
hold the header config to the same caps they apply to ComputeBudget
instructions on version 0. Wire bytes are the canonical (wincode) encoding,
base64 standard alphabet with padding; bincode cannot encode version 1. The
Rust reference is `rust/crates/kit/src/core/tx/`.
