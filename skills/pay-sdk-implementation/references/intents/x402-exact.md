# `x402/exact`

**Status: implemented.** Use the public in-repository sources; do not ask for a
private x402 checkout.

Spec: <https://x402.org>

## References

- Wire types and structural verification:
  `rust/crates/kit/src/x402/protocol/schemes/exact/`
- Paying client: `rust/crates/kit/src/x402/client/exact/`
- Server and settlement: `rust/crates/kit/src/x402/server/exact.rs`
- Pay Kit adapter: `typescript/packages/pay-kit/src/adapters/x402.ts`
- Cross-language vectors: the `x402-exact` entries in
  `harness/src/implementations.ts` and `harness/test/x402-exact.e2e.test.ts`

Initialize the `typescript/external/x402` submodule when the TypeScript SVM
scheme internals are needed. The checked-in Pay Kit adapter and tests show how
that package is integrated.

## Porting order

1. Port the exact wire types and canonical serialization.
2. Port structural verification before settlement or HTTP middleware.
3. Add the client payment builder and server processor.
4. Add replay protection and bind the credential to the route's amount,
   recipient, currency, network, and token program.
5. Register client and server adapters for the `x402-exact` harness intent and
   run them against an existing Rust or TypeScript peer.

## Guardrails

- Support only the x402 versions and header names demonstrated by the current
  reference and harness vectors.
- Treat the payment payload and transaction as untrusted. Verify every required
  account, instruction, amount, mint, signer, and destination before broadcast.
- Consume a payment proof atomically so concurrent replays cannot both settle.
- Do not mark the target language's README cell complete until its focused
  cross-language harness pair passes.

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
