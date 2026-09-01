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
