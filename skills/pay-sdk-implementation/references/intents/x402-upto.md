# `x402/upto`

**Status: implemented.** `upto` authorizes a ceiling and settles the measured
amount after the protected operation.

Spec: <https://x402.org>

## References

- Wire types and verification:
  `rust/crates/kit/src/x402/protocol/schemes/upto/`
- Paying client: `rust/crates/kit/src/x402/client/upto/`
- Server lifecycle: `rust/crates/kit/src/x402/server/upto.rs`
- TypeScript Pay Kit integration:
  `typescript/packages/pay-kit/src/adapters/x402-upto.ts`
- Cross-language vectors: the `x402-upto` entries in
  `harness/src/implementations.ts`

## Porting order

1. Port the challenge and payload types, including the channel-open context.
2. Port verification that binds the authorization to the route and proves the
   actual amount does not exceed the advertised ceiling.
3. Port channel open, post-handler metering, settlement, and close behavior.
4. Register protocol-specific client and server harness adapters.

## Guardrails

- Preserve integer base-unit arithmetic; do not compare floating-point token
  amounts.
- Source current blockhash and slot behavior from the reference implementation.
  Do not reuse expired hints or invent fallback values.
- Settle and seal through the reference lifecycle even when the protected
  handler fails; match the current target-language adapter's error semantics.
- Pin channel roles, mint, network, recipient, fee payer, and ceiling before
  serving the resource.
- Do not claim support from unit tests alone; run the focused `x402-upto`
  harness matrix.
