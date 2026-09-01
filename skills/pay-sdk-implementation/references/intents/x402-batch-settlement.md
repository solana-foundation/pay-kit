# `x402/batch-settlement`

**Status: implemented in the public references.** This scheme serves requests
against cumulative off-chain vouchers and redeems them on chain in batches.

Spec: <https://x402.org>

## References

- Wire types and verification:
  `rust/crates/kit/src/x402/protocol/schemes/batch_settlement/`
- Paying client: `rust/crates/kit/src/x402/client/batch_settlement/`
- Server lifecycle and batch redemption:
  `rust/crates/kit/src/x402/server/batch_settlement.rs`
- Rust public usage: the batch-settlement section in `rust/README.md`
- Current harness coverage status: `harness/README.md` and
  `harness/test/intent-selection.test.ts`

The TypeScript x402 submodule also ships the SVM scheme, but Pay Kit's
TypeScript gate adapter may expose fewer lifecycle operations than the protocol
package. Inspect both the target language's adapter and its harness registration
before defining scope.

## Porting order

1. Port channel, voucher, and cumulative-amount wire types.
2. Port signature, sequence, role, ceiling, and monotonicity verification.
3. Add persistent state with atomic compare-and-set semantics.
4. Add client voucher generation and server-side off-chain acceptance.
5. Add idempotent batch redemption and distribution.
6. Add a scoped batch-settlement harness intent and scenarios before claiming
   cross-language compatibility; the current harness rejects that selector.

## Guardrails

- Key state by the complete channel identity and reject stale or decreasing
  cumulative vouchers.
- Make concurrent voucher acceptance and redemption race-safe.
- Treat a repeated settlement of the same cumulative state as an idempotent
  retry, not a second debit.
- Keep x402 replay keys namespaced away from MPP charge and session state.
- Leave the README cell incomplete when the target language lacks a client,
  server, persistent store, or harness proof required by its advertised scope.
