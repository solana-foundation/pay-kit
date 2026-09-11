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
