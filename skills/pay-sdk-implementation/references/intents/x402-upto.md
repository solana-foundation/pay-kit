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
