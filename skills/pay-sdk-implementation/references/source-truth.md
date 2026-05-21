# Source truth and current research

Read this before making protocol claims, changing compatibility matrices, or
starting a new language port.

## Authoritative references

Use these in order:

1. Local `solana-foundation/mpp-sdk/rust` code and tests.
2. HTTP Payment Authentication / MPP docs: <https://paymentauth.org>
3. Tempo MPP spec PRs: <https://github.com/tempoxyz/mpp-specs>
4. Existing TypeScript SDK and interop harness in this repo.
5. Solana SPL Token, Token-2022, ATA, transaction, and signer references.

For x402 rows in the matrix, use:

1. Local `solana-foundation/x402-sdk` Rust/TypeScript behavior when available.
2. x402 Foundation docs: <https://docs.x402.org/introduction>
3. x402 Foundation repo/specs: <https://github.com/x402-foundation/x402>

Do not let x402 rows define MPP semantics, and do not let MPP session semantics
define x402 `batch-settlement` without maintainer confirmation.

## Solana Foundation references discovered

- `solana-foundation/mpp-sdk`: Rust reference, TypeScript SDK, interop harness,
  and this implementation skill.
- `solana-foundation/x402-sdk`: current x402 Rust/TypeScript and interop
  reference for x402 rows.
- `solana-foundation/pay`: pay skill, MPP/x402 client references, session
  server references, and metering types.
- `solana-foundation/templates`, `kora`, `moneymq`, and `solana-com`: related
  x402 examples/types/docs. Useful for ecosystem context, not primary MPP
  protocol authority.

## Matrix rule

Every matrix cell defaults to not shipped unless that exact cell has evidence.

- `mpp/charge/pull` and `mpp/charge/push` are the baseline cells for new SDKs.
- `mpp/session` is optional and must not appear as shipped in charge-only SDKs.
- `mpp/subscription` remains unshipped until the spec and implementation land.
- x402 cells stay unshipped in MPP SDK ports unless the target language PR
  explicitly implements and verifies that x402 cell.

Prefer `—` plus a known-limits note over optimistic support claims.
