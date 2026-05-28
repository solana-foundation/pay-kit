# Compute-Budget Caps

Tracks issue [#109](https://github.com/solana-foundation/mpp-sdk/issues/109).

## Canonical values

Every server SDK must enforce the same upper bound on the
`ComputeBudget111111111111111111111111111111` instructions
`SetComputeUnitLimit` (discriminator `0x02`) and `SetComputeUnitPrice`
(discriminator `0x03`) that appear in a charge transaction:

| Constant                              | Value      |
| ------------------------------------- | ---------- |
| `MAX_COMPUTE_UNIT_LIMIT`              | `200000`   |
| `MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS` | `5000000` |

Worst-case priority-fee burn per settled charge is bounded by
`MAX_COMPUTE_UNIT_LIMIT * MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS /
1_000_000 = 1_000_000` lamports (`0.001` SOL).

## Rationale

The server signs and broadcasts the client's transaction as fee payer
(charge-pull). Without a cap, an attacker can attach
`SetComputeUnitPrice` instructions whose `micro_lamports` is large enough
to drain the server wallet on every accepted charge, since the fee payer
covers `cu_limit * cu_price / 1_000_000` lamports of priority fee on top
of the base signature fee. The cap pins the maximum drain per accepted
transaction so the server can size its fee-payer float against a known
ceiling.

The exact pair is conservative for the current charge instruction mix
(SPL transfer or transferChecked plus optional ATA create plus optional
memo). Raising the cap requires a security review across every SDK in
this monorepo.

## Per-SDK enforcement

| Language    | File                                                       | Constant                                  |
| ----------- | ---------------------------------------------------------- | ----------------------------------------- |
| Rust        | `rust/crates/mpp/src/server/charge.rs:42`                  | `MAX_COMPUTE_UNIT_LIMIT`                  |
| Rust        | `rust/crates/mpp/src/server/charge.rs:43`                  | `MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS`    |
| TypeScript  | `typescript/packages/mpp/src/server/Charge.ts:233`         | `MAX_COMPUTE_UNIT_LIMIT`                  |
| TypeScript  | `typescript/packages/mpp/src/server/Charge.ts:234`         | `MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS`    |
| PHP         | `php/src/Server/SolanaChargeTransactionVerifier.php:42`    | `MAX_COMPUTE_UNIT_LIMIT`                  |
| PHP         | `php/src/Server/SolanaChargeTransactionVerifier.php:43`    | `MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS`    |
| Ruby        | `ruby/lib/mpp/methods/solana/verifier.rb:8`                | `MAX_COMPUTE_UNIT_LIMIT`                  |
| Ruby        | `ruby/lib/mpp/methods/solana/verifier.rb:9`                | `MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS`    |
| Lua         | `lua/mpp/server/solana_verify.lua:19`                      | `MAX_COMPUTE_UNIT_LIMIT`                  |
| Lua         | `lua/mpp/server/solana_verify.lua:20`                      | `MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS`    |
| Lua (#103)  | `lua/mpp/methods/solana/instructions.lua:31`               | `MAX_COMPUTE_UNIT_LIMIT` (pending PR #103 merge)              |
| Lua (#103)  | `lua/mpp/methods/solana/instructions.lua:32`               | `MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS` (pending PR #103 merge) |
| Go (#101)   | `go/protocols/mpp/server/server.go` (`maxComputeUnitLimit`)              | pending PR #101 merge                     |
| Python (#106) | `python/src/solana_mpp/server/mpp.py`                    | pending PR #106 merge                     |

`harness/test/compute-budget-caps.test.ts` parses each file above
and asserts byte-identical literals against the canonical pair. Go and
Python rows are marked `optional: true` until their PRs land, then
flip to required and surface drift the same way as the other SDKs.

## Adding a new SDK

1. Declare both constants verbatim in the server module that decodes
   `ComputeBudget` instructions during charge verification.
2. Reject the transaction with the canonical `payment_invalid` error
   code when either limit is exceeded; include the cap value in the
   reason string for parity with the existing SDKs.
3. Append a row to `SDKS` in
   `harness/test/compute-budget-caps.test.ts` and to the table
   above. Append a fixture row to
   `charge-compute-budget-over-cap` in
   `harness/src/intents/charge.ts` once the SDK is wired into the
   interop harness.
