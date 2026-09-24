# txv1 (SIMD-0385) support — migration plan and current blockers

Status: **not started (blocked on upstream ecosystem state)**. This document is the
handoff for whoever picks this back up — it captures the design plan and, more
importantly, the exact dependency conflicts that stopped a first attempt on
2026-09-03, so the next attempt doesn't have to re-derive them.

## What this is

Solana's transaction message format v1 ([SIMD-0385][simd-0385], "larger
transaction sizes") raises the transaction size cap from 1232 to 4096 bytes and
moves compute-unit limit, heap size, loaded-accounts-data-size limit, and
priority fee out of `ComputeBudget` instructions into message-level config
fields. It requires the `txv1aq4pp281K9um3tnPgkfX8UqtFT6wcVW3hNezGLL` feature
gate (Agave v4.2+); legacy and v0 transactions are unaffected.

[simd-0385]: https://solana.com/upgrades/larger-transaction-sizes

**Already shipped in the TypeScript SDK** (`pay/typescript/packages/solana-pay/core`):
`buildTransaction(feePayer, ix, { version: 1, config })`, with
`validateTransfer`/`fetchTransaction` handling v1 transparently (see that
package's README, "Transaction versions" section, and
`transactionVersions.test.ts`). **Completely absent from pay-kit** (Rust, and
every other language binding). The ask is Rust parity — every payment flow
that builds a transaction (mpp charge, x402 upto, x402 batch-settlement, x402
exact, core channel open/settlement), not just one call site.

## Design (unblocked once the dependency chain below resolves)

1. **Dependency bump, isolated commit.** Bump `solana-message`/`solana-transaction`
   from `"3"` to `"4"` in `crates/kit/Cargo.toml` (both `[dependencies]` and
   `[dev-dependencies]`). Run the full test suite (414 tests as of this
   writing) before writing any v1 code, to isolate incidental 3→4 breakage
   from the feature work.
2. **Shared version/config module**, new `core/tx_version.rs`:
   ```rust
   pub enum TransactionVersion { Legacy, V0, V1 }

   /// Mirrors TypeScript's `V1TransactionConfig` (solana-pay/core) field-for-field.
   pub struct V1TransactionConfig {
       pub compute_unit_limit: Option<u32>,
       pub heap_size: Option<u32>,
       pub loaded_accounts_data_size_limit: Option<u32>,
       pub priority_fee_lamports: Option<u64>,
   }

   /// One place implementing version dispatch, instead of repeating it at
   /// each of the ~10 builder call sites below.
   pub fn compile_message(
       fee_payer: &Pubkey,
       instructions: &[Instruction],
       blockhash: Hash,
       version: TransactionVersion,
       v1_config: Option<&V1TransactionConfig>,
   ) -> Result<VersionedMessage, Error> {
       match version {
           TransactionVersion::Legacy => /* Message::new_with_blockhash, wrapped VersionedMessage::Legacy */,
           TransactionVersion::V0 => /* v0::Message::try_compile, wrapped VersionedMessage::V0 */,
           TransactionVersion::V1 => /* solana_message::v1::Message::try_compile_with_config, wrapped VersionedMessage::V1 */,
       }
   }
   ```
3. **Thread `tx_version`/`v1_config` through each builder's config struct**,
   defaulting to that site's *current* behavior (most default `Legacy`;
   `x402/client/exact/payment.rs` already builds v0, so it defaults `V0`) —
   zero behavior change unless a caller opts in, matching the TS default
   (`buildTransaction` defaults to v0, v1 is opt-in). Established pattern for
   adding an optional, backward-compatible knob to a config struct (three
   precedents already in the codebase): `UptoConfig`'s `Option<...>` fields
   with a doc comment stating the default (`x402/server/upto.rs:61`),
   `MethodDetails`'s `#[serde(skip_serializing_if = "Option::is_none")]` wire
   fields (`mpp/protocol/solana.rs:974`), and
   `BuildChargeTransactionOptions`'s `compute_budget: ComputeBudgetOptions`
   with an explicit "existing callers see no behavior change unless they opt
   in" comment (`mpp/client/charge.rs:86`).

   Call sites to wire (config struct → call site):
   - `UptoConfig` (`x402/server/upto.rs:61`) → `upto.rs:677`
   - `BuildChargeTransactionOptions` (`mpp/client/charge.rs:47`) → `charge.rs:365`
   - `SettlementConfig` (`core/settlement/worker.rs:77`) → `worker.rs:285`, and
     `settlement/packing.rs:30` (plain params, no struct there)
   - `BatchTerms`/`BatchChannelConfig` (`x402/client/batch_settlement/payment.rs:45`) → `payment.rs:515`
   - `OpenTxOptions` (`core/payment_channels.rs:674`) → `payment_channels.rs:773`
   - `mpp/client/confidential.rs:860` and `mpp/client/subscription.rs:304,361` —
     no dedicated struct at the call site; add plain parameters threaded from
     their callers.
   - `mpp/protocol/solana.rs`'s `MethodDetails` (line 974) is a **wire
     struct** the server sends the client so it knows *how* to build the tx —
     add `tx_version`/`v1_config` there using the same
     `#[serde(skip_serializing_if = "Option::is_none")]` convention as its
     siblings (`fee_payer`, `fee_payer_key`).
4. **No changes needed in decoders/verifiers** (`payment_channels.rs:278`,
   `mpp/server/charge.rs:1134`, `upto.rs:946`, `x402/server/exact.rs:754`,
   `x402/protocol/schemes/batch_settlement/tx_policy.rs:271`) — confirmed
   version-polymorphic already. `tx_policy.rs` (the batch-settlement deposit
   allowlist verifier — security-sensitive) inspects transactions only
   through `tx.message.static_account_keys()`, `.instructions()`,
   `.header()`, `.address_table_lookups()`, never a raw legacy/v0-specific
   layout, and already unconditionally rejects any transaction with a
   non-empty address-lookup-table — v1 has no ALT section at all, so v1
   transactions pass that check for free. `x402/protocol/schemes/exact/verify.rs`
   likewise goes through the same polymorphic accessors. Verify this still
   holds by running the full suite after wiring, not by pre-emptively
   changing code there.
5. **Tests**, mirroring TS's `transactionVersions.test.ts` parity: per
   protocol (mpp charge, x402 upto, x402 batch-settlement deposit, x402
   exact), build a v1 transaction and round-trip it through the *existing*
   decode/verify path; v1 config values round-trip through encode→decode; a
   v1 size-boundary test at 4096 bytes mirroring the existing legacy
   1232-byte boundary test in `mpp/protocol/solana.rs`.
6. **Docs**: a "Transaction versions" note in pay-kit's crate docs/README
   mirroring the TS README section.

## Why this is blocked today (checked 2026-09-03)

Two independent, currently-unresolvable SemVer conflicts in the Solana Rust
crate ecosystem. Neither is fixable by picking different compatible versions
on pay-kit's side — both need an upstream crate to publish a new release.

### 1. `litesvm` vs `solana-sdk >=4.1` (blocks `crates/integration-tests` only)

`solana-sdk 4.1` is the first `solana-sdk` release with a v1-capable
`solana-message` (`^4.5.0`) — see the wincode issue below for why it can't be
older. No released `litesvm`, and no unreleased commit on `litesvm`'s
`master` branch either (checked directly), has pins compatible with it:

| litesvm version | conflicting crate | litesvm needs | solana-sdk 4.1 needs |
|---|---|---|---|
| 0.13.0 | `solana-instruction` | `=3.2.0` | `^3.5.0` |
| 0.16.0 (newest release) | `solana-signature` | `~3.4.1` | `^3.5.0` |
| 0.16.0 / `master` | `solana-short-vec` | `~3.2.2` | `^3.3.0` |

This only matters for `crates/integration-tests` (on-chain litesvm-based
tests) and for `solana-keychain`'s own `sdk-v4` litesvm-backed test — dev-only
dependencies never propagate to downstream consumers, so it does **not**
block `kit`'s own production build once the wincode conflict (below) is
separately resolved.

Worked around for `solana-keychain` by dropping its `litesvm-v4` dev-dependency
entirely and replacing the unresolvable-crate error with a clear
`compile_error!` (see `solana-keychain` PR
[#305](https://github.com/solana-foundation/solana-keychain/pull/305),
`src/tests/litesvm_util.rs`). For pay-kit's own `crates/integration-tests`,
the equivalent workaround attempted was decoupling it out of the `rust/`
workspace (its own `[workspace]` root, dropped from
`rust/Cargo.toml`'s `members`) so its unresolvable lockfile doesn't block
`crates/kit`/`crates/harness-bins`. That workaround was reverted along with
everything else pending the wincode fix below — see "What was reverted."

### 2. `wincode` 0.5.x vs 0.6.0 (blocks `crates/kit` itself — the real blocker)

This is the one that actually stops the migration, because it's between two
of **pay-kit's own production dependencies**, not a dev-only crate:

- `solana-sdk 4.1` requires `solana-message ^4.5.0`.
- `solana-message` moved from `wincode ^0.5.0` to `wincode ^0.6.0` starting at
  version `4.5.0` — so any v1-capable `solana-message` unavoidably pulls
  `wincode ^0.6.0`.
- `solana-transaction-status-client-types` (pay-kit's existing RPC-response
  decoding, pulled in via `solana-rpc-client`/`solana-client` — used
  everywhere) requires `wincode ^0.5.5`, **even in its newest prerelease**
  (`4.4.0-alpha.3`, checked directly).
- `^0.5.5` and `^0.6.0` are mutually exclusive ranges for a pre-1.0 crate —
  Cargo cannot resolve one `wincode` version satisfying both. Downgrading
  `solana-address` (a candidate that also pulled `wincode 0.6.1` transitively)
  does not help: the conflict is between `solana-message`/`solana-sdk-v4` and
  `solana-transaction-status-client-types` directly, not `solana-address`.

**To resume:** check whether `solana-transaction-status-client-types` has
published a release depending on `wincode ^0.6`. That single check gates
everything else in this document.

## solana-keychain: already fixed, ready to consume once unblocked

[solana-keychain PR #305](https://github.com/solana-foundation/solana-keychain/pull/305)
(commit `c25f828`) bumped `solana-keychain`'s `sdk-v4` feature to
`solana-sdk = "4.1"` (from `=4.0.1`, whose `solana-message ^4.0.0` predates v1
support), with the companion fixes required to make that resolve:
- `solana-signature` range widened from `>=3.1, <3.5` to `>=3.4, <4` (the
  original upper bound was dodging a `DecodeError` bug specific to `3.3.0`;
  moving the floor past it instead of capping the ceiling below `3.5` is what
  lets both `sdk-v3` and `sdk-v4`'s ranges stay jointly satisfiable).
- `wincode` bumped `0.4.9` → `0.6`, matching the `SchemaRead` impl
  `solana-sdk 4.1`'s `VersionedTransaction` actually uses.
- `litesvm-v4` dev-dependency removed (see litesvm section above).

This PR is self-contained and useful independent of pay-kit — it can merge on
its own. Once the wincode conflict above resolves, pay-kit would re-pin
`crates/kit/Cargo.toml`'s `solana-keychain` dependency from
`{ version = "1.4", features = ["memory", "sdk-v3"] }` to whatever version
publishes this fix, with `features = ["memory", "sdk-v4"]`.

## What was reverted (2026-09-03)

All of the following were tried, hit the wincode conflict, and were reverted
to keep `main` clean rather than leave the workspace unbuildable:
- `crates/kit/Cargo.toml`: `solana-message`/`solana-transaction` bumped
  `"3"` → `"4"`; `solana-keychain` switched to a git-rev pin at
  `solana-keychain` PR #305's commit (`c25f828`) with `features = ["sdk-v4"]`.
- `rust/Cargo.toml`: `crates/integration-tests` removed from `[workspace]
  members` (with a comment explaining why).
- `crates/integration-tests/Cargo.toml`: given its own empty `[workspace]`
  table (standalone root); its `litesvm` pin bumped `0.13.1` → `0.16`.

None of this is present on `main` — this document is the only trace. Re-derive
these exact edits from this document rather than re-discovering the same
conflicts from scratch.
