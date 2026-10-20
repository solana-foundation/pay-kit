# Conformance findings

Open gaps referenced from `[[known_failing]]` entries by
`tracking = "FINDINGS.md#<anchor>"`. Each finding should become a GitHub issue;
when it does, replace the tracking value with the issue URL and delete the
section here.

Open findings from the phase-1 vectors (pinned spec text, RULINGS ids):

## x402-overpayment-rejected

**Case:** `vector/x402-exact-verify-overpayment-accept`
**SDKs:** typescript

`@solana/pay-kit` verifies x402 exact payments with the vendored upstream
reference facilitator, `@x402/svm` 2.26.0. Its static-layout path (Path 1)
requires the transfer amount to equal the requirement
(`typescript/packages/pay-kit/node_modules/@x402/svm/dist/esm/exact/facilitator/index.mjs:765`,
`amount !== BigInt(requirements.amount)`), which is what the spec text for
that path describes: scheme_exact_svm.md §3.1, “Fee payer isolation, compute
budget validity (compute unit price ≤ 5 lamports/CU on this path),
destination ATA derivation, and exact amount match are enforced as before.”

The normative outcome is looser: §1.4, “A matching transfer MAY exceed
`PaymentRequirements.amount` ... it MUST NOT be less.” §2.3 lets a sponsor be
stricter (“Sponsors MAY introduce stricter limits but MUST NOT relax the §2.1
MUSTs.”), so RULINGS S5 reads the reference implementation's exact-amount
check as a stricter sponsor policy, which pay-kit inherits by default.
Default verifiers accept overpayment; pay-kit does not re-implement the
facilitator to get there. The fix belongs upstream, in the x402 fork
(`typescript/external/x402`): accept `amount >= requirements.amount` on the
static path and align the §3.1 wording with §1.4.

## Resolved on 2026-10-20

Every finding recorded during the harness rework was fixed in the SDKs, with
regression tests, against [RULINGS.md](RULINGS.md):

| Finding | Fixed in |
| --- | --- |
| Clients defaulted `decimals` or the token program (C2, C3) | Python, Kotlin, all reference runners |
| Servers put a symbol on the wire as `currency`, or decimals for SOL (C1, C2) | Rust, Go, Python, Ruby, PHP, Lua |
| `asset` / `payTo` precedence twins in charge vectors (C4) | vectors deleted |
| Rust refused payer-funded split ATA creation; Go could create a top-level recipient ATA (C5) | Rust, Go |
| Go x402 client required a non-spec `protocol` field (X1) | Go |
| Ruby x402 server put a decimal price on the wire; Lua priced every coin with 6 decimals (X2) | Ruby, Lua |
| x402 verify vectors used a placeholder transaction that verifiers accepted | vectors regenerated; every server verifier inspects the transaction |
| Verifiers required an exact amount, allowed the fee payer in non-transfer instructions, or accepted two matching transfers (S3) | Rust, Go, Ruby, PHP, Lua, Python |
| Rust and TypeScript x402 servers could not require `payment-identifier` (S4) | Rust, TypeScript |
| `ts-x402` interop adapters were stubs | real pay-kit client and gate |
| Rust x402 harness server ignored the scenario resource path | harness bins |
| Rust charge pre-broadcast verifier was private | exposed under the `testkit` feature |

## Declared limitations (`[[unsupported]]`, not failures)

- Server-only SDKs (Ruby, PHP, Lua) cannot build transactions.
- Client-only SDKs (Swift, Kotlin) cannot verify.
- Go and Swift session types still model the superseded session draft, so
  session wire vectors are unsupported for them.
- `@solana/pay-kit` speaks x402 v2 only, and cannot pin a caller-chosen
  payment-identifier id.
- The Kotlin conformance runner implements only the session voucher preimage
  vectors.
