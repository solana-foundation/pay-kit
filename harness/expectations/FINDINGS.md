# Conformance findings

Open gaps referenced from `[[known_failing]]` entries by
`tracking = "FINDINGS.md#<anchor>"`. Each finding should become a GitHub issue;
when it does, replace the tracking value with the issue URL and delete the
section here.

Open findings from the phase-1 vectors (pinned spec text, RULINGS ids):

## ts-x402-accepted-not-bound

**Cases:** `vector/x402-exact-v2-verify-wrong-network-reject`,
`vector/x402-exact-verify-accepted-amount-lie-reject`,
`vector/x402-exact-verify-accepted-asset-lie-reject`,
`vector/x402-exact-verify-accepted-payto-lie-reject`
**SDKs:** typescript

`@solana/pay-kit`'s x402 adapter only checks that `accepted` is an object and
then verifies the transaction against the route
(`typescript/packages/pay-kit/src/adapters/x402.ts:146-152`). It never
compares `accepted` with the route, so each lie surfaces as the transaction
check that happens to fail (wrong-network, amount, mint, recipient) instead of
`accepted-mismatch`.

## ts-x402-fee-payer-in-accounts

**Case:** `vector/x402-exact-verify-fee-payer-in-accounts-reject`
**SDKs:** typescript

The vendored `@x402/svm` 2.26.0 exact facilitator
(`typescript/packages/pay-kit/node_modules/@x402/svm/dist/esm/exact/facilitator/index.mjs:728`)
checks the fee payer only as the `TransferChecked` authority and lets it sign
a Memo instruction. scheme_exact_svm.md §2.1.1: “The feePayer MUST NOT appear
in the accounts list of any instruction”. Upstream reference implementation.

## x402-overpayment-rejected

**Case:** `vector/x402-exact-verify-overpayment-accept`
**SDKs:** python, typescript

Both verifiers require the transfer amount to equal the requirement:
`python/src/solana_pay_kit/protocols/x402/exact/verify.py:289` and the
vendored `@x402/svm` 2.26.0 facilitator (`.../exact/facilitator/index.mjs:765`,
`amount !== BigInt(requirements.amount)`). RULINGS S5: overpayment is
tolerated by default (scheme_exact_svm.md §1.4).

## python-duplicate-split-memos

**Case:** `vector/charge-split-duplicate-memo-accept`
**SDKs:** python

The charge verifier keeps the expected split memos in a set
(`python/src/solana_pay_kit/protocols/mpp/server/_verify.py:356`), so two
splits with the same memo text accept one Memo instruction and reject the
second as “unexpected Memo Program instruction”. draft-solana-charge-00
Method Details: “If the same recipient appears more than once in splits,
each occurrence is a distinct payment leg and MUST be verified separately”.

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
