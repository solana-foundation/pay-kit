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

Open findings from the requirement-gap cases (`charge-*-policy.json`,
`x402-*-policy.json`, added from the `pkc req-lint` gap list on 2026-10-20).
Paths are file:line at the commit that recorded them.

## x402-extra-required-signer-accepted

**Case:** `vector/x402-exact-verify-extra-required-signer-reject`
**SDKs:** go, lua, php, python, ruby, typescript

scheme_exact_svm.md §2.1.4: “The transaction MUST NOT require any signatures
beyond the client and the sponsor (feePayer).” The vector adds a third key as
a signer account of the Memo instruction and signs with it. Rust rejects
(`invalid_exact_svm_payload_transaction_unexpected_signer`,
`rust/crates/kit/src/x402/protocol/schemes/exact/verify.rs:321`); every other
x402 verifier accepts, because none compares the header's required signers
with {fee payer, transfer authority}:

- Go `go/protocols/x402/verify.go:81` (`VerifyExactTransaction`)
- Python `python/src/solana_pay_kit/protocols/x402/exact/verify.py:83`
- Ruby `ruby/lib/pay_kit/protocols/x402/protocol/schemes/exact/verify.rb:33`;
  `verify_client_signatures!` (`:68`) only checks that each extra signer signed
- PHP `php/src/Protocols/X402/Exact/Verifier.php:61`
- Lua `lua/pay_kit/protocols/x402/exact/verify.lua:257`; `verify_client_signatures`
  (`:368`) as in Ruby
- TypeScript: the vendored upstream `@x402/svm` static path
  (`typescript/external/x402/typescript/packages/mechanisms/svm/src/exact/facilitator/scheme.ts:966`)
  has only the optional `maxRequiredSignatures` gate (`:773`), which pay-kit
  leaves unset (`typescript/packages/pay-kit/src/config.ts:48`). The fix
  belongs upstream in the x402 fork, or pay-kit sets the option to 2.

The sponsor pays the extra signature fee and the payment's validity depends
on a party outside the client and the sponsor.

## charge-client-sol-token-program-ignored

**Case:** `vector/charge-build-sol-token-program-reject`
**SDKs:** go, python, rust, swift, typescript

draft-solana-charge-00 Method Details, tokenProgram: “MUST NOT be present when
currency is "sol".” Every client builds the SOL transfer and ignores the
field: Rust `rust/crates/kit/src/mpp/client/charge.rs:376`, TypeScript
`typescript/packages/mpp/src/client/Charge.ts:331`, Go
`go/protocols/mpp/client/charge.go:92`, Python
`python/src/solana_pay_kit/protocols/mpp/client/charge.py:208`, Swift
`swift/Sources/SolanaPayKit/Protocols/Mpp/Client/Charge.swift:319`. A client
that cannot tell a malformed challenge from a valid one pays challenges a
server never meant to issue (the Rust case carries a `kit_divergence`).

## charge-client-fee-payer-without-key

**Case:** `vector/charge-build-fee-payer-without-key-reject`
**SDKs:** go, python, rust

Method Details, feePayer: “When true, the feePayerKey field MUST also be
present.” TypeScript (`typescript/packages/mpp/src/client/Charge.ts:197`) and
Swift (`swift/Sources/SolanaPayKit/Protocols/Mpp/Client/Charge.swift:216`)
refuse; Rust (`rust/crates/kit/src/mpp/client/charge.rs:333`), Go
(`go/protocols/mpp/client/charge.go:87`) and Python
(`python/src/solana_pay_kit/protocols/mpp/client/charge.py:169`) silently fall
back to a client-paid transaction, so the client pays fees the challenge
promised to sponsor.

## charge-client-unknown-network

**Case:** `vector/charge-build-unknown-network-reject`
**SDKs:** go, python, swift, typescript

Method Details, network: “MUST be one of "mainnet", "devnet", or "localnet".”
Rust refuses (`rust/crates/kit/src/mpp/client/charge.rs:1031`). The others
build for `testnet`: Go `go/protocols/mpp/client/charge.go:49` (the network
guard at `:327` is opt-in), Python
`python/src/solana_pay_kit/protocols/mpp/client/charge.py:112` (opt-in guard at
`:88`), Swift `swift/Sources/SolanaPayKit/Protocols/Mpp/Client/Charge.swift:164`
(opt-in), TypeScript `typescript/packages/mpp/src/client/Charge.ts:187`, which
also falls back to the mainnet RPC for an unknown network.

## ts-charge-client-split-cap

**Case:** `vector/charge-build-too-many-splits-reject`
**SDKs:** typescript

Method Details, splits: “An array of at most 8 additional payment splits.”
Rust (`rust/crates/kit/src/mpp/client/charge.rs:317`), Go and Python refuse
nine splits; the TypeScript client sums and iterates them with no length check
(`typescript/packages/mpp/src/client/Charge.ts:204`).

## charge-client-amount-not-u64-validated

**Case:** `vector/charge-build-amount-overflow-reject`
**SDKs:** python, typescript

Shared Fields, amount: “The value MUST be a positive integer that fits in a
64-bit unsigned integer”. Both reject 2^64 only by accident, when a lower
layer cannot encode it: TypeScript `BigInt(amount)` with no bound
(`typescript/packages/mpp/src/client/Charge.ts:205`, then the u64 codec
throws), Python `int(amount)` with no bound
(`python/src/solana_pay_kit/protocols/mpp/client/charge.py:155`, then solders
raises "int too big to convert"). Rust, Go and Swift parse a u64 explicitly.

## go-charge-sol-ata-creation-required

**Cases:** `vector/charge-build-sol-ata-creation-required-reject`,
`vector/charge-verify-sol-ata-creation-required-reject`
**SDKs:** go

Method Details, ataCreationRequired: “This field MUST NOT be true unless
currency is an SPL token mint address.” The Go client's SOL branch never reads
the flag (`go/protocols/mpp/client/charge.go:92`) and the server's native
branch ignores it (`go/protocols/mpp/server/server.go:757`; required ATA owners
are only computed on the SPL path, `:811`). Rust, TypeScript and Python refuse
the challenge.

## python-charge-sol-ata-creation-required-order

**Case:** `vector/charge-verify-sol-ata-creation-required-reject`
**SDKs:** python

The Python server refuses the same challenge, but as a missing ATA creation
(`python/src/solana_pay_kit/protocols/mpp/server/_verify.py:550`, after
computing required ATA owners for a native charge at `:349`) instead of
refusing the out-of-spec challenge first. The verdict is right; the reason is
not the rule that applies.

## go-charge-ata-owner-allowlist

**Cases:** `vector/charge-verify-ata-for-top-level-recipient-reject`,
`vector/charge-verify-sponsored-ata-top-level-reject`,
`vector/charge-verify-sponsored-ata-unmarked-split-reject`
**SDKs:** go

Split Recipient ATA Creation: “Clients MUST NOT include ATA creation
instructions for the top-level recipient or any other owner.” and “Clients
MUST NOT include fee-payer-funded ATA creation instructions for the top-level
recipient, unmarked split recipients, or arbitrary owners.” The Go verifier's
ATA owner allowlist is every expected recipient, primary included, regardless
of `ataCreationRequired` or fee sponsorship
(`go/protocols/mpp/server/server.go:938`, enforced at `:1216`). Under
`feePayer: true` the server would fund rent for ATAs the challenge never
authorized. RULINGS C5 records the client half of this as fixed; the server
half was not.

## charge-server-fee-payer-not-checked

**Case:** `vector/charge-verify-fee-payer-not-server-key-reject`
**SDKs:** go, python

Pull Mode Verification: “The transaction MUST have the server's feePayerKey
set as the fee payer account.” Under `feePayer: true`, Go
(`go/protocols/mpp/server/server.go:595`; `feePayerKey` is only used to forbid
it as a transfer source, `:976`) and Python
(`python/src/solana_pay_kit/protocols/mpp/server/_verify.py:558`; account 0 is
only used as the expected ATA payer, `:316`) never compare account 0 with the
key. Python's later slot check (`_assert_signature_slot`,
`python/src/solana_pay_kit/protocols/mpp/server/_verify.py:84`) runs only when
co-signing, after verification passed.

## lua-charge-compute-budget-allowlist

**Case:** `vector/charge-verify-compute-budget-heap-frame-reject`
**SDKs:** lua

Transaction Payload Security: “Servers MUST verify that the transaction
contains only the expected instructions: ... and optionally compute budget
instructions.” Every other server accepts only SetComputeUnitLimit and
SetComputeUnitPrice; Lua treats discriminators 0, 1 and 4 (RequestHeapFrame
among them) as no-ops and accepts them (`lua/pay_kit/solana/instructions.lua:199`;
the hooks path does the same, `lua/pay_kit/protocols/mpp/server/solana_verify.lua:359`).

## ts-charge-ata-empty-data-crash

**Case:** `vector/charge-verify-ata-not-idempotent-reject`
**SDKs:** typescript

A non-idempotent `Create` (empty instruction data) makes the TypeScript
verifier throw a TypeError, “Cannot read properties of undefined (reading
'length')”, instead of the policy rejection
(`typescript/packages/mpp/src/server/Charge.ts:689` reads `ix.data.length`
unguarded). The credential is still refused, by accident.

## x402-fee-payer-drain-category

**Case:** `vector/x402-exact-verify-fee-payer-sol-drain-reject`
**SDKs:** lua, php, python

A System transfer from the sponsor appended after the TransferChecked is
refused by every verifier. Rust, TypeScript, Go and Ruby report fee-payer
isolation (§2.1.1, §2.1.3); Lua, PHP and Python reach the static-layout check
first and report `unknown_fourth_instruction`
(`lua/pay_kit/protocols/x402/exact/verify.lua:289` before `:299`,
`php/src/Protocols/X402/Exact/Verifier.php:115` before `:129`,
`python/src/solana_pay_kit/protocols/x402/exact/verify.py:154` before `:169`).
The verdict is right; the reason hides the fund-safety violation, and a
smart-wallet path that relaxes the layout would have to catch it again.

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
