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
## Interop findings (`pkc run --tier interop`, 2026-10-20)

Recorded by the first run of the interop tier with every adapter paired
against the Rust reference (Kotlin not run locally: no JVM). Case keys are
`interop/<scenario>/<client>/<server>`; the entry lives in the toml of the
side the gap belongs to. The SDK sources were not changed.

## charge-client-network-not-checked

**Cases:** `charge-client-wrong-network/{go,kotlin,rust,swift,typescript}/rust`

The fault proxy rewrites the Rust server's challenge to `methodDetails.network
= "mainnet"` while the client pays a localnet validator. Every client builds
and submits a credential. draft-solana-charge-00: “Clients MUST reject
challenges whose network does not match their configured cluster.” Only the
TypeScript adapter receives a network (`MPP_HARNESS_NETWORK`), and its SDK
does not compare it either.

## charge-client-request-not-verified

**Cases:** `charge-client-over-asking-price/*/rust`,
`charge-client-mis-signed-challenge/*/rust` (go, kotlin, rust, swift, typescript)

The proxy multiplies the challenged amount by 10 000, or swaps the recipient,
after the server bound the challenge id. Every client pays. Core: “Clients
MUST verify before authorizing payment: 1. Requested amount is reasonable for
the resource 2. Recipient/address is expected”. No client SDK exposes an
expected amount or recipient, and the adapter contract passes none; in pull
mode the server's challenge binding is what keeps the funds safe (the
proxy-observed credential never settles).

## x402-client-network-not-checked

**Cases:** `x402-exact-client-wrong-network/{go,kotlin,python,rust,swift}/rust`

The proxy rewrites every `accepts[].network` to solana mainnet while the
client is configured (`X402_HARNESS_NETWORK`) for the devnet CAIP-2 id. These
clients still pay; the TypeScript client refuses.

## charge-canonical-codes-php-lua

**Cases:** `charge-{network-mismatch,cross-server-portability}/rust/{php,lua}`,
`charge-cross-route-replay/rust/php`

PHP and Lua reject with `payment_invalid` where every other server emits the
specific canonical code (`wrong_network`, `challenge_verification_failed`,
`charge_request_mismatch`). The rejection itself is correct.

## lua-charge-replay-route-missing

**Case:** `charge-cross-route-replay/rust/lua`

The Lua adapter does not mount `MPP_HARNESS_REPLAY_SOURCE_PATH`, so the cheap
route a cross-route credential comes from returns 404. Adapter gap.

## charge-decimals-9-servers

**Cases:** `charge-decimals-9/*/rust`, `charge-decimals-9/rust/{go,lua,php}`

A 9-decimal mint at amount 1000: the Rust harness server prices
`price × 10^decimals` (1 000 000, not the scenario's 1000), Go and Lua exit
before readiness, PHP answers 402. Previously masked by `serverIds:
["typescript", "ruby"]`.

## charge-sol-native-servers

**Cases:** `charge-sol-native/rust/{go,lua}`

Native SOL: the Go adapter exits before readiness; the Lua server settles a
transaction without the System Program transfer of 1 000 000 lamports to the
recipient. Previously masked by `serverIds`.

## x402-replay-route-missing

**Cases:** `x402-exact-cross-route-replay/rust/{go,lua,php,python,ruby,ruby-x402-server}`

These x402 adapters do not mount `MPP_HARNESS_REPLAY_SOURCE_PATH`, so the
cross-route case cannot present a cheap-route payment (404). Only the Rust and
TypeScript x402 servers serve it. Adapter gap; the case never ran before
(`clientIds: ["ts-x402"]`).

## x402-canonical-codes

**Cases:** `x402-exact-idempotent-resubmit/*/rust` and
`/rust/{go,lua,php,ruby,ruby-x402-server}`,
`x402-exact-cross-route-replay/rust/typescript`

A second presentation of a settled x402 payment is refused (402) without the
canonical `signature_consumed`: Rust says `payment_invalid`, Go returns a
fresh challenge with no code, Lua and PHP `invalid_proof`, Ruby a raw RPC
error. TypeScript rejects a cross-route payment with `payment_invalid`
(sdkCode `accepted_mismatch`) instead of `charge_request_mismatch`. x402 has
no shared reject-code table yet; the refusals are correct.

## python-x402-double-delivery

**Case:** `x402-exact-idempotent-resubmit/rust/python`

The Python x402 server answers a second presentation of an already-settled
payment with **200 and serves the resource again**. One payment, two
deliveries. scheme_exact.md: “Such methods MUST deduplicate settlements
atomically across every process serving `/settle`”, and “A consumed primitive
MUST produce a settlement failure, never a success.” Security-relevant.

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
- `@solana/mpp` has no stateless subscription usability check and no
  subscriptions instruction encoder, so the `subscription-active-*` and
  `subscription-instruction-*` vectors are unsupported for TypeScript.

## Subscription findings (`subscription-*.json`, 2026-10-21)

From the `subscription` vectors (draft-solana-subscription-00, pinned as
`external/mpp-specs-solana` at `5c4a528`). Paths are file:line at the commit
that recorded them. Rust divergences are recorded on the cases
(`authored(Some(reason))`), so fixing the kit fails the case until the note
is removed.

## subscription-rust-client-kit-extensions

**Case:** `vector/subscription-build-spec-request`
**SDKs:** rust

The Rust client builds `SubscribeData` from methodDetails fields only the
Rust server emits (`amount`, `recipient`, `merchant`, `planIdNumeric`,
`planBump`, `expectedPeriodHours`, `expectedCreatedAt`) and refuses a
challenge without them
(`rust/crates/kit/src/mpp/protocol/intents/subscription.rs:176`,
`rust/crates/kit/src/mpp/client/subscription.rs:266`). A spec-shaped
challenge, which is what `@solana/mpp`'s server issues, carries none of
them: the plan terms are on-chain. The Rust client cannot activate against
the TypeScript server. Fix: read the Plan account (as the TypeScript client
does) and treat the extensions as an optimisation that must agree with it.

## subscription-rust-request-format

**Cases:** `vector/subscription-build-amount-leading-zero-reject`,
`-zero-amount-reject`, `-period-count-leading-zero-reject`,
`-token-program-not-spl-reject`, `-no-decimals-reject`,
`vector/subscription-period-count-leading-zero-reject`, `-sign-reject`
**SDKs:** rust

“The amount value MUST be a string representation of a positive integer in
base 10 with no sign, decimal point, exponent, or surrounding whitespace.
Leading zeros MUST NOT be used.” (the same holds for periodCount). The kit
parses both with `u64::from_str`, which accepts `"010000000"`, `"0"`, `"030"`
and `"+30"` (`rust/crates/kit/src/mpp/protocol/intents/subscription.rs:201-212`).
The builder accepts any `tokenProgram` (“The value MUST be the SPL Token
program or the SPL Token-2022 program”,
`rust/crates/kit/src/mpp/client/subscription.rs:224`), and `decimals` is
optional (`rust/crates/kit/src/mpp/protocol/intents/subscription.rs:322`)
though the table marks it REQUIRED. Two encodings of one set of terms break
the uniqueness of the challenge's canonical bytes.

## subscription-rust-client-plan-unread

**Cases:** `vector/subscription-build-plan-missing-reject`,
`-plan-amount-mismatch-reject`, `-plan-period-mismatch-reject`,
`-plan-mint-mismatch-reject`, `-plan-puller-unauthorized-reject`,
`-plan-no-destination-reject`, `-plan-two-destinations-reject`,
`-plan-other-destination-reject`
**SDKs:** rust (all eight); typescript for the puller and destination cases
(`subscription-ts-plan-pullers-destinations`)

“Clients MUST NOT sign an activation transaction whose on-chain Plan does not
match the challenge.” and “Servers and clients MUST reject request objects
referencing a plan with an empty destination whitelist, more than one non-zero
destination, or a destination different from recipient.” The Rust client
never reads the Plan. The program's `Subscribe` re-checks the terms it is
handed, but nothing catches a plan whose destinations or pullers differ from
what the wallet displays.

## subscription-source-not-verified

**Cases:** `vector/subscription-verify-source-other-address-reject`,
`vector/subscription-verify-source-other-method-reject`
**SDKs:** rust, typescript

“If source is present, servers MUST verify that it uses the did:pkh:solana:
method and that its address matches the subscriber signer extracted from the
activation transaction.” Neither server reads `credential.source`
(`rust/crates/kit/src/mpp/server/subscription.rs:420`,
`typescript/packages/mpp/src/server/Subscription.ts:230`). Both derive the
payer from the transaction, so payment is unaffected, but an application that
logs or keys on `source` trusts an unverified value.

## subscription-rust-sponsor-fee-payer-code

**Case:** `vector/subscription-verify-sponsor-not-fee-payer-reject`
**SDKs:** rust

A sponsored challenge whose activation names the subscriber as fee payer is
rejected as “Could not identify subscriber among transaction signers”
(`rust/crates/kit/src/mpp/server/subscription.rs:1867`) rather than as a fee
payer mismatch: `extract_subscriber_from_tx` skips signer 0 assuming it is the
sponsor and runs before the fee-payer check in `validate_activation_scope`.
The verdict is right, the category is not.

## subscription-rust-wire-optional-authentication

**Case:** `vector/subscription-wire-activation-no-authentication-reject`
**SDKs:** rust

`ActivatePayload.authentication` is an `Option`
(`rust/crates/kit/src/mpp/protocol/intents/subscription.rs:260`), so the wire
type accepts an activation without the REQUIRED proof; `verify_credential`
rejects it later. Making the field required moves the check to the parse
boundary.

## subscription-ts-recipient-ata

**Cases:** every accepted `vector/subscription-build-*`
**SDKs:** typescript

`buildSubscriptionActivationTransaction` also creates the recipient's ATA
(`typescript/packages/mpp/src/client/Subscription.ts:353`, `:407`). The Rust
server's scope check refuses it (“Only one idempotent subscriber ATA creation
is allowed in activation tx”), so a TypeScript client cannot activate against
a Rust server, and the spec's list (“contain no instructions other than those
above plus optional compute-budget and memo instructions.”) does not allow it
either. See RULINGS SUB1.

## subscription-ts-program-not-pinned

**Case:** `vector/subscription-build-untrusted-program-reject`
**SDKs:** typescript

“Servers MUST pin its deployment address in methodDetails.subscriptionProgram,
and clients MUST validate that address before signing.” The TypeScript client
signs for whatever program the challenge names
(`typescript/packages/mpp/src/client/Subscription.ts:297`); with a Plan and an
authority owned by that program it builds and signs. Security-relevant: the
program receives the subscriber's signature and token account.

## subscription-ts-currency-not-mint

**Case:** `vector/subscription-build-currency-not-mint-reject`
**SDKs:** typescript

“Implementations MUST treat currency and methodDetails.mint as the same
value”. The client builds from `methodDetails.mint` and never compares it with
`currency` (`typescript/packages/mpp/src/client/Subscription.ts:264`), so a
wallet can display one token and sign a delegation over another.

## subscription-ts-request-format

**Cases:** `vector/subscription-build-amount-leading-zero-reject`,
`-zero-amount-reject`, `-period-count-leading-zero-reject`,
`-token-program-not-spl-reject`, `vector/subscription-period-count-*-reject`
(leading zero, sign, decimal point, exponent, whitespace)
**SDKs:** typescript

`Number(periodCount)` and `BigInt(amount)`
(`typescript/packages/mpp/src/client/Subscription.ts:273`, `:331`) accept
`"030"`, `"+30"`, `"30.0"`, `"3e1"` and `" 30"`; nothing on the client rejects
a zero amount or a tokenProgram other than SPL Token / Token-2022.

## subscription-ts-plan-pullers-destinations

**Cases:** `vector/subscription-build-plan-puller-unauthorized-reject`,
`-plan-no-destination-reject`, `-plan-two-destinations-reject`,
`-plan-other-destination-reject`
**SDKs:** typescript

The client reads the Plan and checks its mint, amount and period
(`typescript/packages/mpp/src/client/Subscription.ts:329`), but not that the
puller is `plan.owner` or in `plan.pullers`, nor that `plan.destinations` is
exactly the recipient.

## subscription-ts-route-binding-in-mppx

**Cases:** `vector/subscription-verify-forged-challenge-id-reject`,
`-other-method-reject`, `-charge-intent-reject`, `-other-realm-reject`,
`-cheaper-route-reject`, `-shorter-period-route-reject`,
`-other-plan-reject`, `-other-recipient-reject`, `-other-currency-reject`,
`-other-network-reject`, `-no-network-on-devnet-reject`
**SDKs:** typescript

`subscription().verify` trusts the echoed challenge
(`typescript/packages/mpp/src/server/Subscription.ts:230`). The HMAC (tier 1)
and route binding (tier 2, `stableBinding`) live in mppx's `Mppx.create`
handler, which turns every SDK error into a generic `VerificationFailedError`
the testee cannot classify, so the testee drives `verify` directly. A host
that calls `verify` outside `Mppx.create` gets no binding. Either bind inside
the method (as the Rust server does) or have mppx surface the reason so the
testee can drive the handler.

## subscription-ts-push-mode

**Case:** `vector/subscription-verify-push-mode-reject`
**SDKs:** typescript

The server accepts `type="signature"` activations and fetches the
transaction (`typescript/packages/mpp/src/server/Subscription.ts:485`), and
the client offers `broadcast: true`. The profile defines activation as
`type="transaction"` only and says push-mode credentials “do not provide the
per-period enforcement required for this intent”. See RULINGS SUB2.

## subscription-ts-scope-accounts

**Cases:** `vector/subscription-verify-subscribe-other-plan-reject`,
`vector/subscription-verify-unrelated-authority-init-reject`
**SDKs:** typescript

`validateActivationInstructions`
(`typescript/packages/mpp/src/server/Subscription.ts:793-797`) checks
transfer_subscription's receiver and data but not subscribe's accounts (“uses
methodDetails.planAddress as the Plan account”), and accepts any
`initialize_subscription_authority`, including one for an unrelated mint.
