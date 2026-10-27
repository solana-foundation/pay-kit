# Conformance findings

Open gaps referenced from `[[known_failing]]` entries by
`tracking = "FINDINGS.md#<anchor>"`. Each finding should become a GitHub issue;
when it does, replace the tracking value with the issue URL and delete the
section here.

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
**SDKs:** go, python, swift, typescript

draft-solana-charge-00 Method Details, tokenProgram: “MUST NOT be present when
currency is "sol".” Rust refuses (`validate_challenge_details`,
`rust/crates/kit/src/mpp/client/charge.rs`). The others build the SOL
transfer and ignore the field: TypeScript
`typescript/packages/mpp/src/client/Charge.ts:331`, Go
`go/protocols/mpp/client/charge.go:92`, Python
`python/src/solana_pay_kit/protocols/mpp/client/charge.py:208`, Swift
`swift/Sources/SolanaPayKit/Protocols/Mpp/Client/Charge.swift:319`. A client
that cannot tell a malformed challenge from a valid one pays challenges a
server never meant to issue.

## charge-client-fee-payer-without-key

**Case:** `vector/charge-build-fee-payer-without-key-reject`
**SDKs:** go, python

Method Details, feePayer: “When true, the feePayerKey field MUST also be
present.” TypeScript (`typescript/packages/mpp/src/client/Charge.ts:197`),
Swift (`swift/Sources/SolanaPayKit/Protocols/Mpp/Client/Charge.swift:216`)
and Rust (`validate_challenge_details`,
`rust/crates/kit/src/mpp/client/charge.rs`) refuse; Go
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
**SDKs:** python

Pull Mode Verification: “The transaction MUST have the server's feePayerKey
set as the fee payer account.” Under `feePayer: true`, Python
(`python/src/solana_pay_kit/protocols/mpp/server/_verify.py:558`; account 0 is
only used as the expected ATA payer, `:316`) never compares account 0 with the
key. Go now refuses it in its client-signature check
(`solanatx.VerifyClientSignatures`). Python's later slot check (`_assert_signature_slot`,
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
## batch-deposit-balance-unchecked

**Case:** `vector/batch-verify-open-unfunded-payer-reject`,
`vector/batch-verify-top-up-unfunded-payer-reject`
**SDKs:** typescript

scheme_batch_settlement_svm.md, canonical `open` and `top_up`: "It MUST
confirm the payer has sufficient tokens". The pay-kit gate broadcasts the
deposit only after the handler runs, so Rust reads the payer's token account
and the transaction's blockhash before it reserves the request
(`X402BatchSettlement::check_deposit_can_land`). The vendored `@x402/svm`
2.28.0 verify reads no balance; its deposit settle simulates the
transaction, which the offline harness signer stubs, so the vector cannot
observe it there.

## Interop findings (`pkc run --tier interop`, 2026-10-20)

Recorded by the first run of the interop tier with every adapter paired
against the Rust reference (Kotlin not run locally: no JVM). Case keys are
`interop/<scenario>/<client>/<server>`; the entry lives in the toml of the
side the gap belongs to. The SDK sources were not changed.

## charge-client-network-not-checked

**Cases:** `charge-client-wrong-network/{go,kotlin,swift,typescript}/rust`

The fault proxy rewrites the Rust server's challenge to `methodDetails.network
= "mainnet"` while the client pays a localnet validator. These clients build
and submit a credential. draft-solana-charge-00: “Clients MUST reject
challenges whose network does not match their configured cluster.” Every
client adapter receives the cluster (`MPP_HARNESS_NETWORK`); the Rust client
passes it as `BuildChargeTransactionOptions::expected_network` and refuses.
The TypeScript SDK does not compare it.

## charge-client-request-not-verified

**Cases:** `charge-client-over-asking-price/*/rust`,
`charge-client-mis-signed-challenge/*/rust` (go, kotlin, swift, typescript)

The proxy multiplies the challenged amount by 10 000, or swaps the recipient,
after the server bound the challenge id. These clients pay. Core: “Clients
MUST verify before authorizing payment: 1. Requested amount is reasonable for
the resource 2. Recipient/address is expected”. Client adapters receive the
scenario amount and recipient (`MPP_HARNESS_AMOUNT`, `MPP_HARNESS_PAY_TO`);
the Rust client pins them (`max_amount_base_units`, `expected_recipient`) and
refuses. In pull mode the server's challenge binding is what keeps the funds
safe (the proxy-observed credential never settles).

## x402-client-network-not-checked

**Cases:** `x402-exact-client-wrong-network/{go,kotlin,python,swift}/rust`

The proxy rewrites every `accepts[].network` to solana mainnet while the
client is configured (`X402_HARNESS_NETWORK`) for the devnet CAIP-2 id. These
clients still pay; the TypeScript and Rust clients refuse (Rust: a configured
`ChallengeSelection::network` never falls back to another network).

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

**Cases:** `charge-decimals-9/rust/{go,lua,php}`

A 9-decimal mint at amount 1000: Go and Lua exit before readiness, PHP answers
402. (The Rust adapter priced `MPP_HARNESS_PRICE × 10^decimals`, 1 000 000; it
now charges `MPP_HARNESS_AMOUNT` like every other server.) Previously masked by `serverIds:
["typescript", "ruby"]`.

## charge-sol-native-servers

**Cases:** `charge-sol-native/rust/{go,lua}`

Native SOL: the Go adapter exits before readiness; the Lua server settles a
transaction without the System Program transfer of 1 000 000 lamports to the
recipient. Previously masked by `serverIds`.

## x402-replay-route-missing

**Cases:** `x402-exact-cross-route-replay/rust/{go,lua,php,ruby,ruby-x402-server}`

These x402 adapters do not mount `MPP_HARNESS_REPLAY_SOURCE_PATH`, so the
cross-route case cannot present a cheap-route payment (404). Only the Rust and
TypeScript x402 servers serve it. Adapter gap; the case never ran before
(`clientIds: ["ts-x402"]`).

## x402-canonical-codes

**Cases:** `x402-exact-idempotent-resubmit/rust/{go,lua,php,ruby,ruby-x402-server}`,
`x402-exact-cross-route-replay/rust/typescript`

A second presentation of a settled x402 payment is refused (402) without the
canonical `signature_consumed`: Go returns a
fresh challenge with no code, Lua and PHP `invalid_proof`, Ruby a raw RPC
error. TypeScript rejects a cross-route payment with `payment_invalid`
(sdkCode `accepted_mismatch`) instead of `charge_request_mismatch`. x402 has
no shared reject-code table yet; the refusals are correct.

Open findings from the x402 `upto` (SVM) vectors (`x402-upto-*.json`,
2026-10-21). Rust is driven through
`x402::server::upto::testkit::verify_open_pre_broadcast` (the pre-broadcast
half of `X402Upto::verify_open_for_route`, co-signature included);
TypeScript through the vendored `@x402/svm` 2.28.0 upto facilitator's
read-only `verify` (pay-kit's `X402Upto.verifyOpen` calls `settle`, which
broadcasts).

## upto-channel-exists-not-checked

**Case:** `vector/x402-upto-verify-channel-already-open-reject`
**SDKs:** typescript

Phase 3 step 4: “Confirm the channel account does not already exist. If it
does, reject with invalid_upto_svm_channel_already_open.” (RULINGS U2.) The
vendored TS facilitator checks it only in `settle` (deposit), not in `verify`
(`typescript/external/x402/typescript/packages/mechanisms/svm/src/upto/facilitator/scheme.ts:400`).

## upto-slot-wire-type

**Case:** `vector/x402-upto-verify-open-slot-number-accept`
**SDKs:** typescript

The pinned §4.2 table types `openSlot` as `number`, §4.1 types `recentSlot` as
`number`, and both §4.1 examples carry `"recentSlot": 341000000`. TS
`isUptoSvmPayload` requires a string `openSlot`
(`typescript/external/x402/typescript/packages/mechanisms/svm/src/types.ts:79`),
so the spec's own number form is refused. Rust reads both forms
(`Slot` in `rust/crates/kit/src/x402/protocol/schemes/upto/types.rs`). See
RULINGS U1; the fix is upstream spec text or parsers that accept both.

## go-upto-client-expires-beyond-timeout

**Cases:** `interop/x402-upto-basic/go/rust`, `interop/x402-upto-zero-actual/go/rust`
**SDKs:** go

scheme_upto_svm.md Phase 3 step 7: “Reject when maxTimeoutSeconds or remaining
expiresAt - now exceeds the facilitator's maxChannelLifetimeSecs, or when
expiresAt is later than now + maxTimeoutSeconds (plus clock skew).” The Go
upto client adapter passes `time.Now().Add(time.Hour)` as `expiresAt`
(`harness/go-client/main.go:168`) whatever the challenge's
`maxTimeoutSeconds` (300 in the scenario), so the Rust server refuses it
with `invalid_upto_svm_payload_expires_at_mismatch`. The Python, Swift and
Kotlin adapters use `now + maxTimeoutSeconds`.

## go-upto-server-memo-suffix-refused

**Case:** `interop/x402-upto-basic/rust/go`
**SDKs:** go

The acceptance policy allows “An optional suffix of at most four
instructions, each invoking either Lighthouse ... or SPL Memo”, and “Clients
MUST include a Memo instruction containing either the value of extra.memo
(when present) or a random nonce”. `validateUptoOpenInstruction`
(`go/protocols/x402/upto.go:795`) requires the open to be the only
instruction, so a spec-conforming client open on an unbound route (the Rust
client's random-nonce Memo) is refused.

## ts-upto-open-trailing-bytes

**Case:** `vector/x402-upto-verify-open-trailing-byte-reject`
**SDKs:** typescript

“The facilitator MUST fully decode the canonical open instruction data, reject
truncated data or trailing bytes”. `verifyOpenTransaction` decodes the args
with `getOpenInstructionDataDecoder().decode`
(`typescript/external/x402/typescript/packages/mechanisms/svm/src/payment-channels/open.ts:969`),
which ignores bytes past the arguments. The fix belongs in the x402 fork.

## txv1-ts-mpp-no-transaction-versions

**Cases:** `vector/charge-wire-transaction-versions-*`, `vector/session-wire-transaction-versions-*`
**SDKs:** typescript

`@solana/mpp`'s charge and session request schemas
(`typescript/packages/mpp/src/Methods.ts`) have no
`methodDetails.transactionVersions`. zod strips the field, so a server's
advertisement is lost in a round trip and malformed values (`["legacy"]`,
`[0, 2]`, `["1"]`, `1`) parse. Tracks the mpp-specs
feat/solana-transaction-versions draft (`77aa6a1`).

## txv1-ts-mpp-client-v0-only

**Cases:** `vector/charge-build-v1-*`, `vector/charge-build-duplicate-advertisement`, `vector/charge-build-empty-advertisement-reject`
**SDKs:** typescript

The `@solana/mpp` charge client never reads `transactionVersions` and always
builds a version-0 message with the ComputeBudget prefix
(`typescript/packages/mpp/src/client/Charge.ts`). For a `[1]`-only challenge
the build is a version the server never advertised; for the 1.9 KB
large-memo charge it exceeds the version-0 limit instead of using version 1.

## txv1-ts-mpp-server-no-version-admission

**Cases:** `vector/charge-verify-v1-*`, `vector/charge-verify-v0-to-v1-only-reject`, `vector/charge-verify-legacy-*`, `vector/charge-verify-v0-oversize-reject`
**SDKs:** typescript

`verifyChargeTransaction` has no version admission: a version-1 transaction
throws while decoding (`Cannot read properties of undefined (reading
'entries')`: the compiled version-1 message has no `instructions` array), a
version-0 transaction is accepted for a challenge that advertises `[1]` only,
legacy is accepted, and the version-0 size limit is not applied.

## txv1-ts-x402-v1-policy

**Cases:** `vector/x402-verify-v1-compute-limit-over-cap-reject`
**SDKs:** typescript

The `@x402/svm` exact static path applies no compute unit cap unless
`maxComputeUnits` is configured, and neither the runner nor pay-kit
(`typescript/packages/pay-kit/src/config.ts`) sets it, so a version-1
`computeUnitLimit` of 400,001 is sponsored. scheme_exact_svm.md §2.2.1 gives
400,000 as the reference default (“Max compute units | `400,000`”), which
the Rust kit now applies. Fix: default `maxComputeUnits` to 400,000 in
pay-kit or upstream.

## txv1-go

**Cases:** the charge and x402 transaction-version vectors listed in `go.toml`
**SDKs:** go

No transaction-version negotiation: the Go SDK builds version 0 only
(`go/paycore/solanatx/solanatx.go` `NewV0Transaction`), `DecodeTransaction`
refuses every prefix but legacy and version 0, and no charge or x402 type
carries `transactionVersions`. Session wire vectors are unsupported (the Go
session types are on the superseded draft).

## txv1-python

**Cases:** the charge, session and x402 transaction-version vectors listed in `python.toml`
**SDKs:** python

No transaction-version negotiation: builders emit version 0, solders refuses
the version-1 prefix (`python/tests/test_server_v0_transactions.py`), and no
request type carries `transactionVersions`.

## txv1-swift

**Cases:** the charge and x402 transaction-version vectors listed in `swift.toml`
**SDKs:** swift

`TransactionVersion` models legacy and version 0 only
(`swift/Sources/SolanaPayKit/PayCore/Transaction.swift`); the client never
reads `transactionVersions`. Verify and session-wire vectors are unsupported
(client-only SDK, superseded session draft).

## txv1-php

**Cases:** the charge and x402 verify and wire vectors listed in `php.toml` (builds are unsupported: server-only SDK)
**SDKs:** php

Server-only SDK without transaction-version support: it decodes legacy and
version 0 only and reads no `transactionVersions`.

## txv1-ruby

**Cases:** the charge and x402 verify and wire vectors listed in `ruby.toml` (builds are unsupported: server-only SDK)
**SDKs:** ruby

Server-only SDK without transaction-version support: it decodes legacy and
version 0 only and reads no `transactionVersions`.

## txv1-lua

**Cases:** the charge and x402 verify and wire vectors listed in `lua.toml` (builds are unsupported: server-only SDK)
**SDKs:** lua

Server-only SDK without transaction-version support: it decodes legacy and
version 0 only and reads no `transactionVersions`.

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
- `@solana/pay-kit` exposes no upto distribution-hash or channel-PDA helper,
  so those two wire goldens are unsupported for TypeScript.
- `@solana/mpp` has no stateless subscription usability check and no
  subscriptions instruction encoder, so the `subscription-active-*` and
  `subscription-instruction-*` vectors are unsupported for TypeScript.
- The vendored `@x402/svm` exact, upto and batch facilitators accept a fixed
  transaction-version set (legacy, 0 and 1) with no option to narrow it, so
  the vectors that configure a sponsor with `[0]`
  (`input.x402ServerTransactionVersions`, `batchServer.transactionVersions`)
  are unsupported for TypeScript. The spec gives the sponsor's own set no
  default (“The sponsor enforces its own accepted set”), so those vectors
  state it.
- The TypeScript batch testee drives the stateless upstream facilitator, so
  the vectors whose verdict rests on the resource server's store record alone
  (`batchVerdictFromStore`, RULINGS B1: one-above, one-below, stale,
  close-pending, refund at an older cumulative) are unsupported for it.

## Reclassified on 2026-10-27

Findings that were the harness's, not the SDK's, and were closed by fixing
the vectors or adapters instead:

| Finding | Resolution |
| --- | --- |
| `x402-overpayment-rejected` (TS) | §3.1 “exact amount match” and §2.3 sponsor policy make an exact-amount sponsor conformant: `x402-exact-verify-overpayment-accept` also allows `reject amount-mismatch` (`expect.alsoConformant`) |
| `x402-priority-fee-product-uncapped` (Go, Python, Ruby, PHP, Lua, TS), `x402-channel-priority-fee-product-uncapped` (TS) | the 2,000 lamport cap on limit times price is pay-kit's stricter sponsor policy (RULINGS S6); the cap vectors also allow `accept` |
| `txv1-ts-x402-v1-policy` decimals half, `batch-ts-receiver-authorizer-missing-code`, server-mode `channelConfig` in `ts-batch-client-terms`, top-up trailing byte in `ts-batch-setup-reason-code` | the spec does not fix that verdict or code; the vectors list the other conformant verdict |
| `upto-client-blockhash-not-checked` | `extra.recentBlockhash` is a hint the client MAY use (“Pre-fetched blockhash so the client can build `openTransaction` without an RPC round trip.”); the vector pinned Rust policy and was removed |
| `ts-upto-open-size-unbounded`, `ts-upto-no-transaction-versions`, `ts-batch-transaction-versions` (client), the network half of `ts-batch-accepted-not-checked` | the vendored 2.28.0 implements them; the testee mis-mapped the reasons or ignored `batchClient.maxTransactionVersion` |
| `ts-batch-open-binding-memo` (client) | the client opens with the binding memo; the build judge required the caller's `openSlot` where the spec lets the client fetch the cluster slot or use `extra.recentSlot` |
| `txv1-ts-x402-fixed-accepted-set`, `ts-batch-facilitator-stateless` | declared limitations above (`[[unsupported]]`) |

## Fixed in the SDKs on 2026-10-27

| Finding | Fix |
| --- | --- |
| `ts-batch-setup-reason-code` (codes), `ts-batch-refund-cooperative` (sealed refund), `ts-batch-accepted-not-checked`, `batch-ts-receiver-authorizer-missing-code` | `@x402/svm` batch facilitator reports the spec 7 codes and compares `accepted` with the requirements (x402-foundation/x402 PR 3971, vendored at `d411aea1`) |
| `ts-charge-client-split-cap`, `charge-client-sol-token-program-ignored`, `charge-client-unknown-network`, `charge-client-amount-not-u64-validated`, `ts-charge-ata-empty-data-crash`, `session-open-initial-voucher-accepted`, the 1232-byte case of `txv1-ts-mpp-server-no-version-admission` | `@solana/mpp` charge client and server, session open schema |
| `python-x402-double-delivery`, the Python row of `x402-replay-route-missing`, `upto-settlement-funds-recipient-ata`, `session-open-initial-voucher-accepted` (Python), the session wire part of `txv1-python` | Python x402 server refuses a confirmed payment presented again (`signature_consumed`) and grants each confirmation once; the harness x402 server mounts the replay route; upto settlement creates only the payee and treasury accounts and the open is refused until every payout account is usable; session `methodDetails.transactionVersions` and the open-voucher refusal |
| Python `x402-upto` (suite unclaimed: 128 cases) | Python upto server and client follow the Rust kit (`python/src/solana_pay_kit/protocols/x402/upto/`): strict payload parse (`voucherSignature`/`type` refused, `nonce` decimal, `openSlot` number or string), `accepted` matched against the offer, `maxChannelLifetimeSecs` and the completion window, the channel-exists read, the open acceptance policy (layout, memo binding, 14 accounts and their privileges, whole `openArgs` decode, sponsored fee cap), the payer signature before the co-signature, a distinct receiver authorizer, and transaction versions 0/1 on both sides through `_paycore/txv1.py`; the client always emits a memo (declared or a 16-byte hex nonce), derives the salt from the request nonce and reads one `getLatestBlockhash` when a hint is missing |
| `subscription-ts-program-not-pinned`, `subscription-ts-currency-not-mint`, `subscription-ts-request-format`, `subscription-ts-plan-pullers-destinations`, `subscription-ts-recipient-ata`, `subscription-ts-push-mode`, `subscription-source-not-verified`, `subscription-ts-scope-accounts` | `@solana/mpp` subscription client and server |

## Subscription findings (`subscription-*.json`, 2026-10-21)

From the `subscription` vectors (draft-solana-subscription-00, pinned as
`external/mpp-specs-solana` at `5c4a528`). Paths are file:line at the commit
that recorded them. Rust divergences are recorded on the cases
(`authored(Some(reason))`), so fixing the kit fails the case until the note
is removed.

## subscription-source-not-verified

**Cases:** `vector/subscription-verify-source-other-address-reject`,
`vector/subscription-verify-source-other-method-reject`
**SDKs:** typescript (Rust fixed: `verify_credential_source` in
`rust/crates/kit/src/mpp/server/subscription.rs`)

“If source is present, servers MUST verify that it uses the did:pkh:solana:
method and that its address matches the subscriber signer extracted from the
activation transaction.” The TypeScript server does not read
`credential.source` (`typescript/packages/mpp/src/server/Subscription.ts:230`).
It derives the payer from the transaction, so payment is unaffected, but an
application that logs or keys on `source` trusts an unverified value.

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

## x402 batch-settlement findings (`x402-batch-settlement` vectors, 2026-10-21)

Recorded by the first run of the batch-settlement vector suite against the
pinned `scheme_batch_settlement_svm.md` (x402 @03b3919b) and the
transaction-version draft (x402-txv1 @3d723dd). The SDK sources were not
changed.

## batch-open-binding-memo

**Cases:** `batch-build-deposit-open`, `batch-build-terms-payment-flow-authorization`,
`batch-verify-open-accept`, `batch-verify-open-missing-binding-memo-reject`,
`batch-verify-open-foreign-binding-reject`,
`batch-verify-open-grace-period-mismatch-reject` (rust)

The spec binds every channel to one receiver authorizer at open: “The client's
open transaction carries, in addition to the seller/nonce Memo, a binding Memo
whose UTF-8 data is exactly:” `x402:batch-settlement:svm:rcvauth:v1:<key>`, and
the layout rule is “An `open` suffix also carries exactly one binding Memo
from section 3.” The Rust client emits the binding memo only for server-signed
channels (`x402/client/batch_settlement/payment.rs` `resolve_terms`), and the
server's `scan_channel_tx_layout` (`MemoPolicy::Required`) admits exactly one
memo, so it accepts an unbound open and refuses a conforming one with
`setup_transaction` at the memo scan, before decoding `grace_period` or the
binding key. The other open-path rejects (`diverting-distribution`,
`deposit-mismatch`, `stale-slot`, `future-slot`, `channel-pda-mismatch`)
therefore match by code only: Rust reaches the same `setup_transaction` at the
memo scan. They become discriminating once the server accepts the binding memo.

**Resolved in Rust:** the client adds the binding memo after the seller memo on
every open (both voucher modes), and the server's open policy
(`MemoPolicy::RequiredWithBinding`) requires exactly one seller memo and
exactly one binding memo, refusing a binding to any key other than its
`extra.receiverAuthorizer` with `receiver_authorizer_mismatch`. The server
always advertises a receiver authorizer (the fee payer's key unless
configured), and `check_channel_config` requires it on both sides. The kit
exposes `receiver_binding_memo` / `parse_receiver_binding_memo`.

## batch-refund-superseded-shape

**Cases:** `batch-build-refund`, `batch-verify-refund-*` (all but
`batch-verify-refund-with-amount-reject`), `batch-txv1-refund-v1-not-advertised-reject`,
`batch-wire-payload-refund-cooperative`,
`batch-wire-payload-refund-transaction-without-voucher-reject` (rust)

In the pinned spec a refund is a cooperative close by default: the client-mode
payload carries the accepted voucher (“| `voucher` | `BatchVoucher` | REQUIRED
in client mode.”), and the `request_close` transaction is “Omitted unless
retrying after `invalid_batch_settlement_svm_receiver_binding_unavailable`”.
The kit implements the superseded shape: `BatchPayload::Refund` requires
`transaction` and makes `voucher` optional, `build_refund` sends no voucher,
and the server refuses any refund carrying a voucher with `close_authorization`
(`check_no_cooperative_close`) while accepting one without. The
`request_close` envelope policy (`validate_request_close_transaction`) is
therefore unreachable with a conforming payload; the vectors pin the spec's
retry path (voucher plus transaction, binding unavailable).

**Resolved in Rust:** `BatchPayload::Refund` carries a `BatchRefund` whose
`RefundSigner` is exactly one of the client-mode voucher or the server-mode
proof (a refund with neither does not parse, under `payload_type`), with the
`request_close` transaction optional. `build_refund` builds the cooperative
refund (the accepted cumulative as a voucher) and `build_refund_request_close`
the retry. The server refuses a voucher other than its accepted cumulative
(`close_state`), a client-supplied `closeAuthorization`, a server-mode refund
(`payload_type`) and, without a transaction, a channel whose recorded
receiver binding is absent (`receiver_binding_unavailable`) or foreign;
otherwise it fences the record and closes cooperatively with
`settle_and_seal` plus the sealed `distribute`. The kit exposes
`close_authorization_digest`, `sign_close_authorization` and
`verify_close_authorization`.

## batch-claims-unbounded

**Cases:** `batch-wire-redemption-claim-empty-reject`,
`batch-wire-redemption-claim-five-entries-reject` (rust)

“`claims[]` MUST contain between one and four entries so the instruction pairs
fit in a legacy Solana transaction without address lookup tables.” The kit's
`BatchRedemptionPayload::Claim` is an unbounded `Vec`; the server never
receives a claim payload over the wire (it redeems through its own
`claim()`), so this only matters to a facilitator built on the wire type.

**Resolved in Rust:** `claims` and `channels` are a `RedemptionBatch`, whose
constructor and deserializer refuse fewer than one or more than four entries.

## batch-server-reject-codes

**Cases:** `batch-verify-accepted-{amount,pay-to,network}-mismatch-reject`,
`batch-verify-x402-version-1-reject`,
`batch-verify-top-up-{missing-receiver,frozen-payer}-ata-reject`,
`batch-txv1-top-up-v1-not-advertised-reject` (rust)

The Rust server refuses each of these for the right reason under another code.
`paymentPayload.accepted` differing from the route's requirements and a
non-v2 envelope come back as `channel_state` (the shared vocabulary uses
`accepted-mismatch` and `unsupported-version`, as for x402 `exact`). An
unusable settlement ATA comes back as `setup_transaction`; spec §7 names
`invalid_batch_settlement_svm_settlement_simulation` for “setup or
settlement-readiness simulation/checks failed before accepting the deposit”.
An unadvertised message version comes back as `setup_transaction`; x402-txv1
requires the facilitator to reject it “before inspecting any instruction,
with `unsupported_transaction_version`”.

**Resolved in Rust:** an `accepted` mismatch is `invalid_payment_requirements`
and a non-v2 envelope `invalid_x402_version` (the x402 v2 §9 standard codes;
the shared vocabulary maps them to `accepted-mismatch` and
`unsupported-version`, RULINGS B3), an unusable settlement ATA is
`settlement_simulation`, an unadvertised message version
`unsupported_transaction_version` (setup and `request_close` alike), and a
non-integer `extra.withdrawDelay` fails parsing with
`withdraw_delay_out_of_range`.

## batch-v1-loaded-limit-pinned

**Cases:** `batch-txv1-top-up-v1-loaded-limit-below-max` (rust)

x402-txv1: “`loadedAccountsDataSizeLimit` MUST be present”. The kit's
`DeclaredBudget::of` (`core/tx/budget.rs`) also requires it to equal the
runtime maximum (67108864), refusing a version-1 setup transaction that
declares a smaller limit. The spec sets presence, not a value, and lets a
sponsor tighten only the caps it names.

**Resolved in Rust (batch only):** the batch sponsor policy uses
`core::tx::check_v1_budget_caps_loaded_limit_present` (present, positive, at
most 67108864). `check_v1_budget_caps`, shared with MPP session and x402
`upto`, still pins the maximum
([upto-v1-loaded-limit-strict](#upto-v1-loaded-limit-strict)).

## batch-voucher-onchain-bindings

**Cases:** `batch-verify-voucher-onchain-closed-account-reject` (rust)

Phase 3 step 3 requires the channel to exist, be `Open`, and match
`payee == extra.feePayer`, the authorized signer, the grace period, the open
slot “and a distribution to `payTo` matching section 4.1”; a server MAY rely on
its mirrored snapshot only while it is fresh, and “A missing or stale snapshot
MUST fall through to facilitator verification”. The Rust server refreshes a
stale snapshot and re-checks the payer, payee, rent payer, authorizer, mint,
grace period, open slot and distribution hash, so a foreign payee or a
distribution that does not pay `payTo` is refused. It does not read the
account discriminator: an account carrying `ClosedChannel` still serves a
steady-state voucher.

**Resolved in Rust:** `decode_channel_account` refuses any account whose
discriminator is not `Channel` (1) with `channel_state`, so a refresh onto a
`ClosedChannel` account refuses the voucher.

### TypeScript: vendored upstream `@x402/svm` 2.28.0

pay-kit has no batch-settlement implementation of its own; the TypeScript
testee drives the upstream mechanism pay-kit bundles
(`typescript/.x402-vendor/x402-svm-2.28.0.tgz`, solana-foundation/x402
`feat/svm-client-transaction-v1` at `f7043a1`). It implements the
receiver-binding memo and SVM transaction versions; what remains is mostly
reason codes (the generic `transaction_failed` where the scheme names a
specific code, being fixed in x402-foundation/x402 PR 3971) and a few
unchecked rules, cross-checked against the same vectors as the Rust kit.

## ts-batch-refund-cooperative

**Cases:** `batch-verify-refund-sealed-channel-reject` (typescript)

The refund retry (voucher plus `request_close`, RULINGS B2) now verifies. A
refund for a channel the server already sealed is refused as
`invalid_batch_settlement_svm_channel_state`; the vector expects
`invalid_batch_settlement_svm_close_state` (“the channel cannot be closed, or a
cooperative voucher does not equal server state or is behind the channel's
onchain `settled` value”). The payment is refused; only the reason differs.

## ts-batch-setup-reason-code

**Cases:** `vector/batch-verify-top-up-frozen-payer-ata-reject` (typescript)

The reason codes this section used to track (`transaction_failed` for every
setup-transaction violation, `cumulative_amount_mismatch` for an over-deposit
voucher, a foreign binding reported as missing) are fixed in
x402-foundation/x402 PR 3971 (`56ff3cd5`, `d411aea1`). One top-up is still not
rejected at `/verify`: a payer return ATA that is frozen (“it MUST reject
before escrowing when a settlement account is missing, frozen, has the wrong
owner or mint”). `assertSettlementAccounts` checks only that the account
exists and its owner; the top-up simulation at settle would fail it.

## ts-batch-open-slot-window

**Cases:** `batch-verify-open-stale-slot-reject`, `batch-verify-open-future-slot-reject` (typescript)

Phase 1: “The facilitator MUST reject an expired transaction blockhash and an
`openSlot` outside the program's accepted window.” The batch facilitator's
`verify` compares `channelConfig.openSlot` with the open instruction only; it
never reads the cluster slot, so an open 1,501 slots stale or one slot in the
future is accepted and fails only when it lands.

## ts-batch-accepted-not-checked

**Cases:** `batch-verify-accepted-{amount,pay-to}-mismatch-reject` (typescript)

“For every request, `paymentPayload.accepted` MUST equal
`paymentRequirements`.” The facilitator compares `accepted` with the
requirements on scheme and network only (a network mismatch is refused as
`network_mismatch`, which the harness reads as `accepted-mismatch`), so an
amount or payTo mismatch is verified against `paymentRequirements` and
accepted.

## ts-batch-client-terms

**Cases:** `batch-build-deposit-payer-is-fee-payer-reject` (typescript)

The client opens a channel whose payer is the challenge's own `feePayer`
(“`channelConfig.payer` and `channelConfig.payerAuthorizer` MUST NOT equal
`extra.feePayer`.”).
