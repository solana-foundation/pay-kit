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

Open findings from the x402 `upto` (SVM) vectors (`x402-upto-*.json`,
2026-10-21). Rust is driven through
`x402::server::upto::testkit::verify_open_pre_broadcast` (the pre-broadcast
half of `X402Upto::verify_open_for_route`, co-signature included);
TypeScript through the vendored `@x402/svm` 2.26.0 upto facilitator's
read-only `verify` (pay-kit's `X402Upto.verifyOpen` calls `settle`, which
broadcasts). Each Rust divergence is also recorded on its registry entry
(`authored(Some(reason))`).

## upto-client-settle-fields-accepted

**Cases:** `vector/x402-upto-verify-client-voucher-reject`, `-client-voucher-empty-reject`, `-client-type-reject`
**SDKs:** rust

scheme_upto_svm.md Phase 3 step 0: “voucherSignature is claim-only and
server-owned; presence on the client payload (including an empty string or
undefined value) MUST fail with invalid_upto_svm_payload_unexpected_voucher”,
and for `type` “presence on the client payload MUST fail with
invalid_upto_svm_payload_type”. `UptoPayload`
(`rust/crates/kit/src/x402/protocol/schemes/upto/types.rs`) models neither
field and serde drops unknown keys, so `prepare_open`
(`rust/crates/kit/src/x402/server/upto.rs:566`) accepts both.

## upto-lifetime-unbounded

**Cases:** `vector/x402-upto-verify-expires-beyond-timeout-reject`, `-timeout-over-lifetime-reject`, `-expires-over-lifetime-reject`
**SDKs:** rust

Phase 3 step 7: “Reject when maxTimeoutSeconds or remaining expiresAt - now
exceeds the facilitator's maxChannelLifetimeSecs, or when expiresAt is later
than now + maxTimeoutSeconds (plus clock skew).” `verify_upto_payload`
(`rust/crates/kit/src/x402/protocol/schemes/upto/verify.rs:21`) checks only
`validAfter <= now < expiresAt`, and `UptoConfig` has no lifetime ceiling. A
client can authorize a channel whose voucher deadline is days out; abandon-close
MUST NOT run before `expiresAt`, so the sponsor's rent stays locked.

## upto-channel-exists-not-checked

**Case:** `vector/x402-upto-verify-channel-already-open-reject`
**SDKs:** rust, typescript

Phase 3 step 4: “Confirm the channel account does not already exist. If it
does, reject with invalid_upto_svm_channel_already_open.” (RULINGS U2.) Rust
co-signs without reading the channel account (`prepare_open`); the vendored
TS facilitator checks it only in `settle` (deposit), not in `verify`
(`typescript/external/x402/typescript/packages/mechanisms/svm/src/upto/facilitator/scheme.ts:400`).

## upto-payer-signature-not-verified

**Cases:** `vector/x402-upto-verify-missing-payer-signature-reject`, `-invalid-payer-signature-reject`
**SDKs:** rust

“The payload.from signature MUST be present and valid before the facilitator
signs.” Neither `prepare_open` nor `cosign_fee_payer` verifies the payer's
slot, so the sponsor co-signs (and in production broadcasts, paying the fee)
a transaction that cannot land.

## upto-signer-set-not-checked

**Case:** `vector/x402-upto-verify-extra-signer-reject`
**SDKs:** rust

“The complete required-signer set MUST equal the distinct addresses in {
payload.from, extra.feePayer }.” The vector adds a third required signer on
the Memo. `scan_channel_tx_layout`
(`rust/crates/kit/src/core/payment_channel/v1.rs:986`) checks wrapper accounts
only for the fee payer. Same class as `x402-extra-required-signer-accepted`.

## upto-open-privileges-not-checked

**Cases:** `vector/x402-upto-verify-writable-mint-reject`, `vector/x402-upto-verify-open-extra-account-reject`
**SDKs:** rust

“contain exactly the following 14 account positions in order, and contain no
remaining accounts” and “No account outside the writable roles in the table
(including an intentional equal-key union) may be writable.”
`validate_open_instruction` (`rust/crates/kit/src/x402/server/upto.rs:1384`)
compares the keys at positions 0 to 13 and ignores both writable flags and a
fifteenth account.

## upto-second-memo-refused

**Case:** `vector/x402-upto-verify-two-memos-unbound-accept`
**SDKs:** rust

The suffix is “at most four instructions, each invoking either Lighthouse ...
or SPL Memo”; exactly one Memo is required only “If extra.memo is present”.
`scan_channel_tx_layout` refuses a second Memo under `MemoPolicy::Optional`
(`rust/crates/kit/src/core/payment_channel/v1.rs:1107`). Stricter than the
spec; a wallet that adds its own memo to an unbound open is refused.

## upto-seed-fields-textual

**Cases:** `vector/x402-upto-verify-nonce-not-decimal-reject`, `-open-slot-not-decimal-reject`
**SDKs:** rust

`nonce` is a “Unique decimal u64 salt”. Rust compares `payload.nonce` and
`payload.openSlot` with the decoded open arguments as text and reports a
binding mismatch (`open-binding-mismatch`) instead of a malformed payload
(`invalid-payload`).

## upto-slot-wire-type

**Cases:** `vector/x402-upto-verify-open-slot-number-accept` (rust, typescript), `vector/x402-upto-build-recent-slot-number` (rust)
**SDKs:** rust, typescript

The pinned §4.2 table types `openSlot` as `number`, §4.1 types `recentSlot` as
`number`, and both §4.1 examples carry `"recentSlot": 341000000`. Every SDK
emits and requires decimal strings: Rust `UptoPayload.open_slot` and
`UptoExtra.recent_slot` are `String`
(`rust/crates/kit/src/x402/protocol/schemes/upto/types.rs:62`, `:168`), so the
spec's own example challenge fails to parse and the Rust client cannot pay
it; TS `isUptoSvmPayload` requires a string `openSlot`
(`typescript/external/x402/typescript/packages/mechanisms/svm/src/types.ts:79`).
See RULINGS U1; the fix is upstream spec text or parsers that accept both.

## upto-client-memo-nonce-missing

**Case:** `vector/x402-upto-build-memo-nonce`
**SDKs:** rust

“Clients MUST include a Memo instruction containing either the value of
extra.memo (when present) or a random nonce (at least 16 bytes, hex-encoded
for UTF-8 compliance).” `build_upto_payload`
(`rust/crates/kit/src/x402/client/upto/payment.rs:103`) emits a Memo only when
the challenge declares one, so two opens with identical parameters are
byte-identical.

## upto-v1-loaded-limit-strict

**Case:** `vector/x402-upto-verify-v1-small-loaded-limit-accept`
**SDKs:** rust (typescript fails it under `ts-upto-no-transaction-versions`)

x402-txv1 scheme_upto_svm.md: “loadedAccountsDataSizeLimit MUST be present”.
`check_v1_budget_caps` (`rust/crates/kit/src/core/tx/policy.rs:131`) requires
it to equal 64 MiB and rejects a version-1 open that budgets less loaded data.

## ts-upto-open-trailing-bytes

**Case:** `vector/x402-upto-verify-open-trailing-byte-reject`
**SDKs:** typescript

“The facilitator MUST fully decode the canonical open instruction data, reject
truncated data or trailing bytes”. `verifyOpenTransaction` decodes the args
with `getOpenInstructionDataDecoder().decode`
(`typescript/external/x402/typescript/packages/mechanisms/svm/src/payment-channels/open.ts:969`),
which ignores bytes past the arguments. The fix belongs in the x402 fork.

## ts-upto-open-size-unbounded

**Case:** `vector/x402-upto-verify-v0-oversize-reject`
**SDKs:** typescript

x402-txv1 scheme_upto_svm.md: “A legacy or version-0 transaction MUST NOT
exceed 1232 serialized bytes”. The vendored `verifyOpenTransaction` never
measures the transaction, so an oversize open is accepted and only fails at
broadcast.

## ts-upto-no-transaction-versions

**Cases:** every `x402-upto-txv1.json` vector that builds or verifies a version-1 open, plus `vector/x402-upto-build-no-common-version-reject`
**SDKs:** typescript

The vendored `@x402/svm` 2.26.0 (`typescript/external/x402` at 03b3919b)
predates transaction-version negotiation, x402-foundation/x402 PR 3710 (branch
`feat/svm-transaction-versions-upto`), which implements the x402-txv1 draft
(PR 3473). Its client builds version 0 whatever `extra.transactionVersions`
advertises, and its facilitator cannot decode a version-1 message (it throws
reading the absent lookup-table list), so neither
`unsupported_transaction_version` nor the version-1 budget rules are reachable.
Resolved by bumping the vendored x402 packages once PR 3710 lands.
## txv1-rust-legacy-accepted

**Cases:** `vector/charge-verify-legacy-reject`, `vector/charge-verify-legacy-default-reject`, `vector/session-open-legacy-reject`
**SDKs:** rust

The MPP txv1 draft (draft-solana-charge-00, Transaction Versions): “Legacy
messages are not supported: servers MUST NOT advertise "legacy" and MUST
reject a legacy message.” The kit polices a legacy message as version 0
(`rust/crates/kit/src/core/tx/version.rs`, `TxVersion::of`) and its charge
verifier accepts one wherever version 0 is accepted. That reading matches
x402 (§1.5, a facilitator MAY keep accepting legacy), not MPP. The fix is a
protocol-aware envelope check: MPP charge and session refuse
`VersionedMessage::Legacy`; x402 keeps the tolerance.

## txv1-rust-empty-advertisement

**Cases:** `vector/charge-build-empty-advertisement-reject`, `vector/x402-build-empty-advertisement-reject`
**SDKs:** rust

`transactionVersions: []` is read as the absent default `[0]`
(`core::tx::accepted_versions`) and the client builds version 0. Only an
omitted field defaults (RULINGS T2); x402 §1.5: “It MUST fail with
unsupported_transaction_version when the intersection is empty.”

## txv1-rust-x402-legacy-offer-code

**Case:** `vector/x402-build-legacy-only-reject`
**SDKs:** rust

An offer whose `extra.transactionVersions` is `["legacy"]` fails to parse
(`PaymentRequirements` deserialization, `invalid-payload`). §1.5 says the
client intersects and, legacy never being buildable, fails with
`unsupported_transaction_version`. The refusal is right; the code is not.

## txv1-rust-x402-budget-codes

**Case:** `vector/x402-verify-v1-missing-loaded-data-limit-reject`
**SDKs:** rust

`verify_exact_versioned_transaction`
(`rust/crates/kit/src/x402/protocol/schemes/exact/verify.rs`) maps every
`check_v1_budget_caps` error to
`invalid_exact_svm_payload_transaction_instructions_compute_price_instruction_too_high`,
so a version-1 header without `loadedAccountsDataSizeLimit` (or with a zero
limit) is reported as a price-cap violation. The transaction is rejected;
only the reason is wrong.

## txv1-rust-x402-advertisement-fixed

**Cases:** `cross/x402-build-v0-advertised/*/rust`, `cross/x402-build-duplicate-advertisement/*/rust`
**SDKs:** rust

§1.5: “the server MUST copy that value into
PaymentRequirements.extra.transactionVersions.” The kit's x402 server
generates the field itself from `TxV1Mode` (`core::tx::advertised`): `[0, 1]`
or nothing. Fronting a facilitator that advertises `[0]` (or `[1, 0, 1]`),
its route carries a different value than the offer the client echoed, and
the accepted match (“a hint the credential does echo must still equal the
route's”, `rust/crates/kit/src/x402/server/exact.rs` `drop_hints_not_echoed`)
refuses a valid payment. The builds verify against a route that copies the
offer's value (the build judge's sponsor).

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

## txv1-ts-x402-pre-3474

**Cases:** `vector/x402-build-v1-advertised`, `vector/x402-build-duplicate-advertisement`, `vector/x402-build-empty-advertisement-reject`, `vector/x402-build-legacy-only-reject`, `vector/x402-verify-v1-not-accepted-reject`, `vector/x402-verify-v1-explicit-v0-sponsor-reject`
**SDKs:** typescript

The vendored x402 (`typescript/external/x402` @03b3919b) predates
x402-foundation/x402 PR 3474 (feat/svm-transaction-versions-exact). The exact
client ignores `extra.transactionVersions` (always version 0, never
refuses), and the facilitator has no version gate: a version-1 transaction
fails as `invalid_exact_svm_payload_signature_invalid` instead of
`unsupported_transaction_version`. PR 3474 adds the gate and the client
intersection but advertises `[0]` only; version 1 itself is not implemented
upstream yet, so the version-1 accept and policy vectors stay
`[[unsupported]]` (no accepted-version set to configure) until it is.

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

## batch-claims-unbounded

**Cases:** `batch-wire-redemption-claim-empty-reject`,
`batch-wire-redemption-claim-five-entries-reject` (rust)

“`claims[]` MUST contain between one and four entries so the instruction pairs
fit in a legacy Solana transaction without address lookup tables.” The kit's
`BatchRedemptionPayload::Claim` is an unbounded `Vec`; the server never
receives a claim payload over the wire (it redeems through its own
`claim()`), so this only matters to a facilitator built on the wire type.

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

## batch-v1-loaded-limit-pinned

**Cases:** `batch-txv1-top-up-v1-loaded-limit-below-max` (rust)

x402-txv1: “`loadedAccountsDataSizeLimit` MUST be present”. The kit's
`DeclaredBudget::of` (`core/tx/budget.rs`) also requires it to equal the
runtime maximum (67108864), refusing a version-1 setup transaction that
declares a smaller limit. The spec sets presence, not a value, and lets a
sponsor tighten only the caps it names.

## batch-voucher-onchain-bindings

**Cases:** `batch-verify-voucher-onchain-{closed-account,payee,distribution,empty-distribution}-reject` (rust)

Phase 3 step 3 requires the channel to exist, be `Open`, and match
`payee == extra.feePayer`, the authorized signer, the grace period, the open
slot “and a distribution to `payTo` matching section 4.1”; a server MAY rely on
its mirrored snapshot only while it is fresh, and “A missing or stale snapshot
MUST fall through to facilitator verification”. The Rust server refreshes a
stale snapshot in `reconcile_channel` for status, deposit, settled and close
only; `check_channel_bindings` runs only after a deposit confirms. An account
with the `ClosedChannel` discriminator, a foreign payee, or a distribution
hash that does not pay `payTo` therefore serves a steady-state voucher.

### TypeScript: vendored upstream `@x402/svm` 2.26.0

pay-kit has no batch-settlement implementation of its own; the TypeScript
testee drives the upstream mechanism pay-kit bundles
(`typescript/.x402-vendor/x402-svm-2.26.0.tgz`). That tarball was packed
before the pinned spec commit (it has no receiver-binding memo, no `seal`,
no transaction versions), so most of these are the tarball lagging the spec,
cross-checked against the same vectors as the Rust kit.

## ts-batch-open-binding-memo

**Cases:** `batch-build-deposit-open`, `batch-build-terms-payment-flow-authorization`,
`batch-verify-open-*` (typescript)

Same rule as [batch-open-binding-memo](#batch-open-binding-memo): the client
opens without the binding memo and `verifyOpenTransaction` reports “expected
exactly one Memo instruction matching extra.memo, found 2” for the spec's open
(under the generic `transaction_failed` reason).

## ts-batch-transaction-versions

**Cases:** `batch-txv1-top-up-*`, `batch-build-version-intersection-empty-reject` (typescript)

The tarball predates SVM transaction versions (x402-foundation/x402 PR 3473,
pinned as `external/x402-txv1`). A version-1 top-up crashes verification
(“Cannot read properties of undefined (reading 'length')”), a version-0 top-up
over 1232 serialized bytes is accepted, and the client builds version 0 for a
challenge that advertises only `[1]`.

## ts-batch-refund-cooperative

**Cases:** `batch-verify-refund-*`, `batch-txv1-refund-v1-not-advertised-reject`,
`batch-wire-payload-refund-*` (typescript)

The facilitator refuses a refund carrying the voucher with
`close_authorization` (“cooperative close requires a trusted server binding”)
instead of falling back to the `request_close` retry the pinned spec defines
for an unavailable binding, and accepts a client-mode refund without the
voucher. `isBatchPayload` applies the same superseded shape.

## ts-batch-setup-reason-code

**Cases:** `batch-verify-top-up-*` (typescript)

Every static policy violation of a top-up comes back as
`transaction_failed: verifyTopUpTransaction: …` / `verifyOpenTransaction: …`
instead of `invalid_batch_settlement_svm_setup_transaction` (spec §7: “setup
transaction fails the sponsor safety checks”). Two are not rejected at all: a
`top_up` with a trailing data byte (“The facilitator MUST fully decode the
instruction data, reject truncated data or trailing bytes”) and a top-up
whose payer return ATA is frozen (“it MUST reject before escrowing when a
settlement account is missing, frozen, has the wrong owner or mint”). A
voucher over the topped-up ceiling is `cumulative_amount_mismatch`, not
`cumulative_exceeds_deposit`. The accepting top-up and voucher cases, and the
onchain binding rejects of `batch-voucher-onchain-bindings`, pass.

## ts-batch-facilitator-stateless

**Cases:** `batch-verify-voucher-{one-above,one-below,stale}-reject`,
`batch-verify-voucher-close-pending-in-store-reject` (typescript)

RULINGS.md B1: the vectors judge the resource server's Phase 3 rule against
its stored `chargedCumulativeAmount`; the upstream facilitator the testee
drives is stateless and applies only the onchain floor. Upstream's resource
server (`BatchSvmScheme` server hooks) holds that state, but has no
single-shot entry point the vector ABI can drive.

## ts-batch-accepted-not-checked

**Cases:** `batch-verify-accepted-{amount,pay-to,network}-mismatch-reject` (typescript)

“For every request, `paymentPayload.accepted` MUST equal
`paymentRequirements`.” The facilitator verifies against
`paymentRequirements` without comparing `accepted` (amount and payTo
mismatches are accepted) and reports a network mismatch as `network_mismatch`.

## ts-batch-client-terms

**Cases:** `batch-build-deposit-payer-is-fee-payer-reject`,
`batch-verify-voucher-server-mode-config-reject` (typescript)

The client opens a channel whose payer is the challenge's own `feePayer`
(“`channelConfig.payer` and `channelConfig.payerAuthorizer` MUST NOT equal
`extra.feePayer`.”). A `channelConfig.voucherSigner` that disagrees with the
route is reported as `payload_type`; the vectors use `channel_state`, the
code for a channel configuration that does not match the requirements.
