# Conformance findings

Known gaps referenced from `[[known_failing]]` entries by
`tracking = "FINDINGS.md#<anchor>"`. Each finding should become a GitHub issue;
when it does, replace the tracking value with the issue URL and delete the
section here.

## strict-unclosed-quoted-extension

**Case:** `protocol/challenge.parse :: adversarial_unclosed_quoted_extension`
**SDKs:** typescript, php

The canonical mpp-tools golden parses a `WWW-Authenticate: Payment` header
whose unknown extension auth-param has an unterminated quoted value by
ignoring that param. TypeScript (mppx: "Unterminated quoted-string.") and PHP
("Unterminated quoted value") reject the whole header with `parse_error`.
Both reject immediately, so neither is a ReDoS risk.

The canonical case is assigned to the Python adapter only. pay-kit runs it for
every SDK with a 5 s budget because ReDoS resistance matters to every parser.
The PHP divergence was never observed before 2026-10-20 because spawned
protocol runners only executed one smoke case per operation.

**Decision needed:** whether to follow the canonical lenient behaviour (accept,
drop the malformed param) or to propose the strict behaviour upstream. Until
then both SDKs are listed as known failing; a duration blowout on this case
fails CI regardless of the listing.

# Rust vector runner findings

Found on 2026-10-20 when the Rust vector runner
(`rust/crates/kit/examples/vector_runner.rs`) first ran the 54 vectors. The
runner calls only the kit's public API and injects no defaults. Several
findings are about the vectors and the reference runners, not about Rust.

## charge-precedence-twins-not-in-spec

**Cases:** `vector/charge-asset-over-currency-precedence`,
`vector/charge-payto-over-recipient-precedence`
**SDKs:** rust (known failing)

These vectors require a top-level `asset` to win over `currency` and `payTo`
to win over `recipient` in an MPP charge request. Neither field exists anywhere
in mpp-specs (`specs/intents/draft-payment-intent-charge-00.md`,
`specs/methods/solana/draft-solana-charge-00.md`); they are x402 names. The
TypeScript, Python and Go runners pass because each runner applies the
precedence itself in its `flattenRequest` helper before calling the SDK, so
the vectors test runner code. Rust parses the request with the kit's own
`ChargeRequest`, which ignores unknown fields as the spec allows.

**Decision needed:** delete the vectors, or specify the twins in mpp-specs and
implement them in every SDK (not in runners).

## charge-default-vectors-contradict-spec

**Cases:** `vector/charge-spl-field-omitted-defaults`,
`vector/charge-token2022-default-program-by-currency`
**SDKs:** rust (known failing)

`draft-solana-charge-00` `methodDetails`: `decimals` "MUST be present when
`currency` is a mint address", and when `tokenProgram` is omitted "clients
MUST determine the correct token program by fetching the mint account ... If
that lookup fails ... clients MUST reject the challenge rather than falling
back to the Token Program." The vectors omit both fields and expect an offline
build with `decimals = 6` and a currency-derived token program. Rust follows
the spec: it fetches the mint, the offline RPC refuses, and it rejects. The
TypeScript, Python and Go runners pass because the runners inject the defaults
(`flattenRequest`: "decimals default: 6", "default-by-currency") before calling
the SDK. Whether those SDKs apply the same fallback outside the runner was not
checked here.

**Decision needed:** rewrite the vectors to the spec (a reject vector for
missing decimals, a mint-owner RPC fixture for the token-program lookup), and
remove default injection from the runners.

## rust-refuses-payer-funded-split-ata

**Case:** `vector/charge-split-ata-memo-envelope-accept`
**SDKs:** rust (known failing)

When the client is the fee payer, the spec says clients "MUST include one [ATA
creation instruction] for each split whose entry sets `ataCreationRequired:
true`". The Rust builder refuses unless the caller sets
`BuildChargeTransactionOptions::allow_payer_funded_ata_creation`, because the
rent is spent on top of the charged amount. This is a deliberate Rust safety
default that contradicts the spec; the server-side verify half of the vector
therefore never runs for Rust.

**Decision needed:** align the spec with the safety default (servers must
sponsor split ATA rent, or the client MAY refuse), or flip the Rust default.

## x402-build-vectors-need-mint-decimals

**Cases:** `vector/x402-exact-v1-build-devnet`,
`vector/x402-exact-v1-build-mainnet-network-name`
**SDKs:** rust (known failing)

Both v1 offers carry no `extra.decimals`. The Rust client builds a real
`transferChecked`, so it reads the mint over RPC for decimals, which the
offline runner refuses. The vectors supply `x402PinnedTransaction` instead of a
mint fixture. The TypeScript reference passes because its runner never calls
the TypeScript SDK for x402: `harness/src/conformance/x402.ts`
`buildPaymentHeader` wraps the pinned (one-byte placeholder) transaction in a
harness-local envelope. The x402 build vectors therefore test that helper, not
any TypeScript SDK code.

**Decision needed:** add `extra.decimals` (or a mint RPC fixture) to the v1
offers, and drive the real TypeScript x402 client in the reference runner.

## rust-x402-server-ignores-payment-identifier

**Cases:** `vector/x402-ext-server-accepts-valid-id`,
`vector/x402-ext-server-rejects-required-missing-id`
**SDKs:** rust (unsupported)

The Rust x402 server types `PaymentExtensions` but has no configuration to
require a `payment-identifier` and never inspects `extensions` during verify
(`X402::verify_envelope_payload`). A route that advertises
`payment-identifier.info.required = true` accepts credentials without an id.
The Python runner calls the Python SDK's `verify_payment_identifier`; the
TypeScript runner uses a harness-local check in `harness/src/conformance/x402.ts`,
so TypeScript SDK enforcement is not covered either. Recorded as unsupported because the public
API cannot express the vector's server configuration.

## rust-charge-verifier-not-public

**Cases:** all `charge` `verify-transaction` vectors (informational)

Rust's pre-broadcast charge verifier
(`verify_versioned_transaction_pre_broadcast`) is crate-private. The runner
drives the public `Mpp::verify` instead: it mints a real HMAC challenge,
presents the vector's transaction and reports accept when the only failure is
the first network step ("Broadcast RPC error" against an unreachable RPC). The
x402 runner does the same against the vectors' placeholder transaction. This
works and exercises more of the real server, but a stage inferred from an error
message is brittle. Exposing the pure verifiers under the `testkit` feature
would let the runner call them directly.

# Interop findings (not yet reconciled)

Found on 2026-10-20 by running, locally against surfpool, every eligible
x402-exact pair that CI never runs (`interop-coverage.ts` lists them). Interop
claims are not in the expectations files yet, so these have no
`known_failing` entries; they are the input for that step. Go server cases
were excluded (the local checkout had no prebuilt Go server binary) and Kotlin
was not run (no JVM locally).

Result: 55 cases, 26 pass. Every failure falls into one of the classes below.

## go-x402-requires-protocol-field

The Go x402 client only selects `accepts` entries that carry
`"protocol": "x402"` (`go/protocols/x402/client/client.go`, `selectEntry`).
That field is not part of x402 v2 `PaymentRequirements`
(`x402-specification-v2.md` §5.1.2). Servers built on the pay-kit gate add it;
the Rust x402 server does not, so `go-x402 → rust-x402` gets a 402 and the
transport hands it back without paying. Verified directly: the same Rust offer
is rejected by `ParseChallengeVersionedWithExtensions` without the field and
accepted with it. Any strictly spec-conformant server is affected.

## ruby-x402-decimal-amount-on-wire

`ruby-x402-server` advertises `"amount": "0.001"` in its v2 offer. The Ruby
config (`ruby/lib/pay_kit/protocols/x402/server/exact.rb`) converts a price to
base units only when it starts with `$`; any other string is copied verbatim
onto the wire, and nothing checks that it is an integer. The harness passes the
human price, so Rust (`Invalid amount: 0.001`), Go, Python and Swift clients
all reject the offer. The dual-protocol `ruby` server is not affected.

## rust-x402-harness-server-ignores-resource-path

`rust/crates/harness-bins/src/bin/x402_harness_server.rs` hardcodes
`/protected` and ignores `X402_HARNESS_RESOURCE_PATH`, so the
`x402-exact-network-mismatch` and `x402-exact-cross-route-replay` scenarios get
404 instead of exercising the server. Adapter bug, not an SDK bug.

## ts-x402-adapters-are-stubs

The `ts-x402` client sends a v2 payload with no signed transaction, and the
`ts-x402` server returns a fabricated settlement id, accepts a mismatched
network, and advertises the v1 `maxAmountRequired` field inside a v2 offer.
Every pair involving either adapter fails, which is why CI never runs them: the
TypeScript x402 SDK has no interop coverage. `test/x402-exact.e2e.test.ts`
already notes "stub TS fixture; tracked follow-up".
