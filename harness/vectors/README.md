# Conformance vectors

Deterministic, RPC-free cross-SDK parity layer. Each vector is a single
declarative case that every SDK's conformance runner must agree on. The
driver (`harness/test/conformance.test.ts`) spawns one runner process per
SDK per vector over stdin/stdout and asserts the runner output against the
vector's `expect` block.

This layer exists to catch the parity divergences the surfpool matrix
structurally cannot: it only ever exercises canonical, all-fields-present,
happy-path offers, so field-omission defaults, top-level-vs-extra
precedence, compute caps, fee-payer guards, transferChecked decimals, and
canonical-byte encodings slip through green. The vectors encode those
divergence classes directly.

It does NOT replace on-chain settlement tests. Pure build/verify misses
RPC mint-owner resolution, real Token-2022 extension behavior, rent/ATA
effects, fee-payer lamport drain, simulation/broadcast failures, and
confirmation. Those stay in the surfpool matrix.

## Oracle

- `build-transaction` / `verify-transaction` (`intent: "charge"`): the
  oracle is the DECODED SEMANTIC SHAPE, not raw transaction bytes.
  Signatures and account ordering can legitimately differ across SDKs
  while still conforming.
- `build-transaction` / `verify-transaction` (`intent: "x402-exact"`):
  x402 is HTTP-shaped, not transaction-shaped. A client `build` produces
  a base64(JSON) payment header; a server `verify` consumes one. So the
  oracle is the DECODED ENVELOPE shape (`x402EnvelopeShape`), never the
  signed Solana transaction inside `payload.transaction` (that path is
  the surfpool harness matrix's job). See "x402-exact intent" below.
- `canonical-bytes`: the oracle IS exact bytes, because byte-for-byte
  agreement (canonical JSON / JCS, base64url, fixed-width byte encodings)
  is the whole point.

## Schema

Types live in `harness/src/conformance/schema.ts`. A vector:

```jsonc
{
  "id": "charge-spl-field-omitted-defaults",
  "intent": "charge",                 // "charge" | "x402-exact"
  "mode": "build-transaction",        // build-transaction | verify-transaction | canonical-bytes
  "description": "...",
  "input": {
    "request": {                      // decoded charge offer
      "amount": "1000",
      "currency": "<mint or 'sol'>",
      "recipient": "<pubkey>",
      // top-level precedence twins (win over methodDetails copies):
      "asset": "<mint>",
      "payTo": "<pubkey>",
      "computeUnitLimit": 200000,     // build-time overrides for cap rejects
      "computeUnitPrice": "1",
      "methodDetails": {
        "network": "localnet",
        "decimals": 6,                // omit to test the default (6)
        "tokenProgram": "...",        // omit to test default-by-currency
        "recentBlockhash": "11111111111111111111111111111111",
        "feePayer": false,
        "feePayerKey": "<pubkey>",
        "splits": [{ "recipient": "...", "amount": "250", "ataCreationRequired": true, "memo": "..." }]
      }
    },
    "transaction": "<base64 wire tx>", // verify-transaction: verify this instead of building
    "signerSecretKey": [/* 64-byte ed25519 */],
    "rpcFixtures": {
      "recentBlockhash": "...",
      "mintOwners": { "<mint>": "<token program>" }
    },
    "value": { /* canonical-bytes: JSON value to canonicalize */ },
    "encodeBase64Url": { "hexBytes": "00010203...", "utf8": "..." }
  },
  "expect": {
    "outcome": "accept",              // "accept" | "reject"
    "transactionShape": {             // accept build/verify
      "feePayer": "<pubkey>",
      "transfers": [
        { "kind": "spl", "destinationOwner": "<owner>", "mint": "...", "amount": "750", "decimals": 6, "tokenProgram": "..." },
        { "kind": "sol", "destination": "<pubkey>", "amount": "1000000" }
      ],
      "forbiddenPrograms": ["..."],
      "maxComputeUnitLimit": 200000,
      "maxComputeUnitPrice": "5000000",
      "memo": ["..."]
    },
    "exactBytes": { "canonicalJson": "...", "base64Url": "...", "bytes": [/* ints */] },
    "rejectReason": "..."             // reject: documentation only, not asserted
  }
}
```

Notes:

- Offline determinism: build/verify vectors must supply
  `methodDetails.recentBlockhash` (and either `methodDetails.tokenProgram`
  or `rpcFixtures.mintOwners`, or rely on default-by-currency) so the
  build path never reaches a live RPC.
- SPL transfers land in the recipient's ATA. Express the expected
  transfer with `destinationOwner`; the driver derives the ATA. SOL
  transfers use `destination` directly.
- `maxComputeUnitLimit` / `maxComputeUnitPrice` are upper bounds, asserted
  with `<=`.

## x402-exact intent

The x402 `exact` intent is a separate wire contract from MPP charge. The
canonical spine is `rust/crates/x402/src/{constants.rs,
client/exact/payment.rs, server/exact.rs,
protocol/schemes/exact/types.rs}`; the TS reference oracle mirrors it in
`harness/src/conformance/x402.ts`. There is no production TS x402 SDK in
this tree (`@solana/mpp` ships charge only), so that module IS the
contract every per-SDK x402 runner is validated against.

Two wire versions, both covered:

- **v2 (canonical)** — header `PAYMENT-SIGNATURE`. Envelope
  `{ x402Version: 2, accepted: <offer object>, payload: { transaction } }`.
  No top-level `scheme`/`network`. The `accepted` object echoes the
  selected offer: `{ scheme, network, amount, asset, payTo,
  maxTimeoutSeconds, extra }` (maxTimeoutSeconds defaults to 300, extra
  to `{}`).
- **v1 (legacy)** — header `X-PAYMENT`. Envelope
  `{ x402Version: 1, scheme: "exact", network: <legacy slug>, payload: { transaction } }`.
  NO `accepted`. The legacy network slug is `"solana-devnet"` for the
  devnet family, `"solana"` otherwise.

### x402 vector inputs

- `build-transaction`: `x402Version` (1 | 2), `x402Offer` (the selected
  offer), and `x402PinnedTransaction` (a deterministic base64 placeholder
  for the signed-tx proof — the oracle is the envelope, not the bytes).
  The runner emits the decoded `x402EnvelopeShape`.
- `verify-transaction`: `x402PaymentHeader` (the pinned base64
  PAYMENT-SIGNATURE / X-PAYMENT value) plus the server route
  (`x402ServerNetwork`, `x402ServerRecipient`, `x402ServerCurrency`,
  `x402ServerAmount`). The server accepts when the version is supported,
  the network matches, and (v2) the credential's `accepted` echoes the
  route's network/amount/recipient/asset.

#### v2 extensions inputs (echo-and-append)

- `build-transaction`: `x402AdvertisedExtensions` (the `extensions` object
  the server advertised on the inbound PAYMENT-REQUIRED — the client echoes
  it, preserving unknown keys verbatim and omitting an empty object) and
  `x402PaymentIdentifierId` (a pinned `pay_`-shaped id; when omitted and the
  advertised `payment-identifier` is `required`, the runner generates one).
- `verify-transaction`: `x402ServerRequiresPaymentIdentifier` (when true the
  route requires a `payment-identifier` id; the server rejects a credential
  that echoed no valid id). See `docs/x402/extensions-spec.md`.

### x402 oracle shape (`x402EnvelopeShape`)

`{ x402Version, scheme?, network?, hasAccepted, payloadHasTransaction,
acceptedScheme?, acceptedNetwork?, acceptedAsset?, acceptedPayTo?,
acceptedAmount?, hasExtensions?, hasPaymentIdentifier?,
paymentIdentifierRequired?, paymentIdentifierId?, extensionKeys? }`.
Presence is meaningful: a v2 build MUST set `hasAccepted: true` and omit
`scheme`/`network`; a v1 build MUST set `scheme: "exact"`, `network:
<slug>`, and `hasAccepted: false`. The extension fields pin echo-and-append:
`hasExtensions` is false when the server advertised none (no empty `{}`),
`extensionKeys` is the sorted key list so an unknown extension must survive,
and `paymentIdentifierId` (when pinned) is asserted exactly.

### x402 reject vocabulary

Two categories added to the shared `RejectCode` set:

- `unsupported-version` — `x402Version` is neither 1 nor 2.
- `wrong-network` — the credential's network (v1 slug or v2
  `accepted.network`) does not resolve to the server's configured network.
- `payment-identifier-required` — the route required a `payment-identifier`
  (`info.required = true`) but the credential echoed no valid `pay_`-shaped
  id (missing/empty/pattern-violating). Coinbase spec maps this to HTTP 400.

### x402 seeded vectors (this change)

`x402-build.json` + `x402-verify.json`, 3 vectors (EXACT v2 only; the
legacy v1 vectors ship separately):

- `x402-exact-v2-build` — v2 envelope shape, accepted echoes the offer.
- `x402-exact-v2-verify-accept` — server accepts a matching v2 credential.
- `x402-exact-unknown-version-reject` — `x402Version: 3` → reject
  `unsupported-version`.

`x402-extensions.json`, 6 vectors (v2 extensions echo-and-append; see
`docs/x402/extensions-spec.md`):

- `x402-ext-echo-payment-identifier` — echo advertised `payment-identifier`,
  generate a `pay_` id, keep `required`.
- `x402-ext-echo-payment-identifier-pinned-id` — deterministic id append
  without overwriting server `info.required`.
- `x402-ext-preserve-unknown-verbatim` — unknown extension survives verbatim
  alongside `payment-identifier`.
- `x402-ext-omit-when-none-advertised` — no advertised extensions → outbound
  omits `extensions` entirely (no empty `{}`).
- `x402-ext-server-accepts-valid-id` — server accepts a valid echoed id.
- `x402-ext-server-rejects-required-missing-id` — server rejects
  (`payment-identifier-required`) when required and no valid id.

Only the TS reference runner implements the x402 path today; the per-SDK
x402 runners are the tracked follow-up (each drives its own production
x402 SDK and is validated against this oracle).

## Runner contract

One CLI per SDK, identical stdin/stdout contract:

- stdin: one vector as JSON.
- stdout: one `RunnerResult` line as JSON (`{ id, outcome, transactionShape?, x402EnvelopeShape?, exactBytes?, error?, rejectCode? }`).
- A runner that cannot build/verify a vector emits `outcome: "reject"`
  with the SDK's error message in `error`.

The TS reference runner is `harness/src/conformance/ts-runner.ts`. It
drives the real `@solana/mpp` client build (`buildChargeTransaction`),
server verify (`verifyChargeTransaction`), and the JCS reference encoder.

## Seeded vectors (this change)

Vectors across the divergence classes from the audit:

- `charge-defaults.json` — field-omitted defaults (decimals=6, token
  program by currency), Token-2022-by-currency, SOL-native build.
- `charge-precedence.json` — top-level-vs-extra precedence (asset over
  currency, payTo over recipient).
- `charge-rejects.json` — compute-unit-price over 5_000_000 reject,
  fee-payer-as-authority reject, transferChecked decimals mismatch reject,
  splits-consume-amount reject.
- `charge-envelope.json` — full charge envelope accept (primary + split +
  idempotent ATA creation + memo).
- `canonical-bytes.json` — RFC 8785 JCS canonical JSON + base64url,
  48-byte base64url, UTF-8 base64url.
- `wire-bytes.json` — byte-exact canonical wire vectors. Five MPP charge
  challenge-id HMAC vectors (`base64url(HMAC-SHA256(secret, realm|method|
  intent|request|expires|digest|opaque))`, required-only through all-fields,
  mirroring rust `compute_challenge_id`) plus the x402 v2 PAYMENT-SIGNATURE
  and PAYMENT-REQUIRED envelope wire strings (canonicalized via the shared
  JCS path). These pin cross-SDK agreement byte-for-byte where the on-chain
  settlement oracle is blind to the header/id encoding. The `challengeId`
  input drives each SDK's production challenge-id derivation; the envelope
  wire vectors feed the envelope object through the `value` (JCS) path so the
  agreement reuses the canonicalizer all runners already conform on. The
  optional x402 `extra` map is omitted from the envelope vectors because an
  empty `{}` is indistinguishable from `[]` once decoded into a dynamically
  typed runner's untyped container; empty-map encoding is a separate concern
  from envelope wire agreement.

## Per-SDK runner follow-up

The TypeScript reference runner and the Lua server-only runner ship in
this layer. Each remaining SDK gets its own conformance runner CLI
honoring the same stdin/stdout contract, registered in the `RUNNERS`
table in `harness/test/conformance.test.ts`. Tracked follow-up, one per
SDK:

- Rust (`solana-mpp` / `solana-x402` conformance bin)
- Go (`go/...` conformance command)
- PHP (`php/...`)
- Ruby (`ruby/...`)
- Lua (`lua/cmd/conformance/main.lua`) — landed; server-only role
- Python (`python/...`)
- Swift (`swift/...`)
- Kotlin (`kotlin/...`)

Once a runner lands, the driver asserts it against every vector with no
vector changes: add the command to `RUNNERS` and the matrix expands
automatically.

### Role-restricted runners and `unsupported-mode`

Not every SDK plays every role. A server-only SDK (e.g. Lua) ships the
pre-broadcast verifier and the canonical encoders but no client-side
transaction builder, so it cannot run `build-transaction` vectors, nor
`verify-transaction` vectors that expect the runner to BUILD the
transaction first. For those a runner emits

```json
{ "id": "...", "outcome": "unsupported-mode", "error": "..." }
```

and the driver SKIPs (does not fail) that vector for that runner. This is
distinct from `reject`, which is a genuine, asserted policy decision. The
Lua runner therefore conforms to the 3 `canonical-bytes` vectors plus any
`verify-transaction` vector that ships a concrete `input.transaction`,
and skips the build-dependent rest.
