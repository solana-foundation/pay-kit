# x402 v2 Extensions — Porting Spec (payment-identifier + echo-and-append)

Authoritative, language-agnostic spec for porting the x402 v2 `extensions`
mechanism to every pay-kit SDK. The Rust crate under `rust/crates/x402` is
the reference; do not modify it. Every rule below quotes the canonical Rust
source (commit `90235392`, "feat(rust): add support for x402 extensions")
and the coinbase x402 spec it references
(`specs/extensions/payment_identifier.md`, x402 v2 §5.1.2 echo-and-append).

Conformance vectors live at `harness/vectors/x402-extensions.json` and run
RPC-free through the cross-SDK conformance driver
(`harness/test/conformance.test.ts`); the TS reference is
`harness/src/conformance/x402.ts`.

---

## 1. Wire shape

### 1.1 The `extensions` object rides on BOTH envelopes

`extensions?` is an optional object present on:

- the **challenge** (`PaymentRequired`) envelope carried in the
  `PAYMENT-REQUIRED` header — server → client.
  Rust: `PaymentRequiredEnvelope.extensions: Option<serde_json::Value>`
  (`protocol/schemes/exact/types.rs:458` — untyped passthrough on the
  challenge so a server may advertise any extension).
- the **credential** (`PaymentSignature`) envelope carried in the
  `PAYMENT-SIGNATURE` header — client → server.
  Rust: `PaymentSignatureEnvelope.extensions: Option<PaymentExtensions>`
  (`protocol/schemes/exact/types.rs:606-607`, with the doc-comment quoting
  §5.1.2: "the client must include at least the info received; it may
  append additional info but cannot delete or overwrite existing info").

Both fields are emitted only when present
(`#[serde(skip_serializing_if = "Option::is_none")]`), so an absent
extensions object is **omitted from the JSON**, never serialized as `null`
or `{}`.

### 1.2 `PaymentExtensions` shape

```
extensions: {
  "payment-identifier"?: {
    info: { required?: boolean, id?: string },
    schema?: <any JSON, echoed verbatim>
  },
  ...<other extensions, flattened, preserved verbatim>
}
```

Rust `PaymentExtensions` (`types.rs:514-527`):

- `payment_identifier: Option<PaymentIdentifierExtension>` is serialized
  under the **kebab-case** JSON key `payment-identifier`
  (`#[serde(rename = "payment-identifier")]`, `types.rs:519`). This is a
  hard rule: the key is `payment-identifier`, not `paymentIdentifier`.
- `other: BTreeMap<String, serde_json::Value>` is `#[serde(flatten)]`
  (`types.rs:526`): every extension this SDK does not type natively is
  captured here on parse and **re-emitted verbatim** on serialize.

`PaymentIdentifierExtension` (`types.rs:500-507`):

- `info: PaymentIdentifierInfo` (`#[serde(default)]`).
- `schema: Option<serde_json::Value>` — "JSON Schema published by the
  server describing the required client-side fields. Echoed verbatim per
  x402 v2 §5.1.2" (`types.rs:504-505`).

`PaymentIdentifierInfo` (`types.rs:483-493`), serialized **camelCase**:

- `required: Option<bool>` — server-side: whether clients MUST populate
  `id`. When `true` and `id` is missing, the server returns 400
  (`types.rs:484-485`).
- `id: Option<String>` — client-side idempotency key. "Must match
  `^[A-Za-z0-9_-]{16,128}$`" (`types.rs:488`).

Both `info` fields use `skip_serializing_if = "Option::is_none"`, so a
field that is `None` is omitted from the wire (an advertised
`payment-identifier` with only `required: true` serializes as
`{"info":{"required":true}}`, no `id` key).

Coinbase spec cross-check (`specs/extensions/payment_identifier.md`):
extension key `"payment-identifier"`; `info` carries `required` (boolean)
and `id` (string); `id` is `{ "type": "string", "minLength": 16,
"maxLength": 128 }` — exactly the Rust `^[A-Za-z0-9_-]{16,128}$` bound,
with a recommended `pay_` prefix.

---

## 2. The echo-and-append rule (client)

Rust `PaymentExtensions::echoing` (`types.rs:559-565`):

> Echo a server's inbound extensions blob into a typed `PaymentExtensions`.
> Returns `Ok(None)` when the inbound is `None`. Errors only if the inbound
> is not a JSON object.

The client builds the outbound `extensions` by:

1. **Take the inbound** challenge `extensions` object verbatim. If the
   server advertised none, the result is "no extensions" (Rust
   `echoing(None) -> Ok(None)`, `types.rs:561-563`).
2. **Preserve unknown extensions verbatim.** Anything the SDK does not
   recognize round-trips unchanged (Rust `other` flatten map). Verified by
   `payment_extensions_echoes_unknown_keys_verbatim` (`types.rs:1030-1043`:
   serialize round-trips byte-equal to the inbound).
3. **Populate required client-side fields** without overwriting server
   fields. For `payment-identifier`, set `info.id`; keep `info.required`
   and `schema` as received. Rust
   `PaymentExtensions::with_payment_identifier_id`
   (`types.rs:548-553`): `get_or_insert_with(Default)` then
   `entry.info.id = Some(id)`. Verified by
   `with_payment_identifier_id_appends_without_overwriting_server_fields`
   (`types.rs:1063-1085`).
4. **Omit an empty extensions object.** A conforming outbound never carries
   `extensions: {}`. Rust gates this with
   `PaymentExtensions::is_empty` (`types.rs:533-535`: no
   `payment_identifier` and empty `other`) combined with the envelope's
   `skip_serializing_if = "Option::is_none"`. Pass `None` to
   `build_payment_header` when the server advertised nothing.

Client entry point: Rust `build_payment_header(signer, rpc, requirements,
extensions: Option<PaymentExtensions>)`
(`client/exact/payment.rs:125-141`): the new fourth parameter is the echoed
extensions, written straight onto `PaymentSignatureEnvelope.extensions`
(`payment.rs:146`). The legacy v1 path passes `extensions: None`
(`payment.rs:166`) — v1 never carries extensions.

### 2.1 `payment-identifier` id generation

Rust `generate_payment_identifier_id` (`types.rs:575-585`):

- `pay_` prefix + 16 CSPRNG bytes rendered as 32 lowercase hex chars
  (36 chars total).
- Satisfies the spec pattern `^[A-Za-z0-9_-]{16,128}$` and the canonical
  Solana `^pay_[a-zA-Z0-9_-]{10,120}$` shape.
- Callers MUST reuse the same id across retries of the same logical request
  so the server can return a cached 200 instead of charging twice
  (`types.rs:572-574`; coinbase spec idempotency table).

Verified by `generate_payment_identifier_id_matches_spec_pattern`
(`types.rs:1006-1017`): `pay_` prefix, 32-char suffix, all chars in
`[A-Za-z0-9_-]`, total length 16..=128.

---

## 3. Server rules

### 3.1 Advertising on the challenge

The server sets `PaymentRequiredEnvelope.extensions` on the 402 to
advertise an extension. For `payment-identifier`, advertise
`{"payment-identifier":{"info":{"required":<bool>},"schema":<optional>}}`.
The Rust challenge field is an untyped `serde_json::Value`
(`types.rs:458`), so a server may advertise any extension object; default
`required` is `false` per the coinbase spec (omit or set `false` when the
id is optional).

### 3.2 `requires_payment_identifier()`

Rust `PaymentExtensions::requires_payment_identifier`
(`types.rs:538-543`): true iff
`payment-identifier.info.required == Some(true)`.

### 3.3 Reject-when-required-and-missing

When the route requires a `payment-identifier` (`info.required == true`)
and the credential did **not** echo a valid id, the server rejects.

- A valid id is present and matches `^[A-Za-z0-9_-]{16,128}$`.
- Missing, empty, or pattern-violating ids are rejected.
- Coinbase spec: this is **HTTP 400 Bad Request** (idempotency table).
  In the conformance layer it maps to the reject category
  `payment-identifier-required`.

This gate runs in addition to the existing accepted-vs-route field checks
(network / amount / recipient / currency) in Rust
`verify_envelope_payload` (`server/exact.rs:476-542`). The Rust crate at
this commit wires the typed surface and the client echo; the server-side
required-id reject is a spec rule each SDK must implement at its credential
parse site (the reference enforcement lives in the conformance oracle,
`harness/src/conformance/x402.ts` `verifyPaymentHeader`).

---

## 4. JSON casing summary

| Path | Casing | Rule source |
|---|---|---|
| `extensions` | literal | envelope field, `types.rs:458` / `606` |
| `extensions["payment-identifier"]` | kebab-case literal | `serde(rename)`, `types.rs:519` |
| `…["payment-identifier"].info` | camelCase | `types.rs:501` |
| `…info.required` / `…info.id` | camelCase | `types.rs:485` / `491` |
| `…["payment-identifier"].schema` | camelCase | `types.rs:504` |
| unknown extension keys | preserved verbatim | flatten, `types.rs:526` |

Everything except the kebab-case `payment-identifier` key follows the
crate-wide `#[serde(rename_all = "camelCase")]`.

---

## 5. Conformance vectors

`harness/vectors/x402-extensions.json` (6 vectors, RPC-free, oracle =
decoded envelope shape + accept/reject):

| id | mode | asserts |
|---|---|---|
| `x402-ext-echo-payment-identifier` | build | client echoes advertised `payment-identifier`, generates a `pay_`-shaped id, keeps `required` |
| `x402-ext-echo-payment-identifier-pinned-id` | build | deterministic id append without overwriting server `info.required` |
| `x402-ext-preserve-unknown-verbatim` | build | unknown `future-extension` survives verbatim alongside `payment-identifier` (echo-and-append) |
| `x402-ext-omit-when-none-advertised` | build | no advertised extensions → outbound omits `extensions` entirely (no empty `{}`) |
| `x402-ext-server-accepts-valid-id` | verify | server ACCEPTS when a valid id is echoed |
| `x402-ext-server-rejects-required-missing-id` | verify | server REJECTS (`payment-identifier-required`) when required and no valid id |

The envelope-shape oracle gained these pinned fields (schema.ts
`X402EnvelopeShape`): `hasExtensions`, `hasPaymentIdentifier`,
`paymentIdentifierRequired`, `paymentIdentifierId`, `extensionKeys`. A
build that emits an empty `extensions: {}`, drops an unknown extension, or
overwrites server `info` fails the vector.

---

## 6. Per-SDK porting map

Where each SDK builds the `PAYMENT-SIGNATURE` credential (add the echo) and
where it parses the credential / builds the challenge (advertise + reject).
Roles: **both** = client echo + server advertise/reject; **client-only** =
echo only; **server-only** = advertise/reject only.

| SDK | Role | Client: build credential envelope (add echo) | Server: build challenge + parse credential (advertise + reject) |
|---|---|---|---|
| **rust** (reference, do not modify) | both | `client/exact/payment.rs:125` `build_payment_header(..., extensions)` → envelope field `payment.rs:146` | challenge `server/exact.rs:176` `exact_with_options` (`extensions` field); parse `server/exact.rs:307` `parse_payment_signature` + reject in `verify_envelope_payload` `server/exact.rs:476` |
| **typescript** | both | `harness/src/conformance/x402.ts` `buildPaymentHeaderV2` (+ `echoExtensions` / `withPaymentIdentifierId`). Production `@solana/mpp` ships charge only today; the conformance x402 module is the reference path. | `x402.ts` `verifyPaymentHeader` (extensions reject gate); challenge advertised in the fixture server `harness/src/fixtures/typescript/exact-server.ts` `encodePaymentRequiredHeader` |
| **go** | both | `go/protocols/x402/client/client.go:181` `BuildPaymentHeader` → `x402.Credential` struct `go/protocols/x402/x402.go:344` (add an `Extensions` field) | challenge `go/protocols/x402/x402.go:172` `ChallengeEnvelope` + `:184` `ChallengeHeaders` (add `extensions`); credential parse `go/protocols/x402/x402.go:199` `VerifyAndSettle` (add required-id reject) |
| **python** | both | No x402 module yet (`python/src/solana_mpp` ships MPP charge/session only). Land x402 alongside it; mirror the rust client envelope build and the server parse/challenge. | same: new `python/src/solana_mpp/...x402` server build-challenge + parse-credential paths |
| **ruby** | server-only | n/a (no x402 client builder in tree) | challenge `ruby/lib/pay_kit/protocols/x402/server/exact.rb` `exact_challenge` (advertise `extensions`); credential parse `decode_payment_signature` + verify (required-id reject). Types: `ruby/lib/pay_kit/protocols/x402/protocol/schemes/exact/types.rb` |
| **php** | server-only | n/a | challenge `php/src/Protocols/X402/Adapter.php:173` `challengeHeaders` (add `extensions` to `$challenge`); credential parse `php/src/Protocols/X402/Adapter.php:185` `verifyAndSettle` (decode `extensions`, required-id reject) |
| **lua** | server-only | n/a | challenge `lua/pay_kit/protocols/x402/init.lua:141` `exact_challenge` (add `extensions`); credential parse `:156` `decode_payment_signature` + `:188` verify path (required-id reject) |
| **swift** | client-only | `swift/Sources/SolanaMpp/Protocol/Models.swift` (envelope models) + `Client/Charge.swift` (header build). x402 path not yet present; add the echo when porting x402 (per the kotlin/swift unified-port plan). | n/a |
| **kotlin** | client-only | `kotlin/src/main/kotlin/com/solana/mpp/protocol/Models.kt` (envelope models) + `client/Charge.kt` (header build). x402 path not yet present; add the echo when porting x402. | n/a |

Notes:

- **Omit-empty discipline:** every client builder must drop the
  `extensions` key entirely when the echoed object is empty. In Go/PHP/etc.
  this means a pointer/nullable field with omit-empty semantics, not an
  always-present empty map.
- **Unknown-key preservation:** parse the inbound `extensions` into a
  structure that retains unrecognized keys (a flatten map / raw JSON
  object), so the echo re-emits them verbatim. A struct that only models
  `payment-identifier` and drops the rest violates §5.1.2.
- **Casing:** the `payment-identifier` key is kebab-case; `info`,
  `required`, `id`, `schema` are camelCase. Pin this in each SDK's
  serializer config.
