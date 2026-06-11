# x402 EXACT v1 (legacy) wire contract for pay-kit

Language-agnostic spec for the legacy x402 `exact` scheme on Solana/SVM, as
pay-kit implements it. The **Rust spine is the source of truth**: every rule
below cites the rust file:line it mirrors. Where the upstream coinbase x402
spec (Apache-2.0) and the rust spine disagree, **rust wins** and the
divergence is flagged inline.

x402 v1 and v2 are two **separate parallel wire shapes**. There is no
v1<->v2 conversion helper; each is parsed and produced natively. v2 stays the
default producer; v1 is read on the way in and emitted only when the peer
declared v1.

## Version constants

| Constant | Value | rust |
| --- | --- | --- |
| `X402_VERSION_FIELD` | `"x402Version"` | constants.rs:7 |
| `X402_VERSION_V1` | `1` | constants.rs:10 |
| `X402_VERSION_V2` | `2` | constants.rs:13 |
| `EXACT_SCHEME` | `"exact"` | protocol/schemes/exact/types.rs:6 |

## Headers

| Role | v1 header | v2 header | rust |
| --- | --- | --- | --- |
| Client payment | `X-PAYMENT` | `PAYMENT-SIGNATURE` | constants.rs:16,25 |
| Server challenge | `X-PAYMENT-REQUIRED` | `PAYMENT-REQUIRED` | constants.rs:19,28 |
| Settlement result | `X-PAYMENT-RESPONSE` | `PAYMENT-RESPONSE` | constants.rs:22,31 |

The **credential** header values (`X-PAYMENT` / `PAYMENT-SIGNATURE`) and the
v2 **challenge** header (`PAYMENT-REQUIRED`) are **standard (padded) base64**
of the envelope JSON, NOT base64url. The rust producer encodes with
`base64::engine::general_purpose::STANDARD` (client/exact/payment.rs:110,
175-178) and the server decodes with the same engine (server/exact.rs:308).

**Exception — `X-PAYMENT-REQUIRED` (legacy v1 challenge header):** the rust
client parses this header value as **RAW JSON**, not base64
(`serde_json::from_str` on the header value, client/exact/payment.rs). pay-kit
parsers therefore accept the X-PAYMENT-REQUIRED value as raw JSON (and, for
robustness, also a base64 envelope). No pay-kit server emits this header (it
emits v2 `PAYMENT-REQUIRED`); it exists only to harnesserate with an external
v1 server that sends it.

## SVM network names

v1 uses **plain network strings**, not the CAIP-2 identifiers v2 uses.

| Cluster | v1 plain name | v2 CAIP-2 | rust |
| --- | --- | --- | --- |
| mainnet-beta | `solana` | `solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp` | constants.rs:4 / types.rs:12 |
| devnet | `solana-devnet` | `solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1` | types.rs:15 |
| testnet | `solana-testnet` | `solana:4uhcVJyU9pJkvQyS88uRDiswHXSCkY3z` | types.rs:18 |

The v1 producer maps the offer's cluster to a v1 slug with
`v1_network_for_requirements` (client/exact/payment.rs:393-404):
**devnet-family -> `solana-devnet`, everything else -> `solana`**. Note this
only emits `solana` or `solana-devnet`; testnet collapses to `solana` on the
producer side even though the slug `solana-testnet` is otherwise recognized
on parse.

The v1 server normalizes the inbound plain slug back to CAIP-2 via
`caip2_network_for_cluster` before comparing networks
(server/exact.rs:321-326, types.rs:31-39).

## v1 CHALLENGE (server -> client)

The v1 challenge is delivered as the **HTTP 402 JSON body** and/or the
`X-PAYMENT-REQUIRED` header. The client reads the v2 `PAYMENT-REQUIRED`
header first, then the v1 `X-PAYMENT-REQUIRED` header, then the body
(client/exact/payment.rs:237-261).

> **Divergence from the coinbase spec facts.** The spec facts state v1 has
> "no X-PAYMENT-REQUIRED header; the challenge is a 402 body only". The rust
> spine DOES define `X402_V1_PAYMENT_REQUIRED_HEADER = "X-PAYMENT-REQUIRED"`
> (constants.rs:19) and the client parser reads it before the body
> (payment.rs:246-253). pay-kit **follows rust**: support both the
> `X-PAYMENT-REQUIRED` header and the 402 body, with the body as the
> documented fallback.

Challenge JSON shape:

```json
{
  "x402Version": 1,
  "error": "PAYMENT-SIGNATURE header is required",
  "accepts": [
    {
      "scheme": "exact",
      "network": "solana-devnet",
      "maxAmountRequired": "1000",
      "asset": "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
      "payTo": "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
      "resource": "http://localhost:3402/x402/joke",
      "description": "A random joke",
      "maxTimeoutSeconds": 60,
      "extra": { "feePayer": "6AfzJJo1KfhNWKe56wa5EWszTNQ7B1W5Kfh5SY2JkRGQ" }
    }
  ]
}
```

Key field names, distinct from v2:

- The offer list key is **`accepts`** (plural array) — same key as v2, but
  v1 offers use the legacy field names below (types.rs:447-459, the
  `PaymentRequiredEnvelope`).
- The amount field is **`maxAmountRequired`** (string), not v2's `amount`.
  The deserializer accepts both (types.rs:337-339).
- Recipient is **`payTo`** (or legacy `recipient`); asset is **`asset`** (or
  legacy `currency`); timeout is **`maxTimeoutSeconds`** (or legacy
  `maxAge`) — same fallback chain rust uses (types.rs:334-355).
- `extra.feePayer` carries the facilitator fee-payer key; `extra.memo`
  carries an optional server-pinned memo (<=256 bytes,
  client/exact/payment.rs:360-391).

The client selects one offer from `accepts` with the same network/currency
preference logic as v2 (client/exact/payment.rs:288-350): cheapest on the
preferred network by default, or the highest-priority matching currency when
a currency preference is supplied.

## v1 PAYMENT request (client -> server)

`X-PAYMENT` header value = standard base64 of:

```json
{
  "x402Version": 1,
  "scheme": "exact",
  "network": "solana-devnet",
  "payload": { "transaction": "<base64 partially-signed versioned tx>" }
}
```

`scheme` and `network` are **top-level siblings of `payload`** — there is NO
`accepted` object (unlike v2). This is built by `build_payment_header_v1`
(client/exact/payment.rs:153-170): it sets `scheme = "exact"`,
`network = v1_network_for_requirements(...)`, `x402Version = 1`,
`accepted = None`, `resource = None`. The shared `PaymentSignatureEnvelope`
struct serializes `scheme`/`network` only when present
(types.rs:587-608, `skip_serializing_if = "Option::is_none"`), so the v2
producer omits them and the v1 producer includes them.

`payload.transaction` is the standard-base64 of the bincode-serialized
partially-signed `VersionedTransaction`
(client/exact/payment.rs:108-117).

## v1 SETTLEMENT response (server -> client)

`X-PAYMENT-RESPONSE` header value = standard base64 of:

```json
{
  "success": true,
  "transaction": "<signature>",
  "network": "solana-devnet",
  "payer": "<payer pubkey>",
  "errorReason": "<optional, only on failure>"
}
```

## Server dual-accept + version gate

The server decodes the inbound `PAYMENT-SIGNATURE`/`X-PAYMENT` envelope and
dispatches on `x402Version` (server/exact.rs:307-350,
`parse_payment_signature`):

- **v1 (`x402Version == 1`)**: require top-level `scheme == "exact"`
  (else `InvalidPayloadType`), then require
  `caip2_network_for_cluster(network) == expected_network`
  (server/exact.rs:316-327). There is no `accepted` object to bind in v1, so
  the per-option match falls back to the first offered requirement
  (server/exact.rs:438-446).
- **v2 (`x402Version == 2`)**: require an `accepted` object and bind it
  field-by-field to the route requirements (server/exact.rs:328-341,
  476-542).
- **Any other version**: reject with `Unsupported x402 version: <n>`
  (server/exact.rs:342-346). A server MUST NOT silently accept an unknown
  version — it would settle a payment whose wire contract it does not
  understand.

The facilitator MUST-checks on the signed transaction (compute-budget caps,
`transferChecked` shape, fee-payer-not-authority, memo bounds) are
**identical to v2** — both versions reach the same
`verify_exact_versioned_transaction` after the version gate
(server/exact.rs:568-569).

The server still **emits v2 challenges by default**: `exact_with_options`
and `exact_with_payment_options` build envelopes with
`x402_version = X402_VERSION_V2` (server/exact.rs:182-189, 284-291).

## Client dual-read + emit-declared-version

The client reads the v2 header challenge first, then the v1
`X-PAYMENT-REQUIRED` header, then the v1/express body
(client/exact/payment.rs:232-262). It populates the matching offer shape and
emits the version the server's challenge declared: `build_payment_header`
emits v2 (payment.rs:132-150), `build_payment_header_v1` emits v1
(payment.rs:153-170). **v2 stays the default producer.**

## v1 vs v2 field diff (quick reference)

| Concern | v1 | v2 |
| --- | --- | --- |
| Client header name | `X-PAYMENT` | `PAYMENT-SIGNATURE` |
| Challenge header name | `X-PAYMENT-REQUIRED` (+ 402 body) | `PAYMENT-REQUIRED` |
| Settlement header | `X-PAYMENT-RESPONSE` | `PAYMENT-RESPONSE` |
| Base64 variant | standard (padded) | standard (padded) |
| Network identifier | plain (`solana`, `solana-devnet`) | CAIP-2 (`solana:5eykt4...`) |
| Payment envelope scheme/network | top-level siblings of `payload` | absent |
| Payment envelope `accepted` | absent | present (echoes the offer) |
| Challenge amount field | `maxAmountRequired` | `amount` |
| Server binding | scheme + network only | full `accepted` deepEqual |
| Default producer | no (read/echo only) | yes |

## Conformance vectors

The cross-SDK harness exercises this contract RPC-free over the decoded
envelope shape. See `harness/vectors/x402-v1-build.json`,
`harness/vectors/x402-v1-verify.json`, and the reference oracle in
`harness/src/conformance/x402.ts` (`buildPaymentHeaderV1`,
`v1NetworkForOffer`, the v1 arm of `verifyPaymentHeader`).
