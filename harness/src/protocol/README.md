# mpp-protocol conformance layer

Validates pay-kit's per-SDK **protocol layer** (the `Payment` HTTP auth scheme
codec) against the canonical [`tempoxyz/mpp-tools`](https://github.com/tempoxyz/mpp-tools)
conformance vectors vendored under `harness/vectors/mpp-protocol/`.

This is the protocol-primitive counterpart to the live-Solana interop harness
(`harness/src/`) and the cross-SDK charge/x402 conformance layer
(`harness/src/conformance/`). It checks the deterministic protocol math that
every SDK re-implements: challenge / credential / receipt header parse+format,
base64url encode/decode, and the challenge-id HMAC.

## Layout

| File | Role |
|------|------|
| `vectors.ts` | Loads the vendored canonical vectors and flattens them into dispatchable `ProtocolCase`s (handles the `tests.<dir>: true \| {success:false,error_type}` shape). |
| `driver.ts` | Transport-agnostic case runner. `exact` compare for base64url / challenge.id; `semantic` compare for parse/format (re-parses both wires through the paired parse op, with credential request-encoding normalization) — mirrors the canonical runner's `compare_*_semantic`. |
| `runners/typescript.ts` | TypeScript REFERENCE runner. In-process `ProtocolAdapter` over `mppx` (pay-kit's TS protocol core) + a stdin/stdout CLI speaking the canonical adapter ABI. |
| `runners/spawn.ts` | Manifest-driven, spawned-subprocess `ProtocolAdapter`. Discovers `harness/protocol-runners/<lang>.json`, spawns one process per request over the stdin/stdout ABI. |

## Adapter ABI (per-language runner contract)

Each runner reads one request and writes one response, both single-line JSON:

```
stdin :  { "op": "<operation>", "input": <op-specific> }
stdout:  { "success": true,  "result": <op-specific> }
      |  { "success": false, "error": "<msg>", "error_type": "<type>" }
```

Operations (canonical, from `mpp-tools/conformance/operations.json`):

| op | input | success result | compare |
|----|-------|----------------|---------|
| `challenge.parse`   | `{ header }` | challenge object | semantic |
| `challenge.format`  | challenge object | `{ header }` | semantic |
| `credential.parse`  | `{ header }` | credential object | semantic |
| `credential.format` | credential object | `{ header }` | semantic |
| `receipt.parse`     | `{ header }` | receipt object | semantic |
| `receipt.format`    | receipt object | `{ header }` | semantic |
| `base64url.encode`  | `{ text }` | `{ text }` | exact |
| `base64url.decode`  | `{ text }` | `{ text }` | exact |
| `challenge.id`      | `{ secretKey, realm, method, intent, request, expires?, digest?, opaque? }` | `{ id }` | exact |

`error_type` vocabulary: `parse_error` (`.parse`), `format_error` (`.format`),
`encoding_error` (base64url), `generation_error` (`challenge.id`).

## Running

```
cd harness
npx vitest run test/protocol-conformance.test.ts
```

The fast path drives every case in-process through the TS reference adapter.
The spawned-runner block drives a representative slice through each manifest in
`harness/protocol-runners/`, proving the per-language wiring.

## Adding a language runner

1. Implement a stdin/stdout runner in the SDK that maps each `op` to that SDK's
   protocol functions (see the per-operation map in the PR description).
2. Drop `harness/protocol-runners/<lang>.json`:
   `{ "language": "...", "command": [...], "cwd": "<sdk-dir>" }`.

The driver picks it up automatically — no central edit.

## Known divergences

Tracked in `test/protocol-conformance.test.ts` (`KNOWN_TS_DIVERGENCES`). Each is
asserted to STILL diverge so the gap fails loudly the moment an SDK fix lands.
