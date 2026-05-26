<p align="center">
  <img src="https://github.com/solana-foundation/pay-kit/raw/main/docs/assets/banner.png" alt="MPP" width="100%" />
</p>

# @solana/pay-kit

Charge stablecoins (USDC, USDT, PYUSD, ...) for any HTTP endpoint, in
TypeScript. Implements the Solana payment method for the
[Machine Payments Protocol](https://mpp.dev) and ships both the
reference server and client used by every other SDK's interop harness.

**MPP** is [an open protocol proposal](https://paymentauth.org) that lets
any HTTP API accept payments using the `402 Payment Required` flow. You
do not need to know anything about Solana to use this library: pick a
currency, give it your wallet address, and gate a route in two lines.

[![TypeScript](https://img.shields.io/badge/typescript-5%2B-blue)]()
[![Node](https://img.shields.io/badge/node-20%2B-brightgreen)]()

## Quick start

Gate an Express route by passing the MPP middleware (the same wiring
the [`demo/server/`](../demo/server) reference uses):

```ts
import express from 'express'
import { createMpp } from '@solana/mpp/server'

const mpp = createMpp({
  recipient: 'CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY',
  currency: 'USDC',
  network: 'localnet',
  rpcUrl: 'https://402.surfnet.dev:8899',
  secretKey: 'local-dev-secret',
  realm: 'TypeScript MPP Example',
})

const app = express()
app.use(express.json())

app.get('/paid', mpp.charge({ amount: '0.001', description: 'Paid endpoint' }),
  (_req, res) => res.json({ ok: true, paid: true }),
)

app.listen(4567)
```

`currency` accepts a symbol like `"USDC"`, `"USDT"`, `"USDG"`, `"PYUSD"`,
or `"CASH"`. The SDK looks up the mint address, token program, and
decimals from a built-in table. You can also pass a raw mint pubkey for
tokens not in the table.

### Client

```ts
import { createMppClient } from '@solana/mpp/client'

const client = createMppClient({ signer, rpcUrl })
const res = await client.fetch('https://api.example/paid')
```

`createMppClient` returns a fetch-shaped helper whose transport replays
402 responses with the appropriate `Authorization: Payment` credential.

## Protocol compatibility matrix

### MPP

| Intent | Client | Server |
|---|:---:|:---:|
| `mpp/charge/pull` | pass | pass |
| `mpp/charge/push` | pass | pass |
| `mpp/session` | --- | --- |
| `mpp/subscription` | --- | --- |

### x402

| Intent | Client | Server |
|---|:---:|:---:|
| `x402/exact` | pass | pass |
| `x402/upto` | --- | --- |
| `x402/batch-settlement` | --- | --- |

For `mpp/charge/pull`: the server owns the full lifecycle. It issues
signed challenges with a fresh `recentBlockhash`, parses and validates
the `Authorization: Payment` credential, pins the echoed charge request,
decodes the client-signed transaction and checks recipient, amount,
mint, splits, ATA, memos, and compute budget, optionally fee-payer
co-signs, broadcasts via `sendTransaction`, polls `getSignatureStatuses`
to `confirmed` / `finalized`, and emits `payment-receipt` with the
on-chain signature.

For `mpp/charge/push`: the server fetches the transaction by signature
with `getTransaction`, rejects failed or missing metadata, reuses the
same structural transaction verifier as pull mode, consumes the
signature through replay storage, and emits the same receipt shape.

## Examples

The TypeScript demo at [`demo/`](../demo) wires the server-side SDK
into an Express app exposing several stablecoin-gated endpoints
(`/api/v1/stocks/quote/:symbol`, `/api/v1/weather/:city`, ...).

### Run the demo server

```bash
cd demo/server
pnpm install
pnpm dev          # listens on http://localhost:3000
```

### Drive it from a client

```bash
brew install pay
curl  http://127.0.0.1:3000/api/v1/weather/paris       # 402 payment required
pay curl http://127.0.0.1:3000/api/v1/weather/paris    # pays and succeeds
```

Set `RECIPIENT`, `NETWORK`, `RPC_URL`, `MPP_SECRET_KEY`, or
`FEE_PAYER_KEY` to point at a different localnet fixture or wallet.

## Install

```bash
pnpm add @solana/mpp
# or
npm install @solana/mpp
```

## Coding convention

This SDK follows `eslint + prettier` and the per-language style notes
at `skills/pay-sdk-implementation/references/coding-conventions.md`.

The repo-level `pay-sdk-implementation` skill remains the protocol
source of truth: Rust / spec wire format first, TypeScript idioms
second.

## Test

```bash
cd typescript
pnpm install
pnpm typecheck
pnpm test
pnpm test:integration
```

## Interop

The cross-language interop harness lives in
[`../harness`](../harness). The TypeScript SDK ships both the
reference client (`harness/ts-client`) and the in-process reference
server used by every other SDK's adapter.

```bash
cd harness
pnpm install
pnpm test
```

## Spec

This SDK implements the [Solana Charge Intent](https://github.com/tempoxyz/mpp-specs/pull/188)
for the [HTTP Payment Authentication Scheme](https://paymentauth.org).

## Repo layout

```text
typescript/
├── packages/mpp/        SDK package (client + server + protocol)
├── vitest.config*.ts    test configurations
└── package.json         workspace scripts
```

## License

MIT
