<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://github.com/solana-foundation/pay-kit/raw/main/docs/assets/banner-typescript-dark.png">
    <source media="(prefers-color-scheme: light)" srcset="https://github.com/solana-foundation/pay-kit/raw/main/docs/assets/banner-typescript-light.png">
    <img alt="Solana pay-kit — TypeScript" width="100%" style="border-top-left-radius: 8px; border-top-right-radius: 8px; margin-bottom: 16px;" src="https://github.com/solana-foundation/pay-kit/raw/main/docs/assets/banner-typescript-light.png">
  </picture>
</div>

Charge stablecoins (USDC, USDT, PYUSD, …) for any HTTP endpoint, in
TypeScript. One surface (`@solana/pay-kit`) over the
[Machine Payments Protocol](https://paymentauth.org), built on the same
protocol adapter seam as the Ruby, Python, and PHP SDKs — with
[x402](https://x402.org) to follow behind it. Everything runs on
web-standard `Request`/`Response`, so Express, Hono, and plain
`node:http` all sit on the same dispatcher.

You do not need to know anything about Solana to use this library: pick
a currency, give it your wallet address, and gate a route.

[![TypeScript](https://img.shields.io/badge/typescript-5%2B-blue)]()
[![Node](https://img.shields.io/badge/node-20%2B-brightgreen)]()

---

## Quick start

Three progressively-realistic snippets. Express is the framework here;
the same surface works anywhere you can hand the dispatcher a
web-standard `Request`.

### 1. Smallest possible app

Gate one route with an inline price. Save as `server.ts` and boot with
`npx tsx server.ts`. Zero-config beyond the RPC: the package uses a
published demo keypair as the recipient and the hosted Surfpool sandbox
at `https://402.surfnet.dev:8899`.

```ts
// server.ts
import express from 'express'
import { createPayKit, usd } from '@solana/pay-kit'

const pay = await createPayKit({ rpcUrl: 'https://402.surfnet.dev:8899' })

const app = express()
app.get('/report', pay.express(usd('0.10')), (_req, res) => {
  res.send('premium content')
})
app.listen(4567)
```

The middleware halts the request with a 402 challenge if no valid
payment was sent; when one was, it verifies and settles it, sets the
settlement headers on the response, and hands control to your handler.

Hit `/report` with [`pay curl`](#run-the-example) and the customer
walks through Touch ID and a USDC payment.

### 2. Multiple gates via a catalogue

When more than one route is paid, lift the prices into the `pricing`
catalogue. Routes reference gates by name, and the names are typed:
`pay.express('report')` autocompletes and a typo is a compile error.

```ts
import { createPayKit, usd } from '@solana/pay-kit'

const pay = await createPayKit({
  rpcUrl: 'https://402.surfnet.dev:8899',
  pricing: {
    report: { amount: usd('0.10'), description: 'Premium report' },
    apiCall: { amount: usd('0.001') },
  },
})

app.get('/report', pay.express('report'), (req, res) => {
  res.json({ content: 'premium', tx: pay.payment(req)?.transaction })
})
app.get('/api/data', pay.express('apiCall'), (_req, res) => {
  res.json({ data: [] })
})
```

Gates are validated at construction — wrong currency, fee math that
doesn't add up, a fee routed back to the recipient — so configuration
errors surface at boot, before any traffic.

### 3. Production-shape config

Snippet 2's demo recipient and public sandbox are fine for poking
around. Production wants explicit keys, a dedicated RPC, a stable
challenge secret, and a persistent replay store. The route handlers
are unchanged — only the config grows.

```ts
import { createPayKit, Signer, Store, usd } from '@solana/pay-kit'

const PLATFORM = 'CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY'

const pay = await createPayKit({
  network: 'solana_mainnet',
  stablecoins: ['USDC', 'PYUSD'],
  operator: { signer: await Signer.file('config/operator.json') },
  rpcUrl: 'https://mainnet.helius-rpc.com/?api-key=YOUR_HELIUS_KEY',
  mpp: { challengeBindingSecret: process.env.PAY_KIT_MPP_SECRET! },
  replayStore: Store.redis(redisClient), // any ioredis / node-redis / Valkey client
  pricing: {
    report: { amount: usd('0.10'), description: 'Premium report' },

    // Platform-fee pattern:
    // Customer pays $10.00,
    // Operator nets $9.70, PLATFORM nets $0.30.
    marketplaceSale: { amount: usd('10.00'), feeWithin: { [PLATFORM]: usd('0.30') } },
  },
})
```

Two safety rails fire at boot:

- `solana_mainnet` plus the published demo signer throws
  (`DemoSignerOnMainnetError`) — no real funds get routed to a publicly
  known address by accident.
- Outside localnet, a missing `mpp.challengeBindingSecret` throws.
  Provide it in `createPayKit` or via `PAY_KIT_MPP_SECRET` so the HMAC
  stays stable across restarts. On localnet an ephemeral secret is
  generated with a warning.

---

## Run the example

The playground at [`playground/`](https://github.com/solana-foundation/pay-kit/tree/main/playground) wires the server-side
SDK into an Express app exposing every primitive the kit ships
(`/api/v1/stocks/quote/:symbol`, `/api/v1/weather/:city`, x402,
subscriptions, sessions, …).

**Boot the server:**

```bash
cd playground
pnpm install
pnpm dev          # Vite on :5173, Express on :3000
```

**Consume with `pay curl`:**

```bash
# Install the pay CLI:
brew install pay
# or npm install -g @solana/pay

# Fail with 402 - payment required
curl -i http://127.0.0.1:3000/api/v1/weather/paris

# Succeed with 200 - payment provided
pay curl -i http://127.0.0.1:3000/api/v1/weather/paris
```

Set `RECIPIENT`, `NETWORK`, `RPC_URL`, `MPP_SECRET_KEY`, or
`FEE_PAYER_KEY` to point at a different localnet fixture or wallet.

---

## MPP

The [Machine Payments Protocol](https://paymentauth.org) is the broader
HTTP Payment Authentication scheme — a `402 Payment Required`
handshake whose challenge carries a rich intent shape supporting
multi-recipient splits, server-side fee accounting, and a separate
fee-payer signer.

Use MPP when:
- Your gate has a platform or gateway fee (Stripe-Connect "application
  fee" pattern).
- You want the server to subsidize the customer's network fee.
- You want one challenge per gate instead of per-mint-quoted offers.

Supported in TypeScript:

| Intent         | Client | Server |
|----------------|:------:|:------:|
| `charge/pull`  | ✅      | ✅      |
| `charge/push`  | ✅      | ✅      |
| `session`      | ✅      | ✅      |
| `subscription` | ✅      | ✅      |

For `charge/pull` the server owns the full lifecycle: it issues signed
challenges with a fresh `recentBlockhash`, validates the
`Authorization: Payment` credential, decodes the client-signed
transaction and checks recipient, amount, mint, splits, ATA, memos,
and compute budget, optionally co-signs as fee payer, broadcasts, polls
to `confirmed`/`finalized`, and emits `payment-receipt` with the
settlement signature. For `charge/push` the server fetches the
transaction by signature, runs the same structural verifier, and
consumes the signature through the replay store.

## x402

[x402](https://x402.org) revives HTTP `402 Payment Required` as a
client-server payment handshake. The TypeScript surface ships all three
SVM schemes via [`@x402/svm`](external/x402) (client + server +
facilitator each):

| Scheme             | Client | Server |
|--------------------|:------:|:------:|
| `exact`            | ✅      | ✅      |
| `upto`             | ✅      | ✅      |
| `batch-settlement` | ✅      | ✅      |

pay-kit wires `exact` and `upto` straight into gates —
`configure({ accept: ['x402'] })` mounts the `exact` adapter for
fixed-price gates and the in-process `upto` facilitator for usage gates.
For delegated `upto` channels, set `x402.facilitatorFee` to the
facilitator share in basis points; the default is `0`.
`batch-settlement` ships in `@x402/svm` but is not yet exposed as a
pay-kit gate adapter. All three are exercised client- and server-side by
the cross-language conformance suite in the harness.

## Client

Unlike the Ruby, Python, and PHP SDKs (server-only), TypeScript also
ships the paying side, via `@solana/pay-kit/client`:

```ts
import { createPayKitClient } from '@solana/pay-kit/client'

const client = await createPayKitClient({ signer, rpcUrl })
const res = await client.fetch('https://api.example/paid')
```

`client.fetch` is a `fetch`-shaped helper: on a 402 it pays with the
matching protocol (MPP or x402) and retries the request with the
`Authorization: Payment` credential. Pass a third argument
(`'x402'` / `'mpp'`) to force a rail when an endpoint offers both.

---

## Vocabulary

| Term         | Meaning |
|--------------|---------|
| **gate**     | A protected unit. Has an amount, optional fees, accepted protocols. |
| **amount**   | The base amount a gate charges, before any `feeOnTop`. |
| **total**    | What the customer pays: `amount + sum(feeOnTop)`. Derived. |
| **price**    | Value object returned by `usd(…)`: number + currency + settlement. |
| **feeWithin** | Fee taken out of the amount. `payTo` nets less. |
| **feeOnTop** | Fee added to the amount. Customer pays more; `payTo` nets full. |
| **payment**  | Proof submitted by the client to pass a gate. |
| **protocol** | `'x402'` or `'mpp'` (top-level dispatch). |
| **scheme**   | x402 sub-form: `exact`. MPP sub-form: `charge`. |
| **accept**   | Ordered preference list (protocols and stablecoins both). |
| **currency** | Fiat unit a price is quoted in (`USD`, `EUR`, `GBP`). |
| **settlement** | The stablecoin that actually transfers (`USDC`, `USDT`, …). |

## Three primitives

The same trio as the Ruby, Python, and PHP SDKs. TypeScript returns a
result object instead of halting, matching the surrounding ecosystem:

| Method | Purpose |
|--------|---------|
| `pay.requirePayment(request, gate)` | Verify-or-deny; returns `{ status: 402, response }` or `{ status: 200, payment, withSettlement }` |
| `pay.paid(request, gateName?)`      | Predicate, never settles |
| `pay.payment(request)`              | The verified `Payment`, `undefined` until paid |

`gate` accepts a catalogue name, a `Gate`, a bare `Price` (inline
gate), or a per-request resolver function.

## Inline pricing

For one-off endpoints that don't warrant a catalogue entry, pass a
price directly:

```ts
const result = await pay.requirePayment(request, usd('0.25'))
```

## Gate catalogue

Each gate is a frozen value object with an amount, an ordered list of
accepted protocols, and zero or more named fees.

```ts
const SELLER = 'Ay…'
const PLATFORM = 'CX…'

const pricing = createPricing(config, {
  // Simple. Customer pays $0.10, payTo nets $0.10.
  report: { amount: usd('0.10'), description: 'Premium report' },

  // Stripe-Connect "application fee". Customer pays $10.00,
  // SELLER nets $9.70, PLATFORM nets $0.30.
  marketplaceSale: {
    amount: usd('10.00'),
    payTo: SELLER,
    feeWithin: { [PLATFORM]: usd('0.30') },
  },

  // Surcharge. Customer pays $10.50, SELLER nets $10.00, PLATFORM $0.50.
  ticket: {
    amount: usd('10.00'),
    payTo: SELLER,
    feeOnTop: { [PLATFORM]: usd('0.50') },
  },

  // Dynamic per-request pricing.
  tiered: request =>
    usd(new URL(request.url).searchParams.get('tier') === 'premium' ? '5.00' : '0.10'),
})
```

Boot-time validations (all throw `ConfigurationError` or a subtype):

- `payTo` resolves from the gate or `operator.recipient`.
- A fee recipient must differ from `payTo`. Fold the fee into the amount instead.
- All fee prices share one currency with the amount.
- `sum(feeWithin)` must be less than the amount.
- `accept: ['x402']` on a fee-bearing gate throws (`ProtocolIncompatibleError`).

## Signers

Key handling is built on [Solana Keychain](https://www.npmjs.com/package/@solana/keychain).
Local constructors ride on `@solana/keychain-memory`; remote backends
plug in through `Signer.from`:

```ts
import { Signer } from '@solana/pay-kit'

// Local key material:
const fromFile = await Signer.file('config/operator.json')   // Solana CLI JSON
const fromEnv = await Signer.env('OPERATOR_KEY')             // JSON / hex / base58, auto-detected
const ephemeral = await Signer.generate()                    // tests

// Remote signing (AWS KMS, GCP KMS, Vault, Privy, Turnkey, …):
import { createKeychainSigner } from '@solana/keychain'
const remote = Signer.from(
  await createKeychainSigner({ backend: 'vault', /* … */ }),
  { feePayer: false },
)
```

The demo signer (`Signer.demo()`) is byte-for-byte identical across
the Ruby, Python, PHP, and Lua SDKs so processes running different
SDKs can exchange traffic during local development. It is public by
design and refused on mainnet at boot.

## Middleware

The framework shims sit on the dispatcher, the same way Ruby's Rack
middleware, Python's FastAPI/Flask/Django shims, and PHP's PSR-15
middleware sit on theirs.

**Express / Connect** (`pay.express`) — typed against `node:http`, so
it adds no framework dependency and also fits Polka and plain
`node:http` servers:

```ts
app.get('/report', pay.express('report'), (req, res) => {
  res.json({ ok: true, tx: pay.payment(req)?.transaction })
})
```

**Hono** (`pay.hono`) — works with any framework whose context exposes
the web request as `c.req.raw`:

```ts
app.use('/report', pay.hono('report'))
app.get('/report', c => c.json({ ok: true, tx: pay.payment(c.req.raw)?.transaction }))
```

**Fetch handlers** (Cloudflare Workers, Bun, Deno, Next.js) — wrap the
handler instead of chaining middleware:

```ts
import { usd } from '@solana/pay-kit'

export default {
  fetch: pay.fetch(usd('0.10'), (request, payment) =>
    Response.json({ ok: true, tx: payment.transaction }),
  ),
}
```

## Web-standard core

The dispatcher is framework-free: it takes a web-standard `Request`
and produces a web-standard `Response`. Protocol work happens behind
one adapter contract (`detect` / `acceptsEntry` / `challengeHeaders` /
`verifyAndSettle`); the MPP adapter wraps `@solana/mpp`'s charge
method and caches one handler per (recipient, splits) shape. Verified
payments are tracked per `Request`, so `paid()` and `payment()` answer
for the same request object the route handler holds — which is why the
Hono shim needs no context plumbing at all.

---

## Install

```bash
pnpm add @solana/pay-kit
```

## Test

```bash
cd typescript
pnpm install
pnpm typecheck
pnpm test
pnpm test:integration
```

## Harness

The cross-language harness lives in [`harness/`](https://github.com/solana-foundation/pay-kit/tree/main/harness).
The TypeScript SDK ships both the reference client
(`harness/ts-client`) and the in-process reference server used by every
other SDK's adapter.

```bash
cd harness
pnpm install
pnpm test
```

## Spec

This SDK implements the
[Solana Charge Intent](https://paymentauth.org/draft-solana-charge-00.html)
for the [HTTP Payment Authentication Scheme](https://paymentauth.org).
The cross-language surface is specified in
[`docs/paykit-interface.md`](https://github.com/solana-foundation/pay-kit/blob/main/docs/paykit-interface.md).

---

## Repo layout

```text
typescript/
├── packages/pay-kit/    # @solana/pay-kit: gates, pricing, signers, dispatcher
│   └── src/
│       ├── config.ts, gate.ts, price.ts, pricing.ts, signer.ts, errors.ts, …
│       ├── adapter.ts            # The protocol adapter contract
│       ├── adapters/mpp.ts       # MPP charge adapter over @solana/mpp
│       ├── adapters/x402-upto.ts # x402 upto (usage) facilitator + Charge meter
│       └── paykit.ts             # createPayKit + dispatcher (requirePayment /
│                                 #   paid / payment) + express / hono / fetch
├── packages/mpp/        # @solana/mpp: protocol layer (client + server + sessions)
├── vitest.config*.ts    # test configurations
└── package.json         # workspace scripts
```

## Coding convention

This SDK follows `eslint + prettier` and the per-language style notes
at `skills/pay-sdk-implementation/references/coding-conventions.md`.

The repo-level `pay-sdk-implementation` skill remains the protocol
source of truth: Rust / spec wire format first, TypeScript idioms
second.

## License

MIT
