/**
 * PayKit playground API — a minimal, readable showcase of the `@solana/pay-kit`
 * interface. One `createPayKit({ ... pricing })` call configures the server and
 * declares the priced routes; each route is gated with `pay.express(name)`.
 *
 *   - charge gate        → fixed price, settled over MPP or x402 (client's choice)
 *   - x402 gate          → fixed price, x402 `exact` only
 *   - usage gate         → x402 `upto`: authorize a ceiling, settle metered usage
 *   - subscription gate  → MPP `subscription`: activate a recurring plan on first call
 *   - session gate       → MPP `session`: open a channel, stream metered deliveries
 *
 * The SDK reference docs (`/api/v1/docs`) are served unpaid by `docs.ts`. Local
 * funding (faucet, account top-ups, plan bootstrap) is sandbox-only and lives in
 * `sandbox.ts`. Run against the hosted sandbox with zero config: `pnpm dev`.
 */
import crypto from 'node:crypto'
import cors from 'cors'
import express, { type Request, type Response } from 'express'
import {
  createKeyPairSignerFromBytes,
  createSolanaRpc,
  generateKeyPairSigner,
  getBase58Encoder,
  type KeyPairSigner,
} from '@solana/kit'
import { createPayKit, session, subscription, usage, usd } from '@solana/pay-kit'

import { registerDocs } from './docs.js'
import { bootstrapPlan, fundSandbox, fundUsdc, registerFaucet } from './sandbox.js'

const NETWORK = (process.env.NETWORK ?? 'localnet') as 'devnet' | 'localnet' | 'mainnet'
const RPC_URL = process.env.RPC_URL ?? 'https://402.surfnet.dev:8899'
const PORT = parseInt(process.env.PORT || '3000', 10)
const SECRET_KEY = process.env.MPP_SECRET_KEY ?? crypto.randomBytes(32).toString('hex')

// Operator: fee-payer + settlement signer. Generated when no key is supplied.
const operator: KeyPairSigner = process.env.FEE_PAYER_KEY
  ? await createKeyPairSignerFromBytes(getBase58Encoder().encode(process.env.FEE_PAYER_KEY))
  : await generateKeyPairSigner()
const RECIPIENT = process.env.RECIPIENT ?? operator.address
// A second recipient for the marketplace-split demo (the platform's cut).
const PLATFORM = (await generateKeyPairSigner()).address

// Subscription plan PDA: bootstrapped on the sandbox (or supplied via env). The
// subscription route is only mounted when one is available.
const PLAN_ID = NETWORK === 'localnet' ? await bootstrapPlan(RPC_URL) : process.env.PLAN_ID ?? null

// ── PayKit: one config object declares the server + the priced routes ──
const pay = await createPayKit({
  accept: ['x402', 'mpp'],
  // `html: true` serves the interactive pay.sh payment page (+ service worker)
  // on 402s for browser requests; API clients still get the JSON 402.
  mpp: { challengeBindingSecret: SECRET_KEY, html: true },
  network: NETWORK,
  operator: { recipient: RECIPIENT, signer: operator },
  pricing: {
    feed: subscription(usd('0.10'), {
      description: 'Feed subscription',
      periodCount: 1,
      periodUnit: 'day',
      planId: PLAN_ID ?? '',
      puller: operator.address,
    }),
    // MPP charge that splits the payment: the platform takes 0.003 of the 0.01,
    // the seller (operator) nets 0.007. Each transfer carries an on-chain memo —
    // `externalId` labels the seller's payout, the split's `memo` labels the
    // platform fee — so the settlement shows up itemized on-chain / in receipts.
    // Multi-recipient splits aren't expressible in x402 `exact`, so this gate is
    // MPP-only (auto-narrowed off x402).
    joke: {
      amount: usd('0.01'),
      description: 'A programmer joke',
      externalId: 'paykit/joke: seller payout',
      feeWithin: { [PLATFORM]: { memo: 'paykit/joke: platform fee', price: usd('0.003') } },
    },
    // Fixed charge, settled over MPP or x402 (client's choice). This is the
    // canonical paid endpoint the payment-link E2E + cross-language harnesses
    // drive (they expect GET /api/v1/fortune → 402 → `{ "fortune": ... }`).
    fortune: { amount: usd('0.01'), description: 'A fortune cookie' },
    quote: { amount: usd('0.01'), description: 'Stock quote' },
    stream: session(usd('1.00'), { closeDelayMs: 2000, description: 'Metered token stream', unitPrice: usd('0.0001') }),
    summarize: usage(usd('0.1'), { description: 'Summarize text, billed per token' }),
  },
  rpcUrl: RPC_URL,
})

const JOKES = [
  'Why do programmers prefer dark mode? Because light attracts bugs.',
  'A SQL query walks into a bar, sees two tables, and asks: "Can I JOIN you?"',
  'There are 10 kinds of people: those who understand binary and those who don’t.',
]
const FORTUNES = [
  'A smooth long journey! Great expectations.',
  'Your code will compile on the first try today.',
  'A thrilling time is in your immediate future.',
  'The settlement you await will confirm on-chain.',
]
const HEADLINES = [
  { tag: 'engineering', title: 'Solana session validators hit a new throughput record' },
  { tag: 'macro', title: 'Stablecoin transfer volume crosses $4T on-chain quarterly' },
  { tag: 'security', title: 'New payment-channel program audit lands' },
  { tag: 'protocol', title: 'MPP v2 extensions ship to mainnet beta' },
]
const TOKEN_CHUNKS = [
  'A payment channel ',
  'lets a client and server ',
  'authorize many small ',
  'off-chain debits ',
  'against a single on-chain ',
  'deposit, settling the highest ',
  'cumulative voucher at close.',
]
/** Per-token price for the metered route, in USDC base units (6 decimals): $0.0001. */
const PRICE_PER_TOKEN = 100n

const app = express()
app.use(express.json())
app.use(cors({ exposedHeaders: ['www-authenticate', 'payment-required', 'x-payment-response', 'payment-receipt'] }))

// Local sandbox funding + faucet (no-op on real networks).
if (NETWORK === 'localnet') {
  await fundSandbox(RPC_URL, operator.address, RECIPIENT)
  await fundUsdc(RPC_URL, PLATFORM) // the split recipient needs a USDC account to receive its cut
  registerFaucet(app, RPC_URL)
}

// ── Priced routes ──
// Paths are generic (/api/v1/<name>) and names stay clean; the protocol + scheme
// each route accepts is carried by the discovery offers (method/scheme), not the URL.

// Fixed charge, settled over whichever protocol the client picks.
app.get('/api/v1/quote/:symbol', pay.express('quote'), (req: Request, res: Response) => {
  const symbol = String(req.params.symbol).toUpperCase()
  res.json({ price: 100 + (symbol.charCodeAt(0) % 50), symbol, via: pay.payment(req)?.protocol })
})

// Fixed charge, settled over whichever protocol the client picks. Canonical
// paid endpoint for the payment-link E2E + cross-language harnesses.
app.get('/api/v1/fortune', pay.express('fortune'), (_req: Request, res: Response) => {
  res.json({ fortune: FORTUNES[Math.floor(Math.random() * FORTUNES.length)] })
})

// MPP charge with a split: the platform takes 0.003, the seller nets 0.007.
app.get('/api/v1/joke', pay.express('joke'), (_req: Request, res: Response) => {
  res.json({ joke: JOKES[Math.floor(Math.random() * JOKES.length)] })
})

// Usage-metered (x402 `upto`): authorize up to $0.10, bill the tokens produced.
app.post('/api/v1/summarize', express.text({ type: '*/*' }), pay.express('summarize'), (req: Request, res: Response) => {
  const body = typeof req.body === 'string' ? req.body : ''
  const tokens = BigInt(Math.max(1, Math.floor(body.length / 4)))
  pay.charge(req)?.charge(tokens * PRICE_PER_TOKEN)
  res.json({ billedBaseUnits: (tokens * PRICE_PER_TOKEN).toString(), summarizedBytes: body.length, tokens: tokens.toString() })
})

// Subscription: the first call activates a recurring on-chain authorization
// against PLAN_ID, then serves the gated feed. Mounted only when a plan exists.
if (PLAN_ID) {
  app.get('/api/v1/feed', pay.express('feed'), (_req: Request, res: Response) => {
    const headlines = [...HEADLINES].sort(() => Math.random() - 0.5).slice(0, 3)
    res.json({ generatedAt: new Date().toISOString(), headlines })
  })
}

// Session: open a payment channel, then stream metered deliveries (SSE). Each
// chunk costs 0.0001 USDC; settlement runs out-of-band when the channel
// idle-closes (poll `/sessions/receipt/:channelId` for the settle signature).
app.get('/api/v1/stream', pay.express('stream'), (_req: Request, res: Response) => {
  res.writeHead(200, { 'Cache-Control': 'no-cache', Connection: 'keep-alive', 'Content-Type': 'text/event-stream' })
  let i = 0
  const tick = (): void => {
    if (i < TOKEN_CHUNKS.length) {
      res.write(`data: ${JSON.stringify({ chunk: TOKEN_CHUNKS[i], cost: PRICE_PER_TOKEN.toString() })}\n\n`)
      i += 1
      setTimeout(tick, 80)
    } else {
      res.write('data: [DONE]\n\n')
      res.end()
    }
  }
  tick()
})

// Session side-channel + receipt routes — mounted explicitly (pay-kit, like
// mppx, leaves route-mounting to the app rather than auto-injecting them).
// These are protocol machinery, not gated endpoints, so they stay out of discovery.
const streamRoutes = pay.sessionRoutes('stream')
app.post('/api/v1/stream', streamRoutes.voucher) // voucher commits to the resource URL
app.post('/__402/session/deliveries', streamRoutes.deliveries)
app.post('/__402/session/commit', streamRoutes.commit)
app.get('/sessions/receipt/:channelId', streamRoutes.receipt)

// SDK reference docs (unpaid) for the playground's Docs / ApiReference pages.
registerDocs(app)

// ── Discovery + health ──

// OpenAPI 3.1 discovery, introspected from the routes mounted above: each
// `pay.express(gate)` is tagged with its gate, so each operation's
// `x-payment-info.offers` carry the cost, network, recipient (`payTo`), and
// fee payer straight from `pricing`. No route table or bespoke config endpoint
// to keep in sync. The RPC endpoint is deliberately not advertised.
const openapi = await pay.openapiFromExpress(app, { info: { title: 'PayKit Playground', version: '1.0.0' } })
app.get('/openapi.json', (_req: Request, res: Response) => res.json(openapi))

app.get('/api/v1/health', async (_req: Request, res: Response) => {
  let balance: number | undefined
  try {
    const { value } = await createSolanaRpc(RPC_URL).getBalance(operator.address).send()
    balance = Number(value) / 1e9
  } catch {
    /* sandbox may be unreachable */
  }
  res.json({ feePayer: operator.address, feePayerBalance: balance, network: NETWORK, ok: true, recipient: RECIPIENT })
})

const paths = (openapi as { paths?: Record<string, Record<string, unknown>> }).paths ?? {}

const server = app.listen(PORT, () => {
  console.log(`\n  PayKit Playground  http://localhost:${PORT}`)
  console.log(`  Network ${NETWORK}   RPC ${RPC_URL}`)
  console.log(`  Recipient ${RECIPIENT}\n`)
  console.log('  GET  /openapi.json  (discovery)')
  for (const [path, item] of Object.entries(paths)) {
    for (const method of Object.keys(item)) console.log(`  ${method.toUpperCase().padEnd(4)} ${path}`)
  }
  console.log()
})

// A taken port almost always means another instance is already serving — treat
// it as "API is running elsewhere" and step aside cleanly instead of crashing
// with an unhandled 'error' stack (e.g. when `pnpm dev` runs alongside a
// separately-launched API).
server.on('error', (err: NodeJS.ErrnoException) => {
  if (err.code === 'EADDRINUSE') {
    console.log(`\n  Port ${PORT} is already in use — assuming the PayKit API is running elsewhere. Skipping.\n`)
    process.exit(0)
  }
  throw err
})
