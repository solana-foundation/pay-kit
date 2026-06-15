import crypto from 'node:crypto'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import express, { type Request, type Response } from 'express'
import cors from 'cors'
import {
  createKeyPairSignerFromBytes,
  createSolanaRpc,
  generateKeyPairSigner,
  getBase58Encoder,
  type KeyPairSigner,
} from '@solana/kit'
import { configure } from '@solana/pay-kit'

import { registerCharges } from './modules/charges.js'
import { registerFaucet } from './modules/faucet.js'
import { registerX402 } from './modules/x402.js'
import { registerSubscriptions } from './modules/subscriptions.js'
import { registerSessions } from './modules/sessions.js'
import { registerDocs } from './modules/docs.js'
import { bootstrapPlan, planInfoFor } from './shared/plan-bootstrap.js'
import {
  USDC_DECIMALS,
  USDC_MINT,
  SOL_FUND_LAMPORTS,
  USDC_FUND_AMOUNT,
  TOKEN_PROGRAM,
  SYSTEM_PROGRAM,
} from './shared/constants.js'
import { colors } from './shared/utils.js'

const NETWORK = process.env.NETWORK ?? 'localnet'
// Default to the hosted Solana Payment Sandbox so the playground works
// zero-config — it has the payment-channels + subscriptions programs
// preloaded and supports the surfnet cheatcodes used by the faucet. Override
// `RPC_URL` to point at a local surfpool when you need offline iteration.
const RPC_URL = process.env.RPC_URL ?? 'https://402.surfnet.dev:8899'
const SECRET_KEY = process.env.MPP_SECRET_KEY ?? crypto.randomBytes(32).toString('hex')
// `pnpm dev` at the playground root passes PORT through the concurrently
// command line, where an unset PLAYGROUND_PORT expands to an empty string —
// treat empty the same as unset.
const PORT = parseInt(process.env.PORT || '3000', 10)

// ── Fee payer + recipient ──

let feePayerSigner: KeyPairSigner
if (process.env.FEE_PAYER_KEY) {
  feePayerSigner = await createKeyPairSignerFromBytes(getBase58Encoder().encode(process.env.FEE_PAYER_KEY))
} else {
  feePayerSigner = await generateKeyPairSigner()
}

const RECIPIENT = process.env.RECIPIENT ?? feePayerSigner.address

// Fund fee payer + recipient on the local surfnet so the demo works zero-config.
async function bootstrapFunding() {
  const rpc = async (method: string, params: unknown[]) => {
    const res = await fetch(RPC_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
      signal: AbortSignal.timeout(4000),
    })
    return res.json() as Promise<{ error?: { message: string } }>
  }
  try {
    await rpc('surfnet_setAccount', [
      feePayerSigner.address,
      { lamports: SOL_FUND_LAMPORTS, data: '', executable: false, owner: SYSTEM_PROGRAM, rentEpoch: 0 },
    ])
    await rpc('surfnet_setTokenAccount', [
      RECIPIENT,
      USDC_MINT,
      { amount: USDC_FUND_AMOUNT, state: 'initialized' },
      TOKEN_PROGRAM,
    ])
  } catch {
    console.warn(colors.yellow('  Surfpool not reachable — fee payer may not have SOL for fees.'))
  }
}

await bootstrapFunding()

const planId = await bootstrapPlan(RPC_URL, feePayerSigner, RECIPIENT)
const plan = planId ? planInfoFor(planId) : null

// ── Express ──

const app = express()
app.use(express.json())
app.use(
  cors({
    exposedHeaders: [
      'www-authenticate',
      'payment-receipt',
      'x-payment-required',
      'x-payment-response',
    ],
  }),
)

// Health check (used by frontend bootstrap)
app.get('/api/v1/health', async (_req: Request, res: Response) => {
  let feePayerBalance: number | undefined
  try {
    const rpc = createSolanaRpc(RPC_URL)
    const { value } = await rpc.getBalance(feePayerSigner.address).send()
    feePayerBalance = Number(value) / 1e9
  } catch {
    /* surfpool may be down */
  }
  res.json({
    ok: true,
    feePayer: feePayerSigner.address,
    feePayerBalance,
    recipient: RECIPIENT,
    network: NETWORK,
    rpcUrl: RPC_URL,
  })
})

// Config endpoint — drives the frontend's sidebar + endpoint list.
app.get('/api/v1/config', (_req: Request, res: Response) => {
  const endpoints = buildEndpointList(!!plan)
  res.json({
    recipient: RECIPIENT,
    network: NETWORK,
    rpcUrl: RPC_URL,
    feePayer: feePayerSigner.address,
    planId: plan?.planId,
    endpoints,
  })
})

// ── Modules ──

// Charges run on @solana/pay-kit; the boot config is the single source the
// gates, the dispatcher, and the protocol adapter all derive from.
const payConfig = await configure({
  network: NETWORK as 'localnet' | 'devnet' | 'mainnet',
  rpcUrl: RPC_URL,
  operator: { recipient: RECIPIENT, signer: feePayerSigner },
  mpp: { challengeBindingSecret: SECRET_KEY },
})

registerFaucet(app, RPC_URL)
registerCharges(app, payConfig)

if (plan) {
  registerSubscriptions(app, {
    recipient: RECIPIENT,
    network: NETWORK,
    secretKey: SECRET_KEY,
    feePayerSigner,
    rpcUrl: RPC_URL,
    plan,
  })
}

registerSessions(app, {
  recipient: RECIPIENT,
  network: NETWORK,
  secretKey: SECRET_KEY,
  feePayerSigner,
  rpcUrl: RPC_URL,
})
registerX402(app, {
  recipient: RECIPIENT,
  rpcUrl: RPC_URL,
  facilitatorUrl: productionUrl() + '/facilitator',
  feePayerSigner,
})
registerDocs(app)

// ── Static SPA in production ──

const __dirname = path.dirname(fileURLToPath(import.meta.url))
// The web app lives in the playground workspace at the repo root.
const appDist = path.join(__dirname, '..', '..', '..', 'playground', 'app', 'dist')
app.use(express.static(appDist))
app.get('*', (_req: Request, res: Response) => {
  res.sendFile(path.join(appDist, 'index.html'))
})

// ── Listen ──

app.listen(PORT, () => {
  console.log()
  console.log(`  ${colors.bold('PayKit Playground')}  ${colors.dim(`http://localhost:${PORT}`)}`)
  console.log()
  console.log(`  ${colors.dim('Network')}     ${colors.magenta(NETWORK)}`)
  console.log(`  ${colors.dim('RPC')}         ${colors.cyan(RPC_URL)}`)
  console.log(`  ${colors.dim('Recipient')}   ${colors.green(RECIPIENT)}`)
  console.log(`  ${colors.dim('Fee payer')}   ${colors.green(feePayerSigner.address)}`)
  console.log(`  ${colors.dim('Plan')}        ${plan ? colors.green(plan.planId) : colors.yellow('— not bootstrapped')}`)
  console.log(`  ${colors.dim('Sessions')}    ${colors.green('enabled (in-process)')}`)
  console.log()
})

// ── Helpers ──

function productionUrl(): string {
  if (process.env.VERCEL_PROJECT_PRODUCTION_URL)
    return `https://${process.env.VERCEL_PROJECT_PRODUCTION_URL}`
  if (process.env.VERCEL_URL) return `https://${process.env.VERCEL_URL}`
  return `http://localhost:${PORT}`
}

function buildEndpointList(plan: boolean) {
  const list: Array<{
    id: string
    primitive: 'charge' | 'subscription' | 'session' | 'x402'
    method: 'GET' | 'POST'
    path: string
    title: string
    description: string
    cost: string
    /** Machine-readable per-delivery price in base units (sessions only). */
    unitPrice?: string
    params?: Array<{ name: string; default: string; description?: string }>
  }> = [
    {
      id: 'stocks-quote',
      primitive: 'charge',
      method: 'GET',
      path: '/api/v1/stocks/quote/:symbol',
      title: 'Stock quote',
      description: 'Real-time price for a single ticker.',
      cost: '0.01 USDC',
      params: [{ name: 'symbol', default: 'AAPL' }],
    },
    // The stocks-search / stocks-history / weather / fortune routes stay
    // live server-side (the payment-links e2e drives /api/v1/fortune); they
    // are just not advertised in the nav to keep the demo focused.
    {
      id: 'marketplace-buy',
      primitive: 'charge',
      method: 'GET',
      path: '/api/v1/marketplace/buy/:productId',
      title: 'Marketplace purchase',
      description: 'Multi-recipient split (seller + platform + referral).',
      cost: 'varies',
      params: [
        { name: 'productId', default: 'sol-hoodie' },
        { name: 'referrer', default: '' },
      ],
    },
    // The /x402/joke and /x402/fact routes stay live server-side; they are
    // just not advertised in the nav.
    {
      id: 'sessions-stream',
      primitive: 'session',
      method: 'GET',
      path: '/sessions/stream',
      title: 'Metered stream',
      description: 'Pay-per-chunk SSE delivery via session vouchers.',
      cost: '0.0001 USDC / chunk',
      unitPrice: '100',
    },
    {
      id: 'sessions-compute',
      primitive: 'session',
      method: 'POST',
      path: '/sessions/compute',
      title: 'Pay-per-call compute',
      description: 'Voucher-billed inference; cap 0.50 USDC per session.',
      cost: '0.005 USDC / call',
      unitPrice: '5000',
    },
  ]

  if (plan) {
    list.push({
      id: 'premium-feed',
      primitive: 'subscription',
      method: 'GET',
      path: '/api/v1/premium/feed',
      title: 'Subscription',
      description: 'Subscription-gated headlines. Activate once per period.',
      cost: '0.10 USDC / day',
    })
  }

  return list
}
