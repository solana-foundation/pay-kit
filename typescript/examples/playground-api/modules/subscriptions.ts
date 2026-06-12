import type { Express, Request, Response as ExpressResponse } from 'express'
import type { KeyPairSigner } from '@solana/kit'
import { Mppx, solana } from '@solana/mpp/server'
import { toWebRequest } from '../shared/utils.js'
import { TOKEN_PROGRAM, USDC_DECIMALS, USDC_MINT } from '../shared/constants.js'
import type { PlanInfo } from '../shared/plan-bootstrap.js'

const Web = globalThis

interface RegisterOptions {
  recipient: string
  network: string
  secretKey: string
  feePayerSigner: KeyPairSigner
  rpcUrl: string
  plan: PlanInfo
}

const PREMIUM_HEADLINES = [
  { title: 'Solana session validators hit a new throughput record', tag: 'engineering' },
  { title: 'Stablecoin transfer volume crosses $4T on-chain quarterly', tag: 'macro' },
  { title: 'New payment-channel program audit lands', tag: 'security' },
  { title: 'MPP v2 extensions ship to mainnet beta', tag: 'protocol' },
]

/**
 * Subscriptions module — exposes `/api/v1/premium/feed` behind an MPP
 * subscription gate. The active plan is bootstrapped on server boot.
 *
 * The `puller` field is the entity that periodically debits the subscriber
 * for renewals. For the demo, the server's fee-payer doubles as the puller.
 */
export function registerSubscriptions(app: Express, opts: RegisterOptions): void {
  const { recipient, network, secretKey, feePayerSigner, rpcUrl, plan } = opts

  // The subscriptions program only supports day/week period units. Map the
  // playground's plan period (in hours) onto whole-day buckets so the on-chain
  // call validates cleanly.
  const periodDays = Math.max(1, Math.round(plan.periodHours / 24))

  const mppx = Mppx.create({
    secretKey,
    methods: [
      solana.subscription({
        planId: plan.planId,
        mint: USDC_MINT,
        decimals: USDC_DECIMALS,
        tokenProgram: TOKEN_PROGRAM,
        puller: feePayerSigner.address,
        recipient,
        periodUnit: 'day',
        periodCount: periodDays,
        network,
        rpcUrl,
        signer: feePayerSigner,
      }),
    ],
  })

  app.get('/api/v1/premium/feed', async (req: Request, res: ExpressResponse) => {
    const result = await mppx.subscription({
      amount: plan.amount,
      currency: plan.currency,
      description: plan.description,
    })(toWebRequest(req))

    if (result.status === 402) {
      const challenge = result.challenge as globalThis.Response
      res.writeHead(challenge.status, Object.fromEntries(challenge.headers))
      res.end(await challenge.text())
      return
    }

    const headlines = PREMIUM_HEADLINES.slice().sort(() => Math.random() - 0.5).slice(0, 3)
    const response = result.withReceipt(
      Web.Response.json({
        headlines,
        generatedAt: new Date().toISOString(),
        plan: { id: plan.planId, periodHours: plan.periodHours },
      }),
    ) as globalThis.Response
    res.writeHead(response.status, Object.fromEntries(response.headers))
    res.end(await response.text())
  })
}
