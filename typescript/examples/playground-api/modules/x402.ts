import type { Express, Request, Response as ExpressResponse } from 'express'
import express from 'express'
import type { KeyPairSigner } from '@solana/kit'
import { paymentMiddleware } from 'x402-express'

interface RegisterOptions {
  recipient: string
  rpcUrl: string
  facilitatorUrl: string
  feePayerSigner: KeyPairSigner
}

const JOKES = [
  'Why do programmers prefer dark mode? Because light attracts bugs.',
  'There are 10 types of people: those who understand binary and those who don’t.',
  'A SQL query walks into a bar, sees two tables, and asks: "Can I JOIN you?"',
  'A photon checks into a hotel; the bellhop asks if it has any luggage. "No, I’m traveling light."',
]

const FACTS = [
  'Honey never spoils. Archaeologists found 3000-year-old honey in Egyptian tombs.',
  'Octopuses have three hearts and blue blood.',
  'A group of flamingos is called a "flamboyance".',
  'Bananas are berries; strawberries are not.',
]

export function registerX402(app: Express, opts: RegisterOptions): void {
  const { recipient, rpcUrl, facilitatorUrl, feePayerSigner } = opts

  // ── Embedded facilitator ──
  app.get('/facilitator/supported', (_req: Request, res: ExpressResponse) => {
    res.json({
      kinds: [
        {
          scheme: 'exact',
          network: 'solana-devnet',
          extra: { feePayer: feePayerSigner.address },
        },
      ],
    })
  })

  app.post('/facilitator/verify', (req: Request, res: ExpressResponse) => {
    const { paymentPayload } = (req.body ?? {}) as { paymentPayload?: { payload?: { authorization?: { from?: string } } } }
    if (!paymentPayload?.payload) {
      res.json({ isValid: false, invalidReason: 'Missing payload' })
      return
    }
    res.json({
      isValid: true,
      payer: paymentPayload.payload.authorization?.from ?? 'unknown',
    })
  })

  app.post('/facilitator/settle', async (req: Request, res: ExpressResponse) => {
    const { paymentPayload } = (req.body ?? {}) as { paymentPayload?: { payload?: { transaction?: string } } }
    const payload = paymentPayload?.payload
    if (!payload) {
      res.json({ success: false, errorReason: 'Missing payload' })
      return
    }
    try {
      if (payload.transaction) {
        const result = await fetch(rpcUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            jsonrpc: '2.0',
            id: 1,
            method: 'sendTransaction',
            params: [payload.transaction, { encoding: 'base64', skipPreflight: true }],
          }),
        })
        const data = (await result.json()) as { error?: { message: string }; result?: string }
        if (data.error) {
          res.json({ success: false, errorReason: data.error.message })
          return
        }
        res.json({ success: true, transaction: data.result })
        return
      }
      res.json({ success: true, transaction: 'local-facilitator-settled' })
    } catch (err) {
      res.json({
        success: false,
        errorReason: err instanceof Error ? err.message : String(err),
      })
    }
  })

  // ── x402-gated routes ──
  const x402Router = express.Router()
  x402Router.use(
    paymentMiddleware(
      recipient as `0x${string}`,
      {
        '/x402/joke': {
          price: '$0.001',
          network: 'solana-devnet' as never,
          config: { description: 'A random programmer joke' },
        },
        '/x402/fact': {
          price: '$0.001',
          network: 'solana-devnet' as never,
          config: { description: 'A random fun fact' },
        },
      },
      { url: facilitatorUrl as `${string}://${string}` },
    ),
  )

  x402Router.get('/x402/joke', (_req: Request, res: ExpressResponse) => {
    res.json({ joke: JOKES[Math.floor(Math.random() * JOKES.length)], source: 'x402' })
  })

  x402Router.get('/x402/fact', (_req: Request, res: ExpressResponse) => {
    res.json({ fact: FACTS[Math.floor(Math.random() * FACTS.length)], source: 'x402' })
  })

  app.use(x402Router)
}
