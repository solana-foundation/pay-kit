// Server-side subscription: gate any route with `solana.subscription`.
// See ./README.md for the snippet:start/end convention.

import express from 'express'
import type { KeyPairSigner } from '@solana/kit'
import { Mppx, solana } from '@solana/mpp/server'

declare const signer: KeyPairSigner
declare const RECIPIENT: string
declare const PLAN_ID: string
declare const USDC_MINT: string
declare const TOKEN_PROGRAM: string
declare const rpcUrl: string
declare function toWebRequest(req: express.Request): globalThis.Request
declare function forward(challenge: globalThis.Response, res: express.Response): void

// snippet:start
const app = express()
const method = solana.subscription({
  signer, // optional fee payer — co-signs the activation transaction
  planId: PLAN_ID, // on-chain Plan PDA, created ahead of time
  mint: USDC_MINT,
  decimals: 6,
  tokenProgram: TOKEN_PROGRAM,
  puller: signer.address, // entity allowed to pull renewals
  recipient: RECIPIENT,
  periodUnit: 'day',
  periodCount: 1,
  rpcUrl,
})
const mppx = Mppx.create({ methods: [method] })

app.get('${PATH}', async (req, res) => {
  const result = await mppx.subscription({ amount: '100000' /* 0.10 USDC / period */ })(
    toWebRequest(req),
  )
  if (result.status === 402) return forward(result.challenge as globalThis.Response, res)
  return result.withReceipt(globalThis.Response.json({ items: [/* … */] }))
})
// snippet:end

void app
