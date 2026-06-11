// Server-side charge: gate an Express route with `solana.charge`.
// See ./README.md for the snippet:start/end convention.

import express from 'express'
import type { KeyPairSigner } from '@solana/kit'
import { Mppx, solana } from '@solana/mpp/server'

declare const signer: KeyPairSigner
declare const RECIPIENT: string
declare const rpcUrl: string
declare function toWebRequest(req: express.Request): globalThis.Request
declare function forward(challenge: globalThis.Response, res: express.Response): void

// snippet:start
const app = express()
const method = solana.charge({
  signer, // KeyPairSigner — verifies the on-chain charge
  recipient: RECIPIENT,
  network: 'mainnet',
  currency: 'USDC',
  rpcUrl,
})
const mppx = Mppx.create({ methods: [method] })

app.get('${PATH}', async (req, res) => {
  const result = await mppx.charge({ amount: '10000', currency: 'USDC' })(toWebRequest(req))
  if (result.status === 402) return forward(result.challenge as globalThis.Response, res)
  return result.withReceipt(globalThis.Response.json({ ok: true }))
})
// snippet:end

void app
