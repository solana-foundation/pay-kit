// Server-side charge: gate an Express route with `pay.express`.
// See ./README.md for the snippet:start/end convention.

import express from 'express'
import type { KeyPairSigner } from '@solana/kit'
import { createPayKit, usd } from '@solana/pay-kit'

declare const signer: KeyPairSigner
declare const RECIPIENT: string
declare const rpcUrl: string

// snippet:start
const pay = await createPayKit({
  accept: ['mpp', 'x402'], // settle over either protocol — the client picks
  network: 'mainnet',
  operator: { recipient: RECIPIENT, signer }, // KeyPairSigner verifies the charge
  pricing: { quote: { amount: usd('0.01'), description: 'Stock quote' } },
  rpcUrl,
})

const app = express()

// `pay.express(gate)` settles the 402 (MPP or x402) before the handler runs.
app.get('${PATH}', pay.express('quote'), (_req, res) => {
  res.json({ ok: true })
})
// snippet:end

void app
