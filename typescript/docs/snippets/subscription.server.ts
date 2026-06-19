// Server-side subscription: gate a route with a `subscription` pricing gate.
// See ./README.md for the snippet:start/end convention.

import express from 'express'
import type { KeyPairSigner } from '@solana/kit'
import { createPayKit, subscription, usd } from '@solana/pay-kit'

declare const signer: KeyPairSigner
declare const RECIPIENT: string
declare const PLAN_ID: string
declare const rpcUrl: string

// snippet:start
const pay = await createPayKit({
  network: 'mainnet',
  operator: { recipient: RECIPIENT, signer },
  pricing: {
    feed: subscription(usd('0.10'), {
      planId: PLAN_ID, // on-chain Plan PDA, created ahead of time
      puller: signer.address, // entity allowed to pull renewals
      periodUnit: 'day',
      periodCount: 1,
    }),
  },
  rpcUrl,
})

const app = express()

// First call activates the plan on-chain; `pay.express` gates the rest.
app.get('${PATH}', pay.express('feed'), (_req, res) => {
  res.json({ items: [/* … */] })
})
// snippet:end

void app
