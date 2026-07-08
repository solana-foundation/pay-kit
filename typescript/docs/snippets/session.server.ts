// Server-side session: per-chunk billing with off-chain vouchers + on-chain settle at close.
// See ./README.md for the snippet:start/end convention.

import express from 'express'
import type { KeyPairSigner } from '@solana/kit'
import { createPayKit, session, usd } from '@solana/pay-kit'

declare const signer: KeyPairSigner
declare const RECIPIENT: string
declare const rpcUrl: string
declare function chunks(): Iterable<string>

// snippet:start
const pay = await createPayKit({
  network: 'mainnet',
  operator: { recipient: RECIPIENT, signer },
  // Cap 1 USDC per session, metered at 0.0001 USDC per delivered chunk.
  pricing: { stream: session(usd('1.00'), { unitPrice: usd('0.0001') }) },
  rpcUrl,
})

const app = express()

// Gate the stream; settlement runs out-of-band when the channel idle-closes.
app.get('${PATH}', pay.express('stream'), (_req, res) => {
  res.writeHead(200, { 'Content-Type': 'text/event-stream' })
  for (const chunk of chunks()) res.write(`data: ${chunk}\n\n`)
  res.end()
})

// Session side-channel + receipt routes — mounted explicitly (pay-kit, like
// mppx, leaves route-mounting to the app rather than auto-injecting them).
const routes = pay.sessionRoutes('stream')
app.post('${PATH}', routes.voucher) // voucher commits to the resource URL
app.post('/__402/session/deliveries', routes.deliveries)
app.post('/__402/session/commit', routes.commit)
app.get('/sessions/receipt/:channelId', routes.receipt)
// snippet:end

void app
