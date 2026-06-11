// Server-side session: per-chunk billing with off-chain vouchers + on-chain settle at close.
// See ./README.md for the snippet:start/end convention.

import express from 'express'
import { createSolanaRpc, type KeyPairSigner } from '@solana/kit'
import { Mppx, session } from '@solana/mpp/server'

declare const signer: KeyPairSigner
declare const RECIPIENT: string
declare const rpcUrl: string
declare function toWebRequest(req: express.Request): globalThis.Request
declare function forward(challenge: globalThis.Response, res: express.Response): void
declare function chunks(): Iterable<string>

// snippet:start
const app = express()
const method = session({
  // On-chain settlement at close needs BOTH the merchant signer and an rpc client.
  signer,
  rpc: createSolanaRpc(rpcUrl),
  operator: signer.address,
  recipient: RECIPIENT,
  network: 'mainnet',
  currency: 'USDC',
  decimals: 6,
  cap: 1_000_000n, // 1 USDC max per session
  pricing: { perDelivery: 100n },
})
const mppx = Mppx.create({ methods: [method] })

app.get('${PATH}', async (req, res) => {
  const result = await mppx.session({ cap: '1000000', currency: 'USDC' })(toWebRequest(req))
  if (result.status === 402) return forward(result.challenge as globalThis.Response, res)
  for (const chunk of chunks()) res.write(`data: ${chunk}\n\n`)
  res.end()
})
// snippet:end

void app
