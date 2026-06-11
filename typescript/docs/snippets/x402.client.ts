// Client-side x402: wrap `globalThis.fetch` so any request that returns
// 402 Payment Required is paid automatically.
// See ./README.md for the snippet:start/end convention.

import { wrapFetchWithPayment } from 'x402-fetch'
import { createSigner } from 'x402/types'

declare const SECRET_KEY: string

async function main(): Promise<void> {
  // snippet:start
  const signer = await createSigner('solana-devnet', SECRET_KEY)
  const fetch = wrapFetchWithPayment(globalThis.fetch, signer)

  const res = await fetch('${URL}')
  console.log(await res.json())
  // snippet:end
}

void main
