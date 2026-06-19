// Client-side subscription: first call activates on-chain, subsequent calls are free.
// See ./README.md for the snippet:start/end convention.

import { createPayKitClient } from '@solana/pay-kit/client'
import { createKeyPairSignerFromBytes, getBase58Encoder } from '@solana/kit'

declare const SECRET: string

async function main(): Promise<void> {
  // snippet:start
  const signer = await createKeyPairSignerFromBytes(getBase58Encoder().encode(SECRET))
  const client = await createPayKitClient({ signer, rpcUrl: 'http://localhost:8899' })

  // First call activates the subscription on-chain; subsequent calls within
  // the period re-use it for free — pay-kit settles the 402 either way.
  const res = await client.fetch('${URL}')
  console.log(await res.json())
  // snippet:end
}

void main
