// Client-side subscription: first call activates on-chain, subsequent calls are free.
// See ./README.md for the snippet:start/end convention.

import { Mppx, solana } from '@solana/mpp/client'
import { createKeyPairSignerFromBytes, getBase58Encoder } from '@solana/kit'

declare const SECRET: string

async function main(): Promise<void> {
  // snippet:start
  const signer = await createKeyPairSignerFromBytes(getBase58Encoder().encode(SECRET))
  const method = solana.subscription({ signer, rpcUrl: 'http://localhost:8899' })
  const mppx = Mppx.create({ methods: [method] })

  // First call activates the subscription on-chain;
  // subsequent calls within the period re-use it for free.
  const res = await mppx.fetch('${URL}')
  console.log(await res.json())
  // snippet:end
}

void main
