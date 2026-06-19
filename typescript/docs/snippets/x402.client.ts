// Client-side x402: the same pay-kit client settles an x402 challenge.
// Pass the protocol to force the x402 rail when an endpoint offers both.
// See ./README.md for the snippet:start/end convention.

import { createPayKitClient } from '@solana/pay-kit/client'
import { createKeyPairSignerFromBytes, getBase58Encoder } from '@solana/kit'

declare const SECRET: string

async function main(): Promise<void> {
  // snippet:start
  const signer = await createKeyPairSignerFromBytes(getBase58Encoder().encode(SECRET))
  const client = await createPayKitClient({ signer, rpcUrl: 'http://localhost:8899' })

  // Force the x402 rail (omit the 3rd arg to let pay-kit pick MPP or x402).
  const res = await client.fetch('${URL}', undefined, 'x402')
  console.log(await res.json())
  // snippet:end
}

void main
