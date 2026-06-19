// Client-side charge: pay-kit settles the 402 over MPP or x402, then retries.
// See ./README.md for the snippet:start/end convention.

import { createPayKitClient } from '@solana/pay-kit/client'
import { createKeyPairSignerFromBytes, getBase58Encoder } from '@solana/kit'

declare const SECRET: string

async function main(): Promise<void> {
  // snippet:start
  const signer = await createKeyPairSignerFromBytes(getBase58Encoder().encode(SECRET))
  const client = await createPayKitClient({ signer, rpcUrl: 'http://localhost:8899' })

  // On a 402, pay-kit pays with the matching protocol and retries — transparently.
  const res = await client.fetch('${URL}')
  console.log(await res.json())
  // snippet:end
}

void main
