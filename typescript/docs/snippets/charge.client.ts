// Client-side charge: one signed Solana transaction settles the call.
// See ./README.md for the snippet:start/end convention.

import { Mppx, solana } from '@solana/mpp/client'
import { createKeyPairSignerFromBytes, getBase58Encoder } from '@solana/kit'

declare const SECRET: string

async function main(): Promise<void> {
  // snippet:start
  const signer = await createKeyPairSignerFromBytes(getBase58Encoder().encode(SECRET))
  const method = solana.charge({ signer, rpcUrl: 'http://localhost:8899' })
  const mppx = Mppx.create({ methods: [method] })

  const res = await mppx.fetch('${URL}')
  console.log(await res.json())
  // snippet:end
}

void main
