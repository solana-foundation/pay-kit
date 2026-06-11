// Client-side session: open one payment channel, stream paid chunks.
// See ./README.md for the snippet:start/end convention.

import { createPaymentChannelSessionOpener, createSessionFetch } from '@solana/mpp/client'
import type { KeyPairSigner } from '@solana/kit'

declare const signer: KeyPairSigner
declare const rpcUrl: string

async function main(): Promise<void> {
  // snippet:start
  const client = createSessionFetch({
    opener: createPaymentChannelSessionOpener({ signer, rpcUrl }),
  })

  const res = await client.fetch('${URL}')
  for await (const chunk of res.body!) {
    process.stdout.write(chunk)
  }
  // snippet:end
}

void main
