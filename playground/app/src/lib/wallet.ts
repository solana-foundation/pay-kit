import {
  address,
  createKeyPairSignerFromBytes,
  createSolanaRpc,
  getBase58Decoder,
  getBase58Encoder,
  type KeyPairSigner,
} from '@solana/kit'
import { findAssociatedTokenPda } from '@solana-program/token'

const STORAGE_KEY = 'paykit-playground:secret-key'
// Hosted Solana Payment Sandbox — same RPC the playground server defaults to.
// Used for in-browser balance queries + signing previews. Surfnet exposes a
// CORS-friendly endpoint, so the browser can call it directly.
const RPC_URL = 'https://402.surfnet.dev:8899'
const USDC_MINT = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v'
const TOKEN_PROGRAM = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA'

export interface Balances {
  sol: number
  usdc: number
}

export function loadSecretKey(): string | null {
  return localStorage.getItem(STORAGE_KEY)
}

export function saveSecretKey(base58Key: string): void {
  localStorage.setItem(STORAGE_KEY, base58Key)
  signerPromise = null
}

export function clearWallet(): void {
  localStorage.removeItem(STORAGE_KEY)
  signerPromise = null
}

let signerPromise: Promise<KeyPairSigner> | null = null

export async function getSigner(): Promise<KeyPairSigner> {
  if (!signerPromise) {
    const key = loadSecretKey()
    if (!key) throw new Error('No wallet configured')
    signerPromise = createKeyPairSignerFromBytes(getBase58Encoder().encode(key))
  }
  return signerPromise
}

export async function generateWallet(): Promise<KeyPairSigner> {
  const keyPair = await crypto.subtle.generateKey(
    { name: 'Ed25519', namedCurve: 'Ed25519' } as EcKeyGenParams,
    true,
    ['sign', 'verify'],
  )
  const publicKey = new Uint8Array(await crypto.subtle.exportKey('raw', keyPair.publicKey))
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', keyPair.privateKey))
  const privateKey = pkcs8.slice(16, 48)
  const combined = new Uint8Array(64)
  combined.set(privateKey)
  combined.set(publicKey, 32)
  saveSecretKey(getBase58Decoder().decode(combined))
  return getSigner()
}

export async function importKeypairJson(jsonContent: string): Promise<KeyPairSigner> {
  const bytes = JSON.parse(jsonContent) as number[]
  if (!Array.isArray(bytes) || bytes.length !== 64) {
    throw new Error('Invalid keypair file: expected a JSON array of 64 bytes')
  }
  saveSecretKey(getBase58Decoder().decode(new Uint8Array(bytes)))
  return getSigner()
}

export async function getBalances(): Promise<Balances> {
  const signer = await getSigner()
  const rpc = createSolanaRpc(RPC_URL)

  const { value: lamports } = await rpc.getBalance(signer.address).send()
  const sol = Number(lamports) / 1e9

  let usdc = 0
  try {
    const [ata] = await findAssociatedTokenPda({
      owner: signer.address,
      mint: address(USDC_MINT),
      tokenProgram: address(TOKEN_PROGRAM),
    })
    const res = await fetch(RPC_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'getAccountInfo',
        params: [ata, { encoding: 'jsonParsed' }],
      }),
    })
    const data = (await res.json()) as {
      result?: { value?: { data?: { parsed?: { info?: { tokenAmount?: { uiAmount?: number } } } } } }
    }
    const amount = data.result?.value?.data?.parsed?.info?.tokenAmount?.uiAmount
    if (typeof amount === 'number') usdc = amount
  } catch {
    /* token account may not exist yet */
  }

  return { sol, usdc }
}

export async function getSolBalance(addr: string): Promise<number> {
  const rpc = createSolanaRpc(RPC_URL)
  const { value } = await rpc.getBalance(addr as Parameters<typeof rpc.getBalance>[0]).send()
  return Number(value) / 1e9
}

export async function requestAirdrop(): Promise<void> {
  const signer = await getSigner()
  const res = await fetch('/api/v1/faucet/airdrop', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ address: signer.address }),
  })
  const data = (await res.json()) as { error?: string }
  if (!res.ok) throw new Error(data.error ?? 'Airdrop failed')
}

export { RPC_URL, USDC_MINT, TOKEN_PROGRAM }
