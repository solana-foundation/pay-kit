/**
 * LOCAL SANDBOX ONLY.
 *
 * Funding here uses the surfnet (`https://402.surfnet.dev:8899`) cheatcode RPC
 * methods `surfnet_setAccount` / `surfnet_setTokenAccount`. They exist only on
 * the local Solana Payment Sandbox — on devnet/mainnet these calls are no-ops
 * (caught and warned). None of this is part of how a real PayKit server runs;
 * it just makes the playground work zero-config.
 */
import type { Express, Request, Response } from 'express'
import { generateKeyPairSigner } from '@solana/kit'
import { TOKEN_PROGRAM_ADDRESS } from '@solana-program/token'
import { resolveStablecoinMint, SUBSCRIPTIONS_PROGRAM } from '@solana/mpp'

// The sandbox clones mainnet state, so it funds the *mainnet* USDC mint
// regardless of the configured network tag.
const USDC_MINT = resolveStablecoinMint('USDC', 'mainnet') ?? ''
const SYSTEM_PROGRAM = '11111111111111111111111111111111'
const SOL_FUND_LAMPORTS = 100_000_000_000 // 100 SOL
const USDC_FUND_AMOUNT = 100_000_000 // 100 USDC (6 decimals)

/** Fund the given addresses with SOL + USDC on the local sandbox. Best-effort. */
export async function fundSandbox(rpcUrl: string, ...addresses: string[]): Promise<void> {
  try {
    for (const address of addresses) {
      await rpcCall(rpcUrl, 'surfnet_setAccount', [
        address,
        { lamports: SOL_FUND_LAMPORTS, data: '', executable: false, owner: SYSTEM_PROGRAM, rentEpoch: 0 },
      ])
      await rpcCall(rpcUrl, 'surfnet_setTokenAccount', [
        address,
        USDC_MINT,
        { amount: USDC_FUND_AMOUNT, state: 'initialized' },
        TOKEN_PROGRAM_ADDRESS,
      ])
    }
  } catch {
    console.warn('  Sandbox RPC not reachable — accounts may be unfunded.')
  }
}

/** Fund the given addresses with USDC only (no SOL) on the local sandbox.
 * Client wallets never pay network fees — the operator fee-pays every gate —
 * so they only need a USDC balance. Best-effort. */
export async function fundUsdc(rpcUrl: string, ...addresses: string[]): Promise<void> {
  try {
    for (const address of addresses) {
      await rpcCall(rpcUrl, 'surfnet_setTokenAccount', [
        address,
        USDC_MINT,
        { amount: USDC_FUND_AMOUNT, state: 'initialized' },
        TOKEN_PROGRAM_ADDRESS,
      ])
    }
  } catch {
    console.warn('  Sandbox RPC not reachable — USDC not funded.')
  }
}

/** Minimal JSON-RPC 2.0 call for the surfnet cheatcode methods. */
async function rpcCall(rpcUrl: string, method: string, params: unknown[]): Promise<void> {
  const res = await fetch(rpcUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
    signal: AbortSignal.timeout(8000),
  })
  const data = (await res.json()) as { error?: { message: string } }
  if (data.error) throw new Error(`${method}: ${data.error.message}`)
}

/**
 * Stuff a synthetic subscription Plan account on the local sandbox and return
 * its address (the `planId`), or `null` if the sandbox is unreachable.
 *
 * The plan lives at a fresh random address owned by the subscriptions program
 * so the server can issue a subscription challenge that pins it — exercising the
 * full challenge → sign → submit handshake. (On-chain activation needs the real
 * program deployed; this stub just makes the playground self-contained.) The
 * address is distinct from the operator/recipient so reassigning its owner can't
 * break fee-payer eligibility for the other gates.
 */
export async function bootstrapPlan(rpcUrl: string): Promise<string | null> {
  try {
    const planId = (await generateKeyPairSigner()).address
    await rpcCall(rpcUrl, 'surfnet_setAccount', [
      planId,
      { lamports: 1_000_000_000, data: '', executable: false, owner: SUBSCRIPTIONS_PROGRAM, rentEpoch: 0 },
    ])
    return planId
  } catch (err) {
    console.warn('  Sandbox plan bootstrap failed — subscription route disabled:', err instanceof Error ? err.message : String(err))
    return null
  }
}

/** Mount a faucet that airdrops sandbox USDC to an address (no SOL needed). */
export function registerFaucet(app: Express, rpcUrl: string): void {
  app.get('/api/v1/faucet/status', (_req: Request, res: Response) => {
    res.json({ usdcAmount: '100 USDC', usdcMint: USDC_MINT })
  })

  app.post('/api/v1/faucet/airdrop', async (req: Request, res: Response) => {
    const { address } = req.body as { address?: string }
    if (!address) {
      res.status(400).json({ error: 'Missing `address` in request body' })
      return
    }
    try {
      await fundUsdc(rpcUrl, address)
      res.json({ ok: true, usdc: '100 USDC' })
    } catch (err) {
      res.status(500).json({ error: 'Airdrop failed', details: err instanceof Error ? err.message : String(err) })
    }
  })
}
