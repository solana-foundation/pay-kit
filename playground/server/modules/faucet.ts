import type { Express, Request, Response } from 'express'
import { rpcCall } from '../shared/utils.js'
import {
  SOL_FUND_LAMPORTS,
  SYSTEM_PROGRAM,
  TOKEN_PROGRAM,
  USDC_FUND_AMOUNT,
  USDC_MINT,
} from '../shared/constants.js'

export function registerFaucet(app: Express, rpcUrl: string): void {
  app.get('/api/v1/faucet/status', (_req: Request, res: Response) => {
    res.json({ solAmount: '100 SOL', usdcAmount: '100 USDC', usdcMint: USDC_MINT })
  })

  app.post('/api/v1/faucet/airdrop', async (req: Request, res: Response) => {
    const { address } = req.body as { address?: string }
    if (!address) {
      res.status(400).json({ error: 'Missing `address` in request body' })
      return
    }
    try {
      await rpcCall(rpcUrl, 'surfnet_setAccount', [
        address,
        {
          lamports: SOL_FUND_LAMPORTS,
          data: '',
          executable: false,
          owner: SYSTEM_PROGRAM,
          rentEpoch: 0,
        },
      ])
      await rpcCall(rpcUrl, 'surfnet_setTokenAccount', [
        address,
        USDC_MINT,
        { amount: USDC_FUND_AMOUNT, state: 'initialized' },
        TOKEN_PROGRAM,
      ])
      res.json({ ok: true, sol: '100 SOL', usdc: '100 USDC' })
    } catch (err) {
      res.status(500).json({
        error: 'Airdrop failed',
        details: err instanceof Error ? err.message : String(err),
      })
    }
  })
}
