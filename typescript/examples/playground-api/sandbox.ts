/**
 * LOCAL SANDBOX ONLY.
 *
 * Funding here uses the surfnet (`https://402.surfnet.dev:8899`) cheatcode RPC
 * methods `surfnet_setAccount` / `surfnet_setTokenAccount`. They exist only on
 * the local Solana Payment Sandbox — on devnet/mainnet these calls are no-ops
 * (caught and warned). None of this is part of how a real PayKit server runs;
 * it just makes the playground work zero-config.
 */
import type { Express, Request, Response } from 'express';
import { TOKEN_PROGRAM_ADDRESS } from '@solana-program/token';
import { resolveStablecoinMint } from '@solana/mpp';

// The sandbox clones mainnet state, so it funds the *mainnet* USDC mint
// regardless of the configured network tag.
const USDC_MINT = resolveStablecoinMint('USDC', 'mainnet') ?? '';
const SYSTEM_PROGRAM = '11111111111111111111111111111111';
const SOL_FUND_LAMPORTS = 100_000_000_000; // 100 SOL
const USDC_FUND_AMOUNT = 100_000_000; // 100 USDC (6 decimals)

/** Fund the given addresses with SOL + USDC on the local sandbox. Best-effort. */
export async function fundSandbox(rpcUrl: string, ...addresses: string[]): Promise<void> {
    try {
        for (const address of addresses) {
            await rpcCall(rpcUrl, 'surfnet_setAccount', [
                address,
                { lamports: SOL_FUND_LAMPORTS, data: '', executable: false, owner: SYSTEM_PROGRAM, rentEpoch: 0 },
            ]);
            await rpcCall(rpcUrl, 'surfnet_setTokenAccount', [
                address,
                USDC_MINT,
                { amount: USDC_FUND_AMOUNT, state: 'initialized' },
                TOKEN_PROGRAM_ADDRESS,
            ]);
        }
    } catch {
        console.warn('  Sandbox RPC not reachable — accounts may be unfunded.');
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
            ]);
        }
    } catch {
        console.warn('  Sandbox RPC not reachable — USDC not funded.');
    }
}

/** Minimal JSON-RPC 2.0 call for the surfnet cheatcode methods. */
async function rpcCall(rpcUrl: string, method: string, params: unknown[]): Promise<void> {
    const res = await fetch(rpcUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
        signal: AbortSignal.timeout(8000),
    });
    const data = (await res.json()) as { error?: { message: string } };
    if (data.error) throw new Error(`${method}: ${data.error.message}`);
}

export type SubscriptionPlanSnapshot = {
    merchant: string;
    planBump: number;
    planCreatedAt: bigint;
    planId: string;
    planIdNumeric: bigint;
};

/** Read an immutable snapshot from a separately provisioned on-chain Plan. */
export function subscriptionPlanFromEnv(): SubscriptionPlanSnapshot | null {
    const { PLAN_BUMP, PLAN_CREATED_AT, PLAN_ID, PLAN_ID_NUMERIC, PLAN_MERCHANT } = process.env;
    const values = [PLAN_BUMP, PLAN_CREATED_AT, PLAN_ID, PLAN_ID_NUMERIC, PLAN_MERCHANT];
    if (values.every(value => value === undefined)) return null;
    if (values.some(value => value === undefined || value === '')) {
        throw new Error(
            'Subscription requires PLAN_ID, PLAN_BUMP, PLAN_CREATED_AT, PLAN_ID_NUMERIC, and PLAN_MERCHANT',
        );
    }
    const planBump = Number(PLAN_BUMP);
    if (!Number.isInteger(planBump) || planBump < 0 || planBump > 255) throw new Error('PLAN_BUMP must be a u8');
    const planCreatedAt = BigInt(PLAN_CREATED_AT!);
    const planIdNumeric = BigInt(PLAN_ID_NUMERIC!);
    if (planCreatedAt < 0n) throw new Error('PLAN_CREATED_AT must be non-negative');
    if (planIdNumeric < 0n || planIdNumeric > 18_446_744_073_709_551_615n) {
        throw new Error('PLAN_ID_NUMERIC must be a u64');
    }
    return { merchant: PLAN_MERCHANT!, planBump, planCreatedAt, planId: PLAN_ID!, planIdNumeric };
}

/** Mount a faucet that airdrops sandbox USDC to an address (no SOL needed). */
export function registerFaucet(app: Express, rpcUrl: string): void {
    app.get('/api/v1/faucet/status', (_req: Request, res: Response) => {
        res.json({ usdcAmount: '100 USDC', usdcMint: USDC_MINT });
    });

    app.post('/api/v1/faucet/airdrop', async (req: Request, res: Response) => {
        const { address } = req.body as { address?: string };
        if (!address) {
            res.status(400).json({ error: 'Missing `address` in request body' });
            return;
        }
        try {
            await fundUsdc(rpcUrl, address);
            res.json({ ok: true, usdc: '100 USDC' });
        } catch (err) {
            res.status(500).json({
                error: 'Airdrop failed',
                details: err instanceof Error ? err.message : String(err),
            });
        }
    });
}
