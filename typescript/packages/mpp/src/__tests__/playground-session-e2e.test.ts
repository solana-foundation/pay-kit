/**
 * End-to-end test for the playground's in-process session() method.
 *
 * Spawns the playground server pointed at the public Solana Payment Sandbox
 * (https://402.surfnet.dev:8899 — the payment-channels program is already
 * deployed there), funds a fresh wallet through the playground faucet, then
 * drives the exact flow the playground UI drives: a real payment-channel
 * open (client pre-signs, server completes the fee-payer signature and
 * broadcasts), a metered SSE stream with per-chunk vouchers, and the
 * idle-close watchdog's on-chain settle.
 *
 * Run: pnpm vitest run --config vitest.config.surfpool.ts
 */
import { spawn, type ChildProcess } from 'node:child_process';
import { generateKeyPairSigner } from '@solana/kit';
import { afterAll, beforeAll, describe, expect, test } from 'vitest';

import { createPaymentChannelSessionOpener, createSessionFetch } from '../client/index.js';

const SURFNET_RPC = process.env.PLAYGROUND_SURFNET_RPC ?? 'https://402.surfnet.dev:8899';
const PLAYGROUND_PORT = Number(process.env.PLAYGROUND_E2E_PORT ?? '13456');
const PLAYGROUND_URL = `http://127.0.0.1:${PLAYGROUND_PORT}`;
const PLAYGROUND_SERVER_DIR = new URL('../../../../examples/playground-api', import.meta.url).pathname;

async function probeSurfnet(): Promise<boolean> {
    try {
        const res = await fetch(SURFNET_RPC, {
            body: JSON.stringify({ id: 1, jsonrpc: '2.0', method: 'getHealth', params: [] }),
            headers: { 'Content-Type': 'application/json' },
            method: 'POST',
            signal: AbortSignal.timeout(4000),
        });
        return res.ok;
    } catch {
        return false;
    }
}

async function waitForServer(url: string, timeoutMs = 30_000): Promise<boolean> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
        try {
            const res = await fetch(`${url}/api/v1/health`, { signal: AbortSignal.timeout(2000) });
            if (res.ok) return true;
        } catch {
            /* keep trying */
        }
        await new Promise(r => setTimeout(r, 500));
    }
    return false;
}

interface ReceiptBody {
    readonly cumulative: string;
    readonly deposit: string;
    readonly sealed: boolean;
    readonly settledSignature: string | null;
}

async function fetchReceipt(channelId: string): Promise<ReceiptBody | null> {
    const res = await fetch(`${PLAYGROUND_URL}/sessions/receipt/${encodeURIComponent(channelId)}`);
    if (!res.ok) return null;
    return (await res.json()) as ReceiptBody;
}

describe('playground session e2e', () => {
    let serverProc: ChildProcess | undefined;
    let surfnetUp = false;
    let serverReady = false;

    beforeAll(async () => {
        surfnetUp = await probeSurfnet();
        if (!surfnetUp) {
            console.log(`Skipping: surfnet not reachable at ${SURFNET_RPC}`);
            return;
        }
        serverProc = spawn('pnpm', ['start'], {
            cwd: PLAYGROUND_SERVER_DIR,
            env: {
                ...process.env,
                MPP_SECRET_KEY: 'playground-e2e-secret-key',
                NETWORK: 'mainnet',
                PORT: String(PLAYGROUND_PORT),
                RPC_URL: SURFNET_RPC,
            },
            stdio: ['ignore', 'pipe', 'pipe'],
        });
        serverProc.stderr?.on('data', (chunk: Buffer) => {
            process.stderr.write(`[playground] ${chunk}`);
        });
        serverReady = await waitForServer(PLAYGROUND_URL);
        if (!serverReady) console.log('Playground did not become ready in time');
    }, 60_000);

    afterAll(() => {
        if (serverProc && serverProc.exitCode === null) {
            try {
                serverProc.kill('SIGTERM');
            } catch {
                /* ignore */
            }
        }
    });

    test('real open + metered stream + on-chain settle round-trip', async ctx => {
        if (!surfnetUp) ctx.skip(`surfnet not reachable at ${SURFNET_RPC}`);
        if (!serverReady) throw new Error('playground server did not become ready');

        // 1) Fund a fresh wallet through the playground faucet (surfnet
        //    cheatcodes set its SOL balance and USDC token account).
        const wallet = await generateKeyPairSigner();
        const fund = await fetch(`${PLAYGROUND_URL}/api/v1/faucet/airdrop`, {
            body: JSON.stringify({ address: wallet.address }),
            headers: { 'Content-Type': 'application/json' },
            method: 'POST',
        });
        expect(fund.status).toBe(200);

        // 2) Real payment-channel open + metered SSE through the SDK
        //    client — the same flow the playground UI drives. The wallet
        //    pre-signs the open transaction; the server completes the
        //    fee-payer signature, broadcasts, and confirms before metering.
        let channelId: string | undefined;
        const client = createSessionFetch({
            onEvent: event => {
                if (event.type === 'open') channelId = event.open.session.channelId;
            },
            opener: createPaymentChannelSessionOpener({ rpcUrl: SURFNET_RPC, signer: wallet }),
        });
        const res = await client.fetch(`${PLAYGROUND_URL}/sessions/stream`);
        expect(res.status).toBe(200);
        expect(channelId).toBeTruthy();

        // 3) Meter each streamed chunk and commit vouchers for it.
        const body = await res.text();
        let cumulative = 0n;
        for (const line of body.split('\n')) {
            if (!line.startsWith('data: ') || line.includes('[DONE]')) continue;
            const payload = JSON.parse(line.slice('data: '.length)) as { cost?: string };
            cumulative += BigInt(payload.cost ?? '0');
            client.recordCumulative(cumulative);
        }
        expect(cumulative).toBeGreaterThan(0n);
        await client.flush();

        // 4) The receipt endpoint reports the committed voucher watermark.
        const receipt = await fetchReceipt(channelId!);
        expect(receipt).not.toBeNull();
        expect(receipt!.cumulative).toBe(cumulative.toString());

        // 5) The idle-close watchdog (closeDelayMs = 2s) settles the real
        //    channel on-chain — poll until the settle signature lands.
        let settled: string | null = null;
        const deadline = Date.now() + 60_000;
        while (Date.now() < deadline && !settled) {
            await new Promise(r => setTimeout(r, 1500));
            settled = (await fetchReceipt(channelId!))?.settledSignature ?? null;
        }
        expect(settled).toBeTruthy();
    }, 120_000);
});
