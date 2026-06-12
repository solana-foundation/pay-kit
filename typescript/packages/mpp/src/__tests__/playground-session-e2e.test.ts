/**
 * End-to-end test for the playground's in-process session() method.
 *
 * Spawns the playground server pointed at the public Solana Payment Sandbox
 * (https://402.surfnet.dev:8899 — the payment-channels program is already
 * deployed there), opens a channel, sends 3 vouchers, then requests close
 * and asserts the protocol-level voucher accounting via the playground's
 * receipt endpoint.
 *
 * The playground configures `session()` with a merchant signer AND a kit
 * `rpc`, so `close` (and the idle-close watchdog) attempt the on-chain
 * settle. This test opens its channel via the trust path (no on-chain open
 * transaction), so settlement cannot land — the test asserts the off-chain
 * protocol surface only. Settle/distribute instruction encoding is covered
 * at the unit level by `session-on-chain.test.ts` (no surfnet required).
 *
 * Run: pnpm vitest run --config vitest.config.surfpool.ts
 */
import { spawn, type ChildProcess } from 'node:child_process';
import { generateKeyPairSigner, getBase58Decoder, type KeyPairSigner } from '@solana/kit';
import { Challenge, Credential } from 'mppx';
import { afterAll, beforeAll, describe, expect, test } from 'vitest';

import { encodeVoucherMessage } from '../shared/voucher.js';
import type { SessionRequest, SignedVoucher, VoucherData } from '../shared/session-types.js';

const SURFNET_RPC = process.env.PLAYGROUND_SURFNET_RPC ?? 'https://402.surfnet.dev:8899';
const PLAYGROUND_PORT = Number(process.env.PLAYGROUND_E2E_PORT ?? '13456');
const PLAYGROUND_URL = `http://127.0.0.1:${PLAYGROUND_PORT}`;
const PLAYGROUND_SERVER_DIR = new URL('../../../../../playground/server', import.meta.url).pathname;

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

async function makeSignedVoucher(
    signer: KeyPairSigner,
    channelId: string,
    cumulative: bigint,
    expiresAt: number,
): Promise<SignedVoucher> {
    const data: VoucherData = {
        channelId,
        cumulativeAmount: cumulative.toString(),
        expiresAt,
    };
    const message = encodeVoucherMessage(data);
    const [signatures] = await signer.signMessages([{ content: message, signatures: {} }]);
    const sigBytes = signatures?.[signer.address];
    if (!sigBytes) throw new Error('signer produced no signature');
    return { data, signature: getBase58Decoder().decode(new Uint8Array(sigBytes)) };
}

async function getSessionChallenge(path: string): Promise<Challenge.Challenge<SessionRequest, 'session', 'solana'>> {
    const res = await fetch(`${PLAYGROUND_URL}${path}`, { method: path.endsWith('/compute') ? 'POST' : 'GET' });
    expect(res.status).toBe(402);
    const challenge = Challenge.fromResponse(res) as Challenge.Challenge<SessionRequest, 'session', 'solana'>;
    expect(challenge.id).toBeTruthy();
    return challenge;
}

async function postSessionAction(
    path: string,
    challenge: Challenge.Challenge<SessionRequest, 'session', 'solana'>,
    payload: Record<string, unknown>,
): Promise<Response> {
    const credential = Credential.serialize({ challenge, payload });
    const method = path.endsWith('/compute') ? 'POST' : 'GET';
    const init: RequestInit = {
        headers: {
            Authorization: credential,
            'Content-Type': 'application/json',
        },
        method,
    };
    if (method === 'POST') init.body = JSON.stringify({});
    return await fetch(`${PLAYGROUND_URL}${path}`, init);
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

    test('open + 3 vouchers + close round-trip succeeds', async ctx => {
        if (!surfnetUp) ctx.skip(`surfnet not reachable at ${SURFNET_RPC}`);
        if (!serverReady) throw new Error('playground server did not become ready');

        // 1) GET /sessions/stream → 402 session challenge
        const challenge = await getSessionChallenge('/sessions/stream');
        expect(challenge.request.currency).toBeTruthy();
        expect(challenge.request.operator).toBeTruthy();
        expect(challenge.request.recipient).toBeTruthy();
        expect(challenge.request.cap).toBe('1000000');

        const signer = await generateKeyPairSigner();
        // Use a fresh keypair address as the channel id (32-byte base58 pubkey).
        const channelKeyPair = await generateKeyPairSigner();
        const channelId = channelKeyPair.address;
        const deposit = '500000';
        const expiresAt = Math.floor(Date.now() / 1000) + 3600;

        // 2) open via the no-transaction trust path (channelId + deposit + signer)
        const openRes = await postSessionAction('/sessions/stream', challenge, {
            action: 'open',
            authorizedSigner: signer.address,
            channelId,
            deposit,
            mode: 'push',
            signature: 'e2e-open-signature',
        });
        expect(openRes.status).toBe(200);

        // 3) send three increasing vouchers
        for (let i = 1; i <= 3; i++) {
            const cumulative = BigInt(100 * i);
            const voucher = await makeSignedVoucher(signer, channelId, cumulative, expiresAt);
            const voucherRes = await postSessionAction('/sessions/stream', challenge, {
                action: 'voucher',
                voucher,
            });
            expect(voucherRes.status).toBe(200);
        }

        // 4) request close with a final voucher. The server accepts the
        //    voucher and flips the channel to close-pending before it
        //    attempts on-chain settlement; settlement of this trust-path
        //    channel (never opened on-chain) cannot land, so don't assert
        //    the close response status — assert the stored watermark below.
        const finalVoucher = await makeSignedVoucher(signer, channelId, 350n, expiresAt);
        await postSessionAction('/sessions/stream', challenge, {
            action: 'close',
            channelId,
            voucher: finalVoucher,
        });

        // 5) the receipt endpoint must report the final voucher's cumulative
        //    amount — proof the off-chain voucher accounting round-tripped.
        const receiptRes = await fetch(`${PLAYGROUND_URL}/sessions/receipt/${channelId}`);
        expect(receiptRes.status).toBe(200);
        const receipt = (await receiptRes.json()) as { cumulative: string; deposit: string };
        expect(receipt.cumulative).toBe('350');
        expect(receipt.deposit).toBe(deposit);
    }, 30_000);
});
