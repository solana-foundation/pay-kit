// Cross-SDK pinning of the voucher reject-reason wire tags.
//
// The reject reason is a documented stable wire contract: every SDK must emit
// the byte-identical string for each reject tag. This suite loads the shared
// vector (harness/vectors/session-voucher/session-voucher-reject.json) and
// asserts the TypeScript verifier's tags match, tag by tag. The
// settlement-window tag is additionally driven through the verifier so the
// emitted (not just the declared) value is pinned.

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { generateKeyPairSigner, getBase58Decoder } from '@solana/kit';
import { describe, expect, it } from 'vitest';

import type { ChannelState } from '../server/session/store.js';
import { verifyVoucherForChannel, type VoucherRejectReason } from '../server/session/voucher.js';
import type { SignedVoucher, VoucherData } from '../shared/session-types.js';
import { encodeVoucherMessage } from '../shared/voucher.js';

interface RejectVector {
    readonly tag: string;
    readonly reason: string;
    readonly description: string;
}

const here = dirname(fileURLToPath(import.meta.url));
const vectorPath = join(
    here,
    '..',
    '..',
    '..',
    '..',
    '..',
    'harness',
    'vectors',
    'session-voucher',
    'session-voucher-reject.json',
);

function loadRejectVectors(): RejectVector[] {
    const vectors = JSON.parse(readFileSync(vectorPath, 'utf8')) as RejectVector[];
    expect(vectors.length).toBeGreaterThan(0);
    return vectors;
}

// Canonical tag -> the TypeScript reason literal. Typed as `VoucherRejectReason`
// so a drift in the union (a renamed/removed literal) fails typecheck, while a
// drift against the vector fails at runtime below.
const EMITTED: Record<string, VoucherRejectReason> = {
    'below-min-delta': 'below-min-delta',
    'channel-close-pending': 'channel-close-pending',
    'channel-finalized': 'channel-finalized',
    'cumulative-not-monotonic': 'cumulative-not-monotonic',
    'exceeds-deposit': 'exceeds-deposit',
    expired: 'expired',
    'expires-within-settlement-window': 'expires-within-settlement-window',
    'invalid-cumulative': 'invalid-cumulative',
    'invalid-signature': 'invalid-signature',
};

const CHANNEL_ID = '11111111111111111111111111111111';

function channelState(authorizedSigner: string): ChannelState {
    return {
        authorizedSigner,
        channelId: CHANNEL_ID,
        committedDeliveries: [],
        cumulative: 0n,
        deposit: 1_000n,
        finalized: false,
        nextDeliverySequence: 0n,
        pendingDeliveries: [],
    };
}

async function signVoucher(
    signer: Awaited<ReturnType<typeof generateKeyPairSigner>>,
    cumulative: bigint,
    expiresAt: number,
): Promise<SignedVoucher> {
    const data: VoucherData = {
        channelId: CHANNEL_ID,
        cumulativeAmount: cumulative.toString(),
        expiresAt,
    };
    const message = encodeVoucherMessage(data);
    const [signatures] = await signer.signMessages([{ content: message, signatures: {} }]);
    const sigBytes = signatures?.[signer.address];
    if (!sigBytes) throw new Error('signer produced no signature');
    return { data, signature: getBase58Decoder().decode(new Uint8Array(sigBytes)) };
}

describe('voucher reject tags match the shared cross-SDK vector', () => {
    it('pins every reject tag byte-for-byte', () => {
        const vectors = loadRejectVectors();
        expect(vectors.length).toBe(Object.keys(EMITTED).length);
        for (const vector of vectors) {
            expect(EMITTED, `vector tag ${vector.tag} has no TypeScript mapping`).toHaveProperty(vector.tag);
            expect(EMITTED[vector.tag]).toBe(vector.reason);
        }
    });

    it('emits the canonical settlement-window reason from the verifier', async () => {
        const want = loadRejectVectors().find(v => v.tag === 'expires-within-settlement-window')?.reason;
        expect(want).toBeDefined();

        const signer = await generateKeyPairSigner();
        // now=1000, window=900 -> need expiresAt >= 1900; 1500 is in the future
        // but does not outlast the window, so this hits the settlement path.
        const voucher = await signVoucher(signer, 100n, 1_500);
        const result = await verifyVoucherForChannel({
            deposit: 1_000n,
            nowSeconds: 1_000n,
            settlementWindow: 900n,
            signed: voucher,
            state: channelState(signer.address),
        });
        expect(result.status).toBe('rejected');
        if (result.status !== 'rejected') throw new Error('unreachable');
        expect(result.reason).toBe(want);
    });
});
