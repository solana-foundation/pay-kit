import { generateKeyPairSigner, getBase58Decoder, type KeyPairSigner } from '@solana/kit';

import type { SignedVoucher, VoucherData } from '../shared/session-types.js';
import { encodeVoucherMessage } from '../shared/voucher.js';
import { type ChannelState, createMemorySessionStore } from '../server/session/store.js';
import { verifyVoucherForChannel } from '../server/session/voucher.js';

// Helpers ───────────────────────────────────────────────────────────────────

function makeState(overrides: Partial<ChannelState> = {}): ChannelState {
    return {
        channelId: '11111111111111111111111111111111',
        authorizedSigner: '11111111111111111111111111111111',
        deposit: 1_000_000n,
        cumulative: 0n,
        sealed: false,
        nextDeliverySequence: 0n,
        pendingDeliveries: [],
        committedDeliveries: [],
        ...overrides,
    };
}

async function signVoucher(
    signer: KeyPairSigner,
    channelId: string,
    cumulative: bigint,
    expiresAt: bigint,
): Promise<SignedVoucher> {
    const data: VoucherData = {
        channelId,
        cumulativeAmount: cumulative.toString(),
        expiresAt: Number(expiresAt),
    };
    const message = encodeVoucherMessage(data);
    const [signatures] = await signer.signMessages([{ content: message, signatures: {} }]);
    const sigBytes = signatures?.[signer.address];
    if (!sigBytes) throw new Error('signer did not produce a signature');
    return { data, signature: getBase58Decoder().decode(new Uint8Array(sigBytes)) };
}

const FAR_FUTURE = BigInt(Math.floor(Date.now() / 1000) + 3600);

// Store ─────────────────────────────────────────────────────────────────────

describe('createMemorySessionStore', () => {
    test('updateChannel inserts when missing', async () => {
        const store = createMemorySessionStore();
        const result = await store.updateChannel('c1', current => {
            expect(current).toBeUndefined();
            return makeState({ channelId: 'c1', deposit: 5n });
        });
        expect(result.deposit).toBe(5n);
        expect((await store.getChannel('c1'))?.deposit).toBe(5n);
    });

    test('updateChannel sees prior writes', async () => {
        const store = createMemorySessionStore();
        await store.updateChannel('c1', () => makeState({ channelId: 'c1', deposit: 1n }));
        const next = await store.updateChannel('c1', current => {
            expect(current?.deposit).toBe(1n);
            return { ...current!, deposit: 2n };
        });
        expect(next.deposit).toBe(2n);
    });

    test('updateChannel serializes concurrent updates on the same channel', async () => {
        const store = createMemorySessionStore();
        await store.updateChannel('c1', () => makeState({ channelId: 'c1', cumulative: 0n }));

        // Fire 50 concurrent increments; each must see the previous value.
        const tasks = Array.from({ length: 50 }, () =>
            store.updateChannel('c1', current => ({
                ...current!,
                cumulative: current!.cumulative + 1n,
            })),
        );
        await Promise.all(tasks);

        expect((await store.getChannel('c1'))?.cumulative).toBe(50n);
    });

    test('updateChannel error does not poison subsequent updates', async () => {
        const store = createMemorySessionStore();
        await store.updateChannel('c1', () => makeState({ channelId: 'c1', cumulative: 7n }));

        await expect(
            store.updateChannel('c1', () => {
                throw new Error('nope');
            }),
        ).rejects.toThrow('nope');

        const next = await store.updateChannel('c1', current => ({
            ...current!,
            cumulative: current!.cumulative + 1n,
        }));
        expect(next.cumulative).toBe(8n);
    });

    test('listChannels applies filters', async () => {
        const store = createMemorySessionStore();
        await store.updateChannel('a', () => makeState({ channelId: 'a' }));
        await store.updateChannel('b', () => makeState({ channelId: 'b', sealed: true }));
        await store.updateChannel('c', () => makeState({ channelId: 'c', closeRequestedAt: 123n }));

        expect((await store.listChannels()).length).toBe(3);
        expect((await store.listChannels({ sealed: true })).map(s => s.channelId)).toEqual(['b']);
        expect((await store.listChannels({ sealed: false, closePending: true })).map(s => s.channelId)).toEqual(['c']);
    });

    test('deleteChannel + markSealed', async () => {
        const store = createMemorySessionStore();
        await store.updateChannel('c1', () => makeState({ channelId: 'c1' }));

        await store.markSealed('c1');
        expect((await store.getChannel('c1'))?.sealed).toBe(true);

        await store.deleteChannel('c1');
        expect(await store.getChannel('c1')).toBeUndefined();

        await expect(store.markSealed('ghost')).rejects.toThrow();
    });
});

// Verifier ──────────────────────────────────────────────────────────────────

describe('verifyVoucherForChannel', () => {
    test('happy path accepts and returns the delta', async () => {
        const signer = await generateKeyPairSigner();
        const state = makeState({ authorizedSigner: signer.address, deposit: 1_000n });
        const voucher = await signVoucher(signer, state.channelId, 100n, FAR_FUTURE);

        const result = await verifyVoucherForChannel({
            state,
            signed: voucher,
            deposit: state.deposit,
        });

        expect(result.status).toBe('accepted');
        if (result.status === 'accepted') {
            expect(result.newCumulative).toBe(100n);
            expect(result.newSignature).toBe(voucher.signature);
            expect(result.newExpiresAt).toBe(FAR_FUTURE);
        }
    });

    test('idempotent replay returns "replayed"', async () => {
        const signer = await generateKeyPairSigner();
        const voucher = await signVoucher(signer, '11111111111111111111111111111111', 100n, FAR_FUTURE);
        const state = makeState({
            authorizedSigner: signer.address,
            cumulative: 100n,
            highestVoucherSignature: voucher.signature,
            highestVoucherExpiresAt: FAR_FUTURE,
        });

        const result = await verifyVoucherForChannel({ state, signed: voucher, deposit: 1_000n });
        expect(result.status).toBe('replayed');
        if (result.status === 'replayed') {
            expect(result.newCumulative).toBe(100n);
        }
    });

    test('decreasing cumulative is rejected', async () => {
        const signer = await generateKeyPairSigner();
        const voucher = await signVoucher(signer, '11111111111111111111111111111111', 50n, FAR_FUTURE);
        const state = makeState({ authorizedSigner: signer.address, cumulative: 100n });

        const result = await verifyVoucherForChannel({ state, signed: voucher, deposit: 1_000n });
        expect(result.status).toBe('rejected');
        if (result.status === 'rejected') {
            expect(result.reason).toBe('cumulative-not-monotonic');
        }
    });

    test('equal cumulative without matching signature is rejected', async () => {
        const signer = await generateKeyPairSigner();
        const voucher = await signVoucher(signer, '11111111111111111111111111111111', 100n, FAR_FUTURE);
        const state = makeState({
            authorizedSigner: signer.address,
            cumulative: 100n,
            highestVoucherSignature:
                '5J6vbXSpEpGv4VLLqDhuRG6Tbj5n6dgEgvtTwTKpoSjvSwLTW9PSqQc6dpMUDPCvD3KZ5dGsmiTk5jzwYZyD8Xkz',
        });

        const result = await verifyVoucherForChannel({ state, signed: voucher, deposit: 1_000n });
        expect(result.status).toBe('rejected');
        if (result.status === 'rejected') {
            expect(result.reason).toBe('cumulative-not-monotonic');
        }
    });

    test('cumulative exceeds deposit is rejected', async () => {
        const signer = await generateKeyPairSigner();
        const voucher = await signVoucher(signer, '11111111111111111111111111111111', 2_000n, FAR_FUTURE);
        const state = makeState({ authorizedSigner: signer.address, deposit: 1_000n });

        const result = await verifyVoucherForChannel({ state, signed: voucher, deposit: 1_000n });
        expect(result.status).toBe('rejected');
        if (result.status === 'rejected') {
            expect(result.reason).toBe('exceeds-deposit');
        }
    });

    test('delta below minimum is rejected', async () => {
        const signer = await generateKeyPairSigner();
        const voucher = await signVoucher(signer, '11111111111111111111111111111111', 5n, FAR_FUTURE);
        const state = makeState({ authorizedSigner: signer.address, cumulative: 0n });

        const result = await verifyVoucherForChannel({
            state,
            signed: voucher,
            deposit: 1_000n,
            minVoucherDelta: 100n,
        });
        expect(result.status).toBe('rejected');
        if (result.status === 'rejected') {
            expect(result.reason).toBe('below-min-delta');
        }
    });

    test('bad signature is rejected', async () => {
        const signer = await generateKeyPairSigner();
        const other = await generateKeyPairSigner();
        // Sign with `other`, but the channel authorizes `signer` — sig must fail.
        const voucher = await signVoucher(other, '11111111111111111111111111111111', 100n, FAR_FUTURE);
        const state = makeState({ authorizedSigner: signer.address });

        const result = await verifyVoucherForChannel({ state, signed: voucher, deposit: 1_000n });
        expect(result.status).toBe('rejected');
        if (result.status === 'rejected') {
            expect(result.reason).toBe('invalid-signature');
        }
    });

    test('expired voucher is rejected', async () => {
        const signer = await generateKeyPairSigner();
        const past = BigInt(Math.floor(Date.now() / 1000) - 10);
        const voucher = await signVoucher(signer, '11111111111111111111111111111111', 100n, past);
        const state = makeState({ authorizedSigner: signer.address });

        const result = await verifyVoucherForChannel({ state, signed: voucher, deposit: 1_000n });
        expect(result.status).toBe('rejected');
        if (result.status === 'rejected') {
            expect(result.reason).toBe('expired');
        }
    });

    test('sealed channel rejects vouchers', async () => {
        const signer = await generateKeyPairSigner();
        const voucher = await signVoucher(signer, '11111111111111111111111111111111', 100n, FAR_FUTURE);
        const state = makeState({ authorizedSigner: signer.address, sealed: true });

        const result = await verifyVoucherForChannel({ state, signed: voucher, deposit: 1_000n });
        expect(result.status).toBe('rejected');
        if (result.status === 'rejected') {
            expect(result.reason).toBe('channel-sealed');
        }
    });

    test('close-pending channel rejects vouchers', async () => {
        const signer = await generateKeyPairSigner();
        const voucher = await signVoucher(signer, '11111111111111111111111111111111', 100n, FAR_FUTURE);
        const state = makeState({ authorizedSigner: signer.address, closeRequestedAt: 1n });

        const result = await verifyVoucherForChannel({ state, signed: voucher, deposit: 1_000n });
        expect(result.status).toBe('rejected');
        if (result.status === 'rejected') {
            expect(result.reason).toBe('channel-close-pending');
        }
    });

    test('nowSeconds override controls expiry decision deterministically', async () => {
        const signer = await generateKeyPairSigner();
        const voucher = await signVoucher(signer, '11111111111111111111111111111111', 100n, 1_000n);
        const state = makeState({ authorizedSigner: signer.address });

        const expired = await verifyVoucherForChannel({
            state,
            signed: voucher,
            deposit: 1_000n,
            nowSeconds: 2_000n,
        });
        expect(expired.status).toBe('rejected');

        const fresh = await verifyVoucherForChannel({
            state,
            signed: voucher,
            deposit: 1_000n,
            nowSeconds: 500n,
        });
        expect(fresh.status).toBe('accepted');
    });

    test('invalid cumulative string is rejected with invalid-cumulative', async () => {
        const signer = await generateKeyPairSigner();
        const real = await signVoucher(signer, '11111111111111111111111111111111', 100n, FAR_FUTURE);
        // Tamper the data field after signing — verifier should reject on parse before sig.
        const badData: SignedVoucher = {
            data: { ...real.data, cumulativeAmount: 'not-a-number' },
            signature: real.signature,
        };
        const state = makeState({ authorizedSigner: signer.address });

        const result = await verifyVoucherForChannel({ state, signed: badData, deposit: 1_000n });
        expect(result.status).toBe('rejected');
        if (result.status === 'rejected') {
            expect(result.reason).toBe('invalid-cumulative');
        }
    });

    // ── #9 expiry semantics: 0 = never-expires, settlement-window guard ──

    test('expiresAt == 0 is treated as never-expires and accepted', async () => {
        const signer = await generateKeyPairSigner();
        // Sign with expiresAt = 0 — the on-chain program treats 0 as no expiry
        // (`expires_at != 0 && now >= expires_at`), so off-chain must too.
        const voucher = await signVoucher(signer, '11111111111111111111111111111111', 100n, 0n);
        const state = makeState({ authorizedSigner: signer.address });

        // Even with `now` far in the future, a 0 expiry must be accepted.
        const result = await verifyVoucherForChannel({
            state,
            signed: voucher,
            deposit: 1_000n,
            nowSeconds: 9_999_999_999n,
        });
        expect(result.status).toBe('accepted');
        if (result.status === 'accepted') {
            expect(result.newCumulative).toBe(100n);
            expect(result.newExpiresAt).toBe(0n);
        }
    });

    test('idempotent replay of an expiresAt == 0 voucher is accepted', async () => {
        const signer = await generateKeyPairSigner();
        const voucher = await signVoucher(signer, '11111111111111111111111111111111', 100n, 0n);
        const state = makeState({
            authorizedSigner: signer.address,
            cumulative: 100n,
            highestVoucherSignature: voucher.signature,
            highestVoucherExpiresAt: 0n,
        });

        const result = await verifyVoucherForChannel({
            state,
            signed: voucher,
            deposit: 1_000n,
            nowSeconds: 9_999_999_999n,
        });
        expect(result.status).toBe('replayed');
    });

    test('non-zero expiry at or before now is still rejected as expired', async () => {
        const signer = await generateKeyPairSigner();
        const voucher = await signVoucher(signer, '11111111111111111111111111111111', 100n, 1_000n);
        const state = makeState({ authorizedSigner: signer.address });

        // expiresAt == now → expired (mirrors on-chain `now >= expires_at`).
        const atNow = await verifyVoucherForChannel({ state, signed: voucher, deposit: 1_000n, nowSeconds: 1_000n });
        expect(atNow.status).toBe('rejected');
        if (atNow.status === 'rejected') expect(atNow.reason).toBe('expired');
    });

    test('non-zero expiry within the settlement window is rejected', async () => {
        const signer = await generateKeyPairSigner();
        // Voucher valid until t=1500; now=1000; window=900 ⇒ must outlast 1900.
        const voucher = await signVoucher(signer, '11111111111111111111111111111111', 100n, 1_500n);
        const state = makeState({ authorizedSigner: signer.address });

        const result = await verifyVoucherForChannel({
            state,
            signed: voucher,
            deposit: 1_000n,
            nowSeconds: 1_000n,
            settlementWindow: 900n,
        });
        expect(result.status).toBe('rejected');
        if (result.status === 'rejected') {
            expect(result.reason).toBe('expires-within-settlement-window');
        }
    });

    test('non-zero expiry that outlasts the settlement window is accepted', async () => {
        const signer = await generateKeyPairSigner();
        // Voucher valid until t=2500; now=1000; window=900 ⇒ 2500 >= 1900 ⇒ ok.
        const voucher = await signVoucher(signer, '11111111111111111111111111111111', 100n, 2_500n);
        const state = makeState({ authorizedSigner: signer.address });

        const result = await verifyVoucherForChannel({
            state,
            signed: voucher,
            deposit: 1_000n,
            nowSeconds: 1_000n,
            settlementWindow: 900n,
        });
        expect(result.status).toBe('accepted');
    });

    test('expiresAt == 0 bypasses the settlement-window guard', async () => {
        const signer = await generateKeyPairSigner();
        const voucher = await signVoucher(signer, '11111111111111111111111111111111', 100n, 0n);
        const state = makeState({ authorizedSigner: signer.address });

        const result = await verifyVoucherForChannel({
            state,
            signed: voucher,
            deposit: 1_000n,
            nowSeconds: 1_000n,
            settlementWindow: 999_999n,
        });
        expect(result.status).toBe('accepted');
    });

    test('settlement window exactly met (expiresAt == now + window) is accepted', async () => {
        const signer = await generateKeyPairSigner();
        // expiresAt == now + window ⇒ NOT within the window (reject is `<`).
        const voucher = await signVoucher(signer, '11111111111111111111111111111111', 100n, 1_900n);
        const state = makeState({ authorizedSigner: signer.address });

        const result = await verifyVoucherForChannel({
            state,
            signed: voucher,
            deposit: 1_000n,
            nowSeconds: 1_000n,
            settlementWindow: 900n,
        });
        expect(result.status).toBe('accepted');
    });

    // ── #8 cumulative-as-nonce / replay semantics ──

    test('strict increment over the watermark is required (equal-but-new is rejected)', async () => {
        const signer = await generateKeyPairSigner();
        // A *fresh* voucher (new signature) at the exact watermark is NOT a
        // replay — it must be rejected as non-monotonic, not re-served.
        const fresh = await signVoucher(signer, '11111111111111111111111111111111', 100n, FAR_FUTURE);
        const state = makeState({
            authorizedSigner: signer.address,
            cumulative: 100n,
            // Different signature recorded as the highest — so `fresh` is not an
            // exact replay even though its cumulative equals the watermark.
            highestVoucherSignature: '2'.repeat(88),
            highestVoucherExpiresAt: FAR_FUTURE,
        });

        const result = await verifyVoucherForChannel({ state, signed: fresh, deposit: 1_000n });
        expect(result.status).toBe('rejected');
        if (result.status === 'rejected') {
            expect(result.reason).toBe('cumulative-not-monotonic');
        }
    });

    test('exact replay (same cumulative AND signature) is idempotent no-charge, not a fresh serve', async () => {
        const signer = await generateKeyPairSigner();
        const voucher = await signVoucher(signer, '11111111111111111111111111111111', 250n, FAR_FUTURE);
        const state = makeState({
            authorizedSigner: signer.address,
            cumulative: 250n,
            highestVoucherSignature: voucher.signature,
            highestVoucherExpiresAt: FAR_FUTURE,
        });

        const result = await verifyVoucherForChannel({ state, signed: voucher, deposit: 1_000n });
        // 'replayed' is the charged-0 / no-new-delivery signal: the watermark
        // is returned unchanged so the caller serves nothing new.
        expect(result.status).toBe('replayed');
        if (result.status === 'replayed') {
            expect(result.newCumulative).toBe(250n); // unchanged watermark
        }
    });

    test('a lower cumulative reusing the highest signature is rejected (not a replay)', async () => {
        const signer = await generateKeyPairSigner();
        const high = await signVoucher(signer, '11111111111111111111111111111111', 500n, FAR_FUTURE);
        // Watermark is 500 (from `high`). A voucher at 300 carrying the highest
        // signature is neither a strict increment nor an exact replay.
        const lower = await signVoucher(signer, '11111111111111111111111111111111', 300n, FAR_FUTURE);
        const state = makeState({
            authorizedSigner: signer.address,
            cumulative: 500n,
            highestVoucherSignature: high.signature,
            highestVoucherExpiresAt: FAR_FUTURE,
        });

        const result = await verifyVoucherForChannel({ state, signed: lower, deposit: 1_000n });
        expect(result.status).toBe('rejected');
        if (result.status === 'rejected') {
            expect(result.reason).toBe('cumulative-not-monotonic');
        }
    });

    test('a strictly higher cumulative advances the watermark', async () => {
        const signer = await generateKeyPairSigner();
        const next = await signVoucher(signer, '11111111111111111111111111111111', 600n, FAR_FUTURE);
        const state = makeState({
            authorizedSigner: signer.address,
            cumulative: 500n,
            highestVoucherSignature: '3'.repeat(88),
            highestVoucherExpiresAt: FAR_FUTURE,
        });

        const result = await verifyVoucherForChannel({ state, signed: next, deposit: 1_000n });
        expect(result.status).toBe('accepted');
        if (result.status === 'accepted') {
            expect(result.newCumulative).toBe(600n);
            expect(result.newSignature).toBe(next.signature);
        }
    });
});
