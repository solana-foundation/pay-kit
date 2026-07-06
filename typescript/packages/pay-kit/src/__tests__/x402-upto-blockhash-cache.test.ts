import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// --- Boundary mocks -------------------------------------------------------
// The unauthenticated `upto` 402 challenge stamps extra.recentBlockhash, which
// today triggers one getLatestBlockhash RPC per challenge build. A short-TTL,
// single-flight cache must collapse a concurrent burst to a single RPC per TTL.
// The @solana/kit createSolanaRpc factory is stubbed with a counting, latched
// getLatestBlockhash so the test can (a) count RPC calls and (b) hold the RPC
// open until every concurrent challenge is in flight, proving single-flight.

// Counts every getLatestBlockhash().send() invocation across the process.
let rpcCalls = 0;
// A gate the test releases once all concurrent challenges are in flight, so a
// non-single-flight implementation would have already fired N RPCs.
let releaseRpc: (() => void) | undefined;
let rpcGate: Promise<void> | undefined;

function armGate(): void {
    rpcGate = new Promise<void>(resolve => {
        releaseRpc = resolve;
    });
}

vi.mock('@x402/core/facilitator', () => {
    class FakeFacilitator {
        register(): this {
            return this;
        }
    }
    return { x402Facilitator: FakeFacilitator };
});

vi.mock('@x402/svm/upto/facilitator', () => ({ UptoSvmScheme: class {} }));

vi.mock('@x402/core/http', () => ({
    // Echo the recentBlockhash back so the test can assert every challenge saw
    // the same cached value.
    encodePaymentRequiredHeader: (payload: { accepts: { extra?: { recentBlockhash?: string } }[] }) =>
        `REQUIRED:${payload.accepts[0]?.extra?.recentBlockhash ?? 'none'}`,
    encodePaymentResponseHeader: () => 'ENCODED_PAYMENT_RESPONSE',
}));

vi.mock('@solana/mpp/server', async () => {
    const actual = await vi.importActual<typeof import('@solana/mpp/server')>('@solana/mpp/server');
    return { ...actual };
});

vi.mock('@solana/kit', async () => {
    const actual = await vi.importActual<typeof import('@solana/kit')>('@solana/kit');
    return {
        ...actual,
        createSolanaRpc: () => ({
            getLatestBlockhash: () => ({
                send: async () => {
                    rpcCalls += 1;
                    if (rpcGate) await rpcGate;
                    return { value: { blockhash: `BH-${rpcCalls}`, lastValidBlockHeight: 10n } };
                },
            }),
        }),
    };
});

const { X402Upto } = await import('../adapters/x402-upto.js');
const { configure } = await import('../config.js');
const { usd } = await import('../price.js');

async function engine(overrides: Parameters<typeof configure>[0] = {}) {
    const config = await configure({
        mpp: { challengeBindingSecret: 'upto-secret' },
        network: 'solana_localnet',
        ...overrides,
    });
    return new X402Upto(config);
}

function req(): Request {
    return new Request('http://localhost/meter');
}

describe('X402Upto challenge blockhash cache', () => {
    beforeEach(() => {
        rpcCalls = 0;
        releaseRpc = undefined;
        rpcGate = undefined;
    });

    afterEach(() => {
        vi.clearAllMocks();
    });

    it('collapses a concurrent challenge burst to a single getLatestBlockhash RPC', async () => {
        const upto = await engine();

        // Latch the RPC so every concurrent challenge enters #challengeRequirements
        // before the first fetch resolves; without single-flight this fires 20 RPCs.
        armGate();
        const bursts = Array.from({ length: 20 }, () => upto.challengeHeaders(usd('1.00'), req()));
        // Give the microtask queue a chance to line every request up at the gate.
        await Promise.resolve();
        releaseRpc?.();
        const headers = await Promise.all(bursts);

        expect(rpcCalls).toBe(1);
        // Every challenge served the same cached blockhash.
        for (const header of headers) {
            expect(header['payment-required']).toBe('REQUIRED:BH-1');
        }
    });

    it('reuses the cached blockhash for a second challenge within the TTL (no extra RPC)', async () => {
        const upto = await engine();
        await upto.challengeHeaders(usd('1.00'), req());
        await upto.challengeHeaders(usd('2.50'), req());
        expect(rpcCalls).toBe(1);
    });
});
