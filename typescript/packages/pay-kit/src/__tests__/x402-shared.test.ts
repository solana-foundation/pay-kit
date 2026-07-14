import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
    assertPaymentHeaderWithinCap,
    errorMessage,
    MAX_PAYMENT_SIGNATURE_HEADER_LEN,
    x402PaymentHeader,
} from '../adapters/x402-shared.js';

describe('x402PaymentHeader', () => {
    it('reads the X-PAYMENT header', () => {
        const request = new Request('http://t/', { headers: { 'x-payment': 'cred-a' } });
        expect(x402PaymentHeader(request)).toBe('cred-a');
    });

    it('falls back to the PAYMENT-SIGNATURE header', () => {
        const request = new Request('http://t/', { headers: { 'payment-signature': 'cred-b' } });
        expect(x402PaymentHeader(request)).toBe('cred-b');
    });

    it('prefers X-PAYMENT when both are present', () => {
        const request = new Request('http://t/', {
            headers: { 'payment-signature': 'cred-b', 'x-payment': 'cred-a' },
        });
        expect(x402PaymentHeader(request)).toBe('cred-a');
    });

    it('returns undefined when neither header is present', () => {
        expect(x402PaymentHeader(new Request('http://t/'))).toBeUndefined();
    });
});

describe('errorMessage', () => {
    it('extracts the message from an Error', () => {
        expect(errorMessage(new Error('boom'))).toBe('boom');
    });

    it('returns undefined for a non-Error value', () => {
        expect(errorMessage('boom')).toBeUndefined();
        expect(errorMessage(undefined)).toBeUndefined();
        expect(errorMessage({ message: 'nope' })).toBeUndefined();
    });
});

describe('assertPaymentHeaderWithinCap', () => {
    it('accepts a header at exactly the cap', () => {
        expect(() => assertPaymentHeaderWithinCap('A'.repeat(MAX_PAYMENT_SIGNATURE_HEADER_LEN))).not.toThrow();
    });

    it('rejects a header one byte over the cap', () => {
        expect(() => assertPaymentHeaderWithinCap('A'.repeat(MAX_PAYMENT_SIGNATURE_HEADER_LEN + 1))).toThrow(
            /exceeds maximum size/,
        );
    });

    it('measures the cap in UTF-8 bytes, not code units', () => {
        // A multi-byte code point: a string of MAX/2 + 1 two-byte chars is under
        // the cap by code-unit count but over it by byte count. The cap is
        // byte-based (matching Rust's raw-header len()), so this must reject.
        const twoByteChar = 'é'; // 'é', 2 bytes UTF-8, 1 UTF-16 code unit
        const overByBytes = twoByteChar.repeat(MAX_PAYMENT_SIGNATURE_HEADER_LEN / 2 + 1);
        expect(overByBytes.length).toBeLessThanOrEqual(MAX_PAYMENT_SIGNATURE_HEADER_LEN);
        expect(Buffer.byteLength(overByBytes, 'utf8')).toBeGreaterThan(MAX_PAYMENT_SIGNATURE_HEADER_LEN);
        expect(() => assertPaymentHeaderWithinCap(overByBytes)).toThrow(/exceeds maximum size/);
    });
});

// --- Adapter-level cap enforcement ----------------------------------------
// A hostile client sending a multi-megabyte X-PAYMENT header must be rejected
// before either adapter hands the header to decodePaymentSignatureHeader (which
// does the base64 + JSON work). The decode is spied so the assertion proves the
// cap fires FIRST, so no decode work is done for an over-cap header.

const decodeSpy = vi.fn((_header: string) => ({ accepted: { network: 'solana:test' }, payload: {} }));

vi.mock('@x402/core/facilitator', () => {
    class FakeFacilitator {
        register(): this {
            return this;
        }
        verify(): Promise<{ isValid: boolean; payer?: string }> {
            return Promise.resolve({ isValid: true, payer: 'VerifyPayer' });
        }
        settle(): Promise<{ success: boolean; transaction?: string }> {
            return Promise.resolve({ success: true, transaction: 'TxSig' });
        }
    }
    return { x402Facilitator: FakeFacilitator };
});

vi.mock('@x402/svm', async () => {
    const actual = await vi.importActual<typeof import('@x402/svm')>('@x402/svm');
    return { ...actual, toFacilitatorSvmSigner: () => ({}) };
});

vi.mock('@x402/svm/exact/facilitator', () => ({ ExactSvmScheme: class {} }));
vi.mock('@x402/svm/upto/facilitator', () => ({ UptoSvmScheme: class {} }));

vi.mock('@x402/core/http', () => ({
    decodePaymentSignatureHeader: (header: string) => decodeSpy(header),
    encodePaymentRequiredHeader: () => 'ENCODED_PAYMENT_REQUIRED',
    encodePaymentResponseHeader: () => 'ENCODED_PAYMENT_RESPONSE',
}));

vi.mock('@solana/kit', async () => {
    const actual = await vi.importActual<typeof import('@solana/kit')>('@solana/kit');
    return {
        ...actual,
        createSolanaRpc: () => ({
            getLatestBlockhash: () => ({
                send: () =>
                    Promise.resolve({
                        context: { slot: 314n },
                        value: { blockhash: 'BH', lastValidBlockHeight: 1n },
                    }),
            }),
        }),
    };
});

const { createX402ExactAdapter } = await import('../adapters/x402.js');
const { X402Upto } = await import('../adapters/x402-upto.js');
const { configure } = await import('../config.js');
const { Gate } = await import('../gate.js');
const { usd } = await import('../price.js');
const { gateDefaults } = await import('../pricing.js');
const { InvalidProofError } = await import('../errors.js');
const { createMemoryReplayStore } = await import('../replay-store.js');

async function payKitConfig() {
    return configure({
        accept: ['x402'],
        mpp: { challengeBindingSecret: 'x402-cap-secret' },
        network: 'solana_localnet',
        replayStore: createMemoryReplayStore(),
    });
}

function oversizedHeader(): string {
    return 'A'.repeat(MAX_PAYMENT_SIGNATURE_HEADER_LEN + 1);
}

describe('payment-header size cap enforced by the adapters', () => {
    beforeEach(() => {
        decodeSpy.mockClear();
    });

    afterEach(() => {
        vi.clearAllMocks();
    });

    it('exact adapter rejects an over-cap header before decoding it', async () => {
        const config = await payKitConfig();
        const adapter = createX402ExactAdapter(config);
        const gate = Gate.create({ amount: usd('0.10'), name: 'report' }, gateDefaults(config));
        const request = new Request('http://localhost/report', { headers: { 'x-payment': oversizedHeader() } });

        await expect(adapter.verifyAndSettle(gate, request)).rejects.toMatchObject({
            code: 'x402_payment_header_too_large',
        });
        await expect(adapter.verifyAndSettle(gate, request)).rejects.toBeInstanceOf(InvalidProofError);
        expect(decodeSpy).not.toHaveBeenCalled();
    });

    it('upto adapter rejects an over-cap header before decoding it', async () => {
        const config = await payKitConfig();
        const upto = new X402Upto(config);
        const request = new Request('http://localhost/meter', { headers: { 'x-payment': oversizedHeader() } });

        await expect(upto.verifyOpen(request, usd('1.00'))).rejects.toMatchObject({
            code: 'x402_payment_header_too_large',
        });
        await expect(upto.verifyOpen(request, usd('1.00'))).rejects.toBeInstanceOf(InvalidProofError);
        expect(decodeSpy).not.toHaveBeenCalled();
    });

    it('both adapters still decode an at-cap header (boundary is inclusive)', async () => {
        const config = await payKitConfig();
        const adapter = createX402ExactAdapter(config);
        const gate = Gate.create({ amount: usd('0.10'), name: 'report' }, gateDefaults(config));
        const atCap = 'A'.repeat(MAX_PAYMENT_SIGNATURE_HEADER_LEN);
        const request = new Request('http://localhost/report', { headers: { 'x-payment': atCap } });

        // At the cap the header is NOT rejected on size; decode is reached.
        await adapter.verifyAndSettle(gate, request);
        expect(decodeSpy).toHaveBeenCalledWith(atCap);
    });

    it('rejects one channel across independent upto engines sharing the atomic store', async () => {
        vi.useFakeTimers({ now: 1_700_000_000_000 });
        try {
            const config = await payKitConfig();
            const first = new X402Upto(config);
            const second = new X402Upto(config);
            decodeSpy.mockReturnValue({
                accepted: { network: 'solana:test' },
                payload: { channelId: 'shared-channel', expiresAt: 1_700_003_600, from: 'payer' },
            });
            const request = new Request('http://localhost/meter', { headers: { 'x-payment': 'credential' } });

            await expect(first.verifyOpen(request, usd('1.00'))).resolves.toMatchObject({
                maxBaseUnits: 1_000_000n,
            });
            vi.advanceTimersByTime(301_000);
            await expect(second.verifyOpen(request, usd('1.00'))).rejects.toMatchObject({
                code: 'upto_channel_replayed',
            });
        } finally {
            vi.useRealTimers();
        }
    });

    it('accepts independent channels on independent usage routes', async () => {
        const config = await payKitConfig();
        const first = new X402Upto(config);
        const second = new X402Upto(config);

        decodeSpy
            .mockReturnValueOnce({
                accepted: { network: 'solana:test' },
                payload: { channelId: 'route-a-channel', expiresAt: 1_700_003_600, from: 'payer' },
            })
            .mockReturnValueOnce({
                accepted: { network: 'solana:test' },
                payload: { channelId: 'route-b-channel', expiresAt: 1_700_003_600, from: 'payer' },
            });

        await expect(
            first.verifyOpen(
                new Request('http://localhost/usage/a', { headers: { 'x-payment': 'credential-a' } }),
                usd('1.00'),
            ),
        ).resolves.toBeDefined();
        await expect(
            second.verifyOpen(
                new Request('http://localhost/usage/b', { headers: { 'x-payment': 'credential-b' } }),
                usd('1.00'),
            ),
        ).resolves.toBeDefined();
    });

    it('binds a verified channel to one replay route, not the whole engine', async () => {
        const config = await payKitConfig();
        const first = new X402Upto(config);
        const second = new X402Upto(config);
        decodeSpy.mockReturnValue({
            accepted: { network: 'solana:test' },
            payload: { channelId: 'same-channel', expiresAt: 1_700_003_600, from: 'payer' },
        });

        await first.verifyOpen(
            new Request('http://localhost/usage/a', { headers: { 'x-payment': 'credential' } }),
            usd('1.00'),
        );
        const request = new Request('http://localhost/usage/b', { headers: { 'x-payment': 'credential' } });

        await expect(second.verifyOpen(request, usd('1.00'))).rejects.toMatchObject({
            code: 'upto_route_mismatch',
        });
    });

    it('does not claim that the current upto wire binds the challenge route', async () => {
        const config = await payKitConfig();
        const upto = new X402Upto(config);
        decodeSpy.mockReturnValue({
            accepted: { network: 'solana:test' },
            payload: { channelId: 'unbound-route-channel', expiresAt: 1_700_003_600, from: 'payer' },
        });

        // `accepts()` only describes the challenge. The upstream payload has
        // no signed resource pathname, so a credential created from that
        // challenge cannot be checked against `/usage/a` here.
        await upto.accepts(usd('1.00'), new Request('http://localhost/usage/a'));
        await expect(
            upto.verifyOpen(
                new Request('http://localhost/usage/b', { headers: { 'x-payment': 'credential' } }),
                usd('1.00'),
            ),
        ).resolves.toBeDefined();
    });
});
