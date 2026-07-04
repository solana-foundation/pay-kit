import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { InvalidProofError } from '../errors.js';

// --- Boundary mocks -------------------------------------------------------
// The x402 exact adapter settles through an in-process @x402/core facilitator
// (which needs a live RPC + real signatures) and reads a recent blockhash from
// @solana/kit. Both are stubbed so the adapter's own wiring — challenge
// building, header parsing, verify/settle branching — is exercised offline.

type VerifyResult = {
    invalidMessage?: string;
    invalidReason?: string;
    isValid: boolean;
    payer?: string;
};
type SettleResult = {
    errorMessage?: string;
    errorReason?: string;
    payer?: string;
    success: boolean;
    transaction?: string;
};

const facilitatorControl: {
    settle: () => Promise<SettleResult>;
    verify: () => Promise<VerifyResult>;
} = {
    settle: () => Promise.resolve({ payer: 'SettlePayer', success: true, transaction: 'TxSig' }),
    verify: () => Promise.resolve({ isValid: true, payer: 'VerifyPayer' }),
};

const blockhashControl: { impl: () => Promise<{ value: unknown }> } = {
    impl: () =>
        Promise.resolve({
            value: { blockhash: 'BlockHash111', lastValidBlockHeight: 4242n },
        }),
};

const decodeControl: { impl: (header: string) => unknown } = {
    impl: () => ({ accepted: { network: 'solana:test' }, payload: {} }),
};

vi.mock('@x402/core/facilitator', () => {
    class FakeFacilitator {
        register(): this {
            return this;
        }
        verify(): Promise<VerifyResult> {
            return facilitatorControl.verify();
        }
        settle(): Promise<SettleResult> {
            return facilitatorControl.settle();
        }
    }
    return { x402Facilitator: FakeFacilitator };
});

vi.mock('@x402/svm', async () => {
    const actual = await vi.importActual<typeof import('@x402/svm')>('@x402/svm');
    return { ...actual, toFacilitatorSvmSigner: () => ({}) };
});

vi.mock('@x402/svm/exact/facilitator', () => ({ ExactSvmScheme: class {} }));

vi.mock('@x402/core/http', () => ({
    decodePaymentSignatureHeader: (header: string) => decodeControl.impl(header),
    encodePaymentRequiredHeader: () => 'ENCODED_PAYMENT_REQUIRED',
    encodePaymentResponseHeader: () => 'ENCODED_PAYMENT_RESPONSE',
}));

vi.mock('@solana/kit', async () => {
    const actual = await vi.importActual<typeof import('@solana/kit')>('@solana/kit');
    return {
        ...actual,
        createSolanaRpc: () => ({
            getLatestBlockhash: () => ({ send: () => blockhashControl.impl() }),
        }),
    };
});

const { createX402ExactAdapter } = await import('../adapters/x402.js');
const { configure } = await import('../config.js');
const { Gate } = await import('../gate.js');
const { usd } = await import('../price.js');
const { gateDefaults } = await import('../pricing.js');

async function setup() {
    const config = await configure({
        mpp: { challengeBindingSecret: 'x402-adapter-secret' },
        network: 'solana_localnet',
    });
    return { adapter: createX402ExactAdapter(config), config };
}

function paidRequest(header = 'PAYMENT_CRED'): Request {
    return new Request('http://localhost/report', { headers: { 'x-payment': header } });
}

async function gateFor(amount = usd('0.10')) {
    const config = await configure({
        mpp: { challengeBindingSecret: 'x402-adapter-secret' },
        network: 'solana_localnet',
    });
    return Gate.create({ amount, name: 'report' }, gateDefaults(config));
}

describe('createX402ExactAdapter', () => {
    beforeEach(() => {
        facilitatorControl.verify = () => Promise.resolve({ isValid: true, payer: 'VerifyPayer' });
        facilitatorControl.settle = () =>
            Promise.resolve({ payer: 'SettlePayer', success: true, transaction: 'TxSig' });
        blockhashControl.impl = () =>
            Promise.resolve({ value: { blockhash: 'BlockHash111', lastValidBlockHeight: 4242n } });
        decodeControl.impl = () => ({ accepted: { network: 'solana:test' }, payload: {} });
    });

    afterEach(() => {
        vi.clearAllMocks();
    });

    it('exposes protocol/scheme metadata', async () => {
        const { adapter } = await setup();
        expect(adapter.protocol).toBe('x402');
        expect(adapter.scheme).toBe('exact');
    });

    it('embeds a server-fetched blockhash in the challenge requirements', async () => {
        const { adapter } = await setup();
        const gate = await gateFor();
        const headers = await adapter.challengeHeaders(gate, new Request('http://localhost/report'));
        expect(headers['payment-required']).toBe('ENCODED_PAYMENT_REQUIRED');
    });

    it('falls back to bare requirements when the blockhash fetch fails', async () => {
        blockhashControl.impl = () => Promise.reject(new Error('rpc down'));
        const { adapter } = await setup();
        const gate = await gateFor();
        // Still produces a challenge — the catch branch swallows the RPC error.
        const headers = await adapter.challengeHeaders(gate, new Request('http://localhost/report'));
        expect(headers['payment-required']).toBe('ENCODED_PAYMENT_REQUIRED');
    });

    it('rejects a request with no payment header', async () => {
        const { adapter } = await setup();
        const gate = await gateFor();
        await expect(adapter.verifyAndSettle(gate, new Request('http://localhost/report'))).rejects.toMatchObject({
            code: 'missing_x402_payment_header',
        });
    });

    it('rejects an undecodable payment header', async () => {
        decodeControl.impl = () => {
            throw new Error('bad base64');
        };
        const { adapter } = await setup();
        const gate = await gateFor();
        await expect(adapter.verifyAndSettle(gate, paidRequest())).rejects.toMatchObject({
            code: 'invalid_x402_payment_header',
        });
    });

    it('rejects when verification fails, surfacing the invalid reason', async () => {
        facilitatorControl.verify = () =>
            Promise.resolve({ invalidMessage: 'nope', invalidReason: 'signature_consumed', isValid: false });
        const { adapter } = await setup();
        const gate = await gateFor();
        await expect(adapter.verifyAndSettle(gate, paidRequest())).rejects.toMatchObject({
            code: 'signature_consumed',
        });
    });

    it('defaults the invalid reason when verification omits one', async () => {
        facilitatorControl.verify = () => Promise.resolve({ isValid: false });
        const { adapter } = await setup();
        const gate = await gateFor();
        await expect(adapter.verifyAndSettle(gate, paidRequest())).rejects.toMatchObject({ code: 'invalid_proof' });
    });

    it('rejects when settlement fails, surfacing the error reason', async () => {
        facilitatorControl.settle = () =>
            Promise.resolve({ errorMessage: 'rpc down', errorReason: 'settlement_failed', success: false });
        const { adapter } = await setup();
        const gate = await gateFor();
        await expect(adapter.verifyAndSettle(gate, paidRequest())).rejects.toMatchObject({
            code: 'settlement_failed',
        });
    });

    it('defaults the error reason when settlement omits one', async () => {
        facilitatorControl.settle = () => Promise.resolve({ success: false });
        const { adapter } = await setup();
        const gate = await gateFor();
        await expect(adapter.verifyAndSettle(gate, paidRequest())).rejects.toMatchObject({
            code: 'settlement_failed',
        });
    });

    it('settles a valid payment and returns the payment record', async () => {
        const { adapter } = await setup();
        const gate = await gateFor();
        const payment = await adapter.verifyAndSettle(gate, paidRequest('CRED123'));
        expect(payment).toMatchObject({
            gateName: 'report',
            payer: 'SettlePayer',
            protocol: 'x402',
            raw: 'CRED123',
            scheme: 'exact',
            transaction: 'TxSig',
        });
        expect(payment.settlementHeaders['x-payment-response']).toBe('ENCODED_PAYMENT_RESPONSE');
    });

    it('falls back to the verify payer when settlement omits one', async () => {
        facilitatorControl.settle = () => Promise.resolve({ success: true, transaction: 'TxSig' });
        const { adapter } = await setup();
        const gate = await gateFor();
        const payment = await adapter.verifyAndSettle(gate, paidRequest());
        expect(payment.payer).toBe('VerifyPayer');
    });

    it('reads the credential from the payment-signature header', async () => {
        const { adapter } = await setup();
        const gate = await gateFor();
        const request = new Request('http://localhost/report', { headers: { 'payment-signature': 'SIG' } });
        const payment = await adapter.verifyAndSettle(gate, request);
        expect(payment.raw).toBe('SIG');
    });

    it('surfaces an InvalidProofError instance on missing header', async () => {
        const { adapter } = await setup();
        const gate = await gateFor();
        await expect(adapter.verifyAndSettle(gate, new Request('http://localhost/report'))).rejects.toBeInstanceOf(
            InvalidProofError,
        );
    });

    // ── replay / in-flight dedup ────────────────────────────────────────────

    it('rejects a sequential replay of the same payment payload', async () => {
        const { adapter } = await setup();
        const gate = await gateFor();

        const first = await adapter.verifyAndSettle(gate, paidRequest('REPLAY_CRED'));
        expect(first.transaction).toBe('TxSig');

        await expect(adapter.verifyAndSettle(gate, paidRequest('REPLAY_CRED'))).rejects.toMatchObject({
            code: 'x402_payment_replayed',
        });
    });

    it('rejects a concurrent duplicate payload while the first settles', async () => {
        let settleCalls = 0;
        facilitatorControl.settle = () => {
            settleCalls += 1;
            return new Promise(resolve =>
                setTimeout(() => resolve({ payer: 'SettlePayer', success: true, transaction: 'TxSig' }), 20),
            );
        };
        const { adapter } = await setup();
        const gate = await gateFor();

        const results = await Promise.allSettled([
            adapter.verifyAndSettle(gate, paidRequest('RACE_CRED')),
            adapter.verifyAndSettle(gate, paidRequest('RACE_CRED')),
        ]);
        const fulfilled = results.filter(result => result.status === 'fulfilled');
        const rejected = results.filter((result): result is PromiseRejectedResult => result.status === 'rejected');
        expect(fulfilled).toHaveLength(1);
        expect(rejected).toHaveLength(1);
        expect(rejected[0]!.reason).toMatchObject({ code: 'x402_payment_replayed' });
        expect(settleCalls).toBe(1);
    });

    it('keys the dedup on the transaction client signature, not the raw header', async () => {
        // Two different header strings decode to the same signed transaction —
        // e.g. a replayer mutating the unsigned fee-payer slot bytes. The
        // dedup must fire on the client signature embedded in the payload.
        const kit = await vi.importActual<typeof import('@solana/kit')>('@solana/kit');
        const signer = await kit.generateKeyPairSigner();
        const message = kit.pipe(
            kit.createTransactionMessage({ version: 0 }),
            msg => kit.setTransactionMessageFeePayerSigner(signer, msg),
            msg =>
                kit.setTransactionMessageLifetimeUsingBlockhash(
                    {
                        blockhash: 'EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N' as never,
                        lastValidBlockHeight: 0n,
                    },
                    msg,
                ),
        );
        const signed = await kit.signTransactionMessageWithSigners(message as never);
        const wire = kit.getBase64EncodedWireTransaction(signed) as string;
        decodeControl.impl = () => ({ accepted: { network: 'solana:test' }, payload: { transaction: wire } });

        const { adapter } = await setup();
        const gate = await gateFor();

        await adapter.verifyAndSettle(gate, paidRequest('HEADER_A'));
        await expect(adapter.verifyAndSettle(gate, paidRequest('HEADER_B'))).rejects.toMatchObject({
            code: 'x402_payment_replayed',
        });
    });

    it('releases the payload key when settlement fails so a retry can proceed', async () => {
        facilitatorControl.settle = () =>
            Promise.resolve({ errorMessage: 'rpc down', errorReason: 'settlement_failed', success: false });
        const { adapter } = await setup();
        const gate = await gateFor();

        await expect(adapter.verifyAndSettle(gate, paidRequest('RETRY_CRED'))).rejects.toMatchObject({
            code: 'settlement_failed',
        });

        facilitatorControl.settle = () =>
            Promise.resolve({ payer: 'SettlePayer', success: true, transaction: 'TxSig' });
        const retried = await adapter.verifyAndSettle(gate, paidRequest('RETRY_CRED'));
        expect(retried.transaction).toBe('TxSig');
    });

    it('releases the payload key when settlement throws', async () => {
        facilitatorControl.settle = () => Promise.reject(new Error('facilitator crashed'));
        const { adapter } = await setup();
        const gate = await gateFor();

        await expect(adapter.verifyAndSettle(gate, paidRequest('THROW_CRED'))).rejects.toThrow(/facilitator crashed/);

        facilitatorControl.settle = () =>
            Promise.resolve({ payer: 'SettlePayer', success: true, transaction: 'TxSig' });
        const retried = await adapter.verifyAndSettle(gate, paidRequest('THROW_CRED'));
        expect(retried.transaction).toBe('TxSig');
    });

    it('lets distinct payloads settle independently', async () => {
        const { adapter } = await setup();
        const gate = await gateFor();

        const first = await adapter.verifyAndSettle(gate, paidRequest('CRED_ONE'));
        const second = await adapter.verifyAndSettle(gate, paidRequest('CRED_TWO'));
        expect(first.transaction).toBe('TxSig');
        expect(second.transaction).toBe('TxSig');
    });

    it('expires consumed entries after the completion window', async () => {
        vi.useFakeTimers();
        try {
            const { adapter } = await setup();
            const gate = await gateFor();

            await adapter.verifyAndSettle(gate, paidRequest('WINDOW_CRED'));
            // Within the 300s window the replay is still rejected.
            vi.setSystemTime(Date.now() + 299_000);
            await expect(adapter.verifyAndSettle(gate, paidRequest('WINDOW_CRED'))).rejects.toMatchObject({
                code: 'x402_payment_replayed',
            });
            // Past the window the blockhash has expired on-chain; the local
            // entry is pruned and the ledger owns dedup from here.
            vi.setSystemTime(Date.now() + 302_000);
            const late = await adapter.verifyAndSettle(gate, paidRequest('WINDOW_CRED'));
            expect(late.transaction).toBe('TxSig');
        } finally {
            vi.useRealTimers();
        }
    });

    // ── cross-process dedup via a reserving replay store ────────────────────

    /** A reserving Store double: `reserve` is an atomic check-and-set. */
    function reservingStore() {
        const map = new Map<string, unknown>();
        const calls: { reserve: Array<{ key: string; ttlSeconds?: number }>; deletes: string[] } = {
            reserve: [],
            deletes: [],
        };
        return {
            calls,
            store: {
                get: (key: string) => Promise.resolve(map.get(key) ?? null),
                put: (key: string, value: unknown) => {
                    map.set(key, value);
                    return Promise.resolve();
                },
                delete: (key: string) => {
                    calls.deletes.push(key);
                    map.delete(key);
                    return Promise.resolve();
                },
                reserve: (key: string, value: unknown = true, ttlSeconds?: number) => {
                    calls.reserve.push({ key, ttlSeconds });
                    if (map.has(key)) return Promise.resolve(false);
                    map.set(key, value);
                    return Promise.resolve(true);
                },
            },
        };
    }

    async function setupWithStore(store: unknown) {
        const config = await configure({
            mpp: { challengeBindingSecret: 'x402-adapter-secret' },
            network: 'solana_localnet',
            replayStore: store as never,
        });
        return { adapter: createX402ExactAdapter(config) };
    }

    it('claims through the reserving store (with a TTL) when one is configured', async () => {
        const reserving = reservingStore();
        const { adapter } = await setupWithStore(reserving.store);
        const gate = await gateFor();

        await adapter.verifyAndSettle(gate, paidRequest('STORE_CRED'));
        expect(reserving.calls.reserve).toHaveLength(1);
        expect(reserving.calls.reserve[0]!.key.startsWith('x402-exact:consumed:')).toBe(true);
        expect(reserving.calls.reserve[0]!.ttlSeconds).toBe(300);
    });

    it('rejects a sequential replay via the reserving store', async () => {
        const reserving = reservingStore();
        const { adapter } = await setupWithStore(reserving.store);
        const gate = await gateFor();

        await adapter.verifyAndSettle(gate, paidRequest('DUP_CRED'));
        await expect(adapter.verifyAndSettle(gate, paidRequest('DUP_CRED'))).rejects.toMatchObject({
            code: 'x402_payment_replayed',
        });
    });

    it('rejects a concurrent duplicate via the reserving store', async () => {
        let settleCalls = 0;
        facilitatorControl.settle = () => {
            settleCalls += 1;
            return new Promise(resolve =>
                setTimeout(() => resolve({ payer: 'SettlePayer', success: true, transaction: 'TxSig' }), 20),
            );
        };
        const reserving = reservingStore();
        const { adapter } = await setupWithStore(reserving.store);
        const gate = await gateFor();

        const results = await Promise.allSettled([
            adapter.verifyAndSettle(gate, paidRequest('RACE_STORE')),
            adapter.verifyAndSettle(gate, paidRequest('RACE_STORE')),
        ]);
        expect(results.filter(r => r.status === 'fulfilled')).toHaveLength(1);
        expect(results.filter(r => r.status === 'rejected')).toHaveLength(1);
        expect(settleCalls).toBe(1);
    });

    it('releases the reserving-store key when settlement fails', async () => {
        facilitatorControl.settle = () =>
            Promise.resolve({ errorMessage: 'rpc down', errorReason: 'settlement_failed', success: false });
        const reserving = reservingStore();
        const { adapter } = await setupWithStore(reserving.store);
        const gate = await gateFor();

        await expect(adapter.verifyAndSettle(gate, paidRequest('REL_CRED'))).rejects.toMatchObject({
            code: 'settlement_failed',
        });
        expect(reserving.calls.deletes).toHaveLength(1);

        // The released key can be reclaimed by a retry.
        facilitatorControl.settle = () =>
            Promise.resolve({ payer: 'SettlePayer', success: true, transaction: 'TxSig' });
        const retried = await adapter.verifyAndSettle(gate, paidRequest('REL_CRED'));
        expect(retried.transaction).toBe('TxSig');
    });
});
