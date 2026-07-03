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
});
