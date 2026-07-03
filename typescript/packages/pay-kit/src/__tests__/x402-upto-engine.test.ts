import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { InvalidProofError } from '../errors.js';

// --- Boundary mocks -------------------------------------------------------
// The upto engine opens/settles an on-chain payment channel through the
// @x402/svm upto facilitator and @solana/mpp's settlement helpers (all of
// which need a live RPC). Those, plus the @x402/core header codecs and the
// @solana/kit RPC factory, are stubbed so verifyOpen/settle branching,
// payload parsing, recipient splits, and token-program selection run offline.
// resolveStablecoinMint / getStablecoinTokenProgram stay real (offline-safe).

type VerifyResult = { invalidMessage?: string; invalidReason?: string; isValid: boolean; payer?: string };

const facilitatorControl: { verify: () => Promise<VerifyResult> } = {
    verify: () => Promise.resolve({ isValid: true, payer: 'ChannelPayer' }),
};

const decodeControl: { impl: () => unknown } = {
    impl: () => ({
        accepted: { network: 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp' },
        payload: { channelId: 'chan-1', expiresAt: 9_999, from: 'ChannelPayer' },
    }),
};

const settlementControl: {
    submit: (args: unknown) => Promise<{ signature: string }>;
    wait: () => Promise<void>;
} = {
    submit: () => Promise.resolve({ signature: 'SettleSig' }),
    wait: () => Promise.resolve(),
};

// Captures the arguments handed to submitSettleAndDistribute so a test can
// assert splits/voucher wiring without a chain.
let lastSubmit: Record<string, unknown> | undefined;

vi.mock('@x402/core/facilitator', () => {
    class FakeFacilitator {
        register(): this {
            return this;
        }
        verify(): Promise<VerifyResult> {
            return facilitatorControl.verify();
        }
    }
    return { x402Facilitator: FakeFacilitator };
});

vi.mock('@x402/svm/upto/facilitator', () => ({ UptoSvmScheme: class {} }));

vi.mock('@x402/core/http', () => ({
    decodePaymentSignatureHeader: () => decodeControl.impl(),
    encodePaymentRequiredHeader: () => 'ENCODED_PAYMENT_REQUIRED',
    encodePaymentResponseHeader: () => 'ENCODED_PAYMENT_RESPONSE',
}));

vi.mock('@solana/mpp/server', async () => {
    const actual = await vi.importActual<typeof import('@solana/mpp/server')>('@solana/mpp/server');
    return {
        ...actual,
        buildAndSignWireTransaction: () => Promise.resolve('WIRE'),
        encodeVoucherMessageBytes: () => new Uint8Array([1, 2, 3]),
        submitSettleAndDistribute: (args: Record<string, unknown>) => {
            lastSubmit = args;
            return settlementControl.submit(args);
        },
        waitForSignatureConfirmation: () => settlementControl.wait(),
    };
});

vi.mock('@solana/kit', async () => {
    const actual = await vi.importActual<typeof import('@solana/kit')>('@solana/kit');
    return {
        ...actual,
        createSolanaRpc: () => ({
            getLatestBlockhash: () => ({
                send: () => Promise.resolve({ value: { blockhash: 'BH', lastValidBlockHeight: 10n } }),
            }),
        }),
    };
});

const { X402Upto } = await import('../adapters/x402-upto.js');
const { configure } = await import('../config.js');
const { usd } = await import('../price.js');
const { Signer } = await import('../signer.js');

const RECIPIENT = 'AyNAa2VPe2t5pgg8M61iE6kqMudkV98zsT4rkAZuU6tj';

async function engine(overrides: Parameters<typeof configure>[0] = {}) {
    const config = await configure({
        mpp: { challengeBindingSecret: 'upto-secret' },
        network: 'solana_localnet',
        ...overrides,
    });
    return { config, upto: new X402Upto(config) };
}

function paidRequest(): Request {
    return new Request('http://localhost/meter', { headers: { 'x-payment': 'CRED' } });
}

async function openVerified(upto: InstanceType<typeof X402Upto>) {
    return upto.verifyOpen(paidRequest(), usd('1.00'));
}

describe('X402Upto engine', () => {
    beforeEach(() => {
        lastSubmit = undefined;
        facilitatorControl.verify = () => Promise.resolve({ isValid: true, payer: 'ChannelPayer' });
        decodeControl.impl = () => ({
            accepted: { network: 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp' },
            payload: { channelId: 'chan-1', expiresAt: 9_999, from: 'ChannelPayer' },
        });
        settlementControl.submit = () => Promise.resolve({ signature: 'SettleSig' });
        settlementControl.wait = () => Promise.resolve();
    });

    afterEach(() => {
        vi.clearAllMocks();
    });

    describe('challenge + accepts', () => {
        it('emits the encoded PAYMENT-REQUIRED challenge header', async () => {
            const { upto } = await engine();
            const headers = await upto.challengeHeaders(usd('1.00'), new Request('http://localhost/meter'));
            expect(headers['payment-required']).toBe('ENCODED_PAYMENT_REQUIRED');
        });

        it('falls back to bare requirements when the blockhash fetch fails', async () => {
            const kit = await import('@solana/kit');
            const spy = vi.spyOn(kit, 'createSolanaRpc').mockReturnValue({
                getLatestBlockhash: () => ({ send: () => Promise.reject(new Error('rpc down')) }),
            } as never);
            const { upto } = await engine();
            const headers = await upto.challengeHeaders(usd('1.00'), new Request('http://localhost/meter'));
            expect(headers['payment-required']).toBe('ENCODED_PAYMENT_REQUIRED');
            spy.mockRestore();
        });

        it('advertises an upto accepts entry', async () => {
            const { upto } = await engine();
            const [entry] = upto.accepts(usd('1.00'));
            expect(entry.scheme).toBe('upto');
            expect(entry.amount).toBe('1000000');
        });

        it('detects an x402 payment header', async () => {
            const { upto } = await engine();
            expect(upto.detect(new Request('http://localhost/meter'))).toBe(false);
            expect(upto.detect(paidRequest())).toBe(true);
        });
    });

    describe('verifyOpen', () => {
        it('rejects a request with no payment header', async () => {
            const { upto } = await engine();
            await expect(upto.verifyOpen(new Request('http://localhost/meter'), usd('1.00'))).rejects.toMatchObject({
                code: 'missing_x402_payment_header',
            });
        });

        it('rejects an undecodable payment header', async () => {
            decodeControl.impl = () => {
                throw new Error('bad');
            };
            const { upto } = await engine();
            await expect(upto.verifyOpen(paidRequest(), usd('1.00'))).rejects.toMatchObject({
                code: 'invalid_x402_payment_header',
            });
        });

        it('rejects when the facilitator marks the authorization invalid', async () => {
            facilitatorControl.verify = () =>
                Promise.resolve({ invalidMessage: 'no', invalidReason: 'expired', isValid: false });
            const { upto } = await engine();
            await expect(upto.verifyOpen(paidRequest(), usd('1.00'))).rejects.toMatchObject({ code: 'expired' });
        });

        it('defaults the invalid reason when the facilitator omits one', async () => {
            facilitatorControl.verify = () => Promise.resolve({ isValid: false });
            const { upto } = await engine();
            await expect(upto.verifyOpen(paidRequest(), usd('1.00'))).rejects.toMatchObject({ code: 'invalid_proof' });
        });

        it('returns the verified authorization with the ceiling', async () => {
            const { upto } = await engine();
            const verified = await openVerified(upto);
            expect(verified.maxBaseUnits).toBe(1_000_000n);
            expect(verified.payer).toBe('ChannelPayer');
        });

        it('defaults the payer to an empty string when verify omits it', async () => {
            facilitatorControl.verify = () => Promise.resolve({ isValid: true });
            const { upto } = await engine();
            const verified = await openVerified(upto);
            expect(verified.payer).toBe('');
        });
    });

    describe('settle', () => {
        it('settles the metered amount with an operator voucher (splits to the recipient)', async () => {
            const { upto } = await engine({ operator: { recipient: RECIPIENT }, x402: { facilitatorFee: 250 } });
            const verified = await openVerified(upto);
            const settlement = await upto.settle(verified, 400_000n);
            expect(settlement.amount).toBe('400000');
            expect(settlement.transaction).toBe('SettleSig');
            expect(settlement.settlementHeaders['x-payment-response']).toBe('ENCODED_PAYMENT_RESPONSE');
            // recipient != operator -> one split at (10000 - fee) bps.
            expect(lastSubmit?.splits).toEqual([{ bps: 9_750, recipient: RECIPIENT }]);
            expect(lastSubmit?.voucher).toBeDefined();
        });

        it('produces no splits when the operator is its own recipient', async () => {
            // Default recipient is the operator pubkey, so no split entry.
            const { upto } = await engine();
            const verified = await openVerified(upto);
            await upto.settle(verified, 300_000n);
            expect(lastSubmit?.splits).toEqual([]);
        });

        it('clamps the settled amount to the authorized ceiling', async () => {
            const { upto } = await engine();
            const verified = await openVerified(upto);
            const settlement = await upto.settle(verified, 5_000_000n);
            expect(settlement.amount).toBe('1000000');
        });

        it('settles a zero amount with no voucher', async () => {
            const { upto } = await engine();
            const verified = await openVerified(upto);
            const settlement = await upto.settle(verified, 0n);
            expect(settlement.amount).toBe('0');
            expect(lastSubmit?.voucher).toBeUndefined();
        });

        it('wraps a settlement failure in an InvalidProofError', async () => {
            settlementControl.submit = () => Promise.reject(new Error('chain rejected'));
            const { upto } = await engine();
            const verified = await openVerified(upto);
            await expect(upto.settle(verified, 100_000n)).rejects.toMatchObject({ code: 'transaction_failed' });
        });

        it('wraps a confirmation timeout in an InvalidProofError', async () => {
            settlementControl.wait = () => Promise.reject(new Error('timeout'));
            const { upto } = await engine();
            const verified = await openVerified(upto);
            await expect(upto.settle(verified, 100_000n)).rejects.toBeInstanceOf(InvalidProofError);
        });

        it('rejects a channel payload missing required fields', async () => {
            decodeControl.impl = () => ({
                accepted: { network: 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp' },
                payload: { channelId: 'chan-1' },
            });
            const { upto } = await engine();
            const verified = await openVerified(upto);
            await expect(upto.settle(verified, 100_000n)).rejects.toMatchObject({ code: 'invalid_upto_payload' });
        });

        it('rejects a payload that is not an object', async () => {
            decodeControl.impl = () => ({
                accepted: { network: 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp' },
                payload: undefined,
            });
            const { upto } = await engine();
            const verified = await openVerified(upto);
            await expect(upto.settle(verified, 100_000n)).rejects.toMatchObject({ code: 'invalid_upto_payload' });
        });

        it('honors an explicit tokenProgram from the requirements extra', async () => {
            const signer = await Signer.generate();
            const { upto } = await engine({ operator: { signer } });
            const verified = await openVerified(upto);
            const patched = {
                ...verified,
                requirements: {
                    ...verified.requirements,
                    extra: { ...verified.requirements.extra, tokenProgram: 'CustomTokenProgram1111' },
                },
            };
            await upto.settle(patched, 100_000n);
            expect(lastSubmit?.tokenProgram).toBe('CustomTokenProgram1111');
        });

        it('resolves the token program from the mint when the extra omits it', async () => {
            const { upto } = await engine();
            const verified = await openVerified(upto);
            await upto.settle(verified, 100_000n);
            // Real getStablecoinTokenProgram maps USDC -> the SPL Token program.
            expect(lastSubmit?.tokenProgram).toBe('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA');
        });
    });
});
