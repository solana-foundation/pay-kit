import type { ExactSvmSchemeOptions } from '@x402/svm';
import { beforeEach, describe, expect, expectTypeOf, it, vi } from 'vitest';

import type { X402Options } from '../config.js';

// Compile-time drift guard: X402Options must equal the full vendored
// @x402/svm option surface modulo readonly (our config is frozen). Key drift
// in either direction — including upstream adding an option we don't expose —
// optionality drift, and per-key widening/narrowing all fail typecheck.
type ImmutableValue<V> = V extends readonly (infer E)[] ? readonly E[] : V;
type Immutable<T> = { readonly [K in keyof T]: ImmutableValue<T[K]> };
expectTypeOf<Immutable<ExactSvmSchemeOptions>>().toEqualTypeOf<X402Options>();

// The upto challenge requires a server-fetched recentBlockhash + recentSlot
// (one getLatestBlockhash call); stub the RPC so the enriched requirement is
// deterministic offline, and let tests flip `fail` to exercise the
// no-bare-offer failure path.
const rpcState = vi.hoisted(() => ({ fail: false, slot: 314n }));
const ctorCalls = vi.hoisted(() => [] as unknown[][]);
const uptoSettleCalls = vi.hoisted(() => [] as unknown[][]);
vi.mock('@solana/kit', async importOriginal => {
    const actual = await importOriginal<typeof import('@solana/kit')>();
    return {
        ...actual,
        createSolanaRpc: () => ({
            getLatestBlockhash: () => ({
                send: async () => {
                    if (rpcState.fail) throw new Error('rpc down');
                    return {
                        context: { slot: rpcState.slot },
                        value: {
                            blockhash: 'EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N',
                            lastValidBlockHeight: 100n,
                        },
                    };
                },
            }),
        }),
    };
});

// Subclass spy: records constructor args while preserving real behavior.
vi.mock('@x402/svm/exact/facilitator', async importOriginal => {
    const actual = await importOriginal<typeof import('@x402/svm/exact/facilitator')>();
    return {
        ...actual,
        ExactSvmScheme: class extends actual.ExactSvmScheme {
            constructor(...args: ConstructorParameters<typeof actual.ExactSvmScheme>) {
                ctorCalls.push(args);
                super(...args);
            }
        },
    };
});

// Subclass spy: records the requirements each deposit settle runs against.
// `verifyOpen` calls `settle()` (not `verify()`) since @x402/svm >= 2.23 moved
// the open broadcast off the now-read-only `verify()` and onto `settle()`'s
// deposit path.
vi.mock('@x402/svm/upto/facilitator', async importOriginal => {
    const actual = await importOriginal<typeof import('@x402/svm/upto/facilitator')>();
    return {
        ...actual,
        UptoSvmScheme: class extends actual.UptoSvmScheme {
            settle(...args: Parameters<InstanceType<typeof actual.UptoSvmScheme>['settle']>) {
                uptoSettleCalls.push(args);
                return super.settle(...args);
            }
        },
    };
});

import { encodePaymentSignatureHeader } from '@x402/core/http';

import { createX402ExactAdapter } from '../adapters/x402.js';
import { Charge, X402Upto } from '../adapters/x402-upto.js';
import { configure, type PayKitConfig } from '../config.js';
import { Gate } from '../gate.js';
import { usd } from '../price.js';
import { gateDefaults } from '../pricing.js';

async function testConfig(): Promise<PayKitConfig> {
    return await configure({ mpp: { challengeBindingSecret: 'x402-test-secret' }, network: 'solana_localnet' });
}

function gateFor(config: PayKitConfig, amount = usd('0.10')): Gate {
    return Gate.create({ amount, name: 'test' }, gateDefaults(config));
}

describe('x402 exact adapter', () => {
    it('advertises a canonical x402 accepts entry', async () => {
        const config = await testConfig();
        const adapter = createX402ExactAdapter(config);
        const entry = await adapter.acceptsEntry(gateFor(config), new Request('http://localhost/r'));

        expect(entry.protocol).toBe('x402');
        expect(entry.scheme).toBe('exact');
        expect(entry.amount).toBe('100000'); // 0.10 USDC, 6 decimals
        expect(entry.payTo).toBe(config.operator.recipient);
        expect(typeof entry.network).toBe('string');
        expect(typeof entry.asset).toBe('string');
        expect((entry.extra as { feePayer?: string }).feePayer).toBe(config.operator.signer.pubkey);
    });

    it('detects the x402 payment header', async () => {
        const config = await testConfig();
        const adapter = createX402ExactAdapter(config);
        expect(adapter.detect(new Request('http://localhost/r'))).toBe(false);
        expect(adapter.detect(new Request('http://localhost/r', { headers: { 'x-payment': 'abc' } }))).toBe(true);
        expect(adapter.detect(new Request('http://localhost/r', { headers: { 'payment-signature': 'abc' } }))).toBe(
            true,
        );
    });

    it('emits the PAYMENT-REQUIRED challenge header', async () => {
        const config = await testConfig();
        const adapter = createX402ExactAdapter(config);
        const headers = await adapter.challengeHeaders(gateFor(config), new Request('http://localhost/r'));
        expect(typeof headers['payment-required']).toBe('string');
        expect(headers['payment-required'].length).toBeGreaterThan(0);
    });
});

describe('x402 smart-wallet options', () => {
    beforeEach(() => {
        ctorCalls.length = 0;
    });

    it('passes x402 options through configure() into the frozen config', async () => {
        const config = await configure({
            mpp: { challengeBindingSecret: 'x402-test-secret' },
            network: 'solana_localnet',
            x402: { enableSmartWalletVerification: true, smartWalletMaxComputeUnits: 300_000 },
        });
        expect(config.x402.enableSmartWalletVerification).toBe(true);
        expect(config.x402.smartWalletMaxComputeUnits).toBe(300_000);
        expect(Object.isFrozen(config.x402)).toBe(true);
    });

    it('constructs the adapter with smart-wallet verification enabled', async () => {
        const config = await configure({
            mpp: { challengeBindingSecret: 'x402-test-secret' },
            network: 'solana_localnet',
            x402: { enableSmartWalletVerification: true },
        });
        expect(() => createX402ExactAdapter(config)).not.toThrow();
    });

    it('forwards config.x402 to the facilitator constructor', async () => {
        const config = await configure({
            mpp: { challengeBindingSecret: 'x402-test-secret' },
            network: 'solana_localnet',
            x402: { enableSmartWalletVerification: true, smartWalletMaxPriorityFeeMicroLamports: 25_000 },
        });
        createX402ExactAdapter(config);
        expect(ctorCalls.length).toBeGreaterThan(0);
        expect(ctorCalls.at(-1)?.[2]).toEqual(config.x402);
    });

    it('copies the allowlist so callers cannot mutate verification policy', async () => {
        const allowed = ['SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf'];
        const config = await configure({
            mpp: { challengeBindingSecret: 'x402-test-secret' },
            network: 'solana_localnet',
            x402: { smartWalletAllowedPrograms: allowed },
        });
        allowed.push('mutated');
        expect(config.x402.smartWalletAllowedPrograms).toEqual(['SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf']);
        expect(Object.isFrozen(config.x402.smartWalletAllowedPrograms)).toBe(true);
    });
});

describe('x402 upto engine', () => {
    it('advertises an upto accepts entry with role bindings', async () => {
        const config = await testConfig();
        const upto = new X402Upto(config);
        const [entry] = await upto.accepts(usd('1.00'));

        expect(entry.scheme).toBe('upto');
        expect(entry.amount).toBe('1000000'); // 1.00 USDC ceiling
        expect(entry.payTo).toBe(config.operator.recipient);
        expect((entry.extra as { feePayer?: string }).feePayer).toBe(config.operator.signer.pubkey);
        expect((entry.extra as { receiverAuthorizer?: string }).receiverAuthorizer).toBe(config.operator.signer.pubkey);
        expect((entry.extra as { withdrawDelay?: number }).withdrawDelay).toBe(900);
        expect((entry.extra as { tokenProgram?: string }).tokenProgram).toEqual(expect.any(String));
        expect((entry.extra as { assetTransferMethod?: string }).assetTransferMethod).toBeUndefined();
        expect((entry.extra as { facilitatorAddress?: string }).facilitatorAddress).toBeUndefined();
        expect((entry.extra as { facilitatorFee?: number }).facilitatorFee).toBeUndefined();
        expect((entry.extra as { channelProgram?: string }).channelProgram).toBeUndefined();
        // The offer is server-enriched: the client derives the channel openSlot
        // from extra.recentSlot and never fetches the slot itself.
        expect((entry.extra as { recentSlot?: string }).recentSlot).toBe('314');
        expect((entry.extra as { recentBlockhash?: string }).recentBlockhash).toBe(
            'EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N',
        );
    });

    it('fails the challenge instead of advertising a bare upto offer', async () => {
        const config = await testConfig();
        const upto = new X402Upto(config);
        rpcState.fail = true;
        try {
            await expect(upto.accepts(usd('1.00'))).rejects.toThrow(/recentBlockhash\/recentSlot/);
        } finally {
            rpcState.fail = false;
        }
    });

    it('detects the payment header and emits a challenge', async () => {
        const config = await testConfig();
        const upto = new X402Upto(config);
        expect(upto.detect(new Request('http://localhost/u'))).toBe(false);
        expect(upto.detect(new Request('http://localhost/u', { headers: { 'x-payment': 'abc' } }))).toBe(true);
        const headers = await upto.challengeHeaders(usd('1.00'), new Request('http://localhost/u'));
        expect(typeof headers['payment-required']).toBe('string');
    });

    // verifyOpen binds the authorization's openSlot to the challenged
    // recentSlot BEFORE the facilitator broadcasts the open: the facilitator
    // pins the open transaction's openArgs.openSlot to payload.openSlot, so
    // rejecting the payload value here rejects the openArgs transitively.
    async function verifyOpenRequestFor(openSlot: string): Promise<{ request: Request; upto: X402Upto }> {
        const config = await testConfig();
        const upto = new X402Upto(config);
        const [accepted] = await upto.accepts(usd('1.00'));
        const header = encodePaymentSignatureHeader({
            accepted,
            payload: { openSlot },
            x402Version: 2,
        } as never);
        return { request: new Request('http://localhost/u', { headers: { 'x-payment': header } }), upto };
    }

    it('rejects an authorization whose openSlot is ahead of the challenged recentSlot', async () => {
        const { request, upto } = await verifyOpenRequestFor('315');
        await expect(upto.verifyOpen(request, usd('1.00'))).rejects.toThrow(
            /openSlot 315 is ahead of the challenged recentSlot 314/,
        );
    });

    it('rejects an authorization whose openSlot is stale beyond the 1500-slot window', async () => {
        const { request, upto } = await verifyOpenRequestFor('10');
        rpcState.slot = 5_000n;
        try {
            await expect(upto.verifyOpen(request, usd('1.00'))).rejects.toThrow(
                /openSlot 10 is outside the 1500-slot freshness window of the challenged recentSlot 5000/,
            );
        } finally {
            rpcState.slot = 314n;
        }
    });

    // Regression: the facilitator's deposit-settle path runs the same openSlot
    // window check inside `verifyOpenTransaction`, and without a `recentSlot`
    // hint it reads its own `finalized` slot — which lags this challenge's
    // `getLatestBlockhash` context slot by tens of slots and rejects a
    // perfectly fresh open. The requirements `verifyOpen` hands to
    // `facilitator.settle()` must therefore carry the re-observed slot.
    it('hands the facilitator the re-observed recentSlot it window-checks against', async () => {
        uptoSettleCalls.length = 0;
        const { request, upto } = await verifyOpenRequestFor('314');
        await expect(upto.verifyOpen(request, usd('1.00'))).rejects.toThrow();
        const requirements = uptoSettleCalls.at(-1)?.[1] as { extra?: { recentSlot?: unknown } } | undefined;
        expect(requirements?.extra?.recentSlot).toBe('314');
    });

    it('rejects a payload without a decimal-string openSlot before any broadcast', async () => {
        const { request, upto } = await verifyOpenRequestFor('not-a-slot');
        await expect(upto.verifyOpen(request, usd('1.00'))).rejects.toThrow(
            /payload.openSlot must be a u64 decimal string/,
        );
    });

    it('skips the window check when the recentSlot re-fetch fails (program still enforces it)', async () => {
        const { request, upto } = await verifyOpenRequestFor('315');
        rpcState.fail = true;
        try {
            // The slot bind is skipped; verification proceeds and fails later
            // in the facilitator on the (intentionally minimal) payload —
            // proving no ahead-of-recentSlot rejection fired.
            await expect(upto.verifyOpen(request, usd('1.00'))).rejects.toThrow(/unsupported_payload_type/);
        } finally {
            rpcState.fail = false;
        }
    });
});

describe('Charge meter', () => {
    it('defaults to a zero settlement', () => {
        expect(new Charge(1_000_000n).settledBaseUnits()).toBe(0n);
    });

    it('records the reported amount', () => {
        const charge = new Charge(1_000_000n);
        charge.charge(400_000n);
        expect(charge.settledBaseUnits()).toBe(400_000n);
    });

    it('clamps above the ceiling and floors negatives', () => {
        const overCharge = new Charge(1_000_000n);
        overCharge.charge(2_000_000n);
        expect(overCharge.settledBaseUnits()).toBe(1_000_000n);

        const negative = new Charge(1_000_000n);
        negative.charge(-5);
        expect(negative.settledBaseUnits()).toBe(0n);
    });

    it('accepts a plain number', () => {
        const charge = new Charge(1_000_000n);
        charge.charge(250_000);
        expect(charge.settledBaseUnits()).toBe(250_000n);
    });
});
