import { describe, expect, it } from 'vitest';

import type { ProtocolAdapter } from '../adapter.js';
import { configure, type PayKitConfig } from '../config.js';
import { ConfigurationError, InvalidProofError, UnknownGateError } from '../errors.js';
import type { Payment } from '../payment.js';
import { createPayKit } from '../paykit.js';
import { usd } from '../price.js';
import { declareProductionReplayStore } from '../replay-store.js';
import { Signer, type PayKitSigner } from '../signer.js';

const CREDENTIAL_HEADER = 'x-fake-credential';

function createSharedTestReplayStore() {
    const entries = new Map<string, unknown>();
    return declareProductionReplayStore({
        delete: async (key: string) => {
            entries.delete(key);
        },
        get: async (key: string) => entries.get(key) ?? null,
        isDurable: true as const,
        isShared: true as const,
        put: async (key: string, value: unknown) => {
            entries.set(key, value);
        },
        putIfAbsent: async (key: string, value: unknown) => {
            if (entries.has(key)) return false;
            entries.set(key, value);
            return true;
        },
    });
}

class ClassBasedSigner implements PayKitSigner {
    readonly isDemo = false;
    readonly isFeePayer = true;
    readonly pubkey: string;
    readonly signer: PayKitSigner['signer'];
    calls = 0;

    constructor(private readonly delegate: PayKitSigner) {
        this.pubkey = delegate.pubkey;
        this.signer = delegate.signer;
    }

    async sign(message: Uint8Array): Promise<Uint8Array> {
        this.calls += 1;
        return await this.delegate.sign(message);
    }
}

function fakeAdapter(config: PayKitConfig): ProtocolAdapter {
    return {
        async acceptsEntry(gate) {
            return {
                amount: gate.amount.baseUnits().toString(),
                network: 'solana:test',
                payTo: gate.payTo,
                protocol: 'mpp',
                scheme: 'charge',
            };
        },
        async challengeHeaders() {
            return { 'www-authenticate': `Payment realm="${config.mpp.realm}"` };
        },
        detect(request) {
            return request.headers.has(CREDENTIAL_HEADER);
        },
        protocol: 'mpp',
        scheme: 'charge',
        async verifyAndSettle(gate, request): Promise<Payment> {
            const credential = request.headers.get(CREDENTIAL_HEADER);
            if (credential !== 'valid') throw new InvalidProofError('signature_consumed', 'already used');
            return {
                gateName: gate.name,
                payer: 'PayerPubkey',
                protocol: 'mpp',
                raw: credential,
                scheme: 'charge',
                settlementHeaders: { 'x-payment-settlement-signature': 'TxSig' },
                transaction: 'TxSig',
            };
        },
    };
}

async function setup() {
    const config = await configure({ mpp: { challengeBindingSecret: 's3cret', allowUnsafeMemoryStore: true } });
    return createPayKit({
        adapters: [fakeAdapter(config)],
        config,
        pricing: {
            report: { amount: usd('0.10'), description: 'Premium report' },
            tiered: request => usd(new URL(request.url).searchParams.get('tier') === 'pro' ? '5.00' : '0.10'),
        },
    });
}

describe('createPayKit', () => {
    it('rejects a frozen prebuilt non-local config with a one-byte challenge binding secret', async () => {
        const base = await configure({ mpp: { allowUnsafeMemoryStore: true, challengeBindingSecret: 's'.repeat(32) } });
        const config: PayKitConfig = Object.freeze({
            ...base,
            mpp: Object.freeze({ ...base.mpp, challengeBindingSecret: 'x' }),
            network: 'solana_devnet',
        });

        await expect(createPayKit({ config })).rejects.toThrow(
            'mpp.challengeBindingSecret must be at least 32 UTF-8 bytes outside localnet.',
        );
    });

    it('revalidates every boot invariant on frozen prebuilt configs', async () => {
        const base = await configure({ mpp: { allowUnsafeMemoryStore: true, challengeBindingSecret: 's'.repeat(32) } });

        await expect(createPayKit({ config: Object.freeze({ ...base, accept: Object.freeze([]) }) })).rejects.toThrow(
            'accept must list at least one protocol.',
        );
        await expect(
            createPayKit({
                config: Object.freeze({
                    ...base,
                    network: 'solana_testnet' as PayKitConfig['network'],
                }),
            }),
        ).rejects.toThrow('Unknown network "solana_testnet".');
        await expect(
            createPayKit({ config: Object.freeze({ ...base, stablecoins: Object.freeze([]) }) }),
        ).rejects.toThrow('stablecoins must list at least one coin.');
    });

    it('rejects a forged demo wrapper in a prebuilt mainnet config', async () => {
        const demo = await Signer.demo();
        const forgedSigner = { ...demo, isDemo: false };
        const local = await configure({
            mpp: { allowUnsafeMemoryStore: true, challengeBindingSecret: 's'.repeat(32) },
            operator: { signer: forgedSigner },
        });

        await expect(
            createPayKit({
                config: Object.freeze({
                    ...local,
                    network: 'solana_mainnet',
                    replayStore: createSharedTestReplayStore(),
                }),
            }),
        ).rejects.toThrow('The demo signer is public and must not be used on mainnet. Provide operator.signer.');
    });

    it('rejects malformed localnet challenge secrets in prebuilt configs before expiry validation', async () => {
        const base = await configure({ mpp: { allowUnsafeMemoryStore: true, challengeBindingSecret: 's'.repeat(32) } });
        const config = Object.freeze({
            ...base,
            mpp: Object.freeze({ ...base.mpp, challengeBindingSecret: undefined as never, expiresIn: -1 }),
        });

        await expect(createPayKit({ config })).rejects.toThrow(
            'mpp.challengeBindingSecret must be a non-empty string.',
        );
    });

    it('snapshots mutable prebuilt configuration wrappers before adapters observe them', async () => {
        const base = await configure({ mpp: { allowUnsafeMemoryStore: true, challengeBindingSecret: 's'.repeat(32) } });
        const mutableMpp = { ...base.mpp };
        const mutableSigner = { ...base.operator.signer };
        const replayStore = createSharedTestReplayStore();
        const config: PayKitConfig = {
            ...base,
            mpp: mutableMpp,
            operator: { ...base.operator, signer: mutableSigner },
            replayStore,
        };

        const paykit = await createPayKit({ config });
        mutableMpp.realm = 'changed-after-construction';
        mutableSigner.isDemo = false;
        mutableSigner.pubkey = 'changed-after-construction';

        expect(paykit.config.mpp.realm).toBe('App');
        expect(paykit.config.operator.signer.isDemo).toBe(true);
        expect(paykit.config.operator.signer.pubkey).toBe(base.operator.signer.pubkey);
        expect(paykit.config.operator.signer.signer).toBe(mutableSigner.signer);
        expect(paykit.config.replayStore).toBe(replayStore);
        expect(Object.isFrozen(paykit.config)).toBe(true);
        expect(Object.isFrozen(paykit.config.mpp)).toBe(true);
        expect(Object.isFrozen(paykit.config.operator)).toBe(true);
        expect(Object.isFrozen(paykit.config.operator.signer)).toBe(true);
    });

    it('retains a class-based signer sign method in an immutable config snapshot', async () => {
        const classSigner = new ClassBasedSigner(await Signer.generate());
        const config = await configure({
            mpp: { allowUnsafeMemoryStore: true, challengeBindingSecret: 's'.repeat(32) },
            operator: { signer: classSigner },
        });
        const paykit = await createPayKit({ config });

        const signature = await paykit.config.operator.signer.sign(new TextEncoder().encode('snapshot compatibility'));

        expect(signature).toHaveLength(64);
        expect(classSigner.calls).toBe(1);
        expect(paykit.config.operator.signer.signer).toBe(classSigner.signer);
        expect(Object.isFrozen(paykit.config.operator.signer)).toBe(true);
    });

    it('rejects a prebuilt mainnet config carrying the unsafe replay-store escape', async () => {
        const local = await configure({
            mpp: { challengeBindingSecret: 's3cret', allowUnsafeMemoryStore: true },
            operator: { signer: await Signer.generate() },
        });
        await expect(
            createPayKit({
                config: { ...local, network: 'solana_mainnet' },
                pricing: { report: usd('0.10') },
            }),
        ).rejects.toThrow(/forbidden on mainnet/);
    });

    it('rejects a prebuilt mainnet config that hides its process-local replay store', async () => {
        const local = await configure({
            mpp: { challengeBindingSecret: 's3cret', allowUnsafeMemoryStore: true },
            operator: { signer: await Signer.generate() },
        });
        await expect(
            createPayKit({
                config: {
                    ...local,
                    mpp: { ...local.mpp, allowUnsafeMemoryStore: false },
                    network: 'solana_mainnet',
                },
                pricing: { report: usd('0.10') },
            }),
        ).rejects.toThrow(/declareProductionReplayStore/);
    });

    it('rejects a prebuilt mainnet config carrying the demo signer', async () => {
        const local = await configure({
            mpp: { challengeBindingSecret: 's3cret' },
            replayStore: createSharedTestReplayStore(),
        });
        await expect(
            createPayKit({
                config: { ...local, network: 'solana_mainnet' },
                pricing: { report: usd('0.10') },
            }),
        ).rejects.toThrow(/demo signer is public/);
    });

    it('renders a 402 challenge when no credential is present', async () => {
        const paykit = await setup();
        const request = new Request('http://api.test/report');
        const result = await paykit.requirePayment(request, 'report');
        expect('challenge' in result).toBe(true);
        if (!('challenge' in result)) return;
        expect(result.status).toBe(402);
        expect(result.challenge.resource).toBe('/report');
        expect(result.challenge.accepts).toHaveLength(1);
        expect(result.challenge.accepts[0]?.amount).toBe('100000');
        expect(result.response.status).toBe(402);
        expect(result.response.headers.get('www-authenticate')).toContain('Payment realm=');
        const body = (await result.response.json()) as { accepts: unknown[] };
        expect(body.accepts).toHaveLength(1);
        expect(paykit.paid(request)).toBe(false);
    });

    it('settles a valid credential and exposes the payment', async () => {
        const paykit = await setup();
        const request = new Request('http://api.test/report', { headers: { [CREDENTIAL_HEADER]: 'valid' } });
        const result = await paykit.requirePayment(request, 'report');
        expect('payment' in result).toBe(true);
        if (!('payment' in result)) return;
        expect(result.status).toBe(200);
        expect(result.payment.transaction).toBe('TxSig');
        expect(result.payment.gateName).toBe('report');
        expect(result.payment.scheme).toBe('charge');
        expect(result.payment.payer).toBe('PayerPubkey');

        const sealed = await result.withSettlement(Response.json({ ok: true }, { status: 201 }));
        expect(sealed.status).toBe(201);
        expect(sealed.headers.get('x-payment-settlement-signature')).toBe('TxSig');
        expect(((await sealed.json()) as { ok: boolean }).ok).toBe(true);

        expect(paykit.paid(request)).toBe(true);
        expect(paykit.paid(request, 'report')).toBe(true);
        expect(paykit.paid(request, 'tiered')).toBe(false);
        expect(paykit.payment(request)?.transaction).toBe('TxSig');
    });

    it('renders 402 with the canonical code on invalid proof', async () => {
        const paykit = await setup();
        const request = new Request('http://api.test/report', { headers: { [CREDENTIAL_HEADER]: 'replayed' } });
        const result = await paykit.requirePayment(request, 'report');
        expect('challenge' in result).toBe(true);
        if (!('challenge' in result)) return;
        expect(result.status).toBe(402);
        const body = (await result.response.json()) as { code: string; detail: string };
        expect(body.code).toBe('signature_consumed');
        expect(body.detail).toBe('already used');
        expect(paykit.paid(request)).toBe(false);
    });

    it('serves a protocol-owned response for browser/worker requests, JSON 402 for API', async () => {
        const config = await configure({
            mpp: { challengeBindingSecret: 's3cret', html: true, allowUnsafeMemoryStore: true },
        });
        const htmlAdapter: ProtocolAdapter = {
            ...fakeAdapter(config),
            async respond(_gate, request) {
                const url = new URL(request.url);
                if (url.searchParams.has('__mppx_worker'))
                    return new Response('addEventListener', {
                        headers: { 'content-type': 'application/javascript' },
                        status: 200,
                    });
                if ((request.headers.get('accept') ?? '').includes('text/html'))
                    return new Response('<!doctype html>', { headers: { 'content-type': 'text/html' }, status: 402 });
                return undefined;
            },
        };
        const pay = await createPayKit({
            adapters: [htmlAdapter],
            config,
            pricing: { report: { amount: usd('0.10') } },
        });

        const browser = await pay.requirePayment(
            new Request('http://api.test/report', { headers: { accept: 'text/html' } }),
            'report',
        );
        expect('respond' in browser).toBe(true);
        if ('respond' in browser) {
            expect(browser.respond.status).toBe(402);
            expect(browser.respond.headers.get('content-type')).toContain('text/html');
        }

        const worker = await pay.requirePayment(
            new Request('http://api.test/report?__mppx_worker=1', { headers: { accept: 'text/html' } }),
            'report',
        );
        expect('respond' in worker).toBe(true);
        if ('respond' in worker) {
            expect(worker.respond.status).toBe(200);
            expect(worker.respond.headers.get('content-type')).toContain('application/javascript');
        }

        // API clients (no text/html, no worker param) keep the JSON 402.
        const api = await pay.requirePayment(
            new Request('http://api.test/report', { headers: { accept: 'application/json' } }),
            'report',
        );
        expect('challenge' in api).toBe(true);
        if ('challenge' in api) expect(api.status).toBe(402);
    });

    it('resolves gates by name, price, and resolver', async () => {
        const paykit = await setup();
        const denied = await paykit.requirePayment(new Request('http://api.test/x'), usd('0.25'));
        expect('challenge' in denied).toBe(true);
        if ('challenge' in denied) expect(denied.challenge.accepts[0]?.amount).toBe('250000');

        const pro = await paykit.requirePayment(new Request('http://api.test/x?tier=pro'), 'tiered');
        if ('challenge' in pro) expect(pro.challenge.accepts[0]?.amount).toBe('5000000');

        const inline = await paykit.requirePayment(new Request('http://api.test/x'), () => usd('1.00'));
        if ('challenge' in inline) expect(inline.challenge.accepts[0]?.amount).toBe('1000000');

        await expect(
            // @ts-expect-error 'missing' is not a catalogue gate (caught at compile time; also throws at runtime)
            paykit.requirePayment(new Request('http://api.test/x'), 'missing'),
        ).rejects.toThrow(UnknownGateError);
    });

    it('requires a pricing catalogue for name references', async () => {
        const config = await configure({ mpp: { challengeBindingSecret: 's3cret', allowUnsafeMemoryStore: true } });
        const paykit = await createPayKit({ adapters: [fakeAdapter(config)], config });
        await expect(paykit.requirePayment(new Request('http://api.test/x'), 'report')).rejects.toThrow(
            ConfigurationError,
        );
    });
});
