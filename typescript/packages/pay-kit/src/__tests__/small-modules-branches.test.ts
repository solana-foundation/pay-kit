// Branch-coverage tests for the small dependency-light pay-kit modules:
// coin.ts, http.ts, openapi.ts, and signer.ts.
//
// Each of these files sits at 100% line coverage but leaves defaulting and
// error branches uncovered. These tests target exactly those arms:
// the `??` fallback chains, the optional-field guards, and the throw paths.
// No production code is touched.

import { describe, expect, it } from 'vitest';

import { resolveCoin, requireMint } from '../coin.js';
import { ConfigurationError, InvalidKeyError } from '../errors.js';
import { buildOpenApiDocument } from '../openapi.js';
import { usd } from '../price.js';
import { Signer, type KeychainSigner } from '../signer.js';
import { toWebRequest, type NodeRequest } from '../http.js';

// ── coin.ts ──────────────────────────────────────────────────────────────

describe('resolveCoin', () => {
    it('prefers the price primary coin when one is set', () => {
        // usd(amount, ...settlements) → primaryCoin() returns the first settlement.
        expect(resolveCoin(usd('0.10', 'USDT', 'USDC'), ['PYUSD'])).toBe('USDT');
    });

    it('falls back to the first configured stablecoin when the price has no primary', () => {
        expect(resolveCoin(usd('0.10'), ['USDG', 'USDC'])).toBe('USDG');
    });

    it('falls back to USDC when neither a primary coin nor a stablecoin list is present', () => {
        expect(resolveCoin(usd('0.10'), [])).toBe('USDC');
    });
});

describe('requireMint', () => {
    it('returns the mint when one is present', () => {
        expect(requireMint('USDC', 'MintAddr1111111111111111111111111111111111', 'mainnet')).toBe(
            'MintAddr1111111111111111111111111111111111',
        );
    });

    it('throws a ConfigurationError when the mint is missing', () => {
        expect(() => requireMint('USDG', undefined, 'devnet')).toThrow(ConfigurationError);
        expect(() => requireMint('USDG', undefined, 'devnet')).toThrow(/No USDG mint known for devnet/);
    });
});

// ── http.ts ──────────────────────────────────────────────────────────────

describe('toWebRequest', () => {
    it('uses request protocol, host, originalUrl, and method when present', () => {
        const req = {
            headers: { host: 'example.test', accept: 'application/json' },
            method: 'POST',
            originalUrl: '/api/quote',
            protocol: 'https',
        } as unknown as NodeRequest;
        const web = toWebRequest(req);
        expect(web.url).toBe('https://example.test/api/quote');
        expect(web.method).toBe('POST');
        expect(web.headers.get('accept')).toBe('application/json');
    });

    it('defaults protocol/host/url/method and skips undefined headers, joining array headers', () => {
        // No protocol → 'http', no host → 'localhost', no originalUrl (uses url),
        // no method → 'GET'. An undefined header value is skipped; an array header
        // value is appended entry-by-entry.
        const req = {
            headers: {
                host: undefined,
                'x-multi': ['a', 'b'],
                'x-skip': undefined,
            },
            url: '/plain',
        } as unknown as NodeRequest;
        const web = toWebRequest(req);
        expect(web.url).toBe('http://localhost/plain');
        expect(web.method).toBe('GET');
        expect(web.headers.get('x-multi')).toBe('a, b');
        expect(web.headers.has('x-skip')).toBe(false);
    });

    it('defaults the URL path to "/" when neither originalUrl nor url is set', () => {
        const req = { headers: { host: 'h.test' } } as unknown as NodeRequest;
        const web = toWebRequest(req);
        expect(web.url).toBe('http://h.test/');
    });
});

// ── openapi.ts ─────────────────────────────────────────────────────────────

describe('buildOpenApiDocument', () => {
    it('emits a 402 response, x-payment-info, summary, requestBody, and x-service-info when supplied', () => {
        const doc = buildOpenApiDocument({
            info: { title: 'Paid API', version: '3.2.1' },
            routes: [
                {
                    method: 'POST',
                    offers: [{ amount: '1000', intent: 'charge', method: 'x402' }],
                    path: '/paid',
                    requestBody: { required: true },
                    summary: 'Paid route',
                },
            ],
            serviceInfo: { categories: ['finance'] },
        }) as {
            info: { title: string; version: string };
            paths: Record<string, Record<string, Record<string, unknown>>>;
            'x-service-info'?: unknown;
        };

        const op = doc.paths['/paid']!.post!;
        expect((op.responses as Record<string, unknown>)['402']).toEqual({ description: 'Payment Required' });
        expect(op['x-payment-info']).toEqual({ offers: [{ amount: '1000', intent: 'charge', method: 'x402' }] });
        expect(op.summary).toBe('Paid route');
        expect(op.requestBody).toEqual({ required: true });
        expect(doc.info).toEqual({ title: 'Paid API', version: '3.2.1' });
        expect(doc['x-service-info']).toEqual({ categories: ['finance'] });
    });

    it('omits the 402, x-payment-info, summary, requestBody, and x-service-info when absent', () => {
        // offers=null → no 402 and no x-payment-info; no summary/requestBody;
        // no info → default title/version; no serviceInfo → no x-service-info.
        const doc = buildOpenApiDocument({
            routes: [{ method: 'GET', offers: null, path: '/free' }],
        }) as {
            info: { title: string; version: string };
            paths: Record<string, Record<string, Record<string, unknown>>>;
            'x-service-info'?: unknown;
        };

        const op = doc.paths['/free']!.get!;
        const responses = op.responses as Record<string, unknown>;
        expect(responses['402']).toBeUndefined();
        expect(responses['200']).toEqual({ description: 'Successful response' });
        expect(op['x-payment-info']).toBeUndefined();
        expect(op.summary).toBeUndefined();
        expect(op.requestBody).toBeUndefined();
        expect(doc.info).toEqual({ title: 'API', version: '1.0.0' });
        expect(doc['x-service-info']).toBeUndefined();
    });
});

// ── signer.ts ────────────────────────────────────────────────────────────

describe('Signer branch coverage', () => {
    it('from() defaults isFeePayer to true when no options are given', () => {
        // Exercises the `options.feePayer ?? true` default arm.
        const wrapped = Signer.from({ address: 'So11111111111111111111111111111111111111112' } as KeychainSigner);
        expect(wrapped.isFeePayer).toBe(true);
        expect(wrapped.isDemo).toBe(false);
    });

    it('sign() throws InvalidKeyError when the backend returns no signature for the address', async () => {
        // A stub keychain signer whose signMessages resolves without a signature
        // keyed by its address exercises the `if (!signature) throw` arm.
        const stub = {
            address: 'So11111111111111111111111111111111111111112',
            signMessages: async () => [{}],
        } as unknown as KeychainSigner;
        const wrapped = Signer.from(stub);
        await expect(wrapped.sign(new Uint8Array([1, 2, 3]))).rejects.toThrow(InvalidKeyError);
    });

    it('env() auto-detects a 128-char hex secret', async () => {
        // The demo keypair bytes as a 128-char hex string exercise the
        // HEX_PATTERN branch inside env() (the JSON-array branch is already covered).
        const demoBytes = [
            26, 61, 117, 192, 9, 232, 24, 51, 89, 135, 105, 182, 47, 9, 83, 244, 11, 214, 85, 170, 227, 83, 170, 26, 55,
            129, 58, 114, 89, 160, 195, 51, 138, 209, 127, 35, 54, 41, 202, 166, 199, 166, 97, 238, 181, 63, 254, 185,
            45, 16, 174, 102, 250, 198, 30, 191, 232, 236, 147, 167, 41, 178, 151, 26,
        ];
        const hex = demoBytes.map(b => b.toString(16).padStart(2, '0')).join('');
        process.env.PAY_KIT_HEX_ENV_TEST = hex;
        try {
            const signer = await Signer.env('PAY_KIT_HEX_ENV_TEST');
            expect(signer).toBeDefined();
            expect(signer?.pubkey).toBe('ALtYSsZuYyKrNSe6GnVCzxj1T2RPMTPzXMe51xhbmXEq');
        } finally {
            delete process.env.PAY_KIT_HEX_ENV_TEST;
        }
    });
});
