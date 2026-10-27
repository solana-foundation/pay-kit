import { generateKeyPairSigner, type KeyPairSigner } from '@solana/kit';
import { Challenge, resolveStablecoinMint } from '@solana/mpp/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// `createPayKitClient` binds `globalThis.fetch` into a module-level `nativeFetch`
// when its module first loads, so the stub must be installed before that import
// is evaluated — `vi.hoisted` runs ahead of the static imports below.
const { mockFetch } = vi.hoisted(() => {
    const mockFetch = vi.fn<typeof fetch>();
    globalThis.fetch = mockFetch;
    return { mockFetch };
});

import { ClientPermissions, createPayKitClient, PermissionDeniedError } from '../client/index.js';
import { ConfigurationError } from '../errors.js';

const RPC_URL = 'http://127.0.0.1:8899';

function response(status: number, headers: Record<string, string> = {}): Response {
    return new Response(null, { headers, status });
}

describe('createPayKitClient', () => {
    let signer: KeyPairSigner;

    beforeEach(async () => {
        signer = await generateKeyPairSigner();
        mockFetch.mockReset();
    });

    afterEach(() => {
        vi.restoreAllMocks();
    });

    it('passes a non-402 response through untouched without attempting payment', async () => {
        const ok = response(200);
        mockFetch.mockResolvedValue(ok);

        const client = await createPayKitClient({ accept: ['x402', 'mpp'], rpcUrl: RPC_URL, signer });
        const result = await client.fetch('http://api.test/joke');

        expect(result).toBe(ok);
        expect(mockFetch).toHaveBeenCalledTimes(1);
    });

    it('rejects a session intent with ConfigurationError before any signing', async () => {
        mockFetch.mockResolvedValue(response(402, { 'www-authenticate': 'Payment intent="session"' }));

        const client = await createPayKitClient({ accept: ['mpp'], rpcUrl: RPC_URL, signer });

        await expect(client.fetch('http://api.test/stream')).rejects.toBeInstanceOf(ConfigurationError);
        await expect(client.fetch('http://api.test/stream')).rejects.toThrow(/session client/i);
        expect(mockFetch).toHaveBeenCalledTimes(2);
    });

    it('returns the probe unchanged when no accepted protocol matches the challenge headers', async () => {
        const challenge = response(402);
        mockFetch.mockResolvedValue(challenge);

        const client = await createPayKitClient({ accept: ['x402'], rpcUrl: RPC_URL, signer });
        const result = await client.fetch('http://api.test/joke');

        expect(result).toBe(challenge);
        expect(mockFetch).toHaveBeenCalledTimes(1);
    });

    it('fails closed when a 402 was reached through an internal redirect', async () => {
        const challenge = response(402);
        Object.defineProperty(challenge, 'redirected', { value: true });
        mockFetch.mockResolvedValue(challenge);
        const client = await createPayKitClient({ rpcUrl: RPC_URL, signer });

        await expect(client.fetch('https://api.test/redirect')).rejects.toBeInstanceOf(PermissionDeniedError);
        expect(mockFetch).toHaveBeenCalledTimes(1);
    });

    it('denies an over-cap MPP challenge before signing or retrying', async () => {
        const mint = resolveStablecoinMint('USDC', 'mainnet');
        if (!mint) throw new Error('missing mainnet USDC mint');
        const challenge = Challenge.serialize({
            id: 'over-cap',
            intent: 'charge',
            method: 'solana',
            realm: 'test',
            request: {
                amount: '1000001',
                currency: mint,
                methodDetails: {
                    decimals: 6,
                    feePayer: false,
                    network: 'mainnet',
                },
                recipient: signer.address,
            },
        });
        mockFetch.mockResolvedValue(response(402, { 'www-authenticate': challenge }));
        const signTransactions = vi.fn(signer.signTransactions.bind(signer));
        const trackingSigner = new Proxy(signer, {
            get: (target, property, receiver) =>
                property === 'signTransactions' ? signTransactions : Reflect.get(target, property, receiver),
        });
        const client = await createPayKitClient({ accept: ['mpp'], rpcUrl: RPC_URL, signer: trackingSigner });

        await expect(client.fetch('https://api.test/paid')).rejects.toBeInstanceOf(PermissionDeniedError);

        expect(signTransactions).not.toHaveBeenCalled();
        expect(mockFetch).toHaveBeenCalledTimes(1);
    });

    it('denies an unsupported x402 network before signing or retrying', async () => {
        const paymentRequired = btoa(
            JSON.stringify({
                accepts: [
                    {
                        amount: '500000',
                        asset: 'USDC',
                        extra: {},
                        maxTimeoutSeconds: 60,
                        network: 'solana:unsupported',
                        payTo: signer.address,
                        scheme: 'exact',
                    },
                ],
                x402Version: 2,
            }),
        );
        mockFetch.mockResolvedValue(response(402, { 'payment-required': paymentRequired }));
        const signTransactions = vi.fn(signer.signTransactions.bind(signer));
        const trackingSigner = new Proxy(signer, {
            get: (target, property, receiver) =>
                property === 'signTransactions' ? signTransactions : Reflect.get(target, property, receiver),
        });
        const client = await createPayKitClient({ accept: ['x402'], rpcUrl: RPC_URL, signer: trackingSigner });

        await expect(client.fetch('https://api.test/paid')).rejects.toBeInstanceOf(PermissionDeniedError);
        expect(signTransactions).not.toHaveBeenCalled();
        expect(mockFetch).toHaveBeenCalledTimes(1);
    });

    describe('x402 payment-identifier extension', () => {
        const DEVNET = 'solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1';
        const MINT = '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU';
        const TOKEN_PROGRAM = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA';

        /** 82-byte SPL mint: no authorities, 6 decimals, initialized. */
        function mintAccountBase64(): string {
            const data = new Uint8Array(82);
            data[44] = 6;
            data[45] = 1;
            return Buffer.from(data).toString('base64');
        }

        /**
         * Serve the 402 (with `extensions`), the mint and blockhash RPC calls,
         * and capture the payment envelope the client retries with.
         */
        async function payWithExtensions(
            extensions: Record<string, unknown>,
            options: { extra?: Record<string, unknown>; maxTransactionVersion?: 0 | 1 } = {},
        ): Promise<Record<string, unknown>> {
            const feePayer = await generateKeyPairSigner();
            const paymentRequired = btoa(
                JSON.stringify({
                    accepts: [
                        {
                            amount: '1000',
                            asset: MINT,
                            extra: { feePayer: feePayer.address, ...options.extra },
                            maxTimeoutSeconds: 300,
                            network: DEVNET,
                            payTo: feePayer.address,
                            scheme: 'exact',
                        },
                    ],
                    extensions,
                    resource: { url: 'https://api.test/paid' },
                    x402Version: 2,
                }),
            );
            let sent: string | undefined;
            mockFetch.mockImplementation((input: RequestInfo | URL, init?: RequestInit) => {
                const url = input instanceof Request ? input.url : String(input);
                if (url.startsWith(RPC_URL)) {
                    const { id, method } = JSON.parse(String(init?.body)) as { id: number; method: string };
                    const result =
                        method === 'getAccountInfo'
                            ? {
                                  context: { slot: 1 },
                                  value: {
                                      data: [mintAccountBase64(), 'base64'],
                                      executable: false,
                                      lamports: 1_461_600,
                                      owner: TOKEN_PROGRAM,
                                      rentEpoch: 0,
                                      space: 82,
                                  },
                              }
                            : {
                                  context: { slot: 1 },
                                  value: { blockhash: '11111111111111111111111111111111', lastValidBlockHeight: 100 },
                              };
                    return Promise.resolve(Response.json({ id, jsonrpc: '2.0', result }));
                }
                const header = input instanceof Request ? input.headers.get('payment-signature') : null;
                if (header) {
                    sent = header;
                    return Promise.resolve(response(200));
                }
                return Promise.resolve(response(402, { 'payment-required': paymentRequired }));
            });

            const client = await createPayKitClient({
                accept: ['x402'],
                maxTransactionVersion: options.maxTransactionVersion,
                permissions: false,
                rpcUrl: RPC_URL,
                signer,
            });
            const result = await client.fetch('https://api.test/paid');

            expect(result.status).toBe(200);
            if (!sent) throw new Error('client did not send a payment');
            return JSON.parse(atob(sent)) as Record<string, unknown>;
        }

        it('fills a payment id when the server requires one, echoing every declared field', async () => {
            const envelope = await payWithExtensions({
                'future-extension': { info: { foo: 'bar' } },
                'payment-identifier': { info: { required: true }, schema: { required: ['id'], type: 'object' } },
            });

            const extensions = envelope.extensions as Record<string, { info: Record<string, unknown> }>;
            expect(extensions['future-extension']).toEqual({ info: { foo: 'bar' } });
            const identifier = extensions['payment-identifier'];
            expect(identifier).toMatchObject({
                info: { required: true },
                schema: { required: ['id'], type: 'object' },
            });
            expect(identifier.info.id).toMatch(/^pay_[0-9a-f]{32}$/);
        });

        /** First byte of the message: 0x81 for version 1, 0x80 for version 0. */
        function messageVersionByte(envelope: Record<string, unknown>): number {
            const transaction = (envelope.payload as { transaction: string }).transaction;
            const bytes = Buffer.from(transaction, 'base64');
            // Version 1 puts the message first; version 0 after the signatures.
            return bytes[0]! & 0x80 ? bytes[0]! : bytes[1 + 64 * bytes[0]!]!;
        }

        it('builds version 1 when the server advertises it', async () => {
            const envelope = await payWithExtensions({}, { extra: { transactionVersions: [0, 1] } });
            expect(messageVersionByte(envelope)).toBe(0x81);
        });

        it('builds version 0 for a signer limited to version 0', async () => {
            const envelope = await payWithExtensions(
                {},
                { extra: { transactionVersions: [0, 1] }, maxTransactionVersion: 0 },
            );
            expect(messageVersionByte(envelope)).toBe(0x80);
        });

        it('rejects a maxTransactionVersion other than 0 or 1', () => {
            expect(() =>
                createPayKitClient({ accept: ['x402'], maxTransactionVersion: 2 as never, rpcUrl: RPC_URL, signer }),
            ).toThrow(ConfigurationError);
        });

        it('adds no id when the server does not require one', async () => {
            const envelope = await payWithExtensions({ 'payment-identifier': { info: { required: false } } });

            expect(envelope.extensions).toEqual({ 'payment-identifier': { info: { required: false } } });
        });
    });

    describe('MPP charge transaction versions', () => {
        /** Pays a USDC charge advertising `[0, 1]` and returns the message version byte of the credential. */
        async function payMppCharge(maxTransactionVersion?: 0 | 1): Promise<number> {
            const mint = resolveStablecoinMint('USDC', 'mainnet');
            if (!mint) throw new Error('missing mainnet USDC mint');
            const merchant = await generateKeyPairSigner();
            const challenge = Challenge.serialize({
                id: 'versions',
                intent: 'charge',
                method: 'solana',
                realm: 'test',
                request: {
                    amount: '1000',
                    currency: mint,
                    methodDetails: {
                        decimals: 6,
                        network: 'mainnet',
                        tokenProgram: 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA',
                        recentBlockhash: 'EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N',
                        transactionVersions: [0, 1],
                    },
                    recipient: merchant.address,
                },
            });
            let sent: string | undefined;
            mockFetch.mockImplementation((input: RequestInfo | URL) => {
                const header = input instanceof Request ? input.headers.get('authorization') : null;
                if (header) {
                    sent = header;
                    return Promise.resolve(response(200));
                }
                return Promise.resolve(response(402, { 'www-authenticate': challenge }));
            });
            const client = await createPayKitClient({
                accept: ['mpp'],
                maxTransactionVersion,
                permissions: false,
                rpcUrl: RPC_URL,
                signer,
            });

            expect((await client.fetch('https://api.test/paid')).status).toBe(200);
            if (!sent) throw new Error('client did not send a credential');
            const encoded = sent
                .replace(/^Payment\s+/, '')
                .replace(/-/g, '+')
                .replace(/_/g, '/');
            const credential = JSON.parse(Buffer.from(encoded, 'base64').toString('utf8')) as {
                payload: { transaction: string };
            };
            const bytes = Buffer.from(credential.payload.transaction, 'base64');
            // Version 1 puts the message first; version 0 after the signatures.
            return bytes[0]! & 0x80 ? bytes[0]! : bytes[1 + 64 * bytes[0]!]!;
        }

        it('builds version 1 when the challenge lists [0, 1]', async () => {
            expect(await payMppCharge()).toBe(0x81);
        });

        it('builds version 0 for a signer limited to version 0', async () => {
            expect(await payMppCharge(0)).toBe(0x80);
        });

        it('rejects a maxTransactionVersion other than 0 or 1 on an MPP-only client', () => {
            expect(() =>
                createPayKitClient({ accept: ['mpp'], maxTransactionVersion: 2 as never, rpcUrl: RPC_URL, signer }),
            ).toThrow(ConfigurationError);
        });
    });

    it('denies an MPP split to a recipient outside the allowlist before signing', async () => {
        const mint = resolveStablecoinMint('USDC', 'mainnet');
        if (!mint) throw new Error('missing mainnet USDC mint');
        const merchant = await generateKeyPairSigner();
        const attacker = await generateKeyPairSigner();
        const challenge = Challenge.serialize({
            id: 'split',
            intent: 'charge',
            method: 'solana',
            realm: 'test',
            request: {
                amount: '1000',
                currency: mint,
                methodDetails: {
                    decimals: 6,
                    feePayer: false,
                    network: 'mainnet',
                    splits: [{ amount: '400', recipient: attacker.address }],
                },
                recipient: merchant.address,
            },
        });
        mockFetch.mockResolvedValue(response(402, { 'www-authenticate': challenge }));
        const signTransactions = vi.fn(signer.signTransactions.bind(signer));
        const trackingSigner = new Proxy(signer, {
            get: (target, property, receiver) =>
                property === 'signTransactions' ? signTransactions : Reflect.get(target, property, receiver),
        });
        const client = await createPayKitClient({
            accept: ['mpp'],
            permissions: ClientPermissions.builder().allowRecipient(merchant.address).build(),
            rpcUrl: RPC_URL,
            signer: trackingSigner,
        });

        const error: unknown = await client.fetch('https://api.test/paid').catch((caught: unknown) => caught);
        expect(error).toBeInstanceOf(PermissionDeniedError);
        expect((error as PermissionDeniedError).rejections).toEqual([
            expect.objectContaining({
                code: 'recipient_not_allowed',
                message: expect.stringContaining(attacker.address),
            }),
        ]);
        expect(signTransactions).not.toHaveBeenCalled();
        expect(mockFetch).toHaveBeenCalledTimes(1);
    });

    it('denies an x402 payTo outside the recipient allowlist before signing', async () => {
        const merchant = await generateKeyPairSigner();
        const paymentRequired = btoa(
            JSON.stringify({
                accepts: [
                    {
                        amount: '500000',
                        asset: resolveStablecoinMint('USDC', 'mainnet'),
                        extra: {},
                        maxTimeoutSeconds: 60,
                        network: 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp',
                        payTo: signer.address,
                        scheme: 'exact',
                    },
                ],
                x402Version: 2,
            }),
        );
        mockFetch.mockResolvedValue(response(402, { 'payment-required': paymentRequired }));
        const client = await createPayKitClient({
            accept: ['x402'],
            permissions: ClientPermissions.builder().allowRecipient(merchant.address).build(),
            rpcUrl: RPC_URL,
            signer,
        });

        const error: unknown = await client.fetch('https://api.test/paid').catch((caught: unknown) => caught);
        expect((error as PermissionDeniedError).rejections).toEqual([
            expect.objectContaining({ code: 'recipient_not_allowed' }),
        ]);
        expect(mockFetch).toHaveBeenCalledTimes(1);
    });
});
