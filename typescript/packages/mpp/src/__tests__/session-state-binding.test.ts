import {
    address,
    type Address,
    getAddressEncoder,
    getBase64Decoder,
    getBase64Encoder,
    getProgramDerivedAddress,
    getU64Encoder,
    getUtf8Encoder,
} from '@solana/kit';
import { describe, expect, test } from 'vitest';

import { resolveStablecoinMint, TOKEN_PROGRAM } from '../constants.js';
import { getChannelEncoder } from '../generated/payment-channels/accounts/channel.js';
import { PAYMENT_CHANNELS_PROGRAM_ADDRESS } from '../generated/payment-channels/programs/paymentChannels.js';
import { session } from '../server/Session.js';
import { verifyChannelAccountState } from '../server/session/on-chain.js';
import { createMemorySessionStore } from '../server/session/store.js';

const OPERATOR = '9xAXssX9j7vuK99c7cFwqbixzL3bFrzPy9PUhCtDPAYJ';
const RECIPIENT = '5fKb5cF22cFybZB1H4hLDydFhwoQy9JzKzRWaSbMkB6h';
const SIGNER = 'CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY';
const PAYER = '11111111111111111111111111111111';
const CLAIMED_PAYER = 'SysvarRent111111111111111111111111111111111';
const LOCALNET_USDC = resolveStablecoinMint('USDC', 'localnet')!;
const EMPTY_DISTRIBUTION_HASH = Uint8Array.from([
    0xdf, 0x3f, 0x61, 0x98, 0x04, 0xa9, 0x2f, 0xdb, 0x40, 0x57, 0x19, 0x2d, 0xc4, 0x3d, 0xd7, 0x48, 0xea, 0x77, 0x8a,
    0xdc, 0x52, 0xbc, 0x49, 0x8c, 0xe8, 0x05, 0x24, 0xc0, 0x14, 0xb8, 0x11, 0x19,
]);

async function channelId(): Promise<string> {
    const [derived] = await getProgramDerivedAddress({
        programAddress: address(PAYMENT_CHANNELS_PROGRAM_ADDRESS),
        seeds: [
            getUtf8Encoder().encode('channel'),
            getAddressEncoder().encode(address(PAYER)),
            getAddressEncoder().encode(address(RECIPIENT)),
            getAddressEncoder().encode(address(LOCALNET_USDC)),
            getAddressEncoder().encode(address(SIGNER)),
            getU64Encoder().encode(7n),
            getU64Encoder().encode(42n),
        ],
    });
    return derived;
}

function encodeChannel(
    deposit: bigint,
    status = 0,
    gracePeriod = 900,
    settlement: { readonly payoutWatermark: bigint; readonly settled: bigint } = {
        payoutWatermark: 0n,
        settled: 0n,
    },
): string {
    const bytes = getChannelEncoder().encode({
        discriminator: 1,
        version: 1,
        bump: 255,
        status,
        salt: 7n,
        deposit,
        settlement,
        closureStartedAt: 0n,
        payerWithdrawnAt: 0n,
        gracePeriod,
        distributionHash: Array.from(EMPTY_DISTRIBUTION_HASH),
        payer: address(PAYER),
        payee: address(RECIPIENT),
        authorizedSigner: address(SIGNER),
        mint: address(LOCALNET_USDC),
        rentPayer: address(OPERATOR),
        openSlot: 42n,
    });
    return getBase64Decoder().decode(bytes);
}

function rpcWithChannel(data: string) {
    return {
        getAccountInfo: (_address: Address) => ({
            send: async () => ({
                value: { data: [data, 'base64'], owner: PAYMENT_CHANNELS_PROGRAM_ADDRESS },
            }),
        }),
        getSignatureStatuses: (signatures: readonly string[]) => ({
            send: async () => ({
                context: { slot: 42 },
                value: signatures.map(() => ({ err: null, confirmationStatus: 'confirmed' })),
            }),
        }),
    };
}

function credential(payload: unknown, requestOverrides: Record<string, unknown> = {}) {
    return {
        challenge: {
            id: 'challenge-id',
            intent: 'session',
            method: 'solana',
            realm: 'api.test',
            request: {
                cap: '10000',
                currency: 'USDC',
                operator: OPERATOR,
                recipient: RECIPIENT,
                ...requestOverrides,
            },
        },
        payload,
    } as never;
}

function parameters(overrides: Record<string, unknown> = {}) {
    return {
        cap: 10_000n,
        currency: 'USDC',
        decimals: 6,
        network: 'localnet',
        operator: OPERATOR,
        pricing: {},
        recipient: RECIPIENT,
        ...overrides,
    } as Parameters<typeof session>[0];
}

describe('session Channel account state binding', () => {
    test('bare push open fails closed when rpc cannot fetch its transaction', async () => {
        const channel = await channelId();
        const store = createMemorySessionStore();
        const method = session(parameters({ rpc: rpcWithChannel(encodeChannel(4_000n)) as never, store }));
        await expect(
            method.verify({
                credential: credential({
                    action: 'open',
                    authorizedSigner: SIGNER,
                    channelId: channel,
                    deposit: '4000',
                    mode: 'push',
                    payer: CLAIMED_PAYER,
                    signature: 'open-signature',
                }),
                request: {} as never,
            }),
        ).rejects.toThrow(/does not expose getTransaction/);
        expect(await store.getChannel(channel)).toBeUndefined();
    });

    test('binds signature-only opens to the challenge incarnation and configured grace period', async () => {
        const channel = await channelId();
        const store = createMemorySessionStore();
        const method = session(
            parameters({
                rpc: rpcWithChannel(encodeChannel(4_000n, 0, 600)) as never,
                settlementWindowSeconds: 600n,
                store,
            }),
        );

        await expect(
            method.verify({
                credential: credential(
                    {
                        action: 'open',
                        authorizedSigner: SIGNER,
                        channelId: channel,
                        deposit: '1000',
                        mode: 'push',
                        recentSlot: '41',
                        signature: 'open-signature',
                    },
                    { recentSlot: '42' },
                ),
                request: {} as never,
            }),
        ).rejects.toThrow(/does not match challenge recentSlot/);

        await expect(
            method.verify({
                credential: credential(
                    {
                        action: 'open',
                        authorizedSigner: SIGNER,
                        channelId: channel,
                        deposit: '1000',
                        mode: 'push',
                        recentSlot: '43',
                        signature: 'open-signature',
                    },
                    { recentSlot: '43' },
                ),
                request: {} as never,
            }),
        ).rejects.toThrow(/does not expose getTransaction/);
    });

    test('topUp rejects a mismatched resulting deposit and non-open status', async () => {
        const channel = await channelId();
        const store = createMemorySessionStore();
        await store.updateChannel(channel, () => ({
            authorizedSigner: SIGNER,
            channelId: channel,
            committedDeliveries: [],
            cumulative: 0n,
            deposit: 1_000n,
            nextDeliverySequence: 0n,
            operator: PAYER,
            pendingDeliveries: [],
            sealed: false,
        }));
        const payload = {
            action: 'topUp',
            channelId: channel,
            newDeposit: '3000',
            signature: 'topup-signature',
        };
        const mismatch = session(parameters({ rpc: rpcWithChannel(encodeChannel(2_000n)) as never, store }));
        await expect(mismatch.verify({ credential: credential(payload), request: {} as never })).rejects.toThrow(
            /on-chain deposit 2000 != expected 3000/,
        );
        expect((await store.getChannel(channel))?.deposit).toBe(1_000n);

        const wrongSigner = session(parameters({ rpc: rpcWithChannel(encodeChannel(3_000n)) as never, store }));
        await store.updateChannel(channel, current => {
            if (!current) throw new Error('missing test channel');
            return { ...current, authorizedSigner: CLAIMED_PAYER };
        });
        await expect(wrongSigner.verify({ credential: credential(payload), request: {} as never })).rejects.toThrow(
            /authorizedSigner/,
        );

        const sealed = session(parameters({ rpc: rpcWithChannel(encodeChannel(3_000n, 1)) as never, store }));
        await expect(sealed.verify({ credential: credential(payload), request: {} as never })).rejects.toThrow(
            /not open on-chain/,
        );
    });

    test('topUp accepts an existing channel with a settlement watermark', async () => {
        const channel = await channelId();
        const store = createMemorySessionStore();
        await store.updateChannel(channel, () => ({
            authorizedSigner: SIGNER,
            channelId: channel,
            committedDeliveries: [],
            cumulative: 0n,
            deposit: 1_000n,
            nextDeliverySequence: 0n,
            operator: PAYER,
            pendingDeliveries: [],
            sealed: false,
        }));
        const method = session(
            parameters({
                rpc: rpcWithChannel(
                    encodeChannel(3_000n, 0, 900, { payoutWatermark: 1_000n, settled: 1_000n }),
                ) as never,
                store,
            }),
        );

        await expect(
            method.verify({
                credential: credential({
                    action: 'topUp',
                    channelId: channel,
                    newDeposit: '3000',
                    signature: 'topup-signature',
                }),
                request: {} as never,
            }),
        ).resolves.toMatchObject({ status: 'success' });
        expect((await store.getChannel(channel))?.deposit).toBe(3_000n);
    });

    test('topUp fails closed without rpc off localnet', async () => {
        const channel = await channelId();
        const store = createMemorySessionStore();
        await store.updateChannel(channel, () => ({
            authorizedSigner: SIGNER,
            channelId: channel,
            committedDeliveries: [],
            cumulative: 0n,
            deposit: 1_000n,
            nextDeliverySequence: 0n,
            operator: PAYER,
            pendingDeliveries: [],
            sealed: false,
        }));
        const durableStore = { ...store, sessionStoreDurability: 'durable-shared' as const };
        const method = session(parameters({ network: 'devnet', store: durableStore, tokenProgram: TOKEN_PROGRAM }));
        await expect(
            method.verify({
                credential: credential({
                    action: 'topUp',
                    channelId: channel,
                    newDeposit: '3000',
                    signature: 'topup-signature',
                }),
                request: {} as never,
            }),
        ).rejects.toThrow(/requires an rpc client/);
    });

    test('rejects processed signatures and malformed Channel accounts', async () => {
        const channel = await channelId();
        const valid = encodeChannel(2_000n);
        const bytes = getBase64Encoder().encode(valid);
        const expected = {
            authorizedSigner: SIGNER,
            mint: LOCALNET_USDC,
            payee: RECIPIENT,
            programId: PAYMENT_CHANNELS_PROGRAM_ADDRESS,
            rentPayer: OPERATOR,
        };
        for (const malformed of [
            Uint8Array.from([9, ...bytes.slice(1)]),
            Uint8Array.from([bytes[0]!, 9, ...bytes.slice(2)]),
            bytes.slice(0, -1),
        ]) {
            await expect(
                verifyChannelAccountState({
                    channelId: channel,
                    expected,
                    rpc: rpcWithChannel(getBase64Decoder().decode(malformed)),
                }),
            ).rejects.toThrow();
        }

        const processedRpc = {
            ...rpcWithChannel(valid),
            getSignatureStatuses: () => ({
                send: async () => ({
                    context: { slot: 42 },
                    value: [{ confirmationStatus: 'processed', err: null }],
                }),
            }),
        };
        const durableStore = {
            ...createMemorySessionStore(),
            sessionStoreDurability: 'durable-shared' as const,
        };
        const method = session(parameters({ network: 'devnet', rpc: processedRpc as never, store: durableStore }));
        await expect(
            method.verify({
                credential: credential({
                    action: 'open',
                    authorizedSigner: SIGNER,
                    channelId: channel,
                    deposit: '1000',
                    mode: 'push',
                    signature: 'processed-signature',
                }),
                request: {} as never,
            }),
        ).rejects.toThrow(/only processed/);
    });

    test.each([
        ['missing context', undefined],
        ['missing slot', {}],
        ['negative slot', { slot: -1 }],
        ['fractional slot', { slot: 1.5 }],
        ['non-numeric slot', { slot: '42' }],
    ])('rejects a confirmed signature with %s', async (_label, context) => {
        const channel = await channelId();
        let accountInfoRequested = false;
        const rpc = {
            ...rpcWithChannel(encodeChannel(1_000n)),
            getAccountInfo: (_address: Address) => ({
                send: async () => {
                    accountInfoRequested = true;
                    return {
                        value: { data: [encodeChannel(1_000n), 'base64'], owner: PAYMENT_CHANNELS_PROGRAM_ADDRESS },
                    };
                },
            }),
            getSignatureStatuses: () => ({
                send: async () => ({
                    context,
                    value: [{ confirmationStatus: 'confirmed', err: null }],
                }),
            }),
        };
        const method = session(parameters({ rpc: rpc as never }));

        await expect(
            method.verify({
                credential: credential({
                    action: 'open',
                    authorizedSigner: SIGNER,
                    channelId: channel,
                    deposit: '1000',
                    mode: 'push',
                    signature: 'confirmed-signature',
                }),
                request: {} as never,
            }),
        ).rejects.toThrow(/confirmation response has an invalid context slot/);
        expect(accountInfoRequested).toBe(false);
    });

    test('rejects an account whose grace period or distribution hash differs from the challenge', async () => {
        const channel = await channelId();
        const expected = {
            authorizedSigner: SIGNER,
            mint: LOCALNET_USDC,
            payee: RECIPIENT,
            programId: PAYMENT_CHANNELS_PROGRAM_ADDRESS,
            rentPayer: OPERATOR,
        };
        const rpc = rpcWithChannel(encodeChannel(2_000n));

        await expect(
            verifyChannelAccountState({
                channelId: channel,
                expected: { ...expected, gracePeriod: 899 },
                rpc,
            }),
        ).rejects.toThrow(/gracePeriod/);
        await expect(
            verifyChannelAccountState({
                channelId: channel,
                expected: { ...expected, splits: [{ bps: 100, recipient: RECIPIENT }] },
                rpc,
            }),
        ).rejects.toThrow(/distributionHash/);
    });

    test('keeps fresh-channel state binding strict about settlement watermarks', async () => {
        const channel = await channelId();
        await expect(
            verifyChannelAccountState({
                channelId: channel,
                expected: {
                    authorizedSigner: SIGNER,
                    mint: LOCALNET_USDC,
                    payee: RECIPIENT,
                    programId: PAYMENT_CHANNELS_PROGRAM_ADDRESS,
                    rentPayer: OPERATOR,
                },
                rpc: rpcWithChannel(encodeChannel(2_000n, 0, 900, { payoutWatermark: 1_000n, settled: 1_000n })),
            }),
        ).rejects.toThrow(/nonzero settlement watermarks/);
    });
});
