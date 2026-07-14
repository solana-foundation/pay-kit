import {
    createKeyPairSignerFromPrivateKeyBytes,
    getBase64Decoder,
    getBase64Encoder,
    getSignatureFromTransaction,
    getTransactionDecoder,
    type KeyPairSigner,
} from '@solana/kit';
import { describe, expect, test } from 'vitest';

import { buildOpenPaymentChannelTransaction } from '../client/PaymentChannels.js';
import type { SessionRequest } from '../client/Session.js';
import { USDC } from '../constants.js';
import { getChannelEncoder } from '../generated/payment-channels/accounts/channel.js';
import { PAYMENT_CHANNELS_PROGRAM_ADDRESS } from '../generated/payment-channels/programs/paymentChannels.js';
import { session } from '../server/Session.js';
import { createMemorySessionStore } from '../server/session/store.js';

const EMPTY_DISTRIBUTION_HASH = [
    0xdf, 0x3f, 0x61, 0x98, 0x04, 0xa9, 0x2f, 0xdb, 0x40, 0x57, 0x19, 0x2d, 0xc4, 0x3d, 0xd7, 0x48, 0xea, 0x77, 0x8a,
    0xdc, 0x52, 0xbc, 0x49, 0x8c, 0xe8, 0x05, 0x24, 0xc0, 0x14, 0xb8, 0x11, 0x19,
];

function seed(byte: number): Uint8Array {
    const value = new Uint8Array(32);
    value.fill(byte);
    return value;
}

async function loadSigners(): Promise<[KeyPairSigner, KeyPairSigner, KeyPairSigner]> {
    return (await Promise.all([
        createKeyPairSignerFromPrivateKeyBytes(seed(0x21)),
        createKeyPairSignerFromPrivateKeyBytes(seed(0x22)),
        createKeyPairSignerFromPrivateKeyBytes(seed(0x23)),
    ])) as [KeyPairSigner, KeyPairSigner, KeyPairSigner];
}

async function buildOpen(
    payer: KeyPairSigner,
    payee: KeyPairSigner,
    authorizedSigner: KeyPairSigner,
    salt: bigint,
    deposit: bigint,
) {
    const request: SessionRequest = {
        cap: '5000000',
        currency: USDC.mainnet!,
        decimals: 6,
        network: 'localnet',
        operator: payer.address,
        recentBlockhash: 'EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N' as never,
        recentSlot: '4242',
        recipient: payee.address,
    };
    return await buildOpenPaymentChannelTransaction({
        authorizedSigner: authorizedSigner.address,
        deposit,
        gracePeriod: 900,
        programAddress: PAYMENT_CHANNELS_PROGRAM_ADDRESS,
        request,
        salt,
        signer: payer,
    });
}

function encodeChannel(
    open: {
        readonly authorizedSigner: string;
        readonly channelId: string;
        readonly deposit: string;
        readonly mint: string;
        readonly openSlot: string;
        readonly payee: string;
        readonly payer: string;
    },
    deposit = BigInt(open.deposit),
): string {
    const bytes = getChannelEncoder().encode({
        authorizedSigner: open.authorizedSigner as never,
        bump: 255,
        closureStartedAt: 0n,
        deposit,
        discriminator: 1,
        distributionHash: EMPTY_DISTRIBUTION_HASH,
        gracePeriod: 900,
        mint: open.mint as never,
        openSlot: BigInt(open.openSlot),
        payer: open.payer as never,
        payee: open.payee as never,
        payerWithdrawnAt: 0n,
        rentPayer: open.payer as never,
        salt: 7n,
        settlement: { payoutWatermark: 0n, settled: 0n },
        status: 0,
        version: 1,
    });
    return getBase64Decoder().decode(bytes);
}

function makeRpc(wire: string, channelData: string) {
    const calls: string[] = [];
    return {
        calls,
        getAccountInfo: () => ({
            send: async () => {
                calls.push('account');
                return {
                    value: {
                        data: [channelData, 'base64'],
                        owner: PAYMENT_CHANNELS_PROGRAM_ADDRESS,
                    },
                };
            },
        }),
        getSignatureStatuses: (signatures: readonly string[]) => ({
            send: async () => {
                calls.push('status');
                return {
                    context: { slot: 5000 },
                    value: signatures.map(() => ({ confirmationStatus: 'confirmed', err: null })),
                };
            },
        }),
        getTransaction: () => ({
            send: async () => {
                calls.push('transaction');
                return {
                    meta: { err: null, loadedAddresses: { readonly: [], writable: [] } },
                    transaction: [wire, 'base64'],
                } as const;
            },
        }),
    };
}

function openCredential(
    open: Awaited<ReturnType<typeof buildOpen>>,
    payer: KeyPairSigner,
    payee: KeyPairSigner,
    authorizedSigner: KeyPairSigner,
    signature: string,
    deposit = open.deposit,
) {
    return {
        challenge: {
            id: 'signature-only-open',
            intent: 'session',
            method: 'solana',
            realm: 'api.test',
            request: {
                cap: '5000000',
                currency: USDC.mainnet!,
                network: 'localnet',
                operator: payer.address,
                recentSlot: '4242',
                recipient: payee.address,
            },
        },
        payload: {
            action: 'open',
            authorizedSigner: authorizedSigner.address,
            channelId: open.channelId,
            deposit: deposit.toString(),
            mode: 'push',
            recentSlot: '4242',
            signature,
        },
    } as never;
}

async function makeMethod(
    open: Awaited<ReturnType<typeof buildOpen>>,
    payer: KeyPairSigner,
    payee: KeyPairSigner,
    authorizedSigner: KeyPairSigner,
    rpc: ReturnType<typeof makeRpc>,
) {
    return session({
        cap: 5_000_000n,
        currency: USDC.mainnet!,
        decimals: 6,
        network: 'localnet',
        operator: payer.address,
        pricing: {},
        recipient: payee.address,
        rpc: rpc as never,
        store: createMemorySessionStore(),
    });
}

describe('session() signature-only payment-channel opens', () => {
    test('fetches and binds the confirmed transaction before Channel state', async () => {
        const [payer, payee, authorizedSigner] = await loadSigners();
        const open = await buildOpen(payer, payee, authorizedSigner, 7n, 1_000_000n);
        const rpc = makeRpc(
            open.transaction,
            encodeChannel({
                authorizedSigner: authorizedSigner.address,
                channelId: open.channelId,
                deposit: open.deposit,
                mint: open.mint,
                openSlot: open.openSlot,
                payee: payee.address,
                payer: payer.address,
            }),
        );
        const method = await makeMethod(open, payer, payee, authorizedSigner, rpc);

        const receipt = await method.verify({
            credential: openCredential(
                open,
                payer,
                payee,
                authorizedSigner,
                getSignatureFromTransaction(
                    getTransactionDecoder().decode(getBase64Encoder().encode(open.transaction)),
                ),
            ),
            request: {} as never,
        });

        expect(receipt.status).toBe('success');
        expect(rpc.calls.indexOf('transaction')).toBeLessThan(rpc.calls.indexOf('account'));
    });

    test('rejects a confirmed unrelated open before reading Channel state', async () => {
        const [payer, payee, authorizedSigner] = await loadSigners();
        const open = await buildOpen(payer, payee, authorizedSigner, 7n, 1_000_000n);
        const unrelated = await buildOpen(payer, payee, authorizedSigner, 8n, 1_000_000n);
        const unrelatedSignature = getSignatureFromTransaction(
            getTransactionDecoder().decode(getBase64Encoder().encode(unrelated.transaction)),
        );
        const rpc = makeRpc(
            unrelated.transaction,
            encodeChannel({
                authorizedSigner: authorizedSigner.address,
                channelId: open.channelId,
                deposit: open.deposit,
                mint: open.mint,
                openSlot: open.openSlot,
                payee: payee.address,
                payer: payer.address,
            }),
        );
        const method = await makeMethod(open, payer, payee, authorizedSigner, rpc);

        await expect(
            method.verify({
                credential: openCredential(open, payer, payee, authorizedSigner, unrelatedSignature),
                request: {} as never,
            }),
        ).rejects.toThrow(/open channel/);
        expect(rpc.calls).not.toContain('account');
    });

    test('rejects an asserted deposit that differs from authoritative Channel.deposit', async () => {
        const [payer, payee, authorizedSigner] = await loadSigners();
        const open = await buildOpen(payer, payee, authorizedSigner, 7n, 1_000_000n);
        const rpc = makeRpc(
            open.transaction,
            encodeChannel(
                {
                    authorizedSigner: authorizedSigner.address,
                    channelId: open.channelId,
                    deposit: open.deposit,
                    mint: open.mint,
                    openSlot: open.openSlot,
                    payee: payee.address,
                    payer: payer.address,
                },
                900_000n,
            ),
        );
        const method = await makeMethod(open, payer, payee, authorizedSigner, rpc);
        const signature = getSignatureFromTransaction(
            getTransactionDecoder().decode(getBase64Encoder().encode(open.transaction)),
        );

        await expect(
            method.verify({
                credential: openCredential(open, payer, payee, authorizedSigner, signature),
                request: {} as never,
            }),
        ).rejects.toThrow(/on-chain deposit 900000 != expected 1000000/);
    });
});
