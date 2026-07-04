// Regression tests for the on-chain Channel account-state binding.
//
// The instruction-level binding (verifyOpenTx / verifyTopUpTx) proves the
// transaction *contained* a valid open/top_up. This layer proves the
// resulting on-chain Channel *account* matches — decoding it and asserting
// payee/mint/authorizedSigner/deposit and program ownership. It catches a
// deposit that diverges from the asserted amount (e.g. a racing top-up) and
// a look-alike account crafted under a different program.

import {
    address,
    type Address,
    appendTransactionMessageInstruction,
    type Blockhash,
    createTransactionMessage,
    generateKeyPairSigner,
    getBase64Decoder,
    getBase64EncodedWireTransaction,
    getSignatureFromTransaction,
    type KeyPairSigner,
    pipe,
    setTransactionMessageFeePayerSigner,
    setTransactionMessageLifetimeUsingBlockhash,
    signTransactionMessageWithSigners,
} from '@solana/kit';
import { describe, expect, test } from 'vitest';

import { getChannelEncoder } from '../generated/payment-channels/accounts/channel.js';
import { PAYMENT_CHANNELS_PROGRAM_ADDRESS } from '../generated/payment-channels/programs/paymentChannels.js';
import { TOKEN_PROGRAM, USDC } from '../constants.js';
import { session } from '../server/Session.js';
import { buildTopUpInstruction, verifyChannelAccountState } from '../server/session/on-chain.js';
import { createMemorySessionStore } from '../server/session/store.js';

const OPERATOR = '9xAXssX9j7vuK99c7cFwqbixzL3bFrzPy9PUhCtDPAYJ';
const RECIPIENT = '5fKb5cF22cFybZB1H4hLDydFhwoQy9JzKzRWaSbMkB6h';
const CHANNEL_ID = '11111111111111111111111111111111';
const BLOCKHASH = 'EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N' as Blockhash;
const DEVNET_USDC = USDC.devnet!;
const PROGRAM = PAYMENT_CHANNELS_PROGRAM_ADDRESS as string;

/** Encode a Channel account to base64 with the given field overrides. */
function encodeChannel(fields: {
    authorizedSigner: string;
    deposit: bigint;
    mint: string;
    payee: string;
    payer: string;
}): string {
    const bytes = getChannelEncoder().encode({
        discriminator: 0,
        version: 1,
        bump: 255,
        status: 0,
        salt: 7n,
        deposit: fields.deposit,
        settlement: { settled: 0n, payoutWatermark: 0n },
        closureStartedAt: 0n,
        payerWithdrawnAt: 0n,
        gracePeriod: 900,
        distributionHash: new Array(32).fill(0),
        payer: address(fields.payer),
        payee: address(fields.payee),
        authorizedSigner: address(fields.authorizedSigner),
        mint: address(fields.mint),
        rentPayer: address(OPERATOR),
    });
    return getBase64Decoder().decode(bytes);
}

/**
 * RPC mock exposing getSignatureStatuses + getTransaction (instruction
 * binding) AND getAccountInfo (account-state binding). `accounts` maps a
 * channel address to its base64-encoded account (with owner), or to `null`
 * for a not-found account.
 */
function mockFullRpc(
    transactions: Record<string, string>,
    accounts: Record<string, { data: string; owner?: string } | null>,
) {
    return {
        getAccountInfo: (addr: Address) => ({
            send: async () => {
                const acct = accounts[addr as string];
                if (acct === undefined || acct === null) return { value: null };
                return { value: { data: [acct.data, 'base64'], owner: acct.owner ?? PROGRAM } };
            },
        }),
        getSignatureStatuses: (sigs: readonly string[]) => ({
            send: async () => ({ value: sigs.map(sig => (transactions[sig] !== undefined ? { err: null } : null)) }),
        }),
        getTransaction: (sig: string) => ({
            send: async () => {
                const tx = transactions[sig];
                if (tx === undefined) return null;
                return { meta: { err: null }, transaction: [tx, 'base64'] };
            },
        }),
    };
}

function makeCred<P>(payload: P) {
    return {
        challenge: {
            id: 'challenge-id-123',
            intent: 'session',
            method: 'solana',
            realm: 'api.test',
            request: { cap: '1000000', currency: 'USDC', operator: OPERATOR, recipient: RECIPIENT },
        },
        payload,
    } as unknown as Parameters<NonNullable<ReturnType<typeof session>['verify']>>[0]['credential'];
}

function baseParams(overrides: Record<string, unknown> = {}) {
    return {
        cap: 5_000_000n,
        currency: 'USDC',
        decimals: 6,
        network: 'devnet',
        operator: OPERATOR,
        pricing: {},
        recipient: RECIPIENT,
        ...overrides,
    } as Parameters<typeof session>[0];
}

async function openTrusted(
    store: ReturnType<typeof createMemorySessionStore>,
    signer: KeyPairSigner,
    payer: string,
    deposit = '1000',
) {
    const method = session(baseParams({ store, trustedClientOpen: true }));
    await method.verify({
        credential: makeCred({
            action: 'open',
            authorizedSigner: signer.address,
            channelId: CHANNEL_ID,
            deposit,
            mode: 'push',
            payer,
            signature: 'open-sig',
        }),
        request: {} as never,
    });
}

async function buildTopUpWire(payer: KeyPairSigner, amount: bigint) {
    const ix = await buildTopUpInstruction({
        amount,
        channelId: CHANNEL_ID,
        mint: DEVNET_USDC,
        payer,
        tokenProgram: TOKEN_PROGRAM,
    });
    const message = pipe(
        createTransactionMessage({ version: 0 }),
        msg => setTransactionMessageFeePayerSigner(payer, msg),
        msg => setTransactionMessageLifetimeUsingBlockhash({ blockhash: BLOCKHASH, lastValidBlockHeight: 0n }, msg),
        msg => appendTransactionMessageInstruction(ix, msg),
    );
    const signed = await signTransactionMessageWithSigners(message);
    return {
        signature: getSignatureFromTransaction(signed) as string,
        wire: getBase64EncodedWireTransaction(signed) as string,
    };
}

describe('session() verify() topUp on-chain account-state binding', () => {
    test('accepts a top-up whose on-chain deposit reached newDeposit', async () => {
        const store = createMemorySessionStore();
        const signer = await generateKeyPairSigner();
        const payer = await generateKeyPairSigner();
        await openTrusted(store, signer, payer.address, '1000');
        const topUp = await buildTopUpWire(payer, 1_000n);
        const channel = encodeChannel({
            authorizedSigner: signer.address,
            deposit: 2_000n,
            mint: DEVNET_USDC,
            payee: RECIPIENT,
            payer: payer.address,
        });
        const method = session(
            baseParams({
                rpc: mockFullRpc({ [topUp.signature]: topUp.wire }, { [CHANNEL_ID]: { data: channel } }) as never,
                store,
            }),
        );

        const receipt = await method.verify({
            credential: makeCred({
                action: 'topUp',
                channelId: CHANNEL_ID,
                newDeposit: '2000',
                signature: topUp.signature,
            }),
            request: {} as never,
        });
        expect(receipt.status).toBe('success');
        expect((await store.getChannel(CHANNEL_ID))?.deposit).toBe(2_000n);
    });

    test('rejects a top-up whose on-chain deposit did NOT reach newDeposit (racing top-up)', async () => {
        const store = createMemorySessionStore();
        const signer = await generateKeyPairSigner();
        const payer = await generateKeyPairSigner();
        await openTrusted(store, signer, payer.address, '1000');
        // The top_up instruction carries the right +1000 delta, but the
        // on-chain account only shows 1500 (someone else raced a partial state).
        const topUp = await buildTopUpWire(payer, 1_000n);
        const channel = encodeChannel({
            authorizedSigner: signer.address,
            deposit: 1_500n,
            mint: DEVNET_USDC,
            payee: RECIPIENT,
            payer: payer.address,
        });
        const method = session(
            baseParams({
                rpc: mockFullRpc({ [topUp.signature]: topUp.wire }, { [CHANNEL_ID]: { data: channel } }) as never,
                store,
            }),
        );

        await expect(
            method.verify({
                credential: makeCred({
                    action: 'topUp',
                    channelId: CHANNEL_ID,
                    newDeposit: '2000',
                    signature: topUp.signature,
                }),
                request: {} as never,
            }),
        ).rejects.toThrow(/on-chain deposit 1500 != expected 2000/);
        expect((await store.getChannel(CHANNEL_ID))?.deposit).toBe(1_000n);
    });

    test('rejects a channel account owned by a different program', async () => {
        const store = createMemorySessionStore();
        const signer = await generateKeyPairSigner();
        const payer = await generateKeyPairSigner();
        await openTrusted(store, signer, payer.address, '1000');
        const topUp = await buildTopUpWire(payer, 1_000n);
        const channel = encodeChannel({
            authorizedSigner: signer.address,
            deposit: 2_000n,
            mint: DEVNET_USDC,
            payee: RECIPIENT,
            payer: payer.address,
        });
        const method = session(
            baseParams({
                rpc: mockFullRpc(
                    { [topUp.signature]: topUp.wire },
                    { [CHANNEL_ID]: { data: channel, owner: TOKEN_PROGRAM } },
                ) as never,
                store,
            }),
        );

        await expect(
            method.verify({
                credential: makeCred({
                    action: 'topUp',
                    channelId: CHANNEL_ID,
                    newDeposit: '2000',
                    signature: topUp.signature,
                }),
                request: {} as never,
            }),
        ).rejects.toThrow(/owned by .* != payment-channels program/);
    });

    test('rejects when the channel account does not exist on-chain', async () => {
        const store = createMemorySessionStore();
        const signer = await generateKeyPairSigner();
        const payer = await generateKeyPairSigner();
        await openTrusted(store, signer, payer.address, '1000');
        const topUp = await buildTopUpWire(payer, 1_000n);
        const method = session(
            baseParams({
                rpc: mockFullRpc({ [topUp.signature]: topUp.wire }, { [CHANNEL_ID]: null }) as never,
                store,
            }),
        );

        await expect(
            method.verify({
                credential: makeCred({
                    action: 'topUp',
                    channelId: CHANNEL_ID,
                    newDeposit: '2000',
                    signature: topUp.signature,
                }),
                request: {} as never,
            }),
        ).rejects.toThrow(/channel .* not found on-chain/);
    });
});

describe('verifyChannelAccountState unit checks', () => {
    const EXPECTED = {
        authorizedSigner: OPERATOR,
        deposit: 2_000n,
        mint: DEVNET_USDC,
        payee: RECIPIENT,
        payer: RECIPIENT,
    };
    function rpcWith(acct: { data: string; owner?: string } | null) {
        return {
            getAccountInfo: () => ({
                send: async () =>
                    acct === null
                        ? { value: null }
                        : { value: { data: [acct.data, 'base64'], owner: acct.owner ?? PROGRAM } },
            }),
        } as never;
    }

    test('rejects a mismatched payee', async () => {
        const channel = encodeChannel({
            authorizedSigner: OPERATOR,
            deposit: 2_000n,
            mint: DEVNET_USDC,
            payee: OPERATOR, // wrong
            payer: RECIPIENT,
        });
        await expect(
            verifyChannelAccountState({ channelId: CHANNEL_ID, expected: EXPECTED, rpc: rpcWith({ data: channel }) }),
        ).rejects.toThrow(/on-chain payee .* != expected/);
    });

    test('rejects a mismatched mint', async () => {
        const channel = encodeChannel({
            authorizedSigner: OPERATOR,
            deposit: 2_000n,
            mint: USDC.mainnet!, // wrong
            payee: RECIPIENT,
            payer: RECIPIENT,
        });
        await expect(
            verifyChannelAccountState({ channelId: CHANNEL_ID, expected: EXPECTED, rpc: rpcWith({ data: channel }) }),
        ).rejects.toThrow(/on-chain mint .* != expected/);
    });

    test('rejects a mismatched authorizedSigner', async () => {
        const channel = encodeChannel({
            authorizedSigner: RECIPIENT, // wrong
            deposit: 2_000n,
            mint: DEVNET_USDC,
            payee: RECIPIENT,
            payer: RECIPIENT,
        });
        await expect(
            verifyChannelAccountState({ channelId: CHANNEL_ID, expected: EXPECTED, rpc: rpcWith({ data: channel }) }),
        ).rejects.toThrow(/on-chain authorizedSigner .* != expected/);
    });

    test('rejects a non-base64 account encoding', async () => {
        await expect(
            verifyChannelAccountState({
                channelId: CHANNEL_ID,
                expected: EXPECTED,
                rpc: {
                    getAccountInfo: () => ({ send: async () => ({ value: { data: { parsed: {} }, owner: PROGRAM } }) }),
                } as never,
            }),
        ).rejects.toThrow(/unsupported getAccountInfo encoding/);
    });
});
