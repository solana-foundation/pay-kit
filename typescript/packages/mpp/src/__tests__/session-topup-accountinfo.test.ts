// Regression tests for the session topUp account-info-capable-RPC requirement.
//
// The authoritative on-chain Channel account bind (verifyChannelAccountState)
// is what catches a racing top-up: a top_up instruction can carry the right
// +delta while the on-chain account never actually reached `newDeposit`. When
// the configured rpc exposes getTransaction but NOT getAccountInfo, the server
// must NOT silently degrade to the delta-only instruction check — it must
// reject the deposit raise, exactly like the getTransaction capability gate
// throws hard rather than trusting a liveness-only signature.
//
// Trusted-client mode (no rpc at all) is unaffected: with no rpc the payload
// is trusted as-is, matching open verification with rpc unset.

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
import { buildTopUpInstruction } from '../server/session/on-chain.js';
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
 * RPC mock exposing getSignatureStatuses + getTransaction but deliberately
 * NOT getAccountInfo — so the instruction-level delta check can run but the
 * authoritative on-chain account bind cannot. Pre-fix, this silently degraded
 * to the delta-only path; the fix must reject the deposit raise instead.
 */
function mockTxOnlyRpc(transactions: Record<string, string>) {
    return {
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

/**
 * Full RPC mock exposing getSignatureStatuses + getTransaction AND
 * getAccountInfo (the account-state bind). `accounts` maps a channel address
 * to its base64-encoded account (with owner), or to `null` for not-found.
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

/**
 * Open a channel through a no-rpc trusted session sharing `store`, so only
 * the top-up path under test touches the mock RPC. Records the channel payer
 * so the top-up's payer bind and the account-state payer field both line up.
 */
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

/** Build and sign a real top_up transaction, returning its wire bytes + signature. */
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

async function verifyTopUp(method: ReturnType<typeof session>, newDeposit: string, signature: string) {
    return await method.verify({
        credential: makeCred({ action: 'topUp', channelId: CHANNEL_ID, newDeposit, signature }),
        request: {} as never,
    });
}

describe('session() verify() topUp requires an account-info-capable rpc', () => {
    test('rejects a top-up when the rpc exposes getTransaction but not getAccountInfo', async () => {
        const store = createMemorySessionStore();
        const signer = await generateKeyPairSigner();
        const payer = await generateKeyPairSigner();
        await openTrusted(store, signer, payer.address, '1000');
        // A real, well-formed top_up tx with the exact +1000 delta: the
        // instruction-level bind (verifyTopUpTx) passes. Only the authoritative
        // account-state bind is missing because the rpc lacks getAccountInfo —
        // pre-fix, the deposit was silently raised via the delta-only path.
        const topUp = await buildTopUpWire(payer, 1_000n);
        const method = session(baseParams({ rpc: mockTxOnlyRpc({ [topUp.signature]: topUp.wire }) as never, store }));

        await expect(verifyTopUp(method, '2000', topUp.signature)).rejects.toThrow(/does not expose getAccountInfo/);
        // The deposit must remain unchanged — the raise was rejected, not applied.
        expect((await store.getChannel(CHANNEL_ID))?.deposit).toBe(1_000n);
    });

    test('still accepts a top-up when the rpc can bind the on-chain Channel account', async () => {
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

        const receipt = await verifyTopUp(method, '2000', topUp.signature);
        expect(receipt.status).toBe('success');
        expect((await store.getChannel(CHANNEL_ID))?.deposit).toBe(2_000n);
    });

    test('trusted-client mode (no rpc) still raises the deposit without on-chain binding', async () => {
        const store = createMemorySessionStore();
        const signer = await generateKeyPairSigner();
        const payer = await generateKeyPairSigner();
        await openTrusted(store, signer, payer.address, '1000');
        const method = session(baseParams({ store }));

        const receipt = await verifyTopUp(method, '2000', 'any-sig');
        expect(receipt.status).toBe('success');
        expect((await store.getChannel(CHANNEL_ID))?.deposit).toBe(2_000n);
    });
});
