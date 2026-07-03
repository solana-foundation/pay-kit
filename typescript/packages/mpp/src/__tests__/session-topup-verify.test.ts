// Regression tests for the session topUp signature-binding fix.
//
// The topUp payload carries only `{channelId, newDeposit, signature}` —
// no transaction bytes — so before the fix the server accepted ANY
// successful signature (an unrelated transfer, someone else's top-up)
// and raised the deposit by whatever `newDeposit` claimed. The server
// must fetch the transaction behind the signature and verify it holds a
// payment-channels top_up instruction bound to this channel, mint,
// token program, (recorded) payer, and the exact deposit delta.

import {
    address,
    appendTransactionMessageInstruction,
    type Blockhash,
    createTransactionMessage,
    generateKeyPairSigner,
    getBase64Codec,
    getBase64EncodedWireTransaction,
    getCompiledTransactionMessageDecoder,
    getCompiledTransactionMessageEncoder,
    getSignatureFromTransaction,
    getTransactionDecoder,
    getTransactionEncoder,
    type KeyPairSigner,
    pipe,
    setTransactionMessageFeePayerSigner,
    setTransactionMessageLifetimeUsingBlockhash,
    signTransactionMessageWithSigners,
} from '@solana/kit';
import { describe, expect, test } from 'vitest';

import { TOKEN_PROGRAM, USDC } from '../constants.js';
import { session } from '../server/Session.js';
import { buildTopUpInstruction, MULTI_DELEGATOR_PROGRAM_ID, verifyTopUpTx } from '../server/session/on-chain.js';
import { createMemorySessionStore } from '../server/session/store.js';

const OPERATOR = '9xAXssX9j7vuK99c7cFwqbixzL3bFrzPy9PUhCtDPAYJ';
const RECIPIENT = '5fKb5cF22cFybZB1H4hLDydFhwoQy9JzKzRWaSbMkB6h';
const CHANNEL_ID = '11111111111111111111111111111111';
const BLOCKHASH = 'EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N' as Blockhash;
// baseParams uses network 'devnet' + currency 'USDC', so the session
// resolves this mint and the classic token program.
const DEVNET_USDC = USDC.devnet!;

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
 * RPC mock backing both calls handleTopUp makes: `getSignatureStatuses`
 * reports every known signature as landed, and `getTransaction` serves
 * the canned base64 transaction the way a real node does under
 * `encoding: 'base64'` (a `[data, 'base64']` tuple).
 */
function mockTxRpc(transactions: Record<string, string>) {
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
 * Open a channel through a no-rpc session sharing `store`, so the bare
 * push-open assertion is skipped and only the top-up path under test
 * touches the mock RPC.
 */
async function openPushChannel(
    store: ReturnType<typeof createMemorySessionStore>,
    signer: KeyPairSigner,
    options: { channelId?: string; deposit?: string; payer?: string } = {},
) {
    const method = session(baseParams({ store }));
    await method.verify({
        credential: makeCred({
            action: 'open',
            authorizedSigner: signer.address,
            channelId: options.channelId ?? CHANNEL_ID,
            deposit: options.deposit ?? '1000',
            mode: 'push',
            ...(options.payer ? { payer: options.payer } : {}),
            signature: 'open-sig',
        }),
        request: {} as never,
    });
}

/** Build and sign a real top_up transaction, returning its wire bytes + signature. */
async function buildTopUpWire(args: {
    amount: bigint;
    channelId?: string;
    mint?: string;
    payer: KeyPairSigner;
    programId?: string;
    tokenProgram?: string;
}) {
    const ix = await buildTopUpInstruction({
        amount: args.amount,
        channelId: args.channelId ?? CHANNEL_ID,
        mint: args.mint ?? DEVNET_USDC,
        payer: args.payer,
        ...(args.programId ? { programId: address(args.programId) } : {}),
        tokenProgram: args.tokenProgram ?? TOKEN_PROGRAM,
    });
    const message = pipe(
        createTransactionMessage({ version: 0 }),
        msg => setTransactionMessageFeePayerSigner(args.payer, msg),
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

describe('session() verify() topUp transaction binding', () => {
    test('accepts a real top-up transaction and raises the deposit', async () => {
        const store = createMemorySessionStore();
        const signer = await generateKeyPairSigner();
        const payer = await generateKeyPairSigner();
        const topUp = await buildTopUpWire({ amount: 1_000n, payer });
        const method = session(baseParams({ rpc: mockTxRpc({ [topUp.signature]: topUp.wire }) as never, store }));
        await openPushChannel(store, signer);

        const receipt = await verifyTopUp(method, '2000', topUp.signature);
        expect(receipt.status).toBe('success');
        expect(receipt.reference).toBe(topUp.signature);
        expect((await store.getChannel(CHANNEL_ID))?.deposit).toBe(2_000n);
    });

    test('rejects an unrelated successful signature (no top_up instruction)', async () => {
        const store = createMemorySessionStore();
        const signer = await generateKeyPairSigner();
        const payer = await generateKeyPairSigner();
        // A confirmed transaction against a different program entirely —
        // pre-fix, its successful signature was enough to raise the deposit.
        const unrelated = await buildTopUpWire({ amount: 1_000n, payer, programId: MULTI_DELEGATOR_PROGRAM_ID });
        const method = session(
            baseParams({ rpc: mockTxRpc({ [unrelated.signature]: unrelated.wire }) as never, store }),
        );
        await openPushChannel(store, signer);

        await expect(verifyTopUp(method, '2000', unrelated.signature)).rejects.toThrow(
            /no payment-channels top_up instruction found/,
        );
        expect((await store.getChannel(CHANNEL_ID))?.deposit).toBe(1_000n);
    });

    test('rejects a top-up bound to a different channel', async () => {
        const store = createMemorySessionStore();
        const signer = await generateKeyPairSigner();
        const payer = await generateKeyPairSigner();
        const otherChannel = await generateKeyPairSigner();
        const topUp = await buildTopUpWire({ amount: 1_000n, channelId: otherChannel.address, payer });
        const method = session(baseParams({ rpc: mockTxRpc({ [topUp.signature]: topUp.wire }) as never, store }));
        await openPushChannel(store, signer);

        await expect(verifyTopUp(method, '2000', topUp.signature)).rejects.toThrow(
            new RegExp(`channel ${otherChannel.address} != expected`),
        );
        expect((await store.getChannel(CHANNEL_ID))?.deposit).toBe(1_000n);
    });

    test('rejects a top-up whose amount does not match the deposit delta', async () => {
        const store = createMemorySessionStore();
        const signer = await generateKeyPairSigner();
        const payer = await generateKeyPairSigner();
        // On-chain deposit grew by 999, but the payload claims 1000 more.
        const topUp = await buildTopUpWire({ amount: 999n, payer });
        const method = session(baseParams({ rpc: mockTxRpc({ [topUp.signature]: topUp.wire }) as never, store }));
        await openPushChannel(store, signer);

        await expect(verifyTopUp(method, '2000', topUp.signature)).rejects.toThrow(
            /top_up amount 999 != expected deposit delta 1000/,
        );
        expect((await store.getChannel(CHANNEL_ID))?.deposit).toBe(1_000n);
    });

    test('rejects a top-up with the wrong mint', async () => {
        const store = createMemorySessionStore();
        const signer = await generateKeyPairSigner();
        const payer = await generateKeyPairSigner();
        const topUp = await buildTopUpWire({ amount: 1_000n, mint: USDC.mainnet!, payer });
        const method = session(baseParams({ rpc: mockTxRpc({ [topUp.signature]: topUp.wire }) as never, store }));
        await openPushChannel(store, signer);

        await expect(verifyTopUp(method, '2000', topUp.signature)).rejects.toThrow(/mint .* != expected/);
    });

    test('rejects a top-up from a different payer when the channel payer is recorded', async () => {
        const store = createMemorySessionStore();
        const signer = await generateKeyPairSigner();
        const channelPayer = await generateKeyPairSigner();
        const stranger = await generateKeyPairSigner();
        const topUp = await buildTopUpWire({ amount: 1_000n, payer: stranger });
        const method = session(baseParams({ rpc: mockTxRpc({ [topUp.signature]: topUp.wire }) as never, store }));
        await openPushChannel(store, signer, { payer: channelPayer.address });

        await expect(verifyTopUp(method, '2000', topUp.signature)).rejects.toThrow(
            new RegExp(`payer ${stranger.address} != channel payer ${channelPayer.address}`),
        );
    });

    test('fails closed when the configured rpc cannot fetch transactions', async () => {
        const store = createMemorySessionStore();
        const signer = await generateKeyPairSigner();
        // Status-only RPC: the liveness check passes but binding is impossible.
        const statusOnlyRpc = {
            getSignatureStatuses: (sigs: readonly string[]) => ({
                send: async () => ({ value: sigs.map(() => ({ err: null })) }),
            }),
        };
        const method = session(baseParams({ rpc: statusOnlyRpc as never, store }));
        await openPushChannel(store, signer);

        await expect(verifyTopUp(method, '2000', 'topup-sig')).rejects.toThrow(/does not expose getTransaction/);
        expect((await store.getChannel(CHANNEL_ID))?.deposit).toBe(1_000n);
    });

    test('without an rpc the top-up payload is trusted (trusted-client mode)', async () => {
        const store = createMemorySessionStore();
        const signer = await generateKeyPairSigner();
        const method = session(baseParams({ store }));
        await openPushChannel(store, signer);

        const receipt = await verifyTopUp(method, '2000', 'any-sig');
        expect(receipt.status).toBe('success');
        expect((await store.getChannel(CHANNEL_ID))?.deposit).toBe(2_000n);
    });
});

// ── verifyTopUpTx unit-level error branches ─────────────────────────────

describe('verifyTopUpTx', () => {
    const EXPECTED = {
        amountDelta: 1_000n,
        channelId: CHANNEL_ID,
        mint: DEVNET_USDC,
        tokenProgram: TOKEN_PROGRAM,
    };

    function rpcReturning(response: unknown) {
        return { getTransaction: () => ({ send: async () => response }) } as never;
    }

    test('rejects a signature with no transaction behind it', async () => {
        await expect(verifyTopUpTx({ expected: EXPECTED, rpc: rpcReturning(null), signature: 'sig' })).rejects.toThrow(
            /tx sig not found on-chain/,
        );
    });

    test('rejects a transaction that failed on-chain', async () => {
        const payer = await generateKeyPairSigner();
        const topUp = await buildTopUpWire({ amount: 1_000n, payer });
        await expect(
            verifyTopUpTx({
                expected: EXPECTED,
                rpc: rpcReturning({
                    meta: { err: { InstructionError: [0, 'Custom'] } },
                    transaction: [topUp.wire, 'base64'],
                }),
                signature: topUp.signature,
            }),
        ).rejects.toThrow(/failed on-chain/);
    });

    test('rejects a non-base64 getTransaction response shape', async () => {
        await expect(
            verifyTopUpTx({
                expected: EXPECTED,
                rpc: rpcReturning({ meta: { err: null }, transaction: { message: {} } }),
                signature: 'sig',
            }),
        ).rejects.toThrow(/unsupported getTransaction encoding/);
    });

    test('rejects a top-up transaction that uses address-lookup tables', async () => {
        const payer = await generateKeyPairSigner();
        const topUp = await buildTopUpWire({ amount: 1_000n, payer });
        const withAlt = injectAddressTableLookup(topUp.wire);
        await expect(
            verifyTopUpTx({
                expected: EXPECTED,
                rpc: rpcReturning({ meta: { err: null }, transaction: [withAlt, 'base64'] }),
                signature: topUp.signature,
            }),
        ).rejects.toThrow(/address-lookup tables are not permitted/);
    });

    test('rejects a top-up instruction with truncated data', async () => {
        const payer = await generateKeyPairSigner();
        const wire = await buildCustomTopUpWire(payer, { data: new Uint8Array([3]) });
        await expect(
            verifyTopUpTx({
                expected: EXPECTED,
                rpc: rpcReturning({ meta: { err: null }, transaction: [wire, 'base64'] }),
                signature: 'sig',
            }),
        ).rejects.toThrow(/top_up instruction data too short/);
    });

    test('rejects a top-up instruction with too few accounts', async () => {
        const payer = await generateKeyPairSigner();
        const wire = await buildCustomTopUpWire(payer, { truncateAccountsTo: 2 });
        await expect(
            verifyTopUpTx({
                expected: EXPECTED,
                rpc: rpcReturning({ meta: { err: null }, transaction: [wire, 'base64'] }),
                signature: 'sig',
            }),
        ).rejects.toThrow(/too few accounts/);
    });

    test('rejects a top-up with the wrong token program', async () => {
        const payer = await generateKeyPairSigner();
        const topUp = await buildTopUpWire({ amount: 1_000n, payer, tokenProgram: MULTI_DELEGATOR_PROGRAM_ID });
        await expect(
            verifyTopUpTx({
                expected: EXPECTED,
                rpc: rpcReturning({ meta: { err: null }, transaction: [topUp.wire, 'base64'] }),
                signature: topUp.signature,
            }),
        ).rejects.toThrow(/tokenProgram .* != expected/);
    });

    test('rejects a non-positive expected deposit delta even when amounts match', async () => {
        const payer = await generateKeyPairSigner();
        const topUp = await buildTopUpWire({ amount: 0n, payer });
        await expect(
            verifyTopUpTx({
                expected: { ...EXPECTED, amountDelta: 0n },
                rpc: rpcReturning({ meta: { err: null }, transaction: [topUp.wire, 'base64'] }),
                signature: topUp.signature,
            }),
        ).rejects.toThrow(/top_up amount 0 != expected deposit delta 0/);
    });
});

// ── helpers ────────────────────────────────────────────────────────────

/**
 * Build a top-up-shaped transaction with a deliberately malformed
 * instruction (truncated data or a short account list) to exercise the
 * verifier's structural guards.
 */
async function buildCustomTopUpWire(
    payer: KeyPairSigner,
    options: { data?: Uint8Array; truncateAccountsTo?: number },
): Promise<string> {
    const ix = await buildTopUpInstruction({
        amount: 1_000n,
        channelId: CHANNEL_ID,
        mint: DEVNET_USDC,
        payer,
        tokenProgram: TOKEN_PROGRAM,
    });
    const mangled = {
        ...ix,
        ...(options.data ? { data: options.data } : {}),
        ...(options.truncateAccountsTo !== undefined
            ? { accounts: ix.accounts.slice(0, options.truncateAccountsTo) }
            : {}),
    };
    const message = pipe(
        createTransactionMessage({ version: 0 }),
        msg => setTransactionMessageFeePayerSigner(payer, msg),
        msg => setTransactionMessageLifetimeUsingBlockhash({ blockhash: BLOCKHASH, lastValidBlockHeight: 0n }, msg),
        msg => appendTransactionMessageInstruction(mangled as never, msg),
    );
    const signed = await signTransactionMessageWithSigners(message);
    return getBase64EncodedWireTransaction(signed) as string;
}

/**
 * Re-encode a base64 transaction with a synthetic, non-empty
 * `addressTableLookups` entry so `verifyTopUpTx` exercises its ALT
 * guard. Mirrors the helper in session-on-chain.test.ts.
 */
function injectAddressTableLookup(transactionBase64: string): string {
    const tx = getTransactionDecoder().decode(getBase64Codec().encode(transactionBase64));
    const message = getCompiledTransactionMessageDecoder().decode(tx.messageBytes) as Record<string, unknown>;
    const withAlt = {
        ...message,
        version: 0,
        addressTableLookups: [
            {
                lookupTableAddress: address('11111111111111111111111111111111'),
                readonlyIndexes: [1],
                writableIndexes: [0],
            },
        ],
    };
    const messageBytes = new Uint8Array(getCompiledTransactionMessageEncoder().encode(withAlt as never));
    const rebuilt = getTransactionEncoder().encode({ ...tx, messageBytes } as never);
    return getBase64Codec().decode(new Uint8Array(rebuilt));
}
