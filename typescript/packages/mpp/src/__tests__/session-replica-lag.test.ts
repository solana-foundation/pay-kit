/**
 * Replica-lag tolerance for the account reads that follow a confirmed
 * transaction.
 *
 * An RPC provider can serve transaction status and account state from
 * different replicas, so an account a just-confirmed transaction created or
 * mutated can briefly read back missing or stale. Each site below re-reads
 * on exactly one not-yet-visible signal and on nothing else:
 *
 *   - `readUntilVisible` itself: the linear 200/400/600/800/1000ms schedule,
 *     no sleep after the final attempt, non-positive config falling back to
 *     the defaults, and a throwing read never being retried.
 *   - `submitOpenTx` (both the happy path and the broadcast-failure
 *     retry-idempotency branch): only an absent channel account is re-read,
 *     and an exhausted broadcast-failure branch still rethrows the ORIGINAL
 *     broadcast error.
 *   - `submitTopUpTx`: only an absent account is re-read. A visible account
 *     with a stale deposit is rejected on the spot, because deposit only
 *     grows and a concurrent top-up could otherwise clear the threshold.
 *   - `fetchSubscriptionDelegation`: only an absent delegation is re-read.
 *
 * Integration legs inject a 1ms backoff step so the suite never sleeps for
 * real seconds; the schedule itself is asserted against a captured
 * `setTimeout`.
 */
import { address, generateKeyPairSigner, getBase64Codec, type KeyPairSigner, type Signature } from '@solana/kit';
import { describe, expect, test, vi } from 'vitest';

import { buildOpenPaymentChannelTransaction } from '../client/PaymentChannels.js';
import type { SessionRequest } from '../client/Session.js';
import { getChannelEncoder } from '../generated/payment-channels/accounts/channel.js';
import { ChannelStatus } from '../generated/payment-channels/types/channelStatus.js';
import {
    buildTopUpInstruction,
    PAYMENT_CHANNELS_PROGRAM_ID,
    submitOpenTx,
    submitTopUpTx,
    type VerifyOpenTxExpected,
} from '../server/session/on-chain.js';
import { buildAndSignWireTransaction } from '../server/session/wire-tx.js';
import { __testing } from '../server/Subscription.js';
import type { OpenPayload } from '../shared/session-types.js';
import { readUntilVisible } from '../utils/account-read.js';

const TOKEN_PROGRAM = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA';
// resolveStablecoinMint('USDC', 'devnet')
const USDC_DEVNET_MINT = '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU';
const CHALLENGED_BLOCKHASH = 'EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N';
const CHALLENGED_SLOT = 314n;
const OPEN_SIGNATURE = 'OpenSig1111111111111111111111111111111111111111111111111111111' as Signature;
/** Injected step keeps the whole retry budget under 15ms of real time. */
const FAST_BACKOFF = { channelReadBackoffStepMs: 1 } as const;

// ── readUntilVisible ────────────────────────────────────────────────────

/**
 * Run `work` with `setTimeout` replaced by a recorder that fires its
 * callback immediately, so the backoff schedule is observable without
 * sleeping.
 */
async function captureSleeps(work: () => Promise<unknown>): Promise<number[]> {
    const delays: number[] = [];
    const spy = vi.spyOn(globalThis, 'setTimeout').mockImplementation(((callback: () => void, ms?: number) => {
        delays.push(ms ?? 0);
        callback();
        return 0;
    }) as never);
    try {
        await work();
    } finally {
        spy.mockRestore();
    }
    return delays;
}

describe('readUntilVisible', () => {
    test('reads 6 times on a 200/400/600/800/1000ms linear schedule with no trailing sleep', async () => {
        let reads = 0;
        const delays = await captureSleeps(() =>
            readUntilVisible(
                () => {
                    reads += 1;
                    return Promise.resolve('missing');
                },
                value => value !== 'missing',
                {},
            ),
        );

        expect(reads).toBe(6);
        expect(delays).toEqual([200, 400, 600, 800, 1_000]);
        // 3.0s total, 1s longest single wait.
        expect(delays.reduce((sum, ms) => sum + ms, 0)).toBe(3_000);
    });

    test('stops at the first visible read', async () => {
        let reads = 0;
        const delays = await captureSleeps(() =>
            readUntilVisible(
                () => {
                    reads += 1;
                    return Promise.resolve(reads);
                },
                value => value >= 2,
                {},
            ),
        );

        expect(reads).toBe(2);
        expect(delays).toEqual([200]);
    });

    test('non-positive config resolves to the defaults', async () => {
        let reads = 0;
        const delays = await captureSleeps(() =>
            readUntilVisible(
                () => {
                    reads += 1;
                    return Promise.resolve('missing');
                },
                value => value !== 'missing',
                { channelReadBackoffStepMs: 0, channelReadMaxAttempts: 0 },
            ),
        );

        expect(reads).toBe(6);
        expect(delays).toEqual([200, 400, 600, 800, 1_000]);
    });

    test('honors explicit positive overrides', async () => {
        let reads = 0;
        const delays = await captureSleeps(() =>
            readUntilVisible(
                () => {
                    reads += 1;
                    return Promise.resolve('missing');
                },
                value => value !== 'missing',
                { channelReadBackoffStepMs: 50, channelReadMaxAttempts: 3 },
            ),
        );

        expect(reads).toBe(3);
        expect(delays).toEqual([50, 100]);
    });

    test('an RPC transport error is never retried', async () => {
        let reads = 0;
        await expect(
            readUntilVisible(
                () => {
                    reads += 1;
                    return Promise.reject(new Error('socket hang up'));
                },
                () => true,
                {},
            ),
        ).rejects.toThrow(/socket hang up/);
        expect(reads).toBe(1);
    });
});

// ── shared on-chain fixtures ────────────────────────────────────────────

interface ChannelAccountFacts {
    readonly authorizedSigner: string;
    readonly deposit: bigint;
    readonly mint: string;
    readonly payee: string;
    readonly payer: string;
    readonly rentPayer: string;
    readonly status?: number;
}

function channelAccountData(facts: ChannelAccountFacts): string {
    const data = getChannelEncoder().encode({
        authorizedSigner: address(facts.authorizedSigner),
        bump: 255,
        closureStartedAt: 0n,
        deposit: facts.deposit,
        discriminator: 1,
        distributionHash: new Array<number>(32).fill(0),
        gracePeriod: 900,
        mint: address(facts.mint),
        openSlot: CHALLENGED_SLOT,
        payee: address(facts.payee),
        payer: address(facts.payer),
        payerWithdrawnAt: 0n,
        rentPayer: address(facts.rentPayer),
        salt: 7n,
        settlement: { payoutWatermark: 0n, settled: 0n },
        status: facts.status ?? Number(ChannelStatus.Open),
        version: 1,
    });
    return getBase64Codec().decode(data as Uint8Array);
}

/**
 * RPC mock whose `getAccountInfo` walks `accountSequence` (a `null` entry is
 * an absent account) and sticks on the last entry, so a test can spell out
 * "missing, then present" and count the reads it took.
 */
function sequencedRpc(accountSequence: readonly (string | null)[], sendError?: Error) {
    const accountLookups: string[] = [];
    const sends: string[] = [];
    return {
        accountLookups,
        getAccountInfo: (accountAddress: string) => ({
            send: () => {
                const index = Math.min(accountLookups.length, accountSequence.length - 1);
                accountLookups.push(accountAddress);
                const data = accountSequence[index] ?? null;
                return Promise.resolve({
                    context: { slot: 1n },
                    value:
                        data === null
                            ? null
                            : {
                                  data: [data, 'base64'],
                                  executable: false,
                                  lamports: 1_000_000n,
                                  owner: PAYMENT_CHANNELS_PROGRAM_ID.toString(),
                                  rentEpoch: 0n,
                                  space: BigInt(getBase64Codec().encode(data).byteLength),
                              },
                });
            },
        }),
        getLatestBlockhash: () => ({
            send: () =>
                Promise.resolve({
                    context: { slot: CHALLENGED_SLOT },
                    value: { blockhash: CHALLENGED_BLOCKHASH, lastValidBlockHeight: 100n },
                }),
        }),
        getSignatureStatuses: () => ({
            send: () => Promise.resolve({ value: [{ confirmationStatus: 'confirmed', err: null }] }),
        }),
        sendTransaction: (wire: string) => ({
            send: () => {
                if (sendError) return Promise.reject(sendError);
                sends.push(wire);
                return Promise.resolve(OPEN_SIGNATURE);
            },
        }),
        sends,
    };
}

async function verifiedOpenFixture() {
    const payer = await generateKeyPairSigner();
    const sessionSigner = await generateKeyPairSigner();
    const payee = await generateKeyPairSigner();
    const request = {
        amount: '100',
        currency: 'USDC',
        methodDetails: {
            channelProgram: PAYMENT_CHANNELS_PROGRAM_ID.toString(),
            gracePeriodSeconds: 900,
            network: 'devnet',
            recentBlockhash: CHALLENGED_BLOCKHASH,
            recentSlot: CHALLENGED_SLOT.toString(),
            tokenProgram: TOKEN_PROGRAM,
        },
        recipient: payee.address,
        suggestedDeposit: '5000',
    } as unknown as SessionRequest;
    const open = await buildOpenPaymentChannelTransaction({
        authorizedSigner: sessionSigner.address,
        request,
        salt: 7n,
        signer: payer,
    });
    const openPayload: OpenPayload = {
        authorizedSigner: sessionSigner.address,
        channelId: open.channelId,
        depositAmount: open.deposit,
        gracePeriodSeconds: open.gracePeriod,
        mint: open.mint,
        openSlot: open.openSlot,
        payee: open.payee,
        payer: open.payer,
        salt: open.salt,
        transaction: open.transaction,
    };
    const expected: VerifyOpenTxExpected = {
        authorizedSigner: sessionSigner.address,
        channelProgram: PAYMENT_CHANNELS_PROGRAM_ID.toString(),
        currency: 'USDC',
        feePayer: payer.address,
        network: 'devnet',
        openSlot: CHALLENGED_SLOT,
        recentBlockhash: CHALLENGED_BLOCKHASH,
        recipient: open.payee,
        rentPayer: payer.address,
        splits: [],
        tokenProgram: TOKEN_PROGRAM,
    };
    const confirmed = channelAccountData({
        authorizedSigner: sessionSigner.address,
        deposit: 5_000n,
        mint: USDC_DEVNET_MINT,
        payee: open.payee,
        payer: payer.address,
        rentPayer: payer.address,
    });
    return { confirmed, expected, open, openPayload, payer, sessionSigner };
}

// ── submitOpenTx: the confirmed-channel re-read ─────────────────────────

describe('submitOpenTx post-confirm channel read', () => {
    test('re-reads a channel that is not visible yet on the first read', async () => {
        const { confirmed, expected, open, openPayload } = await verifiedOpenFixture();
        const rpc = sequencedRpc([null, null, confirmed]);

        const result = await submitOpenTx({
            channelRead: FAST_BACKOFF,
            confirm: { pollIntervalMs: 1, timeoutMs: 2_000 },
            expected,
            openPayload,
            rpc: rpc as never,
        });

        expect(result.channelId).toBe(open.channelId);
        expect(rpc.accountLookups).toHaveLength(3);
    });

    test('a visible channel with a mismatched field is rejected on the first read', async () => {
        const { expected, open, openPayload, payer, sessionSigner } = await verifiedOpenFixture();
        // Deposit 4_000 against a verified 5_000: visible and wrong, which is
        // never a lag artifact and must not buy a single extra read.
        const rpc = sequencedRpc([
            channelAccountData({
                authorizedSigner: sessionSigner.address,
                deposit: 4_000n,
                mint: USDC_DEVNET_MINT,
                payee: open.payee,
                payer: payer.address,
                rentPayer: payer.address,
            }),
        ]);

        await expect(
            submitOpenTx({
                channelRead: FAST_BACKOFF,
                confirm: { pollIntervalMs: 1, timeoutMs: 2_000 },
                expected,
                openPayload,
                rpc: rpc as never,
            }),
        ).rejects.toThrow(/does not match the verified open transaction/);
        expect(rpc.accountLookups).toHaveLength(1);
    });

    test('a preflight-rejected duplicate is rescued once the landed channel becomes visible', async () => {
        // The money-losing case: the first submission landed and the escrow
        // is funded, the retry dies at preflight, and one unlucky read used
        // to turn a funded channel into a hard failure.
        const { confirmed, expected, open, openPayload } = await verifiedOpenFixture();
        const rpc = sequencedRpc(
            [null, confirmed],
            new Error('Transaction simulation failed: This transaction has already been processed'),
        );

        const result = await submitOpenTx({
            channelRead: FAST_BACKOFF,
            confirm: { pollIntervalMs: 1, timeoutMs: 2_000 },
            expected,
            openPayload,
            rpc: rpc as never,
        });

        expect(result.channelId).toBe(open.channelId);
        expect(rpc.accountLookups).toHaveLength(2);
    });

    test('an exhausted retry on the broadcast-failure branch rethrows the original broadcast error', async () => {
        const { expected, openPayload } = await verifiedOpenFixture();
        const rpc = sequencedRpc(
            [null],
            new Error('Transaction simulation failed: This transaction has already been processed'),
        );

        await expect(
            submitOpenTx({
                channelRead: FAST_BACKOFF,
                confirm: { pollIntervalMs: 1, timeoutMs: 2_000 },
                expected,
                openPayload,
                rpc: rpc as never,
            }),
        ).rejects.toThrow(/already been processed/);
        expect(rpc.accountLookups).toHaveLength(6);
    });
});

// ── submitTopUpTx: the confirmed-deposit re-read ────────────────────────

interface TopUpFixture {
    readonly channel: KeyPairSigner;
    readonly merchant: KeyPairSigner;
    readonly payer: KeyPairSigner;
    readonly sessionSigner: KeyPairSigner;
}

async function topUpFixture(): Promise<TopUpFixture> {
    return {
        channel: await generateKeyPairSigner(),
        merchant: await generateKeyPairSigner(),
        payer: await generateKeyPairSigner(),
        sessionSigner: await generateKeyPairSigner(),
    };
}

function topUpChannelData(f: TopUpFixture, deposit: bigint, status?: number): string {
    return channelAccountData({
        authorizedSigner: f.sessionSigner.address,
        deposit,
        mint: USDC_DEVNET_MINT,
        payee: f.merchant.address,
        payer: f.payer.address,
        rentPayer: f.payer.address,
        ...(status === undefined ? {} : { status }),
    });
}

async function topUpWire(f: TopUpFixture, rpc: unknown, amount: bigint): Promise<string> {
    const instruction = await buildTopUpInstruction({
        amount,
        channelId: f.channel.address,
        mint: USDC_DEVNET_MINT,
        payer: f.payer,
        tokenProgram: TOKEN_PROGRAM,
    });
    return await buildAndSignWireTransaction(rpc as never, f.payer, [instruction]);
}

describe('submitTopUpTx post-confirm channel read', () => {
    test('a visible account whose deposit has not caught up is rejected on the first read', async () => {
        // The money case. Deposit only grows, so a second read that shows
        // 5_000 proves nothing about OUR top-up: a concurrent top-up on this
        // channel raises the same field, and nothing holds a per-channel
        // lock across this read. The sequence below is exactly the one a
        // retry loop would "rescue", so it must reject after one read.
        const f = await topUpFixture();
        const rpc = sequencedRpc([topUpChannelData(f, 1_000n), topUpChannelData(f, 5_000n)]);
        const wire = await topUpWire(f, rpc, 4_000n);

        await expect(
            submitTopUpTx({
                additionalAmount: 4_000n,
                channelId: f.channel.address,
                channelProgram: PAYMENT_CHANNELS_PROGRAM_ID.toString(),
                channelRead: FAST_BACKOFF,
                currentDeposit: 1_000n,
                payer: f.payer.address,
                rpc: rpc as never,
                transaction: wire,
            }),
        ).rejects.toThrow(/does not reflect the submitted top-up/);
        expect(rpc.accountLookups).toHaveLength(1);
    });

    test('re-reads a channel that is not visible yet', async () => {
        const f = await topUpFixture();
        const rpc = sequencedRpc([null, topUpChannelData(f, 5_000n)]);
        const wire = await topUpWire(f, rpc, 4_000n);

        await submitTopUpTx({
            additionalAmount: 4_000n,
            channelId: f.channel.address,
            channelProgram: PAYMENT_CHANNELS_PROGRAM_ID.toString(),
            channelRead: FAST_BACKOFF,
            currentDeposit: 1_000n,
            payer: f.payer.address,
            rpc: rpc as never,
            transaction: wire,
        });

        expect(rpc.accountLookups).toHaveLength(2);
    });

    test('a status other than Open is rejected on the first read, never re-read', async () => {
        // Open is the channel's earliest state, so a stale replica can only
        // serve Open or older: Closing can never be a lag artifact. The
        // status check gates the deposit check, and the deposit here is
        // high enough that only the status can be the rejection reason.
        const f = await topUpFixture();
        const rpc = sequencedRpc([topUpChannelData(f, 5_000n, Number(ChannelStatus.Closing))]);
        const wire = await topUpWire(f, rpc, 4_000n);

        await expect(
            submitTopUpTx({
                additionalAmount: 4_000n,
                channelId: f.channel.address,
                channelProgram: PAYMENT_CHANNELS_PROGRAM_ID.toString(),
                channelRead: FAST_BACKOFF,
                currentDeposit: 1_000n,
                payer: f.payer.address,
                rpc: rpc as never,
                transaction: wire,
            }),
        ).rejects.toThrow(/does not reflect the submitted top-up/);
        expect(rpc.accountLookups).toHaveLength(1);
    });

    test('an account that never becomes visible fails after the attempt budget', async () => {
        const f = await topUpFixture();
        const rpc = sequencedRpc([null]);
        const wire = await topUpWire(f, rpc, 4_000n);

        await expect(
            submitTopUpTx({
                additionalAmount: 4_000n,
                channelId: f.channel.address,
                channelProgram: PAYMENT_CHANNELS_PROGRAM_ID.toString(),
                channelRead: FAST_BACKOFF,
                currentDeposit: 1_000n,
                payer: f.payer.address,
                rpc: rpc as never,
                transaction: wire,
            }),
        ).rejects.toThrow(/Account not found/);
        expect(rpc.accountLookups).toHaveLength(6);
    });
});

// ── fetchSubscriptionDelegation ─────────────────────────────────────────

const SUBSCRIPTION_PDA = '9xAXssX9j7vuK99c7cFwqbixzL3bFrzPy9PUhCtDPAYJ';
/** Zero-filled SubscriptionDelegation: presence is all this site retries on. */
const DELEGATION_DATA = getBase64Codec().decode(new Uint8Array(201));

/**
 * Stub `fetch` with a JSON-RPC `getAccountInfo` responder walking
 * `accountSequence`, and count the calls.
 */
function stubGetAccountInfoFetch(accountSequence: readonly (string | null)[]): { calls: () => number } {
    let calls = 0;
    vi.stubGlobal('fetch', () => {
        const index = Math.min(calls, accountSequence.length - 1);
        calls += 1;
        const data = accountSequence[index] ?? null;
        return Promise.resolve(
            new Response(
                JSON.stringify({
                    id: 1,
                    jsonrpc: '2.0',
                    result: {
                        context: { slot: 1 },
                        value:
                            data === null
                                ? null
                                : {
                                      data: [data, 'base64'],
                                      executable: false,
                                      lamports: 1000000,
                                      owner: SUBSCRIPTION_PDA,
                                      rentEpoch: 0,
                                      space: 201,
                                  },
                    },
                }),
                { headers: { 'Content-Type': 'application/json' }, status: 200 },
            ),
        );
    });
    return { calls: () => calls };
}

describe('fetchSubscriptionDelegation post-activation read', () => {
    test('re-reads a delegation that is not visible yet', async () => {
        const fetchStub = stubGetAccountInfoFetch([null, null, DELEGATION_DATA]);
        try {
            const delegation = await __testing.fetchSubscriptionDelegation(
                'http://localhost:8899',
                SUBSCRIPTION_PDA,
                FAST_BACKOFF,
            );
            expect(delegation).not.toBeNull();
            expect(fetchStub.calls()).toBe(3);
        } finally {
            vi.unstubAllGlobals();
        }
    });

    test('an existing delegation is returned on the first read', async () => {
        // Every field check lives in verify(), outside this function, so any
        // account that exists must short-circuit the loop immediately.
        const fetchStub = stubGetAccountInfoFetch([DELEGATION_DATA]);
        try {
            const delegation = await __testing.fetchSubscriptionDelegation(
                'http://localhost:8899',
                SUBSCRIPTION_PDA,
                FAST_BACKOFF,
            );
            expect(delegation).not.toBeNull();
            expect(fetchStub.calls()).toBe(1);
        } finally {
            vi.unstubAllGlobals();
        }
    });

    test('an absent delegation still resolves to null after the attempt budget', async () => {
        const fetchStub = stubGetAccountInfoFetch([null]);
        try {
            const delegation = await __testing.fetchSubscriptionDelegation(
                'http://localhost:8899',
                SUBSCRIPTION_PDA,
                FAST_BACKOFF,
            );
            expect(delegation).toBeNull();
            expect(fetchStub.calls()).toBe(6);
        } finally {
            vi.unstubAllGlobals();
        }
    });

    test('without the retry option the read stays a single RPC call', async () => {
        const fetchStub = stubGetAccountInfoFetch([null]);
        try {
            const delegation = await __testing.fetchSubscriptionDelegation('http://localhost:8899', SUBSCRIPTION_PDA);
            expect(delegation).toBeNull();
            expect(fetchStub.calls()).toBe(1);
        } finally {
            vi.unstubAllGlobals();
        }
    });
});
