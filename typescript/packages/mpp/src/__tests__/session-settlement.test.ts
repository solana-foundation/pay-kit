// Server settlement money-path coverage for the MPP session method.
//
// Reinstates the topUp / close coverage from the deleted
// session-server.test.ts against the reworked API:
//
//   - topUp: deposit update on success, and the reject paths (unknown
//     channel, sealed channel, mismatched payload, failed on-chain
//     verification).
//   - close: final-voucher monotonicity, idempotent close replay, and
//     failed-settlement retry (a close whose on-chain settle throws must be
//     retryable without losing the voucher watermark).
//   - operator-vs-client close authorization (server/Session.ts
//     handleClose): the operator-authorized and client-authorized paths and
//     the rejection of an unauthorized closer.

import {
    address,
    generateKeyPairSigner,
    getBase64Codec,
    getCompiledTransactionMessageDecoder,
    getCompiledTransactionMessageEncoder,
    getTransactionDecoder,
    getTransactionEncoder,
    type KeyPairSigner,
} from '@solana/kit';
import { getSetComputeUnitLimitInstruction, getSetComputeUnitPriceInstruction } from '@solana-program/compute-budget';
import { findAssociatedTokenPda } from '@solana-program/token';
import { describe, expect, test } from 'vitest';

import { ActiveSession, signSessionAuthentication } from '../client/Session.js';
import { ASSOCIATED_TOKEN_PROGRAM, SYSTEM_PROGRAM } from '../constants.js';
import { getChannelEncoder } from '../generated/payment-channels/accounts/channel.js';
import { ChannelStatus } from '../generated/payment-channels/types/channelStatus.js';
import { session } from '../server/Session.js';
import {
    buildTopUpInstruction,
    PAYMENT_CHANNELS_PROGRAM_ID,
    type ServerInstruction,
} from '../server/session/on-chain.js';
import { type ChannelState, createMemorySessionStore, type SessionStore } from '../server/session/store.js';
import { buildAndSignWireTransaction } from '../server/session/wire-tx.js';

const TOKEN_PROGRAM = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA';
// resolveStablecoinMint('USDC', 'devnet')
const USDC_DEVNET_MINT = '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU';
const BLOCKHASH = 'EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N';

// ── Fixtures ──────────────────────────────────────────────────────────────

/**
 * Minimal RPC mock covering the settlement money path:
 * `getLatestBlockhash` (settle-tx compilation), `sendTransaction`
 * (open/topUp/settle broadcast), and `getSignatureStatuses`
 * (submitTopUpTx confirmation).
 */
function mockRpc(
    options: {
        accountData?: string;
        confirmErr?: unknown;
        /** Confirmation levels served by successive status polls; the last one repeats. */
        confirmationLevels?: readonly string[];
        sendErrors?: number;
        /** Addresses served as existing system-owned accounts. */
        foreignAccounts?: ReadonlySet<string>;
        /** Addresses served as existing token accounts. */
        tokenAccounts?: ReadonlySet<string>;
    } = {},
) {
    let sendErrors = options.sendErrors ?? 0;
    const sent: string[] = [];
    const statusCalls: string[] = [];
    const accountCommitments: unknown[] = [];
    const levels = options.confirmationLevels ?? ['finalized'];
    let statusPolls = 0;
    const rpc = {
        getAccountInfo: (account: string, config?: { commitment?: unknown }) => {
            accountCommitments.push(config?.commitment);
            return {
                send: () =>
                    options.tokenAccounts?.has(account) || options.foreignAccounts?.has(account)
                        ? Promise.resolve({
                              context: { slot: 314n },
                              value: { owner: options.tokenAccounts?.has(account) ? TOKEN_PROGRAM : SYSTEM_PROGRAM },
                          })
                        : Promise.resolve({
                              context: { slot: 314n },
                              value:
                                  options.accountData === undefined
                                      ? null
                                      : {
                                            data: [options.accountData, 'base64'],
                                            executable: false,
                                            lamports: 1_000_000n,
                                            owner: PAYMENT_CHANNELS_PROGRAM_ID.toString(),
                                            rentEpoch: 0n,
                                            space: BigInt(getBase64Codec().encode(options.accountData).byteLength),
                                        },
                          }),
            };
        },
        getLatestBlockhash: () => ({
            send: () =>
                Promise.resolve({
                    context: { slot: 314n },
                    value: { blockhash: BLOCKHASH, lastValidBlockHeight: 100n },
                }),
        }),
        getSignatureStatuses: (sigs: readonly string[]) => ({
            send: () => {
                statusCalls.push(...sigs);
                const confirmationStatus = levels[Math.min(statusPolls++, levels.length - 1)];
                return Promise.resolve({
                    value: sigs.map(() => ({ confirmationStatus, err: options.confirmErr ?? null, slot: 314n })),
                });
            },
        }),
        sendTransaction: (wire: string) => ({
            send: () => {
                if (sendErrors > 0) {
                    sendErrors -= 1;
                    return Promise.reject(new Error('blockhash not found'));
                }
                sent.push(wire);
                return Promise.resolve(`MockSig${sent.length}`);
            },
        }),
    };
    return { accountCommitments, rpc, sent, statusCalls };
}

interface Fixture {
    readonly channel: KeyPairSigner;
    readonly merchant: KeyPairSigner;
    readonly payer: KeyPairSigner;
    readonly sessionSigner: KeyPairSigner;
    readonly store: SessionStore;
}

async function makeFixture(): Promise<Fixture> {
    return {
        channel: await generateKeyPairSigner(),
        merchant: await generateKeyPairSigner(),
        payer: await generateKeyPairSigner(),
        sessionSigner: await generateKeyPairSigner(),
        store: createMemorySessionStore(),
    };
}

function channelState(f: Fixture, overrides: Partial<ChannelState> = {}): ChannelState {
    return {
        authorizedSigner: f.sessionSigner.address,
        channelId: f.channel.address,
        closeRequestedAt: undefined,
        committedDeliveries: [],
        cumulative: 0n,
        deposit: 1_000n,
        highestVoucherExpiresAt: undefined,
        highestVoucherSignature: undefined,
        idleTimeoutSeconds: 300,
        lastActivityAt: Date.now(),
        nextDeliverySequence: 0n,
        openSlot: 314n,
        openingChallengeId: 'open-challenge',
        payer: f.payer.address,
        pendingDeliveries: [],
        processedUses: [],
        rentPayer: f.payer.address,
        sealed: false,
        settledOnChain: 0n,
        spentAmount: 0n,
        voucherSigner: 'client',
        ...overrides,
    };
}

async function seedChannel(f: Fixture, overrides: Partial<ChannelState> = {}): Promise<ChannelState> {
    return await f.store.updateChannel(f.channel.address, () => channelState(f, overrides));
}

/**
 * Base64 account data for the fixture channel as `fetchChannel` returns it,
 * with the given confirmed deposit — served to `submitTopUpTx`'s
 * post-confirm re-check.
 */
function channelAccountData(f: Fixture, deposit: bigint): string {
    const data = getChannelEncoder().encode({
        authorizedSigner: address(f.sessionSigner.address),
        bump: 255,
        closureStartedAt: 0n,
        deposit,
        discriminator: 1,
        distributionHash: new Array<number>(32).fill(0),
        gracePeriod: 900,
        mint: address(USDC_DEVNET_MINT),
        openSlot: 314n,
        payee: address(f.merchant.address),
        payer: address(f.payer.address),
        payerWithdrawnAt: 0n,
        rentPayer: address(f.payer.address),
        salt: 7n,
        settlement: { payoutWatermark: 0n, settled: 0n },
        status: Number(ChannelStatus.Open),
        version: 1,
    });
    return getBase64Codec().decode(data as Uint8Array);
}

function makeMethod(f: Fixture, rpc: unknown, overrides: Record<string, unknown> = {}) {
    return session({
        amount: 100n,
        currency: 'USDC',
        gracePeriodSeconds: 900,
        network: 'devnet',
        recipient: f.merchant.address,
        rpc: rpc as never,
        signer: f.merchant,
        store: f.store,
        ...overrides,
    } as never);
}

function makeCred(f: Fixture, payload: Record<string, unknown>, challengeId = 'challenge-1') {
    return {
        challenge: {
            id: challengeId,
            intent: 'session' as const,
            method: 'solana' as const,
            realm: 'api.test',
            request: {
                amount: '100',
                currency: 'USDC',
                recipient: f.merchant.address,
                methodDetails: {
                    channelProgram: PAYMENT_CHANNELS_PROGRAM_ID.toString(),
                    gracePeriodSeconds: 900,
                    network: 'devnet',
                    tokenProgram: TOKEN_PROGRAM,
                },
            },
        },
        payload,
    };
}

type Method = ReturnType<typeof makeMethod>;

async function verify(method: Method, credential: ReturnType<typeof makeCred>) {
    return await method.verify({ credential, request: credential.challenge.request } as never);
}

/** Build a real, signed top-up wire transaction bound to the fixture channel. */
async function buildTopUpWire(
    f: Fixture,
    rpc: unknown,
    amount: bigint,
    payerSigner?: KeyPairSigner,
    prefix: readonly ServerInstruction[] = [],
): Promise<string> {
    const payer = payerSigner ?? f.payer;
    const instruction = await buildTopUpInstruction({
        amount,
        channelId: f.channel.address,
        mint: USDC_DEVNET_MINT,
        payer,
        tokenProgram: TOKEN_PROGRAM,
    });
    return await buildAndSignWireTransaction(rpc as never, payer, [...prefix, instruction]);
}

/** Re-encode a v0 wire transaction as a legacy (unversioned) wire transaction. */
function reencodeAsLegacy(transactionBase64: string): string {
    const tx = getTransactionDecoder().decode(getBase64Codec().encode(transactionBase64));
    const compiled = getCompiledTransactionMessageDecoder().decode(tx.messageBytes);
    const legacyMessageBytes = getCompiledTransactionMessageEncoder().encode({
        ...compiled,
        version: 'legacy',
    } as never);
    const legacyTx = getTransactionEncoder().encode({
        messageBytes: legacyMessageBytes as never,
        signatures: tx.signatures,
    });
    return getBase64Codec().decode(legacyTx);
}

// ── verify() — topUp ────────────────────────────────────────────────────

describe('session() verify() topUp', () => {
    test('topUp verifies the wire transaction, confirms it on-chain, and raises the deposit', async () => {
        const f = await makeFixture();
        const { rpc, sent, statusCalls } = mockRpc({ accountData: channelAccountData(f, 5_000n) });
        const method = makeMethod(f, rpc);
        await seedChannel(f);

        const wire = await buildTopUpWire(f, rpc, 4_000n);
        const receipt = await verify(
            method,
            makeCred(f, {
                action: 'topUp',
                additionalAmount: '4000',
                channelId: f.channel.address,
                transaction: wire,
            }),
        );

        expect(receipt.status).toBe('success');
        expect(receipt.reference).toBe(f.channel.address);
        // txHash is reserved for the close receipt's settlement signature
        // (draft-solana-session-00 receipt table); a top-up carries none.
        expect(receipt).toMatchObject({
            acceptedCumulative: '0',
            idleTimeoutSeconds: 300,
            intent: 'session',
            spent: '0',
        });
        expect(receipt).not.toHaveProperty('txHash');
        expect(sent).toHaveLength(1);
        expect(statusCalls).toContain('MockSig1');
        const state = await f.store.getChannel(f.channel.address);
        expect(state?.deposit).toBe(5_000n);
    });

    test('topUp is credited only once its signature finalizes, against finalized state', async () => {
        const f = await makeFixture();
        const { accountCommitments, rpc, statusCalls } = mockRpc({
            accountData: channelAccountData(f, 5_000n),
            confirmationLevels: ['confirmed', 'finalized'],
        });
        const method = makeMethod(f, rpc);
        await seedChannel(f);

        const wire = await buildTopUpWire(f, rpc, 4_000n);
        accountCommitments.length = 0;
        const receipt = await verify(
            method,
            makeCred(f, { action: 'topUp', additionalAmount: '4000', channelId: f.channel.address, transaction: wire }),
        );

        expect(receipt.status).toBe('success');
        expect(statusCalls.filter(sig => sig === 'MockSig1')).toHaveLength(2);
        expect(accountCommitments).toEqual(['finalized']);
        expect((await f.store.getChannel(f.channel.address))?.deposit).toBe(5_000n);
    });

    test('topUp accepts Compute Budget instructions within the caps', async () => {
        const f = await makeFixture();
        const { rpc, sent } = mockRpc({ accountData: channelAccountData(f, 5_000n) });
        const method = makeMethod(f, rpc);
        await seedChannel(f);

        const budget = [
            getSetComputeUnitLimitInstruction({ units: 400_000 }),
            getSetComputeUnitPriceInstruction({ microLamports: 5_000_000n }),
        ] as unknown as ServerInstruction[];
        const wire = await buildTopUpWire(f, rpc, 4_000n, undefined, budget);
        const receipt = await verify(
            method,
            makeCred(f, { action: 'topUp', additionalAmount: '4000', channelId: f.channel.address, transaction: wire }),
        );
        expect(receipt.status).toBe('success');
        expect(sent).toHaveLength(1);
    });

    test('topUp rejects an excessive Compute Budget price before broadcasting', async () => {
        const f = await makeFixture();
        const { rpc, sent } = mockRpc({ accountData: channelAccountData(f, 5_000n) });
        const method = makeMethod(f, rpc);
        await seedChannel(f);

        const budget = [
            getSetComputeUnitPriceInstruction({ microLamports: 5_000_001n }),
        ] as unknown as ServerInstruction[];
        const wire = await buildTopUpWire(f, rpc, 4_000n, undefined, budget);
        await expect(
            verify(
                method,
                makeCred(f, {
                    action: 'topUp',
                    additionalAmount: '4000',
                    channelId: f.channel.address,
                    transaction: wire,
                }),
            ),
        ).rejects.toThrow(/submitTopUpTx: compute unit price 5000001 exceeds maximum 5000000/);
        expect(sent).toHaveLength(0);
    });

    test('a resubmitted top-up transaction credits the deposit exactly once', async () => {
        const f = await makeFixture();
        const { rpc, sent } = mockRpc({ accountData: channelAccountData(f, 5_000n) });
        const method = makeMethod(f, rpc);
        await seedChannel(f);

        const wire = await buildTopUpWire(f, rpc, 4_000n);
        const cred = makeCred(f, {
            action: 'topUp',
            additionalAmount: '4000',
            channelId: f.channel.address,
            transaction: wire,
        });
        await verify(method, cred);
        const replayed = await verify(method, cred);

        expect(replayed.status).toBe('success');
        // The replay is answered from the recorded signature — no second
        // broadcast, no second credit.
        expect(sent).toHaveLength(1);
        const state = await f.store.getChannel(f.channel.address);
        expect(state?.deposit).toBe(5_000n);
        expect(state?.processedTopUpSignatures).toHaveLength(1);
    });

    test('concurrently duplicated top-ups credit the deposit exactly once', async () => {
        const f = await makeFixture();
        const { rpc } = mockRpc({ accountData: channelAccountData(f, 5_000n) });
        const method = makeMethod(f, rpc);
        await seedChannel(f);

        const wire = await buildTopUpWire(f, rpc, 4_000n);
        const cred = makeCred(f, {
            action: 'topUp',
            additionalAmount: '4000',
            channelId: f.channel.address,
            transaction: wire,
        });
        // Both submissions read the pre-credit state and pass the replay
        // pre-check; the signature dedupe inside the atomic mutator is what
        // guarantees a single credit.
        const [first, second] = await Promise.all([verify(method, cred), verify(method, cred)]);

        expect(first.status).toBe('success');
        expect(second.status).toBe('success');
        const state = await f.store.getChannel(f.channel.address);
        expect(state?.deposit).toBe(5_000n);
        expect(state?.processedTopUpSignatures).toHaveLength(1);
    });

    test('topUp accepts a legacy-encoded wire transaction under the version-0 rules', async () => {
        const f = await makeFixture();
        const { rpc, sent } = mockRpc({ accountData: channelAccountData(f, 5_000n) });
        const method = makeMethod(f, rpc);
        await seedChannel(f);

        // A pre-cutover client's legacy (unversioned) top-up is verified and
        // broadcast exactly like a v0 one.
        const wire = reencodeAsLegacy(await buildTopUpWire(f, rpc, 4_000n));
        const receipt = await verify(
            method,
            makeCred(f, {
                action: 'topUp',
                additionalAmount: '4000',
                channelId: f.channel.address,
                transaction: wire,
            }),
        );
        expect(receipt.status).toBe('success');
        expect(sent).toHaveLength(1);
    });

    test('topUp rejects an unknown channel before touching the network', async () => {
        const f = await makeFixture();
        const { rpc, sent } = mockRpc();
        const method = makeMethod(f, rpc);
        const ghost = await generateKeyPairSigner();

        const wire = await buildTopUpWire(f, rpc, 4_000n);
        await expect(
            verify(
                method,
                makeCred(f, { action: 'topUp', additionalAmount: '4000', channelId: ghost.address, transaction: wire }),
            ),
        ).rejects.toThrow(/not found/);
        expect(sent).toHaveLength(0);
    });

    test('topUp rejects a sealed channel', async () => {
        const f = await makeFixture();
        const { rpc, sent } = mockRpc();
        const method = makeMethod(f, rpc);
        await seedChannel(f, { sealed: true });

        const wire = await buildTopUpWire(f, rpc, 4_000n);
        await expect(
            verify(
                method,
                makeCred(f, {
                    action: 'topUp',
                    additionalAmount: '4000',
                    channelId: f.channel.address,
                    transaction: wire,
                }),
            ),
        ).rejects.toThrow(/already sealed/);
        expect(sent).toHaveLength(0);
        expect((await f.store.getChannel(f.channel.address))?.deposit).toBe(1_000n);
    });

    test('topUp rejects when close is pending', async () => {
        const f = await makeFixture();
        const { rpc, sent } = mockRpc();
        const method = makeMethod(f, rpc);
        await seedChannel(f, { closeRequestedAt: 123n });

        const wire = await buildTopUpWire(f, rpc, 4_000n);
        await expect(
            verify(
                method,
                makeCred(f, {
                    action: 'topUp',
                    additionalAmount: '4000',
                    channelId: f.channel.address,
                    transaction: wire,
                }),
            ),
        ).rejects.toThrow(/close is pending/);
        expect(sent).toHaveLength(0);
    });

    test('topUp rejects a zero additionalAmount', async () => {
        const f = await makeFixture();
        const { rpc } = mockRpc();
        const method = makeMethod(f, rpc);
        await seedChannel(f);

        await expect(
            verify(
                method,
                makeCred(f, {
                    action: 'topUp',
                    additionalAmount: '0',
                    channelId: f.channel.address,
                    transaction: 'wire',
                }),
            ),
        ).rejects.toThrow(/additionalAmount must be positive/);
    });

    test('topUp rejects a transaction whose payer does not match the persisted channel payer', async () => {
        const f = await makeFixture();
        const { rpc, sent } = mockRpc();
        const method = makeMethod(f, rpc);
        await seedChannel(f);
        const intruder = await generateKeyPairSigner();

        // Self-consistent transaction, but funded by a different payer than
        // the one recorded at open.
        const wire = await buildTopUpWire(f, rpc, 4_000n, intruder);
        await expect(
            verify(
                method,
                makeCred(f, {
                    action: 'topUp',
                    additionalAmount: '4000',
                    channelId: f.channel.address,
                    transaction: wire,
                }),
            ),
        ).rejects.toThrow(/payer or channel does not match persisted channel state/);
        expect(sent).toHaveLength(0);
        expect((await f.store.getChannel(f.channel.address))?.deposit).toBe(1_000n);
    });

    test('topUp rejects when the declared additionalAmount mismatches the instruction amount', async () => {
        const f = await makeFixture();
        const { rpc, sent } = mockRpc();
        const method = makeMethod(f, rpc);
        await seedChannel(f);

        const wire = await buildTopUpWire(f, rpc, 999n);
        await expect(
            verify(
                method,
                makeCred(f, {
                    action: 'topUp',
                    additionalAmount: '4000',
                    channelId: f.channel.address,
                    transaction: wire,
                }),
            ),
        ).rejects.toThrow(/amount does not match additionalAmount/);
        expect(sent).toHaveLength(0);
        expect((await f.store.getChannel(f.channel.address))?.deposit).toBe(1_000n);
    });

    test('topUp rejects when the transaction fails on-chain and leaves the deposit unchanged', async () => {
        const f = await makeFixture();
        const { rpc, sent } = mockRpc({ confirmErr: { InstructionError: [0, 'Custom'] } });
        const method = makeMethod(f, rpc);
        await seedChannel(f);

        const wire = await buildTopUpWire(f, rpc, 4_000n);
        await expect(
            verify(
                method,
                makeCred(f, {
                    action: 'topUp',
                    additionalAmount: '4000',
                    channelId: f.channel.address,
                    transaction: wire,
                }),
            ),
        ).rejects.toThrow(/failed on-chain/);
        expect(sent).toHaveLength(1);
        expect((await f.store.getChannel(f.channel.address))?.deposit).toBe(1_000n);
    });
});

// ── verify() — close final-voucher monotonicity + idempotent replay ──────

async function watermarkedFixture(
    rpcOptions: Parameters<typeof mockRpc>[0] = {},
    methodOverrides: Record<string, unknown> = {},
    fixture?: Fixture,
) {
    const f = fixture ?? (await makeFixture());
    const mock = mockRpc(rpcOptions);
    const method = makeMethod(f, mock.rpc, methodOverrides);
    await seedChannel(f);

    const active = new ActiveSession({ channelId: f.channel.address, signer: f.sessionSigner });
    const voucher = await active.prepareVoucher(250n);
    const receipt = await verify(method, makeCred(f, { action: 'voucher', channelId: f.channel.address, voucher }));
    return { ...mock, active, f, method, receipt, voucher };
}

describe('session() verify() close monotonicity', () => {
    test('an accepted voucher advances the watermark', async () => {
        const { active, f, method, receipt, voucher } = await watermarkedFixture();
        expect(receipt.status).toBe('success');
        expect(receipt.reference).toBe(f.channel.address);
        expect(receipt).toMatchObject({
            acceptedCumulative: '250',
            idleTimeoutSeconds: 300,
            intent: 'session',
            spent: '100',
        });

        const state = await f.store.getChannel(f.channel.address);
        expect(state?.cumulative).toBe(250n);
        expect(state?.highestVoucherSignature).toBe(voucher.signature);

        // A replay of the accepted voucher authorizes no further request and
        // leaves the channel untouched.
        const before = await f.store.getChannel(f.channel.address);
        await expect(
            verify(method, makeCred(f, { action: 'voucher', channelId: f.channel.address, voucher })),
        ).rejects.toThrow(/already accepted/);
        expect(await f.store.getChannel(f.channel.address)).toEqual(before);

        // The next request is paid with a fresh voucher.
        const next = await active.prepareVoucher(500n);
        const fresh = await verify(
            method,
            makeCred(f, { action: 'voucher', channelId: f.channel.address, voucher: next }),
        );
        expect(fresh).toMatchObject({ acceptedCumulative: '500', spent: '200' });
    });

    test('a voucher action whose top-level channelId diverges from the signed voucher is rejected', async () => {
        const { f, method } = await watermarkedFixture();
        const voucher = await new ActiveSession({
            channelId: f.channel.address,
            signer: f.sessionSigner,
        }).prepareVoucher(300n);

        await expect(
            verify(method, makeCred(f, { action: 'voucher', channelId: '11111111111111111111111111111111', voucher })),
        ).rejects.toThrow(/does not match the signed voucher/);

        const state = await f.store.getChannel(f.channel.address);
        expect(state?.cumulative).toBe(250n);
    });

    test('a close whose nested voucher is bound to another channel is rejected', async () => {
        const { f, method, sent } = await watermarkedFixture();
        const foreign = await new ActiveSession({
            channelId: '11111111111111111111111111111111',
            signer: f.sessionSigner,
        }).prepareVoucher(300n);

        await expect(
            verify(method, makeCred(f, { action: 'close', channelId: f.channel.address, voucher: foreign })),
        ).rejects.toThrow(/does not match the close channelId/);

        const state = await f.store.getChannel(f.channel.address);
        expect(state?.closeRequestedAt).toBeUndefined();
        expect(sent).toHaveLength(0);
    });

    test('close rejects a non-monotonic final voucher and does not flip close-pending', async () => {
        const { f, method, sent } = await watermarkedFixture();
        const stale = await new ActiveSession({ channelId: f.channel.address, signer: f.sessionSigner }).prepareVoucher(
            100n,
        );

        await expect(
            verify(method, makeCred(f, { action: 'close', channelId: f.channel.address, voucher: stale })),
        ).rejects.toThrow(/cumulative-not-monotonic/);

        const state = await f.store.getChannel(f.channel.address);
        expect(state?.closeRequestedAt).toBeUndefined();
        expect(state?.cumulative).toBe(250n);
        expect(state?.sealed).toBe(false);
        expect(sent).toHaveLength(0);
    });

    test('close accepts an idempotent replay of the current highest voucher and settles it', async () => {
        const { f, method, sent, voucher } = await watermarkedFixture();

        const receipt = await verify(method, makeCred(f, { action: 'close', channelId: f.channel.address, voucher }));
        expect(receipt.status).toBe('success');
        expect(receipt.reference).toBe(f.channel.address);
        expect(receipt).toMatchObject({ refunded: '750', txHash: 'MockSig1' });
        expect(sent).toHaveLength(1);

        const state = await f.store.getChannel(f.channel.address);
        expect(state?.closeRequestedAt).toBeDefined();
        expect(state?.cumulative).toBe(250n);
        expect(state?.sealed).toBe(true);
        expect(state?.settledOnChain).toBe(250n);
        expect(state?.settledSignature).toBe('MockSig1');
    });

    test('close with an advancing final voucher raises the watermark before settling', async () => {
        const { active, f, method, sent } = await watermarkedFixture();
        const finalVoucher = await active.prepareVoucher(750n);

        const receipt = await verify(
            method,
            makeCred(f, { action: 'close', channelId: f.channel.address, voucher: finalVoucher }),
        );
        expect(receipt.status).toBe('success');
        expect(sent).toHaveLength(1);

        const state = await f.store.getChannel(f.channel.address);
        expect(state?.cumulative).toBe(750n);
        expect(state?.highestVoucherSignature).toBe(finalVoucher.signature);
        expect(state?.sealed).toBe(true);
        expect(state?.settledOnChain).toBe(750n);
    });
});

describe('session() close does not bill unauthenticated reservations', () => {
    // Reservations come only from POST /__402/session/deliveries, which checks
    // no credential: they prove neither the payer's request nor a delivery.
    async function withForeignReservation() {
        const fixture = await watermarkedFixture();
        await fixture.f.store.updateChannel(fixture.f.channel.address, current => ({
            ...current!,
            // Reserved by anyone who knows the channel id, never committed.
            pendingDeliveries: [{ amount: 100n, deliveryId: 'delivery-1', expiresAt: 1n, sequence: 1n }],
        }));
        return fixture;
    }

    test('a reservation neither blocks the close nor raises what it settles', async () => {
        const { f, method, sent, voucher } = await withForeignReservation();
        const before = await f.store.getChannel(f.channel.address);
        const receipt = await verify(method, makeCred(f, { action: 'close', channelId: f.channel.address, voucher }));
        expect(receipt.status).toBe('success');
        expect(sent).toHaveLength(1);
        const state = await f.store.getChannel(f.channel.address);
        expect(state?.settledOnChain).toBe(before!.cumulative);
        expect(state?.spentAmount).toBe(before!.spentAmount);
    });
});

/** Decode a sent wire transaction into program / account addresses / data per instruction. */
function decodeSent(wire: string): { accounts: string[]; data: Uint8Array; program: string }[] {
    const tx = getTransactionDecoder().decode(getBase64Codec().encode(wire));
    const message = getCompiledTransactionMessageDecoder().decode(tx.messageBytes) as unknown as {
        instructions: readonly {
            accountIndices?: readonly number[];
            data?: Uint8Array;
            programAddressIndex: number;
        }[];
        staticAccounts: readonly string[];
    };
    return message.instructions.map(ix => ({
        accounts: (ix.accountIndices ?? []).map(index => message.staticAccounts[index]!),
        data: ix.data ?? new Uint8Array(),
        program: message.staticAccounts[ix.programAddressIndex]!,
    }));
}

async function usdcAta(owner: string): Promise<string> {
    const [ata] = await findAssociatedTokenPda({
        mint: address(USDC_DEVNET_MINT),
        owner: address(owner),
        tokenProgram: address(TOKEN_PROGRAM),
    });
    return ata;
}

describe('session() close settlement treasury', () => {
    // ATA(4zTeC5mVqWLruDexgU2mV66p9t5vCA9JyiZqdGDUspap, USDC_DEVNET_MINT, TOKEN_PROGRAM)
    const DEVNET_TREASURY_ATA = 'BSMX9adNvtMHhBSbiuDeaPZZbF82cmPJkSHyptJSHecz';
    // ATA(Cs2zdfUNonRdRGsiZUQQLdTxzxVvJZmgiX2mpLYKuEqP, USDC_DEVNET_MINT, TOKEN_PROGRAM)
    const MAINNET_TREASURY_ATA = 'FhCMrXE7ciBXZpSwuNwPT4HTkWcsUaMkFrUvDGJD8sP2';

    test('a devnet close distributes to the devnet treasury ATA', async () => {
        const { f, method, sent, voucher } = await watermarkedFixture();

        const receipt = await verify(method, makeCred(f, { action: 'close', channelId: f.channel.address, voucher }));
        expect(receipt.status).toBe('success');
        expect(sent).toHaveLength(1);

        const distribute = decodeSent(sent[0]!).find(
            ix => ix.program === PAYMENT_CHANNELS_PROGRAM_ID.toString() && ix.data[0] === 7,
        );
        expect(distribute).toBeDefined();
        const treasuryAta = distribute!.accounts[6];
        expect(treasuryAta).toBe(DEVNET_TREASURY_ATA);
        expect(treasuryAta).not.toBe(MAINNET_TREASURY_ATA);
    });

    test('session construction rejects a network without a known deployment', async () => {
        const f = await makeFixture();
        expect(() => makeMethod(f, mockRpc().rpc, { currency: USDC_DEVNET_MINT, network: 'testnet' })).toThrow(
            /Unsupported network "testnet"/,
        );
    });
});

describe('session() close settlement destination ATAs', () => {
    const DEVNET_TREASURY = '4zTeC5mVqWLruDexgU2mV66p9t5vCA9JyiZqdGDUspap';

    /**
     * Close a watermarked channel and return every idempotent ATA create in
     * the settle transaction. `existing` / `foreign` pick owners whose USDC
     * ATA address is served as a token account / a system-owned account.
     */
    async function closeAndInspect(options: {
        existing?: (f: Fixture) => readonly string[];
        foreign?: (f: Fixture) => readonly string[];
        splits?: (f: Fixture) => readonly { recipient: string; shareBps: number }[];
    }) {
        const f = await makeFixture();
        const atasOf = async (owners: readonly string[]) => new Set(await Promise.all(owners.map(usdcAta)));
        const tokenAccounts = await atasOf(options.existing?.(f) ?? []);
        const foreignAccounts = await atasOf(options.foreign?.(f) ?? []);
        const { method, sent, voucher } = await watermarkedFixture(
            { foreignAccounts, tokenAccounts },
            options.splits ? { distributionSplits: options.splits(f) } : {},
            f,
        );

        const receipt = await verify(method, makeCred(f, { action: 'close', channelId: f.channel.address, voucher }));
        expect(receipt.status).toBe('success');
        expect(sent).toHaveLength(1);
        const instructions = decodeSent(sent[0]!);
        const creates = instructions
            .filter(ix => ix.program === ASSOCIATED_TOKEN_PROGRAM)
            .map(ix => ({
                ata: ix.accounts[1],
                data: Array.from(ix.data),
                owner: ix.accounts[2],
                payer: ix.accounts[0],
            }));
        const distributeIndex = instructions.findIndex(
            ix => ix.program === PAYMENT_CHANNELS_PROGRAM_ID.toString() && ix.data[0] === 7,
        );
        const lastCreateIndex = instructions.map(ix => ix.program).lastIndexOf(ASSOCIATED_TOKEN_PROGRAM);
        return { creates, distributeIndex, f, lastCreateIndex };
    }

    test('missing payee and treasury ATAs are created before distribute', async () => {
        const { creates, distributeIndex, f, lastCreateIndex } = await closeAndInspect({
            existing: f => [f.payer.address],
        });

        expect(creates).toEqual(
            await Promise.all(
                [f.merchant.address, DEVNET_TREASURY].map(async owner => ({
                    ata: await usdcAta(owner),
                    data: [1],
                    owner,
                    payer: f.merchant.address,
                })),
            ),
        );
        expect(lastCreateIndex).toBeLessThan(distributeIndex);
    });

    test('a missing payer ATA is never created by the merchant', async () => {
        const { creates, f } = await closeAndInspect({ existing: f => [f.merchant.address, DEVNET_TREASURY] });

        expect(creates).toEqual([]);
        expect(creates.map(create => create.ata)).not.toContain(await usdcAta(f.payer.address));
    });

    test('only the missing payee ATA is created', async () => {
        const { creates, f } = await closeAndInspect({ existing: f => [f.payer.address, DEVNET_TREASURY] });

        expect(creates.map(create => create.owner)).toEqual([f.merchant.address]);
    });

    test('existing destination ATAs add no create instructions', async () => {
        const { creates } = await closeAndInspect({
            existing: f => [f.payer.address, f.merchant.address, DEVNET_TREASURY],
        });

        expect(creates).toEqual([]);
    });

    test('a system-owned account at the ATA address is still created', async () => {
        // Lamports sent to an uninitialized ATA address leave it system-owned.
        const { creates, f } = await closeAndInspect({
            existing: f => [f.payer.address, DEVNET_TREASURY],
            foreign: f => [f.merchant.address],
        });

        expect(creates.map(create => create.owner)).toEqual([f.merchant.address]);
    });

    test('split recipient ATAs are created once each, deduplicated against the payee', async () => {
        const splitRecipient = (await generateKeyPairSigner()).address;
        const { creates, f } = await closeAndInspect({
            existing: f => [f.payer.address, DEVNET_TREASURY],
            splits: f => [
                { recipient: splitRecipient, shareBps: 500 },
                { recipient: f.merchant.address, shareBps: 250 },
            ],
        });

        expect(creates.map(create => create.owner)).toEqual([f.merchant.address, splitRecipient]);
    });
});

// ── verify() — close retry after a failed settlement ─────────────────────

describe('session() verify() close retry', () => {
    test('a failed settlement leaves close re-drivable without losing the watermark; the retry settles', async () => {
        const { f, method, sent, voucher } = await watermarkedFixture({ sendErrors: 1 });

        // First close: the on-chain settle submit fails — close stays
        // pending, and the voucher watermark survives untouched.
        await expect(
            verify(method, makeCred(f, { action: 'close', channelId: f.channel.address, voucher })),
        ).rejects.toThrow(/blockhash not found/);
        let state = await f.store.getChannel(f.channel.address);
        expect(state?.closeRequestedAt).toBeDefined();
        expect(state?.sealed).toBe(false);
        expect(state?.settledSignature).toBeUndefined();
        expect(state?.cumulative).toBe(250n);
        expect(state?.highestVoucherSignature).toBe(voucher.signature);

        // Retry succeeds and seals the channel.
        const receipt = await verify(method, makeCred(f, { action: 'close', channelId: f.channel.address, voucher }));
        expect(receipt.status).toBe('success');
        expect(sent).toHaveLength(1);
        state = await f.store.getChannel(f.channel.address);
        expect(state?.sealed).toBe(true);
        expect(state?.settledOnChain).toBe(250n);
        expect(state?.settledSignature).toBe('MockSig1');

        // A third close on the sealed channel rejects.
        await expect(
            verify(method, makeCred(f, { action: 'close', channelId: f.channel.address, voucher })),
        ).rejects.toThrow(/sealed/);
        expect(sent).toHaveLength(1);
    });
});

// ── verify() — operator-vs-client close authorization ────────────────────

describe('session() verify() close authorization', () => {
    test('client-mode close without a voucher is rejected', async () => {
        const { f, method, sent } = await watermarkedFixture();

        await expect(verify(method, makeCred(f, { action: 'close', channelId: f.channel.address }))).rejects.toThrow(
            /client-mode close requires a voucher/,
        );
        const state = await f.store.getChannel(f.channel.address);
        expect(state?.closeRequestedAt).toBeUndefined();
        expect(sent).toHaveLength(0);
    });

    test('client-mode close with an authentication proof is rejected', async () => {
        const { f, method, sent } = await watermarkedFixture();
        const authentication = await signSessionAuthentication({
            challengeId: 'open-challenge',
            channelId: f.channel.address,
            signer: f.payer,
        });

        await expect(
            verify(method, makeCred(f, { action: 'close', authentication, channelId: f.channel.address })),
        ).rejects.toThrow(/client-mode close must not include authentication/);
        const state = await f.store.getChannel(f.channel.address);
        expect(state?.closeRequestedAt).toBeUndefined();
        expect(sent).toHaveLength(0);
    });

    async function operatorFixture(rpcOptions: { sendErrors?: number } = {}) {
        const f = await makeFixture();
        const operator = await generateKeyPairSigner();
        const mock = mockRpc(rpcOptions);
        const method = makeMethod(f, mock.rpc, {
            operatorVoucherSigner: operator,
            voucherSigner: 'operator',
        });
        const authentication = await signSessionAuthentication({
            challengeId: 'open-challenge',
            channelId: f.channel.address,
            signer: f.payer,
        });
        await seedChannel(f, {
            authentication,
            authorizedSigner: operator.address,
            voucherSigner: 'operator',
        });
        return { ...mock, authentication, f, method, operator };
    }

    test('operator-mode close with the bound authentication proof succeeds and settles', async () => {
        const { authentication, f, method, sent } = await operatorFixture();

        const receipt = await verify(
            method,
            makeCred(f, { action: 'close', authentication, channelId: f.channel.address }),
        );
        expect(receipt.status).toBe('success');
        expect(receipt.reference).toBe(f.channel.address);
        expect(receipt).toMatchObject({ refunded: '1000', txHash: 'MockSig1' });
        expect(sent).toHaveLength(1);

        const state = await f.store.getChannel(f.channel.address);
        expect(state?.closeRequestedAt).toBeDefined();
        expect(state?.sealed).toBe(true);
        expect(state?.settledSignature).toBe('MockSig1');
    });

    test('operator-mode close must not include a voucher', async () => {
        const { authentication, f, method, operator, sent } = await operatorFixture();
        const voucher = await new ActiveSession({ channelId: f.channel.address, signer: operator }).prepareVoucher(
            100n,
        );

        await expect(
            verify(method, makeCred(f, { action: 'close', authentication, channelId: f.channel.address, voucher })),
        ).rejects.toThrow(/operator-mode close must not include a voucher/);
        const state = await f.store.getChannel(f.channel.address);
        expect(state?.closeRequestedAt).toBeUndefined();
        expect(sent).toHaveLength(0);
    });

    test('operator-mode close without the bound authentication proof is rejected', async () => {
        const { f, method, sent } = await operatorFixture();

        await expect(verify(method, makeCred(f, { action: 'close', channelId: f.channel.address }))).rejects.toThrow(
            /operator-mode close requires the bound authentication proof/,
        );
        const state = await f.store.getChannel(f.channel.address);
        expect(state?.closeRequestedAt).toBeUndefined();
        expect(sent).toHaveLength(0);
    });

    test('operator-mode close from an unauthorized closer is rejected', async () => {
        const { f, method, sent } = await operatorFixture();
        const intruder = await generateKeyPairSigner();
        // The intruder signs a valid-looking proof for this channel, but it
        // is not the proof bound at open (different payer + signature).
        const forged = await signSessionAuthentication({
            challengeId: 'open-challenge',
            channelId: f.channel.address,
            signer: intruder,
        });

        await expect(
            verify(method, makeCred(f, { action: 'close', authentication: forged, channelId: f.channel.address })),
        ).rejects.toThrow(/close authentication does not match the proof bound at open/);
        const state = await f.store.getChannel(f.channel.address);
        expect(state?.closeRequestedAt).toBeUndefined();
        expect(state?.sealed).toBe(false);
        expect(sent).toHaveLength(0);
    });

    test('operator-mode close against a record with no proof binding names the wiped/legacy state', async () => {
        const { authentication, f, method, sent } = await operatorFixture();
        // Simulate a record rewritten by a pre-binding writer: the binding
        // fields are gone, indistinguishable from a pre-binding record.
        await seedChannel(f, { authentication: undefined, openingChallengeId: '', voucherSigner: undefined });

        await expect(
            verify(method, makeCred(f, { action: 'close', authentication, channelId: f.channel.address })),
        ).rejects.toThrow(/session channel predates proof binding/);
        const state = await f.store.getChannel(f.channel.address);
        expect(state?.closeRequestedAt).toBeUndefined();
        expect(sent).toHaveLength(0);
    });

    test('use against a record with no proof binding names the wiped/legacy state', async () => {
        const { authentication, f, method } = await operatorFixture();
        await seedChannel(f, { authentication: undefined, openingChallengeId: '', voucherSigner: undefined });

        const credential = makeCred(f, { action: 'use', authentication, channelId: f.channel.address });
        const envelope = {
            capturedRequest: {
                headers: new Headers({ 'Idempotency-Key': 'request-1' }),
                method: 'POST',
                url: new URL('https://api.test/inference'),
            },
            challenge: credential.challenge,
            credential,
            request: credential.challenge.request,
        };
        await expect(
            method.verify({ credential, envelope, request: credential.challenge.request } as never),
        ).rejects.toThrow(/session channel predates proof binding/);
    });

    test('operator-mode close rejects a bound proof whose signature does not verify for this channel', async () => {
        const f = await makeFixture();
        const operator = await generateKeyPairSigner();
        const otherChannel = await generateKeyPairSigner();
        const { rpc, sent } = mockRpc();
        const method = makeMethod(f, rpc, {
            operatorVoucherSigner: operator,
            voucherSigner: 'operator',
        });
        // The stored proof was signed over a DIFFERENT channel id, so a close
        // replaying it matches the bound proof byte-for-byte yet fails
        // cryptographic verification against this channel.
        const mismatched = await signSessionAuthentication({
            challengeId: 'open-challenge',
            channelId: otherChannel.address,
            signer: f.payer,
        });
        await seedChannel(f, {
            authentication: mismatched,
            authorizedSigner: operator.address,
            voucherSigner: 'operator',
        });

        await expect(
            verify(method, makeCred(f, { action: 'close', authentication: mismatched, channelId: f.channel.address })),
        ).rejects.toThrow(/invalid close authentication signature/);
        const state = await f.store.getChannel(f.channel.address);
        expect(state?.closeRequestedAt).toBeUndefined();
        expect(sent).toHaveLength(0);
    });
});
