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

import { generateKeyPairSigner, type KeyPairSigner } from '@solana/kit';
import { describe, expect, test } from 'vitest';

import { ActiveSession, signSessionAuthentication } from '../client/Session.js';
import { session } from '../server/Session.js';
import { buildTopUpInstruction, PAYMENT_CHANNELS_PROGRAM_ID } from '../server/session/on-chain.js';
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
function mockRpc(options: { confirmErr?: unknown; sendErrors?: number } = {}) {
    let sendErrors = options.sendErrors ?? 0;
    const sent: string[] = [];
    const statusCalls: string[] = [];
    const rpc = {
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
                return Promise.resolve({ value: sigs.map(() => ({ err: options.confirmErr ?? null })) });
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
    return { rpc, sent, statusCalls };
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
async function buildTopUpWire(f: Fixture, rpc: unknown, amount: bigint, payerSigner?: KeyPairSigner): Promise<string> {
    const payer = payerSigner ?? f.payer;
    const instruction = await buildTopUpInstruction({
        amount,
        channelId: f.channel.address,
        mint: USDC_DEVNET_MINT,
        payer,
        tokenProgram: TOKEN_PROGRAM,
    });
    return await buildAndSignWireTransaction(rpc as never, payer, [instruction]);
}

// ── verify() — topUp ────────────────────────────────────────────────────

describe('session() verify() topUp', () => {
    test('topUp verifies the wire transaction, confirms it on-chain, and raises the deposit', async () => {
        const f = await makeFixture();
        const { rpc, sent, statusCalls } = mockRpc();
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
        expect(receipt.reference).toBe('MockSig1');
        expect(sent).toHaveLength(1);
        expect(statusCalls).toContain('MockSig1');
        const state = await f.store.getChannel(f.channel.address);
        expect(state?.deposit).toBe(5_000n);
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

async function watermarkedFixture(rpcOptions: { sendErrors?: number } = {}) {
    const f = await makeFixture();
    const mock = mockRpc(rpcOptions);
    const method = makeMethod(f, mock.rpc);
    await seedChannel(f);

    const active = new ActiveSession({ channelId: f.channel.address, signer: f.sessionSigner });
    const voucher = await active.prepareVoucher(250n);
    const receipt = await verify(method, makeCred(f, { action: 'voucher', voucher }));
    return { ...mock, active, f, method, receipt, voucher };
}

describe('session() verify() close monotonicity', () => {
    test('an accepted voucher advances the watermark', async () => {
        const { f, receipt, voucher } = await watermarkedFixture();
        expect(receipt.status).toBe('success');
        expect(receipt.reference).toBe(`${f.channel.address}:250`);

        const state = await f.store.getChannel(f.channel.address);
        expect(state?.cumulative).toBe(250n);
        expect(state?.highestVoucherSignature).toBe(voucher.signature);
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
        expect(receipt.reference).toBe('MockSig1');
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
        expect(receipt.reference).toBe('MockSig1');
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
