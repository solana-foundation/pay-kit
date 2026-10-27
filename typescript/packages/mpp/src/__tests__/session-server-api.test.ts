// createSessionServer coverage (draft-solana-session-00): the per-action
// processing `session()` runs, exposed for hosts that drive sessions
// themselves.
//
//   - use: authenticate-then-charge-metered (`authenticateUse` +
//     `chargeOperatorRequest`), fixed-price `processUse`, and their refusals.
//   - open: the pre-broadcast checks (declared fields against the
//     configuration, the derived channel PDA, the exact open instruction,
//     account privileges and client signatures).
//   - topUp: the pre-broadcast checks, sponsored and client-paid.
//   - voucher and close: the operator-mode guard, malformed signatures, the
//     grace-period settlement window and the single recorded close.
//   - client: the challenge checks the open builder makes before signing.

import {
    createSignableMessage,
    generateKeyPairSigner,
    getBase58Decoder,
    getBase64Codec,
    getCompiledTransactionMessageDecoder,
    getCompiledTransactionMessageEncoder,
    getTransactionDecoder,
    getTransactionEncoder,
    type KeyPairSigner,
} from '@solana/kit';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';

import { type ClusterRpcStub, stubClusterRpc } from './cluster-rpc-stub.js';

import { buildOpenPaymentChannelTransaction, createPaymentChannelSessionOpener } from '../client/PaymentChannels.js';
import { DEFAULT_RPC_URLS } from '../constants.js';
import { type SessionRequest, signSessionAuthentication } from '../client/Session.js';
import { createSessionServer } from '../server/Session.js';
import {
    buildTopUpInstruction,
    deriveChannelAddress,
    PAYMENT_CHANNELS_PROGRAM_ID,
} from '../server/session/on-chain.js';
import { type ChannelState, createMemorySessionStore, type SessionStore } from '../server/session/store.js';
import { buildAndSignWireTransaction } from '../server/session/wire-tx.js';
import { encodeVoucherMessageLoose, verifyVoucherSignature } from '../shared/voucher.js';

// The open builder checks the challenged blockhash against the client's
// cluster RPC before signing; answer it locally.
let clusterRpc: ClusterRpcStub;
beforeEach(() => {
    clusterRpc = stubClusterRpc();
});
afterEach(() => {
    vi.unstubAllGlobals();
});

const TOKEN_PROGRAM = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA';
const USDC_DEVNET_MINT = '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU';
const BLOCKHASH = 'EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N';
const SLOT = 250_000_000n;
const CHALLENGE = 'challenge-open';

const rpcStub = {
    getLatestBlockhash: () => ({
        send: () =>
            Promise.resolve({ context: { slot: SLOT }, value: { blockhash: BLOCKHASH, lastValidBlockHeight: 1n } }),
    }),
};

interface Keys {
    readonly operator: KeyPairSigner;
    readonly payer: KeyPairSigner;
    readonly recipient: KeyPairSigner;
    readonly sessionSigner: KeyPairSigner;
    readonly sponsor: KeyPairSigner;
}

async function keys(): Promise<Keys> {
    return {
        operator: await generateKeyPairSigner(),
        payer: await generateKeyPairSigner(),
        recipient: await generateKeyPairSigner(),
        sessionSigner: await generateKeyPairSigner(),
        sponsor: await generateKeyPairSigner(),
    };
}

async function serverFor(
    k: Keys,
    store: SessionStore,
    overrides: Partial<Parameters<typeof createSessionServer>[0]> = {},
) {
    return createSessionServer({
        amount: 25n,
        currency: 'USDC',
        decimals: 6,
        minimumDeposit: 100n,
        network: 'devnet',
        operator: k.operator.address,
        recipient: k.recipient.address,
        rpc: rpcStub as never,
        signer: await generateKeyPairSigner(),
        store,
        ...overrides,
    });
}

function channel(k: Keys, overrides: Partial<ChannelState> = {}): ChannelState {
    return {
        authorizedSigner: k.sessionSigner.address,
        channelId: k.sessionSigner.address,
        committedDeliveries: [],
        cumulative: 0n,
        deposit: 1_000n,
        idleTimeoutSeconds: 300,
        nextDeliverySequence: 0n,
        openSlot: SLOT,
        openingChallengeId: CHALLENGE,
        payer: k.payer.address,
        pendingDeliveries: [],
        processedUses: [],
        rentPayer: k.payer.address,
        sealed: false,
        settledOnChain: 0n,
        spentAmount: 0n,
        voucherSigner: 'client',
        ...overrides,
    };
}

async function seed(store: SessionStore, state: ChannelState): Promise<void> {
    await store.updateChannel(state.channelId, () => state);
}

async function signedVoucher(signer: KeyPairSigner, channelId: string, cumulative: bigint, expiresAt = 4_102_444_800) {
    const data = { channelId, cumulativeAmount: cumulative.toString(), expiresAt };
    const [signatures] = await signer.signMessages([createSignableMessage(encodeVoucherMessageLoose(data))]);
    return {
        signature: getBase58Decoder().decode(new Uint8Array(signatures![signer.address]!)),
        signatureType: 'ed25519' as const,
        signer: signer.address,
        voucher: data,
    };
}

// ── use ─────────────────────────────────────────────────────────────────

async function operatorChannel(k: Keys, store: SessionStore, overrides: Partial<ChannelState> = {}) {
    const channelId = (await generateKeyPairSigner()).address;
    const authentication = await signSessionAuthentication({ challengeId: CHALLENGE, channelId, signer: k.payer });
    await seed(
        store,
        channel(k, {
            authentication,
            authorizedSigner: k.operator.address,
            channelId,
            cumulative: 100n,
            spentAmount: 100n,
            voucherSigner: 'operator',
            ...overrides,
        }),
    );
    return { action: 'use' as const, authentication, channelId };
}

describe('createSessionServer use', () => {
    test('a metered charge persists the operator voucher for acceptedCumulative plus the cost', async () => {
        const k = await keys();
        const store = createMemorySessionStore();
        const server = await serverFor(k, store, { voucherSigner: 'operator' });
        const use = await operatorChannel(k, store);

        const authenticated = await server.authenticateUse(use, 'c1', 'key-1');
        const charge = await server.chargeOperatorRequest(authenticated, k.operator, 7n);

        expect(charge).toMatchObject({ charged: 7n, cumulative: 107n, replay: false, requestTotal: 7n });
        const stored = await store.getChannel(use.channelId);
        expect(stored).toMatchObject({ cumulative: 107n, highestVoucherSignature: charge.voucher.signature });
        expect(stored?.spentAmount).toBe(107n);
        expect(stored?.processedUses).toEqual([
            expect.objectContaining({ amount: 7n, challengeId: 'c1', cumulative: 107n, idempotencyKey: 'key-1' }),
        ]);
        expect(
            await verifyVoucherSignature({
                signatureBase58: charge.voucher.signature,
                signerBase58: k.operator.address,
                voucher: charge.voucher.voucher,
            }),
        ).toBe(true);
    });

    test('a request is charged its running total once: a retry replays, a higher total pays the difference', async () => {
        const k = await keys();
        const store = createMemorySessionStore();
        const server = await serverFor(k, store, { voucherSigner: 'operator' });
        const use = await operatorChannel(k, store);
        const authenticated = await server.authenticateUse(use, 'c1', 'key-1');
        const first = await server.chargeOperatorRequest(authenticated, k.operator, 7n);

        const lower = await server.chargeOperatorRequest(authenticated, k.operator, 5n);
        expect(lower).toMatchObject({ charged: 0n, cumulative: 107n, replay: true });
        expect(lower.voucher.signature).toBe(first.voucher.signature);

        const more = await server.chargeOperatorRequest(authenticated, k.operator, 8n);
        expect(more).toMatchObject({ charged: 1n, cumulative: 108n, replay: false, requestTotal: 8n });
        const stored = await store.getChannel(use.channelId);
        expect(stored?.spentAmount).toBe(108n);
        expect(stored?.processedUses).toHaveLength(1);
    });

    test('the Idempotency-Key recorded under another challenge is refused', async () => {
        const k = await keys();
        const store = createMemorySessionStore();
        const server = await serverFor(k, store, { voucherSigner: 'operator' });
        const use = await operatorChannel(k, store);
        await server.chargeOperatorRequest(await server.authenticateUse(use, 'c1', 'key-1'), k.operator, 7n);

        const other = await server.authenticateUse(use, 'c2', 'key-1');
        await expect(server.chargeOperatorRequest(other, k.operator, 9n)).rejects.toThrow(
            /already used for a different request/,
        );
    });

    test('zero, over-deposit, closing and a foreign signer are refused', async () => {
        const k = await keys();
        const store = createMemorySessionStore();
        const server = await serverFor(k, store, { voucherSigner: 'operator' });
        const use = await operatorChannel(k, store);
        const authenticated = await server.authenticateUse(use, 'c1', 'key-1');

        await expect(server.chargeOperatorRequest(authenticated, k.operator, 0n)).rejects.toThrow(
            /charge amount must be positive/,
        );
        await expect(server.chargeOperatorRequest(authenticated, k.operator, 901n)).rejects.toThrow(
            /insufficient channel availability/,
        );
        await expect(server.chargeOperatorRequest(authenticated, k.payer, 1n)).rejects.toThrow(
            /does not match configured operator/,
        );
        await store.updateChannel(use.channelId, current => ({ ...current!, closeRequestedAt: 1n }));
        await expect(server.chargeOperatorRequest(authenticated, k.operator, 1n)).rejects.toThrow(/close is pending/);
        await expect(server.authenticateUse(use, 'c1', 'key-2')).rejects.toThrow(/close is pending/);
    });

    test('a proof other than the one bound at open does not authenticate', async () => {
        const k = await keys();
        const store = createMemorySessionStore();
        const server = await serverFor(k, store, { voucherSigner: 'operator' });
        const use = await operatorChannel(k, store);
        const stranger = await signSessionAuthentication({
            challengeId: CHALLENGE,
            channelId: use.channelId,
            signer: k.sponsor,
        });

        await expect(server.authenticateUse({ ...use, authentication: stranger }, 'c1', 'key-1')).rejects.toThrow(
            /use authentication does not match the proof bound at open/,
        );
        await expect(server.authenticateUse(use, 'c1', '')).rejects.toThrow(/Idempotency-Key/);
        const clientServer = await serverFor(k, store);
        await expect(clientServer.authenticateUse(use, 'c1', 'key-1')).rejects.toThrow(
            /only valid for operator-signed sessions/,
        );
    });

    test('processUse charges the challenged amount once per key and records it', async () => {
        const k = await keys();
        const store = createMemorySessionStore();
        const server = await serverFor(k, store, { operatorVoucherSigner: k.operator, voucherSigner: 'operator' });
        const use = await operatorChannel(k, store);

        const charge = await server.processUse(use, 'c1', 'key-1');
        expect(charge).toMatchObject({ charged: 25n, cumulative: 125n, replay: false });
        const replay = await server.processUse(use, 'c1', 'key-1');
        expect(replay).toMatchObject({ charged: 0n, cumulative: 125n, replay: true });
        const stored = await store.getChannel(use.channelId);
        expect(stored?.processedUses).toEqual([expect.objectContaining({ amount: 25n, cumulative: 125n })]);
        await expect(
            (await serverFor(k, store, { voucherSigner: 'operator' })).processUse(use, 'c1', 'k'),
        ).rejects.toThrow(/operatorVoucherSigner is required/);
    });
});

// ── open ────────────────────────────────────────────────────────────────

function openRequest(k: Keys, methodDetails: Record<string, unknown> = {}): SessionRequest {
    return {
        amount: '25',
        currency: USDC_DEVNET_MINT,
        methodDetails: {
            channelProgram: PAYMENT_CHANNELS_PROGRAM_ID.toString(),
            decimals: 6,
            gracePeriodSeconds: 900,
            network: 'devnet',
            recentBlockhash: BLOCKHASH,
            recentSlot: SLOT.toString(),
            ...methodDetails,
        },
        recipient: k.recipient.address,
    } as unknown as SessionRequest;
}

async function clientOpen(k: Keys, methodDetails: Record<string, unknown> = {}) {
    const open = await buildOpenPaymentChannelTransaction({
        authorizedSigner: k.sessionSigner.address,
        deposit: 1_000n,
        request: openRequest(k, methodDetails),
        salt: 7n,
        signer: k.payer,
    });
    return {
        authorizedSigner: k.sessionSigner.address,
        channelId: open.channelId,
        depositAmount: open.deposit,
        gracePeriodSeconds: open.gracePeriod,
        mint: open.mint,
        openSlot: open.openSlot,
        payee: open.payee,
        payer: open.payer,
        salt: open.salt,
        transaction: open.transaction as string,
    };
}

const challenge = { challengeId: CHALLENGE, recentBlockhash: BLOCKHASH, recentSlot: SLOT };

/** Rewrite the open's compiled message and re-sign it as `signers`. */
async function rewriteOpen(
    transaction: string,
    edit: (message: Record<string, unknown>) => Record<string, unknown>,
    signers: readonly KeyPairSigner[],
): Promise<string> {
    const tx = getTransactionDecoder().decode(getBase64Codec().encode(transaction));
    const compiled = getCompiledTransactionMessageDecoder().decode(tx.messageBytes) as unknown as Record<
        string,
        unknown
    >;
    const edited = edit(compiled) as { header: { numSignerAccounts: number }; staticAccounts: string[] };
    const messageBytes = getCompiledTransactionMessageEncoder().encode(edited as never);
    // One slot per required signer, in message order.
    let signatures: Record<string, unknown> = Object.fromEntries(
        edited.staticAccounts
            .slice(0, edited.header.numSignerAccounts)
            .map(key => [key, (tx.signatures as Record<string, unknown>)[key] ?? null]),
    );
    for (const signer of signers) {
        const [signature] = await signer.signMessages([{ content: messageBytes as Uint8Array } as never]);
        signatures = { ...signatures, ...signature };
    }
    return getBase64Codec().decode(
        getTransactionEncoder().encode({ messageBytes: messageBytes as never, signatures: signatures as never }),
    );
}

describe('createSessionServer verifyOpenPreBroadcast', () => {
    test('accepts the client open and reports the verified channel', async () => {
        const k = await keys();
        const server = await serverFor(k, createMemorySessionStore());
        const open = await clientOpen(k);

        const verified = await server.verifyOpenPreBroadcast(open, challenge);
        expect(verified).toMatchObject({
            channelId: open.channelId,
            deposit: 1_000n,
            idleTimeoutSeconds: 300,
            openSlot: SLOT,
            payer: k.payer.address,
            rentPayer: k.payer.address,
        });
    });

    test('a declared channel that is not the PDA of the declared fields is refused before the transaction', async () => {
        const k = await keys();
        const server = await serverFor(k, createMemorySessionStore());
        const open = await clientOpen(k);

        await expect(server.verifyOpenPreBroadcast({ ...open, salt: '8' }, challenge)).rejects.toThrow(
            /channelId does not match derived channel PDA/,
        );
        await expect(server.verifyOpenPreBroadcast({ ...open, payee: k.payer.address }, challenge)).rejects.toThrow(
            /payee does not match challenge recipient/,
        );
        await expect(server.verifyOpenPreBroadcast({ ...open, depositAmount: '0' }, challenge)).rejects.toThrow(
            /Deposit must be greater than zero/,
        );
        await expect(server.verifyOpenPreBroadcast({ ...open, depositAmount: '99' }, challenge)).rejects.toThrow(
            /below minimumDeposit/,
        );
        await expect(server.verifyOpenPreBroadcast({ ...open, gracePeriodSeconds: 60 }, challenge)).rejects.toThrow(
            /gracePeriodSeconds does not match challenge/,
        );
    });

    test('an extra writable account or a forged payer signature is refused', async () => {
        const k = await keys();
        const server = await serverFor(k, createMemorySessionStore());
        const open = await clientOpen(k);

        // The mint promoted to writable: every field still matches.
        const writableMint = await rewriteOpen(
            open.transaction,
            message => {
                const header = message.header as Record<string, number>;
                const accounts = message.staticAccounts as string[];
                const mintIndex = accounts.indexOf(USDC_DEVNET_MINT);
                const firstReadonly = accounts.length - header.numReadonlyNonSignerAccounts!;
                const reordered = [...accounts];
                [reordered[mintIndex], reordered[firstReadonly]] = [reordered[firstReadonly]!, reordered[mintIndex]!];
                const remap = (index: number) =>
                    index === mintIndex ? firstReadonly : index === firstReadonly ? mintIndex : index;
                return {
                    ...message,
                    header: { ...header, numReadonlyNonSignerAccounts: header.numReadonlyNonSignerAccounts! - 1 },
                    instructions: (
                        message.instructions as { accountIndices?: number[]; programAddressIndex: number }[]
                    ).map(ix => ({
                        ...ix,
                        accountIndices: ix.accountIndices?.map(remap),
                        programAddressIndex: remap(ix.programAddressIndex),
                    })),
                    staticAccounts: reordered,
                };
            },
            [k.payer],
        );
        await expect(server.verifyOpenPreBroadcast({ ...open, transaction: writableMint }, challenge)).rejects.toThrow(
            /privileges do not match committed policy/,
        );

        // A signature by another key in the payer's slot.
        const forged = await rewriteOpen(open.transaction, message => message, []);
        const tx = getTransactionDecoder().decode(getBase64Codec().encode(forged));
        const [stranger] = await k.sponsor.signMessages([{ content: tx.messageBytes } as never]);
        const forgedWire = getBase64Codec().decode(
            getTransactionEncoder().encode({
                messageBytes: tx.messageBytes,
                signatures: { ...tx.signatures, [k.payer.address]: stranger![k.sponsor.address] } as never,
            }),
        );
        await expect(server.verifyOpenPreBroadcast({ ...open, transaction: forgedWire }, challenge)).rejects.toThrow(
            /invalid client signature/,
        );
    });

    test('a sponsored open leaves the sponsor slot empty and refuses the sponsor as payer', async () => {
        const k = await keys();
        const server = await serverFor(k, createMemorySessionStore(), { feePayer: true, feePayerSigner: k.sponsor });
        const open = await clientOpen(k, { feePayer: true, feePayerKey: k.sponsor.address });

        await expect(server.verifyOpenPreBroadcast(open, challenge)).resolves.toMatchObject({
            rentPayer: k.sponsor.address,
        });
        const clientPaid = await clientOpen(k);
        await expect(server.verifyOpenPreBroadcast(clientPaid, challenge)).rejects.toThrow(/fee payer .* != expected/);
    });

    test('derives the channel PDA from its seed components', async () => {
        const k = await keys();
        const open = await clientOpen(k);
        await expect(
            deriveChannelAddress({
                authorizedSigner: k.sessionSigner.address,
                mint: USDC_DEVNET_MINT,
                openSlot: SLOT,
                payee: k.recipient.address,
                payer: k.payer.address,
                salt: 7n,
            }),
        ).resolves.toBe(open.channelId);
    });
});

// ── topUp ───────────────────────────────────────────────────────────────

async function topUpWire(k: Keys, channelId: string, amount: bigint, feePayer?: KeyPairSigner) {
    const instruction = await buildTopUpInstruction({
        amount,
        channelId,
        mint: USDC_DEVNET_MINT,
        payer: k.payer,
        tokenProgram: TOKEN_PROGRAM,
    });
    const wire = await buildAndSignWireTransaction(rpcStub as never, k.payer, [instruction]);
    if (!feePayer) return wire;
    return await rewriteOpen(
        wire,
        message => {
            // Prepend the sponsor as a writable signer fee payer, unsigned.
            const accounts = message.staticAccounts as string[];
            const header = message.header as Record<string, number>;
            return {
                ...message,
                header: { ...header, numSignerAccounts: header.numSignerAccounts! + 1 },
                instructions: (
                    message.instructions as { accountIndices?: number[]; programAddressIndex: number }[]
                ).map(ix => ({
                    ...ix,
                    accountIndices: ix.accountIndices?.map(index => index + 1),
                    programAddressIndex: ix.programAddressIndex + 1,
                })),
                staticAccounts: [feePayer.address, ...accounts],
            };
        },
        [k.payer],
    );
}

describe('createSessionServer verifyTopUpPreBroadcast', () => {
    test('accepts a client-paid top-up of the stored channel and refuses a mismatch', async () => {
        const k = await keys();
        const store = createMemorySessionStore();
        const server = await serverFor(k, store);
        const state = channel(k);
        await seed(store, state);
        const wire = await topUpWire(k, state.channelId, 500n);

        await expect(
            server.verifyTopUpPreBroadcast({
                action: 'topUp',
                additionalAmount: '500',
                channelId: state.channelId,
                transaction: wire,
            }),
        ).resolves.toBeUndefined();
        await expect(
            server.verifyTopUpPreBroadcast({
                action: 'topUp',
                additionalAmount: '400',
                channelId: state.channelId,
                transaction: wire,
            }),
        ).rejects.toThrow(/does not match additionalAmount/);
        await store.updateChannel(state.channelId, current => ({ ...current!, closeRequestedAt: 1n }));
        await expect(
            server.verifyTopUpPreBroadcast({
                action: 'topUp',
                additionalAmount: '500',
                channelId: state.channelId,
                transaction: wire,
            }),
        ).rejects.toThrow(/close is pending/);
    });

    test('a sponsored channel requires the sponsor as fee payer with its slot empty', async () => {
        const k = await keys();
        const store = createMemorySessionStore();
        const server = await serverFor(k, store, { feePayer: true, feePayerSigner: k.sponsor });
        const state = channel(k, { rentPayer: k.sponsor.address });
        await seed(store, state);
        const payload = { action: 'topUp' as const, additionalAmount: '500', channelId: state.channelId };

        await expect(
            server.verifyTopUpPreBroadcast({
                ...payload,
                transaction: await topUpWire(k, state.channelId, 500n, k.sponsor),
            }),
        ).resolves.toBeUndefined();
        await expect(
            server.verifyTopUpPreBroadcast({ ...payload, transaction: await topUpWire(k, state.channelId, 500n) }),
        ).rejects.toThrow(/fee payer does not match the challenge policy/);
        const unsponsored = await serverFor(k, store);
        await expect(
            unsponsored.verifyTopUpPreBroadcast({
                ...payload,
                transaction: await topUpWire(k, state.channelId, 500n, k.sponsor),
            }),
        ).rejects.toThrow(/requires the channel fee-payer signer/);
    });
});

// ── voucher and close ──────────────────────────────────────────────────

describe('createSessionServer voucher and close', () => {
    test('a voucher debits the challenged amount; an operator channel or a non-base58 signature is refused', async () => {
        const k = await keys();
        const store = createMemorySessionStore();
        const server = await serverFor(k, store);
        const state = channel(k);
        await seed(store, state);
        const voucher = await signedVoucher(k.sessionSigner, state.channelId, 30n);

        const accepted = await server.verifyVoucherForAmount(
            { action: 'voucher', channelId: state.channelId, voucher },
            25n,
        );
        expect(accepted).toMatchObject({ cumulative: 30n, spentAmount: 25n });

        await expect(
            server.verifyVoucherForAmount(
                { action: 'voucher', channelId: state.channelId, voucher: { ...voucher, signature: '0OIl' } },
                25n,
            ),
        ).rejects.toThrow(/invalid payload: voucher signature is not base58/);

        const operatorServer = await serverFor(k, store, { voucherSigner: 'operator' });
        await expect(
            operatorServer.verifyVoucherForAmount({ action: 'voucher', channelId: state.channelId, voucher }, 25n),
        ).rejects.toThrow(/does not authenticate an operator-signed session/);
    });

    test('a voucher expiring within the grace period is refused by default', async () => {
        const k = await keys();
        const store = createMemorySessionStore();
        const server = await serverFor(k, store);
        const state = channel(k);
        await seed(store, state);
        const soon = Math.floor(Date.now() / 1000) + 600;
        const voucher = await signedVoucher(k.sessionSigner, state.channelId, 30n, soon);

        await expect(
            server.verifyVoucherForAmount({ action: 'voucher', channelId: state.channelId, voucher }, 25n),
        ).rejects.toThrow(/settlement window/);
    });

    test('a close is recorded once', async () => {
        const k = await keys();
        const store = createMemorySessionStore();
        const server = await serverFor(k, store);
        const state = channel(k);
        await seed(store, state);
        const voucher = await signedVoucher(k.sessionSigner, state.channelId, 40n);
        const close = { action: 'close' as const, channelId: state.channelId, voucher };

        const closed = await server.processClose(close);
        expect(closed.cumulative).toBe(40n);
        expect(closed.closeRequestedAt).toBeDefined();
        await expect(server.processClose(close)).rejects.toThrow(/Close already requested/);
        await expect(server.processClose({ action: 'close', channelId: state.channelId })).rejects.toThrow(
            /Close already requested/,
        );
    });

    test('a client close without a voucher is refused', async () => {
        const k = await keys();
        const store = createMemorySessionStore();
        const server = await serverFor(k, store);
        await seed(store, channel(k));
        await expect(server.processClose({ action: 'close', channelId: k.sessionSigner.address })).rejects.toThrow(
            /client-mode close requires a voucher/,
        );
    });

    test('operator mode needs the operator address', async () => {
        const k = await keys();
        await expect(
            serverFor(k, createMemorySessionStore(), { operator: undefined, voucherSigner: 'operator' }),
        ).rejects.toThrow(/operator \(or operatorVoucherSigner\) is required/);
        await expect(
            serverFor(k, createMemorySessionStore(), { operatorVoucherSigner: k.payer, voucherSigner: 'operator' }),
        ).rejects.toThrow(/operatorVoucherSigner does not match operator/);
    });
});

// ── client open builder ────────────────────────────────────────────────

describe('client open builder challenge checks', () => {
    test.each([
        [{ decimals: undefined }, /missing decimals/],
        [{ decimals: 10 }, /outside 0 through 9/],
        [{ network: 'testnet' }, /Unsupported network/],
        [{ tokenProgram: '11111111111111111111111111111111' }, /neither SPL Token nor Token-2022/],
        [{ gracePeriodSeconds: 0 }, /gracePeriodSeconds must be greater than zero/],
        [{ channelProgram: 'Stake11111111111111111111111111111111111111' }, /unknown channel program/],
    ])('refuses %o', async (methodDetails, error) => {
        const k = await keys();
        await expect(clientOpen(k, methodDetails)).rejects.toThrow(error);
    });

    test('a program override must be the challenged program', async () => {
        const k = await keys();
        await expect(
            buildOpenPaymentChannelTransaction({
                authorizedSigner: k.sessionSigner.address,
                programAddress: 'Stake11111111111111111111111111111111111111',
                request: openRequest(k),
                signer: k.payer,
            }),
        ).rejects.toThrow(/program override does not match channelProgram/);
    });

    test('the challenged tokenProgram is the one the open uses', async () => {
        const k = await keys();
        const open = await clientOpen(k, { tokenProgram: 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb' });
        const tx = getTransactionDecoder().decode(getBase64Codec().encode(open.transaction));
        const message = getCompiledTransactionMessageDecoder().decode(tx.messageBytes);
        expect(message.staticAccounts).toContain('TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb');
    });

    describe('with the client cluster RPC', () => {
        const build = (k: Awaited<ReturnType<typeof keys>>, rpcUrl?: string) =>
            buildOpenPaymentChannelTransaction({
                authorizedSigner: k.sessionSigner.address,
                deposit: 1_000n,
                request: openRequest(k),
                ...(rpcUrl ? { rpcUrl } : {}),
                signer: k.payer,
            });

        test('a live challenged blockhash builds; a foreign one is refused before signing', async () => {
            const k = await keys();
            const rpcUrl = 'http://cluster.test:8899';
            await expect(build(k, rpcUrl)).resolves.toMatchObject({ payer: k.payer.address });
            expect(clusterRpc.checks.at(-1)?.url).toBe(rpcUrl);
            clusterRpc.live = false;
            await expect(build(k, rpcUrl)).rejects.toThrow(/is not a live blockhash on the client's cluster/);
        });

        test('the check runs by default against the challenged network RPC', async () => {
            const k = await keys();
            await expect(build(k)).resolves.toMatchObject({ payer: k.payer.address });
            expect(clusterRpc.checks).toEqual([{ blockhash: BLOCKHASH, url: DEFAULT_RPC_URLS.devnet }]);
            clusterRpc.live = false;
            await expect(build(k)).rejects.toThrow(/is not a live blockhash on the client's cluster/);
        });

        test('the session opener runs the check by default too', async () => {
            const k = await keys();
            clusterRpc.live = false;
            const opener = createPaymentChannelSessionOpener({ signer: k.payer });
            await expect(
                opener({ challenge: { id: 'challenge-1', request: openRequest(k) } } as never),
            ).rejects.toThrow(/is not a live blockhash on the client's cluster/);
            expect(clusterRpc.checks).toHaveLength(1);
        });

        test("an explicit blockhash override is the caller's own and skips the check", async () => {
            const k = await keys();
            clusterRpc.live = false;
            await expect(
                buildOpenPaymentChannelTransaction({
                    authorizedSigner: k.sessionSigner.address,
                    deposit: 1_000n,
                    recentBlockhash: BLOCKHASH,
                    request: openRequest(k),
                    signer: k.payer,
                }),
            ).resolves.toMatchObject({ payer: k.payer.address });
            expect(clusterRpc.checks).toHaveLength(0);
        });
    });
});
