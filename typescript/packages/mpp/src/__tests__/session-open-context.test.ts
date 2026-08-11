/**
 * Coverage for mpp-specs e702dd8 "feat(solana/session): provide open
 * transaction context": new-channel 402 challenges carry
 * `methodDetails.recentBlockhash` + `methodDetails.recentSlot` from ONE
 * `getLatestBlockhash` observation, the client builds its open against them,
 * and the server binds the open back to the challenged values (openSlot
 * window + compiled-message blockhash) before broadcast.
 *
 * Mirrors the Rust tests in `rust/crates/kit/src/mpp/server/session.rs`
 * (`challenge_and_open_params_use_the_exact_contract`,
 * `challenge_fails_without_open_transaction_context`,
 * `open_enforces_expiry_authentication_and_rpc_verification`,
 * `confirmed_open_is_persisted_and_replays_without_reset` — blockhash leg)
 * and `rust/crates/kit/src/mpp/client/session.rs`
 * (`derive_open_uses_exact_nested_policy_and_validates_inputs`,
 * `transaction_and_opener_bind_fee_payer_and_operator_authentication`).
 */
import {
    generateKeyPairSigner,
    getBase64Codec,
    getCompiledTransactionMessageDecoder,
    getTransactionDecoder,
    getProgramDerivedAddress,
} from '@solana/kit';
import { describe, expect, test, vi } from 'vitest';

import { buildOpenPaymentChannelTransaction, derivePaymentChannelOpen } from '../client/PaymentChannels.js';
import { session as clientSession, type SessionRequest } from '../client/Session.js';
import { session as serverSession } from '../server/Session.js';
import { OPEN_SLOT_WINDOW, PAYMENT_CHANNELS_PROGRAM_ID, verifyOpenTx } from '../server/session/on-chain.js';

const TOKEN_PROGRAM = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA';
// resolveStablecoinMint('USDC', 'devnet')
const USDC_DEVNET_MINT = '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU';
const CHALLENGED_BLOCKHASH = 'EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N';
const CHALLENGED_SLOT = 314n;

function blockhashRpc(options: { currentSlot?: bigint; fail?: boolean; slot?: bigint } = {}) {
    const send = vi.fn(async () => {
        if (options.fail) throw new Error('rpc down');
        return {
            context: { slot: options.slot ?? CHALLENGED_SLOT },
            value: { blockhash: CHALLENGED_BLOCKHASH, lastValidBlockHeight: 100n },
        };
    });
    const getLatestBlockhash = vi.fn(() => ({ send }));
    const getSlot = vi.fn(() => ({ send: async () => options.currentSlot ?? options.slot ?? CHALLENGED_SLOT }));
    return { getLatestBlockhash, getSlot, send };
}

function serverParams(recipient: string, overrides: Record<string, unknown> = {}) {
    return {
        amount: 100n,
        currency: 'USDC',
        gracePeriodSeconds: 900,
        network: 'devnet',
        recipient,
        signer: undefined as never,
        ...overrides,
    };
}

async function methodFor(overrides: Record<string, unknown> = {}) {
    const signer = await generateKeyPairSigner();
    const method = serverSession({
        ...serverParams(signer.address, { signer, ...overrides }),
    } as never);
    return { method, signer };
}

type RequestHook = (options: {
    credential?: unknown;
    request: Record<string, unknown>;
}) => Promise<Record<string, unknown> & { methodDetails: Record<string, unknown> }>;

function requestHook(method: { request?: unknown }): RequestHook {
    return method.request as RequestHook;
}

describe('server challenge open-transaction context', () => {
    test('fresh 402 carries recentBlockhash + recentSlot from one getLatestBlockhash call', async () => {
        const rpc = blockhashRpc();
        const { method } = await methodFor({ rpc });
        const challenge = await requestHook(method)({ request: {} });

        expect(challenge.methodDetails.recentBlockhash).toBe(CHALLENGED_BLOCKHASH);
        // recentSlot is the response *context* slot, a decimal string u64.
        expect(challenge.methodDetails.recentSlot).toBe('314');
        expect(rpc.getLatestBlockhash).toHaveBeenCalledTimes(1);
        expect(rpc.send).toHaveBeenCalledTimes(1);
    });

    test('a warm blockhash cache feeds both fields without an RPC round-trip', async () => {
        const rpc = blockhashRpc();
        const cache = { get: vi.fn(() => ({ blockhash: CHALLENGED_BLOCKHASH, slot: 271n })) };
        const { method } = await methodFor({ blockhashCache: cache, rpc });
        const challenge = await requestHook(method)({ request: {} });

        expect(challenge.methodDetails.recentBlockhash).toBe(CHALLENGED_BLOCKHASH);
        expect(challenge.methodDetails.recentSlot).toBe('271');
        expect(cache.get).toHaveBeenCalledTimes(1);
        expect(rpc.getLatestBlockhash).not.toHaveBeenCalled();
    });

    test('an empty cache falls back to one direct fetch', async () => {
        const rpc = blockhashRpc();
        const { method } = await methodFor({ blockhashCache: { get: () => undefined }, rpc });
        const challenge = await requestHook(method)({ request: {} });

        expect(challenge.methodDetails.recentSlot).toBe('314');
        expect(rpc.getLatestBlockhash).toHaveBeenCalledTimes(1);
    });

    test('the challenge fails when the fetch fails — never a degraded 402 without the fields', async () => {
        const { method } = await methodFor({ rpc: blockhashRpc({ fail: true }) });
        await expect(requestHook(method)({ request: {} })).rejects.toThrow(
            /failed to fetch recentBlockhash\/recentSlot for session challenge/,
        );
    });

    test('the challenge fails without a cache or a blockhash-capable rpc', async () => {
        const { method } = await methodFor({ rpc: {} });
        await expect(requestHook(method)({ request: {} })).rejects.toThrow(
            /requires recentBlockhash\/recentSlot; configure a blockhashCache/,
        );
    });

    test('resume challenges (channelId present) omit both fields and skip the fetch', async () => {
        const rpc = blockhashRpc();
        const { method } = await methodFor({ rpc });
        const channel = await generateKeyPairSigner();
        const challenge = await requestHook(method)({
            request: { methodDetails: { channelId: channel.address } },
        });

        expect(challenge.methodDetails.channelId).toBe(channel.address);
        expect(challenge.methodDetails).not.toHaveProperty('recentBlockhash');
        expect(challenge.methodDetails).not.toHaveProperty('recentSlot');
        expect(rpc.getLatestBlockhash).not.toHaveBeenCalled();
    });

    test('the verify-path recompute (credential present) skips the fetch', async () => {
        const rpc = blockhashRpc();
        const { method } = await methodFor({ rpc });
        const challenge = await requestHook(method)({ credential: {}, request: {} });

        expect(challenge.methodDetails).not.toHaveProperty('recentBlockhash');
        expect(challenge.methodDetails).not.toHaveProperty('recentSlot');
        expect(rpc.getLatestBlockhash).not.toHaveBeenCalled();
    });
});

function challengeRequest(recipient: string, methodDetails: Record<string, unknown> = {}) {
    return {
        amount: '100',
        currency: 'USDC',
        recipient,
        suggestedDeposit: '5000',
        methodDetails: {
            channelProgram: PAYMENT_CHANNELS_PROGRAM_ID.toString(),
            gracePeriodSeconds: 900,
            network: 'devnet',
            recentBlockhash: CHALLENGED_BLOCKHASH,
            recentSlot: CHALLENGED_SLOT.toString(),
            tokenProgram: TOKEN_PROGRAM,
            ...methodDetails,
        },
    };
}

function openCredential(
    request: Record<string, unknown>,
    payload: Record<string, unknown>,
): { challenge: Record<string, unknown>; payload: Record<string, unknown> } {
    return {
        challenge: {
            id: 'open-challenge',
            intent: 'session',
            method: 'solana',
            realm: 'example.test',
            request,
        },
        payload: { action: 'open', ...payload },
    };
}

async function openPayloadFor(signer: { address: string }, openSlot: string) {
    return {
        authorizedSigner: signer.address,
        channelId: signer.address,
        depositAmount: '5000',
        gracePeriodSeconds: 900,
        mint: USDC_DEVNET_MINT,
        openSlot,
        payee: signer.address,
        payer: signer.address,
        salt: '7',
        transaction: 'wire',
    };
}

describe('server open verification binds to the challenged recentSlot', () => {
    test('rejects an openSlot ahead of the challenged recentSlot', async () => {
        const { method, signer } = await methodFor({ rpc: blockhashRpc() });
        const credential = openCredential(
            challengeRequest(signer.address),
            await openPayloadFor(signer, (CHALLENGED_SLOT + 1n).toString()),
        );
        await expect(method.verify({ credential, request: credential.challenge.request } as never)).rejects.toThrow(
            /openSlot 315 is ahead of the challenged recentSlot 314/,
        );
    });

    test('rejects an openSlot staler than OPEN_SLOT_WINDOW behind the challenged recentSlot', async () => {
        const { method, signer } = await methodFor({ rpc: blockhashRpc() });
        const staleRequest = challengeRequest(signer.address, {
            recentSlot: (42n + OPEN_SLOT_WINDOW + 1n).toString(),
        });
        const credential = openCredential(staleRequest, await openPayloadFor(signer, '42'));
        await expect(method.verify({ credential, request: credential.challenge.request } as never)).rejects.toThrow(
            /outside the 1500-slot freshness window of the challenged recentSlot/,
        );
    });

    test('rejects an open against a challenge without the open-transaction context', async () => {
        const { method, signer } = await methodFor({ rpc: blockhashRpc() });
        const bare = challengeRequest(signer.address);
        delete (bare.methodDetails as Record<string, unknown>).recentBlockhash;
        delete (bare.methodDetails as Record<string, unknown>).recentSlot;
        const credential = openCredential(bare, await openPayloadFor(signer, '42'));
        await expect(method.verify({ credential, request: credential.challenge.request } as never)).rejects.toThrow(
            /open requires a challenge carrying recentBlockhash\/recentSlot/,
        );
    });

    test('rejects an openSlot that aged out before verification', async () => {
        const currentSlot = CHALLENGED_SLOT + OPEN_SLOT_WINDOW + 1n;
        const { method, signer: merchant } = await methodFor({ rpc: blockhashRpc({ currentSlot }) });
        const payer = await generateKeyPairSigner();
        const sessionSigner = await generateKeyPairSigner();
        const request = challengeRequest(merchant.address) as unknown as SessionRequest;
        const open = await buildOpenPaymentChannelTransaction({
            authorizedSigner: sessionSigner.address,
            request,
            salt: 7n,
            signer: payer,
        });
        const credential = openCredential(request as unknown as Record<string, unknown>, {
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
        });
        await expect(method.verify({ credential, request: credential.challenge.request } as never)).rejects.toThrow(
            /outside the 1500-slot freshness window of the current cluster slot/,
        );
    });

    test('rejects an off-curve authorizedSigner', async () => {
        const { method, signer } = await methodFor({ rpc: blockhashRpc() });
        const [offCurveSigner] = await getProgramDerivedAddress({
            programAddress: PAYMENT_CHANNELS_PROGRAM_ID,
            seeds: [new TextEncoder().encode('off-curve-signer')],
        });
        const credential = openCredential(challengeRequest(signer.address), {
            ...(await openPayloadFor(signer, CHALLENGED_SLOT.toString())),
            authorizedSigner: offCurveSigner,
        });
        await expect(method.verify({ credential, request: credential.challenge.request } as never)).rejects.toThrow(
            /on-curve Ed25519 public key/,
        );
    });
});

async function clientOpenFixture() {
    const payer = await generateKeyPairSigner();
    const sessionSigner = await generateKeyPairSigner();
    const payee = await generateKeyPairSigner();
    const request = challengeRequest(payee.address) as unknown as SessionRequest;
    return { payee, payer, request, sessionSigner };
}

describe('client open builds against the challenged context', () => {
    test('openSlot defaults to the challenged recentSlot', async () => {
        const { payer, request, sessionSigner } = await clientOpenFixture();
        const open = await derivePaymentChannelOpen({
            authorizedSigner: sessionSigner.address,
            payer: payer.address,
            request,
            salt: 7n,
        });
        expect(open.openSlot).toBe(CHALLENGED_SLOT.toString());
    });

    test('an explicit openSlot override may rewind but never run ahead', async () => {
        const { payer, request, sessionSigner } = await clientOpenFixture();
        const earlier = await derivePaymentChannelOpen({
            authorizedSigner: sessionSigner.address,
            openSlot: CHALLENGED_SLOT - 5n,
            payer: payer.address,
            request,
            salt: 7n,
        });
        expect(earlier.openSlot).toBe((CHALLENGED_SLOT - 5n).toString());

        await expect(
            derivePaymentChannelOpen({
                authorizedSigner: sessionSigner.address,
                openSlot: CHALLENGED_SLOT + 1n,
                payer: payer.address,
                request,
                salt: 7n,
            }),
        ).rejects.toThrow(/openSlot override 315 is ahead of the challenged recentSlot 314/);
    });

    test('a new-channel challenge without recentSlot cannot derive an open', async () => {
        const { payer, request, sessionSigner } = await clientOpenFixture();
        const noSlot = {
            ...request,
            methodDetails: { ...request.methodDetails, recentSlot: undefined },
        } as SessionRequest;
        await expect(
            derivePaymentChannelOpen({
                authorizedSigner: sessionSigner.address,
                payer: payer.address,
                request: noSlot,
                salt: 7n,
            }),
        ).rejects.toThrow(/missing recentSlot; a new-channel challenge must provide it/);
    });

    test('the open transaction compiles against the challenged recentBlockhash — no RPC fetch', async () => {
        const { payer, request, sessionSigner } = await clientOpenFixture();
        const open = await buildOpenPaymentChannelTransaction({
            authorizedSigner: sessionSigner.address,
            request,
            salt: 7n,
            signer: payer,
        });
        expect(open.openSlot).toBe(CHALLENGED_SLOT.toString());
        const decoded = getTransactionDecoder().decode(getBase64Codec().encode(open.transaction));
        const message = getCompiledTransactionMessageDecoder().decode(decoded.messageBytes) as unknown as {
            lifetimeToken?: string;
        };
        expect(message.lifetimeToken).toBe(CHALLENGED_BLOCKHASH);
    });

    test('a new-channel challenge without recentBlockhash cannot build the open, unless overridden', async () => {
        const { payer, request, sessionSigner } = await clientOpenFixture();
        const noBlockhash = {
            ...request,
            methodDetails: { ...request.methodDetails, recentBlockhash: undefined },
        } as SessionRequest;
        await expect(
            buildOpenPaymentChannelTransaction({
                authorizedSigner: sessionSigner.address,
                request: noBlockhash,
                salt: 7n,
                signer: payer,
            }),
        ).rejects.toThrow(/missing recentBlockhash; a new-channel challenge must provide it/);

        // An explicit override is for tests and custom flows that re-issue
        // their own challenge binding.
        const open = await buildOpenPaymentChannelTransaction({
            authorizedSigner: sessionSigner.address,
            recentBlockhash: CHALLENGED_BLOCKHASH,
            request: noBlockhash,
            salt: 7n,
            signer: payer,
        });
        const decoded = getTransactionDecoder().decode(getBase64Codec().encode(open.transaction));
        const message = getCompiledTransactionMessageDecoder().decode(decoded.messageBytes) as unknown as {
            lifetimeToken?: string;
        };
        expect(message.lifetimeToken).toBe(CHALLENGED_BLOCKHASH);
    });

    test('the client session method defaults the open action openSlot from the challenge', async () => {
        const { payer, request, sessionSigner } = await clientOpenFixture();
        const method = clientSession({ channelId: sessionSigner.address, signer: sessionSigner });
        const challenge = {
            id: 'open-challenge',
            intent: 'session' as const,
            method: 'solana' as const,
            realm: 'example.test',
            request,
        };
        const serialized = await method.createCredential({
            challenge: challenge as never,
            context: {
                action: 'open',
                depositAmount: 5_000n,
                gracePeriodSeconds: 900,
                mint: USDC_DEVNET_MINT,
                payee: request.recipient,
                payer: payer.address,
                salt: 7n,
                transaction: 'wire',
            },
        } as never);
        const decoded = JSON.parse(
            atob(
                serialized
                    .replace(/^Payment /i, '')
                    .replace(/-/g, '+')
                    .replace(/_/g, '/'),
            ),
        ) as {
            payload: { openSlot: string };
        };
        expect(decoded.payload.openSlot).toBe(CHALLENGED_SLOT.toString());

        // A later openSlot override is rejected before any credential is built.
        await expect(
            method.createCredential({
                challenge: challenge as never,
                context: {
                    action: 'open',
                    depositAmount: 5_000n,
                    gracePeriodSeconds: 900,
                    mint: USDC_DEVNET_MINT,
                    openSlot: CHALLENGED_SLOT + 1n,
                    payee: request.recipient,
                    payer: payer.address,
                    salt: 7n,
                    transaction: 'wire',
                },
            } as never),
        ).rejects.toThrow(/ahead of the challenged recentSlot/);
    });
});

describe('verifyOpenTx enforces the challenged recentBlockhash', () => {
    async function verifiedOpenFixture() {
        const { payer, request, sessionSigner } = await clientOpenFixture();
        const open = await buildOpenPaymentChannelTransaction({
            authorizedSigner: sessionSigner.address,
            request,
            salt: 7n,
            signer: payer,
        });
        const openPayload = {
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
        const expected = {
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
        return { expected, open, openPayload };
    }

    test('accepts an open built against the challenged recentBlockhash', async () => {
        const { expected, open, openPayload } = await verifiedOpenFixture();
        const verified = await verifyOpenTx({ expected, openPayload: openPayload as never });
        expect(verified.channelId).toBe(open.channelId);
        expect(verified.openSlot).toBe(CHALLENGED_SLOT);
    });

    test('rejects an open whose compiled message uses a different blockhash — before broadcast', async () => {
        const { expected, openPayload } = await verifiedOpenFixture();
        const other = await generateKeyPairSigner();
        await expect(
            verifyOpenTx({
                expected: { ...expected, recentBlockhash: other.address },
                openPayload: openPayload as never,
            }),
        ).rejects.toThrow(/open transaction does not use the challenged recentBlockhash/);
    });
});

describe('verifyOpenTx binds distributionSplits to the challenge', () => {
    async function splitsFixture(openRecipients?: readonly { bps: number; recipient: string }[]) {
        const { payer, request, sessionSigner } = await clientOpenFixture();
        const platform = await generateKeyPairSigner();
        const challengedSplits = [{ recipient: platform.address as string, shareBps: 500 }];
        const challenged = {
            ...request,
            methodDetails: { ...request.methodDetails, distributionSplits: challengedSplits },
        } as unknown as SessionRequest;
        const open = await buildOpenPaymentChannelTransaction({
            authorizedSigner: sessionSigner.address,
            ...(openRecipients ? { recipients: openRecipients } : {}),
            request: challenged,
            salt: 7n,
            signer: payer,
        });
        const declaredSplits = (
            openRecipients ?? challengedSplits.map(s => ({ bps: s.shareBps, recipient: s.recipient }))
        ).map(entry => ({ recipient: entry.recipient, shareBps: entry.bps }));
        const openPayload = {
            authorizedSigner: sessionSigner.address,
            channelId: open.channelId,
            depositAmount: open.deposit,
            ...(declaredSplits.length ? { distributionSplits: declaredSplits } : {}),
            gracePeriodSeconds: open.gracePeriod,
            mint: open.mint,
            openSlot: open.openSlot,
            payee: open.payee,
            payer: open.payer,
            salt: open.salt,
            transaction: open.transaction,
        };
        const expected = {
            authorizedSigner: sessionSigner.address,
            channelProgram: PAYMENT_CHANNELS_PROGRAM_ID.toString(),
            currency: 'USDC',
            feePayer: payer.address,
            network: 'devnet',
            openSlot: CHALLENGED_SLOT,
            recentBlockhash: CHALLENGED_BLOCKHASH,
            recipient: open.payee,
            rentPayer: payer.address,
            splits: challengedSplits,
            tokenProgram: TOKEN_PROGRAM,
        };
        return { expected, open, openPayload };
    }

    test('accepts an open that encodes exactly the challenged splits', async () => {
        const { expected, open, openPayload } = await splitsFixture();
        const verified = await verifyOpenTx({ expected, openPayload: openPayload as never });
        expect(verified.channelId).toBe(open.channelId);
    });

    test('rejects a self-consistent open that drops the challenged splits', async () => {
        // The attack from the review: the client opens with NO splits (its
        // payload and instruction agree with each other), stealing the
        // platform share and making the server's settle-time distribute
        // revert against the committed distributionHash.
        const { expected, openPayload } = await splitsFixture([]);
        await expect(verifyOpenTx({ expected, openPayload: openPayload as never })).rejects.toThrow(
            /distributionSplits do not match the challenge/,
        );
    });

    test('rejects a self-consistent open whose splits redirect the challenged share', async () => {
        const attacker = await generateKeyPairSigner();
        const { expected, openPayload } = await splitsFixture([{ bps: 500, recipient: attacker.address }]);
        await expect(verifyOpenTx({ expected, openPayload: openPayload as never })).rejects.toThrow(
            /distributionSplits do not match the challenge/,
        );
    });
});
