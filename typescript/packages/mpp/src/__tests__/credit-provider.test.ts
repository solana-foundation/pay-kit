/**
 * Musebook credit-provider parity with the Rust kit (PRs #411/#414):
 * pinned devnet deployment resolution, per-payer hook derivation, the
 * client fail-closed matrix, server challenge emission + config
 * validation, and the credit authorization instruction pair.
 *
 * Mirrors `rust/crates/kit/src/core/credit_provider/musebook.rs`,
 * `rust/crates/kit/src/mpp/client/session.rs` (`credit_channel_hooks`,
 * `credit_authorization_instructions`) and
 * `rust/crates/kit/src/mpp/server/session.rs` (`credit_deployment`,
 * challenge `methodDetails`).
 */
import {
    generateKeyPairSigner,
    getAddressEncoder,
    getProgramDerivedAddress,
    getU64Encoder,
    getUtf8Encoder,
} from '@solana/kit';
import { describe, expect, test, vi } from 'vitest';

import { isSolanaSessionChallenge } from '../client/ChallengeSelection.js';
import {
    buildOpenPaymentChannelTransaction,
    creditAuthorizationInstructions,
    derivePaymentChannelOpen,
} from '../client/PaymentChannels.js';
import type { SessionRequest } from '../client/Session.js';
import { session as serverSession } from '../server/Session.js';
import {
    CreditProviderError,
    deploymentForNetwork,
    devnetWithProgram,
    distributionHash,
    encodeAuthorization,
    hooksForDeployment,
    isCreditChannel,
    ledgerAddress,
    MUSEBOOK_DEVNET_DEPLOYMENT,
    MUSEBOOK_DEVNET_PROGRAM_ID,
    PAYMENT_CHANNELS_V2_PROGRAM_ID,
    resolveDeployment,
    SPL_TOKEN_PROGRAM_ID,
    validateCreditProviders,
    validateCreditProvidersForNetwork,
} from '../shared/credit-provider.js';

const TOKEN_2022_PROGRAM = 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb';
const USDC_DEVNET_MINT = '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU';
const RECENT_BLOCKHASH = 'EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N';

async function keys() {
    return {
        authorizedSigner: await generateKeyPairSigner(),
        issuer: await generateKeyPairSigner(),
        payee: await generateKeyPairSigner(),
        payer: await generateKeyPairSigner(),
    };
}

function creditRequest(
    overrides: Record<string, unknown> = {},
    detailOverrides: Record<string, unknown> = {},
): SessionRequest {
    return {
        amount: '100',
        currency: 'USDC',
        methodDetails: {
            channelProgram: PAYMENT_CHANNELS_V2_PROGRAM_ID,
            channelVersion: 2,
            creditIssuer: '11111111111111111111111111111111',
            creditProvider: 'musebook',
            decimals: 6,
            gracePeriodSeconds: 900,
            network: 'devnet',
            recentBlockhash: RECENT_BLOCKHASH,
            recentSlot: '314',
            tokenProgram: SPL_TOKEN_PROGRAM_ID,
            ...detailOverrides,
        },
        recipient: '11111111111111111111111111111111',
        suggestedDeposit: '5000',
        ...overrides,
    } as SessionRequest;
}

describe('deployment resolution', () => {
    test('devnet (bare or solana:-prefixed) resolves the pinned deployment', () => {
        expect(deploymentForNetwork('devnet')).toEqual(MUSEBOOK_DEVNET_DEPLOYMENT);
        expect(deploymentForNetwork('solana:devnet')).toEqual(MUSEBOOK_DEVNET_DEPLOYMENT);
        expect(MUSEBOOK_DEVNET_DEPLOYMENT.programId).toBe(MUSEBOOK_DEVNET_PROGRAM_ID);
        expect(MUSEBOOK_DEVNET_DEPLOYMENT.channelProgramId).toBe(PAYMENT_CHANNELS_V2_PROGRAM_ID);
    });

    test('every other network is unavailable, with no normalization surprises', () => {
        for (const network of ['mainnet', 'solana:mainnet', 'testnet', 'localnet', 'Devnet', '']) {
            expect(deploymentForNetwork(network)).toBeUndefined();
        }
    });

    test('resolve: default program resolves, explicit default matches, override is devnet-only', async () => {
        const other = (await generateKeyPairSigner()).address.toString();
        expect(resolveDeployment('devnet')).toEqual(MUSEBOOK_DEVNET_DEPLOYMENT);
        expect(resolveDeployment('devnet', MUSEBOOK_DEVNET_PROGRAM_ID)).toEqual(MUSEBOOK_DEVNET_DEPLOYMENT);
        expect(resolveDeployment('devnet', other)?.programId).toBe(other);
        expect(resolveDeployment('devnet', other)?.channelProgramId).toBe(PAYMENT_CHANNELS_V2_PROGRAM_ID);
        expect(resolveDeployment('mainnet', other)).toBeUndefined();
        expect(resolveDeployment('devnet', 'not-a-pubkey')).toBeUndefined();
    });

    test('devnetWithProgram builds a devnet-only override and rejects bad keys', async () => {
        const other = (await generateKeyPairSigner()).address.toString();
        expect(devnetWithProgram(other)?.programId).toBe(other);
        expect(devnetWithProgram(other)?.cluster).toBe('devnet');
        expect(devnetWithProgram('not-a-pubkey')).toBeUndefined();
    });
});

describe('provider gate', () => {
    test('without a network every provider is unavailable (fail closed)', () => {
        for (const provider of ['coinflow', 'musebook'] as const) {
            try {
                validateCreditProviders([provider]);
                expect.unreachable();
            } catch (error) {
                expect(error).toBeInstanceOf(CreditProviderError);
                expect((error as CreditProviderError).provider).toBe(provider);
            }
        }
        expect(() => validateCreditProviders([])).not.toThrow();
    });

    test('musebook is available exactly on devnet; coinflow never', () => {
        expect(() => validateCreditProvidersForNetwork(['musebook'], 'devnet')).not.toThrow();
        expect(() => validateCreditProvidersForNetwork(['musebook'], 'solana:devnet')).not.toThrow();
        expect(() => validateCreditProvidersForNetwork(['musebook'], 'mainnet')).toThrow(CreditProviderError);
        expect(() => validateCreditProvidersForNetwork(['coinflow'], 'devnet')).toThrow(CreditProviderError);
    });
});

describe('hook derivation', () => {
    test('the pinned descriptor lands in preFund + postDistribute only', async () => {
        const { payer } = await keys();
        const hooks = await hooksForDeployment(MUSEBOOK_DEVNET_DEPLOYMENT, payer.address, USDC_DEVNET_MINT);
        expect(hooks.postFund).toBeUndefined();
        expect(hooks.preDistribute).toBeUndefined();
        expect(hooks.preFund).toEqual(hooks.postDistribute);
        const descriptor = hooks.preFund!;
        expect(descriptor.programId).toBe(MUSEBOOK_DEVNET_PROGRAM_ID);
        expect(descriptor.entrypoint).toEqual([109, 117, 115, 101, 98, 111, 111, 107]); // "musebook"
        expect(descriptor.staticData).toEqual([]);
        expect(descriptor.accounts).toHaveLength(4);
        const ledger = await ledgerAddress(MUSEBOOK_DEVNET_DEPLOYMENT, payer.address, USDC_DEVNET_MINT);
        expect(descriptor.accounts[0]).toEqual({ address: ledger, writable: true });
        expect(descriptor.accounts[1]?.writable).toBe(true);
        expect(descriptor.accounts[2]?.writable).toBe(true);
        expect(descriptor.accounts[3]).toEqual({ address: SPL_TOKEN_PROGRAM_ID, writable: false });
    });

    test('isCreditChannel is an exact match, not a resemblance', async () => {
        const { payer } = await keys();
        const hooks = await hooksForDeployment(MUSEBOOK_DEVNET_DEPLOYMENT, payer.address, USDC_DEVNET_MINT);
        await expect(isCreditChannel(MUSEBOOK_DEVNET_DEPLOYMENT, hooks, payer.address, USDC_DEVNET_MINT)).resolves.toBe(
            true,
        );
        const otherProgram = { ...hooks, preFund: { ...hooks.preFund!, programId: payer.address } };
        await expect(
            isCreditChannel(MUSEBOOK_DEVNET_DEPLOYMENT, otherProgram, payer.address, USDC_DEVNET_MINT),
        ).resolves.toBe(false);
        const extraSlot = { ...hooks, postFund: hooks.preFund };
        await expect(
            isCreditChannel(MUSEBOOK_DEVNET_DEPLOYMENT, extraSlot, payer.address, USDC_DEVNET_MINT),
        ).resolves.toBe(false);
        const otherMint = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v'; // mainnet USDC
        await expect(isCreditChannel(MUSEBOOK_DEVNET_DEPLOYMENT, hooks, payer.address, otherMint)).resolves.toBe(false);
    });
});

describe('authorization encoding', () => {
    test('distributionHash is the Rust sha256 preimage hash', async () => {
        const { payee } = await keys();
        const sole = [{ bps: 10_000, recipient: payee.address }];
        const hash = await distributionHash(sole);
        expect(hash).toHaveLength(32);
        await expect(distributionHash(sole)).resolves.toEqual(hash);
        const split = await distributionHash([
            { bps: 5_000, recipient: payee.address },
            { bps: 5_000, recipient: payee.address },
        ]);
        expect(split).not.toEqual(hash);
    });

    test('encodeAuthorization lays out the fixed 136-byte body', async () => {
        const { authorizedSigner, payee } = await keys();
        const body = encodeAuthorization({
            authorizedSigner: authorizedSigner.address,
            cap: 7_500n,
            distributionHash: new Uint8Array(32).fill(9),
            expiresAtSlot: 9_314n,
            nonce: 3n,
            openSlot: 314n,
            payee: payee.address,
            salt: 42n,
        });
        expect(body).toHaveLength(136);
        const view = new DataView(body.buffer, body.byteOffset);
        expect(view.getBigUint64(96, true)).toBe(42n); // salt
        expect(view.getBigUint64(104, true)).toBe(314n); // openSlot
        expect(view.getBigUint64(112, true)).toBe(7_500n); // cap
        expect(view.getBigUint64(120, true)).toBe(3n); // nonce
        expect(view.getBigUint64(128, true)).toBe(9_314n); // expiresAtSlot
        expect(body[64]).toBe(9); // distributionHash starts at 64
    });
});

describe('client credit challenges', () => {
    test('a credit challenge parses through the session schema', async () => {
        const { issuer, payee } = await keys();
        const request = creditRequest({ recipient: payee.address }, { creditIssuer: issuer.address });
        const challenge = {
            id: 'credit-challenge',
            intent: 'session',
            method: 'solana',
            realm: 'test',
            request,
        };
        expect(isSolanaSessionChallenge(challenge as never)).toBe(true);
    });

    test('derive returns the channel under the V2 program plus the derived hooks', async () => {
        const { authorizedSigner, issuer, payee, payer } = await keys();
        const request = creditRequest({ recipient: payee.address }, { creditIssuer: issuer.address });
        const open = await derivePaymentChannelOpen({
            authorizedSigner: authorizedSigner.address,
            payer: payer.address,
            request,
            salt: 42n,
        });
        expect(open.channelHooks?.preFund?.programId).toBe(MUSEBOOK_DEVNET_PROGRAM_ID);
        expect(open.channelHooks?.postDistribute).toEqual(open.channelHooks?.preFund);
        const [expectedChannel] = await getProgramDerivedAddress({
            programAddress: PAYMENT_CHANNELS_V2_PROGRAM_ID as never,
            seeds: [
                getUtf8Encoder().encode('channel'),
                getAddressEncoder().encode(payer.address),
                getAddressEncoder().encode(payee.address),
                getAddressEncoder().encode(USDC_DEVNET_MINT as never),
                getAddressEncoder().encode(authorizedSigner.address),
                getU64Encoder().encode(42n),
                getU64Encoder().encode(314n),
            ],
        });
        expect(open.channelId).toBe(expectedChannel.toString());
    });

    test('the fail-closed matrix refuses every degraded credit challenge', async () => {
        const { authorizedSigner, issuer, payee, payer } = await keys();
        const base = { recipient: payee.address };
        const cases: { details: Record<string, unknown>; pattern: RegExp }[] = [
            { details: { creditProvider: 'coinflow' }, pattern: /credit provider coinflow: unavailable/ },
            {
                details: {
                    channelHooks: { preFund: { accounts: [], entrypoint: [], programId: 'x', staticData: [] } },
                },
                pattern: /must not also carry channelHooks/,
            },
            { details: { channelVersion: 1 }, pattern: /pinned V2 channel program/ },
            { details: { channelVersion: undefined }, pattern: /pinned V2 channel program/ },
            {
                details: { channelProgram: 'CHNLxYvVA28MJP9PrFuDXccuoGXAx7jBacfLEkahyGsX' },
                pattern: /pinned V2 channel program/,
            },
            { details: { tokenProgram: TOKEN_2022_PROGRAM }, pattern: /token program must be SPL Token/ },
            { details: { feePayer: true, feePayerKey: issuer.address }, pattern: /sponsored opens are not supported/ },
            { details: { network: 'mainnet' }, pattern: /unavailable on this network/ },
        ];
        for (const { details, pattern } of cases) {
            const request = creditRequest(base, { ...details, creditIssuer: issuer.address });
            await expect(
                derivePaymentChannelOpen({
                    authorizedSigner: authorizedSigner.address,
                    payer: payer.address,
                    request,
                    salt: 42n,
                }),
            ).rejects.toThrow(pattern);
        }
    });

    test('buildOpenPaymentChannelTransaction refuses credit challenges (no V2 client yet)', async () => {
        const { authorizedSigner, issuer, payee, payer } = await keys();
        const request = creditRequest({ recipient: payee.address }, { creditIssuer: issuer.address });
        await expect(
            buildOpenPaymentChannelTransaction({
                authorizedSigner: authorizedSigner.address,
                request,
                signer: payer,
            }),
        ).rejects.toThrow(/V2 hooked channel program/);
    });

    test('creditAuthorizationInstructions builds [Approve, authorize] bound to the open', async () => {
        const { authorizedSigner, issuer, payee, payer } = await keys();
        const request = creditRequest({ recipient: payee.address }, { creditIssuer: issuer.address });
        const open = await derivePaymentChannelOpen({
            authorizedSigner: authorizedSigner.address,
            payer: payer.address,
            request,
            salt: 42n,
        });
        const instructions = await creditAuthorizationInstructions({
            authorizedSigner: authorizedSigner.address,
            open,
            request,
            terms: { cap: 5_000n, expiresAtSlot: 9_314n, nonce: 0n },
        });
        expect(instructions).toHaveLength(2);
        const [approve, authorize] = instructions as [never, never] as unknown as [
            { programAddress: string; data: Uint8Array; accounts: { address: string; role: string }[] },
            { programAddress: string; data: Uint8Array; accounts: { address: string; role: string }[] },
        ];
        expect(approve.programAddress.toString()).toBe(SPL_TOKEN_PROGRAM_ID);
        expect(approve.data[0]).toBe(4); // SPL Token Approve
        expect(new DataView(approve.data.buffer, approve.data.byteOffset).getBigUint64(1, true)).toBe(5_000n);
        expect(authorize.programAddress.toString()).toBe(MUSEBOOK_DEVNET_PROGRAM_ID);
        expect(authorize.data[0]).toBe(2); // provider authorize
        expect(authorize.data).toHaveLength(137);
        const ledger = await ledgerAddress(MUSEBOOK_DEVNET_DEPLOYMENT, payer.address, USDC_DEVNET_MINT);
        expect(authorize.accounts[0]?.address.toString()).toBe(payer.address);
        expect(authorize.accounts[1]?.address.toString()).toBe(issuer.address);
        expect(authorize.accounts[2]?.address.toString()).toBe(ledger);
        await expect(
            creditAuthorizationInstructions({
                authorizedSigner: authorizedSigner.address,
                open,
                request,
                terms: { cap: 4_999n, expiresAtSlot: 9_314n, nonce: 0n },
            }),
        ).rejects.toThrow(/cap is below the channel deposit/);
    });
});

function blockhashRpc() {
    const send = vi.fn(async () => ({
        context: { slot: 314n },
        value: { blockhash: RECENT_BLOCKHASH, lastValidBlockHeight: 100n },
    }));
    return { getLatestBlockhash: vi.fn(() => ({ send })), getSlot: vi.fn(() => ({ send })) };
}

async function creditServerParams(overrides: Record<string, unknown> = {}) {
    const signer = await generateKeyPairSigner();
    const issuerSigner = await generateKeyPairSigner();
    return {
        issuerSigner,
        params: {
            amount: 100n,
            channelProgram: PAYMENT_CHANNELS_V2_PROGRAM_ID,
            creditIssuerSigner: issuerSigner,
            creditMaxCap: 1_000_000n,
            creditProvider: 'musebook',
            currency: 'USDC',
            gracePeriodSeconds: 900,
            network: 'devnet',
            recipient: signer.address,
            rpc: blockhashRpc(),
            signer,
            ...overrides,
        },
    };
}

type RequestHook = (options: {
    credential?: unknown;
    request: Record<string, unknown>;
}) => Promise<Record<string, unknown> & { methodDetails: Record<string, unknown> }>;

describe('server credit sessions', () => {
    test('the challenge advertises creditProvider, creditIssuer and channelVersion 2', async () => {
        const { issuerSigner, params } = await creditServerParams();
        const method = serverSession(params as never) as { request?: unknown };
        const challenge = await (method.request as RequestHook)({ request: {} });
        expect(challenge.methodDetails.channelProgram).toBe(PAYMENT_CHANNELS_V2_PROGRAM_ID);
        expect(challenge.methodDetails.channelVersion).toBe(2);
        expect(challenge.methodDetails.creditProvider).toBe('musebook');
        expect(challenge.methodDetails.creditIssuer).toBe(issuerSigner.address);
        expect(challenge.methodDetails.feePayer).toBeUndefined();
    });

    test('configuration fails closed on every pinned-fact mismatch', async () => {
        const cases: { overrides: Record<string, unknown>; pattern: RegExp }[] = [
            { overrides: { creditIssuerSigner: undefined }, pattern: /creditIssuerSigner is required/ },
            { overrides: { channelProgram: undefined }, pattern: /pinned V2 channel program/ },
            {
                overrides: { channelProgram: 'CHNLxYvVA28MJP9PrFuDXccuoGXAx7jBacfLEkahyGsX' },
                pattern: /pinned V2 channel program/,
            },
            { overrides: { network: 'mainnet' }, pattern: /unavailable on network "mainnet"/ },
            { overrides: { tokenProgram: TOKEN_2022_PROGRAM }, pattern: /tokenProgram must be SPL Token/ },
            { overrides: { creditProvider: 'coinflow' }, pattern: /credit provider coinflow is unavailable/ },
        ];
        for (const { overrides, pattern } of cases) {
            const { params } = await creditServerParams(overrides);
            expect(() => serverSession(params as never)).toThrow(pattern);
        }
        const { issuerSigner, params } = await creditServerParams();
        const feePayerParams = { ...params, feePayer: true, feePayerSigner: issuerSigner };
        expect(() => serverSession(feePayerParams as never)).toThrow(/sponsored sessions are not supported/);
    });
});
