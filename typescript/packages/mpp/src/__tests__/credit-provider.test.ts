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
    address,
    appendTransactionMessageInstructions,
    type Blockhash,
    createTransactionMessage,
    generateKeyPairSigner,
    getAddressEncoder,
    getBase64Codec,
    getBase64EncodedWireTransaction,
    getProgramDerivedAddress,
    getTransactionDecoder,
    getU64Encoder,
    getUtf8Encoder,
    partiallySignTransactionMessageWithSigners,
    pipe,
    setTransactionMessageFeePayerSigner,
    setTransactionMessageLifetimeUsingBlockhash,
} from '@solana/kit';
import { findAssociatedTokenPda } from '@solana-program/token';
import { describe, expect, test, vi } from 'vitest';

import { isSolanaSessionChallenge } from '../client/ChallengeSelection.js';
import {
    buildOpenPaymentChannelTransaction,
    creditAuthorizationInstructions,
    derivePaymentChannelOpen,
} from '../client/PaymentChannels.js';
import type { SessionRequest } from '../client/Session.js';
import { ASSOCIATED_TOKEN_PROGRAM } from '../constants.js';
import { findEventAuthorityPda, getOpenInstruction } from '../generated/payment-channels/index.js';
import { createSessionServer, session as serverSession } from '../server/Session.js';
import { createMemorySessionStore } from '../server/session/store.js';
import {
    CreditProviderError,
    decodeAuthorization,
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
import { buildOpenWithHooks } from '../shared/payment-channels-v2.js';

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
        expect(descriptor.accounts![0]).toEqual({ address: ledger, writable: true });
        expect(descriptor.accounts![1]?.writable).toBe(true);
        expect(descriptor.accounts![2]?.writable).toBe(true);
        expect(descriptor.accounts![3]).toEqual({ address: SPL_TOKEN_PROGRAM_ID, writable: false });
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

// ── Greptile PR #417 fixes ──────────────────────────────────────────────
// The default authorization hash, the hooked-open server verifier, and
// the issuer co-signing step (`processCreditAuthorization`).

const RENT_SYSVAR = 'SysvarRent111111111111111111111111111111111';
const CHALLENGE_CTX = { challengeId: 'credit-open-1', recentBlockhash: RECENT_BLOCKHASH, recentSlot: 314n };

async function creditFixture(overrides: Record<string, unknown> = {}) {
    const { authorizedSigner, issuer, payee, payer } = await keys();
    const request = creditRequest({ recipient: payee.address }, { creditIssuer: issuer.address });
    const open = await derivePaymentChannelOpen({
        authorizedSigner: authorizedSigner.address,
        payer: payer.address,
        request,
        salt: 42n,
    });
    const server = createSessionServer({
        amount: 100n,
        channelProgram: PAYMENT_CHANNELS_V2_PROGRAM_ID,
        creditIssuerSigner: issuer,
        creditMaxCap: 1_000_000n,
        creditProvider: 'musebook',
        currency: 'USDC',
        decimals: 6,
        gracePeriodSeconds: 900,
        minimumDeposit: 100n,
        network: 'devnet',
        operator: (await generateKeyPairSigner()).address,
        recipient: payee.address,
        rpc: blockhashRpc(),
        signer: await generateKeyPairSigner(),
        store: createMemorySessionStore(),
        ...overrides,
    } as never);
    const payload = {
        authorizedSigner: authorizedSigner.address,
        channelId: open.channelId,
        depositAmount: String(open.deposit),
        gracePeriodSeconds: open.gracePeriod,
        mint: open.mint,
        openSlot: String(open.openSlot),
        payee: open.payee,
        payer: open.payer,
        salt: String(open.salt),
    };
    return { authorizedSigner, issuer, open, payee, payer, payload, request, server };
}

async function signWire(
    signer: never,
    instructions: readonly unknown[],
    blockhash: string = RECENT_BLOCKHASH,
): Promise<string> {
    const message = pipe(
        createTransactionMessage({ version: 0 }),
        m => setTransactionMessageFeePayerSigner(signer, m),
        m =>
            setTransactionMessageLifetimeUsingBlockhash(
                { blockhash: blockhash as Blockhash, lastValidBlockHeight: 100n },
                m,
            ),
        m => appendTransactionMessageInstructions(instructions as never, m),
    );
    const signed = await partiallySignTransactionMessageWithSigners(message);
    return getBase64EncodedWireTransaction(signed);
}

async function authorizationTx(
    fx: Awaited<ReturnType<typeof creditFixture>>,
    terms: { cap: bigint; expiresAtSlot: bigint; nonce: bigint } = { cap: 5_000n, expiresAtSlot: 9_314n, nonce: 0n },
    openOverride?: unknown,
    requestOverride?: unknown,
): Promise<string> {
    const instructions = await creditAuthorizationInstructions({
        authorizedSigner: fx.authorizedSigner.address,
        open: (openOverride ?? fx.open) as never,
        request: (requestOverride ?? fx.request) as never,
        terms,
    });
    return signWire(fx.payer as never, instructions);
}

describe('Greptile #417: default authorization hash', () => {
    test('with no splits anywhere, the authorization hashes the empty distribution list', async () => {
        const fx = await creditFixture();
        const instructions = await creditAuthorizationInstructions({
            authorizedSigner: fx.authorizedSigner.address,
            open: fx.open,
            request: fx.request,
            terms: { cap: 5_000n, expiresAtSlot: 9_314n, nonce: 0n },
        });
        const decoded = decodeAuthorization(instructions[1]!.data as Uint8Array);
        expect(decoded).toBeDefined();
        expect([...decoded!.distributionHash]).toEqual([...(await distributionHash([]))]);
        const solePayee = await distributionHash([{ bps: 10_000, recipient: fx.open.payee }]);
        expect([...decoded!.distributionHash]).not.toEqual([...solePayee]);
    });
});

describe('Greptile #417: issuer co-signing (processCreditAuthorization)', () => {
    test('validates the owner authorization and returns it with the issuer signature added', async () => {
        const fx = await creditFixture();
        const tx = await authorizationTx(fx);
        const cosigned = await fx.server.processCreditAuthorization(fx.payload as never, tx, CHALLENGE_CTX as never);
        const decoded = getTransactionDecoder().decode(getBase64Codec().encode(cosigned));
        expect(decoded.signatures[fx.payer.address]).not.toBeNull();
        expect(decoded.signatures[fx.issuer.address]).not.toBeNull();
    });

    test('refuses a cap above creditMaxCap', async () => {
        const fx = await creditFixture({ creditMaxCap: 4_999n });
        const tx = await authorizationTx(fx);
        await expect(
            fx.server.processCreditAuthorization(fx.payload as never, tx, CHALLENGE_CTX as never),
        ).rejects.toThrow(/cap is outside/);
    });

    test('refuses terms bound to a different channel incarnation', async () => {
        const fx = await creditFixture();
        const stranger = await generateKeyPairSigner();
        const otherRequest = creditRequest({ recipient: stranger.address }, { creditIssuer: fx.issuer.address });
        const otherOpen = await derivePaymentChannelOpen({
            authorizedSigner: fx.authorizedSigner.address,
            payer: fx.payer.address,
            request: otherRequest,
            salt: 42n,
        });
        const tx = await authorizationTx(fx, undefined, otherOpen, otherRequest);
        await expect(
            fx.server.processCreditAuthorization(fx.payload as never, tx, CHALLENGE_CTX as never),
        ).rejects.toThrow(/terms do not bind/);
    });

    test('refuses an authorization signed over a foreign blockhash', async () => {
        const fx = await creditFixture();
        const instructions = await creditAuthorizationInstructions({
            authorizedSigner: fx.authorizedSigner.address,
            open: fx.open,
            request: fx.request,
            terms: { cap: 5_000n, expiresAtSlot: 9_314n, nonce: 0n },
        });
        const tx = await signWire(fx.payer as never, instructions, USDC_DEVNET_MINT);
        await expect(
            fx.server.processCreditAuthorization(fx.payload as never, tx, CHALLENGE_CTX as never),
        ).rejects.toThrow(/recentBlockhash/);
    });

    test('fails closed on a server with no credit provider', async () => {
        const fx = await creditFixture();
        const plain = createSessionServer({
            amount: 100n,
            currency: 'USDC',
            decimals: 6,
            minimumDeposit: 100n,
            network: 'devnet',
            recipient: fx.payee.address,
            rpc: blockhashRpc(),
            signer: await generateKeyPairSigner(),
            store: createMemorySessionStore(),
        } as never);
        const tx = await authorizationTx(fx);
        await expect(plain.processCreditAuthorization(fx.payload as never, tx, CHALLENGE_CTX as never)).rejects.toThrow(
            /session has no credit provider/,
        );
    });
});

describe('Greptile #417: hooked opens through the server verifier', () => {
    async function baseOpenInstruction(fx: Awaited<ReturnType<typeof creditFixture>>) {
        const mint = address(fx.open.mint);
        const channel = address(fx.open.channelId);
        const tokenProgram = address(SPL_TOKEN_PROGRAM_ID);
        const [payerTokenAccount] = await findAssociatedTokenPda({ mint, owner: address(fx.open.payer), tokenProgram });
        const [channelTokenAccount] = await findAssociatedTokenPda({ mint, owner: channel, tokenProgram });
        const [eventAuthority] = await findEventAuthorityPda({
            programAddress: address(PAYMENT_CHANNELS_V2_PROGRAM_ID),
        });
        return getOpenInstruction(
            {
                associatedTokenProgram: address(ASSOCIATED_TOKEN_PROGRAM),
                authorizedSigner: address(fx.authorizedSigner.address),
                channel,
                channelTokenAccount,
                eventAuthority,
                mint,
                openArgs: {
                    deposit: BigInt(fx.open.deposit),
                    gracePeriod: fx.open.gracePeriod,
                    openSlot: BigInt(fx.open.openSlot),
                    // The fixture challenge carries no distributionSplits, so
                    // the derived open's recipient list is the empty list.
                    recipients: [],
                    salt: BigInt(fx.open.salt),
                },
                payee: address(fx.open.payee),
                payer: fx.payer,
                payerTokenAccount,
                rent: address(RENT_SYSVAR),
                rentPayer: fx.payer,
                selfProgram: address(PAYMENT_CHANNELS_V2_PROGRAM_ID),
                tokenProgram,
            },
            { programAddress: address(PAYMENT_CHANNELS_V2_PROGRAM_ID) },
        );
    }

    test('a hooked open carrying the derived hooks verifies', async () => {
        const fx = await creditFixture();
        const base = await baseOpenInstruction(fx);
        const hooked = await buildOpenWithHooks(base, fx.open.channelHooks!, fx.open.channelId);
        const tx = await signWire(fx.payer as never, [hooked]);
        const verified = await fx.server.verifyOpenPreBroadcast(
            { ...fx.payload, transaction: tx } as never,
            CHALLENGE_CTX as never,
        );
        expect(verified).toMatchObject({ channelId: fx.open.channelId, deposit: 5_000n });
    });

    test('a plain open is refused for a credit session', async () => {
        const fx = await creditFixture();
        const base = await baseOpenInstruction(fx);
        const tx = await signWire(fx.payer as never, [base]);
        await expect(
            fx.server.verifyOpenPreBroadcast({ ...fx.payload, transaction: tx } as never, CHALLENGE_CTX as never),
        ).rejects.toThrow(/unexpected instruction/);
    });

    test('hooks derived for another mint are refused', async () => {
        const fx = await creditFixture();
        const base = await baseOpenInstruction(fx);
        const foreignHooks = await hooksForDeployment(MUSEBOOK_DEVNET_DEPLOYMENT, fx.payer.address, TOKEN_2022_PROGRAM);
        const hooked = await buildOpenWithHooks(base, foreignHooks, fx.open.channelId);
        const tx = await signWire(fx.payer as never, [hooked]);
        await expect(
            fx.server.verifyOpenPreBroadcast({ ...fx.payload, transaction: tx } as never, CHALLENGE_CTX as never),
        ).rejects.toThrow();
    });
});
