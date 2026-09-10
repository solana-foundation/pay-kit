import {
    type Address,
    address,
    createSolanaRpc,
    getBase64Codec,
    getCompiledTransactionMessageDecoder,
    getTransactionDecoder,
    isTransactionPartialSigner,
    type TransactionPartialSigner,
} from '@solana/kit';
import {
    getSubscriptionAuthorityDecoder,
    getSubscriptionDelegationDecoder,
    SUBSCRIPTION_SIZE,
} from '@solana/subscriptions';
import { findAssociatedTokenPda } from '@solana-program/token';
import { Challenge, type Credential, Method, Receipt, Store } from 'mppx';
import { Transport } from 'mppx/server';

import { type SubscriptionAuthentication, verifySubscriptionAuthentication } from '../client/Subscription.js';
import {
    ASSOCIATED_TOKEN_PROGRAM,
    COMPUTE_BUDGET_PROGRAM,
    DEFAULT_RPC_URLS,
    MEMO_PROGRAM,
    SUBSCRIPTIONS_INIT_AUTHORITY_DISCRIMINATOR,
    SUBSCRIPTIONS_PROGRAM,
    SUBSCRIPTIONS_SUBSCRIBE_DISCRIMINATOR,
    SUBSCRIPTIONS_TRANSFER_DISCRIMINATOR,
    SYSTEM_PROGRAM,
    TOKEN_2022_PROGRAM,
    TOKEN_PROGRAM,
} from '../constants.js';
import * as Methods from '../Methods.js';
import {
    deriveSubscriptionAuthorityPda,
    deriveSubscriptionPda,
    mapSubscriptionPeriodToHours,
} from '../shared/subscription.js';
import { coSignBase64Transaction, transactionSignatureFromBase64 } from '../utils/transactions.js';
import { claimReplayKey, confirmReplayKey, inspectReplayKey, reserveReplayKey } from './replay.js';

/**
 * Creates a Solana `subscription` method for usage on the server.
 *
 * The server publishes a `Plan` on-chain out of band; the 402 challenge
 * pins the `planAddress` along with the period and amount. On activation the
 * client signs a transaction containing `subscribe` + `transfer_subscription`
 * (and optionally `initialize_subscription_authority`), the server
 * (optionally co-signing as fee payer) broadcasts, and on confirmation the
 * server verifies the on-chain `SubscriptionDelegation` matches the
 * challenge before returning the receipt.
 *
 * Subsequent renewal charges are server-driven on-chain transactions; this
 * handler is only concerned with activation.
 *
 * @example
 * ```ts
 * import { Mppx, solana } from '@solana/mpp/server'
 *
 * const mppx = Mppx.create({
 *   methods: [solana.subscription({
 *     planId: '8tWbqLkUJoYy7zXc5h2EvCRoaQEv2xnQjUuYhc3rzCgT',
 *     mint: 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v',
 *     decimals: 6,
 *     tokenProgram: TOKEN_PROGRAM,
 *     puller: '5fKb5cF22cFybZB1H4hLDydFhwoQy9JzKzRWaSbMkB6h',
 *     recipient: '9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin',
 *     periodUnit: 'day',
 *     periodCount: 30,
 *     network: 'devnet',
 *   })],
 * })
 * ```
 */
export function subscription(parameters: subscription.Parameters) {
    const {
        planId,
        mint,
        decimals,
        tokenProgram,
        puller,
        recipient,
        periodUnit,
        periodCount,
        network = 'mainnet-beta',
        subscriptionProgram = SUBSCRIPTIONS_PROGRAM,
        signer,
        store = Store.memory(),
        splits,
        subscriptionExpires,
    } = parameters;

    if (tokenProgram !== TOKEN_PROGRAM && tokenProgram !== TOKEN_2022_PROGRAM) {
        throw new Error(`tokenProgram must be ${TOKEN_PROGRAM} or ${TOKEN_2022_PROGRAM}`);
    }

    if (signer && !isTransactionPartialSigner(signer)) {
        throw new Error('signer must implement signTransactions() for fee payer mode');
    }

    // Validate the period mapping up front so misconfigured servers fail at boot,
    // not on the first challenge.
    mapSubscriptionPeriodToHours(periodUnit, periodCount);
    if (subscriptionExpires) {
        const subscriptionExpiryMs = Date.parse(subscriptionExpires);
        if (!Number.isFinite(subscriptionExpiryMs)) {
            throw new Error('subscriptionExpires must be an RFC3339 timestamp');
        }
        if (subscriptionExpiryMs <= Date.now()) {
            throw new Error('subscriptionExpires must be in the future');
        }
    }

    const rpcUrl = parameters.rpcUrl ?? DEFAULT_RPC_URLS[network] ?? DEFAULT_RPC_URLS['mainnet-beta'];
    const pendingAccessProofs = new WeakMap<Request, { credential: Credential.Credential; secretKey?: string }>();
    const httpTransport = Transport.http();
    const subscriptionTransport = Transport.from({
        ...httpTransport,
        getCredential(input: Request) {
            const credential = httpTransport.getCredential(input);
            if (credential?.payload && (credential.payload as { type?: unknown }).type === 'proof') {
                pendingAccessProofs.set(input, { credential });
                return null;
            }
            return credential;
        },
    });

    const method = Method.toServer(Methods.subscription, {
        async authorize({ challenge, input }) {
            const pending = pendingAccessProofs.get(input);
            if (!pending) return undefined;
            pendingAccessProofs.delete(input);

            const { credential, secretKey } = pending;
            if (!secretKey || !Challenge.verify(credential.challenge, { secretKey })) {
                throw new Error('Subscription proof challenge was not issued by this server');
            }
            assertAccessChallengeMatchesRoute(credential.challenge, challenge);
            const payload = Methods.subscription.schema.credential.payload.parse(credential.payload);
            const boundCredential = { ...credential, payload } as unknown as CredentialPayload;
            const boundRequest = credential.challenge.request as ChallengeRequest;
            return {
                receipt: await verifySubscriptionAccess(boundCredential, boundRequest, rpcUrl, store),
            };
        },

        defaults: {
            amount: '0',
            currency: mint,
            methodDetails: {
                decimals,
                mint,
                planAddress: planId,
                puller,
                subscriptionProgram,
                tokenProgram,
            },
            periodCount: String(periodCount),
            periodUnit,
            recipient,
        },

        preflight({ input, secretKey }) {
            const pending = pendingAccessProofs.get(input);
            if (pending) pending.secretKey = secretKey;
            return undefined;
        },

        async request({ credential, request }) {
            // Build the canonical request from the route's server config so the
            // framework's pinned-field check is meaningful. Returning
            // credential.challenge.request would short-circuit cross-route binding.

            let recentBlockhash: string | undefined;
            if (!credential) {
                try {
                    const res = await fetch(rpcUrl, {
                        body: JSON.stringify({
                            id: 1,
                            jsonrpc: '2.0',
                            method: 'getLatestBlockhash',
                            params: [{ commitment: 'confirmed' }],
                        }),
                        headers: { 'Content-Type': 'application/json' },
                        method: 'POST',
                    });
                    const data = (await res.json()) as { result?: { value?: { blockhash?: string } } };
                    recentBlockhash = data.result?.value?.blockhash;
                } catch {
                    // Non-fatal — client will fetch its own blockhash.
                }
            }

            return {
                ...request,
                amount: request.amount,
                currency: mint,
                methodDetails: {
                    decimals,
                    mint,
                    network,
                    planAddress: planId,
                    puller,
                    subscriptionProgram,
                    tokenProgram,
                    ...(signer ? { feePayer: true, feePayerKey: signer.address } : {}),
                    ...(splits?.length ? { splits } : {}),
                    ...(recentBlockhash ? { recentBlockhash } : {}),
                },
                periodCount: request.periodCount ?? String(periodCount),
                periodUnit: request.periodUnit ?? periodUnit,
                recipient,
                ...(subscriptionExpires ? { subscriptionExpires } : {}),
            };
        },

        stableBinding: subscriptionStableBinding,

        // Durable proofs authorize access rather than activate a payment. The
        // HTTP transport hides them from mppx's activation credential path so
        // its five-minute challenge expiry does not terminate a paid term.
        transport: subscriptionTransport,

        async verify({ credential }) {
            const cred = credential as unknown as CredentialPayload;
            const challenge = cred.challenge.request;
            const payloadType = resolvePayloadType(cred.payload);

            if (payloadType === 'proof') {
                return await verifySubscriptionAccess(cred, challenge, rpcUrl, store);
            }

            assertActivationChallengeNotExpired(cred.challenge.expires);
            assertSubscriptionNotExpired(challenge.subscriptionExpires);

            if (payloadType === 'signature' && challenge.methodDetails.feePayer) {
                throw new Error('type="signature" credentials cannot be used with fee sponsorship (feePayer: true)');
            }

            const settlement = await settleActivation(cred, challenge, rpcUrl, store, signer, payloadType);
            const subscriberAddress = settlement.subscriberAddress;

            const subscriptionPda = await deriveSubscriptionPda({
                planPda: address(challenge.methodDetails.planAddress),
                programId: address(challenge.methodDetails.subscriptionProgram),
                subscriber: address(subscriberAddress),
            });

            const expectedPeriodHours = mapSubscriptionPeriodToHours(
                challenge.periodUnit,
                Number(challenge.periodCount),
            );

            const delegation = await fetchSubscriptionDelegation(
                rpcUrl,
                subscriptionPda,
                address(challenge.methodDetails.subscriptionProgram),
            );
            if (!delegation) {
                throw new Error('SubscriptionDelegation account not found after activation');
            }

            if (delegation.planPda !== challenge.methodDetails.planAddress) {
                throw new Error(
                    `SubscriptionDelegation plan mismatch: expected ${challenge.methodDetails.planAddress}, got ${delegation.planPda}`,
                );
            }
            if (delegation.subscriber !== subscriberAddress) {
                throw new Error(
                    `SubscriptionDelegation subscriber mismatch: expected ${subscriberAddress}, got ${delegation.subscriber}`,
                );
            }
            if (delegation.amountPerPeriod !== challenge.amount) {
                throw new Error(
                    `SubscriptionDelegation amount mismatch: expected ${challenge.amount}, got ${delegation.amountPerPeriod}`,
                );
            }
            if (delegation.periodHours !== expectedPeriodHours) {
                throw new Error(
                    `SubscriptionDelegation period mismatch: expected ${expectedPeriodHours}h, got ${delegation.periodHours}h`,
                );
            }
            if (delegation.amountPulledInPeriod !== challenge.amount) {
                throw new Error('Activation transaction did not execute the first-period charge');
            }

            if (settlement.replay) {
                await confirmReplayKey(store, settlement.replay.key, settlement.replay.binding);
            }

            const authentication = requireSubscriptionAuthentication(cred.payload);
            const bindingKey = subscriptionBindingKey(subscriptionPda.toString());
            const subscriptionId = await deriveSubscriptionId(subscriptionPda.toString(), authentication.challengeId);
            const binding = {
                activationSignature: settlement.activationSignature,
                authentication,
                challengeId: authentication.challengeId,
                periodStartTs: delegation.currentPeriodStartTs,
                subscriptionExpires: challenge.subscriptionExpires,
                subscriptionId,
            } satisfies SubscriptionBinding;
            // A cancelled or revoked subscription can later reuse the same PDA.
            // Reaching this point proves the new activation confirmed and its
            // on-chain delegation matches the challenge, so rotate the bearer
            // binding and invalidate any proof from the prior lifecycle.
            await store.put(bindingKey, binding);

            const periodLengthSeconds = expectedPeriodHours * 3600;
            const periodStartTs = delegation.currentPeriodStartTs;
            const periodEndTs = periodStartTs + periodLengthSeconds;

            return Receipt.from({
                method: 'solana',
                ...(cred.challenge.id ? { challengeId: cred.challenge.id } : {}),
                ...(challenge.externalId ? { externalId: challenge.externalId } : {}),
                // Subscription-specific receipt extensions live alongside the
                // Receipt's standard fields. The mppx framework treats unknown
                // fields as opaque metadata.
                expiresAt: challenge.subscriptionExpires,

                periodEnd: new Date(periodEndTs * 1000).toISOString(),

                periodIndex: 0,

                periodStart: new Date(periodStartTs * 1000).toISOString(),
                reference: settlement.activationSignature,
                status: 'success',
                subscriptionDelegation: subscriptionPda.toString(),
                subscriptionId,
                timestamp: new Date().toISOString(),
            });
        },
    });

    return method;
}

function assertActivationChallengeNotExpired(expires: string | undefined): void {
    if (expires === undefined) return;
    const expiresAt = Date.parse(expires);
    if (Number.isNaN(expiresAt)) throw new Error('challenge expires must be an RFC3339 timestamp');
    if (expiresAt <= Date.now()) throw new Error(`challenge expired at ${expires}`);
}

function assertSubscriptionNotExpired(expires: string | undefined): void {
    if (expires === undefined) return;
    const expiresAt = Date.parse(expires);
    if (Number.isNaN(expiresAt)) throw new Error('subscriptionExpires must be an RFC3339 timestamp');
    if (expiresAt <= Date.now()) throw new Error(`subscription expired at ${expires}`);
}

function assertAccessChallengeMatchesRoute(issued: Challenge.Challenge, current: Challenge.Challenge): void {
    if (
        issued.method !== current.method ||
        issued.intent !== current.intent ||
        issued.realm !== current.realm ||
        issued.opaque !== current.opaque ||
        JSON.stringify(subscriptionStableBinding(issued.request as ChallengeRequest)) !==
            JSON.stringify(subscriptionStableBinding(current.request as ChallengeRequest))
    ) {
        throw new Error('Subscription proof challenge does not match this route');
    }
}

function subscriptionStableBinding(request: ChallengeRequest) {
    const methodDetails = { ...request.methodDetails };
    delete methodDetails.recentBlockhash;
    return {
        amount: request.amount,
        currency: request.currency,
        methodDetails,
        periodCount: request.periodCount,
        periodUnit: request.periodUnit,
        recipient: request.recipient,
        subscriptionExpires: request.subscriptionExpires,
    };
}

// ── Payload type resolution ──

function resolvePayloadType(payload: {
    signature?: string;
    transaction?: string;
    type?: string;
}): 'proof' | 'signature' | 'transaction' {
    if (payload.type === 'proof') return 'proof';
    if (payload.type === 'signature') return 'signature';
    if (payload.type === 'transaction') return 'transaction';
    throw new Error('Missing or invalid payload type: must be "transaction", "signature", or "proof"');
}

// ── Activation settlement ──

async function settleActivation(
    credential: CredentialPayload,
    challenge: ChallengeRequest,
    rpcUrl: string,
    store: Store.Store,
    signer: TransactionPartialSigner | undefined,
    payloadType: 'signature' | 'transaction',
): Promise<{
    activationSignature: string;
    replay?: { binding: string; key: string };
    subscriberAddress: string;
}> {
    if (payloadType === 'transaction') {
        const { transaction: clientTxBase64 } = credential.payload;
        if (!clientTxBase64) {
            throw new Error('Missing transaction data in credential payload');
        }

        const subscriber = extractSubscriberFromTransaction(clientTxBase64, challenge);
        await verifyActivationAuthentication(credential, challenge, subscriber);
        await validateActivationInstructions(clientTxBase64, challenge, subscriber);

        let txToSend = clientTxBase64;
        if (signer) {
            if (challenge.methodDetails.feePayerKey !== signer.address) {
                throw new Error('Configured fee-payer signer does not match challenge feePayerKey');
            }
            txToSend = await coSignBase64Transaction(signer, clientTxBase64);
        }

        const signature = transactionSignatureFromBase64(txToSend);
        const key = `solana-subscription:consumed:${signature}`;
        const binding = JSON.stringify({ challengeId: credential.challenge.id ?? null, request: challenge });
        const replayStatus = await inspectReplayKey(store, key, binding);
        if (replayStatus === 'conflict') {
            throw new Error('Activation signature already consumed');
        }
        if (replayStatus === 'pending') {
            throw new Error('Activation settlement is already in progress; retry shortly');
        }

        let needsConfirmation = replayStatus !== 'retry';
        if (replayStatus === 'expired') {
            const recoveryClaim = await claimReplayKey(store, key, binding);
            if (recoveryClaim === 'conflict') throw new Error('Activation signature already consumed');
            if (recoveryClaim === 'pending') {
                throw new Error('Activation settlement is already in progress; retry shortly');
            }
            needsConfirmation = recoveryClaim !== 'retry';
        } else if (replayStatus === 'available') {
            const replayClaim = await claimReplayKey(store, key, binding);
            if (replayClaim === 'conflict') throw new Error('Activation signature already consumed');
            if (replayClaim === 'pending') {
                throw new Error('Activation settlement is already in progress; retry shortly');
            }
            needsConfirmation = replayClaim !== 'retry';
            if (replayClaim === 'reserved') {
                try {
                    await simulateTransaction(rpcUrl, txToSend);
                } catch (error) {
                    // No transaction was submitted, so releasing this reservation
                    // is safe and lets the client correct and retry the activation.
                    await store.delete(key);
                    throw error;
                }
                // Keep the reservation on an ambiguous send failure: the RPC may
                // have accepted the transaction even if the response was lost.
                await broadcastTransaction(rpcUrl, txToSend);
            }
        }
        if (needsConfirmation) {
            await waitForConfirmation(rpcUrl, signature);
        }
        return { activationSignature: signature, replay: { binding, key }, subscriberAddress: subscriber };
    }

    // ── Push mode (type="signature") ──
    const { signature } = credential.payload;
    if (!signature) {
        throw new Error('Missing signature in credential payload');
    }
    const consumedKey = `solana-subscription:consumed:${signature}`;
    if ((await store.get(consumedKey)) !== null) {
        throw new Error('Activation signature already consumed');
    }
    const tx = await fetchTransactionRaw(rpcUrl, signature);
    if (!tx) throw new Error('Transaction not found or not yet confirmed');
    if (tx.meta?.err) throw new Error('Transaction failed on-chain');
    const [transactionBase64] = tx.transaction;
    const subscriber = extractSubscriberFromTransaction(transactionBase64, challenge);
    await verifyActivationAuthentication(credential, challenge, subscriber);
    await validateActivationInstructions(transactionBase64, challenge, subscriber);

    if (!(await reserveReplayKey(store, consumedKey))) {
        throw new Error('Activation signature already consumed');
    }
    return { activationSignature: signature, subscriberAddress: subscriber };
}

async function verifyActivationAuthentication(
    credential: CredentialPayload,
    challenge: ChallengeRequest,
    subscriber: string,
): Promise<void> {
    const authentication = requireSubscriptionAuthentication(credential.payload);
    if (!credential.challenge.id || authentication.challengeId !== credential.challenge.id) {
        throw new Error('Subscription proof challengeId does not match the activation challenge');
    }
    if (authentication.payer !== subscriber) {
        throw new Error('Subscription proof payer does not match the activation subscriber');
    }
    const subscriptionDelegation = await deriveSubscriptionPda({
        planPda: address(challenge.methodDetails.planAddress),
        programId: address(challenge.methodDetails.subscriptionProgram),
        subscriber: address(subscriber),
    });
    if (!(await verifySubscriptionAuthentication(authentication, subscriptionDelegation.toString()))) {
        throw new Error('Invalid subscription authentication proof');
    }
}

async function verifySubscriptionAccess(
    credential: CredentialPayload,
    challenge: ChallengeRequest,
    rpcUrl: string,
    store: Store.Store,
) {
    const authentication = requireSubscriptionAuthentication(credential.payload);
    const subscriptionDelegation = credential.payload.subscriptionDelegation;
    if (!subscriptionDelegation) throw new Error('Subscription proof payload is missing subscriptionDelegation');
    if (!credential.challenge.id || authentication.challengeId !== credential.challenge.id) {
        throw new Error('Subscription proof challengeId does not match the activation challenge');
    }

    const programId = challenge.methodDetails.subscriptionProgram;
    const expectedDelegation = await deriveSubscriptionPda({
        planPda: address(challenge.methodDetails.planAddress),
        programId: address(programId),
        subscriber: address(authentication.payer),
    });
    if (subscriptionDelegation !== expectedDelegation.toString()) {
        throw new Error('Subscription proof delegation does not match the plan and payer');
    }
    if (!(await verifySubscriptionAuthentication(authentication, subscriptionDelegation))) {
        throw new Error('Invalid subscription authentication proof');
    }

    const stored = await store.get(subscriptionBindingKey(subscriptionDelegation));
    const binding = parseSubscriptionBinding(stored);
    if (
        binding.challengeId !== credential.challenge.id ||
        JSON.stringify(binding.authentication) !== JSON.stringify(authentication)
    ) {
        throw new Error('Subscription proof does not match the activation binding');
    }

    const delegation = await fetchSubscriptionDelegation(rpcUrl, expectedDelegation, address(programId));
    if (!delegation) throw new Error('SubscriptionDelegation account not found');
    if (delegation.planPda !== challenge.methodDetails.planAddress || delegation.subscriber !== authentication.payer) {
        throw new Error('SubscriptionDelegation does not match the bound plan and payer');
    }
    const authorityPda = await deriveSubscriptionAuthorityPda({
        mint: address(challenge.methodDetails.mint),
        programId: address(programId),
        subscriber: address(authentication.payer),
    });
    const authorityInitId = await fetchSubscriptionAuthorityInitId(rpcUrl, authorityPda, address(programId));
    if (authorityInitId !== delegation.authorityInitId) {
        throw new Error('Subscription authority has been invalidated');
    }

    const expectedPeriodHours = mapSubscriptionPeriodToHours(challenge.periodUnit, Number(challenge.periodCount));
    if (
        delegation.amountPerPeriod !== challenge.amount ||
        delegation.periodHours !== expectedPeriodHours ||
        delegation.amountPulledInPeriod !== challenge.amount
    ) {
        throw new Error('Subscription is not paid for the current billing period');
    }

    const now = Math.floor(Date.now() / 1000);
    const periodLengthSeconds = expectedPeriodHours * 3600;
    const periodEndTs = delegation.currentPeriodStartTs + periodLengthSeconds;
    if (now < delegation.currentPeriodStartTs || now >= periodEndTs) {
        throw new Error('Subscription is not paid for the current billing period');
    }
    if (delegation.expiresAtTs !== 0 && now >= delegation.expiresAtTs) {
        throw new Error('Subscription cancellation has taken effect');
    }
    if (binding.subscriptionExpires && Date.parse(binding.subscriptionExpires) <= Date.now()) {
        throw new Error('Subscription has expired');
    }

    const elapsed = delegation.currentPeriodStartTs - binding.periodStartTs;
    if (elapsed < 0 || elapsed % periodLengthSeconds !== 0) {
        throw new Error('Subscription billing anchor does not align with the current period');
    }
    const periodIndex = elapsed / periodLengthSeconds;
    return Receipt.from({
        challengeId: credential.challenge.id,
        expiresAt: binding.subscriptionExpires,
        method: 'solana',
        periodEnd: new Date(periodEndTs * 1000).toISOString(),
        periodIndex,
        periodStart: new Date(delegation.currentPeriodStartTs * 1000).toISOString(),
        reference: binding.activationSignature,
        status: 'success',
        subscriptionDelegation,
        subscriptionId: binding.subscriptionId,
        timestamp: new Date().toISOString(),
    });
}

function requireSubscriptionAuthentication(payload: CredentialPayload['payload']): SubscriptionAuthentication {
    const authentication = payload.authentication;
    if (!authentication || authentication.type !== 'proof') {
        throw new Error('Subscription credential is missing authentication.type="proof"');
    }
    return authentication;
}

function subscriptionBindingKey(subscriptionDelegation: string): string {
    return `solana-subscription:authentication:${subscriptionDelegation}`;
}

async function deriveSubscriptionId(subscriptionDelegation: string, challengeId: string): Promise<string> {
    const digest = await crypto.subtle.digest(
        'SHA-256',
        new TextEncoder().encode(`mpp-subscription-id-v1:${challengeId}:${subscriptionDelegation}`),
    );
    return base64UrlEncodeNoPadding(new Uint8Array(digest).slice(0, 18));
}

function parseSubscriptionBinding(value: unknown): SubscriptionBinding {
    if (!value || typeof value !== 'object') throw new Error('Subscription has no bound authentication proof');
    const binding = value as Partial<SubscriptionBinding>;
    if (
        !binding.authentication ||
        typeof binding.activationSignature !== 'string' ||
        typeof binding.challengeId !== 'string' ||
        typeof binding.periodStartTs !== 'number' ||
        typeof binding.subscriptionId !== 'string'
    ) {
        throw new Error('Subscription authentication binding is malformed');
    }
    return binding as SubscriptionBinding;
}

// ── Transaction parsing (lightweight, pre-broadcast) ──
//
// Decode once at this boundary so subscriber extraction and the instruction
// allowlist operate on the same canonical compiled-message representation.
// Account-state correctness is verified against the resulting delegation
// after confirmation.

type CompiledMessage = {
    addressTableLookups?: readonly unknown[];
    instructions: readonly CompiledInstruction[];
    signerAccounts: readonly string[];
    staticAccounts: readonly string[];
};

type CompiledInstruction = {
    accountIndices: readonly number[];
    data: Uint8Array;
    programAddressIndex: number;
};

function decodeCompiledMessage(clientTxBase64: string): CompiledMessage {
    try {
        const txBytes = getBase64Codec().encode(clientTxBase64);
        const decoded = getTransactionDecoder().decode(txBytes);
        const message = getCompiledTransactionMessageDecoder().decode(decoded.messageBytes) as unknown as Omit<
            CompiledMessage,
            'signerAccounts'
        >;
        return { ...message, signerAccounts: Object.keys(decoded.signatures) };
    } catch (e) {
        throw new Error(`Invalid transaction: ${e instanceof Error ? e.message : String(e)}`);
    }
}

function extractSubscriberFromTransaction(clientTxBase64: string, challenge: ChallengeRequest): string {
    const message = decodeCompiledMessage(clientTxBase64);
    if (message.staticAccounts.length === 0) {
        throw new Error('Transaction has no static accounts');
    }
    const firstAccount = message.staticAccounts[0];

    // When fee sponsorship is in play, the first signer is the server's fee
    // payer; the subscriber is the next signer that is not the puller.
    if (challenge.methodDetails.feePayer && challenge.methodDetails.feePayerKey) {
        if (firstAccount !== challenge.methodDetails.feePayerKey) {
            throw new Error(`Transaction fee payer must be ${challenge.methodDetails.feePayerKey}`);
        }
        for (const account of message.signerAccounts.slice(1)) {
            if (account !== challenge.methodDetails.puller) return account;
        }
        throw new Error('Could not identify subscriber among transaction signers');
    }

    if (challenge.methodDetails.puller && firstAccount === challenge.methodDetails.puller) {
        throw new Error('Subscriber cannot be the server puller');
    }
    return firstAccount;
}

async function validateActivationInstructions(
    clientTxBase64: string,
    challenge: ChallengeRequest,
    subscriber?: string,
): Promise<void> {
    const message = decodeCompiledMessage(clientTxBase64);

    if (message.addressTableLookups?.length) {
        throw new Error('v0 transactions with address lookup tables are not supported in activation flow');
    }

    const programId = challenge.methodDetails.subscriptionProgram;

    let sawSubscribe = false;
    let sawTransferSubscription = false;
    let subscribeIndex = -1;
    let transferIndex = -1;
    let sawInitializeAuthority = false;
    let sawMemo = false;
    let sawComputeUnitLimit = false;
    let sawComputeUnitPrice = false;

    for (const [index, ix] of message.instructions.entries()) {
        const program = message.staticAccounts[ix.programAddressIndex];
        if (program === COMPUTE_BUDGET_PROGRAM) {
            if (ix.data[0] === 2 && ix.data.length === 5) {
                if (sawComputeUnitLimit) throw new Error('Multiple compute-unit-limit instructions found');
                sawComputeUnitLimit = true;
                if (readU32Le(ix.data, 1) > 400_000) throw new Error('Activation compute unit limit exceeds 400000');
                continue;
            }
            if (ix.data[0] === 3 && ix.data.length === 9) {
                if (sawComputeUnitPrice) throw new Error('Multiple compute-unit-price instructions found');
                sawComputeUnitPrice = true;
                const maxPrice = challenge.methodDetails.feePayer ? 10_000n : 5_000_000n;
                if (readU64Le(ix.data, 1) > maxPrice) throw new Error('Activation compute unit price exceeds cap');
                continue;
            }
            throw new Error('Unsupported compute-budget instruction in activation transaction');
        }

        if (program === MEMO_PROGRAM) {
            if (sawMemo) throw new Error('Multiple memo instructions found');
            sawMemo = true;
            const expectedMemo = challenge.externalId;
            if (!expectedMemo || new TextDecoder().decode(ix.data) !== expectedMemo) {
                throw new Error('Activation memo does not match challenge externalId');
            }
            continue;
        }

        if (program === ASSOCIATED_TOKEN_PROGRAM) {
            if (ix.data.length !== 1 || ix.data[0] !== 1) {
                throw new Error('Only idempotent ATA creation is allowed in activation transaction');
            }
            if (!subscriber || ix.accountIndices.length !== 6) {
                throw new Error('Invalid ATA creation instruction in activation transaction');
            }
            const account = (position: number) => message.staticAccounts[ix.accountIndices[position]];
            const ataOwner = account(2);
            if (ataOwner !== subscriber && ataOwner !== challenge.recipient) {
                throw new Error('ATA creation owner does not match the activation subscriber or recipient');
            }
            const [expectedAta] = await findAssociatedTokenPda({
                mint: address(challenge.methodDetails.mint),
                owner: address(ataOwner),
                tokenProgram: address(challenge.methodDetails.tokenProgram),
            });
            if (
                account(1) !== expectedAta ||
                account(3) !== challenge.methodDetails.mint ||
                account(4) !== SYSTEM_PROGRAM ||
                account(5) !== challenge.methodDetails.tokenProgram
            ) {
                throw new Error('ATA creation does not match the activation subscriber and mint');
            }
            continue;
        }

        if (program !== programId) {
            throw new Error(`Unsupported program ${program ?? '<invalid>'} in activation transaction`);
        }
        if (ix.data.length === 0) throw new Error('Empty subscriptions-program instruction');
        if (ix.data[0] === SUBSCRIPTIONS_INIT_AUTHORITY_DISCRIMINATOR) {
            if (sawInitializeAuthority)
                throw new Error('Multiple initialize_subscription_authority instructions found');
            sawInitializeAuthority = true;
        } else if (ix.data[0] === SUBSCRIPTIONS_SUBSCRIBE_DISCRIMINATOR) {
            if (sawSubscribe) throw new Error('Multiple subscribe instructions found');
            sawSubscribe = true;
            subscribeIndex = index;
        } else if (ix.data[0] === SUBSCRIPTIONS_TRANSFER_DISCRIMINATOR) {
            if (sawTransferSubscription) throw new Error('Multiple transfer_subscription instructions found');
            if (!subscriber) throw new Error('Cannot validate transfer_subscription without subscriber');
            const expectedRecipientAta = (
                await findAssociatedTokenPda({
                    mint: address(challenge.methodDetails.mint),
                    owner: address(challenge.recipient),
                    tokenProgram: address(challenge.methodDetails.tokenProgram),
                })
            )[0];
            // Codama v0.5 uses receiver_ata at account 4. Retain the previous
            // nine-account client layout at account 6 during its migration,
            // but bind either accepted shape to the challenged recipient ATA.
            const receiverPosition = ix.accountIndices.length === 10 ? 4 : ix.accountIndices.length === 9 ? 6 : -1;
            if (
                receiverPosition < 0 ||
                message.staticAccounts[ix.accountIndices[receiverPosition]] !== expectedRecipientAta
            ) {
                throw new Error('transfer_subscription receiver does not match the challenge recipient');
            }
            // Codama v0.5 TransferData is discriminator + amount + delegator +
            // mint. Validate it whenever the current schema is presented.
            if (ix.data.length === 73) {
                if (readU64Le(ix.data, 1) !== BigInt(challenge.amount)) {
                    throw new Error('transfer_subscription amount does not match the challenge');
                }
                if (encodeBase58(ix.data.slice(9, 41)) !== subscriber) {
                    throw new Error('transfer_subscription delegator does not match subscriber');
                }
                if (encodeBase58(ix.data.slice(41, 73)) !== challenge.methodDetails.mint) {
                    throw new Error('transfer_subscription mint does not match the challenge');
                }
            } else if (ix.data.length !== 1) {
                throw new Error('Invalid transfer_subscription instruction data');
            }
            sawTransferSubscription = true;
            transferIndex = index;
        } else {
            throw new Error(`Unsupported subscriptions instruction ${ix.data[0]} in activation transaction`);
        }
    }

    if (!sawSubscribe) throw new Error('Activation transaction is missing subscribe instruction');
    if (!sawTransferSubscription)
        throw new Error('Activation transaction is missing transfer_subscription instruction');
    if (transferIndex < subscribeIndex) {
        throw new Error('subscribe must precede transfer_subscription in activation transaction');
    }
    if (challenge.externalId && !sawMemo) {
        throw new Error('Activation transaction is missing challenge externalId memo');
    }
}

// ── On-chain SubscriptionDelegation decoding ──
//
// Keep account layout handling in the official Codama-generated SDK. This
// avoids duplicating offsets here when the subscription program evolves.

type SubscriptionDelegation = {
    amountPerPeriod: string;
    amountPulledInPeriod: string;
    authorityInitId: bigint;
    currentPeriodStartTs: number;
    expiresAtTs: number;
    periodHours: number;
    planPda: string;
    subscriber: string;
};

async function fetchSubscriptionDelegation(
    rpcUrl: string,
    subscriptionPda: { toString(): string },
    expectedOwner?: Address,
): Promise<SubscriptionDelegation | null> {
    const rpc = createSolanaRpc(rpcUrl);
    const account = await rpc.getAccountInfo(address(subscriptionPda.toString()), { encoding: 'base64' }).send();
    if (!account.value) return null;
    if (expectedOwner && account.value.owner !== expectedOwner) {
        throw new Error(`SubscriptionDelegation owner mismatch: expected ${expectedOwner}, got ${account.value.owner}`);
    }
    const [b64] = account.value.data;
    const data = new Uint8Array(getBase64Codec().encode(b64));
    return decodeSubscriptionDelegation(data);
}

async function fetchSubscriptionAuthorityInitId(
    rpcUrl: string,
    authorityPda: { toString(): string },
    expectedOwner: Address,
): Promise<bigint> {
    const rpc = createSolanaRpc(rpcUrl);
    const account = await rpc.getAccountInfo(address(authorityPda.toString()), { encoding: 'base64' }).send();
    if (!account.value) throw new Error('SubscriptionAuthority account not found');
    if (account.value.owner !== expectedOwner) {
        throw new Error(`SubscriptionAuthority owner mismatch: expected ${expectedOwner}, got ${account.value.owner}`);
    }
    const [b64] = account.value.data;
    const data = new Uint8Array(getBase64Codec().encode(b64));
    return getSubscriptionAuthorityDecoder().decode(data).initId;
}

function decodeSubscriptionDelegation(data: Uint8Array): SubscriptionDelegation {
    if (data.length !== SUBSCRIPTION_SIZE) {
        throw new Error(
            `Unexpected SubscriptionDelegation account length: ${data.length} bytes (expected ${SUBSCRIPTION_SIZE})`,
        );
    }
    const decoded = getSubscriptionDelegationDecoder().decode(data);

    return {
        amountPerPeriod: decoded.terms.amount.toString(),
        amountPulledInPeriod: decoded.amountPulledInPeriod.toString(),
        authorityInitId: decoded.header.initId,
        currentPeriodStartTs: Number(decoded.currentPeriodStartTs),
        expiresAtTs: Number(decoded.expiresAtTs),
        periodHours: Number(decoded.terms.periodHours),
        planPda: decoded.header.delegatee,
        subscriber: decoded.header.delegator,
    };
}

function readU64Le(data: Uint8Array, offset: number): bigint {
    let value = 0n;
    for (let i = 0; i < 8; i += 1) {
        value |= BigInt(data[offset + i]) << BigInt(i * 8);
    }
    return value;
}

function readU32Le(data: Uint8Array, offset: number): number {
    return new DataView(data.buffer, data.byteOffset, data.byteLength).getUint32(offset, true);
}

// ── Base58/base64url helpers (minimal, dependency-free) ──

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function encodeBase58(bytes: Uint8Array): string {
    if (bytes.length === 0) return '';
    let leading = 0;
    while (leading < bytes.length && bytes[leading] === 0) leading += 1;
    const buf: number[] = [];
    for (let i = leading; i < bytes.length; i += 1) {
        let carry = bytes[i];
        for (let j = 0; j < buf.length; j += 1) {
            const x = (buf[j] << 8) + carry;
            buf[j] = x % 58;
            carry = Math.floor(x / 58);
        }
        while (carry > 0) {
            buf.push(carry % 58);
            carry = Math.floor(carry / 58);
        }
    }
    let out = '';
    for (let i = 0; i < leading; i += 1) out += '1';
    for (let i = buf.length - 1; i >= 0; i -= 1) out += BASE58_ALPHABET[buf[i]];
    return out;
}

function decodeBase58(s: string): Uint8Array {
    if (s.length === 0) return new Uint8Array();
    const map: Record<string, number> = {};
    for (let i = 0; i < BASE58_ALPHABET.length; i += 1) map[BASE58_ALPHABET[i]] = i;
    let leading = 0;
    while (leading < s.length && s[leading] === '1') leading += 1;
    const buf: number[] = [];
    for (let i = leading; i < s.length; i += 1) {
        const v = map[s[i]];
        if (v === undefined) throw new Error(`Invalid base58 character: ${s[i]}`);
        let carry = v;
        for (let j = 0; j < buf.length; j += 1) {
            const x = buf[j] * 58 + carry;
            buf[j] = x & 0xff;
            carry = x >> 8;
        }
        while (carry > 0) {
            buf.push(carry & 0xff);
            carry >>= 8;
        }
    }
    const out = new Uint8Array(leading + buf.length);
    for (let i = buf.length - 1, k = leading; i >= 0; i -= 1, k += 1) out[k] = buf[i];
    return out;
}

function base64UrlEncodeNoPadding(bytes: Uint8Array): string {
    let s = '';
    for (let i = 0; i < bytes.length; i += 1) s += String.fromCharCode(bytes[i]);
    const b64 = typeof btoa !== 'undefined' ? btoa(s) : Buffer.from(bytes).toString('base64');
    return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// ── RPC helpers ──

type RawTransaction = {
    meta: { err: unknown } | null;
    transaction: [string, 'base64'];
};

async function fetchTransactionRaw(rpcUrl: string, signature: string): Promise<RawTransaction | null> {
    const response = await fetch(rpcUrl, {
        body: JSON.stringify({
            id: 1,
            jsonrpc: '2.0',
            method: 'getTransaction',
            params: [signature, { commitment: 'confirmed', encoding: 'base64', maxSupportedTransactionVersion: 0 }],
        }),
        headers: { 'Content-Type': 'application/json' },
        method: 'POST',
    });
    const data = (await response.json()) as { error?: { message: string }; result?: RawTransaction | null };
    if (data.error) throw new Error(`RPC error: ${data.error.message}`);
    return data.result ?? null;
}

async function simulateTransaction(rpcUrl: string, base64Tx: string): Promise<void> {
    const response = await fetch(rpcUrl, {
        body: JSON.stringify({
            id: 1,
            jsonrpc: '2.0',
            method: 'simulateTransaction',
            params: [base64Tx, { commitment: 'confirmed', encoding: 'base64' }],
        }),
        headers: { 'Content-Type': 'application/json' },
        method: 'POST',
    });
    const data = (await response.json()) as {
        error?: { message: string };
        result?: { value?: { err: unknown; logs?: string[] } };
    };
    if (data.error) throw new Error(`RPC error: ${data.error.message}`);
    const simErr = data.result?.value?.err;
    if (simErr) {
        const logs = data.result?.value?.logs ?? [];
        console.error('[solana-mpp] Subscription simulation failed:', JSON.stringify(simErr));
        for (const log of logs) console.error('[solana-mpp]', log);
        throw new Error(`Activation simulation failed: ${JSON.stringify(simErr)}`);
    }
}

async function broadcastTransaction(rpcUrl: string, base64Tx: string): Promise<string> {
    const response = await fetch(rpcUrl, {
        body: JSON.stringify({
            id: 1,
            jsonrpc: '2.0',
            method: 'sendTransaction',
            params: [base64Tx, { encoding: 'base64', skipPreflight: false }],
        }),
        headers: { 'Content-Type': 'application/json' },
        method: 'POST',
    });
    const data = (await response.json()) as { error?: { message: string }; result?: string };
    if (data.error) throw new Error(`RPC error: ${data.error.message}`);
    if (!data.result) throw new Error('No signature returned from sendTransaction');
    return data.result;
}

async function waitForConfirmation(rpcUrl: string, signature: string, timeoutMs = 30_000): Promise<void> {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
        const response = await fetch(rpcUrl, {
            body: JSON.stringify({
                id: 1,
                jsonrpc: '2.0',
                method: 'getSignatureStatuses',
                params: [[signature]],
            }),
            headers: { 'Content-Type': 'application/json' },
            method: 'POST',
        });
        const data = (await response.json()) as {
            result?: { value: ({ confirmationStatus: string; err: unknown } | null)[] };
        };
        const status = data.result?.value?.[0];
        if (status) {
            if (status.err) throw new Error(`Transaction failed: ${JSON.stringify(status.err)}`);
            if (status.confirmationStatus === 'confirmed' || status.confirmationStatus === 'finalized') return;
        }
        await new Promise(r => setTimeout(r, 2_000));
    }
    throw new Error('Transaction confirmation timeout');
}

// ── Types ──

type CredentialPayload = {
    challenge: {
        expires?: string;
        id?: string;
        request: ChallengeRequest;
    };
    payload: {
        authentication?: SubscriptionAuthentication;
        signature?: string;
        subscriptionDelegation?: string;
        transaction?: string;
        type?: string;
    };
};

type SubscriptionBinding = {
    activationSignature: string;
    authentication: SubscriptionAuthentication;
    challengeId: string;
    periodStartTs: number;
    subscriptionExpires?: string;
    subscriptionId: string;
};

type ChallengeRequest = {
    amount: string;
    currency: string;
    description?: string;
    externalId?: string;
    methodDetails: {
        decimals: number;
        feePayer?: boolean;
        feePayerKey?: string;
        mint: string;
        network?: string;
        planAddress: string;
        puller: string;
        recentBlockhash?: string;
        splits?: Array<{ bps: number; recipient: string }>;
        subscriptionProgram: string;
        tokenProgram: string;
    };
    periodCount: string;
    periodUnit: 'day' | 'week';
    recipient: string;
    subscriptionExpires?: string;
};

// ── Test exports ──
//
// These are exported for direct unit testing without RPC mocking. They are
// not part of the public surface; consumers should use `subscription()`.

export const __testing = {
    base64UrlEncodeNoPadding,
    decodeBase58,
    decodeSubscriptionDelegation,
    encodeBase58,
    extractSubscriberFromTransaction,
    validateActivationInstructions,
};

export declare namespace subscription {
    type Parameters = {
        /** Token decimals for the mint. */
        decimals: number;
        /** Base58 of the SPL token mint. MUST match the on-chain plan.mint. */
        mint: string;
        /** Solana network. Defaults to `mainnet-beta`. */
        network?: 'devnet' | 'localnet' | 'mainnet-beta' | 'testnet' | (string & {});
        /** Positive integer count of `periodUnit` values per billing period (1..365 for day, 1..52 for week). */
        periodCount: number;
        /** Billing period unit. The Solana profile supports `day` and `week` only. */
        periodUnit: 'day' | 'week';
        /** Base58 of the on-chain Plan PDA. */
        planId: string;
        /** Base58 of the server's puller pubkey (must be in plan.pullers or plan.owner). */
        puller: string;
        /** Base58 of the primary recipient wallet. MUST match what plan.destinations resolves to. */
        recipient: string;
        /** Custom RPC URL. Defaults to the public RPC for the selected network. */
        rpcUrl?: string;
        /** Optional fee-payer signer. When set, the server co-signs activation as fee payer. */
        signer?: TransactionPartialSigner;
        /** Advisory distribution splits. The on-chain split is governed by plan.destinations. */
        splits?: Array<{ bps: number; recipient: string }>;
        /** Pluggable key-value store for replay protection. Defaults to in-memory. */
        store?: Store.Store;
        /** Optional {@link https://datatracker.ietf.org/doc/html/rfc3339 | RFC3339} expiry of the recurring authorization. */
        subscriptionExpires?: string;
        /** Base58 of the subscriptions program ID. Defaults to the canonical deployment. */
        subscriptionProgram?: string;
        /** Base58 of the SPL Token or Token-2022 program ID. */
        tokenProgram: string;
    };
}
