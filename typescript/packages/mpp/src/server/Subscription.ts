import {
    address,
    createSolanaRpc,
    getBase64Codec,
    getCompiledTransactionMessageDecoder,
    getSignatureFromTransaction,
    getTransactionDecoder,
    isTransactionPartialSigner,
    type TransactionPartialSigner,
} from '@solana/kit';
import { findAssociatedTokenPda } from '@solana-program/token';
import { Method, Receipt, Store } from 'mppx';

import {
    ASSOCIATED_TOKEN_PROGRAM,
    COMPUTE_BUDGET_PROGRAM,
    DEFAULT_RPC_URLS,
    MEMO_PROGRAM,
    SUBSCRIPTIONS_PROGRAM,
    SUBSCRIPTIONS_SUBSCRIBE_DISCRIMINATOR,
    SUBSCRIPTIONS_TRANSFER_DISCRIMINATOR,
    SYSTEM_PROGRAM,
    TOKEN_2022_PROGRAM,
    TOKEN_PROGRAM,
} from '../constants.js';
import { getSubscriptionAuthorityDecoder } from '../generated/subscriptions/accounts/subscriptionAuthority.js';
import { getSubscriptionDelegationDecoder } from '../generated/subscriptions/accounts/subscriptionDelegation.js';
import { getSubscribeInstructionDataDecoder } from '../generated/subscriptions/instructions/subscribe.js';
import { getTransferSubscriptionInstructionDataDecoder } from '../generated/subscriptions/instructions/transferSubscription.js';
import { findEventAuthorityPda } from '../generated/subscriptions/pdas/eventAuthority.js';
import * as Methods from '../Methods.js';
import {
    deriveSubscriptionAuthorityPda,
    deriveSubscriptionPda,
    mapSubscriptionPeriodToHours,
} from '../shared/subscription.js';
import { coSignBase64Transaction } from '../utils/transactions.js';

const MAX_COMPUTE_UNIT_LIMIT = 200_000;
const MAX_SPONSORED_COMPUTE_UNIT_PRICE_MICROLAMPORTS = 10_000n;

export interface SubscriptionReplayStore extends Store.Store {
    reserve(key: string, value?: unknown, ttlSeconds?: number): Promise<boolean>;
}

async function claimConsumed(store: SubscriptionReplayStore, key: string): Promise<boolean> {
    return await store.reserve(key, true);
}

/**
 * Creates a Solana `subscription` method for usage on the server.
 *
 * The server publishes a `Plan` on-chain out of band; the 402 challenge
 * pins the `planId` along with the period and amount. On activation the
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
        planIdNumeric,
        planBump,
        planCreatedAt,
        merchant,
        mint,
        decimals,
        tokenProgram,
        puller,
        recipient,
        periodUnit,
        periodCount,
        network = 'mainnet-beta',
        programId = SUBSCRIPTIONS_PROGRAM,
        signer,
        store,
        splits,
        subscriptionExpires,
    } = parameters;

    if (tokenProgram !== TOKEN_PROGRAM && tokenProgram !== TOKEN_2022_PROGRAM) {
        throw new Error(`tokenProgram must be ${TOKEN_PROGRAM} or ${TOKEN_2022_PROGRAM}`);
    }

    if (!signer || !isTransactionPartialSigner(signer)) {
        throw new Error('subscription signer is required and must implement signTransactions()');
    }
    if (signer.address !== puller) {
        throw new Error('subscription signer address must equal puller');
    }
    if (!store || typeof store.reserve !== 'function') {
        throw new Error('subscription store must implement atomic reserve(key, value)');
    }

    // Validate the period mapping up front so misconfigured servers fail at boot,
    // not on the first challenge.
    const expectedPeriodHours = mapSubscriptionPeriodToHours(periodUnit, periodCount);

    const rpcUrl = parameters.rpcUrl ?? DEFAULT_RPC_URLS[network] ?? DEFAULT_RPC_URLS['mainnet-beta'];

    const method = Method.toServer(Methods.subscription, {
        defaults: {
            amount: '0',
            currency: mint,
            methodDetails: {
                decimals,
                expectedCreatedAt: String(planCreatedAt),
                expectedPeriodHours: String(expectedPeriodHours),
                merchant,
                mint,
                planBump,
                planId,
                planIdNumeric: String(planIdNumeric),
                puller,
                tokenProgram,
            },
            periodCount: String(periodCount),
            periodUnit,
            recipient,
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
                    expectedCreatedAt: String(planCreatedAt),
                    expectedPeriodHours: String(expectedPeriodHours),
                    feePayer: true,
                    feePayerKey: signer.address,
                    merchant,
                    mint,
                    network,
                    planBump,
                    planId,
                    planIdNumeric: String(planIdNumeric),
                    programId,
                    puller,
                    tokenProgram,
                    ...(splits?.length ? { splits } : {}),
                    ...(recentBlockhash ? { recentBlockhash } : {}),
                },
                periodCount: request.periodCount ?? String(periodCount),
                periodUnit: request.periodUnit ?? periodUnit,
                recipient,
                ...(subscriptionExpires ? { subscriptionExpires } : {}),
            };
        },

        async verify({ credential }) {
            const cred = credential as unknown as CredentialPayload;
            const challenge = cred.challenge.request;
            const payloadType = resolvePayloadType(cred.payload);

            if (payloadType === 'signature') {
                throw new Error('Subscription signature-mode activation is unsupported; submit the signed transaction');
            }

            // `settleActivation` atomically claims the activation signature's
            // replay marker before broadcasting and hands the claimed key back.
            // We now own that reservation: every fallible step below (PDA fetch,
            // terms checks) must release it on error so a transient failure does
            // not permanently brick a legitimate retry, matching the Rust port's
            // release-on-error window. The claim is disarmed (kept) only once a
            // receipt is produced on the happy path, so a genuine replay of the
            // same activation signature stays rejected.
            const { consumedKey, subscriber: subscriberAddress } = await settleActivation(
                cred,
                challenge,
                rpcUrl,
                store,
                signer,
                payloadType,
            );

            try {
                const subscriptionPda = await deriveSubscriptionPda({
                    planPda: address(challenge.methodDetails.planId),
                    programId: address(challenge.methodDetails.programId ?? SUBSCRIPTIONS_PROGRAM),
                    subscriber: address(subscriberAddress),
                });

                const expectedPeriodHours = mapSubscriptionPeriodToHours(
                    challenge.periodUnit,
                    Number(challenge.periodCount),
                );

                const delegation = await fetchSubscriptionDelegation(rpcUrl, subscriptionPda);
                if (!delegation) {
                    throw new Error('SubscriptionDelegation account not found after activation');
                }

                if (delegation.planPda !== challenge.methodDetails.planId) {
                    throw new Error(
                        `SubscriptionDelegation plan mismatch: expected ${challenge.methodDetails.planId}, got ${delegation.planPda}`,
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

                const periodLengthSeconds = expectedPeriodHours * 3600;
                const periodStartTs = delegation.currentPeriodStartTs;
                const periodEndTs = periodStartTs + periodLengthSeconds;

                const subscriptionId = base64UrlEncodeNoPadding(decodeBase58(subscriptionPda.toString()));

                return Receipt.from({
                    method: 'solana',
                    ...(cred.challenge.id ? { challengeId: cred.challenge.id } : {}),
                    ...(challenge.externalId ? { externalId: challenge.externalId } : {}),
                    // Subscription-specific receipt extensions live alongside the
                    // Receipt's standard fields. The mppx framework treats unknown
                    // fields as opaque metadata.
                    // @ts-expect-error subscription extensions are not in the base Receipt type
                    expiresAt: challenge.subscriptionExpires,

                    periodEndTs: new Date(periodEndTs * 1000).toISOString(),

                    periodIndex: '0',

                    periodStartTs: new Date(periodStartTs * 1000).toISOString(),
                    planId: challenge.methodDetails.planId,
                    reference: subscriptionPda.toString(),
                    status: 'success',
                    subscriptionId,
                    timestamp: new Date().toISOString(),
                });
            } catch (err) {
                // A post-settlement failure (PDA fetch, on-chain terms mismatch)
                // means no receipt was issued, so release the reservation the
                // successful claim took — otherwise a transient RPC error or a
                // lagging on-chain read would permanently reject a legitimate
                // retry of the same activation. Best-effort: a failed delete
                // cannot make the original error any worse.
                await store.delete(consumedKey);
                throw err;
            }
        },
    });

    return method;
}

// ── Payload type resolution ──

function resolvePayloadType(payload: {
    signature?: string;
    transaction?: string;
    type?: string;
}): 'signature' | 'transaction' {
    if (payload.type === 'signature') return 'signature';
    if (payload.type === 'transaction') return 'transaction';
    throw new Error('Missing or invalid payload type: must be "transaction" or "signature"');
}

// ── Activation settlement ──

async function settleActivation(
    credential: CredentialPayload,
    challenge: ChallengeRequest,
    rpcUrl: string,
    store: SubscriptionReplayStore,
    signer: TransactionPartialSigner,
    payloadType: 'signature' | 'transaction',
): Promise<{ consumedKey: string; subscriber: string }> {
    if (payloadType === 'transaction') {
        const { transaction: clientTxBase64 } = credential.payload;
        if (!clientTxBase64) {
            throw new Error('Missing transaction data in credential payload');
        }

        const subscriber = await validateActivationInstructions(clientTxBase64, challenge, rpcUrl);

        let txToSend = clientTxBase64;
        const message = decodeCompiledMessage(clientTxBase64);
        if (message.staticAccounts[0] !== signer.address) {
            throw new Error(
                `Signer ${signer.address} must be the transaction fee payer (account index 0) to be co-signed`,
            );
        }
        txToSend = await coSignBase64Transaction(signer, clientTxBase64);

        // The activation signature is the transaction's own first signature and
        // is exactly what `sendTransaction` echoes back, so it is a stable
        // replay key known before broadcast.
        const signature = signatureFromWireTransaction(txToSend);
        const consumedKey = `solana-subscription:consumed:${signature}`;

        if (!(await claimConsumed(store, consumedKey))) {
            throw new Error('Activation signature already consumed');
        }

        try {
            const subscriptionPda = await deriveSubscriptionPda({
                planPda: address(challenge.methodDetails.planId),
                programId: address(challenge.methodDetails.programId ?? SUBSCRIPTIONS_PROGRAM),
                subscriber: address(subscriber),
            });
            const delegationAlreadyExists = (await fetchSubscriptionDelegation(rpcUrl, subscriptionPda)) !== null;

            if (delegationAlreadyExists) {
                if (!(await isSignatureConfirmed(rpcUrl, signature))) {
                    throw new Error(
                        'Subscription is already active, but the submitted activation signature was not confirmed',
                    );
                }
            } else {
                await simulateTransaction(rpcUrl, txToSend);
                const broadcastSignature = await broadcastTransaction(rpcUrl, txToSend);
                if (broadcastSignature !== signature) {
                    throw new Error(
                        'RPC returned a signature that does not match the submitted activation transaction',
                    );
                }
                await waitForConfirmation(rpcUrl, broadcastSignature);
            }
        } catch (err) {
            await store.delete(consumedKey);
            throw err;
        }

        return { consumedKey, subscriber };
    }

    throw new Error('Subscription signature-mode activation is unsupported; submit the signed transaction');
}

/**
 * The first (fee-payer) signature of a signed base64 wire transaction,
 * base58-encoded. This equals the value `sendTransaction` returns, so it is a
 * stable replay key known before broadcast — letting the activation guard claim
 * the consumed marker atomically up front rather than after confirmation.
 */
function signatureFromWireTransaction(wireTxBase64: string): string {
    const tx = getTransactionDecoder().decode(getBase64Codec().encode(wireTxBase64));
    return getSignatureFromTransaction(tx);
}

// ── Transaction parsing (lightweight, pre-broadcast) ──
//
// v0: we extract the subscriber and assert the transaction touches the
// subscriptions program identified by `methodDetails.programId`. Full
// instruction allowlist enforcement (one subscribe, one transfer_subscription,
// in order, with re-derived PDAs) lives in `validateActivationInstructions`
// and is intentionally lightweight in v0; on-chain enforcement is the source
// of truth for amount/period/destination correctness.

type CompiledMessage = {
    addressTableLookups?: readonly unknown[];
    header: {
        numReadonlyNonSignerAccounts: number;
        numReadonlySignerAccounts: number;
        numSignerAccounts: number;
    };
    instructions: readonly CompiledInstruction[];
    staticAccounts: readonly string[];
    version: number | 'legacy';
};

type CompiledInstruction = {
    accountIndices?: readonly number[];
    data: Uint8Array;
    programAddressIndex: number;
};

function assertLegacyOrV0Message(version: number | 'legacy', context: string): void {
    if (version === 'legacy' || version === 0) {
        return;
    }
    throw new Error(
        `${context}: unsupported transaction message version ${version} - only legacy and v0 messages are accepted`,
    );
}

/** Resolve a static account address by index, throwing on an out-of-range index. */
function accountAddress(message: CompiledMessage, index: number, label: string): string {
    const value = message.staticAccounts[index];
    if (value === undefined) {
        throw new Error(`Invalid ${label} index`);
    }
    return value;
}

function decodeCompiledMessage(clientTxBase64: string): CompiledMessage {
    let message: CompiledMessage;
    try {
        const txBytes = getBase64Codec().encode(clientTxBase64);
        const decoded = getTransactionDecoder().decode(txBytes);
        message = getCompiledTransactionMessageDecoder().decode(decoded.messageBytes) as unknown as CompiledMessage;
    } catch (e) {
        throw new Error(`Invalid transaction: ${e instanceof Error ? e.message : String(e)}`);
    }
    // Reject any versioned message beyond legacy/v0 before touching
    // `.instructions` / `.addressTableLookups`. A v1 message decodes to a shape
    // that carries neither field, so the ALT guard would be silently skipped
    // and the instruction loop would crash with a TypeError on hostile input.
    assertLegacyOrV0Message(message.version, 'Activation transaction');
    return message;
}

function extractSubscriberFromTransaction(clientTxBase64: string, challenge: ChallengeRequest): string {
    const message = decodeCompiledMessage(clientTxBase64);
    const signers = message.staticAccounts.slice(0, message.header.numSignerAccounts);
    const feePayer = challenge.methodDetails.feePayerKey;
    if (!feePayer || signers[0] !== feePayer) {
        throw new Error('Configured subscription fee payer must be signer account index 0');
    }
    if (signers.length !== 2 || signers[1] === feePayer) {
        throw new Error('Canonical subscription activation requires exactly fee-payer and subscriber signers');
    }
    return signers[1];
}

async function validateActivationInstructions(
    clientTxBase64: string,
    challenge: ChallengeRequest,
    rpcUrl: string,
): Promise<string> {
    const message = decodeCompiledMessage(clientTxBase64);

    if (message.addressTableLookups?.length) {
        throw new Error('v0 transactions with address lookup tables are not supported in activation flow');
    }

    const programId = challenge.methodDetails.programId ?? SUBSCRIPTIONS_PROGRAM;
    const subscriber = extractSubscriberFromTransaction(clientTxBase64, challenge);
    const feePayer = challenge.methodDetails.feePayerKey!;
    const programAddress = address(programId);
    const planPda = address(challenge.methodDetails.planId);
    const mint = address(challenge.methodDetails.mint);
    const tokenProgram = address(challenge.methodDetails.tokenProgram);
    const subscriptionPda = await deriveSubscriptionPda({
        planPda,
        programId: programAddress,
        subscriber: address(subscriber),
    });
    const subscriptionAuthority = await deriveSubscriptionAuthorityPda({
        mint,
        programId: programAddress,
        subscriber: address(subscriber),
    });
    const [subscriberAta] = await findAssociatedTokenPda({
        mint,
        owner: address(subscriber),
        tokenProgram,
    });
    const [recipientAta] = await findAssociatedTokenPda({
        mint,
        owner: address(challenge.recipient),
        tokenProgram,
    });
    const [eventAuthority] = await findEventAuthorityPda({ programAddress });

    const ataOwners = new Set<string>();
    let subscribeIndex: number | undefined;
    let transferIndex: number | undefined;
    let memoIndex: number | undefined;
    let computeLimitSeen = false;
    let computePriceSeen = false;
    for (const [index, ix] of message.instructions.entries()) {
        const program = message.staticAccounts[ix.programAddressIndex];
        if (program === undefined) {
            throw new Error('Activation transaction instruction references an out-of-range program id index');
        }

        if (program === programId) {
            const disc = ix.data[0];
            if (disc === SUBSCRIPTIONS_SUBSCRIBE_DISCRIMINATOR) {
                if (subscribeIndex !== undefined) throw new Error('Multiple subscribe instructions found');
                subscribeIndex = index;
                if (ix.data.length !== 74) throw new Error('Canonical subscribe instruction data must be 74 bytes');
                assertCanonicalAccounts(message, ix, [
                    [subscriber, true, true],
                    [
                        challenge.methodDetails.merchant,
                        challenge.methodDetails.merchant === feePayer,
                        challenge.methodDetails.merchant === feePayer,
                    ],
                    [planPda, false, false],
                    [subscriptionPda, true, false],
                    [subscriptionAuthority, false, false],
                    [SYSTEM_PROGRAM, false, false],
                    [eventAuthority, false, false],
                    [programId, false, false],
                    [feePayer, true, true],
                ]);
                const decoded = getSubscribeInstructionDataDecoder().decode(ix.data);
                const expectedAmount = BigInt(challenge.amount);
                const expectedPeriodHours = BigInt(challenge.methodDetails.expectedPeriodHours);
                if (
                    decoded.subscribeData.planId !== BigInt(challenge.methodDetails.planIdNumeric) ||
                    decoded.subscribeData.planBump !== challenge.methodDetails.planBump ||
                    decoded.subscribeData.expectedMint !== mint ||
                    decoded.subscribeData.expectedAmount !== expectedAmount ||
                    decoded.subscribeData.expectedPeriodHours !== expectedPeriodHours ||
                    decoded.subscribeData.expectedCreatedAt !== BigInt(challenge.methodDetails.expectedCreatedAt)
                ) {
                    throw new Error('SubscribeData does not match the challenged plan snapshot');
                }
                const liveInitId = await fetchSubscriptionAuthorityInitId(rpcUrl, subscriptionAuthority);
                if (liveInitId === null || decoded.subscribeData.expectedSubscriptionAuthorityInitId !== liveInitId) {
                    throw new Error('SubscribeData authority init id does not match the live SubscriptionAuthority');
                }
            } else if (disc === SUBSCRIPTIONS_TRANSFER_DISCRIMINATOR) {
                if (transferIndex !== undefined) throw new Error('Multiple transfer_subscription instructions found');
                transferIndex = index;
                if (ix.data.length !== 73) {
                    throw new Error('Canonical transfer_subscription instruction data must be 73 bytes');
                }
                assertCanonicalAccounts(message, ix, [
                    [subscriptionPda, true, false],
                    [planPda, false, false],
                    [subscriptionAuthority, false, false],
                    [subscriberAta, true, false],
                    [recipientAta, true, false],
                    [challenge.methodDetails.puller, true, true],
                    [mint, false, false],
                    [tokenProgram, false, false],
                    [eventAuthority, false, false],
                    [programId, false, false],
                ]);
                const decoded = getTransferSubscriptionInstructionDataDecoder().decode(ix.data);
                if (
                    decoded.transferData.amount !== BigInt(challenge.amount) ||
                    decoded.transferData.delegator !== subscriber ||
                    decoded.transferData.mint !== mint
                ) {
                    throw new Error('TransferData does not match subscriber, mint, and challenged amount');
                }
            } else {
                throw new Error(
                    `Activation transaction contains a disallowed subscriptions-program instruction (discriminator ${disc}); only subscribe and transfer_subscription are allowed`,
                );
            }
        } else if (program === COMPUTE_BUDGET_PROGRAM || program === MEMO_PROGRAM) {
            if (program === COMPUTE_BUDGET_PROGRAM) {
                if ((ix.accountIndices?.length ?? 0) !== 0) {
                    throw new Error('Compute budget instruction must not have accounts');
                }
                if (ix.data[0] === 2 && ix.data.length === 5) {
                    if (computeLimitSeen) throw new Error('Duplicate compute unit limit instruction');
                    computeLimitSeen = true;
                    const units = new DataView(ix.data.buffer, ix.data.byteOffset + 1, 4).getUint32(0, true);
                    if (units > MAX_COMPUTE_UNIT_LIMIT) {
                        throw new Error(`Compute unit limit ${units} exceeds maximum ${MAX_COMPUTE_UNIT_LIMIT}`);
                    }
                } else if (ix.data[0] === 3 && ix.data.length === 9) {
                    if (computePriceSeen) throw new Error('Duplicate compute unit price instruction');
                    computePriceSeen = true;
                    const price = new DataView(ix.data.buffer, ix.data.byteOffset + 1, 8).getBigUint64(0, true);
                    if (price > MAX_SPONSORED_COMPUTE_UNIT_PRICE_MICROLAMPORTS) {
                        throw new Error(
                            `Compute unit price ${price} exceeds maximum ${MAX_SPONSORED_COMPUTE_UNIT_PRICE_MICROLAMPORTS}`,
                        );
                    }
                } else {
                    throw new Error('Unsupported or malformed compute budget instruction');
                }
            } else {
                if (memoIndex !== undefined || !challenge.externalId) {
                    throw new Error('Activation memo is duplicated or was not challenged');
                }
                if (
                    (ix.accountIndices?.length ?? 0) !== 0 ||
                    new TextDecoder().decode(ix.data) !== challenge.externalId
                ) {
                    throw new Error('Activation memo does not match externalId');
                }
                memoIndex = index;
            }
            continue;
        } else if (program === ASSOCIATED_TOKEN_PROGRAM) {
            const owner = await validateActivationAtaInstruction(message, ix, challenge, feePayer);
            if (owner !== subscriber && owner !== challenge.recipient) {
                throw new Error('Activation ATA owner must be the subscriber or recipient');
            }
            if (ataOwners.has(owner)) throw new Error('Duplicate activation ATA creation');
            ataOwners.add(owner);
            continue;
        } else {
            throw new Error(
                `Activation transaction invokes a disallowed program ${program}; the fee payer will not co-sign a transaction outside the subscription activation allowlist`,
            );
        }
    }

    if (subscribeIndex === undefined) throw new Error('Activation transaction is missing subscribe instruction');
    if (transferIndex === undefined)
        throw new Error('Activation transaction is missing transfer_subscription instruction');
    if (transferIndex < subscribeIndex) {
        throw new Error('subscribe must precede transfer_subscription in activation transaction');
    }
    if (memoIndex !== undefined && memoIndex < transferIndex) {
        throw new Error('Activation memo must follow transfer_subscription');
    }
    if (!computeLimitSeen) {
        throw new Error('Activation transaction must contain exactly one SetComputeUnitLimit instruction');
    }
    if (!ataOwners.has(subscriber) || !ataOwners.has(challenge.recipient) || ataOwners.size !== 2) {
        throw new Error('Activation must create subscriber and recipient ATAs idempotently');
    }
    return subscriber;
}

function assertCanonicalAccounts(
    message: CompiledMessage,
    ix: CompiledInstruction,
    expected: ReadonlyArray<readonly [string | { toString(): string }, boolean, boolean]>,
): void {
    if ((ix.accountIndices?.length ?? 0) !== expected.length) {
        throw new Error(
            `Canonical instruction expected ${expected.length} accounts, got ${ix.accountIndices?.length ?? 0}`,
        );
    }
    expected.forEach(([expectedAddress, writable, signer], position) => {
        const accountIndex = ix.accountIndices![position];
        const actual = accountAddress(message, accountIndex, `instruction account ${position}`);
        if (actual !== expectedAddress.toString()) {
            throw new Error(`Canonical instruction account ${position} mismatch`);
        }
        if (isSignerIndex(message, accountIndex) !== signer) {
            throw new Error(`Canonical instruction account ${position} signer privilege mismatch`);
        }
        if (isWritableIndex(message, accountIndex) !== writable) {
            throw new Error(`Canonical instruction account ${position} writable privilege mismatch`);
        }
    });
}

function isSignerIndex(message: CompiledMessage, index: number): boolean {
    return index < message.header.numSignerAccounts;
}

function isWritableIndex(message: CompiledMessage, index: number): boolean {
    if (isSignerIndex(message, index)) {
        return index < message.header.numSignerAccounts - message.header.numReadonlySignerAccounts;
    }
    return index < message.staticAccounts.length - message.header.numReadonlyNonSignerAccounts;
}

/**
 * Validate an Associated-Token-Account `CreateIdempotent` instruction in an
 * activation transaction before the fee payer co-signs it. Mirrors the charge
 * verifier's `validateCreateAtaIdempotentInstruction`: require the idempotent
 * discriminator with the canonical 6-account layout, and assert that the
 * funding account is the transaction fee payer, the mint is the plan mint, the
 * token program is the configured one, the owner is one the challenge
 * authorizes, and that the ATA address re-derives from `(owner, mint, token)`.
 */
async function validateActivationAtaInstruction(
    message: CompiledMessage,
    ix: CompiledInstruction,
    challenge: ChallengeRequest,
    expectedPayer: string | undefined,
): Promise<string> {
    if (ix.data.length !== 1 || ix.data[0] !== 1) {
        throw new Error('Activation transaction may only use idempotent ATA creation');
    }
    if (ix.accountIndices?.length !== 6) {
        throw new Error('Unexpected ATA creation account layout in activation transaction');
    }

    const payer = accountAddress(message, ix.accountIndices[0], 'ATA payer');
    const ata = accountAddress(message, ix.accountIndices[1], 'ATA address');
    const owner = accountAddress(message, ix.accountIndices[2], 'ATA owner');
    const mint = accountAddress(message, ix.accountIndices[3], 'ATA mint');
    const systemProgram = accountAddress(message, ix.accountIndices[4], 'ATA system program');
    const tokenProgram = accountAddress(message, ix.accountIndices[5], 'ATA token program');

    if (expectedPayer === undefined || payer !== expectedPayer) {
        throw new Error('ATA payer must be the transaction fee payer in activation transaction');
    }
    if (mint !== challenge.methodDetails.mint) {
        throw new Error('ATA creation mint does not match the plan mint');
    }
    if (systemProgram !== SYSTEM_PROGRAM) {
        throw new Error('ATA creation must reference the System Program');
    }
    if (tokenProgram !== TOKEN_PROGRAM && tokenProgram !== TOKEN_2022_PROGRAM) {
        throw new Error('ATA creation uses an unsupported token program');
    }
    if (challenge.methodDetails.tokenProgram && tokenProgram !== challenge.methodDetails.tokenProgram) {
        throw new Error('ATA creation token program does not match the configured token program');
    }

    const [expectedAta] = await findAssociatedTokenPda({
        mint: address(mint),
        owner: address(owner),
        tokenProgram: address(tokenProgram),
    });
    if (ata !== expectedAta) {
        throw new Error('ATA creation address does not match owner/mint/token program');
    }
    assertCanonicalAccounts(message, ix, [
        [expectedPayer, true, true],
        [expectedAta, true, false],
        [
            owner,
            owner === expectedPayer || owner === message.staticAccounts[1],
            owner === expectedPayer || owner === message.staticAccounts[1],
        ],
        [mint, false, false],
        [SYSTEM_PROGRAM, false, false],
        [tokenProgram, false, false],
    ]);
    return owner;
}

// ── On-chain SubscriptionDelegation decoding (v0) ──
//
// v0 deserialization reads the fields this profile needs by offset. The
// definitive schema lives in the subscriptions program's Codama client; a
// follow-up should adopt that typed client and replace this manual decoder.

type SubscriptionDelegation = {
    amountPerPeriod: string;
    amountPulledInPeriod: string;
    currentPeriodStartTs: number;
    periodHours: number;
    planPda: string;
    subscriber: string;
};

async function fetchSubscriptionDelegation(
    rpcUrl: string,
    subscriptionPda: { toString(): string },
): Promise<SubscriptionDelegation | null> {
    const rpc = createSolanaRpc(rpcUrl);
    const account = await rpc.getAccountInfo(address(subscriptionPda.toString()), { encoding: 'base64' }).send();
    if (!account.value) return null;
    const [b64] = account.value.data;
    const data = new Uint8Array(getBase64Codec().encode(b64));
    return decodeSubscriptionDelegation(data);
}

function decodeSubscriptionDelegation(data: Uint8Array): SubscriptionDelegation {
    const decoded = getSubscriptionDelegationDecoder().decode(data);

    return {
        amountPerPeriod: decoded.terms.amount.toString(),
        amountPulledInPeriod: decoded.amountPulledInPeriod.toString(),
        currentPeriodStartTs: Number(decoded.currentPeriodStartTs),
        periodHours: Number(decoded.terms.periodHours),
        planPda: decoded.header.delegatee,
        subscriber: decoded.header.delegator,
    };
}

// ── Base58/base64url helpers (minimal, dependency-free) ──

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

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

async function fetchSubscriptionAuthorityInitId(
    rpcUrl: string,
    authority: { toString(): string },
): Promise<bigint | null> {
    const rpc = createSolanaRpc(rpcUrl);
    const account = await rpc.getAccountInfo(address(authority.toString()), { encoding: 'base64' }).send();
    if (!account.value) return null;
    const [encoded] = account.value.data;
    return getSubscriptionAuthorityDecoder().decode(getBase64Codec().encode(encoded)).initId;
}

async function isSignatureConfirmed(rpcUrl: string, signature: string): Promise<boolean> {
    const response = await fetch(rpcUrl, {
        body: JSON.stringify({
            id: 1,
            jsonrpc: '2.0',
            method: 'getSignatureStatuses',
            params: [[signature], { searchTransactionHistory: true }],
        }),
        headers: { 'Content-Type': 'application/json' },
        method: 'POST',
    });
    const data = (await response.json()) as {
        error?: { message: string };
        result?: { value?: Array<{ confirmationStatus?: string; err: unknown } | null> };
    };
    if (data.error) throw new Error(`RPC error: ${data.error.message}`);
    const status = data.result?.value?.[0];
    return (
        status !== null &&
        status !== undefined &&
        status.err === null &&
        (status.confirmationStatus === 'confirmed' || status.confirmationStatus === 'finalized')
    );
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
        id?: string;
        request: ChallengeRequest;
    };
    payload: {
        signature?: string;
        transaction?: string;
        type?: string;
    };
};

type ChallengeRequest = {
    amount: string;
    currency: string;
    description?: string;
    externalId?: string;
    methodDetails: {
        decimals: number;
        expectedCreatedAt: string;
        expectedPeriodHours: string;
        feePayer?: boolean;
        feePayerKey?: string;
        merchant: string;
        mint: string;
        network?: string;
        planBump: number;
        planId: string;
        planIdNumeric: string;
        programId?: string;
        puller: string;
        recentBlockhash?: string;
        splits?: Array<{ bps: number; recipient: string }>;
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
    extractSubscriberFromTransaction,
    validateActivationInstructions,
};

export declare namespace subscription {
    type Parameters = {
        /** Token decimals for the mint. */
        decimals: number;
        /** Merchant/plan owner used by the canonical subscribe instruction. */
        merchant: string;
        /** Base58 of the SPL token mint. MUST match the on-chain plan.mint. */
        mint: string;
        /** Solana network. Defaults to `mainnet-beta`. */
        network?: 'devnet' | 'localnet' | 'mainnet-beta' | 'testnet' | (string & {});
        /** Positive integer count of `periodUnit` values per billing period (1..365 for day, 1..52 for week). */
        periodCount: number;
        /** Billing period unit. The Solana profile supports `day` and `week` only. */
        periodUnit: 'day' | 'week';
        /** Plan PDA bump snapshot. */
        planBump: number;
        /** Plan creation timestamp snapshot. */
        planCreatedAt: bigint;
        /** Base58 of the on-chain Plan PDA. */
        planId: string;
        /** Numeric plan id used by SubscribeData. */
        planIdNumeric: bigint;
        /** Base58 of the subscriptions program ID. Defaults to the canonical deployment. */
        programId?: string;
        /** Base58 of the server's puller pubkey (must be in plan.pullers or plan.owner). */
        puller: string;
        /** Base58 of the primary recipient wallet. MUST match what plan.destinations resolves to. */
        recipient: string;
        /** Custom RPC URL. Defaults to the public RPC for the selected network. */
        rpcUrl?: string;
        /** Required puller/fee-payer signer. Its address must equal puller. */
        signer: TransactionPartialSigner;
        /** Advisory distribution splits. The on-chain split is governed by plan.destinations. */
        splits?: Array<{ bps: number; recipient: string }>;
        /** Replay store with an atomic put-if-absent reserve operation. */
        store: SubscriptionReplayStore;
        /** Optional {@link https://datatracker.ietf.org/doc/html/rfc3339 | RFC3339} expiry of the recurring authorization. */
        subscriptionExpires?: string;
        /** Base58 of the SPL Token or Token-2022 program ID. */
        tokenProgram: string;
    };
}
