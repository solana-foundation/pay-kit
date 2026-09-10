import {
    type Address,
    address,
    appendTransactionMessageInstructions,
    type Base64EncodedWireTransaction,
    type Blockhash,
    createSignableMessage,
    createSolanaRpc,
    createTransactionMessage,
    getBase58Decoder,
    getBase58Encoder,
    getBase64Codec,
    getBase64EncodedWireTransaction,
    getPublicKeyFromAddress,
    type Instruction,
    type MessagePartialSigner,
    partiallySignTransactionMessageWithSigners,
    pipe,
    prependTransactionMessageInstructions,
    setTransactionMessageFeePayer,
    setTransactionMessageFeePayerSigner,
    setTransactionMessageLifetimeUsingBlockhash,
    type TransactionSigner,
    verifySignature,
} from '@solana/kit';
import {
    findEventAuthorityPda,
    getInitSubscriptionAuthorityInstructionAsync,
    getPlanDecoder,
    getSubscribeInstructionAsync,
    getSubscriptionAuthorityDecoder,
    getTransferSubscriptionInstruction,
} from '@solana/subscriptions';
import { getSetComputeUnitLimitInstruction, getSetComputeUnitPriceInstruction } from '@solana-program/compute-budget';
import { findAssociatedTokenPda, getCreateAssociatedTokenIdempotentInstruction } from '@solana-program/token';
import type { Challenge as MppxChallenge } from 'mppx';
import { Credential, Method } from 'mppx';

import { DEFAULT_RPC_URLS, MEMO_PROGRAM, normalizeNetwork, SYSTEM_PROGRAM } from '../constants.js';
import * as Methods from '../Methods.js';
import {
    assertPeriodHoursInRange,
    deriveSubscriptionAuthorityPda,
    deriveSubscriptionPda,
    mapSubscriptionPeriodToHours,
} from '../shared/subscription.js';

/** Domain separator for reusable subscription authentication proofs. */
export const SUBSCRIPTION_AUTHENTICATION_DOMAIN = 'mpp-subscription-auth-v1';

/** Reusable payer proof bound to one activation challenge and delegation. */
export interface SubscriptionAuthentication {
    readonly challengeId: string;
    readonly payer: string;
    readonly signature: string;
    readonly type: 'proof';
}

/** A signer that can authorize both the activation transaction and bearer proof. */
export type SubscriptionSigner = MessagePartialSigner & TransactionSigner;

/** Canonical JCS bytes signed by a reusable subscription proof. */
export function subscriptionAuthenticationMessage(parameters: {
    readonly challengeId: string;
    readonly payer: string;
    readonly subscriptionDelegation: string;
}): Uint8Array {
    return new TextEncoder().encode(
        JSON.stringify({
            domain: SUBSCRIPTION_AUTHENTICATION_DOMAIN,
            payer: parameters.payer,
            subscriptionChallengeId: parameters.challengeId,
            subscriptionDelegation: parameters.subscriptionDelegation,
        }),
    );
}

/** Creates a reusable payer proof for access under an active subscription. */
export async function signSubscriptionAuthentication(parameters: {
    readonly challengeId: string;
    readonly signer: MessagePartialSigner;
    readonly subscriptionDelegation: string;
}): Promise<SubscriptionAuthentication> {
    const message = subscriptionAuthenticationMessage({
        challengeId: parameters.challengeId,
        payer: parameters.signer.address,
        subscriptionDelegation: parameters.subscriptionDelegation,
    });
    const [signatures] = await parameters.signer.signMessages([createSignableMessage(message)]);
    const signature = signatures?.[parameters.signer.address];
    if (!signature) throw new Error(`Signer ${parameters.signer.address} did not return a subscription proof`);
    return {
        challengeId: parameters.challengeId,
        payer: parameters.signer.address,
        signature: getBase58Decoder().decode(new Uint8Array(signature)),
        type: 'proof',
    };
}

/** Verifies a reusable payer proof against its bound delegation. */
export async function verifySubscriptionAuthentication(
    authentication: SubscriptionAuthentication,
    subscriptionDelegation: string,
): Promise<boolean> {
    try {
        const publicKey = await getPublicKeyFromAddress(authentication.payer as Address);
        const signature = getBase58Encoder().encode(authentication.signature);
        return await verifySignature(
            publicKey,
            signature as Parameters<typeof verifySignature>[1],
            subscriptionAuthenticationMessage({
                challengeId: authentication.challengeId,
                payer: authentication.payer,
                subscriptionDelegation,
            }),
        );
    } catch {
        return false;
    }
}

/** Serializes a later-use credential from the proof retained at activation. */
export function serializeSubscriptionAccessCredential(parameters: {
    readonly authentication: SubscriptionAuthentication;
    readonly challenge: MppxChallenge.Challenge;
    readonly subscriptionDelegation: string;
}): string {
    return Credential.serialize({
        challenge: parameters.challenge,
        payload: {
            authentication: parameters.authentication,
            subscriptionDelegation: parameters.subscriptionDelegation,
            type: 'proof',
        },
    });
}

/**
 * Creates a Solana `subscription` method for usage on the client.
 *
 * Builds the activation transaction (subscribe, transfer_subscription) and
 * signs as the subscriber. Pull mode requires callers to initialize the
 * authority explicitly; push mode initializes it when needed.
 * When `feePayer: true` is advertised in the challenge, the server's
 * `feePayerKey` is used as fee payer and the transaction is partially
 * signed; the server completes the signature before broadcasting.
 *
 * @example
 * ```ts
 * import { Mppx, solana } from '@solana/mpp/client'
 *
 * const method = solana.subscription({ signer, rpcUrl: 'https://api.devnet.solana.com' })
 * const mppx = Mppx.create({ methods: [method] })
 *
 * const response = await mppx.fetch('https://api.example.com/paid-content')
 * ```
 */
export function subscription(parameters: subscription.Parameters) {
    const { signer, broadcast = false, onProgress } = parameters;

    const method = Method.toClient(Methods.subscription, {
        async createCredential({ challenge }) {
            const { methodDetails } = challenge.request;
            const { network, feePayer: serverPaysFees } = methodDetails;

            if (serverPaysFees && broadcast) {
                throw new Error('broadcast=true cannot be used with fee sponsorship (feePayer: true)');
            }

            const subscriptionDelegation = await deriveSubscriptionPda({
                planPda: address(challenge.request.methodDetails.planAddress),
                programId: address(challenge.request.methodDetails.subscriptionProgram),
                subscriber: signer.address,
            });
            const authentication = await signSubscriptionAuthentication({
                challengeId: challenge.id,
                signer,
                subscriptionDelegation,
            });
            parameters.onAuthentication?.({
                authentication,
                challenge,
                subscriptionDelegation,
            });

            const rpcUrl =
                parameters.rpcUrl ??
                DEFAULT_RPC_URLS[normalizeNetwork(network ?? 'mainnet')] ??
                DEFAULT_RPC_URLS.mainnet;
            const authorityParameters = {
                mint: methodDetails.mint,
                programId: methodDetails.subscriptionProgram,
                rpcUrl,
                signer,
                tokenProgram: methodDetails.tokenProgram,
            };
            let subscriptionAuthorityInitId = await readSubscriptionAuthorityInitId(authorityParameters);
            if (subscriptionAuthorityInitId === null) {
                if (!broadcast) {
                    throw new Error(
                        'SubscriptionAuthority is not initialized; call initializeSubscriptionAuthority before using pull mode',
                    );
                }
                subscriptionAuthorityInitId = await initializeSubscriptionAuthority(authorityParameters);
            }

            const encodedTx = await buildSubscriptionActivationTransaction({
                computeUnitLimit: parameters.computeUnitLimit,
                computeUnitPrice: parameters.computeUnitPrice,
                onProgress,
                request: challenge.request,
                rpcUrl,
                signer,
                subscriptionAuthorityInitId,
            });

            const rpc = createSolanaRpc(rpcUrl);

            if (broadcast) {
                onProgress?.({ type: 'paying' });
                const signature = await rpc
                    .sendTransaction(encodedTx, { encoding: 'base64', skipPreflight: false })
                    .send();
                onProgress?.({ signature, type: 'confirming' });
                await confirmTransaction(rpc, signature);
                onProgress?.({ signature, type: 'activated' });

                return Credential.serialize({
                    challenge,
                    payload: { authentication, signature, type: 'signature' },
                });
            }

            onProgress?.({ transaction: encodedTx, type: 'signed' });
            return Credential.serialize({
                challenge,
                payload: { authentication, transaction: encodedTx, type: 'transaction' },
            });
        },
    });

    return method;
}

/**
 * Build and sign the activation transaction for a Solana subscription challenge.
 *
 * The SubscriptionAuthority is initialized in a separate transaction because
 * the subscribe instruction binds to its on-chain init id. The activation is
 * then assembled from the current Codama client so it stays aligned with the
 * deployed subscriptions program.
 */
export async function buildSubscriptionActivationTransaction(
    parameters: buildSubscriptionActivationTransaction.Parameters,
): Promise<Base64EncodedWireTransaction> {
    const {
        signer,
        subscriptionAuthorityInitId,
        request: { amount, externalId, recipient, methodDetails, periodCount, periodUnit },
        onProgress,
    } = parameters;
    const {
        network,
        mint,
        planAddress: planId,
        subscriptionProgram,
        tokenProgram,
        feePayer: serverPaysFees,
        feePayerKey,
        recentBlockhash: serverBlockhash,
    } = methodDetails;

    const periodHours = mapSubscriptionPeriodToHours(periodUnit, Number(periodCount));
    assertPeriodHoursInRange(periodHours);

    const rpcUrl =
        parameters.rpcUrl ?? DEFAULT_RPC_URLS[normalizeNetwork(network ?? 'mainnet')] ?? DEFAULT_RPC_URLS.mainnet;
    const rpc = createSolanaRpc(rpcUrl);

    onProgress?.({
        amount,
        mint,
        periodHours,
        planId,
        recipient,
        type: 'challenge',
    });

    if (serverPaysFees && !feePayerKey) {
        throw new Error('feePayer=true requires feePayerKey in methodDetails');
    }
    const useServerFeePayer = serverPaysFees === true;

    const subscriberAddress = signer.address;
    const mintAddress = address(mint);
    const planPda = address(planId);
    const programAddress = address(subscriptionProgram);
    const tokenProgramAddress = address(tokenProgram);
    const recipientAddress = address(recipient);

    const subscriptionAuthority = await deriveSubscriptionAuthorityPda({
        mint: mintAddress,
        programId: programAddress,
        subscriber: subscriberAddress,
    });
    const subscriptionPda = await deriveSubscriptionPda({
        planPda,
        programId: programAddress,
        subscriber: subscriberAddress,
    });

    const [subscriberAta] = await findAssociatedTokenPda({
        mint: mintAddress,
        owner: subscriberAddress,
        tokenProgram: tokenProgramAddress,
    });
    const [recipientAta] = await findAssociatedTokenPda({
        mint: mintAddress,
        owner: recipientAddress,
        tokenProgram: tokenProgramAddress,
    });

    const liveAuthorityInitId =
        subscriptionAuthorityInitId ?? (await fetchAuthorityInitId(rpc, subscriptionAuthority, programAddress));
    if (liveAuthorityInitId === null) {
        throw new Error('SubscriptionAuthority must be initialized before building an activation transaction');
    }

    const plan = await fetchPlan(rpc, planPda, programAddress);
    if (plan.data.mint !== mintAddress) throw new Error('Subscription plan mint does not match the challenge');
    if (plan.data.terms.amount !== BigInt(amount))
        throw new Error('Subscription plan amount does not match the challenge');
    if (plan.data.terms.periodHours !== BigInt(periodHours)) {
        throw new Error('Subscription plan period does not match the challenge');
    }

    const payerAddress = useServerFeePayer ? address(feePayerKey!) : subscriberAddress;
    const payerSigner = payerAddress === subscriberAddress ? signer : remoteSigner(payerAddress);
    const pullerAddress = methodDetails.puller ? address(methodDetails.puller) : subscriberAddress;
    const pullerSigner = pullerAddress === subscriberAddress ? signer : remoteSigner(pullerAddress);
    const [eventAuthority] = await findEventAuthorityPda({ programAddress });

    const subscriberAtaIx = stripRemoteSigner(
        getCreateAssociatedTokenIdempotentInstruction({
            ata: subscriberAta,
            mint: mintAddress,
            owner: subscriberAddress,
            payer: payerSigner,
            tokenProgram: tokenProgramAddress,
        }),
        payerAddress,
    );
    const recipientAtaIx = stripRemoteSigner(
        getCreateAssociatedTokenIdempotentInstruction({
            ata: recipientAta,
            mint: mintAddress,
            owner: recipientAddress,
            payer: payerSigner,
            tokenProgram: tokenProgramAddress,
        }),
        payerAddress,
    );
    const generatedSubscribe = await getSubscribeInstructionAsync(
        {
            eventAuthority,
            merchant: plan.owner,
            payer: payerSigner,
            planPda,
            selfProgram: programAddress,
            subscribeData: {
                expectedAmount: BigInt(amount),
                expectedCreatedAt: plan.data.terms.createdAt,
                expectedMint: mintAddress,
                expectedPeriodHours: BigInt(periodHours),
                expectedSubscriptionAuthorityInitId: liveAuthorityInitId,
                planBump: plan.bump,
                planId: plan.data.planId,
            },
            subscriber: signer,
            subscriptionAuthorityPda: subscriptionAuthority,
            subscriptionPda,
            systemProgram: address(SYSTEM_PROGRAM),
        },
        { programAddress },
    );
    const subscribeIx = stripRemoteSigner(generatedSubscribe, payerAddress);
    const transferIx = stripRemoteSigner(
        getTransferSubscriptionInstruction(
            {
                caller: pullerSigner,
                delegatorAta: subscriberAta,
                eventAuthority,
                planPda,
                receiverAta: recipientAta,
                selfProgram: programAddress,
                subscriptionAuthority,
                subscriptionPda,
                tokenMint: mintAddress,
                tokenProgram: tokenProgramAddress,
                transferData: { amount: BigInt(amount), delegator: subscriberAddress, mint: mintAddress },
            },
            { programAddress },
        ),
        pullerAddress,
    );

    const instructions: Instruction[] = [subscriberAtaIx, recipientAtaIx, subscribeIx, transferIx];

    if (externalId) {
        instructions.push(buildMemoInstruction(externalId));
    }

    onProgress?.({ type: 'signing' });

    const latestBlockhash = serverBlockhash
        ? { blockhash: serverBlockhash as Blockhash, lastValidBlockHeight: 0n }
        : (await rpc.getLatestBlockhash().send()).value;

    const txMessage = pipe(
        createTransactionMessage({ version: 0 }),
        msg =>
            useServerFeePayer
                ? setTransactionMessageFeePayer(address(feePayerKey!), msg)
                : setTransactionMessageFeePayerSigner(signer, msg),
        msg => setTransactionMessageLifetimeUsingBlockhash(latestBlockhash, msg),
        msg => appendTransactionMessageInstructions(instructions, msg),
        msg =>
            prependTransactionMessageInstructions(
                [
                    getSetComputeUnitPriceInstruction({ microLamports: parameters.computeUnitPrice ?? 1n }),
                    getSetComputeUnitLimitInstruction({ units: parameters.computeUnitLimit ?? 400_000 }),
                ],
                msg,
            ),
    );

    return getBase64EncodedWireTransaction(await partiallySignTransactionMessageWithSigners(txMessage));
}

/** Explicitly initialize the subscriber authority and return its live init id. */
export async function initializeSubscriptionAuthority(parameters: {
    mint: string;
    programId: string;
    rpcUrl: string;
    signer: SubscriptionSigner;
    tokenProgram: string;
}): Promise<bigint> {
    const rpc = createSolanaRpc(parameters.rpcUrl);
    const mint = address(parameters.mint);
    const programAddress = address(parameters.programId);
    const tokenProgram = address(parameters.tokenProgram);
    const authority = await deriveSubscriptionAuthorityPda({
        mint,
        programId: programAddress,
        subscriber: parameters.signer.address,
    });
    const existing = await fetchAuthorityInitId(rpc, authority, programAddress);
    if (existing !== null) return existing;

    const [ata] = await findAssociatedTokenPda({ mint, owner: parameters.signer.address, tokenProgram });
    const createAta = getCreateAssociatedTokenIdempotentInstruction({
        ata,
        mint,
        owner: parameters.signer.address,
        payer: parameters.signer,
        tokenProgram,
    });
    const init = await getInitSubscriptionAuthorityInstructionAsync(
        {
            owner: parameters.signer,
            subscriptionAuthority: authority,
            tokenMint: mint,
            tokenProgram,
            userAta: ata,
        },
        { programAddress },
    );
    const latestBlockhash = (await rpc.getLatestBlockhash().send()).value;
    const message = pipe(
        createTransactionMessage({ version: 0 }),
        msg => setTransactionMessageFeePayerSigner(parameters.signer, msg),
        msg => setTransactionMessageLifetimeUsingBlockhash(latestBlockhash, msg),
        msg => appendTransactionMessageInstructions([createAta, init], msg),
    );
    const transaction = getBase64EncodedWireTransaction(await partiallySignTransactionMessageWithSigners(message));
    const signature = await rpc.sendTransaction(transaction, { encoding: 'base64', skipPreflight: false }).send();
    await confirmTransaction(rpc, signature);
    const initialized = await fetchAuthorityInitId(rpc, authority, programAddress);
    if (initialized === null) throw new Error('SubscriptionAuthority account missing after initialization');
    return initialized;
}

async function readSubscriptionAuthorityInitId(parameters: {
    mint: string;
    programId: string;
    rpcUrl: string;
    signer: SubscriptionSigner;
    tokenProgram: string;
}): Promise<bigint | null> {
    const rpc = createSolanaRpc(parameters.rpcUrl);
    const programAddress = address(parameters.programId);
    const authority = await deriveSubscriptionAuthorityPda({
        mint: address(parameters.mint),
        programId: programAddress,
        subscriber: parameters.signer.address,
    });
    return await fetchAuthorityInitId(rpc, authority, programAddress);
}

function remoteSigner(remoteAddress: Address): TransactionSigner {
    return {
        address: remoteAddress,
        signTransactions() {
            return Promise.reject(new Error(`Remote signer ${remoteAddress} must be completed by the server`));
        },
    } as TransactionSigner;
}

function stripRemoteSigner(instruction: Instruction, remoteAddress: Address): Instruction {
    return {
        ...instruction,
        accounts: instruction.accounts?.map(meta =>
            meta.address === remoteAddress ? { address: meta.address, role: meta.role } : meta,
        ),
    };
}

async function fetchPlan(
    rpc: ReturnType<typeof createSolanaRpc>,
    plan: Address,
    expectedOwner: Address,
): Promise<ReturnType<ReturnType<typeof getPlanDecoder>['decode']>> {
    const account = await rpc.getAccountInfo(plan, { encoding: 'base64' }).send();
    if (!account.value) throw new Error('Subscription Plan account not found');
    if (account.value.owner !== expectedOwner) throw new Error('Subscription Plan owner does not match the program');
    return getPlanDecoder().decode(getBase64Codec().encode(account.value.data[0]));
}

async function fetchAuthorityInitId(
    rpc: ReturnType<typeof createSolanaRpc>,
    authority: Address,
    expectedOwner: Address,
): Promise<bigint | null> {
    const account = await rpc.getAccountInfo(authority, { encoding: 'base64' }).send();
    if (!account.value) return null;
    if (account.value.owner !== expectedOwner)
        throw new Error('SubscriptionAuthority owner does not match the program');
    return getSubscriptionAuthorityDecoder().decode(getBase64Codec().encode(account.value.data[0])).initId;
}

function buildMemoInstruction(memo: string): Instruction {
    const data = new TextEncoder().encode(memo);
    if (data.byteLength > 566) {
        throw new Error('memo cannot exceed 566 bytes');
    }
    return {
        accounts: [],
        data,
        programAddress: address(MEMO_PROGRAM),
    };
}

async function confirmTransaction(
    rpc: ReturnType<typeof createSolanaRpc>,
    signature: string,
    timeoutMs = 30_000,
): Promise<void> {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
        const { value } = await rpc.getSignatureStatuses([signature as unknown as never]).send();
        const status = value[0];
        if (status) {
            if (status.err) throw new Error(`Transaction failed: ${JSON.stringify(status.err)}`);
            if (status.confirmationStatus === 'confirmed' || status.confirmationStatus === 'finalized') return;
        }
        await new Promise(r => setTimeout(r, 2_000));
    }
    throw new Error('Transaction confirmation timeout');
}

export declare namespace subscription {
    type Parameters = {
        /**
         * If true, the client broadcasts the activation transaction itself and
         * sends the signature as a `type="signature"` credential. Cannot be
         * combined with server fee sponsorship.
         */
        broadcast?: boolean;
        /** Compute unit limit. Defaults to 400,000 (activation can include three program calls). */
        computeUnitLimit?: number;
        /** Compute unit price in micro-lamports for priority fees. Defaults to 1. */
        computeUnitPrice?: bigint;
        /** Receives the reusable access proof. Store it as a secret bearer credential. */
        onAuthentication?: (access: {
            authentication: SubscriptionAuthentication;
            challenge: MppxChallenge.Challenge;
            subscriptionDelegation: Address;
        }) => void;
        /** Called at each step of the activation process. */
        onProgress?: (event: ProgressEvent) => void;
        /** Custom RPC URL. If not set, inferred from the challenge's network field. */
        rpcUrl?: string;
        /** Solana transaction signer. The subscriber's funding key. */
        signer: SubscriptionSigner;
    };

    type ProgressEvent =
        | {
              amount: string;
              mint: string;
              periodHours: number;
              planId: string;
              recipient: string;
              type: 'challenge';
          }
        | { signature: string; type: 'activated' }
        | { signature: string; type: 'confirming' }
        | { transaction: string; type: 'signed' }
        | { type: 'paying' }
        | { type: 'signing' };
}

export declare namespace buildSubscriptionActivationTransaction {
    type Parameters = {
        /** Compute unit limit. Defaults to 400,000. */
        computeUnitLimit?: number;
        /** Compute unit price in micro-lamports for priority fees. Defaults to 1. */
        computeUnitPrice?: bigint;
        /** Called at each step of the activation build/signing process. */
        onProgress?: (
            event:
                | {
                      amount: string;
                      mint: string;
                      periodHours: number;
                      planId: string;
                      recipient: string;
                      type: 'challenge';
                  }
                | { type: 'signing' },
        ) => void;
        /** Decoded request from a Solana MPP subscription challenge. */
        request: {
            amount: string;
            currency: string;
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
        /** Custom RPC URL. If not set, inferred from the challenge network field. */
        rpcUrl?: string;
        /** Solana transaction signer (the subscriber). */
        signer: SubscriptionSigner;
        /** Live init id returned by the separately initialized SubscriptionAuthority. */
        subscriptionAuthorityInitId?: bigint;
    };
}
