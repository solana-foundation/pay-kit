import {
    AccountRole,
    type Address,
    address,
    appendTransactionMessageInstructions,
    type Base64EncodedWireTransaction,
    type Blockhash,
    createSolanaRpc,
    createTransactionMessage,
    getBase64Codec,
    getBase64EncodedWireTransaction,
    type Instruction,
    partiallySignTransactionMessageWithSigners,
    pipe,
    prependTransactionMessageInstructions,
    setTransactionMessageFeePayer,
    setTransactionMessageFeePayerSigner,
    setTransactionMessageLifetimeUsingBlockhash,
    type TransactionSigner,
} from '@solana/kit';
import { getSetComputeUnitLimitInstruction, getSetComputeUnitPriceInstruction } from '@solana-program/compute-budget';
import { findAssociatedTokenPda, getCreateAssociatedTokenIdempotentInstruction } from '@solana-program/token';
import { Credential, Method } from 'mppx';

import {
    DEFAULT_RPC_URLS,
    MEMO_PROGRAM,
    normalizeNetwork,
    SUBSCRIPTIONS_PROGRAM,
    SYSTEM_PROGRAM,
} from '../constants.js';
import { getSubscriptionAuthorityDecoder } from '../generated/subscriptions/accounts/subscriptionAuthority.js';
import { getInitSubscriptionAuthorityInstructionAsync } from '../generated/subscriptions/instructions/initSubscriptionAuthority.js';
import { getSubscribeInstructionAsync } from '../generated/subscriptions/instructions/subscribe.js';
import { getTransferSubscriptionInstruction } from '../generated/subscriptions/instructions/transferSubscription.js';
import { findEventAuthorityPda } from '../generated/subscriptions/pdas/eventAuthority.js';
import * as Methods from '../Methods.js';
import {
    assertPeriodHoursInRange,
    deriveSubscriptionAuthorityPda,
    deriveSubscriptionPda,
    mapSubscriptionPeriodToHours,
} from '../shared/subscription.js';

export function subscription(parameters: subscription.Parameters) {
    const { signer, onProgress } = parameters;
    if ((parameters as { broadcast?: boolean }).broadcast === true) {
        throw new Error('Subscription push activation is unsupported; use broadcast=false');
    }

    return Method.toClient(Methods.subscription, {
        async createCredential({ challenge }) {
            const rpcUrl = resolveSubscriptionRpcUrl(parameters.rpcUrl, challenge.request.methodDetails.network);
            const subscriptionAuthorityInitId =
                parameters.subscriptionAuthorityInitId ??
                (parameters.initializeSubscriptionAuthority
                    ? await initializeSubscriptionAuthority({
                          mint: challenge.request.methodDetails.mint,
                          programId: challenge.request.methodDetails.programId,
                          rpcUrl,
                          signer,
                          tokenProgram: challenge.request.methodDetails.tokenProgram,
                      })
                    : undefined);
            const refreshBlockhash =
                parameters.initializeSubscriptionAuthority === true &&
                parameters.subscriptionAuthorityInitId === undefined;
            if (subscriptionAuthorityInitId === undefined) {
                throw new Error(
                    'subscriptionAuthorityInitId is required unless initializeSubscriptionAuthority=true is explicitly enabled',
                );
            }
            const encodedTx = await buildSubscriptionActivationTransaction({
                computeUnitLimit: parameters.computeUnitLimit,
                computeUnitPrice: parameters.computeUnitPrice,
                onProgress,
                ...(refreshBlockhash ? { refreshBlockhash: true } : {}),
                request: challenge.request,
                rpcUrl,
                signer,
                subscriptionAuthorityInitId,
            });
            onProgress?.({ transaction: encodedTx, type: 'signed' });
            return Credential.serialize({
                challenge,
                payload: { transaction: encodedTx, type: 'transaction' },
            });
        },
    });
}

/**
 * Build and sign a canonical subscription activation transaction.
 *
 * This function never broadcasts. The caller must explicitly initialize the
 * SubscriptionAuthority first and pass its live init id.
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
        expectedCreatedAt,
        expectedPeriodHours,
        feePayer,
        feePayerKey,
        merchant,
        mint,
        network,
        planBump,
        planId,
        planIdNumeric,
        programId = SUBSCRIPTIONS_PROGRAM,
        puller,
        recentBlockhash,
        tokenProgram,
    } = methodDetails;

    if (!feePayer || !feePayerKey) {
        throw new Error('Canonical subscription activation requires feePayer=true and feePayerKey');
    }
    if (feePayerKey !== puller) {
        throw new Error('feePayerKey must equal puller so the server signs the canonical transfer caller');
    }

    const periodHours = mapSubscriptionPeriodToHours(periodUnit, Number(periodCount));
    assertPeriodHoursInRange(periodHours);
    if (BigInt(expectedPeriodHours) !== BigInt(periodHours)) {
        throw new Error('methodDetails.expectedPeriodHours does not match periodCount/periodUnit');
    }

    const rpcUrl = resolveSubscriptionRpcUrl(parameters.rpcUrl, network);
    const rpc = createSolanaRpc(rpcUrl);
    const mintAddress = address(mint);
    const planPda = address(planId);
    const programAddress = address(programId);
    const tokenProgramAddress = address(tokenProgram);
    const recipientAddress = address(recipient);
    const serverSignerAddress = address(feePayerKey);

    onProgress?.({ amount, mint, periodHours, planId, recipient, type: 'challenge' });

    const subscriptionAuthority = await deriveSubscriptionAuthorityPda({
        mint: mintAddress,
        programId: programAddress,
        subscriber: signer.address,
    });
    const subscriptionPda = await deriveSubscriptionPda({
        planPda,
        programId: programAddress,
        subscriber: signer.address,
    });
    const [eventAuthority] = await findEventAuthorityPda({ programAddress });
    const [subscriberAta] = await findAssociatedTokenPda({
        mint: mintAddress,
        owner: signer.address,
        tokenProgram: tokenProgramAddress,
    });
    const [recipientAta] = await findAssociatedTokenPda({
        mint: mintAddress,
        owner: recipientAddress,
        tokenProgram: tokenProgramAddress,
    });

    const remoteServerSigner = remoteSigner(serverSignerAddress);
    const subscriberAtaIx = stripRemoteSigner(
        getCreateAssociatedTokenIdempotentInstruction({
            ata: subscriberAta,
            mint: mintAddress,
            owner: signer.address,
            payer: remoteServerSigner,
            tokenProgram: tokenProgramAddress,
        }),
        serverSignerAddress,
    );
    const recipientAtaIx = stripRemoteSigner(
        getCreateAssociatedTokenIdempotentInstruction({
            ata: recipientAta,
            mint: mintAddress,
            owner: recipientAddress,
            payer: remoteServerSigner,
            tokenProgram: tokenProgramAddress,
        }),
        serverSignerAddress,
    );

    const generatedSubscribe = await getSubscribeInstructionAsync(
        {
            eventAuthority,
            merchant: address(merchant),
            planPda,
            selfProgram: programAddress,
            subscribeData: {
                expectedAmount: BigInt(amount),
                expectedCreatedAt: BigInt(expectedCreatedAt),
                expectedMint: mintAddress,
                expectedPeriodHours: BigInt(expectedPeriodHours),
                expectedSubscriptionAuthorityInitId: subscriptionAuthorityInitId,
                planBump,
                planId: BigInt(planIdNumeric),
            },
            subscriber: signer,
            subscriptionAuthorityPda: subscriptionAuthority,
            subscriptionPda,
            systemProgram: address(SYSTEM_PROGRAM),
        },
        { programAddress },
    );
    const subscribeIx: Instruction = {
        ...generatedSubscribe,
        accounts: [...generatedSubscribe.accounts, { address: serverSignerAddress, role: AccountRole.WRITABLE_SIGNER }],
    };

    const transferIx = stripRemoteSigner(
        getTransferSubscriptionInstruction(
            {
                caller: remoteServerSigner,
                delegatorAta: subscriberAta,
                eventAuthority,
                planPda,
                receiverAta: recipientAta,
                selfProgram: programAddress,
                subscriptionAuthority,
                subscriptionPda,
                tokenMint: mintAddress,
                tokenProgram: tokenProgramAddress,
                transferData: {
                    amount: BigInt(amount),
                    delegator: signer.address,
                    mint: mintAddress,
                },
            },
            { programAddress },
        ),
        serverSignerAddress,
    );

    const instructions: Instruction[] = [subscriberAtaIx, recipientAtaIx, subscribeIx, transferIx];
    if (externalId) instructions.push(buildMemoInstruction(externalId));

    onProgress?.({ type: 'signing' });
    const latestBlockhash =
        !parameters.refreshBlockhash && recentBlockhash
            ? { blockhash: recentBlockhash as Blockhash, lastValidBlockHeight: 0n }
            : (await rpc.getLatestBlockhash().send()).value;
    const txMessage = pipe(
        createTransactionMessage({ version: 0 }),
        msg => setTransactionMessageFeePayer(serverSignerAddress, msg),
        msg => setTransactionMessageLifetimeUsingBlockhash(latestBlockhash, msg),
        msg => appendTransactionMessageInstructions(instructions, msg),
        msg =>
            prependTransactionMessageInstructions(
                [
                    getSetComputeUnitPriceInstruction({ microLamports: parameters.computeUnitPrice ?? 1n }),
                    getSetComputeUnitLimitInstruction({ units: parameters.computeUnitLimit ?? 200_000 }),
                ],
                msg,
            ),
    );
    return getBase64EncodedWireTransaction(await partiallySignTransactionMessageWithSigners(txMessage));
}

/**
 * Explicitly initialize (or read) the subscriber's SubscriptionAuthority and
 * return its live init id. This is the only subscription client API that
 * broadcasts implicitly as part of its explicitly requested operation.
 */
export async function initializeSubscriptionAuthority(
    parameters: initializeSubscriptionAuthority.Parameters,
): Promise<bigint> {
    const { mint, signer, programId = SUBSCRIPTIONS_PROGRAM, tokenProgram } = parameters;
    const rpcUrl = resolveSubscriptionRpcUrl(parameters.rpcUrl, parameters.network);
    const rpc = createSolanaRpc(rpcUrl);
    const mintAddress = address(mint);
    const programAddress = address(programId);
    const tokenProgramAddress = address(tokenProgram);
    const subscriptionAuthority = await deriveSubscriptionAuthorityPda({
        mint: mintAddress,
        programId: programAddress,
        subscriber: signer.address,
    });

    const existing = await fetchSubscriptionAuthorityInitId(rpc, subscriptionAuthority);
    if (existing !== null) return existing;

    const [subscriberAta] = await findAssociatedTokenPda({
        mint: mintAddress,
        owner: signer.address,
        tokenProgram: tokenProgramAddress,
    });
    const createAtaIx = getCreateAssociatedTokenIdempotentInstruction({
        ata: subscriberAta,
        mint: mintAddress,
        owner: signer.address,
        payer: signer,
        tokenProgram: tokenProgramAddress,
    });
    const initIx = await getInitSubscriptionAuthorityInstructionAsync(
        {
            owner: signer,
            subscriptionAuthority,
            tokenMint: mintAddress,
            tokenProgram: tokenProgramAddress,
            userAta: subscriberAta,
        },
        { programAddress },
    );
    const latestBlockhash = (await rpc.getLatestBlockhash().send()).value;
    const message = pipe(
        createTransactionMessage({ version: 0 }),
        msg => setTransactionMessageFeePayerSigner(signer, msg),
        msg => setTransactionMessageLifetimeUsingBlockhash(latestBlockhash, msg),
        msg => appendTransactionMessageInstructions([createAtaIx, initIx], msg),
    );
    const encoded = getBase64EncodedWireTransaction(await partiallySignTransactionMessageWithSigners(message));
    const signature = await rpc.sendTransaction(encoded, { encoding: 'base64', skipPreflight: false }).send();
    await confirmTransaction(rpc, signature);

    const initialized = await fetchSubscriptionAuthorityInitId(rpc, subscriptionAuthority);
    if (initialized === null) {
        throw new Error('Subscription authority account still missing after explicit initialization');
    }
    return initialized;
}

function resolveSubscriptionRpcUrl(rpcUrl?: string, network = 'mainnet'): string {
    return rpcUrl ?? DEFAULT_RPC_URLS[normalizeNetwork(network)] ?? DEFAULT_RPC_URLS.mainnet;
}

function remoteSigner(remoteAddress: Address): TransactionSigner {
    return {
        address: remoteAddress,
        signTransactions() {
            return Promise.reject(
                new Error(`Remote signer ${remoteAddress} must be completed by the subscription server`),
            );
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

async function fetchSubscriptionAuthorityInitId(
    rpc: ReturnType<typeof createSolanaRpc>,
    authority: Address,
): Promise<bigint | null> {
    const account = await rpc.getAccountInfo(authority, { encoding: 'base64' }).send();
    if (!account.value) return null;
    const [encoded] = account.value.data;
    const decoded = getSubscriptionAuthorityDecoder().decode(getBase64Codec().encode(encoded));
    return decoded.initId;
}

function buildMemoInstruction(memo: string): Instruction {
    const data = new TextEncoder().encode(memo);
    if (data.byteLength > 566) throw new Error('memo cannot exceed 566 bytes');
    return { accounts: [], data, programAddress: address(MEMO_PROGRAM) };
}

async function confirmTransaction(
    rpc: ReturnType<typeof createSolanaRpc>,
    signature: string,
    timeoutMs = 30_000,
): Promise<void> {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
        const { value } = await rpc.getSignatureStatuses([signature as never]).send();
        const status = value[0];
        if (status) {
            if (status.err) throw new Error(`Transaction failed: ${JSON.stringify(status.err)}`);
            if (status.confirmationStatus === 'confirmed' || status.confirmationStatus === 'finalized') return;
        }
        await new Promise(resolve => setTimeout(resolve, 2_000));
    }
    throw new Error('Transaction confirmation timeout');
}

type SubscriptionRequest = {
    amount: string;
    currency: string;
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

export declare namespace subscription {
    type Parameters = {
        /** Must remain false; signature-mode subscription activation is rejected by servers. */
        broadcast?: false;
        computeUnitLimit?: number;
        computeUnitPrice?: bigint;
        /** Explicitly initialize a missing authority before building activation. */
        initializeSubscriptionAuthority?: boolean;
        onProgress?: (event: ProgressEvent) => void;
        rpcUrl?: string;
        signer: TransactionSigner;
        /** Live SubscriptionAuthority.initId obtained from initializeSubscriptionAuthority. */
        subscriptionAuthorityInitId?: bigint;
    };

    type ProgressEvent =
        | { amount: string; mint: string; periodHours: number; planId: string; recipient: string; type: 'challenge' }
        | { transaction: string; type: 'signed' }
        | { type: 'signing' };
}

export declare namespace buildSubscriptionActivationTransaction {
    type Parameters = {
        computeUnitLimit?: number;
        computeUnitPrice?: bigint;
        onProgress?: subscription.Parameters['onProgress'];
        refreshBlockhash?: boolean;
        request: SubscriptionRequest;
        rpcUrl?: string;
        signer: TransactionSigner;
        subscriptionAuthorityInitId: bigint;
    };
}

export declare namespace initializeSubscriptionAuthority {
    type Parameters = {
        mint: string;
        network?: string;
        programId?: string;
        rpcUrl?: string;
        signer: TransactionSigner;
        tokenProgram: string;
    };
}
