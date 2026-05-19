import {
    AccountRole,
    type Address,
    address,
    appendTransactionMessageInstructions,
    type Base64EncodedWireTransaction,
    type Blockhash,
    createSolanaRpc,
    createTransactionMessage,
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
import { findAssociatedTokenPda } from '@solana-program/token';
import { Credential, Method } from 'mppx';

import {
    DEFAULT_RPC_URLS,
    MEMO_PROGRAM,
    SUBSCRIPTIONS_INIT_AUTHORITY_DISCRIMINATOR,
    SUBSCRIPTIONS_PROGRAM,
    SUBSCRIPTIONS_SUBSCRIBE_DISCRIMINATOR,
    SUBSCRIPTIONS_TRANSFER_DISCRIMINATOR,
    SYSTEM_PROGRAM,
} from '../constants.js';
import * as Methods from '../Methods.js';
import {
    assertPeriodHoursInRange,
    deriveSubscriptionAuthorityPda,
    deriveSubscriptionPda,
    mapSubscriptionPeriodToHours,
} from '../shared/subscription.js';

/**
 * Creates a Solana `subscription` method for usage on the client.
 *
 * Builds the activation transaction (initialize_subscription_authority if
 * needed, subscribe, transfer_subscription) and signs as the subscriber.
 * When `feePayer: true` is advertised in the challenge, the server's
 * `feePayerKey` is used as fee payer and the transaction is partially
 * signed; the server completes the signature before broadcasting.
 *
 * @example
 * ```ts
 * import { Mppx, solana } from 'solana-mpp-sdk/client'
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

            const encodedTx = await buildSubscriptionActivationTransaction({
                computeUnitLimit: parameters.computeUnitLimit,
                computeUnitPrice: parameters.computeUnitPrice,
                onProgress,
                request: challenge.request,
                rpcUrl:
                    parameters.rpcUrl ??
                    DEFAULT_RPC_URLS[network || 'mainnet-beta'] ??
                    DEFAULT_RPC_URLS['mainnet-beta'],
                signer,
            });

            const rpc = createSolanaRpc(
                parameters.rpcUrl ?? DEFAULT_RPC_URLS[network || 'mainnet-beta'] ?? DEFAULT_RPC_URLS['mainnet-beta'],
            );

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
                    payload: { signature, type: 'signature' },
                });
            }

            onProgress?.({ transaction: encodedTx, type: 'signed' });
            return Credential.serialize({
                challenge,
                payload: { transaction: encodedTx, type: 'transaction' },
            });
        },
    });

    return method;
}

/**
 * Build and sign the activation transaction for a Solana subscription challenge.
 *
 * The transaction layout matches the spec's required ordering:
 *
 *   [ComputeBudgetSetUnitPrice, ComputeBudgetSetUnitLimit,
 *    initialize_subscription_authority?,
 *    subscribe,
 *    transfer_subscription,
 *    memo(externalId)?]
 */
export async function buildSubscriptionActivationTransaction(
    parameters: buildSubscriptionActivationTransaction.Parameters,
): Promise<Base64EncodedWireTransaction> {
    const {
        signer,
        request: { amount, externalId, recipient, methodDetails, periodCount, periodUnit },
        onProgress,
    } = parameters;
    const {
        network,
        mint,
        planId,
        programId = SUBSCRIPTIONS_PROGRAM,
        tokenProgram,
        feePayer: serverPaysFees,
        feePayerKey,
        recentBlockhash: serverBlockhash,
    } = methodDetails;

    const periodHours = mapSubscriptionPeriodToHours(periodUnit, Number(periodCount));
    assertPeriodHoursInRange(periodHours);

    const rpcUrl = parameters.rpcUrl ?? DEFAULT_RPC_URLS[network || 'mainnet-beta'] ?? DEFAULT_RPC_URLS['mainnet-beta'];
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
    const programAddress = address(programId);
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

    const authorityExists = await checkAccountExists(rpc, subscriptionAuthority);

    const instructions: Instruction[] = [];

    if (!authorityExists) {
        instructions.push(
            buildInitSubscriptionAuthorityInstruction({
                ata: subscriberAta,
                mint: mintAddress,
                programAddress,
                subscriber: subscriberAddress,
                subscriptionAuthority,
                tokenProgram: tokenProgramAddress,
            }),
        );
    }

    instructions.push(
        buildSubscribeInstruction({
            payer: useServerFeePayer && feePayerKey ? address(feePayerKey) : subscriberAddress,
            planPda,
            programAddress,
            subscriber: subscriberAddress,
            subscriptionAuthority,
            subscriptionPda,
        }),
    );

    instructions.push(
        buildTransferSubscriptionInstruction({
            mint: mintAddress,
            planPda,
            programAddress,
            puller: methodDetails.puller ? address(methodDetails.puller) : subscriberAddress,
            recipientAta,
            subscriber: subscriberAddress,
            subscriberAta,
            subscriptionAuthority,
            subscriptionPda,
            tokenProgram: tokenProgramAddress,
        }),
    );

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

    const signedTx = useServerFeePayer
        ? await partiallySignTransactionMessageWithSigners(txMessage)
        : await partiallySignTransactionMessageWithSigners(txMessage);

    return getBase64EncodedWireTransaction(signedTx);
}

// ── Instruction builders (v0, hand-rolled) ──
//
// These build the subscriptions program's instructions by inlining
// account orders and discriminator bytes. A follow-up should replace
// them with the Codama-generated overlay instructions exported by the
// `subscriptions` client package.

function buildInitSubscriptionAuthorityInstruction(params: {
    ata: Address;
    mint: Address;
    programAddress: Address;
    subscriber: Address;
    subscriptionAuthority: Address;
    tokenProgram: Address;
}): Instruction {
    return {
        accounts: [
            { address: params.subscriber, role: AccountRole.WRITABLE_SIGNER },
            { address: params.subscriptionAuthority, role: AccountRole.WRITABLE },
            { address: params.mint, role: AccountRole.READONLY },
            { address: params.ata, role: AccountRole.WRITABLE },
            { address: params.tokenProgram, role: AccountRole.READONLY },
            { address: address(SYSTEM_PROGRAM), role: AccountRole.READONLY },
        ],
        data: new Uint8Array([SUBSCRIPTIONS_INIT_AUTHORITY_DISCRIMINATOR]),
        programAddress: params.programAddress,
    };
}

function buildSubscribeInstruction(params: {
    payer: Address;
    planPda: Address;
    programAddress: Address;
    subscriber: Address;
    subscriptionAuthority: Address;
    subscriptionPda: Address;
}): Instruction {
    return {
        accounts: [
            { address: params.subscriber, role: AccountRole.WRITABLE_SIGNER },
            { address: params.payer, role: AccountRole.WRITABLE_SIGNER },
            { address: params.planPda, role: AccountRole.READONLY },
            { address: params.subscriptionPda, role: AccountRole.WRITABLE },
            { address: params.subscriptionAuthority, role: AccountRole.READONLY },
            { address: address(SYSTEM_PROGRAM), role: AccountRole.READONLY },
        ],
        data: new Uint8Array([SUBSCRIPTIONS_SUBSCRIBE_DISCRIMINATOR]),
        programAddress: params.programAddress,
    };
}

function buildTransferSubscriptionInstruction(params: {
    mint: Address;
    planPda: Address;
    programAddress: Address;
    puller: Address;
    recipientAta: Address;
    subscriber: Address;
    subscriberAta: Address;
    subscriptionAuthority: Address;
    subscriptionPda: Address;
    tokenProgram: Address;
}): Instruction {
    return {
        accounts: [
            { address: params.puller, role: AccountRole.WRITABLE_SIGNER },
            { address: params.subscriptionPda, role: AccountRole.WRITABLE },
            { address: params.planPda, role: AccountRole.READONLY },
            { address: params.subscriptionAuthority, role: AccountRole.READONLY },
            { address: params.subscriber, role: AccountRole.READONLY },
            { address: params.subscriberAta, role: AccountRole.WRITABLE },
            { address: params.recipientAta, role: AccountRole.WRITABLE },
            { address: params.mint, role: AccountRole.READONLY },
            { address: params.tokenProgram, role: AccountRole.READONLY },
        ],
        data: new Uint8Array([SUBSCRIPTIONS_TRANSFER_DISCRIMINATOR]),
        programAddress: params.programAddress,
    };
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

async function checkAccountExists(rpc: ReturnType<typeof createSolanaRpc>, accountAddress: Address): Promise<boolean> {
    const account = await rpc.getAccountInfo(accountAddress, { encoding: 'base64' }).send();
    return account.value !== null;
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
        /** Called at each step of the activation process. */
        onProgress?: (event: ProgressEvent) => void;
        /** Custom RPC URL. If not set, inferred from the challenge's network field. */
        rpcUrl?: string;
        /** Solana transaction signer. The subscriber's funding key. */
        signer: TransactionSigner;
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
                planId: string;
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
        /** Custom RPC URL. If not set, inferred from the challenge network field. */
        rpcUrl?: string;
        /** Solana transaction signer (the subscriber). */
        signer: TransactionSigner;
    };
}
