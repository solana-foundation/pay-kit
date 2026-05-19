import {
    address,
    createSolanaRpc,
    getBase64Codec,
    getCompiledTransactionMessageDecoder,
    getTransactionDecoder,
    isTransactionPartialSigner,
    type TransactionPartialSigner,
} from '@solana/kit';
import { Method, Receipt, Store } from 'mppx';

import {
    DEFAULT_RPC_URLS,
    SUBSCRIPTIONS_PROGRAM,
    SUBSCRIPTIONS_SUBSCRIBE_DISCRIMINATOR,
    SUBSCRIPTIONS_TRANSFER_DISCRIMINATOR,
    TOKEN_2022_PROGRAM,
    TOKEN_PROGRAM,
} from '../constants.js';
import * as Methods from '../Methods.js';
import { deriveSubscriptionPda, mapSubscriptionPeriodToHours } from '../shared/subscription.js';
import { coSignBase64Transaction } from '../utils/transactions.js';

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
 * import { Mppx, solana } from 'solana-mpp-sdk/server'
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
        programId = SUBSCRIPTIONS_PROGRAM,
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

    const rpcUrl = parameters.rpcUrl ?? DEFAULT_RPC_URLS[network] ?? DEFAULT_RPC_URLS['mainnet-beta'];

    const method = Method.toServer(Methods.subscription, {
        defaults: {
            amount: '0',
            currency: mint,
            methodDetails: {
                decimals,
                mint,
                planId,
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
                    mint,
                    network,
                    planId,
                    programId,
                    puller,
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

        async verify({ credential }) {
            const cred = credential as unknown as CredentialPayload;
            const challenge = cred.challenge.request;
            const payloadType = resolvePayloadType(cred.payload);

            if (payloadType === 'signature' && challenge.methodDetails.feePayer) {
                throw new Error('type="signature" credentials cannot be used with fee sponsorship (feePayer: true)');
            }

            const subscriberAddress = await settleActivation(cred, challenge, rpcUrl, store, signer, payloadType);

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
            if (delegation.mint !== challenge.methodDetails.mint) {
                throw new Error(
                    `SubscriptionDelegation mint mismatch: expected ${challenge.methodDetails.mint}, got ${delegation.mint}`,
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
    store: Store.Store,
    signer: TransactionPartialSigner | undefined,
    payloadType: 'signature' | 'transaction',
): Promise<string> {
    if (payloadType === 'transaction') {
        const { transaction: clientTxBase64 } = credential.payload;
        if (!clientTxBase64) {
            throw new Error('Missing transaction data in credential payload');
        }

        const subscriber = extractSubscriberFromTransaction(clientTxBase64, challenge);
        validateActivationInstructions(clientTxBase64, challenge);

        let txToSend = clientTxBase64;
        if (signer) {
            txToSend = await coSignBase64Transaction(signer, clientTxBase64);
        }

        await simulateTransaction(rpcUrl, txToSend);
        const signature = await broadcastTransaction(rpcUrl, txToSend);
        await waitForConfirmation(rpcUrl, signature);

        await store.put(`solana-subscription:consumed:${signature}`, true);
        return subscriber;
    }

    // ── Push mode (type="signature") ──
    const { signature } = credential.payload;
    if (!signature) {
        throw new Error('Missing signature in credential payload');
    }
    const consumedKey = `solana-subscription:consumed:${signature}`;
    if (await store.get(consumedKey)) {
        throw new Error('Activation signature already consumed');
    }

    const tx = await fetchTransactionRaw(rpcUrl, signature);
    if (!tx) throw new Error('Transaction not found or not yet confirmed');
    if (tx.meta?.err) throw new Error('Transaction failed on-chain');

    // The subscriber is the first signer that is not the fee payer (when
    // fee sponsorship is in play) or simply the fee payer otherwise.
    const accountKeys = tx.transaction.message.accountKeys ?? [];
    if (accountKeys.length === 0) {
        throw new Error('Transaction has no account keys');
    }
    const firstAccount = typeof accountKeys[0] === 'string' ? accountKeys[0] : accountKeys[0].pubkey;
    const subscriber = firstAccount;

    await store.put(consumedKey, true);
    return subscriber;
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
    instructions: readonly CompiledInstruction[];
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
        return getCompiledTransactionMessageDecoder().decode(decoded.messageBytes) as unknown as CompiledMessage;
    } catch (e) {
        throw new Error(`Invalid transaction: ${e instanceof Error ? e.message : String(e)}`);
    }
}

function extractSubscriberFromTransaction(clientTxBase64: string, challenge: ChallengeRequest): string {
    const message = decodeCompiledMessage(clientTxBase64);
    if (message.staticAccounts.length === 0) {
        throw new Error('Transaction has no static accounts');
    }

    // When fee sponsorship is in play, the first signer is the server's fee
    // payer; the subscriber is the next signer that is not the puller.
    if (challenge.methodDetails.feePayer && challenge.methodDetails.feePayerKey) {
        for (const account of message.staticAccounts.slice(1)) {
            if (account !== challenge.methodDetails.puller) return account;
        }
        throw new Error('Could not identify subscriber among transaction signers');
    }

    const firstAccount = message.staticAccounts[0];
    if (challenge.methodDetails.puller && firstAccount === challenge.methodDetails.puller) {
        throw new Error('Subscriber cannot be the server puller');
    }
    return firstAccount;
}

function validateActivationInstructions(clientTxBase64: string, challenge: ChallengeRequest): void {
    const message = decodeCompiledMessage(clientTxBase64);

    if (message.addressTableLookups?.length) {
        throw new Error('v0 transactions with address lookup tables are not supported in activation flow');
    }

    const programId = challenge.methodDetails.programId ?? SUBSCRIPTIONS_PROGRAM;

    let sawSubscribe = false;
    let sawTransferSubscription = false;
    let subscribeIndex = -1;
    let transferIndex = -1;

    for (const [index, ix] of message.instructions.entries()) {
        const program = message.staticAccounts[ix.programAddressIndex];
        if (program !== programId) continue;
        if (ix.data.length === 0) continue;
        if (ix.data[0] === SUBSCRIPTIONS_SUBSCRIBE_DISCRIMINATOR) {
            if (sawSubscribe) throw new Error('Multiple subscribe instructions found');
            sawSubscribe = true;
            subscribeIndex = index;
        } else if (ix.data[0] === SUBSCRIPTIONS_TRANSFER_DISCRIMINATOR) {
            if (sawTransferSubscription) throw new Error('Multiple transfer_subscription instructions found');
            sawTransferSubscription = true;
            transferIndex = index;
        }
    }

    if (!sawSubscribe) throw new Error('Activation transaction is missing subscribe instruction');
    if (!sawTransferSubscription)
        throw new Error('Activation transaction is missing transfer_subscription instruction');
    if (transferIndex < subscribeIndex) {
        throw new Error('subscribe must precede transfer_subscription in activation transaction');
    }
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
    mint: string;
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

// Offsets correspond to the subscriptions program's
// SubscriptionDelegation layout (see /Users/ludo/Coding/solana-program/
// subscriptions/program/src/state/subscription_delegation.rs). This is a
// minimum-viable decoder: it reads only the fields needed for activation
// verification. Replace with the Codama client in v0.1.
const SUBSCRIPTION_DELEGATION_DISCRIMINATOR_LEN = 1;
const PUBKEY_LEN = 32;

function decodeSubscriptionDelegation(data: Uint8Array): SubscriptionDelegation {
    let offset = SUBSCRIPTION_DELEGATION_DISCRIMINATOR_LEN;
    // Header: delegator (subscriber), delegatee, payer (sponsor), init_id (u64)
    const subscriber = encodeBase58(data.subarray(offset, offset + PUBKEY_LEN));
    offset += PUBKEY_LEN;
    // delegatee
    offset += PUBKEY_LEN;
    // payer
    offset += PUBKEY_LEN;
    // init_id u64
    offset += 8;
    const planPda = encodeBase58(data.subarray(offset, offset + PUBKEY_LEN));
    offset += PUBKEY_LEN;
    const mint = encodeBase58(data.subarray(offset, offset + PUBKEY_LEN));
    offset += PUBKEY_LEN;
    const amountPerPeriod = readU64Le(data, offset).toString();
    offset += 8;
    const periodHours = Number(readU64Le(data, offset));
    offset += 8;
    const currentPeriodStartTs = Number(readI64Le(data, offset));
    offset += 8;
    const amountPulledInPeriod = readU64Le(data, offset).toString();

    return {
        amountPerPeriod,
        amountPulledInPeriod,
        currentPeriodStartTs,
        mint,
        periodHours,
        planPda,
        subscriber,
    };
}

function readU64Le(data: Uint8Array, offset: number): bigint {
    let value = 0n;
    for (let i = 0; i < 8; i += 1) {
        value |= BigInt(data[offset + i]) << BigInt(i * 8);
    }
    return value;
}

function readI64Le(data: Uint8Array, offset: number): bigint {
    const u = readU64Le(data, offset);
    return u >= 1n << 63n ? u - (1n << 64n) : u;
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
    transaction: {
        message: {
            accountKeys: Array<string | { pubkey: string }>;
        };
    };
};

async function fetchTransactionRaw(rpcUrl: string, signature: string): Promise<RawTransaction | null> {
    const response = await fetch(rpcUrl, {
        body: JSON.stringify({
            id: 1,
            jsonrpc: '2.0',
            method: 'getTransaction',
            params: [signature, { commitment: 'confirmed', encoding: 'jsonParsed', maxSupportedTransactionVersion: 0 }],
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
        /** Base58 of the subscriptions program ID. Defaults to the canonical deployment. */
        programId?: string;
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
        /** Base58 of the SPL Token or Token-2022 program ID. */
        tokenProgram: string;
    };
}
