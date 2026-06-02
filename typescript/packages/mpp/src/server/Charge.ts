import {
    address,
    getBase64Codec,
    getCompiledTransactionMessageDecoder,
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
    defaultTokenProgramForCurrency,
    MEMO_PROGRAM,
    resolveStablecoinMint,
    stablecoinSymbolForCurrency,
    SYSTEM_PROGRAM,
    TOKEN_2022_PROGRAM,
    TOKEN_PROGRAM,
} from '../constants.js';
import * as Methods from '../Methods.js';
import { coSignBase64Transaction } from '../utils/transactions.js';
import { PAYMENT_UI_JS } from './html-assets.gen.js';
import { checkNetworkBlockhash } from './network-check.js';

/**
 * Creates a Solana `charge` method for usage on the server.
 *
 * Supports two settlement modes:
 *
 * - **Pull mode** (`type="transaction"`, default): The server receives a
 *   signed transaction from the client, broadcasts it to Solana, confirms
 *   it, and verifies the transfer on-chain. When `signer` is provided,
 *   the server co-signs as fee payer before broadcasting.
 *
 * - **Push mode** (`type="signature"`): The client has already broadcast
 *   and confirmed the transaction. The server verifies the transfer
 *   on-chain using the signature.
 *
 * @example
 * ```ts
 * import { Mppx, solana } from 'solana-mpp-sdk/server'
 *
 * const mppx = Mppx.create({
 *   methods: [solana.charge({
 *     recipient: 'RecipientPubkey...',
 *     spl: 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v',
 *     decimals: 6,
 *     network: 'devnet',
 *   })],
 * })
 *
 * export async function handler(request: Request) {
 *   const result = await mppx.charge({ amount: '1000000', currency: 'USDC' })(request)
 *   if (result.status === 402) return result.challenge
 *   return result.withReceipt(Response.json({ data: '...' }))
 * }
 * ```
 */
export function charge(parameters: charge.Parameters) {
    const {
        recipient,
        currency,
        decimals,
        html: htmlEnabled = false,
        tokenProgram: configuredTokenProgram,
        network = 'mainnet-beta',
        store = Store.memory(),
        splits,
        signer,
    } = parameters;

    const isSplToken = currency !== undefined && currency !== 'sol';
    const tokenProgram = configuredTokenProgram ?? defaultTokenProgramForCurrency(currency, network);

    const rpcUrl = parameters.rpcUrl ?? DEFAULT_RPC_URLS[network] ?? DEFAULT_RPC_URLS['mainnet-beta'];

    if (isSplToken && decimals === undefined) {
        throw new Error('decimals is required when currency is a token mint address');
    }

    if (splits && splits.length > 8) {
        throw new Error('splits cannot exceed 8 entries');
    }

    if (signer && !isTransactionPartialSigner(signer)) {
        throw new Error(
            'signer must implement signTransactions() for fee payer mode (e.g. KeyPairSigner, SolanaSigner)',
        );
    }

    const hasAtaCreationSplits = splits?.some(split => split.ataCreationRequired === true) === true;
    if (!isSplToken && hasAtaCreationSplits) {
        throw new Error('ataCreationRequired requires an SPL token currency');
    }
    if (hasAtaCreationSplits && (currency === undefined || resolveStablecoinMint(currency, network) !== currency)) {
        throw new Error('ataCreationRequired requires currency to be an SPL token mint address');
    }

    const method = Method.toServer(Methods.charge, {
        defaults: {
            currency: currency ?? 'sol',
            methodDetails: {},
            recipient: '',
        },

        html: htmlEnabled
            ? {
                  config: {},
                  content: PAYMENT_UI_JS as string,
                  formatAmount: (request: { amount: string; currency: string }) => {
                      const dec = decimals ?? (request.currency.toLowerCase() === 'sol' ? 9 : 6);
                      const raw = Number(request.amount) / 10 ** dec;
                      const display = raw % 1 === 0 ? raw.toString() : raw.toFixed(Math.min(dec, 2));
                      if (request.currency.toLowerCase() === 'sol') return `${display} SOL`;
                      const sym = stablecoinSymbolForCurrency(request.currency);
                      if (sym) return `$${display}`;
                      return `${display} ${request.currency.slice(0, 6)}`;
                  },
                  text: undefined,
                  theme: {
                      logo: {
                          dark: 'https://solana.com/src/img/branding/solanaLogoMark.svg',
                          light: 'https://solana.com/src/img/branding/solanaLogoMark.svg',
                      },
                  },
              }
            : undefined,

        async request({ credential, request }) {
            // Always build the request from the route's options + server config.
            // The mppx framework compares this `request` against
            // `credential.challenge.request` to enforce route-aware binding
            // (amount, currency, recipient, splits, etc). Returning
            // `credential.challenge.request` here would short-circuit that
            // check and let a credential issued for one route succeed at
            // another — i.e. cross-route credential replay.

            // Skip the blockhash fetch on the verify path: the prefetched
            // blockhash is only useful for the client building its own
            // transaction, which only happens when there's no credential.
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
                methodDetails: {
                    network,
                    ...(isSplToken ? { decimals, tokenProgram } : {}),
                    ...(signer ? { feePayer: true, feePayerKey: signer.address } : {}),
                    ...(splits?.length ? { splits } : {}),
                    ...(recentBlockhash ? { recentBlockhash } : {}),
                },
                recipient,
            };
        },

        async verify({ credential }) {
            const cred = credential as unknown as CredentialPayload;
            const challenge = cred.challenge.request;
            const payloadType = resolvePayloadType(cred.payload);

            // Spec: type="signature" MUST NOT be used with feePayer: true
            if (payloadType === 'signature' && challenge.methodDetails.feePayer) {
                throw new Error('type="signature" credentials cannot be used with fee sponsorship (feePayer: true)');
            }

            if (payloadType === 'transaction') {
                return await verifyTransaction(cred, challenge, rpcUrl, recipient, store, signer, network);
            }

            return await verifySignature(cred, challenge, rpcUrl, recipient, store);
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

// ── Blockhash extraction ──
//
// Used by the network/blockhash sanity check below to read the lifetime
// blockhash out of a base64-encoded wire transaction without doing a full
// instruction decode. The compiled message decoder gives us a
// `lifetimeToken` (== recent blockhash, base58 string) for non-durable-nonce
// transactions, which is exactly what we need.
//
// Returns `null` if the transaction can't be decoded — we leave the real
// error reporting to the downstream broadcast, same fail-open policy as
// `checkNetworkBlockhash` uses for non-prefixed blockhashes.
function extractRecentBlockhash(clientTxBase64: string): string | null {
    try {
        const txBytes = getBase64Codec().encode(clientTxBase64);
        const decoded = getTransactionDecoder().decode(txBytes);
        const message = getCompiledTransactionMessageDecoder().decode(decoded.messageBytes);
        return message.lifetimeToken;
    } catch {
        return null;
    }
}

const MAX_COMPUTE_UNIT_LIMIT = 200_000;
const MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS = 5_000_000n;

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

/**
 * RPC-free pre-broadcast verification of a base64-encoded charge transaction
 * against the challenge it answers: split-count, address-lookup-table,
 * compute-budget, transfer, memo, and instruction-allowlist checks, up to the
 * simulate/send boundary. This is the deterministic half of the charge server
 * verify path; it runs no HMAC challenge step and reaches no live RPC.
 *
 * Exported so the cross-SDK conformance harness can assert the verifier's
 * accept/reject decision against a fixed transaction. A resolved promise means
 * the transaction conforms; a rejected promise carries the rejection reason.
 */
export async function verifyChargeTransaction(clientTxBase64: string, challenge: ChallengeRequest) {
    let message: CompiledMessage;
    try {
        const txBytes = getBase64Codec().encode(clientTxBase64);
        const decoded = getTransactionDecoder().decode(txBytes);
        message = getCompiledTransactionMessageDecoder().decode(decoded.messageBytes) as unknown as CompiledMessage;
    } catch (e) {
        throw new Error(`Invalid transaction: ${e instanceof Error ? e.message : String(e)}`);
    }

    if (message.addressTableLookups?.length) {
        throw new Error('v0 transactions with address lookup tables are not supported');
    }

    const splits = challenge.methodDetails.splits ?? [];
    if (splits.length > 8) {
        throw new Error(`Too many splits: ${splits.length} (maximum 8)`);
    }

    const totalAmount = BigInt(challenge.amount);
    const splitsTotal = splits.reduce((sum, split) => sum + BigInt(split.amount), 0n);
    const primaryAmount = totalAmount - splitsTotal;
    if (primaryAmount <= 0n) {
        throw new Error('Splits consume the entire amount — primary recipient must receive a positive amount');
    }

    const feePayer = expectedFeePayer(message, challenge.methodDetails);
    const isNativeSol = challenge.currency.toLowerCase() === 'sol';
    if (isNativeSol && splits.some(split => split.ataCreationRequired === true)) {
        throw new Error('ataCreationRequired requires an SPL token charge');
    }

    const matchedInstructionIndexes = new Set<number>();
    const ataPolicy = expectedAtaCreationPolicy(challenge, feePayer);

    if (isNativeSol) {
        verifySolTransferPreBroadcast(message, challenge.recipient, primaryAmount, feePayer, matchedInstructionIndexes);
        for (const split of splits) {
            verifySolTransferPreBroadcast(
                message,
                split.recipient,
                BigInt(split.amount),
                feePayer,
                matchedInstructionIndexes,
            );
        }
        verifyMemoInstructionsPreBroadcast(message, challenge.externalId, splits, matchedInstructionIndexes);
        await validateInstructionAllowlist(message, matchedInstructionIndexes, {
            allowedAtaOwners: ataPolicy.allowedAtaOwners,
            expectedMint: undefined,
            expectedTokenProgram: undefined,
            feePayer,
            requiredAtaOwners: ataPolicy.requiredAtaOwners,
        });
        return;
    }

    const expectedMint = resolveStablecoinMint(challenge.currency, challenge.methodDetails.network);
    if (!expectedMint) {
        throw new Error('SPL charge is missing a mint address');
    }
    if (ataPolicy.requiredAtaOwners.size > 0 && challenge.currency !== expectedMint) {
        throw new Error('ataCreationRequired requires currency to be an SPL token mint address');
    }
    const expectedTokenProgram =
        challenge.methodDetails.tokenProgram ??
        defaultTokenProgramForCurrency(challenge.currency, challenge.methodDetails.network);

    await verifySplTransferPreBroadcast(
        message,
        challenge.recipient,
        expectedMint,
        primaryAmount,
        expectedTokenProgram,
        challenge.methodDetails.decimals,
        feePayer,
        matchedInstructionIndexes,
    );
    for (const split of splits) {
        await verifySplTransferPreBroadcast(
            message,
            split.recipient,
            expectedMint,
            BigInt(split.amount),
            expectedTokenProgram,
            challenge.methodDetails.decimals,
            feePayer,
            matchedInstructionIndexes,
        );
    }
    verifyMemoInstructionsPreBroadcast(message, challenge.externalId, splits, matchedInstructionIndexes);
    await validateInstructionAllowlist(message, matchedInstructionIndexes, {
        allowedAtaOwners: ataPolicy.allowedAtaOwners,
        expectedMint,
        expectedTokenProgram,
        feePayer,
        requiredAtaOwners: ataPolicy.requiredAtaOwners,
    });
}

function expectedFeePayer(
    message: CompiledMessage,
    methodDetails: ChallengeRequest['methodDetails'],
): string | undefined {
    if (!methodDetails.feePayer) {
        return undefined;
    }

    const feePayerKey = methodDetails.feePayerKey;
    if (!feePayerKey) {
        throw new Error('feePayer=true requires feePayerKey in methodDetails');
    }

    const txFeePayer = message.staticAccounts[0];
    if (txFeePayer !== feePayerKey) {
        throw new Error(`Transaction fee payer must be ${feePayerKey}`);
    }

    return feePayerKey;
}

function expectedAtaCreationPolicy(
    challenge: ChallengeRequest,
    feePayer: string | undefined,
): { allowedAtaOwners: Set<string>; requiredAtaOwners: Set<string> } {
    const splits = challenge.methodDetails.splits ?? [];
    const requiredAtaOwners = new Set(
        splits.filter(split => split.ataCreationRequired === true).map(split => split.recipient),
    );
    if (feePayer) {
        return { allowedAtaOwners: new Set(requiredAtaOwners), requiredAtaOwners };
    }
    return {
        allowedAtaOwners: new Set(splits.map(split => split.recipient)),
        requiredAtaOwners,
    };
}

function verifySolTransferPreBroadcast(
    message: CompiledMessage,
    recipient: string,
    amount: bigint,
    feePayer: string | undefined,
    matchedInstructionIndexes: Set<number>,
) {
    for (const [index, ix] of message.instructions.entries()) {
        if (matchedInstructionIndexes.has(index)) continue;
        if (programAddress(message, ix) !== SYSTEM_PROGRAM) continue;
        if (ix.data.length < 12 || readU32Le(ix.data, 0) !== 2) continue;
        if (readU64Le(ix.data, 4) !== amount) continue;
        if (ix.accountIndices.length < 2) continue;

        const source = accountAddress(message, ix.accountIndices[0], 'source');
        const destination = accountAddress(message, ix.accountIndices[1], 'destination');
        if (destination !== recipient) continue;
        if (feePayer && source === feePayer) {
            throw new Error('Fee payer cannot fund the SOL payment transfer');
        }

        matchedInstructionIndexes.add(index);
        return;
    }

    throw new Error(`No matching SOL transfer of ${amount} lamports to ${recipient}`);
}

async function verifySplTransferPreBroadcast(
    message: CompiledMessage,
    recipient: string,
    expectedMint: string,
    amount: bigint,
    expectedTokenProgram: string,
    expectedDecimals: number | undefined,
    feePayer: string | undefined,
    matchedInstructionIndexes: Set<number>,
) {
    for (const [index, ix] of message.instructions.entries()) {
        if (matchedInstructionIndexes.has(index)) continue;
        const program = programAddress(message, ix);
        if (program !== TOKEN_PROGRAM && program !== TOKEN_2022_PROGRAM) continue;
        if (program !== expectedTokenProgram) continue;
        if (ix.data.length < 10 || ix.data[0] !== 12) continue;
        if (readU64Le(ix.data, 1) !== amount) continue;
        if (expectedDecimals !== undefined && ix.data[9] !== expectedDecimals) continue;
        if (ix.accountIndices.length < 4) continue;

        const sourceAta = accountAddress(message, ix.accountIndices[0], 'source ATA');
        const mint = accountAddress(message, ix.accountIndices[1], 'mint');
        const destinationAta = accountAddress(message, ix.accountIndices[2], 'destination ATA');
        const authority = accountAddress(message, ix.accountIndices[3], 'authority');
        if (mint !== expectedMint) continue;

        if (feePayer) {
            if (authority === feePayer) {
                throw new Error('Fee payer cannot authorize the SPL payment transfer');
            }
            const [feePayerAta] = await findAssociatedTokenPda({
                mint: address(expectedMint),
                owner: address(feePayer),
                tokenProgram: address(program),
            });
            if (sourceAta === feePayerAta) {
                throw new Error('Fee payer token account cannot fund the SPL payment transfer');
            }
        }

        const [expectedAta] = await findAssociatedTokenPda({
            mint: address(expectedMint),
            owner: address(recipient),
            tokenProgram: address(program),
        });
        if (destinationAta !== expectedAta) continue;

        matchedInstructionIndexes.add(index);
        return;
    }

    throw new Error(`No matching SPL transferChecked of ${amount} to ${recipient}`);
}

async function validateInstructionAllowlist(
    message: CompiledMessage,
    matchedPaymentInstructionIndexes: Set<number>,
    options: {
        allowedAtaOwners: Set<string>;
        expectedMint: string | undefined;
        expectedTokenProgram: string | undefined;
        feePayer: string | undefined;
        requiredAtaOwners: Set<string>;
    },
) {
    const txFeePayer = message.staticAccounts[0];
    if (!txFeePayer) {
        throw new Error('Transaction has no fee payer');
    }
    const expectedAtaPayer = options.feePayer ?? txFeePayer;
    const createdAtaOwners = new Set<string>();

    for (const [index, ix] of message.instructions.entries()) {
        const program = programAddress(message, ix);

        if (program === COMPUTE_BUDGET_PROGRAM) {
            validateComputeBudgetInstruction(ix);
            continue;
        }

        if (program === MEMO_PROGRAM) {
            if (matchedPaymentInstructionIndexes.has(index)) continue;
            throw new Error('Unexpected Memo Program instruction in payment transaction');
        }

        if (program === SYSTEM_PROGRAM) {
            if (matchedPaymentInstructionIndexes.has(index)) continue;
            throw new Error('Unexpected System Program instruction in payment transaction');
        }

        if (program === TOKEN_PROGRAM || program === TOKEN_2022_PROGRAM) {
            if (matchedPaymentInstructionIndexes.has(index)) continue;
            throw new Error('Unexpected Token Program instruction in payment transaction');
        }

        if (program === ASSOCIATED_TOKEN_PROGRAM) {
            const owner = await validateCreateAtaIdempotentInstruction(
                message,
                ix,
                options.expectedMint,
                options.allowedAtaOwners,
                options.expectedTokenProgram,
                expectedAtaPayer,
            );
            createdAtaOwners.add(owner);
            continue;
        }

        throw new Error(`Unexpected program instruction in payment transaction: ${program}`);
    }

    for (const owner of options.requiredAtaOwners) {
        if (!createdAtaOwners.has(owner)) {
            throw new Error(`Missing required ATA creation instruction for split recipient ${owner}`);
        }
    }
}

function validateComputeBudgetInstruction(ix: CompiledInstruction) {
    if ((ix.accountIndices ?? []).length !== 0) {
        throw new Error('Compute budget instruction must not have accounts');
    }

    if (ix.data[0] === 2 && ix.data.length === 5) {
        const units = readU32Le(ix.data, 1);
        if (units > MAX_COMPUTE_UNIT_LIMIT) {
            throw new Error(`Compute unit limit ${units} exceeds maximum ${MAX_COMPUTE_UNIT_LIMIT}`);
        }
        return;
    }

    if (ix.data[0] === 3 && ix.data.length === 9) {
        const price = readU64Le(ix.data, 1);
        if (price > MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS) {
            throw new Error(`Compute unit price ${price} exceeds maximum ${MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS}`);
        }
        return;
    }

    throw new Error('Unsupported compute budget instruction');
}

async function validateCreateAtaIdempotentInstruction(
    message: CompiledMessage,
    ix: CompiledInstruction,
    expectedMint: string | undefined,
    allowedAtaOwners: Set<string>,
    expectedTokenProgram: string | undefined,
    expectedPayer: string,
): Promise<string> {
    if (!expectedMint) {
        throw new Error('ATA creation is not allowed for native SOL payments');
    }
    if (ix.data.length !== 1 || ix.data[0] !== 1) {
        throw new Error('Only idempotent ATA creation is allowed');
    }
    if (ix.accountIndices.length !== 6) {
        throw new Error('Unexpected ATA creation account layout');
    }

    const payer = accountAddress(message, ix.accountIndices[0], 'ATA payer');
    const ata = accountAddress(message, ix.accountIndices[1], 'ATA address');
    const owner = accountAddress(message, ix.accountIndices[2], 'ATA owner');
    const mint = accountAddress(message, ix.accountIndices[3], 'ATA mint');
    const systemProgram = accountAddress(message, ix.accountIndices[4], 'ATA system program');
    const tokenProgram = accountAddress(message, ix.accountIndices[5], 'ATA token program');

    if (payer !== expectedPayer) {
        throw new Error('ATA payer must match the transaction fee payer');
    }
    if (mint !== expectedMint) {
        throw new Error('ATA creation mint does not match the charge currency');
    }
    if (systemProgram !== SYSTEM_PROGRAM) {
        throw new Error('ATA creation must reference the System Program');
    }
    if (tokenProgram !== TOKEN_PROGRAM && tokenProgram !== TOKEN_2022_PROGRAM) {
        throw new Error('ATA creation uses an unsupported token program');
    }
    if (expectedTokenProgram && tokenProgram !== expectedTokenProgram) {
        throw new Error('ATA creation token program does not match methodDetails.tokenProgram');
    }

    const [expectedAta] = await findAssociatedTokenPda({
        mint: address(mint),
        owner: address(owner),
        tokenProgram: address(tokenProgram),
    });
    if (ata !== expectedAta) {
        throw new Error('ATA creation address does not match owner/mint/token program');
    }

    if (!allowedAtaOwners.has(owner)) {
        throw new Error('ATA creation owner is not authorized by the challenge');
    }

    return owner;
}

function programAddress(message: CompiledMessage, ix: CompiledInstruction): string {
    return accountAddress(message, ix.programAddressIndex, 'program address');
}

function accountAddress(message: CompiledMessage, index: number, label: string): string {
    const value = message.staticAccounts[index];
    if (!value) {
        throw new Error(`Invalid ${label} index`);
    }
    return value;
}

function readU32Le(data: Uint8Array, offset: number): number {
    return (data[offset] | (data[offset + 1] << 8) | (data[offset + 2] << 16) | (data[offset + 3] << 24)) >>> 0;
}

function readU64Le(data: Uint8Array, offset: number): bigint {
    let value = 0n;
    for (let i = 0; i < 8; i += 1) {
        value |= BigInt(data[offset + i]) << BigInt(i * 8);
    }
    return value;
}

// ── Pull mode (type="transaction") ──

async function verifyTransaction(
    credential: CredentialPayload,
    challenge: ChallengeRequest,
    rpcUrl: string,
    recipient: string,
    store: Store.Store,
    signer: TransactionPartialSigner | undefined,
    network: string,
) {
    const { transaction: clientTxBase64 } = credential.payload;
    if (!clientTxBase64) {
        throw new Error('Missing transaction data in credential payload');
    }

    // Reject up-front if the client signed against the wrong network
    // (e.g. mainnet keypair pointed at a sandbox-configured server, or
    // vice versa). Cheaper and clearer than letting the broadcast fail
    // with a confusing "transaction not found" error.
    const recentBlockhash = extractRecentBlockhash(clientTxBase64);
    if (recentBlockhash !== null) {
        checkNetworkBlockhash(network, recentBlockhash);
    }

    await verifyChargeTransaction(clientTxBase64, challenge);

    let txToSend = clientTxBase64;

    // When the server has a fee payer signer, decode the client's partially-signed
    // transaction, add the fee payer signature, and re-encode.
    // NOTE: The fee payer covers all tx costs including ATA rent (~0.002 SOL).
    // Recipients can close ATAs to reclaim rent, forcing re-creation on the next
    // payment. Servers should verify ATA existence before signing or factor rent
    // into pricing to mitigate this drain vector.
    if (signer) {
        txToSend = await coSignBase64Transaction(signer, clientTxBase64);
    }

    // Simulate before broadcast to catch failures without wasting fees.
    await simulateTransaction(rpcUrl, txToSend);

    // Broadcast the (now fully-signed) transaction.
    const signature = await broadcastTransaction(rpcUrl, txToSend);

    // Wait for on-chain confirmation.
    await waitForConfirmation(rpcUrl, signature);

    // Verify the confirmed transaction matches the challenge.
    await verifyOnChain(rpcUrl, signature, challenge, recipient);

    // Mark consumed to prevent replay.
    await store.put(`solana-charge:consumed:${signature}`, true);

    return Receipt.from({
        method: 'solana',
        ...(credential.challenge.id ? { challengeId: credential.challenge.id } : {}),
        reference: signature,
        ...(challenge.externalId ? { externalId: challenge.externalId } : {}),
        status: 'success',
        timestamp: new Date().toISOString(),
    });
}

// ── Push mode (type="signature") ──

async function verifySignature(
    credential: CredentialPayload,
    challenge: ChallengeRequest,
    rpcUrl: string,
    recipient: string,
    store: Store.Store,
) {
    const { signature } = credential.payload;
    if (!signature) {
        throw new Error('Missing signature in credential payload');
    }

    // Replay prevention: reject already-consumed transaction signatures.
    const consumedKey = `solana-charge:consumed:${signature}`;
    if (await store.get(consumedKey)) {
        throw new Error('Transaction signature already consumed');
    }

    // Fetch and verify the transaction on-chain.
    const tx = await fetchTransaction(rpcUrl, signature);
    if (!tx) throw new Error('Transaction not found or not yet confirmed');
    if (tx.meta?.err) throw new Error('Transaction failed on-chain');

    const instructions = tx.transaction.message.instructions;
    await verifyInstructions(instructions, challenge, recipient);

    // Mark consumed to prevent replay.
    await store.put(consumedKey, true);

    return Receipt.from({
        method: 'solana',
        ...(credential.challenge.id ? { challengeId: credential.challenge.id } : {}),
        reference: signature,
        ...(challenge.externalId ? { externalId: challenge.externalId } : {}),
        status: 'success',
        timestamp: new Date().toISOString(),
    });
}

// ── Shared on-chain verification ──

async function verifyOnChain(rpcUrl: string, signature: string, challenge: ChallengeRequest, recipient: string) {
    const tx = await fetchTransaction(rpcUrl, signature);
    if (!tx) throw new Error('Transaction not found or not yet confirmed');
    if (tx.meta?.err) throw new Error('Transaction failed on-chain');

    const instructions = tx.transaction.message.instructions;
    await verifyInstructions(instructions, challenge, recipient);
}

async function verifyInstructions(instructions: ParsedInstruction[], challenge: ChallengeRequest, recipient: string) {
    const splits = challenge.methodDetails.splits ?? [];
    const splitsTotal = splits.reduce((sum, s) => sum + BigInt(s.amount), 0n);
    const primaryAmount = BigInt(challenge.amount) - splitsTotal;

    if (primaryAmount <= 0n) {
        throw new Error('Splits consume the entire amount — primary recipient must receive a positive amount');
    }

    const mint = resolveStablecoinMint(challenge.currency, challenge.methodDetails.network);
    const matchedInstructionIndexes = new Set<number>();
    const feePayer = challenge.methodDetails.feePayer === true ? challenge.methodDetails.feePayerKey : undefined;
    if (challenge.methodDetails.feePayer === true && !feePayer) {
        throw new Error('feePayer=true requires feePayerKey in methodDetails');
    }
    const ataPolicy = expectedAtaCreationPolicy(challenge, feePayer);

    if (mint) {
        if (splits.some(split => split.ataCreationRequired === true) && challenge.currency !== mint) {
            throw new Error('ataCreationRequired requires currency to be an SPL token mint address');
        }

        // ── SPL token transfers verification ──
        const expectedTokenProgram =
            challenge.methodDetails.tokenProgram ??
            defaultTokenProgramForCurrency(challenge.currency, challenge.methodDetails.network);

        // Verify primary transfer to recipient.
        await verifySplTransfer(
            instructions,
            recipient,
            String(primaryAmount),
            mint,
            expectedTokenProgram,
            matchedInstructionIndexes,
        );

        // Verify each split transfer.
        for (const split of splits) {
            await verifySplTransfer(
                instructions,
                split.recipient,
                split.amount,
                mint,
                expectedTokenProgram,
                matchedInstructionIndexes,
            );
        }
        verifyMemoInstructions(instructions, challenge.externalId, splits, matchedInstructionIndexes);

        await validateParsedInstructionAllowlist(instructions, matchedInstructionIndexes, {
            allowedAtaOwners: ataPolicy.allowedAtaOwners,
            expectedAtaPayer: feePayer,
            expectedMint: mint,
            expectedTokenProgram,
            requiredAtaOwners: ataPolicy.requiredAtaOwners,
        });
    } else {
        if (splits.some(split => split.ataCreationRequired === true)) {
            throw new Error('ataCreationRequired requires an SPL token charge');
        }

        // ── Native SOL transfers verification ──
        // Verify primary transfer to recipient.
        verifySolTransfer(instructions, recipient, String(primaryAmount), matchedInstructionIndexes);

        // Verify each split transfer.
        for (const split of splits) {
            verifySolTransfer(instructions, split.recipient, split.amount, matchedInstructionIndexes);
        }
        verifyMemoInstructions(instructions, challenge.externalId, splits, matchedInstructionIndexes);

        await validateParsedInstructionAllowlist(instructions, matchedInstructionIndexes, {
            allowedAtaOwners: ataPolicy.allowedAtaOwners,
            expectedAtaPayer: undefined,
            expectedMint: undefined,
            expectedTokenProgram: undefined,
            requiredAtaOwners: ataPolicy.requiredAtaOwners,
        });
    }
}

async function verifySplTransfer(
    instructions: ParsedInstruction[],
    recipientAddress: string,
    expectedAmount: string,
    spl: string,
    tokenProgram: string,
    matchedInstructionIndexes: Set<number>,
) {
    const [expectedAta] = await findAssociatedTokenPda({
        mint: address(spl),
        owner: address(recipientAddress),
        tokenProgram: address(tokenProgram),
    });

    for (const [index, ix] of instructions.entries()) {
        if (matchedInstructionIndexes.has(index)) continue;
        if (typeof ix.parsed !== 'object' || ix.parsed?.type !== 'transferChecked') continue;
        if (ix.programId !== tokenProgram) continue;
        const info = ix.parsed.info as { destination?: string; mint?: string; tokenAmount?: { amount?: string } };
        if (info.destination === expectedAta && info.mint === spl && info.tokenAmount?.amount === expectedAmount) {
            matchedInstructionIndexes.add(index);
            return;
        }
    }

    throw new Error(`No TransferChecked instruction found for recipient ${recipientAddress}`);
}

function verifySolTransfer(
    instructions: ParsedInstruction[],
    recipientAddress: string,
    expectedAmount: string,
    matchedInstructionIndexes: Set<number>,
) {
    for (const [index, ix] of instructions.entries()) {
        if (matchedInstructionIndexes.has(index)) continue;
        if (typeof ix.parsed !== 'object' || ix.parsed?.type !== 'transfer' || ix.program !== 'system') continue;
        const info = ix.parsed.info as { destination?: string; lamports?: number | string };
        if (info.destination === recipientAddress && String(info.lamports) === expectedAmount) {
            matchedInstructionIndexes.add(index);
            return;
        }
    }

    throw new Error(`No system transfer instruction found for recipient ${recipientAddress}`);
}

function verifyMemoInstructionsPreBroadcast(
    message: CompiledMessage,
    externalId: string | undefined,
    splits: Array<{ memo?: string }>,
    matchedInstructionIndexes: Set<number>,
) {
    for (const expectedMemo of expectedMemoEntries(externalId, splits)) {
        const expectedData = new TextEncoder().encode(expectedMemo.value);
        if (expectedData.byteLength > 566) {
            throw new Error('memo cannot exceed 566 bytes');
        }

        let found = false;
        for (const [index, ix] of message.instructions.entries()) {
            if (matchedInstructionIndexes.has(index)) continue;
            if (programAddress(message, ix) !== MEMO_PROGRAM) continue;
            if (bytesEqual(ix.data, expectedData)) {
                matchedInstructionIndexes.add(index);
                found = true;
                break;
            }
        }
        if (!found) {
            throw new Error(`No memo instruction found for ${expectedMemo.label} memo "${expectedMemo.value}"`);
        }
    }
}

function verifyMemoInstructions(
    instructions: ParsedInstruction[],
    externalId: string | undefined,
    splits: Array<{ memo?: string }>,
    matchedInstructionIndexes: Set<number>,
) {
    for (const expectedMemo of expectedMemoEntries(externalId, splits)) {
        if (new TextEncoder().encode(expectedMemo.value).byteLength > 566) {
            throw new Error('memo cannot exceed 566 bytes');
        }

        let found = false;
        for (const [index, ix] of instructions.entries()) {
            if (matchedInstructionIndexes.has(index)) continue;
            if (parsedProgramId(ix) !== MEMO_PROGRAM) continue;
            if (parsedMemoText(ix) === expectedMemo.value) {
                matchedInstructionIndexes.add(index);
                found = true;
                break;
            }
        }
        if (!found) {
            throw new Error(`No memo instruction found for ${expectedMemo.label} memo "${expectedMemo.value}"`);
        }
    }
}

function expectedMemoEntries(externalId: string | undefined, splits: Array<{ memo?: string }>) {
    const entries: Array<{ label: 'externalId' | 'split'; value: string }> = [];
    if (externalId) {
        entries.push({ label: 'externalId', value: externalId });
    }
    for (const split of splits) {
        if (split.memo) {
            entries.push({ label: 'split', value: split.memo });
        }
    }
    return entries;
}

function parsedMemoText(ix: ParsedInstruction): string | undefined {
    if (typeof ix.parsed === 'string') return ix.parsed;
    if (typeof ix.parsed?.info?.memo === 'string') return ix.parsed.info.memo;
    if (typeof ix.parsed?.info?.data === 'string') return ix.parsed.info.data;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i += 1) {
        if (a[i] !== b[i]) return false;
    }
    return true;
}

async function validateParsedInstructionAllowlist(
    instructions: ParsedInstruction[],
    matchedPaymentInstructionIndexes: Set<number>,
    options: {
        allowedAtaOwners: Set<string>;
        expectedAtaPayer: string | undefined;
        expectedMint: string | undefined;
        expectedTokenProgram: string | undefined;
        requiredAtaOwners: Set<string>;
    },
) {
    const createdAtaOwners = new Set<string>();

    for (const [index, ix] of instructions.entries()) {
        const programId = parsedProgramId(ix);

        if (programId === COMPUTE_BUDGET_PROGRAM) {
            continue;
        }

        if (programId === MEMO_PROGRAM) {
            if (matchedPaymentInstructionIndexes.has(index)) continue;
            throw new Error('Unexpected Memo Program instruction in payment transaction');
        }

        if (programId === SYSTEM_PROGRAM) {
            if (matchedPaymentInstructionIndexes.has(index)) continue;
            throw new Error('Unexpected System Program instruction in payment transaction');
        }

        if (programId === TOKEN_PROGRAM || programId === TOKEN_2022_PROGRAM) {
            if (matchedPaymentInstructionIndexes.has(index)) continue;
            throw new Error('Unexpected Token Program instruction in payment transaction');
        }

        if (programId === ASSOCIATED_TOKEN_PROGRAM) {
            const owner = await validateParsedAtaCreationInstruction(ix, options);
            createdAtaOwners.add(owner);
            continue;
        }

        throw new Error(`Unexpected program instruction in payment transaction: ${programId ?? 'unknown'}`);
    }

    for (const owner of options.requiredAtaOwners) {
        if (!createdAtaOwners.has(owner)) {
            throw new Error(`Missing required ATA creation instruction for split recipient ${owner}`);
        }
    }
}

function parsedProgramId(ix: ParsedInstruction): string | undefined {
    if (ix.programId) return ix.programId;
    if (ix.program === 'system') return SYSTEM_PROGRAM;
    if (ix.program === 'compute-budget') return COMPUTE_BUDGET_PROGRAM;
    if (ix.program === 'spl-memo') return MEMO_PROGRAM;
    if (ix.program === 'spl-associated-token-account') return ASSOCIATED_TOKEN_PROGRAM;
    return undefined;
}

async function validateParsedAtaCreationInstruction(
    ix: ParsedInstruction,
    options: {
        allowedAtaOwners: Set<string>;
        expectedAtaPayer: string | undefined;
        expectedMint: string | undefined;
        expectedTokenProgram: string | undefined;
    },
): Promise<string> {
    if (!options.expectedMint) {
        throw new Error('ATA creation is not allowed for native SOL payments');
    }
    if (typeof ix.parsed !== 'object' || ix.parsed?.type !== 'createIdempotent') {
        throw new Error('Only idempotent ATA creation is allowed');
    }

    const info = ix.parsed.info;
    const payer = stringField(info, 'source', 'payer');
    const ata = stringField(info, 'account', 'associatedAccount', 'associatedTokenAddress');
    const owner = stringField(info, 'wallet', 'owner');
    const mint = stringField(info, 'mint');
    const tokenProgram = stringField(info, 'tokenProgram') ?? options.expectedTokenProgram;

    if (!payer || !ata || !owner || !mint || !tokenProgram) {
        throw new Error('ATA creation parsed instruction is missing required fields');
    }
    if (options.expectedAtaPayer && payer !== options.expectedAtaPayer) {
        throw new Error('ATA payer must match the transaction fee payer');
    }
    if (mint !== options.expectedMint) {
        throw new Error('ATA creation mint does not match the charge currency');
    }
    if (tokenProgram !== TOKEN_PROGRAM && tokenProgram !== TOKEN_2022_PROGRAM) {
        throw new Error('ATA creation uses an unsupported token program');
    }
    if (options.expectedTokenProgram && tokenProgram !== options.expectedTokenProgram) {
        throw new Error('ATA creation token program does not match methodDetails.tokenProgram');
    }

    const [expectedAta] = await findAssociatedTokenPda({
        mint: address(mint),
        owner: address(owner),
        tokenProgram: address(tokenProgram),
    });
    if (ata !== expectedAta) {
        throw new Error('ATA creation address does not match owner/mint/token program');
    }

    if (!options.allowedAtaOwners.has(owner)) {
        throw new Error('ATA creation owner is not authorized by the challenge');
    }

    return owner;
}

function stringField(info: Record<string, unknown>, ...keys: string[]): string | undefined {
    for (const key of keys) {
        const value = info[key];
        if (typeof value === 'string') return value;
    }
    return undefined;
}

// ── Types ──

/** Credential payload from the mppx framework. */
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

/** The request portion of a challenge, matching the Methods.ts schema. */
type ChallengeRequest = {
    amount: string;
    currency: string;
    externalId?: string;
    methodDetails: {
        decimals?: number;
        feePayer?: boolean;
        feePayerKey?: string;
        network?: string;
        recentBlockhash?: string;
        splits?: Array<{ amount: string; ataCreationRequired?: boolean; memo?: string; recipient: string }>;
        tokenProgram?: string;
    };
    recipient: string;
};

/** A parsed instruction from a jsonParsed transaction. */
type ParsedInstruction = {
    parsed?:
        | string
        | {
              info: Record<string, unknown>;
              type: string;
          };
    program?: string;
    programId?: string;
};

/** A parsed transaction result from getTransaction RPC. */
type ParsedTransaction = {
    meta: { err: unknown } | null;
    transaction: {
        message: {
            instructions: ParsedInstruction[];
        };
    };
};

// ── RPC helpers ──

async function fetchTransaction(rpcUrl: string, signature: string): Promise<ParsedTransaction | null> {
    const response = await fetch(rpcUrl, {
        body: JSON.stringify({
            id: 1,
            jsonrpc: '2.0',
            method: 'getTransaction',
            params: [
                signature,
                {
                    commitment: 'confirmed',
                    encoding: 'jsonParsed',
                    maxSupportedTransactionVersion: 0,
                },
            ],
        }),
        headers: { 'Content-Type': 'application/json' },
        method: 'POST',
    });
    const data = (await response.json()) as {
        error?: { message: string };
        result?: ParsedTransaction | null;
    };
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
        console.error('[solana-mpp] Simulation failed:', JSON.stringify(simErr));
        for (const log of logs) console.error('[solana-mpp]', log);
        throw new Error(`Transaction simulation failed: ${JSON.stringify(simErr)}`);
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
    const data = (await response.json()) as {
        error?: { message: string };
        result?: string;
    };
    if (data.error) throw new Error(`RPC error: ${data.error.message}`);
    if (!data.result) throw new Error('No signature returned from sendTransaction');
    return data.result;
}

async function waitForConfirmation(rpcUrl: string, signature: string, timeoutMs = 30_000) {
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
            result?: {
                value: ({ confirmationStatus: string; err: unknown } | null)[];
            };
        };
        const status = data.result?.value?.[0];
        if (status) {
            if (status.err) {
                throw new Error(`Transaction failed: ${JSON.stringify(status.err)}`);
            }
            if (status.confirmationStatus === 'confirmed' || status.confirmationStatus === 'finalized') {
                return;
            }
        }
        await new Promise(r => setTimeout(r, 2_000));
    }
    throw new Error('Transaction confirmation timeout');
}

export declare namespace charge {
    type Parameters = {
        /**
         * Currency identifier. "sol" (lowercase) for native SOL, or a
         * base58-encoded SPL token mint address. Defaults to "sol".
         */
        currency?: string;
        /** Token decimals (required when currency is a mint address). */
        decimals?: number;
        /**
         * Enable HTML payment link pages for browser requests.
         * When true, 402 responses for requests with `Accept: text/html`
         * will return an interactive payment page instead of JSON.
         *
         * Usage is seamless — just set `html: true` and `result.challenge`
         * automatically returns HTML for browsers:
         *
         * ```ts
         * const mppx = Mppx.create({
         *   methods: [solana.charge({ recipient, html: true, ... })],
         * })
         *
         * // In your handler:
         * const result = await mppx.charge({ amount: '10000' })(request)
         * if (result.status === 402) return result.challenge  // HTML for browsers, JSON for APIs
         * ```
         */
        html?: boolean;
        /** Solana network. Defaults to 'mainnet-beta'. */
        network?: 'devnet' | 'localnet' | 'mainnet-beta' | (string & {});
        /** Base58-encoded recipient public key that receives payments. */
        recipient: string;
        /** Custom RPC URL. Defaults to public RPC for the selected network. */
        rpcUrl?: string;
        /**
         * Server-side signer for fee sponsorship (feePayer mode).
         * When provided, the server's public key is included in the challenge
         * as `feePayerKey`, and the server co-signs the transaction as fee payer
         * before broadcasting.
         *
         * Accepts any TransactionPartialSigner — KeyPairSigner, Keychain SolanaSigner, etc.
         */
        signer?: TransactionPartialSigner;
        /** Additional payment splits. Same asset as primary payment. Max 8 entries. */
        splits?: Array<{
            /** Amount in base units (same asset as primary). */
            amount: string;
            /** If true, create the split recipient ATA idempotently before payment. */
            ataCreationRequired?: boolean;
            /** Optional memo (max 566 bytes). */
            memo?: string;
            /** Base58-encoded recipient of this split. */
            recipient: string;
        }>;
        /**
         * Pluggable key-value store for consumed-signature tracking (replay prevention).
         * Defaults to in-memory. Use a persistent store in production.
         */
        store?: Store.Store;
        /** Token program hint. If omitted, clients fetch the mint owner and fail closed on lookup errors. */
        tokenProgram?: string;
    };
}
