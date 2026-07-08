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
    signature as toSignature,
    signTransactionMessageWithSigners,
    type TransactionSigner,
} from '@solana/kit';
import { getSetComputeUnitLimitInstruction, getSetComputeUnitPriceInstruction } from '@solana-program/compute-budget';
import { getTransferSolInstruction } from '@solana-program/system';
import {
    findAssociatedTokenPda,
    getCreateAssociatedTokenIdempotentInstruction,
    getTransferCheckedInstruction,
} from '@solana-program/token';
import { Credential, Method } from 'mppx';

import {
    ASSOCIATED_TOKEN_PROGRAM,
    DEFAULT_RPC_URLS,
    MEMO_PROGRAM,
    normalizeNetwork,
    resolveStablecoinMint,
    stablecoinSymbolForCurrency,
    SYSTEM_PROGRAM,
    TOKEN_2022_PROGRAM,
    TOKEN_PROGRAM,
} from '../constants.js';
import * as Methods from '../Methods.js';

/**
 * Creates a Solana `charge` method for usage on the client.
 *
 * Supports two modes controlled by the `broadcast` option:
 *
 * - **Pull mode** (`broadcast: false`, default): Signs the transaction
 *   and sends the serialized bytes as a `type="transaction"` credential.
 *   The server broadcasts it to the Solana network.
 *
 * - **Push mode** (`broadcast: true`): Signs, broadcasts, confirms
 *   the transaction on-chain, and sends the signature as a `type="signature"`
 *   credential. Cannot be used with fee sponsorship.
 *
 * When the server advertises `feePayer: true` in the challenge, the client
 * sets the server's `feePayerKey` as the transaction fee payer and partially
 * signs (transfer authority only). The server adds its fee payer signature
 * before broadcasting.
 *
 * @example
 * ```ts
 * import { Mppx, solana } from '@solana/mpp/client'
 *
 * const method = solana.charge({ signer, rpcUrl: 'https://api.devnet.solana.com' })
 * const mppx = Mppx.create({ methods: [method] })
 *
 * const response = await mppx.fetch('https://api.example.com/paid-content')
 * console.log(await response.json())
 * ```
 */
export function charge(parameters: charge.Parameters) {
    const { signer, broadcast = false, onProgress, maxAmount, expectedNetwork, allowUnknownToken2022 } = parameters;

    const method = Method.toClient(Methods.charge, {
        async createCredential({ challenge }) {
            const { methodDetails } = challenge.request;
            const { network, feePayer: serverPaysFees } = methodDetails;

            if (serverPaysFees && broadcast) {
                throw new Error('broadcast=true cannot be used with fee sponsorship (feePayer: true)');
            }

            // Client-side policy gates (audit #10). The protocol's trust model
            // assumes a human reviews the challenge before signing; auto-pay
            // agents break that, so an auto-pay caller can bind what we'll sign.
            // All gates default to "no constraint" except expiry, which is
            // always-on (fail-closed).
            assertChallengeNotExpired(challenge.expires);
            if (maxAmount !== undefined && BigInt(challenge.request.amount) > maxAmount) {
                throw new Error(
                    `Challenge amount ${challenge.request.amount} exceeds the configured maxAmount ${maxAmount}`,
                );
            }
            if (
                expectedNetwork !== undefined &&
                normalizeNetwork(network ?? 'mainnet') !== normalizeNetwork(expectedNetwork)
            ) {
                throw new Error(
                    `Challenge network "${network ?? 'mainnet'}" does not match the expected network "${expectedNetwork}"`,
                );
            }

            const encodedTx = await buildChargeTransaction({
                allowUnknownToken2022,
                computeUnitLimit: parameters.computeUnitLimit,
                computeUnitPrice: parameters.computeUnitPrice,
                onProgress,
                request: challenge.request,
                rpcUrl:
                    parameters.rpcUrl ??
                    DEFAULT_RPC_URLS[normalizeNetwork(network || 'mainnet')] ??
                    DEFAULT_RPC_URLS.mainnet,
                signer,
            });
            const rpc = createSolanaRpc(
                parameters.rpcUrl ??
                    DEFAULT_RPC_URLS[normalizeNetwork(network || 'mainnet')] ??
                    DEFAULT_RPC_URLS.mainnet,
            );

            if (broadcast) {
                // ── Push mode (type="signature") ──
                onProgress?.({ type: 'paying' });

                const signature = await rpc
                    .sendTransaction(encodedTx, {
                        encoding: 'base64',
                        skipPreflight: false,
                    })
                    .send();

                onProgress?.({ signature, type: 'confirming' });
                await confirmTransaction(rpc, signature);
                onProgress?.({ signature, type: 'paid' });

                return Credential.serialize({
                    challenge,
                    payload: { signature, type: 'signature' },
                });
            }

            // ── Pull mode (type="transaction", default) ──
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
 * Builds and signs the Solana transaction for an MPP charge request.
 *
 * This is the lower-level client SDK entry point for integrations that already
 * have a decoded charge request and want the transaction bytes instead of the
 * full mppx `charge()` method wrapper.
 */
export async function buildChargeTransaction(
    parameters: buildChargeTransaction.Parameters,
): Promise<Base64EncodedWireTransaction> {
    const {
        signer,
        request: { amount, currency, externalId, recipient, methodDetails },
        onProgress,
        allowUnknownToken2022 = false,
    } = parameters;
    const {
        network,
        decimals,
        tokenProgram: tokenProgramAddr,
        feePayer: serverPaysFees,
        feePayerKey,
        recentBlockhash: serverBlockhash,
        splits,
    } = methodDetails;

    // currency is "sol" for native, or the mint address for SPL tokens.
    const mint = resolveStablecoinMint(currency, network);

    const rpcUrl =
        parameters.rpcUrl ?? DEFAULT_RPC_URLS[normalizeNetwork(network || 'mainnet')] ?? DEFAULT_RPC_URLS.mainnet;
    const rpc = createSolanaRpc(rpcUrl);
    onProgress?.({
        amount,
        currency,
        feePayerKey: feePayerKey || undefined,
        recipient,
        type: 'challenge',
    });

    if (serverPaysFees && !feePayerKey) {
        throw new Error('feePayer=true requires feePayerKey in methodDetails');
    }

    const useServerFeePayer = serverPaysFees === true;

    // Compute primary amount (total minus splits).
    const splitsTotal = (splits ?? []).reduce((sum, s) => sum + BigInt(s.amount), 0n);
    const primaryAmount = BigInt(amount) - splitsTotal;
    if (primaryAmount <= 0n) {
        throw new Error('Splits consume the entire amount; primary recipient must receive a positive amount');
    }
    const hasAtaCreationSplits = splits?.some(split => split.ataCreationRequired === true) === true;
    if (!mint && hasAtaCreationSplits) {
        throw new Error('ataCreationRequired requires an SPL token charge');
    }
    if (hasAtaCreationSplits && currency !== mint) {
        throw new Error('ataCreationRequired requires currency to be an SPL token mint address');
    }

    // Build transfer instructions.
    const instructions: Instruction[] = [];
    const addMemoInstruction = (memo: string | undefined) => {
        if (!memo) return;
        const data = new TextEncoder().encode(memo);
        if (data.byteLength > 566) {
            throw new Error('memo cannot exceed 566 bytes');
        }
        instructions.push({
            accounts: [],
            data,
            programAddress: address(MEMO_PROGRAM),
        });
    };

    if (mint) {
        // ── SPL token transfers ──
        const mintAddress = address(mint);
        const tokenProg = tokenProgramAddr ? address(tokenProgramAddr) : await resolveTokenProgram(rpc, mintAddress);

        // Audit #26: refuse to sign unknown Token-2022 mints unless explicitly
        // allowed. Token-2022 mints can carry transfer hooks that execute
        // arbitrary code on every transfer; the server's pre-broadcast checks do
        // not simulate inner instructions in pull mode. Vanilla Token mints have
        // no hooks, so arbitrary mints there stay allowed.
        if (
            String(tokenProg) === TOKEN_2022_PROGRAM &&
            stablecoinSymbolForCurrency(mint) === undefined &&
            !allowUnknownToken2022
        ) {
            throw new Error(
                'Refusing to sign an unknown Token-2022 mint (transfer-hook risk). ' +
                    'Set allowUnknownToken2022: true to override.',
            );
        }

        // Audit #42: decimals MUST be present for SPL (spec §7.2). Silently
        // defaulting to 6 produces a wrong transferChecked divisor for
        // non-6-decimal mints — the worst possible failure for a signer.
        if (decimals === undefined) {
            throw new Error('methodDetails.decimals is required for SPL charges (spec §7.2)');
        }
        const tokenDecimals = decimals;

        const [sourceAta] = await findAssociatedTokenPda({
            mint: mintAddress,
            owner: signer.address,
            tokenProgram: tokenProg,
        });

        const findDestinationAta = async (owner: Address) => {
            const [ata] = await findAssociatedTokenPda({
                mint: mintAddress,
                owner,
                tokenProgram: tokenProg,
            });

            return ata;
        };

        const addAtaCreation = async (owner: Address) => {
            const ata = await findDestinationAta(owner);

            if (useServerFeePayer) {
                instructions.push(
                    createAssociatedTokenAccountIdempotent(address(feePayerKey!), owner, mintAddress, ata, tokenProg),
                );
            } else {
                instructions.push(
                    getCreateAssociatedTokenIdempotentInstruction({
                        ata,
                        mint: mintAddress,
                        owner,
                        payer: signer,
                        tokenProgram: tokenProg,
                    }),
                );
            }

            return ata;
        };

        // Helper: add ATA creation + transferChecked for a recipient.
        const addSplTransfer = async (dest: string, transferAmount: bigint, createAta: boolean) => {
            const destOwner = address(dest);
            const destAta = createAta ? await addAtaCreation(destOwner) : await findDestinationAta(destOwner);

            instructions.push(
                getTransferCheckedInstruction(
                    {
                        amount: transferAmount,
                        authority: signer,
                        decimals: tokenDecimals,
                        destination: destAta,
                        mint: mintAddress,
                        source: sourceAta,
                    },
                    { programAddress: tokenProg },
                ),
            );
        };

        // Primary recipient ATA creation is intentionally out of scope.
        await addSplTransfer(recipient, primaryAmount, false);
        addMemoInstruction(externalId);

        // Split transfers. Audit #20: create the split ATA only when the server
        // flags it via ataCreationRequired, in BOTH modes. Previously
        // client-paid mode auto-funded every split ATA, letting a hostile server
        // drain the client with N dust splits (N × ~0.002 SOL rent).
        for (const split of splits ?? []) {
            await addSplTransfer(split.recipient, BigInt(split.amount), split.ataCreationRequired === true);
            addMemoInstruction(split.memo);
        }
    } else {
        // ── Native SOL transfers ──
        // Primary transfer to recipient.
        instructions.push(
            getTransferSolInstruction({
                amount: primaryAmount,
                destination: address(recipient),
                source: signer,
            }),
        );
        addMemoInstruction(externalId);

        // Split transfers.
        for (const split of splits ?? []) {
            instructions.push(
                getTransferSolInstruction({
                    amount: BigInt(split.amount),
                    destination: address(split.recipient),
                    source: signer,
                }),
            );
            addMemoInstruction(split.memo);
        }
    }

    onProgress?.({ type: 'signing' });

    // Use server-provided blockhash if available, otherwise fetch one.
    const latestBlockhash = serverBlockhash
        ? {
              blockhash: serverBlockhash as Blockhash,
              lastValidBlockHeight: BigInt(0), // Server doesn't provide this; tx lifetime is managed by the blockhash itself.
          }
        : (await rpc.getLatestBlockhash().send()).value;

    const txMessage = pipe(
        createTransactionMessage({ version: 0 }),
        msg =>
            useServerFeePayer
                ? setTransactionMessageFeePayer(address(feePayerKey!), msg)
                : setTransactionMessageFeePayerSigner(signer, msg),
        msg => setTransactionMessageLifetimeUsingBlockhash(latestBlockhash, msg),
        msg => appendTransactionMessageInstructions(instructions, msg),
        // Prepend compute budget instructions per best practice.
        msg =>
            prependTransactionMessageInstructions(
                [
                    getSetComputeUnitPriceInstruction({ microLamports: parameters.computeUnitPrice ?? 1n }),
                    getSetComputeUnitLimitInstruction({ units: parameters.computeUnitLimit ?? 200_000 }),
                ],
                msg,
            ),
    );

    // When server pays fees, partially sign (only the transfer authority).
    // The server will add its fee payer signature before broadcasting.
    const signedTx = useServerFeePayer
        ? await partiallySignTransactionMessageWithSigners(txMessage)
        : await signTransactionMessageWithSigners(txMessage);

    return getBase64EncodedWireTransaction(signedTx);
}

// ── Helpers ──

/**
 * Always-on expiry refusal for the client (audit #10): refuse to sign a
 * challenge whose `expires` timestamp is in the past or malformed. A challenge
 * with no `expires` is accepted — the protocol allows omitting it and the client
 * has no anchor to check against.
 */
function assertChallengeNotExpired(expires: string | undefined): void {
    if (expires === undefined) return;
    const expiresAt = new Date(expires).getTime();
    if (Number.isNaN(expiresAt)) {
        throw new Error(`Refusing to sign: malformed challenge expires timestamp "${expires}"`);
    }
    if (expiresAt < Date.now()) {
        throw new Error('Refusing to sign an expired challenge');
    }
}

/**
 * Creates an Associated Token Account using the idempotent instruction
 * (CreateIdempotent = discriminator 1). This is a no-op if the ATA exists.
 *
 * Used in fee payer mode where the payer is the server's key (not a local
 * signer). The server adds its signature before broadcasting.
 */
function createAssociatedTokenAccountIdempotent(
    payer: Address,
    owner: Address,
    mint: Address,
    ata: Address,
    tokenProgram: Address,
): Instruction {
    return {
        accounts: [
            { address: payer, role: AccountRole.WRITABLE_SIGNER },
            { address: ata, role: AccountRole.WRITABLE },
            { address: owner, role: AccountRole.READONLY },
            { address: mint, role: AccountRole.READONLY },
            { address: address(SYSTEM_PROGRAM), role: AccountRole.READONLY },
            { address: tokenProgram, role: AccountRole.READONLY },
        ],
        data: new Uint8Array([1]),
        programAddress: address(ASSOCIATED_TOKEN_PROGRAM), // CreateIdempotent discriminator
    };
}

async function resolveTokenProgram(rpc: ReturnType<typeof createSolanaRpc>, mint: Address): Promise<Address> {
    const account = await rpc.getAccountInfo(mint, { encoding: 'base64' }).send();
    const owner = account.value?.owner;

    if (!owner) {
        throw new Error('Failed to determine token program for mint: mint account not found');
    }
    if (owner === TOKEN_PROGRAM || owner === TOKEN_2022_PROGRAM) {
        return address(owner);
    }

    throw new Error(`Failed to determine token program for mint: unexpected owner ${owner}`);
}

/**
 * Polls for transaction confirmation via getSignatureStatuses.
 * Only used in push mode.
 */
async function confirmTransaction(rpc: ReturnType<typeof createSolanaRpc>, signature: string, timeoutMs = 30_000) {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
        const { value } = await rpc.getSignatureStatuses([toSignature(signature)]).send();
        const status = value[0];
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
         * Opt-in (audit #26): allow signing unknown Token-2022 mints. Token-2022
         * mints can carry transfer hooks that execute arbitrary code on transfer,
         * so by default the client refuses unknown (non-stablecoin) Token-2022
         * mints. Vanilla Token mints are always allowed regardless of this flag.
         */
        allowUnknownToken2022?: boolean;
        /**
         * If true, the client broadcasts the transaction and sends the signature
         * as a `type="signature"` credential. If false (default), the client sends
         * the signed transaction bytes as a `type="transaction"` credential and the
         * server broadcasts it.
         *
         * Cannot be used with server fee sponsorship (feePayer mode).
         */
        broadcast?: boolean;
        /** Compute unit limit. Defaults to 200,000. */
        computeUnitLimit?: number;
        /** Compute unit price in micro-lamports for priority fees. Defaults to 1. */
        computeUnitPrice?: bigint;
        /**
         * Opt-in guard (audit #10): refuse to sign a challenge whose network does
         * not match this value. Use for auto-pay flows. Defaults to no constraint.
         */
        expectedNetwork?: string;
        /**
         * Opt-in guard (audit #10): refuse to sign a challenge whose amount (in
         * base units) exceeds this cap. Use for auto-pay flows where the server
         * controls what gets signed. Defaults to no constraint.
         */
        maxAmount?: bigint;
        /** Called at each step of the payment process. */
        onProgress?: (event: ProgressEvent) => void;
        /** Custom RPC URL. If not set, inferred from the challenge's network field. */
        rpcUrl?: string;
        /**
         * Solana transaction signer. Compatible with:
         * - ConnectorKit's `useTransactionSigner()` hook
         * - `createKeyPairSignerFromBytes()` from `@solana/kit` for headless usage
         * - Solana Keychain's `SolanaSigner` for remote signers
         * - Any `TransactionSigner` implementation
         */
        signer: TransactionSigner;
    };

    type ProgressEvent =
        | {
              amount: string;
              currency: string;
              feePayerKey?: string;
              recipient: string;
              type: 'challenge';
          }
        | { signature: string; type: 'confirming' }
        | { signature: string; type: 'paid' }
        | { transaction: string; type: 'signed' }
        | { type: 'paying' }
        | { type: 'signing' };
}

export declare namespace buildChargeTransaction {
    type Parameters = {
        /**
         * Allow signing unknown Token-2022 mints (audit #26). Defaults to false;
         * unknown (non-stablecoin) Token-2022 mints are refused because they may
         * carry transfer hooks.
         */
        allowUnknownToken2022?: boolean;
        /** Compute unit limit. Defaults to 200,000. */
        computeUnitLimit?: number;
        /** Compute unit price in micro-lamports for priority fees. Defaults to 1. */
        computeUnitPrice?: bigint;
        /** Called at each step of the payment build/signing process. */
        onProgress?: (
            event:
                | {
                      amount: string;
                      currency: string;
                      feePayerKey?: string;
                      recipient: string;
                      type: 'challenge';
                  }
                | { type: 'signing' },
        ) => void;
        /** Decoded request from a Solana MPP charge challenge. */
        request: {
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
        /** Custom RPC URL. If not set, inferred from the request network field. */
        rpcUrl?: string;
        /** Solana transaction signer. */
        signer: TransactionSigner;
    };
}
