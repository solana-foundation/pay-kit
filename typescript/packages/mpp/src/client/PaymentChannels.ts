import {
    type Address,
    address,
    appendTransactionMessageInstructions,
    type Base64EncodedWireTransaction,
    type Blockhash,
    createNoopSigner,
    createSolanaRpc,
    createTransactionMessage,
    generateKeyPairSigner,
    getAddressEncoder,
    getBase64EncodedWireTransaction,
    getProgramDerivedAddress,
    getU64Encoder,
    getUtf8Encoder,
    partiallySignTransactionMessageWithSigners,
    pipe,
    setTransactionMessageFeePayer,
    setTransactionMessageLifetimeUsingBlockhash,
    type TransactionSigner,
} from '@solana/kit';
import { findAssociatedTokenPda } from '@solana-program/token';

import {
    ASSOCIATED_TOKEN_PROGRAM,
    DEFAULT_RPC_URLS,
    defaultTokenProgramForCurrency,
    normalizeNetwork,
    resolveStablecoinMint,
} from '../constants.js';
import { findEventAuthorityPda, getOpenInstruction } from '../generated/payment-channels/index.js';
import {
    ActiveSession,
    type AmountLike,
    DEFAULT_SESSION_EXPIRES_AT,
    type SessionRequest,
    type SessionSigner,
} from './Session.js';
import type { SessionOpener } from './SessionFetch.js';

const U64_MAX = (1n << 64n) - 1n;
const PAYMENT_CHANNELS_PROGRAM = 'CHNLxYvVA28MJP9PrFuDXccuoGXAx7jBacfLEkahyGsX';
const RENT_SYSVAR = 'SysvarRent111111111111111111111111111111111';
const DEFAULT_GRACE_PERIOD_SECONDS = 900;

/** Placeholder signature used while the operator still needs to broadcast the open transaction. */
export const PENDING_SERVER_SIGNATURE = '1111111111111111111111111111111111111111111111111111111111111111';

/**
 * Payment-channel open fields shared by client-built and server-built open flows.
 */
export interface PaymentChannelOpen {
    readonly channelId: string;
    readonly deposit: string;
    readonly gracePeriod: number;
    readonly mint: string;
    readonly payee: string;
    readonly payer: string;
    readonly salt: string;
}

/**
 * Single payment-channel open transaction plus the fields needed to authorize a session.
 */
export interface PaymentChannelOpenTransaction extends PaymentChannelOpen {
    readonly transaction: Base64EncodedWireTransaction;
}

/**
 * Derives the payment-channel open fields without building a transaction.
 *
 * Use this for server-opened client-voucher sessions: the client must know the
 * channel PDA so it can sign vouchers, but the operator still funds and opens
 * the channel.
 */
export async function derivePaymentChannelOpen(
    parameters: derivePaymentChannelOpen.Parameters,
): Promise<PaymentChannelOpen> {
    const open = await preparePaymentChannelOpen(parameters);
    return {
        channelId: open.channelId,
        deposit: open.deposit.toString(),
        gracePeriod: open.gracePeriod,
        mint: open.mint,
        payee: open.payee,
        payer: open.payer,
        salt: open.salt.toString(),
    };
}

/**
 * Builds the payer-signed payment-channel open transaction for pull/client-voucher sessions.
 *
 * The transaction uses the operator from the session challenge as fee payer and
 * is intentionally left partially signed; the server adds the operator
 * signature before broadcasting it.
 */
export async function buildOpenPaymentChannelTransaction(
    parameters: buildOpenPaymentChannelTransaction.Parameters,
): Promise<PaymentChannelOpenTransaction> {
    const { request, signer } = parameters;
    const open = await preparePaymentChannelOpen({
        ...parameters,
        payer: signer.address,
    });
    const network = normalizeNetwork(request.network ?? 'mainnet');
    const programAddress = open.programAddress;
    const tokenProgram = open.tokenProgram;
    const payer = address(open.payer);
    const payee = address(open.payee);
    const mintAddress = address(open.mint);
    const authorizedSigner = address(parameters.authorizedSigner);
    const feePayer = address(request.operator);
    const [payerTokenAccount] = await findAssociatedTokenPda({
        mint: mintAddress,
        owner: payer,
        tokenProgram,
    });
    const [channelTokenAccount] = await findAssociatedTokenPda({
        mint: mintAddress,
        owner: address(open.channelId),
        tokenProgram,
    });
    const [eventAuthority] = await findEventAuthorityPda({ programAddress });

    // rentPayer is the operator / fee payer: it funds the channel PDA +
    // escrow-ATA rent at open. It is the same key set as fee payer above, so
    // the single operator signature added server-side covers both the
    // fee-payer and rentPayer signer roles. When the operator is the payer
    // itself, reuse the payer signer instance (kit rejects two distinct signer
    // objects for one address); otherwise a noop signer carries the operator
    // address into the instruction without signing here.
    const rentPayerSigner = feePayer === signer.address ? signer : createNoopSigner(feePayer);

    const instruction = getOpenInstruction(
        {
            associatedTokenProgram: address(ASSOCIATED_TOKEN_PROGRAM),
            authorizedSigner,
            channel: address(open.channelId),
            channelTokenAccount,
            eventAuthority,
            mint: mintAddress,
            openArgs: {
                deposit: open.deposit,
                gracePeriod: open.gracePeriod,
                recipients: open.recipients.map(r => ({ bps: r.bps, recipient: r.recipient })),
                salt: open.salt,
            },
            payee,
            payer: signer,
            payerTokenAccount,
            rent: address(RENT_SYSVAR),
            rentPayer: rentPayerSigner,
            selfProgram: programAddress,
            tokenProgram,
        },
        { programAddress },
    );
    const latestBlockhash = request.recentBlockhash
        ? {
              blockhash: request.recentBlockhash as Blockhash,
              lastValidBlockHeight: 0n,
          }
        : (
              await createSolanaRpc(parameters.rpcUrl ?? DEFAULT_RPC_URLS[network] ?? DEFAULT_RPC_URLS.mainnet)
                  .getLatestBlockhash()
                  .send()
          ).value;

    const txMessage = pipe(
        createTransactionMessage({ version: 0 }),
        msg => setTransactionMessageFeePayer(feePayer, msg),
        msg => setTransactionMessageLifetimeUsingBlockhash(latestBlockhash, msg),
        msg => appendTransactionMessageInstructions([instruction], msg),
    );
    const signedTx = await partiallySignTransactionMessageWithSigners(txMessage);

    return {
        channelId: open.channelId,
        deposit: open.deposit.toString(),
        gracePeriod: open.gracePeriod,
        mint: open.mint,
        payee: open.payee,
        payer: open.payer,
        salt: open.salt.toString(),
        transaction: getBase64EncodedWireTransaction(signedTx),
    };
}

/**
 * Creates a high-level opener for pull-mode sessions using client-signed vouchers.
 *
 * The opener turns a session 402 challenge into a payment-channel open action
 * with the signed transaction attached. The server/operator broadcasts that
 * transaction, then subsequent stream commits are cumulative vouchers signed by
 * the generated session key.
 */
export function createPaymentChannelSessionOpener(
    parameters: createPaymentChannelSessionOpener.Parameters,
): SessionOpener {
    return async ({ challenge }) => {
        if (!challenge.request.modes?.includes('pull')) {
            throw new Error('payment-channel session opener requires a pull-mode session challenge');
        }
        if (challenge.request.pullVoucherStrategy !== 'clientVoucher') {
            throw new Error('payment-channel session opener requires pullVoucherStrategy=clientVoucher');
        }

        const sessionSigner = parameters.sessionSigner ?? (await generateKeyPairSigner());
        const open = await buildOpenPaymentChannelTransaction({
            authorizedSigner: sessionSigner.address,
            deposit: parameters.deposit,
            gracePeriod: parameters.gracePeriod,
            programAddress: parameters.programAddress,
            recipients: parameters.recipients,
            request: challenge.request,
            rpcUrl: parameters.rpcUrl,
            salt: parameters.salt,
            signer: parameters.signer,
            tokenProgram: parameters.tokenProgram,
        });
        const session = new ActiveSession({
            channelId: open.channelId,
            cumulative: parameters.cumulative ?? 0n,
            expiresAt: parameters.expiresAt ?? DEFAULT_SESSION_EXPIRES_AT,
            signer: sessionSigner,
        });

        return {
            payload: session.openPaymentChannelAction({
                deposit: open.deposit,
                gracePeriod: open.gracePeriod,
                mint: open.mint,
                mode: 'pull',
                payee: open.payee,
                payer: open.payer,
                salt: open.salt,
                signature: parameters.signature ?? PENDING_SERVER_SIGNATURE,
                transaction: open.transaction,
            }),
            session,
            source: parameters.source,
        };
    };
}

/**
 * Creates an opener for pull/client-voucher sessions where the operator opens
 * the payment channel server-side.
 *
 * The payload contains the deterministic channel PDA and open fields, but no
 * transaction. The server validates those fields, opens the channel with its
 * configured signer, and then the client signs cumulative vouchers for the
 * derived channel.
 */
export function createServerOpenedPaymentChannelSessionOpener(
    parameters: createServerOpenedPaymentChannelSessionOpener.Parameters = {},
): SessionOpener {
    return async ({ challenge }) => {
        if (!challenge.request.modes?.includes('pull')) {
            throw new Error('server-opened payment-channel session opener requires a pull-mode session challenge');
        }
        if (challenge.request.pullVoucherStrategy !== 'clientVoucher') {
            throw new Error('server-opened payment-channel session opener requires pullVoucherStrategy=clientVoucher');
        }

        const sessionSigner = parameters.sessionSigner ?? (await generateKeyPairSigner());
        const open = await derivePaymentChannelOpen({
            authorizedSigner: sessionSigner.address,
            deposit: parameters.deposit,
            gracePeriod: parameters.gracePeriod,
            payer: parameters.payer ?? challenge.request.operator,
            programAddress: parameters.programAddress,
            request: challenge.request,
            salt: parameters.salt,
            tokenProgram: parameters.tokenProgram,
        });
        const session = new ActiveSession({
            channelId: open.channelId,
            cumulative: parameters.cumulative ?? 0n,
            expiresAt: parameters.expiresAt ?? DEFAULT_SESSION_EXPIRES_AT,
            signer: sessionSigner,
        });

        return {
            payload: session.openPaymentChannelAction({
                deposit: open.deposit,
                gracePeriod: open.gracePeriod,
                mint: open.mint,
                mode: 'pull',
                payee: open.payee,
                payer: open.payer,
                salt: open.salt,
                signature: parameters.signature ?? PENDING_SERVER_SIGNATURE,
            }),
            session,
            source: parameters.source,
        };
    };
}

export declare namespace derivePaymentChannelOpen {
    interface Parameters {
        readonly authorizedSigner: string;
        readonly deposit?: AmountLike | undefined;
        readonly gracePeriod?: number | undefined;
        readonly payer: string;
        readonly programAddress?: string | undefined;
        readonly recipients?: readonly { readonly bps: number; readonly recipient: string }[] | undefined;
        readonly request: SessionRequest;
        readonly salt?: AmountLike | undefined;
        readonly tokenProgram?: string | undefined;
    }
}

export declare namespace buildOpenPaymentChannelTransaction {
    interface Parameters {
        readonly authorizedSigner: string;
        readonly deposit?: AmountLike | undefined;
        readonly gracePeriod?: number | undefined;
        readonly programAddress?: string | undefined;
        readonly recipients?: readonly { readonly bps: number; readonly recipient: string }[] | undefined;
        readonly request: SessionRequest;
        readonly rpcUrl?: string | undefined;
        readonly salt?: AmountLike | undefined;
        readonly signer: TransactionSigner;
        readonly tokenProgram?: string | undefined;
    }
}

export declare namespace createPaymentChannelSessionOpener {
    interface Parameters {
        readonly cumulative?: AmountLike | undefined;
        readonly deposit?: AmountLike | undefined;
        readonly expiresAt?: AmountLike | undefined;
        readonly gracePeriod?: number | undefined;
        readonly programAddress?: string | undefined;
        readonly recipients?: readonly { readonly bps: number; readonly recipient: string }[] | undefined;
        readonly rpcUrl?: string | undefined;
        readonly salt?: AmountLike | undefined;
        readonly sessionSigner?: SessionSigner | undefined;
        readonly signature?: string | undefined;
        readonly signer: TransactionSigner;
        readonly source?: string | undefined;
        readonly tokenProgram?: string | undefined;
    }
}

export declare namespace createServerOpenedPaymentChannelSessionOpener {
    interface Parameters {
        readonly cumulative?: AmountLike | undefined;
        readonly deposit?: AmountLike | undefined;
        readonly expiresAt?: AmountLike | undefined;
        readonly gracePeriod?: number | undefined;
        readonly payer?: string | undefined;
        readonly programAddress?: string | undefined;
        readonly salt?: AmountLike | undefined;
        readonly sessionSigner?: SessionSigner | undefined;
        readonly signature?: string | undefined;
        readonly source?: string | undefined;
        readonly tokenProgram?: string | undefined;
    }
}

interface PreparedPaymentChannelOpen {
    readonly channelId: string;
    readonly deposit: bigint;
    readonly gracePeriod: number;
    readonly mint: string;
    readonly payee: string;
    readonly payer: string;
    readonly programAddress: Address;
    readonly recipients: readonly { readonly bps: number; readonly recipient: Address }[];
    readonly salt: bigint;
    readonly tokenProgram: Address;
}

interface FindPaymentChannelPdaParameters {
    readonly authorizedSigner: Address;
    readonly mint: Address;
    readonly payee: Address;
    readonly payer: Address;
    readonly programAddress: Address;
    readonly salt: bigint;
}

async function preparePaymentChannelOpen(
    parameters: derivePaymentChannelOpen.Parameters,
): Promise<PreparedPaymentChannelOpen> {
    const { request } = parameters;
    const network = normalizeNetwork(request.network ?? 'mainnet');
    const mint = resolveStablecoinMint(request.currency, network);
    if (!mint) {
        throw new Error('payment-channel sessions require an SPL token currency');
    }

    const programAddress = address(parameters.programAddress ?? request.programId ?? PAYMENT_CHANNELS_PROGRAM);
    // Mirror the Rust client: the token program defaults from the challenge
    // currency (PYUSD/USDG/CASH are Token-2022 mints).
    const tokenProgram = address(parameters.tokenProgram ?? defaultTokenProgramForCurrency(request.currency, network));
    const payer = address(parameters.payer);
    const payee = address(request.recipient);
    const mintAddress = address(mint);
    const authorizedSigner = address(parameters.authorizedSigner);
    const deposit = parseU64(parameters.deposit ?? request.cap, 'deposit');
    const salt = parseU64(parameters.salt ?? randomU64(), 'salt');
    const gracePeriod = parameters.gracePeriod ?? DEFAULT_GRACE_PERIOD_SECONDS;
    const recipients =
        parameters.recipients?.map(split => ({ bps: split.bps, recipient: address(split.recipient) })) ??
        request.splits?.map(split => ({ bps: split.bps, recipient: address(split.recipient) })) ??
        [];

    const [channelId] = await findPaymentChannelPda({
        authorizedSigner,
        mint: mintAddress,
        payee,
        payer,
        programAddress,
        salt,
    });

    return {
        channelId,
        deposit,
        gracePeriod,
        mint,
        payee,
        payer,
        programAddress,
        recipients,
        salt,
        tokenProgram,
    };
}

async function findPaymentChannelPda(parameters: FindPaymentChannelPdaParameters) {
    return await getProgramDerivedAddress({
        programAddress: parameters.programAddress,
        seeds: [
            getUtf8Encoder().encode('channel'),
            getAddressEncoder().encode(parameters.payer),
            getAddressEncoder().encode(parameters.payee),
            getAddressEncoder().encode(parameters.mint),
            getAddressEncoder().encode(parameters.authorizedSigner),
            getU64Encoder().encode(parameters.salt),
        ],
    });
}

function parseU64(value: AmountLike, name: string): bigint {
    let parsed: bigint;
    if (typeof value === 'bigint') {
        parsed = value;
    } else if (typeof value === 'number') {
        if (!Number.isSafeInteger(value)) throw new Error(`${name} must be a safe integer`);
        parsed = BigInt(value);
    } else if (/^\d+$/.test(value)) {
        parsed = BigInt(value);
    } else {
        throw new Error(`${name} must be an unsigned integer`);
    }

    if (parsed < 0n || parsed > U64_MAX) {
        throw new Error(`${name} must fit in u64`);
    }
    return parsed;
}

function randomU64(): bigint {
    const bytes = new Uint8Array(8);
    globalThis.crypto.getRandomValues(bytes);
    return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getBigUint64(0, true);
}
