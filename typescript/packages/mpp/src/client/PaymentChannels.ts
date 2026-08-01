import {
    type Address,
    address,
    appendTransactionMessageInstructions,
    type Base64EncodedWireTransaction,
    type Blockhash,
    createNoopSigner,
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
    defaultTokenProgramForCurrency,
    normalizeNetwork,
    resolveStablecoinMint,
} from '../constants.js';
import { findEventAuthorityPda, getOpenInstruction } from '../generated/payment-channels/index.js';
import {
    ActiveSession,
    type AmountLike,
    DEFAULT_SESSION_EXPIRES_AT,
    resolveIdleTimeoutSeconds,
    resolveOpenBlockhash,
    resolveOpenSlot,
    type SessionRequest,
    type SessionSigner,
    signSessionAuthentication,
} from './Session.js';
import type { SessionOpener } from './SessionFetch.js';

const U64_MAX = (1n << 64n) - 1n;
const RENT_SYSVAR = 'SysvarRent111111111111111111111111111111111';
const DEFAULT_GRACE_PERIOD_SECONDS = 900;

/** Placeholder signature used while the operator still needs to broadcast the open transaction. */
/**
 * Payment-channel open fields shared by client-built and server-built open flows.
 */
export interface PaymentChannelOpen {
    readonly channelId: string;
    readonly deposit: string;
    readonly gracePeriod: number;
    readonly mint: string;
    readonly openSlot: string;
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
        openSlot: open.openSlot.toString(),
        payee: open.payee,
        payer: open.payer,
        salt: open.salt.toString(),
    };
}

/**
 * Builds the payer-signed payment-channel open transaction for a session.
 *
 * The transaction uses the operator from the session challenge as fee payer and
 * is intentionally left partially signed; the server adds the operator
 * signature before broadcasting it.
 */
export async function buildOpenPaymentChannelTransaction(
    parameters: buildOpenPaymentChannelTransaction.Parameters,
): Promise<PaymentChannelOpenTransaction> {
    const { request, signer } = parameters;
    // The open transaction is bound to the challenge: the blockhash comes
    // from the challenged `recentBlockhash` (an explicit override is for
    // tests and custom flows) and `openSlot` defaults to the challenged
    // `recentSlot` inside `preparePaymentChannelOpen` — the client never
    // fetches either on its own.
    const recentBlockhash = resolveOpenBlockhash(parameters.recentBlockhash, request);
    const open = await preparePaymentChannelOpen({
        ...parameters,
        payer: signer.address,
    });
    const programAddress = open.programAddress;
    const tokenProgram = open.tokenProgram;
    const payer = address(open.payer);
    const payee = address(open.payee);
    const mintAddress = address(open.mint);
    const authorizedSigner = address(parameters.authorizedSigner);
    const feePayer = address(
        request.methodDetails.feePayer
            ? requireString(request.methodDetails.feePayerKey, 'methodDetails.feePayerKey')
            : signer.address,
    );
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
                openSlot: open.openSlot,
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
    // Only the blockhash is compiled into the message; the challenge does not
    // carry a lastValidBlockHeight, so pin the lifetime with a sentinel — the
    // server broadcasts (and the program enforces freshness), not this client.
    const lifetime = { blockhash: recentBlockhash as Blockhash, lastValidBlockHeight: U64_MAX };

    const txMessage = pipe(
        createTransactionMessage({ version: 0 }),
        msg => setTransactionMessageFeePayer(feePayer, msg),
        msg => setTransactionMessageLifetimeUsingBlockhash(lifetime, msg),
        msg => appendTransactionMessageInstructions([instruction], msg),
    );
    const signedTx = await partiallySignTransactionMessageWithSigners(txMessage);

    return {
        channelId: open.channelId,
        deposit: open.deposit.toString(),
        gracePeriod: open.gracePeriod,
        mint: open.mint,
        openSlot: open.openSlot.toString(),
        payee: open.payee,
        payer: open.payer,
        salt: open.salt.toString(),
        transaction: getBase64EncodedWireTransaction(signedTx),
    };
}

/**
 * Creates a high-level payment-channel session opener.
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
        const voucherSigner = challenge.request.methodDetails.voucherSigner ?? 'client';
        const sessionSigner =
            voucherSigner === 'operator'
                ? parameters.signer
                : (parameters.sessionSigner ?? (await generateKeyPairSigner()));
        const authorizedSigner =
            voucherSigner === 'operator'
                ? requireString(challenge.request.methodDetails.operator, 'methodDetails.operator')
                : sessionSigner.address;
        const open = await buildOpenPaymentChannelTransaction({
            authorizedSigner,
            deposit: parameters.deposit,
            gracePeriod: parameters.gracePeriod,
            openSlot: parameters.openSlot,
            programAddress: parameters.programAddress,
            recentBlockhash: parameters.recentBlockhash,
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
        const authentication =
            voucherSigner === 'operator'
                ? await signSessionAuthentication({
                      challengeId: challenge.id,
                      channelId: open.channelId,
                      signer: parameters.signer,
                  })
                : undefined;

        return {
            payload: session.openPaymentChannelAction({
                ...(authentication ? { authentication } : {}),
                authorizedSigner,
                depositAmount: open.deposit,
                distributionSplits: challenge.request.methodDetails.distributionSplits,
                gracePeriodSeconds: open.gracePeriod,
                idleTimeoutSeconds: resolveIdleTimeoutSelection(challenge.request, parameters.idleTimeoutSeconds),
                mint: open.mint,
                openSlot: open.openSlot,
                payee: open.payee,
                payer: open.payer,
                salt: open.salt,
                transaction: open.transaction,
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
        /**
         * Slot used as a channel PDA seed. Defaults to the challenged
         * `methodDetails.recentSlot`; an override may be earlier than the
         * challenged slot, never later.
         */
        readonly openSlot?: AmountLike | undefined;
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
        /**
         * Slot used as a channel PDA seed. Defaults to the challenged
         * `methodDetails.recentSlot`; an override may be earlier than the
         * challenged slot, never later.
         */
        readonly openSlot?: AmountLike | undefined;
        readonly programAddress?: string | undefined;
        /**
         * Blockhash for the open transaction. Defaults to the challenged
         * `methodDetails.recentBlockhash`, which the server requires the
         * compiled message to use; an explicit override is for tests and
         * custom flows that re-issue their own challenge binding.
         */
        readonly recentBlockhash?: string | undefined;
        readonly recipients?: readonly { readonly bps: number; readonly recipient: string }[] | undefined;
        readonly request: SessionRequest;
        /** Unused: the open now derives its blockhash and slot from the challenge, never from RPC. */
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
        /** Selected inactivity threshold; must be one of the challenge's offered values. */
        readonly idleTimeoutSeconds?: number | undefined;
        /**
         * Slot used as a channel PDA seed. Defaults to the challenged
         * `methodDetails.recentSlot`; an override may be earlier than the
         * challenged slot, never later.
         */
        readonly openSlot?: AmountLike | undefined;
        readonly programAddress?: string | undefined;
        /** Blockhash override for the open transaction. Defaults to the challenged `recentBlockhash`. */
        readonly recentBlockhash?: string | undefined;
        readonly recipients?: readonly { readonly bps: number; readonly recipient: string }[] | undefined;
        /** Unused: the open now derives its blockhash and slot from the challenge, never from RPC. */
        readonly rpcUrl?: string | undefined;
        readonly salt?: AmountLike | undefined;
        readonly sessionSigner?: SessionSigner | undefined;
        readonly signature?: string | undefined;
        readonly signer: SessionSigner & TransactionSigner;
        readonly source?: string | undefined;
        readonly tokenProgram?: string | undefined;
    }
}

function resolveIdleTimeoutSelection(request: SessionRequest, selected?: number): number | undefined {
    const details = request.methodDetails;
    if (!details.idleTimeoutOptionsSeconds) return undefined;
    return resolveIdleTimeoutSeconds({
        defaultSeconds: details.idleTimeoutSeconds ?? 300,
        options: details.idleTimeoutOptionsSeconds,
        selected,
    });
}

interface PreparedPaymentChannelOpen {
    readonly channelId: string;
    readonly deposit: bigint;
    readonly gracePeriod: number;
    readonly mint: string;
    readonly openSlot: bigint;
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
    readonly openSlot: bigint;
    readonly payee: Address;
    readonly payer: Address;
    readonly programAddress: Address;
    readonly salt: bigint;
}

async function preparePaymentChannelOpen(
    parameters: derivePaymentChannelOpen.Parameters,
): Promise<PreparedPaymentChannelOpen> {
    const { request } = parameters;
    const network = normalizeNetwork(request.methodDetails.network);
    const mint = resolveStablecoinMint(request.currency, network);
    if (!mint) {
        throw new Error('payment-channel sessions require an SPL token currency');
    }

    const programAddress = address(parameters.programAddress ?? request.methodDetails.channelProgram);
    // Mirror the Rust client: the token program defaults from the challenge
    // currency (PYUSD/USDG/CASH are Token-2022 mints).
    const tokenProgram = address(parameters.tokenProgram ?? defaultTokenProgramForCurrency(request.currency, network));
    const payer = address(parameters.payer);
    const payee = address(request.recipient);
    const mintAddress = address(mint);
    const authorizedSigner = address(parameters.authorizedSigner);
    const deposit = parseU64(
        requireValue(parameters.deposit ?? request.suggestedDeposit ?? request.minimumDeposit, 'deposit'),
        'deposit',
    );
    const salt = parseU64(parameters.salt ?? randomU64(), 'salt');
    // The challenged `recentSlot` is the default `openSlot`; an explicit
    // override may only rewind (the server rejects an openSlot ahead of its
    // challenge). A new-channel challenge without `recentSlot` cannot derive
    // an open unless the caller supplies the slot explicitly.
    const openSlot = resolveOpenSlot({
        challengedRecentSlot: request.methodDetails.recentSlot,
        override: parameters.openSlot,
    });
    const gracePeriod =
        parameters.gracePeriod ?? request.methodDetails.gracePeriodSeconds ?? DEFAULT_GRACE_PERIOD_SECONDS;
    const recipients =
        parameters.recipients?.map(split => ({ bps: split.bps, recipient: address(split.recipient) })) ??
        request.methodDetails.distributionSplits?.map(split => ({
            bps: split.shareBps,
            recipient: address(split.recipient),
        })) ??
        [];

    const [channelId] = await findPaymentChannelPda({
        authorizedSigner,
        mint: mintAddress,
        openSlot,
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
        openSlot,
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
            getU64Encoder().encode(parameters.openSlot),
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

function requireString(value: string | undefined, name: string): string {
    if (!value) throw new Error(`${name} required`);
    return value;
}

function requireValue<Value>(value: Value | undefined, name: string): Value {
    if (value === undefined) throw new Error(`${name} required`);
    return value;
}

function randomU64(): bigint {
    const bytes = new Uint8Array(8);
    globalThis.crypto.getRandomValues(bytes);
    return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getBigUint64(0, true);
}
