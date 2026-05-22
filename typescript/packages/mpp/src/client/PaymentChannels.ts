import {
    AccountRole,
    type Address,
    address,
    appendTransactionMessageInstructions,
    type Base64EncodedWireTransaction,
    type Blockhash,
    createSolanaRpc,
    createTransactionMessage,
    generateKeyPairSigner,
    getAddressEncoder,
    getArrayEncoder,
    getBase64EncodedWireTransaction,
    getProgramDerivedAddress,
    getStructEncoder,
    getU8Encoder,
    getU16Encoder,
    getU32Encoder,
    getU64Encoder,
    getUtf8Encoder,
    type Instruction,
    type InstructionWithSigners,
    partiallySignTransactionMessageWithSigners,
    pipe,
    type ReadonlyUint8Array,
    setTransactionMessageFeePayer,
    setTransactionMessageLifetimeUsingBlockhash,
    type TransactionSigner,
} from '@solana/kit';
import { findAssociatedTokenPda } from '@solana-program/token';

import {
    ASSOCIATED_TOKEN_PROGRAM,
    DEFAULT_RPC_URLS,
    normalizeNetwork,
    resolveStablecoinMint,
    SYSTEM_PROGRAM,
    TOKEN_PROGRAM,
} from '../constants.js';
import {
    ActiveSession,
    type AmountLike,
    DEFAULT_SESSION_EXPIRES_AT,
    type SessionRequest,
    type SessionSigner,
} from './Session.js';
import type { SessionOpener } from './SessionFetch.js';

const U64_MAX = (1n << 64n) - 1n;
const PAYMENT_CHANNELS_PROGRAM = 'GuoKrzaBiZnW5DvJ3yZVE7xHqbcBvaX9SH6P6Cn9gNvc';
const RENT_SYSVAR = 'SysvarRent111111111111111111111111111111111';
const OPEN_DISCRIMINATOR = 1;
const DEFAULT_GRACE_PERIOD_SECONDS = 900;
const PENDING_SERVER_SIGNATURE = '1111111111111111111111111111111111111111111111111111111111111111';

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
    const [eventAuthority] = await findEventAuthorityPda(programAddress);

    const instruction = getOpenPaymentChannelInstruction({
        associatedTokenProgram: address(ASSOCIATED_TOKEN_PROGRAM),
        authorizedSigner,
        channel: address(open.channelId),
        channelTokenAccount,
        deposit: open.deposit,
        eventAuthority,
        gracePeriod: open.gracePeriod,
        mint: mintAddress,
        payee,
        payer: signer,
        payerTokenAccount,
        programAddress,
        recipients: open.recipients,
        rent: address(RENT_SYSVAR),
        salt: open.salt,
        selfProgram: programAddress,
        tokenProgram,
    });
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

interface OpenPaymentChannelInstructionParameters {
    readonly associatedTokenProgram: Address;
    readonly authorizedSigner: Address;
    readonly channel: Address;
    readonly channelTokenAccount: Address;
    readonly deposit: bigint;
    readonly eventAuthority: Address;
    readonly gracePeriod: number;
    readonly mint: Address;
    readonly payee: Address;
    readonly payer: TransactionSigner;
    readonly payerTokenAccount: Address;
    readonly programAddress: Address;
    readonly recipients: readonly { readonly bps: number; readonly recipient: Address }[];
    readonly rent: Address;
    readonly salt: bigint;
    readonly selfProgram: Address;
    readonly tokenProgram: Address;
}

type OpenPaymentChannelInstruction = InstructionWithSigners & Omit<Instruction, 'accounts'>;

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
    const tokenProgram = address(parameters.tokenProgram ?? TOKEN_PROGRAM);
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

async function findEventAuthorityPda(programAddress: Address) {
    return await getProgramDerivedAddress({
        programAddress,
        seeds: [getUtf8Encoder().encode('event_authority')],
    });
}

function getOpenPaymentChannelInstruction(
    parameters: OpenPaymentChannelInstructionParameters,
): OpenPaymentChannelInstruction {
    return {
        accounts: [
            {
                address: parameters.payer.address,
                role: AccountRole.WRITABLE_SIGNER,
                signer: parameters.payer,
            },
            { address: parameters.payee, role: AccountRole.READONLY },
            { address: parameters.mint, role: AccountRole.READONLY },
            { address: parameters.authorizedSigner, role: AccountRole.READONLY },
            { address: parameters.channel, role: AccountRole.WRITABLE },
            { address: parameters.payerTokenAccount, role: AccountRole.WRITABLE },
            { address: parameters.channelTokenAccount, role: AccountRole.WRITABLE },
            { address: parameters.tokenProgram, role: AccountRole.READONLY },
            { address: address(SYSTEM_PROGRAM), role: AccountRole.READONLY },
            { address: parameters.rent, role: AccountRole.READONLY },
            { address: parameters.associatedTokenProgram, role: AccountRole.READONLY },
            { address: parameters.eventAuthority, role: AccountRole.READONLY },
            { address: parameters.selfProgram, role: AccountRole.READONLY },
        ],
        data: getOpenInstructionData(parameters),
        programAddress: parameters.programAddress,
    };
}

function getOpenInstructionData(parameters: OpenPaymentChannelInstructionParameters): ReadonlyUint8Array {
    return getStructEncoder([
        ['discriminator', getU8Encoder()],
        [
            'openArgs',
            getStructEncoder([
                ['salt', getU64Encoder()],
                ['deposit', getU64Encoder()],
                ['gracePeriod', getU32Encoder()],
                [
                    'recipients',
                    getArrayEncoder(
                        getStructEncoder([
                            ['recipient', getAddressEncoder()],
                            ['bps', getU16Encoder()],
                        ]),
                    ),
                ],
            ]),
        ],
    ]).encode({
        discriminator: OPEN_DISCRIMINATOR,
        openArgs: {
            deposit: parameters.deposit,
            gracePeriod: parameters.gracePeriod,
            recipients: [...parameters.recipients],
            salt: parameters.salt,
        },
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
