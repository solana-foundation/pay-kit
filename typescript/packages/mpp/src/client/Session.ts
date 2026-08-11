import {
    type Address,
    createSignableMessage,
    getBase58Decoder,
    getBase58Encoder,
    getPublicKeyFromAddress,
    type MessagePartialSigner,
    verifySignature,
} from '@solana/kit';
import type { Challenge as MppxChallenge, Receipt as MppxReceipt } from 'mppx';
import { Credential, Method, z } from 'mppx';

import * as Methods from '../Methods.js';
import { encodeVoucherMessageLoose } from '../shared/voucher.js';

const U64_MAX = (1n << 64n) - 1n;

/**
 * Default voucher expiry timestamp, matching the Rust SDK and program tests.
 */
export const DEFAULT_SESSION_EXPIRES_AT = 4_102_444_800;
export const MAX_IDLE_TIMEOUT_SECONDS = 2_592_000;
export const SESSION_AUTHENTICATION_DOMAIN = 'mpp-session-auth-v1';

/**
 * Numeric input accepted by the session helpers.
 */
export type AmountLike = bigint | number | string;

/** Party that signs cumulative vouchers. */
export type SessionVoucherSigner = 'client' | 'operator';

/** Receipt extension required by the Solana session intent. */
export interface SessionReceipt extends MppxReceipt.Receipt {
    readonly acceptedCumulative: string;
    readonly challengeId?: string | undefined;
    readonly idleTimeoutSeconds: number;
    readonly intent: 'session';
    readonly refunded?: string | undefined;
    readonly spent: string;
    readonly txHash?: string | undefined;
}

/** Reusable payer proof for an operator-signed channel. */
export interface SessionAuthentication {
    readonly challengeId: string;
    readonly payer: string;
    readonly signature: string;
    readonly type: 'proof';
}

/**
 * Signer capable of Ed25519-signing exact voucher message bytes.
 */
export type SessionSigner = MessagePartialSigner;

/**
 * Basis-point split distributed when a session settles.
 */
export interface SessionSplit {
    /** Base58 address receiving this share. */
    readonly recipient: string;
    /** Share of the settled amount, in basis points (100 = 1%). */
    readonly shareBps: number;
}

/** Solana-specific method details carried by a session challenge. */
export interface SessionMethodDetails {
    readonly channelId?: string | undefined;
    readonly channelProgram: string;
    readonly decimals?: number | undefined;
    readonly distributionSplits?: SessionSplit[] | undefined;
    readonly feePayer?: boolean | undefined;
    readonly feePayerKey?: string | undefined;
    readonly gracePeriodSeconds?: number | undefined;
    readonly idleTimeoutOptionsSeconds?: number[] | undefined;
    readonly idleTimeoutSeconds?: number | undefined;
    readonly minVoucherDelta?: string | undefined;
    readonly network: string;
    readonly operator?: string | undefined;
    /**
     * Base58 blockhash the client MUST use as the open transaction's recent
     * blockhash. Conditionally REQUIRED when `channelId` is absent (new
     * channel); MUST be absent when resuming an existing channel.
     */
    readonly recentBlockhash?: string | undefined;
    /**
     * RPC context slot from the same `getLatestBlockhash` response as
     * `recentBlockhash` — the client's default `openSlot`. A u64 decimal
     * string on the wire; same conditionality as `recentBlockhash`.
     */
    readonly recentSlot?: string | undefined;
    readonly tokenProgram?: string | undefined;
    readonly ttlSeconds?: number | undefined;
    readonly voucherSigner?: SessionVoucherSigner | undefined;
}

/**
 * Request embedded in a Solana `session` challenge.
 */
export interface SessionRequest extends Record<string, unknown> {
    /** Price per unit of service, in base units. */
    readonly amount: string;
    /** Currency identifier: a symbol like `'USDC'` or an SPL mint address. */
    readonly currency: string;
    /** Human-readable description of what the session pays for. */
    readonly description?: string | undefined;
    /** Merchant correlation id echoed in receipts. */
    readonly externalId?: string | undefined;
    /** Solana-specific channel policy. */
    readonly methodDetails: SessionMethodDetails;
    /** Hard floor for the initial deposit. */
    readonly minimumDeposit?: string | undefined;
    /** Primary recipient of the settled amount (base58). */
    readonly recipient: string;
    /** Suggested initial deposit. */
    readonly suggestedDeposit?: string | undefined;
    /** Unit priced by `amount`. */
    readonly unitType?: string | undefined;
}

/**
 * Parsed MPP challenge for the Solana session method.
 */
export type SessionChallenge = MppxChallenge.Challenge<SessionRequest, 'session', 'solana'>;

/**
 * Voucher content signed by the client session key.
 */
export interface VoucherData {
    /** Channel / session id the voucher is bound to (base58). */
    readonly channelId: string;
    /** Cumulative amount authorized so far, in base units. */
    readonly cumulativeAmount: string;
    /** Unix timestamp (seconds) at which the voucher expires; omitted means no expiry. */
    readonly expiresAt?: number | undefined;
}

/**
 * Voucher-like input accepted by low-level serialization helpers.
 */
export interface VoucherDataInput {
    /** Channel / session id the voucher is bound to (base58). */
    readonly channelId: string;
    /** Cumulative amount authorized so far, in base units. */
    readonly cumulativeAmount: AmountLike;
    /** Unix timestamp (seconds) at which the voucher expires. */
    readonly expiresAt: AmountLike;
}

/**
 * Signed cumulative voucher.
 */
export interface SignedVoucher {
    /** Base58 Ed25519 signature over the canonical voucher bytes. */
    readonly signature: string;
    /** Voucher signature algorithm. */
    readonly signatureType: 'ed25519';
    /** Base58 public key that signed the voucher. */
    readonly signer: string;
    /**
     * The signed voucher fields, carried on the wire as `voucher` per the
     * spec's Signed Voucher table (mpp-specs e702dd8).
     */
    readonly voucher: VoucherData;
}

/**
 * Open action payload for a payment channel.
 */
export interface OpenPayload {
    /** Reusable payer proof required for operator-signed vouchers. */
    readonly authentication?: SessionAuthentication | undefined;
    /** Opaque server-scoped authorization policy echoed on the wire. */
    readonly authorizationPolicy?: Record<string, unknown> | undefined;
    /** Public key authorized to sign vouchers for this session (base58). */
    readonly authorizedSigner: string;
    /** Opaque capability map echoed on the wire. */
    readonly capabilities?: Record<string, unknown> | undefined;
    /** Channel address, base58. */
    readonly channelId: string;
    /** Deposit locked in the payment channel, in base units. */
    readonly depositAmount: string;
    /** Distribution split preimage bound by the open instruction. */
    readonly distributionSplits?: readonly SessionSplit[] | undefined;
    /** Close grace period in seconds. */
    readonly gracePeriodSeconds: number;
    /** Negotiated inactivity threshold in seconds. */
    readonly idleTimeoutSeconds?: number | undefined;
    /** SPL mint of the funding asset (base58). */
    readonly mint: string;
    /** Slot the open was built against; the channel `openSlot` PDA seed. */
    readonly openSlot: string;
    /** Channel payee (base58). */
    readonly payee: string;
    /** Channel payer (base58). */
    readonly payer: string;
    /** Channel-derivation salt (decimal string). */
    readonly salt: string;
    /** Base64 signed or partially signed open transaction. */
    readonly transaction: string;
}

/**
 * Client action sent as a Solana session credential payload.
 */
export type SessionAction =
    | {
          readonly action: 'close';
          readonly authentication?: SessionAuthentication | undefined;
          readonly channelId: string;
          readonly voucher?: SignedVoucher | undefined;
      }
    | {
          readonly action: 'topUp';
          readonly additionalAmount: string;
          readonly channelId: string;
          readonly transaction: string;
      }
    | { readonly action: 'use'; readonly authentication: SessionAuthentication; readonly channelId: string }
    | { readonly action: 'voucher'; readonly channelId: string; readonly voucher: SignedVoucher }
    | (OpenPayload & { readonly action: 'open' });

/**
 * Payload body posted to a commit endpoint by the consumer helpers.
 */
export interface CommitPayload {
    /** Delivery being committed. */
    readonly deliveryId: string;
    /** Signed cumulative voucher covering the delivery. */
    readonly voucher: SignedVoucher;
}

/**
 * Server-issued metering directive attached to a delivered message.
 */
export interface MeteringDirective {
    /** Price of this delivery, in base units. */
    readonly amount: string;
    /** Endpoint the commit should be POSTed to. Falls back to the transport default. */
    readonly commitUrl?: string | undefined;
    /** Currency identifier the amount is denominated in. */
    readonly currency: string;
    /** Unique id of the reserved delivery. */
    readonly deliveryId: string;
    /** Unix timestamp (seconds) after which the reservation lapses. */
    readonly expiresAt: number;
    /** Opaque server token echoed back on commit. Clients must not modify it. */
    readonly proof?: string | undefined;
    /** Server-side delivery sequence number, monotonic per session. */
    readonly sequence: number;
    /** Session / channel the delivery is billed against. */
    readonly sessionId: string;
}

/**
 * Final usage for a metered stream.
 */
export interface MeteringUsage {
    /** Total metered amount, in base units. */
    readonly amount: string;
    /** Delivery the usage belongs to. */
    readonly deliveryId: string;
}

/**
 * Payload paired with the directive needed to acknowledge it.
 */
export interface MeteredEnvelope<Payload> {
    /** Directive to commit once the payload is processed. */
    readonly metering: MeteringDirective;
    /** The delivered application payload. */
    readonly payload: Payload;
}

/**
 * Commit status returned by the server.
 */
export type CommitStatus = 'committed' | 'replayed';

/**
 * Receipt returned after a commit is accepted.
 */
export interface CommitReceipt {
    /** Amount this commit added, in base units. */
    readonly amount: string;
    /** Session cumulative after the commit, in base units. */
    readonly cumulative: string;
    /** Delivery the commit settled. */
    readonly deliveryId: string;
    /** Session / channel the commit was applied to. */
    readonly sessionId: string;
    /** `committed` on first acceptance, `replayed` on idempotent retries. */
    readonly status: CommitStatus;
}

/**
 * Context accepted by the `session()` MPP client method.
 */
export interface SessionContext {
    /** Session action to perform. */
    readonly action?: 'close' | 'open' | 'topUp' | 'use' | 'voucher' | undefined;
    /** Top-up amount to add, in base units. */
    readonly additionalAmount?: AmountLike | undefined;
    /** Incremental amount for `voucher` / `commit`, in base units. */
    readonly amount?: AmountLike | undefined;
    /** Reusable payer proof for operator-mode use and close. */
    readonly authentication?: SessionAuthentication | undefined;
    /** Absolute cumulative amount for `voucher`, in base units. */
    readonly cumulativeAmount?: AmountLike | undefined;
    /** Delivery to commit. Defaults to `directive.deliveryId`. */
    readonly deliveryId?: string | undefined;
    /** Initial channel deposit, in base units. */
    readonly depositAmount?: AmountLike | undefined;
    /** Metering directive being committed. */
    readonly directive?: MeteringDirective | undefined;
    /** Close: last unsettled increment to sign into the closing voucher, in base units. */
    readonly finalIncrement?: AmountLike | undefined;
    /** Channel close grace period in seconds. */
    readonly gracePeriodSeconds?: number | undefined;
    /** Selected inactivity threshold; must be one of the challenge's offered values. */
    readonly idleTimeoutSeconds?: number | undefined;
    /** SPL mint of the deposit (base58). */
    readonly mint?: string | undefined;
    /** Slot the open is built against (a channel PDA seed). */
    readonly openSlot?: AmountLike | undefined;
    /** Channel payee (base58). */
    readonly payee?: string | undefined;
    /** Channel payer (base58). */
    readonly payer?: string | undefined;
    /** Channel-derivation salt. */
    readonly salt?: AmountLike | undefined;
    /** Active session to act on, overriding the method-level session. */
    readonly session?: ActiveSession | undefined;
    /** Optional client identifier serialized into the credential. */
    readonly source?: string | undefined;
    /** Base64 signed or partially signed transaction. */
    readonly transaction?: string | undefined;
    /** Pre-signed voucher for `voucher` / `close`, bypassing local signing. */
    readonly voucher?: SignedVoucher | undefined;
}

/**
 * Runtime context schema for mppx routing. Detailed validation happens in the SDK helper.
 */
export const sessionContextSchema = z.custom<SessionContext>();

/** Validates the idle-timeout option list defined by the session draft. */
export function validateIdleTimeoutOptions(options: readonly number[]): void {
    if (options.length === 0) throw new Error('idleTimeoutOptionsSeconds must not be empty');
    let previous = 0;
    for (const value of options) {
        if (!Number.isInteger(value) || value < 1 || value > MAX_IDLE_TIMEOUT_SECONDS) {
            throw new Error(`idle timeout must be an integer between 1 and ${MAX_IDLE_TIMEOUT_SECONDS}`);
        }
        if (value <= previous) throw new Error('idleTimeoutOptionsSeconds must be strictly increasing');
        previous = value;
    }
}

/** Resolves an effective timeout while rejecting unsupported client selections. */
export function resolveIdleTimeoutSeconds(parameters: {
    readonly defaultSeconds: number;
    readonly options?: readonly number[] | undefined;
    readonly selected?: number | undefined;
}): number {
    const { defaultSeconds, options, selected } = parameters;
    if (!Number.isInteger(defaultSeconds) || defaultSeconds < 1 || defaultSeconds > MAX_IDLE_TIMEOUT_SECONDS) {
        throw new Error(`default idle timeout must be between 1 and ${MAX_IDLE_TIMEOUT_SECONDS}`);
    }
    if (options) validateIdleTimeoutOptions(options);
    if (selected !== undefined) {
        if (!options) throw new Error('idleTimeoutSeconds is not allowed when no options were advertised');
        if (!options.includes(selected)) throw new Error('idleTimeoutSeconds was not one of the advertised options');
        return selected;
    }
    return options && !options.includes(defaultSeconds)
        ? requireValue(options[0], 'idle timeout option')
        : defaultSeconds;
}

/**
 * Resolves the open transaction's `openSlot` against the challenged
 * `recentSlot`.
 *
 * An explicit override is allowed — but never later than the challenged
 * `recentSlot` (an earlier slot is fine; the channel PDA derives from it and
 * the server rejects anything ahead of its challenge). Without an override the
 * challenged `recentSlot` is REQUIRED: a new-channel challenge must provide
 * it, and the client never fetches a slot of its own.
 *
 * Mirrors the `open_slot` resolution in `rust/crates/kit/src/mpp/client/session.rs`.
 */
export function resolveOpenSlot(parameters: {
    readonly challengedRecentSlot?: string | undefined;
    readonly override?: AmountLike | undefined;
}): bigint {
    const { challengedRecentSlot, override } = parameters;
    if (override !== undefined) {
        const openSlot = parseAmount(override, 'openSlot');
        if (challengedRecentSlot !== undefined) {
            const recentSlot = parseAmount(challengedRecentSlot, 'methodDetails.recentSlot');
            if (openSlot > recentSlot) {
                throw new Error(
                    `openSlot override ${openSlot.toString()} is ahead of the challenged recentSlot ${recentSlot.toString()}`,
                );
            }
        }
        return openSlot;
    }
    if (challengedRecentSlot === undefined) {
        throw new Error('session challenge is missing recentSlot; a new-channel challenge must provide it');
    }
    return parseAmount(challengedRecentSlot, 'methodDetails.recentSlot');
}

/**
 * Resolves the open transaction's blockhash: an explicit override wins,
 * otherwise the challenged `recentBlockhash` is REQUIRED — the server verifies
 * the compiled open message uses exactly this blockhash, so the client never
 * fetches its own.
 *
 * Mirrors `resolve_open_blockhash` in `rust/crates/kit/src/mpp/client/session.rs`.
 */
export function resolveOpenBlockhash(override: string | undefined, request: SessionRequest): string {
    if (override) return override;
    const challenged = request.methodDetails.recentBlockhash;
    if (!challenged) {
        throw new Error('session challenge is missing recentBlockhash; a new-channel challenge must provide it');
    }
    return challenged;
}

/** Canonical JCS bytes signed by a reusable operator-mode proof. */
export function sessionAuthenticationMessage(parameters: {
    readonly challengeId: string;
    readonly channelId: string;
    readonly payer: string;
}): Uint8Array {
    return new TextEncoder().encode(
        JSON.stringify({
            channelId: parameters.channelId,
            domain: SESSION_AUTHENTICATION_DOMAIN,
            payer: parameters.payer,
            sessionChallengeId: parameters.challengeId,
        }),
    );
}

/** Creates a reusable payer proof for an operator-signed channel. */
export async function signSessionAuthentication(parameters: {
    readonly challengeId: string;
    readonly channelId: string;
    readonly signer: MessagePartialSigner;
}): Promise<SessionAuthentication> {
    const message = sessionAuthenticationMessage({
        challengeId: parameters.challengeId,
        channelId: parameters.channelId,
        payer: parameters.signer.address,
    });
    const [signatures] = await parameters.signer.signMessages([createSignableMessage(message)]);
    const signature = signatures?.[parameters.signer.address];
    if (!signature) throw new Error(`Signer ${parameters.signer.address} did not return a session proof`);
    return {
        challengeId: parameters.challengeId,
        payer: parameters.signer.address,
        signature: getBase58Decoder().decode(new Uint8Array(signature)),
        type: 'proof',
    };
}

/** Verifies a reusable payer proof against its bound channel. */
export async function verifySessionAuthentication(
    authentication: SessionAuthentication,
    channelId: string,
): Promise<boolean> {
    try {
        const publicKey = await getPublicKeyFromAddress(authentication.payer as Address);
        const signature = getBase58Encoder().encode(authentication.signature);
        return await verifySignature(
            publicKey,
            signature as Parameters<typeof verifySignature>[1],
            sessionAuthenticationMessage({
                challengeId: authentication.challengeId,
                channelId,
                payer: authentication.payer,
            }),
        );
    } catch {
        return false;
    }
}

/**
 * Builds canonical payment-channel voucher bytes:
 * `magic (0x56, 0x01) || channel_id || cumulative_amount_le_u64 || expires_at_le_i64`.
 *
 * Delegates to the shared encoder so client and server agree on the bytes
 * they sign / verify.
 */
export function voucherMessageBytes(data: VoucherDataInput): Uint8Array {
    return encodeVoucherMessageLoose(data);
}

/**
 * Serializes a Solana session action as an MPP `Authorization` header value.
 */
export function serializeSessionCredential(parameters: serializeSessionCredential.Parameters): string {
    return Credential.serialize({
        challenge: parameters.challenge,
        payload: parameters.payload,
        ...(parameters.source ? { source: parameters.source } : {}),
    });
}

export declare namespace serializeSessionCredential {
    interface Parameters {
        /** Challenge the credential answers (echoed for stateless verification). */
        readonly challenge: SessionChallenge;
        /** Session action to authorize. */
        readonly payload: SessionAction;
        /** Optional client identifier serialized into the credential. */
        readonly source?: string | undefined;
    }
}

/**
 * Tracks local voucher state for an open Solana payment session.
 */
export class ActiveSession {
    readonly #channelId: string;
    #cumulative: bigint;
    #expiresAt: number;
    readonly #signer: SessionSigner;

    constructor(channelId: string, signer: SessionSigner, options?: ActiveSession.Options);
    constructor(parameters: ActiveSession.Parameters);
    constructor(
        channelIdOrParameters: ActiveSession.Parameters | string,
        signer?: SessionSigner,
        options: ActiveSession.Options = {},
    ) {
        const parameters =
            typeof channelIdOrParameters === 'string'
                ? {
                      channelId: channelIdOrParameters,
                      signer: requireValue(signer, 'signer'),
                      ...options,
                  }
                : channelIdOrParameters;

        this.#channelId = parameters.channelId;
        this.#signer = parameters.signer;
        this.#cumulative = parseAmount(parameters.cumulative ?? 0n, 'cumulative');
        this.#expiresAt = parseSafeInteger(parameters.expiresAt ?? DEFAULT_SESSION_EXPIRES_AT, 'expiresAt');
    }

    /** Channel/session identifier used by all vouchers. */
    get channelId(): string {
        return this.#channelId;
    }

    /** Current local cumulative watermark. */
    get cumulative(): bigint {
        return this.#cumulative;
    }

    /** Current local cumulative watermark as a decimal string. */
    get cumulativeAmount(): string {
        return this.#cumulative.toString();
    }

    /** Expiry timestamp used for newly signed vouchers. */
    get expiresAt(): number {
        return this.#expiresAt;
    }

    /** Session key authorized to sign vouchers. */
    get signer(): SessionSigner {
        return this.#signer;
    }

    /** Public key authorized to sign vouchers. */
    get authorizedSigner(): string {
        return this.#signer.address;
    }

    /** Updates the expiry timestamp used for subsequent vouchers. */
    setExpiresAt(expiresAt: AmountLike): void {
        this.#expiresAt = parseSafeInteger(expiresAt, 'expiresAt');
    }

    /**
     * Signs an absolute cumulative voucher without advancing local state.
     */
    async prepareVoucher(cumulative: AmountLike): Promise<SignedVoucher> {
        const nextCumulative = parseAmount(cumulative, 'cumulative');
        if (nextCumulative <= this.#cumulative) {
            throw new Error(
                `Voucher cumulative ${nextCumulative.toString()} must exceed current watermark ${this.#cumulative.toString()}`,
            );
        }

        const data: VoucherData = {
            channelId: this.#channelId,
            cumulativeAmount: nextCumulative.toString(),
            expiresAt: this.#expiresAt,
        };

        const [signatureDictionary] = await this.#signer.signMessages([
            createSignableMessage(voucherMessageBytes({ ...data, expiresAt: data.expiresAt ?? 0 })),
        ]);
        const signatureBytes = signatureDictionary?.[this.#signer.address];
        if (!signatureBytes) {
            throw new Error(`Signer ${this.#signer.address} did not return a voucher signature`);
        }

        return {
            signature: getBase58Decoder().decode(new Uint8Array(signatureBytes)),
            signatureType: 'ed25519',
            signer: this.#signer.address,
            voucher: data,
        };
    }

    /**
     * Signs an increment from the current watermark without advancing local state.
     */
    async prepareIncrement(amount: AmountLike): Promise<SignedVoucher> {
        return await this.prepareVoucher(this.#cumulative + parseAmount(amount, 'amount'));
    }

    /**
     * Records a prepared voucher as accepted by the server.
     */
    recordVoucher(voucher: SignedVoucher): void {
        if (voucher.voucher.channelId !== this.#channelId) {
            throw new Error(
                `Voucher channel ${voucher.voucher.channelId} does not match active session ${this.#channelId}`,
            );
        }

        const cumulative = parseAmount(voucher.voucher.cumulativeAmount, 'cumulativeAmount');
        if (cumulative <= this.#cumulative) {
            throw new Error(
                `Voucher cumulative ${cumulative.toString()} must exceed current watermark ${this.#cumulative.toString()}`,
            );
        }

        this.#cumulative = cumulative;
    }

    /**
     * Signs an absolute cumulative voucher and advances local state.
     */
    async signVoucher(cumulative: AmountLike): Promise<SignedVoucher> {
        const voucher = await this.prepareVoucher(cumulative);
        this.recordVoucher(voucher);
        return voucher;
    }

    /**
     * Signs an increment from the current watermark and advances local state.
     */
    async signIncrement(amount: AmountLike): Promise<SignedVoucher> {
        return await this.signVoucher(this.#cumulative + parseAmount(amount, 'amount'));
    }

    /**
     * Builds a `voucher` action for a freshly signed increment.
     */
    async voucherAction(amount: AmountLike): Promise<SessionAction> {
        const voucher = await this.signIncrement(amount);
        return { action: 'voucher', channelId: voucher.voucher.channelId, voucher };
    }

    /**
     * Builds a `commit` action for a delivery and freshly signed increment.
     */
    async commitAction(delivery: MeteringDirective | string, amount?: AmountLike): Promise<CommitPayload> {
        const deliveryId = typeof delivery === 'string' ? delivery : delivery.deliveryId;
        const resolvedAmount =
            typeof delivery === 'string' ? requireValue(amount, 'amount') : (amount ?? delivery.amount);
        return { deliveryId, voucher: await this.signIncrement(resolvedAmount) };
    }

    /**
     * Builds a detailed payment-channel `open` action.
     */
    openPaymentChannelAction(
        parameters: ActiveSession.PaymentChannelOpenParameters,
    ): OpenPayload & { readonly action: 'open' } {
        return {
            action: 'open',
            authorizedSigner: parameters.authorizedSigner ?? this.authorizedSigner,
            channelId: this.#channelId,
            depositAmount: formatAmount(parameters.depositAmount, 'depositAmount'),
            ...(parameters.distributionSplits ? { distributionSplits: parameters.distributionSplits } : {}),
            gracePeriodSeconds: parameters.gracePeriodSeconds,
            mint: parameters.mint,
            openSlot: formatAmount(parameters.openSlot, 'openSlot'),
            payee: parameters.payee,
            payer: parameters.payer,
            salt: formatAmount(parameters.salt, 'salt'),
            transaction: parameters.transaction,
            ...(parameters.authentication ? { authentication: parameters.authentication } : {}),
            ...(parameters.idleTimeoutSeconds !== undefined
                ? { idleTimeoutSeconds: parameters.idleTimeoutSeconds }
                : {}),
        };
    }

    /**
     * Builds a `topUp` action after the top-up transaction is confirmed.
     */
    topUpAction(additionalAmount: AmountLike, transaction: string): SessionAction {
        return {
            action: 'topUp',
            additionalAmount: formatAmount(additionalAmount, 'additionalAmount'),
            channelId: this.#channelId,
            transaction,
        };
    }

    /** Builds a billable request action for an operator-signed session. */
    useAction(authentication: SessionAuthentication): SessionAction {
        return { action: 'use', authentication, channelId: this.#channelId };
    }

    /**
     * Builds a cooperative `close` action, optionally signing a final increment.
     */
    async closeAction(finalIncrement?: AmountLike, authentication?: SessionAuthentication): Promise<SessionAction> {
        if (authentication) {
            return { action: 'close', authentication, channelId: this.#channelId };
        }
        if (finalIncrement === undefined || parseAmount(finalIncrement, 'finalIncrement') === 0n) {
            throw new Error('client-mode close requires a voucher');
        }

        return {
            action: 'close',
            channelId: this.#channelId,
            voucher: await this.signIncrement(finalIncrement),
        };
    }
}

export declare namespace ActiveSession {
    interface Options {
        /** Cumulative already authorized when resuming a session, in base units. Defaults to 0. */
        readonly cumulative?: AmountLike | undefined;
        /** Voucher expiry as a unix timestamp (seconds). Defaults to {@link DEFAULT_SESSION_EXPIRES_AT}. */
        readonly expiresAt?: AmountLike | undefined;
    }

    interface Parameters extends Options {
        /** Channel address, base58. */
        readonly channelId: string;
        /** Key that signs vouchers for this session. */
        readonly signer: SessionSigner;
    }

    interface PaymentChannelOpenParameters {
        /** Reusable payer proof for an operator-signed session. */
        readonly authentication?: SessionAuthentication | undefined;
        /** Authorized voucher signer; operator sessions use the advertised operator. */
        readonly authorizedSigner?: string | undefined;
        /** Deposit locked in the channel, in base units. */
        readonly depositAmount: AmountLike;
        /** Distribution split preimage bound by the open transaction. */
        readonly distributionSplits?: readonly SessionSplit[] | undefined;
        /** Close grace period in seconds. */
        readonly gracePeriodSeconds: number;
        /** Selected inactivity threshold from the challenge's offered values. */
        readonly idleTimeoutSeconds?: number | undefined;
        /** SPL mint of the deposit (base58). */
        readonly mint: string;
        /** Slot the open transaction was built against (a channel PDA seed). */
        readonly openSlot: AmountLike;
        /** Channel payee (base58). */
        readonly payee: string;
        /** Channel payer (base58). */
        readonly payer: string;
        /** Channel-derivation salt. */
        readonly salt: AmountLike;
        /** Base64 signed or partially signed open transaction. */
        readonly transaction: string;
    }
}

/**
 * Creates the Solana `session` MPP client method.
 */
export function session(parameters: session.Parameters = {}) {
    let activeSession =
        parameters.session ??
        (parameters.channelId && parameters.signer
            ? new ActiveSession({
                  channelId: parameters.channelId,
                  expiresAt: parameters.expiresAt,
                  signer: parameters.signer,
              })
            : undefined);

    const getSession = (context: SessionContext | undefined): ActiveSession => {
        activeSession = context?.session ?? activeSession;
        if (!activeSession) {
            throw new Error('session action requires an ActiveSession or both `channelId` and `signer` parameters');
        }
        return activeSession;
    };

    const createAction = async (
        challenge: SessionChallenge,
        context: SessionContext | undefined,
    ): Promise<SessionAction> => {
        if (!context?.action && parameters.createAction) {
            return await parameters.createAction({ challenge, context, session: activeSession });
        }

        switch (context?.action) {
            case 'open':
                return await createOpenAction(getSession(context), challenge, context, parameters);
            case 'voucher':
                return await createVoucherAction(getSession(context), context);
            case 'topUp':
                return getSession(context).topUpAction(
                    requireValue(context.additionalAmount, 'additionalAmount'),
                    requireString(context.transaction, 'transaction'),
                );
            case 'use':
                return getSession(context).useAction(
                    requireValue(context.authentication ?? parameters.authentication, 'authentication'),
                );
            case 'close':
                return await getSession(context).closeAction(
                    context.finalIncrement ?? context.amount,
                    context.authentication ?? parameters.authentication,
                );
            case undefined:
                throw new Error(
                    'No session action provided. Pass context.action or configure session({ createAction }).',
                );
        }
    };

    return Method.toClient(Methods.session, {
        context: sessionContextSchema,
        async createCredential({ challenge, context }) {
            const payload = await createAction(challenge, context);
            return serializeSessionCredential({
                challenge,
                payload,
                source: context?.source ?? parameters.source,
            });
        },
    });
}

export declare namespace session {
    interface CreateActionParameters {
        /** Challenge being answered. */
        readonly challenge: SessionChallenge;
        /** Per-request context passed to the method handler. */
        readonly context?: SessionContext | undefined;
        /** Active session, when one has already been opened. */
        readonly session?: ActiveSession | undefined;
    }

    interface Parameters {
        /** Reusable proof for an already-open operator-signed channel. */
        readonly authentication?: SessionAuthentication | undefined;
        /** Channel id to resume. Requires `signer`; ignored when `session` is given. */
        readonly channelId?: string | undefined;
        /** Override that builds the session action for each challenge (custom wallet flows). */
        readonly createAction?:
            | ((parameters: CreateActionParameters) => Promise<SessionAction> | SessionAction)
            | undefined;
        /** Voucher expiry for a resumed session, unix seconds. */
        readonly expiresAt?: AmountLike | undefined;
        /** Existing session to drive instead of creating one. */
        readonly session?: ActiveSession | undefined;
        /** Voucher signer for a resumed session. */
        readonly signer?: SessionSigner | undefined;
        /** Optional client identifier serialized into credentials. */
        readonly source?: string | undefined;
    }
}

async function createOpenAction(
    session_: ActiveSession,
    challenge: SessionChallenge,
    context: SessionContext,
    parameters: session.Parameters,
): Promise<SessionAction> {
    const details = challenge.request.methodDetails;
    const voucherSigner = details.voucherSigner ?? 'client';
    const payer = requireString(context.payer, 'payer');
    let authentication = context.authentication ?? parameters.authentication;
    if (voucherSigner === 'operator' && !authentication) {
        if (session_.signer.address !== payer) {
            throw new Error('operator-mode open requires the payer signer to create authentication');
        }
        authentication = await signSessionAuthentication({
            challengeId: challenge.id,
            channelId: session_.channelId,
            signer: session_.signer,
        });
    }

    return session_.openPaymentChannelAction({
        ...(authentication ? { authentication } : {}),
        authorizedSigner:
            voucherSigner === 'operator'
                ? requireString(details.operator, 'methodDetails.operator')
                : session_.authorizedSigner,
        depositAmount: requireValue(context.depositAmount ?? challenge.request.suggestedDeposit, 'depositAmount'),
        distributionSplits: details.distributionSplits,
        gracePeriodSeconds: requireValue(
            context.gracePeriodSeconds ?? details.gracePeriodSeconds,
            'gracePeriodSeconds',
        ),
        ...(details.idleTimeoutOptionsSeconds
            ? {
                  idleTimeoutSeconds: resolveIdleTimeoutSeconds({
                      defaultSeconds: details.idleTimeoutSeconds ?? 300,
                      options: details.idleTimeoutOptionsSeconds,
                      selected: context.idleTimeoutSeconds,
                  }),
              }
            : {}),
        mint: context.mint ?? challenge.request.currency,
        // Explicit overrides stay allowed (never later than the challenged
        // recentSlot); the default is the challenged recentSlot itself.
        openSlot: resolveOpenSlot({ challengedRecentSlot: details.recentSlot, override: context.openSlot }),
        payee: context.payee ?? challenge.request.recipient,
        payer,
        salt: requireValue(context.salt, 'salt'),
        transaction: requireString(context.transaction, 'transaction'),
    });
}

async function createVoucherAction(session_: ActiveSession, context: SessionContext): Promise<SessionAction> {
    if (context.voucher) {
        return { action: 'voucher', channelId: context.voucher.voucher.channelId, voucher: context.voucher };
    }
    if (context.cumulativeAmount !== undefined) {
        const voucher = await session_.signVoucher(context.cumulativeAmount);
        return { action: 'voucher', channelId: voucher.voucher.channelId, voucher };
    }
    return await session_.voucherAction(requireValue(context.amount, 'amount'));
}

function formatAmount(value: AmountLike, name: string): string {
    return parseAmount(value, name).toString();
}

function parseAmount(value: AmountLike, name: string): bigint {
    const parsed = parseInteger(value, name);
    if (parsed < 0n) throw new Error(`${name} must be non-negative`);
    if (parsed > U64_MAX) throw new Error(`${name} exceeds u64 max`);
    return parsed;
}

function parseSafeInteger(value: AmountLike, name: string): number {
    const parsed = parseInteger(value, name);
    if (parsed < 0n) throw new Error(`${name} must be non-negative`);
    if (parsed > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error(`${name} exceeds Number.MAX_SAFE_INTEGER`);
    return Number(parsed);
}

function parseInteger(value: AmountLike, name: string): bigint {
    if (typeof value === 'bigint') return value;
    if (typeof value === 'number') {
        if (!Number.isSafeInteger(value)) throw new Error(`${name} must be a safe integer`);
        return BigInt(value);
    }
    if (!/^\d+$/.test(value)) throw new Error(`${name} must be an integer string`);
    return BigInt(value);
}

function requireString(value: string | undefined, name: string): string {
    if (!value) throw new Error(`${name} required`);
    return value;
}

function requireValue<Value>(value: Value | undefined, name: string): Value {
    if (value === undefined) throw new Error(`${name} required`);
    return value;
}
