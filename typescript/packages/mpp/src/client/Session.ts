import { createSignableMessage, getBase58Decoder, type MessagePartialSigner } from '@solana/kit';
import type { Challenge as MppxChallenge } from 'mppx';
import { Credential, Method, z } from 'mppx';

import * as Methods from '../Methods.js';
import { encodeVoucherMessageLoose } from '../shared/voucher.js';

const U64_MAX = (1n << 64n) - 1n;

/**
 * Default voucher expiry timestamp, matching the Rust SDK and program tests.
 */
export const DEFAULT_SESSION_EXPIRES_AT = 4_102_444_800;

/**
 * Numeric input accepted by the session helpers.
 */
export type AmountLike = bigint | number | string;

/**
 * Funding mode used to open a Solana payment session.
 */
export type SessionMode = 'pull' | 'push';

/**
 * Voucher authority used when a challenge advertises pull-mode sessions.
 *
 * `clientVoucher` does not require multi-delegate setup; `operatedVoucher`
 * is the operator-signed path that uses delegated token movement.
 */
export type SessionPullVoucherStrategy = 'clientVoucher' | 'operatedVoucher';

/**
 * Signer capable of Ed25519-signing exact voucher message bytes.
 */
export type SessionSigner = MessagePartialSigner;

/**
 * Basis-point split distributed when a session settles.
 */
export interface SessionSplit {
    /** Share of the settled amount, in basis points (100 = 1%). */
    readonly bps: number;
    /** Base58 address receiving this share. */
    readonly recipient: string;
}

/**
 * Request embedded in a Solana `session` challenge.
 */
export interface SessionRequest extends Record<string, unknown> {
    /** Maximum the session may spend, in base units. */
    readonly cap: string;
    /** Currency identifier: a symbol like `'USDC'` or an SPL mint address. */
    readonly currency: string;
    /** Token decimals (6 for the supported stablecoins). */
    readonly decimals?: number | undefined;
    /** Human-readable description of what the session pays for. */
    readonly description?: string | undefined;
    /** Merchant correlation id echoed in receipts. */
    readonly externalId?: string | undefined;
    /** Smallest voucher increment the server accepts, in base units. */
    readonly minVoucherDelta?: string | undefined;
    /** Funding modes the server supports. Omitted or empty means push only. */
    readonly modes?: SessionMode[] | undefined;
    /** Solana network slug (`mainnet`, `devnet`, `localnet`). */
    readonly network?: string | undefined;
    /** Operator public key vouchers are addressed to (base58). */
    readonly operator: string;
    /** Payment-channels program id override (base58). */
    readonly programId?: string | undefined;
    /** Voucher authority for pull-mode sessions. */
    readonly pullVoucherStrategy?: SessionPullVoucherStrategy | undefined;
    /** Server-provided recent blockhash, saving the client an RPC round-trip. */
    readonly recentBlockhash?: string | undefined;
    /** Primary recipient of the settled amount (base58). */
    readonly recipient: string;
    /** Basis-point splits distributed at close. */
    readonly splits?: SessionSplit[] | undefined;
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
    /** Unix timestamp (seconds) at which the voucher expires. */
    readonly expiresAt: number;
    /** Optional client-side voucher counter. Not part of the signed bytes. */
    readonly nonce?: number | undefined;
}

/**
 * Voucher-like input accepted by low-level serialization helpers.
 */
export interface VoucherDataInput {
    /** Channel / session id the voucher is bound to (base58). */
    readonly channelId: string;
    /** Legacy wire alias for `cumulativeAmount`. */
    readonly cumulative?: AmountLike | undefined;
    /** Cumulative amount authorized so far, in base units. */
    readonly cumulativeAmount?: AmountLike | undefined;
    /** Unix timestamp (seconds) at which the voucher expires. */
    readonly expiresAt: AmountLike;
    /** Optional client-side voucher counter. Not part of the signed bytes. */
    readonly nonce?: number | undefined;
}

/**
 * Signed cumulative voucher.
 */
export interface SignedVoucher {
    /** The signed voucher fields. */
    readonly data: VoucherData;
    /** Base58 Ed25519 signature over the canonical voucher bytes. */
    readonly signature: string;
}

/**
 * Open action payload for payment channels or delegated-token pull sessions.
 */
export interface OpenPayload {
    /** Pull mode: delegated amount approved by the wallet, in base units. */
    readonly approvedAmount?: string | undefined;
    /** Public key authorized to sign vouchers for this session (base58). */
    readonly authorizedSigner: string;
    /** Channel address (push) or delegated token account (pull), base58. */
    readonly channelId?: string | undefined;
    /** Push mode: deposit locked in the payment channel, in base units. */
    readonly deposit?: string | undefined;
    /** Push mode: close grace period in seconds. */
    readonly gracePeriod?: number | undefined;
    /** Pull mode: pre-signed multi-delegate init transaction (base64), when the PDA may not exist yet. */
    readonly initMultiDelegateTx?: string | undefined;
    /** SPL mint of the funding asset (base58). */
    readonly mint?: string | undefined;
    /** Funding mode this open uses. */
    readonly mode: SessionMode;
    /** Pull mode: wallet that owns the delegated token account (base58). */
    readonly owner?: string | undefined;
    /** Push mode: channel payee (base58). */
    readonly payee?: string | undefined;
    /** Push mode: channel payer (base58). */
    readonly payer?: string | undefined;
    /** Push mode: channel-derivation salt (decimal string). */
    readonly salt?: string | undefined;
    /** Open transaction signature, or {@link PENDING_SERVER_SIGNATURE} when the server broadcasts. */
    readonly signature: string;
    /** Pull mode: delegated token account vouchers draw from (base58). */
    readonly tokenAccount?: string | undefined;
    /** Push mode: base64 signed open transaction for server-side submission. */
    readonly transaction?: string | undefined;
    /** Pull mode: pre-signed delegation update transaction (base64). */
    readonly updateDelegationTx?: string | undefined;
}

/**
 * Client action sent as a Solana session credential payload.
 */
export type SessionAction =
    | { readonly action: 'close'; readonly channelId: string; readonly voucher?: SignedVoucher | undefined }
    | { readonly action: 'commit'; readonly deliveryId: string; readonly voucher: SignedVoucher }
    | { readonly action: 'topUp'; readonly channelId: string; readonly newDeposit: string; readonly signature: string }
    | { readonly action: 'voucher'; readonly voucher: SignedVoucher }
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
    /** Session action to perform. Defaults to `open` until a session is active, then `voucher`. */
    readonly action?: 'close' | 'commit' | 'open' | 'topUp' | 'voucher' | undefined;
    /** Incremental amount for `voucher` / `commit`, in base units. */
    readonly amount?: AmountLike | undefined;
    /** Pull opens: delegated amount approved by the wallet, in base units. */
    readonly approvedAmount?: AmountLike | undefined;
    /** Absolute cumulative amount for `voucher`, in base units. */
    readonly cumulativeAmount?: AmountLike | undefined;
    /** Delivery to commit. Defaults to `directive.deliveryId`. */
    readonly deliveryId?: string | undefined;
    /** Push opens: channel deposit, in base units. Defaults to the challenge cap. */
    readonly deposit?: AmountLike | undefined;
    /** Metering directive being committed. */
    readonly directive?: MeteringDirective | undefined;
    /** Close: last unsettled increment to sign into the closing voucher, in base units. */
    readonly finalIncrement?: AmountLike | undefined;
    /** Push opens: channel close grace period in seconds. */
    readonly gracePeriod?: number | undefined;
    /** Pull opens: pre-signed multi-delegate init transaction (base64). */
    readonly initMultiDelegateTx?: string | undefined;
    /** Push opens: SPL mint of the deposit (base58). */
    readonly mint?: string | undefined;
    /** Funding mode for `open`. Defaults to the first server-advertised mode. */
    readonly mode?: SessionMode | undefined;
    /** TopUp: new total deposit, in base units. */
    readonly newDeposit?: AmountLike | undefined;
    /** Pull opens: wallet that owns the delegated token account (base58). */
    readonly owner?: string | undefined;
    /** Push opens: channel payee (base58). */
    readonly payee?: string | undefined;
    /** Push opens: channel payer (base58). */
    readonly payer?: string | undefined;
    /** Push opens: channel-derivation salt. */
    readonly salt?: AmountLike | undefined;
    /** Active session to act on, overriding the method-level session. */
    readonly session?: ActiveSession | undefined;
    /** Open / topUp transaction signature (base58). */
    readonly signature?: string | undefined;
    /** Optional client identifier serialized into the credential. */
    readonly source?: string | undefined;
    /** Pull opens: delegated token account vouchers draw from (base58). */
    readonly tokenAccount?: string | undefined;
    /** Push opens: base64 signed open transaction for server-side submission. */
    readonly transaction?: string | undefined;
    /** Pull opens: pre-signed delegation update transaction (base64). */
    readonly updateDelegationTx?: string | undefined;
    /** Pre-signed voucher for `voucher` / `close`, bypassing local signing. */
    readonly voucher?: SignedVoucher | undefined;
}

/**
 * Runtime context schema for mppx routing. Detailed validation happens in the SDK helper.
 */
export const sessionContextSchema = z.custom<SessionContext>();

/**
 * Returns the funding modes advertised by a session request; an omitted or
 * empty `modes` list means the server only supports push.
 */
export function sessionRequestModes(request: Pick<SessionRequest, 'modes'>): readonly SessionMode[] {
    return request.modes && request.modes.length > 0 ? request.modes : ['push'];
}

/**
 * Builds canonical payment-channel voucher bytes:
 * `channel_id || cumulative_amount_le_u64 || expires_at_le_i64`.
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
    #nonce: number;
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
        this.#nonce = parseSafeInteger(parameters.nonce ?? 0n, 'nonce');
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

    /** Current local voucher nonce. */
    get nonce(): number {
        return this.#nonce;
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
            nonce: this.#nonce + 1,
        };

        const [signatureDictionary] = await this.#signer.signMessages([
            createSignableMessage(voucherMessageBytes(data)),
        ]);
        const signatureBytes = signatureDictionary?.[this.#signer.address];
        if (!signatureBytes) {
            throw new Error(`Signer ${this.#signer.address} did not return a voucher signature`);
        }

        return {
            data,
            signature: getBase58Decoder().decode(new Uint8Array(signatureBytes)),
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
        if (voucher.data.channelId !== this.#channelId) {
            throw new Error(
                `Voucher channel ${voucher.data.channelId} does not match active session ${this.#channelId}`,
            );
        }

        const cumulative = parseAmount(voucher.data.cumulativeAmount, 'cumulativeAmount');
        if (cumulative <= this.#cumulative) {
            throw new Error(
                `Voucher cumulative ${cumulative.toString()} must exceed current watermark ${this.#cumulative.toString()}`,
            );
        }

        this.#cumulative = cumulative;
        this.#nonce =
            voucher.data.nonce === undefined
                ? this.#nonce + 1
                : Math.max(this.#nonce, parseSafeInteger(voucher.data.nonce, 'nonce'));
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
        return { action: 'voucher', voucher: await this.signIncrement(amount) };
    }

    /**
     * Builds a `commit` action for a delivery and freshly signed increment.
     */
    async commitAction(delivery: MeteringDirective | string, amount?: AmountLike): Promise<SessionAction> {
        const deliveryId = typeof delivery === 'string' ? delivery : delivery.deliveryId;
        const resolvedAmount =
            typeof delivery === 'string' ? requireValue(amount, 'amount') : (amount ?? delivery.amount);
        return { action: 'commit', deliveryId, voucher: await this.signIncrement(resolvedAmount) };
    }

    /**
     * Builds a payment-channel `open` action.
     */
    openAction(
        deposit: AmountLike,
        signature: string,
        options: ActiveSession.OpenOptions = {},
    ): OpenPayload & { readonly action: 'open' } {
        return {
            action: 'open',
            authorizedSigner: this.authorizedSigner,
            channelId: this.#channelId,
            deposit: formatAmount(deposit, 'deposit'),
            mode: options.mode ?? 'push',
            signature,
            ...(options.transaction ? { transaction: options.transaction } : {}),
        };
    }

    /**
     * Builds a detailed payment-channel `open` action.
     */
    openPaymentChannelAction(
        parameters: ActiveSession.PaymentChannelOpenParameters,
    ): OpenPayload & { readonly action: 'open' } {
        return {
            action: 'open',
            authorizedSigner: this.authorizedSigner,
            channelId: this.#channelId,
            deposit: formatAmount(parameters.deposit, 'deposit'),
            gracePeriod: parameters.gracePeriod,
            mint: parameters.mint,
            mode: parameters.mode ?? 'push',
            payee: parameters.payee,
            payer: parameters.payer,
            salt: formatAmount(parameters.salt, 'salt'),
            signature: parameters.signature,
            ...(parameters.transaction ? { transaction: parameters.transaction } : {}),
        };
    }

    /**
     * Builds a pull-mode `open` action after delegation is confirmed.
     */
    openPullAction(parameters: ActiveSession.PullOpenParameters): OpenPayload & { readonly action: 'open' } {
        return {
            action: 'open',
            approvedAmount: formatAmount(parameters.approvedAmount, 'approvedAmount'),
            authorizedSigner: this.authorizedSigner,
            ...(parameters.initMultiDelegateTx ? { initMultiDelegateTx: parameters.initMultiDelegateTx } : {}),
            mode: 'pull',
            owner: parameters.owner,
            signature: parameters.signature,
            tokenAccount: parameters.tokenAccount ?? this.#channelId,
            ...(parameters.updateDelegationTx ? { updateDelegationTx: parameters.updateDelegationTx } : {}),
        };
    }

    /**
     * Builds a `topUp` action after the top-up transaction is confirmed.
     */
    topUpAction(newDeposit: AmountLike, signature: string): SessionAction {
        return {
            action: 'topUp',
            channelId: this.#channelId,
            newDeposit: formatAmount(newDeposit, 'newDeposit'),
            signature,
        };
    }

    /**
     * Builds a cooperative `close` action, optionally signing a final increment.
     */
    async closeAction(finalIncrement?: AmountLike): Promise<SessionAction> {
        if (finalIncrement === undefined || parseAmount(finalIncrement, 'finalIncrement') === 0n) {
            return { action: 'close', channelId: this.#channelId };
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
        /** Starting voucher counter when resuming a session. */
        readonly nonce?: AmountLike | undefined;
    }

    interface Parameters extends Options {
        /** Channel address (push) or delegated token account (pull), base58. */
        readonly channelId: string;
        /** Key that signs vouchers for this session. */
        readonly signer: SessionSigner;
    }

    interface OpenOptions {
        /** Funding mode. Defaults to `push`. */
        readonly mode?: SessionMode | undefined;
        /** Base64 signed open transaction for server-side submission. */
        readonly transaction?: string | undefined;
    }

    interface PaymentChannelOpenParameters extends OpenOptions {
        /** Deposit locked in the channel, in base units. */
        readonly deposit: AmountLike;
        /** Close grace period in seconds. */
        readonly gracePeriod: number;
        /** SPL mint of the deposit (base58). */
        readonly mint: string;
        /** Channel payee (base58). */
        readonly payee: string;
        /** Channel payer (base58). */
        readonly payer: string;
        /** Channel-derivation salt. */
        readonly salt: AmountLike;
        /** Open transaction signature (base58). */
        readonly signature: string;
    }

    interface PullOpenParameters {
        /** Delegated amount approved by the wallet, in base units. */
        readonly approvedAmount: AmountLike;
        /** Pre-signed multi-delegate init transaction (base64), when the PDA may not exist yet. */
        readonly initMultiDelegateTx?: string | undefined;
        /** Wallet that owns the delegated token account (base58). */
        readonly owner: string;
        /** Delegation transaction signature, or {@link PENDING_SERVER_SIGNATURE}. */
        readonly signature: string;
        /** Delegated token account vouchers draw from (base58). Defaults to the derived account. */
        readonly tokenAccount?: string | undefined;
        /** Pre-signed delegation update transaction (base64). */
        readonly updateDelegationTx?: string | undefined;
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
                return createOpenAction(getSession(context), challenge, context);
            case 'voucher':
                return await createVoucherAction(getSession(context), context);
            case 'commit':
                return await createCommitAction(getSession(context), context);
            case 'topUp':
                return getSession(context).topUpAction(
                    requireValue(context.newDeposit ?? context.deposit, 'newDeposit'),
                    requireString(context.signature, 'signature'),
                );
            case 'close':
                return await getSession(context).closeAction(context.finalIncrement ?? context.amount);
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

function createOpenAction(
    session_: ActiveSession,
    challenge: SessionChallenge,
    context: SessionContext,
): SessionAction {
    const signature = requireString(context.signature, 'signature');
    const mode = context.mode ?? sessionRequestModes(challenge.request)[0] ?? 'push';

    if (mode === 'pull' && shouldUseDelegatedPull(context, challenge)) {
        return session_.openPullAction({
            approvedAmount: context.approvedAmount ?? context.deposit ?? challenge.request.cap,
            initMultiDelegateTx: context.initMultiDelegateTx,
            owner: requireString(context.owner, 'owner'),
            signature,
            tokenAccount: context.tokenAccount,
            updateDelegationTx: context.updateDelegationTx,
        });
    }

    if (
        context.payer !== undefined ||
        context.payee !== undefined ||
        context.mint !== undefined ||
        context.salt !== undefined ||
        context.gracePeriod !== undefined
    ) {
        return session_.openPaymentChannelAction({
            deposit: context.deposit ?? challenge.request.cap,
            gracePeriod: requireValue(context.gracePeriod, 'gracePeriod'),
            mint: requireString(context.mint, 'mint'),
            mode,
            payee: requireString(context.payee, 'payee'),
            payer: requireString(context.payer, 'payer'),
            salt: requireValue(context.salt, 'salt'),
            signature,
            transaction: context.transaction,
        });
    }

    return session_.openAction(context.deposit ?? challenge.request.cap, signature, {
        mode,
        transaction: context.transaction,
    });
}

function shouldUseDelegatedPull(context: SessionContext, challenge: SessionChallenge): boolean {
    if (context.mode !== 'pull' && sessionRequestModes(challenge.request)[0] !== 'pull') return false;
    return (
        challenge.request.pullVoucherStrategy === 'operatedVoucher' ||
        context.approvedAmount !== undefined ||
        context.initMultiDelegateTx !== undefined ||
        context.owner !== undefined ||
        context.tokenAccount !== undefined ||
        context.updateDelegationTx !== undefined
    );
}

async function createVoucherAction(session_: ActiveSession, context: SessionContext): Promise<SessionAction> {
    if (context.voucher) return { action: 'voucher', voucher: context.voucher };
    if (context.cumulativeAmount !== undefined) {
        return { action: 'voucher', voucher: await session_.signVoucher(context.cumulativeAmount) };
    }
    return await session_.voucherAction(requireValue(context.amount, 'amount'));
}

async function createCommitAction(session_: ActiveSession, context: SessionContext): Promise<SessionAction> {
    const deliveryId = context.deliveryId ?? context.directive?.deliveryId;
    if (!deliveryId) throw new Error('deliveryId required for commit action');
    return await session_.commitAction(deliveryId, context.amount ?? context.directive?.amount);
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
