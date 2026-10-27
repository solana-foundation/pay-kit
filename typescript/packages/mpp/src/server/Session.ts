import { isOffCurveAddress } from '@solana/addresses';
import {
    type Address,
    address,
    createSignableMessage,
    createSolanaRpc,
    getBase58Decoder,
    isTransactionPartialSigner,
    type MessagePartialSigner,
    type Signature,
    type TransactionPartialSigner,
    type TransactionSigner,
} from '@solana/kit';
import { Method, Receipt } from 'mppx';

import {
    DEFAULT_SESSION_EXPIRES_AT,
    resolveIdleTimeoutSeconds,
    validateIdleTimeoutOptions,
    verifySessionAuthentication,
} from '../client/Session.js';
import { defaultTokenProgramForCurrency, resolveStablecoinMint, stablecoinSymbolForCurrency } from '../constants.js';
import * as Methods from '../Methods.js';
import type {
    CommitReceipt,
    MeteringDirective,
    OpenPayload,
    SessionAction,
    SessionAuthentication,
    SessionReceipt,
    SessionRequest,
    SessionSplit,
    SessionVoucherSigner,
    SignedVoucher,
} from '../shared/session-types.js';
import { encodeVoucherMessageLoose, normalizeSignedVoucher, verifyVoucherSignature } from '../shared/voucher.js';
import { createLifecycle, type Lifecycle } from './session/lifecycle.js';
import {
    deriveChannelAddress,
    OPEN_SLOT_WINDOW,
    PAYMENT_CHANNELS_PROGRAM_ID,
    type SettleRpc,
    submitOpenTx,
    submitSettleAndDistribute,
    type SubmitSettleAndDistributeResult,
    submitTopUpTx,
    transactionSignatureFromWire,
    treasuryOwnerForNetwork,
    verifyOpenTx,
    type VerifyOpenTxExpected,
    verifyTopUpTx,
} from './session/on-chain.js';
import {
    CHANNEL_STATE_SCHEMA_VERSION,
    type ChannelState,
    type CommittedDelivery,
    createMemorySessionStore,
    type PendingDelivery,
    type ProcessedUse,
    type SessionStore,
} from './session/store.js';
import { verifyVoucherForChannel, type VoucherVerifyResult } from './session/voucher.js';
import { buildAndSignWireTransaction } from './session/wire-tx.js';

/** Default forced-close grace period, in seconds. Mirrors Rust `payment_channels::DEFAULT_GRACE_PERIOD_SECONDS`. */
const DEFAULT_GRACE_PERIOD_SECONDS = 900;

// The Rust mirror keeps this default literal in
// `crate::protocol::intents::session::DEFAULT_SESSION_EXPIRES_AT` (year 2100).
const DEFAULT_DIRECTIVE_EXPIRES_AT = 4_102_444_800;

// Lazily-created default store shared by `session()` and `session.routes()`
// when both are built from the same parameters object — otherwise each call
// would get its own memory store and deliveries could never find channels
// opened through the method handler.
const defaultStores = new WeakMap<session.Parameters, SessionStore>();

function resolveSessionStore(parameters: session.Parameters): SessionStore {
    if (parameters.store) return parameters.store;
    const existing = defaultStores.get(parameters);
    if (existing) return existing;
    const created = createMemorySessionStore();
    defaultStores.set(parameters, created);
    return created;
}

/**
 * Creates a Solana `session` MPP method for the server.
 *
 * A session opens a payment channel once, then
 * accepts off-chain cumulative vouchers for subsequent paid deliveries.
 * On close, the server settles the highest accepted voucher on-chain and
 * distributes proceeds to the configured splits.
 *
 * Mirrors `SessionServer` in `rust/crates/mpp/src/server/session.rs`.
 *
 * @example
 * ```ts
 * import { Mppx, session } from '@solana/mpp/server'
 *
 * const sess = session({
 *   recipient: RECIPIENT,
 *   signer,
 *   amount: 100n,
 *   suggestedDeposit: 10_000_000n,
 *   currency: 'USDC',
 *   decimals: 6,
 *   network: 'devnet',
 *   rpc: createSolanaRpc('https://api.devnet.solana.com'),
 * })
 *
 * const mppx = Mppx.create({ methods: [sess] })
 * ```
 */
export function session(parameters: session.Parameters) {
    if (parameters.voucherSigner === 'operator' && !parameters.operatorVoucherSigner) {
        throw new Error('operatorVoucherSigner is required when voucherSigner is operator');
    }
    const config = resolveSessionConfig(parameters);
    const {
        amount,
        distributionSplits,
        feePayer,
        feePayerSigner,
        gracePeriodSeconds,
        idleTimeoutOptionsSeconds,
        idleTimeoutSeconds,
        minVoucherDelta,
        minimumDeposit,
        network,
        operator,
        recipient,
        resolvedDecimals,
        resolvedMint,
        resolvedProgramId,
        rpc,
        store,
        suggestedDeposit,
        tokenProgram,
        voucherSigner,
    } = config;
    const { currency, decimals, signer } = parameters;
    const operatorVoucherSigner = parameters.operatorVoucherSigner;
    const lifecycleRef: { value: Lifecycle | undefined } = { value: undefined };

    // Note: lifecycle's closeOnIdle would normally drive an on-chain settle.
    // Because that requires a configured merchant signer + rpc, we only
    // create the lifecycle when both are present.
    if (idleTimeoutSeconds > 0) {
        lifecycleRef.value = createLifecycle(
            store,
            async channelId => {
                try {
                    await closeAndSettleChannel({
                        channelId,
                        currency,
                        decimals,
                        merchantSigner: signer,
                        mint: resolvedMint,
                        network,
                        programId: resolvedProgramId,
                        recipient,
                        rentPayer: feePayerSigner?.address,
                        rpc,
                        splits: distributionSplits?.map(split => ({ bps: split.shareBps, recipient: split.recipient })),
                        store,
                        tokenProgram,
                    });
                } catch (error) {
                    // No synchronous caller to report to — surface the
                    // failure the same way Charge does for simulation
                    // errors so operators can see why a settle didn't land.
                    console.warn(`[solana-mpp] idle-close settle failed for ${channelId}:`, error);
                }
            },
            idleTimeoutSeconds * 1_000,
        );
    }
    const server = buildSessionServer(config, lifecycleRef);

    const method = Method.toServer(Methods.session, {
        defaults: {
            amount: amount.toString(),
            currency: resolvedMint,
            methodDetails: {
                channelProgram: resolvedProgramId.toString(),
                network,
            },
            recipient,
        },

        async request({ credential, request }) {
            // A route-supplied channelId marks a resume challenge for an
            // already-open channel: recentBlockhash/recentSlot MUST be absent
            // (there is no open transaction to build). A fresh new-channel 402
            // REQUIRES both, from ONE getLatestBlockhash observation.
            const resumeChannelId = (request as { methodDetails?: { channelId?: string } }).methodDetails?.channelId;
            // Skip the fetch on the verify path (credential present): the
            // client builds its open against the challenge it was actually
            // issued — echoed back and HMAC-verified — so re-fetching here
            // would only burn an RPC call. The pinned challenge binding does
            // not pin the transient blockhash fields.
            const openContext =
                resumeChannelId || credential
                    ? undefined
                    : await challengeOpenTransactionContext(parameters.blockhashCache, rpc);

            const challengeRequest: SessionRequest = {
                amount: request.amount ?? amount.toString(),
                currency: resolvedMint,
                ...(request.description ? { description: request.description } : {}),
                ...(request.externalId ? { externalId: request.externalId } : {}),
                ...(minimumDeposit !== undefined ? { minimumDeposit: minimumDeposit.toString() } : {}),
                recipient,
                ...(suggestedDeposit !== undefined ? { suggestedDeposit: suggestedDeposit.toString() } : {}),
                ...(parameters.unitType ? { unitType: parameters.unitType } : {}),
                methodDetails: {
                    ...(resumeChannelId ? { channelId: resumeChannelId } : {}),
                    channelProgram: resolvedProgramId.toString(),
                    decimals: resolvedDecimals,
                    ...(distributionSplits?.length ? { distributionSplits: [...distributionSplits] } : {}),
                    ...(feePayer ? { feePayer: true, feePayerKey: feePayerSigner?.address } : {}),
                    ...(gracePeriodSeconds !== undefined ? { gracePeriodSeconds } : {}),
                    ...(idleTimeoutOptionsSeconds ? { idleTimeoutOptionsSeconds: [...idleTimeoutOptionsSeconds] } : {}),
                    idleTimeoutSeconds,
                    ...(minVoucherDelta !== undefined && minVoucherDelta > 0n
                        ? { minVoucherDelta: minVoucherDelta.toString() }
                        : {}),
                    network,
                    ...(operator ? { operator } : {}),
                    ...(openContext
                        ? { recentBlockhash: openContext.blockhash, recentSlot: openContext.slot.toString() }
                        : {}),
                    tokenProgram,
                    voucherSigner,
                },
            };

            return challengeRequest as Record<string, unknown> & SessionRequest;
        },

        async verify({ credential, envelope }) {
            const cred = credential as unknown as CredentialPayload;
            const action = cred.payload.action;
            const receiptOptions = { challengeId: cred.challenge.id, externalId: cred.challenge.request.externalId };

            switch (action) {
                case 'open':
                    assertChallengeOpenNotExpired(cred.challenge.expires);
                    return await handleOpen({
                        config,
                        // Verified outer challenge facts the open is bound to
                        // (mirrors the Rust SessionOpenContext): the challenged
                        // blockhash + slot flow from the (HMAC-verified) echoed
                        // challenge into open verification.
                        context: {
                            challengeId: cred.challenge.id ?? '',
                            ...(cred.challenge.expires !== undefined ? { expires: cred.challenge.expires } : {}),
                            ...challengedOpenContext(cred.challenge.request),
                        },
                        externalId: cred.challenge.request.externalId,
                        lifecycle: lifecycleRef.value,
                        payload: cred.payload,
                    });
                case 'use': {
                    if (!operatorVoucherSigner) {
                        throw new Error('use is only valid when voucherSigner is operator');
                    }
                    await server.processUse(
                        cred.payload,
                        cred.challenge.id ?? '',
                        envelope?.capturedRequest.headers.get('Idempotency-Key') ?? '',
                        parseU64String(cred.challenge.request.amount, 'amount'),
                    );
                    return await receiptFor(store, cred.payload.channelId, receiptOptions);
                }
                case 'voucher':
                    await server.verifyVoucherForAmount(
                        cred.payload,
                        parseU64String(cred.challenge.request.amount, 'amount'),
                    );
                    return await receiptFor(store, cred.payload.voucher.voucher.channelId, receiptOptions);
                case 'topUp':
                    return await handleTopUp({
                        challengeId: cred.challenge.id,
                        config,
                        externalId: cred.challenge.request.externalId,
                        lifecycle: lifecycleRef.value,
                        payload: cred.payload,
                    });
                case 'close':
                    return await handleClose({
                        challengeId: cred.challenge.id,
                        config,
                        externalId: cred.challenge.request.externalId,
                        lifecycle: lifecycleRef.value,
                        merchantSigner: signer,
                        payload: cred.payload,
                    });
                default:
                    throw new Error(`Unknown session action: ${String(action)}`);
            }
        },
    });

    return method;
}

/**
 * A session server's fully resolved configuration: the {@link session.Parameters}
 * after defaults, mint/token-program resolution and validation. Shared by the
 * `session()` method handler and {@link createSessionServer}.
 */
interface ResolvedSessionConfig {
    readonly amount: bigint;
    /** The configured currency (symbol or mint), as given. */
    readonly currency: string;
    readonly distributionSplits: readonly SessionSplit[] | undefined;
    readonly feePayer: boolean;
    readonly feePayerSigner: TransactionPartialSigner | undefined;
    readonly gracePeriodSeconds: number | undefined;
    readonly idleTimeoutOptionsSeconds: readonly number[] | undefined;
    readonly idleTimeoutSeconds: number;
    readonly minVoucherDelta: bigint | undefined;
    readonly minimumDeposit: bigint | undefined;
    readonly network: string;
    /** The operator's address (the voucher signer in operator mode). */
    readonly operator: string | undefined;
    readonly operatorVoucherSigner: MessagePartialSigner | undefined;
    readonly recipient: string;
    readonly resolvedDecimals: number;
    readonly resolvedMint: string;
    readonly resolvedProgramId: Address;
    readonly rpc: RpcLike;
    /**
     * The forced-close window a non-zero voucher expiry must outlast: the
     * explicit `settlementWindowSeconds`, else the channel grace period.
     */
    readonly settlementWindow: bigint | undefined;
    readonly store: SessionStore;
    readonly suggestedDeposit: bigint | undefined;
    readonly tokenProgram: string;
    readonly voucherSigner: SessionVoucherSigner;
}

function resolveSessionConfig(parameters: session.Parameters): ResolvedSessionConfig {
    const {
        recipient,
        signer,
        amount,
        suggestedDeposit,
        minimumDeposit,
        currency,
        decimals,
        network = 'mainnet',
        channelProgram,
        voucherSigner = 'client',
        distributionSplits,
        rpc,
        idleTimeoutOptionsSeconds,
        idleTimeoutSeconds = 300,
        minVoucherDelta,
        feePayer = false,
        feePayerSigner,
        gracePeriodSeconds = DEFAULT_GRACE_PERIOD_SECONDS,
        settlementWindowSeconds,
        operatorVoucherSigner,
    } = parameters;

    if (amount <= 0n) {
        throw new Error('amount must be positive');
    }
    if (!rpc) throw new Error('rpc is required for session funding verification');
    if (!isTransactionPartialSigner(signer)) {
        throw new Error('signer must implement signTransactions()');
    }
    if (feePayerSigner && !isTransactionPartialSigner(feePayerSigner)) {
        throw new Error('feePayerSigner must implement signTransactions()');
    }
    if (feePayer && !feePayerSigner) throw new Error('feePayerSigner is required when feePayer is true');
    if (distributionSplits && distributionSplits.length > 32) {
        throw new Error('distributionSplits cannot exceed 32 entries');
    }
    if (idleTimeoutOptionsSeconds) validateIdleTimeoutOptions(idleTimeoutOptionsSeconds);
    resolveIdleTimeoutSeconds({ defaultSeconds: idleTimeoutSeconds, options: idleTimeoutOptionsSeconds });
    if (
        operatorVoucherSigner &&
        parameters.operator !== undefined &&
        operatorVoucherSigner.address !== parameters.operator
    ) {
        throw new Error('operatorVoucherSigner does not match operator');
    }
    const operator = operatorVoucherSigner?.address ?? parameters.operator;
    if (voucherSigner === 'operator' && !operator) {
        throw new Error('operator (or operatorVoucherSigner) is required when voucherSigner is operator');
    }
    const store = resolveSessionStore(parameters);
    const resolvedProgramId = (channelProgram ?? PAYMENT_CHANNELS_PROGRAM_ID) as Address;
    // Settlement derives the treasury ATA per cluster; reject unknown networks up front.
    treasuryOwnerForNetwork(network);
    const resolvedMint = resolveStablecoinMint(currency, network);
    if (!resolvedMint) throw new Error('session currency must be an SPL token mint; use wrapped SOL instead of SOL');
    const resolvedDecimals = decimals ?? (stablecoinSymbolForCurrency(resolvedMint) ? 6 : undefined);
    if (resolvedDecimals === undefined) throw new Error('decimals is required for a session SPL token mint');
    if (!Number.isInteger(resolvedDecimals) || resolvedDecimals < 0 || resolvedDecimals > 9) {
        throw new Error('decimals must be an integer from 0 to 9');
    }
    const tokenProgram = parameters.tokenProgram ?? defaultTokenProgramForCurrency(currency, network);
    // draft-solana-session-00: a voucher's non-zero expiry must outlast the
    // channel's forced-close grace period, so the operator can still settle
    // after the payer starts a forced close. Mirrors the Rust server, which
    // uses `grace_period_seconds` as the window.
    const settlementWindow =
        settlementWindowSeconds ?? (gracePeriodSeconds !== undefined ? BigInt(gracePeriodSeconds) : undefined);
    return {
        amount,
        currency,
        distributionSplits,
        feePayer,
        feePayerSigner,
        gracePeriodSeconds,
        idleTimeoutOptionsSeconds,
        idleTimeoutSeconds,
        minVoucherDelta,
        minimumDeposit,
        network,
        operator,
        operatorVoucherSigner,
        recipient,
        resolvedDecimals,
        resolvedMint,
        resolvedProgramId,
        rpc,
        settlementWindow,
        store,
        suggestedDeposit,
        tokenProgram,
        voucherSigner,
    };
}

function assertChallengeOpenNotExpired(expires: string | undefined): void {
    if (expires === undefined) return;
    const expiresAt = Date.parse(expires);
    if (Number.isNaN(expiresAt)) throw new Error('challenge expires must be an RFC3339 timestamp');
    if (expiresAt <= Date.now()) throw new Error(`challenge expired at ${expires}`);
}

/**
 * Verified outer challenge facts required while opening a session — the
 * challenged `recentBlockhash` the compiled open message must use, and the
 * challenged `recentSlot` the payload's `openSlot` must sit at-or-before
 * within {@link OPEN_SLOT_WINDOW}. Mirrors `SessionOpenContext` in
 * `rust/crates/kit/src/mpp/server/session.rs`.
 */
export interface SessionOpenContext {
    readonly recentBlockhash: string;
    readonly recentSlot: bigint;
}

/**
 * Extracts the open-transaction context from the (HMAC-verified) echoed
 * challenge. Both fields are REQUIRED on the new-channel challenge an `open`
 * answers — a challenge without them (e.g. a resume challenge) never
 * authorized an open.
 */
function challengedOpenContext(request: SessionRequest): SessionOpenContext {
    const details = request.methodDetails;
    if (!details.recentBlockhash || details.recentSlot === undefined) {
        throw new Error(
            'open requires a challenge carrying recentBlockhash/recentSlot; only a new-channel challenge provides them',
        );
    }
    return {
        recentBlockhash: details.recentBlockhash,
        recentSlot: parseU64String(details.recentSlot, 'methodDetails.recentSlot'),
    };
}

/**
 * Fetch the open-transaction context (`recentBlockhash` + `recentSlot`) for a
 * new-channel challenge.
 *
 * Prefers the shared cache (refreshed out of band) to avoid a blocking RPC
 * round-trip per 402; falls back to ONE direct `getLatestBlockhash` call,
 * whose response carries both the blockhash (`result.value.blockhash`) and
 * the context slot (`result.context.slot`).
 *
 * Fails loudly (retryable) rather than issuing a degraded challenge without
 * the fields: both are REQUIRED for a new-channel challenge — the client
 * derives the channel PDA from `recentSlot` and MUST use the challenged
 * blockhash — so a silent omission would surface as a non-retryable payment
 * failure at open time. Mirrors `challenge_open_transaction_context` in the
 * Rust SessionServer.
 */
async function challengeOpenTransactionContext(
    cache: session.BlockhashCache | undefined,
    rpc: RpcLike,
): Promise<{ blockhash: string; slot: bigint }> {
    const cached = cache?.get();
    if (cached) return { blockhash: cached.blockhash, slot: BigInt(cached.slot) };
    const candidate = rpc as Partial<LatestBlockhashRpc>;
    if (typeof candidate.getLatestBlockhash !== 'function') {
        throw new Error(
            'session challenge requires recentBlockhash/recentSlot; configure a blockhashCache or an rpc that supports getLatestBlockhash',
        );
    }
    let response;
    try {
        response = await candidate.getLatestBlockhash({ commitment: 'confirmed' }).send();
    } catch (error) {
        throw new Error(`failed to fetch recentBlockhash/recentSlot for session challenge: ${errorMessage(error)}`);
    }
    return { blockhash: response.value.blockhash, slot: BigInt(response.context.slot) };
}

/** RPC subset used to fetch the challenge open-transaction context. */
type LatestBlockhashRpc = {
    getLatestBlockhash(config?: { commitment?: 'confirmed' | 'finalized' | 'processed' }): {
        send(): Promise<{
            context: { slot: bigint | number };
            value: { blockhash: string };
        }>;
    };
};

// ─────────────────────────────────────────────────────────────────────
// Routes — side-channel HTTP endpoints for deliveries / commit.
// ─────────────────────────────────────────────────────────────────────

/**
 * Build the side-channel route handlers used by the session for metering.
 *
 * - `POST /__402/session/deliveries`: reserve capacity for a delivery,
 *   return a `MeteringDirective` the client commits later.
 * - `POST /__402/session/commit`: commit a reserved delivery and return
 *   a `CommitReceipt`.
 *
 * Mirrors the in-process methods `begin_delivery` / `process_commit` in
 * `SessionServer`. The framework's `session()` method handler does not
 * touch these — they're a separate HTTP surface for metered streaming.
 */
session.routes = function routes(parameters: session.Parameters): session.RoutesHandlers {
    const store = resolveSessionStore(parameters);
    // Deliveries must advertise the same resolved mint challenges do
    // (`currency: resolvedMint` in `session()`'s request/verify handlers),
    // not the raw symbol a caller may have configured.
    const currency = resolveStablecoinMint(parameters.currency, parameters.network ?? 'mainnet');
    if (!currency) throw new Error('session currency must be an SPL token mint; use wrapped SOL instead of SOL');

    return {
        async commit(request) {
            const body = (await request.json().catch(() => null)) as CommitRequestBody | null;
            if (!body || typeof body !== 'object') return jsonError(400, 'invalid request body');
            if (!body.deliveryId) return jsonError(400, 'deliveryId required');
            if (!body.voucher) return jsonError(400, 'voucher required');

            try {
                const receipt = await commitDelivery(store, {
                    deliveryId: body.deliveryId,
                    settlementWindow: parameters.settlementWindowSeconds,
                    voucher: body.voucher,
                });
                return Response.json(receipt, { status: 200 });
            } catch (error) {
                return jsonError(400, errorMessage(error));
            }
        },
        async deliveries(request) {
            const body = (await request.json().catch(() => null)) as DeliveryRequestBody | null;
            if (!body || typeof body !== 'object') return jsonError(400, 'invalid request body');
            if (!body.sessionId) return jsonError(400, 'sessionId required');
            const amount = parseU64String(body.amount, 'amount');
            if (amount === 0n) return jsonError(400, 'amount must be positive');

            try {
                const deliveriesUrl = new URL(request.url);
                // Advertise a path-only sibling URL: the client resolves it
                // against its public resource origin. This avoids leaking an
                // internal reverse-proxy origin and preserves mount prefixes
                // such as `/gateway/__402/session/*`.
                const commitPath = deliveriesUrl.pathname.replace(/\/deliveries\/?$/, '/commit');
                const directive = await reserveDelivery(store, {
                    amount,
                    commitUrl: commitPath,
                    currency,
                    deliveryId: body.deliveryId,
                    expiresAt: body.expiresAt ?? DEFAULT_DIRECTIVE_EXPIRES_AT,
                    proof: body.proof,
                    sessionId: body.sessionId,
                });
                return Response.json(directive, { status: 200 });
            } catch (error) {
                return jsonError(400, errorMessage(error));
            }
        },
    };
};

// ─────────────────────────────────────────────────────────────────────
// Action handlers
// ─────────────────────────────────────────────────────────────────────

/**
 * The challenge an `open` answers: its id, optional expiry, and the
 * challenged `recentBlockhash` / `recentSlot` the open transaction is bound
 * to. Mirrors `SessionOpenContext` in `rust/crates/kit/src/mpp/server/session.rs`.
 */
export interface SessionOpenChallenge extends SessionOpenContext {
    readonly challengeId: string;
    /** RFC 3339 challenge expiry; an expired challenge never authorizes an open. */
    readonly expires?: string | undefined;
}

/** What {@link SessionServer.verifyOpenPreBroadcast} established about an open. */
export interface VerifiedSessionOpen {
    readonly channelId: string;
    readonly deposit: bigint;
    /** Effective negotiated idle timeout, in seconds. */
    readonly idleTimeoutSeconds: number;
    readonly openSlot: bigint;
    readonly payer: string;
    /** The channel rent payer: the sponsor when the server pays fees, else the payer. */
    readonly rentPayer: string;
}

/** A `use` proof authenticated against its channel, not yet charged. */
export interface AuthenticatedUse {
    readonly authentication: SessionAuthentication;
    readonly challengeId: string;
    readonly channelId: string;
    readonly idempotencyKey: string;
}

/** The operator voucher an accepted `use` charge persisted. */
export interface OperatorCharge {
    /** Amount newly charged by this call (zero on a replay). */
    readonly charged: bigint;
    readonly cumulative: bigint;
    /** True when the request was already charged at least this much. */
    readonly replay: boolean;
    /** The request's metered total recorded for it. */
    readonly requestTotal: bigint;
    readonly voucher: SignedVoucher;
}

type OpenAction = OpenPayload & { readonly action: 'open' };
type VoucherAction = { readonly action: 'voucher'; readonly channelId: string; readonly voucher: SignedVoucher };
type TopUpAction = {
    readonly action: 'topUp';
    readonly additionalAmount: string;
    readonly channelId: string;
    readonly transaction: string;
};
type CloseAction = {
    readonly action: 'close';
    readonly authentication?: SessionAuthentication | undefined;
    readonly channelId: string;
    readonly voucher?: SignedVoucher | undefined;
};
type UseAction = { readonly action: 'use'; readonly authentication: SessionAuthentication; readonly channelId: string };

/**
 * A session server's per-action processing over its channel store, without
 * the HTTP challenge binding `session()` adds. `session()` runs every action
 * through these; hosts that drive sessions themselves (metered streaming,
 * custom transports) call them directly.
 *
 * The `*PreBroadcast` methods run every check the server makes before it
 * co-signs or broadcasts a client transaction and touch neither the store
 * nor the network. Mirrors `SessionServer` (and its `testkit` hooks) in
 * `rust/crates/kit/src/mpp/server/session.rs`.
 */
export interface SessionServer {
    /**
     * Authenticate a request under an operator-signed session with its `use`
     * proof, without charging it. Hosts whose price is known only after
     * serving authenticate here, serve, then call
     * {@link SessionServer.chargeOperatorRequest} with the metered total.
     * Nothing is reserved between the two calls.
     */
    authenticateUse(payload: UseAction, challengeId: string, idempotencyKey: string): Promise<AuthenticatedUse>;
    /**
     * Charge an authenticated request up to `requestTotal`, its metered cost
     * so far (draft-solana-session-00 Debit Processing): sign the operator
     * voucher for `acceptedCumulative` plus what the request was not yet
     * charged, and persist it with the new `acceptedCumulative` and
     * `spentAmount`. A retry asking for a total already reached returns the
     * recorded voucher with `replay: true`; an Idempotency-Key recorded for
     * another challenge is refused. A zero total is rejected.
     */
    chargeOperatorRequest(
        authenticated: AuthenticatedUse,
        signer: MessagePartialSigner,
        requestTotal: bigint,
    ): Promise<OperatorCharge>;
    /**
     * Record a `close`: verify the final voucher (client mode) or the bound
     * proof (operator mode) and mark the channel close-pending. Settlement is
     * not part of it.
     */
    processClose(payload: CloseAction): Promise<ChannelState>;
    /**
     * Meter one operator-signed request at the challenged `amount`, exactly
     * once per Idempotency-Key.
     */
    processUse(
        payload: UseAction,
        challengeId: string,
        idempotencyKey: string,
        amount?: bigint,
    ): Promise<OperatorCharge>;
    /** The channel store this server reads and writes. */
    readonly store: SessionStore;
    /**
     * Every check the server makes on an `open` before it persists or
     * broadcasts: the challenge, the declared open parameters against the
     * server's configuration, the `openSlot` window, the voucher-signer mode
     * and proof, then the transaction. The window against the live cluster
     * slot needs RPC and is not part of it.
     */
    verifyOpenPreBroadcast(payload: OpenPayload, challenge: SessionOpenChallenge): Promise<VerifiedSessionOpen>;
    /**
     * Every check the server makes on a `topUp` before it co-signs or
     * broadcasts: a positive amount for a stored channel that is still open,
     * then the transaction.
     */
    verifyTopUpPreBroadcast(payload: TopUpAction): Promise<void>;
    /**
     * Accept a client voucher paying for one request priced at `amount` (the
     * challenged amount), advancing the watermark and debiting `amount` in
     * one store update. An exact replay of the highest voucher is rejected.
     */
    verifyVoucherForAmount(payload: VoucherAction, amount: bigint): Promise<ChannelState>;
}

/**
 * Creates a {@link SessionServer} over the configured channel store.
 *
 * @example
 * ```ts
 * const server = createSessionServer({ ...parameters, operator: OPERATOR, voucherSigner: 'operator' })
 * const authenticated = await server.authenticateUse(payload, challengeId, idempotencyKey)
 * // ... serve the request, metering its cost ...
 * const { voucher } = await server.chargeOperatorRequest(authenticated, operatorSigner, meteredTotal)
 * ```
 */
export function createSessionServer(parameters: session.Parameters): SessionServer {
    return buildSessionServer(resolveSessionConfig(parameters), { value: undefined });
}

function buildSessionServer(
    config: ResolvedSessionConfig,
    lifecycleRef: { readonly value: Lifecycle | undefined },
): SessionServer {
    const { store } = config;
    return {
        authenticateUse: (payload, challengeId, idempotencyKey) =>
            authenticateUse(config, payload, challengeId, idempotencyKey),
        chargeOperatorRequest: async (authenticated, signer, requestTotal) => {
            const charge = await chargeOperatorRequest(config, authenticated, signer, requestTotal);
            await touchLifecycle(lifecycleRef.value, store, authenticated.channelId);
            return charge;
        },
        processClose: payload => recordClose(config, payload),
        processUse: async (payload, challengeId, idempotencyKey, amount) => {
            const signer = config.operatorVoucherSigner;
            if (!signer) throw new Error('operatorVoucherSigner is required for use');
            const charge = await processUse(
                config,
                signer,
                payload,
                challengeId,
                idempotencyKey,
                amount ?? config.amount,
            );
            await touchLifecycle(lifecycleRef.value, store, payload.channelId);
            return charge;
        },
        store,
        verifyOpenPreBroadcast: async (payload, challenge) => (await validateOpen(config, payload, challenge)).open,
        verifyTopUpPreBroadcast: async payload => {
            await prepareTopUp(config, payload);
        },
        verifyVoucherForAmount: async (payload, amount) => {
            const state = await acceptVoucher(config, payload, amount);
            lifecycleRef.value?.touch(state.channelId, state.idleTimeoutSeconds);
            return state;
        },
    };
}

async function touchLifecycle(lifecycle: Lifecycle | undefined, store: SessionStore, channelId: string): Promise<void> {
    if (!lifecycle) return;
    const state = await store.getChannel(channelId);
    lifecycle.touch(channelId, state?.idleTimeoutSeconds);
}

async function receiptFor(
    store: SessionStore,
    channelId: string,
    options: SessionReceiptOptions,
): Promise<Receipt.Receipt> {
    const state = await store.getChannel(channelId);
    if (!state) throw new Error(`Channel ${channelId} not found`);
    return sessionReceipt(state, options);
}

// ─────────────────────────────────────────────────────────────────────
// open
// ─────────────────────────────────────────────────────────────────────

interface ValidatedOpen {
    readonly expected: VerifyOpenTxExpected;
    readonly open: VerifiedSessionOpen;
}

/**
 * Every pre-broadcast check on an `open`, in the Rust server's order: the
 * challenge expiry, the declared open parameters against the configuration
 * (`payment_channel_open_params`), the `openSlot` window against the
 * challenged `recentSlot`, the voucher-signer mode and bearer proof, then the
 * transaction (`verifyOpenTx`).
 */
async function validateOpen(
    config: ResolvedSessionConfig,
    payload: OpenPayload,
    context: SessionOpenChallenge,
): Promise<ValidatedOpen> {
    assertChallengeOpenNotExpired(context.expires);
    const deposit = parseU64String(payload.depositAmount, 'depositAmount');
    const idleTimeoutSeconds = resolveIdleTimeoutSeconds({
        defaultSeconds: config.idleTimeoutSeconds,
        options: config.idleTimeoutOptionsSeconds,
        selected: payload.idleTimeoutSeconds,
    });
    if (deposit === 0n) throw new Error('Deposit must be greater than zero');

    // The open parameters the payload declares, against the configuration.
    const authorizedSigner = address(payload.authorizedSigner);
    if (isOffCurveAddress(authorizedSigner)) {
        throw new Error('payment-channel authorizedSigner must be an on-curve Ed25519 public key');
    }
    if (config.voucherSigner === 'operator' && payload.authorizedSigner !== config.operator) {
        throw new Error('operator voucher signing requires authorizedSigner to match the operator');
    }
    if (payload.payee !== config.recipient) {
        throw new Error('payment-channel open payee does not match challenge recipient');
    }
    if (payload.mint !== config.resolvedMint) {
        throw new Error('payment-channel open mint does not match challenge currency');
    }
    if (config.gracePeriodSeconds === undefined || config.gracePeriodSeconds <= 0) {
        throw new Error('challenge must specify a positive gracePeriodSeconds');
    }
    if (payload.gracePeriodSeconds !== config.gracePeriodSeconds) {
        throw new Error('payment-channel open gracePeriodSeconds does not match challenge');
    }
    if (config.minimumDeposit !== undefined && deposit < config.minimumDeposit) {
        throw new Error('payment-channel open depositAmount is below minimumDeposit');
    }
    const declaredSplits = payload.distributionSplits ?? [];
    const configuredSplits = config.distributionSplits ?? [];
    if (
        declaredSplits.length !== configuredSplits.length ||
        declaredSplits.some(
            (split, index) =>
                split.recipient !== configuredSplits[index]?.recipient ||
                split.shareBps !== configuredSplits[index]?.shareBps,
        )
    ) {
        throw new Error('payment-channel open distributionSplits do not match challenge');
    }
    const rentPayer = config.feePayer ? config.feePayerSigner?.address : payload.payer;
    if (!rentPayer) throw new Error('unable to determine channel rent payer');
    // The sponsor co-signs as fee payer and rent payer; if it were also the
    // channel payer, that one signature would authorize the deposit out of the
    // sponsor's own token account. Mirrors `reject_sponsor_as_payer` in Rust.
    if (config.feePayer && payload.payer === rentPayer) {
        throw new Error('payment-channel payer must differ from the sponsored fee payer');
    }
    const openSlot = parseU64String(payload.openSlot, 'openSlot');
    const derivedChannel = await deriveChannelAddress({
        authorizedSigner: payload.authorizedSigner,
        mint: payload.mint,
        openSlot,
        payee: payload.payee,
        payer: payload.payer,
        programAddress: config.resolvedProgramId,
        salt: parseU64String(payload.salt, 'salt'),
    });
    if (derivedChannel !== payload.channelId) {
        throw new Error('payment-channel open channelId does not match derived channel PDA');
    }

    // Bind the open to the specific challenge that authorized it: the client
    // takes `openSlot` from the challenged `recentSlot` (an earlier slot is
    // allowed, a later one never is), so a payload outside this window was
    // not built against this challenge. Mirrors `process_open` in the Rust
    // SessionServer.
    const { recentBlockhash, recentSlot } = context;
    if (openSlot > recentSlot) {
        throw new Error(
            `open openSlot ${openSlot.toString()} is ahead of the challenged recentSlot ${recentSlot.toString()}`,
        );
    }
    if (recentSlot - openSlot > OPEN_SLOT_WINDOW) {
        throw new Error(
            `open openSlot ${openSlot.toString()} is outside the ${OPEN_SLOT_WINDOW.toString()}-slot freshness window of the challenged recentSlot ${recentSlot.toString()}`,
        );
    }

    if (config.voucherSigner === 'operator') {
        const authentication = payload.authentication;
        if (!authentication) throw new Error('operator voucher signing requires authentication');
        if (authentication.challengeId !== context.challengeId) {
            throw new Error('session authentication challengeId does not match the open challenge');
        }
        if (authentication.payer !== payload.payer) {
            throw new Error('session authentication payer does not match the channel payer');
        }
        if (!(await verifySessionAuthentication(authentication, payload.channelId))) {
            throw new Error('invalid session authentication signature');
        }
    } else if (payload.authentication) {
        throw new Error('authentication is only valid when voucherSigner is operator');
    }

    const expected: VerifyOpenTxExpected = {
        authorizedSigner: payload.authorizedSigner,
        channelProgram: config.resolvedProgramId.toString(),
        currency: config.resolvedMint,
        feePayer: rentPayer,
        minimumDeposit: config.minimumDeposit,
        mint: config.resolvedMint,
        network: config.network,
        openSlot,
        recentBlockhash,
        recipient: config.recipient,
        rentPayer,
        splits: configuredSplits,
        tokenProgram: config.tokenProgram,
    };
    const verified = await verifyOpenTx({ expected, openPayload: payload });
    return {
        expected,
        open: {
            channelId: verified.channelId,
            deposit: verified.deposit,
            idleTimeoutSeconds,
            openSlot: verified.openSlot,
            payer: verified.payer,
            rentPayer,
        },
    };
}

interface HandleOpenArgs {
    readonly config: ResolvedSessionConfig;
    readonly context: SessionOpenChallenge;
    readonly externalId: string | undefined;
    readonly lifecycle: Lifecycle | undefined;
    readonly payload: OpenAction;
}

async function handleOpen(args: HandleOpenArgs): Promise<Receipt.Receipt> {
    const { config, context, payload } = args;
    const { expected, open: verified } = await validateOpen(config, payload, context);
    const { recentSlot } = context;
    const openSlot = verified.openSlot;
    const existingChannel = await config.store.getChannel(verified.channelId);
    if (!existingChannel) {
        const observedSlot = await currentClusterSlot(config.rpc);
        // A load-balanced RPC can serve getSlot from a replica one slot behind
        // the getLatestBlockhash context used for this server-signed challenge.
        // The challenge already bounds openSlot <= recentSlot, so use the newer
        // observation without weakening the future-slot or freshness checks.
        const verificationSlot = observedSlot < recentSlot ? recentSlot : observedSlot;
        if (verificationSlot - openSlot > OPEN_SLOT_WINDOW) {
            throw new Error(
                `open openSlot ${openSlot.toString()} is outside the ${OPEN_SLOT_WINDOW.toString()}-slot freshness window of the current cluster slot ${verificationSlot.toString()}`,
            );
        }
    }

    const newState: ChannelState = {
        authentication: payload.authentication,
        authorizedSigner: payload.authorizedSigner,
        channelId: verified.channelId,
        closeRequestedAt: undefined,
        committedDeliveries: [],
        cumulative: 0n,
        deposit: verified.deposit,
        highestVoucherExpiresAt: undefined,
        highestVoucherSignature: undefined,
        idleTimeoutSeconds: verified.idleTimeoutSeconds,
        lastActivityAt: Date.now(),
        nextDeliverySequence: 0n,
        openSlot: verified.openSlot,
        openingChallengeId: context.challengeId,
        payer: verified.payer,
        pendingDeliveries: [],
        processedUses: [],
        rentPayer: verified.rentPayer,
        schemaVersion: CHANNEL_STATE_SCHEMA_VERSION,
        sealed: false,
        settledOnChain: 0n,
        spentAmount: 0n,
        voucherSigner: config.voucherSigner,
    };

    // The existence check lives inside the atomic mutator so a concurrent
    // open replay cannot race a fresh create.
    const persisted = await config.store.updateChannel(verified.channelId, async current => {
        if (current) {
            if (current.sealed) {
                throw new Error(`Channel ${verified.channelId} is already sealed`);
            }
            if (
                payload.authorizedSigner !== current.authorizedSigner ||
                verified.payer !== current.payer ||
                verified.deposit !== current.deposit ||
                verified.openSlot !== current.openSlot ||
                verified.rentPayer !== current.rentPayer ||
                context.challengeId !== current.openingChallengeId ||
                config.voucherSigner !== current.voucherSigner ||
                !optionalSessionAuthenticationMatches(payload.authentication, current.authentication)
            ) {
                throw new Error(`open replay does not match existing channel ${verified.channelId}`);
            }
            // Idempotent replay: never reset the voucher watermark.
            return { ...current, lastActivityAt: Date.now() };
        }
        await submitOpenTx({
            expected,
            openPayload: payload,
            payerSigner: config.feePayer ? config.feePayerSigner : undefined,
            rpc: config.rpc as SubmitOpenRpc,
        });
        return newState;
    });
    args.lifecycle?.touch(verified.channelId, persisted.idleTimeoutSeconds);

    // txHash is reserved for the close receipt's settlement signature
    // (draft-solana-session-00 receipt table); open does not settle on-chain
    // funds, so it carries no txHash.
    return sessionReceipt(persisted, {
        challengeId: context.challengeId,
        externalId: args.externalId,
    });
}

// ─────────────────────────────────────────────────────────────────────
// use (operator-signed sessions)
// ─────────────────────────────────────────────────────────────────────

/** Requests a channel remembers for exactly-once `use` retries. Mirrors Rust `MAX_PROCESSED_USES`. */
const MAX_PROCESSED_USES = 256;

function checkIdempotencyKey(idempotencyKey: string): void {
    if (!idempotencyKey) throw new Error('operator-signed use requires an Idempotency-Key header');
}

/**
 * The checks a `use` proof must pass against the channel record: the channel
 * is operator-signed and bound at open to exactly this proof, which was issued
 * for the opening challenge by the payer and verifies over the channel id.
 * Mirrors `check_use_binding` in Rust.
 */
async function checkUseBinding(state: ChannelState, proof: SessionAuthentication): Promise<void> {
    // A record with no binding at all is not a mismatch: it either predates
    // proof binding or was rewritten by a pre-binding writer. Name it so the
    // client knows re-opening — not retrying the proof — is the fix.
    if (!state.openingChallengeId && !state.authentication) {
        throw new Error('session channel predates proof binding; open a new session');
    }
    if (
        state.voucherSigner !== 'operator' ||
        !state.authentication ||
        !sessionAuthenticationMatches(proof, state.authentication) ||
        proof.challengeId !== state.openingChallengeId ||
        proof.payer !== state.payer ||
        !(await verifySessionAuthentication(proof, state.channelId))
    ) {
        throw new Error('use authentication does not match the proof bound at open');
    }
}

function assertUseChannelOpen(state: ChannelState): void {
    if (state.sealed || state.closeRequestedAt !== undefined) {
        throw new Error('Channel is closed or close is pending');
    }
}

function recordUse(processedUses: readonly ProcessedUse[], entry: ProcessedUse): ProcessedUse[] {
    const kept = processedUses.filter(recorded => recorded.idempotencyKey !== entry.idempotencyKey);
    kept.push(entry);
    return kept.slice(Math.max(0, kept.length - MAX_PROCESSED_USES));
}

async function signOperatorVoucher(
    signer: MessagePartialSigner,
    channelId: string,
    cumulative: bigint,
): Promise<SignedVoucher> {
    const data = {
        channelId,
        cumulativeAmount: cumulative.toString(),
        expiresAt: DEFAULT_SESSION_EXPIRES_AT,
    };
    const [signatures] = await signer.signMessages([createSignableMessage(encodeVoucherMessageLoose(data))]);
    const signature = signatures?.[signer.address];
    if (!signature) throw new Error('operator voucher signer did not return a signature');
    return {
        signature: getBase58Decoder().decode(new Uint8Array(signature)),
        signatureType: 'ed25519',
        signer: signer.address,
        voucher: data,
    };
}

function recordedVoucher(channelId: string, signer: string, entry: ProcessedUse): SignedVoucher {
    return {
        signature: entry.voucherSignature,
        signatureType: 'ed25519',
        signer,
        voucher: {
            channelId,
            cumulativeAmount: entry.cumulative.toString(),
            expiresAt: DEFAULT_SESSION_EXPIRES_AT,
        },
    };
}

async function processUse(
    config: ResolvedSessionConfig,
    signer: MessagePartialSigner,
    payload: UseAction,
    challengeId: string,
    idempotencyKey: string,
    price: bigint,
): Promise<OperatorCharge> {
    if (price === 0n) throw new Error('session amount must be positive');
    checkIdempotencyKey(idempotencyKey);
    if (config.voucherSigner !== 'operator') {
        throw new Error('use is only valid for operator-signed sessions');
    }
    if (signer.address !== config.operator) {
        throw new Error('operator signing key does not match configured operator');
    }
    const existing = await config.store.getChannel(payload.channelId);
    if (!existing) throw new Error(`Channel ${payload.channelId} not found`);
    assertUseChannelOpen(existing);
    await checkUseBinding(existing, payload.authentication);

    let charge: OperatorCharge | undefined;
    await config.store.updateChannel(payload.channelId, async current => {
        if (!current) throw new Error(`Channel ${payload.channelId} not found`);
        assertUseChannelOpen(current);
        await checkUseBinding(current, payload.authentication);
        const replay = current.processedUses.find(use => use.idempotencyKey === idempotencyKey);
        if (replay) {
            charge = {
                charged: 0n,
                cumulative: replay.cumulative,
                replay: true,
                requestTotal: replay.amount ?? price,
                voucher: recordedVoucher(current.channelId, signer.address, replay),
            };
            return current;
        }
        const cumulative = current.cumulative + price;
        if (cumulative > current.deposit) throw new Error('insufficient channel availability');
        const voucher = await signOperatorVoucher(signer, current.channelId, cumulative);
        charge = { charged: price, cumulative, replay: false, requestTotal: price, voucher };
        return {
            ...current,
            cumulative,
            highestVoucherExpiresAt: BigInt(DEFAULT_SESSION_EXPIRES_AT),
            highestVoucherSignature: voucher.signature,
            lastActivityAt: Date.now(),
            processedUses: recordUse(current.processedUses, {
                amount: price,
                challengeId,
                cumulative,
                idempotencyKey,
                voucherSignature: voucher.signature,
            }),
            spentAmount: current.spentAmount + price,
        };
    });
    if (!charge) throw new Error('use did not produce a voucher');
    return charge;
}

async function authenticateUse(
    config: ResolvedSessionConfig,
    payload: UseAction,
    challengeId: string,
    idempotencyKey: string,
): Promise<AuthenticatedUse> {
    checkIdempotencyKey(idempotencyKey);
    if (config.voucherSigner !== 'operator') {
        throw new Error('use is only valid for operator-signed sessions');
    }
    const state = await config.store.getChannel(payload.channelId);
    if (!state) throw new Error(`Channel ${payload.channelId} not found`);
    assertUseChannelOpen(state);
    await checkUseBinding(state, payload.authentication);
    return { authentication: payload.authentication, challengeId, channelId: payload.channelId, idempotencyKey };
}

/**
 * What the request has been charged so far, if the channel records it. A key
 * recorded for another challenge, or without a total, names another request
 * and is refused. Mirrors `recorded_use` in Rust.
 */
function recordedUse(state: ChannelState, authenticated: AuthenticatedUse): ProcessedUse | undefined {
    const entry = state.processedUses.find(use => use.idempotencyKey === authenticated.idempotencyKey);
    if (!entry) return undefined;
    if (entry.amount === undefined || entry.challengeId !== authenticated.challengeId) {
        throw new Error('Idempotency-Key was already used for a different request');
    }
    return entry;
}

/** Bound on retries when a concurrent charge moves the watermark. Mirrors Rust `OPERATOR_CHARGE_ATTEMPTS`. */
const OPERATOR_CHARGE_ATTEMPTS = 8;

async function chargeOperatorRequest(
    config: ResolvedSessionConfig,
    authenticated: AuthenticatedUse,
    signer: MessagePartialSigner,
    requestTotal: bigint,
): Promise<OperatorCharge> {
    if (requestTotal <= 0n) throw new Error('operator charge amount must be positive');
    if (config.voucherSigner !== 'operator') {
        throw new Error('operator charges are only valid for operator-signed sessions');
    }
    if (signer.address !== config.operator) {
        throw new Error('operator signer does not match configured operator');
    }
    const { channelId } = authenticated;
    const assertBound = (state: ChannelState): void => {
        if (
            state.voucherSigner !== 'operator' ||
            !state.authentication ||
            !sessionAuthenticationMatches(authenticated.authentication, state.authentication)
        ) {
            throw new Error('use authentication does not match the proof bound at open');
        }
    };
    const replayed = (entry: ProcessedUse): OperatorCharge => ({
        charged: 0n,
        cumulative: entry.cumulative,
        replay: true,
        requestTotal: entry.amount ?? 0n,
        voucher: recordedVoucher(channelId, signer.address, entry),
    });
    for (let attempt = 0; attempt < OPERATOR_CHARGE_ATTEMPTS; attempt++) {
        const state = await config.store.getChannel(channelId);
        if (!state) throw new Error(`Channel ${channelId} not found`);
        assertUseChannelOpen(state);
        assertBound(state);
        const recorded = recordedUse(state, authenticated);
        if (recorded && (recorded.amount ?? 0n) >= requestTotal) return replayed(recorded);
        const chargedBefore = recorded?.amount ?? 0n;
        const delta = requestTotal - chargedBefore;
        const base = state.cumulative;
        const cumulative = base + delta;
        if (cumulative > state.deposit) throw new Error('insufficient channel availability');
        // Sign before the update so the signer may be remote; the update
        // commits only if nothing moved since this read.
        const voucher = await signOperatorVoucher(signer, channelId, cumulative);
        let outcome: OperatorCharge | 'moved' | undefined;
        await config.store.updateChannel(channelId, current => {
            if (!current) throw new Error('Channel not found');
            assertUseChannelOpen(current);
            assertBound(current);
            const latest = recordedUse(current, authenticated);
            if (latest && (latest.amount ?? 0n) >= requestTotal) {
                outcome = replayed(latest);
                return current;
            }
            if (current.cumulative !== base || (latest?.amount ?? 0n) !== chargedBefore) {
                outcome = 'moved';
                return current;
            }
            if (cumulative > current.deposit) throw new Error('insufficient channel availability');
            outcome = { charged: delta, cumulative, replay: false, requestTotal, voucher };
            return {
                ...current,
                cumulative,
                highestVoucherExpiresAt: BigInt(DEFAULT_SESSION_EXPIRES_AT),
                highestVoucherSignature: voucher.signature,
                lastActivityAt: Date.now(),
                processedUses: recordUse(current.processedUses, {
                    amount: requestTotal,
                    challengeId: authenticated.challengeId,
                    cumulative,
                    idempotencyKey: authenticated.idempotencyKey,
                    voucherSignature: voucher.signature,
                }),
                spentAmount: current.spentAmount + delta,
            };
        });
        if (outcome === 'moved') continue;
        if (!outcome) throw new Error('operator charge did not produce a voucher');
        return outcome;
    }
    throw new Error(`channel ${channelId} kept advancing concurrently; retry the request`);
}

// ─────────────────────────────────────────────────────────────────────
// voucher
// ─────────────────────────────────────────────────────────────────────

/** Rust `OPERATOR_VOUCHER_ERROR`. */
const OPERATOR_VOUCHER_ERROR =
    'a voucher does not authenticate an operator-signed session; present the session bearer proof (use)';

async function acceptVoucher(
    config: ResolvedSessionConfig,
    payload: VoucherAction,
    price: bigint,
): Promise<ChannelState> {
    if (price === 0n) throw new Error('session amount must be positive');
    // draft-solana-session-00: in operator mode, vouchers are
    // operator-generated settlement artifacts and MUST NOT authenticate the
    // caller; the caller authenticates with `use`.
    if (config.voucherSigner === 'operator') throw new Error(OPERATOR_VOUCHER_ERROR);
    const signed = normalizeSignedVoucher(payload.voucher);
    // The top-level channelId is the routing key; it must never diverge from
    // the signed voucher's inner channelId (spec: servers MUST reject the
    // action when the two differ).
    if (payload.channelId !== signed.voucher.channelId) {
        throw new Error(
            `invalid-voucher: voucher action channelId ${payload.channelId} does not match the signed voucher's channelId ${signed.voucher.channelId}`,
        );
    }
    const channelId = signed.voucher.channelId;
    const existing = await config.store.getChannel(channelId);
    if (!existing) throw new Error(`Channel ${channelId} not found`);
    if (existing.voucherSigner === 'operator') throw new Error(OPERATOR_VOUCHER_ERROR);

    const verify = (state: ChannelState) =>
        verifyVoucherForChannel({
            deposit: state.deposit,
            minVoucherDelta: config.minVoucherDelta,
            settlementWindow: config.settlementWindow,
            signed,
            state,
        });
    // Pre-flight reject for cheap cases (signature still checked atomically).
    rejectIfVoucherRejected(await verify(existing));

    // Atomic re-check inside the lock (mirrors the Rust closure pattern).
    return await config.store.updateChannel(channelId, async current => {
        if (!current) throw new Error(`Channel ${channelId} not found`);
        const result = await verify(current);
        rejectIfVoucherRejected(result);
        if (result.status === 'replayed') {
            // Each voucher authorizes one request; a replay changes no state.
            throw new Error('voucher was already accepted; sign a new voucher for this request');
        }
        if (result.status !== 'accepted') throw new Error('voucher was not accepted');
        if (result.newCumulative - current.spentAmount < price) {
            throw new Error('insufficient authorized voucher availability');
        }
        return {
            ...current,
            cumulative: result.newCumulative,
            highestVoucherExpiresAt: result.newExpiresAt,
            highestVoucherSignature: result.newSignature,
            lastActivityAt: Date.now(),
            spentAmount: current.spentAmount + price,
        };
    });
}

// ─────────────────────────────────────────────────────────────────────
// topUp
// ─────────────────────────────────────────────────────────────────────

/**
 * Every pre-broadcast check on a `topUp`: a positive `additionalAmount` for
 * a stored channel that is still open, then the transaction against the
 * stored channel and the fee-payer policy it was opened under.
 */
async function prepareTopUp(
    config: ResolvedSessionConfig,
    payload: TopUpAction,
): Promise<{ readonly additionalAmount: bigint; readonly existing: ChannelState; readonly sponsor: boolean }> {
    const additionalAmount = parseU64String(payload.additionalAmount, 'additionalAmount');
    if (additionalAmount === 0n) throw new Error('additionalAmount must be positive');
    const existing = await config.store.getChannel(payload.channelId);
    if (!existing) throw new Error(`Channel ${payload.channelId} not found`);
    assertTopUpChannelOpen(existing);
    // The channel's rent payer decides who pays the top-up's fee: the
    // configured sponsor when it opened the channel, else the payer.
    const sponsorSigner = config.feePayerSigner;
    if (config.feePayer && sponsorSigner?.address === existing.payer) {
        throw new Error('payment-channel payer must differ from the sponsored fee payer');
    }
    let sponsor: boolean;
    if (config.feePayer && sponsorSigner && sponsorSigner.address === existing.rentPayer) {
        sponsor = true;
    } else if (existing.rentPayer === existing.payer) {
        sponsor = false;
    } else if (config.feePayer && sponsorSigner) {
        throw new Error('configured session fee payer does not match the channel rentPayer');
    } else {
        throw new Error('sponsored session top-up requires the channel fee-payer signer');
    }
    await verifyTopUpTx({
        additionalAmount,
        channelId: payload.channelId,
        channelProgram: config.resolvedProgramId.toString(),
        feePayer: sponsor ? existing.rentPayer : existing.payer,
        mint: config.resolvedMint,
        payer: existing.payer,
        serverFeePayer: sponsor ? existing.rentPayer : undefined,
        tokenProgram: config.tokenProgram,
        transaction: payload.transaction,
    });
    return { additionalAmount, existing, sponsor };
}

function assertTopUpChannelOpen(state: ChannelState): void {
    if (state.sealed) throw new Error('Channel is already sealed');
    if (state.closeRequestedAt !== undefined) {
        throw new Error('Channel close is pending — no further top-ups accepted');
    }
}

interface HandleTopUpArgs {
    readonly challengeId: string | undefined;
    readonly config: ResolvedSessionConfig;
    readonly externalId: string | undefined;
    readonly lifecycle: Lifecycle | undefined;
    readonly payload: TopUpAction;
}

async function handleTopUp(args: HandleTopUpArgs): Promise<Receipt.Receipt> {
    const { config, payload } = args;
    const receiptOptions = { challengeId: args.challengeId, externalId: args.externalId };
    if (parseU64String(payload.additionalAmount, 'additionalAmount') === 0n) {
        throw new Error('additionalAmount must be positive');
    }
    // Idempotent replay: this exact transaction was already credited, so
    // report success without re-broadcasting (a re-broadcast of a landed
    // transaction fails at preflight).
    const topUpSignature = transactionSignatureFromWire(payload.transaction) as unknown as string;
    const stored = await config.store.getChannel(payload.channelId);
    if (stored?.processedTopUpSignatures?.includes(topUpSignature)) {
        // txHash is reserved for the close receipt's settlement signature
        // (draft-solana-session-00 receipt table); a top-up does not settle
        // on-chain funds itself, so it carries no txHash.
        return sessionReceipt(stored, receiptOptions);
    }

    const { additionalAmount, existing, sponsor } = await prepareTopUp(config, payload);

    await submitTopUpTx({
        additionalAmount,
        channelId: payload.channelId,
        channelProgram: config.resolvedProgramId.toString(),
        currentDeposit: existing.deposit,
        payer: existing.payer,
        payerSigner: sponsor ? config.feePayerSigner : undefined,
        rpc: config.rpc as SubmitOpenRpc,
        transaction: payload.transaction,
    });

    const result = await config.store.updateChannel(payload.channelId, current => {
        if (!current) throw new Error(`Channel ${payload.channelId} not found`);
        // Signature dedupe must live inside the atomic mutator: two
        // in-flight submissions of the same signed top-up both confirm the
        // same landed transaction, so only the first check-and-record may
        // credit the deposit.
        if (current.processedTopUpSignatures?.includes(topUpSignature)) return current;
        assertTopUpChannelOpen(current);
        return {
            ...current,
            deposit: current.deposit + additionalAmount,
            lastActivityAt: Date.now(),
            processedTopUpSignatures: [...(current.processedTopUpSignatures ?? []), topUpSignature],
        };
    });
    args.lifecycle?.touch(result.channelId, result.idleTimeoutSeconds);

    return sessionReceipt(result, receiptOptions);
}

// ─────────────────────────────────────────────────────────────────────
// close
// ─────────────────────────────────────────────────────────────────────

/**
 * Accept the optional final voucher and flip the channel to close-pending
 * atomically. Mirrors `process_close` in Rust, before settlement.
 */
async function recordClose(
    config: ResolvedSessionConfig,
    payload: CloseAction,
    options: { readonly retrySettle?: boolean } = {},
): Promise<ChannelState> {
    const channelId = payload.channelId;
    // Same routing-key invariant as the voucher action: a final voucher
    // nested in a close must be bound to the channel being closed.
    if (payload.voucher && payload.voucher.voucher.channelId !== channelId) {
        throw new Error(
            `invalid-voucher: close voucher channelId ${payload.voucher.voucher.channelId} does not match the close channelId ${channelId}`,
        );
    }
    const now = BigInt(Math.floor(Date.now() / 1000));

    return await config.store.updateChannel(channelId, async current => {
        if (!current) throw new Error(`Channel ${channelId} not found`);
        if (current.sealed) throw new Error('Channel is already sealed');
        // A close is recorded once (Rust `process_close`). The method handler
        // alone lets a repeated close through while the recorded close has
        // not settled yet, so a settlement that failed can be retried.
        const settleRetry =
            options.retrySettle === true &&
            current.closeRequestedAt !== undefined &&
            current.settledSignature === undefined;
        if (current.closeRequestedAt !== undefined && !settleRetry) throw new Error('Close already requested');
        // A close that presents authentication against a record with no proof
        // binding (and no operator marker) is an operator-signed session whose
        // record predates — or was stripped of — the binding fields.
        if (
            payload.authentication &&
            current.voucherSigner !== 'operator' &&
            !current.openingChallengeId &&
            !current.authentication
        ) {
            throw new Error('session channel predates proof binding; the lifecycle worker will close it');
        }
        if (current.voucherSigner === 'operator') {
            if (payload.voucher) throw new Error('operator-mode close must not include a voucher');
            if (!payload.authentication) {
                throw new Error('operator-mode close requires the bound authentication proof');
            }
            if (!current.authentication && !current.openingChallengeId) {
                throw new Error('session channel predates proof binding; the lifecycle worker will close it');
            }
            if (
                !current.authentication ||
                !sessionAuthenticationMatches(payload.authentication, current.authentication) ||
                payload.authentication.challengeId !== current.openingChallengeId ||
                payload.authentication.payer !== current.payer ||
                !(await verifySessionAuthentication(payload.authentication, channelId))
            ) {
                throw new Error('close authentication does not match the proof bound at open');
            }
        } else {
            if (payload.authentication) throw new Error('client-mode close must not include authentication');
            if (!payload.voucher) throw new Error('client-mode close requires a voucher');
        }
        if (settleRetry) return current;

        // Uncommitted reservations are not billed. Here they come only from
        // `POST /__402/session/deliveries`, which checks no credential and has
        // no release: a reservation proves neither that the payer asked for
        // it nor that anything was delivered, so billing it would let anyone
        // who knows the channel id charge the payer (or block its close).
        // Rust bills `PendingDelivery::owed_at_close` because there the host
        // itself creates reservations for responses it sends; TypeScript has
        // no such host-created reservation yet.

        if (payload.voucher) {
            const signed = normalizeSignedVoucher(payload.voucher);
            // Route the final voucher (replay AND advancing) through the verifier
            // so expiry + the settlement-window margin are enforced on both paths —
            // an idempotent replay must not record close-pending against a voucher
            // that no longer outlasts the window, or the async settle fails on-chain.
            const verdict = await verifyVoucherForChannel({
                deposit: current.deposit,
                settlementWindow: config.settlementWindow,
                signed,
                state: current,
            });
            // Mirrors Rust `process_close`: a final voucher that fails
            // verification — a non-replay at/below the watermark, or an expiry
            // that no longer outlasts the settlement window even on replay — is
            // a hard error; the close aborts rather than settle a stale amount.
            rejectIfVoucherRejected(verdict);
            if (verdict.status === 'accepted') {
                return {
                    ...current,
                    closeRequestedAt: now,
                    cumulative: verdict.newCumulative,
                    highestVoucherExpiresAt: verdict.newExpiresAt,
                    highestVoucherSignature: verdict.newSignature,
                };
            }
            // Idempotent replay of the current highest voucher: watermark
            // unchanged; signature + expiry/window already re-verified above.
        }
        return { ...current, closeRequestedAt: now };
    });
}

interface HandleCloseArgs {
    readonly challengeId: string | undefined;
    readonly config: ResolvedSessionConfig;
    readonly externalId: string | undefined;
    readonly lifecycle: Lifecycle | undefined;
    readonly merchantSigner: TransactionPartialSigner | undefined;
    readonly payload: CloseAction;
}

async function handleClose(args: HandleCloseArgs): Promise<Receipt.Receipt> {
    const { config } = args;
    const channelId = args.payload.channelId;
    await recordClose(config, args.payload, { retrySettle: true });

    let onChainSignature: string | undefined;
    if (args.merchantSigner) {
        const closed = await closeAndSettleChannel({
            channelId,
            currency: config.currency,
            decimals: config.resolvedDecimals,
            merchantSigner: args.merchantSigner,
            mint: config.resolvedMint,
            network: config.network,
            programId: config.resolvedProgramId,
            recipient: config.recipient,
            rentPayer: config.feePayerSigner?.address,
            rpc: config.rpc,
            splits: config.distributionSplits?.map(split => ({ bps: split.shareBps, recipient: split.recipient })),
            store: config.store,
            tokenProgram: config.tokenProgram,
        });
        onChainSignature = closed?.signature as unknown as string | undefined;
    }

    args.lifecycle?.removeChannel(channelId);

    const finalState = await config.store.getChannel(channelId);
    if (!finalState) throw new Error(`Channel ${channelId} not found after close`);
    return sessionReceipt(finalState, {
        challengeId: args.challengeId,
        externalId: args.externalId,
        refunded: finalState.deposit - finalState.cumulative,
        txHash: onChainSignature,
    });
}

interface SessionReceiptOptions {
    readonly challengeId: string | undefined;
    readonly externalId: string | undefined;
    readonly refunded?: bigint | undefined;
    readonly txHash?: string | undefined;
}

/** Build the receipt extension required by draft-solana-session-00. */
function sessionReceipt(state: ChannelState, options: SessionReceiptOptions): SessionReceipt {
    if (state.idleTimeoutSeconds === undefined) {
        throw new Error(`Channel ${state.channelId} is missing its negotiated idle timeout`);
    }
    return {
        acceptedCumulative: state.cumulative.toString(),
        ...(options.challengeId ? { challengeId: options.challengeId } : {}),
        ...(options.externalId ? { externalId: options.externalId } : {}),
        idleTimeoutSeconds: state.idleTimeoutSeconds,
        intent: 'session',
        method: 'solana',
        reference: state.channelId,
        ...(options.refunded !== undefined ? { refunded: options.refunded.toString() } : {}),
        spent: state.spentAmount.toString(),
        status: 'success',
        timestamp: new Date().toISOString(),
        ...(options.txHash ? { txHash: options.txHash } : {}),
    };
}

async function currentClusterSlot(rpc: RpcLike): Promise<bigint> {
    const getSlot = (rpc as { getSlot?: (config?: { commitment?: string }) => { send(): Promise<bigint> } }).getSlot;
    if (!getSlot) throw new Error('open freshness validation requires an RPC getSlot method');
    try {
        return await getSlot.call(rpc, { commitment: 'confirmed' }).send();
    } catch (error) {
        throw new Error(`failed to fetch current cluster slot for session open: ${String(error)}`);
    }
}

function sessionAuthenticationMatches(left: SessionAuthentication, right: SessionAuthentication): boolean {
    return (
        left.type === right.type &&
        left.challengeId === right.challengeId &&
        left.payer === right.payer &&
        left.signature === right.signature
    );
}

function optionalSessionAuthenticationMatches(
    left: SessionAuthentication | undefined,
    right: SessionAuthentication | undefined,
): boolean {
    if (left === undefined || right === undefined) return left === right;
    return sessionAuthenticationMatches(left, right);
}

// ─────────────────────────────────────────────────────────────────────
// Delivery reservation + commit (shared by Methods and routes)
// ─────────────────────────────────────────────────────────────────────

interface ReserveDeliveryArgs {
    readonly amount: bigint;
    readonly commitUrl?: string | undefined;
    readonly currency: string;
    readonly deliveryId?: string | undefined;
    readonly expiresAt: number;
    readonly proof?: string | undefined;
    readonly sessionId: string;
}

async function reserveDelivery(store: SessionStore, args: ReserveDeliveryArgs): Promise<MeteringDirective> {
    if (args.amount <= 0n) throw new Error('amount must be positive');

    let directive: MeteringDirective | undefined;
    await store.updateChannel(args.sessionId, current => {
        if (!current) throw new Error(`Channel ${args.sessionId} not found`);
        if (current.sealed) throw new Error('Channel is already sealed');
        if (current.closeRequestedAt !== undefined) {
            throw new Error('Channel close is pending — no further deliveries accepted');
        }

        const pendingTotal = current.pendingDeliveries.reduce((sum, p) => sum + p.amount, 0n);
        if (current.cumulative + pendingTotal + args.amount > current.deposit) {
            throw new Error(`Delivery amount ${args.amount} exceeds available deposit`);
        }

        const sequence = current.nextDeliverySequence + 1n;
        const deliveryId = args.deliveryId ?? `${args.sessionId}:${sequence.toString()}`;
        if (
            current.pendingDeliveries.some(p => p.deliveryId === deliveryId) ||
            current.committedDeliveries.some(c => c.deliveryId === deliveryId)
        ) {
            throw new Error(`Delivery ${deliveryId} already exists`);
        }
        const pending: PendingDelivery = {
            amount: args.amount,
            deliveryId,
            expiresAt: BigInt(args.expiresAt),
            sequence,
        };
        directive = {
            amount: args.amount.toString(),
            ...(args.commitUrl ? { commitUrl: args.commitUrl } : {}),
            currency: args.currency,
            deliveryId,
            expiresAt: args.expiresAt,
            ...(args.proof ? { proof: args.proof } : {}),
            sequence: Number(sequence),
            sessionId: args.sessionId,
        };
        return {
            ...current,
            nextDeliverySequence: sequence,
            pendingDeliveries: [...current.pendingDeliveries, pending],
        };
    });

    if (!directive) throw new Error('Delivery reservation did not produce a directive');
    return directive;
}

interface CommitDeliveryArgs {
    readonly deliveryId: string;
    /** Reject a final-commit voucher expiring within `now + settlementWindow`
     * so a committed delivery can't expire before the async settle lands. */
    readonly settlementWindow: bigint | undefined;
    readonly voucher: SignedVoucher;
}

async function commitDelivery(store: SessionStore, args: CommitDeliveryArgs): Promise<CommitReceipt> {
    const signed = normalizeSignedVoucher(args.voucher);
    const channelId = signed.voucher.channelId;
    const newCumulative = parseU64String(signed.voucher.cumulativeAmount, 'cumulativeAmount');
    const now = BigInt(Math.floor(Date.now() / 1000));

    let outcome: { amount: bigint; cumulative: bigint; status: 'committed' | 'replayed' } | undefined;
    await store.updateChannel(channelId, async current => {
        if (!current) throw new Error(`Channel ${channelId} not found`);
        if (current.sealed) throw new Error('Channel is already sealed');
        if (current.closeRequestedAt !== undefined) {
            throw new Error('Channel close is pending — no further commits accepted');
        }

        // Idempotent replay window.
        const committed = current.committedDeliveries.find(c => c.deliveryId === args.deliveryId);
        if (committed) {
            if (committed.cumulative === newCumulative && committed.voucherSignature === signed.signature) {
                // Mirrors Rust `process_commit`: the replay path still
                // re-verifies the voucher signature.
                await assertVoucherSignature(signed, current.authorizedSigner);
                outcome = { amount: committed.amount, cumulative: committed.cumulative, status: 'replayed' };
                return current;
            }
            throw new Error(`Delivery ${args.deliveryId} was already committed with a different voucher`);
        }

        const pendingIdx = current.pendingDeliveries.findIndex(p => p.deliveryId === args.deliveryId);
        if (pendingIdx < 0) throw new Error(`Delivery ${args.deliveryId} not found`);
        const pending = current.pendingDeliveries[pendingIdx];
        if (pending.expiresAt <= now) throw new Error(`Delivery ${args.deliveryId} has expired`);
        if (newCumulative <= current.cumulative) {
            throw new Error(`Commit cumulative ${newCumulative} must exceed watermark ${current.cumulative}`);
        }
        const actualAmount = newCumulative - current.cumulative;
        if (actualAmount > pending.amount) {
            throw new Error(`Commit amount ${actualAmount} exceeds reserved amount ${pending.amount}`);
        }

        // Verify signature on the voucher (matches Rust process_commit).
        const verdict = await verifyVoucherForChannel({
            deposit: current.deposit,
            settlementWindow: args.settlementWindow,
            signed,
            state: current,
        });
        if (verdict.status === 'rejected') {
            throw new Error(`${verdict.reason}: ${verdict.detail}`);
        }

        const nextPending = current.pendingDeliveries.filter((_, i) => i !== pendingIdx);
        const committedDelivery: CommittedDelivery = {
            amount: actualAmount,
            cumulative: newCumulative,
            deliveryId: args.deliveryId,
            voucherSignature: signed.signature,
        };
        outcome = { amount: actualAmount, cumulative: newCumulative, status: 'committed' };
        return {
            ...current,
            committedDeliveries: [...current.committedDeliveries, committedDelivery],
            cumulative: newCumulative,
            highestVoucherExpiresAt: BigInt(signed.voucher.expiresAt ?? 0),
            highestVoucherSignature: signed.signature,
            lastActivityAt: Date.now(),
            pendingDeliveries: nextPending,
            spentAmount: current.spentAmount + actualAmount,
        };
    });

    if (!outcome) throw new Error('Commit did not produce a receipt');
    return {
        amount: outcome.amount.toString(),
        cumulative: outcome.cumulative.toString(),
        deliveryId: args.deliveryId,
        sessionId: channelId,
        status: outcome.status,
    };
}

// ─────────────────────────────────────────────────────────────────────
// Close + settle + distribute orchestration
// ─────────────────────────────────────────────────────────────────────

interface CloseAndSettleArgs {
    readonly channelId: string;
    readonly currency: string;
    readonly decimals: number | undefined;
    readonly merchantSigner: TransactionPartialSigner;
    readonly mint: string;
    readonly network: string;
    readonly programId: Address;
    readonly recipient: string;
    readonly rentPayer: string | undefined;
    readonly rpc: RpcLike;
    readonly splits: readonly { readonly bps: number; readonly recipient: string }[] | undefined;
    readonly store: SessionStore;
    readonly tokenProgram: string;
}

/**
 * Build + submit settle_and_seal (+ optional Ed25519 precompile) +
 * distribute IXs for a channel that has already flipped to
 * `closeRequestedAt`. Marks the channel as sealed on success.
 *
 * Returns `undefined` when the channel cannot be settled (e.g. no
 * highest voucher recorded — nothing to settle).
 */
async function closeAndSettleChannel(args: CloseAndSettleArgs): Promise<SubmitSettleAndDistributeResult | undefined> {
    const state = await args.store.getChannel(args.channelId);
    if (!state) return undefined;

    let voucher: { authorizedSigner: string; signed: SignedVoucher } | undefined;
    if (state.highestVoucherSignature && state.highestVoucherExpiresAt !== undefined && state.cumulative > 0n) {
        voucher = {
            authorizedSigner: state.authorizedSigner,
            signed: {
                signature: state.highestVoucherSignature,
                signatureType: 'ed25519',
                signer: state.authorizedSigner,
                voucher: {
                    channelId: args.channelId,
                    cumulativeAmount: state.cumulative.toString(),
                    expiresAt: Number(state.highestVoucherExpiresAt),
                },
            },
        };
    }

    const result = await submitSettleAndDistribute({
        buildAndSignWireTransaction: instructions =>
            buildAndSignWireTransaction(
                args.rpc as unknown as Parameters<typeof buildAndSignWireTransaction>[0],
                args.merchantSigner as unknown as TransactionSigner,
                instructions,
            ),
        channelId: args.channelId,
        currency: args.currency,
        mint: args.mint,
        network: args.network,
        payee: args.recipient,
        payer: state.payer,

        programId: args.programId,
        rentPayer: state.rentPayer,
        rpc: args.rpc as unknown as SettleRpc,
        signer: args.merchantSigner as unknown as TransactionSigner,
        splits: args.splits ?? [],
        tokenProgram: args.tokenProgram,
        voucher,
    });

    await args.store.updateChannel(args.channelId, current => {
        if (!current) throw new Error(`Channel ${args.channelId} disappeared during settle`);
        return {
            ...current,
            sealed: true,
            settledOnChain: current.cumulative,
            settledSignature: result.signature as unknown as string,
        };
    });
    return result;
}

// ─────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────

function rejectIfVoucherRejected(result: VoucherVerifyResult): void {
    if (result.status === 'rejected') {
        throw new Error(`${result.reason}: ${result.detail}`);
    }
}

/** Throw unless the voucher's Ed25519 signature verifies against `authorizedSigner`. */
async function assertVoucherSignature(signed: SignedVoucher, authorizedSigner: string): Promise<void> {
    if (signed.signatureType !== 'ed25519' || signed.signer !== authorizedSigner) {
        throw new Error('invalid-signature: voucher signer does not match the channel');
    }
    let valid = false;
    try {
        valid = await verifyVoucherSignature({
            signatureBase58: signed.signature,
            signerBase58: authorizedSigner,
            voucher: signed.voucher,
        });
    } catch (error) {
        throw new Error(`invalid-signature: ${errorMessage(error)}`);
    }
    if (!valid) {
        throw new Error('invalid-signature: Voucher signature verification failed');
    }
}

function parseU64String(value: string, name: string): bigint {
    if (!/^\d+$/.test(value)) throw new Error(`${name} is not an unsigned integer string: ${value}`);
    const parsed = BigInt(value);
    if (parsed < 0n || parsed > (1n << 64n) - 1n) throw new Error(`${name} outside u64 range`);
    return parsed;
}

function errorMessage(error: unknown): string {
    if (error instanceof Error) return error.message;
    return String(error);
}

function jsonError(status: number, message: string): Response {
    return Response.json({ error: message }, { status });
}

// ─────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────

/**
 * RPC client accepted by {@link session}: a full `createSolanaRpc` client or
 * any object exposing the `getSignatureStatuses` / `sendTransaction` subset
 * the session lifecycle uses.
 */
export type RpcLike = ReturnType<typeof createSolanaRpc> | SubmitOpenRpc;

/** Minimal RPC subset used to verify open transactions. */
export type VerifyOpenRpc = {
    getSignatureStatuses(signatures: readonly Signature[]): {
        send(): Promise<{ value: ReadonlyArray<{ err: unknown } | null> }>;
    };
};

/** Minimal RPC subset used to verify and submit open transactions. */
export type SubmitOpenRpc = VerifyOpenRpc & {
    getAccountInfo(address: Address, config?: unknown): { send(): Promise<unknown> };
    /**
     * Optional: lets a narrow RPC serve fresh-challenge issuance too. A
     * new-channel 402 needs `recentBlockhash`/`recentSlot` from one
     * `getLatestBlockhash` call; without this (or a `blockhashCache`) the
     * challenge fails rather than degrade.
     */
    getLatestBlockhash?(config?: unknown): {
        send(): Promise<{ context: { slot: bigint | number }; value: { blockhash: string } }>;
    };
    sendTransaction(wire: string, config?: unknown): { send(): Promise<Signature> };
};

type CredentialPayload = {
    challenge: {
        expires?: string;
        id?: string;
        request: SessionRequest;
    };
    payload: SessionAction;
};

interface DeliveryRequestBody {
    amount: string;
    commitUrl?: string;
    deliveryId?: string;
    expiresAt?: number;
    proof?: string;
    sessionId: string;
}

interface CommitRequestBody {
    deliveryId: string;
    voucher: SignedVoucher;
}

export declare namespace session {
    interface RoutesHandlers {
        /** POST handler — commit a reserved delivery. */
        readonly commit: (request: Request) => Promise<Response>;
        /** POST handler — reserve a metered delivery. */
        readonly deliveries: (request: Request) => Promise<Response>;
    }

    /**
     * One cached `getLatestBlockhash` observation: the blockhash from
     * `result.value.blockhash` plus the slot from `result.context.slot`.
     */
    interface CachedBlockhash {
        readonly blockhash: string;
        readonly slot: bigint | number;
    }

    /**
     * Host-refreshed recent-blockhash cache shared with challenge issuance,
     * so the challenge's `recentBlockhash`/`recentSlot` come from one cached
     * `getLatestBlockhash` instead of a blocking RPC round-trip per 402.
     * Return `undefined` when empty or stale to fall back to a direct fetch.
     * Mirrors `SessionServer::with_blockhash_cache` in the Rust SDK.
     */
    interface BlockhashCache {
        get(): CachedBlockhash | undefined;
    }

    interface Parameters {
        /** Price per unit of service, in base units. */
        readonly amount: bigint;
        /**
         * Optional shared recent-blockhash cache consulted before the direct
         * `getLatestBlockhash` fallback when issuing new-channel challenges.
         */
        readonly blockhashCache?: BlockhashCache;
        /** Payment-channels program ID. */
        readonly channelProgram?: Address | string;
        /** Currency identifier (e.g. 'USDC' or an SPL mint address). */
        readonly currency: string;
        /** Token decimals (default 6). */
        readonly decimals?: number;
        /** Ordered split preimage proposed by the merchant. */
        readonly distributionSplits?: readonly SessionSplit[];
        /** Whether the server sponsors the open transaction fee. */
        readonly feePayer?: boolean;
        /** Signer that sponsors fees and channel rent when `feePayer` is true. */
        readonly feePayerSigner?: TransactionPartialSigner;
        /**
         * Forced-close grace period written into new channels, in seconds.
         * Defaults to 900 (the Rust `DEFAULT_GRACE_PERIOD_SECONDS`).
         */
        readonly gracePeriodSeconds?: number;
        /** Inactivity thresholds offered to clients for a new channel. */
        readonly idleTimeoutOptionsSeconds?: readonly number[];
        /** Server-selected inactivity threshold in seconds. Defaults to 300. */
        readonly idleTimeoutSeconds?: number;
        /** Minimum voucher increment in base units. Defaults to 0. */
        readonly minVoucherDelta?: bigint;
        /** Minimum accepted initial deposit. */
        readonly minimumDeposit?: bigint;
        /** Solana network. Defaults to 'mainnet'. */
        readonly network?: string;
        /**
         * The operator's address: the voucher signer of an operator-signed
         * session. Defaults to `operatorVoucherSigner.address`; a
         * {@link createSessionServer} that only verifies opens and closes
         * needs the address alone.
         */
        readonly operator?: string;
        /** Ed25519 signer used to create cumulative vouchers in operator mode. */
        readonly operatorVoucherSigner?: MessagePartialSigner;
        /** Primary recipient (base58). */
        readonly recipient: string;
        /** RPC client used to submit, confirm, and verify channel transactions. */
        readonly rpc: RpcLike;
        /**
         * Settlement window in seconds — the forced-close grace period a
         * non-zero voucher `expiresAt` must outlast. When set, a voucher
         * whose `expiresAt` falls within `now + settlementWindowSeconds`
         * is rejected (`expires-within-settlement-window`) so the merchant
         * can still land an async settle_and_seal before it expires.
         * A voucher with `expiresAt == 0` never expires and is unaffected.
         * Defaults to 0 (window check disabled). Typically set to the
         * channel `gracePeriod`.
         */
        readonly settlementWindowSeconds?: bigint;
        /** Merchant signer for settle_and_seal + distribute IXs. */
        readonly signer: TransactionPartialSigner;
        /** Pluggable session store. Defaults to in-memory. */
        readonly store?: SessionStore;
        /** Suggested initial deposit. */
        readonly suggestedDeposit?: bigint;
        /** SPL token program (TOKEN_PROGRAM or TOKEN_2022_PROGRAM). Defaults from currency/network. */
        readonly tokenProgram?: string;
        /** Unit priced by `amount`. */
        readonly unitType?: string;
        /** Voucher signing authority advertised by this session. */
        readonly voucherSigner?: SessionVoucherSigner;
    }
}
