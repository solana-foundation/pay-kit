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
    OPEN_SLOT_WINDOW,
    PAYMENT_CHANNELS_PROGRAM_ID,
    submitOpenTx,
    submitSettleAndDistribute,
    type SubmitSettleAndDistributeResult,
    submitTopUpTx,
    transactionSignatureFromWire,
    verifyOpenTx,
} from './session/on-chain.js';
import {
    CHANNEL_STATE_SCHEMA_VERSION,
    type ChannelState,
    type CommittedDelivery,
    createMemorySessionStore,
    type PendingDelivery,
    type SessionStore,
} from './session/store.js';
import { verifyVoucherForChannel, type VoucherVerifyResult } from './session/voucher.js';
import { buildAndSignWireTransaction } from './session/wire-tx.js';

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
        gracePeriodSeconds,
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
    if (voucherSigner === 'operator' && !operatorVoucherSigner) {
        throw new Error('operatorVoucherSigner is required when voucherSigner is operator');
    }
    const operator = operatorVoucherSigner?.address;
    const store = resolveSessionStore(parameters);
    const resolvedProgramId = (channelProgram ?? PAYMENT_CHANNELS_PROGRAM_ID) as Address;
    const resolvedMint = resolveStablecoinMint(currency, network);
    if (!resolvedMint) throw new Error('session currency must be an SPL token mint; use wrapped SOL instead of SOL');
    const resolvedDecimals = decimals ?? (stablecoinSymbolForCurrency(resolvedMint) ? 6 : undefined);
    if (resolvedDecimals === undefined) throw new Error('decimals is required for a session SPL token mint');
    if (!Number.isInteger(resolvedDecimals) || resolvedDecimals < 0 || resolvedDecimals > 9) {
        throw new Error('decimals must be an integer from 0 to 9');
    }
    const tokenProgram = parameters.tokenProgram ?? defaultTokenProgramForCurrency(currency, network);
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

            switch (action) {
                case 'open':
                    assertChallengeOpenNotExpired(cred.challenge.expires);
                    return await handleOpen({
                        challengeId: cred.challenge.id,
                        currency: resolvedMint,
                        distributionSplits,
                        externalId: cred.challenge.request.externalId,
                        feePayer,
                        feePayerSigner,
                        gracePeriodSeconds,
                        idleTimeoutOptionsSeconds,
                        idleTimeoutSeconds,
                        lifecycle: lifecycleRef.value,
                        minimumDeposit,
                        mint: resolvedMint,
                        network,
                        // Verified outer challenge facts the open is bound to
                        // (mirrors the Rust SessionOpenContext): the challenged
                        // blockhash + slot flow from the (HMAC-verified) echoed
                        // challenge into open verification.
                        openContext: challengedOpenContext(cred.challenge.request),
                        operator,
                        payload: cred.payload,
                        programId: resolvedProgramId,
                        recipient,
                        rpc,
                        store,
                        tokenProgram,
                        voucherSigner,
                    });
                case 'use':
                    if (!operatorVoucherSigner) {
                        throw new Error('use is only valid when voucherSigner is operator');
                    }
                    return await handleUse({
                        challengeId: cred.challenge.id,
                        externalId: cred.challenge.request.externalId,
                        idempotencyKey: envelope?.capturedRequest.headers.get('Idempotency-Key') ?? '',
                        lifecycle: lifecycleRef.value,
                        operatorVoucherSigner,
                        payload: cred.payload,
                        price: parseU64String(cred.challenge.request.amount, 'amount'),
                        store,
                    });
                case 'voucher':
                    return await handleVoucher({
                        challengeId: cred.challenge.id,
                        externalId: cred.challenge.request.externalId,
                        lifecycle: lifecycleRef.value,
                        minVoucherDelta,
                        payload: cred.payload,
                        price: parseU64String(cred.challenge.request.amount, 'amount'),
                        settlementWindow: settlementWindowSeconds,
                        store,
                    });
                case 'topUp':
                    return await handleTopUp({
                        challengeId: cred.challenge.id,
                        channelProgram: resolvedProgramId.toString(),
                        externalId: cred.challenge.request.externalId,
                        lifecycle: lifecycleRef.value,
                        payload: cred.payload,
                        rpc,
                        store,
                    });
                case 'close':
                    return await handleClose({
                        challengeId: cred.challenge.id,
                        currency,
                        decimals: resolvedDecimals,
                        externalId: cred.challenge.request.externalId,
                        lifecycle: lifecycleRef.value,
                        merchantSigner: signer,
                        mint: resolvedMint,
                        network,
                        payload: cred.payload,
                        programId: resolvedProgramId,
                        recipient,
                        rentPayer: feePayerSigner?.address,
                        rpc,
                        settlementWindow: settlementWindowSeconds,
                        splits: distributionSplits?.map(split => ({ bps: split.shareBps, recipient: split.recipient })),
                        store,
                        tokenProgram,
                    });
                default:
                    throw new Error(`Unknown session action: ${String(action)}`);
            }
        },
    });

    return method;
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
                const directive = await reserveDelivery(store, {
                    amount,
                    commitUrl: body.commitUrl,
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

interface HandleOpenArgs {
    readonly challengeId: string | undefined;
    readonly currency: string;
    /** Server-configured splits the challenge advertised; the open must encode exactly these. */
    readonly distributionSplits: readonly SessionSplit[] | undefined;
    readonly externalId: string | undefined;
    readonly feePayer: boolean;
    readonly feePayerSigner: TransactionPartialSigner | undefined;
    readonly gracePeriodSeconds: number | undefined;
    readonly idleTimeoutOptionsSeconds: readonly number[] | undefined;
    readonly idleTimeoutSeconds: number;
    readonly lifecycle: Lifecycle | undefined;
    readonly minimumDeposit: bigint | undefined;
    readonly mint: string;
    readonly network: string;
    readonly openContext: SessionOpenContext;
    readonly operator: string | undefined;
    readonly payload: OpenPayload & { readonly action: 'open' };
    readonly programId: Address;
    readonly recipient: string;
    readonly rpc: RpcLike;
    readonly store: SessionStore;
    readonly tokenProgram: string;
    readonly voucherSigner: SessionVoucherSigner;
}

async function handleOpen(args: HandleOpenArgs): Promise<Receipt.Receipt> {
    const { payload } = args;
    const authorizedSigner = address(payload.authorizedSigner);
    if (isOffCurveAddress(authorizedSigner)) {
        throw new Error('open authorizedSigner must be an on-curve Ed25519 public key');
    }
    if (args.voucherSigner === 'operator' && (!args.operator || payload.authorizedSigner !== args.operator)) {
        throw new Error('operator voucher signing requires authorizedSigner to match the operator');
    }
    if (args.voucherSigner === 'client' && payload.authentication) {
        throw new Error('authentication is only valid when voucherSigner is operator');
    }

    if (args.gracePeriodSeconds === undefined || args.gracePeriodSeconds <= 0) {
        throw new Error('challenge must specify a positive gracePeriodSeconds');
    }
    if (payload.gracePeriodSeconds !== args.gracePeriodSeconds) {
        throw new Error('open gracePeriodSeconds does not match the challenge');
    }
    const openSlot = parseU64String(payload.openSlot, 'openSlot');
    // Bind the open to the specific challenge that authorized it: the client
    // takes `openSlot` from the challenged `recentSlot` (an earlier slot is
    // allowed, a later one never is), so a payload outside this window was
    // not built against this challenge. Mirrors `process_open` in the Rust
    // SessionServer.
    const { recentBlockhash, recentSlot } = args.openContext;
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
    const rentPayer = args.feePayer ? args.feePayerSigner?.address : payload.payer;
    if (!rentPayer) throw new Error('unable to determine channel rent payer');
    const expected = {
        authorizedSigner: payload.authorizedSigner,
        channelProgram: args.programId.toString(),
        currency: args.currency,
        feePayer: rentPayer,
        minimumDeposit: args.minimumDeposit,
        mint: args.mint,
        network: args.network,
        openSlot,
        recentBlockhash,
        recipient: args.recipient,
        rentPayer,
        splits: args.distributionSplits ?? [],
        tokenProgram: args.tokenProgram,
    };
    const verified = await verifyOpenTx({ expected, openPayload: payload });
    const existingChannel = await args.store.getChannel(verified.channelId);
    if (!existingChannel) {
        const currentSlot = await currentClusterSlot(args.rpc);
        if (openSlot > currentSlot) {
            throw new Error(`open openSlot ${openSlot.toString()} is ahead of the current cluster slot ${currentSlot}`);
        }
        if (currentSlot - openSlot > OPEN_SLOT_WINDOW) {
            throw new Error(
                `open openSlot ${openSlot.toString()} is outside the ${OPEN_SLOT_WINDOW.toString()}-slot freshness window of the current cluster slot ${currentSlot.toString()}`,
            );
        }
    }

    const effectiveIdleTimeoutSeconds = resolveIdleTimeoutSeconds({
        defaultSeconds: args.idleTimeoutSeconds,
        options: args.idleTimeoutOptionsSeconds,
        selected: payload.idleTimeoutSeconds,
    });
    if (args.voucherSigner === 'operator') {
        const authentication = payload.authentication;
        if (!authentication) throw new Error('operator voucher signing requires authentication');
        if (authentication.challengeId !== args.challengeId) {
            throw new Error('session authentication challengeId does not match the open challenge');
        }
        if (authentication.payer !== verified.payer) {
            throw new Error('session authentication payer does not match the channel payer');
        }
        if (!(await verifySessionAuthentication(authentication, verified.channelId))) {
            throw new Error('invalid session authentication signature');
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
        idleTimeoutSeconds: effectiveIdleTimeoutSeconds,
        lastActivityAt: Date.now(),
        nextDeliverySequence: 0n,
        openSlot: verified.openSlot,
        openingChallengeId: args.challengeId,
        payer: verified.payer,
        pendingDeliveries: [],
        processedUses: [],
        rentPayer,
        schemaVersion: CHANNEL_STATE_SCHEMA_VERSION,
        sealed: false,
        settledOnChain: 0n,
        spentAmount: 0n,
        voucherSigner: args.voucherSigner,
    };

    // The existence check lives inside the atomic mutator so a concurrent
    // open replay cannot race a fresh create.
    const persisted = await args.store.updateChannel(verified.channelId, async current => {
        if (current) {
            if (current.sealed) {
                throw new Error(`Channel ${verified.channelId} is already sealed`);
            }
            if (
                payload.authorizedSigner !== current.authorizedSigner ||
                verified.payer !== current.payer ||
                verified.deposit !== current.deposit ||
                verified.openSlot !== current.openSlot ||
                rentPayer !== current.rentPayer ||
                args.challengeId !== current.openingChallengeId ||
                args.voucherSigner !== current.voucherSigner ||
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
            payerSigner: args.feePayer ? args.feePayerSigner : undefined,
            rpc: args.rpc as SubmitOpenRpc,
        });
        return newState;
    });
    args.lifecycle?.touch(verified.channelId, persisted.idleTimeoutSeconds);

    // txHash is reserved for the close receipt's settlement signature
    // (draft-solana-session-00 receipt table); open does not settle on-chain
    // funds, so it carries no txHash.
    return sessionReceipt(persisted, {
        challengeId: args.challengeId,
        externalId: args.externalId,
    });
}

interface HandleVoucherArgs {
    readonly challengeId: string | undefined;
    readonly externalId: string | undefined;
    readonly lifecycle: Lifecycle | undefined;
    readonly minVoucherDelta: bigint | undefined;
    readonly payload: { readonly action: 'voucher'; readonly channelId: string; readonly voucher: SignedVoucher };
    readonly price: bigint;
    /** Forced-close grace period a non-zero voucher expiry must outlast. */
    readonly settlementWindow: bigint | undefined;
    readonly store: SessionStore;
}

interface HandleUseArgs {
    readonly challengeId: string | undefined;
    readonly externalId: string | undefined;
    readonly idempotencyKey: string;
    readonly lifecycle: Lifecycle | undefined;
    readonly operatorVoucherSigner: MessagePartialSigner;
    readonly payload: {
        readonly action: 'use';
        readonly authentication: SessionAuthentication;
        readonly channelId: string;
    };
    readonly price: bigint;
    readonly store: SessionStore;
}

async function handleUse(args: HandleUseArgs): Promise<Receipt.Receipt> {
    const price = args.price;
    if (price === 0n) throw new Error('session amount must be positive');
    if (!args.idempotencyKey) throw new Error('operator-signed use requires an Idempotency-Key header');
    const existing = await args.store.getChannel(args.payload.channelId);
    if (!existing) throw new Error(`Channel ${args.payload.channelId} not found`);
    // A record with no binding at all is not a mismatch: it either predates
    // proof binding or was rewritten by a pre-binding writer. Name it so the
    // client knows re-opening — not retrying the proof — is the fix.
    if (!existing.openingChallengeId && !existing.authentication) {
        throw new Error('session channel predates proof binding; open a new session');
    }
    if (existing.voucherSigner !== 'operator' || !existing.authentication) {
        throw new Error('use is only valid for an operator-signed channel');
    }
    if (!sessionAuthenticationMatches(args.payload.authentication, existing.authentication)) {
        throw new Error('session authentication does not match the proof bound at open');
    }
    if (!(await verifySessionAuthentication(args.payload.authentication, args.payload.channelId))) {
        throw new Error('invalid session authentication signature');
    }

    let voucherSignature = '';
    let cumulative = 0n;
    let idleTimeoutSeconds: number | undefined;
    const finalState = await args.store.updateChannel(args.payload.channelId, async current => {
        if (!current) throw new Error(`Channel ${args.payload.channelId} not found`);
        if (current.sealed || current.closeRequestedAt !== undefined) {
            throw new Error('Channel is closed or close is pending');
        }
        const replay = current.processedUses.find(use => use.idempotencyKey === args.idempotencyKey);
        if (replay) {
            cumulative = replay.cumulative;
            voucherSignature = replay.voucherSignature;
            idleTimeoutSeconds = current.idleTimeoutSeconds;
            return current;
        }
        cumulative = current.cumulative + price;
        idleTimeoutSeconds = current.idleTimeoutSeconds;
        if (cumulative > current.deposit) throw new Error('insufficient channel availability');
        const data = {
            channelId: current.channelId,
            cumulativeAmount: cumulative.toString(),
            expiresAt: DEFAULT_SESSION_EXPIRES_AT,
        };
        const [signatures] = await args.operatorVoucherSigner.signMessages([
            createSignableMessage(encodeVoucherMessageLoose(data)),
        ]);
        const signature = signatures?.[args.operatorVoucherSigner.address];
        if (!signature) throw new Error('operator voucher signer did not return a signature');
        voucherSignature = getBase58Decoder().decode(new Uint8Array(signature));
        return {
            ...current,
            cumulative,
            highestVoucherExpiresAt: BigInt(DEFAULT_SESSION_EXPIRES_AT),
            highestVoucherSignature: voucherSignature,
            lastActivityAt: Date.now(),
            processedUses: [
                ...current.processedUses,
                {
                    challengeId: args.challengeId ?? '',
                    cumulative,
                    idempotencyKey: args.idempotencyKey,
                    voucherSignature,
                },
            ],
            spentAmount: current.spentAmount + price,
        };
    });
    args.lifecycle?.touch(args.payload.channelId, idleTimeoutSeconds);

    return sessionReceipt(finalState, {
        challengeId: args.challengeId,
        externalId: args.externalId,
    });
}

async function handleVoucher(args: HandleVoucherArgs): Promise<Receipt.Receipt> {
    if (args.price === 0n) throw new Error('session amount must be positive');
    const signed = normalizeSignedVoucher(args.payload.voucher);
    // The top-level channelId is the routing key; it must never diverge from
    // the signed voucher's inner channelId (spec: servers MUST reject the
    // action when the two differ).
    if (args.payload.channelId !== signed.voucher.channelId) {
        throw new Error(
            `invalid-voucher: voucher action channelId ${args.payload.channelId} does not match the signed voucher's channelId ${signed.voucher.channelId}`,
        );
    }
    const channelId = signed.voucher.channelId;
    const existing = await args.store.getChannel(channelId);
    if (!existing) throw new Error(`Channel ${channelId} not found`);

    // Pre-flight reject for cheap cases (signature still checked atomically).
    const preflight = await verifyVoucherForChannel({
        deposit: existing.deposit,
        minVoucherDelta: args.minVoucherDelta,
        settlementWindow: args.settlementWindow,
        signed,
        state: existing,
    });
    rejectIfVoucherRejected(preflight);

    // Atomic re-check inside the lock (mirrors the Rust closure pattern).
    const finalState = await args.store.updateChannel(channelId, async current => {
        if (!current) throw new Error(`Channel ${channelId} not found`);
        const result = await verifyVoucherForChannel({
            deposit: current.deposit,
            minVoucherDelta: args.minVoucherDelta,
            settlementWindow: args.settlementWindow,
            signed,
            state: current,
        });
        if (result.status === 'rejected') {
            // Caller will translate; reuse the Rust convention of throwing.
            throw new Error(`${result.reason}: ${result.detail}`);
        }
        if (result.status === 'replayed') {
            // An idempotent replay of the already-accepted highest voucher
            // must not deliver additional service or debit spentAmount
            // again — the client already paid for it.
            return { ...current, lastActivityAt: Date.now() };
        }
        if (result.newCumulative - current.spentAmount < args.price) {
            throw new Error('insufficient authorized voucher availability');
        }
        return {
            ...current,
            cumulative: result.newCumulative,
            highestVoucherExpiresAt: result.newExpiresAt,
            highestVoucherSignature: result.newSignature,
            lastActivityAt: Date.now(),
            spentAmount: current.spentAmount + args.price,
        };
    });
    args.lifecycle?.touch(channelId, finalState.idleTimeoutSeconds);

    return sessionReceipt(finalState, {
        challengeId: args.challengeId,
        externalId: args.externalId,
    });
}

interface HandleTopUpArgs {
    readonly challengeId: string | undefined;
    readonly channelProgram: string;
    readonly externalId: string | undefined;
    readonly lifecycle: Lifecycle | undefined;
    readonly payload: {
        readonly action: 'topUp';
        readonly additionalAmount: string;
        readonly channelId: string;
        readonly transaction: string;
    };
    readonly rpc: RpcLike;
    readonly store: SessionStore;
}

async function handleTopUp(args: HandleTopUpArgs): Promise<Receipt.Receipt> {
    const additionalAmount = parseU64String(args.payload.additionalAmount, 'additionalAmount');
    if (additionalAmount === 0n) throw new Error('additionalAmount must be positive');

    // Cheap pre-checks before touching the network.
    const existing = await args.store.getChannel(args.payload.channelId);
    if (!existing) throw new Error(`Channel ${args.payload.channelId} not found`);
    // Idempotent replay: this exact transaction was already credited, so
    // report success without re-broadcasting (a re-broadcast of a landed
    // transaction fails at preflight).
    const topUpSignature = transactionSignatureFromWire(args.payload.transaction) as unknown as string;
    if (existing.processedTopUpSignatures?.includes(topUpSignature)) {
        // txHash is reserved for the close receipt's settlement signature
        // (draft-solana-session-00 receipt table); a top-up does not settle
        // on-chain funds itself, so it carries no txHash.
        return sessionReceipt(existing, {
            challengeId: args.challengeId,
            externalId: args.externalId,
        });
    }
    if (existing.sealed) throw new Error('Channel is already sealed');
    if (existing.closeRequestedAt !== undefined) {
        throw new Error('Channel close is pending — no further top-ups accepted');
    }

    await submitTopUpTx({
        additionalAmount,
        channelId: args.payload.channelId,
        channelProgram: args.channelProgram,
        currentDeposit: existing.deposit,
        payer: existing.payer,
        rpc: args.rpc as SubmitOpenRpc,
        transaction: args.payload.transaction,
    });

    const result = await args.store.updateChannel(args.payload.channelId, current => {
        if (!current) throw new Error(`Channel ${args.payload.channelId} not found`);
        // Signature dedupe must live inside the atomic mutator: two
        // in-flight submissions of the same signed top-up both confirm the
        // same landed transaction, so only the first check-and-record may
        // credit the deposit.
        if (current.processedTopUpSignatures?.includes(topUpSignature)) return current;
        if (current.sealed) throw new Error('Channel is already sealed');
        if (current.closeRequestedAt !== undefined) {
            throw new Error('Channel close is pending — no further top-ups accepted');
        }
        return {
            ...current,
            deposit: current.deposit + additionalAmount,
            lastActivityAt: Date.now(),
            processedTopUpSignatures: [...(current.processedTopUpSignatures ?? []), topUpSignature],
        };
    });
    args.lifecycle?.touch(result.channelId, result.idleTimeoutSeconds);

    return sessionReceipt(result, {
        challengeId: args.challengeId,
        externalId: args.externalId,
    });
}

interface HandleCloseArgs {
    readonly challengeId: string | undefined;
    readonly currency: string;
    readonly decimals: number | undefined;
    readonly externalId: string | undefined;
    readonly lifecycle: Lifecycle | undefined;
    readonly merchantSigner: TransactionPartialSigner | undefined;
    readonly mint: string;
    readonly network: string;
    readonly payload: {
        readonly action: 'close';
        readonly authentication?: SessionAuthentication | undefined;
        readonly channelId: string;
        readonly voucher?: SignedVoucher | undefined;
    };
    readonly programId: Address;
    readonly recipient: string;
    readonly rentPayer: string | undefined;
    readonly rpc: RpcLike;
    readonly settlementWindow: bigint | undefined;
    readonly splits: readonly { readonly bps: number; readonly recipient: string }[] | undefined;
    readonly store: SessionStore;
    readonly tokenProgram: string;
}

async function handleClose(args: HandleCloseArgs): Promise<Receipt.Receipt> {
    const channelId = args.payload.channelId;
    // Same routing-key invariant as the voucher action: a final voucher
    // nested in a close must be bound to the channel being closed.
    if (args.payload.voucher && args.payload.voucher.voucher.channelId !== channelId) {
        throw new Error(
            `invalid-voucher: close voucher channelId ${args.payload.voucher.voucher.channelId} does not match the close channelId ${channelId}`,
        );
    }
    const now = BigInt(Math.floor(Date.now() / 1000));

    // Accept the optional final voucher and flip close-pending atomically.
    await args.store.updateChannel(channelId, async current => {
        if (!current) throw new Error(`Channel ${channelId} not found`);
        if (current.sealed) throw new Error('Channel is already sealed');
        // A close that presents authentication against a record with no proof
        // binding (and no operator marker) is an operator-signed session whose
        // record predates — or was stripped of — the binding fields.
        if (
            args.payload.authentication &&
            current.voucherSigner !== 'operator' &&
            !current.openingChallengeId &&
            !current.authentication
        ) {
            throw new Error('session channel predates proof binding; the lifecycle worker will close it');
        }
        if (current.voucherSigner === 'operator') {
            if (args.payload.voucher) throw new Error('operator-mode close must not include a voucher');
            if (!args.payload.authentication) {
                throw new Error('operator-mode close requires the bound authentication proof');
            }
            if (!current.authentication) {
                throw new Error('session channel predates proof binding; the lifecycle worker will close it');
            }
            if (!sessionAuthenticationMatches(args.payload.authentication, current.authentication)) {
                throw new Error('close authentication does not match the proof bound at open');
            }
            if (!(await verifySessionAuthentication(args.payload.authentication, channelId))) {
                throw new Error('invalid close authentication signature');
            }
        } else {
            if (args.payload.authentication) throw new Error('client-mode close must not include authentication');
            if (!args.payload.voucher) throw new Error('client-mode close requires a voucher');
        }

        if (current.closeRequestedAt !== undefined) {
            if (current.settledSignature === undefined) return current;
            throw new Error('Close already requested');
        }

        if (args.payload.voucher) {
            const signed = normalizeSignedVoucher(args.payload.voucher);
            // Route the final voucher (replay AND advancing) through the verifier
            // so expiry + the settlement-window margin are enforced on both paths —
            // an idempotent replay must not record close-pending against a voucher
            // that no longer outlasts the window, or the async settle fails on-chain.
            const verdict = await verifyVoucherForChannel({
                deposit: current.deposit,
                settlementWindow: args.settlementWindow,
                signed,
                state: current,
            });
            if (verdict.status === 'rejected') {
                // Mirrors Rust `process_close`: a final voucher that fails
                // verification — a non-replay at/below the watermark, or an expiry
                // that no longer outlasts the settlement window even on replay — is
                // a hard error; the close aborts rather than settle a stale amount.
                throw new Error(`${verdict.reason}: ${verdict.detail}`);
            }
            if (verdict.status === 'replayed') {
                // Idempotent replay of the current highest voucher: watermark
                // unchanged; signature + expiry/window already re-verified above.
                return { ...current, closeRequestedAt: now };
            }
            if (verdict.status === 'accepted') {
                return {
                    ...current,
                    closeRequestedAt: now,
                    cumulative: verdict.newCumulative,
                    highestVoucherExpiresAt: verdict.newExpiresAt,
                    highestVoucherSignature: verdict.newSignature,
                };
            }
        }
        return { ...current, closeRequestedAt: now };
    });

    let onChainSignature: string | undefined;
    if (args.merchantSigner) {
        const closed = await closeAndSettleChannel({
            channelId,
            currency: args.currency,
            decimals: args.decimals,
            merchantSigner: args.merchantSigner,
            mint: args.mint,
            network: args.network,
            programId: args.programId,
            recipient: args.recipient,
            rentPayer: args.rentPayer,
            rpc: args.rpc,
            splits: args.splits,
            store: args.store,
            tokenProgram: args.tokenProgram,
        });
        onChainSignature = closed?.signature as unknown as string | undefined;
    }

    args.lifecycle?.removeChannel(channelId);

    const finalState = await args.store.getChannel(channelId);
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
        rpc: args.rpc as unknown as {
            sendTransaction: (wire: string, config?: unknown) => { send: () => Promise<Signature> };
        },
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
        /** Forced-close grace period written into new channels. */
        readonly gracePeriodSeconds: number;
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
