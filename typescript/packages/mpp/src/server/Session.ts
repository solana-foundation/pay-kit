import {
    type Address,
    createSolanaRpc,
    isTransactionPartialSigner,
    type Signature,
    type TransactionPartialSigner,
    type TransactionSigner,
} from '@solana/kit';
import { Method, Receipt } from 'mppx';

import { DEFAULT_RPC_URLS, defaultTokenProgramForCurrency, resolveStablecoinMint } from '../constants.js';
import * as Methods from '../Methods.js';
import type {
    CommitReceipt,
    MeteringDirective,
    OpenPayload,
    SessionMode,
    SessionPullVoucherStrategy,
    SessionRequest,
    SessionSettlementAuthority,
    SessionSplit,
    SignedVoucher,
} from '../shared/session-types.js';
import { normalizeSignedVoucher, verifyVoucherSignature } from '../shared/voucher.js';
import { createLifecycle, type Lifecycle } from './session/lifecycle.js';
import {
    type MultiDelegateSubmitRpc,
    PAYMENT_CHANNELS_PROGRAM_ID,
    submitInitMultiDelegateTxIfMissing,
    submitOpenTx,
    submitSettleAndDistribute,
    type SubmitSettleAndDistributeResult,
    verifyOpenTx,
} from './session/on-chain.js';
import {
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
 * A session opens a payment channel (or delegated-token pull) once, then
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
 *   operator: OPERATOR,
 *   recipient: RECIPIENT,
 *   signer,              // optional: server-side fee payer / merchant signer
 *   cap: 10_000_000n,    // 10 USDC default cap
 *   currency: 'USDC',
 *   decimals: 6,
 *   network: 'devnet',
 *   modes: ['push'],
 *   pricing: { perDelivery: 100n },
 *   rpc: createSolanaRpc('https://api.devnet.solana.com'),
 * })
 *
 * const mppx = Mppx.create({ methods: [sess] })
 * ```
 */
export function session(parameters: session.Parameters) {
    const {
        operator,
        recipient,
        signer,
        cap,
        currency,
        decimals,
        network = 'mainnet',
        programId,
        modes,
        pullVoucherStrategy,
        settlementAuthority = 'clientVoucher',
        splits,
        pricing,
        rpc,
        closeDelayMs = 0,
        minVoucherDelta,
        openTxSubmitter = 'client',
        paymentChannelPayerSigner,
        settlementWindowSeconds,
    } = parameters;

    if (cap <= 0n) {
        throw new Error('cap must be positive');
    }
    if (signer && !isTransactionPartialSigner(signer)) {
        throw new Error('signer must implement signTransactions()');
    }
    if (paymentChannelPayerSigner && !isTransactionPartialSigner(paymentChannelPayerSigner)) {
        throw new Error('paymentChannelPayerSigner must implement signTransactions()');
    }
    if (splits && splits.length > 8) {
        throw new Error('splits cannot exceed 8 entries');
    }
    const effectiveModes: SessionMode[] = modes && modes.length > 0 ? modes.slice() : ['push'];
    if (effectiveModes.includes('pull') && !pullVoucherStrategy) {
        throw new Error('pullVoucherStrategy is required when modes includes "pull"');
    }
    if (openTxSubmitter !== 'client' && openTxSubmitter !== 'server') {
        throw new Error(`openTxSubmitter must be 'client' or 'server', got ${String(openTxSubmitter)}`);
    }
    if (pricing.perDelivery !== undefined && pricing.perDelivery <= 0n) {
        throw new Error('pricing.perDelivery must be positive when set');
    }

    const rpcUrl = parameters.rpcUrl ?? DEFAULT_RPC_URLS[network] ?? DEFAULT_RPC_URLS['mainnet'];
    const store = resolveSessionStore(parameters);
    const resolvedProgramId = (programId ?? PAYMENT_CHANNELS_PROGRAM_ID) as Address;
    const resolvedMint = resolveStablecoinMint(currency, network) ?? currency;
    const tokenProgram = parameters.tokenProgram ?? defaultTokenProgramForCurrency(currency, network);
    const lifecycleRef: { value: Lifecycle | undefined } = { value: undefined };

    // Note: lifecycle's closeOnIdle would normally drive an on-chain settle.
    // Because that requires a configured merchant signer + rpc, we only
    // create the lifecycle when both are present.
    if (closeDelayMs > 0) {
        lifecycleRef.value = createLifecycle(
            store,
            async channelId => {
                if (!signer || !rpc) return;
                try {
                    await closeAndSettleChannel({
                        channelId,
                        currency,
                        decimals,
                        merchantSigner: signer,
                        mint: resolvedMint,
                        network,
                        operator,
                        programId: resolvedProgramId,
                        recipient,
                        rpc,
                        splits,
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
            closeDelayMs,
        );
    }

    const method = Method.toServer(Methods.session, {
        defaults: {
            cap: cap.toString(),
            currency,
            operator,
            recipient,
        },

        async request({ credential, request }) {
            // Don't fetch a blockhash on the verify path — the client
            // already built whatever tx it needed against its own
            // blockhash. We only prefetch when issuing a fresh 402.
            // The current slot rides along from the same response's context:
            // it becomes the channel `openSlot` PDA seed, which the client
            // must take from the challenge rather than its own RPC.
            let recentBlockhash: string | undefined;
            let recentSlot: string | undefined;
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
                    const data = (await res.json()) as {
                        result?: { context?: { slot?: number }; value?: { blockhash?: string } };
                    };
                    recentBlockhash = data.result?.value?.blockhash;
                    const slot = data.result?.context?.slot;
                    if (typeof slot === 'number') recentSlot = String(slot);
                } catch {
                    // Non-fatal — client will fetch its own blockhash, and
                    // push opens fail with a clear recentSlot error client-side.
                }
            }

            // Clamp cap to the server max (mirrors Rust
            // `build_challenge_request` clamp behavior).
            const requestedCap = parseU64String(request.cap ?? cap.toString(), 'cap');
            const effectiveCap = requestedCap > cap ? cap : requestedCap;

            const challengeRequest: SessionRequest = {
                cap: effectiveCap.toString(),
                currency,
                ...(decimals !== undefined ? { decimals } : {}),
                ...(request.description ? { description: request.description } : {}),
                ...(request.externalId ? { externalId: request.externalId } : {}),
                ...(minVoucherDelta !== undefined && minVoucherDelta > 0n
                    ? { minVoucherDelta: minVoucherDelta.toString() }
                    : {}),
                // Omit modes when only push (Rust mirror).
                ...(effectiveModes.length === 1 && effectiveModes[0] === 'push' ? {} : { modes: effectiveModes }),
                network,
                operator,
                ...(programId ? { programId: programId.toString() } : {}),
                ...(effectiveModes.includes('pull') && pullVoucherStrategy ? { pullVoucherStrategy } : {}),
                ...(recentBlockhash ? { recentBlockhash } : {}),
                ...(recentSlot ? { recentSlot } : {}),
                recipient,
                settlementAuthority,
                ...(splits?.length ? { splits: [...splits] } : {}),
            };

            return challengeRequest as Record<string, unknown> & SessionRequest;
        },

        async verify({ credential }) {
            const cred = credential as unknown as CredentialPayload;
            const action = cred.payload.action;

            switch (action) {
                case 'open':
                    return await handleOpen({
                        cap,
                        challengeId: cred.challenge.id,
                        challengeOpenSlot: parseOptionalU64(cred.challenge.request.recentSlot, 'recentSlot'),
                        currency,
                        externalId: cred.challenge.request.externalId,
                        lifecycle: lifecycleRef.value,
                        merchantSigner: signer,
                        mint: resolvedMint,
                        modes: effectiveModes,
                        network,
                        openTxSubmitter,
                        operator,
                        payerSigner: paymentChannelPayerSigner,
                        payload: cred.payload,
                        programId: resolvedProgramId,
                        pullVoucherStrategy,
                        recipient,
                        rpc,
                        settlementAuthority,
                        store,
                    });
                case 'voucher':
                    return await handleVoucher({
                        challengeId: cred.challenge.id,
                        externalId: cred.challenge.request.externalId,
                        lifecycle: lifecycleRef.value,
                        minVoucherDelta,
                        payload: cred.payload,
                        settlementWindow: settlementWindowSeconds,
                        store,
                    });
                case 'commit':
                    return await handleCommit({
                        challengeId: cred.challenge.id,
                        externalId: cred.challenge.request.externalId,
                        lifecycle: lifecycleRef.value,
                        payload: cred.payload,
                        settlementWindow: settlementWindowSeconds,
                        store,
                    });
                case 'topUp':
                    return await handleTopUp({
                        cap,
                        challengeId: cred.challenge.id,
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
                        decimals,
                        externalId: cred.challenge.request.externalId,
                        lifecycle: lifecycleRef.value,
                        merchantSigner: signer,
                        mint: resolvedMint,
                        network,
                        operator,
                        payload: cred.payload,
                        programId: resolvedProgramId,
                        recipient,
                        rpc,
                        settlementWindow: settlementWindowSeconds,
                        splits,
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
    const cap = parameters.cap;
    if (cap === undefined) throw new Error('cap is required');
    const store = resolveSessionStore(parameters);
    const currency = parameters.currency;

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
    readonly cap: bigint;
    readonly challengeId: string | undefined;
    /** Slot issued in the 402 challenge; the open tx must echo it. */
    readonly challengeOpenSlot: bigint | undefined;
    readonly currency: string;
    readonly externalId: string | undefined;
    readonly lifecycle: Lifecycle | undefined;
    readonly merchantSigner: TransactionPartialSigner | undefined;
    readonly mint: string;
    readonly modes: SessionMode[];
    readonly network: string;
    readonly openTxSubmitter: 'client' | 'server';
    /** Operator / fee-payer pubkey (base58); pins the open `rentPayer`. */
    readonly operator: string;
    readonly payerSigner: TransactionPartialSigner | undefined;
    readonly payload: OpenPayload & { readonly action: 'open' };
    readonly programId: Address;
    readonly pullVoucherStrategy: SessionPullVoucherStrategy | undefined;
    readonly recipient: string;
    readonly rpc: RpcLike | undefined;
    readonly settlementAuthority: SessionSettlementAuthority;
    readonly store: SessionStore;
}

async function handleOpen(args: HandleOpenArgs): Promise<Receipt.Receipt> {
    const { payload } = args;
    const mode = payload.mode;
    if (!args.modes.includes(mode)) {
        throw new Error(`Session mode ${mode} is not supported by this challenge`);
    }
    if (mode === 'pull' && !args.pullVoucherStrategy) {
        throw new Error('pull-mode open requires a pullVoucherStrategy on the server config');
    }
    if (args.settlementAuthority === 'delegated' && payload.authorizedSigner !== args.operator) {
        throw new Error('delegated settlement requires authorizedSigner to match the operator');
    }

    let channelId: string;
    let deposit: bigint;
    let signature: string | undefined;
    // Channel payer (the deposit funder / distribute refund destination),
    // captured from the verified open when a transaction is present.
    let channelPayer: string | undefined;
    // Slot the channel was opened at — a channel PDA seed, persisted so the
    // PDA can be re-derived and reclaim gated later. Read from the verified
    // open transaction when present; otherwise from the client payload's
    // `recentSlot` echo.
    let openSlot: bigint | undefined = parseOptionalU64(payload.recentSlot, 'recentSlot');

    if (mode === 'push' && !payload.transaction && !payload.channelId) {
        throw new Error('open payload missing transaction or channelId');
    }

    if (payload.transaction) {
        // Payment-channel-backed open. This covers push sessions and
        // clientVoucher pull sessions whose deposit lives in an on-chain
        // payment channel (the `createPaymentChannelSessionOpener` flow):
        // both attach the pre-signed open transaction for verification —
        // and, with `openTxSubmitter: 'server'`, server-side broadcast.
        const expected = {
            authorizedSigner: payload.authorizedSigner,
            currency: args.currency,
            maxCap: args.cap,
            mint: args.mint,
            network: args.network,
            openSlot: args.challengeOpenSlot,
            operator: args.operator,
            programId: args.programId.toString(),
            recipient: args.recipient,
        };

        if (args.openTxSubmitter === 'server') {
            if (!args.rpc) throw new Error('openTxSubmitter=server requires an rpc client');
            // Decode (no RPC) first so an idempotent replay of an
            // already-persisted open does not rebroadcast the tx.
            const preVerified = await verifyOpenTx({ expected, openPayload: payload });
            const existing = await args.store.getChannel(preVerified.channelId);
            if (existing) {
                channelId = preVerified.channelId;
                deposit = preVerified.deposit;
                channelPayer = preVerified.payer;
                openSlot = preVerified.openSlot;
                signature = payload.signature;
            } else {
                const submitted = await submitOpenTx({
                    expected,
                    openPayload: payload,
                    payerSigner: args.payerSigner,
                    rpc: args.rpc as SubmitOpenRpc,
                });
                channelId = submitted.channelId;
                deposit = submitted.deposit;
                channelPayer = submitted.payer;
                openSlot = submitted.openSlot;
                signature = submitted.signature as unknown as string;
            }
        } else {
            const verified = await verifyOpenTx({
                expected,
                openPayload: payload,
                rpc: args.rpc as VerifyOpenRpc | undefined,
            });
            channelId = verified.channelId;
            deposit = verified.deposit;
            channelPayer = verified.payer;
            openSlot = verified.openSlot;
            signature = payload.signature;
        }
    } else if (mode === 'push') {
        // No transaction in payload: the client asserts a previously
        // broadcast open. When an RPC client is configured the open
        // signature is confirmed on-chain before persisting (mirrors
        // Rust `process_open`); without one the channelId/deposit
        // fields are trusted as-is, matching Rust with `rpc_url`
        // unset. The generated payment-channels client has no Channel
        // account decoder yet, so the on-chain channel fields
        // (payee/mint/authorizedSigner/deposit) are not re-checked.
        channelId = expectString(payload.channelId, 'channelId');
        deposit = parseU64String(expectString(payload.deposit, 'deposit'), 'deposit');
        signature = payload.signature;
        if (args.rpc) {
            await assertSignatureSucceeded(args.rpc as VerifyOpenRpc, expectString(signature, 'signature'), 'open');
        }
    } else {
        // pull mode: trust the channelId/tokenAccount + approvedAmount.
        // Keying order matches Rust `OpenPayload::session_id()`: prefer
        // channelId, then tokenAccount.
        channelId = payload.channelId ?? expectString(payload.tokenAccount, 'channelId/tokenAccount');
        const approved = expectString(payload.approvedAmount ?? payload.deposit, 'approvedAmount/deposit');
        deposit = parseU64String(approved, 'approvedAmount');
        signature = payload.signature;

        // Operated-voucher pulls may attach a pre-signed InitMultiDelegate
        // transaction; submit it idempotently when the PDA is missing.
        if (
            args.pullVoucherStrategy === 'operatedVoucher' &&
            payload.initMultiDelegateTx &&
            payload.owner &&
            args.merchantSigner &&
            isMultiDelegateSubmitRpc(args.rpc)
        ) {
            await submitInitMultiDelegateTxIfMissing({
                initMultiDelegateTx: payload.initMultiDelegateTx,
                mint: payload.mint ?? args.mint,
                owner: payload.owner,
                rpc: args.rpc,
            });
        }
    }

    if (deposit === 0n) throw new Error('deposit must be greater than zero');
    if (deposit > args.cap) throw new Error(`deposit ${deposit} exceeds cap ${args.cap}`);

    const newState: ChannelState = {
        authorizedSigner: payload.authorizedSigner,
        channelId,
        closeRequestedAt: undefined,
        committedDeliveries: [],
        cumulative: 0n,
        deposit,
        highestVoucherExpiresAt: undefined,
        highestVoucherSignature: undefined,
        nextDeliverySequence: 0n,
        openSlot,
        // Prefer the payer read from the verified open transaction (account 0,
        // what the channel actually records) over the client-supplied payload
        // fields, which could be stale/wrong. Fall back to the payload only for
        // opens with no transaction to verify (bare push assertion / pull).
        operator: channelPayer ?? payload.owner ?? payload.payer,
        pendingDeliveries: [],
        sealed: false,
    };

    // The existence check lives inside the atomic mutator so a concurrent
    // open replay cannot race a fresh create.
    await args.store.updateChannel(channelId, current => {
        if (current) {
            if (current.sealed) {
                throw new Error(`Channel ${channelId} is already sealed`);
            }
            if (payload.authorizedSigner !== current.authorizedSigner) {
                throw new Error(
                    `open replay: authorizedSigner ${payload.authorizedSigner} does not match existing channel ${channelId}`,
                );
            }
            // Idempotent replay: never reset the voucher watermark.
            return current;
        }
        return newState;
    });
    args.lifecycle?.touch(channelId);

    return Receipt.from({
        method: 'solana',
        ...(args.challengeId ? { challengeId: args.challengeId } : {}),
        ...(args.externalId ? { externalId: args.externalId } : {}),
        reference: signature ?? channelId,
        status: 'success',
        timestamp: new Date().toISOString(),
    });
}

interface HandleVoucherArgs {
    readonly challengeId: string | undefined;
    readonly externalId: string | undefined;
    readonly lifecycle: Lifecycle | undefined;
    readonly minVoucherDelta: bigint | undefined;
    readonly payload: { readonly action: 'voucher'; readonly voucher: SignedVoucher };
    /** Forced-close grace period a non-zero voucher expiry must outlast. */
    readonly settlementWindow: bigint | undefined;
    readonly store: SessionStore;
}

async function handleVoucher(args: HandleVoucherArgs): Promise<Receipt.Receipt> {
    const signed = normalizeSignedVoucher(args.payload.voucher);
    const channelId = signed.data.channelId;
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
    let finalResult: VoucherVerifyResult = preflight;
    await args.store.updateChannel(channelId, async current => {
        if (!current) throw new Error(`Channel ${channelId} not found`);
        const result = await verifyVoucherForChannel({
            deposit: current.deposit,
            minVoucherDelta: args.minVoucherDelta,
            settlementWindow: args.settlementWindow,
            signed,
            state: current,
        });
        finalResult = result;
        if (result.status === 'rejected') {
            // Caller will translate; reuse the Rust convention of throwing.
            throw new Error(`${result.reason}: ${result.detail}`);
        }
        if (result.status === 'replayed') return current;
        return {
            ...current,
            cumulative: result.newCumulative,
            highestVoucherExpiresAt: result.newExpiresAt,
            highestVoucherSignature: result.newSignature,
        };
    });
    args.lifecycle?.touch(channelId);

    const cumulative =
        finalResult.status === 'accepted' || finalResult.status === 'replayed' ? finalResult.newCumulative : 0n;

    return Receipt.from({
        method: 'solana',
        ...(args.challengeId ? { challengeId: args.challengeId } : {}),
        ...(args.externalId ? { externalId: args.externalId } : {}),
        reference: `${channelId}:${cumulative.toString()}`,
        status: 'success',
        timestamp: new Date().toISOString(),
    });
}

interface HandleCommitArgs {
    readonly challengeId: string | undefined;
    readonly externalId: string | undefined;
    readonly lifecycle: Lifecycle | undefined;
    readonly payload: { readonly action: 'commit'; readonly deliveryId: string; readonly voucher: SignedVoucher };
    readonly settlementWindow: bigint | undefined;
    readonly store: SessionStore;
}

async function handleCommit(args: HandleCommitArgs): Promise<Receipt.Receipt> {
    const receipt = await commitDelivery(args.store, {
        deliveryId: args.payload.deliveryId,
        settlementWindow: args.settlementWindow,
        voucher: args.payload.voucher,
    });
    args.lifecycle?.touch(receipt.sessionId);

    return Receipt.from({
        method: 'solana',
        ...(args.challengeId ? { challengeId: args.challengeId } : {}),
        ...(args.externalId ? { externalId: args.externalId } : {}),
        reference: `${receipt.sessionId}:${receipt.deliveryId}:${receipt.cumulative}`,
        status: 'success',
        timestamp: new Date().toISOString(),
    });
}

interface HandleTopUpArgs {
    readonly cap: bigint;
    readonly challengeId: string | undefined;
    readonly externalId: string | undefined;
    readonly lifecycle: Lifecycle | undefined;
    readonly payload: {
        readonly action: 'topUp';
        readonly channelId: string;
        readonly newDeposit: string;
        readonly signature: string;
    };
    readonly rpc: RpcLike | undefined;
    readonly store: SessionStore;
}

async function handleTopUp(args: HandleTopUpArgs): Promise<Receipt.Receipt> {
    const newDeposit = parseU64String(args.payload.newDeposit, 'newDeposit');
    if (newDeposit > args.cap) {
        throw new Error(`newDeposit ${newDeposit} exceeds cap ${args.cap}`);
    }

    // Cheap pre-checks before touching the network.
    const existing = await args.store.getChannel(args.payload.channelId);
    if (!existing) throw new Error(`Channel ${args.payload.channelId} not found`);
    if (existing.sealed) throw new Error('Channel is already sealed');
    if (existing.closeRequestedAt !== undefined) {
        throw new Error('Channel close is pending — no further top-ups accepted');
    }

    // Confirm the top-up transaction on-chain before raising the deposit
    // (parity with the open-signature verification).
    if (args.rpc) {
        await assertSignatureSucceeded(args.rpc as VerifyOpenRpc, args.payload.signature, 'topUp');
    }

    const result = await args.store.updateChannel(args.payload.channelId, current => {
        if (!current) throw new Error(`Channel ${args.payload.channelId} not found`);
        if (current.sealed) throw new Error('Channel is already sealed');
        if (current.closeRequestedAt !== undefined) {
            throw new Error('Channel close is pending — no further top-ups accepted');
        }
        if (newDeposit <= current.deposit) {
            throw new Error(`newDeposit ${newDeposit} must exceed current deposit ${current.deposit}`);
        }
        return { ...current, deposit: newDeposit };
    });
    args.lifecycle?.touch(result.channelId);

    return Receipt.from({
        method: 'solana',
        ...(args.challengeId ? { challengeId: args.challengeId } : {}),
        ...(args.externalId ? { externalId: args.externalId } : {}),
        reference: args.payload.signature,
        status: 'success',
        timestamp: new Date().toISOString(),
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
    /** Operator recorded as the channel `rentPayer` at open. */
    readonly operator: string;
    readonly payload: {
        readonly action: 'close';
        readonly channelId: string;
        readonly voucher?: SignedVoucher | undefined;
    };
    readonly programId: Address;
    readonly recipient: string;
    readonly rpc: RpcLike | undefined;
    readonly settlementWindow: bigint | undefined;
    readonly splits: readonly SessionSplit[] | undefined;
    readonly store: SessionStore;
    readonly tokenProgram: string;
}

async function handleClose(args: HandleCloseArgs): Promise<Receipt.Receipt> {
    const channelId = args.payload.channelId;
    const now = BigInt(Math.floor(Date.now() / 1000));

    // Accept the optional final voucher and flip close-pending atomically.
    await args.store.updateChannel(channelId, async current => {
        if (!current) throw new Error(`Channel ${channelId} not found`);
        if (current.sealed) throw new Error('Channel is already sealed');
        if (current.closeRequestedAt !== undefined) {
            // Re-drivable close: a prior close flipped the flag but the
            // on-chain settle never recorded a signature — let the retry
            // proceed (without mutating the watermark) so the channel is
            // not stranded by a transient settlement failure.
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
    if (args.merchantSigner && args.rpc) {
        const closed = await closeAndSettleChannel({
            channelId,
            currency: args.currency,
            decimals: args.decimals,
            merchantSigner: args.merchantSigner,
            mint: args.mint,
            network: args.network,
            operator: args.operator,
            programId: args.programId,
            recipient: args.recipient,
            rpc: args.rpc,
            splits: args.splits,
            store: args.store,
            tokenProgram: args.tokenProgram,
        });
        onChainSignature = closed?.signature as unknown as string | undefined;
    }

    args.lifecycle?.removeChannel(channelId);

    return Receipt.from({
        method: 'solana',
        ...(args.challengeId ? { challengeId: args.challengeId } : {}),
        ...(args.externalId ? { externalId: args.externalId } : {}),
        reference: onChainSignature ?? channelId,
        status: 'success',
        timestamp: new Date().toISOString(),
    });
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
    const channelId = signed.data.channelId;
    const newCumulative = parseU64String(signed.data.cumulativeAmount, 'cumulativeAmount');
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
            highestVoucherExpiresAt: BigInt(signed.data.expiresAt),
            highestVoucherSignature: signed.signature,
            pendingDeliveries: nextPending,
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
    /** Operator recorded as the channel `rentPayer` at open. */
    readonly operator: string;
    readonly programId: Address;
    readonly recipient: string;
    readonly rpc: RpcLike;
    readonly splits: readonly SessionSplit[] | undefined;
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

    // The distribute refund goes to the channel payer (the program enforces
    // `payer == channel.payer`). It is recorded as `state.operator` at open.
    // Never fall back to the recipient: refunding the merchant would derive the
    // wrong refund token account and the settlement would fail on-chain.
    if (!state.operator) {
        throw new Error(
            `cannot settle channel ${args.channelId}: the channel payer (refund destination) was not recorded at open`,
        );
    }

    let voucher: { authorizedSigner: string; signed: SignedVoucher } | undefined;
    if (state.highestVoucherSignature && state.highestVoucherExpiresAt !== undefined && state.cumulative > 0n) {
        voucher = {
            authorizedSigner: state.authorizedSigner,
            signed: {
                data: {
                    channelId: args.channelId,
                    cumulativeAmount: state.cumulative.toString(),
                    expiresAt: Number(state.highestVoucherExpiresAt),
                },
                signature: state.highestVoucherSignature,
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
        payer: state.operator,

        programId: args.programId,
        // rentPayer reclaims the channel/escrow rent at distribute; it is the
        // operator recorded as the channel rentPayer at open (the fee payer),
        // not the refund payer carried in state.operator.
        rentPayer: args.operator,
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
        return { ...current, sealed: true, settledSignature: result.signature as unknown as string };
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

/** Throw unless `signature` exists on-chain and executed without error. */
async function assertSignatureSucceeded(rpc: VerifyOpenRpc, signature: string, context: string): Promise<void> {
    const [status] = (await rpc.getSignatureStatuses([signature as Signature]).send()).value;
    if (!status) {
        throw new Error(`${context}: tx ${signature} not found on-chain`);
    }
    if (status.err) {
        throw new Error(`${context}: tx ${signature} failed on-chain: ${JSON.stringify(status.err)}`);
    }
}

/** Throw unless the voucher's Ed25519 signature verifies against `authorizedSigner`. */
async function assertVoucherSignature(signed: SignedVoucher, authorizedSigner: string): Promise<void> {
    let valid = false;
    try {
        valid = await verifyVoucherSignature({
            signatureBase58: signed.signature,
            signerBase58: authorizedSigner,
            voucher: signed.data,
        });
    } catch (error) {
        throw new Error(`invalid-signature: ${errorMessage(error)}`);
    }
    if (!valid) {
        throw new Error('invalid-signature: Voucher signature verification failed');
    }
}

function isMultiDelegateSubmitRpc(rpc: RpcLike | undefined): rpc is MultiDelegateSubmitRpc {
    if (!rpc) return false;
    const candidate = rpc as Partial<MultiDelegateSubmitRpc>;
    return (
        typeof candidate.getAccountInfo === 'function' &&
        typeof candidate.sendTransaction === 'function' &&
        typeof candidate.getSignatureStatuses === 'function'
    );
}

function expectString(value: string | undefined, name: string): string {
    if (!value) throw new Error(`${name} required`);
    return value;
}

function parseU64String(value: string, name: string): bigint {
    if (!/^\d+$/.test(value)) throw new Error(`${name} is not an unsigned integer string: ${value}`);
    const parsed = BigInt(value);
    if (parsed < 0n || parsed > (1n << 64n) - 1n) throw new Error(`${name} outside u64 range`);
    return parsed;
}

/** Parse an optional u64 carried on the wire as a decimal string or number. */
function parseOptionalU64(value: number | string | undefined, name: string): bigint | undefined {
    if (value === undefined) return undefined;
    return parseU64String(String(value), name);
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
    sendTransaction(wire: string, config?: unknown): { send(): Promise<Signature> };
};

type CredentialPayload = {
    challenge: {
        id?: string;
        request: SessionRequest;
    };
    payload:
        | {
              readonly action: 'topUp';
              readonly channelId: string;
              readonly newDeposit: string;
              readonly signature: string;
          }
        | { readonly action: 'close'; readonly channelId: string; readonly voucher?: SignedVoucher | undefined }
        | { readonly action: 'commit'; readonly deliveryId: string; readonly voucher: SignedVoucher }
        | { readonly action: 'voucher'; readonly voucher: SignedVoucher }
        | (OpenPayload & { readonly action: 'open' });
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
    interface SessionPricing {
        /** Default delivery price in base units. Optional — callers may price each delivery individually. */
        readonly perDelivery?: bigint | undefined;
    }

    interface RoutesHandlers {
        /** POST handler — commit a reserved delivery. */
        readonly commit: (request: Request) => Promise<Response>;
        /** POST handler — reserve a metered delivery. */
        readonly deliveries: (request: Request) => Promise<Response>;
    }

    interface Parameters {
        /** Maximum session cap the server will offer (base units). */
        readonly cap: bigint;
        /** Idle-close delay in ms. 0 (default) disables the watchdog. */
        readonly closeDelayMs?: number;
        /** Currency identifier (e.g. 'USDC' or an SPL mint address). */
        readonly currency: string;
        /** Token decimals (default 6). */
        readonly decimals?: number;
        /** Minimum voucher increment in base units. Defaults to 0. */
        readonly minVoucherDelta?: bigint;
        /** Funding modes. Defaults to ['push']. */
        readonly modes?: readonly SessionMode[];
        /** Solana network. Defaults to 'mainnet'. */
        readonly network?: string;
        /** Server submits the client's push-mode open tx itself. */
        readonly openTxSubmitter?: 'client' | 'server';
        /** Operator public key (base58). */
        readonly operator: string;
        /** Signer used when push-mode `openTxSubmitter='server'` requires a fee-payer signer. */
        readonly paymentChannelPayerSigner?: TransactionPartialSigner;
        /** Pricing hints surfaced to clients (Phase F+ will use these). */
        readonly pricing: SessionPricing;
        /** Payment-channels program ID override. */
        readonly programId?: Address | string;
        /** Voucher authority for pull-mode sessions. Required when modes includes 'pull'. */
        readonly pullVoucherStrategy?: SessionPullVoucherStrategy;
        /** Primary recipient (base58). */
        readonly recipient: string;
        /** Optional RPC client used for on-chain checks + transactions. */
        readonly rpc?: RpcLike;
        /** RPC URL for blockhash prefetch. Defaults from `network`. */
        readonly rpcUrl?: string;
        /** Voucher signing authority advertised by this session. */
        readonly settlementAuthority?: SessionSettlementAuthority;
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
        readonly signer?: TransactionPartialSigner;
        /** Optional basis-point splits distributed at close. Max 8. */
        readonly splits?: readonly SessionSplit[];
        /** Pluggable session store. Defaults to in-memory. */
        readonly store?: SessionStore;
        /** SPL token program (TOKEN_PROGRAM or TOKEN_2022_PROGRAM). Defaults from currency/network. */
        readonly tokenProgram?: string;
    }
}
