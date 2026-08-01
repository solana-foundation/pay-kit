/**
 * The MPP session engine: wraps `@solana/mpp`'s `session()` method + its
 * `session.routes()` side-channel behind a small per-gate engine. Unlike the
 * fixed/subscription adapters, a session is a streaming protocol — the channel
 * opens on the gated route, deliveries are metered through the side-channel,
 * and settlement happens out-of-band (an idle-close watchdog settles on-chain),
 * so it can't ride the one-shot `ProtocolAdapter` contract.
 *
 * pay-kit does NOT auto-mount the side-channel routes (mppx-consistent): the
 * instance exposes `handler` / `deliveries` / `commit` / `receipt` and the app
 * mounts them. All four share one in-memory session store per gate.
 */
import { createSolanaRpc } from '@solana/kit';
import { resolveStablecoinMint } from '@solana/mpp';
import { createMemorySessionStore, Mppx, PAYMENT_CHANNELS_PROGRAM_ID, session } from '@solana/mpp/server';

import { requireMint, resolveCoin } from '../coin.js';
import type { PayKitConfig } from '../config.js';
import { ConfigurationError } from '../errors.js';
import type { Gate } from '../gate.js';
import { toSolanaNetwork } from '../protocol.js';

/** Outcome of running the session method on the gated route. */
export type SessionResult =
    | { readonly challenge: Response; readonly status: 402 }
    | { readonly status: 200; readonly withReceipt: (response: Response) => Response };

/** Settle-status of a channel, read by the `/sessions/receipt/:id` poll. */
export type SessionReceipt = {
    readonly channelId: string;
    readonly cumulative: string;
    readonly deposit: string;
    readonly sealed: boolean;
    readonly settledSignature: string | null;
};

/** Per-gate session engine: the gated handler plus the side-channel + receipt readers. */
export type SessionEngine = {
    /** Voucher-commit side-channel (`POST /__402/session/commit`). */
    readonly commit: (request: Request) => Promise<Response>;
    /** Delivery-reservation side-channel (`POST /__402/session/deliveries`). */
    readonly deliveries: (request: Request) => Promise<Response>;
    /** The gated route handler: opens/meters the channel, returns 402 or a receipt-sealer. */
    readonly handler: (request: Request) => Promise<SessionResult>;
    /** Settle-status for a channel, or `undefined` if unknown. */
    readonly receipt: (channelId: string) => Promise<SessionReceipt | undefined>;
};

/**
 * Build the session engine for a `session` gate. One in-memory store is shared
 * across the gated handler and the side-channel routes so the receipt poll can
 * read whichever channel a request opened.
 */
export function createSessionEngine(config: PayKitConfig, gate: Gate): SessionEngine {
    if (!gate.session) {
        throw new ConfigurationError(`Gate "${gate.name}": session engine requires a session config.`);
    }
    if (!config.operator.feePayer) {
        throw new ConfigurationError(
            `Gate "${gate.name}": session gates require an operator that sponsors fees (operator.feePayer).`,
        );
    }
    const network = toSolanaNetwork(config.network);
    const coin = resolveCoin(gate.amount, config.stablecoins);
    const mint = requireMint(coin, resolveStablecoinMint(coin, network), config.network);

    const signer = config.operator.signer.signer;
    const store = createMemorySessionStore();
    // New-channel 402s carry methodDetails.recentBlockhash/recentSlot from one
    // getLatestBlockhash on `rpc` (the session method fetches them; wire a
    // `blockhashCache` into `params` to share a host-refreshed cache instead).
    // When the fetch fails, the challenge fails - the engine never advertises
    // a degraded session offer, matching the x402 upto adapter.
    const idleTimeoutSeconds =
        gate.session.closeDelayMs === undefined ? 300 : Math.max(1, Math.ceil(gate.session.closeDelayMs / 1_000));
    const params = {
        amount: gate.session.unitPrice,
        channelProgram: PAYMENT_CHANNELS_PROGRAM_ID,
        currency: mint,
        decimals: 6,
        feePayer: true,
        feePayerSigner: signer,
        gracePeriodSeconds: 900,
        idleTimeoutSeconds,
        network,
        recipient: gate.payTo,
        rpc: createSolanaRpc(config.rpcUrl),
        signer,
        store,
        suggestedDeposit: gate.amount.baseUnits(),
    };

    const mppx = Mppx.create({
        methods: [session(params)],
        realm: config.mpp.realm,
        secretKey: config.mpp.challengeBindingSecret,
    });
    const handler = mppx.session({
        amount: params.amount.toString(),
        currency: mint,
        description: gate.description ?? 'Metered session',
        methodDetails: {
            channelProgram: PAYMENT_CHANNELS_PROGRAM_ID.toString(),
            network,
        },
        recipient: gate.payTo,
    });
    const routes = session.routes(params);

    return {
        commit: request => routes.commit(request),
        deliveries: request => routes.deliveries(request),
        handler: request => handler(request) as Promise<SessionResult>,
        async receipt(channelId: string): Promise<SessionReceipt | undefined> {
            const state = await store.getChannel(channelId);
            if (!state) return undefined;
            return {
                channelId: state.channelId,
                cumulative: state.cumulative.toString(),
                deposit: state.deposit.toString(),
                sealed: state.sealed,
                settledSignature: state.settledSignature ?? null,
            };
        },
    };
}
