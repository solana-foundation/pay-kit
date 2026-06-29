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
import { createMemorySessionStore, Mppx, session } from '@solana/mpp/server';

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
    readonly finalized: boolean;
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
    const params = {
        cap: gate.amount.baseUnits(),
        ...(gate.session.closeDelayMs !== undefined ? { closeDelayMs: gate.session.closeDelayMs } : {}),
        currency: mint,
        decimals: 6,
        modes: ['pull'] as const,
        network,
        openTxSubmitter: 'server' as const,
        operator: config.operator.signer.pubkey,
        paymentChannelPayerSigner: signer,
        pricing: { perDelivery: gate.session.unitPrice },
        pullVoucherStrategy: 'clientVoucher' as const,
        recipient: gate.payTo,
        rpc: createSolanaRpc(config.rpcUrl),
        rpcUrl: config.rpcUrl,
        signer,
        store,
    };

    const mppx = Mppx.create({
        methods: [session(params)],
        realm: config.mpp.realm,
        secretKey: config.mpp.challengeBindingSecret,
    });
    const handler = mppx.session({
        cap: params.cap.toString(),
        currency: mint,
        description: gate.description ?? 'Metered session',
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
                finalized: state.finalized,
                settledSignature: state.settledSignature ?? null,
            };
        },
    };
}
