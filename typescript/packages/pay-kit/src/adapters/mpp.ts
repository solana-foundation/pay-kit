import { createHmac } from 'node:crypto';

import { defaultTokenProgramForCurrency, guardChallengeValue, resolveStablecoinMint } from '@solana/mpp';
import { Mppx, solana } from '@solana/mpp/server';
import { Receipt } from 'mppx';

import type { ProtocolAdapter } from '../adapter.js';
import type { AcceptsEntry } from '../challenge.js';
import { requireMint, resolveCoin } from '../coin.js';
import { assertReplayStorePolicy, type PayKitConfig } from '../config.js';
import { ConfigurationError, InvalidProofError } from '../errors.js';
import type { Gate } from '../gate.js';
import type { Payment } from '../payment.js';
import { caip2, toSolanaNetwork } from '../protocol.js';
import {
    atomicReplayStoreView,
    isAtomicReplayStore,
    isProductionReplayStore,
    type ReplayStore,
} from '../replay-store.js';

/** Settlement header mirrored by every PayKit SDK. */
const SETTLEMENT_SIGNATURE_HEADER = 'x-payment-settlement-signature';
const SUBSCRIPTION_RESOURCE_BINDING_DOMAIN = 'pay-kit:mpp-subscription-resource:v1';

/**
 * Produces a non-path resource identifier so subscription credentials bind to
 * the exact current path and raw query without exposing query values on wire.
 */
function subscriptionResourceFor(request: Request, challengeBindingSecret: string): string {
    const url = new URL(request.url);
    // Keep the URL parser's path semantics, but retain raw search text rather
    // than normalizing through URLSearchParams: ordering, duplicates, and
    // percent-encoding are therefore all binding-significant.
    const canonical = JSON.stringify([SUBSCRIPTION_RESOURCE_BINDING_DOMAIN, url.pathname, url.search]);
    const digest = createHmac('sha256', challengeBindingSecret).update(canonical).digest('hex');
    return `${SUBSCRIPTION_RESOURCE_BINDING_DOMAIN}:hmac-sha256:${digest}`;
}

type ChargeResult =
    | { readonly challenge: Response; readonly status: 402 }
    | { readonly status: 200; readonly withReceipt: (response: Response) => Response };
type ChargeHandler = (request: Request) => Promise<ChargeResult>;

type Split = { readonly amount: string; readonly memo?: string; readonly recipient: string };

function splitsFor(gate: Gate): readonly Split[] {
    return gate.fees.map(fee => ({
        amount: fee.price.baseUnits().toString(),
        recipient: fee.recipient,
        ...(fee.memo ? { memo: fee.memo } : {}),
    }));
}

/**
 * The on-wire `amount` is the customer's total; the charge verifier carves
 * the splits out of it (`primary = amount − Σsplits`). With all fees lowered
 * to splits, `payTo` nets `gate.amount − Σwithin` — exactly `gate.payout()`.
 */
function totalAmount(gate: Gate): bigint {
    return gate.total().baseUnits();
}

function handlerCacheKey(parts: readonly unknown[]): string {
    return JSON.stringify(parts, (_key, value: unknown) =>
        typeof value === 'bigint' ? `pay-kit:bigint:${value.toString()}` : value,
    );
}

/** The MPP scheme a gate settles through: `subscription` for recurring gates, else `charge`. */
function schemeFor(gate: Gate): 'charge' | 'subscription' {
    return gate.kind === 'subscription' ? 'subscription' : 'charge';
}

/**
 * The MPP protocol adapter: wraps `@solana/mpp`'s charge method behind the
 * PayKit {@link ProtocolAdapter} contract. One Mppx handler is created per
 * distinct (recipient, splits) shape and cached.
 */
export function createMppAdapter(config: PayKitConfig): ProtocolAdapter {
    if (config.replayStore === undefined) {
        throw new ConfigurationError('MPP adapter requires the replayStore resolved by configure().');
    }
    if (!isAtomicReplayStore(config.replayStore)) {
        throw new ConfigurationError('MPP adapter replayStore must implement atomic putIfAbsent(key, value).');
    }
    // Explicitly typed so the atomic narrowing survives into the nested
    // handler closures below (control-flow narrowing does not cross them).
    const injectedStore: ReplayStore = config.replayStore;
    assertReplayStorePolicy(config);
    // One atomic view feeds both charge and subscription methods. The view
    // exposes reserve() (aliasing putIfAbsent) so the subscription server's
    // claimConsumed reservation runs against the same cross-instance atomic
    // marker as charge replay. Production status is tracked on the injected
    // store (not the view), so subscription durability is checked on
    // injectedStore below.
    const replayStore = atomicReplayStoreView(injectedStore);
    const network = toSolanaNetwork(config.network);
    const handlers = new Map<string, ChargeHandler>();

    function handlerFor(gate: Gate): ChargeHandler {
        const coin = resolveCoin(gate.amount, config.stablecoins);
        const mint = requireMint(coin, resolveStablecoinMint(coin, network), config.network);
        const splits = splitsFor(gate);
        // Key on every field a built handler captures, so gates differing only
        // in amount, description, or externalId get distinct handlers.
        const key = handlerCacheKey([
            gate.kind,
            gate.payTo,
            mint,
            splits,
            gate.subscription ?? null,
            totalAmount(gate).toString(),
            gate.description ?? null,
            gate.externalId ?? null,
        ]);
        let handler = handlers.get(key);
        if (!handler) {
            const signer = config.operator.feePayer ? { signer: config.operator.signer.signer } : {};
            const realm = guardChallengeValue('realm', config.mpp.realm);
            const description = gate.description ? guardChallengeValue('description', gate.description) : undefined;
            if (gate.subscription) {
                const { merchant, periodCount, periodUnit, planBump, planCreatedAt, planId, planIdNumeric, puller } =
                    gate.subscription;
                if (!config.operator.feePayer) {
                    throw new ConfigurationError('Subscription gates require an operator fee payer.');
                }
                // Subscription activation replay needs a durable, shared store.
                // The nominal marker is #237's production declaration: outside
                // localnet the injected store must be declared production via
                // declareProductionReplayStore(). The unsafe-memory opt-in
                // (createUnsafeMemoryReplayStore) is authorized-unsafe but never
                // production, so it is rejected here even under
                // PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE: the opt-in covers charge
                // replay, never subscription activation replay.
                if (config.network !== 'solana_localnet' && !isProductionReplayStore(injectedStore)) {
                    throw new ConfigurationError(
                        'Subscription gates outside localnet require a durable shared replay store declared with ' +
                            'declareProductionReplayStore(); the in-memory opt-in (PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE) ' +
                            'does not cover subscription activation replay.',
                    );
                }
                const mppx = Mppx.create({
                    methods: [
                        solana.subscription({
                            decimals: 6,
                            merchant,
                            mint,
                            network,
                            periodCount,
                            periodUnit,
                            planBump,
                            planCreatedAt,
                            planId,
                            planIdNumeric,
                            puller,
                            recipient: gate.payTo,
                            rpcUrl: config.rpcUrl,
                            // feePayer is required for subscriptions (asserted above), so
                            // the operator signer is always threaded through.
                            signer: config.operator.signer.signer,
                            store: replayStore,
                            tokenProgram: defaultTokenProgramForCurrency(mint, network),
                        }),
                    ],
                    realm,
                    secretKey: config.mpp.challengeBindingSecret,
                });
                handler = request =>
                    mppx.subscription({
                        ...optionsFor(gate, description),
                        currency: mint,
                        resource: subscriptionResourceFor(request, config.mpp.challengeBindingSecret),
                    })(request);
            } else {
                const mppx = Mppx.create({
                    methods: [
                        solana.charge({
                            allowUnsafeMemoryStore: config.mpp.allowUnsafeMemoryStore === true,
                            currency: mint,
                            decimals: 6,
                            ...(config.mpp.html ? { html: true } : {}),
                            network,
                            recipient: gate.payTo,
                            rpcUrl: config.rpcUrl,
                            ...signer,
                            ...(splits.length > 0 ? { splits: [...splits] } : {}),
                            store: replayStore,
                        }),
                    ],
                    realm,
                    secretKey: config.mpp.challengeBindingSecret,
                });
                handler = request => mppx.charge(optionsFor(gate, description))(request);
            }
            handlers.set(key, handler);
        }
        return handler;
    }

    function optionsFor(gate: Gate, description: string | undefined) {
        const expires = expirationFor(config.mpp.expiresIn);
        return {
            amount: totalAmount(gate).toString(),
            ...(description !== undefined ? { description } : {}),
            ...(gate.externalId ? { externalId: gate.externalId } : {}),
            ...(expires === undefined ? {} : { expires }),
        };
    }

    return {
        acceptsEntry(gate: Gate): Promise<AcceptsEntry> {
            const coin = resolveCoin(gate.amount, config.stablecoins);
            const splits = splitsFor(gate);
            return Promise.resolve({
                amount: totalAmount(gate).toString(),
                currency: coin,
                network: caip2(config.network),
                payTo: gate.payTo,
                protocol: 'mpp',
                realm: config.mpp.realm,
                scheme: schemeFor(gate),
                ...(splits.length > 0 ? { splits } : {}),
                ...(gate.subscription ? { planId: gate.subscription.planId } : {}),
            });
        },

        async challengeHeaders(gate: Gate, request: Request): Promise<Readonly<Record<string, string>>> {
            const result = await handlerFor(gate)(request);
            if (result.status !== 402) return {};
            const wwwAuthenticate = result.challenge.headers.get('www-authenticate');
            return wwwAuthenticate ? { 'www-authenticate': wwwAuthenticate } : {};
        },

        detect(request: Request): boolean {
            return request.headers.get('authorization')?.toLowerCase().startsWith('payment ') ?? false;
        },

        protocol: 'mpp',

        // The mppx charge method (with `html: true`) content-negotiates the 402:
        // `result.challenge` is the interactive HTML payment page for browsers
        // (`Accept: text/html`) and the service-worker script for the
        // `?__mppx_worker` request — each with its own status (402 / 200). Hand
        // that Response back for pay-kit to send.
        async respond(gate: Gate, request: Request): Promise<Response | undefined> {
            if (!config.mpp.html) return undefined;
            const result = await handlerFor(gate)(request);
            if (result.status !== 402) return undefined;
            const response = result.challenge;
            // The service worker is served from the resource's sub-path (e.g.
            // /api/v1/x?__mppx_worker) but the page registers it at scope "/".
            // Browsers reject that broader scope unless the worker response
            // carries `Service-Worker-Allowed: /` — mppx doesn't set it, so add
            // it here (otherwise registration throws and the payment flow stalls).
            const url = new URL(request.url);
            if (url.searchParams.has('__mppx_worker') || url.searchParams.has('__mpp_worker')) {
                const headers = new Headers(response.headers);
                headers.set('Service-Worker-Allowed', '/');
                return new Response(response.body, { headers, status: response.status });
            }
            return response;
        },

        scheme: 'charge',

        async verifyAndSettle(gate: Gate, request: Request): Promise<Payment> {
            const result = await handlerFor(gate)(request);
            if (result.status === 402) {
                throw new InvalidProofError(...(await problemOf(result.challenge)));
            }
            const sealed = result.withReceipt(new Response(null));
            const receiptHeader = sealed.headers.get('payment-receipt');
            const receipt = receiptHeader ? Receipt.deserialize(receiptHeader) : undefined;
            const transaction = receipt?.reference ?? '';
            return {
                gateName: gate.name,
                payer: undefined,
                protocol: 'mpp',
                raw: request.headers.get('authorization') ?? undefined,
                scheme: schemeFor(gate),
                settlementHeaders: {
                    ...(receiptHeader ? { 'payment-receipt': receiptHeader } : {}),
                    ...(transaction ? { [SETTLEMENT_SIGNATURE_HEADER]: transaction } : {}),
                },
                transaction,
            };
        },
    };
}

/** Validate the configured TTL at issuance, when the clock actually matters. */
function expirationFor(expiresIn: number): string | undefined {
    if (expiresIn === 0) return undefined;
    const expires = new Date(Date.now() + expiresIn * 1000);
    if (!Number.isFinite(expires.getTime())) {
        throw new ConfigurationError('mpp.expiresIn must produce a valid expiration date at challenge issuance.');
    }
    return expires.toISOString();
}

/** Extracts a canonical (code, detail) pair from an mppx problem-details 402. */
async function problemOf(challenge: Response): Promise<[string, string | undefined]> {
    try {
        const body: unknown = await challenge.clone().json();
        if (typeof body === 'object' && body !== null) {
            const problem = body as { code?: unknown; detail?: unknown; title?: unknown };
            const code = typeof problem.code === 'string' ? problem.code : 'invalid_proof';
            const detail =
                typeof problem.detail === 'string'
                    ? problem.detail
                    : typeof problem.title === 'string'
                      ? problem.title
                      : undefined;
            return [code, detail];
        }
    } catch {
        // Non-JSON challenge body; fall through to the generic code.
    }
    return ['invalid_proof', undefined];
}
