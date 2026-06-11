import { resolveStablecoinMint } from '@solana/mpp';
import { Mppx, solana } from '@solana/mpp/server';
import { Receipt } from 'mppx';

import type { ProtocolAdapter } from '../adapter.js';
import type { AcceptsEntry } from '../challenge.js';
import type { PayKitConfig } from '../config.js';
import { ConfigurationError, InvalidProofError } from '../errors.js';
import type { Gate } from '../gate.js';
import type { Payment } from '../payment.js';
import { caip2, toSolanaNetwork } from '../protocol.js';

/** Settlement header mirrored by every PayKit SDK. */
const SETTLEMENT_SIGNATURE_HEADER = 'x-payment-settlement-signature';

type ChargeResult =
    | { readonly challenge: Response; readonly status: 402 }
    | { readonly status: 200; readonly withReceipt: (response: Response) => Response };
type ChargeHandler = (request: Request) => Promise<ChargeResult>;

type Split = { readonly amount: string; readonly recipient: string };

function splitsFor(gate: Gate): readonly Split[] {
    return gate.fees.map(fee => ({ amount: fee.price.baseUnits().toString(), recipient: fee.recipient }));
}

/**
 * The on-wire `amount` is the customer's total; the charge verifier carves
 * the splits out of it (`primary = amount − Σsplits`). With all fees lowered
 * to splits, `payTo` nets `gate.amount − Σwithin` — exactly `gate.payout()`.
 */
function totalAmount(gate: Gate): bigint {
    return gate.total().baseUnits();
}

/**
 * The MPP protocol adapter: wraps `@solana/mpp`'s charge method behind the
 * PayKit {@link ProtocolAdapter} contract. One Mppx handler is created per
 * distinct (recipient, splits) shape and cached.
 */
export function createMppAdapter(config: PayKitConfig): ProtocolAdapter {
    const network = toSolanaNetwork(config.network);
    const handlers = new Map<string, ChargeHandler>();

    function coinFor(gate: Gate): { coin: string; mint: string } {
        const coin = gate.amount.primaryCoin() ?? config.stablecoins[0] ?? 'USDC';
        const mint = resolveStablecoinMint(coin, network);
        if (!mint) throw new ConfigurationError(`No ${coin} mint known for ${config.network}.`);
        return { coin, mint };
    }

    function handlerFor(gate: Gate): ChargeHandler {
        const { mint } = coinFor(gate);
        const splits = splitsFor(gate);
        const key = JSON.stringify([gate.payTo, mint, splits]);
        let handler = handlers.get(key);
        if (!handler) {
            const mppx = Mppx.create({
                methods: [
                    solana.charge({
                        currency: mint,
                        decimals: 6,
                        network,
                        recipient: gate.payTo,
                        rpcUrl: config.rpcUrl,
                        ...(config.operator.feePayer ? { signer: config.operator.signer.signer } : {}),
                        ...(splits.length > 0 ? { splits: [...splits] } : {}),
                        ...(config.replayStore ? { store: config.replayStore } : {}),
                    }),
                ],
                realm: config.mpp.realm,
                secretKey: config.mpp.challengeBindingSecret,
            });
            handler = request => mppx.charge(optionsFor(gate))(request);
            handlers.set(key, handler);
        }
        return handler;
    }

    function optionsFor(gate: Gate) {
        return {
            amount: totalAmount(gate).toString(),
            ...(gate.description ? { description: gate.description } : {}),
            ...(gate.externalId ? { externalId: gate.externalId } : {}),
            ...(config.mpp.expiresIn > 0
                ? { expires: new Date(Date.now() + config.mpp.expiresIn * 1000).toISOString() }
                : {}),
        };
    }

    return {
        acceptsEntry(gate: Gate): Promise<AcceptsEntry> {
            const { coin } = coinFor(gate);
            const splits = splitsFor(gate);
            return Promise.resolve({
                amount: totalAmount(gate).toString(),
                currency: coin,
                network: caip2(config.network),
                payTo: gate.payTo,
                protocol: 'mpp',
                realm: config.mpp.realm,
                scheme: 'charge',
                ...(splits.length > 0 ? { splits } : {}),
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
                scheme: 'charge',
                settlementHeaders: {
                    ...(receiptHeader ? { 'payment-receipt': receiptHeader } : {}),
                    ...(transaction ? { [SETTLEMENT_SIGNATURE_HEADER]: transaction } : {}),
                },
                transaction,
            };
        },
    };
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
