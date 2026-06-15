import type { GateRef, PayKit } from './paykit.js';
import type { Payment } from './payment.js';

/**
 * Wraps a fetch-style handler with payment gating — for Cloudflare Workers,
 * Bun, Deno, and Next.js route handlers, where the unit of composition is
 * `(request: Request) => Response` rather than middleware.
 *
 * Unpaid requests get the 402 challenge; paid requests run `handler` with
 * the verified {@link Payment} and the reply carries the settlement headers.
 *
 * @example
 * ```ts
 * export default {
 *   fetch: withPayment(paykit, usd('0.10'), (request, payment) =>
 *     Response.json({ ok: true, tx: payment.transaction }),
 *   ),
 * };
 * ```
 */
export function withPayment(
    paykit: PayKit,
    gate: GateRef,
    handler: (request: Request, payment: Payment) => Promise<Response> | Response,
): (request: Request) => Promise<Response> {
    return async request => {
        const result = await paykit.requirePayment(request, gate);
        if (result.status === 402) return result.response;
        return result.withSettlement(await handler(request, result.payment));
    };
}
