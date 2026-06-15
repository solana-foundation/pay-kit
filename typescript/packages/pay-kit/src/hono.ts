/**
 * Middleware for Hono and any other framework whose context exposes the
 * web-standard request as `c.req.raw` and the outgoing response as `c.res`.
 *
 * Typed structurally, so this package does not depend on Hono. Because the
 * dispatcher tracks verified payments by the web `Request` itself, no
 * context variable is needed — read the proof with `paykit.payment(c.req.raw)`.
 *
 * @example
 * ```ts
 * import { requirePayment } from '@solana/pay-kit/hono';
 *
 * app.use('/report', requirePayment(paykit, 'report'));
 * app.get('/report', c => c.json({ ok: true, tx: paykit.payment(c.req.raw)?.transaction }));
 * ```
 */
import type { GateRef, PayKit } from './paykit.js';

/** The minimal context shape the middleware needs. Hono's `Context` satisfies it. */
export type WebContext = {
    readonly req: { readonly raw: Request };
    readonly res: Response;
};

/** Hono-style continuation. */
export type WebNext = () => Promise<void>;

/**
 * Route middleware: verify-or-deny before downstream handlers run.
 *
 * Returns the 402 challenge `Response` when the request is unpaid (Hono
 * short-circuits on a returned response). On success it runs the rest of the
 * chain and merges the settlement headers into the final response.
 */
export function requirePayment(
    paykit: PayKit,
    gate: GateRef,
): (c: WebContext, next: WebNext) => Promise<Response | undefined> {
    return async (c, next) => {
        const result = await paykit.requirePayment(c.req.raw, gate);
        if (result.status === 402) return result.response;
        await next();
        for (const [name, value] of Object.entries(result.payment.settlementHeaders)) {
            c.res.headers.set(name, value);
        }
        return undefined;
    };
}
