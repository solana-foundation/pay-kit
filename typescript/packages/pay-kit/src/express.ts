/**
 * Express / Connect middleware over the PayKit dispatcher — the TypeScript
 * sibling of Ruby's Rack middleware and PHP's PSR-15 `RequirePayment`.
 *
 * Typed against `node:http` structurally, so it works with Express, Connect,
 * Polka, and anything else that speaks (req, res, next) — without adding a
 * framework dependency to this package.
 *
 * @example
 * ```ts
 * import { paid, payment, requirePayment } from '@solana/pay-kit/express';
 *
 * app.get('/report', requirePayment(paykit, 'report'), (req, res) => {
 *   res.json({ ok: true, tx: payment(req)?.transaction });
 * });
 * ```
 */
import { Buffer } from 'node:buffer';
import type { IncomingMessage, ServerResponse } from 'node:http';

import type { GateRef, PayKit } from './paykit.js';
import type { Payment } from './payment.js';

/** The minimal request shape the middleware needs. Express requests satisfy it. */
export type NodeRequest = IncomingMessage & {
    /** Express sets this to the full original path; plain node uses `url`. */
    readonly originalUrl?: string;
    /** Express sets this from the connection / trust-proxy settings. */
    readonly protocol?: string;
};

/** Connect-style continuation. */
export type NextFunction = (error?: unknown) => void;

const payments = new WeakMap<object, Payment>();

/** Converts a node request (headers, method, URL) into a web-standard `Request`. */
export function toWebRequest(req: NodeRequest): Request {
    const protocol = req.protocol ?? 'http';
    const host = req.headers.host ?? 'localhost';
    const url = new URL(req.originalUrl ?? req.url ?? '/', `${protocol}://${host}`);
    const headers = new Headers();
    for (const [name, value] of Object.entries(req.headers)) {
        if (value === undefined) continue;
        for (const entry of Array.isArray(value) ? value : [value]) headers.append(name, entry);
    }
    return new Request(url, { headers, method: req.method ?? 'GET' });
}

/** Writes a web-standard `Response` to a node response. */
export async function sendResponse(res: ServerResponse, response: Response): Promise<void> {
    res.writeHead(response.status, Object.fromEntries(response.headers));
    res.end(Buffer.from(await response.arrayBuffer()));
}

/**
 * Route middleware: verify-or-deny before the handler runs.
 *
 * On a missing or invalid payment the 402 challenge is written and the chain
 * stops. On success the verified {@link Payment} becomes available through
 * {@link payment}/{@link paid} and the settlement headers are set on the
 * response so the handler's reply carries the receipt.
 *
 * `gate` is the same union the dispatcher takes: a catalogue name, a `Gate`,
 * a bare `Price`, or a per-request resolver.
 */
export function requirePayment(
    paykit: PayKit,
    gate: GateRef,
): (req: NodeRequest, res: ServerResponse, next: NextFunction) => Promise<void> {
    return async (req, res, next) => {
        try {
            const result = await paykit.requirePayment(toWebRequest(req), gate);
            if (result.status === 402) {
                await sendResponse(res, result.response);
                return;
            }
            payments.set(req, result.payment);
            for (const [name, value] of Object.entries(result.payment.settlementHeaders)) {
                res.setHeader(name, value);
            }
            next();
        } catch (error) {
            next(error);
        }
    };
}

/** The verified payment on this request, or `undefined` until paid. */
export function payment(req: object): Payment | undefined {
    return payments.get(req);
}

/** Whether this request carries a verified payment (optionally for a specific gate). */
export function paid(req: object, gateName?: string): boolean {
    const verified = payments.get(req);
    return verified !== undefined && (gateName === undefined || verified.gateName === gateName);
}
