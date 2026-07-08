/**
 * Internal HTTP glue shared by the instance framework handlers
 * ({@link PayKit.express}, {@link PayKit.hono}). Typed structurally against
 * `node:http` and Hono's context so this package depends on neither framework.
 */
import { Buffer } from 'node:buffer';
import type { IncomingMessage, ServerResponse } from 'node:http';

/** The minimal node request shape the middleware needs. Express requests satisfy it. */
export type NodeRequest = IncomingMessage & {
    /** Express sets this to the full original path; plain node uses `url`. */
    readonly originalUrl?: string;
    /** Express sets this from the connection / trust-proxy settings. */
    readonly protocol?: string;
};

/** A node `ServerResponse`, re-exported so callers need not import `node:http`. */
export type NodeResponse = ServerResponse;

/** Connect-style continuation. */
export type NextFunction = (error?: unknown) => void;

/** The minimal context shape the Hono handler needs. Hono's `Context` satisfies it. */
export type WebContext = {
    readonly req: { readonly raw: Request };
    readonly res: Response;
};

/** Hono-style continuation. */
export type WebNext = () => Promise<void>;

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
