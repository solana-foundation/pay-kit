/**
 * Test helper: stubs the client's cluster RPC that the session open builder
 * consults (`isBlockhashValid`) before signing over the challenged
 * blockhash. The check is mandatory and defaults to the challenged
 * network's public RPC, so unit tests that build opens stub `fetch` instead
 * of reaching the network.
 */
import { vi } from 'vitest';

export interface ClusterRpcStub {
    /** Blockhashes queried through `isBlockhashValid`, with the RPC URL each was sent to. */
    readonly checks: { readonly blockhash: string; readonly url: string }[];
    /** Whether the stub reports the queried blockhash as live. */
    live: boolean;
}

/** Replaces global `fetch` with a JSON-RPC stub answering `isBlockhashValid`. Undo with `vi.unstubAllGlobals()`. */
export function stubClusterRpc(): ClusterRpcStub {
    const stub: ClusterRpcStub = { checks: [], live: true };
    vi.stubGlobal('fetch', async (url: unknown, init?: { body?: unknown }) => {
        const { id, method, params } = JSON.parse(String(init?.body)) as {
            id: number;
            method: string;
            params: unknown[];
        };
        if (method !== 'isBlockhashValid') {
            throw new Error(`cluster RPC stub: unexpected method ${method}`);
        }
        stub.checks.push({ blockhash: String(params[0]), url: String(url) });
        return new Response(
            JSON.stringify({ id, jsonrpc: '2.0', result: { context: { slot: 1 }, value: stub.live } }),
            {
                headers: { 'content-type': 'application/json' },
            },
        );
    });
    return stub;
}
