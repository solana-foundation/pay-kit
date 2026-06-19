/**
 * Express route introspection for OpenAPI discovery. The middleware returned by
 * {@link import('./paykit.js').PayKit.express} is tagged with its gate
 * ({@link GATE_METADATA}); walking the router stack then pairs each mounted
 * path + method with the gate guarding it — so the discovery document is
 * derived from how routes are actually mounted, with no hand-written table.
 *
 * A generic route enumerator (e.g. `express-list-endpoints`) surfaces paths and
 * method names but not the handler references needed to recover the gate, so
 * the small stack walk here is intentional. Tolerant of Express 4 (`_router`)
 * and Express 5 (`router`).
 */

/** Symbol under which `pay.express(gate)` stashes the gate on its middleware. */
export const GATE_METADATA = Symbol.for('paykit.openapi.gate');

/** A route discovered on an Express app: HTTP method, OpenAPI path, and its gate. */
export type IntrospectedRoute = { gate: unknown; method: string; path: string };

type RouteLayer = {
    route?: { methods?: Record<string, boolean>; path?: string[] | string; stack?: { handle?: unknown }[] };
};

/** The minimal Express-app shape this introspection needs (Express 4 or 5). */
export type ExpressRoutesApp = {
    _router?: { stack?: RouteLayer[] };
    router?: { stack?: RouteLayer[] };
};

/** Convert an Express path (`/q/:sym`) to the OpenAPI form (`/q/{sym}`). */
function toOpenApiPath(path: string): string {
    return path.replace(/:([A-Za-z0-9_]+)/g, '{$1}');
}

/**
 * The router stack, tolerant of Express 4 vs 5. Express 4 lazily creates
 * `_router` (present once routes are mounted); Express 5 exposes `router`.
 * Probe `_router` first because in Express 4.22+ the `router` getter *throws*
 * a deprecation error rather than returning undefined.
 */
function routerStackOf(app: ExpressRoutesApp): RouteLayer[] {
    if (app._router?.stack) return app._router.stack;
    try {
        return app.router?.stack ?? [];
    } catch {
        return [];
    }
}

function gateOf(stack: { handle?: unknown }[] | undefined): unknown {
    for (const layer of stack ?? []) {
        const gate = (layer.handle as { [GATE_METADATA]?: unknown } | undefined)?.[GATE_METADATA];
        if (gate !== undefined) return gate;
    }
    return undefined;
}

/**
 * Enumerate the gated routes mounted on an Express app.
 *
 * @param app - The Express application (or router) to introspect
 * @returns One entry per (method, path) guarded by a `pay.express` gate
 */
export function introspectExpressRoutes(app: ExpressRoutesApp): IntrospectedRoute[] {
    const stack = routerStackOf(app);
    const routes: IntrospectedRoute[] = [];
    for (const layer of stack) {
        const route = layer.route;
        if (!route?.path) continue;
        const gate = gateOf(route.stack);
        if (gate === undefined) continue;
        const paths = Array.isArray(route.path) ? route.path : [route.path];
        for (const path of paths) {
            for (const method of Object.keys(route.methods ?? { get: true })) {
                routes.push({ gate, method: method.toUpperCase(), path: toOpenApiPath(path) });
            }
        }
    }
    return routes;
}
