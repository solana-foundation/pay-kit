import { describe, expect, it } from 'vitest';

import { type ExpressRoutesApp, GATE_METADATA, introspectExpressRoutes } from '../express-routes.js';

/** A gate-tagged middleware, like the one `pay.express(gate)` returns. */
function tagged(gate: unknown): { [GATE_METADATA]: unknown } {
    return Object.assign(() => undefined, { [GATE_METADATA]: gate });
}

describe('introspectExpressRoutes', () => {
    it('reads the Express 4 lazily-created _router stack', () => {
        const app: ExpressRoutesApp = {
            _router: {
                stack: [{ route: { methods: { get: true }, path: '/report', stack: [{ handle: tagged('report') }] } }],
            },
        };
        expect(introspectExpressRoutes(app)).toEqual([{ gate: 'report', method: 'GET', path: '/report' }]);
    });

    it('falls back to the Express 5 router stack when _router is absent', () => {
        const app: ExpressRoutesApp = {
            router: {
                stack: [{ route: { methods: { post: true }, path: '/pay', stack: [{ handle: tagged('gate5') }] } }],
            },
        };
        expect(introspectExpressRoutes(app)).toEqual([{ gate: 'gate5', method: 'POST', path: '/pay' }]);
    });

    it('tolerates the Express 4.22+ router getter that throws a deprecation error', () => {
        const app = {
            get router(): { stack?: never[] } {
                throw new Error('router is deprecated');
            },
        } as unknown as ExpressRoutesApp;
        expect(introspectExpressRoutes(app)).toEqual([]);
    });

    it('returns an empty stack when neither _router nor router is present', () => {
        expect(introspectExpressRoutes({})).toEqual([]);
        // router present but with no stack -> `?? []`.
        expect(introspectExpressRoutes({ router: {} })).toEqual([]);
    });

    it('skips layers without a route or without a route path', () => {
        const app: ExpressRoutesApp = {
            _router: {
                stack: [
                    {}, // no route at all
                    { route: { methods: { get: true }, stack: [{ handle: tagged('x') }] } }, // route without path
                    { route: { methods: { get: true }, path: '/ok', stack: [{ handle: tagged('kept') }] } },
                ],
            },
        };
        expect(introspectExpressRoutes(app)).toEqual([{ gate: 'kept', method: 'GET', path: '/ok' }]);
    });

    it('ignores routes whose handler stack carries no gate (untagged free routes)', () => {
        const app: ExpressRoutesApp = {
            _router: {
                stack: [
                    { route: { methods: { get: true }, path: '/health', stack: [{ handle: () => undefined }] } },
                    { route: { methods: { get: true }, path: '/free' } }, // no stack at all
                ],
            },
        };
        expect(introspectExpressRoutes(app)).toEqual([]);
    });

    it('converts :params to {params} and expands an array of paths', () => {
        const app: ExpressRoutesApp = {
            _router: {
                stack: [
                    {
                        route: {
                            methods: { get: true },
                            path: ['/q/:sym', '/quote/:sym'],
                            stack: [{ handle: tagged('quote') }],
                        },
                    },
                ],
            },
        };
        expect(introspectExpressRoutes(app)).toEqual([
            { gate: 'quote', method: 'GET', path: '/q/{sym}' },
            { gate: 'quote', method: 'GET', path: '/quote/{sym}' },
        ]);
    });

    it('emits one entry per method and defaults to GET when methods are absent', () => {
        const app: ExpressRoutesApp = {
            _router: {
                stack: [
                    {
                        route: {
                            methods: { get: true, post: true },
                            path: '/multi',
                            stack: [{ handle: tagged('m') }],
                        },
                    },
                    // No `methods` map -> defaults to { get: true }.
                    { route: { path: '/defaulted', stack: [{ handle: tagged('d') }] } },
                ],
            },
        };
        const routes = introspectExpressRoutes(app);
        expect(routes).toContainEqual({ gate: 'm', method: 'GET', path: '/multi' });
        expect(routes).toContainEqual({ gate: 'm', method: 'POST', path: '/multi' });
        expect(routes).toContainEqual({ gate: 'd', method: 'GET', path: '/defaulted' });
    });
});
