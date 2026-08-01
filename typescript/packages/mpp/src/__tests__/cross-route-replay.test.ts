/**
 * Cross-route credential replay regression tests.
 *
 * mppx implements a route-aware binding check (see ~/Coding/mppx/src/server/Mppx.ts):
 * after HMAC, it compares the route's expected `challenge.request` to the
 * credential's claimed `challenge.request` on `amount/currency/recipient/...`.
 *
 * That check only works if the method's `request()` hook returns the route's
 * expected request — not the credential-supplied one. An earlier version of
 * our Solana `charge()` short-circuited to `credential.challenge.request`,
 * which made `challenge.request === credential.challenge.request` and
 * trivially passed the binding check, opening cross-route credential replay.
 *
 * These tests drive the full mppx flow and would have caught that bug.
 */
import { test, expect } from 'vitest';
import { Challenge, Credential } from 'mppx';
import { Mppx } from 'mppx/server';
import { charge } from '../server/Charge.js';

const RECIPIENT = '9xAXssX9j7vuK99c7cFwqbixzL3bFrzPy9PUhCtDPAYJ';
const SECRET_KEY = 'cross-route-replay-test-secret-at-least-32-bytes';
const REALM = 'api.example.com';

function makeHandler() {
    return Mppx.create({
        methods: [charge({ recipient: RECIPIENT, network: 'devnet', rpcUrl: 'https://mock-rpc' })],
        realm: REALM,
        secretKey: SECRET_KEY,
    });
}

async function getChallenge(handler: ReturnType<typeof makeHandler>, amount: string) {
    const result = await handler.charge({
        amount,
        currency: 'sol',
        expires: new Date(Date.now() + 60_000).toISOString(),
        recipient: RECIPIENT,
    })(new Request('https://example.com/cheap'));

    if (result.status !== 402) throw new Error(`expected 402 from initial route, got ${result.status}`);
    return Challenge.fromResponse(result.challenge);
}

test('cross-route: credential issued for /cheap is rejected at /expensive (different amount)', async () => {
    const handler = makeHandler();

    const cheap = await getChallenge(handler, '1000');
    const credential = Credential.from({
        challenge: cheap,
        payload: { type: 'signature', signature: '5UfDuX6nSqMzMR8W7n6K3b1GKLmaqEisBFCcYPRLjNHrCbVQJF3BVjkE7aQJMQ2K' },
    });

    const expensiveHandle = handler.charge({
        amount: '1000000',
        currency: 'sol',
        expires: new Date(Date.now() + 60_000).toISOString(),
        recipient: RECIPIENT,
    });
    const result = await expensiveHandle(
        new Request('https://example.com/expensive', {
            headers: { Authorization: Credential.serialize(credential) },
        }),
    );

    expect(result.status).toBe(402);
    if (result.status !== 402) return;

    const body = (await result.challenge.json()) as { detail: string };
    expect(body.detail).toMatch(/does not match|amount/i);
});

test('cross-route: credential issued for one currency is rejected at another', async () => {
    // Two routes on the same handler, different currencies.
    const handler = Mppx.create({
        methods: [charge({ recipient: RECIPIENT, network: 'devnet', rpcUrl: 'https://mock-rpc' })],
        realm: REALM,
        secretKey: SECRET_KEY,
    });

    const solRoute = handler.charge({
        amount: '1000',
        currency: 'sol',
        expires: new Date(Date.now() + 60_000).toISOString(),
        recipient: RECIPIENT,
    });
    const solResult = await solRoute(new Request('https://example.com/sol'));
    if (solResult.status !== 402) throw new Error('expected 402');
    const solChallenge = Challenge.fromResponse(solResult.challenge);

    const credential = Credential.from({
        challenge: solChallenge,
        payload: { type: 'signature', signature: '5UfDuX6nSqMzMR8W7n6K3b1GKLmaqEisBFCcYPRLjNHrCbVQJF3BVjkE7aQJMQ2K' },
    });

    // Replay the SOL credential at a USDC route.
    const usdcRoute = handler.charge({
        amount: '1000',
        currency: 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v',
        expires: new Date(Date.now() + 60_000).toISOString(),
        recipient: RECIPIENT,
    });
    const result = await usdcRoute(
        new Request('https://example.com/usdc', {
            headers: { Authorization: Credential.serialize(credential) },
        }),
    );

    expect(result.status).toBe(402);
    if (result.status !== 402) return;

    const body = (await result.challenge.json()) as { detail: string };
    expect(body.detail).toMatch(/does not match|currency/i);
});

test('same-route: a freshly-issued challenge round-trips through request() with route values', async () => {
    // Ensures the fix didn't break the legitimate path: when the credential
    // matches the route, the binding check passes and we proceed to verify.
    // (We expect verify to fail downstream because the payload is bogus, but
    // crucially the failure must not be a binding-check 402.)
    const handler = makeHandler();
    const chal = await getChallenge(handler, '1000');
    const credential = Credential.from({
        challenge: chal,
        payload: { type: 'signature', signature: '5UfDuX6nSqMzMR8W7n6K3b1GKLmaqEisBFCcYPRLjNHrCbVQJF3BVjkE7aQJMQ2K' },
    });

    // Re-issue via a route with identical params.
    const sameRoute = handler.charge({
        amount: '1000',
        currency: 'sol',
        expires: new Date(Date.now() + 60_000).toISOString(),
        recipient: RECIPIENT,
    });
    const result = await sameRoute(
        new Request('https://example.com/route', {
            headers: { Authorization: Credential.serialize(credential) },
        }),
    );

    // The binding check should pass; the failure (if any) should come from
    // downstream verification, not from a "does not match" binding mismatch.
    if (result.status === 402) {
        const body = (await result.challenge.json()) as { detail: string };
        expect(body.detail).not.toMatch(/does not match this route's requirements/i);
    }
});
