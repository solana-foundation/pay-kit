/**
 * Coverage for the session-side ChallengeSelection helpers
 * (selectSolanaSessionChallenge, selectSolanaSessionChallengeFromResponse,
 * isSolanaSessionChallenge, and matchesSessionNetwork/Currency).
 */
import { test, expect, describe } from 'vitest';
import { Challenge } from 'mppx';

import { USDC } from '../constants.js';
import {
    isSolanaSessionChallenge,
    selectSolanaSessionChallenge,
    selectSolanaSessionChallengeFromResponse,
} from '../client/ChallengeSelection.js';

const recipient = 'CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY';

function sessionChallenge(
    id: string,
    overrides: {
        currency?: string;
        network?: string;
        modes?: string[];
        method?: string;
        intent?: string;
    } = {},
): Challenge.Challenge {
    return {
        id,
        intent: overrides.intent ?? 'session',
        method: overrides.method ?? 'solana',
        realm: 'test',
        request: {
            cap: '1000000',
            currency: overrides.currency ?? USDC.devnet,
            operator: recipient,
            recipient,
            network: overrides.network ?? 'devnet',
            modes: overrides.modes,
        },
    };
}

describe('isSolanaSessionChallenge', () => {
    test('returns true for a valid solana session challenge', () => {
        expect(isSolanaSessionChallenge(sessionChallenge('s1'))).toBe(true);
    });

    test('returns false for non-solana method', () => {
        expect(isSolanaSessionChallenge(sessionChallenge('s1', { method: 'evm' }))).toBe(false);
    });

    test('returns false for non-session intent', () => {
        expect(isSolanaSessionChallenge(sessionChallenge('s1', { intent: 'charge' }))).toBe(false);
    });

    test('returns false when the request shape is invalid', () => {
        const ch = sessionChallenge('s1');
        // Strip required field.
        delete (ch.request as Record<string, unknown>).recipient;
        expect(isSolanaSessionChallenge(ch)).toBe(false);
    });
});

describe('selectSolanaSessionChallenge', () => {
    test('selects the first matching session challenge by default', () => {
        const sel = selectSolanaSessionChallenge([sessionChallenge('a'), sessionChallenge('b')]);
        expect(sel?.id).toBe('a');
    });

    test('skips non-session and non-solana challenges', () => {
        const sel = selectSolanaSessionChallenge([
            sessionChallenge('skip', { method: 'evm' }),
            sessionChallenge('keep'),
        ]);
        expect(sel?.id).toBe('keep');
    });

    test('throws when a solana session challenge has an invalid request shape', () => {
        const ch = sessionChallenge('bad');
        delete (ch.request as Record<string, unknown>).recipient;
        expect(() => selectSolanaSessionChallenge([ch])).toThrow('Invalid Solana session challenge request');
    });

    test('filters by network when network option provided', () => {
        const sel = selectSolanaSessionChallenge(
            [sessionChallenge('main', { network: 'mainnet' }), sessionChallenge('dev', { network: 'devnet' })],
            { network: 'devnet' },
        );
        expect(sel?.id).toBe('dev');
    });

    test('filters by currency when currency option provided', () => {
        const sel = selectSolanaSessionChallenge(
            [
                sessionChallenge('usdc'),
                sessionChallenge('cash', { currency: 'CASHx9KJUStyftLFWGvEVf59SGeG9sh5FfcnZMVPCASH' }),
            ],
            { currency: 'USDC', network: 'devnet' },
        );
        expect(sel?.id).toBe('usdc');
    });

    test('returns undefined when no candidate matches the requested mode', () => {
        const sel = selectSolanaSessionChallenge([sessionChallenge('only-push', { modes: ['push'] })], {
            mode: 'pull',
        });
        expect(sel).toBeUndefined();
    });

    test('selects by string mode', () => {
        const sel = selectSolanaSessionChallenge(
            [sessionChallenge('push-only', { modes: ['push'] }), sessionChallenge('pull-only', { modes: ['pull'] })],
            { mode: 'pull' },
        );
        expect(sel?.id).toBe('pull-only');
    });

    test('selects by array of preferred modes', () => {
        const sel = selectSolanaSessionChallenge(
            [sessionChallenge('push-only', { modes: ['push'] }), sessionChallenge('pull-only', { modes: ['pull'] })],
            { mode: ['pull', 'push'] },
        );
        // First candidate matches → returns first.
        expect(sel?.id === 'push-only' || sel?.id === 'pull-only').toBe(true);
    });

    test('defaults challenges without modes to ["push"]', () => {
        const sel = selectSolanaSessionChallenge([sessionChallenge('no-modes')], { mode: 'push' });
        expect(sel?.id).toBe('no-modes');
    });
});

describe('selectSolanaSessionChallengeFromResponse', () => {
    test('throws when the response is missing a WWW-Authenticate header', () => {
        const response = new Response(null, { status: 402 });
        expect(() => selectSolanaSessionChallengeFromResponse(response)).toThrow();
    });
});
