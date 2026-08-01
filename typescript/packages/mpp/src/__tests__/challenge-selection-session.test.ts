/**
 * Coverage for the session-side ChallengeSelection helpers
 * (selectSolanaSessionChallenge, selectSolanaSessionChallengeFromResponse,
 * and isSolanaSessionChallenge) against the mpp-specs e702dd8 session wire
 * contract: SessionRequest carries amount + methodDetails (channelProgram,
 * network, voucherSigner, recentBlockhash/recentSlot for new channels, or
 * channelId for resume) instead of the superseded top-level cap/programId
 * draft fields.
 */
import { Challenge } from 'mppx';

import { USDC } from '../constants.js';
import {
    isSolanaSessionChallenge,
    selectSolanaSessionChallenge,
    selectSolanaSessionChallengeFromResponse,
    type SolanaSessionChallenge,
} from '../client/ChallengeSelection.js';

const recipient = 'CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY';
const CHANNEL_PROGRAM = 'CHNLxYvVA28MJP9PrFuDXccuoGXAx7jBacfLEkahyGsX';
const RECENT_BLOCKHASH = 'EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N';

function sessionChallenge(
    id: string,
    overrides: {
        channelId?: string;
        currency?: string;
        intent?: string;
        method?: string;
        network?: string;
    } = {},
): Challenge.Challenge {
    const resume = overrides.channelId !== undefined;
    return {
        id,
        intent: overrides.intent ?? 'session',
        method: overrides.method ?? 'solana',
        realm: 'test',
        request: {
            amount: '1000',
            currency: overrides.currency ?? USDC.devnet,
            methodDetails: {
                channelProgram: CHANNEL_PROGRAM,
                network: overrides.network ?? 'devnet',
                voucherSigner: 'client',
                ...(resume
                    ? { channelId: overrides.channelId }
                    : { recentBlockhash: RECENT_BLOCKHASH, recentSlot: '123456789' }),
            },
            recipient,
        },
    };
}

describe('isSolanaSessionChallenge', () => {
    test('returns true for a valid solana session challenge', () => {
        expect(isSolanaSessionChallenge(sessionChallenge('s1'))).toBe(true);
    });

    test('returns true for a resume challenge carrying a channelId', () => {
        expect(isSolanaSessionChallenge(sessionChallenge('s1', { channelId: 'chan-1' }))).toBe(true);
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

    test('returns false when methodDetails is missing required fields', () => {
        const ch = sessionChallenge('s1');
        // channelProgram is required by the session wire contract.
        delete ((ch.request as Record<string, unknown>).methodDetails as Record<string, unknown>).channelProgram;
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

    test('normalizes the legacy mainnet-beta alias when filtering by network', () => {
        const sel = selectSolanaSessionChallenge(
            [sessionChallenge('dev', { network: 'devnet' }), sessionChallenge('main', { network: 'mainnet' })],
            { network: 'mainnet-beta' },
        );
        expect(sel?.id).toBe('main');
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

    test('returns undefined when no session challenge matches the filters', () => {
        const sel = selectSolanaSessionChallenge(
            [sessionChallenge('main', { currency: USDC.mainnet, network: 'mainnet' })],
            { currency: 'USDC', network: 'devnet' },
        );
        expect(sel).toBeUndefined();
    });

    test('narrows valid session challenges to the typed request shape', () => {
        const candidate = sessionChallenge('typed');
        expect(isSolanaSessionChallenge(candidate)).toBe(true);

        const typed = candidate as SolanaSessionChallenge;
        expect(typed.request.methodDetails.channelProgram).toBe(CHANNEL_PROGRAM);
        expect(typed.request.methodDetails.network).toBe('devnet');
        expect(typed.request.methodDetails.recentBlockhash).toBe(RECENT_BLOCKHASH);
        expect(typed.request.methodDetails.recentSlot).toBe('123456789');
    });
});

describe('selectSolanaSessionChallengeFromResponse', () => {
    test('throws when the response is missing a WWW-Authenticate header', () => {
        const response = new Response(null, { status: 402 });
        expect(() => selectSolanaSessionChallengeFromResponse(response)).toThrow();
    });

    test('selects from HTTP WWW-Authenticate challenges', () => {
        const response = new Response(null, {
            headers: {
                'WWW-Authenticate': [
                    Challenge.serialize(
                        sessionChallenge('usdc-mainnet', { currency: USDC.mainnet, network: 'mainnet' }),
                    ),
                    Challenge.serialize(sessionChallenge('usdc-devnet')),
                ].join(', '),
            },
            status: 402,
        });

        const selected = selectSolanaSessionChallengeFromResponse(response, {
            currency: 'USDC',
            network: 'devnet',
        });

        expect(selected?.id).toBe('usdc-devnet');
    });
});
