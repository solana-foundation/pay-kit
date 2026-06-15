import { generateKeyPairSigner } from '@solana/kit';
import { describe, expect, test } from 'vitest';

import {
    ActiveSession,
    selectSolanaSessionChallenge,
    type SessionChallenge,
    sessionRequestModes,
} from '../client/index.js';

const recipient = 'CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY';

function sessionChallenge(overrides: Partial<SessionChallenge['request']> = {}): SessionChallenge {
    return {
        id: 'session-client-test',
        intent: 'session',
        method: 'solana',
        realm: 'test',
        request: {
            cap: '1000000',
            currency: 'USDC',
            decimals: 6,
            network: 'localnet',
            operator: recipient,
            recipient,
            ...overrides,
        },
    };
}

describe('sessionRequestModes', () => {
    test('treats an empty modes array the same as an omitted one: push-only', () => {
        expect(sessionRequestModes({})).toEqual(['push']);
        expect(sessionRequestModes({ modes: [] })).toEqual(['push']);
        expect(sessionRequestModes({ modes: ['pull'] })).toEqual(['pull']);
        expect(sessionRequestModes({ modes: ['pull', 'push'] })).toEqual(['pull', 'push']);
    });
});

describe('selectSolanaSessionChallenge with empty modes', () => {
    test('a challenge with modes: [] matches push preferences', () => {
        const challenge = sessionChallenge({ modes: [] });
        expect(selectSolanaSessionChallenge([challenge], { mode: 'push' })).toMatchObject({
            id: 'session-client-test',
        });
    });

    test('a challenge with modes: [] does not match pull preferences', () => {
        const challenge = sessionChallenge({ modes: [] });
        expect(selectSolanaSessionChallenge([challenge], { mode: 'pull' })).toBeUndefined();
    });
});

describe('ActiveSession nonce validation', () => {
    test('rejects nonces above Number.MAX_SAFE_INTEGER at construction', async () => {
        const signer = await generateKeyPairSigner();
        const channel = await generateKeyPairSigner();
        expect(
            () =>
                new ActiveSession({
                    channelId: channel.address,
                    nonce: 2n ** 53n,
                    signer,
                }),
        ).toThrow('nonce exceeds Number.MAX_SAFE_INTEGER');
    });

    test('accepts safe-integer nonces', async () => {
        const signer = await generateKeyPairSigner();
        const channel = await generateKeyPairSigner();
        const session = new ActiveSession({ channelId: channel.address, nonce: 41n, signer });
        expect(session.nonce).toBe(41);
    });
});
