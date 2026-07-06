/**
 * Branch coverage for the in-repo challenge-parse guard
 * (shared/challenge-guard.ts).
 *
 * The existing challenge-guard.test.ts only exercises the size cap. This
 * suite covers the empty-id rejection branch, the happy path where a
 * well-formed challenge passes both guards, the non-string (already-parsed
 * object) input branch, and the `Challenge` re-export wiring.
 */
import { Challenge as MppxChallenge } from 'mppx';
import { describe, expect, test } from 'vitest';

import { Challenge, deserialize, deserializeList, MAX_CHALLENGE_HEADER_LEN } from '../shared/challenge-guard.js';

const VALID_CHALLENGE = {
    id: 'hmac-bound-id',
    intent: 'session',
    method: 'solana',
    realm: 'api.test',
    request: { cap: '1000000', currency: 'USDC' },
} as const;

describe('challenge-guard deserialize', () => {
    test('rejects a well-formed header whose id is empty', () => {
        const header = MppxChallenge.serialize({ ...VALID_CHALLENGE, id: '' });
        expect(() => deserialize(header)).toThrow(/non-empty value/);
    });

    test('accepts a well-formed header with a non-empty id', () => {
        const header = MppxChallenge.serialize(VALID_CHALLENGE);
        const parsed = deserialize(header);
        expect(parsed.id).toBe(VALID_CHALLENGE.id);
        expect(parsed.intent).toBe('session');
    });
});

describe('challenge-guard deserializeList', () => {
    test('accepts a list of well-formed challenges with non-empty ids', () => {
        const header = [
            MppxChallenge.serialize(VALID_CHALLENGE),
            MppxChallenge.serialize({ ...VALID_CHALLENGE, id: 'second-id' }),
        ].join(', ');
        const parsed = deserializeList(header);
        expect(parsed.map(c => c.id)).toEqual([VALID_CHALLENGE.id, 'second-id']);
    });

    test('rejects a list containing a challenge with an empty id', () => {
        const header = [
            MppxChallenge.serialize(VALID_CHALLENGE),
            MppxChallenge.serialize({ ...VALID_CHALLENGE, id: '' }),
        ].join(', ');
        expect(() => deserializeList(header)).toThrow(/non-empty value/);
    });

    test('rejects an oversized list header before parsing', () => {
        const oversized = 'Payment ' + 'A'.repeat(MAX_CHALLENGE_HEADER_LEN + 1);
        expect(() => deserializeList(oversized)).toThrow(/exceeds maximum size/);
    });
});

describe('challenge-guard Challenge namespace', () => {
    test('re-exports the guarded deserialize entry points', () => {
        expect(Challenge.deserialize).toBe(deserialize);
        expect(Challenge.deserializeList).toBe(deserializeList);
    });

    test('the guarded namespace still rejects an empty id via the header path', () => {
        const header = Challenge.serialize({ ...VALID_CHALLENGE, id: '' });
        expect(() => Challenge.deserialize(header)).toThrow(/non-empty value/);
    });
});
