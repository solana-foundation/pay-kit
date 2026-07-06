/**
 * Coverage for the in-repo challenge-serialize guard (shared/challenge-guard.ts).
 *
 * mppx's `Challenge.serialize` interpolates quoted-string parameter values
 * (`realm`, `description`, ...) verbatim: it neither escapes an embedded
 * backslash / double-quote nor rejects a carriage-return / newline. Its
 * `deserialize` is escape-aware, so the codec is asymmetric — a value with a
 * quote fails to round-trip, and a value with a CR/LF splits the emitted
 * `WWW-Authenticate` header (a header-injection surface). We close both gaps
 * at OUR `@solana/mpp` boundary, mirroring the existing deserialize guard.
 */
import { describe, expect, test } from 'vitest';

import { Challenge, deserialize, serialize, serializeList } from '../shared/challenge-guard.js';

const BASE = {
    id: 'ch_guard',
    intent: 'charge',
    method: 'tempo',
    realm: 'api.example.com',
    request: {},
} as const;

describe('challenge-guard serialize', () => {
    test('a quote/backslash-bearing field round-trips through deserialize', () => {
        // Before the fix mppx emits `description="Pay "premium" \ API"` with no
        // escaping, so deserialize truncates at the first inner quote and the
        // description comes back as "Pay " — a lossy round-trip. The guard must
        // escape backslash and quote so serialize -> deserialize is lossless.
        const challenge = { ...BASE, description: 'Pay "premium" \\ API', realm: 'a"b\\c' };
        const wire = serialize(challenge);
        const parsed = deserialize(wire);
        expect(parsed.description).toBe(challenge.description);
        expect(parsed.realm).toBe(challenge.realm);
    });

    test('a field containing a carriage-return is rejected', () => {
        // Before the fix serialize emits the CR verbatim, splitting the header.
        const challenge = { ...BASE, description: 'legit\rInjected-Header: evil' };
        expect(() => serialize(challenge)).toThrow(/carriage-return|newline|CR|LF/i);
    });

    test('a field containing a newline is rejected', () => {
        const challenge = { ...BASE, realm: 'api.example.com\nInjected-Header: evil' };
        expect(() => serialize(challenge)).toThrow(/carriage-return|newline|CR|LF/i);
    });

    test('a field containing a full CRLF is rejected', () => {
        const challenge = { ...BASE, description: 'a\r\nb' };
        expect(() => serialize(challenge)).toThrow(/carriage-return|newline|CR|LF/i);
    });

    test('a well-formed challenge with no special characters serializes unchanged', () => {
        const challenge = { ...BASE, description: 'plain description' };
        const wire = serialize(challenge);
        const parsed = deserialize(wire);
        expect(parsed.id).toBe(challenge.id);
        expect(parsed.description).toBe('plain description');
        expect(wire).not.toMatch(/[\r\n]/);
    });

    test('the emitted wire never contains a bare carriage-return or newline', () => {
        const challenge = { ...BASE, description: 'a "quoted" \\ value', realm: 'r"e\\alm' };
        expect(serialize(challenge)).not.toMatch(/[\r\n]/);
    });
});

describe('challenge-guard serializeList', () => {
    test('escapes and CR/LF-guards every challenge in the list', () => {
        const first = { ...BASE, id: 'ch_a', description: 'Pay "x" API' };
        const second = { ...BASE, id: 'ch_b', realm: 'r\\e"alm' };
        const wire = serializeList([first, second]);
        const parsed = Challenge.deserializeList(wire);
        expect(parsed.map(c => c.id)).toEqual(['ch_a', 'ch_b']);
        expect(parsed[0]?.description).toBe('Pay "x" API');
        expect(parsed[1]?.realm).toBe('r\\e"alm');
    });

    test('rejects the whole list when any challenge carries a CR/LF field', () => {
        const good = { ...BASE, id: 'ch_ok' };
        const bad = { ...BASE, id: 'ch_bad', description: 'x\r\ny' };
        expect(() => serializeList([good, bad])).toThrow(/carriage-return|newline|CR|LF/i);
    });
});

describe('challenge-guard Challenge namespace', () => {
    test('re-exports the guarded serialize entry points', () => {
        expect(Challenge.serialize).toBe(serialize);
        expect((Challenge as { serializeList: typeof serializeList }).serializeList).toBe(serializeList);
    });

    test('the guarded namespace serialize round-trips a quote-bearing field', () => {
        const challenge = { ...BASE, description: 'Pay "premium" API' };
        const parsed = Challenge.deserialize(Challenge.serialize(challenge));
        expect(parsed.description).toBe('Pay "premium" API');
    });
});
