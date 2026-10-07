import { describe, expect, test } from 'vitest';
import { Store } from 'mppx/server';

import {
    claimReplayKey,
    confirmReplayKey,
    consumeReplayKey,
    inspectReplayKey,
    reserveReplayKey,
} from '../server/replay.js';

describe('reserveReplayKey', () => {
    test('allows exactly one concurrent claimant', async () => {
        const store = Store.memory();
        const results = await Promise.all(
            Array.from({ length: 16 }, () => reserveReplayKey(store, 'solana-charge:consumed:same-signature')),
        );

        expect(results.filter(Boolean)).toHaveLength(1);
    });
});

describe.each([false, true])('single-use charge consumption (atomic=%s)', atomic => {
    test('only one overlapping settlement can grant access, including after lease expiry', async () => {
        const backing = Store.memory();
        const store = atomic ? backing : { get: backing.get, put: backing.put, delete: backing.delete };
        const key = 'solana-charge:consumed:overlapping-owners';
        await claimReplayKey(store, key, 'challenge-a');
        await store.put(key, { binding: 'challenge-a', leaseUntil: 0, state: 'pending' });
        await expect(claimReplayKey(store, key, 'challenge-a')).resolves.toBe('reserved');

        const outcomes = await Promise.all(
            Array.from({ length: 16 }, () => consumeReplayKey(store, key, 'challenge-a')),
        );
        expect(outcomes.filter(Boolean)).toHaveLength(1);
        await expect(consumeReplayKey(store, key, 'challenge-a')).resolves.toBe(false);
        await expect(consumeReplayKey(store, key, 'challenge-b')).resolves.toBe(false);
    });

    test('does not consume missing or differently bound reservations', async () => {
        const backing = Store.memory();
        const store = atomic ? backing : { get: backing.get, put: backing.put, delete: backing.delete };
        const key = 'solana-charge:consumed:binding';
        await expect(consumeReplayKey(store, key, 'challenge-a')).resolves.toBe(false);
        await claimReplayKey(store, key, 'challenge-a');
        await expect(consumeReplayKey(store, key, 'challenge-b')).resolves.toBe(false);
        await expect(consumeReplayKey(store, key, 'challenge-a')).resolves.toBe(true);
    });
});

describe('challenge-bound subscription receipt recovery', () => {
    test('allows the same challenge to resume and rejects a different challenge', async () => {
        const store = Store.memory();
        const key = 'solana-charge:consumed:same-signature';

        await expect(claimReplayKey(store, key, 'challenge-a')).resolves.toBe('reserved');
        await expect(claimReplayKey(store, key, 'challenge-a')).resolves.toBe('pending');
        await expect(claimReplayKey(store, key, 'challenge-b')).resolves.toBe('conflict');

        await confirmReplayKey(store, key, 'challenge-a');
        await expect(claimReplayKey(store, key, 'challenge-a')).resolves.toBe('retry');
        await expect(claimReplayKey(store, key, 'challenge-b')).resolves.toBe('conflict');
    });

    test('distinguishes confirmed and expired records before settlement RPCs', async () => {
        const store = Store.memory();
        const key = 'solana-charge:consumed:recovery-signature';

        await store.put(key, { binding: 'challenge-a', leaseUntil: 0, state: 'pending' });
        await expect(inspectReplayKey(store, key, 'challenge-a')).resolves.toBe('expired');

        await store.put(key, { binding: 'challenge-a', leaseUntil: 0, state: 'confirmed' });
        await expect(inspectReplayKey(store, key, 'challenge-a')).resolves.toBe('retry');
        await expect(inspectReplayKey(store, key, 'challenge-b')).resolves.toBe('conflict');
    });
});
