import { describe, expect, test } from 'vitest';
import { Store } from 'mppx/server';

import { claimReplayKey, confirmReplayKey, inspectReplayKey, reserveReplayKey } from '../server/replay.js';

describe('reserveReplayKey', () => {
    test('allows exactly one concurrent claimant', async () => {
        const store = Store.memory();
        const results = await Promise.all(
            Array.from({ length: 16 }, () => reserveReplayKey(store, 'solana-charge:consumed:same-signature')),
        );

        expect(results.filter(Boolean)).toHaveLength(1);
    });
});

describe('challenge-bound replay recovery', () => {
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
