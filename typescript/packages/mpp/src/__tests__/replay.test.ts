import { describe, expect, test } from 'vitest';
import { Store } from 'mppx/server';

import { reserveReplayKey } from '../server/replay.js';

describe('reserveReplayKey', () => {
    test('allows exactly one concurrent claimant', async () => {
        const store = Store.memory();
        const results = await Promise.all(
            Array.from({ length: 16 }, () => reserveReplayKey(store, 'solana-charge:consumed:same-signature')),
        );

        expect(results.filter(Boolean)).toHaveLength(1);
    });
});
