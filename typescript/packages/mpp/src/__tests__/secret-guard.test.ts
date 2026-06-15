/**
 * Audit #24: the @solana/mpp boundary rejects a weak HMAC secret key before any
 * challenge is signed. mppx@0.5.x accepts any non-empty secret, so the floor is
 * enforced here in the `Mppx.create` wrapper (see server/secret-guard.ts).
 */
import { afterEach, expect, test } from 'vitest';
import { charge } from '../server/Charge.js';
import { MIN_SECRET_KEY_BYTES, Mppx } from '../server/secret-guard.js';

const RECIPIENT = '9xAXssX9j7vuK99c7cFwqbixzL3bFrzPy9PUhCtDPAYJ';
const methods = () => [charge({ recipient: RECIPIENT, network: 'devnet', rpcUrl: 'https://mock-rpc' })];

// A 'a'.repeat(N) string is N UTF-8 bytes, so length maps directly to byte count.
const strong = 'a'.repeat(MIN_SECRET_KEY_BYTES);
const tooShort = 'a'.repeat(MIN_SECRET_KEY_BYTES - 1);

afterEach(() => {
    delete process.env.MPP_SECRET_KEY;
});

test('rejects an explicit secret key shorter than the floor', () => {
    expect(() => Mppx.create({ methods: methods(), secretKey: tooShort })).toThrow(/at least 32 bytes/);
});

test('accepts an explicit secret key at the floor', () => {
    delete process.env.MPP_SECRET_KEY;
    expect(() => Mppx.create({ methods: methods(), secretKey: strong })).not.toThrow();
});

test('rejects a short MPP_SECRET_KEY from the environment', () => {
    process.env.MPP_SECRET_KEY = tooShort;
    expect(() => Mppx.create({ methods: methods() })).toThrow(/at least 32 bytes/);
});

test('accepts a strong MPP_SECRET_KEY from the environment', () => {
    process.env.MPP_SECRET_KEY = strong;
    expect(() => Mppx.create({ methods: methods() })).not.toThrow();
});
