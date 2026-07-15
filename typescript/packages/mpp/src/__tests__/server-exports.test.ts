/**
 * Tests for server/Methods.ts and server/index.ts exports.
 *
 * Validates that the server barrel modules expose the expected public API.
 */
import { solana } from '../server/Methods.js';
import { charge, solana as solanaFromIndex } from '../server/index.js';

const RECIPIENT = '9xAXssX9j7vuK99c7cFwqbixzL3bFrzPy9PUhCtDPAYJ';

describe('server/Methods.ts', () => {
    test('solana is a callable function', () => {
        expect(typeof solana).toBe('function');
    });

    test('solana.charge is a function', () => {
        expect(typeof solana.charge).toBe('function');
    });

    test('solana() creates a charge method (default)', () => {
        const method = solana({
            recipient: RECIPIENT,
            network: 'devnet',
            allowUnsafeMemoryStore: true,
        });

        expect(method).toBeDefined();
        expect(typeof method.verify).toBe('function');
    });

    test('solana.charge() creates a charge method', () => {
        const method = solana.charge({
            recipient: RECIPIENT,
            network: 'devnet',
            allowUnsafeMemoryStore: true,
        });

        expect(method).toBeDefined();
        expect(typeof method.verify).toBe('function');
    });
});

describe('server/index.ts', () => {
    test('exports charge function', () => {
        expect(typeof charge).toBe('function');
    });

    test('exports solana namespace', () => {
        expect(typeof solanaFromIndex).toBe('function');
        expect(solanaFromIndex).toBe(solana);
    });
});
