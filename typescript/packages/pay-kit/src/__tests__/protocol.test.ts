import { describe, expect, it } from 'vitest';

import { caip2, toNetwork, toSolanaNetwork } from '../protocol.js';

describe('toNetwork', () => {
    it('normalizes Solana slugs to canonical names', () => {
        expect(toNetwork('devnet')).toBe('solana_devnet');
        expect(toNetwork('localnet')).toBe('solana_localnet');
        expect(toNetwork('mainnet')).toBe('solana_mainnet');
        expect(toNetwork('mainnet-beta')).toBe('solana_mainnet');
    });

    it('passes canonical names through unchanged', () => {
        expect(toNetwork('solana_devnet')).toBe('solana_devnet');
        expect(toNetwork('solana_localnet')).toBe('solana_localnet');
        expect(toNetwork('solana_mainnet')).toBe('solana_mainnet');
    });
});

describe('toSolanaNetwork', () => {
    it('maps every canonical network to its Solana slug', () => {
        expect(toSolanaNetwork('solana_devnet')).toBe('devnet');
        expect(toSolanaNetwork('solana_localnet')).toBe('localnet');
        expect(toSolanaNetwork('solana_mainnet')).toBe('mainnet');
    });
});

describe('caip2', () => {
    it('advertises the devnet genesis for devnet', () => {
        expect(caip2('solana_devnet')).toBe('solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1');
    });

    it('advertises the mainnet genesis for localnet and mainnet', () => {
        const mainnet = 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp';
        expect(caip2('solana_localnet')).toBe(mainnet);
        expect(caip2('solana_mainnet')).toBe(mainnet);
    });
});
