import { describe, expect, it } from 'vitest';

import { ConfigurationError, MixedCurrenciesError } from '../errors.js';
import { eur, usd } from '../price.js';

describe('Price', () => {
    it('canonicalizes decimal strings', () => {
        expect(usd('0.10').amount).toBe('0.1');
        expect(usd('10').amount).toBe('10');
        expect(usd('10.000000').amount).toBe('10');
    });

    it('rejects malformed amounts', () => {
        expect(() => usd('')).toThrow(ConfigurationError);
        expect(() => usd('-1')).toThrow(ConfigurationError);
        expect(() => usd('1.2345678')).toThrow(ConfigurationError);
        expect(() => usd('0,10')).toThrow(ConfigurationError);
    });

    it('converts to base units', () => {
        expect(usd('0.10').baseUnits()).toBe(100_000n);
        expect(usd('10.00').baseUnits()).toBe(10_000_000n);
        expect(usd('1').baseUnits(9)).toBe(1_000_000_000n);
        expect(usd('1').baseUnits(2)).toBe(100n);
    });

    it('adds and subtracts exactly', () => {
        expect(usd('0.10').plus(usd('0.05')).amount).toBe('0.15');
        expect(usd('10.00').minus(usd('0.30')).amount).toBe('9.7');
        expect(() => usd('0.10').minus(usd('0.20'))).toThrow(ConfigurationError);
    });

    it('refuses cross-currency arithmetic', () => {
        expect(() => usd('1').plus(eur('1'))).toThrow(MixedCurrenciesError);
        expect(() => usd('1').minus(eur('1'))).toThrow(MixedCurrenciesError);
        expect(() => usd('1').isGreaterThan(eur('1'))).toThrow(MixedCurrenciesError);
    });

    it('carries settlement preference', () => {
        expect(usd('1').primaryCoin()).toBeUndefined();
        expect(usd('1', 'PYUSD', 'USDC').primaryCoin()).toBe('PYUSD');
        expect(usd('1', 'PYUSD').withAmount('2').settlements).toEqual(['PYUSD']);
    });
});
