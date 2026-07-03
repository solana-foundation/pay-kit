import { describe, expect, it } from 'vitest';

import { errorMessage, x402PaymentHeader } from '../adapters/x402-shared.js';

describe('x402PaymentHeader', () => {
    it('reads the X-PAYMENT header', () => {
        const request = new Request('http://t/', { headers: { 'x-payment': 'cred-a' } });
        expect(x402PaymentHeader(request)).toBe('cred-a');
    });

    it('falls back to the PAYMENT-SIGNATURE header', () => {
        const request = new Request('http://t/', { headers: { 'payment-signature': 'cred-b' } });
        expect(x402PaymentHeader(request)).toBe('cred-b');
    });

    it('prefers X-PAYMENT when both are present', () => {
        const request = new Request('http://t/', {
            headers: { 'payment-signature': 'cred-b', 'x-payment': 'cred-a' },
        });
        expect(x402PaymentHeader(request)).toBe('cred-a');
    });

    it('returns undefined when neither header is present', () => {
        expect(x402PaymentHeader(new Request('http://t/'))).toBeUndefined();
    });
});

describe('errorMessage', () => {
    it('extracts the message from an Error', () => {
        expect(errorMessage(new Error('boom'))).toBe('boom');
    });

    it('returns undefined for a non-Error value', () => {
        expect(errorMessage('boom')).toBeUndefined();
        expect(errorMessage(undefined)).toBeUndefined();
        expect(errorMessage({ message: 'nope' })).toBeUndefined();
    });
});
