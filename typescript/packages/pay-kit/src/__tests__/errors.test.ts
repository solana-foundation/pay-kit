import { describe, expect, it } from 'vitest';

import {
    ChallengeExpiredError,
    ConfigurationError,
    DemoSignerOnMainnetError,
    InvalidKeyError,
    InvalidProofError,
    MixedCurrenciesError,
    PaymentRequiredError,
    PayKitError,
    ProtocolIncompatibleError,
    ProtocolNotSupportedError,
    UnknownGateError,
} from '../errors.js';

describe('PayKit error taxonomy', () => {
    it('roots every error under PayKitError with a stable name', () => {
        const cases: [PayKitError, string][] = [
            [new PayKitError('boom'), 'PayKitError'],
            [new ConfigurationError('boom'), 'ConfigurationError'],
            [new DemoSignerOnMainnetError('boom'), 'DemoSignerOnMainnetError'],
            [new MixedCurrenciesError('boom'), 'MixedCurrenciesError'],
            [new ProtocolIncompatibleError('boom'), 'ProtocolIncompatibleError'],
            [new InvalidKeyError('boom'), 'InvalidKeyError'],
        ];
        for (const [error, name] of cases) {
            expect(error).toBeInstanceOf(PayKitError);
            expect(error).toBeInstanceOf(Error);
            expect(error.name).toBe(name);
        }
    });

    it('builds UnknownGateError with a catalogue hint', () => {
        const error = new UnknownGateError('report');
        expect(error).toBeInstanceOf(ConfigurationError);
        expect(error.name).toBe('UnknownGateError');
        expect(error.message).toContain('Unknown gate "report"');
        expect(error.message).toContain('Pricing catalogue');
    });

    it('renders PaymentRequiredError as a 402 with no credential', () => {
        const error = new PaymentRequiredError('pay up');
        expect(error).toBeInstanceOf(PayKitError);
        expect(error.name).toBe('PaymentRequiredError');
        expect(error.httpStatus).toBe(402);
        expect(error.message).toBe('pay up');
    });

    it('renders ProtocolNotSupportedError as a 406', () => {
        const error = new ProtocolNotSupportedError('no such protocol');
        expect(error).toBeInstanceOf(PayKitError);
        expect(error.name).toBe('ProtocolNotSupportedError');
        expect(error.httpStatus).toBe(406);
    });

    it('carries the canonical code on InvalidProofError, defaulting message to the code', () => {
        const withDetail = new InvalidProofError('signature_consumed', 'already used');
        expect(withDetail).toBeInstanceOf(PayKitError);
        expect(withDetail.name).toBe('InvalidProofError');
        expect(withDetail.httpStatus).toBe(402);
        expect(withDetail.code).toBe('signature_consumed');
        expect(withDetail.message).toBe('already used');

        // No detail: the message falls back to the code.
        const codeOnly = new InvalidProofError('invalid_proof');
        expect(codeOnly.code).toBe('invalid_proof');
        expect(codeOnly.message).toBe('invalid_proof');
    });

    it('specializes ChallengeExpiredError with the challenge_expired code', () => {
        const withDetail = new ChallengeExpiredError('too late');
        expect(withDetail).toBeInstanceOf(InvalidProofError);
        expect(withDetail.name).toBe('ChallengeExpiredError');
        expect(withDetail.code).toBe('challenge_expired');
        expect(withDetail.httpStatus).toBe(402);
        expect(withDetail.message).toBe('too late');

        // No detail: message falls back to the code carried by the base constructor.
        const codeOnly = new ChallengeExpiredError();
        expect(codeOnly.code).toBe('challenge_expired');
        expect(codeOnly.message).toBe('challenge_expired');
    });
});
