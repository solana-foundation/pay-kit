/**
 * Canonical PayKit error taxonomy, shared across the cross-language SDK
 * family (see docs/paykit-interface.md). Every error extends
 * {@link PayKitError} so callers can catch the whole family at once.
 */

/** Root of the PayKit error hierarchy. */
export class PayKitError extends Error {
    override name = 'PayKitError';
}

/** Boot-time configuration problem. Raised before any request is served. */
export class ConfigurationError extends PayKitError {
    override name = 'ConfigurationError';
}

/** The package-shipped demo signer was configured on mainnet. */
export class DemoSignerOnMainnetError extends ConfigurationError {
    override name = 'DemoSignerOnMainnetError';
}

/** A gate mixes prices denominated in different fiat currencies. */
export class MixedCurrenciesError extends ConfigurationError {
    override name = 'MixedCurrenciesError';
}

/** A gate explicitly requests a protocol its shape is incompatible with (e.g. fees + x402). */
export class ProtocolIncompatibleError extends ConfigurationError {
    override name = 'ProtocolIncompatibleError';
}

/** A gate name was not found in the configured pricing catalogue. */
export class UnknownGateError extends ConfigurationError {
    override name = 'UnknownGateError';

    constructor(gateName: string) {
        super(`Unknown gate "${gateName}". Register it in the Pricing catalogue passed to createPayKit().`);
    }
}

/** A signer secret could not be parsed (wrong length, bad encoding, unreadable file). */
export class InvalidKeyError extends PayKitError {
    override name = 'InvalidKeyError';
}

/** The request carried no payment credential. Rendered as HTTP 402 with a challenge. */
export class PaymentRequiredError extends PayKitError {
    override name = 'PaymentRequiredError';
    readonly httpStatus = 402;
}

/**
 * The request carried a payment credential that failed verification or
 * settlement. Rendered as HTTP 402.
 */
export class InvalidProofError extends PayKitError {
    override name = 'InvalidProofError';
    readonly httpStatus = 402;
    /** Canonical cross-SDK machine code (e.g. `signature_consumed`), asserted by conformance. */
    readonly code: string;

    constructor(code: string, detail?: string) {
        super(detail ?? code);
        this.code = code;
    }
}

/** The payment credential references a challenge that has expired. */
export class ChallengeExpiredError extends InvalidProofError {
    override name = 'ChallengeExpiredError';

    constructor(detail?: string) {
        super('challenge_expired', detail);
    }
}

/** The client requested a payment protocol this server does not accept. Rendered as HTTP 406. */
export class ProtocolNotSupportedError extends PayKitError {
    override name = 'ProtocolNotSupportedError';
    readonly httpStatus = 406;
}
