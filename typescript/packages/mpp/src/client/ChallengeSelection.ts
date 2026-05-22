import type { z } from 'mppx';
import { Challenge } from 'mppx';

import { normalizeNetwork, resolveStablecoinMint } from '../constants.js';
import { charge as chargeMethod, session as sessionMethod } from '../Methods.js';
import type { SessionMode } from './Session.js';

/** A typed Solana charge challenge accepted by the MPP client. */
export type SolanaChargeChallenge = Challenge.Challenge<
    z.output<typeof chargeMethod.schema.request>,
    typeof chargeMethod.intent,
    typeof chargeMethod.name
>;

/** A typed Solana session challenge accepted by the MPP client. */
export type SolanaSessionChallenge = Challenge.Challenge<
    z.output<typeof sessionMethod.schema.request>,
    typeof sessionMethod.intent,
    typeof sessionMethod.name
>;

/** Options for selecting one Solana charge challenge from a challenge set. */
export type SelectSolanaChargeChallengeOptions = {
    /** Currency symbol or mint address the client wants to pay with. */
    currency?: string | readonly string[] | undefined;
    /** Solana network identifier, e.g. "mainnet-beta", "devnet", or "localnet". */
    network?: string | undefined;
};

/** Options for selecting one Solana session challenge from a challenge set. */
export type SelectSolanaSessionChallengeOptions = SelectSolanaChargeChallengeOptions & {
    /** Preferred funding mode. */
    mode?: SessionMode | readonly SessionMode[] | undefined;
};

/**
 * Returns true when a challenge is a schema-valid Solana charge challenge.
 */
export function isSolanaChargeChallenge(challenge: Challenge.Challenge): challenge is SolanaChargeChallenge {
    if (challenge.method !== chargeMethod.name || challenge.intent !== chargeMethod.intent) {
        return false;
    }
    return chargeMethod.schema.request.safeParse(challenge.request).success;
}

/**
 * Returns true when a challenge is a schema-valid Solana session challenge.
 */
export function isSolanaSessionChallenge(challenge: Challenge.Challenge): challenge is SolanaSessionChallenge {
    if (challenge.method !== sessionMethod.name || challenge.intent !== sessionMethod.intent) {
        return false;
    }
    return sessionMethod.schema.request.safeParse(challenge.request).success;
}

/**
 * Selects the Solana charge challenge the client should sign.
 *
 * Servers can return multiple charge challenges for the same resource, for
 * example one challenge per supported stablecoin. This helper filters by
 * network and currency preferences while preserving server order otherwise.
 */
export function selectSolanaChargeChallenge(
    challenges: readonly Challenge.Challenge[],
    options: SelectSolanaChargeChallengeOptions = {},
): SolanaChargeChallenge | undefined {
    const candidates: SolanaChargeChallenge[] = [];

    for (const challenge of challenges) {
        if (challenge.method !== chargeMethod.name || challenge.intent !== chargeMethod.intent) {
            continue;
        }

        const result = chargeMethod.schema.request.safeParse(challenge.request);
        if (!result.success) {
            throw new Error('Invalid Solana charge challenge request');
        }

        const typedChallenge = {
            ...challenge,
            request: result.data,
        } as SolanaChargeChallenge;

        if (!matchesNetwork(typedChallenge, options.network)) {
            continue;
        }

        candidates.push(typedChallenge);
    }

    if (!options.currency) {
        return candidates[0];
    }

    const acceptedCurrencies = normalizeCurrencyPreference(options.currency);
    for (const acceptedCurrency of acceptedCurrencies) {
        const candidate = candidates.find(challenge => matchesCurrency(challenge, acceptedCurrency));
        if (candidate) {
            return candidate;
        }
    }
}

/**
 * Selects the Solana session challenge the client should open.
 */
export function selectSolanaSessionChallenge(
    challenges: readonly Challenge.Challenge[],
    options: SelectSolanaSessionChallengeOptions = {},
): SolanaSessionChallenge | undefined {
    const candidates: SolanaSessionChallenge[] = [];

    for (const challenge of challenges) {
        if (challenge.method !== sessionMethod.name || challenge.intent !== sessionMethod.intent) {
            continue;
        }

        const result = sessionMethod.schema.request.safeParse(challenge.request);
        if (!result.success) {
            throw new Error('Invalid Solana session challenge request');
        }

        const typedChallenge = {
            ...challenge,
            request: result.data,
        } as SolanaSessionChallenge;

        if (!matchesSessionNetwork(typedChallenge, options.network)) {
            continue;
        }
        if (!matchesSessionCurrency(typedChallenge, options.currency)) {
            continue;
        }

        candidates.push(typedChallenge);
    }

    if (!options.mode) {
        return candidates[0];
    }

    const acceptedModes = typeof options.mode === 'string' ? [options.mode] : options.mode;
    return candidates.find(challenge => {
        const challengeModes = challenge.request.modes ?? ['push'];
        return acceptedModes.some(mode => challengeModes.includes(mode));
    });
}

/**
 * Extracts all HTTP `WWW-Authenticate` challenges from a response and selects
 * the Solana charge challenge the client should sign.
 */
export function selectSolanaChargeChallengeFromResponse(
    response: Response,
    options: SelectSolanaChargeChallengeOptions = {},
): SolanaChargeChallenge | undefined {
    return selectSolanaChargeChallenge(Challenge.fromResponseList(response), options);
}

/**
 * Extracts all HTTP `WWW-Authenticate` challenges from a response and selects
 * the Solana session challenge the client should open.
 */
export function selectSolanaSessionChallengeFromResponse(
    response: Response,
    options: SelectSolanaSessionChallengeOptions = {},
): SolanaSessionChallenge | undefined {
    return selectSolanaSessionChallenge(Challenge.fromResponseList(response), options);
}

function matchesNetwork(challenge: SolanaChargeChallenge, network: string | undefined): boolean {
    if (!network) {
        return true;
    }
    return normalizeNetwork(challenge.request.methodDetails.network ?? 'mainnet') === normalizeNetwork(network);
}

function matchesCurrency(challenge: SolanaChargeChallenge, currency: string | readonly string[] | undefined): boolean {
    if (!currency) {
        return true;
    }

    const acceptedCurrencies = normalizeCurrencyPreference(currency);
    const challengeNetwork = challenge.request.methodDetails.network;
    return acceptedCurrencies.some(acceptedCurrency =>
        currenciesMatch(challenge.request.currency, acceptedCurrency, challengeNetwork),
    );
}

function normalizeCurrencyPreference(currency: string | readonly string[] | undefined): readonly string[] {
    if (!currency) {
        return [];
    }
    return typeof currency === 'string' ? [currency] : currency;
}

function currenciesMatch(challengeCurrency: string, acceptedCurrency: string, network: string | undefined): boolean {
    const challengeMint = resolveStablecoinMint(challengeCurrency, network);
    const acceptedMint = resolveStablecoinMint(acceptedCurrency, network);
    return challengeMint === acceptedMint;
}

function matchesSessionNetwork(challenge: SolanaSessionChallenge, network: string | undefined): boolean {
    if (!network) {
        return true;
    }
    return normalizeNetwork(challenge.request.network ?? 'mainnet') === normalizeNetwork(network);
}

function matchesSessionCurrency(
    challenge: SolanaSessionChallenge,
    currency: string | readonly string[] | undefined,
): boolean {
    if (!currency) {
        return true;
    }

    const acceptedCurrencies = normalizeCurrencyPreference(currency);
    return acceptedCurrencies.some(acceptedCurrency =>
        currenciesMatch(challenge.request.currency, acceptedCurrency, challenge.request.network),
    );
}
