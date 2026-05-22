import { Challenge } from 'mppx';

import { USDC } from '../constants.js';
import {
    isSolanaChargeChallenge,
    selectSolanaChargeChallenge,
    selectSolanaChargeChallengeFromResponse,
    type SolanaChargeChallenge,
} from '../client/ChallengeSelection.js';

const recipient = 'CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY';

function challenge(
    id: string,
    overrides: {
        currency?: string;
        method?: string;
        network?: string;
    } = {},
): Challenge.Challenge {
    return {
        id,
        intent: 'charge',
        method: overrides.method ?? 'solana',
        realm: 'test',
        request: {
            amount: '1000',
            currency: overrides.currency ?? USDC.devnet,
            methodDetails: {
                decimals: 6,
                feePayer: true,
                feePayerKey: recipient,
                network: overrides.network ?? 'devnet',
            },
            recipient,
        },
    };
}

describe('selectSolanaChargeChallenge', () => {
    test('selects the first matching Solana charge challenge by default', () => {
        const selected = selectSolanaChargeChallenge([challenge('first'), challenge('second')]);

        expect(selected?.id).toBe('first');
    });

    test('matches stablecoin symbols against mint-address challenges on the challenge network', () => {
        const selected = selectSolanaChargeChallenge([challenge('usdc-devnet')], {
            currency: 'USDC',
            network: 'devnet',
        });

        expect(selected?.id).toBe('usdc-devnet');
    });

    test('honors client currency preference order over server challenge order', () => {
        const selected = selectSolanaChargeChallenge(
            [
                challenge('mainnet-usdc', { currency: USDC.mainnet, network: 'mainnet-beta' }),
                challenge('devnet-usdc', { currency: USDC.devnet, network: 'devnet' }),
            ],
            {
                currency: [USDC.devnet, USDC.mainnet],
            },
        );

        expect(selected?.id).toBe('devnet-usdc');
    });

    test('returns undefined when no typed Solana charge challenge matches', () => {
        const selected = selectSolanaChargeChallenge(
            [
                challenge('stripe', { method: 'stripe' }),
                challenge('usdc-mainnet', { currency: USDC.mainnet, network: 'mainnet-beta' }),
            ],
            { currency: 'USDC', network: 'devnet' },
        );

        expect(selected).toBeUndefined();
    });

    test('narrows valid Solana charge challenges', () => {
        const candidate = challenge('baseline');
        expect(isSolanaChargeChallenge(candidate)).toBe(true);

        const typed = candidate as SolanaChargeChallenge;
        expect(typed.request.methodDetails.network).toBe('devnet');
    });

    test('throws when a Solana charge challenge has an invalid request shape', () => {
        expect(() =>
            selectSolanaChargeChallenge([
                {
                    ...challenge('invalid'),
                    request: { amount: '1000' },
                },
            ]),
        ).toThrow('Invalid Solana charge challenge request');
    });
});

describe('selectSolanaChargeChallengeFromResponse', () => {
    test('selects from HTTP WWW-Authenticate challenges', () => {
        const response = new Response(null, {
            headers: {
                'WWW-Authenticate': [
                    Challenge.serialize(
                        challenge('usdc-mainnet', {
                            currency: USDC.mainnet,
                            network: 'mainnet-beta',
                        }),
                    ),
                    Challenge.serialize(challenge('usdc-devnet')),
                ].join(', '),
            },
            status: 402,
        });

        const selected = selectSolanaChargeChallengeFromResponse(response, {
            currency: 'USDC',
            network: 'devnet',
        });

        expect(selected?.id).toBe('usdc-devnet');
    });
});
