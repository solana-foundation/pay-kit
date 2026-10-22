import { describe, expect, it } from 'vitest';

import {
    AssetPermission,
    ClientPermissions,
    OriginPermissionOverride,
    type PaymentDestination,
    PermissionConfigurationError,
    PermissionDeniedError,
    usd,
} from '../client/index.js';

const UNKNOWN_MINT = '11111111111111111111111111111111';
const PAYEE = 'CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY';
const SPLIT = '9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin';

function payee(amount: bigint): PaymentDestination[] {
    return [{ amount, recipient: PAYEE }];
}

describe('client permissions', () => {
    it('defaults to mainnet stablecoins with a one-dollar cap', () => {
        const permissions = ClientPermissions.builder().build();

        expect(
            permissions.authorize({
                amount: 1_000_000n,
                destinations: payee(1_000_000n),
                mint: 'USDC',
                network: 'mainnet',
                origin: 'https://api.example/path',
            }),
        ).toEqual({ maxAmountAtomic: 1_000_000n });
        expect(() =>
            permissions.authorize({
                amount: 1_000_001n,
                destinations: payee(1_000_001n),
                mint: 'USDC',
                network: 'mainnet',
                origin: 'https://api.example',
            }),
        ).toThrow(PermissionDeniedError);
    });

    it('supports global and exact-origin caps without granting an origin', () => {
        const permissions = ClientPermissions.builder()
            .allowOrigin('https://api.example/path')
            .maxAmountPerPayment(usd('2'))
            .overrideOrigin(
                OriginPermissionOverride.builder('https://trusted.example/resource')
                    .maxAmountPerPayment(usd('5'))
                    .build(),
            )
            .build();

        expect(
            permissions.authorize({
                amount: 2_000_000n,
                destinations: payee(2_000_000n),
                mint: 'USDC',
                network: 'mainnet',
                origin: 'https://api.example/another-path',
            }),
        ).toEqual({ maxAmountAtomic: 2_000_000n });
        expect(() =>
            permissions.authorize({
                amount: 1n,
                destinations: payee(1n),
                mint: 'USDC',
                network: 'mainnet',
                origin: 'https://trusted.example',
            }),
        ).toThrow(PermissionDeniedError);
    });

    it('lets an exact-origin asset cap override a global asset cap', () => {
        const permissions = ClientPermissions.builder()
            .allowAsset(AssetPermission.withCap('mainnet', UNKNOWN_MINT, 10n))
            .overrideOrigin(
                OriginPermissionOverride.builder('https://trusted.example')
                    .assetCap(AssetPermission.withCap('mainnet', UNKNOWN_MINT, 25n))
                    .build(),
            )
            .build();

        expect(
            permissions.authorize({
                amount: 25n,
                destinations: payee(25n),
                mint: UNKNOWN_MINT,
                network: 'mainnet',
                origin: 'https://trusted.example',
            }),
        ).toEqual({ maxAmountAtomic: 25n });
        expect(() =>
            permissions.authorize({
                amount: 11n,
                destinations: payee(11n),
                mint: UNKNOWN_MINT,
                network: 'mainnet',
                origin: 'https://other.example',
            }),
        ).toThrow(PermissionDeniedError);
    });

    it('rejects unknown assets unless explicitly allowed', () => {
        expect(() =>
            ClientPermissions.builder()
                .build()
                .authorize({
                    amount: 1n,
                    destinations: payee(1n),
                    mint: UNKNOWN_MINT,
                    network: 'mainnet',
                    origin: 'https://api.example',
                }),
        ).toThrow(PermissionDeniedError);

        expect(
            ClientPermissions.builder()
                .allowAnyAsset()
                .build()
                .authorize({
                    amount: 99n,
                    destinations: payee(99n),
                    mint: UNKNOWN_MINT,
                    network: 'mainnet',
                    origin: 'https://api.example',
                }),
        ).toEqual({ maxAmountAtomic: undefined });
    });

    it('parses dollar caps exactly and rejects excess precision', () => {
        expect(usd('$0.000001').microUsd).toBe(1n);
        expect(() => usd('0.0000001')).toThrow(PermissionConfigurationError);
        expect(() => usd('0')).toThrow(PermissionConfigurationError);
    });

    it('restricts the primary recipient and every split to the recipient allowlist', () => {
        const permissions = ClientPermissions.builder().allowRecipient(PAYEE).build();
        const terms = { amount: 1_000n, mint: 'USDC', network: 'mainnet', origin: 'https://api.example' } as const;

        expect(permissions.authorize({ ...terms, destinations: payee(1_000n) })).toEqual({
            maxAmountAtomic: 1_000_000n,
        });
        const withSplit = [
            { amount: 900n, recipient: PAYEE },
            { amount: 100n, recipient: SPLIT },
        ];
        expect(() => permissions.authorize({ ...terms, destinations: withSplit })).toThrow(
            expect.objectContaining({ rejections: [expect.objectContaining({ code: 'recipient_not_allowed' })] }),
        );
        expect(() => permissions.authorize({ ...terms, destinations: [{ amount: 1_000n, recipient: SPLIT }] })).toThrow(
            expect.objectContaining({ rejections: [expect.objectContaining({ code: 'recipient_not_allowed' })] }),
        );

        const both = ClientPermissions.builder().allowRecipient(PAYEE).allowRecipient(SPLIT).build();
        expect(both.authorize({ ...terms, destinations: withSplit })).toEqual({ maxAmountAtomic: 1_000_000n });
        expect(
            ClientPermissions.builder()
                .allowRecipient(PAYEE)
                .allowAnyRecipient()
                .build()
                .authorize({ ...terms, destinations: withSplit }),
        ).toEqual({ maxAmountAtomic: 1_000_000n });
        expect(() => ClientPermissions.builder().allowRecipient('not-an-address')).toThrow(
            PermissionConfigurationError,
        );
    });

    it('rejects destinations that are empty, malformed, or do not add up to the amount', () => {
        const permissions = ClientPermissions.builder().build();
        const terms = { amount: 1_000n, mint: 'USDC', network: 'mainnet', origin: 'https://api.example' } as const;
        const invalid = expect.objectContaining({
            rejections: [expect.objectContaining({ code: 'invalid_challenge_terms' })],
        });

        expect(() => permissions.authorize({ ...terms, destinations: [] })).toThrow(invalid);
        expect(() => permissions.authorize({ ...terms, destinations: payee(999n) })).toThrow(invalid);
        expect(() =>
            permissions.authorize({ ...terms, destinations: [{ amount: 1_000n, recipient: 'not-an-address' }] }),
        ).toThrow(invalid);
    });
});
