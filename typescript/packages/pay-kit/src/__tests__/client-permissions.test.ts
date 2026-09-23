import { describe, expect, it } from 'vitest';

import {
    AssetPermission,
    ClientPermissions,
    OriginPermissionOverride,
    PermissionConfigurationError,
    PermissionDeniedError,
    usd,
} from '../client/index.js';

const UNKNOWN_MINT = '11111111111111111111111111111111';

describe('client permissions', () => {
    it('defaults to mainnet stablecoins with a one-dollar cap', () => {
        const permissions = ClientPermissions.builder().build();

        expect(
            permissions.authorize({
                amount: 1_000_000n,
                mint: 'USDC',
                network: 'mainnet',
                origin: 'https://api.example/path',
            }),
        ).toEqual({ maxAmountAtomic: 1_000_000n });
        expect(() =>
            permissions.authorize({
                amount: 1_000_001n,
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
                mint: 'USDC',
                network: 'mainnet',
                origin: 'https://api.example/another-path',
            }),
        ).toEqual({ maxAmountAtomic: 2_000_000n });
        expect(() =>
            permissions.authorize({
                amount: 1n,
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
                mint: UNKNOWN_MINT,
                network: 'mainnet',
                origin: 'https://trusted.example',
            }),
        ).toEqual({ maxAmountAtomic: 25n });
        expect(() =>
            permissions.authorize({
                amount: 11n,
                mint: UNKNOWN_MINT,
                network: 'mainnet',
                origin: 'https://other.example',
            }),
        ).toThrow(PermissionDeniedError);
    });

    it('rejects unknown assets unless explicitly allowed', () => {
        expect(() =>
            ClientPermissions.builder().build().authorize({
                amount: 1n,
                mint: UNKNOWN_MINT,
                network: 'mainnet',
                origin: 'https://api.example',
            }),
        ).toThrow(PermissionDeniedError);

        expect(
            ClientPermissions.builder().allowAnyAsset().build().authorize({
                amount: 99n,
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
});
