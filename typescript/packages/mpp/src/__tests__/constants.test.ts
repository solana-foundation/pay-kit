/**
 * Tests for constants.ts — validates exported program addresses and RPC URL mappings.
 */
import {
    ASSOCIATED_TOKEN_PROGRAM,
    CASH,
    COMPUTE_BUDGET_PROGRAM,
    DEFAULT_RPC_URLS,
    MEMO_PROGRAM,
    PYUSD,
    SYSTEM_PROGRAM,
    TOKEN_2022_PROGRAM,
    TOKEN_PROGRAM,
    USDC,
    USDG,
    USDT,
    defaultTokenProgramForCurrency,
    resolveStablecoinMint,
    stablecoinSymbolForCurrency,
} from '../constants.js';

describe('token program addresses', () => {
    test('TOKEN_PROGRAM is the expected base58 address', () => {
        expect(TOKEN_PROGRAM).toBe('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA');
    });

    test('TOKEN_2022_PROGRAM is the expected base58 address', () => {
        expect(TOKEN_2022_PROGRAM).toBe('TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb');
    });

    test('ASSOCIATED_TOKEN_PROGRAM is the expected base58 address', () => {
        expect(ASSOCIATED_TOKEN_PROGRAM).toBe('ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL');
    });

    test('SYSTEM_PROGRAM is all ones', () => {
        expect(SYSTEM_PROGRAM).toBe('11111111111111111111111111111111');
    });

    test('COMPUTE_BUDGET_PROGRAM is the expected base58 address', () => {
        expect(COMPUTE_BUDGET_PROGRAM).toBe('ComputeBudget111111111111111111111111111111');
    });

    test('MEMO_PROGRAM is the expected base58 address', () => {
        expect(MEMO_PROGRAM).toBe('MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr');
    });
});

describe('USDC mint addresses', () => {
    test('has devnet mint', () => {
        expect(USDC.devnet).toBe('4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU');
    });

    test('has mainnet-beta mint', () => {
        expect(USDC.mainnet).toBe('EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v');
    });
});

describe('stablecoin mint addresses', () => {
    test('has USDT mainnet mint', () => {
        expect(USDT.mainnet).toBe('Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB');
    });

    test('has USDG mints', () => {
        expect(USDG.devnet).toBe('4F6PM96JJxngmHnZLBh9n58RH4aTVNWvDs2nuwrT5BP7');
        expect(USDG.mainnet).toBe('2u1tszSeqZ3qBWF3uNGPFc8TzMk2tdiwknnRMWGWjGWH');
    });

    test('has PYUSD mints', () => {
        expect(PYUSD.devnet).toBe('CXk2AMBfi3TwaEL2468s6zP8xq9NxTXjp9gjMgzeUynM');
        expect(PYUSD.mainnet).toBe('2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo');
    });

    test('has Phantom CASH mainnet mint', () => {
        expect(CASH.mainnet).toBe('CASHx9KJUStyftLFWGvEVf59SGeG9sh5FfcnZMVPCASH');
    });

    test('resolves stablecoin symbols by network', () => {
        expect(resolveStablecoinMint('USDC', 'devnet')).toBe(USDC.devnet);
        expect(resolveStablecoinMint('USDT', 'mainnet-beta')).toBe(USDT.mainnet);
        expect(resolveStablecoinMint('USDG', 'devnet')).toBe(USDG.devnet);
        expect(resolveStablecoinMint('PYUSD', 'devnet')).toBe(PYUSD.devnet);
        expect(resolveStablecoinMint('CASH', 'mainnet-beta')).toBe(CASH.mainnet);
        expect(resolveStablecoinMint('SOL')).toBeUndefined();
        expect(resolveStablecoinMint('CustomMint111111111111111111111111111111')).toBe(
            'CustomMint111111111111111111111111111111',
        );
    });

    test('detects stablecoin display symbols', () => {
        expect(stablecoinSymbolForCurrency(PYUSD.mainnet)).toBe('PYUSD');
        expect(stablecoinSymbolForCurrency(USDG.mainnet)).toBe('USDG');
        expect(stablecoinSymbolForCurrency(CASH.mainnet)).toBe('CASH');
        expect(stablecoinSymbolForCurrency('CASH')).toBe('CASH');
        expect(stablecoinSymbolForCurrency('CustomMint111111111111111111111111111111')).toBeUndefined();
    });

    test('defaults stablecoins to the correct token program', () => {
        expect(defaultTokenProgramForCurrency('CASH')).toBe(TOKEN_2022_PROGRAM);
        expect(defaultTokenProgramForCurrency(CASH.mainnet)).toBe(TOKEN_2022_PROGRAM);
        expect(defaultTokenProgramForCurrency('PYUSD', 'devnet')).toBe(TOKEN_2022_PROGRAM);
        expect(defaultTokenProgramForCurrency(PYUSD.mainnet)).toBe(TOKEN_2022_PROGRAM);
        expect(defaultTokenProgramForCurrency('USDG', 'devnet')).toBe(TOKEN_2022_PROGRAM);
        expect(defaultTokenProgramForCurrency(USDG.mainnet)).toBe(TOKEN_2022_PROGRAM);
        expect(defaultTokenProgramForCurrency('USDC')).toBe(TOKEN_PROGRAM);
        expect(defaultTokenProgramForCurrency('USDT')).toBe(TOKEN_PROGRAM);
    });
});

describe('DEFAULT_RPC_URLS', () => {
    test('has devnet URL', () => {
        expect(DEFAULT_RPC_URLS.devnet).toBe('https://api.devnet.solana.com');
    });

    test('has mainnet URL', () => {
        expect(DEFAULT_RPC_URLS.mainnet).toBe('https://api.mainnet-beta.solana.com');
    });

    test('has localnet URL', () => {
        expect(DEFAULT_RPC_URLS.localnet).toBe('http://localhost:8899');
    });

    // Canonical slug is `mainnet`; `mainnet-beta` is a backward-compat
    // alias. This test catches alias drift: if a future commit changes
    // the URL for one spelling but forgets the other, downstream consumers
    // doing raw bracket access on either key get inconsistent results.
    test('mainnet-beta alias matches mainnet', () => {
        expect(DEFAULT_RPC_URLS['mainnet-beta']).toBe(DEFAULT_RPC_URLS.mainnet);
        expect(USDC['mainnet-beta']).toBe(USDC.mainnet);
        expect(USDT['mainnet-beta']).toBe(USDT.mainnet);
        expect(USDG['mainnet-beta']).toBe(USDG.mainnet);
        expect(PYUSD['mainnet-beta']).toBe(PYUSD.mainnet);
        expect(CASH['mainnet-beta']).toBe(CASH.mainnet);
    });
});
