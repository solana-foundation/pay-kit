<?php

declare(strict_types=1);

namespace PayKit\PayCore\Solana;

use SolanaPhpSdk\Keypair\PublicKey;
use SolanaPhpSdk\Programs\AssociatedTokenProgram;
use SolanaPhpSdk\Programs\TokenProgram;

/**
 * Canonical Solana mint addresses for the stablecoins MPP charge supports.
 *
 * Mirrors `typescript/packages/mpp/src/constants.ts` so the PHP server-side
 * resolution matches what TypeScript / Rust clients embed in transactions.
 *
 * Use the static {@see resolve()} helper to turn a symbol like `"USDC"` and a
 * network like `"localnet"` into the concrete mint pubkey. Callers who already
 * pass a 32+ character base58 pubkey get it back unchanged.
 */
final class Mints
{
    // The canonical mainnet slug is `mainnet`. Legacy `mainnet-beta`
    // input is folded back to `mainnet` by normalizeNetwork() below before
    // any lookup happens, so the const arrays carry the canonical key only.
    /** @var array<string, string> */
    public const USDC = [
        'devnet' => '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU',
        'mainnet' => 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v',
    ];

    /** @var array<string, string> */
    public const USDT = [
        'mainnet' => 'Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB',
    ];

    /** @var array<string, string> */
    public const USDG = [
        'devnet' => '4F6PM96JJxngmHnZLBh9n58RH4aTVNWvDs2nuwrT5BP7',
        'mainnet' => '2u1tszSeqZ3qBWF3uNGPFc8TzMk2tdiwknnRMWGWjGWH',
    ];

    /** @var array<string, string> */
    public const PYUSD = [
        'devnet' => 'CXk2AMBfi3TwaEL2468s6zP8xq9NxTXjp9gjMgzeUynM',
        'mainnet' => '2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo',
    ];

    /** @var array<string, string> */
    public const CASH = [
        'mainnet' => 'CASHx9KJUStyftLFWGvEVf59SGeG9sh5FfcnZMVPCASH',
    ];

    /** @var array<string, array<string, string>> */
    private const MAP = [
        'USDC' => self::USDC,
        'USDT' => self::USDT,
        'USDG' => self::USDG,
        'PYUSD' => self::PYUSD,
        'CASH' => self::CASH,
    ];

    /** Stablecoins that live on the Token-2022 program. */
    private const TOKEN_2022_SYMBOLS = ['PYUSD', 'USDG', 'CASH'];

    private function __construct()
    {
    }

    /**
     * Resolve a currency token to its concrete mint pubkey for the given network.
     *
     * - `"SOL"` (case-insensitive) returns `null`, since native SOL has no mint.
     * - A 32+ character base58 string is treated as already-resolved and
     *   returned unchanged.
     * - A known symbol like `"USDC"` is mapped via the network table; missing
     *   networks fall back to mainnet.
     * - Anything else is returned unchanged so the caller's existing string
     *   propagates through verification (and surfaces a clear error if invalid).
     */
    public static function resolve(string $currency, string $network = 'mainnet'): ?string
    {
        if (strtoupper($currency) === 'SOL') {
            return null;
        }
        if (strlen($currency) >= 32) {
            return $currency;
        }
        $entry = self::MAP[strtoupper($currency)] ?? null;
        if ($entry === null) {
            return $currency;
        }
        $normalized = self::normalizeNetwork($network);
        return $entry[$normalized] ?? $entry['mainnet'];
    }

    /**
     * Maintainer canonical for the mainnet slug is `mainnet`. Accept
     * `mainnet-beta` (Solana CLI default), `mainnet`, and any equivalent
     * casing as aliases for the same network when looking up stablecoin
     * mappings. Other networks pass through unchanged.
     */
    private static function normalizeNetwork(string $network): string
    {
        return match (strtolower($network)) {
            'mainnet', 'mainnet-beta' => 'mainnet',
            default => $network,
        };
    }

    /**
     * The SPL token program that owns a given currency. Returns
     * `TokenProgram::TOKEN_2022_PROGRAM_ID` for stablecoins that live on
     * Token-2022 (PYUSD, USDG, CASH); `TokenProgram::PROGRAM_ID` for everything
     * else (including unknown / direct-mint inputs).
     *
     * WARNING (audit #28): for an *arbitrary, unknown* mint address this
     * returns the legacy Token program, which is wrong for any Token-2022 mint
     * not in the static table. Callers that may receive arbitrary mints (e.g.
     * the MPP charge verifier) MUST NOT rely on this default — see
     * {@see isKnownMint()} to detect the case and {@see resolveTokenProgramOnChain()}
     * to resolve the owner on-chain.
     */
    public static function tokenProgramFor(string $currency, string $network = 'mainnet'): string
    {
        $symbol = self::symbolFor($currency, $network);
        return $symbol !== null && in_array($symbol, self::TOKEN_2022_SYMBOLS, true)
            ? TokenProgram::TOKEN_2022_PROGRAM_ID
            : TokenProgram::PROGRAM_ID;
    }

    /**
     * True when `$currency` resolves to a mint we know from the static table
     * (by symbol or by mint address). Unknown arbitrary mint addresses return
     * false — for those the token program cannot be inferred without an
     * on-chain owner lookup (audit #28).
     */
    public static function isKnownMint(string $currency, string $network = 'mainnet'): bool
    {
        return self::symbolFor($currency, $network) !== null;
    }

    /**
     * True when `$currency` is a bare base58 mint address (32+ chars) rather
     * than a short symbol like "USDC". Used to tell "unknown symbol" (safe to
     * leave as legacy) from "unknown arbitrary mint" (must resolve on-chain).
     */
    public static function looksLikeMintAddress(string $currency): bool
    {
        return strtoupper($currency) !== 'SOL'
            && strlen($currency) >= 32
            && PublicKey::isBase58AlphabetString($currency);
    }

    /**
     * Resolve the owning token program for an arbitrary mint by fetching the
     * mint account's owner on-chain (spec §7.2), instead of guessing legacy
     * Token (audit #28). Mirrors Rust `resolve_server_token_program`.
     *
     * `$accountOwnerFetcher` is given the mint address and must return the
     * account owner's base58 pubkey, or null if the account does not exist.
     * Rejects any owner that is neither the Token Program nor the Token-2022
     * Program.
     *
     * @param callable(string):?string $accountOwnerFetcher
     */
    public static function resolveTokenProgramOnChain(string $mint, callable $accountOwnerFetcher): string
    {
        $owner = $accountOwnerFetcher($mint);
        if ($owner === null || $owner === '') {
            throw new \InvalidArgumentException('mint account not found on-chain: ' . $mint);
        }
        if ($owner !== TokenProgram::PROGRAM_ID && $owner !== TokenProgram::TOKEN_2022_PROGRAM_ID) {
            throw new \InvalidArgumentException(
                'mint ' . $mint . ' is not owned by the Token or Token-2022 program (owner: ' . $owner . ')',
            );
        }

        return $owner;
    }

    /**
     * Derive the Associated Token Account address for (owner, mint,
     * tokenProgram). Used by the boot-time preflight to assert the
     * recipient owns an ATA for each accepted stablecoin.
     */
    public static function deriveAta(string $owner, string $mint, string $tokenProgram): string
    {
        [$ata] = AssociatedTokenProgram::findAssociatedTokenAddress(
            new PublicKey($owner),
            new PublicKey($mint),
            new PublicKey($tokenProgram),
        );
        return (string) $ata;
    }

    /**
     * Reverse lookup: given a currency (symbol or mint), return the matching
     * symbol, or `null` if unknown.
     */
    public static function symbolFor(string $currency, string $network = 'mainnet'): ?string
    {
        $upper = strtoupper($currency);
        if (isset(self::MAP[$upper])) {
            return $upper;
        }
        foreach (self::MAP as $symbol => $entries) {
            if (in_array($currency, $entries, true)) {
                return $symbol;
            }
        }
        $resolved = self::resolve($currency, $network);
        if ($resolved === null || $resolved === $currency) {
            return null;
        }
        foreach (self::MAP as $symbol => $entries) {
            if (in_array($resolved, $entries, true)) {
                return $symbol;
            }
        }
        return null;
    }
}
