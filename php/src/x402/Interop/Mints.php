<?php

declare(strict_types=1);

namespace SolanaMpp\X402\Interop;

/**
 * Canonical well-known stablecoin mint addresses for the x402 `exact` scheme.
 *
 * Mirrors the Rust spine's `protocol::schemes::exact::types::mints` module
 * (`rust/crates/x402/src/protocol/schemes/exact/types.rs`) byte-for-byte.
 *
 * Only the symbol/network combinations spine declares are present here.
 * Resolution is fail-closed: an unknown symbol or an unsupported
 * symbol/network pair returns `null`. Callers must NOT silently fall back to
 * mainnet — that would silently mis-bind devnet challenges to mainnet mints.
 */
final class Mints
{
    public const USDC_MAINNET = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';
    public const USDC_DEVNET  = '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU';
    public const USDC_TESTNET = self::USDC_DEVNET;

    public const USDT_MAINNET = 'Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB';

    public const USDG_MAINNET = '2u1tszSeqZ3qBWF3uNGPFc8TzMk2tdiwknnRMWGWjGWH';
    public const USDG_DEVNET  = '4F6PM96JJxngmHnZLBh9n58RH4aTVNWvDs2nuwrT5BP7';
    public const USDG_TESTNET = self::USDG_DEVNET;

    public const PYUSD_MAINNET = '2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo';
    public const PYUSD_DEVNET  = 'CXk2AMBfi3TwaEL2468s6zP8xq9NxTXjp9gjMgzeUynM';
    public const PYUSD_TESTNET = self::PYUSD_DEVNET;

    public const CASH_MAINNET = 'CASHx9KJUStyftLFWGvEVf59SGeG9sh5FfcnZMVPCASH';

    /**
     * Per-symbol per-network table, mirroring the spine `mints` module.
     * Networks not declared in spine are intentionally absent.
     *
     * @var array<string, array<string, string>>
     */
    private const TABLE = [
        'USDC' => [
            'mainnet' => self::USDC_MAINNET,
            'devnet'  => self::USDC_DEVNET,
            'testnet' => self::USDC_TESTNET,
        ],
        'USDT' => [
            'mainnet' => self::USDT_MAINNET,
        ],
        'USDG' => [
            'mainnet' => self::USDG_MAINNET,
            'devnet'  => self::USDG_DEVNET,
            'testnet' => self::USDG_TESTNET,
        ],
        'PYUSD' => [
            'mainnet' => self::PYUSD_MAINNET,
            'devnet'  => self::PYUSD_DEVNET,
            'testnet' => self::PYUSD_TESTNET,
        ],
        'CASH' => [
            'mainnet' => self::CASH_MAINNET,
        ],
    ];

    private function __construct()
    {
    }

    /**
     * Resolve a stablecoin symbol + network to its canonical mint address.
     *
     * Fail-closed: returns `null` if the symbol is unknown, or if spine does
     * not declare a mint for the requested network (e.g. USDT devnet). Do
     * NOT introduce a silent mainnet fallback — that would silently
     * mis-bind devnet/testnet challenges to mainnet mints.
     *
     * Network aliases accepted (matching spine's `resolve_stablecoin_mint`):
     *   mainnet, mainnet-beta -> mainnet
     *   devnet, localnet      -> devnet
     *   testnet               -> testnet
     */
    public static function resolve(string $symbol, string $network): ?string
    {
        $entry = self::TABLE[strtoupper($symbol)] ?? null;
        if ($entry === null) {
            return null;
        }

        $normalized = self::normalizeNetwork($network);
        return $entry[$normalized] ?? null;
    }

    private static function normalizeNetwork(string $network): string
    {
        return match (strtolower($network)) {
            'mainnet', 'mainnet-beta' => 'mainnet',
            'devnet', 'localnet'      => 'devnet',
            'testnet'                 => 'testnet',
            default                   => strtolower($network),
        };
    }
}
