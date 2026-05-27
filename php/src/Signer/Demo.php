<?php

declare(strict_types=1);

namespace PayKit\Signer;

use SolanaPhpSdk\Keypair\Keypair;

/**
 * Hard-coded demo keypair shipped with the package. The same identity
 * across every PayKit SDK (Ruby PayKit::Signer::Demo,
 * Lua pay_kit.signer.demo, etc.), so a process running one SDK can
 * exchange traffic with a process running another during local dev.
 *
 * Config::__construct refuses to combine this signer with
 * Network::SolanaMainnet. Single Boot of this class via instance()
 * caches the underlying LocalSigner.
 */
final class Demo
{
    public const PUBKEY = 'ALtYSsZuYyKrNSe6GnVCzxj1T2RPMTPzXMe51xhbmXEq';

    /**
     * 64-byte secret matching the Ruby / Lua demo signer.
     *
     * @var list<int>
     */
    private const SECRET_BYTES = [
        26,  61, 117, 192,   9, 232,  24,  51,  89, 135, 105, 182,  47,   9,  83, 244,
        11, 214,  85, 170, 227,  83, 170,  26,  55, 129,  58, 114,  89, 160, 195,  51,
       138, 209, 127,  35,  54,  41, 202, 166, 199, 166,  97, 238, 181,  63, 254, 185,
        45,  16, 174, 102, 250, 198,  30, 191, 232, 236, 147, 167,  41, 178, 151,  26,
    ];

    private static ?LocalSigner $instance = null;

    /** @codeCoverageIgnore */
    private function __construct()
    {
    }

    public static function instance(): LocalSigner
    {
        if (self::$instance === null) {
            $bytes = '';
            foreach (self::SECRET_BYTES as $b) {
                $bytes .= chr($b);
            }
            self::$instance = LocalSigner::fromKeypair(Keypair::fromSecretKey($bytes), isDemo: true);
        }
        return self::$instance;
    }

    /**
     * Test-only: reset the cached singleton so the next instance()
     * call rebuilds. Used by config_test fixtures.
     *
     * @internal
     */
    public static function resetForTests(): void
    {
        self::$instance = null;
    }
}
