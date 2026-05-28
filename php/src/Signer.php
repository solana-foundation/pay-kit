<?php

declare(strict_types=1);

namespace PayKit;

use PayKit\Exception\InvalidKeyException;
use PayKit\Signer\Demo;
use PayKit\Signer\LocalSigner;
use Throwable;
use PayKit\PayCore\Network;

/**
 * Factory class for the local-signer family.
 *
 * Constructors are static methods. The shipped instances satisfy
 * {@see LocalSigner}'s contract (`pubkey()`, `sign($msg)`,
 * `isFeePayer()`, `isDemo()`). Remote enclave signers (KMS) live in
 * {@see Kms} (reserved namespace, post-v1).
 *
 * Returned values are immutable; the secret bytes are held inside the
 * Keypair wrapper and never reach user code unless the caller asks.
 */
final class Signer
{
    /** @codeCoverageIgnore */
    private function __construct()
    {
    }

    /**
     * The package-shipped demo keypair. Boots the demo workflow with
     * zero configuration; Config::__construct refuses to combine this
     * with Network::SolanaMainnet.
     */
    public static function demo(): LocalSigner
    {
        return Demo::instance();
    }

    /**
     * Build a LocalSigner from raw 64-byte secret bytes. Accepts either
     * a binary string of exactly 64 bytes, or an array<int, int> of
     * 64 integers in [0, 255] (the Solana-CLI JSON-array shape parsed
     * but not stringified).
     *
     * @param string|array<int,int> $secret
     */
    public static function bytes(string|array $secret): LocalSigner
    {
        return LocalSigner::fromBytes($secret);
    }

    /**
     * Build a LocalSigner from a Solana-CLI JSON-array string,
     * e.g. "[1,2,3,...,64]".
     */
    public static function json(string $jsonArray): LocalSigner
    {
        $trimmed = trim($jsonArray);
        if ($trimmed === '') {
            throw new InvalidKeyException('pay_kit: Signer::json received empty input');
        }
        $decoded = json_decode($trimmed, true, flags: JSON_THROW_ON_ERROR);
        if (!is_array($decoded)) {
            throw new InvalidKeyException('pay_kit: Signer::json expected a JSON array');
        }
        return LocalSigner::fromBytes($decoded);
    }

    /**
     * Build a LocalSigner from a base58 representation of the 64-byte
     * secret (the Phantom / Solflare export shape).
     */
    public static function base58(string $base58Secret): LocalSigner
    {
        return LocalSigner::fromBase58($base58Secret);
    }

    /**
     * Build a LocalSigner from a 128-character hex string.
     */
    public static function hex(string $hexSecret): LocalSigner
    {
        return LocalSigner::fromHex($hexSecret);
    }

    /**
     * Read a Solana-CLI keypair JSON file and build a LocalSigner.
     */
    public static function file(string $path): LocalSigner
    {
        if (!is_string($path) || $path === '') {
            throw new InvalidKeyException('pay_kit: Signer::file expects a non-empty path');
        }
        if (!is_readable($path)) {
            throw new InvalidKeyException(
                sprintf('pay_kit: Signer::file cannot read %s', $path),
            );
        }
        $contents = file_get_contents($path);
        if ($contents === false) {
            throw new InvalidKeyException(
                sprintf('pay_kit: Signer::file read failed for %s', $path),
            );
        }
        return self::json($contents);
    }

    /**
     * Read an env var and auto-detect the encoding (JSON array, hex,
     * base58). Returns `null` when the var is unset or empty so the
     * Operator's null-as-default contract composes cleanly. A var that
     * IS set but malformed raises {@see InvalidKeyException} because
     * silent fallback would mask a real bug.
     */
    public static function env(string $name): ?LocalSigner
    {
        if ($name === '') {
            throw new InvalidKeyException('pay_kit: Signer::env expects a non-empty name');
        }
        $raw = getenv($name);
        if ($raw === false || $raw === '') {
            return null;
        }
        $trimmed = trim($raw);
        if ($trimmed === '') {
            return null;
        }
        try {
            if (str_starts_with($trimmed, '[')) {
                return self::json($trimmed);
            }
            if (strlen($trimmed) === 128 && ctype_xdigit($trimmed)) {
                return self::hex($trimmed);
            }
            return self::base58($trimmed);
        } catch (Throwable $e) {
            if ($e instanceof InvalidKeyException) {
                throw $e;
            }
            throw new InvalidKeyException(
                sprintf('pay_kit: Signer::env(%s) failed to parse: %s', $name, $e->getMessage()),
                previous: $e,
            );
        }
    }

    /**
     * Generate a fresh ephemeral keypair. Test-only — production
     * callers load from file or env so the same identity survives
     * across restarts.
     */
    public static function generate(): LocalSigner
    {
        return LocalSigner::generate();
    }
}
