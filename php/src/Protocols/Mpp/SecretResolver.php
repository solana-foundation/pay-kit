<?php

declare(strict_types=1);

namespace PayKit\Protocols\Mpp;

/**
 * Auto-resolves the MPP HMAC challenge-binding secret when the
 * application doesn't set one explicitly. Mirrors Ruby PR #142's
 * preflight chain so the example apps boot without the operator
 * having to set anything:
 *
 *   1. ENV[\$envVar] -- production pattern (orchestrator-supplied).
 *   2. ./.env parsed for the same key -- sticky across restarts,
 *      shared by PHP-FPM workers in the same project root.
 *   3. Generate `bin2hex(random_bytes(32))` and append to ./.env
 *      (mode 0600 if the file is being created) so subsequent boots
 *      reuse the same value.
 *
 * If ./.env is unwritable (read-only container, etc.), keeps the
 * in-memory generated value and signals via the returned `persisted`
 * flag. Caller is expected to surface a warning in that case --
 * the secret rotates per process and invalidates in-flight challenges
 * on restart.
 *
 * The dotenv parser is intentionally a tolerant ~10-line reader so
 * we don't pull in a dotenv dependency for this one feature.
 *
 * @internal
 */
final class SecretResolver
{
    /** @codeCoverageIgnore */
    private function __construct()
    {
    }

    /**
     * @return array{secret:string,source:string,persisted:bool}
     */
    public static function resolveMppSecret(
        string $envVar = 'PAY_KIT_MPP_CHALLENGE_BINDING_SECRET',
        ?string $dotenvPath = null,
    ): array {
        $dotenvPath ??= getcwd() !== false ? getcwd() . '/.env' : '.env';

        $fromEnv = getenv($envVar);
        if (is_string($fromEnv) && $fromEnv !== '') {
            return ['secret' => $fromEnv, 'source' => 'env', 'persisted' => true];
        }

        $fromDotenv = self::readDotenv($dotenvPath, $envVar);
        if ($fromDotenv !== null) {
            return ['secret' => $fromDotenv, 'source' => 'dotenv', 'persisted' => true];
        }

        $generated = bin2hex(random_bytes(32));
        $persisted = self::appendToDotenv($dotenvPath, $envVar, $generated);
        return [
            'secret'    => $generated,
            'source'    => $persisted ? 'generated+persisted' : 'generated',
            'persisted' => $persisted,
        ];
    }

    private static function readDotenv(string $path, string $key): ?string
    {
        if (!is_readable($path)) {
            return null;
        }
        $handle = @fopen($path, 'r');
        if ($handle === false) {
            return null;
        }
        try {
            while (($line = fgets($handle)) !== false) {
                $trimmed = trim($line);
                if ($trimmed === '' || str_starts_with($trimmed, '#')) {
                    continue;
                }
                $eq = strpos($trimmed, '=');
                if ($eq === false) {
                    continue;
                }
                $name = trim(substr($trimmed, 0, $eq));
                if ($name !== $key) {
                    continue;
                }
                $value = trim(substr($trimmed, $eq + 1));
                // Strip optional surrounding quotes.
                if (strlen($value) >= 2 && (
                    ($value[0] === '"' && substr($value, -1) === '"') ||
                    ($value[0] === "'" && substr($value, -1) === "'")
                )) {
                    $value = substr($value, 1, -1);
                }
                return $value !== '' ? $value : null;
            }
        } finally {
            fclose($handle);
        }
        return null;
    }

    private static function appendToDotenv(string $path, string $key, string $value): bool
    {
        $line = sprintf('%s=%s%s', $key, $value, PHP_EOL);
        $existed = is_file($path);
        // Use 'a' to append; create with 0600 if it didn't exist.
        $fh = @fopen($path, 'a');
        if ($fh === false) {
            return false;
        }
        try {
            if (!$existed) {
                @chmod($path, 0600);
            }
            $bytes = fwrite($fh, $line);
            return $bytes === strlen($line);
        } finally {
            fclose($fh);
        }
    }
}
