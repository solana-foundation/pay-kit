<?php

declare(strict_types=1);

namespace PayKit;

use PayKit\Exception\ConfigurationException;
use Throwable;
use PayKit\PayCore\Network;
use PayKit\PayCore\Stablecoin;

/**
 * Boot-time soundness checks. Mirrors Ruby PR #142 + Lua PR #141:
 *
 *   1. Fee-payer SOL balance >= 0.001 SOL.
 *   2. Recipient ATA exists for each accepted stablecoin.
 *
 * On `solana_localnet` with the demo signer, missing accounts are
 * auto-provisioned via Surfnet cheatcodes (surfnet_setAccount,
 * surfnet_setTokenAccount) so the example apps "just work" against
 * https://402.surfnet.dev:8899. Anywhere else, the missing account
 * raises {@see ConfigurationException} at boot. RPC failures during
 * preflight are caught and logged (not raised) so an unreachable
 * endpoint never blocks boot.
 *
 * Opt-out: `Config(preflight: false)` or
 * `PAY_KIT_DISABLE_PREFLIGHT=1`.
 */
final class Preflight
{
    public const MIN_FEE_PAYER_LAMPORTS = 1_000_000;
    public const AUTOFUND_LAMPORTS      = 10_000_000_000;
    public const SYSTEM_PROGRAM_ID      = '11111111111111111111111111111111';

    /** @var callable(string $method, array<int,mixed> $params): mixed|null */
    private static $rpcCallableOverride = null;

    /** @codeCoverageIgnore */
    private function __construct()
    {
    }

    public static function isDisabledByEnv(): bool
    {
        $raw = getenv('PAY_KIT_DISABLE_PREFLIGHT');
        return $raw === '1' || $raw === 'true';
    }

    /**
     * @param (callable(string,array<int,mixed>):mixed)|null $override
     * @internal
     */
    public static function setRpcCallableForTests(?callable $override): void
    {
        self::$rpcCallableOverride = $override;
    }

    public static function run(Config $config): void
    {
        $autofix = self::autofixEnabled($config);

        try {
            self::checkFeePayerSol($config, $autofix);
        } catch (ConfigurationException $e) {
            throw $e;
        } catch (Throwable $e) {
            // RPC failure is transient; do not block boot.
            self::warn('skipped fee-payer balance check: ' . $e->getMessage());
        }

        foreach ($config->stablecoins as $coin) {
            try {
                self::checkRecipientAta($config, $coin, $autofix);
            } catch (ConfigurationException $e) {
                throw $e;
            } catch (Throwable $e) {
                self::warn(sprintf(
                    'skipped %s ATA check: %s',
                    $coin->value,
                    $e->getMessage(),
                ));
            }
        }
    }

    private static function autofixEnabled(Config $config): bool
    {
        if ($config->network !== Network::SolanaLocalnet) {
            return false;
        }
        return $config->operator->signer?->isDemo() === true;
    }

    private static function checkFeePayerSol(Config $config, bool $autofix): void
    {
        if (!$config->operator->feePayer) {
            return;
        }
        $signer = $config->operator->signer;
        if ($signer === null) {
            return;
        }
        $pubkey = $signer->pubkey();
        $result = self::rpcCall($config, 'getBalance', [$pubkey, ['commitment' => 'confirmed']]);
        $lamports = is_array($result) && isset($result['value']) ? (int) $result['value'] : 0;
        if ($lamports >= self::MIN_FEE_PAYER_LAMPORTS) {
            return;
        }
        if ($autofix) {
            self::info(sprintf(
                'funding demo fee-payer %s with %d lamports via surfnet_setAccount',
                $pubkey,
                self::AUTOFUND_LAMPORTS,
            ));
            self::rpcCall($config, 'surfnet_setAccount', [
                $pubkey,
                [
                    'lamports'   => self::AUTOFUND_LAMPORTS,
                    'data'       => '',
                    'executable' => false,
                    'owner'      => self::SYSTEM_PROGRAM_ID,
                    'rentEpoch'  => 0,
                ],
            ]);
            return;
        }
        throw new ConfigurationException(sprintf(
            'pay_kit preflight: fee-payer %s has %d lamports on %s (need >= %d). '
            . 'Fund the account before booting.',
            $pubkey,
            $lamports,
            $config->network->value,
            self::MIN_FEE_PAYER_LAMPORTS,
        ));
    }

    private static function checkRecipientAta(Config $config, Stablecoin $coin, bool $autofix): void
    {
        $mintsLabel = $config->network->mintsLabel();
        $mint = \PayKit\PayCore\Solana\Mints::resolve($coin->value, $mintsLabel);
        if ($mint === null) {
            return; // native SOL has no ATA
        }
        $tokenProgram = \PayKit\PayCore\Solana\Mints::tokenProgramFor($coin->value, $mintsLabel);
        $recipient = $config->effectiveRecipient();
        $ata = \PayKit\PayCore\Solana\Mints::deriveAta($recipient, $mint, $tokenProgram);

        $info = self::rpcCall($config, 'getAccountInfo', [
            $ata,
            ['encoding' => 'base64', 'commitment' => 'confirmed'],
        ]);
        $value = is_array($info) && array_key_exists('value', $info) ? $info['value'] : null;
        if ($value !== null) {
            return;
        }

        if ($autofix) {
            self::info(sprintf(
                'provisioning %s ATA for %s (mint=%s) via surfnet_setTokenAccount',
                $coin->value,
                $recipient,
                $mint,
            ));
            self::rpcCall($config, 'surfnet_setTokenAccount', [
                $recipient,
                $mint,
                ['amount' => 0, 'state' => 'initialized'],
                $tokenProgram,
            ]);
            return;
        }
        throw new ConfigurationException(sprintf(
            'pay_kit preflight: recipient %s has no %s ATA on %s (expected %s). '
            . 'Create the ATA before booting.',
            $recipient,
            $coin->value,
            $config->network->value,
            $ata,
        ));
    }

    /**
     * @param array<int,mixed> $params
     */
    private static function rpcCall(Config $config, string $method, array $params): mixed
    {
        $override = self::$rpcCallableOverride;
        if ($override !== null) {
            return $override($method, $params);
        }
        $body = json_encode([
            'jsonrpc' => '2.0',
            'id'      => 1,
            'method'  => $method,
            'params'  => $params,
        ], JSON_THROW_ON_ERROR);
        $ctx = stream_context_create([
            'http' => [
                'method'  => 'POST',
                'header'  => "Content-Type: application/json\r\n",
                'content' => $body,
                'timeout' => 5,
                'ignore_errors' => true,
            ],
        ]);
        $raw = @file_get_contents($config->rpcUrl, false, $ctx);
        if ($raw === false) {
            throw new \RuntimeException(sprintf('rpc transport failure to %s', $config->rpcUrl));
        }
        $decoded = json_decode($raw, true);
        if (!is_array($decoded)) {
            throw new \RuntimeException('rpc returned non-JSON: ' . substr($raw, 0, 100));
        }
        return $decoded['result'] ?? null;
    }

    private static function warn(string $msg): void
    {
        error_log('[pay_kit preflight] WARN ' . $msg);
    }

    private static function info(string $msg): void
    {
        error_log('[pay_kit preflight] INFO ' . $msg);
    }
}
