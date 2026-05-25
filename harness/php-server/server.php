<?php

declare(strict_types=1);

/**
 * Pure-PHP MPP interop charge server.
 *
 * Drives the same `SolanaChargeHandler` users of the SDK get; this file is
 * just env reading + a tiny socket-level HTTP framer so the harness can spawn
 * it and read a `ready` JSON line with an ephemeral port.
 */

use SolanaMpp\Intent\ChargeRequest;
use SolanaMpp\Server\ChargeServer;
use SolanaMpp\Server\SolanaChargeHandler;
use SolanaMpp\Store\FileStore;
use SolanaPhpSdk\Keypair\Keypair;
use SolanaPhpSdk\Rpc\RpcClient;

// solana-php's CurlHttpClient still calls the no-op-since-PHP-8.0 curl_close()
// which raises E_DEPRECATED on PHP 8.5+. Route deprecations to stderr so they
// don't pollute the ready/result JSON the harness parses from stdout.
error_reporting(error_reporting() & ~E_DEPRECATED & ~E_USER_DEPRECATED);
ini_set('display_errors', 'stderr');

require __DIR__ . '/../../php/vendor/autoload.php';

// ── Env ──────────────────────────────────────────────────────────────────────

/** Read a required env var or die with a clear error. */
function require_env(string $name): string
{
    $value = getenv($name);
    if (!is_string($value) || $value === '') {
        fwrite(STDERR, "Missing required env: $name\n");
        exit(2);
    }
    return $value;
}

function optional_env(string $name, string $default): string
{
    $value = getenv($name);
    return is_string($value) && $value !== '' ? $value : $default;
}

/**
 * Parse a JSON array-of-bytes secret key (Solana CLI / web3.js format) into
 * the 64-byte string Keypair::fromSecretKey expects.
 */
function secret_key_from_json(string $raw): string
{
    /** @var mixed $decoded */
    $decoded = json_decode($raw, true, flags: JSON_THROW_ON_ERROR);
    if (!is_array($decoded) || count($decoded) !== Keypair::SECRET_KEY_LENGTH) {
        throw new InvalidArgumentException('secret key JSON must be a 64-element byte array');
    }
    $bytes = '';
    foreach ($decoded as $byte) {
        if (!is_int($byte) || $byte < 0 || $byte > 255) {
            throw new InvalidArgumentException('secret key bytes must be u8 integers');
        }
        $bytes .= chr($byte);
    }
    return $bytes;
}

$rpcUrl = require_env('MPP_INTEROP_RPC_URL');
$network = optional_env('MPP_INTEROP_NETWORK', 'localnet');
$mint = require_env('MPP_INTEROP_MINT');
$amount = require_env('MPP_INTEROP_AMOUNT');
$paymentMode = optional_env('MPP_INTEROP_PAYMENT_MODE', 'pull');
$payTo = require_env('MPP_INTEROP_PAY_TO');
$secretKey = optional_env('MPP_INTEROP_SECRET_KEY', 'mpp-interop-secret-key');
$resourcePath = optional_env('MPP_INTEROP_RESOURCE_PATH', '/paid');
$settlementHeader = optional_env('MPP_INTEROP_SETTLEMENT_HEADER', 'x-payment-settlement-signature');
$replayPath = getenv('MPP_INTEROP_REPLAY_SOURCE_PATH') ?: null;
$replayAmount = getenv('MPP_INTEROP_REPLAY_SOURCE_AMOUNT') ?: null;
/** @var mixed $splitsDecoded */
$splitsDecoded = json_decode(optional_env('MPP_INTEROP_SPLITS', '[]'), true, flags: JSON_THROW_ON_ERROR);
if (!is_array($splitsDecoded)) {
    fwrite(STDERR, "MPP_INTEROP_SPLITS must decode to an array\n");
    exit(2);
}
/** @var array<int, array<string, mixed>> $splits */
$splits = $splitsDecoded;

$feePayer = Keypair::fromSecretKey(secret_key_from_json(require_env('MPP_INTEROP_FEE_PAYER_SECRET_KEY')));

// ── SDK wiring ───────────────────────────────────────────────────────────────

$rpc = new RpcClient($rpcUrl);
$handler = new SolanaChargeHandler(
    challenges: new ChargeServer(
        secretKey: $secretKey,
        realm: 'MPP Interop',
        blockhashProvider: fn (): string => $rpc->getLatestBlockhash()['blockhash'],
    ),
    rpc: $rpc,
    feePayer: $feePayer,
    network: $network,
    settlementHeader: $settlementHeader,
    // Per-PID FileStore so two server processes in the same interop run
    // don't collide on the in-memory MemoryStore default. Push-mode
    // replay tests rely on durable cross-request consumption.
    replayStore: new FileStore(sys_get_temp_dir() . '/mpp-php-interop-replay-' . getmypid()),
);

/**
 * @param array<int, array<string, mixed>> $splits
 */
function build_charge_request(string $amount, string $mint, string $payTo, string $network, string $paymentMode, ?string $feePayerKey, array $splits): ChargeRequest
{
    $methodDetails = [
        'network' => $network,
        'decimals' => 6,
    ];
    // B34: push-mode routes MUST NOT advertise a server-side fee payer.
    // Only pull-mode routes attach feePayer/feePayerKey so the server
    // co-signs the client-built transaction before broadcast.
    if ($paymentMode !== 'push') {
        $methodDetails['feePayer'] = true;
        $methodDetails['feePayerKey'] = $feePayerKey;
    }
    if ($splits !== []) {
        $methodDetails['splits'] = $splits;
    }
    return new ChargeRequest(
        amount: $amount,
        currency: $mint,
        recipient: $payTo,
        description: 'PHP interop protected content',
        methodDetails: $methodDetails,
    );
}

// ── HTTP framing ─────────────────────────────────────────────────────────────

/**
 * @param resource $conn
 * @return array{method: string, path: string, headers: array<string, string>}|null
 */
function read_request(mixed $conn): ?array
{
    $requestLine = fgets($conn);
    if (!is_string($requestLine) || trim($requestLine) === '') {
        return null;
    }
    $parts = preg_split('/\s+/', trim($requestLine));
    if ($parts === false || count($parts) < 2) {
        return null;
    }
    [$method, $path] = [$parts[0], $parts[1]];

    $headers = [];
    while (true) {
        $line = fgets($conn);
        if (!is_string($line)) {
            return null;
        }
        $line = rtrim($line, "\r\n");
        if ($line === '') {
            break;
        }
        $colon = strpos($line, ':');
        if ($colon === false) {
            continue;
        }
        $name = strtolower(trim(substr($line, 0, $colon)));
        $value = trim(substr($line, $colon + 1));
        $headers[$name] = $value;
    }
    return ['method' => $method, 'path' => $path, 'headers' => $headers];
}

/**
 * @param resource $conn
 * @param array<string, string> $headers
 */
function write_response(mixed $conn, int $status, array $headers, mixed $body): void
{
    $reason = match ($status) {
        200 => 'OK',
        402 => 'Payment Required',
        404 => 'Not Found',
        default => 'Server Error',
    };
    if (is_array($body)) {
        $payload = json_encode($body, JSON_THROW_ON_ERROR);
    } elseif (is_string($body)) {
        $payload = $body;
    } else {
        $payload = '';
    }
    $merged = array_merge(['connection' => 'close', 'content-length' => (string) strlen($payload)], $headers);

    $head = "HTTP/1.1 $status $reason\r\n";
    foreach ($merged as $name => $value) {
        $head .= $name . ': ' . $value . "\r\n";
    }
    $head .= "\r\n";
    fwrite($conn, $head . $payload);
}

// ── Listen + accept ──────────────────────────────────────────────────────────

$listener = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
if ($listener === false) {
    fwrite(STDERR, "bind failed: $errstr ($errno)\n");
    exit(1);
}
$name = stream_socket_get_name($listener, false);
if (!is_string($name)) {
    fwrite(STDERR, "stream_socket_get_name failed\n");
    exit(1);
}
$port = (int) substr($name, strrpos($name, ':') + 1);

fwrite(STDOUT, json_encode([
    'type' => 'ready',
    'implementation' => 'php',
    'role' => 'server',
    'port' => $port,
    'capabilities' => ['charge'],
], JSON_THROW_ON_ERROR) . "\n");
fflush(STDOUT);

if (function_exists('pcntl_async_signals')) {
    pcntl_async_signals(true);
    $shutdown = function () use ($listener): void {
        if (is_resource($listener)) {
            fclose($listener);
        }
        exit(0);
    };
    pcntl_signal(SIGTERM, $shutdown);
    pcntl_signal(SIGINT, $shutdown);
}

while (is_resource($listener)) {
    $conn = @stream_socket_accept($listener, -1);
    if ($conn === false) {
        continue;
    }
    try {
        $req = read_request($conn);
        if ($req === null) {
            fclose($conn);
            continue;
        }

        if ($req['method'] === 'GET' && $req['path'] === '/health') {
            write_response($conn, 200, ['content-type' => 'application/json'], ['ok' => true]);
            fclose($conn);
            continue;
        }

        $protectedAmount = null;
        if ($req['method'] === 'GET' && $req['path'] === $resourcePath) {
            $protectedAmount = $amount;
        } elseif ($req['method'] === 'GET' && $replayPath !== null && $req['path'] === $replayPath) {
            $protectedAmount = $replayAmount ?? $amount;
        }

        if ($protectedAmount === null) {
            write_response($conn, 404, ['content-type' => 'application/json'], ['error' => 'not_found']);
            fclose($conn);
            continue;
        }

        $request = build_charge_request($protectedAmount, $mint, $payTo, $network, $paymentMode, $handler->feePayerPubkey(), $splits);
        $authorization = $req['headers']['authorization'] ?? null;
        $result = $handler->handle($authorization, $request);

        write_response($conn, $result->status, $result->headers, $result->body);
        fclose($conn);
    } catch (Throwable $error) {
        fwrite(STDERR, 'interop php server error: ' . $error->getMessage() . "\n");
        if (is_resource($conn)) {
            try {
                write_response($conn, 500, ['content-type' => 'application/json'], ['error' => $error->getMessage()]);
            } catch (Throwable) {
                // ignore secondary failure
            }
            fclose($conn);
        }
    }
}
