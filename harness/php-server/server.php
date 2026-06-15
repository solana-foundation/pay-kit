<?php

declare(strict_types=1);

/**
 * Cross-language harness adapter for the PHP PayKit umbrella.
 *
 * One TCP server, two settle paths (x402:exact and mpp:charge),
 * picked per scenario by which env namespace the harness orchestrator
 * sets (or by the explicit PAY_KIT_HARNESS_PROTOCOL hint). Mirrors
 * harness/lua-server/server.lua and the Ruby pay-kit-server pattern.
 *
 * Drives the harness contract:
 *   1. Read env (PAY_KIT_HARNESS_PROTOCOL OR exclusive MPP_/X402_).
 *   2. Boot the PayKit umbrella + register one gate at the requested amount.
 *   3. Listen on a free TCP port; print {"type":"ready",...} on stdout.
 *   4. Route GET /<resource> through the matching protocol adapter.
 */

// solana-php's CurlHttpClient still calls curl_close(); silence the
// PHP 8.5+ deprecation so the ready/result JSON stays clean.
error_reporting(error_reporting() & ~E_DEPRECATED & ~E_USER_DEPRECATED);
ini_set('display_errors', 'stderr');

require __DIR__ . '/../../php/vendor/autoload.php';

use Nyholm\Psr7\Factory\Psr17Factory;
use PayKit\PayKit;
use PayKit\Config;
use PayKit\PayCore\Currency;
use PayKit\Gate;
use PayKit\PayCore\Network;
use PayKit\Operator;
use PayKit\Price;
use PayKit\Protocol;
use PayKit\Protocols\Mpp\Intent\ChargeRequest;
use PayKit\Protocols\Mpp\MppConfig;
use PayKit\Protocols\Mpp\Server\ChargeServer;
use PayKit\Protocols\Mpp\Server\SolanaChargeHandler;
use PayKit\Protocols\X402\Adapter as X402Adapter;
use PayKit\Signer;
use PayKit\PayCore\Stablecoin;
use PayKit\Store\FileStore;
use SolanaPhpSdk\Keypair\Keypair;
use SolanaPhpSdk\Rpc\RpcClient;

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

// ── Detect intent ───────────────────────────────────────────────────────────

$explicit = strtolower(optional_env('PAY_KIT_HARNESS_PROTOCOL', ''));
$x402Active = false;
if ($explicit === 'x402') {
    $x402Active = true;
} elseif ($explicit === 'mpp' || $explicit === 'charge') {
    $x402Active = false;
} else {
    $x402Set = (getenv('X402_HARNESS_RPC_URL') ?: '') !== '';
    $mppSet  = (getenv('MPP_HARNESS_RPC_URL') ?: '') !== '';
    if ($x402Set === $mppSet) {
        fwrite(STDERR, "set exactly one of X402_HARNESS_RPC_URL / MPP_HARNESS_RPC_URL, or set PAY_KIT_HARNESS_PROTOCOL\n");
        exit(2);
    }
    $x402Active = $x402Set;
}

// ── Per-protocol env read ───────────────────────────────────────────────────

if ($x402Active) {
    $rpcUrl       = require_env('X402_HARNESS_RPC_URL');
    $payTo        = require_env('X402_HARNESS_PAY_TO');
    $facilitatorSecretJson = require_env('X402_HARNESS_FACILITATOR_SECRET_KEY');
    $amountUnits  = optional_env('X402_HARNESS_AMOUNT', '1000');
    $mint         = optional_env('X402_HARNESS_MINT', 'USDC');
    $networkRaw   = optional_env('X402_HARNESS_NETWORK', 'solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1');
    $resourcePath = optional_env('X402_HARNESS_RESOURCE_PATH', '/paid');
    $settlementHeader = optional_env('X402_HARNESS_SETTLEMENT_HEADER', 'x-payment-settlement-signature');
} else {
    $rpcUrl       = require_env('MPP_HARNESS_RPC_URL');
    $payTo        = require_env('MPP_HARNESS_PAY_TO');
    $mint         = require_env('MPP_HARNESS_MINT');
    $amountUnits  = require_env('MPP_HARNESS_AMOUNT');
    $mppSecret    = optional_env('MPP_HARNESS_SECRET_KEY', 'pay-kit-harness-secret');
    $networkRaw   = optional_env('MPP_HARNESS_NETWORK', 'localnet');
    $resourcePath = optional_env('MPP_HARNESS_RESOURCE_PATH', '/paid');
    $settlementHeader = optional_env('MPP_HARNESS_SETTLEMENT_HEADER', 'x-payment-settlement-signature');
    $paymentMode  = optional_env('MPP_HARNESS_PAYMENT_MODE', 'pull');
    $replayPath   = getenv('MPP_HARNESS_REPLAY_SOURCE_PATH') ?: null;
    $replayAmount = getenv('MPP_HARNESS_REPLAY_SOURCE_AMOUNT') ?: null;
    /** @var mixed $splitsDecoded */
    $splitsDecoded = json_decode(optional_env('MPP_HARNESS_SPLITS', '[]'), true, flags: JSON_THROW_ON_ERROR);
    $splits = is_array($splitsDecoded) ? $splitsDecoded : [];
    $feePayer = Keypair::fromSecretKey(secret_key_from_json(require_env('MPP_HARNESS_FEE_PAYER_SECRET_KEY')));
}

// ── Boot the SDK ────────────────────────────────────────────────────────────

if ($x402Active) {
    // x402 mode: build the umbrella PayKit + X402 Adapter with the
    // facilitator key as the operator's signer.
    $signer = Signer::json($facilitatorSecretJson);
    $client = new PayKit(new Config(
        network:     resolve_network($networkRaw),
        accept:      [Protocol::X402],
        stablecoins: [Stablecoin::Usdc],
        rpcUrl:      $rpcUrl,
        operator:    new Operator(recipient: $payTo, signer: $signer, feePayer: true),
        mpp:         new MppConfig(challengeBindingSecret: 'unused-x402'),
        preflight:   false,
    ));
    $adapter = new X402Adapter($client->config);
    $gate = new Gate(amount: Price::usd(format_decimal_amount($amountUnits)));
} else {
    // MPP mode: build the lower-level ChargeServer + SolanaChargeHandler
    // (the existing MPP adapter path; matches the legacy harness shape).
    $rpc = new RpcClient($rpcUrl);
    $handler = new SolanaChargeHandler(
        challenges: new ChargeServer(
            secretKey: $mppSecret,
            realm:     'MPP Harness',
            blockhashProvider: fn (): string => $rpc->getLatestBlockhash()['blockhash'],
        ),
        rpc:        $rpc,
        feePayer:   $feePayer,
        network:    $networkRaw,
        settlementHeader: $settlementHeader,
        replayStore: new FileStore(sys_get_temp_dir() . '/mpp-php-harness-replay-' . getmypid()),
    );
}

function resolve_network(string $raw): Network
{
    if (str_starts_with($raw, 'solana:')) {
        return $raw === 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp'
            ? Network::SolanaMainnet
            : Network::SolanaDevnet;
    }
    return match ($raw) {
        'mainnet' => Network::SolanaMainnet,
        'devnet'  => Network::SolanaDevnet,
        default   => Network::SolanaLocalnet,
    };
}

/**
 * Convert a smallest-units integer string to a 6-decimal Price::usd
 * argument (e.g. "1000" -> "0.001" for USDC).
 */
function format_decimal_amount(string $units, int $decimals = 6): string
{
    $n = (int) $units;
    if ($n === 0) {
        return '0';
    }
    $divisor = 10 ** $decimals;
    $whole = intdiv($n, $divisor);
    $frac = $n - ($whole * $divisor);
    if ($frac === 0) {
        return (string) $whole;
    }
    return rtrim(sprintf('%d.%0' . $decimals . 'd', $whole, $frac), '0');
}

/**
 * @param array<int,array<string,mixed>> $splits
 */
function build_charge_request(string $amount, string $mint, string $payTo, string $network, string $paymentMode, ?string $feePayerKey, array $splits): ChargeRequest
{
    $methodDetails = [
        'network'  => $network,
        'decimals' => 6,
    ];
    if ($paymentMode !== 'push') {
        $methodDetails['feePayer']    = true;
        $methodDetails['feePayerKey'] = $feePayerKey;
    }
    if ($splits !== []) {
        $methodDetails['splits'] = $splits;
    }
    return new ChargeRequest(
        amount:        $amount,
        currency:      $mint,
        recipient:     $payTo,
        description:   'PHP harness protected content',
        methodDetails: $methodDetails,
    );
}

// ── HTTP framing ────────────────────────────────────────────────────────────

/**
 * @param resource $conn
 * @return array{method:string,path:string,headers:array<string,string>}|null
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
 * @param array<string,string> $headers
 */
function write_response(mixed $conn, int $status, array $headers, mixed $body): void
{
    $reason = match ($status) {
        200 => 'OK',
        402 => 'Payment Required',
        404 => 'Not Found',
        default => 'Server Error',
    };
    $payload = is_array($body) ? json_encode($body, JSON_THROW_ON_ERROR) : (is_string($body) ? $body : '');
    $merged = array_merge(['connection' => 'close', 'content-length' => (string) strlen($payload)], $headers);
    $head = "HTTP/1.1 $status $reason\r\n";
    foreach ($merged as $name => $value) {
        $head .= $name . ': ' . $value . "\r\n";
    }
    fwrite($conn, $head . "\r\n" . $payload);
}

// ── Build a PSR-7 request for the x402 adapter ──────────────────────────────

function psr7_from_socket(array $req): \Psr\Http\Message\ServerRequestInterface
{
    $factory = new Psr17Factory();
    $r = $factory->createServerRequest($req['method'], $req['path']);
    foreach ($req['headers'] as $k => $v) {
        $r = $r->withHeader($k, $v);
    }
    return $r;
}

// ── Listen + accept ─────────────────────────────────────────────────────────

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
    'type'           => 'ready',
    'implementation' => 'php',
    'role'           => 'server',
    'port'           => $port,
    'capabilities'   => [$x402Active ? 'exact' : 'charge'],
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
        $isProtected = ($req['method'] === 'GET' && $req['path'] === $resourcePath);
        $isReplay = (!$x402Active && $req['method'] === 'GET'
            && isset($replayPath) && $replayPath !== null && $req['path'] === $replayPath);
        if (!$isProtected && !$isReplay) {
            write_response($conn, 404, ['content-type' => 'application/json'], ['error' => 'not_found']);
            fclose($conn);
            continue;
        }

        if ($x402Active) {
            // x402 path through the umbrella adapter.
            $psrReq = psr7_from_socket($req);
            $sig = $req['headers']['payment-signature'] ?? '';
            if ($sig === '') {
                // No credential — emit 402 challenge.
                $accepts = [$adapter->acceptsEntry($gate, $psrReq)];
                $challengeHeaders = $adapter->challengeHeaders($gate, $psrReq);
                write_response($conn, 402, array_merge(['content-type' => 'application/json'], $challengeHeaders), [
                    'error'    => 'payment_required',
                    'resource' => $req['path'],
                    'accepts'  => $accepts,
                ]);
            } else {
                try {
                    $payment = $adapter->verifyAndSettle($gate, $psrReq);
                    // The harness reads the settlement signature from a
                    // configurable header name (X402_HARNESS_SETTLEMENT_HEADER);
                    // the default is x-payment-settlement-signature but
                    // scenarios override it (e.g. x-fixture-settlement).
                    $headers = array_merge(
                        ['content-type' => 'application/json'],
                        $payment->settlementHeaders,
                        [$settlementHeader => $payment->transaction],
                    );
                    write_response($conn, 200, $headers, [
                        'ok'          => true,
                        'paid'        => true,
                        'protocol'    => 'x402',
                        'transaction' => $payment->transaction,
                    ]);
                } catch (Throwable $e) {
                    write_response($conn, 402, ['content-type' => 'application/json'], [
                        'error'   => 'invalid_proof',
                        'message' => $e->getMessage(),
                    ]);
                }
            }
        } else {
            // Existing MPP path (untouched).
            $protectedAmount = $isReplay && $replayAmount !== null ? (string) $replayAmount : $amountUnits;
            $request = build_charge_request($protectedAmount, $mint, $payTo, $networkRaw, $paymentMode, $handler->feePayerPubkey(), $splits);
            $authorization = $req['headers']['authorization'] ?? null;
            $result = $handler->handle($authorization, $request);
            write_response($conn, $result->status, $result->headers, $result->body);
        }
        fclose($conn);
    } catch (Throwable $error) {
        fwrite(STDERR, 'harness php server error: ' . $error->getMessage() . "\n");
        if (is_resource($conn)) {
            try {
                write_response($conn, 500, ['content-type' => 'application/json'], ['error' => $error->getMessage()]);
            } catch (Throwable) {
                // ignore
            }
            fclose($conn);
        }
    }
}
