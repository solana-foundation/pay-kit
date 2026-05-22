<?php

declare(strict_types=1);

// solana-php's CurlHttpClient still calls the no-op-since-PHP-8.0 curl_close()
// which raises E_DEPRECATED on PHP 8.5+. Route deprecations to stderr so they
// don't pollute the HTTP response body.
error_reporting(error_reporting() & ~E_DEPRECATED & ~E_USER_DEPRECATED);
ini_set('display_errors', 'stderr');

use SolanaMpp\Intent\ChargeRequest;
use SolanaMpp\Server\ChargeServer;
use SolanaMpp\Server\SolanaChargeHandler;
use SolanaPhpSdk\Rpc\RpcClient;

require_once __DIR__ . '/../../vendor/autoload.php';

$rpc = new RpcClient('https://402.surfnet.dev:8899');
$handler = new SolanaChargeHandler(
    challenges: new ChargeServer(
        secretKey: 'local-dev-secret',
        realm: 'PHP example',
        blockhashProvider: fn (): string => $rpc->getLatestBlockhash()['blockhash'],
    ),
    rpc: $rpc,
    network: 'localnet',
);
$request = new ChargeRequest(
    amount: '1000',
    currency: 'USDC',
    recipient: 'CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY',
    methodDetails: ['network' => 'localnet', 'decimals' => 6],
);

$rawAuth = $_SERVER['HTTP_AUTHORIZATION'] ?? null;
$result = $handler->handle(is_string($rawAuth) ? $rawAuth : null, $request);

http_response_code($result->status);
foreach ($result->headers as $name => $value) {
    // Pin the status on every header() call so PHP's built-in CLI server
    // doesn't rewrite 402 to 401 when WWW-Authenticate is present.
    header($name . ': ' . $value, true, $result->status);
}
echo json_encode($result->body, JSON_THROW_ON_ERROR);
