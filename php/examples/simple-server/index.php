<?php

declare(strict_types=1);

// Dual-protocol example using the PayKit umbrella against the
// bundled PHP built-in web server. Boots with:
//
//   cd php/examples/simple-server
//   composer install
//   php -S 127.0.0.1:4567 index.php
//
// Then in another terminal:
//   curl  http://127.0.0.1:4567/paid          # 402 with x402 + mpp accepts
//   pay curl http://127.0.0.1:4567/paid       # 200 with payment-receipt
//
// The middleware picks the protocol from the client's headers per
// request: x402 via `payment-signature`, MPP via `Authorization: Payment`.

// solana-php's CurlHttpClient still calls the no-op-since-PHP-8.0
// curl_close() which raises E_DEPRECATED on PHP 8.5+. Route those to
// stderr so they don't pollute the HTTP response body.
error_reporting(error_reporting() & ~E_DEPRECATED & ~E_USER_DEPRECATED);
ini_set('display_errors', 'stderr');

require_once __DIR__ . '/../../vendor/autoload.php';

use PayKit\PayKit;
use PayKit\Config;
use PayKit\Gate;
use PayKit\Middleware\RequirePayment;
use PayKit\PayCore\HttpFactory;
use PayKit\PayCore\Network;
use PayKit\Price;
use PayKit\Protocols\Mpp\MppConfig;

// Boot the umbrella. Zero-config localnet defaults: Surfpool hosted
// RPC, demo recipient, demo signer. `preflight: false` keeps the
// example bootable offline; production callers leave preflight on.
$client = new PayKit(new Config(
    network: Network::SolanaLocalnet,
    preflight: false,
    // The challenge-binding secret must be >= 32 bytes (audit #24). This is a
    // throwaway dev value; generate yours with `openssl rand -base64 32`.
    mpp: new MppConfig(realm: 'PHP example', challengeBindingSecret: 'local-dev-secret-0123456789abcdef-01'),
));

// One inline-priced gate. Accepts both x402 and MPP per default
// Config::$accept (Protocol::X402, Protocol::Mpp in order).
$paidGate = new Gate(amount: Price::usd('0.10'));
$middleware = new RequirePayment($client, $paidGate);

$request = HttpFactory::serverRequestFromGlobals();
$path    = $request->getUri()->getPath();
$factory = HttpFactory::responseFactory();
$stream  = HttpFactory::streamFactory();

if ($path === '/health') {
    HttpFactory::emit(
        $factory->createResponse(200)
            ->withHeader('content-type', 'application/json')
            ->withBody($stream->createStream(json_encode(['ok' => true]) ?: '{}')),
    );
    return;
}

if ($path !== '/paid') {
    HttpFactory::emit(
        $factory->createResponse(404)
            ->withHeader('content-type', 'application/json')
            ->withBody($stream->createStream(json_encode(['error' => 'not_found']) ?: '{}')),
    );
    return;
}

$response = $middleware->process(
    $request,
    new class ($factory, $stream) implements Psr\Http\Server\RequestHandlerInterface {
        public function __construct(
            private readonly Psr\Http\Message\ResponseFactoryInterface $factory,
            private readonly Psr\Http\Message\StreamFactoryInterface $stream,
        ) {
        }
        public function handle(Psr\Http\Message\ServerRequestInterface $req): Psr\Http\Message\ResponseInterface
        {
            return $this->factory->createResponse(200)
                ->withHeader('content-type', 'application/json')
                ->withBody($this->stream->createStream(json_encode(['ok' => true, 'paid' => true]) ?: '{}'));
        }
    },
);

HttpFactory::emit($response);
