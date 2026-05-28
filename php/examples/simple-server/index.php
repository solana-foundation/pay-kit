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
// The Client picks the protocol from the client's headers per
// request: x402 via PAYMENT-SIGNATURE, MPP via Authorization: Payment.

// solana-php's CurlHttpClient still calls the no-op-since-PHP-8.0
// curl_close() which raises E_DEPRECATED on PHP 8.5+. Route those to
// stderr so they don't pollute the HTTP response body.
error_reporting(error_reporting() & ~E_DEPRECATED & ~E_USER_DEPRECATED);
ini_set('display_errors', 'stderr');

require_once __DIR__ . '/../../vendor/autoload.php';

use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7Server\ServerRequestCreator;
use PayKit\Client;
use PayKit\Config;
use PayKit\Gate;
use PayKit\Middleware\RequirePayment;
use PayKit\Network;
use PayKit\Price;
use PayKit\Protocol;
use PayKit\Protocols\Mpp\MppConfig;

// Boot the umbrella. Zero-config localnet defaults: Surfpool hosted
// RPC, demo recipient, demo signer.
$client = new Client(new Config(
    network: Network::SolanaLocalnet,
    preflight: false, // example boots offline-friendly
    mpp: new MppConfig(realm: 'PHP example', challengeBindingSecret: 'local-dev-secret'),
));

// One inline-priced gate. Accepts both x402 and MPP per default
// Config::$accept (Protocol::X402, Protocol::Mpp in order).
$paidGate = new Gate(amount: Price::usd('0.10'));

// Wire a single PSR-15 middleware around a tiny "200 OK" handler.
$middleware = new RequirePayment($client, $paidGate);

$factory = new Psr17Factory();
$creator = new ServerRequestCreator($factory, $factory, $factory, $factory);
$request = $creator->fromGlobals();

if ($request->getUri()->getPath() === '/health') {
    $factory->createResponse(200)
        ->withHeader('content-type', 'application/json')
        ->withBody($factory->createStream(json_encode(['ok' => true]) ?: '{}'))
        ->getBody()
        ->rewind();
    echo json_encode(['ok' => true]);
    return;
}

if ($request->getUri()->getPath() !== '/paid') {
    http_response_code(404);
    header('content-type: application/json');
    echo json_encode(['error' => 'not_found']);
    return;
}

$response = $middleware->process(
    $request,
    new class () implements Psr\Http\Server\RequestHandlerInterface {
        public function handle(Psr\Http\Message\ServerRequestInterface $req): Psr\Http\Message\ResponseInterface
        {
            $factory = new Psr17Factory();
            return $factory->createResponse(200)
                ->withHeader('content-type', 'application/json')
                ->withBody($factory->createStream(json_encode(['ok' => true, 'paid' => true]) ?: '{}'));
        }
    },
);

http_response_code($response->getStatusCode());
foreach ($response->getHeaders() as $name => $values) {
    foreach ($values as $value) {
        header(sprintf('%s: %s', $name, $value), false);
    }
}
echo (string) $response->getBody();
