<p align="center">
  <img src="https://github.com/solana-foundation/pay-kit/raw/main/docs/assets/banner.png" alt="MPP" width="100%" />
</p>

# solana/pay-kit

Charge stablecoins (USDC, USDT, PYUSD, ...) for any HTTP endpoint, in PHP.
Implements the Solana payment method for the
[Machine Payments Protocol](https://mpp.dev) and ships a drop-in Laravel
middleware for `402 Payment Required` flows.

**MPP** is [an open protocol proposal](https://paymentauth.org) that lets
any HTTP API accept payments using the `402 Payment Required` flow. You
do not need to know anything about Solana to use this library: pick a
currency, give it your wallet address, and gate a route in two lines.

[![PHP](https://img.shields.io/badge/PHP-8.1%2B-blue)]()
[![Coverage](https://img.shields.io/badge/coverage-90%25-brightgreen)]()

## Quick start

Gate a Laravel route with the `mpp.charge` middleware (from
[`examples/laravel/routes/api.php`](examples/laravel/routes/api.php)):

```php
<?php

use Illuminate\Support\Facades\Route;

Route::get('/paid', function () {
    return response()->json(['ok' => true, 'paid' => true]);
})->middleware('mpp.charge');
```

The `MppCharge` middleware (see
[`examples/laravel/app/Http/Middleware/MppCharge.php`](examples/laravel/app/Http/Middleware/MppCharge.php))
constructs a `SolanaChargeHandler`, inspects the `Authorization: Payment`
header, returns a 402 with a signed `WWW-Authenticate` challenge when no
valid credential is supplied, and otherwise lets the route render any
body it likes while emitting the `Payment-Receipt` header.

`currency` accepts a symbol like `"USDC"`, `"USDT"`, `"USDG"`, `"PYUSD"`,
or `"CASH"`. The SDK looks up the mint address, token program, and
decimals from a built-in table. You can also pass a raw mint pubkey for
tokens not in the table.

### Raw SDK usage

```php
use SolanaMpp\Intent\ChargeRequest;
use SolanaMpp\Server\ChargeServer;
use SolanaMpp\Server\SolanaChargeHandler;
use SolanaPhpSdk\Rpc\RpcClient;

$rpc = new RpcClient('https://402.surfnet.dev:8899');
$handler = new SolanaChargeHandler(
    challenges: new ChargeServer(
        secretKey: 'local-dev-secret',
        realm: 'api',
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

$result = $handler->handle($_SERVER['HTTP_AUTHORIZATION'] ?? null, $request);
```

`SolanaChargeHandler::handle()` returns either a `PaymentRequiredResponse`
(402) or a `ChargeSettlement` (200) with the on-chain signature. Both
expose the same `status` / `headers` / `body` properties so the HTTP
layer can project either path uniformly.

## Protocol compatibility matrix

### MPP

| Intent | Client | Server |
|---|:---:|:---:|
| `mpp/charge/pull` | --- | pass |
| `mpp/charge/push` | --- | planned |
| `mpp/session` | --- | --- |
| `mpp/subscription` | --- | --- |

### x402

| Intent | Client | Server |
|---|:---:|:---:|
| `x402/exact` | --- | --- |
| `x402/upto` | --- | --- |
| `x402/batch-settlement` | --- | --- |

This package ships server support only. Use a TypeScript, Rust, Go,
Python, Kotlin, or Swift client to drive payment flows against a
PHP-hosted endpoint.

For `mpp/charge/pull`: `SolanaChargeHandler` owns the full lifecycle. It
issues signed challenges with a pre-fetched `recentBlockhash`, parses
and validates the `Authorization: Payment` credential, pins the echoed
`ChargeRequest`, decodes the client-signed transaction and checks
recipient, amount, mint, splits, ATA, memos, and compute budget, rejects
Surfpool-signed transactions on non-localnet networks, optionally
fee-payer co-signs, broadcasts via `sendTransaction`, polls
`getSignatureStatuses` to `confirmed` / `finalized`, and emits
`payment-receipt` with the on-chain signature.

Push mode and the `x402/*` server surface are out of scope for this
package today.

## Examples

Two runnable examples ship with this package:

- [`examples/simple-server/`](examples/simple-server/index.php) - a
  single-file PHP script demonstrating the raw protocol on top of the
  SDK helpers.
- [`examples/laravel/`](examples/laravel/README.md) - a Laravel 12 app
  that registers `MppCharge` as a route middleware.

### Run the Laravel example

```bash
cd php/examples/laravel
composer install
cp .env.example .env
php -S 127.0.0.1:4567 -t public
```

### Drive it from a client

```bash
brew install pay
curl  http://127.0.0.1:4567/paid       # 402 payment required
pay curl http://127.0.0.1:4567/paid    # pays and succeeds
```

The Laravel example defaults to Surfpool localnet
(`https://402.surfnet.dev:8899`), `USDC`, and a local example recipient.
Override `MPP_RPC_URL`, `MPP_CURRENCY`, `MPP_PAY_TO`, `MPP_AMOUNT`, or
`MPP_FEE_PAYER_SECRET_KEY` for a different localnet fixture. See
[`examples/laravel/README.md`](examples/laravel/README.md) for how the
middleware is wired and how to apply it to your own routes.

## Solana dependencies

| Dependency | Why | Version |
|---|---|---|
| PHP standard library | server-side 402 helpers and HMAC challenge signing | 8.1+ |
| `solana-php/solana-sdk` | Solana transaction decode plus SPL Token, ATA, Memo, and System program primitives | `dev-master` |
| `phpunit/phpunit` | tests and coverage gate | `^10.0 || ^11.0` |
| `phpstan/phpstan` | static analysis at max level | `^2.1` |
| `friendsofphp/php-cs-fixer` | PSR-12-compatible format checks | `^3.89` |
| Ed25519 verifier | server-side voucher verification | --- |
| RFC 8785 canonical JSON | request field pre-base64url | local implementation |

The PHP SDK keeps Solana dependencies intentionally small.
`solana-php/solana-sdk` supplies Solana wire primitives only; MPP still
owns the payment verification semantics.

## Coding convention

This SDK follows PHP 8.1+, PSR-4 autoloading, PSR-12-compatible
formatting, and the
[`php-best-practices`](https://skills.sh/asyrafhussin/agent-skills/php-best-practices)
skill. The pass focuses on strict types, parameter and return types,
typed readonly properties, small focused classes, explicit exceptions,
and input validation before parsing payment credentials.

The repo-level `pay-sdk-implementation` skill remains the protocol source
of truth: Rust / spec wire format first, PHP idioms second.

## Code coverage

```bash
cd php
composer run lint
composer test
composer run test:coverage
```

CI runs the linter and `composer run test:coverage` with `pcov`. The
coverage command enforces a 90% line coverage gate and uploads
`php/build/coverage/clover.xml`.

## Interop

The PHP server has a direct harness adapter at
[`harness/php-server/server.php`](../harness/php-server/server.php).
Focused harness commands:

```bash
cd harness
MPP_INTEROP_CLIENTS=typescript MPP_INTEROP_SERVERS=php pnpm test
MPP_INTEROP_CLIENTS=rust       MPP_INTEROP_SERVERS=php pnpm test
```

## Spec

This SDK implements the [Solana Charge Intent](https://github.com/tempoxyz/mpp-specs/pull/188)
for the [HTTP Payment Authentication Scheme](https://paymentauth.org).

## Repo layout

```text
php/
├── src/Core/     # Payment headers, credentials, receipts, base64url JSON
├── src/Intent/   # Charge intent request model
├── src/Server/   # 402 challenge issuance + credential verification
├── examples/     # Simple-server script and Laravel middleware example
└── tests/        # PHPUnit unit tests
```

## License

MIT
