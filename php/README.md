<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://github.com/solana-foundation/pay-kit/raw/main/docs/assets/banner-php-dark.png">
    <source media="(prefers-color-scheme: light)" srcset="https://github.com/solana-foundation/pay-kit/raw/main/docs/assets/banner-php-light.png">
    <img alt="Solana pay-kit — PHP" width="100%" style="border-top-left-radius: 8px; border-top-right-radius: 8px; margin-bottom: 16px;" src="https://github.com/solana-foundation/pay-kit/raw/main/docs/assets/banner-php-light.png">
  </picture>
</div>

Charge stablecoins (USDC, USDT, PYUSD, …) for any HTTP endpoint, in PHP.
One package, one surface, two protocols underneath:
[x402](https://x402.org) and the
[Machine Payments Protocol](https://paymentauth.org). Laravel and
Symfony ride on top of a pure PSR-15 middleware.

You do not need to know anything about Solana to use this library: pick a
currency, give it your wallet address, and gate a route in two lines.

[![PHP](https://img.shields.io/badge/php-8.2%2B-blue)]()
[![Coverage](https://img.shields.io/badge/coverage-92%25-brightgreen)]()
[![Branch coverage](https://img.shields.io/badge/branch%20coverage-tracked-blue)]()

---

## Quick start

Three progressively-realistic snippets. Each one runs as-is, copy,
paste, hit the URL. Laravel is the framework here; the same surface
works in Slim, Mezzio, Symfony, and any other PSR-15-aware host.

### 1. Smallest possible app

Gate one route with an inline price. Zero-config: the package uses a
published demo keypair as the recipient and the hosted Surfpool
sandbox at `https://402.surfnet.dev:8899` as the RPC.

```php
// routes/api.php
use PayKit\Gate;
use PayKit\Price;
use Illuminate\Support\Facades\Route;

Route::get('/report', fn () => ['premium' => 'report'])
    ->middleware(['paykit:inline'])
    ->defaults('paykit.gate', new Gate(amount: Price::usd('0.10')));
```

`PayKitServiceProvider` mounts the package; the `paykit:<name>` route
middleware halts the request with a 402 if no valid payment is sent,
or sets the verified `Payment` on the request and forwards to the
route handler if one is.

Hit `/report` with [`pay curl`](#run-the-example) and the customer
walks through Touch ID and a USDC payment.

### 2. Multiple gates via a Pricing class

Lift the prices into a `Pricing` subclass; routes reference gates by
property name.

```php
// app/Pricing.php
namespace App;

use PayKit\Gate;
use PayKit\Price;
use PayKit\Protocol;

final class Pricing extends \PayKit\Pricing
{
    public readonly Gate $report;
    public readonly Gate $apiCall;

    public function __construct()
    {
        $this->report  = new Gate(amount: Price::usd('0.10'), description: 'Premium report');
        $this->apiCall = new Gate(amount: Price::usd('0.001'), accept: [Protocol::X402]);
    }
}
```

```php
// routes/api.php
Route::get('/report',   fn () => ['premium' => 'report'])->middleware('paykit:report');
Route::get('/api/data', fn () => ['data' => []])->middleware('paykit:apiCall');
```

Gates are validated at boot. Wrong currency, missing recipient, fee
math that does not add up - all raise from `new Gate(...)` before any
request lands.

### 3. Production-shape config

```php
// config/paykit.php
return [
    'network'     => 'solana_mainnet',
    'rpc_url'     => 'https://mainnet.helius-rpc.com/?api-key=YOUR_HELIUS_KEY',
    'accept'      => ['x402', 'mpp'],
    'stablecoins' => ['USDC', 'PYUSD'],
    'operator' => [
        'recipient' => 'AyNAa2VPe2t5pgg8M61iE6kqMudkV98zsT4rkAZuU6tj',
        'key'       => '/etc/paykit/operator.json',
        'fee_payer' => true,
    ],
    'mpp_challenge_binding_secret' => 'dev-only-rotate-in-prod',
];
```

```php
// app/Pricing.php — same shape, with a fee-bearing gate
final class Pricing extends \PayKit\Pricing
{
    public readonly Gate $marketplaceSale;

    public function __construct()
    {
        // Customer pays $10.00 ; SELLER nets $9.70 ; PLATFORM nets $0.30
        $this->marketplaceSale = new Gate(
            amount:    Price::usd('10.00'),
            feeWithin: ['CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY' => Price::usd('0.30')],
        );
    }
}
```

Two safety rails fire at boot:

- `solana_mainnet` plus the demo signer raises `DemoSignerOnMainnetException`.
- Missing `mpp_challenge_binding_secret` - Preflight surfaces the gap and
  points at `PAY_KIT_MPP_CHALLENGE_BINDING_SECRET` as the env override.

---

## Run the example

```bash
git clone https://github.com/solana-foundation/pay-kit
cd pay-kit/php/examples/laravel
composer install
php artisan serve --port=4567
```

On `solana_localnet` with the demo signer, the package provisions the
recipient's USDC account on Surfpool via cheatcodes the first time,
then settles real on-chain payments after that.

```bash
brew install pay     # or: npm install -g @solana/pay

curl -i http://127.0.0.1:4567/api/paid     # 402 - payment required
pay curl -i http://127.0.0.1:4567/api/paid # 200 - payment provided
```

---

## x402

[x402](https://x402.org) revives HTTP `402 Payment Required` as a
client-server payment handshake. x402 is single-recipient by design;
gates with `feeWithin` or `feeOnTop` auto-disable x402.

| Intent             | Status |
|--------------------|--------|
| `exact`            | ✅      |
| `upto`             | —      |
| `batch-settlement` | —      |

## MPP

The [Machine Payments Protocol](https://paymentauth.org) supports
multi-recipient splits, server-side fee accounting, and a separate
fee-payer signer. Use MPP when your gate has a platform fee or the
server subsidises the customer's network fee.

| Intent         | Status |
|----------------|--------|
| `charge/pull`  | ✅      |
| `charge/push`  | ✅      |
| `session`      | —      |
| `subscription` | —      |

---

## Server-only

This package ships server support only. Drive the client side from:

- [`pay curl`](https://github.com/solana-foundation/pay)
- The Rust, TypeScript, Go, Python, Ruby, Kotlin, Swift, or Lua
  pay-kit client SDKs (sibling READMEs in this repo)

---

## Vocabulary

| Term            | Meaning                                                              |
|-----------------|----------------------------------------------------------------------|
| **operator**    | Merchant identity: recipient + signer + fee-payer flag.              |
| **gate**        | A protected unit. Amount, optional fees, accepted protocols.         |
| **amount**      | Base amount a gate charges, before any `feeOnTop`.                   |
| **total**       | What the customer pays: `amount + sum(feeOnTop)`. Derived.           |
| **price**       | Value object: number + currency + settlement preference list.           |
| **feeWithin**   | Fee taken out of the amount. ``payTo` recipient nets less.            |
| **feeOnTop**    | Fee added to the amount. Customer pays more; `payTo` nets full.      |
| **payment**     | Proof submitted by the client to pass a gate.                        |
| **protocol**    | `Protocol::X402` or `Protocol::Mpp`.                                 |
| **scheme**      | A protocol sub-form: x402 `exact`, MPP `charge`.                     |
| **currency**    | The unit a price is denominated in (USDC, USDT, PYUSD, …).           |
| **settlement**  | The on-chain transfer that fulfils a verified payment.              |
| **accept**      | Ordered preference list (protocols and stablecoins both).            |

## Three primitives

Namespace functions under `PayKit\Middleware\`. Import per file:

```php
use function PayKit\Middleware\{payment, isPaid, isPaidFor, requirePayment};
```

| Function                                  | Returns       | On failure                    |
|-------------------------------------------|---------------|-------------------------------|
| `RequirePayment` (PSR-15 middleware)      | next handler  | 402 response                  |
| `payment($request)`                       | `?Payment`    | `null` if unauthenticated     |
| `isPaid($request)`                        | `bool`        | never                         |
| `isPaidFor($request, $gate)`              | `bool`        | never                         |
| `requirePayment($request)`                | `Payment`     | throws PaymentRequiredException |

## Inline pricing

```php
$app->get('/oneoff', $handler)
    ->add(new \PayKit\Middleware\RequirePayment($client, new Gate(amount: Price::usd('0.25'))));
```

## Gate DSL

Boot-time validations (all raise from `new Gate(...)`):

- `payTo` is required (gate kwarg or `operator.recipient`)
- All fee prices share one currency with the amount
- `sum(feeWithin) <= amount`
- `accept: [Protocol::X402]` on a fee-bearing gate raises `ProtocolIncompatibleException`

## PSR-15-first

The core middleware is `PayKit\Middleware\RequirePayment`. Slim and Mezzio
mount it directly; Laravel and Symfony adapters are thin shims over
the same class. The Laravel `paykit` route-middleware alias bridges
the framework request to PSR-7 via `symfony/psr-http-message-bridge`
and delegates to `RequirePayment` so both stacks share one code path.

---

## Coverage

```bash
cd php
composer install
composer run lint
vendor/bin/phpunit
```

## Harness

The interop adapter lives at
[`harness/php-server`](../harness/php-server) (out of the shipped
library). It boots one gated endpoint that cross-language clients pay
against:

```bash
cd harness
MPP_INTEROP_CLIENTS=typescript MPP_INTEROP_SERVERS=php pnpm test
MPP_INTEROP_CLIENTS=rust       MPP_INTEROP_SERVERS=php pnpm test
```

## Spec

This SDK implements the
[Solana Charge Intent](https://paymentauth.org/draft-solana-charge-00.html)
for the [HTTP Payment Authentication Scheme](https://paymentauth.org),
plus the [x402 exact scheme](https://x402.org) on Solana with the full
11-rule structural verifier.

---

## Repo layout

```text
php/
├── src/
│   ├── PayKit.php, Config.php, Operator.php, Signer.php, Gate.php, Price.php,
│   │   Fee.php, Pricing.php, Payment.php, Preflight.php    # umbrella surface
│   ├── Protocol.php, Stablecoin.php                        # umbrella backed enums
│   ├── Signer/{Demo, LocalSigner}.php                      # signer factory + impl
│   ├── Exception/Exceptions.php                            # typed exceptions (one file)
│   ├── Middleware/{RequirePayment, functions}.php          # PSR-15 middleware + ns fns
│   ├── Frameworks/{Laravel, Symfony}/                      # umbrella adapters
│   ├── PayCore/                                            # protocol-agnostic primitives
│   │   ├── Currency.php, Network.php, HttpFactory.php
│   │   ├── Rfc3339Parser.php                               # RFC 3339
│   │   ├── Wire/{Base64Url, Json}.php                      # base64url + RFC 8785
│   │   ├── Rpc/{RpcGateway, SolanaRpcGateway}.php          # JSON-RPC transport
│   │   └── Solana/Mints.php                                # mint table + token program
│   ├── Protocols/
│   │   ├── Mpp/{Adapter, MppConfig, SecretResolver}.php    # MPP protocol
│   │   │   ├── Core/{Challenge, ChallengeEcho, Credential, Receipt, Headers}.php
│   │   │   ├── Intent/ChargeRequest.php
│   │   │   └── Server/{ChargeServer, SolanaChargeHandler, ...}.php
│   │   └── X402/{Adapter, X402Config}.php                  # x402 protocol
│   │       └── Exact/Verifier.php                          # x402 exact scheme
│   └── Store/{Store, MemoryStore, FileStore}.php           # replay store
├── examples/{laravel, simple-server}/
└── tests/                                                  # PHPUnit suite
```

## Coding convention

PSR-1, PSR-12, PER-CS for code style. `php-cs-fixer` + `phpstan
--level=max` in CI. `strict_types=1` on every file. Constructor
property promotion everywhere. `readonly` classes for value objects.
`brick/math` `BigDecimal` for money - never `float`.

## License

MIT
