<p align="center">
  <img src="https://github.com/solana-foundation/mpp-sdk/raw/main/assets/banner.png" alt="MPP" width="100%" />
</p>

# solana-foundation/mpp-sdk-php

Solana payment method for the [Machine Payments Protocol](https://mpp.dev),
for PHP.

**MPP** is [an open protocol proposal](https://paymentauth.org) that lets
any HTTP API accept payments using the `402 Payment Required` flow.

[![PHP](https://img.shields.io/badge/PHP-8.1%2B-blue)]()
[![Coverage](https://img.shields.io/badge/coverage-90%25-green)]()

## Repo layout

```text
php/
├── src/Core/     # Payment headers, credentials, receipts, base64url JSON
├── src/Intent/   # Charge intent request model
├── src/Server/   # 402 challenge issuance + credential verification
├── examples/     # Minimal protected endpoint
└── tests/        # PHPUnit unit tests
```

## Quick start — server (charge)

```php
use SolanaMpp\Intent\ChargeRequest;
use SolanaMpp\Server\ChargeServer;

$server = new ChargeServer(secretKey: 'local-dev-secret', realm: 'api');
$request = new ChargeRequest(
    amount: '1000',
    currency: 'USDC',
    recipient: 'ExampleRecipient1111111111111111111111111111111',
    methodDetails: ['network' => 'localnet'],
);

header('www-authenticate: ' . $server->createChallengeHeader($request));
http_response_code(402);
```

## Quick start — client (auto-402)

PHP is server-side only for the current MPP roadmap. Use a client SDK or the
`pay` CLI to complete the 402 challenge/credential flow.

```bash
brew install pay

# start the example server
cd php
composer install
php -S 127.0.0.1:4567 examples/charge-server.php

# payment required
curl http://localhost:4567/paid

# payment successful
pay curl http://localhost:4567/paid
```

## Client compatibility matrix

| Intent | Status |
|---|:---:|
| `x402/exact` | — |
| `x402/upto` | — |
| `x402/batch-settlement` | — |
| `mpp/charge/pull` | — |
| `mpp/charge/push` | — |
| `mpp/session` | — |
| `mpp/subscription` | — |

## Server compatibility matrix

| Intent | Status |
|---|:---:|
| `x402/exact` | — |
| `x402/upto` | — |
| `x402/batch-settlement` | — |
| `mpp/charge/pull` | ✅ |
| `mpp/charge/push` | — |
| `mpp/session` | — |
| `mpp/subscription` | — |

The PHP server checkmark means this package can issue charge challenges,
validate `Payment` credentials, pin the echoed charge request to the protected
route, and emit payment receipts. Native PHP transaction settlement verification
now decodes and validates pull-mode transaction payloads before any downstream
settlement step. Because the Solana verifier runs before broadcast, use
`createReceiptHeaderForReference()` with the final on-chain signature after
settlement. RPC-backed broadcast, confirmation, fee-payer co-signing, push
signature lookup, and replay storage are follow-ups; the Surfpool-backed
interop server still performs the final broadcast after PHP accepts the
credential envelope.

## How to use the library

```bash
cd php
composer install
```

```php
use SolanaMpp\Core\Credential;
use SolanaMpp\Server\ChargeServer;
```

Public surface is documented inline; every public type/function carries a
summary so PHPStan/IDE hover can show intent, inputs, and outputs without
round-tripping to source.

## How to use the example

```bash
cd php
composer install
php -S 127.0.0.1:4567 examples/charge-server.php

# In another terminal:
brew install pay

# payment required
curl -i http://127.0.0.1:4567/paid

# payment successful
pay curl http://127.0.0.1:4567/paid
```

The example spins up one protected endpoint at `/paid`. Use the interop harness
for the full Surfpool-backed transaction flow.

## Solana dependencies

| Dependency | Why | Version |
|---|---|---|
| PHP standard library | server-side 402 helpers and HMAC challenge signing | 8.1+ |
| `solana-php/solana-sdk` | Solana transaction decode plus SPL Token, ATA, Memo, and System program primitives | `dev-master` locked at `0bde2b0` |
| `phpunit/phpunit` | tests and coverage gate | `^10.0 || ^11.0` |
| `phpstan/phpstan` | static analysis at max level | `^2.1` |
| `friendsofphp/php-cs-fixer` | PSR-12-compatible format checks | `^3.89` |
| Ed25519 verifier | server-side voucher verification | — |
| RFC 8785 canonical JSON | request field pre-base64url | local implementation |

PHP does not currently construct Solana transactions or act as a wallet client.
The TypeScript interop fixture verifies PHP server behavior by combining this
package with the TypeScript transaction client.
`solana-php/solana-sdk` is installed from GitHub as a VCS dependency because
the package is not yet available through the default Composer registry lookup.
MPP still owns the payment verification semantics; the dependency only supplies
Solana wire primitives.

## Coding convention

This SDK follows PHP 8.1+, PSR-4 autoloading, PSR-12-compatible formatting, and
the [`php-best-practices`](https://skills.sh/asyrafhussin/agent-skills/php-best-practices)
skill selected for this PR. The pass focuses on strict types, parameter and
return types, typed readonly properties, small focused classes, explicit
exceptions, and input validation before parsing payment credentials.

The repo-level `pay-sdk-implementation` skill remains the protocol source of
truth: Rust/spec wire format first, PHP idioms second.

## Code coverage

```bash
cd php
composer run lint
composer test
composer run test:coverage
```

CI runs the linter and `composer run test:coverage` with `pcov`. The coverage
command enforces a 90% line coverage gate and uploads
`php/build/coverage/clover.xml`.

## Spec

This SDK implements the [Solana Charge Intent](https://github.com/tempoxyz/mpp-specs/pull/188)
for the [HTTP Payment Authentication Scheme](https://paymentauth.org).

## License

MIT
