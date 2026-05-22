<p align="center">
  <img src="https://github.com/solana-foundation/mpp-sdk/raw/main/assets/banner.png" alt="MPP" width="100%" />
</p>

# solana/pay-sdk

Solana payment method for the [Machine Payments Protocol](https://mpp.dev),
for PHP.

**MPP** is [an open protocol proposal](https://paymentauth.org) that lets
any HTTP API accept payments using the `402 Payment Required` flow.

[![PHP](https://img.shields.io/badge/PHP-8.1%2B-blue)]()
[![Coverage](https://img.shields.io/badge/coverage-90%25-brightgreen)]()

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
http_response_code($result->status);
foreach ($result->headers as $name => $value) {
    header("$name: $value", true, $result->status);
}
echo json_encode($result->body, JSON_THROW_ON_ERROR);
```

`SolanaChargeHandler::handle()` returns either a `PaymentRequiredResponse`
(402, missing/invalid credential) or a `ChargeSettlement` (200, with the
on-chain signature). Both expose the same `status` / `headers` / `body`
properties so the HTTP layer can project either path uniformly.

## Quick start

Launch the bare PHP server from `examples/simple-server/`:

```bash
# Install dependencies
composer install

# Launch server
php -S 127.0.0.1:4567 -t examples/simple-server
```

In another terminal, send requests using `curl` and  `pay`:

```bash
brew install pay

# payment required
curl http://localhost:4567/paid

# payment successful
pay curl http://localhost:4567/paid
```

For a Laravel integration that wires the SDK in as a middleware, see
[`examples/laravel/`](examples/laravel/README.md).

## Client compatibility matrix

PHP is server-side only for the current MPP roadmap. 

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

Split into two columns because the work an MPP server does breaks into two
phases: **Verification** (protocol-level — parse the credential, validate the
challenge, decode and check the embedded transaction structure) and
**Settlement** (chain-level — fee-payer co-sign, broadcast, confirm).

| Intent | Status |
|---|:---:|
| `x402/exact` | — |
| `x402/upto` | — |
| `x402/batch-settlement` | — |
| `mpp/charge/pull` | ✅ |
| `mpp/charge/push` | — |
| `mpp/session` | — |
| `mpp/subscription` | — |

For `mpp/charge/pull`: `SolanaChargeHandler` owns the full lifecycle — issue
signed challenges with a pre-fetched `recentBlockhash`, parse/validate the
`Authorization: Payment` credential, pin the echoed `ChargeRequest`, decode
the client-signed transaction and check
recipient/amount/mint/splits/ATA/memos/compute budget, reject Surfpool-signed
transactions on non-localnet networks, fee-payer co-sign (when configured),
broadcast via `sendTransaction`, poll `getSignatureStatuses` to
`confirmed`/`finalized`, and emit `payment-receipt` with the on-chain
signature. The pure-PHP interop server at
[`tests/interop/php-server/server.php`](../tests/interop/php-server/server.php)
exercises this end-to-end through Surfpool in CI for both TypeScript and Rust
clients.

## Roadmap

- **Push-mode signature verifier.** A `PaymentVerifier` that handles
  `payload['signature']`: fetch the transaction by signature, run the same
  structural checks as `SolanaChargeTransactionVerifier`, and reject if the
  on-chain state doesn't match the challenge. Unblocks `mpp/charge/push`.
- **Replay storage.** A pluggable store keyed by challenge id (or signature)
  so a credential can only settle once. The TS and Rust SDKs already define
  this interface; PHP needs an equivalent contract plus an in-memory default.
- **Other intents.** `x402/*`, `mpp/session`, `mpp/subscription` aren't yet
  scoped on the PHP side.

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

## How to use the examples

Two examples ship with this package:

- [`examples/simple-server/`](examples/simple-server/index.php) — a single-file
  PHP script demonstrating the raw protocol on top of the SDK helpers.
- [`examples/laravel/`](examples/laravel/README.md) — a Laravel 12 app that
  registers `MppCharge` as a route middleware (`->middleware('mpp.charge')`).

### Simple PHP server

```bash
cd php
composer install
php -S 127.0.0.1:4567 -t examples/simple-server

# In another terminal:
brew install pay

# payment required
curl -i http://127.0.0.1:4567/paid

# payment successful
pay curl http://127.0.0.1:4567/paid
```

### Laravel server with MPP middleware

```bash
cd php/examples/laravel
composer install
cp .env.example .env
php -S 127.0.0.1:4567 -t public

# Same curl / pay flow as above.
```

See [`examples/laravel/README.md`](examples/laravel/README.md) for how the
middleware is wired and how to apply it to your own routes.

Both examples expose one protected endpoint at `/paid`. Use the interop harness
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
