# Laravel + MPP middleware

A minimal Laravel 12 app that gates a route behind MPP using `App\Http\Middleware\MppCharge`.

## Layout

```text
examples/laravel/
├── app/Http/Middleware/MppCharge.php   # Thin wrapper around SolanaChargeHandler
├── bootstrap/app.php                   # Registers the `mpp.charge` middleware alias
├── public/index.php                    # Laravel front controller
├── routes/api.php                      # Route protected by `mpp.charge`
└── composer.json                       # Pulls in laravel/framework and the local SDK
```

## Run

```bash
cd php/examples/laravel
composer install
cp .env.example .env

php -S 127.0.0.1:4567 -t public
```

In another terminal:

```bash
# payment required → 402 with www-authenticate
curl -i http://127.0.0.1:4567/paid

# payment successful → 200 with payment-receipt
brew install pay
pay curl http://127.0.0.1:4567/paid
```

## How the middleware works

`MppCharge` delegates the full MPP charge lifecycle to the SDK's
`SolanaChargeHandler`:

1. Constructor builds the `ChargeRequest` (amount / currency / recipient
   from `.env`) and configures `SolanaChargeHandler` with an `RpcClient`
   pointing at the Solana RPC endpoint.
2. `handle()` passes the `Authorization` header to the handler. The handler
   verifies HMAC + expiry, pins the challenge against the expected request,
   decodes and validates the client-signed transaction
   (`SolanaChargeTransactionVerifier`), rejects Surfpool-signed transactions
   on non-localnet networks, broadcasts via `sendTransaction`, and polls
   until `confirmed`/`finalized`.
3. On 402 (missing or invalid credential) the middleware short-circuits with
   the SDK-built `application/problem+json` response and the
   `www-authenticate` challenge header.
4. On success (`ChargeSettlement`) the middleware forwards to the route via
   `$next($request)` and attaches `payment-receipt` plus the on-chain
   signature header to the route's response. The route keeps full control of
   its own body.

To use a fee-payer signer (so the client doesn't have to hold SOL), pass a
`Keypair` to `SolanaChargeHandler`'s `feePayer:` parameter and set
`methodDetails.feePayer = true` / `methodDetails.feePayerKey = $handler->feePayerPubkey()`
on the `ChargeRequest`.

## Apply the middleware to other routes

In `routes/api.php`:

```php
Route::get('/paid', fn () => response()->json(['ok' => true]))
    ->middleware('mpp.charge');
```

Or group several routes:

```php
Route::middleware('mpp.charge')->group(function () {
    Route::get('/paid', /* ... */);
    Route::post('/transcribe', /* ... */);
});
```
