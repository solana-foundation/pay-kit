# Laravel + MPP middleware

A minimal Laravel 12 app that gates a route behind MPP using `App\Http\Middleware\MppCharge`.

## Layout

```text
examples/laravel/
├── app/Http/Middleware/MppCharge.php   # Wraps ChargeServer; issues 402, verifies, attaches receipt
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

`MppCharge::handle()`:

1. Builds the `ChargeRequest` once in the constructor (amount, currency, recipient — sourced from `.env`).
2. If `Authorization` is missing → returns 402 with a signed `www-authenticate` challenge.
3. If present → verifies via `ChargeServer::verifyAuthorizationHeader()`, pinning the echoed challenge to the expected request. The bundled `ExampleVerifier` accepts any non-empty `signature`/`transaction` reference — swap it for `SolanaChargeTransactionVerifier` or your own implementation before going live.
4. On success → forwards to the route, then attaches `payment-receipt` to the outgoing response.

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
