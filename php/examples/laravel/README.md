# Laravel + PayKit umbrella

A minimal Laravel 12 app that gates routes behind the dual-protocol
PayKit middleware. The `paykit:<name>` route-middleware alias is
registered automatically by
`PayKit\Frameworks\Laravel\PayKitServiceProvider`, and the active
protocol (x402 or MPP) is picked per request from the client's
`payment-signature` / `Authorization: Payment` header.

## Layout

```text
examples/laravel/
├── app/Pricing.php          # Three named gates: paid, x402Only, marketplaceSale
├── bootstrap/app.php        # Standard Laravel 12 bootstrap (provider auto-discovers)
├── public/index.php         # Laravel front controller
├── routes/api.php           # Routes protected by `paykit:<name>`
└── composer.json            # Pulls in laravel/framework and the local SDK
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
# payment required: 402 with x402 + mpp accepts entries
curl -i http://127.0.0.1:4567/paid

# payment successful: 200 with the per-protocol settlement header
brew install pay
pay curl http://127.0.0.1:4567/paid
```

## How the middleware works

The provider builds a `PayKit\Client` from `config('paykit')` and
aliases the route middleware. Each route declares which named gate
from `App\Pricing` to apply:

```php
Route::get('/paid', fn () => response()->json(['ok' => true, 'paid' => true]))
    ->middleware('paykit:paid');

Route::get('/api/data', fn () => response()->json(['data' => []]))
    ->middleware('paykit:x402Only');

Route::post('/marketplace/buy', fn () => response()->json(['sold' => true]))
    ->middleware('paykit:marketplaceSale');
```

`paykit:<name>` resolves `<name>` against the `App\Pricing` instance
the container auto-wires. On a missing or invalid credential the
middleware short-circuits with a 402 that lists both `x402` and `mpp`
offers in `accepts[]`. On success the verified `PayKit\Payment` is
attached to the request as the `paykit.payment` attribute and the
per-protocol settlement header (`x-payment-settlement-signature` for
MPP, `payment-response` for x402) is merged into the controller's
response.
