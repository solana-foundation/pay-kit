# Sinatra example

Demonstrates the `solana-pay-kit` surface: a single Sinatra app
that protects routes with either `x402:exact` or `mpp:charge`,
declared once in `pay_kit.rb`.

## Layout

```
config.ru     Rack entry
app.rb        Sinatra::Base + PayKit::Sinatra helpers
pay_kit.rb    PayKit.configure block + Pricing class + PayKit.pricing= assignment
```

## Run

```sh
cd ruby/examples/sinatra
bundle exec rackup -p 4567
```

## Routes

| Route               | Gate                | Protocols  | Notes |
|---------------------|---------------------|------------|-------|
| `GET /health`       | none                | n/a        | free probe |
| `GET /report`       | `:report`           | x402 + mpp | default config |
| `GET /stats`        | none (opportunistic)| n/a        | `paid?(:report)` |
| `GET /oneoff`       | inline `usd("0.25")`| x402 + mpp | one-shot, no registry entry |
| `GET /tiered?tier=` | `:tiered`           | x402 + mpp | dynamic price (basic vs premium) |
| `GET /marketplace/sale` | `:marketplace_sale` | mpp only | x402 auto-disabled (fee_within) |

## Manual curl proof

```sh
# Unpaid hits 402 with both schemes advertised
curl -i http://localhost:4567/report

# Server-Sent 402 body lists the accepts[] array:
#   { "error": "payment_required",
#     "resource": "/report",
#     "accepts": [ { protocol: "x402", ... }, { protocol: "mpp", ... } ] }
```

The 402 response also carries protocol-specific headers:

- `PAYMENT-REQUIRED` (base64 challenge body, x402 v2)
- `WWW-Authenticate: Payment ...` (MPP challenge)

## Configuration env vars

| Env var | Default | Notes |
|---------|---------|-------|
| `PAY_KIT_PAY_TO`              | demo address | default recipient |
| `PAY_KIT_NETWORK`             | `solana_devnet` | one of `solana_{mainnet,devnet,localnet}` |
| `PAY_KIT_ACCEPT`              | `x402,mpp` | ordered preference |
| `PAY_KIT_STABLECOINS`         | `USDC` | ordered settlement preference |
| `PAY_KIT_X402_FACILITATOR`    | surfnet | facilitator RPC URL |
| `PAY_KIT_X402_FACILITATOR_KEY`| `[]` | JSON-array secret key (set for real settlement) |
| `PAY_KIT_MPP_REALM`           | `PayKit Demo` | MPP realm string |
| `PAY_KIT_MPP_SECRET`          | demo value | HMAC challenge secret |
| `PAY_KIT_SELLER` / `PAY_KIT_PLATFORM` / `PAY_KIT_GATEWAY` | demo | fee-routing recipients |
