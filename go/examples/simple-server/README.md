# Go simple-server example

A minimal `net/http` server that mirrors the Ruby
[`examples/simple-server/app.rb`](../../../ruby/examples/simple-server/app.rb)
shape using the Go MPP SDK. It exposes `/health` (free) and `/paid`
(gated by the Solana charge method), and renders the
`Mpp::Challenge` / `Mpp::Settlement` tagged union by hand with the
SDK's lower-level `Charge`, `ParseAuthorization`, and
`VerifyCredentialWithExpected` primitives.

## Run

```bash
cd go/examples/simple-server
PORT=4572 go run .
```

The server binds to `127.0.0.1:$PORT` and defaults to Surfpool localnet
(`https://402.surfnet.dev:8899`), `USDC`, and the example recipient
`CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY`. Override any of these
through the env vars below.

## DX check

In another terminal:

```bash
brew install pay
curl -i http://127.0.0.1:4572/paid          # 402 with WWW-Authenticate
pay curl http://127.0.0.1:4572/paid         # 200 with Payment-Receipt
```

`pay curl` reads the `WWW-Authenticate: Payment ...` header, signs a
charge transaction with your local wallet, retries the request with the
`Authorization: Payment ...` header, and prints the response together
with the on-chain signature exposed on
`x-payment-settlement-signature`.

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `4572` | TCP port on `127.0.0.1` |
| `MPP_RPC_URL` | `https://402.surfnet.dev:8899` | Solana RPC endpoint |
| `MPP_CURRENCY` | `USDC` | currency symbol or raw mint pubkey |
| `MPP_NETWORK` | `localnet` | network passed into challenge methodDetails |
| `MPP_PAY_TO` | `CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY` | recipient pubkey |
| `MPP_SECRET_KEY` | `go-mpp-dev-secret` | HMAC challenge signing secret |
| `MPP_FEE_PAYER_SECRET_KEY` | unset | optional 64-byte JSON array; when set the server co-signs as fee payer |

When `MPP_FEE_PAYER_SECRET_KEY` is unset, the client pays its own fees,
just like the Ruby example's `nil` fee-payer branch.

## Behavior

- `GET /health` returns `200 {"ok":true}`.
- `GET /paid` with no `Authorization` header returns `402` with a
  signed `WWW-Authenticate: Payment` challenge and an
  `application/problem+json` body carrying the canonical L6 / P1
  structured error code shared across every MPP server SDK:
  `{"code":"payment_invalid","error":"payment_invalid","message":"Payment required","status":402,"title":"Payment Required","type":"https://paymentauth.org/problems/payment_invalid"}`.
- `GET /paid` with a valid `Authorization: Payment` credential returns
  `200`, sets `Payment-Receipt`, and mirrors the on-chain signature on
  `x-payment-settlement-signature`.
- Verification rejections re-issue a 402 with the canonical L6 code
  that matches the rejection class:
  `charge_request_mismatch` (amount, recipient, splits mismatch),
  `challenge_route_mismatch` (currency, method, intent, realm mismatch),
  `challenge_verification_failed` (HMAC id mismatch),
  `challenge_expired`, `wrong_network`, `signature_consumed`, and
  `payment_invalid` for malformed payloads or on-chain rejections.
