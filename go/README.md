<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://github.com/solana-foundation/pay-kit/raw/main/docs/assets/banner-go-dark.png">
    <source media="(prefers-color-scheme: light)" srcset="https://github.com/solana-foundation/pay-kit/raw/main/docs/assets/banner-go-light.png">
    <img alt="Solana pay-kit — Go" width="100%" style="border-top-left-radius: 8px; border-top-right-radius: 8px; margin-bottom: 16px;" src="https://github.com/solana-foundation/pay-kit/raw/main/docs/assets/banner-go-light.png">
  </picture>
</div>

# github.com/solana-foundation/pay-kit/go

Charge stablecoins (USDC, USDT, PYUSD, ...) for any HTTP endpoint, in Go.
Implements the Solana payment method for the
[Machine Payments Protocol](https://mpp.dev) and ships a `net/http`
middleware for `402 Payment Required` flows.

**MPP** is [an open protocol proposal](https://paymentauth.org) that lets
any HTTP API accept payments using the `402 Payment Required` flow. You
do not need to know anything about Solana to use this library: pick a
currency, give it your wallet address, and gate a route in two lines.

[![Go](https://img.shields.io/badge/go-1.26%2B-blue)]()
[![Coverage](https://img.shields.io/badge/coverage-90%25-brightgreen)]()

## Quick start

Gate a `net/http` route with `server.PaymentMiddleware` (from
[`examples/simple-server/`](examples/simple-server)):

```go
package main

import (
    "net/http"

    "github.com/solana-foundation/pay-kit/go/server"
)

func main() {
    handler, err := server.New(server.Config{
        Recipient: "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
        Currency:  "USDC",
        Decimals:  6,
        Network:   "localnet",
        RPCURL:    "https://402.surfnet.dev:8899",
        SecretKey: "local-dev-secret",
        Realm:     "Go MPP Example",
    })
    if err != nil { panic(err) }

    paid := server.PaymentMiddleware(handler, func(r *http.Request) (string, server.ChargeOptions, error) {
        return "0.001", server.ChargeOptions{Description: "Paid endpoint"}, nil
    })(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte(`{"ok":true,"paid":true}`))
    }))

    http.Handle("/paid", paid)
    http.ListenAndServe(":4572", nil)
}
```

`Currency` accepts a symbol like `"USDC"`, `"USDT"`, `"USDG"`, `"PYUSD"`,
or `"CASH"`. The SDK looks up the mint address, token program, and
decimals from a built-in table. Pass a raw mint pubkey for tokens not
in the table.

The `Mpp` handler owns every static knob (recipient, default currency,
network, RPC, optional fee payer signer). Per-request you pass the
charge amount through the `ChargeFunc`. The blockhash is fetched lazily
through the RPC client so a busy endpoint does not pay an RPC round trip
on every protected request.

### Client

```go
import "github.com/solana-foundation/pay-kit/go/client"

httpClient := client.NewClient(signer, rpcClient)
resp, err := httpClient.Get("https://api.example/paid")
```

`client.NewClient` returns an `*http.Client` whose transport replays
401 / 402 responses with the appropriate `Authorization: Payment`
credential. Use `client.BuildCredentialHeader` directly if you want to
own the retry yourself.

## Protocol compatibility matrix

### MPP

| Intent | Client | Server |
|---|:---:|:---:|
| `mpp/charge/pull` | pass | pass |
| `mpp/charge/push` | pass | pass |
| `mpp/session` | --- | --- |
| `mpp/subscription` | --- | --- |

### x402

| Intent | Client | Server |
|---|:---:|:---:|
| `x402/exact` | --- | --- |
| `x402/upto` | --- | --- |
| `x402/batch-settlement` | --- | --- |

For `mpp/charge/pull`: the server owns the full lifecycle. It issues
signed challenges with a fresh `recentBlockhash`, parses and validates
the `Authorization: Payment` credential, pins the echoed charge request,
decodes the client-signed transaction and checks recipient, amount,
mint, splits, ATA, memos, and compute budget, rejects Surfpool-signed
transactions on non-localnet networks, optionally fee-payer co-signs,
broadcasts via `sendTransaction`, polls `getSignatureStatuses` to
`confirmed` / `finalized`, and emits `payment-receipt` with the on-chain
signature.

For `mpp/charge/push`: the server fetches the transaction by signature
with `getTransaction`, rejects failed or missing metadata, reuses the
same structural transaction verifier as pull mode, consumes the
signature through replay storage, and emits the same receipt shape.

## Examples

One runnable example ships with this package:

- [`examples/simple-server/`](examples/simple-server) - bare `net/http`
  server that constructs an `mpp/server` handler with the Solana charge
  method and exposes `/health` (free) and `/paid` (gated).

### Run the example

```bash
cd go/examples/simple-server
PORT=4572 go run .
```

### Drive it from a client

```bash
brew install pay
curl  http://127.0.0.1:4572/paid       # 402 payment required
pay curl http://127.0.0.1:4572/paid    # pays and succeeds
```

The example defaults to Surfpool localnet (`https://402.surfnet.dev:8899`),
`USDC`, and a local example recipient. Override `MPP_RPC_URL`,
`MPP_CURRENCY`, `MPP_NETWORK`, `MPP_PAY_TO`, `MPP_SECRET_KEY`, or
`MPP_FEE_PAYER_SECRET_KEY` (a 64-byte JSON array) for a different
localnet fixture.

## Solana dependencies

| Dependency | Why | Version |
|---|---|---|
| `github.com/gagliardetto/solana-go` | transaction message encoding, ATA derivation, base58 keys | pinned in `go.mod` |
| `github.com/gagliardetto/solana-go/programs/token` | SPL Token transfer instruction layout | bundled with `solana-go` |
| `github.com/gagliardetto/solana-go/programs/token-2022` | Token-2022 transfer instruction layout | bundled with `solana-go` |
| `github.com/gagliardetto/solana-go/programs/compute-budget` | compute unit limit / price instructions | bundled with `solana-go` |
| `github.com/gagliardetto/solana-go/programs/system` | native SOL transfer instructions | bundled with `solana-go` |
| internal canonical JSON | base64url-encoded canonical JSON with `json.Number` preservation | in package |

The Go SDK keeps the transitive dependency tree to the `solana-go`
toolkit and the Go standard library. Canonical JSON encoding routes
through a `json.Number`-preserving decoder so large amounts beyond IEEE
754 safe integer range stay byte-stable across TypeScript, Rust, and Go.

## Coding convention

This SDK follows the
[`samber/cc-skills-golang`](https://www.skills.sh/samber/cc-skills-golang)
collection as the primary Go skill set. Translated to this SDK: small
interfaces, explicit error returns, table-driven tests, deterministic
wire serialization, defensive payment verification, and branch-aware
tests on security-sensitive paths.

The repo-level `pay-sdk-implementation` skill remains the protocol source
of truth: Rust / spec wire format first, Go idioms second.

## Test

```bash
cd go
go test ./...
```

The CI Go job runs the SDK packages with `-coverprofile` and enforces a
90 percent line coverage gate via `scripts/check_coverage.sh`.

## Interop

The Go SDK ships both a client (`harness/go-client`) and a server
(`harness/go-server`) adapter. Focused harness commands:

```bash
cd harness
MPP_INTEROP_CLIENTS=go         MPP_INTEROP_SERVERS=rust pnpm test
MPP_INTEROP_CLIENTS=typescript MPP_INTEROP_SERVERS=go   pnpm test
MPP_INTEROP_CLIENTS=rust       MPP_INTEROP_SERVERS=go   pnpm test
```

## Spec

This SDK implements the [Solana Charge Intent](https://github.com/tempoxyz/mpp-specs/pull/188)
for the [HTTP Payment Authentication Scheme](https://paymentauth.org).

## Repo layout

```text
go/
├── client/                       HTTP client transport and credential builder
├── server/                       PaymentMiddleware, Mpp handler, challenge issuer, verifier
├── protocol/                     Solana wire format (challenge, intents, charge request)
├── protocol/core/                Headers, credentials, receipts, base64url JSON
├── internal/utils/               RPC client, transaction builders, ATA helpers
├── internal/testutil/            Fake RPC and signer helpers for tests
└── go.mod
```

## License

MIT
