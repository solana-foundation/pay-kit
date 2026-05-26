<p align="center">
  <img src="https://github.com/solana-foundation/pay-kit/raw/main/assets/banner.png" alt="MPP" width="100%" />
</p>

# mpp-sdk-go

Charge stablecoins (USDC, USDT, PYUSD, …) for any HTTP endpoint, in Go.
Implements the Solana payment method for the
[Machine Payments Protocol](https://mpp.dev).

**MPP** is [an open protocol proposal](https://paymentauth.org) that lets
any HTTP API accept payments using the `402 Payment Required` flow. You
do not need to know anything about Solana to use this library: pick a
currency, give it your wallet address, and gate a route in two lines.

[![Go](https://img.shields.io/badge/go-1.26%2B-blue)]()
[![Coverage](https://img.shields.io/badge/coverage-90%25-brightgreen)]()

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

## Quick start, server

```go
import (
    mpp "github.com/solana-foundation/pay-kit/go"
    "github.com/solana-foundation/pay-kit/go/server"
)

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

http.Handle("/paid", server.PaymentMiddleware(handler, func(r *http.Request) (string, server.ChargeOptions, error) {
    return "0.001", server.ChargeOptions{Description: "Paid endpoint"}, nil
})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    w.Write([]byte(`{"ok":true,"paid":true}`))
})))
```

`Currency` accepts a symbol like `"USDC"`, `"USDT"`, `"USDG"`, `"PYUSD"`,
or `"CASH"`. The SDK looks up the mint address, token program, and
decimals from a built-in table. Pass a raw mint pubkey for tokens not in
the table.

The `Mpp` handler owns every static knob (recipient, default currency,
network, RPC, optional fee payer signer). Per-request you pass the
charge amount through the `ChargeFunc`. The blockhash is fetched lazily
through the RPC client so a busy endpoint does not pay an RPC round trip
on every protected request.

### `net/http` integration

`server.PaymentMiddleware` wraps any `http.Handler`. It returns a 402
challenge on the first request, validates the credential on the retry,
and exposes the receipt to the wrapped handler through
`server.ReceiptFromContext`.

### Direct invocation

For frameworks where middleware does not fit, call `handler.Charge`
followed by `handler.VerifyCredential` (or
`handler.VerifyCredentialWithExpected` if the route pins the request
shape).

## Quick start, client

```go
import (
    "github.com/solana-foundation/pay-kit/go/client"
)

httpClient := client.NewClient(signer, rpcClient)
resp, err := httpClient.Get("https://api.example/paid")
```

`client.NewClient` returns an `*http.Client` whose transport replays
401/402 responses with the appropriate `Authorization: Payment`
credential. Use `client.BuildCredentialHeader` directly if you want to
own the retry yourself.

## Running the examples

A single runnable example ships at
[`examples/simple-server/`](examples/simple-server). It mirrors the
Ruby [`examples/simple-server/app.rb`](../ruby/examples/simple-server/app.rb)
shape: read env vars, construct an `mpp/server` handler with the
Solana charge method, expose `/health` (free) and `/paid` (gated), and
render the `Mpp::Challenge` / `Mpp::Settlement` tagged union by hand
with the SDK's lower-level primitives.

```bash
cd go/examples/simple-server
PORT=4572 go run .
```

In another terminal:

```bash
brew install pay
curl -i http://127.0.0.1:4572/paid          # 402 with WWW-Authenticate
pay curl http://127.0.0.1:4572/paid         # 200 with Payment-Receipt
```

The example defaults to Surfpool localnet (`https://402.surfnet.dev:8899`),
`USDC`, and a local example recipient. Override `MPP_RPC_URL`,
`MPP_CURRENCY`, `MPP_NETWORK`, `MPP_PAY_TO`, `MPP_SECRET_KEY`, or
`MPP_FEE_PAYER_SECRET_KEY` (a 64-byte JSON array) for a different
localnet fixture.

## Running the interop adapters

```bash
cd harness/go-server
go run .   # starts a Surfpool-backed protected endpoint on a random port

cd ../go-client
go run .   # exercises the same flow against any registered server
```

In another terminal:

```bash
brew install pay
curl http://localhost:<port>/protected       # 402 payment required
pay curl http://localhost:<port>/protected   # pays and succeeds
```

The interop adapters read `MPP_INTEROP_RPC_URL`, `MPP_INTEROP_MINT`,
`MPP_INTEROP_PAY_TO`, `MPP_INTEROP_FEE_PAYER_SECRET_KEY`, optional
`MPP_INTEROP_NETWORK`, `MPP_INTEROP_PRICE`, `MPP_INTEROP_RESOURCE_PATH`,
`MPP_INTEROP_SETTLEMENT_HEADER`, `MPP_INTEROP_SECRET_KEY`,
`MPP_INTEROP_REPLAY_SOURCE_PATH` + `MPP_INTEROP_REPLAY_SOURCE_PRICE`,
and `MPP_INTEROP_SPLITS` (JSON array).

## Client compatibility matrix

| Intent | Status |
|---|:---:|
| `x402/exact` | — |
| `x402/upto` | — |
| `x402/batch-settlement` | — |
| `mpp/charge/pull` | ✅ |
| `mpp/charge/push` | ✅ |
| `mpp/session` | — |
| `mpp/subscription` | — |

## Server compatibility matrix

Split into two phases because an MPP server first verifies the
credential and then settles or confirms the payment on-chain.

| Intent | Status |
|---|:---:|
| `x402/exact` | — |
| `x402/upto` | — |
| `x402/batch-settlement` | — |
| `mpp/charge/pull` | ✅ |
| `mpp/charge/push` | ✅ |
| `mpp/session` | — |
| `mpp/subscription` | — |

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

The direct Go interop server at
[`harness/go-server/main.go`](../harness/go-server/main.go)
exercises this end-to-end through Surfpool for both TypeScript and Rust
clients.

## Solana dependencies

| Dependency | Why | Version |
|---|---|---|
| `github.com/gagliardetto/solana-go` | transaction message encoding, ATA derivation, base58 keys | `v0.0.0-20260403020633-3cb13b392078` (lgalabru fork) |
| `github.com/gagliardetto/solana-go/programs/token` | SPL Token transfer instruction layout | bundled with `solana-go` |
| `github.com/gagliardetto/solana-go/programs/token-2022` | Token-2022 transfer instruction layout | bundled with `solana-go` |
| `github.com/gagliardetto/solana-go/programs/compute-budget` | compute unit limit / price instructions | bundled with `solana-go` |
| `github.com/gagliardetto/solana-go/programs/system` | native SOL transfer instructions | bundled with `solana-go` |
| internal canonical JSON | base64url-encoded canonical JSON with `json.Number` preservation | in package |

The Go SDK keeps the transitive dependency tree to the `solana-go`
toolkit and the Go standard library. Canonical JSON encoding routes
through a `json.Number`-preserving decoder so large amounts beyond IEEE
754 safe integer range stay byte-stable across TypeScript, Rust, and
Go.

## Coding convention

This SDK follows the
[`samber/cc-skills-golang`](https://www.skills.sh/samber/cc-skills-golang)
collection as the primary Go skill set. The skills most load-bearing
for this SDK:

- `golang-code-style`, `golang-naming`, `golang-project-layout`,
  `golang-lint` for idiomatic structure
- `golang-error-handling`, `golang-safety`, `golang-context` for
  defensive payment verification and cancellation propagation
- `golang-testing`, `golang-stretchr-testify`, `golang-benchmark` for
  table-driven and security-branch-aware coverage
- `golang-concurrency`, `golang-performance` for deterministic wire
  serialization under load
- `golang-security`, `golang-dependency-management`,
  `golang-documentation` for supply chain and godoc parity

Translated to this SDK: small interfaces, explicit error returns,
table-driven tests, deterministic wire serialization, defensive
payment verification, and branch-aware tests on security-sensitive
paths.

The repo-level `pay-sdk-implementation` skill remains the protocol
source of truth: Rust and spec wire format first, Go idioms second.

## Test

```bash
cd go
go test ./...
```

If the local sandbox blocks the default Go cache, use temp caches:

```bash
GOCACHE=/tmp/mpp-go-cache GOMODCACHE=/tmp/mpp-go-mod go test ./...
```

The CI Go job runs the SDK packages with `-coverprofile` and enforces a
90 percent line coverage gate via `scripts/check_coverage.sh`.

## Interop

The cross-language interop harness lives in `../harness`. The Go
SDK ships both a client (`harness/go-client`) and a server
(`harness/go-server`) adapter. Both are opt-in via the
`MPP_INTEROP_CLIENTS` and `MPP_INTEROP_SERVERS` env vars.

Focused harness commands:

```bash
cd harness
MPP_INTEROP_CLIENTS=go         MPP_INTEROP_SERVERS=rust pnpm test
MPP_INTEROP_CLIENTS=typescript MPP_INTEROP_SERVERS=go   pnpm test
MPP_INTEROP_CLIENTS=rust       MPP_INTEROP_SERVERS=go   pnpm test
```

## Spec

This SDK implements the [Solana Charge Intent](https://github.com/tempoxyz/mpp-specs/pull/188)
for the [HTTP Payment Authentication Scheme](https://paymentauth.org).

## License

MIT
