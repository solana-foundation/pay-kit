<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://github.com/solana-foundation/pay-kit/raw/main/docs/assets/banner-go-dark.png">
    <source media="(prefers-color-scheme: light)" srcset="https://github.com/solana-foundation/pay-kit/raw/main/docs/assets/banner-go-light.png">
    <img alt="Solana pay-kit — Go" width="100%" style="border-top-left-radius: 8px; border-top-right-radius: 8px; margin-bottom: 16px;" src="https://github.com/solana-foundation/pay-kit/raw/main/docs/assets/banner-go-light.png">
  </picture>
</div>

# github.com/solana-foundation/pay-kit/go

Charge stablecoins (USDC, USDT, PYUSD, ...) for any HTTP endpoint, in Go.
One `paykit` umbrella, one surface, two protocols underneath:
[x402](https://x402.org) and the
[Machine Payments Protocol](https://paymentauth.org). The kit ships a
`net/http` middleware for `402 Payment Required` flows.

You do not need to know anything about Solana to use this library: pick a
currency, give it your wallet address, and gate a route in two lines.

[![Go](https://img.shields.io/badge/go-1.26%2B-blue)]()
[![Coverage](https://img.shields.io/badge/coverage-91%25-brightgreen)]()

## Quick start

Gate a `net/http` route with the `paykit` umbrella. Importing the two
protocol adapters registers them, so the `402` challenge advertises
**x402** and **MPP** at once and a client may settle with either.

```go
package main

import (
    "fmt"
    "net/http"

    "github.com/solana-foundation/pay-kit/go/paykit"
    _ "github.com/solana-foundation/pay-kit/go/protocols/mpp"
    _ "github.com/solana-foundation/pay-kit/go/protocols/x402"
    _ "github.com/solana-foundation/pay-kit/go/paycore/signer"
)

func main() {
    client, err := paykit.New(paykit.Config{
        Network: paykit.SolanaLocalnet,
        Accept:  []paykit.Protocol{paykit.X402, paykit.MPP},
        MPP: paykit.MPPConfig{
            Realm:                  "MyApp",
            ChallengeBindingSecret: []byte("local-dev-secret"),
        },
    })
    if err != nil {
        panic(err)
    }

    report := paykit.Gate{Amount: paykit.MustParseUSD("0.10"), Desc: "Premium report"}

    mux := http.NewServeMux()
    mux.Handle("/report", client.Require(report)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        pmt, _ := paykit.PaymentFrom(r.Context())
        fmt.Fprintf(w, `{"ok":true,"paid_via":%q}`, pmt.Protocol)
    })))
    http.ListenAndServe(":4567", mux)
}
```

`client.Require(gate)` is plain `func(http.Handler) http.Handler`
middleware, so it composes with chi, gorilla, or the stdlib mux. Inside
the handler, `paykit.PaymentFrom(ctx)` returns the verified payment.

Zero-config boots on the in-memory demo signer (it logs a warning and
defaults to the Surfpool sandbox). For production set
`Operator.Signer` and `RPCURL`; mainnet with the demo signer returns
`ErrDemoSignerOnMainnet`.

Amounts go through `paykit.MustParseUSD("0.10")` (or the error-returning
`ParseUSD`); narrow the settlement asset with
`MustParseUSD("0.10", paykit.USDC, paykit.USDT)`.

### Client

The umbrella is server-side. To *pay* a gated endpoint, the protocol
client transports settle a `402` in one retry:

```go
import x402client "github.com/solana-foundation/pay-kit/go/protocols/x402/client"

httpClient := x402client.NewClient(signer, rpcClient) // x402
resp, err := httpClient.Get("https://api.example/report")
```

The sibling `protocols/mpp/client` does the same for MPP
(`Authorization: Payment`). Both wrap an `http.RoundTripper`, so any
`*http.Client` call settles transparently.

## x402

The exact-amount scheme, settled locally against the operator signer or
delegated to a facilitator. Both client and server ship.

| Intent | Client | Server |
|---|:---:|:---:|
| `x402/exact` | ✅ | ✅ |
| `x402/upto` | — | — |
| `x402/batch-settlement` | — | — |

## MPP

The Solana charge intent, in both pull (client-signed) and push
(client-broadcast) modes. Both client and server ship.

| Intent | Client | Server |
|---|:---:|:---:|
| `mpp/charge/pull` | ✅ | ✅ |
| `mpp/charge/push` | ✅ | ✅ |
| `mpp/session` | — | — |
| `mpp/subscription` | — | — |

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

- [`examples/simple-server/`](examples/simple-server) - umbrella
  `net/http` server: a single `client.Require` gate that advertises
  both x402 and MPP, exposing `/health` (free) and `/paid` (gated).

### Run the example

```bash
cd go/examples/simple-server
go run .                                  # listens on 127.0.0.1:4567
```

### Drive it from a client

```bash
brew install pay
curl http://127.0.0.1:4567/paid                      # 402 with x402 + mpp accepts
pay --sandbox --x402 curl http://127.0.0.1:4567/paid # pays via x402
pay --sandbox --mpp  curl http://127.0.0.1:4567/paid # pays via MPP
```

The example boots on the in-memory demo signer and the Surfpool
sandbox; see
[`examples/simple-server/README.md`](examples/simple-server/README.md)
for the full walkthrough.

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
91 percent line coverage gate via `scripts/check_coverage.sh`.

## Harness

The Go SDK plugs into the cross-SDK harness as a server
(`harness/go-server`, both protocols) and as clients
(`harness/go-client` drives MPP charge, and its x402 mode — registered
as `go-x402` — drives the x402-exact client). Focused harness commands:

```bash
cd harness
# MPP charge
MPP_HARNESS_CLIENTS=typescript MPP_HARNESS_SERVERS=go   pnpm test
MPP_HARNESS_CLIENTS=go         MPP_HARNESS_SERVERS=rust pnpm test
# x402 exact: go client -> go server
MPP_HARNESS_SERVERS=go MPP_HARNESS_INTENTS=x402-exact \
  MPP_HARNESS_SCENARIOS=x402-exact-basic \
  X402_HARNESS_CLIENTS=go-x402 X402_HARNESS_SERVERS=go pnpm test
```

## Spec

This SDK implements the
[Solana Charge Intent](https://paymentauth.org/draft-solana-charge-00.html)
for the [HTTP Payment Authentication Scheme](https://paymentauth.org).

## Vocabulary

| Term | Meaning |
|---|---|
| gate | a guarded route; `client.Require(gate)` wraps the handler |
| amount | the face price a gate charges, e.g. `MustParseUSD("0.10")` |
| total | amount plus any `fee_on_top`; what the payer actually settles |
| price | the typed amount value (`paykit.Price`) carried by a gate |
| fee_within | a split taken out of the amount, paid to a fee recipient |
| fee_on_top | a surcharge added on top of the amount, paid by the payer |
| payment | the verified `paykit.Payment` attached to the request context |
| protocol | the wire protocol that settled: `x402` or `mpp` |
| scheme | a protocol sub-form: x402 `exact`, mpp `charge` |
| currency | the fiat unit a price is quoted in: `USD`, `EUR`, `GBP` |
| settlement | the on-chain stablecoin the payer pays in (`USDC`, `USDT`, ...) |

## Repo layout

```text
go/
├── paykit/                       umbrella API: x402 + MPP behind one Config and middleware
├── paycore/                      PayCore: protocol-agnostic primitives
│   ├── solanatx/                 shared tx builders, ATA derivation, RPC helpers (used by mpp + x402)
│   └── signer/                   Ed25519 signer factories behind a KMS-ready interface
├── protocols/
│   ├── mpp/                      MPP adapter that registers the Solana charge method
│   │   ├── core/                 MPP type facade, replay store, expiry helpers, errors
│   │   ├── wire/                 challenge, credential, receipt, base64url JSON
│   │   ├── intents/              charge request intent
│   │   ├── server/               PaymentMiddleware, Mpp handler, challenge issuer, verifier
│   │   ├── client/               HTTP client transport and credential builder
│   │   └── errorcodes/           canonical L6 fault codes
│   └── x402/                     x402 "exact" adapter and structural transaction verifier
├── internal/testutil/            Fake RPC and signer helpers for tests
└── go.mod
```

## License

MIT
