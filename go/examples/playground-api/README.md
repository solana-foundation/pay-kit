# playground-api (Go)

The Go port of [`typescript/examples/playground-api`](../../../typescript/examples/playground-api/),
the HTTP API behind the [pay-kit playground](../../../playground/). It serves
the same endpoints with the same payment gating semantics against the Solana
Payment Sandbox (a hosted test validator, no real funds):

- **Charges**: `solana.charge` endpoints (stock quote, marketplace purchase
  with multi-recipient splits, fortune payment link) gated through the Go
  `paykit` umbrella client, plus a faucet that funds wallets through surfpool
  cheatcodes.
- **Sessions**: the in-process Go session method gating `/sessions/stream`
  (pay-per-chunk SSE) and `/sessions/compute` (pay-per-call), with real
  payment-channel opens (server-completed fee-payer signature), voucher
  metering through the `/__402/session/*` side channel, and on-chain
  settlement via the idle-close watchdog.
- **x402**: two `exact`-scheme demo routes plus the embedded facilitator
  endpoints.
- `/api/v1/config`: the endpoint catalog and wallet/network metadata the web
  app renders.

## Running

```bash
cd go
go run ./examples/playground-api    # listens on :3000
```

or through the justfile:

```bash
just -f go/Justfile serve-playground          # :3000
just -f go/Justfile serve-playground 3210     # custom port
```

## Pointing the playground at this server

Set `PAYKIT_PLAYGROUND_API_URL` and the playground's `pnpm dev` skips
launching the TypeScript server; the web app's dev proxy targets this one
instead:

```bash
# terminal 1: the Go API
cd go && PORT=3210 go run ./examples/playground-api

# terminal 2: UI only, proxied to the running API
cd playground
PAYKIT_PLAYGROUND_API_URL=http://localhost:3210 pnpm dev
```

## Environment variables

Same table as the TypeScript example:

| Variable | Default | Purpose |
|----------|---------|---------|
| `PORT` | `3000` | Listen port |
| `NETWORK` | `localnet` | Solana network tag for MPP / x402 challenges |
| `RPC_URL` | `https://402.surfnet.dev:8899` | Surfpool RPC endpoint (hosted sandbox by default) |
| `RECIPIENT` | (auto-generated) | Solana address that receives payments |
| `FEE_PAYER_KEY` | (auto-generated) | Base58 fee-payer keypair (server signs as fee payer) |
| `MPP_SECRET_KEY` | (random per-boot) | MPP secret key for challenge HMAC |

Additional Go-only knobs: `DOCS_ROOT` overrides the generated-docs directory
when the binary runs outside the repository checkout, and the standard
`PAY_KIT_DISABLE_PREFLIGHT=1` skips the paykit boot preflight.

## Endpoints

| Method | Path | Gate |
|--------|------|------|
| GET | `/api/v1/health` | free |
| GET | `/api/v1/config` | free |
| GET | `/api/v1/docs`, `/api/v1/docs/:lang/tree`, `/api/v1/docs/:lang/file` | free |
| GET | `/api/v1/faucet/status` | free |
| POST | `/api/v1/faucet/airdrop` | free |
| GET | `/api/v1/stocks/quote/:symbol` | charge 0.01 USDC |
| GET | `/api/v1/stocks/search?q=` | charge 0.01 USDC |
| GET | `/api/v1/stocks/history/:symbol` | charge 0.05 USDC |
| GET | `/api/v1/weather/:city` | charge 0.01 USDC |
| GET | `/api/v1/marketplace/products` | free |
| GET | `/api/v1/marketplace/buy/:productId?referrer=` | charge with splits |
| GET | `/api/v1/fortune` | charge 0.01 USDC, HTML payment link |
| GET | `/api/v1/premium/feed` | 501 stub (see below) |
| GET | `/sessions/stream` | session, cap 1.00 USDC, 0.0001 USDC/chunk |
| POST | `/sessions/stream` | session voucher commits |
| POST | `/sessions/compute` | session, cap 0.50 USDC, 0.005 USDC/call |
| POST | `/__402/session/deliveries` | session side channel |
| POST | `/__402/session/commit` | session side channel |
| GET | `/sessions/receipt/:channelId` | free settle-status poll |
| GET | `/facilitator/supported` | free |
| POST | `/facilitator/verify`, `/facilitator/settle` | free |
| GET | `/x402/joke`, `/x402/fact` | x402 exact, $0.001 |

As in the TypeScript example, the stocks-search / stocks-history / weather /
fortune and `/x402/*` routes stay live server-side but are not advertised in
the `/api/v1/config` nav catalog.

## Differences from the TypeScript example

Nothing is silently dropped; where the Go SDK lacks a capability the closest
faithful behavior is served and listed here:

1. **Subscriptions**: the Go SDK does not implement the
   `solana.subscription` server method yet, so there is no plan bootstrap
   and `GET /api/v1/premium/feed` answers `501 {"error":"not_implemented"}`.
   The endpoint catalog omits the subscription entry, which is exactly how
   the TypeScript server behaves when its plan bootstrap fails, so the
   playground UI renders its graceful empty state.
2. **x402 gating is self-hosted**: the TypeScript routes are gated by
   `x402-express` POSTing to the embedded facilitator; the Go x402 adapter
   only implements self-hosted mode, so `/x402/joke` and `/x402/fact` verify
   and settle in-process with the operator signer. The
   `/facilitator/supported|verify|settle` endpoints are still served with
   the same response shapes for external x402 clients. The challenge
   advertises the configured `NETWORK` instead of the TypeScript example's
   hardcoded `solana-devnet` (localnet shares the devnet genesis hash).

The stocks endpoints call the same Yahoo Finance endpoints as the
`yahoo-finance2` package the TypeScript server uses (v7 quote with crumb
auth, v1 search, v8 chart) and apply the same field coercions, so the
response bodies match the TypeScript server's field for field.

## Layout

Mirrors the TypeScript module structure as files of one `main` package:

```
main.go            # bootstrap, fee payer, surfpool funding, /api/v1/{health,config}, CORS, SPA
charges.go         # stocks/weather/marketplace + fortune payment link
yahoo.go           # Yahoo Finance client matching yahoo-finance2's response shapes
sessions.go        # in-process session methods + side-channel routes + receipt
subscriptions.go   # documented 501 stub (no Go subscription method yet)
x402.go            # embedded facilitator + x402-gated routes
faucet.go          # SOL + USDC airdrop via surfpool cheatcodes
docs.go            # generated-docs browser with path-escape guard
constants.go       # example-specific constants (faucet amounts, USDC decimals)
utils.go           # rpcCall, ANSI helpers, receipt logging
```

## Tests

```bash
cd go
go test ./examples/playground-api/                          # offline smoke test (stub RPC)
go test ./examples/playground-api/ -run SessionE2ESurfpool  # sandbox-gated session lifecycle
```

The smoke test boots the full route table against a stub JSON-RPC server and
checks every endpoint's unauthenticated behavior. The e2e mirrors
`playground-session-e2e.test.ts` (real channel open, metered SSE, side-channel
commit, on-chain settle) and skips explicitly when the sandbox is unreachable
or under `-short`. CI also boots this server against a local surfnet and runs
the payment-link Playwright suite from `html/` against `/api/v1/fortune`, the
same coverage the TypeScript playground API gets.
