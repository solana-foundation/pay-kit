# playground-api

The HTTP API behind the [pay-kit playground](../../../playground/). An
Express server that exercises `@solana/mpp` and `@solana/pay-kit`
server-side against the Solana Payment Sandbox (a hosted test
validator — no real funds):

- **Charges** — `solana.charge` endpoints (stock quote, marketplace
  purchase with multi-recipient splits, fortune payment link) plus a
  faucet that funds wallets through surfpool cheatcodes.
- **Sessions** — an in-process `session()` method gating
  `/sessions/stream` (pay-per-chunk SSE) and `/sessions/compute`
  (pay-per-call), with real payment-channel opens, voucher metering,
  and on-chain settlement.
- **Subscriptions** — `solana.subscription` gating `/api/v1/premium/feed`.
- **x402** — `x402-express` routes with an embedded facilitator.
- `/api/v1/config` — the endpoint list and wallet/network metadata the
  web app renders.

## Running

```bash
pnpm install
pnpm dev     # tsx watch, listens on :3000
pnpm start   # one-shot, no watch
```

The usual way to run it is through the playground, which launches the
API and the web app together:

```bash
cd ../../../playground
pnpm dev     # API on :3000, web app on :5173
```

## Pointing the playground at an external API

Set `PAYKIT_PLAYGROUND_API_URL` and the playground's `pnpm dev` skips
launching this server; the web app's dev proxy targets your URL
instead:

```bash
# terminal 1 — run the API wherever and however you like
PORT=3210 pnpm start

# terminal 2 — UI only, proxied to the running API
cd ../../../playground
PAYKIT_PLAYGROUND_API_URL=http://localhost:3210 pnpm dev
```

This works with any host serving the same routes, so you can point the
UI at a deployed instance or at a server written in another pay-kit
language.

## Environment variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `PORT` | `3000` | Express listen port |
| `NETWORK` | `localnet` | Solana network tag for MPP / x402 challenges |
| `RPC_URL` | `https://402.surfnet.dev:8899` | Surfpool RPC endpoint (hosted sandbox by default) |
| `RECIPIENT` | (auto-generated) | Solana address that receives payments |
| `FEE_PAYER_KEY` | (auto-generated) | Base58 fee-payer keypair (server signs as fee payer) |
| `MPP_SECRET_KEY` | (random per-boot) | MPP secret key for challenge HMAC |

## Layout

```
index.ts                  # bootstrap, fee payer, surfpool funding, /api/v1/config
modules/
├── charges.ts            # stocks/weather/marketplace/fortune + faucet
├── subscriptions.ts      # solana.subscription gating /api/v1/premium/feed
├── sessions.ts           # in-process session() method + side-channel routes
├── x402.ts               # x402-express + embedded facilitator
└── faucet.ts             # SOL + USDC airdrop via surfpool cheatcodes
shared/
├── constants.ts          # USDC mint, programs
├── utils.ts              # toWebRequest, rpcCall, ANSI helpers
└── plan-bootstrap.ts     # initialize_plan OR surfnet_setAccount fallback
```

This package is intentionally **not** part of the `typescript/`
pnpm workspace: it depends on `@solana/mpp` and `@solana/pay-kit`
through `file:` links and keeps its own lockfile, so its demo
dependencies (Express, x402, yahoo-finance2) stay out of the SDK
workspace's dependency tree and `pnpm audit` surface.

`tsconfig.snippets.json` typechecks the canonical documentation
snippets in [`typescript/docs/snippets/`](../../docs/snippets/) against
this package's installed dependencies; the playground's `pnpm build`
runs it via `pnpm check-snippets`.
