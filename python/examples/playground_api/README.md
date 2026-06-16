# playground-api (Python)

The Python port of [`go/examples/playground-api`](../../../go/examples/playground-api/),
the HTTP API behind the [pay-kit playground](../../../playground/). It serves
the same endpoints with the same payment gating semantics against the Solana
Payment Sandbox (a hosted test validator, no real funds):

- **Charges**: `solana.charge` endpoints (a single-recipient stock quote and a
  marketplace purchase with multi-recipient splits) gated through the `pay_kit`
  umbrella surface, plus a faucet that funds wallets through surfpool cheatcodes.
- **Sessions**: the in-process MPP session method gating `/sessions/stream`
  (pay-per-chunk SSE) and `/sessions/compute` (pay-per-call), with voucher
  metering through the `/__402/session/*` side channel and on-chain settlement
  via the idle-close watchdog.
- `/api/v1/config`: the endpoint catalog and wallet/network metadata the web
  app renders.

This is the application skeleton: the boot wiring, shared config/state, the
free endpoints (health, config, faucet, docs, SPA), and the `register_*` seam
the charge / session feature endpoints plug into. The feature endpoints are
implemented separately. Every route the server exposes is advertised in the
`/api/v1/config` catalog the web app renders.

## Running

```sh
pip install -e ".[playground]"
python -m examples.playground_api.main         # listens on :3000
```

or directly through uvicorn (no surfnet funding):

```sh
uvicorn examples.playground_api.app:app --port 3000
```

## Pointing the playground at this server

Set `PAYKIT_PLAYGROUND_API_URL` and the playground's `pnpm dev` skips launching
its own server; the web app's dev proxy targets this one instead:

```sh
# terminal 1: the Python API
cd python && PORT=3210 python -m examples.playground_api.main

# terminal 2: UI only, proxied to the running API
cd playground
PAYKIT_PLAYGROUND_API_URL=http://localhost:3210 pnpm dev
```

## Environment variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `PORT` | `3000` | Listen port |
| `NETWORK` | `localnet` | Solana network tag for MPP challenges |
| `RPC_URL` | `https://402.surfnet.dev:8899` | Surfpool RPC endpoint (hosted sandbox by default) |
| `RECIPIENT` | (auto-generated) | Solana address that receives payments |
| `FEE_PAYER_KEY` | (auto-generated) | Base58 fee-payer keypair (server signs as fee payer) |
| `MPP_SECRET_KEY` | (random per-boot) | MPP secret key for challenge HMAC |
| `DOCS_ROOT` | (repo `docs/api`) | Overrides the generated-docs directory outside a checkout |

## Endpoints

| Method | Path | Gate |
|--------|------|------|
| GET | `/api/v1/health` | free |
| GET | `/api/v1/config` | free |
| GET | `/api/v1/docs`, `/api/v1/docs/:lang/tree`, `/api/v1/docs/:lang/file` | free |
| GET | `/api/v1/faucet/status` | free |
| POST | `/api/v1/faucet/airdrop` | free |
| GET | `/api/v1/stocks/quote/:symbol` | charge 0.01 USDC |
| GET | `/api/v1/marketplace/products` | free |
| GET | `/api/v1/marketplace/buy/:productId?referrer=` | charge with splits |
| GET | `/sessions/stream` | session, cap 1.00 USDC, 0.0001 USDC/chunk |
| POST | `/sessions/stream` | session voucher commits |
| POST | `/sessions/compute` | session, cap 0.50 USDC, 0.005 USDC/call |
| POST | `/__402/session/deliveries` | session side channel |
| POST | `/__402/session/commit` | session side channel |
| GET | `/sessions/receipt/:channelId` | free settle-status poll |

## Differences from the other playground APIs

The Python SDK does not implement the `solana.subscription` server method yet,
so the playground exposes no subscription route (the other examples gate one).
The endpoint catalog omits the subscription entry and the playground UI renders
its graceful empty state.

## Layout

Mirrors the Go module structure as files of one Python package:

```
app.py          # boot wiring (AppState, create_app), the register_* seam,
                # /api/v1/{health,config}, SPA serving (CORS/handlers via
                # pay_kit.fastapi.install)
main.py         # entrypoint: surfnet funding + uvicorn
docs.py         # generated-docs browser with path-escape guard
constants.py    # example-specific constants (faucet amounts, USDC decimals/mint)
utils.py        # rpcCall, env helpers, receipt logging, JSON error body
```
