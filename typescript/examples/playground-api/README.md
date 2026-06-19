# playground-api

A minimal Express server showing how to gate routes with
[`@solana/pay-kit`](../../packages/pay-kit). One `createPayKit({ ... pricing })`
call configures the server and declares the priced routes; each route is gated
with `pay.express(name)`. Read [`index.ts`](./index.ts) top-to-bottom — it's the
whole thing.

## Routes

Paths are generic (`/api/v1/<name>`); the protocol + scheme each route demonstrates
lives in the OpenAPI summary, not the URL.

| Method | Path | Gate | Scheme | What it shows |
|--------|------|------|--------|---------------|
| `GET` | `/api/v1/quote/:symbol` | `quote` (`usd('0.01')`) | mpp/charge · x402/exact | A fixed charge the client settles over **MPP or x402** (its choice). |
| `GET` | `/api/v1/joke` | `joke` (`{ amount: usd('0.001'), accept: ['x402'] }`) | x402/exact | A fixed price, **x402 `exact`** only. |
| `POST` | `/api/v1/summarize` | `summarize` (`usage(usd('0.10'))`) | x402/upto | Authorize a ceiling, then bill metered usage via `pay.charge(req)`, refunding the rest. |
| `GET` | `/api/v1/feed` | `feed` (`subscription(usd('0.10'), …)`) | mpp/subscription | The first call activates a recurring on-chain plan; mounted only when a plan is bootstrapped. |
| `GET` | `/api/v1/stream` | `stream` (`session(usd('1.00'), …)`) | mpp/session | Open a payment channel, stream metered deliveries (SSE), settle out-of-band on idle-close. |

The handler reads the verified receipt with `pay.payment(req)` and (for usage
gates) the meter with `pay.charge(req)`. That's the entire app surface.

The session gate also needs its side-channel + receipt routes mounted — pay-kit
hands them over explicitly (it doesn't auto-mount, matching mppx):

```ts
const s = pay.sessionRoutes('stream')
app.post('/__402/session/deliveries', s.deliveries)
app.post('/__402/session/commit', s.commit)
app.get('/sessions/receipt/:channelId', s.receipt)
```

The SDK reference docs are served unpaid at `/api/v1/docs`, `/api/v1/docs/:lang/tree`,
and `/api/v1/docs/:lang/file` by [`docs.ts`](./docs.ts).

## Discovery

`GET /openapi.json` is an OpenAPI 3.1 document built by `pay.openapiFromExpress(app)`:
it introspects the mounted routes and, for each, emits an `x-payment-info`
extension whose `offers[]` carry the price, accepted protocols, network, and
recipient — derived from `pricing`, so there's nothing to maintain by hand. The
shape follows the [payment-discovery draft](https://paymentauth.org/draft-payment-discovery-00.html)
(`intent` / `method` / `amount` per offer). The server's RPC URL is intentionally
not advertised. The runtime 402 challenge remains authoritative.

## Running

```bash
pnpm install
pnpm dev     # tsx watch, listens on :3000 (zero-config against the hosted sandbox)
pnpm start   # one-shot, no watch
```

On `localnet` (the default) the server funds its operator + recipient and mounts
a faucet (`/api/v1/faucet/airdrop`) using sandbox cheatcodes — see
[`sandbox.ts`](./sandbox.ts). None of that runs on devnet/mainnet.

## Environment variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `PORT` | `3000` | Express listen port |
| `NETWORK` | `localnet` | Solana network for the payment challenges |
| `RPC_URL` | `https://402.surfnet.dev:8899` | RPC endpoint (hosted sandbox by default) |
| `RECIPIENT` | (operator address) | Address that receives payments |
| `FEE_PAYER_KEY` | (auto-generated) | Base58 operator keypair — fee-pays + signs settlement |
| `MPP_SECRET_KEY` | (random per-boot) | HMAC secret binding MPP challenges |

## Layout

```
index.ts          # the whole server: createPayKit + gated routes + meta endpoints
docs.ts           # unpaid SDK-reference markdown server (Docs / ApiReference)
sandbox.ts        # LOCAL SANDBOX ONLY — surfnet funding + faucet + plan bootstrap
```

This package is intentionally **not** part of the `typescript/` pnpm workspace:
it links `@solana/pay-kit` (and its `@solana/mpp` peer) through `file:` and keeps
its own lockfile, so demo dependencies stay out of the SDK workspace.
