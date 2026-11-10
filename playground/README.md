<div align="center">
  <h1>PayKit Playground</h1>
  <p>An interactive workbench for every pay-kit primitive.</p>
</div>

A single-page React + Express playground that lets you poke every payment surface the kit ships:

- **Charges** — stocks, weather, marketplace splits, a browser-friendly payment link
- **x402** — embedded facilitator + the canonical `/x402/joke` and `/x402/fact` routes
- **Subscriptions** — server-side `solana.subscription` gating a `/api/v1/premium/feed`
- **Sessions** — payment-channel sessions served in-process by `@solana/mpp`
- **Credit-funded session** — a credit provider funds an MPP session through the V2 channel's lifecycle hooks
  (local sandbox only, see below)
- **Docs** — language quickstarts for TypeScript, Rust, Go, Python, Ruby, PHP, Lua, Kotlin, Swift.
  TypeScript's card is generated from `typescript/docs/snippets/` (see `docs/snippets-convention.md`);
  the other languages use curated entries until their snippet directories are populated

It runs against the local Solana Payment Sandbox (Surfpool on `:8899`) so nothing on it costs real money.

## Quick start

```bash
# 1. Run the sandbox (in another terminal)
surfpool start

# 2. From the repo root
cd playground
pnpm install
pnpm dev               # Vite on :5173, Express on :3000
```

Open <http://localhost:5173>. The first visit generates an in-browser keypair and lets you airdrop 100 SOL +
100 USDC via Surfpool cheatcodes. Then pick any endpoint from the sidebar and hit **Send**.

### Sessions

The Sessions tab is served in-process by `@solana/mpp`'s `session()` method — no extra CLI or sidecar
required. The playground server gates `/sessions/stream` and `/sessions/compute` with the session method;
each endpoint accepts the standard MPP open / voucher / topUp / close action set over the 402 challenge
surface.

### Credit-funded session

The **Credit-funded session** card runs the flow of payment-channels#102 and its reference credit provider
(`examples/credit-provider`) end to end from the browser wallet:

1. the customer holds 2 USDC of credits with a provider program (ledger and vault planted with cheatcodes);
2. the merchant's 402 advertises `channelVersion: 2` and the provider's `preFund` / `postDistribute` hooks;
3. the provider's issuer signs an approval for that exact channel (an exact-cap refund approval plus
   `authorize`), which the customer co-signs;
4. `openWithHooks`: `preFund` debits 1 USDC of credits and supplies the backing the channel escrows;
5. three requests paid with vouchers (0.01 USDC each);
6. close: settle, then `distributeWithHooks`; the merchant gets 0.03 and `postDistribute` returns the
   unspent 0.97 to custody and restores those credits.

The wallet's own USDC is never spent. The card needs the local sandbox (`surfpool start`, `RPC_URL` and
`VITE_RPC_URL` at `http://127.0.0.1:8899`) and the two payment-channels artifacts:

```bash
PC=~/path/to/payment-channels   # stack/nightly-7-canary-devnet (payment-channels#112)
(cd $PC && just test-credit-provider-surfpool)   # builds both artifacts, then runs the provider's own e2e
export PAYMENT_CHANNELS_V2_SO=$PC/target/deploy-v2/payment_channels.so
export CREDIT_PROVIDER_SO=$PC/target/deploy/credit_provider.so
RPC_URL=http://127.0.0.1:8899 VITE_RPC_URL=http://127.0.0.1:8899 pnpm dev
```

At startup the API writes the hook-enabled channel program over the canonical address (the same build
serves V1 channels, so the other cards keep working) and the provider at a fresh address. Without the
artifacts, or off the local sandbox, the card shows why it is disabled and `tests/credits.spec.ts` skips.

## Keyboard shortcuts

| Shortcut | Action |
|----------|--------|
| `⌘K` | Open the endpoint command palette |
| `⌘\` | Toggle the sidebar |
| `⌘.` | Toggle dark / light theme |

## Architecture

```
playground/
├── app/                          # React SPA (Vite)
│   ├── index.html                # title: "PayKit Playground"
│   └── src/
│       ├── App.tsx               # shell, routing, wallet lifecycle, ⌘K, theme
│       ├── App.css               # ported from ~/Coding/pay/pdb's design system
│       ├── components/           # Header, Sidebar, RequestBuilder, FlowTimeline,
│       │                         # EventLog, ResponsePane, CodeTabs, WalletPill/Modal/Setup,
│       │                         # EndpointPicker
│       ├── pages/                # Charges, Subscriptions, Sessions, X402, Docs
│       ├── lib/                  # wallet (in-browser keypair),
│       │                         # flow (payAndFetch generator over @solana/mpp),
│       │                         # snippets (renders snippets.gen.json + inline fallbacks),
│       │                         # format, docs.gen
│       └── hooks/                # useTheme, useConfig, useKeyboard
```

The API the playground talks to lives in the TypeScript workspace at
[`typescript/examples/playground-api/`](../typescript/examples/playground-api)
(Express + tsx):

```
typescript/examples/playground-api/
├── index.ts                  # bootstrap, fee payer, surfpool funding,
│                             # /api/v1/config endpoint
├── modules/
│   ├── charges.ts            # stocks/weather/marketplace/fortune + faucet
│   ├── subscriptions.ts      # solana.subscription gating /api/v1/premium/feed
│   ├── sessions.ts           # in-process session() method + side-channel routes
│   ├── x402.ts               # x402-express + embedded facilitator
│   └── faucet.ts             # SOL + USDC airdrop via surfpool cheatcodes
└── shared/
    ├── constants.ts          # USDC mint, programs
    ├── utils.ts              # toWebRequest, rpcCall, ANSI helpers
    └── plan-bootstrap.ts     # initialize_plan OR surfnet_setAccount fallback
```

The visual system is a port of the [payment debugger (pdb)](https://github.com/solana-foundation/pay/tree/main/pdb)
— the same CSS variables, badge palette, header chevron, and sequence-diagram pattern, restyled into a
request-builder layout.

## Environment variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `PAYKIT_PLAYGROUND_API_URL` | (unset) | Use an already-running playground API at this URL; `pnpm dev` then launches only the web app and proxies to it |
| `PORT` | `3000` | Express listen port |
| `NETWORK` | `localnet` | Solana network tag for MPP / x402 challenges |
| `RPC_URL` | `https://402.surfnet.dev:8899` | Surfpool RPC endpoint (hosted sandbox by default) |
| `RECIPIENT` | (auto-generated) | Solana address that receives payments |
| `FEE_PAYER_KEY` | (auto-generated) | Base58 fee-payer keypair (server signs as fee payer) |
| `MPP_SECRET_KEY` | (random per-boot) | MPP secret key for challenge HMAC |
| `PAYMENT_CHANNELS_V2_SO` | (unset) | Hook-enabled payment-channels program; enables the credit-funded session card (local sandbox only) |
| `CREDIT_PROVIDER_SO` | (unset) | payment-channels `examples/credit-provider` program; required with `PAYMENT_CHANNELS_V2_SO` |

## Production

```bash
pnpm build      # builds the SPA into app/dist
pnpm start      # runs Express; serves the SPA from app/dist on :3000
```

A single process serves the static SPA + the API behind the same origin — point a tunnel at `:3000` and ship.

## Why pdb's style?

PDB ([payment debugger](https://github.com/solana-foundation/pay/tree/main/pdb)) is the right reference for
this kind of dev tool: dark + light, GitHub-flavored tokens, monospace headers, a left-rail sidebar of
endpoints, and a sequence-diagram view of the 402 handshake. The playground reuses the design system
verbatim, but replaces pdb's SSE-correlated multi-flow view with a single-request workbench that fits the
"try it" use case.
