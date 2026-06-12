<div align="center">
  <h1>PayKit Playground</h1>
  <p>An interactive workbench for every pay-kit primitive.</p>
</div>

A single-page React + Express playground that lets you poke every payment surface the kit ships:

- **Charges** — stocks, weather, marketplace splits, a browser-friendly payment link
- **x402** — embedded facilitator + the canonical `/x402/joke` and `/x402/fact` routes
- **Subscriptions** — server-side `solana.subscription` gating a `/api/v1/premium/feed`
- **Sessions** — payment-channel sessions served in-process by `@solana/mpp`
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
