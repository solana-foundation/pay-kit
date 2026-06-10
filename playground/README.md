<div align="center">
  <h1>PayKit Playground</h1>
  <p>An interactive workbench for every pay-kit primitive.</p>
</div>

A single-page React + Express playground that lets you poke every payment surface the kit ships:

- **Charges** — stocks, weather, marketplace splits, a browser-friendly payment link
- **x402** — embedded facilitator + the canonical `/x402/joke` and `/x402/fact` routes
- **Subscriptions** — server-side `solana.subscription` gating a `/api/v1/premium/feed`
- **Sessions** — payment-channel sessions hosted by the `pay` CLI sidecar
- **Docs** — language quickstarts for TypeScript, Rust, Go, Python, Ruby, PHP, Lua, Kotlin, Swift

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

The Sessions tab proxies `/sessions/*` to the `pay` CLI sidecar. To enable it:

```bash
brew install pay         # or: npm install -g @solana/pay
```

The playground server auto-spawns `pay --sandbox server start sidecar/sessions.yml` on `:18402` and probes its
health endpoint. If `pay` isn't on PATH, the Sessions tab shows an install banner and the Send button is disabled
— code snippets still render.

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
│       │                         # snippets (per-language code generators),
│       │                         # format, docs.gen
│       └── hooks/                # useTheme, useConfig, useKeyboard
└── server/                       # Express + tsx
    ├── index.ts                  # bootstrap, fee payer, surfpool funding, sidecar spawn,
    │                             # /api/v1/config endpoint
    ├── modules/
    │   ├── charges.ts            # stocks/weather/marketplace/fortune + faucet
    │   ├── subscriptions.ts      # solana.subscription gating /api/v1/premium/feed
    │   ├── sessions.ts           # reverse-proxy to `pay` sidecar
    │   ├── x402.ts               # x402-express + embedded facilitator
    │   └── faucet.ts             # SOL + USDC airdrop via surfpool cheatcodes
    ├── shared/
    │   ├── constants.ts          # USDC mint, programs
    │   ├── utils.ts              # toWebRequest, rpcCall, ANSI helpers
    │   ├── sidecar.ts            # spawn + health-probe the `pay` binary
    │   └── plan-bootstrap.ts     # initialize_plan OR surfnet_setAccount fallback
    └── sidecar/
        └── sessions.yml          # `pay server start` config
```

The visual system is a port of the [payment debugger (pdb)](https://github.com/solana-foundation/pay/tree/main/pdb)
— the same CSS variables, badge palette, header chevron, and sequence-diagram pattern, restyled into a
request-builder layout.

## Environment variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `PORT` | `3000` | Express listen port |
| `NETWORK` | `localnet` | Solana network tag for MPP / x402 challenges |
| `RPC_URL` | `http://localhost:8899` | Surfpool RPC endpoint |
| `RECIPIENT` | (auto-generated) | Solana address that receives payments |
| `FEE_PAYER_KEY` | (auto-generated) | Base58 fee-payer keypair (server signs as fee payer) |
| `MPP_SECRET_KEY` | (random per-boot) | MPP secret key for challenge HMAC |
| `PAY_CLI_PATH` | (auto-detected) | Override path to the `pay` binary |
| `SIDECAR_PORT` | `18402` | Port the `pay` sidecar listens on |
| `PLAYGROUND_DISABLE_SIDECAR` | _unset_ | Set to `1` to skip the sidecar (Sessions tab will show banner) |

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
