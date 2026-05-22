<p align="center">
  <img src="https://github.com/solana-foundation/mpp-sdk/raw/main/assets/banner.png" alt="MPP" width="100%" />
</p>

# @solana/mpp

Solana payment method for the [Machine Payments Protocol](https://mpp.dev).

**MPP** is [an open protocol proposal](https://paymentauth.org) that lets any HTTP API accept payments using the `402 Payment Required` flow.

## SDK Implementations

The Solana MPP SDK is available in 6 languages. Every implementation follows the same protocol and is tested for cross-language interoperability.

| | TypeScript | Rust | Go | Python | Lua | Ruby |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| **Package** | [@solana/mpp](https://www.npmjs.com/package/@solana/mpp) | — | — | — | — | — |
| **Server (charge)** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Client (auto-402)** | ✅ | ✅ | ✅ | ✅ | — | — |
| **Payment links** | ✅ | ✅ | ✅ | ✅ | ✅ | — |
| **Fee sponsorship** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Split payments** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **SPL tokens** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Token-2022** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Replay protection** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Session (pay-as-you-go)** | — | — | — | — | — | — |

### Testing

Every implementation is validated at three levels:

1. **Unit tests** — each SDK has its own test suite with coverage enforcement
2. **E2E payment tests** — Playwright browser tests verify the full payment link flow (wallet → transaction → service worker → on-chain verification) against Surfpool
3. **Cross-language interop** — a TypeScript/Vitest process harness runs language client and server adapters against Surfpool, proving that enabled clients and servers stay protocol-compatible

The interop harness can run a full client/server cross-product, but CI keeps the default matrix small and intentional: enabled clients are tested against the Rust server, and the Rust client is tested against enabled servers. The harness builds real Solana transactions and verifies on-chain settlement via Surfpool, catching protocol divergences that per-language unit tests miss.

```
          Clients                          Servers
   ┌────────────────┐              ┌────────────────────┐
   │  TypeScript    │──────┐       │  TypeScript :3000   │
   │  Rust          │──────┤       │  Rust       :3001   │
   │  Go            │──────┼──────▶│  Go         :3002   │
   │  Python        │──────┤       │  Lua        :3003   │
   └────────────────┘      │       │  Python     :3004   │
                           │       │  Ruby       :3005   │
                           │       └─────────┬──────────┘
                           │                 │
                           │          ┌──────┴───────┐
                           └─────────▶│   Surfpool   │
                                      │    :8899     │
                                      └──────────────┘
```

### Coverage

| Language | Coverage | Tests |
|----------|----------|-------|
| TypeScript | ![TS](https://img.shields.io/badge/coverage-67_tests-blue) | `just ts-test` |
| Rust | ![Rust](https://img.shields.io/badge/coverage-271_tests-blue) | `just rs-test` |
| Go | ![Go](https://img.shields.io/badge/coverage-84%25-green) | `just go-test` |
| Python | ![Python](https://img.shields.io/badge/coverage-87%25-green) | `just py-test` |
| Lua | ![Lua](https://img.shields.io/badge/coverage-41_tests-blue) | `just lua-test` |
| Ruby | ![Ruby](https://img.shields.io/badge/coverage-98%25-green) | `just rb-test-cover` |
| Interop | ![Interop](https://img.shields.io/badge/interop-TypeScript_harness-brightgreen) | `cd tests/interop && pnpm test` |

See [`tests/interop/README.md`](tests/interop/README.md) for the process adapter contract used by the Surfpool-backed client/server matrix.

## Install

```bash
# TypeScript
pnpm add @solana/mpp

# Rust
cargo add solana-mpp

# Go
go get github.com/solana-foundation/mpp-sdk/go

# Python
pip install solana-mpp

# Ruby
cd ruby && bundle install
```

## Quick Start

### Server (charge)

<details>
<summary>TypeScript</summary>

```ts
import { Mppx, solana } from '@solana/mpp/server'

const mppx = Mppx.create({
  secretKey: process.env.MPP_SECRET_KEY,
  methods: [
    solana.charge({
      recipient: 'RecipientPubkey...',
      currency: 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v',
      decimals: 6,
      html: true, // enables payment links for browsers
    }),
  ],
})

const result = await mppx.charge({
  amount: '1000000',
  currency: 'USDC',
})(request)

if (result.status === 402) return result.challenge
return result.withReceipt(Response.json({ data: '...' }))
```
</details>

<details>
<summary>Python</summary>

```python
from solana_mpp.server import Mpp, Config

mpp = Mpp(Config(
    recipient="RecipientPubkey...",
    currency="EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
    decimals=6,
    html=True,
))

challenge = mpp.charge("1.00")  # 1 USDC
receipt = await mpp.verify_credential(credential)
```
</details>

<details>
<summary>Go</summary>

```go
import "github.com/solana-foundation/mpp-sdk/go/server"

m, _ := server.New(server.Config{
    Recipient: "RecipientPubkey...",
    Currency:  "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
    Decimals:  6,
    HTML:      true,
})

challenge, _ := m.Charge(ctx, "1.00")
receipt, _ := m.VerifyCredential(ctx, credential)
```
</details>

<details>
<summary>Rust</summary>

```rust
use solana_mpp::server::{Config, Mpp};

let mpp = Mpp::new(Config {
    recipient: "RecipientPubkey...".into(),
    currency: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".into(),
    decimals: 6,
    html: true,
    ..Default::default()
})?;

let challenge = mpp.charge("1.00")?;
let receipt = mpp.verify_credential(&credential).await?;
```
</details>

### Payment Links

Set `html: true` on `solana.charge()` and any endpoint becomes a shareable payment link. Browsers see a payment page; API clients get the standard `402` flow.

```
Open http://localhost:3000/api/v1/fortune in a browser
→ Payment page with "Continue with Solana" button
→ Click → wallet signs → transaction confirmed on-chain
→ Page reloads with the paid content
```

See the [payment links guide](https://mpp.dev/guides/payment-links) for framework-specific setup.

### Fee Sponsorship

The server can pay transaction fees on behalf of clients:

```ts
solana.charge({
  recipient: '...',
  signer: feePayerSigner, // KeyPairSigner, Keychain SolanaSigner, etc.
})
```

### Split Payments

Send one charge to multiple recipients in the same asset:

```ts
solana.charge({
  recipient: 'SellerPubkey...',
  currency: 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v',
  decimals: 6,
  splits: [
    { recipient: 'PlatformPubkey...', amount: '50000', memo: 'platform fee' },
    { recipient: 'ReferrerPubkey...', amount: '20000', memo: 'referral fee' },
  ],
})
```

## Demo

An interactive playground with a React frontend and Express backend, running against [Surfpool](https://surfpool.run).

```bash
surfpool start
pnpm demo:install
pnpm demo:server
pnpm demo:app
```

See [demo/README.md](demo/README.md) for full details.

## Development

```bash
just build            # Build all SDKs (html → ts → rust → go → ruby)
just test             # Test all SDKs
just pre-commit       # Full pre-commit checks

# Per-language
just ts-test          # TypeScript tests
just rs-test          # Rust tests
just go-test          # Go tests
just py-test          # Python tests
just lua-test         # Lua tests
just rb-test-cover    # Ruby tests with line and branch coverage

# Integration
just html-build       # Build payment link assets
just html-test-e2e    # Playwright E2E tests
```

## Spec

This SDK implements the [Solana Charge Intent](https://github.com/tempoxyz/mpp-specs/pull/188) for the [HTTP Payment Authentication Scheme](https://paymentauth.org).

## License

MIT
