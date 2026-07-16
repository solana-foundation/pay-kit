<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://github.com/solana-foundation/pay-kit/raw/main/docs/assets/banner-rust-dark.png">
    <source media="(prefers-color-scheme: light)" srcset="https://github.com/solana-foundation/pay-kit/raw/main/docs/assets/banner-rust-light.png">
    <img alt="Solana pay-kit — Rust" width="100%" style="border-top-left-radius: 8px; border-top-right-radius: 8px; margin-bottom: 16px;" src="https://github.com/solana-foundation/pay-kit/raw/main/docs/assets/banner-rust-light.png">
  </picture>
</div>

Charge stablecoins (USDC, USDT, PYUSD, …) for any HTTP endpoint, in Rust. One
surface (`solana-pay-kit`) over both the
[Machine Payments Protocol](https://paymentauth.org) and
[x402](https://x402.org): a gated route advertises both, and the client pays
with whichever it supports. It is the Rust sibling of the TypeScript, Go,
Python, Ruby, PHP, Lua, Kotlin, and Swift SDKs and speaks the same wire format.

You do not need to know anything about Solana to use this library: pick a
currency, give it your wallet address, and gate a route.

[![Rust](https://img.shields.io/badge/rust-2021-orange)]()
[![axum](https://img.shields.io/badge/axum-0.8-blue)]()

---

## Quick start

Three progressively-realistic snippets. [axum](https://github.com/tokio-rs/axum)
is the framework here.

### 1. Smallest possible app

Gate one route with an inline price. Zero-config beyond the RPC: pass a published
demo recipient and the hosted Surfpool sandbox at `https://402.surfnet.dev:8899`.

```rust
use axum::Router;
use solana_pay_kit::{paid_get, PayKit, PayKitConfig, Payment};

async fn report(payment: Payment) -> String {
    format!("premium content (paid {} via {})", payment.amount, payment.protocol)
}

#[tokio::main]
async fn main() {
    let pay = PayKit::new(PayKitConfig {
        recipient: "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY".to_string(),
        network: "localnet".to_string(),
        rpc_url: Some("https://402.surfnet.dev:8899".to_string()),
        ..Default::default()
    })
    .expect("valid config");

    let app = Router::new().route("/report", paid_get(report, "0.10", &pay));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:4567").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
```

The gate halts the request with a 402 challenge if no valid payment was sent;
when one was, it verifies and settles it, sets the settlement header on the
response, and hands control to your handler. Hit `/report` with
[`pay curl`](#run-the-example) and the customer walks through Touch ID and a
USDC payment.

### 2. Multiple gates

Each route names its own price. There is no catalogue type — `paid_get` /
`paid_post` take the price inline, fixed or per-request.

```rust
use solana_pay_kit::{paid_get, Price};

let app = Router::new()
    .route("/report", paid_get(report, "0.10", &pay))
    .route("/api/data", paid_get(api_data, "0.001", &pay))
    // Per-request pricing: ?tier=premium costs more.
    .route(
        "/quote",
        paid_get(
            quote,
            Price::dynamic(|ctx| match ctx.query_param("tier").as_deref() {
                Some("premium") => "5.00".to_string(),
                _ => "0.10".to_string(),
            }),
            &pay,
        ),
    );
```

### 3. Production-shape config

Snippet 1's demo recipient and public sandbox are fine for poking around.
Production wants your own wallet, a dedicated RPC, a stable challenge secret,
and — if you sponsor the network fee — a signer. The route handlers are
unchanged; only `PayKitConfig` grows.

```rust
use solana_pay_kit::{PayKit, PayKitConfig};
use solana_pay_kit::solana_keychain::memory::MemorySigner;
use std::sync::Arc;

let pay = PayKit::new(PayKitConfig {
    recipient: "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY".to_string(),
    network: "mainnet".to_string(),
    rpc_url: Some("https://mainnet.helius-rpc.com/?api-key=YOUR_KEY".to_string()),
    challenge_binding_secret: Some(std::env::var("MPP_SECRET_KEY")?),
    // Sponsor the customer's network fee: drives MPP fee-sponsored mode and
    // supplies x402's fee-payer address from the same key.
    fee_payer_signer: Some(Arc::new(MemorySigner::from_bytes(&operator_key)?)),
    ..Default::default()
})?;
```

Safety rails fire at boot:

- A `challenge_binding_secret` shorter than 32 bytes (or empty) is rejected —
  generate one with `openssl rand -base64 32`. When it is `None`, the MPP layer
  reads `MPP_SECRET_KEY`.
- An unknown `network` slug is rejected; the canonical slugs are `mainnet`,
  `devnet`, and `localnet`.

---

## Run the example

```bash
cargo run -p solana-pay-kit --example axum_quickstart --features axum   # listens on :4567

# Fail with 402 — payment required (carries both protocol challenges)
curl -i http://127.0.0.1:4567/report

# Succeed with 200 — payment provided
pay curl -i http://127.0.0.1:4567/report     # brew install pay
```

Set `MPP_SECRET_KEY` to override the demo challenge secret.

---

## How a 402 carries both protocols

An unpaid request gets a single `402 Payment Required` that advertises both
protocols, so any pay-kit client can pay:

- `WWW-Authenticate: Payment …` — the MPP charge challenge.
- `PAYMENT-REQUIRED: …` — the x402 challenge.

The headers are disjoint, so the paid retry is unambiguous: an
`Authorization: Payment` credential is verified as MPP; a `PAYMENT-SIGNATURE`
(or `X-PAYMENT`) header is verified as x402. Either way the resolved price is
pinned during verification, so a credential minted for a cheaper route on the
same server is rejected.

## MPP

The [Machine Payments Protocol](https://paymentauth.org) is a `402 Payment
Required` handshake whose challenge carries a rich intent shape supporting
multi-recipient splits, server-side fee accounting, and a separate fee-payer
signer. Use it when your gate has a platform/gateway fee, you want the server to
subsidize the network fee, or you want one challenge per gate.

Supported in Rust (`solana-pay-kit::mpp`):

| Intent         | Client | Server |
|----------------|:------:|:------:|
| `charge/pull`  | ✅      | ✅      |
| `charge/push`  | ✅      | ✅      |
| `session`      | ✅      | ✅      |
| `subscription` | ✅      | ✅      |

For `charge/pull` the server owns the full lifecycle: it issues signed
challenges with a fresh `recentBlockhash`, validates the `Authorization:
Payment` credential, decodes the client-signed transaction and checks recipient,
amount, mint, splits, ATA, memos, and compute budget, optionally co-signs as fee
payer, broadcasts, polls to `confirmed`, and emits `Payment-Receipt`.

## x402

[x402](https://x402.org) revives HTTP `402 Payment Required`. The Rust
implementation (`solana_pay_kit::x402`, gated by the `x402` feature) ships the
single-recipient `exact` scheme and the usage-based `upto` scheme — both server
and client — plus SIWX.

| Scheme         | Client | Server |
|----------------|:------:|:------:|
| `exact`        | ✅      | ✅      |
| `upto`         | ✅      | ✅      |
| `batch-settlement` | ✅      | ✅      |

`upto` charges for actual usage up to a ceiling: it settles on a payment channel
after the handler runs, so it needs a `fee_payer_signer` (used as both fee payer
and receiver authorizer by default) and is gated with `paid_upto_get` /
`paid_upto_post` rather than `paid_get` / `paid_post`.

`batch-settlement` is for high-throughput APIs: the client opens one channel and
signs a cumulative voucher per request, which the gate (`paid_batch_get` /
`paid_batch_post`) verifies off-chain and serves immediately. The operator
redeems vouchers on-chain later in batches via `pay.x402_batch()` (`settle_batch`
/ `distribute`). It also needs a `fee_payer_signer`.

## Client

Unlike the Ruby, Python, PHP, and Lua SDKs (server-only), Rust also ships the
paying side, via the protocol-layer crate re-exported at `solana_pay_kit::mpp`:

```rust
use solana_pay_kit::mpp::client::{build_credential_header, parse_challenge};
use solana_pay_kit::solana_keychain::memory::MemorySigner;
use solana_pay_kit::mpp::solana_rpc_client::rpc_client::RpcClient;

// 1. Read the 402 challenge from the WWW-Authenticate header.
let challenge = parse_challenge(www_authenticate_header)?;
// 2. Sign a payment for it and replay the request with the credential.
let authorization = build_credential_header(&signer, &rpc, &challenge).await?;
```

`build_charge_transaction_with_options` adds auto-pay guardrails — a spending
cap (`max_amount_base_units`), an expected-network pin, and a refusal to sign
unknown Token-2022 mints unless opted in.

---

## Vocabulary

| Term | Meaning |
|------|---------|
| **recipient** | The wallet address that receives payment. |
| **amount** | The price a route charges, as a dollar string (`"0.10"`). |
| **currency** | The stablecoin symbol or mint address (`"USDC"`). |
| **challenge** | The 402 body the server issues (`PaymentChallenge`). |
| **credential** | The proof the client submits (`Authorization: Payment` / `PAYMENT-SIGNATURE`). |
| **payment** | The verified result handed to your handler (`Payment`). |
| **reference** | The settlement reference — MPP receipt reference or x402 signature. |
| **protocol** | `mpp` or `x402` (top-level dispatch). |
| **scheme** | MPP sub-form: `charge`. x402 sub-form: `exact`. |
| **fee payer** | Who pays the network fee; the server sponsors it when `fee_payer_signer` is set. |
| **network** | `mainnet`, `devnet`, or `localnet`. |

## Primitives

| Item | Purpose |
|------|---------|
| `paid_get(handler, price, &pay)` / `paid_post(…)` | Gate a route; returns a `MethodRouter`. |
| `Payment` | Handler argument: the verified payment (`amount`, `protocol`, `reference`). |
| `Price` | A fixed amount (`"0.10".into()`) or `Price::dynamic(closure)`. |

Dropping a layer, `PayKit` exposes the per-protocol handlers — `pay.mpp()` and
`pay.x402()` — and `Mpp::verify_payment_for_amount(credential, amount)` is the
amount-pinned verify the gate builds on.

## Pricing

```rust
use solana_pay_kit::{paid_get, Price};

// Fixed: a &str or String converts straight into a price.
let route = paid_get(handler, "0.10", &pay);

// Per-request: the closure sees the request (method, URI, headers).
let route = paid_get(
    handler,
    Price::dynamic(|ctx| match ctx.query_param("tier").as_deref() {
        Some("premium") => "5.00".to_string(),
        _ => "0.10".to_string(),
    }),
    &pay,
);
```

The resolved amount is what the credential is pinned against, so dynamic pricing
is replay-safe too.

## Signers

Key handling is built on
[Solana Keychain](https://github.com/solana-foundation/solana-keychain),
re-exported as `solana_pay_kit::solana_keychain` (the older protocol-scoped
paths remain compatibility aliases). Local key material rides on `MemorySigner`;
remote backends (AWS KMS, GCP KMS, Vault, …) implement `SolanaSigner`:

```rust
use solana_pay_kit::solana_keychain::memory::MemorySigner;

let signer = MemorySigner::from_bytes(&secret_key_bytes)?; // 64-byte keypair
```

Set `fee_payer_signer` on `PayKitConfig` to sponsor the network fee — one key
drives MPP fee-sponsored mode and supplies x402's fee-payer address. The
`gcp_kms` feature wires the GCP KMS backend.

---

## Install

```toml
# Gate routes with the unified dual-protocol axum gate (this guide):
solana-pay-kit = { version = "0.1", features = ["axum"] }

# Single protocol:
solana-pay-kit = { version = "0.1", default-features = false, features = ["mpp"] }
```

Feature flags:

| Feature | Default | Enables |
|---------|:-------:|---------|
| `mpp` | ✅ | the MPP module, re-exported as `solana_pay_kit::mpp` |
| `x402` | ✅ | the x402 module, re-exported as `solana_pay_kit::x402` |
| `server` | — | server-side verification for the enabled protocols |
| `client` | — | client-side payment building for the enabled protocols |
| `axum` | — | the `paid_get` / `paid_post` gate (implies `server` + both protocols) |
| `gcp_kms` | — | GCP KMS signing backend |

## Test

```bash
cd rust
cargo test -p solana-pay-kit --features axum
cargo test --workspace

# Single protocol module:
cargo test -p solana-pay-kit --lib mpp
cargo test -p solana-pay-kit --lib x402
```

## Harness

The cross-language harness lives in [`../harness`](../harness). The unpublished
`paykit-harness-bins` crate ships the `mpp_harness_*` / `x402_harness_*`
binaries used by the cross-language conformance suite.

```bash
cd ../harness
pnpm test
```

## Spec

This SDK implements the
[Solana Charge Intent](https://paymentauth.org/draft-solana-charge-00.html) for
the [HTTP Payment Authentication Scheme](https://paymentauth.org), and the x402
`exact` scheme. The cross-language surface is specified in
[`docs/paykit-interface.md`](../docs/paykit-interface.md).

---

## Layout

```text
rust/
├── Cargo.toml                     # workspace root
├── crates/
│   ├── kit/                       # solana-pay-kit: the ONE publishable crate
│   │   └── src/
│   │       ├── lib.rs             # feature-gated: pub mod core/mpp/x402/generated
│   │       ├── core/              # shared Solana primitives
│   │       ├── mpp/               # MPP charge/session/subscription (client + server)
│   │       ├── x402/              # x402 exact + upto + SIWX
│   │       ├── generated/         # inlined Codama program clients
│   │       │   ├── payment_channels/generated/
│   │       │   └── subscriptions/generated/
│   │       ├── gate.rs            # PayKit, paid_get/paid_post, Payment, Price
│   │       └── select.rs          # cross-protocol balance-aware selection
│   ├── harness-bins/              # paykit-harness-bins: conformance bins (unpublished)
│   └── integration-tests/         # paykit-integration-tests: surfpool/litesvm (unpublished)
```

## Coding convention

This SDK follows the per-language style notes in the repo-level
`pay-sdk-implementation` skill, which remains the protocol source of truth: Rust
/ spec wire format first.

## License

MIT
