# solana-pay-kit

Charge stablecoins (USDC, USDT, PYUSD, …) for any HTTP endpoint, in Rust. One
gated route accepts payment over **both** the [Machine Payments
Protocol](https://paymentauth.org) (MPP) and [x402](https://paymentauth.org) —
the client pays with whichever it supports.

You do not need to know anything about Solana to use this library: pick a
currency, give it your wallet address, and gate a route. `solana-pay-kit` is the
Rust sibling of the TypeScript, Go, Python, Ruby, PHP, Lua, Kotlin, and Swift
pay-kit SDKs and speaks the same wire format.

## Install

```toml
# The unified axum gate (MPP + x402). Pulls in both protocol servers.
solana-pay-kit = { version = "0.1", features = ["axum"] }
```

Feature flags:

| Feature | Enables |
|---|---|
| `mpp` (default) | the MPP module, re-exported as `solana_pay_kit::mpp` |
| `x402` (default) | the x402 module, re-exported as `solana_pay_kit::x402` |
| `server` | server-side verification for the enabled protocols |
| `client` | client-side payment building for the enabled protocols |
| `axum` | the unified `paid_get` / `paid_post` gate (implies `server` + both protocols) |
| `gcp_kms` | GCP KMS signing backend |

## Quick start

Gate a route in one line. An unpaid request gets a 402 that advertises both
protocols; a paying client gets `200` and the handler sees the verified payment.

```rust
use axum::Router;
use solana_pay_kit::{paid_get, PayKit, PayKitConfig, Payment};

async fn report(payment: Payment) -> String {
    format!("paid {} via {}: {}", payment.amount, payment.protocol, payment.reference)
}

#[tokio::main]
async fn main() {
    let pay = PayKit::new(PayKitConfig {
        recipient: "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY".to_string(),
        network: "devnet".to_string(),
        rpc_url: Some("https://402.surfnet.dev:8899".to_string()),
        ..Default::default()
    })
    .expect("valid config");

    let app: Router = Router::new().route("/report", paid_get(report, "0.10", &pay));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:4567").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
```

For production, point `rpc_url` at a real RPC, use `network: "mainnet"`, and set
a stable `challenge_binding_secret` of at least 32 bytes (`openssl rand -base64
32`); the server rejects a short or empty secret at startup. When
`challenge_binding_secret` is `None` the MPP layer reads `MPP_SECRET_KEY`.

## Run the example

```bash
cargo run -p solana-pay-kit --example axum_quickstart --features axum   # listens on :4567

curl -i http://127.0.0.1:4567/report          # 402 Payment Required (both challenges)
pay curl -i http://127.0.0.1:4567/report        # Touch ID → USDC → 200
```

## What the 402 carries

A request with no payment gets a single `402 Payment Required` that advertises
both protocols, so any pay-kit client can pay:

- `WWW-Authenticate: Payment …` — the MPP charge challenge.
- `PAYMENT-REQUIRED: …` — the x402 challenge.

The headers are disjoint, so the paid retry is unambiguous: an `Authorization:
Payment` credential is verified as MPP; a `PAYMENT-SIGNATURE` (or `X-PAYMENT`)
header is verified as x402. Either way the resolved price is pinned during
verification, so a credential minted for a cheaper route on the same server is
rejected.

## The `Payment` handler argument

On a gated route, add a `Payment` parameter to read the verified payment. It is
always present — the gate returns 402 before the handler runs.

```rust
async fn handler(payment: Payment) -> String {
    // payment.amount    -> the price charged, e.g. "0.10"
    // payment.protocol  -> Protocol::Mpp or Protocol::X402
    // payment.reference -> settlement reference (MPP receipt ref or x402 signature)
    payment.reference
}
```

The response automatically carries the settlement header for the protocol used
(`Payment-Receipt` for MPP, `PAYMENT-RESPONSE` for x402).

## Dynamic pricing

Price a route per request with `Price::dynamic`:

```rust
let route = paid_get(
    quote,
    Price::dynamic(|ctx| match ctx.query_param("tier").as_deref() {
        Some("premium") => "5.00".to_string(),
        _ => "0.10".to_string(),
    }),
    &pay,
);
```

The closure receives a read-only view of the request (method, URI, headers) and
returns the dollar amount. The resolved amount is what the credential is pinned
against.

## Fee sponsorship and signers

By default the paying client covers the network fee. To sponsor it from the
server, set `fee_payer_signer` on `PayKitConfig` — it drives MPP's fee-sponsored
mode and supplies the x402 fee-payer address from the same key. Signers come
from [Solana Keychain](https://github.com/solana-foundation/solana-keychain),
re-exported as `solana_pay_kit::mpp::solana_keychain`:

```rust
use solana_pay_kit::mpp::solana_keychain::memory::MemorySigner;
use std::sync::Arc;

let signer = MemorySigner::from_bytes(&secret_key_bytes)?; // 64-byte keypair
let pay = PayKit::new(PayKitConfig {
    recipient: recipient.to_string(),
    fee_payer_signer: Some(Arc::new(signer)),
    ..Default::default()
})?;
```

Remote backends (AWS KMS, GCP KMS, Vault, …) implement
`solana_keychain::SolanaSigner`; the `gcp_kms` feature wires the GCP backend.

## Dropping to a single protocol

`solana-pay-kit` re-exports both protocol crates for when you want one protocol
or a lower-level API:

- `solana_pay_kit::mpp` — [`solana-mpp`](../mpp/README.md): the MPP charge
  server (`Mpp`), the typed `MppCharge<C>` axum extractor, sessions, and
  subscriptions.
- `solana_pay_kit::x402` — [`solana-x402`](../x402): the x402 `exact` server and
  SIWX.

`PayKit` is built from both: `PayKit::new` derives an `Mpp` and an `X402` from
one `PayKitConfig`, and `pay.mpp()` / `pay.x402()` expose them.

## Test

```bash
cargo test -p solana-pay-kit --features axum
```

## Spec

- [Solana Charge Intent](https://paymentauth.org/draft-solana-charge-00.html)
- [HTTP Payment Authentication Scheme](https://paymentauth.org)
- `../../../docs/paykit-interface.md`

## License

MIT.
