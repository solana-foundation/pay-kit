# Rust pay-kit workspace

Rust implementations of the Solana payment protocols supported by this repo:

- **MPP** (`solana-mpp`) — Machine Payments Protocol (charge + session intents).
- **x402** (`solana-x402`) — HTTP 402 with the `exact` scheme, plus SIWX.
- **pay-kit** (`solana-pay-kit`) — facade crate that re-exports both behind
  feature flags `mpp` and `x402` (both default).

## Layout

```text
rust/
├── Cargo.toml                       # workspace root
├── crates/
│   ├── core/                        # shared Solana primitives (solana-pay-core)
│   │   └── payment-channels/        # generated Solana program client subcrate
│   ├── mpp/                         # solana-mpp
│   ├── x402/                        # solana-x402 (incl. siwx)
│   └── kit/                         # solana-pay-kit (facade)
└── tests/                           # cross-protocol scenarios (planned)
```

## Test

```bash
cd rust
cargo test --workspace
```

Single-protocol:

```bash
cargo test -p solana-mpp
cargo test -p solana-x402
```

## Facade usage

Default — both protocols enabled:

```toml
solana-pay-kit = "0.1"
```

Single protocol:

```toml
solana-pay-kit = { version = "0.1", default-features = false, features = ["mpp"] }
```

## Interop

The TypeScript interop harness can run the Rust server and client adapters from
`../harness`.

```bash
cd ../harness
pnpm test
```
