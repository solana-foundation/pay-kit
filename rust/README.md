# Rust MPP SDK

Rust is the strongest native implementation for the Solana payment method in
the Machine Payments Protocol.

This crate provides:

- Solana `charge` client and server helpers
- transaction and verification primitives
- optional server/client features
- reference binaries used by the interop harness

## Layout

```text
rust/
├── src/                         SDK source
├── tests/                       Rust test suite
├── payment_channels_client/     local helper crate
└── Cargo.toml
```

## Test

```bash
cd rust
cargo test
```

## Local Payment Check

Use `curl` to confirm the server returns a payment challenge, then use the
`pay` CLI to complete the 402 challenge/credential flow.

```bash
brew install pay

# payment required
curl http://localhost:4567/paid

# payment successful
pay curl http://localhost:4567/paid
```

## Interop

The TypeScript interop harness can run the Rust server and client adapters from
`../tests/interop`.

```bash
cd ../tests/interop
pnpm test
```
