# TypeScript MPP SDK

TypeScript is the primary JavaScript implementation for the Solana payment
method in the Machine Payments Protocol.

This package provides:

- Solana `charge` client and server helpers
- session and subscription helpers where implemented
- shared browser payment-link assets
- the reference TypeScript interop harness used by CI

## Layout

```text
typescript/
├── packages/mpp/        SDK package
├── vitest.config*.ts    test configurations
└── package.json         workspace scripts
```

## Install

```bash
cd typescript
pnpm install
```

## Test

```bash
pnpm typecheck
pnpm test
pnpm test:integration
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

The cross-language interop harness lives in `../tests/interop`.

```bash
cd ../tests/interop
pnpm install
pnpm test
```
