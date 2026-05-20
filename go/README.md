# Go MPP SDK

Go implements Solana MPP helpers for server and client-side `charge` flows.

This module provides:

- protocol core helpers for MPP headers and credentials
- Solana charge request and transaction helpers
- HTTP client/server helpers
- test coverage for charge verification behavior

## Layout

```text
go/
├── client/       HTTP client helpers
├── protocol/     wire and Solana protocol helpers
├── server/       server middleware and verification helpers
└── go.mod
```

## Test

```bash
cd go
go test ./...
```

If local sandboxing blocks the default Go cache, use temp caches:

```bash
GOCACHE=/tmp/mpp-go-cache GOMODCACHE=/tmp/mpp-go-mod go test ./...
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
MPP_INTEROP_CLIENTS=typescript MPP_INTEROP_SERVERS=go pnpm test
```
