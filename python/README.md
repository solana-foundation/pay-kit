# Python MPP SDK

Python implements Solana MPP helpers for server and client-side `charge` flows.

This package provides:

- MPP header, challenge, credential, and receipt helpers
- Solana charge client and server helpers
- payment-page HTML helpers
- pytest coverage for protocol and server behavior

## Layout

```text
python/
├── src/solana_mpp/     SDK source
├── tests/              pytest suite
└── pyproject.toml
```

## Install

```bash
cd python
uv sync --extra dev
```

## Test

```bash
uv run --extra dev pytest
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

The cross-language interop harness lives in `../tests/interop`. Python adapter
coverage is being added separately; on current `main`, use the Python test suite
above for Python changes and the TypeScript/Rust interop harness for
cross-language regression checks.
