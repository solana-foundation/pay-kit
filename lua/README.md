# Lua MPP SDK

This module mirrors the shared `mpp-sdk` structure for Lua:

- `mpp.protocol.core` for shared header and challenge primitives
- `mpp.protocol.intents` for intent-specific request helpers
- `mpp.server` for server-side challenge generation and credential verification

The initial Lua implementation is server-first so it can back a native Kong/OpenResty
plugin without forcing a Go pluginserver binary.

## Layout

```text
lua/
├── mpp/
│   ├── protocol/
│   │   ├── core/
│   │   └── intents/
│   ├── server/
│   └── util/
└── tests/
```

## Running Tests

```bash
cd lua
lua tests/run.lua
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

For coverage, when `luacov` is available:

```bash
just lua-test-cover
```
