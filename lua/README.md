<p align="center">
  <img src="https://github.com/solana-foundation/mpp-sdk/raw/main/assets/banner.png" alt="MPP" width="100%" />
</p>

# mpp (Lua)

Solana payment method for the [Machine Payments Protocol](https://mpp.dev),
for Lua. Runs on LuaJIT 2.1 (the OpenResty / Kong production runtime).

**MPP** is [an open protocol proposal](https://paymentauth.org) that lets
any HTTP API accept payments using the `402 Payment Required` flow.

[![Lua](https://img.shields.io/badge/LuaJIT-2.1-blue)]()
[![Coverage](https://img.shields.io/badge/coverage-90%25-green)]()
[![Tests](https://img.shields.io/badge/tests-121-blue)]()

## Repo layout

```
lua/
├── mpp/
│   ├── protocol/        # Wire format (challenge, headers, intents)
│   ├── server/          # 402 challenge issuance + credential verification
│   │   └── charge_handler.lua  # Settlement orchestrator (broadcast, await, replay-store)
│   ├── solana/
│   │   └── rpc.lua      # Transport-agnostic JSON-RPC client
│   └── util/            # base64url, canonical JSON, HMAC primitives
├── tests/               # Unit tests, ≥90% coverage gate via luacov
├── scripts/             # Coverage gate helpers
├── mpp-dev-1.rockspec   # Rockspec for `luarocks install`
└── Justfile             # install / test / lint / test-cover / audit
```

## Quick start, server (charge)

```lua
local mpp = require('mpp')
local rpc = mpp.solana.rpc.new({
  url = 'https://402.surfnet.dev:8899',
  transport = function(url, body)
    -- Provide any HTTP transport that performs a POST and returns the
    -- response body string. PR B ships an OpenResty/lua-http transport.
    return your_http_post(url, body)
  end,
})

local handler = mpp.charge_handler.new({
  rpc = rpc,
  network = 'mainnet',
  replay_store = mpp.store.memory(),
  transaction_verifier = function(transaction_base64, request)
    -- Decode + verify transferChecked, ATA, memo, splits.
    -- Delegate to mpp.server.solana_verify in PR B's example server.
  end,
})

local server = mpp.server.new({
  recipient = '3yGpUKnU5HSVSMxye83YuseTeSQykiS5N4eh6iQn1d2h',
  currency = 'USDC',
  decimals = 6,
  network = 'mainnet',
  secret_key = os.getenv('MPP_SECRET_KEY'),
  verify_payment = handler:as_callback(),
})

local challenge = server:charge('0.001')
-- Issue WWW-Authenticate; on credential, call server:verify_credential_with_expected(...)
```

## Quick start, client (auto-402)

Lua is server-side in this repository. A Lua client is out of scope for the
current Milestone 1 grant; consumers driving a Lua-protected endpoint should
use the canonical TypeScript or Rust client from the same monorepo.

## Client compatibility matrix

| Cell | Status |
|---|:---:|
| `x402/exact` | — |
| `x402/upto` | — |
| `x402/batch-settlement` | — |
| `mpp/charge/pull` | — |
| `mpp/charge/push` | — |
| `mpp/session` | — |
| `mpp/subscription` | — |

## Server compatibility matrix

| Cell | Status |
|---|:---:|
| `x402/exact` | — |
| `x402/upto` | — |
| `x402/batch-settlement` | — |
| `mpp/charge/pull` | ✅ |
| `mpp/charge/push` | ✅ |
| `mpp/session` | — |
| `mpp/subscription` | — |

## How to use the library

```bash
# install (LuaJIT 2.1 + project-local rocks tree)
brew install luajit luarocks
cd lua && just install

# require in your code
local mpp = require('mpp')
```

Public surface is documented inline. Every public type and function carries
a one-line summary so the language's hover/LSP shows it without round-trips
to source.

## How to use the example

PR A ships the foundation: RPC client, charge handler with full settlement
lifecycle, unit tests, coverage gate, and CI workflow. The runnable
example servers (`lua/examples/simple-server.lua` and `lua/examples/openresty/`)
plus the interop adapter at `tests/interop/lua-server/` ship in PR B, which
also clears the manual DX gate via `curl` (returns 402) and `pay curl`
(returns 200 with `payment-receipt`).

## Solana dependencies

| Dependency | Why | Version |
|---|---|---|
| `LuaJIT` | runtime; matches OpenResty / Kong production | 2.1 |
| `luarocks` | rocks tree bootstrap (`luarocks --lua-version=5.1 init`) | 3.x |
| `luacheck` | lint (per repo coding-conventions) | 1.2 |
| `luacov` | coverage measurement, ≥90% gate | 0.17 |

The Lua SDK open-codes the small set of Solana wire constants it needs (see
`mpp/protocol/solana.lua`) rather than pulling in a heavy Solana client. The
JSON-RPC client at `mpp/solana/rpc.lua` is transport-agnostic so callers can
plug in `socket.http`, `cqueues-http`, or OpenResty's `ngx.location.capture`
without changing the handler.

## Coding convention

This SDK follows the conventions in
`skills/pay-sdk-implementation/references/coding-conventions.md`:

- `luacheck` for lint (configured at `lua/.luacheckrc`).
- `snake_case` for functions, `PascalCase` for types, `SCREAMING_SNAKE` for
  constants.
- One-line doc comment on every public function / type.
- Wire-format field names are **camelCase JSON** even though Lua field names
  are `snake_case` internally; only the serialized form is camelCase.

### Lua best-practice source

The Lua source-of-truth used during this PR is the
[lua-users wiki style guide](http://lua-users.org/wiki/LuaStyleGuide) plus
the OpenResty Lua coding style guide
(<https://github.com/openresty/openresty/blob/master/lua-coding-style.md>).
These were chosen because OpenResty / Kong is the target deployment runtime
for production Lua MPP servers (LuaJIT 2.1, the `ngx_*` API surface).

## Code coverage

```bash
just lua-test-cover     # ≥90% line gate via luacov
```

Reported coverage is uploaded as a CI artifact (see
`.github/workflows/lua.yml`).

## Spec

This SDK implements the [Solana Charge Intent](https://github.com/tempoxyz/mpp-specs/pull/188)
for the [HTTP Payment Authentication Scheme](https://paymentauth.org).

## License

MIT
