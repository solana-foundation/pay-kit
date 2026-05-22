<p align="center">
  <img src="https://github.com/solana-foundation/mpp-sdk/raw/main/assets/banner.png" alt="MPP" width="100%" />
</p>

# mpp (Lua)

Charge stablecoins (USDC, USDT, PYUSD, …) for any HTTP endpoint, in Lua.
Runs on LuaJIT 2.1 (the OpenResty / Kong production runtime). Implements
the Solana payment method for the
[Machine Payments Protocol](https://mpp.dev).

**MPP** is [an open protocol proposal](https://paymentauth.org) that lets
any HTTP API accept payments using the `402 Payment Required` flow. You
don't need to know anything about Solana to use this library — pick a
currency, give it your wallet address, and gate a route in two lines.

[![LuaJIT](https://img.shields.io/badge/luajit-2.1-blue)]()
[![Coverage](https://img.shields.io/badge/coverage-90%25-brightgreen)]()
[![Tests](https://img.shields.io/badge/tests-125-blue)]()

## Repo layout

```text
lua/
├── mpp/protocol/         # Wire format (challenge, headers, intents)
├── mpp/server/           # 402 challenge issuance + credential verification
│   ├── charge_handler.lua  # Settlement orchestrator (broadcast, consume, await)
│   ├── solana_verify.lua   # Per-instruction allowlist + structural verifier
│   ├── network_check.lua   # Rejects Surfpool-signed transactions on mainnet
│   └── html.lua            # Optional 402 payment-link HTML render
├── mpp/solana/rpc.lua    # Transport-agnostic JSON-RPC client
├── mpp/store.lua         # Replay store (in-memory; OpenResty shared-dict adapter in PR B)
├── mpp/util/             # base64url, canonical JSON, HMAC primitives
├── tests/                # Unit tests, ≥90% line coverage gate via luacov
├── mpp-dev-1.rockspec    # LuaJIT 2.1 pinned rockspec
└── Justfile              # install / test / lint / test-cover / audit
```

## Quick start — server

```lua
local mpp = require('mpp')
local store = require('mpp.store')
local rpc = require('mpp.solana.rpc').new({
  url = 'https://402.surfnet.dev:8899',
  transport = function(url, body)
    -- Plug any HTTP transport that POSTs the body and returns the response
    -- string. PR B ships an OpenResty `ngx.location.capture` transport.
    return your_http_post(url, body)
  end,
})

local handler = mpp.server.charge_handler.new({
  rpc = rpc,
  network = 'mainnet',
  replay_store = store.memory(),
  transaction_verifier = mpp.server.solana_verify.new_signature_verifier({
    expected_recipient = 'CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY',
    expected_currency = 'USDC',
    expected_decimals = 6,
  }),
})

local server = mpp.server.new({
  recipient = 'CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY',
  currency = 'USDC',
  decimals = 6,
  network = 'mainnet',
  secret_key = os.getenv('MPP_SECRET_KEY'),
  realm = 'Lua MPP Example',
  verify_payment = handler:as_callback(),
})

-- In your request handler:
local result = server:handle_request({
  method = 'GET',
  path = '/paid',
  headers = parsed_request_headers,
  amount = '1000',
  description = 'Paid endpoint',
})
-- result.status is 200 with a Payment-Receipt header on success,
-- or 402 with a WWW-Authenticate challenge on missing/invalid credential.
```

`currency` accepts a symbol like `"USDC"`, `"USDT"`, `"USDG"`, `"PYUSD"`,
or `"CASH"` — the SDK looks up the mint address, token program, and
decimals from a built-in table. You can also pass a raw mint pubkey for
tokens not in the table.

The handler owns every static knob (recipient, default currency, network,
RPC, optional fee payer). Per-request you only pass `amount` and
`description`. The blockhash is fetched lazily and cached for ~2 seconds
inside the RPC client so a busy endpoint doesn't pay an RPC round-trip on
every protected request.

### Framework integrations

The Lua SDK is transport-agnostic: it does not own the HTTP server. Bind
it inside your framework of choice.

- **OpenResty / Kong (target deployment runtime)**: call
  `server:handle_request(...)` from an `access_by_lua_block` and let
  the upstream serve only on a 200 result.
- **Bare LuaJIT (development, tests)**: drive it from a raw
  `socket.tcp()` accept loop. The PR B `lua/examples/simple-server.lua`
  ships a 60-line reference implementation.

## Running the examples

Two runnable examples ship in this PR. Both exercise the 402
challenge-issuance path; on-chain settlement (the `pay curl` 200
response) ships in the follow-up Lua PR B which adds the heavy
Solana stack (base58, transaction bincode codec, Ed25519 signer,
ATA derive) and the interop adapter at `tests/interop/lua-server/`.

### Bare LuaJIT simple-server

```bash
cd lua && eval "$(luarocks --lua-version=5.1 --tree lua_modules path)"
luajit examples/simple-server.lua          # listens on 127.0.0.1:4569
```

```bash
curl -i http://127.0.0.1:4569/health        # 200 OK
curl -i http://127.0.0.1:4569/paid          # 402 Payment Required with
                                            # signed WWW-Authenticate header
```

### OpenResty / nginx middleware

```bash
cd lua/examples/nginx
openresty -p . -c nginx.conf                # listens on 127.0.0.1:4570
```

The Lua middleware (`access.lua`) runs in nginx's access phase and
either returns 402 with a signed challenge or lets the upstream
content phase render the protected payload. The shared dict
`mpp_replay` is wired in `nginx.conf` for future replay-store use.

Both examples accept the same env overrides: `PORT`, `MPP_PAY_TO`,
`MPP_CURRENCY`, `MPP_NETWORK`, `MPP_SECRET_KEY`, `MPP_AMOUNT`.

## Client compatibility matrix

Lua is server-side only for the current MPP roadmap.

| Intent | Status |
|---|:---:|
| `x402/exact` | — |
| `x402/upto` | — |
| `x402/batch-settlement` | — |
| `mpp/charge/pull` | — |
| `mpp/charge/push` | — |
| `mpp/session` | — |
| `mpp/subscription` | — |

## Server compatibility matrix

Split into two phases because an MPP server first verifies the credential
and then settles or confirms the payment on-chain.

| Intent | Status |
|---|:---:|
| `x402/exact` | — |
| `x402/upto` | — |
| `x402/batch-settlement` | — |
| `mpp/charge/pull` | ✅ |
| `mpp/charge/push` | ✅ |
| `mpp/session` | — |
| `mpp/subscription` | — |

For `mpp/charge/pull`: the handler owns the full lifecycle, issue signed
challenges with a fresh `recentBlockhash`, parse and validate the
`Authorization: Payment` credential, pin the echoed charge request,
decode the client-signed transaction and check recipient / amount / mint
/ splits / ATA / memos / compute budget, reject Surfpool-signed
transactions on non-localnet networks, optionally fee-payer co-sign,
broadcast via `sendTransaction`, **consume the signature in the replay
store before** polling `getSignatureStatuses` to `confirmed` /
`finalized`, and emit `payment-receipt` with the on-chain signature. The
consume-before-await ordering closes the confirmation-timeout double-pay
window (see #96 / Greptile P1 on #85).

For `mpp/charge/push`: the handler fetches the transaction by signature
with `getTransaction`, rejects failed or missing metadata, reuses the
same structural transaction verifier as pull mode, consumes the
signature through replay storage, and emits the same receipt shape.

The direct Lua interop server at
[`tests/interop/lua-server/server.lua`](../tests/interop/lua-server/server.lua)
ships in PR B; this PR ships the foundation exercised by the unit suite.

## Examples

Two examples ship with this package:

- [`examples/simple-server.lua`](examples/simple-server.lua) — bare
  LuaJIT TCP accept loop that calls `mpp.server` directly. Mirrors
  the Ruby `examples/simple-server/app.rb` shape.
- [`examples/nginx/`](examples/nginx) — OpenResty / nginx config
  with `access_by_lua_file` loading a Lua middleware in the access
  phase. The canonical Kong / OpenResty deployment shape.

Both expose `/health` (free) and `/paid` (gated). Use the interop
harness in PR B for the full Surfpool-backed settlement flow.

## Solana dependencies

| Dependency | Why | Version |
|---|---|---|
| `LuaJIT` | runtime; matches OpenResty / Kong production | 2.1 |
| `luarocks` | rocks tree bootstrap (`luarocks --lua-version=5.1 init`) | 3.x |
| `luacheck` | lint (per repo coding-conventions) | 1.2 |
| `luacov` | line coverage measurement, ≥90% gate | 0.17 |
| internal Base58 helper | account / signature encoding (PR B) | in package |
| internal HMAC-SHA256 | constant-time challenge id compare | in package |
| internal canonical JSON helper | RFC 8785-style sorted JSON before base64url | in package |

The Lua SDK keeps Solana dependencies intentionally small. It open-codes
the wire constants it needs (see `mpp/protocol/solana.lua`) rather than
pulling in a heavy Solana client. The JSON-RPC client at
`mpp/solana/rpc.lua` is transport-agnostic so callers can plug
`socket.http`, `cqueues-http`, or OpenResty's `ngx.location.capture`
without changing the handler.

## Coding convention

This SDK follows `luacheck + LuaJIT 2.1` and the best-practice skills
selected for this PR:

- [`skills.sh/mindrally/skills/lua`](https://www.skills.sh/mindrally/skills/lua)
  for idiomatic Lua (local-over-global for the LuaJIT trace recorder,
  tables as the primary data structure, `pcall` / `xpcall` for error
  boundaries instead of try / catch ports, metatables for OO shapes,
  1-based indexing throughout).
- [`skills.sh/germanfndez/fiveai-skills/lua-basics`](https://www.skills.sh/germanfndez/fiveai-skills/lua-basics)
  for the embedded-Lua performance and code-quality patterns that apply
  on hot paths (cached upvalue references for `table.concat` and other
  library functions, numeric `for` loops over `pairs` / `ipairs` where
  the data is array-shaped, defensive `tonumber`, no global function
  definitions, constants in `SCREAMING_SNAKE`).

OpenResty / Kong is the target deployment runtime; the `ngx_*` API
surface and shared-dict storage shape what production callers see, so
hot-path code stays allocation-free and avoids string concatenation
inside loops (`table.concat` is used everywhere a buffer accumulates,
see the WWW-Authenticate formatter in `mpp/protocol/core/headers.lua`).

- `snake_case` for functions, `PascalCase` for types, `SCREAMING_SNAKE`
  for constants.
- One-line doc comment on every public function / type.
- Wire-format field names stay **camelCase JSON** even when Lua field
  names are `snake_case` internally; only the serialized form is
  camelCase.

The repo-level `pay-sdk-implementation` skill remains the protocol
source of truth: Rust / spec wire format first, Lua idioms second.

## Code coverage

```bash
cd lua
just lua-lint
just lua-audit
just lua-test-cover
```

`just lua-test-cover` runs the unit suite under LuaJIT with `luacov`
instrumentation and enforces the local coverage gate.

Coverage gate:

- line coverage: at least 90 percent (reported by luacov)

Branch coverage is not reported by luacov; the language ships a
single-pass coverage model. The unit suite still exercises the payment
verifier's critical decisions: valid / invalid credentials, cross-route
replay, settlement ordering (broadcast → consume → await), signature
replay rejection, transaction failures, missing metadata, timeouts.

## Interop

The Lua interop adapter ships in PR B (depends on the Solana stack:
base58, transaction bincode codec, ed25519 signer, ATA PDA derivation).
Once landed, the focused harness commands will be:

```bash
cd tests/interop
MPP_INTEROP_CLIENTS=typescript MPP_INTEROP_SERVERS=lua pnpm test
MPP_INTEROP_CLIENTS=rust       MPP_INTEROP_SERVERS=lua pnpm test
```

## Spec

This SDK implements the [Solana Charge Intent](https://github.com/tempoxyz/mpp-specs/pull/188)
for the [HTTP Payment Authentication Scheme](https://paymentauth.org).

## License

MIT
