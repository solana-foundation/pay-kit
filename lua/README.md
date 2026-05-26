<p align="center">
  <img src="https://github.com/solana-foundation/pay-kit/raw/main/docs/assets/banner.png" alt="MPP" width="100%" />
</p>

# solana-pay-kit

Charge stablecoins (USDC, USDT, PYUSD, ...) for any HTTP endpoint, in Lua.
Runs on LuaJIT 2.1 (the OpenResty / Kong production runtime). Implements
the Solana payment method for the
[Machine Payments Protocol](https://mpp.dev).

This library is **server-only**. It issues 402 challenges, verifies
`Authorization: Payment` credentials, and settles charges against the
Solana RPC. Client support lives in the TypeScript, Rust, Go, Python,
Ruby, Kotlin, and Swift packages.

**MPP** is [an open protocol proposal](https://paymentauth.org) that lets
any HTTP API accept payments using the `402 Payment Required` flow. You
do not need to know anything about Solana to use this library: pick a
currency, give it your wallet address, and gate a route in two lines.

[![LuaJIT](https://img.shields.io/badge/luajit-2.1-blue)]()
[![Coverage](https://img.shields.io/badge/coverage-90%25-brightgreen)]()
[![Tests](https://img.shields.io/badge/tests-125-blue)]()

## Quick start

Wire the SDK into nginx with an `access_by_lua_file` step (from
[`examples/nginx/nginx.conf`](examples/nginx/nginx.conf)):

```nginx
worker_processes  1;
events { worker_connections 256; }

http {
  lua_package_path  '../../?.lua;../../?/init.lua;;';
  lua_shared_dict   mpp_replay  10m;

  server {
    listen 127.0.0.1:4570 reuseport;

    location = /health {
      default_type application/json;
      return 200 '{"ok":true}';
    }

    location = /paid {
      default_type application/json;
      access_by_lua_file access.lua;
      return 200 '{"ok":true,"paid":true}';
    }
  }
}
```

The Lua middleware (see
[`examples/nginx/access.lua`](examples/nginx/access.lua)) runs in
nginx's access phase: it returns 402 with a signed `WWW-Authenticate`
challenge when the caller has no `Authorization: Payment` credential, or
verifies and settles the payment before letting the upstream content
phase render the protected payload.

`currency` accepts a symbol like `"USDC"`, `"USDT"`, `"USDG"`, `"PYUSD"`,
or `"CASH"`. The SDK looks up the mint address, token program, and
decimals from a built-in table. You can also pass a raw mint pubkey for
tokens not in the table.

### Framework targets

The Lua SDK is transport-agnostic: it does not own the HTTP server. Bind
it inside your framework of choice.

- **OpenResty / Kong** (target deployment runtime): call
  `server:handle_request(...)` from an `access_by_lua_block` and let the
  upstream serve only on a 200 result.
- **Bare LuaJIT** (development, tests): drive it from a raw
  `socket.tcp()` accept loop. `examples/simple-server.lua` ships a
  reference implementation wired to the real Solana settlement
  lifecycle.

## Protocol compatibility matrix

This library is server-only. Client support lives in the TypeScript,
Rust, Go, Python, Ruby, Kotlin, and Swift packages.

### MPP

| Intent | Server |
|---|:---:|
| `mpp/charge/pull` | pass |
| `mpp/charge/push` | pass |
| `mpp/session` | --- |
| `mpp/subscription` | --- |

### x402

| Intent | Server |
|---|:---:|
| `x402/exact` | --- |
| `x402/upto` | --- |
| `x402/batch-settlement` | --- |

For `mpp/charge/pull`: the handler owns the full lifecycle. It issues
signed challenges with a fresh `recentBlockhash`, parses and validates
the `Authorization: Payment` credential, pins the echoed charge request,
decodes the client-signed transaction and checks recipient, amount,
mint, splits, ATA, memos, and compute budget, rejects Surfpool-signed
transactions on non-localnet networks, optionally fee-payer co-signs,
broadcasts via `sendTransaction`, **consumes the signature in the replay
store before** polling `getSignatureStatuses` to `confirmed` /
`finalized`, and emits `payment-receipt` with the on-chain signature.
The consume-before-await ordering closes the confirmation-timeout
double-pay window.

For `mpp/charge/push`: the handler fetches the transaction by signature
with `getTransaction`, rejects failed or missing metadata, reuses the
same structural transaction verifier as pull mode, consumes the
signature through replay storage, and emits the same receipt shape.

## Examples

Three runnable examples ship with this package:

- [`examples/simple-server.lua`](examples/simple-server.lua) - bare
  LuaJIT TCP accept loop that calls `mpp.server` directly.
- [`examples/nginx/`](examples/nginx) - OpenResty / nginx config with
  `access_by_lua_file` loading a Lua middleware in the access phase.
- [`examples/openresty/kong-plugin/`](examples/openresty/kong-plugin) -
  Kong custom plugin. The canonical production deployment shape.

### Run the nginx example

```bash
# install openresty
brew tap openresty/brew
brew install openresty

# start the proxy
cd lua/examples/nginx
PORT=4570 openresty -p . -c nginx.conf
```

### Run the bare LuaJIT example

```bash
cd lua
eval "$(luarocks --lua-version=5.1 --tree lua_modules path)"
luajit examples/simple-server.lua    # listens on 127.0.0.1:4569
```

### Drive it from a client

```bash
brew install pay
curl  http://127.0.0.1:4570/paid       # 402 payment required
pay curl http://127.0.0.1:4570/paid    # pays and succeeds
```

All examples accept the same env overrides: `PORT`, `MPP_PAY_TO`,
`MPP_CURRENCY`, `MPP_NETWORK`, `MPP_SECRET_KEY`, `MPP_AMOUNT`,
`MPP_RPC_URL`, `MPP_FEE_PAYER_SECRET_KEY`.

## Solana dependencies

| Dependency | Why | Version |
|---|---|---|
| `LuaJIT` | runtime; matches OpenResty / Kong production | 2.1 |
| `luarocks` | rocks tree bootstrap | 3.x |
| `luacheck` | lint (per repo coding-conventions) | 1.2 |
| `luacov` | line coverage measurement, >=90% gate | 0.17 |
| `luasodium` | libsodium binding for Ed25519 sign / verify | >= 2.0 |
| `luasocket` | TCP transport for examples and interop | >= 3.0 |
| `luasec` | HTTPS transport for the RPC client | >= 1.3 |
| `mpp.util.base58` | account / signature encoding | in package |
| `mpp.methods.solana.*` | wire-format codec, instruction parsers, ATA derivation, verifier | in package |
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
selected for this PR
([mindrally/skills/lua](https://www.skills.sh/mindrally/skills/lua),
[germanfndez/fiveai-skills/lua-basics](https://www.skills.sh/germanfndez/fiveai-skills/lua-basics)).
OpenResty / Kong is the target deployment runtime; hot-path code stays
allocation-free and avoids string concatenation inside loops.

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
instrumentation and enforces the local coverage gate (line coverage
at least 90 percent).

## Interop

The Lua interop server at
[`harness/lua-server/server.lua`](../harness/lua-server/server.lua)
participates in the cross-language harness:

```bash
cd harness
MPP_INTEROP_CLIENTS=typescript MPP_INTEROP_SERVERS=lua pnpm exec vitest run test/e2e.test.ts
MPP_INTEROP_CLIENTS=rust       MPP_INTEROP_SERVERS=lua pnpm exec vitest run test/e2e.test.ts
```

## Spec

This SDK implements the [Solana Charge Intent](https://github.com/tempoxyz/mpp-specs/pull/188)
for the [HTTP Payment Authentication Scheme](https://paymentauth.org).

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
├── mpp/store.lua         # Replay store
├── mpp/util/             # base64url, canonical JSON, HMAC primitives
├── tests/                # Unit tests, >=90% line coverage gate via luacov
├── mpp-dev-1.rockspec    # LuaJIT 2.1 pinned rockspec
└── Justfile              # install / test / lint / test-cover / audit
```

## License

MIT
