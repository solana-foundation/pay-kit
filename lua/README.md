<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://github.com/solana-foundation/pay-kit/raw/main/docs/assets/banner-lua-dark.png">
    <source media="(prefers-color-scheme: light)" srcset="https://github.com/solana-foundation/pay-kit/raw/main/docs/assets/banner-lua-light.png">
    <img alt="Solana pay-kit — Lua" width="100%" style="border-top-left-radius: 8px; border-top-right-radius: 8px; margin-bottom: 16px;" src="https://github.com/solana-foundation/pay-kit/raw/main/docs/assets/banner-lua-light.png">
  </picture>
</div>

Charge stablecoins (USDC, USDT, PYUSD, ...) for any HTTP endpoint, in
Lua. One rock, one surface, two protocols underneath:
[x402](https://x402.org) and the
[Machine Payments Protocol](https://paymentauth.org). Kong and APISIX
ride on top of a pure OpenResty middleware.

You do not need to know anything about Solana to use this. Pick a
currency, give it your wallet address, and gate a route in two lines.
The rock handles the challenge, the verification, and the on-chain
settlement underneath.

[![LuaJIT](https://img.shields.io/badge/luajit-2.1-blue)]()
[![Coverage](https://img.shields.io/badge/coverage-91%25-brightgreen)]()
[![Branch coverage](https://img.shields.io/badge/branch-90%25-brightgreen)]()

---

## Quick start

Three progressively-realistic snippets. Each one runs as-is, copy,
paste, hit the URL. OpenResty is the framework here; the same
surface works inside Kong and APISIX plugins.

### 1. Smallest possible app

Gate one route with an inline price. Save the snippet as `nginx.conf`
and boot with `openresty -p . -c nginx.conf`. Zero-config: the rock
uses a published demo keypair as the recipient and the hosted
Surfpool sandbox at `https://402.surfnet.dev:8899` as the RPC.

```nginx
# nginx.conf
worker_processes 1;
events { worker_connections 256; }
daemon off;
error_log stderr info;

http {
  lua_shared_dict pay_kit_replay 10m;

  init_by_lua_block {
    local pay_kit = require('pay_kit')
    assert(pay_kit.configure({ network = 'solana_localnet' }))
    pay_kit.gate('report', { amount = pay_kit.usd('0.10') })
  }

  server {
    listen 4570;
    location = /report {
      access_by_lua_block { require('pay_kit').require_payment('report') }
      default_type application/json;
      return 200 '{"ok":true}';
    }
  }
}
```

`require('pay_kit')` is the umbrella. `require_payment(name)`
halts the request with a 402 if no valid payment was sent, or sets
`ngx.ctx.pay_kit_payment` and returns control to the content phase
if one was.

Hit `/report` with [`pay curl`](#run-the-example) and the customer
walks through Touch ID and a USDC payment.

### 2. Multiple gates via a registry

When more than one route is paid, lift the prices into a module so
the catalogue lives in one place. Routes reference gates by name.

```nginx
# nginx.conf
worker_processes 1;
events { worker_connections 256; }
daemon off;
error_log stderr info;

http {
  lua_shared_dict pay_kit_replay 10m;
  lua_package_path './?.lua;;';

  init_by_lua_block {
    local pay_kit = require('pay_kit')
    assert(pay_kit.configure({ network = 'solana_localnet' }))
    require('pricing')  -- registers every gate
  }

  server {
    listen 4570;
    location = /report {
      access_by_lua_block { require('pay_kit').require_payment('report') }
      return 200 '{"premium":"report"}';
    }
    location = /api/data {
      access_by_lua_block { require('pay_kit').require_payment('api_call') }
      return 200 '{"data":[]}';
    }
  }
}
```

```lua
-- pricing.lua
local pay_kit = require('pay_kit')

pay_kit.gate('report',   { amount = pay_kit.usd('0.10'),
                           description = 'Premium report' })
pay_kit.gate('api_call', { amount = pay_kit.usd('0.001'),
                           accept = { 'x402' } })
```

Gates are validated at boot. Wrong currency, missing recipient, fee
math that does not add up - all raise from `configure()` / `gate()`
before any request lands. `accept` is an allowlist; the `api_call`
gate above refuses to settle over MPP.

### 3. Production-shape config

Snippet 2's demo recipient and the hosted Surfpool RPC are fine for
poking around. Production wants explicit keys, a dedicated RPC, and
an accepted-stablecoin list. The location blocks are unchanged, only
the `init_by_lua_block` grows.

```nginx
# nginx.conf
worker_processes auto;
events { worker_connections 1024; }
error_log stderr info;

http {
  lua_shared_dict pay_kit_replay 10m;
  lua_package_path './?.lua;;';

  init_by_lua_block {
    local pay_kit = require('pay_kit')
    local signer  = require('pay_kit.signer')

    local PLATFORM = 'CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY'

    assert(pay_kit.configure({
      network     = 'solana_mainnet',
      rpc_url     = 'https://mainnet.helius-rpc.com/?api-key=YOUR_HELIUS_KEY',
      stablecoins = { 'USDC', 'PYUSD' },
      operator = {
        signer    = signer.file('/etc/paykit/operator.json'),
        recipient = 'AyNAa2VPe2t5pgg8M61iE6kqMudkV98zsT4rkAZuU6tj',
        fee_payer = true,
      },
    }))

    pay_kit.gate('report', { amount = pay_kit.usd('0.10'),
                             description = 'Premium report' })

    -- Platform-fee pattern:
    -- Customer pays $10.00,
    -- Operator nets $9.70, PLATFORM nets $0.30.
    pay_kit.gate('marketplace_sale', {
      amount     = pay_kit.usd('10.00'),
      fee_within = { [PLATFORM] = pay_kit.usd('0.30') },
    })
  }

  server {
    listen 4570;
    location = /report          { access_by_lua_block { require('pay_kit').require_payment('report') }          return 200 '{"premium":"report"}'; }
    location = /marketplace/buy { access_by_lua_block { require('pay_kit').require_payment('marketplace_sale') } return 200 '{"sold":true}'; }
  }
}
```

Two safety rails fire at boot:

- `solana_mainnet` plus the published demo signer raises. No real
  funds get routed to a publicly-known address by accident.
- Missing `mpp.challenge_binding_secret`? Preflight surfaces the
  gap and points at `PAY_KIT_MPP_CHALLENGE_BINDING_SECRET` as the
  env override.

Override any literal in the snippet with `os.getenv` if you want it
out of source control; the snippets keep the strings inline so you
do not have to mentally substitute while reading.

---

## Run the example

The runnable demo lives at [`examples/nginx/`](examples/nginx) - one
gated endpoint, both protocols, real Solana settlement against the
hosted Surfpool sandbox. A bare [`examples/simple-server.lua`](examples/simple-server.lua)
TCP loop covers hosts without OpenResty.

**Boot the server:**

```bash
git clone https://github.com/solana-foundation/pay-kit
cd pay-kit/lua/examples/nginx
luarocks --lua-version=5.1 --tree=../../lua_modules install pay-kit
openresty -p . -c nginx.conf
```

Boot logs preflight output. On `solana_localnet` with the demo
signer, the rock provisions the recipient's USDC account on Surfpool
via cheatcodes the first time, then settles real on-chain payments
after that.

**Consume with `pay curl`:**

```bash
# Install the pay CLI:
brew install pay
# or npm install -g @solana/pay

# Fail with 402 - payment required
curl -i http://127.0.0.1:4570/report

# Succeed with 200 - payment provided
pay curl -i http://127.0.0.1:4570/report
```

---

## x402

[x402](https://x402.org) revives HTTP `402 Payment Required` as a
client-server payment handshake. Your server gates a route; a paying
client receives the 402 with payment instructions, signs a Solana
transaction off-chain, and replays the same request with a
`PAYMENT-SIGNATURE` header. The Lua server verifies the signature,
broadcasts the transaction, and returns the original response with a
`PAYMENT-RESPONSE` header carrying the on-chain settlement signature.

x402 is **single-recipient by design**: the facilitator pays the
network fees, the customer's signed transaction settles funds to
`pay_to`. Gates with `fee_within` or `fee_on_top` recipients
auto-disable x402 because stock x402 facilitators settle to one
address.

Supported on the Lua server:

| Intent             | Status |
|--------------------|--------|
| `exact`            | ✅      |
| `upto`             | —      |
| `batch-settlement` | —      |

## MPP

The [Machine Payments Protocol](https://paymentauth.org) is the
broader HTTP Payment Authentication scheme, same 402 handshake but
the challenge carries a richer intent shape that supports
multi-recipient splits, server-side fee accounting, and a separate
fee-payer signer.

Use MPP when:

- Your gate has a platform or gateway fee (Stripe-Connect
  "application fee" pattern).
- You want the server to subsidize the customer's network fee.
- You want one challenge per gate instead of per-mint-quoted offers.

Supported on the Lua server:

| Intent         | Status |
|----------------|--------|
| `charge/pull`  | ✅      |
| `charge/push`  | ✅      |
| `session`      | —      |
| `subscription` | —      |

---

## Server-only

This rock ships **server support only**. The pay-kit server emits
challenges, verifies proofs, and broadcasts settlement transactions;
it does not pay. Drive the client side from:

- [`pay curl`](https://github.com/solana-foundation/pay) — recommended
- The Rust, TypeScript, Go, Python, Ruby, Kotlin, or Swift pay-kit
  client SDKs (sibling READMEs in this repo)

---

## Vocabulary

| Term         | Meaning |
|--------------|---------|
| **gate**     | A protected unit. Has an amount, optional fees, accepted protocols. |
| **amount**   | The base amount a gate charges, before any `fee_on_top`. |
| **total**    | What the customer pays: `amount + sum(fee_on_top)`. Derived. |
| **price**    | Value object returned by `usd(...)`: number + currency + settlement. |
| **fee_within** | Fee taken out of the amount. `pay_to` nets less. |
| **fee_on_top** | Fee added to the amount. Customer pays more; `pay_to` nets full. |
| **payment**  | Proof submitted by the client to pass a gate. |
| **protocol** | `'x402'` or `'mpp'` (top-level dispatch). |
| **scheme**   | x402 sub-form: `'exact'`. MPP sub-form: `'charge'`. |
| **currency** | Fiat unit a price is quoted in (`'USD'`, `'EUR'`). |
| **accept**   | Ordered preference list (protocols and stablecoins both). |
| **settlement** | On-chain asset that actually transfers (`USDC`, `USDT`). |

## Three primitives

Mirrors `lua-resty-openidc`'s `authenticate` / `get_user` / `unauth_action`:

| Function | Purpose |
|----------|---------|
| `pay_kit.require_payment(name)`     | Bang form. Halts via `ngx.exit(402)` if unpaid. |
| `pay_kit.try_payment(name)`         | Returns `(payment, err, response)`. Never halts. |
| `pay_kit.payment()`                 | The verified payment proof, `nil` until paid. |
| `pay_kit.paid()` / `paid_for(name)` | Predicate; never halts. |

`require_payment` is the one Kong and APISIX plugins call. `try_payment`
hands you the 402 envelope so non-OpenResty Lua hosts (raw `socket.tcp`,
embedded test loops) can render the response themselves.

## Inline pricing

For one-off endpoints that do not warrant a registry entry, skip
the gate name and pass an options table directly:

```lua
location = /oneoff {
  access_by_lua_block {
    require('pay_kit').require_payment({
      amount = require('pay_kit').usd('0.25'),
      description = 'One-off',
    })
  }
  return 200 '{"ok":true}';
}
```

## Gate DSL

Each gate is a frozen value object with an amount, an ordered list of
accepted protocols, and zero or more named fees.

```lua
local pay_kit = require('pay_kit')

local SELLER   = 'Ay...'
local PLATFORM = 'CX...'

-- Simple. Customer pays $0.10, pay_to nets $0.10.
pay_kit.gate('report', { amount = pay_kit.usd('0.10'),
                         description = 'Premium report' })

-- x402-only.
pay_kit.gate('api_call', { amount = pay_kit.usd('0.001'),
                           accept = { 'x402' } })

-- Stripe-Connect "application fee". Customer pays $10.00,
-- SELLER nets $9.70, PLATFORM nets $0.30. x402 auto-disabled.
pay_kit.gate('marketplace_sale', {
  amount     = pay_kit.usd('10.00'),
  pay_to     = SELLER,
  fee_within = { [PLATFORM] = pay_kit.usd('0.30') },
})

-- Surcharge. Customer pays $10.50, SELLER nets $10.00, PLATFORM $0.50.
pay_kit.gate('ticket', {
  amount     = pay_kit.usd('10.00'),
  pay_to     = SELLER,
  fee_on_top = { [PLATFORM] = pay_kit.usd('0.50') },
})

-- Dynamic per-request pricing.
pay_kit.gate('tiered', function(req)
  local tier = req.query.tier
  return { amount = pay_kit.usd(tier == 'premium' and '5.00' or '0.10') }
end)
```

Boot-time validations (all raise from `gate()`):

- `pay_to` is required (gate kwarg or `operator.recipient`).
- Fee recipient must differ from `pay_to`. Fold the fee into the amount instead.
- All fee prices share one currency with the amount.
- `sum(fee_within) <= amount`.
- `accept = { 'x402' }` on a fee-bearing gate raises.

## OpenResty-first

The Kong plugin (`plugins/kong/plugins/pay-kit/`, `PRIORITY = 1010`)
and the APISIX plugin (`plugins/apisix/plugins/pay-kit.lua`,
`priority = 2520`) are
~100-line shims over `pay_kit`. Kong sits between
`basic-auth` (1001) and OpenID Connect (1050); APISIX sits just
above `jwt-auth` (2510). Both call `pay_kit.try_payment` from the
access phase and stamp `payment.settlement_headers` from the header-filter
phase.

```nginx
# Raw OpenResty
http {
  lua_shared_dict pay_kit_replay 10m;
  init_by_lua_block { require('pay_kit').configure({ ... }) }
  server {
    location /paid {
      access_by_lua_block { require('pay_kit').require_payment('paid') }
      proxy_pass http://backend;
    }
  }
}
```

Kong and APISIX both resolve their plugins via `lua_package_path`.
Add the `plugins/` subtree to the path and their loaders will find
the gateway-specific entry-points at their conventional require
names (`kong.plugins.pay-kit.*`, `apisix.plugins.pay-kit`):

```bash
# Kong
KONG_LUA_PACKAGE_PATH='./lua/plugins/?.lua;./lua/?.lua;;'
KONG_PLUGINS='bundled,pay-kit'

# APISIX
apisix_lua_package_path: './lua/plugins/?.lua;./lua/?.lua;;'
```

The shared dict `pay_kit_replay` is the cross-worker replay store.
Without it, the rock falls back to a per-worker in-memory LRU and
logs a `WARN` at boot (fine for dev, not for multi-worker prod).

### Ed25519 backend

Resolves at module load:

1. **lua-resty-openssl** (preferred). Bundled with Kong 3.x; one
   `luarocks install lua-resty-openssl` on APISIX. No system libsodium
   needed.
2. **luasodium** (fallback). Plain LuaJIT dev environments without
   OpenResty or OpenSSL still get a working signer.

`require('pay_kit.util.ed25519').backend()` returns `'openssl'`,
`'luasodium'`, or `'none'` so operators can log which path is hot.

---

## Coverage

```bash
cd lua
just lint
just test-cover
```

`just test-cover` runs the spec suite under luacov and the
ATA-derive fixture spec a second time without luacov (the JIT
disable under luacov makes the on-curve check 100x slower; running
unwrapped once still gives the branch coverage the rest of the suite
needs). Refresh the README badges from `luacov.report.out`.

Gates:

- Line coverage: at least 90 percent
- Tests: 561 passing, 1 skipped

## Harness

The Lua server has one dual-protocol adapter at
[`harness/lua-server/server.lua`](../harness/lua-server/server.lua)
that reads either `MPP_INTEROP_*` or `X402_INTEROP_*` env (or the
`PAY_KIT_INTEROP_PROTOCOL` hint when both namespaces are populated).
Focused harness commands:

```bash
cd harness
MPP_INTEROP_CLIENTS=typescript  MPP_INTEROP_SERVERS=lua pnpm test
MPP_INTEROP_CLIENTS=rust        MPP_INTEROP_SERVERS=lua pnpm test
X402_INTEROP_CLIENTS=rust-x402  MPP_INTEROP_SERVERS=lua pnpm test
```

CI runs the same matrix in `.github/workflows/lua.yml`.

## Spec

This SDK implements the
[Solana Charge Intent](https://paymentauth.org/draft-solana-charge-00.html)
for the [HTTP Payment Authentication Scheme](https://paymentauth.org),
plus the [x402 exact scheme](https://x402.org) on Solana.

---

## Repo layout

```text
lua/
├── pay_kit/                                # PayKit core (no resty/ or mpp/ prefix)
│   ├── init.lua                            # configure / gate / usd / require_payment ...
│   ├── errors.lua                          # canonical error strings
│   ├── kms.lua                             # post-v1 reserved namespace
│   ├── preflight.lua                       # boot-time soundness + surfnet cheatcodes
│   ├── signer.lua + signer/{demo,local}    # signer factory family
│   ├── store.lua                           # memory() + shared_dict(name) replay store
│   ├── solana/                             # PayCore: Solana primitives + cosocket RPC
│   │   ├── ata.lua, base58.lua, instructions.lua, transaction.lua
│   │   ├── local_signer.lua, mints.lua, network_check.lua, tx_cosign.lua, verifier.lua
│   │   └── rpc.lua, rpc_transport.lua, rpc_transport_resty.lua
│   ├── util/                               # PayCore: generic util (base64, bit, crypto, ed25519, json, uint)
│   ├── protocol/core/                      # MPP wire format (headers, types, challenge, error_codes)
│   ├── protocols/                          # per-protocol code; neither imports the other
│   │   ├── mpp/
│   │   │   ├── init.lua, charge.lua, expires.lua, error.lua, store.lua
│   │   │   └── server/                     # MPP server (charge_handler, solana_verify, ...)
│   │   └── x402/
│   │       ├── init.lua                    # x402 adapter (offer + cosign + broadcast)
│   │       └── exact/verify.lua            # 11-rule SVM-exact structural verifier
│   └── internal/{config,dispatcher,fee,gate,operator,price,registry}.lua
├── plugins/                                # framework wrappers
│   ├── resty/pay-kit.lua                   # OpenResty re-export
│   ├── kong/plugins/pay-kit/               # Kong plugin (loader path-pinned)
│   └── apisix/plugins/pay-kit.lua          # APISIX plugin (loader path-pinned)
├── examples/                               # simple-server.lua + nginx/ runnable demos
└── tests/                                  # hand-rolled spec runner (tests/run.lua) + luacov gate
```

## Coding convention

LuaJIT 2.1 idioms, `luacheck` clean, no globals outside the
`luacheck: globals` allowlist. Pure functions where possible;
explicit error strings prefixed with `pay_kit:` so call sites can
grep. Protocol-critical paths (the 11-rule x402 verifier, MPP
credential parsing, Ed25519 cosign) get branch tests.

The repo-level
[`skills/pay-sdk-implementation`](../skills/pay-sdk-implementation/SKILL.md)
skill remains the protocol source of truth: Rust spec wire format
first, Lua idioms second.

## License

MIT
